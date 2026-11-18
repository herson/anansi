#!/usr/bin/env bash
# Builds the Docker image and checks the things unit tests cannot see:
#   1. no secret value from .env ends up in the image
#   2. the server refuses to listen on 0.0.0.0 without ANANSI_API_KEY
#   3. the container runs as a non-root user
#   4. the image has every package pinned in the runtime lock, and no docs tools
#   5. the image can render a PDF report (its fonts are data files, not imports)
#   6. with a key, the dashboard answers through the published port
#   7. a schedule is kept on the named volume and survives replacing the
#      container, as an image update with docker-compose.yml does
#   8. the dashboard writes its log file (logging is set up by the entry
#      point, not on import)
#   9. the image runs the Python version its Dockerfile names
set -euo pipefail

IMAGE="anansi:smoke"
CONTAINER="anansi-smoke-$$"
PORT="${SMOKE_PORT:-18000}"
API_KEY="smoke-$(openssl rand -hex 8)"
CANARY="anansi-canary-$(openssl rand -hex 16)"
VOLUME="anansi-smoke-data-$$"

cd "$(dirname "$0")/.."

PATTERNS="$(mktemp)"
EXPORT_TAR="$(mktemp)"
PLANTED_ENV=""
cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker volume rm -f "$VOLUME" >/dev/null 2>&1 || true
  rm -f "$PATTERNS" "$EXPORT_TAR"
  if [ -n "$PLANTED_ENV" ]; then rm -f .env; fi
}
trap cleanup EXIT

# Secret values that must never appear in the image: a planted canary when
# there is no .env (CI), otherwise every non-trivial value in the real .env.
if [ -e .env ]; then
  sed -n 's/^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=//p' .env \
    | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//' \
    | awk 'length >= 8' > "$PATTERNS"
else
  PLANTED_ENV=1
  echo "ANANSI_CANARY=$CANARY" > .env
  echo "$CANARY" > "$PATTERNS"
fi

docker build -q -t "$IMAGE" . >/dev/null
echo "ok: image built"

docker create --name "$CONTAINER" "$IMAGE" >/dev/null
docker export -o "$EXPORT_TAR" "$CONTAINER"
if [ -s "$PATTERNS" ] && grep -aqF -f "$PATTERNS" "$EXPORT_TAR"; then
  echo "FAIL: a secret value from .env was found in the image (value not printed)" >&2
  exit 1
fi
docker rm "$CONTAINER" >/dev/null
echo "ok: build-context secrets are not in the image"

if NO_KEY_OUTPUT="$(docker run --rm "$IMAGE" 2>&1)"; then
  echo "FAIL: server started on 0.0.0.0 without ANANSI_API_KEY" >&2
  exit 1
fi
if ! grep -q "Refusing to listen" <<<"$NO_KEY_OUTPUT"; then
  echo "FAIL: server exited without an API key, but not because of the key check:" >&2
  echo "$NO_KEY_OUTPUT" | tail -5 >&2
  exit 1
fi
echo "ok: server refuses to start without an API key"

if [ "$(docker run --rm --entrypoint id "$IMAGE" -u)" = "0" ]; then
  echo "FAIL: the container runs as root" >&2
  exit 1
fi
echo "ok: container runs as a non-root user"

WANT_PYTHON="$(sed -nE 's/^FROM python:([0-9]+\.[0-9]+)-.*/\1/p' Dockerfile)"
GOT_PYTHON="$(docker run --rm --entrypoint python "$IMAGE" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
if [ -z "$WANT_PYTHON" ] || [ "$GOT_PYTHON" != "$WANT_PYTHON" ]; then
  echo "FAIL: the image runs Python $GOT_PYTHON, the Dockerfile names '$WANT_PYTHON'" >&2
  exit 1
fi
echo "ok: the image runs Python $GOT_PYTHON"

# Every pin in the runtime lock is installed (pip resolves nothing from an
# index), and documentation tools stay out of the image (ADR-0010).
if ! docker run --rm --entrypoint pip "$IMAGE" install --dry-run --no-index --no-deps \
    --require-hashes -r requirements.txt >/dev/null 2>&1; then
  echo "FAIL: the image does not have every package pinned in requirements.txt" >&2
  exit 1
fi
if docker run --rm --entrypoint pip "$IMAGE" show mkdocs >/dev/null 2>&1; then
  echo "FAIL: the image contains mkdocs, a documentation tool" >&2
  exit 1
fi
echo "ok: the image has the locked runtime packages and no docs tools"

# The PDF fonts are data files, not imports: check they reached the image.
if ! docker run --rm --entrypoint python "$IMAGE" -c '
from domain.findings import Finding
from modules.reporting_pdf import PDFReporter
PDFReporter({"target": "10.0.0.0/24"}, [Finding("10.0.0.5", 80, "tcp", "http", "Zażółć httpd", "2.0")]).generate("/tmp/smoke.pdf")
' >/dev/null; then
  echo "FAIL: the image cannot render a PDF report with non-Latin-1 text" >&2
  exit 1
fi
echo "ok: the image renders a PDF report with non-Latin-1 text"

BASE="http://127.0.0.1:$PORT"
AUTH="X-API-Key: $API_KEY"

start_dashboard() {
  docker run -d --name "$CONTAINER" -p "127.0.0.1:$PORT:8000" \
    -v "$VOLUME:/app/data" -e ANANSI_API_KEY="$API_KEY" "$IMAGE" >/dev/null
  for _ in $(seq 1 30); do
    if curl -fsS -H "$AUTH" "$BASE/api/status" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "FAIL: dashboard did not answer on port $PORT" >&2
  docker logs "$CONTAINER" >&2 || true
  exit 1
}

start_dashboard
echo "ok: dashboard answers through the published port"

JOB_ID="$(curl -fsS -X POST -H "$AUTH" "$BASE/api/schedule?target=10.0.0.1&cron=0+2+*+*+*" \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')"
docker rm -f "$CONTAINER" >/dev/null
start_dashboard
SCHEDULES="$(curl -fsS -H "$AUTH" "$BASE/api/schedule")"
if ! grep -qF "\"$JOB_ID\"" <<<"$SCHEDULES"; then
  echo "FAIL: the schedule was lost when the container was replaced" >&2
  exit 1
fi
echo "ok: schedules survive replacing the container"

if ! docker exec "$CONTAINER" test -s /app/logs/anansi.log; then
  echo "FAIL: the dashboard wrote nothing to /app/logs/anansi.log" >&2
  exit 1
fi
echo "ok: the dashboard writes its log file"
