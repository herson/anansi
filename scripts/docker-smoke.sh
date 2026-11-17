#!/usr/bin/env bash
# Builds the Docker image and checks the things unit tests cannot see:
#   1. no secret value from .env ends up in the image
#   2. the server refuses to listen on 0.0.0.0 without ANANSI_API_KEY
#   3. the container runs as a non-root user
#   4. with a key, the dashboard answers through the published port and can
#      write its database to a named volume, as docker-compose.yml does
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

docker run -d --name "$CONTAINER" -p "127.0.0.1:$PORT:8000" \
  -v "$VOLUME:/app/data" -e ANANSI_API_KEY="$API_KEY" "$IMAGE" >/dev/null
for _ in $(seq 1 30); do
  if curl -fsS -H "X-API-Key: $API_KEY" "http://127.0.0.1:$PORT/api/status" >/dev/null 2>&1; then
    echo "ok: dashboard answers through the published port"
    exit 0
  fi
  sleep 1
done
echo "FAIL: dashboard did not answer on port $PORT" >&2
docker logs "$CONTAINER" >&2 || true
exit 1
