#!/usr/bin/env bash
# Compiles each requirements*.in into a hashed lockfile for every Python
# version CI supports (ADR-0010).
#
#   scripts/lock-requirements.sh                        re-lock, keeping current pins
#   scripts/lock-requirements.sh --upgrade              move every pin to its newest version
#   scripts/lock-requirements.sh --upgrade-package X    move one package
#   scripts/lock-requirements.sh --check                fail if a lockfile is out of date
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON_MIN="3.10"
LOCKS=(requirements requirements-dev requirements-docs)

compile() {  # compile <name> <output dir> [uv args...]
  local name="$1" out="$2"
  shift 2
  uv pip compile "$name.in" --universal --python-version "$PYTHON_MIN" --generate-hashes \
    --quiet --custom-compile-command "scripts/lock-requirements.sh" -o "$out/$name.txt" "$@"
}

if [ "${1:-}" = "--check" ]; then
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  status=0
  for name in "${LOCKS[@]}"; do
    if [ ! -f "$name.txt" ]; then
      echo "FAIL: $name.txt is missing; run scripts/lock-requirements.sh" >&2
      status=1
      continue
    fi
    cp "$name.txt" "$TMP/$name.txt"
    # -c paths in .in files are relative to the .in file, so compile in place
    # and write the result to the temporary copy.
    compile "$name" "$TMP"
    if ! diff -u "$name.txt" "$TMP/$name.txt" >&2; then
      echo "FAIL: $name.txt does not match $name.in; run scripts/lock-requirements.sh" >&2
      status=1
    fi
  done
  [ "$status" = 0 ] && echo "ok: lockfiles match their .in files"
  exit "$status"
fi

for name in "${LOCKS[@]}"; do
  compile "$name" . "$@"
  echo "locked $name.txt"
done
