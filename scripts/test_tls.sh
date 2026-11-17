#!/usr/bin/env bash
set -euo pipefail

test_dir="$(mktemp -d)"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$test_dir"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" -keyout "$test_dir/key.pem" -out "$test_dir/cert.pem" >/dev/null 2>&1
printf '%s' '0123456789abcdef0123456789abcdef' > "$test_dir/token"

env CIPHERNOTE_TRANSPORT=http CIPHERNOTE_HOST=127.0.0.1 CIPHERNOTE_PORT=18443 CIPHERNOTE_AUTH_TOKEN_FILE="$test_dir/token" CIPHERNOTE_TLS_CERT="$test_dir/cert.pem" CIPHERNOTE_TLS_KEY="$test_dir/key.pem" node src/server.js >"$test_dir/server.log" 2>&1 &
server_pid="$!"

for _ in {1..30}; do
  if curl --silent --insecure --fail https://127.0.0.1:18443/healthz >/dev/null; then
    status="$(curl --silent --insecure --output /dev/null --write-out '%{http_code}' --request POST https://127.0.0.1:18443/mcp)"
    test "$status" = "401"
    exit 0
  fi
  sleep 0.2
done

cat "$test_dir/server.log" >&2
exit 1
