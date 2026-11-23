#!/bin/bash
# CVE-2026-125396 — rung-5 lab chain over a loopback HTTP upload.
# A local service accepts attacker-controlled document+font bytes, saves them,
# and spawns the lab gs on the saved document under -dSAFER. Controls: fixed
# binary and unmodified font. Nothing binds off 127.0.0.1.
set -u
cd "$(dirname "$0")" || exit 99
ROOT="$(cd .. && pwd)"
LIVE="$ROOT/live"
E="$ROOT/harness/evidence"
DOC="$ROOT/exp/command-safer.ps"
VULN="$ROOT/harness/bin/gs-vuln"
FIXED="$ROOT/harness/bin/gs-fixed"
INJ="$ROOT/harness/font-injected.pfa"
SAFE="$ROOT/harness/font-safe.pfa"
PORT=18741
mkdir -p "$E" "$LIVE/r5-runs"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() { if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi; }
hasnt() { if grep -qF "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi; }

normalize() {
python3 - "$1" "$2" <<'PY'
import json, pathlib, sys
d = json.load(open(sys.argv[1]))
print("RC=" + str(d["rc"]))
for line in d["stdout"].splitlines():
    if line.startswith(("PATH_CONTROL", "PIPE_", "CLEAN_VALUE", "NO_STALE_REF")):
        print(line)
m = pathlib.Path(sys.argv[2])
print("MARKER=" + (m.read_text().strip() if m.exists() else "NONE"))
PY
}

run_case() {
  name="$1" gsbin="$2" font="$3" marker="$4"
  dir="$LIVE/r5-runs/$name"
  rm -rf "$dir"; mkdir -p "$dir"; rm -f "$marker"
  GS_BIN="$gsbin" R5_MARKER="$marker" R5_UPLOAD_ROOT="$dir" \
    python3 "$LIVE/r5_server.py" "$PORT" > "$dir/server.log" 2>&1 &
  spid=$!
  ready=0
  for i in $(seq 1 50); do
    if curl -sf --max-time 1 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.1
  done
  [ "$ready" -eq 1 ] || { echo "server-not-ready:$name"; kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null; return; }
  python3 "$LIVE/r5_request.py" "$PORT" "$DOC" "$font" > "$dir/response.json"
  kill "$spid" 2>/dev/null
  wait "$spid" 2>/dev/null
  normalize "$dir/response.json" "$marker" > "$E/r5-$name.norm"
  has "$dir/server.log" '"POST /upload HTTP/1.1" 200' "wire-$name-http-upload"
}

VULN_MARK=/tmp/r5-http-vuln-marker
FIXED_MARK=/tmp/r5-http-fixed-marker
SAFE_MARK=/tmp/r5-http-safe-marker
run_case vuln-injected "$VULN" "$INJ" "$VULN_MARK"
run_case fixed-injected "$FIXED" "$INJ" "$FIXED_MARK"
run_case vuln-safe "$VULN" "$SAFE" "$SAFE_MARK"

V="$E/r5-vuln-injected.norm"
has "$V" 'RC=0' 'r5-vuln-rc0'
has "$V" 'PATH_CONTROL_BYTES_BEFORE=1' 'r5-vuln-path-active-before'
has "$V" 'PATH_CONTROL_BYTES_AFTER=0' 'r5-vuln-path-control-cleared'
has "$V" 'PIPE_OPENED=true' 'r5-vuln-pipe-opened'
has "$V" 'PATH_CONTROL_BYTES_RESTORED=1' 'r5-vuln-state-restored'
has "$V" 'CLEAN_VALUE=12345' 'r5-vuln-aliased-slot-clean'
has "$V" 'MARKER=GS_R5_OK' 'r5-vuln-benign-command-side-effect'

F="$E/r5-fixed-injected.norm"
has "$F" 'NO_STALE_REF' 'r5-fixed-no-stale-ref'
has "$F" 'MARKER=NONE' 'r5-fixed-no-command'

S="$E/r5-vuln-safe.norm"
has "$S" 'NO_STALE_REF' 'r5-safe-font-no-stale-ref'
has "$S" 'MARKER=NONE' 'r5-safe-font-no-command'

TRACE_SHA256="$(cat "$E/r5-vuln-injected.norm" "$E/r5-fixed-injected.norm" "$E/r5-vuln-safe.norm" | sha256sum | cut -d' ' -f1)"
printf 'TRACE_SHA256=%s\n' "$TRACE_SHA256"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
