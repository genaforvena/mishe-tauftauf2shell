#!/bin/sh
# W302: gated gdb watch of the W300 fault case, one fresh stock Rails worker
# per trial. Labeled conditions: pinned 3.4.11 plain build, threads=2, shallow
# layout, ASLR off; the notimeout shim is a gdb-timing diagnostic only.
# Usage: sh lab/repro/ruby2shell-onigmo-repeat-fault.sh [N] [first-port]
set -eu
cd "$(dirname "$0")/../.."
n=${1:-6}
port0=${2:-4961}
export RUBY2SHELL_ONIGMO_GEM_PATH=lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0
export RUBY2SHELL_ONIGMO_LAYOUT=shallow
export RUBY2SHELL_ONIGMO_ASLR_OFF=1
export RAILS_MAX_THREADS=2
export RUBY2SHELL_ONIGMO_SECOND=1
export RUBY2SHELL_ONIGMO_SECOND_REFLECT=1
export RUBY2SHELL_ONIGMO_SECOND_UNITS=32767
export RUBY2SHELL_ONIGMO_GDB_RUBY=lab/build/plain/ruby-3.4.11-plain/bin/ruby
export RUBY2SHELL_ONIGMO_RUBY=lab/repro/ruby2shell-onigmo-gdbwrap.sh
export RUBY2SHELL_ONIGMO_GDB_SCRIPT=lab/repro/ruby2shell-onigmo-watch-fault.gdb
export RUBY2SHELL_ONIGMO_NOTIMEOUT_RB="$PWD/lab/repro/ruby2shell-onigmo-notimeout.rb"
export RUBY2SHELL_ONIGMO_TIMEOUT=120
EV=lab/build/evidence
mkdir -p "$EV"
summary="$EV/w302-summary.txt"
: > "$summary"

i=1
while [ "$i" -le "$n" ]; do
  tag=w302-f$i
  port=$((port0 + i))
  rm -f "$EV/$tag.second.sent"
  export RUBY2SHELL_ONIGMO_SECOND_MARKER="$PWD/$EV/$tag.second.sent"
  export RUBY2SHELL_ONIGMO_PORT="$port"
  echo "=== $tag port=$port $(date -u +%H:%M:%SZ)" | tee -a "$summary"
  timeout 400 python3 lab/repro/ruby2shell-onigmo-repeat-wire.py attack "$tag" \
    > "$EV/$tag.driver.out" 2>&1 || true
  python3 - "$EV/$tag.json" "$EV/$tag.server.log" "$tag" >> "$summary" <<'PY'
import json, sys, re
jpath, lpath, tag = sys.argv[1:]
try:
    d = json.load(open(jpath))
except OSError:
    print(tag, "NO_JSON")
    raise SystemExit
print(tag, "ready", d.get("ready"), "first", d.get("http_status"), d.get("response_bytes"),
      "second", d.get("second_http_status"), d.get("second_response_bytes"),
      "health", d.get("health"), "exit", d.get("exit_after_request"),
      "err", d.get("request_error"), "secs", d.get("request_seconds"))
text = open(lpath, errors="replace").read()
print(tag, "writes", text.count("ONIG_FAULT BEFORE"),
      "marks", text.count("ONIG_FAULT SECOND_MARK"),
      "signals", text.count("ONIG_FAULT SIGNAL"))
for line in text.splitlines():
    if re.search(r"ONIG_FAULT (ARM|SECOND_MARK|SIGNAL|SI_ADDR|LAST_WRITE|SI_REGS|SI_BT)", line):
        print(tag, line[:400])
PY
  tail -3 "$summary"
  i=$((i + 1))
done
