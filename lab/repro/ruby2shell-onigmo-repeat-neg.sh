#!/bin/sh
# W303: gated gdb watch of wrapped repeat IDs -1..-16 on one fresh stock Rails
# worker per trial. Labeled conditions: pinned 3.4.11 plain build, shallow
# layout, ASLR off by default, stock notes route; the notimeout shim is a
# gdb-timing diagnostic only, never part of a wire-only claim.
# Usage: sh lab/repro/ruby2shell-onigmo-repeat-neg.sh "8 4 16" [stack_pad] [first_port]
set -eu
cd "$(dirname "$0")/../.."
ids=${1:-"8 4 16"}
stack_pad=${2:-0}
port0=${3:-4991}
export RUBY2SHELL_ONIGMO_GEM_PATH=lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0
export RUBY2SHELL_ONIGMO_LAYOUT=shallow
export RUBY2SHELL_ONIGMO_STACK_PAD="$stack_pad"
export RUBY2SHELL_ONIGMO_ASLR_OFF=1
export RAILS_MAX_THREADS=1
export RUBY2SHELL_ONIGMO_GDB_RUBY=lab/build/plain/ruby-3.4.11-plain/bin/ruby
export RUBY2SHELL_ONIGMO_RUBY=lab/repro/ruby2shell-onigmo-gdbwrap.sh
export RUBY2SHELL_ONIGMO_GDB_SCRIPT=lab/repro/ruby2shell-onigmo-watch-neg.gdb
export RUBY2SHELL_ONIGMO_NOTIMEOUT_RB="$PWD/lab/repro/ruby2shell-onigmo-notimeout.rb"
export RUBY2SHELL_ONIGMO_TIMEOUT=60
EV=lab/build/evidence
mkdir -p "$EV"
summary="$EV/w303-summary-p${stack_pad}.txt"
: > "$summary"

i=0
for k in $ids; do
  i=$((i + 1))
  # Recorded mapping: ID = units + 2 (mod 65536); units=65533 gave ID -1.
  units=$((65534 - k))
  tag=w303-n${k}-p${stack_pad}
  port=$((port0 + i))
  export RUBY2SHELL_ONIGMO_UNITS="$units"
  export RUBY2SHELL_ONIGMO_PORT="$port"
  echo "=== $tag id=-$k units=$units port=$port $(date -u +%H:%M:%SZ)" | tee -a "$summary"
  timeout 200 python3 lab/repro/ruby2shell-onigmo-repeat-wire.py attack "$tag" \
    > "$EV/$tag.driver.out" 2>&1 || true
  python3 - "$EV/$tag.json" "$EV/$tag.server.log" "$tag" >> "$summary" <<'PY'
import json, re, sys
jpath, lpath, tag = sys.argv[1:]
try:
    d = json.load(open(jpath))
except OSError:
    print(tag, "NO_JSON")
    raise SystemExit
print(tag, "ready", d.get("ready"), "first", d.get("http_status"), d.get("response_bytes"),
      "health", d.get("health"), "secs", d.get("request_seconds"),
      "err", d.get("request_error"), "exit", d.get("exit_after_request"))
text = open(lpath, errors="replace").read()
lines = [line for line in text.splitlines() if "ONIG_NEG " in line]
print(tag, "neg_lines", len(lines), "writes", sum("ONIG_NEG BEFORE" in l or "ONIG_NEG AFTER" in l for l in lines),
      "watches", sum("ONIG_NEG WATCH" in l for l in lines),
      "reads", sum("ONIG_NEG READ " in l for l in lines),
      "signals", sum("ONIG_NEG SIGNAL" in l for l in lines))
for line in lines:
    if re.search(r"ARM|SECOND_MARK|SIGNAL|LAST_WRITE|SI_ADDR|WATCH|READ", line):
        print(tag, line[:500])
for line in lines[:6]:
    print(tag, "sample", line[:400])
PY
  tail -5 "$summary"
done
