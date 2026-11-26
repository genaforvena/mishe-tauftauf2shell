#!/usr/bin/env bash
# ActiveSupport::Inflector as a real Rails consumer of the Onigmo case-fold
# OOB read.  Affected 3.4.12 ASan reports a READ of size 1 at regexec.c:4278
# for pluralize("ßs") / singularize("ßs", "ẞs", "statusß"); fixed 3.4.13 is
# clean for every case.  ASCII controls are clean on both builds.
# Evidence is gitignored under lab/build/evidence/casefold-inflector/.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
EVID=lab/build/evidence/casefold-inflector
mkdir -p "$EVID"
SCRIPT=lab/repro/ruby2shell-casefold-inflector.rb
for ver in 12 13; do
  bin="lab/build/ruby-3.4.${ver}-asan/bin/ruby"
  gemdir="lab/build/plain/ruby-3.4.${ver}-plain/lib/ruby/gems/3.4.0"
  [ -x "$bin" ] || { echo "missing $bin"; continue; }
  for method in pluralize singularize camelize titleize; do
    for word in 'ß' 'sß' 'ßs' 'ẞs' 'İs' 's' 'ss' 'statusß'; do
      hex=$(printf '%s' "$word" | od -An -tx1 | tr -d ' \n')
      out="$EVID/3.4.${ver}-${method}-${hex}.out"
      GEM_HOME="$gemdir" GEM_PATH="$gemdir" \
        UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=0 \
        ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
        timeout 20 "$bin" "$SCRIPT" "$method" "$word" >"$out" 2>&1
      rc=$?
      hit=$(grep -c 'ERROR: AddressSanitizer' "$out" || true)
      printf '3.4.%s %-12s %-10s rc=%s asan=%s %s\n' \
        "$ver" "$method" "$word" "$rc" "$hit" "$out"
    done
  done
done
