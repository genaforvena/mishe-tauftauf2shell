#!/usr/bin/env bash
# Steering check for the GHSA-7x2q stale-BBuf free on stock glibc.
# Expected on 3.4.12 plain: SIGSEGV (or "free(): invalid pointer") whose fault
# address varies between runs with identical input; 3.4.13 plain: RegexpError,
# rc=0. Five runs per tail and per allocator mode keep a layout flake from
# being read as steering. Gitignored evidence under lab/build/evidence/uaf-steer.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
EVID=lab/build/evidence/uaf-steer
mkdir -p "$EVID"
exec 2>>"$EVID/shell-notices.log"
RB12=lab/build/plain/ruby-3.4.12-plain/bin/ruby
RB13=lab/build/plain/ruby-3.4.13-plain/bin/ruby
SCRIPT=lab/repro/ruby2shell-uaf-steer.rb
for tail in x y z; do
  for mode in default tcache0; do
    lowbits=""
    for i in 1 2 3 4 5; do
      out="$EVID/3.4.12-$tail-$mode-$i.out"
      if [ "$mode" = tcache0 ]; then
        if ( GLIBC_TUNABLES=glibc.malloc.tcache_count=0 timeout 30 \
          "$RB12" "$SCRIPT" "$tail" >"$out" 2>&1 ); then rc=0; else rc=$?; fi
      else
        if ( timeout 30 "$RB12" "$SCRIPT" "$tail" >"$out" 2>&1 ); then rc=0; else rc=$?; fi
      fi
      addr=$(grep -m1 -o 'Segmentation fault at 0x[0-9a-fA-F]*' "$out" | tail -c 4)
      marker=$(grep -m1 -oE 'REGEXPERROR|NOERROR|free\(\): invalid pointer|Segmentation fault' "$out")
      echo "3.4.12 tail=$tail mode=$mode run=$i rc=$rc marker=${marker:-none} low12=${addr:-none}"
      [ -n "$addr" ] && lowbits="$lowbits $addr"
    done
    distinct=$(printf '%s\n' $lowbits | sort -u | wc -l)
    echo "SUMMARY 3.4.12 tail=$tail mode=$mode distinct_low12=$distinct/5"
  done
  out="$EVID/3.4.13-$tail.out"
  timeout 30 "$RB13" "$SCRIPT" "$tail" >"$out" 2>&1
  echo "3.4.13 tail=$tail rc=$? $(head -1 "$out")"
done
