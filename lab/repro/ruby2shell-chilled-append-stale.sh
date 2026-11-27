#!/usr/bin/env bash
# W329: vulnerable 3.4.12 vs fixed 3.4.13 matrix for the chilled-string append
# stale-pointer lane, plus read-only gdb observation of the memcpy source.
# All traffic is local script execution; no network, marker or debugger write.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/chilled-append-stale
mkdir -p "$EVID"
: >"$EVID/matrix.txt"

for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  case "$build" in
    *-plain) rb="lab/build/plain/${build%-plain}/ruby" ;;
    *) rb="lab/build/$build/bin/ruby" ;;
  esac
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  for drive in append_str append_int join; do
    for recv in sym dup; do
      for action in none shrink replace reclaim enc; do
        tag="$build-$drive-$recv-$action"
        W329_ACTION="$action" W329_N=50 ASAN_OPTIONS=detect_leaks=0 \
          timeout 30 "$rb" lab/repro/ruby2shell-chilled-append-stale.rb "$drive" "$recv" \
          >"$EVID/$tag.out" 2>"$EVID/$tag.err"
        rc=$?
        asan=$(grep -c 'ERROR: AddressSanitizer' "$EVID/$tag.err" || true)
        result=$(grep '^RESULT ' "$EVID/$tag.out" | tail -1)
        line="$build $drive/$recv/$action rc=$rc asan=$asan ${result:-NO_RESULT}"
        echo "$line"
        echo "$line" >>"$EVID/matrix.txt"
      done
    done
  done
done

export W329_ACTION=reclaim W329_N=50
# Read-only gdb: at str_buf_cat4 entry the source is the pre-warning RHS
# buffer; at the memcpy line, after Warning.warn replaced the RHS, the same
# pointer is still used and its bytes are now allocator metadata.
: >"$EVID/gdb.txt"
gdb -q -batch -x lab/repro/ruby2shell-chilled-append-stale-gdb.cmd \
  --args lab/build/ruby-3.4.12/ruby \
  lab/repro/ruby2shell-chilled-append-stale.rb append_str sym reclaim \
  >>"$EVID/gdb.txt" 2>&1
gdb -q -batch -x lab/repro/ruby2shell-chilled-append-stale-fixed-gdb.cmd \
  --args lab/build/ruby-3.4.13/ruby \
  lab/repro/ruby2shell-chilled-append-stale.rb append_str sym reclaim \
  >>"$EVID/gdb.txt" 2>&1
grep -E 'cat4-entry|memcpy src|^0x[0-9a-f]+:|RESULT ' "$EVID/gdb.txt" || true
