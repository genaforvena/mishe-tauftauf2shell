#!/usr/bin/env bash
# W333 second stage: whole-receiver backref (start=0), exercising the
# beg==0/vlen==0 early rb_str_drop_bytes path and equal-length shrinks on
# 4 builds. Local script execution only: no network, no debugger write.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/backref-coercion
mkdir -p "$EVID"
: >"$EVID/whole-matrix.txt"
for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  case "$build" in
    *-plain) rb="lab/build/plain/${build%-plain}/ruby" ;;
    *) rb="lab/build/$build/bin/ruby" ;;
  esac
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  for mut in none shrink shrink1; do
    for enc in binary utf8; do
      full=296; [ "$enc" = utf8 ] && full=592
      for vlen in 0 1 "$full"; do
        tag="$build-whole-$mut-$enc-v$vlen"
        W333_WHOLE=1 W333_MUT="$mut" W333_CAP=0 W333_VLEN="$vlen" W333_ENC="$enc" \
          ASAN_OPTIONS=detect_leaks=0 timeout 15 "$rb" \
          lab/repro/ruby2shell-backref-coercion.rb \
          >"$EVID/$tag.out" 2>"$EVID/$tag.err"
        rc=$?
        asan=$(grep -c 'ERROR: AddressSanitizer' "$EVID/$tag.err" || true)
        kind=$(grep -m1 -E 'ERROR: AddressSanitizer: [a-z-]+' "$EVID/$tag.err" || true)
        frame=$(grep -m1 -E 'rb_str_update|str_mod_check|rb_str_subpat_set|memmove' "$EVID/$tag.err" || true)
        result=$(grep '^RESULT ' "$EVID/$tag.out" | tail -1)
        echo "$build whole=1 mut=$mut enc=$enc v=$vlen rc=$rc asan=$asan ${kind} ${frame} ${result:-NO_RESULT}" \
          | sed 's/  */ /g' >>"$EVID/whole-matrix.txt"
      done
    done
  done
done
cat "$EVID/whole-matrix.txt"
