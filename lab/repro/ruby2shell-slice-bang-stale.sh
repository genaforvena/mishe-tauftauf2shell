#!/usr/bin/env bash
# W335: 4-build differential for the rb_str_slice_bang stale-backref guard.
# Stage 1: 28 arms (4 builds x 7 input shapes).
# Stage 2: 20 arms (4 builds x 5 post-coercion receiver lengths).
# Stage 3: 12 arms (4 builds x 3 receiver lengths: 1 KiB, 8 KiB, 64 KiB).
# Evidence is gitignored under lab/build/evidence/slice-bang-stale/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/slice-bang-stale
mkdir -p "$EVID"
: >"$EVID/matrix.txt"
: >"$EVID/gen-matrix.txt"
: >"$EVID/large-matrix.txt"

run() { # build tag arm extra-env-vars...
  local build="$1" tag="$2" arm="$3"; shift 3
  local rb
  case "$build" in
    *-plain) rb="lab/build/plain/${build%-plain}/ruby" ;;
    *) rb="lab/build/$build/bin/ruby" ;;
  esac
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  ASAN_OPTIONS=detect_leaks=0 W335_ARM="$arm" "$@" timeout 15 "$rb" \
    lab/repro/ruby2shell-slice-bang-stale.rb \
    >"$EVID/$tag.out" 2>"$EVID/$tag.err"
  local rc=$?
  local asan kind frame result
  asan=$(grep -c 'ERROR: AddressSanitizer' "$EVID/$tag.err" || true)
  kind=$(grep -m1 -E 'ERROR: AddressSanitizer: [a-z-]+.*' "$EVID/$tag.err" || true)
  frame=$(grep -m1 -E 'rb_str_slice_bang|rb_str_new|memcpy|TERM_FILL' "$EVID/$tag.err" || true)
  result=$(grep -m1 '^RESULT' "$EVID/$tag.out" || true)
  printf '%s tag=%s arm=%s rc=%s asan=%s %s %s %s\n' \
    "$build" "$tag" "$arm" "$rc" "$asan" "$kind" "$frame" "${result:-NO_RESULT}" \
    | sed 's/  */ /g'
}

for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  for arm in whole off off1 none grow reclaim plain; do
    if [ "$arm" = off1 ]; then
      run "$build" "$build-$arm" "$arm" env W335_SHRINK=287 >>"$EVID/matrix.txt"
    else
      run "$build" "$build-$arm" "$arm" >>"$EVID/matrix.txt"
    fi
  done
done
cat "$EVID/matrix.txt"

for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  for shrink in 1 8 128 510 512; do
    run "$build" "$build-whole-s$shrink" whole env W335_SHRINK="$shrink" \
      >>"$EVID/gen-matrix.txt"
  done
done
cat "$EVID/gen-matrix.txt"

for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  for n in 1024 8192 65536; do
    run "$build" "$build-whole-L$n" whole env W335_MATCH="$n" W335_TAIL=8 \
      >>"$EVID/large-matrix.txt"
  done
done
cat "$EVID/large-matrix.txt"
