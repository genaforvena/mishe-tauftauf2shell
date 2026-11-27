#!/usr/bin/env bash
# W334: 4-build differential for the rb_str_partition/rpartition tail bound.
# Stage 1: 24 arms (4 builds x 6 input shapes).
# Stage 2: 16 arms (4 builds x 4 receiver lengths, 2k+1 bytes).
# Evidence is gitignored under lab/build/evidence/partition-stale/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/partition-stale
mkdir -p "$EVID"
: >"$EVID/matrix.txt"
: >"$EVID/gen-matrix.txt"

run() { # build tag arm extra-env-vars...
  local build="$1" tag="$2" arm="$3"; shift 3
  local rb
  case "$build" in
    *-plain) rb="lab/build/plain/${build%-plain}/ruby" ;;
    *) rb="lab/build/$build/bin/ruby" ;;
  esac
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  ASAN_OPTIONS=detect_leaks=0 W334_ARM="$arm" "$@" timeout 15 "$rb" \
    lab/repro/ruby2shell-partition-stale.rb \
    >"$EVID/$tag.out" 2>"$EVID/$tag.err"
  local rc=$?
  local asan kind frame sizes result
  asan=$(grep -c 'ERROR: AddressSanitizer' "$EVID/$tag.err" || true)
  kind=$(grep -m1 -E 'ERROR: AddressSanitizer: [a-z-]+.*' "$EVID/$tag.err" || true)
  frame=$(grep -m1 -E 'rb_str_rpartition|str_subseq|rb_str_partition' "$EVID/$tag.err" || true)
  sizes=$(grep -m1 -o 'str=[0-9]* sep=[0-9]*' "$EVID/$tag.err" || true)
  result=$(grep -m1 '^\[' "$EVID/$tag.out" || true)
  printf '%s tag=%s arm=%s rc=%s asan=%s %s %s %s %s\n' \
    "$build" "$tag" "$arm" "$rc" "$asan" "$kind" "$frame" "$sizes" "${result:-NO_RESULT}" \
    | sed 's/  */ /g'
}

for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  for arm in rp_n1 rp_n2 rp_n4 p_n1 rp_to_str rp_ascii; do
    run "$build" "$build-$arm" "$arm" >>"$EVID/matrix.txt"
  done
done
cat "$EVID/matrix.txt"

for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  for k in 0 1 2 4; do
    run "$build" "$build-gen-k$k" rp_gen env W334_K="$k" >>"$EVID/gen-matrix.txt"
  done
done
cat "$EVID/gen-matrix.txt"
