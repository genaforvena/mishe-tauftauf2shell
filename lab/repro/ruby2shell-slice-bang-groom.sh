#!/usr/bin/env bash
# W336: 4-build differential for groomed bytes disclosed by slice!.
# Stage 1: 24 arms (4 builds x 2 shapes x 3 sizes: 544/1064/8232 bytes).
# Stage 2: 4 arms (4 builds x nocoerce control at 544 bytes).
# Evidence is gitignored under lab/build/evidence/slice-bang-groom/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/slice-bang-groom
mkdir -p "$EVID"
: >"$EVID/matrix.txt"
: >"$EVID/control-matrix.txt"

run() { # build tag arm a b extra-env...
  local build="$1" tag="$2" arm="$3" a="$4" b="$5"; shift 5
  local rb
  case "$build" in
    *-plain) rb="lab/build/plain/${build%-plain}/ruby" ;;
    *) rb="lab/build/$build/bin/ruby" ;;
  esac
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  ASAN_OPTIONS=detect_leaks=0 W336_ARM="$arm" W336_A="$a" W336_B="$b" \
    timeout 15 "$rb" lab/repro/ruby2shell-slice-bang-groom.rb \
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
  for spec in bands:256:286 bands:512:551 bands:4096:4135 \
              uniform:256:286 uniform:512:551 uniform:4096:4135; do
    IFS=: read -r arm a b <<<"$spec"
    run "$build" "$build-$arm-$((a + b + 1))" "$arm" "$a" "$b" \
      >>"$EVID/matrix.txt"
  done
done
cat "$EVID/matrix.txt"

for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  run "$build" "$build-nocoerce" nocoerce 256 286 >>"$EVID/control-matrix.txt"
done
cat "$EVID/control-matrix.txt"
