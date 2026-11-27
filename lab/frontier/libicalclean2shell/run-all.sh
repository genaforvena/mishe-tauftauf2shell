#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
mkdir -p runs

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

while read -r hash rest; do
  if [ "${#hash}" -eq 64 ]; then
    [ -f "$rest" ] || { fail "missing pin $rest"; continue; }
    actual=$(sha256sum "$rest" | cut -d' ' -f1)
    [ "$actual" = "$hash" ] && pass "pin $rest" || fail "pin $rest"
  fi
done < pins/PIN_HASHES.txt

ensure_source() {
  dir=$1
  commit=$2
  if [ ! -f "$dir/src/libical/icalparser.c" ]; then
    git clone --quiet --single-branch --branch "$3" https://github.com/libical/libical.git "$dir"
  fi
  actual=$(git -C "$dir" rev-parse HEAD)
  [ "$actual" = "$commit" ] && pass "source $dir $commit" || fail "source $dir got $actual"
}

build_lib() {
  src=$1
  build=$2
  sanitizer=$3
  if [ ! -f "$build/lib/libical.a" ]; then
    cmake -S "$src" -B "$build" \
      -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_FLAGS="-O1 -g $sanitizer -fno-omit-frame-pointer" \
      -DLIBICAL_STATIC=ON -DLIBICAL_GLIB=OFF -DLIBICAL_GLIB_BUILD_DOCS=OFF \
      -DLIBICAL_GOBJECT_INTROSPECTION=OFF -DLIBICAL_JAVA_BINDINGS=OFF \
      -DLIBICAL_BUILD_TESTING=OFF -DLIBICAL_BUILD_EXAMPLES=OFF -DLIBICAL_BUILD_DOCS=OFF \
      > "runs/configure-$(basename "$build").log" 2>&1
    cmake --build "$build" --target ical -j2 \
      > "runs/build-$(basename "$build").log" 2>&1
  fi
  [ -f "$build/lib/libical.a" ] && pass "library $(basename "$build")" || fail "library $(basename "$build")"
}

ensure_source src-vuln 9cfca65c122fa23b9680a28e0c9225a2fd015fc5 v4.0.6
ensure_source src-fixed cb58c3cb287bee48aa50cc60753155116a8f9081 v4.0.7
build_lib src-vuln build-vuln-asan '-fsanitize=address,undefined'
build_lib src-fixed build-fixed-asan '-fsanitize=address,undefined'
build_lib src-vuln build-vuln-plain ''
build_lib src-fixed build-fixed-plain ''

ICU_LIBS=$(pkg-config --libs icu-i18n)
compile_repro() {
  version=$1
  build=$2
  output=$3
  sanitizer=$4
  clang -O1 -g $sanitizer -fno-omit-frame-pointer \
    -I"$build/src" -I"$build/src/libical" \
    -I"src-$version/src" -I"src-$version/src/libical" \
    "${5:-reproducer/05-uaf-clean-ownership.c}" "$build/lib/libical.a" \
    -lm -lpthread $ICU_LIBS -o "$output"
}

compile_repro vuln build-vuln-asan runs/vuln-asan '-fsanitize=address,undefined'
compile_repro fixed build-fixed-asan runs/fixed-asan '-fsanitize=address,undefined'
compile_repro vuln build-vuln-plain runs/vuln-plain ''
compile_repro vuln build-vuln-plain runs/rung4-vuln-plain '' rung4_reclaim.c
compile_repro fixed build-fixed-plain runs/rung4-fixed-plain '' rung4_reclaim.c

run_expect() {
  case_name=$1
  expected_rc=$2
  pattern=$3
  shift 3
  set +e
  env ASAN_OPTIONS=detect_leaks=1 "$@" > "runs/$case_name.out" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq "$expected_rc" ] && grep -Fq "$pattern" "runs/$case_name.out"; then
    pass "$case_name rc=$rc pattern=$pattern"
  else
    fail "$case_name rc=$rc expected=$expected_rc pattern=$pattern"
  fi
}

for version in vuln fixed; do
  for mode in clean-free-destroy clean-inspect-twice clean-free-twice two-sessions complete; do
    for shape in truncated unclosed-child; do
      case_name="$version-$mode-$shape"
      if [ "$version" = vuln ] && [ "$mode" != complete ]; then
        run_expect "$case_name" 1 "ERROR: AddressSanitizer: heap-use-after-free" \
          "./runs/$version-asan" "$mode" "$shape"
        if [ "$mode" = clean-inspect-twice ] || [ "$mode" = clean-free-twice ]; then
          if grep -Fq "second clean returned the same pointer: yes" "runs/$case_name.out"; then
            pass "$case_name stale pointer aliases first return"
          else
            fail "$case_name missing stale-pointer alias"
          fi
        fi
      elif [ "$mode" = complete ]; then
        run_expect "$case_name" 0 "mode=complete" "./runs/$version-asan" "$mode" "$shape"
      else
        run_expect "$case_name" 0 "mode=$mode shape=$shape" "./runs/$version-asan" "$mode" "$shape"
        if [ "$mode" = clean-inspect-twice ] && grep -Fq "second clean returned the same pointer: no" "runs/$case_name.out"; then
          pass "$case_name fixed parser clears ownership"
        fi
      fi
    done
  done
done

run_expect plain-vuln-clean-free-destroy 139 "first clean returned: non-NULL" \
  ./runs/vuln-plain clean-free-destroy truncated
run_expect plain-vuln-complete 0 "mode=complete" \
  ./runs/vuln-plain complete truncated

run_expect rung4-vuln-zero 139 "MODE=zero" ./runs/rung4-vuln-plain zero
run_expect rung4-vuln-chosen 0 "SURVIVED mode=chosen offset48_after=0x4141414141414141" \
  ./runs/rung4-vuln-plain chosen
run_expect rung4-fixed-zero 0 "SURVIVED mode=zero offset48_after=0000000000000000" \
  ./runs/rung4-fixed-plain zero
run_expect rung4-fixed-chosen 0 "SURVIVED mode=chosen offset48_after=0x4141414141414141" \
  ./runs/rung4-fixed-plain chosen
for case_name in rung4-vuln-zero rung4-vuln-chosen rung4-fixed-zero rung4-fixed-chosen; do
  if grep -Fq "REUSE=1" "runs/$case_name.out"; then
    pass "$case_name tcache reused freed component"
  else
    fail "$case_name did not reuse freed component"
  fi
done
run_expect rung4-vuln-chosen-gdb 0 "parent=0x4141414141414141" \
  gdb -q -batch -x observe.gdb --args ./runs/rung4-vuln-plain chosen

# Plain-build observations are recorded separately after the ASan matrix.
printf 'PASS=%s FAIL=%s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
