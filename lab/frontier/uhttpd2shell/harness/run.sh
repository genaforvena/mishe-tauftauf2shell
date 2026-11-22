#!/bin/bash
# Reproducible ASan harness for GHSA-2mpg-6wp5-435p.
# Builds verbatim pinned uhttpd functions against pinned libubox; no sockets,
# no external systems.  Two full rounds are run and compared for determinism.
set -u
cd "$(dirname "$0")" || exit 1
H=$PWD; P=$H/pins; E=$H/evidence; B=$H/build
mkdir -p "$E" "$B"
CC=${CC:-gcc}
CFLAGS="-O0 -g -std=gnu99 -I$H -I$P -Wno-unused-variable"
ASAN_FLAGS="-fsanitize=address -fno-omit-frame-pointer"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:print_summary=1
pass=0; fail=0

check() {
  local name=$1 ok=$2 detail=$3
  if [ "$ok" = 1 ]; then
    printf 'PASS %s %s\n' "$name" "$detail"
    pass=$((pass+1))
  else
    printf 'FAIL %s %s\n' "$name" "$detail"
    fail=$((fail+1))
  fi
}

# assert_case NAME OUTFILE WANT_RC [PATTERN ...]
# Patterns beginning with '!' must NOT be present in the captured output.
assert_case() {
  local name=$1 out=$2 want_rc=$3; shift 3
  local ok=1 pat
  for pat in "$@"; do
    case "$pat" in
      '!'*) if grep -qF -- "${pat#\!}" "$out"; then ok=0; fi ;;
      *)    if ! grep -qF -- "$pat" "$out"; then ok=0; fi ;;
    esac
  done
  [ "$rc" -eq "$want_rc" ] || ok=0
  local detail="rc=$rc"
  if [ "$ok" = 1 ]; then
    printf 'PASS %s %s\n' "$name" "$detail" >> "$ROUND_PASS"
    pass=$((pass+1))
  else
    printf 'FAIL %s %s\n' "$name" "$detail"
    fail=$((fail+1))
  fi
}

note_pass() {
  printf 'PASS %s %s\n' "$1" "$2" >> "$ROUND_PASS"
  pass=$((pass+1))
}


# ---- regenerate the verbatim includes and build --------------------------
for pin in vuln fixed; do
  python3 "$H/gen.py" "$pin" >/dev/null || exit 1
done

build_one() {
  local bin=$1 pin=$2 mode=$3 asan=$4
  python3 "$H/gen.py" "$pin" >/dev/null || return 1
  local defs="-DPIN_FN=${pin}_uh_ubus_send_request"
  [ "$pin" = vuln ] && defs="$defs -DPIN_NAME_VULN"
  local extra=""
  [ "$mode" = model ] && extra="$extra -DMODEL"
  [ "$asan" = asan ] && extra="$extra -DMODEL_ASAN $ASAN_FLAGS"
  if [ "$mode" = model ]; then
    # Rename only the real definition (separate TU) so the shim in
    # harness.c keeps the public name blobmsg_add_field.
    local obj="$B/blobmsg-model${asan:+-asan}.o"
    local oflags="$CFLAGS"
    [ "$asan" = asan ] && oflags="$oflags $ASAN_FLAGS"
    $CC $oflags -c -Dblobmsg_add_field=real_blobmsg_add_field_unused \
      "$P/blobmsg.c" -o "$obj" || return 1
    $CC $CFLAGS $extra $defs -o "$bin" "$H/harness.c" "$P/blob.c" "$obj" || return 1
  else
    $CC $CFLAGS $extra $defs \
      -o "$bin" "$H/harness.c" "$P/blob.c" "$P/blobmsg.c" || return 1
  fi
}

build_one "$B/real-vuln-asan" vuln real asan || exit 1
build_one "$B/real-fixed-asan" fixed real asan || exit 1
build_one "$B/model-vuln-asan" vuln model asan || exit 1
build_one "$B/model-fixed-asan" fixed model asan || exit 1
build_one "$B/model-vuln-plain" vuln model plain || exit 1
build_one "$B/model-fixed-plain" fixed model plain || exit 1

# Optional clang coverage: compile both pinned functions with the ASan flags.
if command -v clang >/dev/null 2>&1; then
  for pin in vuln fixed; do
    python3 "$H/gen.py" "$pin" >/dev/null || exit 1
    local_extra=""
    [ "$pin" = vuln ] && local_extra="-DPIN_NAME_VULN"
    clang $CFLAGS $ASAN_FLAGS -DPIN_FN=${pin}_uh_ubus_send_request $local_extra \
      -o "$B/clang-real-${pin}-asan" \
      "$H/harness.c" "$P/blob.c" "$P/blobmsg.c" || exit 1
  done
  CLANG_OK=1
else
  CLANG_OK=0
fi

# ---- case runner ---------------------------------------------------------

run_round() {
  local round=$1
  ROUND_PASS="$E/round${round}-pass.txt"
  local CHOSEN="$E/round${round}-chosen-hashes.txt"
  : > "$ROUND_PASS"; : > "$CHOSEN"
  local name bin casename want out line h

  run_case() {
    name=$1; bin=$2; casename=$3; want=$4; shift 4
    out="$E/raw-r${round}-${name}.txt"
    "$bin" "$casename" > "$out" 2>&1
    rc=$?
    assert_case "$name" "$out" "$want" "$@"
  }

  # Pin provenance check: fresh `git show` + rename, compared byte-for-byte.
  for pin in vuln fixed; do
    out="$E/verify-${pin}-r${round}.txt"
    if python3 "$H/gen.py" "$pin" --verify > "$out" 2>&1; then
      note_pass "pin-sha-${pin}" "sha256=$(sed -n 's/.*sha256=\([0-9a-f]*\).*/\1/p' "$out")"
    else
      printf 'FAIL pin-sha-%s see %s\n' "$pin" "$out"
      fail=$((fail+1))
    fi
  done
  if (cd "$P" && sha256sum -c PIN_HASHES.txt > "$E/hash-check-r${round}.txt" 2>&1); then
    note_pass pin-hash-files "sha256sum -c OK"
  else
    printf 'FAIL pin-hash-files see %s\n' "$E/hash-check-r${round}.txt"
    fail=$((fail+1))
  fi

  # REAL libubox: ASan observes the OOB strcmp read, 2 bytes past malloc(20).
  run_case real-vuln-asan "$B/real-vuln-asan" real-vuln-asan 1 \
    'ERROR: AddressSanitizer: heap-buffer-overflow' 'READ of size' \
    '2 bytes after 20-byte region' 'strcmp' 'uh_ubus_send_request'

  # REAL libubox, fixed pin: rejected before the loop, no ASan, no invoke.
  run_case real-fixed-asan "$B/real-fixed-asan" real-fixed-asan 0 \
    'CASE=real-fixed-asan' 'ERROR=3' 'INVOKED=0' 'COMPLETED=0' \
    '!ERROR: AddressSanitizer'

  # MODEL ASan: the 16-byte modeled copy into an exact 8-byte destination.
  run_case model-vuln-41-asan "$B/model-vuln-asan" model-vuln-41-asan 1 \
    'ERROR: AddressSanitizer: heap-buffer-overflow' 'WRITE of size 16' \
    'uh_ubus_send_request' 'WRITE_LEN=4294967293' 'WRITE_OFF=20'

  # MODEL fixed pin: shim never called.
  run_case model-fixed-41-asan "$B/model-fixed-asan" model-fixed-41-asan 0 \
    'CASE=model-fixed-41-asan' 'ERROR=3' 'INVOKED=0' 'SHIM_CALLS=0' \
    '!WRITE_LEN=' '!ERROR: AddressSanitizer'

  # MODEL plain builds: chosen-byte readback, 16 bytes from attacker filler.
  local sixteen41=$(printf '41%.0s' $(seq 1 16))
  local sixteen5a=$(printf '5a%.0s' $(seq 1 16))
  run_case model-vuln-41-plain "$B/model-vuln-plain" model-vuln-41-plain 0 \
    "WRITE_OFF=20 WRITE_LEN=4294967293 BYTES=$sixteen41" \
    'CASE=model-vuln-41-plain'
  line=$(grep -m1 -F 'MODEL_RESULT' "$out" || true)
  h=$(printf '%s\n' "$line" | sha256sum | cut -d' ' -f1)
  printf '%s %s\n' model-vuln-41-plain "$h" >> "$CHOSEN"

  run_case model-vuln-5a-plain "$B/model-vuln-plain" model-vuln-5a-plain 0 \
    "WRITE_OFF=20 WRITE_LEN=4294967293 BYTES=$sixteen5a" \
    'CASE=model-vuln-5a-plain'
  line=$(grep -m1 -F 'MODEL_RESULT' "$out" || true)
  h=$(printf '%s\n' "$line" | sha256sum | cut -d' ' -f1)
  printf '%s %s\n' model-vuln-5a-plain "$h" >> "$CHOSEN"

  run_case model-fixed-5a-plain "$B/model-fixed-plain" model-fixed-5a-plain 0 \
    'CASE=model-fixed-5a-plain' 'ERROR=3' 'SHIM_CALLS=0' '!WRITE_LEN='

  # SAFE control: a well-formed TABLE params; no giant write on either pin.
  run_case safe-vuln-asan "$B/model-vuln-asan" model-vuln-safe-asan 0 \
    'CASE=model-vuln-safe-asan' 'WRITE_LEN=4' \
    '!WRITE_LEN=4294967293' '!ERROR: AddressSanitizer'
  run_case safe-fixed-asan "$B/model-fixed-asan" model-fixed-safe-asan 0 \
    'CASE=model-fixed-safe-asan' 'WRITE_LEN=4' \
    '!WRITE_LEN=4294967293' '!ERROR: AddressSanitizer'

  # Optional clang smoke: both pins on the exact 20-byte crafted blob.
  if [ "$CLANG_OK" = 1 ]; then
    out="$E/raw-r${round}-clang-real-vuln.txt"
    "$B/clang-real-vuln-asan" real-vuln-asan > "$out" 2>&1
    rc=$?
    assert_case clang-real-vuln-asan "$out" 1 \
      'ERROR: AddressSanitizer: heap-buffer-overflow' 'READ of size' \
      '2 bytes after 20-byte region' 'strcmp' 'uh_ubus_send_request'
  fi
  if [ "$CLANG_OK" = 1 ]; then
    out="$E/raw-r${round}-clang-real-fixed.txt"
    "$B/clang-real-fixed-asan" real-fixed-asan > "$out" 2>&1
    rc=$?
    assert_case clang-build-asan "$out" 0 \
      'CASE=real-fixed-asan' 'ERROR=3' 'INVOKED=0' '!ERROR: AddressSanitizer'
  fi
}

run_round 1
run_round 2
# Report one deterministic set of PASS lines (the final round).
cat "$E/round2-pass.txt"

# Determinism: normalized PASS lines (no pids/addresses in them) and the
# hashes of the chosen-byte lines must be identical across the two rounds.
if diff -u "$E/round1-pass.txt" "$E/round2-pass.txt" > "$E/determinism-pass.diff" 2>&1; then
  check deterministic-pass-lines 1 "identical across 2 rounds"
else
  check deterministic-pass-lines 0 "see $E/determinism-pass.diff"
fi
if diff -u "$E/round1-chosen-hashes.txt" "$E/round2-chosen-hashes.txt" > "$E/determinism-chosen.diff" 2>&1; then
  check deterministic-chosen-hashes 1 "identical across 2 rounds"
else
  check deterministic-chosen-hashes 0 "see $E/determinism-chosen.diff"
fi

# Stable raw-output aliases for the second (final) round.
for f in "$E"/raw-r2-*.txt; do
  cp "$f" "$E/$(basename "$f" | sed 's/^raw-r2-//')"
done

printf 'TOTAL pass=%d fail=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
