#!/usr/bin/env bash
# xrdp2shell — one-command clean-room replay of the real-library rung-3/rung-4
# evidence. Rebuilds the xrdp 0.10.6 ASan and plain libraries from a fresh copy
# of the pinned source tree, rebuilds the committed drivers, and re-runs every
# gate. No external probe; nothing contacts a network.
#
#   bash lab/xrdp2shell-real/verify_cleanroom.sh
#   XRDP_CLEANROOM_WORK=/tmp/other-work bash lab/xrdp2shell-real/verify_cleanroom.sh
#   XRDP_CLEANROOM_SRC=/path/to/xrdp/src bash lab/xrdp2shell-real/verify_cleanroom.sh
#
# Exit 0 iff every assertion passes. Source provisioning is separate: this
# script copies an existing source tree and records its git commit; it does
# not clone. The lab tree used for the recorded run is
# lab/build/xrdp2shell-live/src, git commit 440a538149561ec8e8e57552ab8f2e0e3f273cd5.
set -uo pipefail

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 2
REPO=$(cd "$HERE/../.." && pwd) || exit 2
WORK=${XRDP_CLEANROOM_WORK:-/tmp/xrdp2shell-cleanroom}
SRC_IN=${XRDP_CLEANROOM_SRC:-$REPO/lab/build/xrdp2shell-live/src}
[ -f "$SRC_IN/configure.ac" ] || { echo "FAIL no source at $SRC_IN" >&2; exit 2; }

OUT=$WORK/out
rm -rf "$WORK"
mkdir -p "$OUT" || exit 2
cp -a "$SRC_IN" "$WORK/src" || exit 2
SRC=$WORK/src
BASAN=$WORK/build-asan
BPLAIN=$WORK/build-plain

pass=0; fail=0
say() { printf '%s\n' "$*"; }
ck() { local name=$1 pat=$2 f=$3; if grep -aEq "$pat" "$f"; then say "PASS $name"; pass=$((pass+1)); else say "FAIL $name [/$pat/ in $f]"; fail=$((fail+1)); fi; }
ckabs() { local name=$1 pat=$2 f=$3; if ! grep -aEq "$pat" "$f"; then say "PASS $name"; pass=$((pass+1)); else say "FAIL $name [unexpected /$pat/ in $f]"; fail=$((fail+1)); fi; }
# UBSan hex dumps use unstable double spaces; normalise before matching.
ckhex() { local name=$1 pat=$2 f=$3; if tr -s ' ' <"$f" | grep -aEq "$pat"; then say "PASS $name"; pass=$((pass+1)); else say "FAIL $name [/$pat/ in $f]"; fail=$((fail+1)); fi; }

say "xrdp2shell clean-room replay $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "source commit: $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
say "source path:   $SRC_IN"
say "drivers:"
sha256sum "$HERE/real_drdynvc_driver.c" "$HERE/wire_drdynvc_driver.c" \
  "$HERE/chosen_bytes_real_path.c"
say

# ---- clean-room ASan build --------------------------------------------------
mkdir -p "$BASAN" && cd "$BASAN" || exit 2
../src/configure \
  'CFLAGS=-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined' \
  LDFLAGS=-fsanitize=address,undefined --prefix="$BASAN/install" \
  --enable-fuse=no --enable-vsock=no --enable-jpeg=no --enable-opus=no \
  --enable-mp3lame=no --enable-xrdpvr=no --enable-painter=no \
  --enable-rfxcodec=no --enable-freerdp1=no >"$OUT/asan-configure.log" 2>&1 \
  || { say "FAIL asan configure"; tail -20 "$OUT/asan-configure.log"; exit 2; }
make -j4 >"$OUT/asan-build.log" 2>&1 \
  || { say "FAIL asan make"; tail -20 "$OUT/asan-build.log"; exit 2; }
say "PASS clean-room ASan build"
pass=$((pass+1))
say "ASan libs:"
sha256sum "$BASAN/libxrdp/.libs/libxrdp.a" "$BASAN/common/.libs/libcommon.a"

cc -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
  -include config_ac.h -I"$BASAN" -I"$SRC/libxrdp" -I"$SRC/common" \
  -I"$SRC/include" "$HERE/real_drdynvc_driver.c" \
  "$BASAN/libxrdp/.libs/libxrdp.a" "$BASAN/common/.libs/libcommon.a" \
  -lssl -lcrypto -lpthread -ldl -lm -o "$OUT/real_driver" 2>"$OUT/cc-real.err" \
  || { say "FAIL compile real driver"; cat "$OUT/cc-real.err"; exit 2; }
cc -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$BASAN" -I"$SRC/libxrdp" -I"$SRC/common" -I"$SRC/include" \
  "$HERE/wire_drdynvc_driver.c" "$BASAN/libxrdp/.libs/libxrdp.a" \
  "$BASAN/common/.libs/libcommon.a" -lssl -lcrypto -lpthread -ldl -lm \
  -o "$OUT/wire_driver" 2>"$OUT/cc-wire.err" \
  || { say "FAIL compile wire driver"; cat "$OUT/cc-wire.err"; exit 2; }
say "PASS both ASan drivers compile clean"

run() { local tag=$1 bin=$2 p=$3 t=$4; ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
  "$OUT/$bin" "$p" "$t" >"$OUT/$tag.txt" 2>&1; echo "$tag rc=$?"; }
run real_8164 real_driver 8164 8164
run real_8165 real_driver 8165 8165
run real_20000 real_driver 20000 20000
run wire_8164 wire_driver 8164 8164
run wire_8191 wire_driver 8191 8191
run wire_20000 wire_driver 20000 20000
say

ck "real 8164 clean" 'callback_calls=1' "$OUT/real_8164.txt"
ckabs "real 8164 no ASan" 'AddressSanitizer|ERROR: Address' "$OUT/real_8164.txt"
ck "real 8165 OOB" 'WRITE of size 8165' "$OUT/real_8165.txt"
ck "real 20000 OOB" 'WRITE of size 20000' "$OUT/real_20000.txt"
ckhex "real 20000 chosen marker" '58 52 44 50 32 53 48 45 4c 4c 2d 43 48 4f 53 45 4e 2d 4d 41 52 4b 45 52' "$OUT/real_20000.txt"
ck "wire 8164 clean" 'callback_calls=1' "$OUT/wire_8164.txt"
ckabs "wire 8164 no ASan" 'AddressSanitizer|ERROR: Address' "$OUT/wire_8164.txt"
ck "wire 8191 OOB" 'WRITE of size 8191' "$OUT/wire_8191.txt"
ck "wire 8191 sink stack" 'drdynvc_process_data_first|xrdp_rdp_recv' "$OUT/wire_8191.txt"
ck "wire 20000 MCS reject" 'rv=1' "$OUT/wire_20000.txt"

# ---- clean-room plain build, chosen-byte reader ----------------------------
mkdir -p "$BPLAIN" && cd "$BPLAIN" || exit 2
../src/configure --prefix="$BPLAIN/install" --disable-fuse --disable-vsock \
  --disable-jpeg --disable-opus --disable-mp3lame --disable-xrdpvr \
  --disable-painter --disable-rfxcodec --disable-freerdp1 \
  'CFLAGS=-g -O1 -fno-omit-frame-pointer' LDFLAGS= >"$OUT/plain-configure.log" 2>&1 \
  || { say "FAIL plain configure"; tail -20 "$OUT/plain-configure.log"; exit 2; }
make -j4 >"$OUT/plain-build.log" 2>&1 \
  || { say "FAIL plain make"; tail -20 "$OUT/plain-build.log"; exit 2; }
say "PASS clean-room plain build"
pass=$((pass+1))
say "plain libs:"
sha256sum "$BPLAIN/libxrdp/.libs/libxrdp.a" "$BPLAIN/common/.libs/libcommon.a"

cc -g -O1 -fno-omit-frame-pointer -include config_ac.h -I"$BPLAIN" \
  -I"$SRC/libxrdp" -I"$SRC/common" -I"$SRC/include" \
  "$HERE/chosen_bytes_real_path.c" "$BPLAIN/libxrdp/.libs/libxrdp.a" \
  "$BPLAIN/common/.libs/libcommon.a" -lssl -lcrypto -lpthread -ldl -lm \
  -o "$OUT/chosen_reader" 2>"$OUT/cc-chosen.err" \
  || { say "FAIL compile chosen-byte reader"; cat "$OUT/cc-chosen.err"; exit 2; }
"$OUT/chosen_reader" >"$OUT/chosen.txt" 2>&1
say "chosen reader rc=$?"
cat "$OUT/chosen.txt"
say
ck "chosen canary offsets" 'CANARY delta=8208 k1=84 k2=484' "$OUT/chosen.txt"
ck "chosen markers readback" 'CHOSEN_BYTES m1=PASS m2=PASS' "$OUT/chosen.txt"
ck "chosen callback seen" 'callback_calls=1 bytes_seen=20000' "$OUT/chosen.txt"

say
say "TOTAL pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
