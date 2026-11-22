#!/bin/sh
# Build the EoE harness against both hash-pinned SOES releases.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$ROOT/build"
for V in 3.2.0 3.2.1; do
   SRC="$ROOT/src/SOES-$V"
   INC="-I$SRC -I$SRC/soes -I$SRC/soes/include/sys/gcc -I$SRC/applications/linux_lan9252demo"
   clang -g -O0 -fsanitize=address $INC \
      "$ROOT/harness/eoe_overflow.c" "$SRC/soes/esc_eoe.c" \
      -o "$ROOT/build/eoe_asan_$V"
   echo "built $ROOT/build/eoe_asan_$V"
   clang -g -O0 $INC \
      "$ROOT/harness/eoe_overflow.c" "$SRC/soes/esc_eoe.c" \
      -o "$ROOT/build/eoe_plain_$V"
   echo "built $ROOT/build/eoe_plain_$V"
done

# PDO-mapping size overflow harness (CVE-2026-129811): real sizeOfPDO +
# real RXPDO_update/COE_pdoUnpack against the pinned globals. Section GC
# drops unused stack functions whose HAL externs are intentionally absent.
for SPEC in "3.2.0:" "3.2.1:-DSOES_FIXED_VERSION"; do
   V=${SPEC%%:*}; DEFINE=${SPEC##*:}
   SRC="$ROOT/src/SOES-$V"
   INC="-I$SRC -I$SRC/soes -I$SRC/soes/include/sys/gcc -I$SRC/applications/linux_lan9252demo"
   clang -g -O0 -Wall -ffunction-sections -fdata-sections $DEFINE $INC \
      "$ROOT/harness/pdo_overflow.c" "$SRC/soes/esc_coe.c" \
      -Wl,--gc-sections -o "$ROOT/build/pdo_overflow_$V"
   clang -g -O0 -fsanitize=address -ffunction-sections -fdata-sections $DEFINE $INC \
      "$ROOT/harness/pdo_overflow.c" "$SRC/soes/esc_coe.c" \
      -Wl,--gc-sections -o "$ROOT/build/pdo_overflow_asan_$V"
   echo "built $ROOT/build/pdo_overflow_$V and pdo_overflow_asan_$V"
done

# CoE-mailbox path (soes2shell wake 2026-11-22): real ESC_coeprocess()/SDO
# download installs the mapping before sizeOfPDO/RXPDO_update run.
for SPEC in "3.2.0:" "3.2.1:-DSOES_FIXED_VERSION"; do
   V=${SPEC%%:*}; DEFINE=${SPEC##*:}
   SRC="$ROOT/src/SOES-$V"
   INC="-I$SRC -I$SRC/soes -I$SRC/soes/include/sys/gcc -I$SRC/applications/linux_lan9252demo"
   clang -g -O0 -Wall -ffunction-sections -fdata-sections $DEFINE $INC \
      "$ROOT/harness/coe_mailbox_overflow.c" "$SRC/soes/esc_coe.c" \
      -Wl,--gc-sections -o "$ROOT/build/coe_mailbox_$V"
   clang -g -O0 -fsanitize=address -ffunction-sections -fdata-sections $DEFINE $INC \
      "$ROOT/harness/coe_mailbox_overflow.c" "$SRC/soes/esc_coe.c" \
      -Wl,--gc-sections -o "$ROOT/build/coe_mailbox_asan_$V"
   echo "built $ROOT/build/coe_mailbox_$V and coe_mailbox_asan_$V"
done

# CVE-2026-129796 triage: real SDO_download() flexible-object writes through
# ESC_coeprocess(), with the hash-pinned 3.2.1 source as the fixed control.
for SPEC in "3.2.0:" "3.2.1:-DSOES_FIXED_VERSION"; do
   V=${SPEC%%:*}; DEFINE=${SPEC##*:}
   SRC="$ROOT/src/SOES-$V"
   INC="-I$SRC -I$SRC/soes -I$SRC/soes/include/sys/gcc -I$SRC/applications/linux_lan9252demo"
   clang -g -O0 -Wall -ffunction-sections -fdata-sections $DEFINE $INC \
      "$ROOT/harness/coe_download_overflow.c" "$SRC/soes/esc_coe.c" \
      -Wl,--gc-sections -o "$ROOT/build/coe_download_$V"
   clang -g -O0 -fsanitize=address -ffunction-sections -fdata-sections $DEFINE $INC \
      "$ROOT/harness/coe_download_overflow.c" "$SRC/soes/esc_coe.c" \
      -Wl,--gc-sections -o "$ROOT/build/coe_download_asan_$V"
   echo "built $ROOT/build/coe_download_$V and coe_download_asan_$V"
done

# CVE-2026-129798 triage: real segmented SDO-download writes through
# ESC_coeprocess(), with the hash-pinned 3.2.1 source as the fixed control.
for SPEC in "3.2.0:" "3.2.1:-DSOES_FIXED_VERSION"; do
   V=${SPEC%%:*}; DEFINE=${SPEC##*:}
   SRC="$ROOT/src/SOES-$V"
   INC="-I$SRC -I$SRC/soes -I$SRC/soes/include/sys/gcc -I$SRC/applications/linux_lan9252demo"
   clang -g -O0 -Wall -ffunction-sections -fdata-sections $DEFINE $INC \
      "$ROOT/harness/coe_segment_overflow.c" "$SRC/soes/esc_coe.c" \
      -Wl,--gc-sections -o "$ROOT/build/coe_segment_$V"
   clang -g -O0 -fsanitize=address -ffunction-sections -fdata-sections $DEFINE $INC \
      "$ROOT/harness/coe_segment_overflow.c" "$SRC/soes/esc_coe.c" \
      -Wl,--gc-sections -o "$ROOT/build/coe_segment_asan_$V"
   echo "built $ROOT/build/coe_segment_$V and coe_segment_asan_$V"
done

# CVE-2026-129814 triage: real SDO Information Get OD handler writes the name
# terminator one byte past the last mailbox slot in 3.2.0; pinned 3.2.1 control.
for SPEC in "3.2.0:" "3.2.1:-DSOES_FIXED_VERSION"; do
   V=${SPEC%%:*}; DEFINE=${SPEC##*:}
   SRC="$ROOT/src/SOES-$V"
   INC="-I$SRC -I$SRC/soes -I$SRC/soes/include/sys/gcc -I$SRC/applications/linux_lan9252demo"
   clang -g -O0 -Wall -ffunction-sections -fdata-sections $DEFINE $INC \
      "$ROOT/harness/coe_terminator_overflow.c" "$SRC/soes/esc_coe.c" \
      -Wl,--gc-sections -o "$ROOT/build/coe_terminator_$V"
   clang -g -O0 -fsanitize=address -ffunction-sections -fdata-sections $DEFINE $INC \
      "$ROOT/harness/coe_terminator_overflow.c" "$SRC/soes/esc_coe.c" \
      -Wl,--gc-sections -o "$ROOT/build/coe_terminator_asan_$V"
   echo "built $ROOT/build/coe_terminator_$V and coe_terminator_asan_$V"
done
