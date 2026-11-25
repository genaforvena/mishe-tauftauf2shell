#!/bin/sh
# Real-source MCUboot decrypt experiment. No source file inside
# decrypt_region_inplace() or boot_enc_decrypt() is edited.
set -eu
cd "$(dirname "$0")"
UP=../upstream-parent
mkdir -p evidence

DEFS="-D__BOOTSIM__ -DMCUBOOT_HAVE_ASSERT_H -DMCUBOOT_USE_FLASH_AREA_GET_SECTORS -DMCUBOOT_MAX_IMG_SECTORS=128 -DMCUBOOT_BOOT_MAX_ALIGN=8 -DMCUBOOT_IMAGE_NUMBER=1 -DMCUBOOT_ENC_IMAGES -DMCUBOOT_ENCRYPT_KW -DMCUBOOT_USE_TINYCRYPT -DMCUBOOT_ENC_BUILTIN_KEY -DMCUBOOT_FIH_PROFILE_OFF"
INCS="-I $UP/sim/mcuboot-sys/csupport -I $UP/boot/bootutil/include -I $UP/boot/bootutil/src -I $UP/ext/tinycrypt/lib/include"

# Compile the real decryptor separately: the rename macro must not touch the
# interposing wrapper in real-harness.c.
# shellcheck disable=SC2086
gcc -c -O1 -g $DEFS $INCS -Dboot_enc_decrypt=real_boot_enc_decrypt \
    -o encrypted-real.o "$UP/boot/bootutil/src/encrypted.c" 2>evidence/encrypted-build.err || {
        cat evidence/encrypted-build.err; exit 1;
    }
# shellcheck disable=SC2086
gcc -c -O1 -g -fsanitize=address $DEFS $INCS -Dboot_enc_decrypt=real_boot_enc_decrypt \
    -o encrypted-real-asan.o "$UP/boot/bootutil/src/encrypted.c" 2>evidence/encrypted-asan-build.err || {
        cat evidence/encrypted-asan-build.err; exit 1;
    }

# shellcheck disable=SC2086
gcc -O1 -g -fno-stack-protector $DEFS $INCS -o real-plain real-harness.c \
    encrypted-real.o \
    "$UP/ext/tinycrypt/lib/source/aes_encrypt.c" \
    "$UP/ext/tinycrypt/lib/source/aes_decrypt.c" \
    "$UP/ext/tinycrypt/lib/source/utils.c" \
    "$UP/ext/tinycrypt/lib/source/ctr_mode.c" 2>evidence/plain-build.err || {
        cat evidence/plain-build.err; exit 1;
    }

# shellcheck disable=SC2086
gcc -O1 -g -fsanitize=address -DASAN_BUILD $DEFS $INCS -o real-asan real-harness.c \
    encrypted-real-asan.o \
    "$UP/ext/tinycrypt/lib/source/aes_encrypt.c" \
    "$UP/ext/tinycrypt/lib/source/aes_decrypt.c" \
    "$UP/ext/tinycrypt/lib/source/utils.c" \
    "$UP/ext/tinycrypt/lib/source/ctr_mode.c" 2>evidence/asan-build.err || {
        cat evidence/asan-build.err; exit 1;
    }


# shellcheck disable=SC2086
gcc -O1 -g -fno-stack-protector -DFIXED_SOURCE $DEFS $INCS -o fixed-plain real-harness.c \
    encrypted-real.o \
    "$UP/ext/tinycrypt/lib/source/aes_encrypt.c" \
    "$UP/ext/tinycrypt/lib/source/aes_decrypt.c" \
    "$UP/ext/tinycrypt/lib/source/utils.c" \
    "$UP/ext/tinycrypt/lib/source/ctr_mode.c" 2>evidence/fixed-plain-build.err || {
        cat evidence/fixed-plain-build.err; exit 1;
    }

# shellcheck disable=SC2086
gcc -O1 -g -fsanitize=address -DASAN_BUILD -DFIXED_SOURCE $DEFS $INCS -o fixed-asan real-harness.c \
    encrypted-real-asan.o \
    "$UP/ext/tinycrypt/lib/source/aes_encrypt.c" \
    "$UP/ext/tinycrypt/lib/source/aes_decrypt.c" \
    "$UP/ext/tinycrypt/lib/source/utils.c" \
    "$UP/ext/tinycrypt/lib/source/ctr_mode.c" 2>evidence/fixed-asan-build.err || {
        cat evidence/fixed-asan-build.err; exit 1;
    }
for mode in edge attack attack2 safe; do
    ./real-plain "$mode" >"evidence/plain-$mode.out" 2>&1 || true
    ./real-asan "$mode" >"evidence/asan-$mode.out" 2>&1 || true
    ./fixed-plain "$mode" >"evidence/fixed-plain-$mode.out" 2>&1 || true
    ./fixed-asan "$mode" >"evidence/fixed-asan-$mode.out" 2>&1 || true
done
echo "BUILT real-plain real-asan fixed-plain fixed-asan; outputs in evidence/"
