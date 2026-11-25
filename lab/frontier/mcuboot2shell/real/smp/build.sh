#!/bin/sh
# Native host build of the verbatim MCUboot SMP upload path. No Zephyr SDK;
# OS/flash/UART are shims, protocol + encryption sources are upstream.
set -eu
cd "$(dirname "$0")"
UP=../../upstream-parent
mkdir -p evidence
DEFS="-D__BOOTSIM__ -DMCUBOOT_HAVE_ASSERT_H -DMCUBOOT_USE_FLASH_AREA_GET_SECTORS -DMCUBOOT_MAX_IMG_SECTORS=128 -DMCUBOOT_BOOT_MAX_ALIGN=8 -DMCUBOOT_IMAGE_NUMBER=1 -DMCUBOOT_ENC_IMAGES -DMCUBOOT_ENCRYPT_KW -DMCUBOOT_USE_TINYCRYPT -DMCUBOOT_ENC_BUILTIN_KEY -DMCUBOOT_FIH_PROFILE_OFF -DMCUBOOT_SERIAL_RAW_PROTOCOL -DMCUBOOT_USE_SNPRINTF -DMCUBOOT_PERUSER_MGMT_GROUP_ENABLED=0"
INCS="-I shiminc -I . -I $UP/sim/mcuboot-sys/csupport -I $UP/boot/bootutil/include -I $UP/boot/bootutil/src -I $UP/boot/boot_serial/include -I $UP/boot/boot_serial/src -I $UP/boot/zcbor/include -I $UP/ext/tinycrypt/lib/include"
# shellcheck disable=SC2086
gcc -c -O1 -g $DEFS $INCS -Dboot_enc_decrypt=real_boot_enc_decrypt \
    -Dboot_enc_load=real_boot_enc_load -o encrypted-smp.o \
    "$UP/boot/bootutil/src/encrypted.c" 2>evidence/encrypted-build.err || {
        cat evidence/encrypted-build.err; exit 1;
    }
# shellcheck disable=SC2086
gcc -std=gnu11 -O1 -g -fno-stack-protector $DEFS $INCS -o smp-host smp-host.c \
    smp-shims.c \
    boot_serial-host.c \
    "$UP/boot/boot_serial/src/zcbor_bulk.c" \
    "$UP/boot/zcbor/src/zcbor_decode.c" \
    "$UP/boot/zcbor/src/zcbor_encode.c" \
    "$UP/boot/zcbor/src/zcbor_common.c" \
    encrypted-smp.o \
    "$UP/ext/tinycrypt/lib/source/aes_encrypt.c" \
    "$UP/ext/tinycrypt/lib/source/aes_decrypt.c" \
    "$UP/ext/tinycrypt/lib/source/utils.c" \
    "$UP/ext/tinycrypt/lib/source/ctr_mode.c" 2>evidence/build.err || {
        cat evidence/build.err; exit 1;
    }
echo "BUILT smp-host"
