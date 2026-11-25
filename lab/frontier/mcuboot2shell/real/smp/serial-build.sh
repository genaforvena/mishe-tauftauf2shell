#!/bin/sh
# W6: native socket-backed UART build of the real MCUboot serial read loop.
set -eu
cd "$(dirname "$0")"
VARIANT=${1:-parent}
FIXED_DEFS=
case "$VARIANT" in
    parent)
        OUT=smp-serial
        ENC_INC=encryption-host.inc
        ;;
    fixed)
        OUT=smp-serial-fixed
        ENC_INC=../../src/mcuboot-fixed-boot_serial_encryption.c
        FIXED_DEFS=-DM2S_FIXED_CONTROL
        ;;
    *)
        echo "usage: sh serial-build.sh [parent|fixed]" >&2
        exit 2
        ;;
esac
OUT="$OUT" ENC_INC="$ENC_INC" \
EXTRA_DEFS="-DM2S_SOCKET_UART -DMCUBOOT_SERIAL_WAIT_FOR_DFU -DMCUBOOT_SERIAL_INACTIVITY_TIMEOUT $FIXED_DEFS" \
    sh build.sh
