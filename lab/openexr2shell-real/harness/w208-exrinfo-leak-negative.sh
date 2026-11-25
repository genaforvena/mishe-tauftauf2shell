#!/bin/sh
# W208: exrinfo's %p diagnostic cannot leak an ASLR-dependent address from a file.
# Replay: cd lab/openexr2shell-real && sh harness/w208-exrinfo-leak-negative.sh
set -eu

BIN=build-vuln-plain/bin/exrinfo
OUT=evidence/w208-exrinfo-leak-negative.out
FORGED=evidence/w208-opaque.exr
SRC=src/openexr-3.5.2/src
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ ! -x "$BIN" ]; then
    make -C build-vuln-plain exrinfo -j4 >/dev/null
fi

expect_hash () {
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] || { echo "PIN FAIL $1: $got" >&2; exit 1; }
}

# Pinned source and baseline case.
expect_hash "$SRC/lib/OpenEXRCore/debug.c" \
    9a52e451d604abfa6e40482473e973c6433e3746a24c8b7c941cb60ac016df0b
expect_hash "$SRC/lib/OpenEXRCore/attributes.c" \
    f7a985bb09d148c2bc7a208b0ca71db32b2c6a659e5fbb27033b9e70fac9316f
expect_hash "$SRC/lib/OpenEXRCore/context.c" \
    adc4a60f431e583e0d3d911effc3616badfd56514dbf38420f7f1ba11a32d98e
expect_hash "$SRC/lib/OpenEXRCore/chunk.c" \
    984e612076e003f2b9012bba6c7a55ab24169af4a1a15e3de9bf712157afde5e
expect_hash "$SRC/bin/exrinfo/main.c" \
    3204e4ff7aed84555e67e14ceb7bc6c937f7a0a736c324fbe0c0b51434019cf5
expect_hash cases/baseline.exr \
    07edcb58a3f2d63eedb5f746229f83dfc879981bf8a9d9cdf66df43a4cd6eb8e
expect_hash harness/w208-opaque-forge.py \
    eed2901aa63807cb87d5b6e59ca8ca5922c07065ba8b985010dc2b87b1ca7eda

# The only %p print of function pointers is the opaque-attribute branch.
grep -q '"(size %d unp size %d hdlrs %p %p %p)"' "$SRC/lib/OpenEXRCore/debug.c"
grep -q 'attr->opaque->unpack_func_ptr = handler->opaque->unpack_func_ptr;' \
    "$SRC/lib/OpenEXRCore/attributes.c"
# No shipped tool registers a custom handler; no exrinfo decode call exists.
if grep -rq 'exr_register_attr_type_handler' "$SRC/bin"; then
    echo "UNEXPECTED handler registration in a shipped tool" >&2; exit 1
fi
if grep -q 'exr_decoding_run' "$SRC/bin/exrinfo/main.c"; then
    echo "UNEXPECTED decode call in exrinfo" >&2; exit 1
fi
CHILD=$(nm -D "$BIN" | grep -Ec ' U (system|popen|execl|execle|execlp|execv|execve|execvp|fork|posix_spawn)@' || true)
[ "$CHILD" -eq 0 ] || { echo "UNEXPECTED command import: $CHILD" >&2; exit 1; }

# Forge a valid EXR with a custom-type attribute, parsed as OPAQUE.
python3 harness/w208-opaque-forge.py cases/baseline.exr "$FORGED" >/dev/null
FORGED_HASH=$(sha256sum "$FORGED" | cut -d' ' -f1)
"$BIN" -v -a "$FORGED" >"$TMP/file.out" 2>&1
cat "$FORGED" | "$BIN" -v -a - >"$TMP/stdin.out" 2>&1
HANDLERS=$(grep -o 'hdlrs .*)' "$TMP/file.out")
STDIN_HANDLERS=$(grep -o 'hdlrs .*)' "$TMP/stdin.out")
[ "$HANDLERS" = "hdlrs (nil) (nil) (nil))" ] || {
    echo "UNEXPECTED opaque handlers: $HANDLERS" >&2; exit 1; }
[ "$STDIN_HANDLERS" = "$HANDLERS" ] || {
    echo "STDIN path differs: $STDIN_HANDLERS" >&2; exit 1; }

HEX=$(grep -o '0x[0-9a-fA-F]\+' "$TMP/file.out" | grep -v -i '^0x0d$' | sort -u | wc -l)
[ "$HEX" -eq 0 ] || { echo "UNEXPECTED address-like tokens: $HEX" >&2; exit 1; }

{
    echo "PINNED debug.c 9a52e451d604abfa6e40482473e973c6433e3746a24c8b7c941cb60ac016df0b"
    echo "PINNED attributes.c f7a985bb09d148c2bc7a208b0ca71db32b2c6a659e5fbb27033b9e70fac9316f"
    echo "PINNED context.c adc4a60f431e583e0d3d911effc3616badfd56514dbf38420f7f1ba11a32d98e"
    echo "PINNED chunk.c 984e612076e003f2b9012bba6c7a55ab24169af4a1a15e3de9bf712157afde5e"
    echo "PINNED exrinfo/main.c 3204e4ff7aed84555e67e14ceb7bc6c937f7a0a736c324fbe0c0b51434019cf5"
    echo "PINNED baseline.exr 07edcb58a3f2d63eedb5f746229f83dfc879981bf8a9d9cdf66df43a4cd6eb8e"
    echo "FORGED_OPAQUE_EXR $FORGED_HASH"
    echo "OPAQUE_HANDLERS $HANDLERS"
    echo "STDIN_HANDLERS $STDIN_HANDLERS"
    echo "ADDRESS_LIKE_TOKENS_EXCLUDING_COMPRESSION_ENUM $HEX"
    echo "COMMAND_IMPORTS $CHILD"
    echo "HANDLER_REGISTRATIONS_IN_BIN 0"
    echo "DECODE_CALLS_IN_EXRINFO 0"
    echo "RESULT PASS"
} >"$OUT"
cat "$OUT"
