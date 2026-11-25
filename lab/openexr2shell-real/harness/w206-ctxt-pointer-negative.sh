#!/bin/sh
# W206: bounded NEGATIVE for the "different live victim pointer" lane.
# At the pinned W202 call site the 104-byte copy covers eight ctxt function
# pointers.  All eight resolve into the PIE exrcheck binary, none into libc,
# and the pinned binary imports no command-executing function.  With ASLR on
# there is therefore no libc-resident victim to retarget by a partial write,
# and no same-mapping command call to retarget either (W205).
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

for spec in \
    'cases/p202-memcpy-system.exr 7f3eda1b00f54b56ec75108f9012be6b035c8b6393ec1d7c2241f94be91e412e' \
    'cases/w195-pre-copy2-dump.bin f7c32f6ad820de0532396426d0ad9a8aa58440071636b03e1592cf766daffdc0' \
    'cases/make_w202_poc.py f884e414c180bde4bb036547e65a8c5b95b269f141afb1b98a3764f6bed43402' \
    'harness/w202-command.cmd 2ea315718753d90adc2a4d398a939d9ccd47a5e77b063ae33a191ff2b2cf12bc' \
    'harness/w206-ctxt-pointers.cmd 0cfc9fc856b1449571a590d8d0afc34bc352ebcae4eeea5535aecbffc0cef867'
do
    set -- $spec
    test "$(sha256sum "$1" | cut -d' ' -f1)" = "$2"
done

BIN=./build-vuln-plain/bin/exrcheck
SRC=src/openexr-3.5.2/src/lib/OpenEXRCore

# The post-copy consumer calls only ctxt->free_fn; assert the exact source line.
grep -q '^    ctxt->free_fn (attr);$' "$SRC/attributes.c"
grep -q 'ud->destroy_unpacked_func_ptr (' "$SRC/opaque.c"

# No command-executing symbol is defined by, or imported into, the PIE binary.
test -z "$(nm "$BIN" | grep -iE ' (system|__libc_system|popen|execl|execv|execve|execlp|posix_spawn)$' || true)"
test -z "$(nm -D "$BIN" | grep -iE ' U (system|__libc_system|popen|execl|execv|execve|execlp|posix_spawn)@' || true)"
grep -q 'FREEFN_BEFORE=0x555555663e50' evidence/w202-chain.out

RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT
gdb -q -batch -ex 'set args -c cases/p202-memcpy-system.exr' \
    -x harness/w206-ctxt-pointers.cmd "$BIN" > "$RAW" 2>&1 || true

grep -q '^CTXT=0x555555826f00$' "$RAW"
grep -q '^0x555555826f60:.*0x0000555555663e50$' "$RAW"
grep -q '^P0=0x555555618350 P1=(nil) P2=0x55555561a2d0 P3=0x55555561a250$' "$RAW"
grep -q '^P4=0x55555561a360 P5=0x5555555c59f0 P6=0x555555663db0 P7=0x555555663e50$' "$RAW"
grep -q '^dispatch_read in section .text of ' "$RAW"
grep -q '^dispatch_standard_error in section .text of ' "$RAW"
grep -q '^dispatch_print_error in section .text of ' "$RAW"
grep -q 'core_error_handler_cb.* in section .text of ' "$RAW"
grep -q '^internal_exr_alloc in section .text of ' "$RAW"
grep -q '^internal_exr_free in section .text of ' "$RAW"
# Seven of the eight slots hold a function pointer; do_write (+48) is NULL.
test "$(grep -c ' in section .text of ' "$RAW")" -eq 7
test "$(grep '^P[0-7]=' "$RAW" | grep -c '(nil)')" -eq 1
test "$(grep '^P[0-7]=' "$RAW" | wc -l)" -eq 2
# None of the resolved pointers may live in a shared library.
test "$(grep ' in section .text of ' "$RAW" | grep -vc '/bin/exrcheck$')" -eq 0

awk '
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell\/lab\/openexr2shell-real/, "LAB") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell/, "SITE") }
    { print }
' < "$RAW" > evidence/w206-ctxt-pointers.out
# No libc-mapped address in the ctxt window itself (ASLR-off dump).
! grep -q '0x00007f' evidence/w206-ctxt-pointers.out
{
    echo 'ASLR=off'
    grep '^CTXT=' evidence/w206-ctxt-pointers.out
    grep '^0x555555826f' evidence/w206-ctxt-pointers.out
    grep '^P[0-7]=' evidence/w206-ctxt-pointers.out
    grep ' in section .text of ' evidence/w206-ctxt-pointers.out \
        | sed 's| in section .text of .*| in section .text of LAB/build-vuln-plain/bin/exrcheck|'
    echo 'LIBC_RESIDENT_CTXT_FNPTRS=0 COMMAND_SYMBOLS_IN_PIE=0'
    echo 'POST_COPY_CTXT_CALL=attributes.c:271 ctxt->free_fn(attr)'
    echo 'RESULT PASS'
} > evidence/w206-ctxt-pointer-negative.out

printf 'RESULT PASS\n'
sha256sum evidence/w206-ctxt-pointer-negative.out
