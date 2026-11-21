#!/bin/sh
# Differential harness for SRS GHSA-qr8h-p53p-x564: pinned RTCP decoder bytes.
# All external reads were provisioning; this harness uses no sockets/network.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p out
rm -f out/*.log out/trace.txt out/trace.sha256

fail=0
trace=out/trace.txt
: > "$trace"

check() {
    rc=$1; name=$2
    if [ "$rc" -eq 0 ]; then printf 'PASS %s\n' "$name" >> "$trace";
    else printf 'FAIL %s\n' "$name" >> "$trace"; fail=$((fail + 1)); fi
}
val() { grep -m1 -o "$2=[^ ]*" "$1" 2>/dev/null | cut -d= -f2-; }
present() { grep -q "$2" "$1" 2>/dev/null; }

run_case() {
    name=$1; bin=$2; shift 2
    "$bin" "$@" > "out/$name.log" 2>&1
    printf '%s\n' "$?" > "out/$name.rc"
}

# --- pinned inputs (fetched from primary sources 2026-11-21) ---------------
cat > out/pins.expected <<'EOF'
5a0d5189bc6cfe5259b36fc73c3d7064c2a154d0a278518996d1b265f14b3281  pins/advisory.json
64cd635d2f6e9d0be85a63898d865d50134913b78c18376f593e7cb384bc6d68  pins/buffer.cpp.vuln
a562c2cbbbc66241a2f48355af82300c1e26d5bba7487c1d00b6c2d0977e07d0  pins/commit8.json
f2c42ce0b276afc98434f0c52896f430a470a61bba7aa8b8bc966f5b0055530e  pins/fix.patch
6b95dbe792fc1efc6a02f1c416ec890545784d3c92860dddbfc02a8cdf238b31  pins/rtcp.cpp.fixed
1a108163ee650e6ea495bdb04a4e645f317894928931180bc016cafbdf85b942  pins/rtcp.cpp.vuln
918f69de0c4047ab5c9c96a0776c349f9754cc9fd18efac084165e415b8874b2  pins/srs_kernel_buffer.hpp
cf7a415951a785b352184131071f230e32c49550ff58e848bdfb13f7a91f00ba  pins/srs_kernel_rtc_rtcp.hpp
645ef6d22a215271daa109eaad6eb0862e7020a84eecf1561410721903a2ffb1  pins/srs_kernel_error.hpp
66d0b09d4987efdeb4c410af144ec7f7d992ec99211219839f2a81960e89997f  pins/srs_kernel_error.cpp
b21f73ac38046051167466b47a597e9efdae49f1519ca2f885495c0d9963b468  driver_pre.cpp
06353a70cea375afff1ce7e847b532da0721a4463b537767335e84e3dabbf2b9  driver_post.cpp
f67fb44947f8e135b4310f81804189ca237d385295801dca0b98da3cb19e66fc  gen_driver.py
EOF
sha256sum -c out/pins.expected > /dev/null 2>&1
check $? pins_sha256

# --- generate verbatim-source drivers and build ------------------------------
python3 gen_driver.py vuln out/driver_vuln.cpp &&
python3 gen_driver.py fixed out/driver_fixed.cpp
check $? generate_drivers
CXX='c++ -x c++ -O1 -g -std=c++17 -w'
$CXX -fsanitize=address -o out/vuln_asan out/driver_vuln.cpp &&
$CXX -fsanitize=address -o out/fixed_asan out/driver_fixed.cpp &&
$CXX -o out/vuln_plain out/driver_vuln.cpp &&
$CXX -o out/fixed_plain out/driver_fixed.cpp
check $? build

# --- rung 1: length=0 aborts the parent, fixed build rejects ----------------
run_case vuln_assert_plain out/vuln_plain assert
run_case fixed_assert_plain out/fixed_plain assert
if [ "$(cat out/vuln_assert_plain.rc)" = 134 ] &&
   present out/vuln_assert_plain.log 'srs_assert failed: require(size)'; then c=0; else c=1; fi
check $c rung1_vuln_length_zero_assert
if [ "$(cat out/fixed_assert_plain.rc)" = 0 ] &&
   present out/fixed_assert_plain.log 'require length for ssrc' &&
   ! present out/fixed_assert_plain.log 'srs_assert failed'; then c=0; else c=1; fi
check $c rung1_fixed_length_zero_rejects

# --- rung 2/3: upper bound only; ASan heap overflow in pinned read_bytes ----
run_case vuln_bye_asan out/vuln_asan bye
run_case fixed_bye_asan out/fixed_asan bye
run_case vuln_benign_asan out/vuln_asan benign
run_case vuln_twcc_asan out/vuln_asan twcc
if [ "$(val out/vuln_bye_asan.log declared_payload)" = 1596 ] &&
   [ "$(val out/vuln_bye_asan.log wire_bytes)" = 1604 ]; then c=0; else c=1; fi
check $c rung2_declared_length_exceeds_buffer
if present out/vuln_bye_asan.log 'ERROR: AddressSanitizer: heap-buffer-overflow' &&
   present out/vuln_bye_asan.log 'WRITE of size 1596' &&
   present out/vuln_bye_asan.log 'pinned/srs_kernel_buffer.cpp:246'; then c=0; else c=1; fi
check $c rung3_asan_bye_overflow_pinned_frame
if [ "$(cat out/fixed_bye_asan.rc)" = 0 ] &&
   present out/fixed_bye_asan.log 'payload len=1596 exceeds 1500' &&
   ! present out/fixed_bye_asan.log 'ERROR: AddressSanitizer'; then c=0; else c=1; fi
check $c rung3_fixed_bye_rejects
if [ "$(cat out/vuln_benign_asan.rc)" = 0 ] &&
   ! present out/vuln_benign_asan.log 'ERROR: AddressSanitizer'; then c=0; else c=1; fi
check $c rung3_benign_clean
if present out/vuln_twcc_asan.log 'ERROR: AddressSanitizer: heap-buffer-overflow' &&
   present out/vuln_twcc_asan.log 'WRITE of size 1596'; then c=0; else c=1; fi
check $c rung3_asan_twcc_overflow

# --- rung 4: chosen bytes in a collaborator, guard-page negative ------------
run_case vuln_collab_5a out/vuln_plain collab 5a
run_case vuln_collab_41 out/vuln_plain collab 41
run_case vuln_collab_benign out/vuln_plain collab_benign 5a
run_case vuln_guard out/vuln_plain guard 5a
if [ "$(val out/vuln_collab_5a.log chosen)" = 96 ] &&
   [ "$(val out/vuln_collab_5a.log first)" = 0 ] &&
   [ "$(val out/vuln_collab_5a.log last)" = 95 ]; then c=0; else c=1; fi
check $c rung4_chosen_5a_past_1500
if [ "$(val out/vuln_collab_41.log chosen)" = 96 ]; then c=0; else c=1; fi
check $c rung4_chosen_41_differential
if [ "$(val out/vuln_collab_benign.log chosen)" = 0 ]; then c=0; else c=1; fi
check $c rung4_benign_zero_control
if [ "$(cat out/vuln_guard.rc)" = 77 ] &&
   present out/vuln_guard.log 'guard_fault=1'; then c=0; else c=1; fi
check $c rung4_guard_page_fault

# --- trace ------------------------------------------------------------------
printf 'asan_write=%s\n' "$(grep -m1 -o 'WRITE of size [0-9]*' out/vuln_bye_asan.log)" >> "$trace"
printf 'asan_append_frame=%s\n' "$(grep -m1 -o 'pinned/srs_kernel_buffer.cpp:[0-9]*' out/vuln_bye_asan.log)" >> "$trace"
printf 'chosen=%s\n' "$(val out/vuln_collab_5a.log chosen)" >> "$trace"
printf 'checks=%s\n' "$(grep -c '^PASS ' "$trace")" >> "$trace"
printf 'failures=%s\n' "$fail" >> "$trace"
sha256sum "$trace" | cut -d' ' -f1 > out/trace.sha256
printf '%s\n' "$(cat out/trace.sha256)"
[ "$fail" -eq 0 ]
