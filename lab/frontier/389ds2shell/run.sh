#!/bin/sh
# Differential harness for 389-ds-base CVE-2026-11610 / GHSA-2g8g-f92j-g4gq:
# pinned sasl_io.c bytes, issue #7658 fix f15ffd63. No sockets, loopback only.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p out
rm -f out/*.log out/*.c out/*.rc out/trace.txt out/trace.sha256 out/pins.expected

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
run_case() { name=$1; bin=$2; shift 2; "$bin" "$@" > "out/$name.log" 2>&1; printf '%s\n' "$?" > "out/$name.rc"; }

# --- primary-source pins ---------------------------------------------------
cat > out/pins.expected <<'EOF'
a03a6156d71594fc2a596b012c84574125734f5f747b3e1623b2b83209b44431  pins/advisory.json
1be123890bb0da43cc9ba03a55f403e2fb648e9504030a1bbddfcf1fde2aa4f5  pins/cve.json
6163717e3d5d3951643b7164a3746652b3f88ff1c799c3d9b4dcca897b493ab9  pins/issue7658.json
6b251fb60bac1b12c119a46141177c6ec7f6da48be77ed1d047d0483635bb00e  pins/fix.json
9cea2e7bf22b1d8cd1296378c1416c63fdede17e4966466d2fd33e19318d84f3  pins/sasl_io.c.e63592d5e6b0
f82aa846fbd2c6f07315e73a862042621184e8df1667b29f07db3be2333ea38b  pins/sasl_io.c.f15ffd63e2bd
$(sha256sum gen_driver.py)
EOF
sha256sum -c out/pins.expected > /dev/null 2>&1
check $? pins_sha256

python3 gen_driver.py vuln > out/driver_vuln.c &&
python3 gen_driver.py fixed > out/driver_fixed.c
check $? generate_drivers

cc -O1 -g -std=c11 -fsanitize=address -o out/vuln_asan out/driver_vuln.c &&
cc -O1 -g -std=c11 -DFIXED -fsanitize=address -o out/fixed_asan out/driver_fixed.c &&
cc -O1 -g -std=c11 -o out/vuln_plain out/driver_vuln.c &&
cc -O1 -g -std=c11 -DFIXED -o out/fixed_plain out/driver_fixed.c

check $? build

# --- rung 1: deterministic trigger; benign and fixed stay clean -----------
run_case vuln_overflow_asan out/vuln_asan asan
run_case vuln_benign_asan out/vuln_asan benign 5a 512
run_case fixed_overflow_asan out/fixed_asan asan
if [ "$(cat out/vuln_overflow_asan.rc)" != 0 ] &&
   [ "$(val out/vuln_overflow_asan.log declared_count)" = 9000 ] &&
   [ "$(val out/vuln_overflow_asan.log caller_len)" = 512 ] &&
   [ "$(val out/vuln_overflow_asan.log overflow)" = 8488 ]; then c=0; else c=1; fi
check $c rung1_vuln_deterministic_trigger
if [ "$(cat out/vuln_benign_asan.rc)" = 0 ] &&
   ! present out/vuln_benign_asan.log 'ERROR: AddressSanitizer'; then c=0; else c=1; fi
check $c rung1_benign_clean
if [ "$(cat out/fixed_overflow_asan.rc)" = 0 ] &&
   [ "$(val out/fixed_overflow_asan.log return)" = 512 ] &&
   ! present out/fixed_overflow_asan.log 'ERROR: AddressSanitizer'; then c=0; else c=1; fi
check $c rung1_fixed_caps_to_caller_len

run_case vuln_bound_511 out/vuln_asan asan 5a 511
run_case vuln_bound_512 out/vuln_asan asan 5a 512
run_case vuln_bound_513 out/vuln_asan asan 5a 513
if [ "$(cat out/vuln_bound_511.rc)" = 0 ] &&
   [ "$(cat out/vuln_bound_512.rc)" = 0 ] &&
   [ "$(cat out/vuln_bound_513.rc)" != 0 ] &&
   present out/vuln_bound_513.log 'ERROR: AddressSanitizer: heap-buffer-overflow' &&
   present out/vuln_bound_513.log 'WRITE of size 513'; then c=0; else c=1; fi
check $c rung1_asan_boundary_exact

# --- rung 2/3: accounting and ASan-confirmed corruption -------------------
if [ "$(val out/vuln_overflow_asan.log declared_count)" = 9000 ] &&
   [ "$(val out/vuln_overflow_asan.log overflow)" = 8488 ]; then c=0; else c=1; fi
check $c rung2_declared_count_exceeds_caller_buffer
if present out/vuln_overflow_asan.log 'ERROR: AddressSanitizer: heap-buffer-overflow' &&
   present out/vuln_overflow_asan.log 'WRITE of size 9000' &&
   present out/vuln_overflow_asan.log 'pins/sasl_io.c.vuln:456' &&
   present out/vuln_overflow_asan.log 'after 512-byte region'; then c=0; else c=1; fi
check $c rung3_asan_write_pinned_frame

# --- rung 4: chosen bytes in collaborator, differential, benign, guard ----
run_case vuln_collab_5a out/vuln_plain collab 5a
run_case vuln_collab_41 out/vuln_plain collab 41
run_case vuln_collab_benign out/vuln_plain collab 5a 512
run_case fixed_collab out/fixed_plain collab 5a
run_case vuln_guard out/vuln_plain guard 5a
if [ "$(val out/vuln_collab_5a.log chosen)" = 8488 ] &&
   [ "$(val out/vuln_collab_5a.log first)" = 0 ] &&
   [ "$(val out/vuln_collab_5a.log last)" = 8487 ] &&
   [ "$(val out/vuln_collab_5a.log pattern)" = 5a ]; then c=0; else c=1; fi
check $c rung4_chosen_bytes_past_512
if [ "$(val out/vuln_collab_41.log chosen)" = 8488 ] &&
   [ "$(val out/vuln_collab_41.log pattern)" = 41 ]; then c=0; else c=1; fi
check $c rung4_pattern_differential
if [ "$(val out/vuln_collab_benign.log chosen)" = 0 ]; then c=0; else c=1; fi
check $c rung4_benign_zero_control
if [ "$(val out/fixed_collab.log chosen)" = 0 ]; then c=0; else c=1; fi
check $c rung4_fixed_no_chosen_bytes
if [ "$(cat out/vuln_guard.rc)" = 77 ] &&
   present out/vuln_guard.log 'guard_fault=1'; then c=0; else c=1; fi
check $c rung4_guard_page_fault

# --- normalized trace -----------------------------------------------------
printf 'asan_write=%s\n' "$(grep -m1 -o 'WRITE of size [0-9]*' out/vuln_overflow_asan.log)" >> "$trace"
printf 'asan_frame=%s\n' "$(grep -m1 -o 'pins/sasl_io.c.vuln:[0-9]*' out/vuln_overflow_asan.log)" >> "$trace"
printf 'declared=%s\n' "$(val out/vuln_overflow_asan.log declared_count)" >> "$trace"
printf 'chosen=%s\n' "$(val out/vuln_collab_5a.log chosen)" >> "$trace"
printf 'checks=%s\n' "$(grep -c '^PASS ' "$trace")" >> "$trace"
printf 'failures=%s\n' "$fail" >> "$trace"
sha256sum "$trace" | cut -d' ' -f1 > out/trace.sha256
printf 'trace_sha256=%s\n' "$(cat out/trace.sha256)"
cat "$trace"
[ "$fail" -eq 0 ]
