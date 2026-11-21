#!/bin/sh
# Reproducible differential harness for the memcached LRU-crawler idle-client
# overflow. All memcached logic is verbatim pinned source; see PROVENANCE.md.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p out
rm -f out/*.log out/trace.txt out/trace.sha256

fail=0
trace=out/trace.txt
: > "$trace"

check() {
    if [ "$1" -eq 0 ]; then printf 'PASS %s\n' "$2" >> "$trace";
    else printf 'FAIL %s\n' "$2" >> "$trace"; fail=$((fail + 1)); fi
}

val() { grep -m1 -o "$2=[^ ]*" "$1" 2>/dev/null | cut -d= -f2-; }
present() { grep -q "$2" "$1" 2>/dev/null; }

run_case() {
    name=$1; bin=$2; mode=$3; backend=$4; fill=$5; asan=$6
    rc=0
    if [ "$asan" = 1 ]; then
        MC_NO_SIGSEGV_HANDLER=1 MC_POLL_MODE="$mode" MC_ITEMS=2000 \
        MC_BACKEND="$backend" MC_KEY_FILL="$fill" \
        ASAN_OPTIONS=abort_on_error=0:detect_leaks=0:log_path=stderr \
            "./out/$bin" "$name" > "out/$name.log" 2>&1 || rc=$?
    else
        MC_POLL_MODE="$mode" MC_ITEMS=2000 MC_BACKEND="$backend" MC_KEY_FILL="$fill" \
            "./out/$bin" "$name" > "out/$name.log" 2>&1 || rc=$?
    fi
    printf 'case=%s rc=%s\n' "$name" "$rc" >> "$trace"
    return "$rc"
}

# --- pinned bytes -----------------------------------------------------------
cat > out/pins.expected <<'EOF'
b82268114e6b70c4ae1e0b3ed6e46fc1e470d9f834f5a89624be94ac090d96ee  pins/crawler.c.vuln
49cafef4386b574b03b5cabfd0894e91cdfa50eb9bdf5f84c46a07b519c18fc6  pins/crawler.c.fixed
8bd3348e61fad57241fc9ce340dc7471dffc3f36c9ac2d4e1f0b495eacbd67ef  pins/fix.patch
ece160a168ea7bf81927e1385d8fd6dbe7d37ba37dbf5112cca5f8b5f8d7fd7f  pins/commit.json
ef377cf2f45d2a70d8d56298ca1edd57dee661c169588bee27d95ca7f293e340  pins/tag.json
95822c84af9e2979a526b91e2c42f3589b556541205c262375852de0a9738ed4  pins/proto_text.c.vuln
90931425c2c91aa44c82cf63ae178c068bd6ceaf0713a1205516218d955d780b  pins/memcached.c.vuln
ff1114a83a572ded538132f689dbc648ca3c74a976809ad0b46a113228a72ddc  pins/release-1.6.44.html
EOF
sha256sum -c out/pins.expected > /dev/null 2>&1
check $? pins_sha256

# --- build ------------------------------------------------------------------
python3 gen_driver.py > /dev/null
PLAIN_W='-Wl,--wrap=poll,--wrap=malloc'
cc -O1 -g -std=gnu11 -w -o out/vuln_plain out/driver_vuln.c $PLAIN_W
cc -O1 -g -std=gnu11 -w -o out/fixed_plain out/driver_fixed.c $PLAIN_W
# ASan builds call malloc directly so its allocation stack reaches pinned :831.
cc -O1 -g -std=gnu11 -w -fsanitize=address -DMC_NO_REAL_MALLOC -o out/vuln_asan out/driver_vuln.c -Wl,--wrap=poll
cc -O1 -g -std=gnu11 -w -fsanitize=address -DMC_NO_REAL_MALLOC -o out/fixed_asan out/driver_fixed.c -Wl,--wrap=poll
check $? build

# --- rung 1: deterministic trigger and fixed guard --------------------------
run_case vuln_timeout_plain vuln_plain 0 plain 90 0
vrc=$?
if [ "$vrc" -eq 77 ] && present out/vuln_timeout_plain.log 'plain_fault=1'; then c=0; else c=1; fi
check $c rung1_vuln_idle_client_fault

run_case fixed_timeout_plain fixed_plain 0 plain 90 0
frc=$?
if [ "$frc" -eq 0 ] && [ "$(val out/fixed_timeout_plain.log write_ret)" = -1 ] &&
   [ "$(val out/fixed_timeout_plain.log closes)" = 1 ] &&
   ! present out/fixed_timeout_plain.log 'fault=1'; then c=0; else c=1; fi
check $c rung1_fixed_timeout_closes_client

# --- rung 2: accounting failure, fixed EAGAIN loop bounded ------------------
run_case vuln_eagain_plain vuln_plain 2 plain 90 0
run_case fixed_eagain_plain fixed_plain 2 plain 90 0
if [ "$(val out/vuln_eagain_plain.log bytes_written)" = 0 ] &&
   [ "$(val out/vuln_eagain_plain.log write_calls)" = 1 ] &&
   [ "$(val out/vuln_eagain_plain.log write_ret)" = 0 ] &&
   [ "$(val out/vuln_eagain_plain.log closes)" = 0 ] &&
   [ "$(val out/fixed_eagain_plain.log write_ret)" = -1 ]; then c=0; else c=1; fi
check $c rung2_sent_underflow_false_success

# --- rung 3: ASan-confirmed corruption at pinned lines ----------------------
run_case vuln_timeout_asan vuln_asan 0 plain 90 1
run_case fixed_timeout_asan fixed_asan 0 plain 90 1
run_case vuln_benign_asan vuln_asan 1 plain 90 1
printf 'asan_error=%s\n' "$(grep -m1 -o 'ERROR: AddressSanitizer: heap-buffer-overflow' out/vuln_timeout_asan.log)" >> "$trace"
printf 'asan_write=%s\n' "$(grep -m1 -o 'WRITE of size [0-9]*' out/vuln_timeout_asan.log)" >> "$trace"
printf 'asan_append_frame=%s\n' "$(grep -o 'crawler.c.vuln:[0-9]*' out/vuln_timeout_asan.log | sed -n '1p')" >> "$trace"
printf 'asan_alloc_frame=%s\n' "$(grep -o 'crawler.c.vuln:[0-9]*' out/vuln_timeout_asan.log | sed -n '2p')" >> "$trace"
printf 'asan_region=%s\n' "$(grep -m1 -o '0 bytes after 131072-byte region' out/vuln_timeout_asan.log)" >> "$trace"
if present out/vuln_timeout_asan.log 'heap-buffer-overflow' &&
   [ "$(grep -o 'crawler.c.vuln:[0-9]*' out/vuln_timeout_asan.log | sed -n '1p')" = 'crawler.c.vuln:310' ] &&
   [ "$(grep -o 'crawler.c.vuln:[0-9]*' out/vuln_timeout_asan.log | sed -n '2p')" = 'crawler.c.vuln:825' ] &&
   ! present out/fixed_timeout_asan.log 'ERROR: AddressSanitizer' &&
   ! present out/vuln_benign_asan.log 'ERROR: AddressSanitizer'; then c=0; else c=1; fi
check $c rung3_asan_overflow_pinned_fixed_clean

# --- rung 4: chosen bytes past the nominal region, real-libc negative -------
run_case vuln_bounded vuln_plain 0 bounded 90 0
run_case vuln_bounded_benign vuln_plain 0 bounded 65 0
run_case fixed_guard fixed_plain 0 guard 90 0
if [ "$(val out/vuln_bounded.log bounded_at_0)" = 5a ] &&
   [ "$(val out/vuln_bounded.log bounded_at_4)" = 5a ] &&
   [ "$(val out/vuln_bounded.log bounded_at_65536)" = 5a ] &&
   [ "$(val out/vuln_bounded_benign.log bounded_at_0)" = 41 ] &&
   [ "$(val out/vuln_bounded_benign.log bounded_at_4)" = 41 ] &&
   [ "$(val out/vuln_bounded_benign.log bounded_at_65536)" = 41 ] &&
   [ "$(val out/vuln_bounded.log buflen)" = 131072 ]; then c=0; else c=1; fi
check $c rung4_chosen_key_bytes_past_131072
if [ "$(val out/fixed_guard.log guard_page_offset)" = 131072 ] &&
   [ "$(val out/fixed_guard.log write_ret)" = -1 ]; then c=0; else c=1; fi
check $c rung4_guard_mapping_valid

printf 'checks=%s\n' "$(grep -c '^PASS ' "$trace")" >> "$trace"
printf 'failures=%s\n' "$fail" >> "$trace"
sha256sum "$trace" | cut -d' ' -f1 > out/trace.sha256
printf '%s\n' "$(cat out/trace.sha256)"
[ "$fail" -eq 0 ]
