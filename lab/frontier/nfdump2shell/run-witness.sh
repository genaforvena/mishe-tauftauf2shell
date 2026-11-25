#!/usr/bin/env bash
# One-command offline replay of the nfdump2shell staged rung-3/rung-4-PARTIAL
# evidence. Run from anywhere: bash lab/frontier/nfdump2shell/run-witness.sh
# Prints "WITNESS REPLAY PASS" only if every pin hash and staged control holds.
set -u
cd "$(dirname "$0")"
fail=0
ok() { printf 'PASS %s\n' "$1"; }
no() { printf 'FAIL %s\n' "$1"; fail=$((fail+1)); }
hashcheck() { # FILE EXPECTED_SHA256 LABEL
  got=$(sha256sum "$1" | cut -d' ' -f1)
  if [ "$got" = "$2" ]; then ok "$3"; else no "$3 (got $got)"; fi
}
need() { # FILE PATTERN LABEL
  if grep -q "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi
}
need_not() {
  if grep -q "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi
}

echo '== pinned source bytes (sha256)'
hashcheck pins/nfd_raw-parent.c f946944aa4c65085af96dc56fb622e40fd4eb8c3662e8ba7f2336a9377f92869 'parent nfd_raw.c'
hashcheck pins/nfd_raw-fixed.c b6fbdd91fbac138ec1eac2c2becabcf82a59b9f46249979027cf086ceaa650ea 'fix nfd_raw.c'
hashcheck pins/nfxV3-parent.c 408cbbc8859d62fe1002817d73c5b08800caa4640e107843af16a34de44ad0ae 'parent nfxV3.c'
hashcheck pins/nfxV3-fixed.c d94b82d3d2a295c6692d3f03fc5b0ee06eb5f621ba7dcb6dcae1b3ef85cdf77e 'fix nfxV3.c'
hashcheck pins/verify-parent.inc c020fe80a020eba2035b2a629f9437611d087c1ca9567c4911538ab9decf51d6 'verbatim VerifyV3Record parent'
hashcheck pins/verify-fixed.inc 0f66f0a3eb2b8cd4125c200d3875c564a66a6ce2147771b360342c56e8db0e16 'verbatim VerifyV3Record fix'
hashcheck pins/process-parent.inc 5c8857c7c6fd1b4ebc3af9ffea78e58f7b4e6fa8a6523a8c2a85982be4dd8cdb 'verbatim Process_nfd parent'
hashcheck pins/process-fixed.inc 73473a1a48ad7ecfc2da0e8003f0c544861e450d14ea9c1a57baafb81f62a24c 'verbatim Process_nfd fix'

echo '== staged runner (10 PASS / 0 FAIL expected)'
mkdir -p harness/out
if bash run-all.sh > harness/out/witness-run.log 2>&1; then
  ok "staged runner $(tail -1 harness/out/witness-run.log)"
else
  no "staged runner $(tail -1 harness/out/witness-run.log)"
fi
need harness/out/witness-run.log 'TOTAL: 10 PASS / 0 FAIL' 'staged runner total'

echo '== rung 3: ASan WRITE-8 at the exact allocation'
A=harness/out/vuln-asan-attack.log
need "$A" 'heap-buffer-overflow' 'gcc ASan heap-buffer-overflow'
need "$A" 'WRITE of size 8' 'gcc ASan WRITE of size 8'
need "$A" '0 bytes after 48-byte region' 'gcc ASan 0 bytes after 48-byte region'
need "$A" 'Process_nfd' 'gcc ASan stack reaches pinned Process_nfd'
need harness/out/vuln-clang-asan-attack.log 'WRITE of size 8' 'clang ASan WRITE of size 8'

echo '== fixed and safe-input controls'
need harness/out/witness-run.log 'PASS fixed-asan rejects short EXgenericFlow' 'fixed build rejects short element'
need harness/out/witness-run.log 'PASS vuln-asan safe-full clean' 'vulnerable safe-full clean'
need harness/out/witness-run.log 'PASS fixed-asan safe-empty clean' 'fixed safe-empty clean'

echo '== rung 4 PARTIAL: chosen value at the declared element end'
P=harness/out/vuln-plain-attack-canary.log
need "$P" 'ELEM_LEN=20 REC_SIZE=32 TOTAL=48' 'truncated element arithmetic'
E=$(sed -n 's/^EXPECTED_BYTES=//p' "$P")
AFTER=$(sed -n 's/^CANARY_AFTER=//p' "$P")
if [ -n "$E" ] && [ "$AFTER" = "$E" ]; then
  ok "plain chosen value $AFTER at element end"
else
  no "plain chosen value (expected=$E after=$AFTER)"
fi
need "$P" 'EXPECTED_BYTES=9b50351f49010000' 'deterministic chosen msecReceived bytes'
need_not "$P" 'AddressSanitizer' 'plain build no sanitizer report'

if [ "$fail" -eq 0 ]; then
  printf 'WITNESS REPLAY PASS\n'
else
  printf 'WITNESS REPLAY FAIL (%s)\n' "$fail"
fi
exit "$fail"
