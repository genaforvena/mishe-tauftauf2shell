#!/usr/bin/env bash
# Run the direct-call evidence matrix. No network, no sockets.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
mkdir -p evidence
LOG=evidence/evidence.log
: > "$LOG"

printf 'codebasememory2shell direct-call matrix, generated %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$LOG"
printf 'pins and harness hashes:\n' >> "$LOG"
sha256sum PINS.sha256 harness.c build.sh run-all.sh >> "$LOG" 2>/dev/null || true
printf '\n' >> "$LOG"

run_one() {
  local bin="$1" n="$2" kind="$3" tag raw out rc qrc err
  tag="$(basename "$bin")"
  raw="evidence/${tag}-${kind}-${n}.out"
  if [[ "$bin" == *asan* ]]; then
    out=$(ASAN_OPTIONS=detect_leaks=0 timeout 30 "$bin" "$n" "$kind" 2>&1)
  else
    out=$(timeout 30 "$bin" "$n" "$kind" 2>&1)
  fi
  rc=$?
  printf '%s' "$out" > "$raw"
  qrc=$(printf '%s\n' "$out" | grep -m1 -o 'RC=-*[0-9]*' | cut -d= -f2 || true)
  err=$(printf '%s\n' "$out" | grep -m1 -E 'ERROR: AddressSanitizer|runtime error:|SUMMARY: AddressSanitizer|stack smashing' || true)
  printf '%-30s N=%-3s %-6s exit=%-3s query_rc=%-3s %s\n' "$tag" "$n" "$kind" "$rc" "${qrc:-n/a}" "${err:-clean}" | tee -a "$LOG"
}

for kind in RETURN WITH; do
  for n in 16 31 32 33 48 64; do
    run_one ./harness-vuln-asan "$n" "$kind"
  done
  for n in 32 33 48; do
    run_one ./harness-fixed-asan "$n" "$kind"
    run_one ./harness-vuln-plain "$n" "$kind"
  done
done

printf '\nrecover-mode ASan (continues past the first error to reach the WRITE):\n' >> "$LOG"
ASAN_OPTIONS=detect_leaks=0:halt_on_error=0 timeout 30 \
  ./harness-vuln-asan-recover 48 RETURN > evidence/recover-48.out 2>&1 || true
grep -m1 -A14 'WRITE of size' evidence/recover-48.out >> "$LOG" || true


sha256sum "$LOG" > evidence/evidence.sha256
printf 'done: %s (%s)\n' "$LOG" "$(cat evidence/evidence.sha256)"
