#!/bin/sh
# CVE-2026-75820: drive a long personal-dict word through the real aspell -a
# suggestion path on a vulnerable (0.60.8.2) and fixed (0.60.8.3) ASan build.
# Usage: sh harness/75820-suggest-probe.sh <evidence-dir>
set -u
base="$(cd "$(dirname "$0")/.." && pwd)"
rb="$base/real-build"
out="${1:-$base/harness/evidence/75820-suggest}"
out="$(mkdir -p "$out" && cd "$out" && pwd)"
dict="$rb/en-install/dict"
data="$rb/en-install/data"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1

for ver in 0.60.8.2 0.60.8.3; do
  aspell="$rb/build-asan-$ver/aspell"
  if [ "$ver" = 0.60.8.2 ] && [ -n "${ASPELL_VULN:-}" ]; then aspell="$ASPELL_VULN"; fi
  for n in 250 251 255 256 260 511; do
    word=$(printf '%*s' "$n" '' | tr ' ' a)
    near="${word%?}b"
    personal="$out/personal-$ver-$n"
    printf 'personal_ws-1.1 en 1 utf-8\n%s\n' "$word" > "$personal"
    for kind in exact near short; do
      case "$kind" in
        exact) query="$word" ;;
        near)  query="$near" ;;
        short) query=aaaaa ;;
      esac
      log="$out/$ver-n$n-$kind.out"
      printf '%s\n' "$query" | "$aspell" --lang=en --dict-dir="$dict" \
        --data-dir="$data" --personal="$personal" -a > "$log" 2>&1
      rc=$?
      printf '%s n=%s %s rc=%s asan=%s assert=%s bytes=%s\n' \
        "$ver" "$n" "$kind" "$rc" \
        "$(grep -c 'ERROR: AddressSanitizer' "$log")" \
        "$(grep -c 'Assertion' "$log")" \
        "$(stat -c%s "$log")" | tee -a "$out/summary.txt"
    done
  done
done
