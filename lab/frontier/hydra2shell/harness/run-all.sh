#!/bin/sh
# Rebuild and exercise the direct-call matrix. Loopback-only: no network calls.
set -u
cd "$(dirname "$0")/.."
mkdir -p evidence
rm -f evidence/matrix.log
for cc in gcc clang; do
  command -v "$cc" >/dev/null 2>&1 || continue
  CC="$cc" sh harness/build.sh || exit 1
  for variant in vuln fixed; do
    for mode in attack single normal; do
      out="evidence/${cc}-${variant}-${mode}.out"
      ASAN_OPTIONS=detect_leaks=0 timeout 10 "./harness/${cc}-${variant}-asan" "$mode" >"$out" 2>&1
      rc=$?
      err=$(grep -m1 'ERROR: AddressSanitizer' "$out" || true)
      err=$(printf '%s\n' "$err" | sed -E 's/^==[0-9]+==/==PID==/')
      {
        printf '%s %s %s rc=%s\n' "$cc" "$variant" "$mode" "$rc"
        [ -n "$err" ] && printf '  %s\n' "$err"
        grep -m1 '^MODE=' "$out" || true
      } | tee -a evidence/matrix.log
    done
  done
done
sha256sum evidence/matrix.log > evidence/matrix.log.sha256
