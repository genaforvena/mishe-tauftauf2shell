#!/bin/sh
# Real-GPGME replay for CVE-2026-129975. Requires the ASan builds described
# in REALBUILD.md (or PROVENANCE.md); does not rebuild and makes no network
# contact. Cases use a loopback fake gpg and the public GPGME status callback.
set -u
cd "$(dirname "$0")" || exit 2
mkdir -p evidence
pass=0; fail=0
check() {
  if [ "$1" = "$2" ]; then pass=$((pass+1));
  else fail=$((fail+1)); echo "FAIL: $3 (got '$1', want '$2')"; fi
}
hash() { sha256sum "$1" | cut -d' ' -f1; }

check "$(hash ../pinned/engine-gpg.c)" c4ef11bda841fc6d07c83063c6968a6db50db3393af2d661054c59b979311d55 "pinned engine-gpg.c"
check "$(hash ../pinned/fix.patch)" 2fde658ab8b32439c14f58c214f2463b4109aa68d9cbd26c432f17303049c500 "pinned fix.patch"
check "$(hash gpgme-2.2.0/src/engine-gpg.c)" c4ef11bda841fc6d07c83063c6968a6db50db3393af2d661054c59b979311d55 "built vulnerable source"
check "$(hash gpgme-fixed/src/engine-gpg.c)" 10179f7853d9284a21af4ad4ab94753654aa40119f9bdef43852e98482b75b08 "built patched source"
check "$(grep -c 'gpg->status.buffer = buffer;' gpgme-2.3.1/src/engine-gpg.c)" 1 "2.3.1 immediate writeback"

run() { name=$1; bin=$2; len=$3; marker=$4
  FAKE_GPG_LEN="$len" FAKE_GPG_MARKER="$marker" ASAN_OPTIONS=detect_leaks=0 \
    "./$bin" ./fake-gpg.py >"evidence/$name.out" 2>&1
  echo $? >"evidence/$name.rc"
}

run real-vuln-attack status-trigger 1200 H
run real-vuln-attack-z status-trigger 1200 Z
run real-vuln-safe status-trigger 120 0
run real-fixed-attack status-trigger-fixed 1200 H
run real-fixed-safe status-trigger-fixed 120 0
run real-231-attack status-trigger-231 1200 H

check "$(cat evidence/real-vuln-attack.rc)" 1 "real vulnerable attack faults"
check "$(grep -c 'attempting double-free' evidence/real-vuln-attack.out)" 1 "ASan names double free"
check "$(grep -c 'gpg_release .*engine-gpg.c:602' evidence/real-vuln-attack.out)" 1 "second free in real gpg_release"
check "$(grep -c 'read_status .*engine-gpg.c:1494' evidence/real-vuln-attack.out)" 1 "first free in real read_status realloc"
check "$(grep -c 'status_cb call=1 keyword=GOOD arglen=1200 byte\[1000\]=0x48' evidence/real-vuln-attack.out)" 1 "chosen byte in real callback"
check "$(cat evidence/real-vuln-attack-z.rc)" 1 "second chosen byte also faults"
check "$(grep -c 'byte\[1000\]=0x5a' evidence/real-vuln-attack-z.out)" 1 "second chosen byte visible"
for name in real-vuln-safe real-fixed-attack real-fixed-safe real-231-attack; do
  check "$(cat "evidence/$name.rc")" 0 "$name rc"
  check "$(grep -c AddressSanitizer "evidence/$name.out")" 0 "$name sanitizer-clean"
done
check "$(grep -c 'gpgme version=2.3.1' evidence/real-231-attack.out)" 1 "2.3.1 control is the real release"

echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
