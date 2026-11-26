#!/usr/bin/env bash
# One-command witness replay for the unarr2shell staged evidence.
# Rehashes every pin, removes all build output, and rebuilds from scratch.
set -u
cd "$(dirname "$0")"

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }

echo "== pin verification =="
for pair in \
 "src-v1.1.0.tar.gz 4dc03f03e6215c4fcba4927962c7551c1eea690ae6de7c6251de4006d76adfd5" \
 "pinned/parse-tar-v1.1.0.c d07acabdfb4c8d1b1673f81daafb3fd0cc6c563a053797e6e6127ad2f797ce14" \
 "pinned/parse-tar-v1.2.0.c bd9bf8d99e1274ba6a870c39ee694c80843dc3b7821fca7b219bef480f3a4482" \
 "pinned/parse-tar-v1.2.1.c bd9bf8d99e1274ba6a870c39ee694c80843dc3b7821fca7b219bef480f3a4482" \
 "harness/driver.c 16258974dae175312a4df9cad329c2adc5a5b9410b659d097319c652ea13c88f" \
 "harness/make-poc.py 6f7bdcada7872cfb6ae7d8d13734dbc58fea82bee0a37eb624d2da15ddf0a22f" \
 "harness/run-all.sh fc8a0be05461ad8fcb571f857a37cee7e6586a49c2a8293c7e8dbae6544d3b12"; do
    set -- $pair
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] && ok "pin $1" || bad "pin $1 ($got != $2)"
done

echo "== clean rebuild and full run =="
rm -rf build src-locally-fixed evidence-replay
mkdir -p evidence-replay
# run-all.sh writes its evidence into ./evidence; clear stale evidence first.
rm -rf evidence
if bash harness/run-all.sh > evidence-replay/run-all.log 2>&1; then
    ok "run-all.sh full replay"
else
    bad "run-all.sh full replay"
fi
grep -E '^TOTAL:' evidence-replay/run-all.log || true
grep -E '^(PASS|FAIL) ' evidence-replay/run-all.log | tail -20 || true

# Re-assert the sink against the freshly written evidence.
grep -q 'WRITE of size 101' evidence/asan-vuln-attack.out \
  && grep -q 'tar_get_name' evidence/asan-vuln-attack.out \
  && ok "GCC ASan WRITE-101 at tar_get_name" \
  || bad "GCC ASan WRITE-101 at tar_get_name"
grep -q 'WRITE of size 101' evidence/asan-clang-vuln-attack.out \
  && grep -q 'tar_get_name' evidence/asan-clang-vuln-attack.out \
  && ok "Clang ASan WRITE-101 at tar_get_name" \
  || bad "Clang ASan WRITE-101 at tar_get_name"

echo "REPLAY_PASS=$pass REPLAY_FAIL=$fail"
if [ "$fail" -eq 0 ]; then
    echo "WITNESS REPLAY PASS"
    exit 0
fi
echo "WITNESS REPLAY FAIL"
exit 1
