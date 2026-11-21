#!/bin/bash
# Replay the open62541 TransferSubscriptions sampling-list UAF on pinned tags.
# Usage: bash run.sh <outdir>   (fresh outdir recommended)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(realpath -m "${1:-$HERE/out-run}")"
mkdir -p "$OUT" "$HERE/src"
: > "$OUT/pass.log"
p(){ echo "PASS $1" | tee -a "$OUT/pass.log"; }

# Provisioning only: public release tarballs, hash-verified before any build.
for v in 1.5.4 1.5.6; do
  if [ ! -f "$HERE/src/open62541-$v.tar.gz" ]; then
    curl -fsSL --retry 2 --connect-timeout 15 \
      -o "$HERE/src/open62541-$v.tar.gz" \
      "https://github.com/open62541/open62541/archive/refs/tags/v$v.tar.gz" || exit 1
  fi
done
(cd "$HERE/src" && sha256sum -c SHA256SUMS >/dev/null) && p 'pinned SHA-256SUMS verified' || exit 1

for v in 1.5.4 1.5.6; do
  mkdir -p "$OUT/$v"
  tar xzf "$HERE/src/open62541-$v.tar.gz" -C "$OUT/$v" --strip-components=1
  cmake -S "$OUT/$v" -B "$OUT/$v/out-asan" \
    -DCMAKE_BUILD_TYPE=Debug -DUA_BUILD_EXAMPLES=OFF -DUA_BUILD_UNIT_TESTS=OFF \
    -DUA_BUILD_TOOLS=OFF -DUA_ENABLE_SUBSCRIPTIONS=ON \
    -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1' \
    -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' > "$OUT/cfg-$v.log" 2>&1 || exit 1
  cmake --build "$OUT/$v/out-asan" -j4 > "$OUT/build-$v.log" 2>&1 || exit 1
  gcc -std=c99 -g -O1 -fsanitize=address -fno-omit-frame-pointer \
    -I"$OUT/$v/out-asan/src_generated" -I"$OUT/$v/include" \
    -I"$OUT/$v/plugins/include" -I"$OUT/$v/deps" -I"$OUT/$v/src" -I"$OUT/$v" \
    -o "$OUT/harness-$v" "$HERE/uaf_harness.c" \
    "$OUT/$v/out-asan/bin/libopen62541.a" -lpthread -lm || exit 1
done
p 'both tagged trees built verbatim with ASan; harness compiled against each'

ASAN_OPTIONS=detect_leaks=0 "$OUT/harness-1.5.4" > "$OUT/vuln.log" 2>&1
VRC=$?
ASAN_OPTIONS=detect_leaks=0 "$OUT/harness-1.5.6" > "$OUT/fixed.log" 2>&1
FRC=$?

grep -q 'real Service_TransferSubscriptions succeeded' "$OUT/vuln.log" && \
  grep -q 'forced old subscription removal via UA_Subscription_delete' "$OUT/vuln.log" && \
  p 'vulnerable 1.5.4: real create/register/transfer/delete sequence completed'
grep -q 'ERROR: AddressSanitizer: heap-use-after-free' "$OUT/vuln.log" && \
  grep -q 'WRITE of size 8' "$OUT/vuln.log" && \
  grep -q 'UA_MonitoredItem_unregisterSampling .*ua_subscription.c:1645' "$OUT/vuln.log" && \
  p 'ASan heap-use-after-free WRITE of size 8 at ua_subscription.c:1645'
grep -q 'in delayedFreeSubscription .*ua_subscription.c:277' "$OUT/vuln.log" && \
  p 'freed object is the old subscription (delayedFreeSubscription:277)'
grep -q 'in UA_Subscription_new .*ua_subscription.c:259' "$OUT/vuln.log" && \
  p 'freed object was allocated by Service_CreateSubscription (UA_Subscription_new:259)'

grep -q 'real Service_TransferSubscriptions succeeded' "$OUT/fixed.log" && \
  grep -q 'forced old subscription removal via UA_Subscription_delete' "$OUT/fixed.log" && \
  grep -q 'RESULT REACHED END WITHOUT ASAN REPORT' "$OUT/fixed.log" && \
  p 'fixed 1.5.6: same sequence completes with no ASan report'
if grep -q 'AddressSanitizer' "$OUT/fixed.log"; then
  echo "FAIL fixed build reported ASan" | tee -a "$OUT/pass.log"; exit 1
fi
p "exit codes: vulnerable=$VRC fixed=$FRC (UAF aborts vulnerable only)"
printf 'TRACE sha256=%s\n' "$(sha256sum "$OUT/pass.log" | cut -d' ' -f1)"
