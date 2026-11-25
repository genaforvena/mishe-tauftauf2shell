#!/bin/sh
# One-command replay of all seven awslc2shell suites from a clean git archive.
#
#   mkdir -p /tmp/awslc-replay
#   git archive HEAD lab/frontier/awslc2shell | tar x -C /tmp/awslc-replay
#   AWSLC_LAB=/abs/path/to/lab/frontier/awslc2shell \
#     sh /tmp/awslc-replay/lab/frontier/awslc2shell/replay-witness.sh
#
# AWS-LC source trees and the five built libcrypto.a libraries are gitignored.
# The wrapper symlinks them from AWSLC_LAB, checks both pinned cipher.c hashes
# and the fix patch, rebuilds every small harness binary from the archived C
# sources, then runs the seven suites and checks each expected PASS count.
# Only loopback/network-free lab binaries are run. A normalized summary is
# written to witness-replay.summary; exit 0 only when every check passes.
set -u
HERE=$(cd "$(dirname "$0")" && pwd -P) || exit 1
cd "$HERE" || exit 1

UP=${AWSLC_LAB:-.}
UP=$(cd "$UP" && pwd -P) || { echo "AWSLC_LAB is not a directory: $UP" >&2; exit 2; }

need() {
  p=$1
  if [ -e "$p" ]; then return 0; fi
  if [ -e "$UP/$p" ]; then
    ln -s "$UP/$p" "$p" || exit 2
    return 0
  fi
  echo "REPLAY setup FAIL: missing $p (set AWSLC_LAB to the provisioned lab)" >&2
  exit 2
}

for p in src src-fixed build-asan build-asan-c build-fixed build-plain \
         build-fixed-plain; do
  need "$p"
done
for p in src/crypto/fipsmodule/cipher/cipher.c \
         src-fixed/crypto/fipsmodule/cipher/cipher.c fix-cipher.patch \
         build-asan/crypto/libcrypto.a build-asan-c/crypto/libcrypto.a \
         build-fixed/crypto/libcrypto.a build-plain/crypto/libcrypto.a \
         build-fixed-plain/crypto/libcrypto.a; do
  need "$p"
done

SUMMARY=witness-replay.summary
: > "$SUMMARY"
overall=0
say() { printf '%s\n' "$1" | tee -a "$SUMMARY"; }
pin() {
  name=$1 file=$2 hash=$3
  if sha256sum "$file" | grep -q "^$hash"; then
    say "PIN OK $name $hash"
  else
    say "PIN FAIL $name $hash"
    overall=1
  fi
}
pin vuln-cipher src/crypto/fipsmodule/cipher/cipher.c \
  72797ecccdd9fc8572962f00a7aba609a183eb1cf3dfd5e7b9a199d51f6250cb
pin fixed-cipher src-fixed/crypto/fipsmodule/cipher/cipher.c \
  b40e79909b53a7e0eb6533e73ac328d099699fa4ea26fc18a859c6000b2754e7
pin fix-patch fix-cipher.patch \
  bf6afd852a6da2a88f920fd9efdee718302213f27b69d5b2f6a5a8ba485893a9

# Harnesses from archived sources against the provisioned pinned libraries.
A="-fsanitize=address -fno-omit-frame-pointer -g -O0"
cc $A -I src/include harness.c build-asan/crypto/libcrypto.a \
  -lpthread -o harness-vuln || exit 2
cc $A -I src/include harness.c build-asan-c/crypto/libcrypto.a \
  -lpthread -o harness-c || exit 2
cc $A -I src-fixed/include harness.c build-fixed/crypto/libcrypto.a \
  -lpthread -o harness-fixed || exit 2
cc $A -I src/include consumer.c build-asan-c/crypto/libcrypto.a \
  -lpthread -ldl -o consumer-vuln || exit 2
cc $A -I src/include consumer.c build-fixed/crypto/libcrypto.a \
  -lpthread -ldl -o consumer-fixed || exit 2
cc -O0 -g -Wall -Wextra -I src/include metadata.c \
  build-plain/crypto/libcrypto.a -lpthread -ldl -o metadata-vuln || exit 2
cc -O0 -g -Wall -Wextra -I src-fixed/include metadata.c \
  build-fixed-plain/crypto/libcrypto.a -lpthread -ldl -o metadata-fixed || exit 2
sh build-global-datum.sh >> "$SUMMARY" 2>&1 || exit 2
sh build-frame-datum.sh >> "$SUMMARY" 2>&1 || exit 2

expect() {
  suite=$1 want=$2
  out=$(sh "$suite.sh" 2>&1)
  rc=$?
  line=$(printf '%s\n' "$out" | grep -E '^(RESULT:|TOTAL )' | sed -n '$p')
  got=$(printf '%s\n' "$line" | sed -n 's/^[^0-9]*\([0-9][0-9]*\) PASS.*/\1/p')
  fails=$(printf '%s\n' "$line" | sed -n 's/.*\/ \([0-9][0-9]*\) FAIL.*/\1/p')
  if [ "$rc" -eq 0 ] && [ "$got" = "$want" ] && [ "$fails" = "0" ]; then
    say "SUITE OK $suite $line"
  else
    say "SUITE FAIL $suite want $want PASS / 0 FAIL, rc=$rc, got [$line]"
    overall=1
  fi
}

expect run-all 14
expect run-consumer 31
expect run-metadata 10
expect run-stack-layout 16
expect run-global-datum 15
expect run-des 11
expect run-frame-datum 27

# run-stack-layout.sh rewrites its tracked log with host-local stack deltas.
# The summary above is the normalized replay record; no log restore here so
# the wrapper never hides a failed run.
say "REPLAY_AWSLC_$([ "$overall" -eq 0 ] && echo OK || echo FAIL)"
exit "$overall"
