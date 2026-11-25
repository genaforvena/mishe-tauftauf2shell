#!/bin/sh
# One-command author replay of the permutation RR write experiment.
# Loopback only. Runs a real plain build against decrypted RR replies, plus
# a no-inject baseline and a locally patched-build control.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p evidence
PIN=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
FIX=70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7
sha_p=$(sha256sum plain-src/display_ipopt.c | cut -d' ' -f1)
sha_f=$(sha256sum plain-fixed-src/display_ipopt.c | cut -d' ' -f1)
[ "$sha_p" = "$PIN" ] || { echo "pinned sha mismatch $sha_p"; exit 2; }
[ "$sha_f" = "$FIX" ] || { echo "fixed sha mismatch $sha_f"; exit 2; }

echo "STAGE baseline"
NO_INJECT=1 MODE=inc EXPECT=baseline RUN_TAG=baseline sh fullip-proof.sh || exit 1
echo "STAGE attack-dec"
MODE=dec EXPECT=attack RUN_TAG=attack-dec sh fullip-proof.sh || exit 1
echo "STAGE fixed-dec"
BIN=plain-fixed-src/hping3 MODE=dec EXPECT=fixed RUN_TAG=fixed-dec sh fullip-proof.sh || exit 1
echo "REPLAY_PERM_OK: 3 stages"
