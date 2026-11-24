#!/bin/sh
# Reproduce the pinned lab tree. No network access at run time.
set -eu
cd "$(dirname "$0")"

TARBALL=contiki-ng-release-v5.2.tar.gz
TREE=contiki-ng-release-v5.2
EXPECTED=78133c774812197b43a979e4b8f1026c8740929c45f749c2dccd4a2670819c95

echo "$EXPECTED  $TARBALL" | sha256sum -c -
rm -rf "$TREE"
tar xzf "$TARBALL"
cp harness.c "$TREE/examples/multicast/harness.c"
# Lab-only: enable the real MPL forwarder TX path.
(cd "$TREE" && git apply ../project-conf.patch)
echo "BOOTSTRAP: $TREE ready"
