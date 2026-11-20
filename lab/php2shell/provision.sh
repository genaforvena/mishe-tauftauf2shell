#!/bin/sh
# php2shell provisioning — pinned fetch + verify of lab sources.
#
# Affected:  PHP 8.4.26  (CVE-2026-109618 / CVE-2026-109619, both <8.4.27)
# Fixed:     PHP 8.4.27  (contains fix commit 3584a98 "Avoid state corruption
#                        via bailout", which fixes BOTH CVEs in one commit)
#
# sha256 values are the official ones published by php.net (verified against
# https://www.php.net/releases/index.php?json&version=8.4.x on 2026-11-20).
# Re-fetch that JSON to cross-check if php.net ever publishes a correction.
#
# Usage: sh lab/php2shell/provision.sh   (idempotent; skips what is present)

set -e
SITE=$(cd "$(dirname "$0")/../.." && pwd)
SRC="$SITE/lab/src"
BUILD="$SITE/lab/build"
AFFECTED=8.4.26
FIXED=8.4.27
SHA_AFFECTED=32a2de53862ad44ed4a5005244ce4f1b50c271e74dced215449a4443b40569f1
SHA_FIXED=dcf93923b0e38e0d5252b25b796520b5a47761a08b3488b6d0b5d1115764d3f0

# Fix commit (master); parent 512c04e39f674dbf4133b8fbbd381cd8c2df6836.
FIX_COMMIT=3584a98bda0f2c0d367255b046798b0d3a221a19
# sha256 of the reconstructed per-file patch (lab/src/php-fix-3584a98.patch,
# built from the GitHub commit API on 2026-11-20):
SHA_PATCH=0bd74e0720e94d7c6dbe673e573a1b5974c39a536d04a9797c5423e076c0274d

fetch_tarball() {
    v=$1; sha=$2
    f="$SRC/php-$v.tar.xz"
    if [ ! -f "$f" ]; then
        echo "fetching php-$v.tar.xz from php.net"
        curl -fsSL --max-time 300 "https://www.php.net/distributions/php-$v.tar.xz" -o "$f"
    fi
    echo "$sha  $f" | sha256sum -c -
}

fetch_tarball "$AFFECTED" "$SHA_AFFECTED"
fetch_tarball "$FIXED" "$SHA_FIXED"

for v in "$AFFECTED" "$FIXED"; do
    if [ ! -d "$BUILD/php-$v" ]; then
        echo "extracting php-$v into lab/build/"
        tar -C "$BUILD" -xf "$SRC/php-$v.tar.xz"
    fi
done

# Fix patch. github.com/<org>/<repo>/commit/<sha>.patch 503'd for this commit
# (8745 added lines, 300 files), so reconstruct it from the GitHub commit API,
# which carries the per-file 'patch' fields.
p="$SRC/php-fix-$FIX_COMMIT.patch"
if [ ! -f "$p" ]; then
    echo "fetching fix commit $FIX_COMMIT via GitHub commit API"
    curl -fsSL --max-time 300 \
        "https://api.github.com/repos/php/php-src/commits/$FIX_COMMIT" \
        -o "$SITE/lab/tmp/fix-commit-$FIX_COMMIT.json"
    python3 - "$SITE/lab/tmp/fix-commit-$FIX_COMMIT.json" "$p" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
if d['sha'] != '3584a98bda0f2c0d367255b046798b0d3a221a19':
    sys.exit('unexpected commit sha from API')
out = []
for f in d['files']:
    if 'patch' not in f:
        sys.exit(f"no patch field for {f['filename']}")
    out.append(f"diff --git a/{f['filename']} b/{f['filename']}\n"
               f"--- a/{f['filename']}\n+++ b/{f['filename']}\n{f['patch']}\n")
open(sys.argv[2], 'w').write(''.join(out))
EOF
fi
echo "$SHA_PATCH  $p" | sha256sum -c -

echo "provisioned: php-$AFFECTED (affected), php-$FIXED (fixed), fix patch $FIX_COMMIT"
