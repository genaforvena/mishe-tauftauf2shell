#!/bin/sh
# php2shell provisioning — pinned fetch + verify of lab sources.
#
# Affected:  PHP 8.4.26  (CVE-2026-109618 / CVE-2026-109619, both <8.4.27;
#                       also CVE-2026-126714 / CVE-2026-115560, both <8.4.28)
# Fixed:     PHP 8.4.27  (contains fix commit 3584a98 "Avoid state corruption
#                        via bailout", which fixes BOTH 618/619 CVEs)
# Fixed2:    PHP 8.4.28  (2026-11-19 security release; fixes CVE-2026-126714
#                        session-splice and CVE-2026-115560 serialize-mismatch)
# BranchCover: last AFFECTED heads of the other branches for CVE-2026-126714
# (fixed only in the 2026-11-19 release 8.2.36/8.3.37/8.4.28/8.5.13):
# Fixed3:   PHP 8.5.13 (2026-11-19 security release; fixes CVE-2026-129474,
#           magic-method backtrace stale-argument read / GHSA-8mjj-2r7p-4hg2)
#   8.2.35 / 8.3.36 / 8.5.12 — splice harnesses run per branch, one per wake.
# Branch-head sha256 values verified against
# https://www.php.net/releases/index.php?json on 2026-11-20.
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
FIXED2=8.4.28
SHA_AFFECTED=32a2de53862ad44ed4a5005244ce4f1b50c271e74dced215449a4443b40569f1
SHA_FIXED=dcf93923b0e38e0d5252b25b796520b5a47761a08b3488b6d0b5d1115764d3f0
SHA_FIXED2=0c8ec360e5dd8154f270b2fd50cd44ecc824e6ee39c85f911312b80d4daecd72
BRANCH1=8.2.35
BRANCH2=8.3.36
BRANCH3=8.5.12
SHA_BRANCH1=5737b98601fe5ab1b8c5db0c82ed3158acb9283ed3081ffe2faffb9ac81455e6
SHA_BRANCH2=dd54693aa334c5c4d72e9aee96b082c2473750a18a6c1d105789c93a3b1692fd
SHA_BRANCH3=08bc2eba2a588654ade1357174aa646b761556c862dda0678345ee29ed481209
SHA_FIXED3=607602acaf0c3061818e9916ec44a058e8b3d43959a83862b9cd3ec7bf5b785f
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
fetch_tarball "$FIXED2" "$SHA_FIXED2"
fetch_tarball "$FIXED3" "$SHA_FIXED3"

fetch_tarball "$BRANCH1" "$SHA_BRANCH1"
fetch_tarball "$BRANCH2" "$SHA_BRANCH2"
fetch_tarball "$BRANCH3" "$SHA_BRANCH3"

for v in "$AFFECTED" "$FIXED" "$FIXED2" "$FIXED3" "$BRANCH1" "$BRANCH2" "$BRANCH3"; do
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

echo "provisioned branch heads: $BRANCH1 $BRANCH2 $BRANCH3 (CVE-2026-126714 affected)"

echo "provisioned: php-$AFFECTED (affected), php-$FIXED (fixed 618/619), php-$FIXED2 (fixed 126714/115560), fix patch $FIX_COMMIT"
