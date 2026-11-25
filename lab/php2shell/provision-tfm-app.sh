#!/bin/bash
# php2shell — provision the tinyfilemanager "r5-app" lane: a real PHP web
# application whose authentication state lives entirely in the NATIVE php
# session ($_SESSION['filemanager']['logged'] = username string, default
# config, password login) and whose designed admin function is file
# management — an authenticated admin uploads arbitrary files (no
# extension allowlist by default) into the docroot, where the server
# executes them. Consumer for the CVE-2026-126714 splice:
#   promoted record  filemanager|a:1:{s:5:"logged";s:5:"admin";}
# is NUL-free and pipe-free inside the serialized value, so it rides the
# same objk-filename geometry as the committed Drupal harness.
#
# Pinned: tinyfilemanager release tag 2.6
#   zipball sha256 e68f9daf6ec15e8e49f9b024cd34537f88f0df6c08ecf7567752b2522eae6a8b
#   extracted tinyfilemanager.php sha256 94677b427bf60e3ee0980b3136273f580b38776e4aae5a6388d9c1528a7e2fe1
# Default configuration is UNMODIFIED ($use_auth = true; $auth_users carries
# the 'admin' key, so Login::isLogged()-equivalent line 352 isset-check
# passes for the promoted 'admin' value; 'admin' is not in
# $readonly_users, so uploads are permitted).
#
# Usage: bash lab/php2shell/provision-tfm-app.sh
#   Installs lab/src/php2shell-r5-app/tfm-app/web/index.php

set -e
SITE=$(cd "$(dirname "$0")/../.." && pwd)
ZIPURL=https://codeload.github.com/prasathmani/tinyfilemanager/zip/refs/tags/2.6
ZSHA=e68f9daf6ec15e8e49f9b024cd34537f88f0df6c08ecf7567752b2522eae6a8b
FSHA=94677b427bf60e3ee0980b3136273f580b38776e4aae5a6388d9c1528a7e2fe1
DEST="$SITE/lab/src/php2shell-r5-app/tfm-app"
ZIP="$DEST/tfm-2.6.zip"

if [ -f "$DEST/web/index.php" ] && sha256sum "$DEST/web/index.php" | grep -q "$FSHA"; then
    echo "tinyfilemanager 2.6 already provisioned: $DEST/web/index.php"
    exit 0
fi
mkdir -p "$DEST/web"
if [ ! -f "$ZIP" ] || ! sha256sum "$ZIP" | grep -q "$ZSHA"; then
    curl -sL -o "$ZIP" "$ZIPURL"
fi
sha256sum "$ZIP" | grep -q "$ZSHA" || { echo "zipball sha256 mismatch: $ZIP"; exit 1; }
python3 - "$ZIP" "$DEST/web/index.php" <<'EOF'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
data = z.read("tinyfilemanager-2.6/tinyfilemanager.php")
open(sys.argv[2], "wb").write(data)
EOF
sha256sum "$DEST/web/index.php" | grep -q "$FSHA" || { echo "extracted file sha256 mismatch"; exit 1; }
echo "provisioned $DEST/web/index.php (tinyfilemanager 2.6, pinned sha256)"
