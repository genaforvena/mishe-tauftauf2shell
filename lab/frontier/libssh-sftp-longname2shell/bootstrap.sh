#!/bin/sh
# Provisioning only: fetch immutable public source/patch pins, then verify.
# No host is probed; all later work is local and loopback-only.
set -eu
cd "$(dirname "$0")"
mkdir -p pins
BASE=https://gitlab.com/libssh/libssh-mirror
V=8b2809ae13e1030a06e8699a248520934c08ba81
F=b2065f71c905d347b5e8dd7f8e24856807d71e99
curl -fsSL "$BASE/-/raw/$V/src/sftpserver.c" -o pins/sftpserver.c.vuln
curl -fsSL "$BASE/-/raw/$F/src/sftpserver.c" -o pins/sftpserver.c.fixed
curl -fsSL "$BASE/-/commit/$F.patch" -o pins/fix.patch
if [ ! -s pins/advisory.txt ]; then
  curl -fsSL https://www.libssh.org/security/advisories/CVE-2026-15370.txt -o pins/advisory.txt
fi
python3 gen_driver.py
echo BOOTSTRAP_OK
