#!/bin/sh
# Provisioning only: fetch public pinned sources/advisory/patch, then verify.
# No host is probed; all later work is local, with no listener.
set -eu
cd "$(dirname "$0")"
mkdir -p pins
BASE=https://raw.githubusercontent.com/sm0svx/svxlink
V=d6451c1e5ff7070537fb5763d316b21ba6c68796
F=8eb1008f822a97a42184097ee57e51a302181c75
curl -fsSL "$BASE/$V/src/echolib/EchoLinkStationData.cpp" -o pins/EchoLinkStationData.cpp.vuln
curl -fsSL "$BASE/$F/src/echolib/EchoLinkStationData.cpp" -o pins/EchoLinkStationData.cpp.fixed
curl -fsSL "$BASE/$V/src/echolib/EchoLinkStationData.h" -o pins/EchoLinkStationData.h
curl -fsSL "https://github.com/sm0svx/svxlink/commit/$F.patch" -o pins/fix.patch
# Advisory HTML is a dynamic public page: keep the committed snapshot as
# provenance and fetch only when absent, so a live page change cannot break
# re-provisioning. The four immutable source/patch pins are always refetched.
if [ ! -s pins/advisory.html ]; then
  curl -fsSL https://github.com/sm0svx/svxlink/security/advisories/GHSA-5g48-xjmf-7p4q -o pins/advisory.html
fi
python3 gen_driver.py
echo BOOTSTRAP_OK
