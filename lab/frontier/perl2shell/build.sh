#!/bin/sh
# Provisioning + local build only. No network probes, no services.
set -eu
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/perl2shell
cd "$BASE"
echo "START $(date -u)"
if [ ! -f perl-5.45.1.tar.gz ]; then
  curl -fsSL -o perl-5.45.1.tar.gz https://www.cpan.org/src/5.0/perl-5.45.1.tar.gz
fi
echo "TARBALL $(wc -c < perl-5.45.1.tar.gz)"
tar xzf perl-5.45.1.tar.gz
cd perl-5.45.1
echo "PIN_CMP_BEGIN $(date -u)"
./Configure -des -Dusedevel -DDEBUGGING -Doptimize='-g -O1 -fsanitize=address' -Aldflags='-fsanitize=address' > ../configure.log 2>&1
cmp regexp.h ../src/v5.45.1-regexp.h
echo "PIN_CMP_OK $(date -u)"
echo "CONFIGURED $(date -u)"
make -j2 > ../build-vuln.log 2>&1
cp perl ../perl-5.45.1-asan-vuln
echo "VULN_BUILD_OK $(date -u)"
# Fixed control: apply the two CNA fix commits to the same tree, verify bytes
# match the pinned 5.45.2 files, then rebuild only regexec.o and relink.
cp regexec.c ../vuln-regexec.c.saved
cp regexp.h ../vuln-regexp.h.saved
patch -p1 < ../src/568e6fd.patch > ../patch1.log 2>&1
patch -p1 < ../src/54cf3d4.patch > ../patch2.log 2>&1
if cmp -s regexec.c ../src/v5.45.2-regexec.c && cmp -s regexp.h ../src/v5.45.2-regexp.h; then
  echo "FIXED_PINS_MATCH"
  make -j2 > ../build-fixed.log 2>&1
  cp perl ../perl-5.45.2-asan-fixed
  echo "FIXED_BUILD_OK $(date -u)"
else
  echo "FIXED_PINS_MISMATCH $(date -u)"
fi
echo "DONE $(date -u)"
