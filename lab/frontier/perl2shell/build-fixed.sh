#!/bin/sh
# Fixed control: same pinned 5.45.1 tree with the two CNA fix commits applied.
# Patched files are NOT byte-identical to the 5.45.2 tag (other commits landed
# in between); the fix hunks are verified by source inspection instead.
set -eu
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/perl2shell
cd "$BASE/perl-5.45.1"
echo "FIXED_START $(date -u)"
if [ -f ../vuln-regexec.c.saved ]; then
  cp ../vuln-regexec.c.saved regexec.c
  cp ../vuln-regexp.h.saved regexp.h
fi
patch -p1 < ../src/568e6fd.patch > ../fixpatch1.log 2>&1
patch -p1 < ../src/54cf3d4.patch > ../fixpatch2.log 2>&1
grep -q 'STRLEN len = reginfo->strend - reginfo->strbeg' regexec.c
grep -q 'len < ((~(STRLEN)0) - 7)/n' regexec.c
grep -q 'STRLEN poscache_maxiter' regexp.h
echo "FIX_HUNKS_PRESENT $(date -u)"
make -j2 > ../build-fixed.log 2>&1
cp perl ../perl-5.45.1-asan-fixed
echo "FIXED_BUILD_OK $(date -u)"
