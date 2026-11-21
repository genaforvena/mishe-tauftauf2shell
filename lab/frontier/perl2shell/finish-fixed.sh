#!/bin/sh
set -eu
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/perl2shell
cd "$BASE/perl-5.45.1"
echo "RESUME $(date -u)"
make -j2 > "$BASE/build-vuln-resume.log" 2>&1
cp perl "$BASE/perl-5.45.1-asan-vuln"
echo "VULN_COMPLETE $(date -u)"
cd "$BASE"
./build-fixed.sh
