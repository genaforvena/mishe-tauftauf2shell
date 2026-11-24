#!/bin/sh
# Run each probe case with the same ASAN_OPTIONS as the existing lab run-all.sh.
set -eu
cd "$(dirname "$0")"
mkdir -p outputs
rm -f commands.txt exit-codes.txt outputs/*

export ASAN_OPTIONS=abort_on_error=1:allocator_may_return_null=1

run_case() { # label binary mode input
  label=$1; bin=$2; mode=$3; input=$4
  cmd="./$bin $mode $input"
  printf '%s\n' "$cmd" >> commands.txt
  set +e
  $cmd > "outputs/$label.out" 2>&1
  rc=$?
  set -e
  printf '%s rc=%s\n' "$label" "$rc" >> exit-codes.txt
  printf 'COMMAND: %s\nEXIT: %s\n' "$cmd" "$rc" > "outputs/$label.meta"
}

python3 gen_ico.py ../poc-chosen.bmp crafted.ico
python3 gen_ico.py ../safe.bmp safe.ico
python3 gen_ico.py ../poc-chosen.bmp crafted-full.ico full
sha256sum crafted.ico safe.ico crafted-full.ico ../poc-chosen.bmp ../safe.bmp > inputs.sha256

run_case vuln-shared-crafted consumer-vuln shared ../poc-chosen.bmp
run_case vuln-shared-safe    consumer-vuln shared ../safe.bmp

run_case vuln-shared-short-ico consumer-vuln shared crafted.ico
run_case vuln-ico-short        consumer-vuln ico   crafted.ico
run_case vuln-ico-safe         consumer-vuln ico   safe.ico
run_case vuln-ico-full         consumer-vuln ico   crafted-full.ico
run_case vuln-shared-full-ico  consumer-vuln shared crafted-full.ico
run_case vuln-direct-crafted consumer-vuln direct ../poc-chosen.bmp

run_case fixed-shared-crafted consumer-fixed shared ../poc-chosen.bmp
run_case fixed-shared-safe    consumer-fixed shared ../safe.bmp
run_case fixed-shared-ico     consumer-fixed shared crafted.ico
run_case fixed-ico-crafted    consumer-fixed ico   crafted.ico
run_case fixed-ico-full       consumer-fixed ico   crafted-full.ico
run_case fixed-direct-crafted consumer-fixed direct ../poc-chosen.bmp

echo "run OK"
