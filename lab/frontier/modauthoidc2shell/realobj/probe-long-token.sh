#!/usr/bin/env bash
# W14: does a value-less state token fault a NON-ASan process with a real
# apr_pool_t / request_rec / Cookie table? Local process only, no listener,
# no socket, no wire. Verbatim pinned parser slices, no module build.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/evidence/longtoken"
mkdir -p "$OUT"
INC="-I/usr/include/apache2 $(pkg-config --cflags apr-1)"
LIB="$(pkg-config --libs apr-1 apr-util-1)"

for v in vuln fixed release; do
  D="" ; [ "$v" = fixed ] && D="-DFIXED_VARIANT" ; [ "$v" = release ] && D="-DRELEASE_VARIANT"
  gcc -O0 -g -std=gnu11 $D $INC -o "pl-$v" driver_long.c $LIB \
    2>"$OUT/build-pl-$v.log" || { echo "BUILD_FAIL pl-$v"; exit 1; }
done
gcc -O0 -g -std=gnu11 -fsanitize=address $INC -o al-vuln driver_long.c $LIB \
  2>"$OUT/build-al-vuln.log" || { echo "BUILD_FAIL al-vuln"; exit 1; }
echo "BUILDS_OK $(date -u +%Y-%m-%dT%H:%M:%SZ)"

LENGTHS="30 7800 16000 32000 48000 65000 100000"
: > "$OUT/results.txt"
for n in $LENGTHS; do
  for b in pl-vuln pl-fixed pl-release; do
    crash=0; clean=0; dispatch=0
    for t in 1 2 3 4 5; do
      o=$(MO_TOKEN_LEN=$n timeout 15 ./$b read 0 2>&1); rc=$?
      echo "$o" | grep -q 'PROCESS_CALLS=1' && dispatch=$((dispatch+1))
      if [ $rc -eq 0 ]; then clean=$((clean+1)); else crash=$((crash+1)); fi
      printf '%s len=%s trial=%s rc=%s %s\n' "$b" "$n" "$t" "$rc" "$(echo "$o" | head -1)" \
        >> "$OUT/raw-by-trial.txt"
    done
    printf '%s len=%s clean=%s/5 nonzero=%s/5 dispatch=%s/5\n' "$b" "$n" "$clean" "$crash" "$dispatch" \
      | tee -a "$OUT/results.txt"
  done
done

for n in 7800 65000; do
  for t in 1 2 3; do
    o=$(MO_TOKEN_LEN=$n MO_TOKEN_EQ=1 timeout 15 ./pl-vuln read 0 2>&1); rc=$?
    printf 'wellformed pl-vuln len=%s trial=%s rc=%s %s\n' "$n" "$t" "$rc" "$(echo "$o" | head -1)" \
      | tee -a "$OUT/wellformed.txt"
  done
done

for n in 30 7800 65000; do
  o=$(MO_TOKEN_LEN=$n ASAN_OPTIONS=detect_leaks=0 timeout 15 ./al-vuln read 0 2>&1); rc=$?
  printf 'asan al-vuln len=%s rc=%s %s\n' "$n" "$rc" \
    "$(echo "$o" | grep -m1 -E 'ERROR: AddressSanitizer|VARIANT=')" | tee -a "$OUT/asan.txt"
done

sha256sum driver_long.c > "$OUT/driver-sha256.txt"
echo "results: $OUT"
