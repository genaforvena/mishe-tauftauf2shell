#!/bin/sh
# Compile stack-layout.c against both pinned plain libraries across ordinary
# GCC/Clang flag sets.  Expect the chosen byte at out[31] only in the vulnerable
# build, and no natural stack control datum at that address in either build.
set -u
cd "$(dirname "$0")"
log=stack-layout-replay.log
: > "$log"
if [ ! -f build-plain/crypto/libcrypto.a ] ||
   [ ! -f build-fixed-plain/crypto/libcrypto.a ]; then
  sh build-plain.sh > "$log" 2>&1 || exit 2
fi

pass=0
fail=0
for lib in vuln fixed; do
  case $lib in
    vuln) inc=src/include; a=build-plain/crypto/libcrypto.a; want=48 ;;
    fixed) inc=src-fixed/include; a=build-fixed-plain/crypto/libcrypto.a; want=ab ;;
  esac
  for comp in gcc clang; do
    for opt in O0 O1 O2 O3; do
      bin="stack-layout-$lib-$comp-$opt"
      label="$lib/$comp/$opt"
      if ! "$comp" "-$opt" -g -w -fno-omit-frame-pointer -fno-stack-protector \
          -I "$inc" stack-layout.c "$a" -lpthread -ldl -o "$bin" 2>>"$log"; then
        printf '%s COMPILE_FAIL\n' "$label" >> "$log"
        fail=$((fail + 1))
        continue
      fi
      result=$("./$bin" 2>>"$log")
      ok=1
      case "$result" in
        *"oob_byte=0x$want"*) ;;
        *) ok=0 ;;
      esac
      for field in cb_after_delta cb_before_delta tail_delta frame_delta; do
        delta=$(printf '%s\n' "$result" | sed -n "s/.*$field=\\(-*[0-9]*\\).*/\\1/p")
        if [ -z "$delta" ] || [ "$delta" = 0 ]; then ok=0; fi
      done
      if [ "$ok" = 1 ]; then
        pass=$((pass + 1))
        printf '%s %s PASS\n' "$label" "$result" >> "$log"
      else
        fail=$((fail + 1))
        printf '%s %s FAIL\n' "$label" "$result" >> "$log"
      fi
      rm -f "$bin"
    done
  done
done
printf 'TOTAL %d PASS / %d FAIL\n' "$pass" "$fail" >> "$log"
cat "$log"
[ "$fail" -eq 0 ]
