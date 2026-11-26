#!/bin/sh
# W225 one-command replay: the two FIPS-labeled snapshots built in real FIPS
# mode (-DFIPS=1 -DASAN=1, Clang, no-ASM) against the pinned harness. This
# closes the limit recorded in PROVENANCE.md:332 (W224 used default, non-FIPS
# configuration of those snapshots). All paths are relative to this directory;
# no network access. Set FORCE_BUILD=1 to rebuild the libraries.
cd "$(dirname "$0")" || exit 2
V=out-of-tree/versions
pass=0
fail=0
check() {
  name=$1
  expected=$2
  actual=$3
  if [ "$expected" = "$actual" ]; then
    echo "PASS $name: $actual"
    pass=$((pass + 1))
  else
    echo "FAIL $name: expected [$expected] got [$actual]"
    fail=$((fail + 1))
  fi
}
hash() { sha256sum "$1" | cut -d' ' -f1; }

for t in AWS-LC-FIPS-3.3.0 AWS-LC-FIPS-3.6.0; do
  case "$t" in
    AWS-LC-FIPS-3.3.0)
      tar_hash=c137191845248c31251972f37a18381db10e579ebc205ebabb464d6f8abb759f
      cipher_hash=0689f3dcfa4624178ef0637cce3654a69295921e7b8a6c8b60e19d0bd301aa4e
      kind=vuln ;;
    AWS-LC-FIPS-3.6.0)
      tar_hash=e3444e64c5e0adeaf23be8234f96e8e0834a68892df7dbd0ce511c81db3e557e
      cipher_hash=b3bafb43554b819954b5c9c2bfec6ddbe24ac488ea0e067834d1f02901526a3b
      kind=fixed ;;
  esac
  src="$V/$t-src"
  mode_build="$V/build-fipsmode-${t#AWS-LC-FIPS-}"
  lib="$mode_build/crypto/libcrypto.a"
  check "$t.tarball_sha" "$tar_hash" "$(hash "$V/$t.tar.gz")"
  check "$t.cipher_sha" "$cipher_hash" "$(hash "$src/crypto/fipsmodule/cipher/cipher.c")"
  if [ ! -f "$lib" ] || [ "${FORCE_BUILD:-0}" = 1 ]; then
    rm -rf "$mode_build" || exit 2
    CC=clang cmake -S "$src" -B "$mode_build" -DCMAKE_BUILD_TYPE=Debug \
      -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF -DFIPS=1 -DASAN=1 \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_C_FLAGS='-g -O0 -DOPENSSL_NO_ASM -Wno-error=unknown-warning-option' \
      > "$V/cmake-fipsmode-${t#AWS-LC-FIPS-}.log" 2>&1 || {
      echo "FAIL $t.cmake"; fail=$((fail + 1)); continue; }
    cmake --build "$mode_build" --target crypto -j4 \
      > "$V/build-fipsmode-${t#AWS-LC-FIPS-}.log" 2>&1 || {
      echo "FAIL $t.build"; fail=$((fail + 1)); continue; }
  fi
  check "$t.fips_mode" 1 "$(grep -c '^FIPS:UNINITIALIZED=1' "$mode_build/CMakeCache.txt")"
  check "$t.asan_mode" 1 "$(grep -c '^ASAN:UNINITIALIZED=1' "$mode_build/CMakeCache.txt")"
  check "$t.boringssl_fips_define" 1 "$(grep -c '^C_DEFINES.*-DBORINGSSL_FIPS' "$mode_build/crypto/CMakeFiles/crypto_objects.dir/flags.make")"
  check "$t.c_defines_asan" 1 "$(grep -c '^C_FLAGS.*-fsanitize=address' "$mode_build/crypto/CMakeFiles/crypto_objects.dir/flags.make")"
  check "$t.lib_built" 0 "$([ -f "$lib" ]; echo $?)"
  cc=clang
  $cc -fsanitize=address -fsanitize-address-use-after-scope \
    -fno-omit-frame-pointer -g -O0 -I "$src/include" harness.c "$lib" \
    -lpthread -o "$V/harness-fipsmode-${t#AWS-LC-FIPS-}" \
    > "$V/compile-fipsmode-${t#AWS-LC-FIPS-}.log" 2>&1
  check "$t.compile" 0 "$?"
  h="$V/harness-fipsmode-${t#AWS-LC-FIPS-}"
  if [ ! -x "$h" ]; then
    echo "FAIL $t.harness_missing"; fail=$((fail + 1)); continue
  fi

  out=$("$h" asan 2>&1); rc=$?
  out2=$("$h" asan-ecb 2>&1)
  out3=$("$h" byte2 2>&1)
  if [ "$kind" = vuln ]; then
    check "$t.asan_rc" 1 "$rc"
    check "$t.asan_write" 1 "$(printf '%s\n' "$out" | grep -c 'WRITE of size 16')"
    check "$t.asan_region" 1 "$(printf '%s\n' "$out" | grep -c '0 bytes after 31-byte region')"
    check "$t.asan_site" 1 "$(printf '%s\n' "$out" | grep -c 'in EVP_DecryptUpdate')"
    check "$t.ecb_write" 1 "$(printf '%s\n' "$out2" | grep -c 'WRITE of size 16')"
    check "$t.chosen_byte" 1 "$(printf '%s\n' "$out3" | grep -c 'byte31=0x48 chosen=0x48 CHOSEN_BYTE_PRESENT')"
  else
    check "$t.asan_rc" 0 "$rc"
    check "$t.asan_clean" 0 "$(printf '%s\n' "$out" | grep -c 'ERROR: AddressSanitizer')"
    check "$t.byte_unmodified" 1 "$(printf '%s\n' "$out3" | grep -c 'byte31=0xab chosen=0x48 CHOSEN_BYTE_ABSENT')"
  fi
done

echo "RESULT: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
