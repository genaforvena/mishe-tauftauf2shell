#!/bin/sh
# W224 one-command replay: vendor-listed AWS-LC 4.x / FIPS 2.x / FIPS 3.x
# vulnerable and patched releases against the pinned harness. All paths are
# relative to this directory; build artifacts stay in gitignored out-of-tree/.
#
# Prerequisite: the six tagged tarballs named below are provisioned in
# out-of-tree/versions/ (fetch URLs and sha256 in PROVENANCE.md). This script
# never contacts the network. Set FORCE_BUILD=1 to rebuild existing libraries.
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

for t in v4.0.0 v4.2.0 AWS-LC-FIPS-2.0.17 AWS-LC-FIPS-2.0.18 \
         AWS-LC-FIPS-3.3.0 AWS-LC-FIPS-3.6.0; do
  case "$t" in
    v4.0.0)               tar_hash=dec49e5c38dd8d3b4c2700c692bbb457a149cd6d23ad99463ce3612720c23bb0; cipher_hash=adb5f9ccbadaddc22a62e6c25e5dcbe713e0573d2bff32cd6b41ecd561428d96; kind=vuln ;;
    v4.2.0)               tar_hash=45e1735cb55571eb69782dff6a196e8b63d330056f25d6636c815cea2b8fc58b; cipher_hash=6f8e5b8b2b5a49a82cf5f03f7aeb25453de7dfd1ce9594b9be360ef7cd165264; kind=fixed ;;
    AWS-LC-FIPS-2.0.17)   tar_hash=14ce24f28906305b11c284b68cb748dc51f75bdf54d4b3323bdec687659c7a62; cipher_hash=fa2050b41c1f38db6389ca7d8ac26a9c2e652d83ab10c3965582355ee9a3fe79; kind=vuln ;;
    AWS-LC-FIPS-2.0.18)   tar_hash=404ab9f4d7bbfab52c21bbfa5b6fac5c31cab9a1c8dfe18646ae154194379a42; cipher_hash=8d42edac1577afacc5d5aee7e8b0358e1a41dd56765484d94fe054d18e651950; kind=fixed ;;
    AWS-LC-FIPS-3.3.0)    tar_hash=c137191845248c31251972f37a18381db10e579ebc205ebabb464d6f8abb759f; cipher_hash=0689f3dcfa4624178ef0637cce3654a69295921e7b8a6c8b60e19d0bd301aa4e; kind=vuln ;;
    AWS-LC-FIPS-3.6.0)    tar_hash=e3444e64c5e0adeaf23be8234f96e8e0834a68892df7dbd0ce511c81db3e557e; cipher_hash=b3bafb43554b819954b5c9c2bfec6ddbe24ac488ea0e067834d1f02901526a3b; kind=fixed ;;
  esac
  src="$V/$t-src"
  lib="$V/build-$t/crypto/libcrypto.a"
  check "$t.tarball_sha" "$tar_hash" "$(hash "$V/$t.tar.gz")"
  if [ ! -f "$src/crypto/fipsmodule/cipher/cipher.c" ]; then
    mkdir -p "$src" || continue
    tar xzf "$V/$t.tar.gz" -C "$src" --strip-components=1 || continue
  fi
  check "$t.cipher_sha" "$cipher_hash" "$(hash "$src/crypto/fipsmodule/cipher/cipher.c")"
  if [ ! -f "$lib" ] || [ "${FORCE_BUILD:-0}" = 1 ]; then
    cmake -S "$src" -B "$V/build-$t" -DCMAKE_BUILD_TYPE=Debug \
      -DBUILD_TESTING=OFF -DDISABLE_GO=ON -DDISABLE_PERL=ON \
      -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O0 -DOPENSSL_NO_ASM' \
      > "$V/cmake-$t.log" 2>&1 || { echo "FAIL $t.cmake"; fail=$((fail + 1)); continue; }
    cmake --build "$V/build-$t" --target crypto -j4 > "$V/build-$t.log" 2>&1 \
      || { echo "FAIL $t.build"; fail=$((fail + 1)); continue; }
  fi
  check "$t.lib_built" 0 "$([ -f "$lib" ]; echo $?)"
  cc -fsanitize=address -fno-omit-frame-pointer -g -O0 -I "$src/include" \
    harness.c "$lib" -lpthread -o "$V/harness-$t" > "$V/compile-$t.log" 2>&1
  check "$t.compile" 0 "$?"
  if [ ! -x "$V/harness-$t" ]; then
    echo "FAIL $t.harness_missing"; fail=$((fail + 1)); continue
  fi

  out=$("$V/harness-$t" asan 2>&1)
  rc=$?
  if [ "$kind" = vuln ]; then
    check "$t.asan_rc" 1 "$rc"
    check "$t.asan_write" 1 "$(printf '%s\n' "$out" | grep -c 'WRITE of size 16')"
    check "$t.asan_region" 1 "$(printf '%s\n' "$out" | grep -c '0 bytes after 31-byte region')"
    check "$t.asan_site" 1 "$(printf '%s\n' "$out" | grep -c 'in EVP_DecryptUpdate')"
    out2=$("$V/harness-$t" asan-ecb 2>&1)
    check "$t.ecb_write" 1 "$(printf '%s\n' "$out2" | grep -c 'WRITE of size 16')"
    out3=$("$V/harness-$t" byte2 2>&1)
    check "$t.chosen_byte" 1 "$(printf '%s\n' "$out3" | grep -c 'byte31=0x48 chosen=0x48 CHOSEN_BYTE_PRESENT')"
  else
    check "$t.asan_rc" 0 "$rc"
    check "$t.asan_clean" 0 "$(printf '%s\n' "$out" | grep -c 'ERROR: AddressSanitizer')"
    out3=$("$V/harness-$t" byte2 2>&1)
    check "$t.byte_unmodified" 1 "$(printf '%s\n' "$out3" | grep -c 'byte31=0xab chosen=0x48 CHOSEN_BYTE_ABSENT')"
  fi
done

echo "RESULT: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
