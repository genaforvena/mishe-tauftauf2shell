#!/bin/bash
# xschem2shell: verbatim pinned rawtovcd.c, GCC+Clang ASan/plain, fixed and safe controls.
set -u
export ASAN_OPTIONS=detect_leaks=0
cd "$(dirname "$0")" || exit 1
mkdir -p evidence
pass=0
fail=0

build() {
  cc="$1"; pin="$2"; san="$3"; out="$4"; extra="${5:-}"
  flags="-g -O0 $extra"
  if [ "$san" = asan ]; then flags="$flags -fsanitize=address -fno-omit-frame-pointer"; fi
  "$cc" $flags -DPIN_PATH="\"../pins/$pin.c\"" probe.c -lm -o "$out" \
    > "evidence/$out.build.log" 2>&1
}

ok() { echo "PASS $1"; pass=$((pass+1)); }
no() { echo "FAIL $1"; fail=$((fail+1)); }

# ASan attack: OOB pointer store through the file-carried names[] index.
asan_attack() {
  cc="$1"; pin="$2"; tag="$3"; idx="$4"
  f="evidence/$tag-asan-attack-$idx.out"
  "./${tag}-asan" attack "$idx" > "$f" 2>&1
  rc=$?
  if [ $rc -ne 0 ] && grep -q 'ERROR: AddressSanitizer' "$f" \
     && grep -q 'WRITE of size 8' "$f" && grep -q 'rawtovcd-vuln.c:130' "$f"; then
    ok "$tag asan attack idx=$idx: OOB WRITE-8 at pinned line 130"
  else
    no "$tag asan attack idx=$idx: rc=$rc"
  fi
}

# Fixed control: same crafted file must be rejected, no sanitizer error.
fixed_attack() {
  cc="$1"; tag="$2"; idx="$3"
  f="evidence/$tag-fixed-attack-$idx.out"
  "./${tag}-asan" attack "$idx" > "$f" 2>&1
  rc=$?
  if [ $rc -eq 0 ] && ! grep -q 'AddressSanitizer' "$f" \
     && grep -q 'bad variable record' "$f"; then
    ok "$tag fixed attack idx=$idx: rejected, clean"
  else
    no "$tag fixed attack idx=$idx: rc=$rc"
  fi
}

safe_lane() {
  tag="$1"; san="$2"
  f="evidence/$tag-$san-safe.out"
  "./${tag}-${san}" safe > "$f" 2>&1
  rc=$?
  if [ $rc -eq 0 ] && ! grep -q 'AddressSanitizer' "$f" \
     && grep -q 'res=1 nvars=2' "$f"; then
    ok "$tag $san safe: in-bounds index 1, clean"
  else
    no "$tag $san safe: rc=$rc"
  fi
}

for cc in gcc clang; do
  build "$cc" rawtovcd-vuln asan "${cc}-vuln-asan"
  build "$cc" rawtovcd-fixed asan "${cc}-fixed-asan"
  build "$cc" rawtovcd-vuln plain "${cc}-vuln-plain" "-DREADBACK=1"
  build "$cc" rawtovcd-fixed plain "${cc}-fixed-plain"
done

for cc in gcc clang; do
  for idx in 2 16 64 -2; do
    asan_attack "$cc" vuln "${cc}-vuln" "$idx"
    fixed_attack "$cc" "${cc}-fixed" "$idx"
  done
  safe_lane "${cc}-vuln" asan
  safe_lane "${cc}-fixed" asan
  safe_lane "${cc}-vuln" plain
  safe_lane "${cc}-fixed" plain
done

# Plain readback: file-chosen index 2, allocator-derived pointer at the OOB slot.
f=evidence/gcc-vuln-plain-readback.out
./gcc-vuln-plain attack 2 > "$f" 2>&1
if grep -q 'slot_bytes=' "$f" && ! grep -q 'slot_bytes=0000000000000000' "$f"; then
  ok 'gcc plain attack idx=2: OOB pointer value read back at chosen slot'
else
  no 'gcc plain attack idx=2: OOB pointer readback'
fi

echo "TOTAL pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
