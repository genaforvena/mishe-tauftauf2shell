libfontenc2shell W183 — chosen-byte overwrite of a LIVE parser object pointer
(2026-11-24)

New result at the real-library public-API boundary. Earlier W181 wrote a
contiguous identity ramp past the 131072-byte enc buffer into wilderness; this
experiment writes chosen 16-bit words at chosen OOB offsets AFTER a live
FontEncSimpleMapRec has been allocated, and overwrites its `map` data pointer
with an entirely attacker-chosen 64-bit value. A subsequent public
FontEncRecode() call reads through that redirected pointer and returns an
attacker-chosen word.

Mechanism
---------
setCode() (build-vuln/src/encparse.c:452-496) sizes the map at 0x10000 entries
(131072 bytes) but accepts index = (from >> 8) * row_size + (from & 0xFF) with
from up to 0xFFFF and row_size from SIZE. With SIZE 256 258:
  0xff00            -> index 65790  -> offset +508 bytes past the region
  0xfe10 .. 0xfe13  -> index 65548..65551 -> +24..+30 bytes past the region
The chosen store is at :495. Each mapping's first CODE call resets first/last,
so there is no identity ramp: exactly one chosen 2-byte store per mapping.

parseEncodingFile() allocates `sm` (FontEncSimpleMapRec, 16 bytes) and its
compact `newmap` at ENDMAPPING (:641, :650). With MALLOC_MMAP_THRESHOLD_=262144
the 131072-byte buffer and those objects share the brk heap. Layout in the
setarch -R runner (ASLR disabled), inferred from the store addresses and the
probe output:

  enc buffer      = 0x555555562560   (131072 bytes, ends 0x555555582560)
  mapping2's sm   = 0x555555582570   (+16 past the buffer)
  sm->map field   = 0x555555582578   (+24 past the buffer)
  target word     = 0x55555558257a   (+26 past the buffer)

gdb-layout.txt records the same stores under gdb; the debugger environment
shifts every allocation 0x10 lower, so gdb sees the field at 0x555555582568
and the marker at 0x55555558274c. The offsets relative to the buffer are
identical; the hardcoded words in crafted.enc target the setarch -R runner.

mapping2's sm and newmap already exist when mappings 4-7 perform their stores.
The four stores at indices 65548..65551 replace all four 16-bit halves of
sm->map. In crafted.enc the replacement value is 0x000055555558257a, i.e.
+26 past the buffer, a location holding the chosen word 0x5558 that was also
written by one of those stores. The mapping-2 map pointer starts at
0x555555582590 with map[0] = 0x1111; after the overwrite it is
0x55555558257a and FontEncRecode(254, mapping2) returns 0x5558 (21848).

Inputs and controls
-------------------
crafted.enc: SIZE 256 258; seven mappings; words 0x1111, 0xdead, 0x257a,
0x5558, 0x5555, 0x0000 chosen at the OOB offsets above.
safe.enc: same seven mappings with SIZE 256 256, all indices in bounds.
Library builds: vulnerable parent 7418fa7 and fixed 5920c6e, real pinned trees
under lab/frontier/libfontenc2shell/build-* (see realpath/rebuild.sh).

Observed (run.sh output files in this directory)
------------------------------------------------
vuln-crafted.txt   mapping2 map=0x55555558257a, map0=recode=21848 (0x5558);
                   mapping3 unchanged at map=0x555555582610, map0=57005
                   (0xdead). No crash.
vuln-safe.txt      mapping2 map=0x555555562570, map0=recode=4369 (0x1111);
                   no pointer change.
fixed-crafted.txt  every out-of-range mapping rejected; map=(nil), len=0,
                   recode=0. No corruption.
vuln-asan-crafted  ASan heap-buffer-overflow, WRITE of size 2 at
.txt              setCode ../src/encparse.c:495, 508 bytes after a 131072-byte
                   region allocated by reallocarray at :477, frames through
                   FontEncFind:738 -> main.

Reproduce: sh realpath/evidence/ptrctrl/run.sh from the repository root. The
script needs the build-* trees provisioned by realpath/rebuild.sh.

Grade limit
-----------
This is rung 4 at the REAL library public-API boundary: chosen bytes at chosen
offsets, complete partial-to-full control of one live object's data pointer,
and an observed read through that pointer. It is NOT rung 5. ASLR is disabled
with setarch -R and MALLOC_MMAP_THRESHOLD_=262144 is set to keep the object
layout fixed; the chosen pointer value is an absolute heap address, so under
normal ASLR the redirect target is not stable. No saved return address,
control-flow diversion, shellcode, marker execution, command, X server
process, wire input or privileged context was exercised. The redirected
object is a parser-internal map used by FontEncRecode, not a function pointer.
Keep the grade as: live ASan rung 3; rung 4 chosen-store and now live-object
pointer control under a fixed layout; rung 5 UNKNOWN.
