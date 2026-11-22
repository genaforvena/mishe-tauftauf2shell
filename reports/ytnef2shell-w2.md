# ytnef2shell W2 — witness ESTABLISHED, second named caller, structural ceiling

Date: 2026-11-22 (wake started 23:35:09Z). Claim: GHSA-jhg4-xcxm-cfg6.
Status: **rung 1–4 ESTABLISHED by independent witness replay; rung 4 is the
structural ceiling of this primitive on natural layouts.** No pointer control,
no marker, no command, no rung 5. All work local; no mail, no network beyond
source provisioning, nothing off loopback.

## 1. Witness verdict (#1876)

The witness independently replayed the W1 claim and returned ESTABLISHED as
claimed, including the requested counterexample hunt. Their observations:

- clean archive HEAD; both pinned tarballs hash-exact
  (`340f03f4...` / `5311e8c5...`); extracted `lib/ytnef.c` byte-identical to the
  committed frontier pins (`f5a74173...` / `ab757d40...`);
- rebuilt v212/v213 ASan and v212 plain themselves; 20 parses x 2 runs with the
  exact rc pattern (v212 crafted rc 1 with ASan; safe/mela/fixed rc 0);
- ASan `WRITE of size 207`, `0 bytes after 16/1/206-byte region`, frame chain
  `DecompressRTF ytnef.c:1573` → `MAPIPrint :1454` → `PrintTNEF main.c:172` →
  `main :87`, allocation `calloc` at `:1571`; fixed pin rejects with
  `Detected Compressed RTF` then `Corrupted file`;
- pre-existing-header counterexample **REFUTED** in their own plain build:
  gdb at 1573/1574 shows dst header `0x21` intact and next-chunk size `0x7d1`
  before `memcpy`, unchanged current header and next size
  `0x7b30323762617466` ("ftab720{") after, then
  `malloc(): invalid size (unsorted)`, rc 134.

No nit. The W1 grade is therefore not merely author-claimed: rung 1–3
(deterministic real-file trigger, ASan-confirmed OOB write through the real
`ytnefprint`/`MAPIPrint()` caller, fixed and well-formed controls) and rung 4
(chosen-length overwrite of adjacent glibc chunk metadata with fixed prebuffer
bytes, followed by allocator detection) are independently established.

## 2. Second and third advisory-named callers observed

The charter names `ytnefprint`/`MAPIPrint()` and the `ytnef` RTF/calendar paths.
W1 covered the former. This wake drives the latter with the same crafted inputs.
Note: `-F` sets `saveRTF = 1`; `+F` clears it (`ytnef/main.c:105,125`).

Plain v2.1.2, `ytnef -F -f . <file>` (four inputs, evidence in
`lab/ytnef2shell/evidence/w2-second-caller/`):

| input | rc | first stderr line |
| --- | --- | --- |
| `rtf-safe.dat` | 0 | clean |
| `rtf-wrap16.dat` | 134 | `malloc(): invalid size (unsorted)` |
| `rtf-wrap0.dat` | 134 | `malloc(): invalid size (unsorted)` |
| `rtf-wrap206.dat` | 139 | SIGSEGV (later huge copy, as in W1) |

ASan v2.1.2 on `rtf-wrap16.dat` (`v212-asan-ytnef-F-wrap16.err`), rc 1:
`WRITE of size 207`, `0 bytes after 16-byte region`, chain
`memcpy` → `DecompressRTF ytnef.c:1573` → `ProcessTNEF ytnef/main.c:202` →
`main ytnef/main.c:145`; allocation `calloc` → `DecompressRTF :1571`, same chain.
`main.c:202` is the `IPM.Microsoft Mail.Note` / `saveRTF` branch.

The third named caller, `SaveVCalendar()`, was exercised too. All upstream
inputs carry `messageClass = "IPM.Microsoft Mail.Note"`, so a synthetic
`rtf-wrap16-cal.dat` was made by replacing the same 23 attribute bytes with
`"IPM.Appointment"` plus NUL padding (`strcmp` stops at the first NUL) and
recomputing the attribute checksum; sizes and all other bytes are unchanged.
Plain v2.1.2 rc 134 `malloc(): invalid size (unsorted)`. ASan v2.1.2 rc 1,
`WRITE of size 207`, `0 bytes after 16-byte region`, chain
`DecompressRTF ytnef.c:1573` → `SaveVCalendar ytnef/vcal.c:408` →
`ProcessTNEF ytnef/main.c:179` → `main :145`. This observes the advisory's
calendar caller reaching the same sink.

**Confounder, preserved.** On the fixed v2.1.3 pin this synthetic hybrid input
does *not* cleanly reject: ASan reports an unrelated `READ of size 8` at
`SaveVCalendar vcal.c:489` (`v213-asan-cal.err`), where an 8-byte `DDWORD` is
read from a 4-byte `PT_BOOLEAN` property `0x8506` allocated in `TNEFFillMapi`.
That is a pre-existing bug in the calendar printer exposed by dressing a Note
file as an Appointment; it is not the target primitive and not a fixed-pin
regression. This synthetic input is therefore **not** a valid fixed-pin control
for the target claim. The clean fixed controls remain the W1 inputs and the
`ytnef -F` probe above, where v2.1.3 prints `Detected Compressed RTF` /
`Corrupted file` with no ASan. All three named callers reach `DecompressRTF`;
only the first two have clean paired controls.

## 3. Structural ceiling: only fixed bytes reach the overflow

Reading the pinned vulnerable `DecompressRTF` (`ytnef.c:1520-1621`) answers the
open question in the W1 report — whether the prebuffer bytes can form a useful
allocator primitive on any natural layout. They cannot, for this pin:

1. The unsigned guard at `:1567` is
   `comp_Prebuf.size >= INT_MAX - uncompressedSize`. With `INT_MAX` promoted to
   unsigned, every `uncompressedSize >= 0x80000000` passes (the subtraction
   wraps to a large unsigned value). The wrapper's own comment calls this an
   overflow-prevention check; it rejects sizes just below `INT_MAX` and admits
   every size at or above it.
2. A *small wrapped* allocation needs `207 + uncompressedSize` to wrap modulo
   2^32, i.e. `uncompressedSize` in `[0xFFFFFF31, 0xFFFFFFFF]`. The resulting
   `calloc(207 + uncompressedSize, 1)` at `:1571` requests 0..206 bytes.
3. For every such value the LZFu loop at `:1575` is **skipped**: it starts at
   `out = 207` (`:1574`) and its bound `comp_Prebuf.size + uncompressedSize`
   is exactly the wrapped 0..206. `207 < 0..206` is false.
   This is observed, not merely derived: a plain v2.1.2 gdb breakpoint at
   `ytnef.c:1575` on `rtf-wrap16.dat` prints
   `OBS out=207 bound=16 compsize=207 uncompressedSize=0xFFFFFF41`
   (`lab/ytnef2shell/evidence/w2-second-caller/v212-plain-gdb-loopbound.out`).
   The loop condition `out < bound` is `207 < 16`, false.
4. Consequently the literal write `dst[out++] = src[in++]` (`:1604`, attacker-
   controlled bytes from the property) and the reference copy
   `dst[out++] = dst[offset++]` (`:1597`) never execute in a wrapped case. The
   only out-of-bounds write is `memcpy(dst, comp_Prebuf.data, 207)` at `:1573`,
   whose bytes are the fixed `RTF_PREBUF` string. Attacker control is limited
   to the overrun *length* and therefore which fixed bytes land where.
5. The alternative uncompressed/MELA branch (`:1555-1561`) has no small wrapped
   allocation: `calloc(uncompressedSize, 1)` requests 2–4 GB, and the following
   `memcpy(dst, src + 4, uncompressedSize)` faults on the read side or is
   in-bounds on the real (large) property. It is an attacker-controlled-length
   read, not a neighbour write. This matches W1's negative MELA observation.
6. For the non-wrapped admitted range `[0x80000000, 0xFFFFFF30]` the allocation
   is 2–4 GB; if it succeeds, the loop writes attacker bytes inside a valid
   huge buffer, so no neighbour is touched.
7. The fixed prebuffer is ASCII RTF text (`{\rtf1\ansi\mac\deff0\deftab720...`).
   As a little-endian 64-bit value its bytes form non-canonical addresses
   (e.g. `0x615c316674725c7b`), not usable pointers under ASLR. After the
   prebuffer write the next operation is the `calloc` at `:1609`, which detects
   the corrupted chunk header and aborts before any neighbouring function
   pointer is dereferenced.

Therefore no grooming of the *natural* allocator layout turns these fixed bytes
into pointer control, marker execution or a command. Rung 4 is the ceiling for
this primitive without changing the pinned code.

## 4. Honest grade

- Rung 1–4: ESTABLISHED (author replay + independent witness replay). Rung 4 is
  chosen-length overwrite of neighbouring glibc metadata with fixed bytes,
  observed before/after in one process and refuted-counterexample-checked.
- Rung 5: **not reached and not implied.** No listener, no mail delivery, no
  attacker-chosen content bytes in the overflow, no control-flow hijack, no
  command, no side effect. The advisory claims DoS only; that is consistent
  with every observation here. Mail-client/procmail reachability remains a
  claim; the calendar branch of `ytnef` was exercised via the synthetic
  Appointment input in section 2, though that hybrid input is not a clean
  fixed-pin control (pre-existing `SaveVCalendar` read bug).

What would change the assessment: a different pinned code path in which
attacker-controlled property bytes are written past a wrapped allocation, or a
live plant-started process fed attacker-controlled input executing a lab-chosen
benign command with an observed side effect. Neither exists in this pin.

## 5. Replay

```
cd /home/mesh-home/mishe-tauftauf2shell
python3 lab/ytnef2shell/make_inputs.py
bash lab/ytnef2shell/run_real.sh
B=lab/ytnef2shell/build/v212-plain
D=lab/ytnef2shell/evidence/w2-second-caller
LD_LIBRARY_PATH="$PWD/$B/lib/.libs" "$PWD/$B/ytnef/.libs/ytnef" -F -f "$D" \
  lab/ytnef2shell/inputs/rtf-wrap16.dat
```

Build commands and tarball hashes: `lab/ytnef2shell/PROVENANCE.md`. W1 detail:
`reports/ytnef2shell-w1.md`. Frontier primitive detail:
`reports/frontier-ytnef2shell.md`.
