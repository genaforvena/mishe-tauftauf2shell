# Frontier brief: ytnef `DecompressRTF()` wrapped prebuffer overflow — GHSA-jhg4-xcxm-cfg6 (ytnef2shell)

Status W127 (2026-11-22): screened in and measured at rung 3 (ASan-confirmed
heap out-of-bounds write in a verbatim pinned function) plus a scoped rung 4
(attacker-chosen overrun length lands fixed RTF prebuffer bytes at chosen
offsets past a shortened allocation, direct-call/stub scope). Duplicate check
before provisioning: no prior `reports/frontier-*ytnef*`, no ytnef window,
charter or mind on the tape, and ytnef is absent from the do-not-duplicate list
in `walls/frontier.md`. Related but distinct claims: CVE-2026-111145 /
CVE-2026-111146 and public issue #112 are read bugs also fixed in 2.1.3; this
brief's primary primitive is the compressed-stream allocation wrap and
207-byte prebuffer write. FRR CVE-2026-129217 (OOB read, established peer),
sblim-sfcb (no upstream fix) and Mosquitto (already owned) were ranked below
this candidate. The operator owns final admission; wake units and full-flag
sync stay with the person.

## 1. Verified ground truth

- Claim: GHSA-jhg4-xcxm-cfg6, "Heap buffer overflow and out-of-bounds read in
  `DecompressRTF()` via crafted TNEF (winmail.dat)", published 2026-11-20 by
  maintainer Yeraze; HIGH; CWE-190/CWE-122 for the write and CWE-125 for the
  read; **no CVE ID assigned at publication**. Affected `<= 2.1.2` (advisory
  also names master `5b24cfc`, not fetched here); patched `2.1.3`.
- Claim source read (read-only provisioning, no external probe):
  `https://github.com/Yeraze/ytnef/security/advisories/GHSA-jhg4-xcxm-cfg6`
  and the oss-sec announcement at `https://seclists.org/oss-sec/2026/q4/802`.
  Source pins fetched read-only from `https://github.com/Yeraze/ytnef.git`:
  `v2.1.2` = `d9f08914`, `v2.1.3` = `f0ccad7d`.
- Primitive claimed: for a compressed (LZFu) stream the 32-bit
  `uncompressedSize` comes from the stream. The guard
  `comp_Prebuf.size >= INT_MAX - uncompressedSize` is evaluated in unsigned
  arithmetic and passes for sizes near `0xFFFFFFFF`; `calloc(comp_Prebuf.size
  + uncompressedSize, 1)` then wraps to a small allocation while the following
  `memcpy` copies the fixed 207-byte RTF prebuffer. The advisory claims a
  1..207-byte overrun with **attacker-chosen length and fixed content**. The
  uncompressed (MELA) branch separately `memcpy`s `uncompressedSize` bytes from
  `src + 4` without checking the property size.
- Reachability claim (unverified here): any email sender can reach the sink in
  software that parses TNEF with libytnef; `ytnefprint` reaches it via
  `MAPIPrint()`, `ytnef` via `SaveVCalendar()` on appointment/meeting-request
  messages even with `+F`; the `ytnefprocess` procmail hook is claimed to reach
  it on delivery with no user action. The advisory claims DoS, not RCE.

## 2. Source-bound mechanism and fix

Vulnerable pin `d9f08914`, `lib/ytnef.c` inside `DecompressRTF()`:

```c
comp_Prebuf.size = strlen(RTF_PREBUF);            /* 207 on this host */
...
if (comp_Prebuf.size >= INT_MAX - uncompressedSize) { ... return NULL; }
dst = calloc(comp_Prebuf.size + uncompressedSize, 1);
memcpy(dst, comp_Prebuf.data, comp_Prebuf.size);
out = comp_Prebuf.size;
```

`BYTE`, `DWORD` and `ULONG` are `unsigned char` / `unsigned int` in the pinned
`lib/tnef-types.h`; `INT_MAX - 0xFFFFFF41` therefore wraps to `0x800000BE`
(mod 2^32), the guard passes, and `207 + 0xFFFFFF41` wraps to `16`. The pinned
`calloc` is 16 bytes; the pinned `memcpy` writes 207 bytes, so 191 bytes land
past the allocation. Choosing `uncompressedSize` from `0xFFFFFF31` through
`0xFFFFFFFF` selects a wrapped allocation of 0 through 206 bytes and an
overrun of 207 down to 1 byte; the written bytes are the first N bytes of the
fixed `RTF_PREBUF` macro.

Fixed pin `f0ccad7d` changes the relevant lines:

```c
unsigned int prebufSize = strlen(RTF_PREBUF);
...
if (uncompressedSize >= INT_MAX - prebufSize) { ... return NULL; }
dst = calloc(prebufSize + uncompressedSize, 1);
memcpy(dst, RTF_PREBUF, prebufSize);
```

and adds a property-size check to the MELA branch, sets `*size`, and rejects
NULL property data. The saved fix diff is
`lab/frontier/ytnef2shell/src/fix-2.1.3.patch` (sha256 `e158ff7b...`).

## 3. Local reproduction — observed bytes

Harness `lab/frontier/ytnef2shell/harness/run.sh` (full pin hashes, input
table and instrumentation boundary in that directory's `PROVENANCE.md`).
The `RTF_PREBUF` define, `SwapDWord()` and `DecompressRTF()` are **verbatim**
from each pin and re-extracted and asserted on every run.

- **240 PASS / 0 FAIL twice**, gcc and clang, two pins, 72 normalized evidence
  logs. Path-independent concatenated content hash
  `a2819d82cc5fdf23c88ee65fc4d8eb08a48fe01be80afa092fdf37ac43bce639`.
- Vulnerable pin, `uncompressedSize = 4294967105 (0xFFFFFF41)`, 20-byte input:
  `ERROR: AddressSanitizer: heap-buffer-overflow`, `WRITE of size 207`,
  `0 bytes after 16-byte region`, frame `DecompressRTF`; pinned allocation in
  the same frame. `0xFFFFFF31` gives a 1-byte ASan region (zero-size request)
  and `0xFFFFFFFF` a 206-byte region; each still reports a 207-byte write.
- MELA control on the vulnerable pin: `READ of size 64`, `0 bytes after
  20-byte region`, frame `DecompressRTF`.
- Fixed pin on all four attack cases: rc 0, `Corrupted file`, no ASan report,
  no allocation in the plain arena. A well-formed 8-literal LZFu stream is
  clean on both pins (`OUTSIZE=8`) and its plain-arena sentinel is intact.
- Plain-mode chosen-length readback with a `0xEE` sentinel: `ALLOC=16
  OVERRUN=191 B0=64 BMID=6f BEND=78 TAIL=ee`, `ALLOC=0 OVERRUN=207 B0=7b
  BMID=65 BEND=78 TAIL=ee`, and `ALLOC=206 OVERRUN=1 B0=78 BMID=78 BEND=78
  TAIL=ee` on the vulnerable pin. `B*` are the fixed prebuffer bytes at the
  chosen offsets; `TAIL` is the first untouched sentinel byte. Fixed pin:
  `ALLOC=none OVERRUN=0 TAIL=ee`.

## 4. Honest grade and what is *not* established

- **Rung 1 (reproducible trigger)**: yes, deterministic direct call with a
  scripted 20-byte stream header.
- **Rung 2 (state failure)**: yes, the pinned guard passes while the wrapped
  allocation is 16/0/206 bytes and the copy count stays 207; the plain arena
  records the exact mismatch, and the fixed pin rejects before allocating.
- **Rung 3 (confirmed corruption)**: yes, ASan heap-buffer-overflow write in
  the verbatim vulnerable function with clean fixed pin and safe control.
- **Rung 4 (scoped)**: yes, in the direct-call/stub sense — the attacker
  chooses the wrapped allocation size (1..207-byte overrun) and therefore the
  destination offsets of fixed prebuffer bytes. This is **not** a real TNEF
  parse, a real libytnef allocator layout, an adjacent object corruption, a
  pointer control, or a benign marker execution. Content bytes are fixed by
  the pinned prebuffer, not chosen by the attacker.
- **Rung 5**: not attempted and not implied. No ytnef build, TNEF blob, mail
  client, procmail hook, listener or command. The advisory's reachability and
  DoS claims stay claims. The MELA read has no leak-back channel here.

Known limits: the harness uses a 20-byte input rather than a full property or
TNEF file; the plain build renames only the verbatim function's `calloc`/
`free` to a static arena, so the OOB destination is an artificial slot, not a
glibc chunk; the stream header is synthesised directly rather than parsed
from a TNEF map; the advisory's "CVE pending" status may change after
publication.

## 5. Cheapest next rung-moving experiment

Build ytnef `v2.1.2` with ASan and feed it a real `winmail.dat` whose
`PR_RTF_COMPRESSED` property holds a compressed stream with
`compressedSize = property_size - 4`, `uncompressedSize = 0xFFFFFF41`, magic
`0x75465a4c`, then run `ytnefprint` (or `ytnef +F` on an appointment message)
over that local file. Expect the same ASan report at the real prebuffer
`memcpy`. With a non-ASan build, groom an adjacent chunk and read back the 191
bytes past the undersized allocation to see whether fixed prebuffer bytes
reach a glibc header or a neighbouring object. Fixed `v2.1.3` and a
well-formed RTF property are mandatory controls. This is local file parsing;
no external system or network is needed.

## 6. Disposition

Staging to a dedicated `ytnef2shell` mind is in progress in W127 (brief,
harness and pins committed first; charter, seed wall, two-pane inner window,
registry entry and DMs to follow in this wake). The window will already exist;
do not create another. Until operator admission this is a staged candidate,
not an admitted target.
