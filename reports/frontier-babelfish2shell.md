# Frontier brief — Babelfish TDS prelogin heap overflow (Babelfish2Shell)

**Status: new frontier find, handed off to the operator 2026-11-20 ~22:1xZ for
admission (standing approval #6). Rungs 1/2/3 ESTABLISHED and sender-chosen
bytes at sender-chosen offsets observed in an extracted, source-bound harness;
the harness grade for rung 4 is CHOSEN-BYTE CONTROL IN THE EXTRACTED HARNESS,
NOT a live process or real-allocator demonstration. Live Babelfish process,
real TDS endpoint, heap layout, neighbouring objects and any control-flow
hijack are UNKNOWN. Two-pane window `babelfish2shell` (inner socket), seed
wall, registry entry and witness/operator DMs were filed with the handoff;
wake trigger units and the presentation entry are owed from the person's
full-flag sync.**

## Verified ground truth (claim sources + this lab, 2026-11-20)

- **Advisory**: CVE-2026-119923, "Heap-based Buffer Overflow in Babelfish for
  PostgreSQL TDS Prelogin Parser" (CNA Amazon, published 2026-11-06),
  GHSA-vq28-vgj3-r26w (published 2026-11-07), AWS bulletin 2026-166-AWS.
  Critical **9.8**, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (CVSS 4.0
  9.3), **CWE-122**. Claim: a remote, unauthenticated actor sending a crafted
  TDS prelogin packet to the TDS port (default 1433) can corrupt process
  memory; the CVE record claims arbitrary OS commands as the database process
  user, which is a claim, not a demonstration.
- **Affected**: Babelfish for PostgreSQL extension 1.0-1.5, 2.1-2.15,
  3.1-3.12, 4.0-4.8, 5.1-5.4, plus Amazon Aurora PostgreSQL with Babelfish.
  **Fixed**: extension 4.10, 5.6, 6.1 or later.
- **Fix commit**: `ab820bddaffa540af82f2f689c3e535f82f14d89` ("[OSS-ONLY]
  Minor fixes and improvements in TDS and PL/tsql handling (#4955)",
  2026-08-26) on the 4.x line; backports `66fe10002e37` (5.6) and
  `f0b8bd54aad1` (6.1). Vulnerable tag read: `BABEL_4_8_0`; fixed tag read:
  `BABEL_4_10_0`.
- **Claim sources read**: CVE record, GHSA advisory, AWS bulletin, GitHub
  Advisory Database and OSV mirrors, fix commit `.patch`, and raw source at
  the two exact tags plus PostgreSQL `REL_16_STABLE/src/common/stringinfo.c`.
  Full URLs, SHAs and line facts in
  `lab/frontier/babelfish2shell/PROVENANCE.md`. Read-only provisioning only;
  **no probe, connection or traffic to any non-loopback system**.
- **OSV caution preserved**: OSV's GIT range endpoints (`86c24eb5...`,
  `a2ab3b3d...`) are CI-only commits in the packaging repo, not code fixes.
  They were read, rejected as fix evidence, and the real fix was located by
  listing commits touching `tdslogin.c` at the patched tag.
- **Scope separation**: this is a different codebase and wire protocol from
  the already-owned postgres2shell lane (FDW `ExecBatchInsert` slot OOB).
  Babelfish is AWS's TDS wire-protocol extension in C; the defect is in its
  prelogin handshake parser. It is also distinct from CVE-2026-119924 (an
  authenticated RPC procedure-name OOB read in the same repo).
- **Ranking**: high tractability. The defect is a single missing buffer
  resize in one C function; the input is the first unauthenticated packet on
  the TDS port; the copied bytes are sender-chosen, so unlike the GStreamer
  constant-write finding a chosen-byte claim is in reach. No groom, credential
  or protocol state is needed for rungs 1-3. Ranked above the screened-out
  lanes on the wall.

## Source-bound mechanism (read from the fix, not inferred)

Line numbers are from the exact provisioned vulnerable tag
(`tdslogin.c.BABEL_4_8_0`) unless marked fixed.

1. `:193-200` — `PreLoginOption` carries `uint16_t offset`, `uint16_t length`
   and an inline `StringInfoData val`.
2. `:342-363` — `ParsePreLoginRequest()` allocates each option with `palloc0`,
   reads the token (1 byte), then `offset` and `length` as network-order
   16-bit values from the wire, then calls `initStringInfo(&temp->val)`. There
   is no upper bound on `length` (wire maximum 65535).
3. PostgreSQL `initStringInfo` (`stringinfo.c.REL_16_STABLE`) does
   `int size = 1024; str->data = palloc(size); str->maxlen = size;` — a fixed
   1024-byte allocation.
4. `:377-383` — after the 0xFF terminator, the loop calls
   `TdsGetbytes(prev->val.data, prev->length)` for each option. `TdsGetbytes`
   (`tdscomm.c.BABEL_4_8_0:634-659`) `memcpy`s `min(LeftInPacket, len)` bytes
   in a loop until `len` is exhausted. `val.data` is never enlarged, so a
   `length` above 1024 writes past the 1024-byte allocation.
5. The fix (`ab820bdd`, tdslogin.c hunk) rejects `length >
   TDS_DEFAULT_INIT_PACKET_SIZE` (4096, `tds_int.h:50`) and resizes with
   `resetStringInfo` + `enlargeStringInfo(&prev->val, prev->length)` before
   the copy, then sets `val.len` and NUL-terminates. It also adds the
   no-options NULL-deref guard, an ENCRYPTION-option length check and login
   offset/bounds checks (the consolidated NULL-deref finding).

**Value control**: the overflow bytes are the sender's packet bytes, copied
verbatim. The attacker controls both the count (`length`) and the values. This
is the opposite of the GStreamer finding, where only the constant zero was
written; it is the reason rung 4 is graded as chosen-byte control here.

## Local harness evidence

Files: `lab/frontier/babelfish2shell/{prelogin_overflow.c,run.sh}` plus
`PROVENANCE.md` and `src/`. Pins at the named tag:
`c5559f0836fb42b10896233eac4668bccb3bf98f77749e2bf6df0ed588005102` (C) and
`d4b09e8cd60adbc9ff591a95a5177e63782e95ecc12f676236f4251e5595a988`
(run.sh). `bash lab/frontier/babelfish2shell/run.sh` printed **ALL CHECKS PASS,
rc 0**:

- **Rung 1 (reproducible trigger)**: `token=0x02 length=4096 si_capacity=1024
  oob_writes=3072 first_oob=1024 last_oob=4095`, wire header
  `02 00 00 10 00 ff`, `verdict=TRIGGER`. The 6-byte header models token,
  network-order offset/length and the terminator; the payload follows.
- **Rung 2 (observed state failure)**: with neighbour stamps at destination
  offsets 1100 and 2000, `L=1050` (26 OOB bytes) clobbers neither, `L=1150`
  (126 OOB bytes) clobbers the first only, `L=2100` (1076 OOB bytes) clobbers
  both — `verdict=LENGTH_CONTROL_OBSERVED`. The declared length chooses which
  offsets are reached.
- **Rung 3 (ASan-confirmed corruption)**: gcc 13.3.0, `-fsanitize=address`,
  exact 1024-byte allocation, `length=4096`: `ERROR: AddressSanitizer:
  heap-buffer-overflow`, `WRITE of size 4096`, `0 bytes after 1024-byte
  region`, stack `wire_getbytes (prelogin_overflow.c:74) <- mode_rung3 (:319)
  <- main`, rc 1.
- **Rung 4 (chosen bytes at chosen offsets)**: packet bytes `de ad be ef ca
  fe ba be` at destination offset 1100 and `41 42 43 44` at offset 2000 read
  back byte-for-byte; `chosen_bytes_written=12 offsets_exact=1
  value_source=wire_packet`, `verdict=CHOSEN_BYTES_AT_CHOSEN_OFFSETS`.
- **Fixed control**: the `ab820bdd` behaviour (cap 4096, `enlargeStringInfo`)
  with the same `length=4096` gives `rc=0 oob_writes=0 verdict=PASS`, and the
  fixed path under ASan is clean (`fixed_asan rc=0`, no sanitizer report).
- **Determinism**: two independent 5-run groups hash to the same
  `sha256=e216eeeccd591787a5305b58a3e0ac8097bc59ecbba9e5ffca21efebc712895d`.

### Grade

Rungs **1/2/3 ESTABLISHED** in the extracted harness; rung **4 shows
sender-chosen bytes at sender-chosen offsets in that harness** (not merely a
length-controlled write of a constant), but **no live-process demonstration**:
no real Babelfish/PostgreSQL process, TDS endpoint, real palloc/heap layout,
real neighbouring object, pointer control or marker execution was observed.
The consumer-reality check from the plant's nginx lesson is still owed: the
real `TdsGetbytes` copies into a PostgreSQL palloc chunk whose actual usable
size and adjacent allocation must be measured before any rung-4 claim on a
stock build. This is a claim for the witness to replay, not acceptance.

## Cheapest local experiment to move it up a rung

1. Build Babelfish 4.8 + its patched PostgreSQL 16 with ASan on loopback,
   connect a raw TDS client to 127.0.0.1:1433 and send a prelogin packet with
   `length=4096` and a marked payload. Confirm the real `info->val.data`
   allocation is 1024 bytes, observe the ASan WRITE past it, and record which
   genuine palloc neighbour is clobbered. This converts the extracted struct
   into the live one and resolves the allocator-layout UNKNOWN.
2. For a live rung 4, groom or identify a real neighbouring field whose
   overwriting by chosen packet bytes gives a useful effect (length, hook,
   free-function pointer). Keep value-control claims separate from any
   pointer-control or execution claim; the latter is NOT established here.
3. Re-run the same packet against 4.10 with the same harness to confirm the
   cap + resize removes the fault on a stock patched build.

## Handoff state

Two-artifact rule satisfied at handoff: this brief is committed, and a live
two-pane window named `babelfish2shell` (top: seed wall/brief, bottom: chat and
wake log) exists on the inner tmux socket, with a `kind:target` entry in
`operator/window-registry.json` and a seed wall at
`.mishe-tauftauf/walls/babelfish2shell.md`. Witness replay request and operator
admission DM were filed on the tape; the latter states the window already
exists. Owed by the operator/person: charter, docs/task.md entry and wake
trigger units (only via the person's full-flag sync, never a bare
`mishe sync`). Do not duplicate this lane; it belongs to its new mind.

## What would change my mind

A primary source showing the prelogin `length` is bounded before
`TdsGetbytes`, a clean witness replay losing the ASan WRITE or the chosen-byte
read-back, a fix commit without the `enlargeStringInfo` hunk, or proof that a
real stock build's `initStringInfo` allocation is larger than 1024 bytes.
