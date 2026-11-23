# Frontier brief: Snap7 — CVE-2026-131848 (snap72shell)

Staged 2026-11-23 by `frontier` under the standing similar-things mandate.
Operator admission is pending; a live two-pane target window will be registered
with this brief. Nothing here is an independent witness verdict.

## 1. Verified ground truth

- Claim: Snap7 through 1.4.3 has an out-of-bounds write in
  `TSnap7MicroClient::opReadMultiVars()`. A malicious or impersonating PLC
  answers a normal multi-variable read with an unchecked per-item `DataLength`;
  the client `memcpy`s up to 65535 bytes into each caller-supplied item buffer.
  CNA NVD, CVE-2026-131848 / GHSA-xr6p-cjp3-pvwg, HIGH 8.3,
  `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N`, CWE-787,
  published 2026-11-18 (VulnCheck advisory dated 2026-11-17).
- Sources: <https://github.com/advisories/GHSA-xr6p-cjp3-pvwg>,
  <https://www.vulncheck.com/advisories/snap7-through-1.4.3-out-of-bounds-write-via-tsnap7microclient-opreadmultivars>,
  reporter's issue <https://github.com/davenardella/snap7/issues/32> (opened
  2026-08-01 by Mayur021, still open).
- Pinned source: `davenardella/snap7` commit
  `30f37da3114024a71ba93f7fd855c680b97a406f`, the current upstream HEAD
  (2025-07-14 "Add files via upload"). `s7_micro_client.cpp` sha256
  `d42d94c458b6534a1070ee5506ce3f784be3af5bb91de4f88ea4f9dea7c0c486`;
  supporting headers pinned alongside it. Full hashes and URLs in
  `lab/frontier/snap72shell/PROVENANCE.md`.
- **Reopen rationale.** W136 screened Snap7 out as "client-side, no fixed
  version or patch bytes in the advisory." That disposition was correct at the
  time. Issue #32 now supplies an explicit source-bound suggested fix and a
  complete dynamic PoC recipe with an ASan trace; those patch bytes are pinned
  here. No upstream fix commit exists — HEAD is still the vulnerable commit —
  so the fixed control is derived from the reporter's proposed hunk, not from
  an upstream release. This is weaker than an upstream fixed blob and is
  labeled as such wherever it is used.

## 2. Source-bound mechanism and fix

Read from the pinned blob, not from advisory prose. In
`s7_micro_client.cpp::opReadMultiVars()` (pinned lines 307-431):

- Line 400 checks only `ResParams->ItemCount != ItemsCount` — the item **count**.
  No check bounds the per-item **length**.
- Line 413 takes `Slice = SwapWord(ResData[c]->DataLength)` from the response;
  lines 415-416 divide it by 8 unless the server also picks a non-byte
  transport size (`TS_ResOctet`, `TS_ResReal`, `TS_ResBit`). With
  `TS_ResOctet = 0x09`, 65535 passes through unchanged.
- Line 418 is the sink: `memcpy(Item->pdata, ResData[c]->Data, Slice);`.
  `Item->pdata` is the application's per-item destination, sized from the
  caller's `Amount`, not an internal snap7 buffer.
- Line 427 advances `Offset += (4 + Slice)` with the same unvalidated number,
  so after one large item the next iteration's `ResData[c]` header is itself
  read outside the 4096-byte `TIsoPayload`. The `Slice++` at line 425 wraps a
  word at 65535.

The issue's suggested fix (pinned separately, sha256
`a4127166e9274f8fbefbda4f0536ad33808bed7135277ad93593ce02c322b233` as the
generated fixed function slice) bounds `Slice` against both
`IsoSize - (ResHeaderSize23 + sizeof(TResFunReadParams)) - Offset - 4` (bytes
actually received) and `Item->Amount * DataSizeByte(Item->WordLen)` (bytes the
caller allocated), returning `errCliInvalidPlcAnswer` before the copy. The
`MaxDest` bound is the one that ties the peer's number to the caller's object.

## 3. Local experiment and observed bytes

`lab/frontier/snap72shell/harness/run.sh` re-extracts the vulnerable function
verbatim from the pinned blob on every run, builds plain and ASan variants with
gcc and clang, and checks the ladder. Three consecutive runs gave **43 PASS /
0 FAIL**; normalized trace hash
`24c8438c85474ab76ade31d8c9d98e1a510f926b4f97cf6ee8948208427eda59`.

- Rung 1: wire `DataLength = 0xFFFF` yields `SLICE=65535` on the octet path and
  `SLICE=8191` on the byte path, against a caller buffer of `MAXDEST=1` —
  `SLICE_OVER_MAXDEST=65534`.
- Rung 2: the call returns `RC=0` and writes all 65535 bytes through a one-byte
  heap destination.
- Rung 3: gcc **and** clang ASan report `heap-buffer-overflow`, `WRITE of size
  65535`, `0 bytes after 1-byte region`, with the vulnerable frame
  `TSnap7MicroClient::opReadMultiVars()` at pinned line 418.
- Rung 4 (scoped): wire seed `0x5a` puts `DEST0=5a` and `DEST17=6b` in the
  caller's buffer; seed `0x3c` puts `DEST0=3c` and `DEST17=4d`. No stale bytes
  from the previous seed. Negative preserved: only 32 real payload bytes are
  present in the crafted response, so from offset 32 onward the copied source
  is the zeroed PDU buffer (`DEST64=00`) — chosen bytes are demonstrated inside
  the 32 real bytes, not past them.
- Fixed control: the issue's proposed guard returns
  `errCliInvalidPlcAnswer` (`RC=8388608`), leaves the destination untouched, and
  is ASan-clean.
- Safe control: a declared length of 1 returns `RC=0`, writes `0x5a` as sent,
  and is ASan-clean on both vulnerable and fixed builds.

The harness replaces `isoExchangeBuffer()` with a stub that places the crafted
response in `PDU.Payload` and records its length in `IsoSize`, as the real
routine does. No socket, listener, PLC or external host is involved.

## 4. Rung-4 feasibility and honest ceiling at handoff (superseded in §7)

Feasible to rung 4 in the scoped sense: the peer chooses the copy length, the
copy destination is the caller's object, and the first 32 copied bytes are
peer-chosen and land byte-exact at peer-influenced offsets. Ceiling: this is a
**client-side** bug — the attacker must control or impersonate a PLC (the CVSS
`AT:P`), and no live client process was driven over a wire in this wake. The
response is injected by a harness stub, not received from a fake PLC. There is
no pointer redirect, ROP, function-pointer overwrite, command execution or
rung 5. No upstream fixed version or commit exists; the fixed control is a
pinned derivative of a public issue proposal and a witness should treat it as
such. Robustness caveat: the write length is a 16-bit word, so the maximum
single-item overflow is 65535 bytes and the transport-size branch divides it
by 8 for the byte case.

## 5. Cheapest next experiment (completed in §7)

Build the real snap7 library from the pinned commit under ASan and run a
loopback fake S7 server that completes COTP connection setup and Setup
Communication, then answers a `Cli_ReadMultiVars()` request with
`ReturnCode = 0xFF`, `TransportSize = TS_ResOctet`, `DataLength = 0xFFFF` and
only 32 real payload bytes, while the caller requests one one-byte item. Expect
`WRITE of size 65535`, 0 bytes after a one-byte region, in
`opReadMultiVars()` — the same observation as issue #32, but with the crafted
response arriving over a plant-started 127.0.0.1 socket instead of a stub.
Controls: the guarded build and a well-behaved response. Only after that
observation would the remote precondition be measured rather than assumed.

## 6. Candidates researched this wake (not staged)

- Mongoose CVE-2026-63626 (PPP IPv6CP heap overflow, fix `751f1474`) and
  CVE-2026-134171 (IPv6 checksum OOB read, fix `cd05b162`): real upstream fix
  commits, tiny C stack, deterministic packets. Top next candidates.
- mod_auth_openidc CVE-2026-54789 (state-cookie parser, fix `8017478`): a
  three-line loop with a fix-commit unit test. Strong next candidate.
- PJSIP CVE-2026-57160 (generic-array header off-by-one, fix `d6a0e7f7`):
  fixed on master only, no tagged release.
- CTranslate2 CVE-2026-102566 (model loader, fix `d9b991e`): larger C++ build.
- QuickJS-NG CVE-2026-120438 / CVE-2026-120439 remain parked from W136:
  32-bit-host only and this host cannot link `gcc -m32`.
- All exclusion-list targets unchanged; no duplicate lane opened.

## 7. W1 live loopback observation — 2026-11-23 05:23Z

The §5 experiment was completed in `lab/frontier/snap72shell/live/`, not left
as a plan. `run_live.sh` builds the real pinned client under gcc ASan (and a
guarded variant generated from the pinned issue-#32 function), starts a
plant-written fake S7 responder bound only to 127.0.0.1, and replays COTP CR/CC,
S7 Setup Communication and one `Cli_ReadMultiVars()` answer. Two consecutive
runs gave the same normalized trace SHA-256
`1f25bf6311e1a659e4da947abc07d001cfacc5fe39dd67618560e425df3773d4`.

- Attack wire (`ReturnCode=0xFF`, `TransportSize=0x09`, `DataLength=0xFFFF`,
  32 real bytes): the live client connected and ASan reported
  `heap-buffer-overflow`, `WRITE of size 65535`, 0 bytes after a one-byte
  caller allocation, in `opReadMultiVars()` at pinned line 418.
- Guarded build on the same wire returned `errCliInvalidPlcAnswer` (8388608),
  left the destination at `00` and was ASan-clean. The guard is the pinned
  reporter proposal, not an upstream fix.
- Safe one-byte response: both builds returned 0 with `DST0=5a`, ASan-clean.
- Plain vulnerable build with a 200000-byte caller buffer, attack wire:
  `DST0=5a DEST17=6b DEST64=00` — peer-chosen bytes land at offsets 0 and 17
  in the live destination; beyond the 32 real bytes the copied source is the
  zeroed PDU buffer.

Ceiling is now rung 4 **wire-reachable in the lab**: the write is driven by a
plant-started loopback responder into a live pinned client process, not by a
stub injection. It is still not rung 5. Position requires control or
impersonation of a PLC (`AT:P`); there is no pointer redirect, command or
observed command side effect, and no upstream fixed release. Hashes, exact
frames, ASan reports and both replay transcripts are in `PROVENANCE.md` and
`live/evidence/`.
