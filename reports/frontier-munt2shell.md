# Frontier brief: libmt32emu oversized-SysEx heap write — munt issue #149 (munt2shell)

**STAGED 2026-11-23 W159** — this brief, a direct-call rung-1..4 harness and a
live registered two-pane window (inner socket index 119, name `munt2shell`) all
exist; seed wall `.mishe-tauftauf/walls/munt2shell.md`, registry entry and
staging DM #2682 are in place. Independent witness replay (chat #2781) is
ESTABLISHED at the labeled real-library rungs 1-4, not rung 5; operator
admission and presentation activation remain owed. No CVE or GHSA number was
found for this issue: **UNKNOWN**.
Byte-exact pins and hashes: `lab/frontier/munt2shell/PINS.sha256`; harness
provenance including stubs, negatives and commands:
`lab/frontier/munt2shell/PROVENANCE.md`. Frontier owns no further work on this
target.

## 1. Verified ground truth

- Source claim: public GitHub issue https://github.com/munt/munt/issues/149,
  "munt (libmt32emu): heap out-of-bounds write in the MIDI stream parser on an
  oversized SysEx message", opened 2026-11-01 by @Haind03, closed 2026-11-05.
  CWE-787 / CWE-122 / CWE-131 claimed by the reporter. The issue explicitly
  says the finding came from static source review: no PoC, build, crash or
  runtime observation was claimed there. Treated as a claim, reproduced here.
- Affected: library tag `libmt32emu_2_8_3` (reporter calls it the latest release
  at 2026-06-06) and the code on dev/master at review time. Pinned vulnerable
  source is the raw file at that tag (commit object `008feb32227a`, raw
  `mt32emu/src/MidiStreamParser.cpp` sha256
  `0d9424e07eb9718ea4aafd...ef785810814753e213f20`).
- Fix: upstream commit `1749f7fed5cdb3a9015acce076a1512b1615dc3b`
  (2026-11-02T18:07:20Z, "mt32emu: Fixed heap buffer overflow in
  `MidiStreamParserImpl::parseSysex` (#149)"), with unit tests. The patched
  source at that commit hashes `6031e579d0777276ff49f1be0afec5c...108612268cf0c3a`.
  Both library tag `libmt32emu_2_8_4` and application tag `munt_2_8_4` contain
  the fix hunk (verified from raw source at both tags). Note the two tag
  namespaces differ: raw `MidiStreamParser.cpp` at `munt_2_8_3` already contains
  the fix; the vulnerable release tag named by the issue is the **library**
  tag `libmt32emu_2_8_3`. This discrepancy is recorded, not smoothed over.
- No advisory index entry, CVSS score or CVE identifier was found for this
  issue in the GitHub advisory database feed; all are UNKNOWN. The issue's
  write-up link (hackmd) is a claim and was not needed for the mechanism read.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; pinned bytes live in
`pins/MidiStreamParser.cpp.{vuln,fixed}` and are included verbatim under
`#line` control by the generated drivers.

In the vulnerable pin, `MidiStreamParserImpl::parseStream()` (`:88-116`) passes
the whole caller block to `parseSysex()` when the first byte is `0xF0` and the
parser buffer is empty; there is no per-call size bound. `parseSysex()`
(`:223-257`) scans for `0xF7` or another status byte. If the SysEx ends without
either, it sets `streamBufferSize = sysexLength` at `:248`, calls
`checkStreamBufferCapacity(false)` at `:249` and, when that returns true,
copies `sysexLength` bytes into `streamBuffer` with `memcpy` at `:250`.

`checkStreamBufferCapacity()` (`:132-143`) grows a smaller buffer to exactly
`MAX_STREAM_BUFFER_SIZE` (32768, `globals.h:122,145`) and returns true at
`:140` without ever checking that the requested `streamBufferSize` fits. With
the default 1000-byte capacity (`SYSEX_BUFFER_SIZE`, `globals.h:127,148`) a
single 40001-byte incomplete SysEx triggers the grow to 32768 and a 40001-byte
copy: 7233 chosen bytes land past the allocation. The copy length comes from
the caller's byte block; the overflow bytes are 7-bit SysEx data (0x5a in the
harness), so both content and length are input-controlled.

Fix `1749f7f` changes two places: `checkStreamBufferCapacity()` now requires
`streamBufferSize < MAX_STREAM_BUFFER_SIZE` in the grow branch
(`MidiStreamParser.cpp.fixed:136`), so an oversized one-shot message takes the
safe discard path; and `parseSysex()` clamps the copy to `streamBufferCapacity`
with `bytesToCopy` (`:253-254`, "Better be paranoid about buffer overflows").
The fixed discard branch no longer overwrites `streamBufferSize`
(`:257-259`), leaving a size larger than capacity as a bookkeeping oddity; it
does not produce an out-of-bounds write on this path.

## 3. Cheapest local experiment

Build two drivers that include the pinned class implementation slices under
`#line` (vulnerable `:68-295`, fixed `:68-299`), with declared stubs for the
scalar types, `MidiReceiver`/`MidiReporter` interfaces, `Synth` helper and the
driver. Allocate the parser's `new[]` buffer exactly in ASan builds; in plain
builds append a 0xa5 canary so chosen bytes can be read past the boundary.
Call the public `parseStream()` once with a 40001-byte incomplete SysEx block
(`0xF0` + 40000 bytes of `0x5a`, no `0xF7`); compare against a complete 102-byte
SysEx and a safe 101-byte incomplete fragment.

Commands (from `lab/frontier/munt2shell/harness/`):
`./run.sh` generates the drivers and builds 8 binaries (gcc/clang x vulnerable/fixed
x plain/ASan); `./check.sh` runs 24 invocations plus a gdb probe and prints a
normalized trace hash.

## 4. Observed evidence (W159, direct-call harness)

- Rung 1 — vulnerable plain build: `parseStream()` returns normally after the
  40001-byte block; baseline dispatches one complete SysEx (`sysex=1`,
  `lastlen=102`); safe fragment dispatches none.
- Rung 2 — fixed build handles the same attack with `rc=0` and no bytes past
  the 32768-byte boundary; the vulnerable build writes chosen `0x5a` at
  offsets 32768..32771 in both gcc and clang plain builds.
- Rung 3 — gcc and clang ASan both report
  `ERROR: AddressSanitizer: heap-buffer-overflow`, `WRITE of size 40001`,
  `0 bytes after 32768-byte region`, at pinned
  `MidiStreamParser.cpp.vuln:250`, with the stack through `parseSysex :249`
  and `parseStream :106`.
- Rung 4 — gdb on the plain vulnerable build, stopped at the destructor's
  `delete[]` after the copy, shows `g_last_size = 32768` and sixteen `0x5a`
  bytes at `g_last_alloc+32768` — chosen bytes, exact offset.
- `129 PASS / 0 FAIL` over 24 runs plus 3 gdb assertions; trace
  `735c136e1c6740ca50ed5790f054cbd4331c16a1d48998b22926de8ac0d1146f`.
  Raw outputs and preserved negatives: `lab/frontier/munt2shell/evidence/`.

## 5. Ceiling and cheapest next rung

Direct calls only, with stubbed C++ interfaces and allocator. No libmt32emu
build, synth, MIDI file/device/host, audio pipeline, socket, wire, pointer
control or command execution in this staged harness; the later real-library
and ALSA lanes are in §§6-7. The issue's attacker model — a
MIDI/SysEx file, named pipe, virtual port or network-forwarded stream — is a
claim, not exercised here. The cheapest move toward a real consumer is to
build the pinned 2.8.3 library, feed a single oversized SysEx block through
`DefaultMidiStreamParser::parseStream()` under ASan, and observe whether the
corrupted heap region is subsequently used before aborts; a rung-5 path would
then need a network-facing host that forwards untrusted bulk SysEx dumps.
Rung 5 is UNKNOWN, not established.

## 6. Real-library confirmation (munt2shell W160, 2026-11-23)

The staged stubbed harness has been reproduced on the **real library**. The
pinned `libmt32emu_2_8_3` tarball (sha256
`81f8c462f46bc8901618762ae34cf9de93894ff81f41db73c79472fa3baef875`) hashes
its three `PINS.sha256` files exactly; applying the pinned `fix.patch` to a
copy yields the pinned fixed cpp hash `6031e579…108612268cf0c3a`. Both are
built by upstream CMake as a static `mt32emu` target. The driver in
`lab/frontier/munt2shell/real/` constructs a real `Synth`, a real
`DefaultMidiStreamParser` and the real C API context; nothing in the parser
or its types is stubbed. Commands:
`cd lab/frontier/munt2shell/real && ./build_and_run.sh && ./build_clang_asan.sh`.
Details and raw outputs: `real/REAL_EVIDENCE.md` and `real/evidence/`.

gcc and clang ASan both report `heap-buffer-overflow`, `WRITE of size 40001`,
0 bytes after a real 32768-byte region, at the unmodified upstream
`MidiStreamParser.cpp:250`; allocation at `:137` from `:249`, stack through
`parseStream :106`. The C API stack adds `mt32emu_parse_stream` at
`c_interface.cpp:760`, i.e. the public ABI forwards the caller's block
without a size bound. In plain builds a harness readback tail past the real
32768-byte allocation holds exactly 7233 chosen `0x5a` bytes (`40001-32768`);
the pinned-fixed build allocates no 32768-byte buffer, writes no chosen
bytes and returns 0 in all scenarios. Terminated and short-fragment controls
behave as in the staged harness.

Post-write consumer probe: feeding `0xF7` after the oversized slice produces
no SysEx dispatch and one overrun debug report. `parseSysexFragment()` sees
capacity already at `MAX_STREAM_BUFFER_SIZE`, discards, and the only later
overwritten bytes on this path — a negative result for an in-library live
consumer, not proof that no host is affected.

One in-tree host path was measured (below); no socket, wire input, grooming
into a live object, pointer control, command or marker side effect was
measured; the issue's network narrative stays a claim. Independent witness
chat #2781 replayed the real-library lane from a clean archive and returned
ESTABLISHED at these rungs 1-4, with no counterexample to the mechanism and
no grade change. Its chosen-byte readback is from the harness's 16384-byte
`operator new[]` tail, not a live allocator neighbour. **Grade: real-library
rungs 1-4 (witness ESTABLISHED); rung 5 UNKNOWN.**

## 7. In-tree host reachability: ALSA sequencer negative (W160)

The pinned tarball contains `mt32emu_alsadrv/src/alsadrv.cpp`, a real Linux
host whose sequencer input copies an ALSA sysex event into `EVENT_SYSEX`
(`alsadrv.cpp:682-688`) and forwards the whole buffer in one call to
`MidiStreamParser::parseStream()` (`:1182`). `alsa_probe.c` measures the
consumer's actual behavior on this host: a local duplex sequencer client
sends variable `SND_SEQ_EVENT_SYSEX` events to its own port and reads them
back. Payloads up to **5572 bytes** arrive intact; **5573 bytes and above**,
including 40001, are rejected by the kernel with `-12` (ENOMEM) and no event
is received. The 5600-byte event limit (payload + 28-byte header) did not
move when client pools were enlarged from 4096 to 131072. Raw sweep:
`lab/frontier/munt2shell/real/evidence/alsa-sweep.txt`; analysis:
`real/ALSA_CEILING.md`.

Consequence: on this host the ALSA host cannot deliver the single >32768-byte
fragment this defect requires; its first fragment grows the buffer safely and
later fragments take the bounded `parseSysexFragment()` path. This is a
measured negative for one consumer on one kernel, not a claim about all ALSA
setups, Qt/Win32 hosts (Qt5 unavailable here) or third-party C-API users;
`mt32emu_parse_stream()` itself remains an unclamped forward. All probe
events were loopback-only inside the local kernel sequencer.

## 8. Independent witness verdict (chat #2781, 2026-11-23)

The witness rebuilt from a clean `git archive HEAD lab/frontier/munt2shell`
(commits 6e59110/04e2960 authoring the real-library and ALSA lanes): 7/7
`PINS.sha256` entries OK, provisioned tarball hash
`81f8c462f46bc8901618762ae34cf9de93894ff81f41db73c79472fa3baef875` OK.
Both source trees were re-extracted, the fixed tree repatched with
`pins/fix.patch`, and all six drivers rebuilt from committed sources and
flags with the project's CMake. The witness's 34-case rc matrix matches the
committed matrix case for case, and all 34 `.out` files are
normalized-identical (path, PID, address and build id aside).

- gcc and clang ASan: `WRITE of size 40001`, 0 bytes after a 32768-byte
  region, at upstream `MidiStreamParser.cpp:250`; allocation at `:137` from
  `:249`, stack through `parseStream :106` and C API
  `mt32emu_parse_stream` at `c_interface.cpp:760`. Fixed build `rc=0` in all
  scenarios; source re-read confirms the `1749f7f` guard
  `streamBufferSize < MAX_STREAM_BUFFER_SIZE` suppresses the 32768-byte
  allocation and clamps the copy.
- Causal variation: changing only the attack byte `0x5a` to `0x37` in the
  witness's own driver copy moved the chosen tail bytes to `0x37`
  (`tail_0x37 = 7233/16384`); ASan still reported the same 40001-byte write.
  Chosen bytes track input, not a harness constant.
- Abort order (the witness's answer to follow-up #2768): a real-allocator
  plain build without the tail probe aborts `rc=134` with
  `malloc(): corrupted top size`, but gdb places that abort in `printf` at
  `driver.cpp:105`, after `mt32emu_parse_stream` returned at `:104`. No
  abort precedes the out-of-bounds store.
- In-library consumer negative rechecked in source: after the overflow
  `streamBufferSize = 40001` exceeds capacity, so
  `checkStreamBufferCapacity(true)` returns false and
  `parseSysexFragment()` takes the discard path at `:289-291`; there is no
  `handleSysex` of corrupted bytes.
- ALSA ceiling independently remeasured: 5572-byte payload delivered with
  matching `ext.len`; 5573 and 40001 rejected (`send rc=-12`,
  `receive rc=-28`). The in-tree host path is closed on this kernel; other
  hosts and routes remain UNKNOWN.

Witness ceiling: rung-4 chosen bytes come from the harness's 16384-byte
`operator new[]` tail, not a live allocator neighbour; there is no host
process, socket or wire input, grooming into a live object, pointer control,
marker or command. Verdict: ESTABLISHED at real-library rungs 1-4, NOT rung
5, no counterexample and no grade change.
