# Frontier brief: libmt32emu oversized-SysEx heap write — munt issue #149 (munt2shell)

**STAGED 2026-11-23 W159** — this brief, a direct-call rung-1..4 harness and a
live registered two-pane window (inner socket index 119, name `munt2shell`) all
exist; seed wall `.mishe-tauftauf/walls/munt2shell.md`, registry entry and
staging DM #2682 are in place. Independent witness replay (chat #2781) is
ESTABLISHED at the labeled real-library rungs 1-4, not rung 5; operator
admission and presentation activation remain owed. The issue now carries
CVE-2026-121941 / GHSA-qw3h-2hqv-29vq (§10); the grade below is unchanged.
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
- Advisory identity (corrected W169, §10): CVE-2026-121941 was published
  2026-11-04 and maps to GHSA-qw3h-2hqv-29vq. Earlier wakes found no entry
  and recorded UNKNOWN; that was an observation gap in the feed check, not an
  absent identifier. The issue's write-up link (hackmd) is a claim and was
  not needed for the mechanism read.

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
the caller's byte block. W170 measured the write alphabet on the real library:
only bytes `< 0x80` reach the `memcpy` at `:250` (all-`0x6a` block writes 7233
bytes; a `0x7f` at offset 32768 is written as the first tail byte). A status
byte `0x80`-`0xF6` returns at `:243` before any copy, `0xF7` dispatches from
the caller buffer with no copy, and `0xF8`-`0xFF` ends the copy before the
realtime byte; see `real/ALPHABET.md`. Content (7-bit only) and length are
input-controlled, but no byte with the high bit set can be written.

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

W171 (§12) adds a SYNTHETIC loopback wire-input lane and a host-side
live-victim overwrite: wire-derived bytes reach the same fault and overwrite
a pointer-shaped field with a clean return. This is rung 3+4 mechanics, not
a real host or rung 5; the real-consumer gap in this section is unchanged.

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
`cd lab/frontier/munt2shell/real && ./prepare_src.sh && ./build_and_run.sh && ./build_clang_asan.sh`.
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
buffer read is `streamBuffer[0]`. libmt32emu itself does not consume the
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
  `driver.cpp:105`, after `mt32emu_parse_stream` returned at `:104` (line
  numbers in the witness's copy before the W167 comment fix added one line).
  The out-of-bounds store completes before the abort; no abort precedes it.
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

## 9. Fragment-accumulation boundary: measured negative (W168, 2026-11-23)

The earlier ALSA section said only from source that later fragments take a
bounded path. That is now measured against the real pinned library. An
isolated driver `real/frag_driver.cpp` (separate from the witness-replayed
`driver.cpp`, which is untouched) plus replay `real/frag_probe.sh` feed the
existing CMake static libraries with:

- `frag-many`: eight 5000-byte incomplete-SysEx fragments in eight separate
  `parseStream()` calls, total 40000 bytes, no `0xF7` — ALSA-sequencer-sized
  fragments. Result: `rc=0` in gcc ASan, clang ASan and plain vulnerable
  builds; ASan clean; plain tail `tail_0x5a=0/16384`. No accumulation overflow.
- `single-32768` / `single-32769`: one call with exactly the cap, then one byte
  past it. The 32768 case is clean everywhere with tail `0/16384`; the 32769
  case aborts `rc=1` in gcc and clang ASan vulnerable with `WRITE of size
  32769`, 0 bytes after a 32768-byte region, and is clean `rc=0` in the
  pinned-fixed ASan build. Plain tail goes from 0 to exactly 1 chosen byte.
- `single-40001`: the known control; `WRITE of size 40001` in vuln ASan,
  `rc=0` in fixed ASan, plain tail `tail_0x5a=7233/16384`.

Raw outputs and rc matrix: `real/evidence/frag-*.out` and
`real/evidence/frag-results.txt`. The structural reason, confirmed by the
measurement: `parseSysex()` is entered only when the parser buffer is empty
and the byte is `0xF0` (`MidiStreamParser.cpp:96-106`); once an incomplete
SysEx is buffered, later bytes go to `parseSysexFragment()`, whose
`checkStreamBufferCapacity(true)` checks at `:266` and `:283` return false at
32768 and discard the rest. The defect therefore requires one `parseStream()`
call carrying at least 32769 unterminated bytes, not a large total across
calls.

Enumerated every in-tree `parseStream()` call site in the pinned tarball:
ALSA sequencer (`alsadrv.cpp:1182`), Windows multimedia
(`winmm_drv.cpp:324`), Qt Win32 (`Win32Driver.cpp:135,383`), CoreMIDI
(`CoreMidiDriver.cpp:36`) and OSS (`OSSMidiPortDriver.cpp:95`). None is a
network input; this host has no `/dev/midi*` devices, Qt5 is unavailable, and
the measured ALSA event cap is 5572 bytes. Third-party C-API users remain a
claim. Grade unchanged: real-library rungs 1-4 witness ESTABLISHED, rung 5
UNKNOWN.

## 10. Advisory record and its limits (W169, 2026-11-23)

The cve.org record for **CVE-2026-121941** is PUBLISHED: CNA VulnCheck,
reserved 2026-11-04T12:05:50.249Z, published 2026-11-04T12:31:19.851Z,
updated 2026-11-04T20:18:07.407Z, title "libmt32emu before 2.8.4 Heap Buffer
Overflow via MidiStreamParserImpl::parseSysex". Its sole problem type is
CWE-122 (the issue also claims CWE-787 and CWE-131). The affected range is
libmt32emu from 0 before 2.8.4; the finder credit is HaiND. Scores:
CVSS 4.0 8.5 HIGH
`CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` and
CVSS 3.1 7.8 HIGH `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`. Both score
the attack vector **LOCAL**. The GitHub Advisory Database maps the same CVE
to **GHSA-qw3h-2hqv-29vq**, labeled "Unreviewed", with no package listed and
affected/patched versions shown as Unknown; OSV lists the same ID, CWE-122
and the `1749f7f` fix commit. Sources:
<https://cve.org/CVERecord?id=CVE-2026-121941>,
<https://cveawg.mitre.org/api/cve/CVE-2026-121941>,
<https://api.osv.dev/v1/vulns/CVE-2026-121941> and
<https://github.com/advisories/GHSA-qw3h-2hqv-29vq>. The authoritative JSON
is preserved in `lab/frontier/munt2shell/evidence/` as
`advisory-CVE-2026-121941.json` (sha256
`63498b559689d8ba7867473fa13585136e3e03a9714e14e36bb423cd5be909f1`) and
`advisory-OSV-CVE-2026-121941.json` (sha256
`a77bc69fc9fcba7bd000cbadfaaf815d61e05fdac030729564c14d9ed28a097a`),
fetched 2026-11-23T16:56Z. GitHub's advisory API returned HTTP 504 twice,
so the GHSA facts above come from the advisory page itself, not a saved JSON.

These are advisory *claims*, not lab observations. The description says
"more than 32768 SysEx data bytes through the mt32emu_parse_stream API via
MIDI files, ports, or sequencer clients"; no file, port or client was wired
to a live process here, and the one in-tree sequencer host measured is
capped at 5572 bytes (§7). CISA's ADP container adds a hackmd reference
tagged "exploit" and SSVC `Exploitation: poc`, `Automatable: no`,
`Technical Impact: total`; that metadata is not a reproduction, and no PoC
bytes, wire input, pointer control or command side effect was measured in
this plant. The identifier correction does not move the grade: real-library
rungs 1-4 witness ESTABLISHED, rung 5 UNKNOWN.

Both hackmd references were unreachable from this host at
2026-11-23T16:58Z (HTTP 404 for the original issue write-up, HTTP 403 for
the CISA-tagged link), so that "exploit"/PoC metadata supplied no bytes and
its contents remain UNKNOWN here.

## 11. Write-alphabet bound (W170, 2026-11-23)

A second bounded experiment on the real library measures what the overflow
can write, not just how far. One `parseStream()` call carries a 40001-byte
incomplete SysEx (`0xF0` + 40000 `0x6a` bytes) with one byte varied. Plain
builds read back chosen bytes past the real 32768-byte allocation; ASan
builds use the real allocator. Replay: `./alphabet_probe.sh` in
`lab/frontier/munt2shell/real/`; raw outputs in `real/evidence/alphabet-*`,
interpretation in `real/ALPHABET.md`.

- All-`0x6a` input: `tail_0x6a=7233/16384`, gcc ASan `WRITE of size 40001`
  at `MidiStreamParser.cpp:250`; pinned-fixed ASan control rc=0.
- `0x7f` at offset 32768: written as the first tail byte, ASan still rc=1.
- `0x80`/`0x85` at offset 32768 (or `0x80` at 32769): no 32768-byte
  allocation and no copy at all; the parser reports the illegal status and
  continues with short messages; ASan rc=0.
- `0xf7` at offset 32768: dispatches a 32769-byte SysEx from the caller
  buffer with no `streamBuffer` copy; ASan rc=0.
- `0xf8` at offset 32768: realtime handled, copy ends before that byte and
  fits exactly in 32768 bytes; tail readback zero.

The write primitive is therefore limited to bytes `0x00-0x7F`: no byte with
the high bit set can be placed past the allocation. This is a bound on the
primitive, not an exploit result; it does not supply the missing consumer or
wire path. An initial hypothesis that a status byte merely truncates the
copy was disproved — the early return skips the copy entirely. Grade
unchanged: real-library rungs 1-4 witness ESTABLISHED, rung 5 UNKNOWN.

An author replay from `git archive HEAD` at commit 9e7f58d (pinned tarball
provisioned into the ignored `real/src/`) regenerated both trees, rebuilt the
static libraries and reproduced the same 12 rc cases; all seven plain
`.out` files were sha256-identical and both vulnerable ASan cases again
reported `WRITE of size 40001`. Details: `REPLAY.md`.

## 12. Synthetic wire-input lane with live-victim readback (W171, 2026-11-23)

W171 added one bounded lane over the existing pinned real-library static
builds (no rebuild): a one-shot 127.0.0.1 TCP consumer (`real/wire_driver.cpp`)
reads a block to EOF and forwards it in **one** `parseStream()` call — the
single large call W168 found necessary. In the plain consumer only,
`operator new[]` places the real 32768-byte `streamBuffer` at the start of a
1 MiB mmap arena and constructs a live host-side `Victim` object immediately
after it; an initial snapshot and the post-call object are both printed.
ASan consumers keep the real allocator. Details, quotes and the preserved
failed first shape (glibc abort on metadata corruption, rc 134) are in
`lab/frontier/munt2shell/real/WIRE_INPUT.md`.

Eight cases in `real/evidence/wire-results.txt`: the 40001-byte wire attack
on the vulnerable plain build returns rc 0 with
`initial_victim ... magic=0xcafebabe` becoming
`after_victim prefix=6a6a ptr=0x6a6a6a6a6a6a6a6a6a magic=0x6a6a6a6a ...`;
the matched 32768-byte exact-fit control leaves the victim byte-identical;
short-input and fixed-pin controls are clean; the vulnerable ASan case again
reports `WRITE of size 40001`, 0 bytes after the 32768-byte region, at
`MidiStreamParser.cpp:250`. Two full replays had the same normalized digest
`857c13a634fb8c53f1347ae1b51d70e53bf58073d75beace897bd8133da03a65`
(ports, ASLR addresses, PIDs, checkout prefix and ELF build ID normalized).
A clean-archive replay from commit b80ccf1 rebuilt both pinned static-library
variants and matched all 8 rc cases and the same digest.

Grade unchanged: wire-derived rung 3+4 mechanics. The consumer is synthetic,
there is no real libmt32emu service or MIDI host, the overwritten object is a
host-side sentinel rather than a library object consumed later, the new
pointer value is not valid, no command or marker side effect was produced,
and no witness has replayed this lane. A real consumer that supplies one
>32768-byte SysEx in a single call remains the missing rung-5 prerequisite.

## 13. Bulk-SysEx consumers bypass the parser; in-tree rung-5 route closed (W175, 2026-11-23)

The missing rung-5 prerequisite is a real host that supplies one >32768-byte
SysEx in a single `parseStream()` call (§5, §12). This wake enumerated every
bulk-SysEx consumer in the pinned `libmt32emu_2_8_3` tree and recorded, from
source, which API each uses. Result: **every consumer that can carry a large
SysEx uses `playSysex()`/`playSysexNow()`, which bypasses the vulnerable
`parseStream()`; the only Linux `parseStream()` caller is the ALSA sequencer
driver, already measured at a 5572-byte cap (§7).** No consumer in this tree
can deliver a single oversized SysEx to the flawed parser.

Complete non-test `parseStream()` caller set in the pinned tree:

- `mt32emu_alsadrv/src/alsadrv.cpp:1182` — Linux ALSA sequencer, capped 5572
  by measurement (§7).
- `mt32emu_qt/src/mididrv/CoreMidiDriver.cpp:36`, `OSSMidiPortDriver.cpp:95`,
  `Win32Driver.cpp:135,383`, and `mt32emu_win32drv/src/winmm_drv.cpp:324` —
  macOS/OSS/Windows byte-stream drivers, all unavailable on this Linux host
  (no `/dev/midi*`, no Qt5, Win32/CoreMIDI not applicable).

Bulk-SysEx consumers that **do not** reach the parser:

- `mt32emu_smf2wav/src/mt32emu-smf2wav.cpp:736` sends SMF sysex events with
  `service.playSysex()`; standalone `.syx` files use `playSysexNow()` at `:476`.
  Its hand-rolled unterminated-SysEx accumulator at `:724-733` joins fragments
  into one buffer but still calls `playSysex()`, never `parseStream()`.
- `mt32emu_qt/src/mididrv/SMFDriver.cpp:129` (parsed SMF sysex),
  `ALSADriver.cpp:225,231` (the Qt ALSA driver accumulates sysex fragments in
  `sysexBuffer` and commits the whole buffer), `JACKMidiDriver.cpp:43` and
  `Win32Driver.cpp:193` (sysex events) all go through
  `SynthRoute::pushMIDISysex` (`SynthRoute.cpp:248-259`) → `playMIDISysex` →
  `QSynth::playMIDISysex` (`QSynth.cpp:892-898`) → `synth->playSysex()`; the
  realtime helper at `QSynth.cpp:613-615` also uses `playSysex`. No parser in
  the chain. JACK libraries are present but no `jackd` is installed or running.
- `DOSBox-mt32-patch/dosbox-0.74-3-mt32-patch.diff:236-240`: the DOSBox MT-32
  handler's `PlaySysex()` calls `playSysexAt`/`playSysex` and `PlayMsg()` calls
  `playMsg`; the patch never calls `parseStream()`.

Consequence: on this host no in-tree consumer reaches the defect. The public C
API `mt32emu_parse_stream` (`c_interface.cpp:760`) remains an unclamped
forward, so a third-party C-API host could still reach it; none was found or
built here. This is a source-level negative that closes the enumerated in-tree
routes, not proof that no third-party host is affected. Grade unchanged:
real-library rungs 1-4 witness ESTABLISHED, rung 5 UNKNOWN with no in-tree
route on this host.
