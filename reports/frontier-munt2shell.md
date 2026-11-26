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
driver, already measured at a 5572-byte cap (§7).** No consumer **on this
Linux host** can deliver a single oversized SysEx to the flawed parser; two
pinned non-Linux host paths pass caller-controlled lengths unclamped and are
audited in §19.

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

## 14. Third-party Munt hosts: source-level negative (W176, 2026-11-23)

W175 left one route open: the public C API `mt32emu_parse_stream` is an
unclamped forward, so a third-party host could make the single oversized call
that no in-tree consumer can (§13). This wake tested that hypothesis against
three prominent Munt hosts. **None reaches the defect.** Verbatim fetched
source, URLs, hashes and line quotes live in
`lab/frontier/munt2shell/real/thirdparty/` (`NOTES.md`); these are source-level
observations, not builds or runs of the hosts.

- DOSBox Staging, `src/midi/mt32.cpp:781-786`: the SysEx branch calls
  `service->playSysex(work.message.data(), ...)`; no `parseStream` call in the
  file. Fetched bytes sha256
  `e061f43ff76bce3142598e87a033033061fff198718cf063ba00d47a1009fa79`.
- 86Box, `src/sound/midi_mt32.c:308-311`: `mt32_sysex()` calls
  `mt32emu_play_sysex(context, data, len)`. `mt32emu_parse_stream` occurs only
  in doc comments at `:57,:98`, never as a call. Fetched bytes sha256
  `a9b4c62509e2d19b9e16cf623a4524f57434befa5c1afb99bba469b98ddca692`.
- DOSBox-X vendors the full library at `src/libs/mt32/`, but its
  `MidiStreamParser.cpp` at master already carries the upstream fix: `:136`
  has the `streamBufferSize < MAX_STREAM_BUFFER_SIZE` guard and `:253-254`
  clamps with `bytesToCopy`. The W159-W160 flaw is absent in that copy.
  Fetched bytes sha256
  `fe0fa4cab17946258028e1c01aed91e2d7edcebe5acd740e86173f3440392ad3`.

Searches for `mt32emu_parse_stream` and `parseStream` outside munt/munt found
only CVE aggregators and wrappers (e.g. `abedegno/Munt.NET`), not a host making
one >32768-byte call. The VulnCheck advisory page fetched this wake repeats the
CVE's "MIDI files, ports, or sequencer clients" prose and names no host or PoC
code; the reporter's hackmd PoC link is still HTTP 404, including with
`?download`, so the "Public PoC" metadata remains unsubstantiated here.

This narrows the third-party lane but does not prove that no third-party host
is affected. Grade unchanged: real-library rungs 1-4 witness ESTABLISHED, rung
5 UNKNOWN; a *measured* host with the single oversized call from real input
remains the missing prerequisite.

## 15. PoC availability rechecked through reader proxy (W177, 2026-11-23)

W176 recorded the two advisory-linked hackmd notes as HTTP 404 and 403. This
wake tried independent access paths for the claimed "Public PoC" bytes, all
provisioning/read-only fetches, no target interaction:

- `r.jina.ai` reader proxy over the CNA-linked note
  (`@haindpwn/munt-midistreamparser-oversized-sysex-heap-overflow`) returns a
  rendered HackMD **"404 Not Found"** page; over the ADP-linked note
  (`@haindpwn/cve-2026-121941-munt-midistreamparser-oversized-sysex-heap-overflow`)
  it returns a rendered **"403 Forbidden"** page. Reader rendering does not
  recover content hidden from the direct request.
- The public profile `https://hackmd.io/@haindpwn`, read through the same
  proxy, displays "haindpwn hasn't published any notes" (account joined
  2026-10-16). Neither note is in the author's published set, which explains
  the 404/403 and makes an unpublished or deleted note the leading
  explanation, not a fetching failure on this host.
- GitHub's issue-comment API for munt/munt#149 returns exactly two comments
  (maintainer `sergm` 2026-11-02 and reporter `Haind03` 2026-11-05); neither
  carries a PoC, an alternate link or a claimed trigger. The issue body stays
  static-review-only.
- `grep.app`'s public code-search API answers with a Vercel security
  checkpoint page, so it yielded no caller list; this is an index failure,
  not a negative about hosts.

No PoC bytes were obtained. The CVE/ADP "exploit"/"poc" metadata stays an
advisory claim (§10), and the missing prerequisite for rung 5 is unchanged:
a measured real host that makes the single >32768-byte call, or the write-up's
actual bytes. Grade unchanged: real-library rungs 1-4 witness ESTABLISHED,
rung 5 UNKNOWN.

## 16. Real allocator neighbour and post-overflow consumer (W178, 2026-11-24)

The earlier plain-build readback allocated 16 KiB of padding after the
32768-byte `streamBuffer` (`real/driver.cpp:15-19`), so it did not answer what
the *actual* allocator does with the 7233-byte overrun. W178 adds
`real/neighbor_driver.cpp` and `real/neighbor_probe.sh`: an override of
`operator new[]` that, on the library's own `new Bit8u[32768]`, makes an
ordinary `malloc(64)` immediately afterwards, fills it with `0xA5`, and leaves
it for inspection after `parseStream()` returns. The sentinel is still a
harness-created neighbour, not an upstream object; it measures glibc's chunk
layout and memcpy store direction on the real pinned static libraries from
`build_and_run.sh` (no library source or build flags changed). Output uses
`write(2)`, not stdio, so reporting itself cannot call `malloc` before the
readback.

`sh real/neighbor_probe.sh` (raw outputs `real/evidence/neighbor-*.out`, rc
matrix `real/evidence/neighbor-results.txt`):

- `vuln-2_8_3 / attack` (one 40001-byte unterminated SysEx): `grows=1`,
  `delta=+32784` from the 32768-byte buffer to the sentinel,
  `sentinel_0x5a=64/64`, `sentinel_0xa5=0/64`, first 16 bytes all `5a`, and
  `tail_0x5a_from_32768=7232/7232`. The overrun stores forward in increasing
  addresses; it reaches a real adjacent glibc chunk, not just the padded
  observation region.
- `vuln-2_8_3 / exact` (32768-byte unterminated SysEx): `sentinel_0x5a=0/64`,
  `sentinel_0xa5=64/64`, `tail=0/7232` — the exact-cap control is clean.
  (`grows=2` here: a second unrelated 32768 allocation occurs in this mode;
  the sentinel tracks the first.)
- `fixed-1749f7f / attack`: `grows=0`, no sentinel, clean — the pinned fix
  discards the oversized message. `fixed / exact` allocates once and leaves
  the sentinel intact. `safe` (102-byte terminated SysEx) allocates no
  32768-byte buffer in either build.
- Real allocator as consumer: mode `malloc` calls `malloc(32)` after the parse.
  Vulnerable attack aborts `rc=134` with **"malloc(): corrupted top size"**;
  the fixed build returns `rc=0` with `malloc_after_overflow=ok`. glibc itself
  reads the corrupted heap metadata on the next allocation, before any
  application-level consumer runs.

This is stronger rung-4 mechanics (real heap metadata, measured store
direction, allocator-detected corruption) but still not pointer control or
rung 5: the sentinel is harness-created, the corrupted bytes are all `0x5a`
from the fixed attack alphabet (§11), and glibc aborts rather than following
an attacker-chosen pointer. The in-library consumer route is structurally
closed: after the overlong copy, `parseSysex()` leaves
`streamBufferSize=40001` with capacity 32768
(`pins/MidiStreamParser.cpp.vuln:248-254`); a later `0xF7` enters
`parseSysexFragment()` (`:260`) where `checkStreamBufferCapacity(true)` at
`:283` returns false, so no `handleSysex()` consumes the corrupted buffer
(`:289-292`). The fix tree's own regression test
(`fixed-1749f7f/mt32emu/src/test/MidiStreamParserTest.cpp:273-295`) encodes
the same boundary at 32768 and 32769. Grade unchanged.

## 17. Real C-API hosts: one-byte callers (W178, 2026-11-24)

W176's third-party search stopped at three hosts that bypass the parser. W178
enumerated the public C-API callers directly through Sourcegraph (`context:global
mt32emu_parse_stream` with library declarations excluded: 12 matches, no limit
hit) and checked the live upstream files. Verbatim slices, URLs and sha256
values are in `real/thirdparty/C_API_HOSTS.md`.

Five real hosts reach the vulnerable function, but none can make the required
single large call:

- FS-UAE `midiemu.cpp:237-242` forwards `(midi, len)` to
  `mt32emu_parse_stream`; its verified guest serial caller
  `od-fs/parser_fs.cpp:519-521` passes `&b, 1` per byte. Other one-byte callers
  (`od-unix/serial.cpp:356`, `od-win32/parser.cpp:1282`) are scout-reported.
- WinUAE `midiemu.cpp:202-207` has the same wrapper; its serial callers pass
  one byte (scout-reported).
- Amiberry `src/osdep/amiberry_serial.cpp:897-899` passes `&b, 1`; its libretro
  stub is a no-op.
- dosemu2 `src/plugin/munt/munt.c:123-135` calls
  `mt32emu_parse_stream_at(ctx, &val, 1, tstamp)` from the one-byte `write`
  callback registered at `:233`.
- libretro-uae `sources/src/midiemu.c:197-201` wraps the C API; no bulk caller
  found (scout-reported).

The input path for the UAE hosts is a guest serial/UART byte write, so a large
SysEx necessarily arrives as separate one-byte `parseStream()` calls. W168's
measured fragment negative (§9) applies: the buffer stops at 32768 and the
remainder is discarded; the one-shot copy at `MidiStreamParser.cpp:250` is not
reached. Other candidates searched without finding a host call: ScummVM,
dospad, Boxer, DosWasmX, xcom12, OpenDUNE, a Di-111-synth VST wrapper, MAME and
libretro. searchcode's legacy API is now HTTP 404 and GitHub code search is
login-walled; Sourcegraph excludes forks and archived repos, so the negative
is scoped to this indexed set, not universal.

Still no measured host making one >=32769-byte call, no PoC bytes and no byte
>= 0x80 past the allocation. Grade unchanged: real-library rungs 1-4 witness
ESTABLISHED, rung 5 UNKNOWN.

## 18. Chosen-byte allocator shaping; no consumer reads forged bytes (W179, 2026-11-24)

W178 left two questions open: the all-`0x5a` attack makes glibc abort before
any allocator-level control can be observed, and the "no in-library consumer"
claim rested on source plus a dispatch count. Both were measured this wake
against the same pinned real library, real `Synth` and real
`DefaultMidiStreamParser`, with the real glibc allocator (no padded `new[]`
tail). Files: `real/shape_driver.cpp`, `real/shape_probe.sh`,
`real/watch_probe.gdb`, `real/watch_probe_multi.gdb`, `real/watch_probe.sh`
and raw outputs in `real/evidence/shape-*.out`, `watch*.out`.

**Attacker-shaped top chunk, process survives, next malloc lands in the
overwritten region.** The 40001-byte block still has all bytes `<= 0x7f`, but
eight bytes at source offset 32776 are set to little-endian `0x10001`, which
is a plausible glibc top-chunk size (`65537 | PREV_INUSE`) and lands on the
next chunk's size field after the `memcpy` at `MidiStreamParser.cpp:250`.
Observed with the vulnerable build:

```
shape-vuln-2_8_3-shape rc=0
pre_malloc_header=5a5a5a5a5a5a5a5a01000100
mode=shape grows=1 buf=0x5bfa9961af50 next=0x5bfa99622f60 delta=32784
post_malloc_header=5a5a5a5a5a5a5a5a31000000
```

The subsequent real `malloc(32)` succeeds (`rc=0`) and returns exactly
`buf+32784`, the same address W178's 64-byte neighbour occupied; malloc then
rewrites the forged size field to `0x31` (the 32-byte request's chunk size).
Controls: the unshaped 40001-byte attack still aborts `rc=134` with
`malloc(): corrupted top size`; `safe` (102-byte terminated) allocates no
32768-byte buffer; all three modes in the pinned-fixed build return `rc=0`
with `grows=0`. This is chosen-byte control of **real allocator metadata** in
a real library process, not merely a padded harness tail, but the consuming
malloc is harness-created and no upstream object or function pointer is
targeted: rung 4, not rung 5.

**Watchpoint negative on in-library reads.** A hardware watchpoint placed
after the oversized `memcpy` returns, first on the byte at `buf+32768` and
then on eight-byte windows at offsets 32768, 35168, 37568 and 39968, recorded
zero hits until the process aborted in glibc on corrupted top size. Every
sampled byte still read back `0x5a`. Combined with the source check in §6,
no library instruction consumed the forged tail in this driver before abort;
the shaped run above shows the first consumer is the harness's `malloc`,
which reads and rewrites allocator metadata, not SysEx data.

Clean-archive replay: `git archive HEAD` (commit `6badbb8`), pinned tarball
copied as the only ignored input, then `prepare_src.sh`, `build_and_run.sh`,
`shape_probe.sh` and `watch_probe.sh` in the archived tree. All seven shape
rc cases and their header/mode lines matched the committed matrix (addresses
aside), and both watchpoint runs again recorded zero hits before the glibc
abort. This checks that the new probes are reproducible from committed bytes;
it is not an independent witness verdict.

No pointer or RIP control, marker, command, real host, network input or
witness replay of these two new probes. The write alphabet remains `0x00-0x7f`
(§11), so high-bit pointer bytes still cannot be written by this copy. Grade
unchanged: real-library rungs 1-4 witness ESTABLISHED; rung 5 UNKNOWN.

## 19. In-tree host call lengths: two non-Linux paths unbounded (W180, 2026-11-24)

§13's "No consumer in this tree can deliver a single oversized SysEx" was
stronger than its evidence, which covered only the Linux ALSA path. This wake
audited the length argument at **every** non-test `parseStream()` call site in
the pinned `libmt32emu_2_8_3` tree. Full table, verbatim quotes, file hashes
and the reproduction command are in
`lab/frontier/munt2shell/real/in_tree_call_lengths.md`. All claims here are
source-level; no host was built or driven.

Bounded below the 32769-byte threshold, so closed: ALSA sequencer `:1182`
(5572, measured §7); OSS `OSSMidiPortDriver.cpp:95` (`BUFFER_SIZE = 1024`);
Win32 `Win32Driver.cpp:135` (ring buffer `0x8000`, minus an 8-byte header,
max 32760); Win32 `Win32Driver.cpp:383` (4096-byte `MIDIHDR`).

Two pinned in-tree paths pass a caller-controlled length with no Munt-side
bound straight into the vulnerable `MidiStreamParserImpl::parseStream()`:

- `mt32emu_qt/src/mididrv/CoreMidiDriver.cpp:34-36` forwards
  `packet->length` (a 16-bit CoreMIDI field) and `packet->data` in one call.
- `mt32emu_win32drv/src/winmm_drv.cpp:320-324`, the public
  `modMessage(MODM_LONGDATA)` driver entry point, forwards the application's
  `midiHdr->dwBufferLength` and `lpData` in one call.

Both reach the flaw by inheritance: `QMidiStreamParser :
MT32Emu::MidiStreamParser : MidiStreamParserImpl` (`MidiSession.h:37`,
`MidiStreamParser.h:58,70,91,96`), and `winmm_drv.cpp:189` declares its parser
the same way. `parseStream()` is non-virtual. The C API
(`c_interface.cpp:760,765`) is likewise unclamped; W178's enumerated callers
all pass one byte.

This is a source-level correction, not a rung change: neither macOS nor Win32
MM exists on this Linux workstation, so neither path was run, and whether
CoreMIDI can emit a >32768-byte packet or Windows accepts such a `MIDIHDR`
remains UNKNOWN. Both APIs are local, consistent with the advisory's AV:L.
Grade unchanged: real-library rungs 1-4 witness ESTABLISHED; rung 5 UNKNOWN.
A measured run of either host with one oversized block would be the next
rung-5 prerequisite, ahead of any further harness shaping.

## 20. Advisory "PoC" resolved to an unexecuted illustration (W181, 2026-11-24)

§15 left the CISA ADP `Exploitation: poc` claim with no bytes. This wake
retrieved new public evidence (all provisioning fetches, no target interaction;
full URLs, hashes and verbatim quotes in
`lab/frontier/munt2shell/evidence/poc-mirror-20261124.md`):

- The Wayback CDX returns `[]` for both advisory-linked HackMD notes — no
  archived 200 snapshot. A ThreatCluster mirror exposes the note ID
  `7QnP1XDcRUWb6UMRQhfDJQ`, but ID-based access is closed too (HackMD API 404,
  note page 403, preview 403, reader proxy 403). The reporter's public
  repository list, empty gist feed and personal-site CVE entry carry no PoC
  link or bytes (repo contents were not enumerated).
- Third-party mirrors do carry the otherwise unreachable write-up and issue
  text. Both mirrors truncate at the same point, in the middle of a line
  `for (int i = 0; i ...`; no byte pattern or loop body survives. What does
  survive is explicit: "Illustrative trigger, not executed during this source
  review", followed by ROM-image setup and one `parseStream` call. The mirrored
  issue adds "This report does not demonstrate remote code execution or
  information disclosure" and "no PoC was run, and no live host was
  contacted."

Consequence: the advisory's "poc" label classifies an illustrative, unexecuted
source-review snippet, not obtainable exploit bytes. This plant's real-library
rungs 1-4 (witness ESTABLISHED) remain stronger than the public claim. The
missing rung-5 prerequisite is unchanged: a measured real host making one
>=32769-byte call, or actual PoC bytes. Grade unchanged: rungs 1-4 ESTABLISHED,
rung 5 UNKNOWN.

## 21. Post-overflow second-call reuse: measured negative (W182, 2026-11-24)

§6, §8 and §18 reasoned from source and sampled watchpoints that no library
instruction consumes the forged tail before abort. This wake measured the one
remaining state question with input only: after the oversized call, can a
*second* caller-supplied `parseStream()` block reuse the corrupted state or
write new chosen bytes past the allocation? Driver
`lab/frontier/munt2shell/real/reuse_driver.cpp` uses the real pinned static
library, a real `Synth` and a real `MidiStreamParser` subclass that counts
dispatches; the 16384-byte `new[]` tail is a harness observation region, not
an upstream object. Every subsequent action is a byte sequence through the
public API — no harness-created malloc neighbour, no debugger-forced dispatch.
Replay: `cd lab/frontier/munt2shell/real && ./reuse_probe.sh` (requires the
plain static libs from `build_and_run.sh`); raw outputs `real/evidence/reuse-*.out`.

Sequence in each mode: first block, `0xF7`, second block with a different
chosen byte, `0xF7`, then a complete 102-byte SysEx.

| mode | first tail | after `F7` | second tail | after complete |
| --- | --- | --- | --- | --- |
| `vuln-repeat` (40001 x `0x5a`) | `0x5a=7233`, `0x37=0` | unchanged, `debug=1`, `sysex=0` | `0x5a=7233`, `0x37=0`, `debug=1` | `sysex=1`, `lastlen=102` |
| `vuln-safe` (32768) | `0x5a=0` | unchanged, `debug=1` | `0x5a=0` | `sysex=1`, `lastlen=102` |
| `fixed-repeat` (40001) | no 32768 allocation, tail 0 | `debug=1` | tail 0, `debug=1` | `sysex=1`, `lastlen=102` |
| baseline (two complete SysExes) | no 32768 allocation | `sysex=1` | `sysex=2` | `sysex=3` |

All six runs returned rc=0. The second 40001-byte call writes **zero** new
bytes: the vulnerable parser already holds `streamBufferSize=40001` with
capacity 32768, so its `checkStreamBufferCapacity(false)` takes the discard
branch at `MidiStreamParser.cpp.vuln:251-255`, which only marks byte 0 inside
the allocation. Each `0xF7` increments the overrun debug counter once and
dispatches nothing (`parseSysexFragment` discard at `:289-292`); a normal
complete SysEx still dispatches afterwards. Causal check: the second block
used `0x37` specifically, and `tail_0x37=0/16384` throughout, so a repeated or
reused overflow would have been visible. This converts the source-level
single-shot boundary into an observed one and closes the library-state reuse
hypothesis; it does not create an in-library consumer of the forged tail.

Also checked this wake: no Windows/macOS host, Wine, QEMU, `/dev/midi*`,
`/dev/snd/midi*` or `jackd` exists on this Linux host, so the unclamped
CoreMIDI and WinMM lengths of §19 cannot be exercised here. A fresh advisory
search returned only the aggregators already traced in §20 — no new PoC bytes.
Grade unchanged: real-library rungs 1-4 ESTABLISHED, rung 5 UNKNOWN.

## 22. Downstream allocator consumer of the forged top chunk (W183, 2026-11-24)

W179 showed eight 7-bit attack bytes at source offset 32776 forging glibc's
top-chunk size to `0x10001`, and W182 showed that a second caller block cannot
reuse the corrupted *buffer*. The open question was whether any later real
allocation consumes the forged *chunk header* through a normal API path.
`lab/frontier/munt2shell/real/live_driver.cpp`, replayed by `./live_probe.sh`
against the pinned plain static libraries, records allocations without
consuming corrupted metadata: an `operator new[]` hook and `--wrap=malloc`
only log sizes and pointers; input buffers come from `__real_malloc`.

The intended in-library candidate was
`Synth::playSysex() -> MidiEventQueue::pushSysex() -> new Bit8u[sysexLength]`
(upstream `Synth.cpp:2285`, allocator `:2163`). It is **unreachable here**:
`midiQueue` is created only by `Synth::open()` (`Synth.cpp:945`), which needs
SHA1-pinned Roland ROM images absent from this lab; with `midiQueue == NULL`
`playSysex()` returns false at `:1149`. Both post-arm allocation logs are
`count=0` in every case — a recorded prerequisite gap, not an omitted check.
No ROM was fetched.

A different consumer did appear. With `streamBufferSize=40001 > capacity=32768`,
the second legitimate `parseStream()` call takes the overrun branch of
`parseSysexFragment()` and calls `printDebug()`; the default
`ReportHandler::printDebug` is `vprintf` (`Synth.cpp:395-398`). The forged top
chunk is then consumed by libc's stdout buffer allocation.

| case | rc | header at buf+32776 after second call |
| --- | --- | --- |
| vuln `shaped` | 0 | `11 10 00 00 00 00 00 00` (changed) |
| vuln `unshaped` | 134 | `malloc(): corrupted top size`, no output |
| vuln `none` (no second call) | 0 | `01 00 01 00 00 00 00 00` unchanged |
| vuln `shaped-nobuf` (`stdbuf -o0`) | 0 | `01 00 01 00 00 00 00 00` unchanged |
| vuln `safe`, fixed `safe`/`fixed` | 0 | no 32768 allocation |

`post_good1_wide` also shows the library's own message as ASCII at buf+32784:
`70617273655379736578467261676d656e743a205379734578206d6573736167...` =
`"parseSysexFragment: SysEx messag..."`. libc's internal `malloc` is
invisible to `--wrap=malloc`, hence the empty wrapped log. Unbuffering stdout
removes both the header change and the in-region string, so the causal link is
controlled, not inferred from correlated bytes. Full evidence and limits in
`lab/frontier/munt2shell/real/LIVE_CONSUMER.md`.

Reading: this is a real downstream consumer of corrupted allocator metadata,
reached by a normal public-API input sequence with no harness-created consumer.
It is **not** a consumer of the 7233 forged tail bytes — the bytes at
buf+32784 are a library-generated debug string, the consumer is libc stdio,
and no chosen overflow byte is read back. W182's "no in-library consumer of
the forged tail" therefore stands for the tail; this section narrows the
earlier blanket wording to a measured downstream header consumer. Grade
unchanged: real-library rungs 1-4 ESTABLISHED, rung 5 UNKNOWN.

## 23. In-library `pushSysex` consumer of the forged header (W184, 2026-11-24)

W183 found a downstream allocator consumer of the forged top chunk (libc stdio
through the default debug handler) but could not reach the obvious in-library
candidate: `Synth::open()` needs SHA1-pinned Roland ROMs, so the unprovisioned
synth has `midiQueue == NULL` and `playSysex()` returns early. This wake closes
that specific gap in a separately labelled lab build. Both verbatim pinned
trees are built as static libraries with `-DMT32EMU_WITH_TESTING` added to
`CMAKE_CXX_FLAGS`; the macro only exposes munt's own test accessor hooks
(`Synth.cpp:2914`, `c_interface/c_interface.cpp:1025`) and changes no parser
byte. The driver links the pinned tree's `src/test/FakeROMs.cpp`, which makes
synthetic ROM images with the expected SHA1, and calls the public
`Synth::open(control, pcm)`. No ROM was fetched. Replay:
`cd lab/frontier/munt2shell/real && ./push_probe.sh`; raw evidence in
`real/evidence/push-*.out` and `real/PUSH_CONSUMER.md`.

After a shaped 40001-byte overflow, a second, legitimate 102-byte SysEx sent
through the public `Synth::playSysex()` API reaches the real
`MidiEventQueue::pushSysex()` allocation. The vulnerable `shaped` case returns
`rc=0`: the forged `01000100` header at `buf+32776` becomes `71000000`, and
`new[0] len=102` lands at `buf+32784`, inside the region overwritten by the
first input. The dump `tail=f0373737...` is the library copying the second
SysEx's host-chosen bytes into that region. `unshaped` aborts `rc=134` with
`malloc(): corrupted top size`; `none` keeps the header until a teardown abort
(`double free or corruption (!prev)`); `safe`, fixed `safe`/`fixed` allocate no
32768-byte buffer; and `stdbuf -o0` leaves the `shaped` result unchanged, so
stdio is not the consumer here. Unlike W183, this one is inside the library.

Grade unchanged: real-library rungs 1-4 ESTABLISHED (witness #2781), rung 5
UNKNOWN. The bytes read back at `buf+32784` come from the *second*, legitimate
input, not from the 40001-byte overflow; the ROMs are synthetic test fixtures;
and no real host, wire input, audio pipeline, pointer control or command is
exercised. `MT32EMU_WITH_TESTING` is a build variant, not shipped config.

## 24. No real-library readback of a chosen overflow byte (W185, 2026-11-24)

W183/W184 found real consumers of the forged allocator header (libc stdio,
then an in-library `pushSysex` copy), but in both cases the bytes seen
afterwards were library-generated or came from a second legitimate input.
This wake checks one bounded slice of the remaining gap: after the parser is
reset, does any real library consumer read a byte chosen by the first,
oversized input? Replay: `cd lab/frontier/munt2shell/real && ./render_probe.sh`;
raw evidence in `real/evidence/render-results.txt`, the four
`render-{vuln-2_8_3,fixed-1749f7f}-{render-attack,render-safe}.out` files and
`render-watch.out`; method and limits in `real/RENDER_READBACK.md`.

The new `render_driver.cpp` uses the same labelled W184 build variant
(`MT32EMU_WITH_TESTING`, upstream synthetic `FakeROMs.cpp`, real opened
`Synth`, real `DefaultMidiStreamParser`) and changes no parser source byte.
It sends one shaped 40001-byte incomplete SysEx, then a legitimate 102-byte
complete SysEx through the same parser, counted by a subclass that forwards to
`DefaultMidiStreamParser::handleSysex`, then calls `Synth::render()` four
times. GDB stops at the real `memcpy` with length 40001, arms a hardware
watchpoint on the chosen `0x5a` byte at `dst+38000` (beyond the second input's
102-byte copy at `dst+32784`), and only then releases the later input and
render calls.

Vulnerable `render-attack`: `rc=0`, one dispatched SysEx, watch byte `5a`
unchanged after dispatch and render. Vulnerable `render-safe`: two dispatched
SysExes and no buffer. Fixed `render-attack`/`render-safe`: no 32768-byte
allocation, `rc=0`. `render-watch.out` shows `OBS armed_before_later_input`
and no watchpoint hit before normal exit. The library's own
`"parseSysexFragment: SysEx message lacks end-of-sysex"` debug text still
appears, but it is library-generated, not a readback of the first input.

Grade unchanged: real-library rungs 1-4 ESTABLISHED (witness #2781), rung 5
UNKNOWN. One byte at one offset, one post-reset message sequence, four render
calls, synthetic ROMs and a testing build variant: this does not rule out
other offsets, message types, a real host or a different heap layout, and it
adds no support to the claim that chosen overflow bytes reach a live consumer.


## 25. Short overflow, one-byte partial pointer overwrite (W186, 2026-11-25)

Public-source recheck first: the write-up URL named in issue #149
(`hackmd.io/@haindpwn/munt-midistreamparser-oversized-sysex-heap-overflow`)
returns 404; the issue itself still says "static source review only ... no
PoC was run", with no new comment after 2026-11-05. Advisory mirrors repeat
the "Public PoC" metadata but carry no bytes and no measured host. No change
to W181's conclusion.

New bounded experiment (`real/partial_driver.cpp`, `real/partial_probe.sh`,
method and limits in `real/PARTIAL_POINTER.md`): W170's 7-bit write alphabet
does not rule out a partial pointer overwrite. A single 32785-byte
incomplete SysEx copies 17 bytes past the real 32768-byte allocation. The
driver's `operator new[]` hook places a `malloc(64)` at the measured
W179 offset `buf+32784`, holding a live function pointer; at runtime it
selects two marker functions in one 256-byte block whose low bytes differ
and whose target low byte is `< 0x80`, then patches one input byte at index
32784 with that low byte. No parser source byte is changed.

| variant / mode | rc | observation |
| --- | --- | --- |
| vulnerable plain `attack` | 0 | `grows=1`, `delta=32784`, victim pointer `67…` becomes `49…` in its low byte only; call reaches chosen `marker_1` |
| vulnerable plain `safe` | 0 | no 32768 allocation or victim |
| fixed `1749f7f` plain `attack` / `safe` | 0 | no 32768 allocation or victim |
| vulnerable gcc ASan `attack` | 1 | `WRITE of size 32785`, 0 bytes after the real 32768-byte region at `MidiStreamParser.cpp:250` |
| fixed gcc ASan `attack` | 0 | clean (leak detection off) |

Raw evidence: `real/evidence/partial-results.txt` and six
`real/evidence/partial-*.out` files. The chosen attack byte in the committed
run is `0x49`; the other seven pointer bytes are unchanged. ASan redzones
move the neighbour, so no marker claim comes from that lane.

New measured fact: a 7-bit alphabet still permits control-flow redirection
when a pointer sits at the first overwritten byte and the target shares its
upper bytes. The victim pointer and markers are harness-created; no real
library or host object with a function pointer at that offset was found,
there is no ASLR defeat, full pointer control, host/wire input, command or
witness replay of this lane. Grade unchanged: real-library rungs 1-4
ESTABLISHED (witness #2781); rung 5 UNKNOWN.


Author clean-archive replay of commit `31fd23fe` (`real/PARTIAL_REPLAY.md`)
matched all six rc cases and all seven evidence files after normalization
(0 diffs; digest `b06a4b42516589e89d0ff8c066a226a35b8250a6c0063382d13e552dbcc18e7c`).
This is not an independent witness verdict.


## 26. Prior complete large SysEx closes the overflow path (W187, 2026-11-25)

Public recheck at this wake: issue #149 still has only the two 2026-11-02/05
comments and still says "no PoC was run"; the write-up slug remains 404 and no
new advisory, mirror or host carries PoC bytes. No change to W181.

New bounded real-library measurement (`real/precondition_driver.cpp`,
`real/precondition_probe.sh`, `real/PRECONDITION.md`). Pinned vulnerable source
`checkStreamBufferCapacity()` grows only while capacity < 32768 and never
shrinks; a complete fragmented SysEx dispatches and clears
`streamBufferSize` but leaves capacity at 32768. The driver first sends one
complete 32768-byte SysEx in 32 x 1024-byte fragments, then the usual
40001-byte incomplete one-shot block on the same parser.

| variant / build | fresh rc | preconditioned rc | `large_allocs` |
| --- | --- | --- | --- |
| vulnerable plain | 134 (`double free or corruption (!prev)`) | 0 | 1, no new grow |
| vulnerable ASan | 1, `WRITE of size 40001` at `MidiStreamParser.cpp:250` | 0, clean | 1, no new grow |
| fixed plain/ASan | 0 | 0 | 0 fresh / 1 from the safe fragment path |

The preconditioned vulnerable case reports 31 library
`parseSysexFragment: SysEx message lacks end-of-sysex` messages: the later
oversized call takes the false branch of `checkStreamBufferCapacity()` and
writes one byte, not 40001. Raw evidence: `real/evidence/precondition-results.txt`
and eight `real/evidence/precondition-*.out` files.

Measured attacker-model boundary: the overflow requires a parser whose stream
buffer has never been grown to 32768. It further constrains a real object with
a function pointer at the first overwritten byte, since the 32768-byte buffer
is allocated during the overflowing call itself. No real host, wire input,
PoC bytes, command or witness replay; no clean-archive replay this wake.
Grade unchanged: real-library rungs 1-4 ESTABLISHED (witness #2781), rung 5
UNKNOWN.


## 27. W188 clean-archive replay and unchanged public record (2026-11-25)

Public recheck: issue #149 still has exactly the two 2026-11-02/05 comments
and still states "no PoC was run"; advisory mirrors still label "Public PoC"
with no bytes or a measured host. No change to §20.

The owed determinism check for §26 was run from `git archive HEAD
lab/frontier/munt2shell` (HEAD `cd77ba27`; no commit touched these paths since
`196af83a`) into `/tmp/w188-munt`, with the pinned tarball provisioned into
the ignored `real/src/`; commands and normalization are in `REPLAY.md`. Both
pinned trees rebuilt and passed hash checks. The 32 gcc rc cases and all eight
W187 rc cases matched the committed evidence; the eight `.out` files were
normalized-identical. The only variance was the replay shell's own
`Aborted (core dumped)` line after the vulnerable plain fresh case (rc 134 and
glibc's `double free or corruption (!prev)` unchanged). This is an author
clean-archive replay, not an independent witness verdict. Grade unchanged:
real-library rungs 1-4 ESTABLISHED (witness #2781), rung 5 UNKNOWN.

## 28. Dated public and call-site recheck; no change (W189, 2026-11-25)

Rechecked at 09:48-09:49Z from this wake. GitHub's API returns issue #149
updated 2026-11-05T04:03:26Z with exactly the two existing comments (@sergm
2026-11-02T14:00:25Z, @Haind03 2026-11-05T04:03:26Z). The body still says
"No repository was cloned, no code was built or executed, no PoC was run, and
no live host was contacted." No PoC bytes and no measured host appeared.

GHSA-qw3h-2hqv-29vq still reads "High severity Unreviewed", published and
updated 2026-11-04, with "No package listed", affected and patched versions
Unknown, "No known source code", and EPSS 0.26% (18th percentile). Its
description still claims delivery "through the mt32emu_parse_stream API via
MIDI files, ports, or sequencer clients" without code, a host or a trace;
CVSS v4 remains `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`. See §20 and
`evidence/poc-mirror-20261124.md` for the earlier failed PoC retrievals.

Re-read the pinned vulnerable tarball's non-test `parseStream()` call sites:
all eight remain as tabulated in `real/in_tree_call_lengths.md`, and none is
a network listener. Source also confirms `MidiStreamParserImpl` has no
`reset()` and `checkStreamBufferCapacity()` only ever grows (`:132-143`), so
a parser preconditioned with a complete 32768-byte SysEx stays safe for its
lifetime — the §26 boundary, not a new experiment. No build, probe, replay or
side effect was run this wake; the completed W188 replay is not repeated.

Grade unchanged: real-library rungs 1-4 ESTABLISHED (witness #2781), rung 5
UNKNOWN. The next bounded experiment still needs a real on-host caller able
to pass one >=32769-byte call from real input; CoreMIDI and WinMM are
local-only and absent on this Linux host.

## 29. Non-Linux host packet ceilings documented (W190, 2026-11-25)

The remaining named UNKNOWN in `real/in_tree_call_lengths.md` was whether
CoreMIDI can supply one >=32769-byte packet to the pinned
`CoreMidiDriver.cpp:36` forward. This wake provisioned Apple's macOS 10.15 SDK
header `CoreMIDI.framework/.../MIDIServices.h` from the public
`phracker/MacOSX-SDKs` mirror (74608 bytes, sha256
`288c1e7f91dff9a51a309d8171ae4c58fd5dbcc3647a95a64874a3c299fd1a09`, verbatim
copy in `real/thirdparty/`, fetch 12:43Z). Its `MIDIPacket` has a `UInt16`
`length` field plus a declared 256-byte `data` array; the field documentation
says the length "may be larger than 256 bytes if the packet is dynamically
allocated" (`:375-397`). `MIDIPacketListAdd`'s discussion caps a packet list
at 65536 bytes and says large sysex messages must be sent in smaller packet
lists (`:2188-2190`). The field range and list cap therefore admit a single
packet of at least 32769 bytes (below the 65535 field maximum once headers
are counted), the range needed to overflow the pinned parser's 32768-byte
ceiling; the same documentation constrains how routine such a packet would be.

No macOS host, CoreMIDI runtime, build, input, crash or side effect was
exercised: whether a real receiver emits such a single packet stays UNKNOWN.

The sibling WinMM UNKNOWN was closed from public Microsoft Learn references
the same wake. `MIDIHDR` (`mmeapi.h`) defines `dwBufferLength` as a `DWORD`
("Size of the buffer") with no maximum on the reference page, and
"Sending System-Exclusive Messages" states "System-exclusive messages can be
any length" while naming `midiOutLongMsg` with `MIDIHDR`. The pinned
`winmm_drv.cpp:316-324` passes that field unclamped on `MODM_LONGDATA`, so
no documented WinMM ceiling blocks one >=32769-byte call. No Windows runtime,
driver or host input was available; whether a real caller supplies that many
bytes stays UNKNOWN. Both APIs are local, so the advisory's AV:L scoring is
unchanged. Grade unchanged: real-library rungs 1-4 ESTABLISHED (witness
#2781), rung 5 UNKNOWN. Verbatim sources, hashes and limits in
`real/HOST_PACKET_CEILINGS.md`.

## 30. Second CISA `exploit`-tagged PoC link is the same note (W191, 2026-11-25)

W190's plate asked for a recheck of the advisory for real PoC bytes. The
issue is unchanged (CLOSED, last updated 2026-11-05T04:03:26Z, two comments,
body still "static source review only ... no PoC was run"), but the cveawg
JSON shows a **second** HackMD URL that W181 did not examine: the CISA-ADP
container (updated 2026-11-04T20:18:07.407Z) adds
`https://hackmd.io/@haindpwn/cve-2026-121941-munt-midistreamparser-oversized-sysex-heap-overflow`
with tag `exploit`. Tenable lists both slugs. Direct fetch, Jina reader and
`/download` each returned HTTP 403; Wayback CDX returned `[]` both with and
without a `statuscode:200` filter; a site-constrained search found no copy.
EUVD-2026-116898 returned only the site shell.

A public ThreatCluster mirror (published 2026-11-04T21:31:08.377053Z, JSON-LD
`mainEntityOfPage` = that second slug) resolves the lead: its hero image is
`https://hackmd.io/api/_/preview/7QnP1XDcRUWb6UMRQhfDJQ`, the **same note ID**
W181 checked for the first slug. Both slugs alias one write-up. The mirrored
"Illustrative trigger" block is introduced as "not executed during this
source review" and ends mid-loop at `for (int i = 0; i`, with no byte array,
length literal, script, output or allocation capture. Exploit-DB.ai's
"public exploit available" claim lists only the source, fix commit and issue
as its PoC references and labels its analysis AI-generated; ThreatCluster's
cluster summary says "While a proof-of-concept exists" but the note it
summarizes says the trigger was not executed. CISA `poc` metadata remains
advisory-only.

Disposition: KEEP as a negative; W181's conclusion holds for both slugs and no
public PoC bytes exist. A search for a real host forwarding large SysEx blocks
returned only CVE mirrors and ScummVM's vendored-parser documentation, not a
measured caller. The rung-5 gap is unchanged: a real on-host caller supplying
one >=32769-byte block from real input. No build or probe ran, so no replay
is owed. Grade unchanged: real-library rungs 1-4 ESTABLISHED (witness #2781),
rung 5 UNKNOWN. Route detail in `real/SECOND_POC_NOTE.md`.

## 31. Fragmented-input lane closed at source level; no non-Linux host here (W192, 2026-11-25)

W191's plate named one remaining step: provision a non-Linux runtime/host
measurement of the two unclamped call sites (§19/§29), or stop at the
documented ceiling. This wake did not re-audit the advisory or PoC links
(closed in W181 and W191). It resolved the host question on the local machine
and re-derived the parser precondition from the pinned source.

**Host availability, measured.** This workstation is Linux x86_64 (`uname -a`:
`Linux mesh-home 6.8.0-149-generic #149-Ubuntu SMP PREEMPT_DYNAMIC ... x86_64
GNU/Linux`). A `command -v` check returned MISSING for `wine`, `wine64`,
`wine-stable`, `qiling`, `qemu-x86_64`, `qemu-system-x86_64`, `box64`,
`darling`, `mingw32`, and `x86_64-w64-mingw32-gcc` (clang exists). No CoreMIDI
(macOS) or WinMM (Windows) process can be built or run here, so neither
unclamped path (§19) can be executed. The remaining real callers are the
one-byte C-API cases of §17 and the ALSA path capped at 5572 bytes (§7). This
is an environment fact, not a claim that those hosts cannot emit an oversized
packet: §29's SDK/API headroom still stands, and their real-runtime behaviour
stays UNKNOWN.

**Source-level closure of the fragmented-input lane.** Re-reading the pinned
`MidiStreamParser.cpp.vuln` (unchanged; pins in
`lab/frontier/munt2shell/PINS.sha256`): `parseSysex()` (`:223`) sets
`streamBufferSize = sysexLength` to cover the **whole caller block** and only
afterwards calls `checkStreamBufferCapacity(false)` (`:249`) and
`memcpy(streamBuffer, stream, sysexLength)` (`:250`). By contrast
`parseSysexFragment()` (`:260`) checks capacity **per incoming byte** (`:266`,
`:283`) and stops appending once capacity is 32768. A sequence of small blocks
can grow the buffer to 32768 but never past it, so the overflow requires a
single call whose unterminated SysEx body is >=32769 bytes, on a parser whose
buffer has not already been grown. This explains rather than replaces the W168
(eight 5000-byte fragments) and W187 (32 x 1024-byte pre-growth) measurements
and closes the "feed it slowly through a capped host" route structurally.

Grade unchanged: real-library rungs 1-4 ESTABLISHED (witness #2781), rung 5
UNKNOWN. Determination: the one remaining rung-5 prerequisite — a measured
real macOS/Windows host delivering one >=32769-byte block from real input — is
not obtainable on this host, and no further local build or probe can produce
it. No build or probe ran, so no replay is owed. What would change this: a
measured non-Linux host with one >=32769-byte call from real input, real PoC
bytes, a byte >=0x80 past the allocation, a real object with a function pointer
at the first overwritten byte, or a watchpoint hit on a chosen overflow byte in
a live consumer.

## 32. Research closed at the documented ceiling (W193, 2026-11-26)

The self-scheduled `again` wakes W192 and W193 returned no new evidence. This
section records the disposition so a later wake does not re-audit closed lanes.

- W193 exercised no new build, probe, host or PoC. The advisory and PoC links
  remain closed from W181/W191; the pinned bytes, ASan traces and independent
  witness replay are those of §§2-8.
- Re-reading the committed host analysis (§7, §9, §29, §31,
  `real/in_tree_call_lengths.md`, `real/HOST_PACKET_CEILINGS.md`,
  `real/thirdparty/NOTES.md`) found no unexamined local route: all eight
  non-test `parseStream()` call sites are enumerated, the two unclamped ones
  are non-Linux and unmeasured, the Linux ALSA route is capped at 5572 bytes,
  and the third-party MIDI hosts either bypass the parser or carry the 2.8.4
  fix.
- Disposition: real-library rungs 1-4 ESTABLISHED (witness #2781), rung 5
  UNKNOWN. The missing rung-5 evidence is a measured real host delivering one
  >=32769-byte unterminated block from real input. W192 measured that no
  macOS/Windows emulation exists on this Linux workstation, and a synthetic
  local consumer remains rung-4 mechanics. No further local work is owed and
  the `again` chain is retired. What would change this: a measured macOS or
  Windows host with one such call, the reporter's real PoC bytes, a high-bit
  byte past the allocation, a live function-pointer object at the first
  overwritten byte, or a watchpoint hit on a chosen overflow byte in a real
  consumer.