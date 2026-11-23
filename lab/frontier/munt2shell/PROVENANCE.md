# munt2shell — provenance and preserved negatives

## Provenance

- Candidate found from a public issue (read-only provisioning):
  https://github.com/munt/munt/issues/149, opened 2026-11-01 by @Haind03,
  closed 2026-11-05. Reporter's static review claimed an oversized-SysEx heap
  write in `MidiStreamParserImpl::parseSysex`; no runtime PoC was claimed.
- Vulnerable bytes: library tag `libmt32emu_2_8_3`, raw
  `mt32emu/src/MidiStreamParser.cpp`, `MidiStreamParser.h`, `globals.h`.
  Tag object `008feb32227a16bad343573b33da2196656b8e93`.
- Fixed bytes: upstream commit `1749f7fed5cdb3a9015acce076a1512b1615dc3b`
  (2026-11-02), the fix named in the issue thread by the maintainer, same
  three paths. Patch: `https://github.com/munt/munt/commit/1749f7f.patch`.
- The fix hunk is also present at raw tags `libmt32emu_2_8_4` and `munt_2_8_4`.
  Raw `MidiStreamParser.cpp` at `munt_2_8_3` already contains the fix, so the
  issue's "latest release 2.8.3" refers to the library tag namespace; both
  tag bodies were checked and the difference is preserved here.
- No probe was sent to any external host: only issue, raw source, patch and
  advisory pages were fetched. All seven fetched files are hashed in
  `PINS.sha256`.

## What is verbatim and what is a stub

| variant | pinned slice | source file |
|---|---|---|
| vuln | `:68-295` (constructor through `parseSysexFragment`) | `pins/MidiStreamParser.cpp.vuln` |
| fixed | `:68-299` (same functions, fixed) | `pins/MidiStreamParser.cpp.fixed` |

Slices are emitted by `harness/run.sh` under `#line` control into
`driver-{vuln,fixed}.cpp`. Declared stubs in the generated header: `Bit8u` and
`Bit32u` typedefs, the two 32768/1000 buffer-size constants quoted from
`globals.h:122,145,127,148`, an empty `MT32EMU_EXPORT`, `Synth` with only
`getShortMessageLength()` (unused by the SysEx scenarios), the
`MidiReceiver`/`MidiReporter` abstract interfaces copied from the pinned
header, and the `MidiStreamParserImpl`/`MidiStreamParser` declarations copied
from the pinned header. The driver derives a `TestParser` that counts
dispatched messages. No synth, MIDI device, file parser, socket, audio
pipeline or libmt32emu build is involved.

Plain builds replace global `operator new[]` with a `malloc` that appends a
16384-byte `0xa5` canary, so chosen bytes at offsets 32768+ can be read after
the copy; ASan builds use the real allocator to catch the first out-of-bounds
write. This canary is a harness artifact, not upstream allocator behavior.

## Scenarios and rungs

- `baseline`: 102-byte terminated SysEx (`0xF0` + 100 data bytes + `0xF7`);
  one `handleSysex` call, length 102, no overflow.
- `fragment`: 101-byte incomplete SysEx; buffer grows to 32768 and copies 101
  bytes safely; no dispatch.
- `attack`: 40001-byte incomplete SysEx (`0xF0` + 40000 bytes of `0x5a`, no
  `0xF7`); `sysexLength=40001`, buffer grows to 32768, `memcpy` of 40001 bytes
  writes chosen `0x5a` from offset 32768 through offset 40000.

Rung 3 (gcc and clang ASan) reports `WRITE of size 40001`, 0 bytes after a
32768-byte region, at pinned `MidiStreamParser.cpp.vuln:250`, allocated at
`:137` from `:249`, stack through `parseStream :106`. Rung 4 (gdb, plain
vulnerable) shows `g_last_size = 32768` and sixteen `0x5a` bytes at
`g_last_alloc+32768`. Fixed builds return 0 for all three scenarios with no
ASan report and no chosen bytes past the boundary.

## Commands and results

```
cd lab/frontier/munt2shell/harness
./run.sh     # generate 2 drivers, build 8 binaries
./check.sh   # 24 runs + gdb probe -> PASS/FAIL + trace hash
```

First run: `PASS=129 FAIL=0
TRACE=735c136e1c6740ca50ed5790f054cbd4331c16a1d48998b22926de8ac0d1146f`.
Trace excludes PID, addresses, paths and build ids; raw outputs are in
`harness/evidence/`. Three consecutive check runs and a clean-archive replay
are recorded in `REPLAY.md`.

## Preserved negatives and corrections

- First plain-build check attempt segfaulted in the fixed-build `attack`
  scenario: the harness read canary bytes at `buf+32768` when the fixed path
  never allocated a 32768-byte buffer. Fixed by recording the allocation size
  in the stub allocator and reading the canary only when that size is at
  least 32768. Not a property of upstream code.
- The initial 1024-byte canary was smaller than the 7233-byte overflow; the
  vulnerable plain build aborted in `malloc()` with "corrupted top size".
  Enlarged to 16384 bytes; the plain build then returns 0 with chosen bytes
  observable, while ASan still catches the very first out-of-range write.
- The first gdb probe stopped at the `delete[]` inside
  `checkStreamBufferCapacity()` (the old 1000-byte buffer, before the copy)
  and showed unchanged `0xa5` canary bytes. `ignore 1 1` moves it to the
  destructor's free after the copy, where the 0x5a bytes are present.
- `gcc file.cpp` links without libstdc++ here; drivers are built with `g++`
  and `clang++`. Both are labelled gcc and clang in the binaries and evidence.
- The GitHub advisory API ignores `cwe_id`, `severity`, `sort`, `page`,
  `since` and `until` query parameters on this host: each request returns the
  same 100-entry window. No advisory covering this munt issue was found in
  that window; the absence of a CVE/GHSA is UNKNOWN rather than proven.
- The reporter's claim of attacker-controlled MIDI/network inputs is not
  reproduced here; there is no evidence of a reachable network parser in
  libmt32emu itself. Rung 5 remains UNKNOWN.
