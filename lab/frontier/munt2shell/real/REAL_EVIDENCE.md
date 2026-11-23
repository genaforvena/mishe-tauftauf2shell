# munt2shell — real libmt32emu build (W159 follow-up, 2026-11-23)

This lane upgrades the staged direct-call harness to the **real library**. No
parser code, type or allocator is stubbed: the static `mt32emu` target is built
by the project's own CMake files from the pinned source, and the driver calls
the real `Synth`, `DefaultMidiStreamParser` and public C API. The only harness
artifact is a plain-build readable tail appended by a replacement global
`operator new[]` (see ceiling below); ASan builds use the real allocator.

## Provenance (verified this wake)

- Provisioned `https://github.com/munt/munt/archive/refs/tags/libmt32emu_2_8_3.tar.gz`,
  sha256 `81f8c462f46bc8901618762ae34cf9de93894ff81f41db73c79472fa3baef875`.
- Vulnerable tree `src/vuln-2_8_3`: the three pinned files hash exactly to
  `PINS.sha256` (MidiStreamParser.cpp `0d9424e0…ef785810814753e213f20`).
- Fixed tree `src/fixed-1749f7f`: pinned `pins/fix.patch` applied with `patch -p1`
  to a copy of the same tarball; MidiStreamParser.cpp becomes
  `6031e579d0777276ff49f1be0afec5cfd879716330108d32f810612268cf0c3a`, exactly
  the pinned fixed hash. Both source trees are gitignored and regenerable
  with `./prepare_src.sh` (see `../REPLAY.md`).

## Commands

```
cd lab/frontier/munt2shell/real
./prepare_src.sh        # verify tarball + pins; extract; patch; rehash trees
./build_and_run.sh      # gcc: 2 variants x {asan,plain} x 8 scenarios
./build_clang_asan.sh   # clang ASan: C API attack, vuln and fixed
```

Inputs: `driver.cpp`; scenario `*-attack` is one `0xF0` + 40000 x `0x5a` slice
with no `0xF7` (40001 bytes), fed in a single `parseStream` call. Controls:
102-byte terminated SysEx, 101-byte incomplete fragment, pinned-fixed build.

## Observed (raw output in `evidence/`)

- **ASan, real library, gcc** (`vuln-2_8_3-asan-{default,capi}-attack.out`):
  `heap-buffer-overflow`, `WRITE of size 40001`, `0 bytes after 32768-byte
  region`, at the real source line `MidiStreamParser.cpp:250`; allocation from
  `checkStreamBufferCapacity()` at `:137`, called from `:249`, called from
  `parseStream()` at `:106`. The `capi` stack additionally shows
  `mt32emu_parse_stream` at `c_interface.cpp:760` — the public C ABI forwards
  the caller's byte block without a size bound.
- **ASan, real library, clang** (`vuln-2_8_3-clang-asan-capi-attack.out`):
  same write size, same 32768-byte region, `MidiStreamParser.cpp:250:3`.
- **Plain build readback** (`vuln-2_8_3-plain-{default,capi,count}-attack.out`):
  one 32768-byte allocation and **7233 of 0x5a bytes** in the 16384-byte
  readable tail immediately past it — exactly `40001 - 32768`. First 16 tail
  bytes are `5a5a…`. Fixed build: zero 32768-byte allocations, zero chosen
  bytes, `rc=0` in every scenario.
- **Controls**: terminated 102-byte SysEx dispatches one `handleSysex` with
  `lastlen=102` in both builds; the 101-byte fragment dispatches none.
- **Post-write consumer probe** (`vuln-2_8_3-plain-count-attack-complete.out`):
  feeding `0xF7` after the oversized first slice yields `sysex=0` and exactly
  one debug report (streamBuffer overrun). In this minimal host the library
  never dispatches the corrupted buffer: `parseSysexFragment()` sees capacity
  already at `MAX_STREAM_BUFFER_SIZE`, takes the discard path at `:289-291`,
  and the only later read of the buffer is `streamBuffer[0]` (in bounds).
  The overwritten bytes are not consumed by libmt32emu on this path before
  process exit. This is a negative result for an in-library live consumer,
  not proof that no application can be affected.

## Source-observed reachability (claim, not a runtime wire test)

`mt32emu/src/c_interface/c_interface.cpp:758-760` implements
`mt32emu_parse_stream()` as an unclamped forward to the parser, and
`:573,751` instantiate `DefaultMidiStreamParser`. A host that passes
attacker-controlled bulk MIDI bytes to that C API reaches the defect. No
host application, MIDI file/device/port, socket, wire input, audio pipeline,
pointer control, command or marker side effect was tested. Independent
witness chat #2781 replayed this lane from a clean archive and returned
ESTABLISHED at rungs 1-4; the issue's network-forwarding narrative remains a
claim and rung 5 stays UNKNOWN.

## Ceiling

Real-library rungs 1-4 (rung 3 ASan in gcc and clang at the exact upstream
source line, rung 4 chosen bytes at the real allocation boundary). The tail
is a harness observation region, not an upstream object; no claim is made
that it is a live allocator neighbour. No rung-5 path was measured.
