# In-tree `parseStream()` call lengths (munt2shell W180, 2026-11-24)

## Question

Report §13 concluded "No consumer in this tree can deliver a single oversized
SysEx to the flawed parser." That overstates a result that was only measured
for the Linux ALSA path. This file audits the **actual length argument** at
every non-test `parseStream()` call site in the pinned vulnerable release
tree, from source only. No host was built or run on this Linux workstation.

Source root: `src/vuln-2_8_3/` (pinned `libmt32emu_2_8_3` tarball, sha256
`81f8c462f46bc8901618762ae34cf9de93894ff81f41db73c79472fa3baef875`).

Reproduce the call-site set:

```
grep -rn --include='*.cpp' --include='*.h' 'parseStream(' src/vuln-2_8_3/ \
  | grep -v '/test/' | grep -v 'MidiStreamParser.cpp:' | grep -v 'MidiStreamParser.h:'
```

## Complete non-test call-site set and the length actually passed

| Call site | Length argument | Bound in pinned tree | Reaches >32768 in one call? |
| --- | --- | --- | --- |
| `mt32emu/src/c_interface/c_interface.cpp:760`, `:765` | caller `length` | none | yes (public C API; W178's third-party callers all pass 1) |
| `mt32emu/src/c_interface/cpp_interface.h:280` | caller `length` | none | yes (wrapper over the C API) |
| `mt32emu_alsadrv/src/alsadrv.cpp:1182` | `newev.sysex_len` | kernel event ceiling, measured 5572 (`ALSA_CEILING.md`) | no, measured |
| `mt32emu_qt/src/mididrv/OSSMidiPortDriver.cpp:95` | `messageLength` | `BUFFER_SIZE = 1024`, `read(fd, buffer, BUFFER_SIZE)` at `:34,:65` | no, static |
| `mt32emu_qt/src/mididrv/Win32Driver.cpp:135` | `longDataLength` | `RING_BUFFER_SIZE = 0x8000` (32768), `:31`; `longDataLength = dataBlockLength - DATA_HEADER_LENGTH` with `DATA_HEADER_LENGTH = 8`, `:111`; max 32760 | no, static |
| `mt32emu_qt/src/mididrv/Win32Driver.cpp:383` | `pMIDIhdr->dwBytesRecorded` | `MidiInHdr.dwBufferLength = 4096`, `:411` | no, static |
| **`mt32emu_qt/src/mididrv/CoreMidiDriver.cpp:36`** | **`packet->length`** | **none in Munt**; CoreMIDI `MIDIPacket.length` is a 16-bit field | **yes, source-reachable** |
| **`mt32emu_win32drv/src/winmm_drv.cpp:324`** | **`midiHdr->dwBufferLength`** | **none in Munt**; caller-supplied `MIDIHDR` on a public `MODM_LONGDATA` driver entry point | **yes, source-reachable** |

## The two open paths, verbatim

`CoreMidiDriver.cpp` (sha256
`71aea35c2ddb559e122720a29715e8a4146a3d294d2b6b49050a443268a5f866`):

```
24:void CoreMidiDriver::readProc(const MIDIPacketList *packetList, void *readProcRefCon, void *) {
31:	MIDIPacket const *packet = &packetList->packet[0];
32:	UInt32 numPackets = packetList->numPackets;
33:	while (numPackets > 0) {
34:		UInt32 packetLen = packet->length;
35:		if (packetLen > 0) {
36:			qMidiStreamParser.parseStream(packet->data, packetLen);
```

`winmm_drv.cpp` (sha256
`2d3893c083836f466673db67b703101e19fe55f30d38ced1687a3caa1e9c9f9b`):

```
316:	case MODM_LONGDATA: {
320:		MIDIHDR *midiHdr = (MIDIHDR *)dwParam1;
321:		if ((midiHdr->dwFlags & MHDR_PREPARED) == 0) {
322:			return MIDIERR_UNPREPARED;
323:		}
324:		driver.clients[dwUser].midiStreamParser->parseStream((const Bit8u *)midiHdr->lpData, midiHdr->dwBufferLength);
```

`modMessage` is the driver's exported `DriverProc` message handler
(`winmm_drv.cpp:73,244`); `MODM_LONGDATA` is the standard Win32 multimedia
"long MIDI output data" message. The `MIDIHDR` and its buffer are supplied by
the calling application, so the length is not chosen by Munt.

Both parsers are the vulnerable library class, not a lookalike:

- `MidiSession.h:37` — `class QMidiStreamParser : public MT32Emu::MidiStreamParser`
  (sha256 `c7834edaaf4c86d672bb25537dbe9d1b4c769905579e79f0210159e7c41eccd4`).
- `MidiStreamParser.h:58,70,91` — `MidiStreamParserImpl::parseStream()` is
  non-virtual and calls private `parseSysex()`; `MidiStreamParser : public
  MidiStreamParserImpl` at `:96`
  (sha256 `fd5bc8e65dd4593d2928f464015e760fca57a5b8b812770434f2372f28111964`).
- `winmm_drv.cpp:189` — local `class MidiStreamParserImpl : public MidiStreamParser`.

## Limits

- Source-level reachability only. No macOS or Windows host exists on this
  Linux workstation (Qt5 absent; no CoreMIDI, no Win32 MM). Neither path was
  built, run or driven with input; there is no crash, trace or side effect.
- CoreMIDI: Apple's macOS 10.15 SDK header was consulted in W190 (verbatim
  copy and hashes in `HOST_PACKET_CEILINGS.md`). `MIDIPacket.length` is
  `UInt16` and is documented to exceed the declared 256-byte `data` array
  when dynamically allocated; packet lists are capped at 65536 bytes
  including headers. The documented contract admits a single packet of at
  least 32769 bytes, but the same documentation says large SysEx messages
  must be split across lists.
  Whether a real receiver ever emits such a single packet remains UNKNOWN.
- WinMM: Microsoft Learn's `MIDIHDR` reference defines `dwBufferLength` as a
  `DWORD` ("Size of the buffer") with no stated maximum, and its
  "Sending System-Exclusive Messages" page says "System-exclusive messages
  can be any length" (`HOST_PACKET_CEILINGS.md`). No Windows runtime was
  consulted, so whether a real `MODM_LONGDATA` caller supplies >=32769 bytes
  remains UNKNOWN. The Munt-side fact is that neither path bounds the value
  before the copy.
- These are local host APIs, not remote listeners. The advisory scores AV:L;
  this audit does not change that. Rung 5 still requires a measured live
  process, attacker-controlled input, a chosen command side effect and a
  witness replay.

## Consequence

§13's unqualified "No consumer in this tree can deliver a single oversized
SysEx" is corrected to: no consumer **on this Linux host** does; two pinned
non-Linux host paths pass caller-controlled lengths unclamped and remain
untested. Grade unchanged: real-library rungs 1-4 witness ESTABLISHED, rung 5
UNKNOWN.
