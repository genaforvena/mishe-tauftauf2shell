# Non-Linux host packet ceilings: CoreMIDI and WinMM (munt2shell W190, 2026-11-25)

## Question

`real/in_tree_call_lengths.md` left one UNKNOWN: the pinned vulnerable tree's
`mt32emu_qt/src/mididrv/CoreMidiDriver.cpp:34-36` passes `packet->length`
straight to `parseStream()` with no clamp, but no Apple SDK header or runtime
had been consulted, so it was unknown whether CoreMIDI can deliver one packet
>=32769 bytes. This wake consults public headers/docs only. **No macOS host,
CoreMIDI runtime, build, input, crash or side effect was exercised.**

## Provisioned reference (public source fetch, not lab testing)

- URL: `https://raw.githubusercontent.com/phracker/MacOSX-SDKs/master/MacOSX10.15.sdk/System/Library/Frameworks/CoreMIDI.framework/Versions/A/Headers/MIDIServices.h`
- Fetched 2026-11-25 12:43Z; 74608 bytes; stored verbatim here as
  `thirdparty/MacOSX10.15-MIDIServices.h` with sha256
  `288c1e7f91dff9a51a309d8171ae4c58fd5dbcc3647a95a64874a3c299fd1a09`.

Verbatim excerpts (line numbers in the stored header):

```
375:	@field			length
376:						The number of valid MIDI bytes which follow, in data. (It
377:						may be larger than 256 bytes if the packet is dynamically
378:						allocated.)
...
392:struct MIDIPacket
393:{
394:	MIDITimeStamp		timeStamp;
395:	UInt16				length;
396:	Byte				data[256];
397:};
...
2188:	@discussion
2189:		The maximum size of a packet list is 65536 bytes. Large sysex messages must be sent in
2190:		smaller packet lists.
```

## Measured facts and limits

- The `length` field is `UInt16` (field range up to 65535), and the SDK
  explicitly documents packets larger than the declared 256-byte `data`
  array when dynamically allocated. Packet lists are capped at 65536 bytes
  including packet headers, so the usable single-packet range is somewhat
  below the field maximum but still contains 32769..65535. That is the
  single-call size the pinned parser needs to overflow its 32768-byte
  ceiling.
- The same sentence warns that large SysEx messages must be sent in smaller
  packet lists. It constrains how routine a 32769+-byte **single packet** would
  be; it does not prove one cannot be received from a local MIDI source.
  Whether a real CoreMIDI receiver ever delivers such a packet is **UNKNOWN**:
  no macOS, CoreMIDI runtime or Apple driver was available or run here.
- The pinned Munt-side forward remains unclamped:
  `mt32emu_qt/src/mididrv/CoreMidiDriver.cpp:34-36` calls
  `qMidiStreamParser.parseStream(packet->data, packetLen)` for each packet.
  CoreMIDI is a local host API, not a network listener; this does not alter the
  advisory's AV:L scoring.

## WinMM long-SysEx buffer length (second open path)

Microsoft Learn references fetched 12:45Z from public pages (provisioning,
not lab testing):

- `https://learn.microsoft.com/en-us/windows/win32/api/mmeapi/ns-mmeapi-midihdr`
  defines `MIDIHDR::dwBufferLength` as a `DWORD` and says only "Size of the
  buffer"; `dwBytesRecorded` "should be less than or equal to" it. No maximum
  is stated on that reference page.
- `https://learn.microsoft.com/en-us/windows/win32/multimedia/sending-system-exclusive-messages`
  states: "MIDI system-exclusive messages are the only MIDI messages that will
  not fit into a single doubleword value. System-exclusive messages can be any
  length." It names `midiOutLongMsg` and `MIDIHDR` as the API pair.

The pinned Munt path `mt32emu_win32drv/src/winmm_drv.cpp:316-324` handles
`MODM_LONGDATA` with a prepared `MIDIHDR` and passes
`midiHdr->dwBufferLength` unclamped to `parseStream()`. The documented WinMM
API therefore imposes no 32768-byte ceiling on that field, so one >=32769-byte
call is structurally possible from a local WinMM application. No Windows
header, driver, runtime or host input was available here: whether a real
`MODM_LONGDATA` sender ever supplies that many bytes remains UNKNOWN.

## Disposition

Both named UNKNOWNs in `in_tree_call_lengths.md` are narrowed from "no
SDK/header consulted" to "documented field/API headroom, host behaviour
unmeasured". Neither upgrades the grade: rungs 1-4 remain ESTABLISHED
(witness #2781), rung 5 UNKNOWN. What would change that: a measured macOS or
Windows process passing one >=32769-byte block from real input, with a chosen
side effect and an independent witness replay.

