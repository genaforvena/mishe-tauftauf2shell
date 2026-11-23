# ALSA sequencer consumer ceiling (munt2shell, 2026-11-23)

Question: the pinned tarball contains an in-tree Linux host,
`mt32emu_alsadrv/src/alsadrv.cpp`, whose ALSA sequencer input path creates an
`EVENT_SYSEX` from `seq_ev->data.ext.len` at `:682-688` and forwards the whole
buffer in one call to `SysexHandler::parseStream()` at `:1182`. Can that host
deliver the 40001-byte first fragment that the real-library ASan lane needs?

Measurement (not assumption): `alsa_probe.c` opens a duplex ALSA sequencer
client, self-subscribes a port, sends `SND_SEQ_EVENT_SYSEX` variable events of
a chosen payload length and reads them back on loopback. Client pools were set
to 131072. Raw sweep: `evidence/alsa-sweep.txt`.

- Payloads up to **5572 bytes** are delivered intact
  (`ext.len` matches, first `0xF0`, last `0x5a`); ALSA reports
  `rc = len + 28`.
- Payload **5573 bytes and above** (including 40001) are rejected by the
  kernel with `-12` (ENOMEM); the listener sees `rc=-28`. The boundary did
  not move when the client pools were enlarged from 4096 to 131072.
- The working ceiling is `5572 + 28 = 5600` bytes per event, far below the
  32769 bytes needed to overflow the parser's 32768-byte buffer in one call.

Source check (host code, pinned 2.8.3 tarball): `alsadrv.cpp:682-688` copies
one ALSA event into one `EVENT_SYSEX`; `:1182` calls `parseStream()` once per
event. A first fragment at or below 5572 bytes takes the vulnerable grow
branch safely (buffer grows to 32768, copies at most 5572). Later fragments
go through `parseSysexFragment()` at `MidiStreamParser.cpp:260-295`, which is
bounded by `checkStreamBufferCapacity()` and is not the reported defect.

**Result: this in-tree Linux host path is structurally closed for this defect
on this host.** It is a measured negative for a specific consumer on this
kernel, not a claim about every ALSA configuration or about other hosts such
as `mt32emu_qt` (Qt5 unavailable here) or third-party users of the C API.
The C API itself remains an unclamped forward (`c_interface.cpp:758-760`); a
host supplying bulk bytes by another route could still reach the defect.
Rung 5 stays UNKNOWN. No external system was probed: all events went to the
probe's own port through the local kernel sequencer.
