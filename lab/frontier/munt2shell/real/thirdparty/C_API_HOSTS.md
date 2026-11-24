# Real third-party `mt32emu_parse_stream` hosts (W178, 2026-11-24)

Reachability evidence only; no exploitability claim. All fetches are
provisioning (raw.githubusercontent.com), 2026-11-24. Line numbers are from the
fetched bytes at the recorded sha256, not from a local checkout. Four sites
were re-fetched and quoted directly; the remaining two were reported by a
read-only scout from the same URLs and are marked `scout-only`.

Sourcegraph public search (`context:global mt32emu_parse_stream
-file:c_interface.cpp -file:cpp_interface.h -file:c_interface.h -file:c_types.h
count:100`) returned 12 non-library matches with no limit hit. searchcode's
legacy API returned HTTP 404 (site now MCP-only); GitHub code search was
login-walled. Sourcegraph excludes forks and archived repos by default, so the
list is not exhaustive.

## FS-UAE — verified, one byte per call

`https://raw.githubusercontent.com/FrodeSolheim/fs-uae/master/midiemu.cpp`
sha256 `5b083f7f02c955baadb167517dc6d6b44201cdd87e08373158a4105a0d4641d2`:

```c
237:void midi_emu_parse(uae_u8 *midi, int len)
238:{
239:	if (mt32context) {
240:		mt32emu_parse_stream(mt32context, midi, len);
241:	}
242:}
```

`.../od-fs/parser_fs.cpp` sha256
`9390ac73e650ee5463fb532d23032ee486e42c765cf5403d5fea760747a7469d`, inside
`writeser()` (guest serial byte write):

```c
518:#ifdef WITH_MIDIEMU
519:	} else if (midi_emu) {
520:		uae_u8 b = (uae_u8)c;
521:		midi_emu_parse(&b, 1);
522:#endif
```

The scout also found one-byte callers at `od-unix/serial.cpp:356` and
`od-win32/parser.cpp:1282` (scout-only).

## WinUAE — verified, one byte per call

`https://raw.githubusercontent.com/tonioni/WinUAE/master/midiemu.cpp` sha256
`4132d05a47f450934685bea74aeb0643c3569cb86a60fb7d6510085c830fa75c`:

```c
202:void midi_emu_parse(uae_u8 *midi, int len)
203:{
204:	if (mt32context) {
205:		mt32emu_parse_stream(mt32context, midi, len);
206:	}
207:}
```

Callers `od-unix/serial.cpp:363`, `od-win32/parser.cpp:1282` pass `&byte, 1`
(scout-only).

## Amiberry — verified caller, wrapper scout-only

`https://raw.githubusercontent.com/BlitterStudio/amiberry/master/src/osdep/amiberry_serial.cpp`
sha256 `9794b90bb378fa8aedfd643758cfa6449b61517561a9dd3e8aba14d3738146bd`:

```c
896:#ifdef WITH_MIDIEMU
897:	} else if (midi_emu) {
898:		auto b = static_cast<uae_u8>(c);
899:		midi_emu_parse(&b, 1);
900:#endif
```

Wrapper `src/midiemu.cpp:249-253` (sha256
`aa44005343283e63ae303f0c98cc6c9a1f3d814079727891658bb7ab7ad0c585`) and the
no-op `libretro/libretro_stubs.cpp:220-224` are scout-only.

## dosemu2 — verified, one byte per call

`https://raw.githubusercontent.com/dosemu2/dosemu2/master/src/plugin/munt/munt.c`
sha256 `d9c05bc6c81bf7dc49d16e4c2811aa8895feefb7559cf701f2b78c4b5164f0a9`,
inside `midomunt_write(unsigned char val, ...)`, which is registered as the
synth `.write` callback at `:233`:

```c
131:    now = GETusTIME(0);
132:    /* timstamp is measured in samples */
133:    tstamp = (now - mf_time_base) * munt_srate / 1000000;
134:    mt32emu_parse_stream_at(ctx, &val, 1, tstamp);
135:}
```

## libretro-uae — scout-only

`sources/src/midiemu.c:197-201` wraps the C API; symbol search found no other
caller in that repository.

## Disposition

Every verified call passes exactly one byte; an oversized SysEx therefore
arrives as single-byte fragments and cannot reach the vulnerable one-shot
`parseSysex()` copy (report §9). Together with §§13-14 this closes the
third-party host route examined here. Not exhaustive: Sourcegraph omits
forks/archived repos, and a measured host outside the indexed set remains the
one fact that would change the grade.
