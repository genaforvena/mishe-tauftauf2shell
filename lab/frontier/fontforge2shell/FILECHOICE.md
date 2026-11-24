# FILECHOICE — file-chosen bytes in a real consumer of the poisoned chunk (W7, 2026-11-24 20:0xZ)

Scope: real headless FontForge 20251009, non-ASan Debug `build-plain/`,
patched `build-fixed-plain/`, ASan `build-asan/` and patched `build-fixed/`,
scripting `Import()` of locally crafted PCFs. Author-side only, independently
unwitnessed. NO grade change: witness #3309 stays rungs 1-4 ESTABLISHED at the
direct-call scope, NO r5. This closes W6's "overflow content is host-derived"
UNKNOWN at the labeled real-headless path: the overflow bytes now come from
the second PCF file.

## Input and allocator path

`make-filechoice-case.py` (sha256
`8dcb6424e3e35d8a259e150572a1dcee34f9a16cfa757a61dd39e199e1aeb84a`)
derives all inputs locally from the pinned `truncated.pcf`:

- `size-71.pcf` (sha256
  `adcca7c44838a52f189a49d509b3fe6a0d2922b179d552378083bf45d9a7a928`):
  four metrics glyphs, `min2=max2=0`, `min1=max1=0x71`, one glyph-index low
  byte `0xfe`, so `glyph=-2`, `tot=1`, RHS `0x71` written at `encs-8`, the
  low half of the physical 0x20 chunk's size word. After `free(encs)` the
  chunk is in tcache bin 5 (0x70-size chunks).
- `choice-4.pcf` (sha256
  `916122bae3b06aba59343fe86fd45f2e067eb1237da4bc631e618349c51d7114`):
  complete four-glyph PCF reusing the pinned properties table. Its second
  `Import()` calls `pcf_properties()` (`fvimportbdf.c:1464`), whose
  `props = malloc(cnt*sizeof(struct props))` is `malloc(3*32) = 96` bytes:
  a 0x70 chunk, i.e. bin 5. The loop at :1465-1469 copies 96 bytes of
  file-derived `name_offset`, `isStr` and `val` integers into it. Only 24
  bytes are physically usable, so 72 bytes land past the chunk.
- `choice-4-var.pcf` (sha256
  `5067b026cb87f9c477fb626732dd4b569cc6e1d40282f566dcf2b3eedd1a3e07`)
  is `choice-4.pcf` with ONE byte changed at file offset 0x62:
  `props[2].name_offset` `0x17 -> 0x1a` (another valid substring of the
  same properties string). This is the file-chosen-byte discriminator.

## Measured result

`gdb -q -batch -x gdb-props-consumer.cmd ./build-plain/bin/fontforge`
(`gdb-props-consumer.out`, sha256
`e0638afea13f4ecdd0fef03568d63834873471799e4dc8ee36719ee43597e27f`;
command sha256 `9fc5a6548be7d0ba2116e91c888f5890da254d4cef46ca5c78645a02a1446d42`):

- At `fvimportbdf.c:1751 if glyph < 0`: `glyph=-2`, `encs=0x555555c48240`,
  original chunk size `0x21`; the hardware watchpoint caught
  `Old value = 33`, `New value = 113` (`0x71`), and the corrupted word was
  still `0x71` at `free(encs)`.
- Break at `fvimportbdf.c:1469 if props==$encsp` in the second import:
  `PROPS ptr=0x555555c48240 encsp=0x555555c48240 equal=1 cnt=3`, with a
  backtrace `pcf_properties:1470 -> SFImportBDF:2074 -> _SFImportBDF:2226
  -> FVImportBDF:2329`. The poisoned chunk was handed to a real application
  allocation, not debugger-forced.
- `x/96bx props` shows the file-derived integers in the chunk. At user
  offset `0x40` (40 bytes past the physical 24-byte usable area) the word
  is `17 00 00 00 00 00 00 00`, exactly `props[2].name_offset = 0x17`
  from file offset 0x62.
- The variant run (`gdb-props-var.out`, sha256
  `7bcff1d4c4a1d8015f3e2b08dfd539810f7ed087ef04196b2bc5f14846299819`;
  command sha256
  `8871664857a3d80df1fff11188edffa32c616833cd88741c332da389a173abf9`)
  reports `PROPS ptr=0x555555c48250 encsp=0x555555c48250 equal=1 cnt=3`
  and the same word at offset `0x40` is now
  `1a 00 00 00 00 00 00 00`. The one-byte PCF change moved one byte in
  the overflow; the bytes there are file-chosen.

The tcache-pop watcher (`gdb-tcache-pop.cmd` / `gdb-tcache-pop2.cmd`,
transcripts `gdb-tcache-pop.out`, `gdb-tcache-pop2.out`) identifies an
intervening consumer: the notice `smprintf` at `FVImportBDF:2326` calls
`malloc(97)` (bin 5), then frees the same pointer at :2328 before
`pcf_properties` takes it. A 0x71-sized poison therefore has two real
consumers on this path; the second one writes file bytes.

## Controls

| input / build | result |
|---|---|
| vulnerable plain, `import-filechoice.ff` | exit 0 (`ff-vuln.out`) |
| vulnerable plain, in-bounds first-import control | exit 0 (`ff-control.out`) |
| patched plain, same script | exit 0 (`ff-fixed.out`) |
| vulnerable ASan (`build-asan`) | exit 1, `WRITE of size 4` at `fvimportbdf.c:1751`, `8 bytes before a 16-byte region` (`ff-asan-vuln.out`) |
| patched ASan (`build-fixed`) | exit 0, no report (`ff-asan-fixed.out`) |

## Negative lanes preserved

- First attempt poisoned bin 3 with `0x51` and expected the second import's
  `bitmap = malloc(sizebitmaps)` (88/72-byte variants) to be the consumer.
  `pcf_properties` allocates the same 0x50 size first; the bitmap buffer
  received a different chunk. Superseded, not repeated.
- Bin 5 with `sizebitmaps=88`: `smprintf` and then `pcf_properties` consume
  the entry before `PcfReadBitmaps:1681`, so the bitmap buffer again got a
  different chunk. Superseded by the props lane.
- A watchpoint on the chunk's first word (`gdb-find-consumer.cmd`) saw the
  first-import `figureProperEncoding` writes to `encs[0]`/`encs[1]` before
  `free`; those are in-bounds and are not the overflow.

## Limits

Still no GUI `Import()` menu (GTK-3 dev packages absent; all builds
`ENABLE_GUI=OFF`), no pointer/IP control, no command execution, no ASLR or
grooming study, no network/wire path, and no independent witness verdict on
any real-path result. The chosen bytes here are file-derived PCF property
integers in a heap overflow, not a controlled address. NO r5. Any new claim
goes to `witness`.
