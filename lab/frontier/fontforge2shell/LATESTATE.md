# W26 — actual negative reach and surviving-free later state (2026-11-25)

## Correction: the writable window is 1024 bytes, not 128 KiB

W15/W18/W23/W24/W25 described `glyph` as a signed 16-bit value and scanned
`encs-131072 .. encs`. That was wrong. Pinned `getformint16()`
(`fvimportbdf.c:1354-1363`) assembles bytes into an `int` but never
sign-extends:

- a complete two-byte index is `0..65535`;
- a missing high byte after a present low byte yields `low-256`, i.e.
  `-256..-1`;
- EOF before either byte yields `-1`.

The vulnerable guard `glyph!=0xffff && glyph<b->glyphcnt` therefore accepts
negative indices only in `-256..-1`. The single 4-byte store reaches
`encs-1024 .. encs-4`. Repeated EOF iterations can rewrite `encs-4`, but do
not extend the range.

`make-range-case.py` builds the discriminator. In both real headless builds,
gdb at `fvimportbdf.c:1750` reports:

```
RANGE full glyph=48882 accepted=0       # complete 0xBEF2
RANGE partial glyph=-14 accepted=1      # low 0xF2, high byte EOF
```

Inputs: `range-full.pcf` sha256
`5fca5c1919fe02319321a5de9e7bb59780cadab1b78408aad70b60815e3722c8`;
`range-partial.pcf` sha256
`8e2e6732d3faf464bcc2c1bd55d943bb452aff98d07e01e21afdbde25e7ce5cf`.
The earlier 128 KiB scans covered a superset, so their observed bytes remain
valid; their reach wording and any conclusion that depended on the larger
range are corrected here.

## Surviving-free later-object scan

W25 could not reach a later object because the high-size-word corruption
aborts at `free(encs)`. W7 already measured a surviving input:
`size-71.pcf` writes `0x71` into the low size word at `encs-8`; a second
`Import(choice-4.pcf)` reuses the chunk for `pcf_properties.props`.

`replay-w26.sh` stops at `fvimportbdf.c:1751 if glyph<0`, saves `encs`, stops
at `fvimportbdf.c:1469 if props==$w26e`, dumps the heap, and continues to the
real `Save()` consumer at `sfd.c:1671`. Both `build-plain` (PIE) and
`build-nopie` report `glyph=-2 i=0`, `props==encs`, `cnt=3`, and reach the
later Save breakpoint. `scan-w26.py` scans only the final 1024 bytes of the
dump against every `r-xp` mapping, including shared libraries and the vDSO.
Both are `CAND_COUNT 0` / `RESULT NONE`:

```
b88042281496bd3687aa256fc2832ce070f73db7dfd8ea2c8ca04389f8d1887a  scan-w26-pie.out
eb4d373e8b716dbb2ef3287700f0757a0d1360f39029702e094311eb7452a321  scan-w26-nopie.out
```

Live-tree replay: 18/18 PASS, rc 0, final line
`REPLAY_W26_OK: 18 checks, 0 failed`. Build prerequisites are the existing
`build-plain` and `build-nopie` trees plus W7's generated PCFs; the script
builds nothing and uses no network or loopback service.

## Preserved failed lead: called gconv pointers exist, but out of reach

The first W26 scan mistakenly covered the old 128 KiB range and all code
mappings. It found five libc text pointers in both builds at
`encs-66616`, `-66608`, `-66512`, `-33736` and `-33632`. Gdb resolved them to
`__gconv_transform_utf8_internal`, `__gconv_btwoc_ascii`,
`__gconv_transform_internal_ucs4le`, `__gconv_transform_ucs4le_internal` and
`__gconv_transform_internal_utf8`. Breakpoints on the pointer values showed
`__gconv_transform_utf8_internal` and its UCS4-LE step called after the store
through `iconv -> UniFromEnc -> SCBuildDummy -> _SFMakeChar`.

That looked like a called-function-pointer target, so a PCF with complete
index `0xBEF2` (intended as `-16654`) and RHS `0x00414243` was built. It never
reached `fvimportbdf.c:1751`: gdb at `:1750` showed `glyph=48882`, rejected by
the guard. The apparent target is 65 KiB before `encs`; the real negative
reach is 1 KiB. This is an author-side negative caused by the missing
sign-extension assumption, not a pointer-control result.

## Disposition

No executable pointer is present in the actual reachable window at the
measured surviving-free later-consumer state in either build. The range
correction narrows all earlier window claims; it does not change the
witness-established direct-call grade. No branch at a chosen address, no
marker, no command, no r5, no witness verdict and no new replay demand.
#4165 remains the single queued bundled offer. A different heap state that
places a live called pointer within `encs-1024..encs-4`, or a second-stage
overflow that reaches one, remains UNKNOWN and would require fresh evidence.
