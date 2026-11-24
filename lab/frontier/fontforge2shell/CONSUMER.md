# CONSUMER — who reads the overwritten slot (2026-11-24 08:0xZ, W3)

Scope: real headless FontForge 20251009 (non-ASan Debug `build-plain/`),
scripting `Import()` of `truncated.pcf`, this host's glibc/x86-64. This is
author-side measurement; it does not change the witness grade (rungs 1-4
at the labeled direct-call scope, NO r5).

## Question

W2 measured the four attacker-derived bytes at `encs[-1]` in the real
process. Who consumes that slot? `encs` is a 16-byte allocation from
`malloc(b->glyphcnt*sizeof(int))` at `fvimportbdf.c:1726`; on this 64-bit
glibc the chunk header is eight bytes before user data, so `encs[-1]`
(strictly, the four bytes at `encs-4`) is the **high half of the same
chunk's size word**, not a separate application object.

## Measurement

`gdb-consumer-plain.cmd` / `gdb-consumer-plain.out` (sha256
`26dd5ce2f3ffb2b19fc51f82d1ca2b26d4bf29644cc434c0867e914919a5f391` /
`53630de80fc3ebc8d370095fe650b3550c4a2e19e38606e8e7add5f23d96f6b5`):

- At the negative-glyph breakpoint: `glyph=-1, i=3, encs=0x555555c48240`;
  `prev_size=0`, `size=0x21`, `malloc_usable_size(encs)=24`.
- Hardware watchpoint on `*(int*)((char*)encs-4)`: `Old value = 0`,
  `New value = 5458253 (0x53494d)`; chunk header afterwards
  `0x0000000000000000 0x0053494d00000021`; bytes at `encs-4`:
  `4d 49 53 00`.
- Conditional breakpoint on `free` with the saved `encs` pointer caught
  `__GI___libc_free (mem=0x555555c48240)` called from
  `PcfReadEncodingsNames` at `fvimportbdf.c:1770`, with the header still
  `size=0x0053494d00000021`. Continuing printed
  `double free or corruption (out)` and SIGABRT.

So the consumer is the allocator itself: the same `free(encs)` that the
source issues at line 1770 reads the corrupted size word and aborts. No
other application consumer of the overwritten bytes was observed. The
three chosen bytes become the high half of the chunk size; the fourth is
zero for these field values.

## Controls (same builds and method)

- `gdb-header-fixed.out` (sha256
  `86c939cc23fbbbc54f5bbd2a5530fb9a39cc53636cf809f0af3e25d1a4c9bc61`):
  patched build, same `truncated.pcf`, at `fvimportbdf.c:1770`:
  `size=0x21`, process exited normally.
- `gdb-header-complete.out` (sha256
  `cdb90282913a74c06140370a4d92e4aab5871b1bbf5257d1ff81c91efad3dbbb`):
  vulnerable build, complete table, at line 1770: `size=0x21`, process
  exited normally.

## Value dependence: a silent plain-build overwrite (measured)

`zero-write.pcf` (290 bytes, sha256
`f20ef994ccb09bfddb44a7544c57aabd7bcbb308a1216b29d9dac8d8abf08b5d`)
keeps the four TOC tables but makes BDF_ENCODINGS an empty table: all five
16-bit fields zero, TOC size 4 words, file ending after `def`, so the
first glyph read is EOF. The vulnerable plain build on this file prints
no allocator error and exits 0 (`plain-zero-write-import.out`, sha256
`ce8173e7f6298283725788d3131e4335f1f72a07a004c87158a2c00cd364eaaf`),
while the ASan build still reports `WRITE of size 4` at
`fvimportbdf.c:1751` (`asan-zero-write-import.out`, sha256
`ddb27848526a1d27ff8913d34820f3a270921a60e8f4fd8e61eb41173b2c41ed`).
`gdb-zero-write-post.out` (sha256
`db107e04f9841355a4aa18d9c82ef7c54d38ff7babf2adb60b8dfaa49cb6a2a8`)
shows `glyph=-1, i=0, tot=1`, RHS `0x0`, after the store `encs[-1]=0`,
bytes `00 00 00 00` at `encs-4`, chunk size still `0x21` both after the
store and at `free(encs)`; the process exits normally. The same OOB write
is therefore silent in the plain build when the file-derived value leaves
the size word unchanged; ASan still detects the address violation.

Failed hypothesis preserved: the first attempt (`zero-value.pcf`, sha256
`5060aa5b4883b2e66b2b2aebb0e15548714d6ac60fafc331e711f3a608378a39`)
set `min2=max2=0xfffd` expecting -3, but `getformint16()` does not
sign-extend: gdb printed `min2=65533`, RHS `0x1000000`, and the plain
build still aborted (`gdb-zero.out`). A second intermediate truncation to
286 bytes cut `max1` and `def` off the end of the file, so gdb printed
`max1=-1, tot=0` and the loop never ran; the final file uses 290 bytes.

## Honest limits

This identifies the corruption target and the failing consumer; it does
not widen the primitive. The write remains four bytes at a fixed offset
with a file-derived value, now measured with both a nonzero and a zero
value, and there is no pointer/IP or command control. A value that yields
some other plausible 64-bit chunk size (rather than the original `0x21`)
remains UNKNOWN; ASLR and grooming were not studied; no witness verdict on
this W3 extension.
