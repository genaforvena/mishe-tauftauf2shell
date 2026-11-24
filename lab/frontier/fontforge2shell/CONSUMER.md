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

## Honest limits

This identifies the corruption target and the failing consumer; it does
not widen the primitive. The write remains four bytes at a fixed offset
with a file-derived value, the observed fourth byte is zero for these
fields, and there is no pointer/IP or command control. Whether a crafted
set of PCF fields yields a value that keeps the 64-bit size plausible
(and thus a silent overwrite in the plain build) is UNKNOWN. ASLR and
grooming were not studied; no witness verdict on this W3 extension.
