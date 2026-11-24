# CONSUME — real consumer of W5's poisoned tcache entry (2026-11-24 19:2xZ, W6)

Scope: real headless FontForge 20251009, non-ASan Debug `build-plain/`,
ASan `build-asan/`, patched `build-fixed-plain/` and `build-fixed/`,
scripting `Import()` of locally crafted PCFs. Author-side only. NO grade
change: witness #3309 stays rungs 1-4 ESTABLISHED at the direct-call
scope, NO r5. This closes W5's "no observed consumer" UNKNOWN at the
labeled real-headless path.

## Input and trigger

Reuse the pinned W5 input `size-91.pcf` (sha256
`e29a2e464c4fbafadc09fc68776e295d2e165e6113f75b6ff93d40f27f3c9dd2`):
four metrics glyphs, `min2=max2=0`, `min1=max1=0x91`, one glyph-index low
byte `0xfe`, so `glyph=-2` and `encs[-2]` (the low half of `encs`'s own
glibc size word) receives `0x91`. `encs = malloc(4*4=16)` is a 0x20
chunk (24-byte usable area); the store changes its size word from
`0x21` to `0x91`, and `free(encs)` puts that physically-small chunk into
tcache bin 7, the bin for 0x90 chunks.

New script `import-size-consumer.ff` (sha256
`458003e68b18077dd1b3c8cc85d671a16fc4fd553014ad15212697207901bde0`)
imports `size-91.pcf` first, then a locally generated 32-glyph complete
PCF `sponge-32.pcf` (sha256
`129afa8dc7a6f0e3dcbff69738753c58713999a9edd3e04a2a6916a14f62350f`).
The second `Import()`'s `FVImportBDF()` line 2317 emits the localized
notice "Loading font from %.100s"; glibc gettext resolves it through
`_nl_find_domain()` -> `_nl_make_l10nflist()`.

## Measured result

`gdb -q -batch -x gdb-real-consumer.cmd ./build-plain/bin/fontforge`
(`gdb-real-consumer.out`, sha256
`4d07f487f8aad61c051fe4bf8e1d35f387ba6049dba0cf07c7f0dd74b56dd8ce`;
command file sha256
`4a979775bae3a66767214d11059fe672c2868195ced31ee4a2aafc0c24441603`):

- Break at `fvimportbdf.c:1751 if glyph < 0`: `glyph=-2`,
  `encs=0x555555c48240`, original size word `0x21`.
- Hardware watchpoint on the size word: `Old value = 33`,
  `New value = 145`; word reads `0x91` at the stop.
- Conditional breakpoint on `__libc_malloc` with `$rdi==128`: hit from
  `_nl_make_l10nflist` (`l10nflist.c:166`), reached from
  `FVImportBDF` line 2317 via `bImport` -> `docall` -> `Import`.
  `finish` shows `ret = 0x555555c48240`, i.e. the returned pointer is
  exactly the poisoned `encs` (`equal=1`) while its size word still
  reads `0x91`. tcache bin 7 was consumed by a real, unforced consumer.
- Hardware watchpoint on `*(long*)((char*)encs+0x20)` (the next chunk's
  size field, past the physical 0x20 chunk) then fired with
  `Old value = -1`, `New value = 7089066239396177256`
  (`0x62616c2f6c6c6568`, ASCII bytes `68 65 6c 6c 2f 6c 61 62` =
  "hell/lab"). Backtrace:
  `__memcpy_avx_unaligned_erms` -> `__GI_memcpy` with
  `__len=91`, `__src=0x555555c21810`, `__dest=0x555555c48240`
  -> `_nl_make_l10nflist` (`l10nflist.c:185`) -> `_nl_find_domain`
  -> `__dcigettext` -> `FVImportBDF:2317`.
- `x/24bx encs` shows the copied locale-directory string starting at
  the chunk user pointer (`2f 68 6f 6d 65 2f 6d 65 73 68 ...` =
  "/home/mesh..."). A real allocator consumer therefore wrote 91 bytes
  into a chunk with 24 usable bytes, overwriting the following chunk's
  header. This is a size-confusion / adjacent-metadata overwrite, not
  pointer or IP control.

The overflow content is the host's locale path, not file-derived; what
the file controls is the corrupted size word `0x91` and therefore which
tcache size class is poisoned. The 91-byte length is this host's locale
directory length, not a chosen value.

## Controls

| input / build | result |
|---|---|
| vulnerable plain, `import-size-consumer.ff` | exit 0 (`plain-size-consumer.out`) |
| patched plain (`build-fixed-plain`), same script | exit 0 (`fixed-size-consumer.out`) |
| patched ASan (`build-fixed`), same script | exit 0, no report (`fixed-asan-size-consumer.out`) |
| vulnerable ASan (`build-asan`), same script | exit 1, `WRITE of size 4` at `fvimportbdf.c:1751`, `8 bytes before a 16-byte region` (`asan-size-consumer.out`) |
| vulnerable plain, complete-table control `size-complete.pcf` then `sponge-32.pcf` | exit 0 (`plain-size-consumer-control.out`) |

## Negative results preserved

- A 15-metrics-glyph variant (`make-consumer-case.py`, `consumer-91.pcf`,
  sha256 `26bcda6fe8891b896877118ebc135fb636961a27d78053fe9c32894dcd12fb20`)
  also corrupts `encs`'s size word (`0x51 -> 0x91`, `gdb-consumer-tcache.out`),
  but `PcfParse:1835`'s `mult = calloc(mcnt+1, 8)` did **not** consume the
  poisoned entry: an isolated glibc probe showed `calloc(16,8)` skips
  tcache bin 7 while `malloc(128)` takes it. In that variant the gettext
  `malloc(128)` also received a different chunk because extra 0x90-sized
  frees put new entries ahead of `encs`. Do not redo that lane unchanged.
- The one-import path has no post-free `malloc(128)` consumer; W5's
  negative probe stands for that path. The consumer here requires a
  second `Import()` in the same process.

## Limits

Still no GUI `Import()` menu (GTK-3 dev packages absent; all builds
`ENABLE_GUI=OFF`), no pointer/IP control, no chosen bytes in the
overflow, no command execution, no ASLR/grooming study, no network or
wire path, and no independent witness verdict on any real-path result.
NO r5. Any new claim goes to `witness`.
