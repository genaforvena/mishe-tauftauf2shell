# Ruby2Shell — investigation report

Target: **Ruby2Shell** — CVE-2026-132825 / GHSA-34m4-m9fh-gqp5.
Claim (verialabs.com/ruby2shell/): one-byte heap overflow in
single-byte-encoding case conversion — upcasing `ß` writes two bytes
(`SS`) while the loop bound-checks only one; the output buffer is sized
input length + 20, so 21 `ß` overflow by one byte. Written byte fixed
(`S` upcase, `s` fold); attacker controls buffer size via input length.
Reached via `upcase`/`swapcase`/`downcase(:fold)`/`casecmp?`; UTF-8
unaffected. Affected 3.3<3.3.14, 3.4<3.4.13, 4.0<4.0.10; fix
`ruby/ruby@d582f8f`. Vendor claims Rails and classic Sinatra exposure
in default configs; a PoC is announced for 2026-11-25.

Everything below was reproduced in this plant's lab. External claims are
cited as claims, not adopted.

## Provenance (2026-11-20)

- `ruby-3.4.12.tar.xz`/`.tar.gz` (affected) and `ruby-3.4.13.tar.xz`/
  `.tar.gz` (fixed) downloaded to `lab/src/`, sha256-verified against
  the release announcements (2026-10-23 / 2026-11-18).
- Fix commit `ruby/ruby@d582f8f` fetched to `lab/src/ruby-fix-d582f8f.patch`
  (243 lines): in each of 14 single-byte encodings the case-map loop
  bound `to < to_end` becomes `to_end - to > 1`.

## Source-level mechanism (read as specification, verified from trees)

- `string.c:7777`: `#define CASE_MAPPING_ADDITIONAL_LENGTH 20`.
- `string.c:7830` (buffer sizing): first buffer capa = remaining source
  length × 1 + 20 (buffer_count starts at 1); `case_map` writes into
  `current_buffer->space`, `to_end = space + capa`.
- `enc/iso_8859_1.c:267` (loop guard): `to < to_end` guarantees only
  ONE byte of room; sharp-s upcase writes TWO — `*to++ = 'S'` at :272
  then `*to++ = code` ('S') at :293. N sharp-s → 2N output bytes into
  capa N+20 → overflow iff N ≥ 21. At N=21 indices 0..40 are valid;
  the last 'S' lands at index 41, exactly one byte past the end.
- Fixed tree `ruby-3.4.13`: same line 267 reads `to_end - to > 1`.

## Rung 1–2: reproduced under ASan (observed 2026-11-20, wake 3)

Build: gcc 13.3.0, `CFLAGS='-O1 -g -fsanitize=address,undefined
-fno-omit-frame-pointer'`, `LDFLAGS='-fsanitize=address,undefined'`,
in-tree build of the 3.4.12 tarball, installed to
`lab/build/ruby-3.4.12-asan`. (One ext not built: `fiddle`, needs
libffi-dev — irrelevant here. UBSan misalignment reports in ruby's own
siphash/vm code appear on every run including clean ones; background
noise, not findings.)

Reproduction — one command, no environment overrides:

```
lab/build/ruby-3.4.12-asan/bin/ruby lab/repro/ruby2shell-rung1.rb
```

`lab/repro/ruby2shell-rung1.rb` (committed, `a4825ca`): 21 `ß` bytes,
`force_encoding(Encoding::ISO_8859_1)`, `upcase`.

Observed (exit 1, full reports in
`lab/build/evidence/evidence-ruby2shell-rung1-*.txt`, gitignored lab
bulk — regenerate with the command above):

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x507000068571
WRITE of size 1 at 0x507000068571 thread T0
    #0 case_map enc/iso_8859_1.c:293
    #1 rb_str_casemap string.c:7839
    #2 rb_str_upcase string.c:8017
0x507000068571 is located 0 bytes after 65-byte region
allocated by thread T0 here:
    #4 rb_str_casemap string.c:7834  (via ruby_xmalloc)
SUMMARY: AddressSanitizer: heap-buffer-overflow enc/iso_8859_1.c:293 in case_map
```

The allocation is exactly the predicted geometry: 65 bytes =
24-byte `mapping_buffer` header + capa 41 (N=21 + 20), and the write
is the first byte past the region — the source-level prediction
confirmed byte-for-byte. This establishes **rung 2 (reproducible
crash)** and, per the ladder, **rung 3 (confirmed corruption)** for
the ASan build: ASan observed the out-of-bounds store itself.

## Negative control (fixed 3.4.13) — observed 2026-11-20

Clean. `ruby-3.4.13` tarball, identical configure flags and prefix
convention, installed to `lab/build/ruby-3.4.13-asan`
(`ruby 3.4.13 (2026-11-19 revision 48857d6f2e)`; affected build is
`ruby 3.4.12 (2026-10-23 revision 366f5fdc00)`). Same script, same
one-line invocation:

```
lab/build/ruby-3.4.13-asan/bin/ruby lab/repro/ruby2shell-rung1.rb
```

Observed: exit 0, `upcase returned, out len=42`, **zero**
AddressSanitizer reports (full output in
`lab/build/evidence/evidence-ruby2shell-rung1-control-3413.txt`;
its only diagnostics are the same UBSan misalignment noise present on
every run of these builds). The affected/fixed differential is
observed end-to-end: identical input and build recipe, one loop bound
in `enc/iso_8859_1.c:267` (`to < to_end` vs `to_end - to > 1`) is
the only relevant difference.

## Consumer reality — observed 2026-11-20, mechanism CORRECTED

**Superseded hypothesis (wake-2 arithmetic, preserved, falsified):**
the case-map loop was assumed to write all 2N output bytes into the
first buffer ("write runs to offset 24+2N−1; N≈40+ overwrites the full
next size field"). Valgrind on the plain build at N=40 showed ZERO
invalid writes — falsified.

**Corrected mechanism (verified in `string.c:7828-7851`):** when
`case_map` stops at `to == to_end`, the caller chains a new buffer
(`capa = remaining × buffer_count + 20`) and continues. The overflow is
therefore **exactly ONE byte** at `space` index capa — allocation
offset R = 24 + capa — and happens only when capa is ODD (the
sharp-s iteration that starts at `to = to_end−1`).

- **Pure sharp-s input:** capa = N+20, overflow iff N odd ≥ 21;
  R = N+44 is then always ODD. A glibc size-field LSB needs offset
  ≡ 8 (mod 16) — even. So the byte lands in the request's own slack
  or the next chunk's `prev_size`, never in a size field: the pure
  vector is structurally inert on stock glibc (valgrind: one invalid
  write, "0 bytes after a block of size 65"; all stock sweeps clean).
  The ASan report at N=21 is real but ASan-only, exactly as the
  nginx2root lesson warns.
- **Parity flip — one leading 1-byte char (`"a" + N×ß`):** the 'a'
  makes `to` odd, so overflow requires capa = N+21 EVEN (N odd), and
  R = N+45 is EVEN. At N ≡ 11 (mod 16) (27, 43, 59, …) R ≡ 8
  (mod 16): the single 0x53 byte lands EXACTLY on the next glibc
  chunk's size-field LSB. 0x53 = PREV_INUSE|IS_MMAPPED set.

**Observed on stock glibc 2.39** (plain build
`lab/build/plain/ruby-3.4.12-plain`, rev 366f5fdc00, no
sanitizers, no tunables): valgrind confirms one invalid write at
`iso_8859_1.c:293` "0 bytes after" blocks of size 72 (N=27) and 88
(N=43). Fresh-process runs at N=27/43/59 abort inside glibc with
metadata-corruption diagnostics — `corrupted size vs. prev_size`,
`munmap_chunk(): invalid pointer`, `corrupted size vs. prev_size in
fastbins` (N=43 aborted in 5 of 10 observed runs; layout-dependent,
NOT deterministic — clean runs occur with the same command). glibc
itself reporting corrupted heap metadata establishes **rung 3 on the
production consumer**: the write demonstrably corrupts a neighboring
chunk's size field on stock glibc, not only under ASan. Evidence:
`lab/build/evidence/sweep-rung3-mixed.txt`,
`lab/build/evidence/vg-rung3-*.txt`.

Reproduction: `lab/repro/ruby2shell-rung3-mixed.rb` (mixed input),
`lab/repro/ruby2shell-rung3-plain.rb` (pure input); run as
`lab/build/plain/ruby-3.4.12-plain/bin/ruby lab/repro/ruby2shell-rung3-mixed.rb 43`.

## Next

1. Stage A — placement: groom the heap so the chunk following the
   mapping_buffer is a chosen victim (canary object), and prove the
   0x53 byte changes it at the chosen offset. The parity-flipped
   size-LSB write is the primitive; whether 0x53 (PREV_INUSE|IS_MMAPPED)
   into a chosen size LSB buys anything beyond aborts is the open
   rung-4 question.
2. If no chosen-victim effect is achievable, record the negative
   result and move to the next target lane (PHP2Shell).
