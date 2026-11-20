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

## Negative control (fixed 3.4.13)

Status: **in progress** (ASan build of the 3.4.13 tree building at
report time). Expected: same script runs clean, prints
`upcase returned, out len=42`. Will be recorded here with the actual
observed result — clean or not — when the build lands.

## Consumer-reality pre-check (planning arithmetic — NOT observed)

Before any grooming mechanics (nginx2root lesson), on this host's
production glibc (2.39):

- Allocation request R = 24 + (N+20) = N+44; the write runs to
  offset 24+2N−1 within the chunk.
- glibc chunk C = round16(R+8), usable C−8. At N=21, R=65, C=80,
  usable 72: the single byte at offset 65 lands in malloc slack —
  production glibc would NOT corrupt anything at N=21. The ASan report
  fires because ASan sizes the allocation exactly and redzones it.
- Reaching the NEXT chunk's size field needs 24+2N−1 ≥ C−8. At N=40:
  R=84, C=96, write end 103 → slack 84..87, full size field 88..95,
  bytes 96..103 into the next chunk's header. So production impact
  needs N ≈ 40+, and the payload is UNIFORM: every overflow byte is
  0x53 'S' (upcase) or 0x73 's' (fold) — no byte choice. A fully
  overwritten size field 0x5353… is garbage glibc rejects on free;
  the plausible angle is ending the write INSIDE the size field
  (partial, LSB) by choosing N.
- All arithmetic, no measurement: the true heap neighbor on this host
  must be observed (plain-glibc build, next rung work) before Stage A
  placement is designed. If the neighbor's layout makes the
  uniform-'S' write structurally inert, this path is recorded as a
  negative result.

## Next

1. Negative control on fixed 3.4.13 (in progress).
2. Plain-glibc (non-ASan) 3.4.12 build; observe the actual heap
   neighbor of the mapping_buffer and what the uniform-'S' write
   reaches at N ≈ 40+.
3. Stage A placement (canary) only if step 2 leaves a live path.
