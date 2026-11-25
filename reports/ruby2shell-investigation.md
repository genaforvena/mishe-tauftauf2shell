# Ruby2Shell — investigation report

Target: **Ruby2Shell** — CVE-2026-132825 / GHSA-34m4-m9fh-gqp5.
Claim (verialabs.com/ruby2shell/): one-byte heap overflow in
single-byte-encoding case conversion — upcasing `ß` writes two bytes
(`SS`) while the loop bound-checks only one; the output buffer is sized
input length + 20, so 21 `ß` overflow by one byte. Written byte fixed
(`S` upcase, `s` fold); attacker controls buffer size via input length.
Reached via `upcase`/`swapcase`/`downcase(:fold)`/`casecmp?`; UTF-8
unaffected. Affected 3.3<3.3.14, 3.4<3.4.13, 4.0<4.0.10; fix
`ruby/ruby@d582f8f`. Veria claims Rails and classic Sinatra exposure
in default configs, and dates its public PoC 2026-11-25 "or later if
major vendors have not shipped a fix by then".

Public status (checked 2026-11-20 12:08Z): advisory public since
2026-11-18/19 — the ruby-lang.org news item fixes GHSA-34m4-m9fh-gqp5
in 4.0.10/3.4.13/3.3.14 and states "We are aware of PoCs that prove
this flaw can be used to trigger RCE in some scenarios";
CVE-2026-132825 published 2026-11-19 (MITRE). The advisory credits the
primitive to Stephan Lipp (Ada Logics) and Anthropic; Veria's page adds
Moritz Sanft (with OpenAI) as a discoverer, claims first RCE
demonstration, and lists 3.2-and-older as affected back to 2.4.0
(EOL, unfixed).
Disclosure landscape re-check (2026-11-20 12:08Z; Veria page stamp
"Updated 20 November 2026 at 11:58 UTC", i.e. after the 11:55Z
check): PoC still unpublished, still dated 2026-11-25. Two additions,
both recorded as vendor claims, not lab findings: (1) a
self-hosted-software table — GitHub Enterprise Server 3.22.5 and
earlier listed **Vulnerable with no fixed release**; Chatwoot 4.20.1,
GitLab 19.6.1/19.5.8/19.4.10, Mastodon 4.7.6/4.6.12/4.5.22/4.4.29,
OpenProject 17.9.8/17.8.3 and the Discourse base image
2.0.20261119-0203 listed as vendor-patched. (2) A "Primitive" section
naming the overflow byte `S` (0x53, upcase) / `s` (0x73, case-fold)
and stating that copying the result out of the buffer reads one byte
out of bounds. The byte alphabet **agrees exactly** with this report's
independently measured Stage A′ alphabet {0x53, 0x73} — an external
confirmation of our source audit, not new information for it.
The copy-out OOB read is now **separately reproduced** under valgrind on
the affected plain build (see "Copy-out OOB read" below): a distinct
observed invalid access, but not a new impact grade — the byte read is
the same 0x53/0x73 the overflow wrote and the returned string is correct.

Everything below was reproduced in this plant's lab. External claims are
cited as claims, not adopted.

**Current ladder position: rung 5 — witness-ESTABLISHED on 2026-11-22 under
the labeled host- and harness-specific lab conditions.** A fresh-context
independent replay from clean archive commit
`8b9d8f97f0ec1237fe1fb2bc30339d1a32db1341` reproduced two distinct-command
attacks plus safe/fixed controls and returned ESTABLISHED with no
contradiction. A single
multipart POST to the live Sinatra/WEBrick target now executes its
request-carried benign `touch` command through a forged CRuby `T_DATA`
finalizer. The final matrix produced three distinct target-created markers in
3/3 affected runs, with marker-absent safe-input and plain-3.4.13 controls;
`strace` independently recorded `/bin/sh -c -- /usr/bin/touch …` and the
resulting `execve("/usr/bin/touch", …)`. See "Rung 5 over HTTP" below for the
address oracles, custom grooming, exact build and post-response abort boundary.

**Prior rung-4 result: demonstrated impact in the lab, request-reachable over
HTTP on BOTH claimed default stacks (2026-11-20, wake 8).** The Stage B overlap (wake 6: chosen bytes over a live chunk,
5/5, control clean; witness verdict ESTABLISHED at rung 4, tape #51) is
driven from a single multipart HTTP POST through a default-config
classic Sinatra app (wake 7) and through a default `rails new` app
(wake 8) — same geometry, same readback, same 5/5 + control on each;
the witness independently re-ran both HTTP sections from the committed
scripts and returned ESTABLISHED at rung 4 request-reachable for each
(tape #65, 2026-11-20). The Stage C strengthening lane (wake 9: tcache
poisoning → arbitrary-address allocation, 5/5 + control 3/3) is
likewise witness-ESTABLISHED at rung 4 as strengthened pointer control
(tape #89, 2026-11-20): the witness re-ran the committed driver,
parsed the mtrace traces independently of the driver oracle,
recomputed the PROTECT_PTR splice, and reproduced a target-move
counterexample.
The 2026-11-21 HTTP depth experiment carried this pointer-control chain
onto the Sinatra request thread (3/3 attacks, 2/2 controls): the
attacker-nominated address was handed out and its 'z' bytes were read
back through the live HTTP consumer, with the process aborting
afterwards in WEBrick worker-thread teardown (see "Stage C over HTTP"
below). No ladder grade change: the lane was already ESTABLISHED at
rung 4.
The sink (`Rack::MethodOverride` upcasing a multipart part that declares
`charset=ISO-8859-1`) runs before routing, CSRF and auth.

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

## Copy-out OOB read — reproduced under valgrind (observed 2026-11-21)

Veria's Primitive section claims that copying the case-mapped result out
of the buffer reads one byte out of bounds. This is now **separately
reproduced** on the affected plain build; it is a second observed invalid
access, not Stage C and not a new ladder grade.

Source reason: `case_map` returns `to - to_start`
(`enc/iso_8859_1.c:298`), which includes the OOB byte because the last
sharp-s pair writes at `space[capa-1]` and `space[capa]`. `rb_str_casemap`
then copies `current_buffer->used` bytes — `rb_str_new(space,
target_length)` at `string.c:7857` when one buffer suffices, or
`memcpy(..., used)` at `string.c:7866` when buffers chain. For 21 `ß`
(capa 41, 42 output bytes) the single-buffer path reads 42 bytes from a
41-byte `xmalloc`.

Observation (plain affected build
`lab/build/plain/ruby-3.4.12-plain/bin/ruby`, stock glibc 2.39, valgrind
memcheck; gitignored evidence `lab/build/evidence/vg-copyout-N21.txt`,
N=20 control `lab/build/evidence/vg-copyout-N20.txt`):

Reproduce (plain affected build; the `21` → `20` swap is the clean
control):

```
valgrind --error-limit=no \
  lab/build/plain/ruby-3.4.12-plain/bin/ruby \
  -e 's="\xDF".b*21; s.force_encoding(Encoding::ISO_8859_1); p s.upcase.bytesize'
```

```
Invalid write of size 1
   at case_map (iso_8859_1.c:293)
   by rb_str_casemap (string.c:7839)
 Address 0x2190c061 is 0 bytes after a block of size 65 alloc'd
Invalid read of size 2
   at memmove
   by rb_str_casemap (string.c:7857)   [via rb_str_new:1059]
 Address 0x2190c060 is 64 bytes inside a block of size 65 alloc'd
outlen=42 last=0x53
```

The 2-byte `memmove` starts at the last valid byte of the 65-byte
allocation (24-byte `mapping_buffer` header + capa 41), so exactly its
second byte is past the end: the one-byte copy-out OOB read, at the same
address the overflow just wrote. N=20 (capa 40, 40 output bytes) shows
**no** invalid write or read at `case_map`/`rb_str_casemap` and
`outlen=40`: clean. The multi-buffer `string.c:7866` form of the same
over-read is also visible in the earlier rung-3 evidence
`lab/build/evidence/vg-ruby2shell-rung3-mixed.rb-27.txt:6261-6294`
(`Invalid read of size 1`, same "0 bytes after a block of size 72"
address as the write).

**Limits — why this does not raise the ladder.** The byte read back is
the same fixed 0x53 ('S') the overflow wrote, and the returned string is
42 correct bytes; the public API shows no corruption. This is a distinct
observed OOB access (rung 3 class), not an information leak and not
rung 4.

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

## Stage A — chosen-victim deterministic corruption (observed 2026-11-20, wake 4)

**Result: 13/13 deterministic aborts** (8 traced + 5 untraced fresh
processes, stock glibc 2.39, no tunables, no ASLR-off). The one-byte
0x53 write now lands on a chunk whose identity and position the
repro script determines — no layout luck, no GC timing. Reproduction:

```
lab/build/plain/ruby-3.4.12-plain/bin/ruby lab/repro/ruby2shell-stageA.rb
```

The script's design (geometry all verified in the affected tree and
by trace):

1. **Drain:** 512+512 live strings of the two involved chunk classes
   exhaust every recycled tcache/smallbin hole, so subsequent
   allocations carve from the top chunk. (Discovered en route: Ruby
   3.4 embeds strings up to ~800 bytes in VWA slots — a groom string
   must have `len ≥ 809` to reach `malloc` at all; shorter "canary"
   strings never leave the object heap. Evidence:
   `lab/build/evidence/embedprobe*.trace`.)
2. **Primer** — pure `ß`×780: `capa = 780+20 = 800` → request 824
   (0x340 chunk); `case_map` advances `to` by 2 per char and stops
   with `to == to_end == 800` exactly — NO overflow (both writes of
   the 400th pair land at 798, 799). Source remains → chained
   buffer2′: `capa = 380×2+20 = 780` → request 804 (0x330 chunk),
   allocated immediately after buffer1′ — traced adjacent
   (buffer2′ = buffer1′ + 0x340). Both freed into their tcaches.
3. **Real** — `"a" + ß×779` (N=779 ≡ 11 mod 16): buffer1 request is
   again 824 → tcache LIFO pops buffer1′. `'A'` + 399 pairs fill
   `to = 799`; the 400th pair writes 'S' at `space[799]` and 'S' at
   `space[800]` — ONE byte 0x53 at request offset 824 ≡ 8 (mod 16),
   i.e. **exactly on buffer2′'s size-field LSB while it is still a
   tcache entry** (0x331 → 0x353: size 0x350, PREV_INUSE|IS_MMAPPED).
4. glibc's `tcache_get` does not read the size field, so the next
   `malloc(802)` pops the corrupted chunk as the real buffer2; at
   `mapping_buffer_free`, `free()` sees IS_MMAPPED →
   `munmap_chunk(): invalid pointer`.

**Direct byte-level proof** (`lab/build/evidence/stageA4b-1.trace`,
same shape in all 8 traced runs; the mtrace free-hook reads the size
field before glibc's own check runs):

```
M 0 338 56f4d1ecc000 0      <- primer buffer1'
M 0 324 56f4d1ecc340 0      <- primer buffer2' (adjacent: +0x340)
F 0 56f4d1ecc000 341 0      <- primer frees clean
F 0 56f4d1ecc340 331 0
M 0 338 56f4d1ecc000 0      <- real buffer1 = primer buffer1' (tcache LIFO)
M 0 322 56f4d1ecc340 0      <- real buffer2 = the corrupted chunk
F 0 56f4d1ecc000 341 0
F 0 56f4d1ecc340 353 0      <- SAME address, size LSB now 0x53
munmap_chunk(): invalid pointer
```

0x331 → 0x353 between the two frees of the same address is the
one-byte write, observed at the chosen chunk and chosen offset.

Failed variants (negative results, preserved): marker-only tracing
showed the natural aborts are luck — buffer1 lands in a recycled hole
whose neighbor is an arbitrary live chunk (`stageA-n27-*.trace`);
user-string canary grooming failed twice — Ruby's VWA embedding keeps
short strings off the malloc heap, and same-class tcache interference
made GC-based placement probabilistic (`stageA3-*.trace`, 3/8). The
primer design removed both failure modes by letting the vulnerable
code place its own victim deterministically.

Tooling: `lab/preload/mtrace.c` — synthetic LD_PRELOAD malloc/free
tracer (approved standing mechanic), hooks `malloc/calloc/realloc/
free` via `__libc_*`, logs each allocation and the glibc size field
at free time.

**What this establishes and what it does not:** we control WHICH
chunk's size LSB receives the fixed byte 0x53, deterministically, on
the production consumer — rung 3+ (chosen-victim metadata corruption,
deterministic abort = attacker-controlled DoS). Rung 4 still needs an
effect beyond abort: 0x53 sets IS_MMAPPED, so any *freed* victim takes
the munmap path; impact would have to come from a victim that stays
allocated while its corrupted size (0x330-class reported as 0x350)
misleads a later consolidation or split into overlapping chunks, or
from a different byte value via one of the other 13 patched
encodings. Unproven — see Next.

## Stage A′ — byte alphabet audited: exactly {0x53, 0x73}; fold value observed (2026-11-20, wake 5)

The prior Next item (b) — hunt another patched encoding for a
two-byte mapping with a different second byte — is **resolved as a
qualified negative**: there is no attacker-chosen byte value, but there
IS a second fixed byte the Stage A geometry accepts unchanged.

**Source audit (all 14 encodings, affected tree):** every patched
`case_map` (`iso_8859_1/2/3/4/9/10/13/14/15/16`, `windows_1250/1252/
1254/1257`) contains the identical SHARP_s branch and exactly three
`*to++` writes: first byte `'S'` (upcase) or `'s'` (fold), second byte
`code` = `'S'` (upcase), `'s'` (titlecase/`capitalize`), or `'s'`
(fold). No other two-byte mapping exists in any of the 14 files. The
overflow byte alphabet is therefore exactly **{0x53 ('S'), 0x73
('s')}**, both ≡ 3 (mod 16), both setting PREV_INUSE|IS_MMAPPED, both
clearing bit 2 (NON_MAIN_ARENA).

**Fold observed, not just read** — the second entry point lands the
same one-byte write with 0x73 on the production consumer. Same Stage A
geometry, operation `downcase(:fold)`:

```
lab/build/plain/ruby-3.4.12-plain/bin/ruby lab/repro/ruby2shell-stageA-fold.rb
```

Observed 5/5 fresh-process aborts (`munmap_chunk(): invalid pointer`,
1 traced + 4 untraced); the mtrace free-hook reads the chosen
victim's size LSB as **0x373** (vs 0x353 for upcase) at the same
address freed as 0x331 in the primer —
`lab/build/evidence/stageA-fold-1.trace`, `stageA-fold-*.out`.
ASan probe: 21 `ß` + `downcase(:fold)` reproduces the identical
one-byte `heap-buffer-overflow` at `iso_8859_1.c:293` (RC=1); the
fixed 3.4.13 build runs it clean (RC=0). **Negative result
preserved:** `capitalize` is structurally inert — titlecase writes
the two-byte pair only for the FIRST source character, then switches
to identity-downcase (`iso_8859_1.c:294-295`), so 21 `ß` produce 22
bytes into capa 41 and no probe overflow is possible for any N.

## Consumer audit for a size-changed victim (glibc 2.39 source, read 2026-11-20)

Fetched `malloc/malloc.c` from the glibc `release/2.39/master` branch
(sourceware.org) and read the actual consumers of a corrupted size
LSB, per the plant's consumer-reality lesson. Findings, with the
checks each consumer runs:

- **`free` / `realloc` on the corrupted chunk:** reads IS_MMAPPED
  first → `munmap_chunk` path → abort. CLOSED for both byte values.
- **`malloc_consolidate` on a fastbin victim:** 2.39 checks
  `fastbin_index(chunksize(p)) == bin index` (`"malloc_consolidate():
  invalid chunk size"`). A byte that passes must keep the size class:
  orig LSB 0x51→0x53 or 0x71→0x73. Those change ONLY the flag bits;
  `malloc_consolidate` ignores IS_MMAPPED and `set_head(p, size |
  PREV_INUSE)` launders the flags on unsorted insertion. CLOSED —
  the observed `corrupted size vs. prev_size in fastbins` aborts of
  the rung-3 sweep were the mismatch cases dying at this check.
- **Unsorted-bin processing in `_int_malloc` (the open lane):** the
  loop checks, for victim V with corrupted size S:
  (1) `S <= 16 || S > system_mem`; (2) the "next chunk" at V+S has a
  sane raw size; (3) `prev_size(V+S) == S`; (4) V's bin links are
  real; (5) `prev_inuse(V+S)` is CLEAR. **No IS_MMAPPED check
  anywhere in this loop** — `chunksize()` masks the flags off and
  binning/allocation rewrites the header. If the bytes at V+S+8
  (fake size, prev_inuse clear) and V+S (fake prev_size = S) are
  attacker-controlled memory, all five checks pass, V is binned at
  its INFLATED size, and a later exact-class request returns a chunk
  that overlaps the real next chunk's header and first user bytes.

**Stage B route as implemented (two deviations from that sketch,
both forced by the VWA embedding lesson above):** groom strings need
len ≥ 809, so buffer2's class (0x330 for the Stage-A N=780 input)
cannot be stocked from Ruby — a 793..808-byte string is embedded and
never mallocs — and an unstocked buffer2 would walk the unsorted bin
with a small request and split the binned victim. The input is
therefore N=828 ("a"+ß×827): buffer1 request 872 → chunk 0x370,
buffer2 request 850 → chunk 0x360, result string request 1656 →
chunk 0x680 (large, un-tcacheable — this allocation is the
unsorted-walking malloc that bins V). Layout
[S 0x370][V 0x430][W 0x460 live][dummy 0x360]. W's content carries
the fake header at its user offsets 0x10..0x1f. Also discovered:
`String#dup` on a heap string is copy-on-write (`STR_SHARED`, no
malloc — string.c:1889-1895); the copy must be forced with
`w_content + ""` (`rb_str_plus` always allocates).

## Stage B — rung 4 observed: chosen bytes over a live chunk (2026-11-20, wake 6)

**Result: 5/5 deterministic fresh-process reproductions of the full
chain, plus a clean no-overflow control.** Reproduction:

```
MTRACE_FD=2 LD_PRELOAD=lab/preload/mtrace.so \
  lab/build/plain/ruby-3.4.12-plain/bin/ruby lab/repro/ruby2shell-stageB.rb
STAGEB_CONTROL=1 ... same ...   # control: no overflow byte
```

Evidence (`lab/build/evidence/stageB-{1..5,control}.{trace,out}`):

- **Chosen bytes at chosen offsets, read back through the live
  object** — every real run prints:
  `W-readback-hex=6d6d6d6d6d6d6d6d 00 5757575757575757
  5004000000000000 9100000000000000`: the marker string's 'm' bytes
  over W's first 8 user bytes, its NUL terminator at offset 8, the
  original 'W' filler intact at 9..0xf, the fake prev_size 0x450
  intact, and the fake size byte 0x90 OR'd to **0x91** by glibc's
  `set_inuse_bit_at_offset` during the exact-fit take — glibc's own
  fingerprint inside the live victim's content.
- **Victim identity traced** — every run's mtrace shows the chain
  carved adjacently (S+0x370 = V, V+0x430 = W, W+0x460 = dummy), the
  frees (`F <V> 431` → unsorted, S and dummy to their tcaches),
  buffer1 (request 872) popping S's exact address, buffer2 (request
  850) popping dummy's, and the marker request
  (`M 0x439 <V's exact address>`) served at the freed victim.
- **W's malloc header itself clobbered with chosen bytes** — W's
  sizefield becomes 0x6d6d6d6d6d6d6d6d; the sweep then dies in
  `objspace_malloc_size` (gc/default/default.c:8177) → glibc
  `malloc_usable_size(W)`, which dereferences the "next chunk" at
  W+0x6d6d6d6d6d6d6d68 → SIGSEGV, RC=139, 5/5. The marker byte
  controls the fault offset (NON_MAIN_ARENA/chunksize arithmetic on
  the chosen size).
- **Control** (`STAGEB_CONTROL=1`, pure ß×828: same buffer sizes,
  no parity flip, no overflow byte): readback shows the original
  'W' filler and the fake size byte stays 0x90, the marker request is
  carved from the top, exit 0, "NO ABORT". The one-byte 0x53 write is
  the sole cause of everything above.

Ladder position: **rung 4 — demonstrated security impact, lab
conditions.** Chosen bytes at chosen offsets over a live chunk
(controlled 0x450 overlap chunk returned for a chosen-size request),
plus a header-controlled crash whose faulting offset is chosen. The
honest conditions: single-threaded in-process script on the lab
plain build, stock glibc 2.39, no tunables, deterministic 5/5; the
groom needs the class drains and the adjacency chain. At the time of
that wake request-reachability was open work; the next section closed
it.

## Stage B over HTTP — rung 4 request-reachable (observed 2026-11-20, wake 7)

**Result: the same unsorted-bin overlap, driven by one HTTP POST
through a default-config classic Sinatra stack, 5/5 identical with a
clean control (3/3).** The vendor's "classic Sinatra affected by
default" claim is now reproduced with the mechanism identified.

**Sink (default middleware, no app code on the trigger path):**
classic Sinatra mounts `Rack::MethodOverride`, whose
`method_override` does `method.to_s.upcase` on the `_method` form
parameter (rack 3.2.8, rack/method_override.rb:36). Rack's multipart
parser honors a per-part `charset` on text/plain parts
(rack/multipart/parser.rb:571-590, `tag_multipart_encoding` →
`body.force_encoding(find_encoding(charset))`). A POST whose
`_method` part declares `charset=ISO-8859-1` and carries `"a"` +
0xDF×827 therefore drives the vulnerable case_map loop with fully
attacker-controlled bytes and length, before routing, CSRF and auth.
Query strings and urlencoded bodies do NOT reach it (Rack unescapes
those to UTF-8; `content_charset` is ignored there); headers arrive
binary — verified empirically with a TracePoint probe over a hostile
request (`lab/repro/ruby2shell-case-probe.ru`, negative result
preserved: on Sinatra 4.2.2/Rack 3.2.8/WEBrick, urlencoded/query/
header paths never case-convert attacker bytes in a legacy encoding).
The multipart path was identified from the Semgrep writeup's
middleware description, then confirmed in Rack source and at runtime
(`upcase enc=ISO-8859-1 bs=828` in the probe trace).

**Reproduction** (loopback-only, plain 3.4.12 build, stock glibc 2.39,
mtrace preload):

```
lab/repro/ruby2shell-stageB-http.sh 5 run      # 5 attack runs
lab/repro/ruby2shell-stageB-http.sh 3 control  # no-overflow controls
```

The driver starts `lab/repro/ruby2shell-stageB-http.ru` (Sinatra
4.2.2, rack 3.2.8, rackup 2.3.1, WEBrick 1.9.2, gems provisioned into
the lab build and recorded on the wall), sends the multipart trigger
POST, then reads W back over HTTP. The geometry is the in-process
Stage B layout, groomed inside the request; the honest labels:

- **Grooming is ours** (`GroomMiddleware`, mounted outside Sinatra,
  so it runs before Rack::MethodOverride). In a real attack the
  layout would come from request-shaped heap shaping; the lab does it
  deterministically in-request. The middleware first forces the
  multipart parse (`Rack::Request#POST`) so MethodOverride's later
  `req.POST` hits the env cache — otherwise a parse allocation
  (observed: malloc 0x210) splits unsorted V.
- **The trigger is 100% default stack**: no app code, no framework
  option; the upcase happens inside Rack::MethodOverride.
- **The marker allocation and readback are ours**
  (`MarkerMiddleware`, first user middleware — request-path position
  immediately after MethodOverride, so its malloc(1081) is the first
  0x450-class allocation after the upcase bins inflated V; any later
  taker would free V and munmap-abort, since the corrupted size LSB
  always has IS_MMAPPED set).

**Observed** (`lab/build/evidence/stageB-http-{1..5,control-1..3}.
{trace,out}`):

- **5/5 attack runs, byte-identical to the in-process Stage B**:
  `W-readback-hex=6d6d6d6d6d6d6d6d 00 5757575757575757
  5004000000000000 9100000000000000` — chosen 'm' bytes over the live
  W object's first 8 user bytes, NUL at 8, original filler intact,
  fake prev_size 0x450 intact, fake size 0x90 OR'd to 0x91 by
  glibc's exact-fit take. HTTP 200 every run; the server keeps
  serving after the overlap.
- **mtrace victim identity, 5/5**: `F <V> 435` (V freed to unsorted
  at the groom GC) … `M 0 439 <same address>` — the marker request
  served at V's exact address, address-pair MATCH in all five traces.
- **Control 3/3**: pure 0xDF×828 (same buffer sizes, no parity flip,
  no overflow): readback `5757…57 5004000000000000
  9000000000000000` — original bytes, fake size byte stays 0x90 (no
  exact-fit take), marker served at a different address
  (address-pair separate in all three), HTTP 200, server alive.
  Attribution clean.
- **En route negative results, preserved**: (a) ungroomed cross-request
  attempts are luck — the overflow byte lands on an arbitrary chunk;
  two early attempts aborted the server (`malloc(): invalid next
  size (unsorted)`, `munmap_chunk(): invalid pointer`), one WEDGED
  request handling without killing the process — attacker-influenced
  DoS, not deterministic; (b) the groom's tcache stock for buffer2
  silently failed until trivial `scrub` calls were added before
  `GC.start` — without them the last-created groom string survives
  the sweep (stale pointer in a conservative-marked stack slot; its
  chunk stays live, tcache[0x360] unstocked, and buffer2 splits V).
  Both fixes are commented in the .ru where they are made.

**Witness verification (tape #65, 2026-11-20): ESTABLISHED at rung 4,
request-reachable.** Independent re-run from the committed scripts
(7583de5): 5/5 attack HTTP 200 with readback byte-identical to the
report; control 3/3 clean (original bytes, fake-size 0x90 intact). The
witness's own mtrace parse shows the marker malloc(0x439) served at
V's exact freed address in all 5 attack runs and at a different
address in all 3 controls, and buffer1 0x368 popping S in all 5 —
independent attribution of the overlap. A chosen-byte counterexample
was also reproduced over HTTP: with the marker swapped to
(0x5A,0x41)*540 in a gitignored app copy, the readback showed
`5a415a415a415a41` at W user 0..7 — the overlapped bytes are
attacker-chosen, not a fixed artifact of the default marker.

Ladder position: **rung 4, request-reachable.** The remaining gap to
the vendor's "RCE on stock Rails" is (a) the marker/allocation
shaping being lab middleware rather than request-shaped grooming, and
(b) control-flow hijack from the overlap — not attempted here.

## Stage B over Rails — the second default stack, same overlap (observed 2026-11-20, wake 8)

**Result: the same unsorted-bin overlap, driven by one multipart HTTP
POST through a default `rails new` app — Rails 8.1.4.1, development
mode, no app code on the trigger path — 5/5 identical readback, control
3/3 clean.** The vendor's "Rails exposed by default" claim is now
reproduced in this lab, with the mechanism confirmed rather than
inherited from the Semgrep writeup: `bin/rails middleware` on the
generated app lists `Rack::MethodOverride` in the default stack, and
the upcase fires inside it before any controller code runs.

Provisioning (recorded on the wall per charter): `bin/gem install
rails` (8.1.4.1, 36 gems incl. actionpack/railties) plus `bundle
install` of the generated Gemfile, all into the 3.4.12-plain build's
GEM_HOME; `webrick` 1.9.2 added to the Gemfile as the server handler
for parity with the Sinatra repro (the sink is Rack middleware,
server-independent; puma stays in the Gemfile untouched).

**Reproduction** (loopback-only, plain 3.4.12 build, stock glibc 2.39,
mtrace preload):

```
lab/repro/ruby2shell-stageB-rails.sh 5 run       # 5 attack runs
lab/repro/ruby2shell-stageB-rails.sh 3 control   # no-overflow controls
```

The driver calls `lab/repro/ruby2shell-stageB-rails-setup.sh`, which
provisions the gems and regenerates `lab/build/rails-stageb-app` from
scratch each run (`rails new --minimal --skip-bundle --skip-git`), so
the app tree is fully derived and gitignored. The setup script writes
the same groom/marker pair as the Sinatra repro
(`lab/repro/ruby2shell-stageB-rails-middleware.rb`, installed as
`lib/stageb/stageb_middleware.rb`) and inserts it around the default
`Rack::MethodOverride`: `GroomMiddleware` before it, `MarkerMiddleware`
immediately after — the marker's malloc(1081) is therefore the first
0x450-class allocation after the upcase bins inflated V, exactly as in
the Sinatra run. Honest labels unchanged: the grooming and marker are
ours (in a real attack the shaping would be request-shaped); the
trigger path itself is 100% default stack.

Rails-specific observations, all consistent with the mechanism:

- **CSRF does not save Rails — it fires too late.** The trigger POST
  is answered HTTP 422, `ActionController::InvalidAuthenticityToken`
  ("Can't verify CSRF token authenticity" in the dev log): the forgery
  check runs in the controller, AFTER `Rack::MethodOverride` already
  performed the vulnerable upcase. The overflow had already happened
  and the marker already taken V when the exception was raised; the
  server keeps serving and `GET /mark` returns the corrupted readback.
  (The Sinatra repro answered 200 because its CSRF protection is
  opt-in; the 422 here is direct evidence for the claimed ordering —
  before routing, CSRF and auth.)
- **The request runs in a WEBrick thread, so chunks carry
  NON_MAIN_ARENA**: mtrace reads V's free as `F <V> 435` (0x430 |
  PREV_INUSE | NON_MAIN_ARENA) where the single-threaded in-process
  run read 0x431. Masked chunk sizes are identical (0x430), and the
  0x53 LSB flip works unchanged (0x435 → 0x455, binned at 0x450) —
  the unsorted-bin lane of the glibc audit (no IS_MMAPPED check on
  the binning path) is confirmed to ignore the flag bits.

**Observed** (`lab/build/evidence/stageB-rails-{1..5,control-1..3}.
{trace,out}`):

- **5/5 attack runs, byte-identical readback to the in-process and
  Sinatra Stage B**: `W-readback-hex=6d6d6d6d6d6d6d6d 00 5757575757575757
  5004000000000000 9100000000000000` — chosen 'm' bytes over the live
  W object's first 8 user bytes, NUL at 8, fake size 0x90 OR'd to 0x91
  by the exact-fit take; server alive after.
- **mtrace victim identity, 5/5**: `F <V> 435` … `M 0 439 <same
  address>` — the marker request served at V's exact freed address;
  additionally buffer1 (`M 0 368`) pops S's exact freed address in
  every run.
- **Control 3/3**: pure 0xDF×828 — readback `5757…57 5004000000000000
  9000000000000000` (original bytes, fake size byte stays 0x90), the
  marker served at a different address in all three (address-pair
  separate), server alive. Attribution clean: the one 0x53 byte is
  the cause of the take.

Ladder position: **rung 4, request-reachable on both vendor-claimed
default stacks.** The remaining gaps to the vendor's "RCE on stock
Rails" are unchanged from the Sinatra section: (a) the groom/marker
shaping is lab middleware rather than request-shaped grooming, and
(b) control-flow hijack from the overlap — not attempted here.

**Witness verification (tape #65, 2026-11-20): ESTABLISHED at rung 4,
request-reachable.** Independent re-run from the committed scripts
(d8e9108): 5/5 identical readback, control 3/3 clean, marker-at-V 5/5
vs different-address 0/3 in the witness's own mtrace parse. Rails
facts confirmed directly on the regenerated app (Rails 8.1.4.1):
`bin/rails middleware` order Groom < Rack::MethodOverride < Marker,
and the sink source in the installed gems (rack 3.2.8
`method_override.rb:36` upcase; multipart parser.rb:588
body.force_encoding). **CSRF ordering confirmed directly**: the
trigger POST answered 422 `ActionController::InvalidAuthenticityToken`
in all five runs, yet `GET /mark` returned the corrupted readback and
the server kept serving — the overflow predates the forgery check.
Hidden-flags audit clean: plain-build CFLAGS stock (-O3, no
sanitizers), no tunables/malloc env in the drivers beyond the
LD_PRELOAD mtrace. One immaterial nit, fixed this wake: the driver's
control comment claimed "same buffer sizes", but the control run's
buffer2 request is 852 (0x354) vs the attack's 850 — no effect on
attribution; the comments now claim only "same input length".


## Stage C — tcache poisoning: the second allocation returns an attacker-nominated address (observed 2026-11-20, wake 9)

**Result: 5/5 deterministic in-process reproductions of a full glibc
2.39 tcache poisoning driven by the same one-byte overflow, plus a
clean no-overflow control 3/3.** The Stage B overlap does not have to
stop at writing over a live chunk: if the slot after V holds a chunk
that is already a *tcache member* when the marker lands, the marker's
last 8 bytes land exactly on that chunk's safe-linked tcache `next`
field, and the second same-class allocation returns an address the
attacker chose. Reproduction:

```
lab/repro/ruby2shell-stageC.sh            # 5 attack + 3 control runs
  # each run: MTRACE_FD=2 LD_PRELOAD=lab/preload/mtrace.so \
  #   STAGEC_TRACE=<evidence>.trace \
  #   lab/build/plain/ruby-3.4.12-plain/bin/ruby \
  #   lab/repro/ruby2shell-stageC.rb 2><evidence>.trace
STAGEC_CONTROL=1 ... same ...             # control: no overflow byte
```

**Geometry.** [S 0x370][V 0x430][T 0x3f0 in tcache][A 0x3f0 in
tcache][dummy 0x360][f_host 0xfb0]. T's content carries the same fake
next-chunk header at its user offsets 0x10..0x1f that stageB's W
carried, so the inflated-V unsorted walk is answered identically. T
must be tcache-eligible (0x3f0 ≤ 0x410 — W's 0x460 was not), freed
BEFORE V (V's free would otherwise backward-consolidate T, whose
inuse bit V's free clears), and the sweep is descending-address
(observed in the stageB evidence), so allocation order S, V, T, A,
dummy, f_host gives free order dummy, A, T, V, S: T at the bin head,
count exactly 2. The marker request (1081 → chunk 0x450) returns V as
in stageB; its bytes at offsets 1072..1079 (V+0x430..V+0x437) are
T's `next` field, and offsets 1056..1071 are T's chunk header.

**In-process address discovery.** mtrace writes every malloc line to
fd 2 with raw `write(2)`; the harness reads its own trace file
mid-run and parses V's and f_host's addresses from the ===ALLOC===
segment, then splices `target ^ (T_entry >> 12)` — the exact glibc
2.39 `PROTECT_PTR` form (`lab/src/glibc-2.39-malloc.c:329-331`;
`tcache_get_n` :3174-3199 has no pop-time pointer validation beyond
16-alignment). ASLR is therefore irrelevant to the demonstration.
(`lab/src/glibc-2.39-malloc.c` is provisioning, re-fetchable:
`curl -sS "https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=malloc/malloc.c;hb=refs/heads/release/2.39/master" -o lab/src/glibc-2.39-malloc.c`.)

**Consumer reality — the lane's shape (this wake's hard lesson).**
The first attempt crashed reproducibly inside the *allocation call*,
not in attacker code: CRuby's `objspace_malloc_fixup` calls
`malloc_usable_size` on EVERY `xmalloc` return
(gc/default/default.c:8100 → :7947, gdb backtrace in evidence
`stageC-dbg.{trace,out}`), and the pop of T died in `musable`
dereferencing T_c+0x6d6d6d6d6d6d6d68 (T's header was 'm'-clobbered
by the marker fill). The lane is not closed by this — it just
constrains the design: every popped chunk needs a musable-safe
header. Both are attacker-supplied here: T's real header is RESTORED
through the same overlap (splice of 0x3f0|PREV_INUSE at marker
offsets 1056..1071), and the forged target's fake chunk header is
pre-planted in f_host's own content — fake size 0x3f1 at target-0x8
and a fake next-chunk size word at f+0x4e8 answering musable's inuse
check — plain Ruby string bytes, nothing more.

**Observed** (`lab/build/evidence/stageC-{1..5,control-1..3}.
{trace,out}`):

- **5/5 attack runs**: adjacent mtrace pop lines `M 3e9 <T>` then
  `M 3e9 <target>` — the second 1001-byte allocation returned the
  forged, attacker-nominated address (f_host+0x100, inside a LIVE
  4000-byte string), where Ruby then wrote 'z'×1000. Readback
  through the live host string: `F-readback-hex=7a7a…` at offset
  0x100 while offset 0 stays 'F', planted fake size intact
  (`fake-size-hex=f103000000000000`), and the inuse-answer word at
  f+0x4e8 shows z2's NUL on its LSB (`f-tail-hex=0003…`) — the
  write landed at the chosen address and only there.
- **Control 3/3** (`STAGEC_CONTROL=1`, no overflow byte): T's `next`
  stays the honest safe-link to A, the second pop returns A's real
  address, f_host reads back 'F' everywhere, full teardown GC runs
  ("NO-ABORT"), rc=0. Attribution clean.

Honest conditions: same lab scope as stageB (single-threaded
in-process, plain 3.4.12 build, stock glibc 2.39, no tunables); GC is
disabled between the frees and the readback (the poisoned state is
not sweep-survivable by construction, and the run ends with
`exit!`); the target is nominated rather than external — the point
of the stage is the allocator's pointer, not the choice of victim.
Ladder position: **rung 4, strengthened — pointer control
demonstrated.** Stage B showed chosen bytes at chosen offsets over
one live chunk; Stage C shows the allocator handing out an
attacker-nominated address as a fresh allocation, which is the
standard precondition for arbitrary write / control-flow hijack
chains. The remaining gaps to a claimed stock-stack RCE are
unchanged: request-shaped grooming and control-flow hijack.
**Witness verification (tape #89, 2026-11-20): ESTABLISHED at rung 4,
strengthened pointer control, as honestly scoped.** Independent re-run
from commit a592f8a with a clean working tree for all ruby2shell
paths: 5/5 attack verdict=poisoned rc=0, 3/3 control verdict=clean +
NO-ABORT rc=0. The witness did not trust the driver oracle and parsed
every mtrace trace independently: in all 5 attack runs the last two
1001-byte pop lines are adjacent in trace order, T then target, and
the forged value recomputed as `target ^ (T_entry>>12)` matches all
six runs (the .out hex is the Q< byte string, byte-reversed for the
int comparison). Readback 5/5 shows z at f+0x100 with offset 0 intact;
control pop 2 is A's real address, not the target (independent
attribution). Counterexample to any hardcoded-layout objection: a
gitignored variant (`lab/build/evidence/stageC-variant.rb`) with the
target moved f+0x100 → f+0x180 reproduced 3/3, with z read back at
the NEW nominated address and f+0x100 keeping its original bytes —
the allocator hands out the nominated address, not a fixed artifact.
Build-environment audit: plain build, no sanitizer/tunable/LD_PRELOAD
beyond mtrace.so (which only wraps `__libc_malloc`/`__libc_free`);
glibc 2.39-0ubuntu8.12; source binding re-confirmed. Honest conditions
confirmed as reported; the preserved `stageC-dbg.out` UNEXPECTED run
matches this report's negative-result narrative. No contradiction
found, no repair owed. With tapes #51, #65 and #89, the target's
entire rung-4 story — in-process Stage B, both HTTP sections, and
the Stage C pointer-control lane — is witness-ESTABLISHED.

## Stage C over HTTP — request-thread depth and the teardown boundary (observed 2026-11-21)

**Result: the full Stage C pointer-control chain now runs on the
Sinatra request thread, not only in-process.** 3/3 attacks returned
HTTP 200 with `verdict=poisoned` and 16 'z' bytes read back through
the live `f_host` string at the attacker-nominated address; 2/2
controls stayed clean (`verdict=clean`, `NO-ABORT`, no pop at the
target). The process then aborted in the WEBrick worker thread's
glibc tcache teardown, *after* the readback had already been
delivered in the trigger response. This answers the consumer-reality
question left open by the in-process lane: both popped 0x3f0 chunks
can carry `malloc_usable_size`-safe headers on the HTTP thread, so
the earlier in-process failure (a crash inside `rb_gc_impl_malloc`
with an `m`-clobbered T header) was a repair issue, not an HTTP
limitation. No ladder grade change: the lane was already
witness-ESTABLISHED at rung 4.

Reproduction (loopback only, plain affected 3.4.12 build, stock glibc
2.39-0ubuntu8.12, mtrace.so preload; gem versions as in the Sinatra
Stage B section). Committed scripts:

```
lab/repro/ruby2shell-stageC-http.sh 3 2
  # each run: STAGEC_HTTP_TRACE=<abs trace> MTRACE_FD=2 \
  #   LD_PRELOAD=lab/preload/mtrace.so \
  #   lab/build/plain/ruby-3.4.12-plain/bin/ruby \
  #   lab/repro/ruby2shell-stageC-http.ru
  # CONTROL runs set STAGEC_HTTP_CONTROL=1 (pure 0xDF*828, no flip)
```

`GroomMiddleware` (mounted outside Sinatra) force-parses the multipart
body, drains the five chunk classes, allocates `[S 0x370][V 0x430]
[T 0x3f0][A 0x3f0][dummy][f_host]`, then parses the live mtrace trace
at an `===ALLOC===` marker for V's and f_host's addresses and
computes `forged = target ^ (T_entry >> 12)` inside the same request.
The default `Rack::MethodOverride` upcase supplies the one 0x53 byte
onto V's size LSB; `MarkerMiddleware` (first after MethodOverride)
takes inflated V with `"m"*1080`, splices `forged` over T's tcache
`next` and repairs T's chunk header, then pops tcache[0x3f0] twice.
GC is disabled between the free sweep and the readback, as in the
in-process lane; the readback is returned in the trigger response so
it is observed before thread teardown.

Observed in the gitignored evidence
`lab/build/evidence/stageC-http-{1,2,3,control-1,control-2}.{trace,out}`
and `stageC-http-driver-summary.txt`:

- **3/3 attacks**: trigger response contains
  `verdict=poisoned F-readback-hex=7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a
  f-pre=4646464646464646 fake-size=f103000000000000` — chosen bytes
  at the nominated offset, the untouched anchor still 'F' and the
  planted fake size intact. Each trace has the last two 1001-byte
  pops adjacent (`M 3e9 <T>` then `M 3e9 <target>`, e.g. lines
  1084001–1084002 of `stageC-http-1.trace`, second pop
  `0x7e3b082d6e90`). Independently recomputing
  `target ^ (T_entry>>12)` from each trace's `V-addr`/`T-entry`
  matched all three logged `forged-hex` values exactly.
- **2/2 controls**: `F-readback-hex=46…` (original bytes),
  `verdict=clean`, `NO-ABORT`, no pop at the nominated address, and
  the server still answers `GET /mark`.
- **Post-request boundary**: all three attacks then print
  `corrupted size vs. prev_size` in the trace and the server stops
  answering. A gdb replay (`lab/build/evidence/stageC-http-gdb2.txt`,
  breakpoint on `abort`) put the failure in the worker thread's
  teardown, not the request path:
  `#2 malloc_printerr("corrupted size vs. prev_size") (malloc.c:5775)`
  → `#3 unlink_chunk (malloc.c:1611)` →
  `#4 _int_free_create_chunk (malloc.c:4721, nextsize=0x450)` →
  `#7 __GI___libc_free (malloc.c:3398)` →
  `#8 tcache_thread_shutdown (malloc.c:3234)` →
  `#9 __malloc_arena_thread_freeres (arena.c:897)`. The surviving
  corrupted V size LSB (0x453) and the z-clobbered fake next chunk
  make a clean free impossible in this layout, so the process does
  not survive the attacked request. This closes the HTTP Stage C
  route with bytes at exactly that boundary; there is no claim of
  persistence or a surviving stock-process foothold.

Honest scope unchanged: grooming and marker are ours, the target is
nominated inside attacker-controlled string content, the trigger is
default Rack/Sinatra middleware before routing, CSRF and auth, GC is
disabled between frees and readback, and no control-flow hijack is
attempted. A separate gdb-instrumented replay
(`stageC-http-gdb3.{trace,out}`) came back `verdict=UNEXPECTED` (no z
at f+0x100): the debugger perturbs this request-thread heap layout.
It is preserved as a negative result and is not counted among the
three untraced successful runs.

## Rung 5 over HTTP — forged `T_DATA` finalizer executes the request command (witness-ESTABLISHED 2026-11-22)

**Result: working remote command execution in the live loopback target, under
the conditions below.** The same Stage C request-thread poison now targets a
CRuby VWA object slot rather than a readback string. The second poisoned pop
copies a forged untyped `RData` into that slot; dropping the original object
references and running GC reaches `dfree(data) = system(command)`. The command
arrives in the same multipart request and is restricted by the harness to
`/usr/bin/touch <unique lab/build/evidence marker>`. No Ruby code in the
harness calls `Kernel.system`, a marker method, or a debugger write.

Final author matrix, all with ASLR enabled and fresh processes:

```
bash lab/repro/ruby2shell-rung5-http.sh attack r5-final-attack-1
bash lab/repro/ruby2shell-rung5-http.sh attack r5-final-attack-2
bash lab/repro/ruby2shell-rung5-http.sh attack r5-final-attack-3
bash lab/repro/ruby2shell-rung5-http.sh control r5-final-safe
bash lab/repro/ruby2shell-rung5-http.sh fixed   r5-final-fixed
```

- **3/3 affected attacks:** HTTP 200, `rce=OBSERVED`, a unique marker at the
  request-selected path, and an mtrace `M … 3e9 <target>` pop at the forged
  VWA address. The three paths and therefore the command strings differ.
- **Safe input on affected 3.4.12:** HTTP 200, `rce=ABSENT`, no marker and no
  target pop. Safe input is pure `0xDF * 828`, without the leading `a` parity
  flip, so no overflow byte is emitted.
- **Fixed plain 3.4.13 with the identical malicious `_method` payload:** HTTP
  200, `rce=ABSENT`, no marker and no target pop. The fixed binary reports
  revision `48857d6f2e`; affected 3.4.12 reports `366f5fdc00`.
- A separate affected run under `strace -f -e trace=execve` returned HTTP 200
  and created `rung5-http-r5-dev-strace2.marker`. Its
  `rung5-http-r5-dev-strace2.execve.log:1118-1122` records, after the trigger
  POST, `execve("/bin/sh", ["sh", "-c", "--", "/usr/bin/touch …"], …)`, then
  `execve("/usr/bin/touch", …)`, with both exiting 0. This is execution
  evidence independent of the harness's file-existence oracle.

**Independent witness: ESTABLISHED.** A fresh-context verifier archived full
commit `8b9d8f97f0ec1237fe1fb2bc30339d1a32db1341` into
`lab/build/evidence/w-ruby-r5/tree`, compiled the archived `mtrace.c`, and used
the shared pinned prebuilt Ruby binaries/gems through `lab/build/plain` (it did
not rebuild Ruby). From that clean source tree it ran `witness-alpha`,
`witness-beta`, `witness-control` and `witness-fixed` sequentially. Alpha and
beta each returned HTTP 200 + `rce=OBSERVED`, created different empty marker
files and had exactly one independently scanned full-trace target pop; their
request commands and SHA-256 values differed while their malicious `_method`
payloads were identical. Control and fixed each returned HTTP 200 +
`rce=ABSENT`, with no marker and zero full-trace target pops. The fixed and
attack `_method` payloads were byte-identical. The witness also audited that
neither Ruby nor the shell/Python driver directly invokes `system`, spawn,
backticks, `FileUtils.touch` or marker-file writes, and that ASLR is enabled
(`/proc/sys/kernel/randomize_va_space=2`). Its machine-readable verdict and
per-run evidence index is
`lab/build/evidence/w-ruby-r5/tree/lab/build/evidence/witness-verification.json`.
No contradiction or code repair was found; its sole wording nit — distinguish
identical `_method` bytes from whole multipart bodies with unique marker paths
— is folded above. This establishes only the host/harness-specific claim, not
stock-application wire-only RCE.

Evidence is under gitignored `lab/build/evidence/rung5-http-<tag>.{out,trace,
server.log,marker}`. The driver exits nonzero unless the response, marker and
poisoned-pop conditions all match the mode, so a dead server cannot pass a
control merely by leaving the marker absent.

### Finalizer consumer and payload

`gc.c:1164-1215` reads an untyped data object's `DATA_PTR` at `RData+0x20`
and `dfree` at `+0x18`; nonzero `dfree` other than the immediate-free cases
reaches `rb_gc_impl_make_zombie`. `gc/default/default.c:2623-2641` preserves
those two fields in the zombie, and `run_final` at `:2900-2905` executes
`RZOMBIE(zombie)->dfree(RZOMBIE(zombie)->data)`. The five qwords forged at
the victim are:

```
+0x00  0x0c                 RUBY_T_DATA, typed_flag remains zero at +0x10
+0x08  live String class    RBasic.klass
+0x10  0                    untyped; no mark callback
+0x18  libc system address  dfree
+0x20  f_host address       data -> NUL-terminated request command
```

The victim is a 640-byte VWA slot formerly holding an embedded 615-byte
String. `ObjectSpace.dump` selects a measured contiguous downward triple and
reports its class. The poisoned target is the victim address aligned down to
16 bytes, so the forged object begins at payload offset 0 or 8. The lower
neighbor's last 16 bytes contain two `0x3f3` qwords; either alignment thus
presents `target-8 = 0x3f3`. With `IS_MMAPPED` set, glibc 2.39
`malloc_usable_size` (`malloc.c:5236-5247`) uses that qword without a
next-chunk read, satisfying CRuby's `objspace_malloc_fixup`. The upper
neighbor is overwritten as inert untyped `T_DATA` with `data=NULL`, allowing
the same GC sweep to free it without another call. The rest of each 640-byte
slot is payload padding, not additional object headers.

The first 0x3f0 pop returns T with its repaired `0x3f1` header. The second is
`$payload + ''`, forcing a fresh 1001-byte malloc and a 1000-byte chosen-byte
copy into the aligned VWA target. `$victims` is then cleared; `$ov`, `$z1` and
`$z2` stay live so their corrupted malloc chunks are not freed before the
finalizer. GC is re-enabled only at this point, and the harness checks the
marker after `GC.start`.

### Address provenance and exact conditions

- Source pins remain `ruby-3.4.12.tar.xz` SHA-256
  `db6c147940d7ad0b706823d42c8e6713c36dec70a1f83f635f1d3a7f0599ec90`
  and `ruby-3.4.13.tar.xz`
  `6474dff9c02ea685fc44877a4807a27366bf109b176dad182108bb8c96d09589`.
  Both plain builds use gcc 13.3.0, default CFLAGS/LDFLAGS and
  `./configure --disable-install-doc --prefix=<matching -plain prefix>`; no
  sanitizer, allocator tunable or ASLR disablement. The matching fixed build
  was made from the pinned tarball with `make -j2 && make install` into
  `lab/build/plain/ruby-3.4.13-plain`.
- Host allocator/libc is Ubuntu glibc `2.39-0ubuntu8.12`. `system` is libc
  offset `0x58750`, measured from the host symbol and confirmed by the execve
  trace. Ruby reads `/proc/self/maps` and adds that offset. V's buffer and
  f_host's command address come from the synthetic `mtrace.so` preload;
  safe-linking uses the observed T entry. VWA addresses and the class pointer
  come from `ObjectSpace.dump`. These are explicit in-process information
  capabilities, not wire-only disclosures. ASLR was enabled for every run;
  exploitability without these oracles remains UNKNOWN.
- Sinatra 4.2.2, Rack 3.2.8, rackup 2.3.1 and WEBrick 1.9.2 bind only
  `127.0.0.1:4549`. `Rack::MethodOverride` supplies the pre-route,
  pre-CSRF/auth ISO-8859-1 upcase. `GroomMiddleware` and `MarkerMiddleware`
  are lab code: they force multipart parsing, drain the five malloc classes,
  select the VWA triple, construct the fake object and invoke GC. The command
  is accepted only when it equals the authorized unique `touch` command.
  Request-shaped grooming on an unmodified application is not claimed.
- GC is disabled between the free sweep and forged-object copy, then enabled
  to reach the real finalizer. No debugger is involved in the final matrix or
  command execution. The affected process can abort with `corrupted size vs.
  prev_size` after the HTTP 200 and marker; persistence and clean survival
  remain unclaimed. The proof is per build and host layout, not a claim of
  stock Rails RCE or portability to other allocators.

Harness-development negatives are retained in the same evidence namespace:
the initial four-slot victim pool returned 500 before the trigger on 3.4.13
(`no contiguous victim triple`), so the committed harness measures twelve
slots on both versions; the first execve run hit the driver's former
10-second readiness timeout before WEBrick started, so the allowance is now
30 seconds. Neither is counted as an exploit success or a vulnerability
negative.

## Stock-application, oracle-free, persistent RCE attempt — bounded NEGATIVE (2026-11-22)

**Owner objective:** remove the custom groom/marker middleware and every
in-process address oracle, execute on an unmodified stock application, then
keep that process alive for a second command. Persistence here means a reusable
live process, not an OS backdoor or restart persistence. **This objective was
not achieved.** No stock command execution, remote address oracle, reliable
survival or second-request command is claimed. The witness-established
host/harness-specific rung-5 result above is unchanged.

### Unmodified baseline and controls

`lab/repro/ruby2shell-stock-baseline.ru` is classic Sinatra 4.2.2 with pinned
Rack/rackup/WEBrick gems but no routes and no application middleware; the only
settings are loopback bind/port 4550. Sinatra selects stock Puma 8.1.2.
`Rack::MethodOverride` handles the multipart `_method` before the default 404.
The driver runs the plain affected/fixed binaries with no `LD_PRELOAD`,
ObjectSpace, maps read or debugger. Optional mtrace/GDB scripts below are
analysis-only and are never part of an oracle-free claim.

```
RUBY2SHELL_STOCK_N=556 bash lab/repro/ruby2shell-stock-baseline.sh attack stock-n556-attack
RUBY2SHELL_STOCK_N=556 bash lab/repro/ruby2shell-stock-baseline.sh control stock-final-safe
RUBY2SHELL_STOCK_N=556 bash lab/repro/ruby2shell-stock-baseline.sh fixed stock-final-fixed
```

- N=828 attack: **3/3 pre-response SIGABRT** with `malloc(): invalid next size
  (unsorted)`; no later request is possible. Safe affected and fixed 3.4.13
  requests return 404 and survive.
- N=556 attack: **2/3 runs** return the attack 404 and a later GET 404, then
  print `corrupted size vs. prev_size` during SIGTERM teardown. The other **1/3**
  aborts before response with `malloc(): mismatching next->prev_size
  (unsorted)`. This is not reliable persistence. Final safe/fixed N=556
  controls both return both 404s and terminate normally on SIGTERM (rc 143).
- N=1292 and the tested expanding filler/order candidates all abort on
  unsorted next-header integrity checks. The different aborts are preserved in
  `lab/build/evidence/stock-baseline-*.server.log`.

### Size-field geometry and the N=556 fastbin boundary

For the 24-byte `mapping_buffer` header and `capa=N+20`, the OOB byte reaches
the next chunk's size qword only for **N ≡ 12 (mod 16)**. Other tested lengths
hit padding or `prev_size`; they were not treated as equivalent. Since the
byte is replaced, not ORed, masked-size growth after `0x53` requires original
low byte `01/11/21/31/41`; for example `0x31 → 0x53` grows `0x30 → 0x50`,
whereas `0x2f1 → 0x253` shrinks by `0xa0`.

`ruby2shell-stock-size.gdb` breaks before `case_map` with ASLR explicitly left
enabled and prints the untouched size, links and next header. The N=828 example
in `stock-first-attack-gdb.log` has untouched size `0x2f1`; after the write the
shortened `0x253` chunk leads malloc into a non-header. In contrast, the
post-result N=556 probe (`stock-after-n556-gdb-{2,3}.log`) shows size `0x53`.
The second qword after that chunk is not `tcache_key`, ruling out the observed
entry being a tcache member. It is a fastbin-class chunk. glibc's fastbin
consolidation requires the size's class to match the bin, so a `0x30 → 0x50`
class change is source-closed as an overlap route. The observed teardown error
is `corrupted size vs. prev_size`, **not** a demonstrated fastbin overlap or a
claimed direct observation of a fastbin-index abort.

Reproduction/analysis entry points:

```
gdb -q -batch -ex 'set $wanted=848' -x lab/repro/ruby2shell-stock-size.gdb \
  --args lab/build/plain/ruby-3.4.12-plain/bin/ruby lab/repro/ruby2shell-stock-baseline.ru
RUBY2SHELL_STOCK_N=556 RUBY2SHELL_STOCK_TRACE=1 \
  bash lab/repro/ruby2shell-stock-baseline.sh attack stock-n556-trace
gdb -q -batch -ex 'set $wanted=576' -x lab/repro/ruby2shell-stock-after.gdb \
  --args lab/build/plain/ruby-3.4.12-plain/bin/ruby lab/repro/ruby2shell-stock-baseline.ru
```

The driver accepts `RUBY2SHELL_STOCK_N`, `RUBY2SHELL_STOCK_FILL` and
`RUBY2SHELL_STOCK_ORDER=method-first|filler-first`; these change only wire
bytes. The mtrace N=556 sequence is request `0x258` (first buffer), `0x242`
(second), `0x458` (result), followed by the valid case-map frees and the stock
404. No allocation returns the corrupted neighbor before teardown.

### Unsorted expansion, primers and disclosure negatives

- ASLR-on size sweeps found expanding arena-linked candidates, including
  N=1292 shapes `0x441 → 0x453` and `0x421 → 0x453`. At the second allocation,
  however, the expanded next position contains Ruby internal data and invalid
  sizes (one measured example: `0xffffffff00000001`) rather than a valid fake
  chunk. Baseline requests abort; no header spray was claimed.
- Small/large filler lengths and filler-first ordering were swept. Some runs
  placed `_method` or filler bytes in the original next chunk, but not with a
  stable expanding size and valid expanded header. N=1292/fill=20 repeated
  probes produced differing `0x5e1`, `0x611`, `0x421`, `0x181` victims.
- Persistent GET warm-ups and safe multipart primers did not stabilize an
  expansion. Primed examples were all shrinking or invalid geometries
  (`0x2ed1`, `0x3051`, `0xe81`, `0x3081`, `0x6981`, `0xc71`). A spray requiring
  a fixed `prev_size` would therefore be guessing, not evidence.
- Sinatra development error pages were tested as a possible remote address
  channel. Empty multipart produces handled **400**
  `Rack::Multipart::EmptyContentError` with no object/address dump. Unknown
  charset falls back to `Encoding::BINARY` and returns 404, also with no debug
  environment or `Object#inspect` address. No stock exception that reflects
  native/heap addresses was found on this path.
- Public research check: Veria's page still schedules its stock-Rails PoC for
  **2026-11-25** and publishes no exploitation mechanics. This negative
  Sinatra/Puma investigation neither reproduces nor refutes that separate
  Rails claim.

**Boundary:** the existing RCE needs its custom layout and in-process oracles.
The tested stock requests do not supply a stable unsorted expansion with valid
attacker-controlled next headers, a usable fastbin/tcache overlap, a remote
address disclosure or reliable cleanup. Stock/oracle-free command execution
and a second persistent command remain UNKNOWN, not achieved. Reopen on the
published stock-Rails mechanics or a measured stock first-taker/disclosure and
survivable allocator layout.

### Stock Rails follow-up — true allocator split, rung 5 still blocked (2026-11-24)

`lab/repro/ruby2shell-stock-rails-setup.sh` generates an unmodified
`rails new --minimal` application (Rails 8.1.4.1, Puma 8.1.2, Rack 3.2.8), and
`RUBY2SHELL_STOCK_RAILS_FULL=1` generates a full `rails new` application (the
generated lockfile selected Rack 3.2.9). No route, controller, middleware,
ObjectSpace dump, maps read, debugger write or marker hook is added.
`lab/repro/ruby2shell-stock-rails.sh` launches the selected app on loopback and
uses only multipart bytes. Its default mode has no preload; the separate
`RUBY2SHELL_STOCK_CASE_PROBE=1` mode is analysis-only and is never an
oracle-free result.

Rails' development routing-error page reflects the original `_method` and other
multipart parameters through `PP.pp(filtered_parameters)`. With
`charset=ASCII-8BIT` on the non-method parts this is a valid escaped-string
response channel, not a native-address disclosure. It does not expose an
`RString` buffer pointer or a libc address.

#### Measured N=524 split and exact controls

The useful fixed body has 32 non-file parts of 1024 bytes, each filled with
little-endian `[prev_size=0x250, size=0x90]`, a 256-byte filler with the same
pair, and `_method = "a" + 0xDF*523`. The common environment is:

```
RUBY2SHELL_STOCK_N=524
RUBY2SHELL_STOCK_DRAIN=1024:32
RUBY2SHELL_STOCK_DRAIN_FAKE=1
RUBY2SHELL_STOCK_FILL=256
RUBY2SHELL_STOCK_FILL_PREV=0x250
RUBY2SHELL_STOCK_FILL_SIZE=0x90
RUBY2SHELL_STOCK_PART_CHARSET=1
```

For the trailing-byte experiment, `RUBY2SHELL_STOCK_TAIL_HEX=00005102` replaces
the last four `_method` bytes. Run `attack`, `control`, or `fixed` as the first
argument of `ruby2shell-stock-rails.sh` with those variables exported. The
fixed mode uses plain 3.4.13 with byte-identical malicious body bytes.

The analysis probe's most useful observation is preserved in
`lab/build/evidence/stock-rails-rails-stage2d-n524-r498.server.log`:

```
B ... size=0x201 ... next_prev=0x250 next_size=0x90
A ... size=0x253 ... next_prev=0x250 next_size=0x90
C ... request=0x222 ... size=0x235
V ... size=0x235 fd=0x20a bk=0x1f2 ... next_prev=0x20 next_size=0x90
```

This is a real `0x200 -> 0x250` expansion, not a flag-only `0x251 -> 0x253`
case. The second mapping-buffer allocation (`request=0x222`) returns V as a
`0x230` chunk. Its `capa=0x20a` and `used=0x1f2` are visible at the V free.
The mapping bytes therefore extend ten bytes into the original physical
remainder and replace its size low bytes with `0x251`. This is author-observed
stock-application allocator control, not a rung-5 result and not an independent
witness grade change.

A fixed-shape batch of 512 fresh processes with the four-byte tail recorded 16
valid expanded headers: ten `0x210`, three `0x250`, two `0x220`, and one
`0x200`; 47 total runs completed the attack and later health request. The only
`0x200` case above had no result-allocation return of the forged physical
chunk. The forged physical chunk remained unobserved by a useful consumer.
A separate seeded 512-layout N=524/572 search found zero `0x3f0` physical
neighbors (one valid `0x250` expansion with a different neighbor, 131 total
survivors). A full-default-Rails batch of 24 probes likewise found no `0x3f0`
consumer and produced eight non-expanding survivors. These are negative
results, not exploit successes.

The final uninstrumented matrix uses the exact N=524/tail body above:

- **3/3 affected attacks:** pre-response SIGABRT, HTTP 000, no later request.
- **3/3 safe affected controls:** attack-shaped multipart bytes except pure
  `0xDF` `_method`, HTTP 404 plus later `/up` HTTP 200, clean SIGTERM.
- **3/3 fixed 3.4.13 controls with identical malicious bytes:** HTTP 404 plus
  later `/up` HTTP 200, clean SIGTERM.

Evidence is `lab/build/evidence/stock-rails-rails-final-{attack,safe,fixed}-*`.
There is no command marker, target `execve`, address oracle, exploited surviving
process or second command to test. The true split does not supply the Stage-C
`0x3f0` tcache neighbor needed by the existing finalizer chain, and blind
safe-link partial overwrites do not replace it: `REVEAL_PTR` needs the heap page
mask, and a copied mask only retargets a same-page legitimate successor.

**Rung-5 boundary:** stock/oracle-free/persistent RCE remains **NOT ACHIEVED**.
The new result is a measured stock allocator split and a clean negative control
matrix, not RCE. Reopen on Veria's published stock-Rails mechanics (still
unpublished at 2026-11-24T04:11Z) or a measured pointer-bearing `0x3f0`
physical consumer followed by a wire-visible disclosure and a second command.

### Consumer-visibility correction — the forged qword is structurally inert (2026-11-25)

The committed case probe's consumer check (`p == case_physical`) compared a
malloc **user pointer** against the forged **chunk-start** address, so a P
line could never fire for a real chunk allocation: the 2026-11-24 "no
result-allocation return of the forged physical chunk" was measured with a
structurally blind instrument. `lab/preload/mtrace.c` now tracks the forged
window `[case_physical+0x10, +0x78)` instead: `G` lines dump eight window
qwords at every B/A/V snapshot, `P` lines print any malloc return inside the
window (headers read via `process_vm_readv`, so a bad header cannot crash
the tracer), and `Q` lines print any free of a window user pointer BEFORE
`__libc_free`, so an aborting free still records the header it saw.
Committed tabulator: `lab/repro/ruby2shell-cons-vis-tabulate.py`.

Batch: 49 fresh processes, the 2026-11-24 N=524 environment plus
`RUBY2SHELL_STOCK_CASE_PROBE=1`, 6-way parallel on ports 4560–4565.
Representative evidence `lab/build/evidence/stock-rails-cons-vis-*.server.log`
(gitignored bulk). Observed:

- 5/49 runs complete the attack and survive. Victim geometries vary per
  boot (B size fields from `0x81` to `0xb51`); the expansion class
  (`B=0x231 → 0x250`) recurred twice (runs 4 and 11, alive, both WITHOUT
  the second mapping buffer returning at the victim). The r498 shape
  (B=0x201, C consumption, tail qword) did not recur in 49 runs.
- **Zero Q lines in 49 runs:** no free of any window user pointer happens on
  the request thread. The real neighbor's corrupted header is never
  validated, and the tail-forged `0x251` qword — which lands at
  `case_physical+0x18`, the live neighbor's second user qword, not at any
  chunk-header position malloc can walk — forms a pseudo-chunk at
  `case_physical+0x10` whose user pointer (`+0x20`) nothing ever frees, so
  no free list can ever contain it. In the tested geometry the forged qword
  is structurally inert, not merely unobserved. The 11-24 negative stands,
  now with a corrected instrument.
- **New measured consumer fact:** post-attack request-thread allocations
  return at the victim: run 12 (`B=0x251`, alive) and run 34 (`B=0xb51`,
  alive) print `C request=0x21c`/`0x1f8` pops at the victim user pointer,
  matching the preserved `stock-rails-rails-stage2d-n524-r498.server.log`;
  run 34 additionally carves three `0x20` chunks (`P request=0x10/0x18/0x10`)
  from the real remainder beyond the fake next position. In an expansion
  geometry such consumers' write spans cover the live neighbor. The next
  named experiment is the content provenance of the `0x21c`/`0x1f8`
  consumers: attacker-derived bytes would make this a request-shaped
  Stage-B analog on the unmodified app.

Boundary unchanged: no command, no disclosure, no persistence;
stock/oracle-free/persistent RCE remains NOT ACHIEVED. Veria's page was
re-checked on the 2026-11-25 dated trigger (twice this wake): stamp still
"Updated 21 November 2026 at 03:52 UTC", PoC still scheduled and
unpublished; the day's secondary coverage adds no mechanics.

Reproduce (single probe run, then tabulate):

```
RUBY2SHELL_STOCK_N=524 RUBY2SHELL_STOCK_DRAIN=1024:32 \
RUBY2SHELL_STOCK_DRAIN_FAKE=1 RUBY2SHELL_STOCK_FILL=256 \
RUBY2SHELL_STOCK_FILL_PREV=0x250 RUBY2SHELL_STOCK_FILL_SIZE=0x90 \
RUBY2SHELL_STOCK_PART_CHARSET=1 RUBY2SHELL_STOCK_TAIL_HEX=00005102 \
RUBY2SHELL_STOCK_CASE_PROBE=1 \
bash lab/repro/ruby2shell-stock-rails.sh attack cons-vis-1
python3 lab/repro/ruby2shell-cons-vis-tabulate.py
```

The batch loop ran the same environment 48 more times via
`xargs -P6` with `RUBY2SHELL_STOCK_PORT=$((4560 + i % 6))` and tags
`cons-vis-<i>`.
### Victim-region consumer provenance — the 0x21c/0x1f8 pops are fixed-size,
### not wire-shaped (2026-11-25)

This wake closed the 11-25 named experiment. `lab/preload/mtrace.c` gained
an `H` line (victim-chunk content qwords at every free of the victim) and an
optional stop-at-pop mode (`MTRACE_CASE_STOP_C`, optionally gated by
`MTRACE_CASE_STOP_REQ=0x21c,0x1f8` — synchronous `raise(SIGTRAP)`). A
separate return-address-logging build (`lab/preload/mtrace-ra.c`,
`ra=` chains plus a raw-syscall `/proc/self/maps` dump, resolver
`lab/repro/ruby2shell-cons-ra-resolve.py`) identified one window consumer
directly: the 0x4e6 window pop of run consJ-29 resolves into
`ld-linux-x86-64.so.2` — a lazy `dlopen` allocation (libcrypt loading during
the request), C-internal content. The `ruby2shell-stock-rails.sh` driver
gained a `RUBY2SHELL_STOCK_EXTRA_HEADER` wire knob for the shaping test.

**Shaping result: the 0x21c/0x1f8 consumers are not attacker-shaped.** With
the exact 11-24/25 N=524/tail environment and the geometry-preserving mtrace
build, batches varying ONLY wire bytes — an attacker header padded to
L=0/60/120/240 bytes (10 runs each) and the route path lengthened by
100/300 bytes (10 runs each) — produced ten surviving runs with the
post-attack pops, and every one printed exactly `C request=0x21c` then
`C request=0x1f8` at the victim user pointer (e.g. runs
`stock-rails-consM-h{0,60,120,240}-*`, `stock-rails-consR-p{100,300}-*`,
gitignored bulk). Fixed sizes invariant under header and route shaping mean
the two consumers are framework-internal fixed-size allocations —
**C-internal content, allocator mechanics**, not a request-shaped Stage-B
analog on the unmodified app. The exact Ruby call sites remain UNKNOWN: the
RA/gdb instruments cannot run in the producing geometry (see the coupling
finding below), so no call-site claim is made. In the surviving samples the
0x21c consumer frees the victim off the request thread (no H at its free) and
the chunk returns with size LSB `0x05` at the 0x1f8 pop.

**Measured structure facts around the split (analysis-only probe runs,
author-observed):**

- The unsorted-split overlap survives end to end in the wild: run
  `stock-rails-consH-20` (B `0x221`→A `0x253`, real 0x220 victim in
  unsorted, forged 0x250-class) split the forged size, carved a fake 0x20
  remainder chunk 0x10 into the neighbor region, and real request-thread
  allocations (`P request=0x3`, then `0x10`) occupied the fake chunk, with
  one freed ON the request thread (`Q`). The 11-25 "Q=0/49" is
  geometry-specific, not structural. The run completed 404 + later `/up`
  200 and tore down gracefully. The planted `[0x250,0x90]` pattern at the
  fake-next position is what let the split pass its checks.
- In other geometries the upcase RESULT STRING (request `0x414`, nb 0x420)
  itself pops the victim from unsorted and splits it: gdb catch
  `consC-gdbF-5` printed `C request=0x414 ptr=<victim> size=0x425` in a
  B=0x451 unsorted geometry. Engineering note: the SIGSTOP used there
  engages asynchronously, so stop-time backtraces are late snapshots — the
  trapped thread had already unwound into RoutingError handling
  (`RUBY_TAG_RAISE` through `rb_ary_collect`), consistent with the
  delivered 404.
- The development routing-error page reflects every multipart parameter
  verbatim (`PP.pp(filtered_parameters)`; measured 169434-byte response,
  128530-byte params block). In the one surviving expansion sample whose
  response was parsed, all 32 drain values were byte-clean: the carve did
  not land inside a reflected string. The reflection channel exists, but
  no forged region has been observed inside a reflected value.

**Instrument-coupling caution (measured):** the recycled-chunk identity is
hypersensitive to the preload's mapped page span. The 4-page mtrace builds
reproduce the surviving target class (~10% of runs, e.g. consH 5/60
0x21c-runs; consM/consR batches above); the 6-page RA build eliminated it
(0/124 runs, `consJ`/`consK`). Any instrument that grows `mtrace.so` across
a page boundary invalidates prior geometry statistics — future stock sweeps
must pin the preload span. Environment-string padding is NOT a geometry
knob (env strings live on the stack; 0/64 padded runs moved nothing).

External re-check at the dated 2026-11-25 trigger: Veria's page stamp is
unchanged since 21 Nov 03:52Z and the PoC remains unpublished; the day's
public GitHub "PoC" repos (evenomn, googlesky, hackpatato) contain only
crash/sanitizer-level reproductions — evenomn's glibc-effective one-byte
size-LSB corruption (glibc 2.31, no-ASLR, local-only) matches this report's
Stage A mechanics and adds no remote path. Nothing to reopen on.

Boundary unchanged: no command, no disclosure, no persistence;
stock/oracle-free/persistent RCE remains **NOT ACHIEVED**. The strongest
new lever is the surviving unsorted-split overlap: the named next
experiment is shaping the carve position (via `RUBY2SHELL_STOCK_N` and the
drain part sizes, which move the split remainder) so the fake chunk lands
inside a REFLECTED drain-string body — that would make both the allocator
metadata (tcache pointers) and any chosen overlay bytes wire-visible in
the error page — the missing oracle-free disclosure + readback channel.

First sampling pass of the carve-landing experiment (same day): a
60-run shaped sweep over the carve-position knobs — `N` ∈ {508, 524, 556}
and drain part sizes 1024/1152/1280 bytes ×32 parts (five arms, tags
`stock-rails-consS-n*-*`, gitignored bulk) — produced 11 surviving runs
and 22 runs with post-attack victim pops, and a byte-exact parse of every
surviving response found **zero** reflected-value corruption: the split
remainder did not land inside any reflected drain string in the sampled
space. Together with the 14 earlier surviving responses (all clean), the
reflection channel remains unproven as an oracle; landing it needs
additional geometry knobs (drain part count, filler shape, part order) or
the forged region's position to move relative to the reflected chunks.
Preserved as a negative result, not retried into existence.

### Wire-shaped victim grooming — bounded NEGATIVE, six measured blockers
### (2026-11-25, later the same day)

A reflected-region landing needs the upcase's first case buffer to pop a
FREE chunk directly below a LIVE, wire-chosen request string (the error page
reflects params verbatim, so a forged or split region inside such a string
is wire-visible). Every measured route to that arrangement is closed:

1. **The victim is boot-recycled; parse shaping cannot move it.** The
   armed-emit trace (`stock-rails-diag1.server.log`) shows the attack's
   first case buffer popping a chunk with no in-window allocation history
   (boot-era), its neighbor a C-internal 0x20 churn site. Sweeps over
   attack size (N=1004 aligned to nb 0x420, the drain part class; tags
   `consU-*`) and drain part counts 32–126 (tags `consV-*`) produced 74
   B-lines and zero live-drain-string victims (0x421-class with the
   planted window). N=1024 (misaligned, N≢12 mod 16) lands the byte off
   the size field entirely — B reads garbage (tags `consT-*`) —
   reconfirming the alignment law.
2. **No in-request parse frees.** Rack 3.2.8's parser allocates TWO
   live 0x409-class buffers per 1024-byte part (`on_mime_body`'s content
   slice plus the growing body; 65 allocations for 32 parts, some
   adjacent live pairs measured). An armed-emit trace at 112 parts shows
   225 pre-upcase 0x409-class allocations and **zero frees** before the
   upcase (`stock-rails-diag2.server.log`): the slice-strings become
   garbage but no GC pass runs during parse.
3. **Cross-request string plants do not transfer.** Benign multipart
   primers (4–6 pattern parts, no `_method`) before the attack never
   changed the pop: 24 grid runs (`tw-*` logs) all popped boot-unsorted
   chunks — Ruby GC frees the primer's strings only after the attack's
   upcase window.
4. **Puma's thread pool splits the tcaches.** In every paired run the
   primer and the attack were served by different worker threads
   (different tids on the probe lines) — per-thread tcaches make plants
   non-transferable, and the primer's own error-page render allocates
   1048-class buffers (three armed 1048-pops per primer, measured) that
   consume any same-thread plant immediately.
5. **The deterministic casemap plant reaches the attack's region but
   not a live neighbor.** A primer whose `_method` is pure `ß`×1004 (same
   geometry, no corruption) deterministically frees its first (nb 0x420)
   and second (nb 0x410) case buffers mid-request. The following attack
   still overflowed a boot-region chunk — a real `0x4f0 → 0x4f50`
   expansion, abort (`tw4-*`: victim `0x4f01 → 0x4f53`) — proving the
   attack's pop reaches primer-influenced memory, but the
   `[free pop][live reflected neighbor]` arrangement was never observed.
6. **Monotone-consumption frontier.** Within one request the upcase's
   pop is the first free chunk past the live parse frontier, so the chunk
   after the pop is free by construction; an in-request free is needed to
   break this, and (2) shows none exists pre-upcase.

Remaining unexplored (named for the next wake): a stock route that runs
`Rack::MethodOverride` without the debug-page render (not present in
`rails new --minimal`), same-thread request pacing (not wire-exposed on
stock Puma), and Veria's unpublished PoC mechanics. Boundary unchanged:
no command, no disclosure, no persistence; stock/oracle-free/persistent
RCE remains **NOT ACHIEVED**.
## Stock Sinatra 500-page address oracle — measured, insufficient (2026-11-25, third push)

New claim, measured this wake: a stock Sinatra 4.2.2 development 500 page
discloses Ruby **GC-heap object addresses** without `ObjectSpace.dump`,
`/proc/self/maps`, mtrace, a preload or a debugger. Cause is framework code,
not app code: `sinatra-4.2.2/lib/sinatra/show_exceptions.rb:347-350` renders
every Rack env value with `val` (`Object#to_s`), and
`rack-3.2.8/lib/rack/show_exceptions.rb:389-392` renders them with
`val.inspect`; non-string env objects therefore print their default
`#<Class:0x...>` identity. Prior stock work tested only the **handled**
empty-multipart 400 and unknown-charset 404 paths, so this data class had
not been measured.

Repro (analysis-only, committed): `bash
lab/repro/ruby2shell-errorpage-oracle.sh 4611 verify-oracle-1`. The app is
one plain classic-Sinatra route (`get('/x') { params.fetch('required') }`)
with no groom/marker middleware and no exploit code; the script's post-response
`/proc/PID/maps` read only classifies the leaked values and feeds nothing.
Observed: three HTTP 500 responses of ~141,682 bytes, each with **20 distinct
`0x...` tokens**. Twelve are boot-stable across three requests in one
process (`puma.config`, `rack.logger`, `rack.errors`, two request Procs);
eight are request-scoped (`rack.input` `#<StringIO:0x...>`,
`sinatra.accept` `#<Sinatra::Request::AcceptEntry:0x...>`, and two
Puma response Procs). Fresh-process comparison of the sorted address sets
showed **zero low-12-bit overlap**, so page offsets are not portable across
processes.

Classification against the live `/proc/PID/maps` snapshot: **20/20** leaked
addresses fall in `[anon:Ruby:GC:default:heap_page_body_allocate]`;
**zero** in glibc `[heap]`, **zero** in libc and **zero** in the Ruby text
mapping. Ruby is PIE (`Type: DYN`; `system@plt` at `0x37650`, only a relative
offset), so a GC pointer does not yield a code base either.

Wire reachability is narrower than the page's existence: eight malformed
wire-only requests against a truly route-less stock classic Sinatra app
(NUL `X-HTTP-Method-Override`, invalid `%-` path, missing multipart
boundary, bad base64 transfer-encoding, NUL form value, 8 KB header, bad
`Accept` q-value, unknown multipart charset) **all returned 404 with no
address tokens**. The oracle needs an app-level exception; a bare app does
not provide one. The stock Rails dev error page is also closed as a channel:
`lab/build/evidence/stock-rails-consH-20.html` (169,434 bytes) contains
**zero** `0x...` tokens — Rails filters the env dump.

**Boundary — no grade change.** This oracle can substitute for
`ObjectSpace.dump` when discovering GC-heap VWA slots, but the harness chain
still needs two oracles it does not supply: glibc-heap chunk addresses
(mtrace `M … 419` / `M … fa1` lines, for the tcache safe-linking key and the
command-string address) and libc base (`/proc/self/maps`, for
`system`). It therefore does not unlock stock/oracle-free/persistent rung 5,
which remains **NOT ACHIEVED**. The harness-condition witness-ESTABLISHED
rung 5 was re-smoked this wake: attack `rce=OBSERVED` + target-created
marker + one poisoned target pop; safe affected input and the identical
malicious `_method` on fixed 3.4.13 both `rce=ABSENT`, no marker, no pop.

Disclosure landscape at the dated trigger (checked 2026-11-25): Veria's
page still carries `dateModified 2026-11-21T03:52Z` and still says the PoC
will be published "on 25 November 2026, or later"; Moritz Sanft's
`durendal.sh/blog/ruby-case-mapping-bugs` confirms pre-auth RCE on a plain
`rails new` app (first with jemalloc, then glibc) but publishes **no
mechanics**; the three fetched public PoC repos are sanitizer/crash-level
only. No external mechanics were adopted as fact.

Persistence was also measured directly on the harness chain this wake: a
single-process run that kept the WEBrick server alive after the successful
attack (`rce=OBSERVED`, marker created, HTTP 200) could not serve a later
`GET /health` or a second `POST /trigger` — both returned `HTTP 000` while
the process was still in teardown, and the server log ended with
`corrupted size vs. prev_size`. This confirms the reported post-response
abort boundary with bytes: the harness rung-5 command executes, but the
exploited process does not remain usable for a second command.

## Keep-alive same-thread pairing — measured, closed at the Rails configuration (2026-11-25)

The last named lead for cross-request heap plants was HTTP keep-alive as a
wire-only way to keep a primer and the attack on one Puma worker thread,
thereby sharing a per-thread tcache. New analysis-only repro
`lab/repro/ruby2shell-keepalive-thread.sh [port] [tag]` measures this directly:
a stock classic-Sinatra route echoes `Thread.current.object_id`; three arms
send five GETs on one connection (`num_connects=1,0,0,0,0` proves reuse), five
GETs on separate connections, and two concurrent connections. The optional
`KA_THREADS=3:3` launcher runs the same app under the fixed thread pool used
by the earlier Rails paired runs. No groom, marker, ObjectSpace, mtrace, maps
or debugger is in the request path.

**Default pool (Puma `min=0/max=5`), 3/3 fresh processes:** arm A returned one
thread id for all five requests (`344`), arm B also returned `344` for all
five separate connections, arm C split (`344` plus a second id). This shows the
earlier "different threads on every paired run" observation is not universal,
but it is a property of the pool configuration, not a usable opening.

**Fixed pool (Puma `min=3/max=3`, the `rails new`-relevant shape), 3/3 fresh
processes:** arm A rotated `704, 728, 688, 704, 728` (runs 1–2) and
`712, 736, 736, 688, 712` (run 3) despite confirmed connection reuse; arm B
rotated similarly; arm C used two distinct threads. The earlier paired-run
evidence corroborates this shape: `stock-rails-tw4-1.server.log` shows the
primer's B lines at `tid=3823467` and the attack's B/A lines at
`tid=3823468`, with Puma `Min threads: 3`.

**Boundary — no grade change.** Keep-alive does not pin worker threads on the
configuration that matters, so the per-thread-tcache blocker #4 stands. Even
where a thread is shared (default pool), blockers #2 and #3 still apply: the
Rack parser performs no frees during parse, and GC frees primer strings only
after the attack's upcase window. No cross-request plant transfer is measured.
Stock/oracle-free/persistent rung 5 remains **NOT ACHIEVED**.

## Metadata-repair persistence attempt plus wire-oracle survey — two bounded NEGATIVEs (2026-11-25, direct-session push)

Owner asked again for full rung-5 (wire-only, unmodified app, no oracles,
second distinct command). Two named leads were executed; both are bounded
negatives. No grade or label changes.

**A. Restoring T's malloc header does not restore persistence.** The abort
signature was isolated first: every affected run ends with
`F <heap_base+0x1980> 2015` in the mtrace trace immediately after
`corrupted size vs. prev_size` in the server log
(`lab/build/evidence/rung5-http-survive-1.trace:1805655`,
`rung5-http-repair-base-3.server.log`). The harness forges T's malloc header
from `$ov[1056,16]`, replacing T's measured size field `0x405` with `0x3f1`;
the new instrumentation logs `T-hdr-prev=0x0 size=0x405` before poisoning.
A repair path gated on `RUBY2SHELL_R5_REPAIR=1` captures T's original qwords
while T is live, then restores them and zeroes T's tcache `next` plus the
forged object's `dfree`, using `/proc/self/mem` `pread`/`pwrite` (Fiddle is
absent from the pinned plain build). `ruby2shell-rung5-http.sh survive` issues
a first POST with marker1, `GET /health`, and a second POST with a distinct
marker2; it requires one unchanged PID, two `rce=OBSERVED` responses, two
markers and no abort line. Observed (`survive-1`): HTTP 200 and `rce=OBSERVED`
with marker1, `repair=T-header-restored dfree-cleared` in the server log, then
both follow-up requests `HTTP 000`, the process aborted with
`corrupted size vs. prev_size`, and marker2 absent. Header restoration is
therefore necessary but not sufficient — the fatal free is a boot-time
0x2010-class chunk at heap offset 0x1980, downstream of the poisoned state,
not T itself. A gdb diagnosis is preserved as a tooling negative: Ruby's
`IO.for_fd` rejects the fd gdb leaves open ("The given fd is not accessible
because RubyVM reserves it"); with `ptrace_scope=1` gdb must launch the
inferior, whose fd-2 mtrace stream then overwhelms the captured log. No
second command was executed; persistence remains NOT ACHIEVED at harness
scope.

**B. No wire-only glibc-heap or libc-base oracle exists on the default
stacks.** A read-only survey of the pinned Sinatra 4.2.2 / Rack 3.2.8-3.2.9 /
WEBrick 1.9.2 / Puma 8.1.2 / Rails 8.1.4.1 stacks checked the remaining
default surfaces: `Object#to_s`/`inspect` pointer rendering
(`object.c:727-736`, reachable only on the already-measured Sinatra dev 500
page), `rb_gc_impl_object_id` monotonic-counter semantics
(`gc/default/default.c:1586-1615`), `IO#inspect` (`io.c:3058-3083`),
IPSocket/Tempfile inspect, Rack `ShowExceptions` env and param rendering,
Rails `DebugView` filtered env, `Rack::MethodOverride`'s static rescue, and
Puma's static malformed-request responses. The only address class any default
surface emits is Ruby GC-anon `VALUE` pointers; no glibc `[heap]` chunk
address, libc/Ruby code base or stack address is exposed. The labelled gap
stays closed: the harness needs mtrace for glibc-heap addresses and
`/proc/self/maps` for libc base, with no wire-only substitute on an unmodified
app. Veria's advisory was re-fetched at the dated 25 Nov trigger:
`dateModified` is still `2026-11-21T03:52Z` and the PoC section still promises
publication "on 25 November 2026, or later"; no external mechanics were
adopted.

The harness-condition matrix was re-verified after instrumentation: `attack`
PASS (HTTP 200, `rce=OBSERVED`, unique marker, one target pop), `control`
PASS (safe `0xDF` input: `rce=ABSENT`, no marker/pop) and `fixed` PASS
(identical malicious `_method` on plain 3.4.13: `rce=ABSENT`, no marker/pop).
Stock/oracle-free/persistent rung 5 stays NOT ACHIEVED.

### consH-20 low-byte tcache retarget — bounded NEGATIVE (2026-11-25)

Named lead: the surviving consH-20 class carves a fake `0x20` chunk into the
neighbor region; could the single `0x53` overflow byte overwrite that fake
chunk's tcache `next` low byte and redirect a real request-thread allocation
into a chosen nearby region, without an absolute address oracle? The
`lab/preload/mtrace.so` case probe answers this directly: `P` lines print any
malloc return inside the forged window `[physical+0x10, +0x78)` (headers read
with `process_vm_readv`, so a bad header cannot crash the tracer), `Q` lines
print any free of a window user pointer *before* `__libc_free`, `H` lines dump
victim content at free, and `G` lines dump eight window qwords at every
snapshot.

Batch: **144 fresh processes** on the unmodified `rails new --minimal` app with
the documented N=524 / 32×1024-byte `/ [prev_size=0x250, size=0x90]`
geometry — 24 runs without the four-byte tail and 120 with
`RUBY2SHELL_STOCK_TAIL_HEX=00005102`, 6-way parallel on ports 4560–4565.
Totals from `ruby2shell-cons-vis-tabulate.py`: 11 survivors (404 + later
`/up` 200 + graceful teardown), 52 real expansions, 30 runs with a second
buffer consumption at the victim, **one run with a window `P` and one with a
window `Q`**, 23 with victim-content `H` lines. The tail qword was never
observed at window q38: `q38=0x251` in 0/144 runs; that qword stayed the drain
pattern `0x90`.

The single window-consuming survivor (`stock-rails-consH20-tail-79.server.log`,
gitignored bulk) is the historical consH-20 shape:

```
B ... size=0x201 ... next_prev=0x250 next_size=0x90 physical=...b000
A ... size=0x253 ... physical=...b050 physical_prev=0x250 physical_size=0x90
C request=0x222 ptr=<victim> size=0x235
H ... q0=0x20a q8=0x1f2 q10=0 q18=0x5353535353535353 ... q38=0x5353535353535353
P request=0x3  ptr=...b040 size=0x25
Q          ptr=...b040 size=0x25 fd=0 bk=0
P request=0x10 ptr=...b040 size=0x25
P request=0x28 ptr=...b010 size=0x35
```

This is the second predicted branch, not the first. The overflow byte lands on
the **victim size field** (`0x201` → `0x253`), not on the fake `0x20` chunk's
tcache `next`; the forged window recycles three tiny C-internal allocations
(requests `0x3`, `0x10`, `0x28` bytes) and one is freed on the request thread.
Their content is not attacker-shaped: the only wire-derived bytes at the
victim are the fixed `0x53` upcase byte (`q18`–`q38` all `0x5353…`), and the
victim header `q0/q8 = 0x20a/0x1f2` is the mapping-buffer `capa/used`. No
steered allocation carrying attacker-chosen bytes was observed, so no
oracle-free Stage-B analog exists on this stock app. Rung 4 and the labelled
harness-condition rung 5 are unchanged; stock/oracle-free/persistent rung 5
remains **NOT ACHIEVED**. The rare survivor is preserved as a measured positive
for allocator control, not upgraded.

Reproduce (analysis-only, loopback; new committed driver, 24 runs by default):

```
bash lab/repro/ruby2shell-consH20-retarget.sh
# equivalent single probe, then tabulate:
RUBY2SHELL_STOCK_CASE_PROBE=1 RUBY2SHELL_STOCK_N=524 \
RUBY2SHELL_STOCK_DRAIN=1024:32 RUBY2SHELL_STOCK_DRAIN_FAKE=1 \
RUBY2SHELL_STOCK_FILL=256 RUBY2SHELL_STOCK_FILL_PREV=0x250 \
RUBY2SHELL_STOCK_FILL_SIZE=0x90 RUBY2SHELL_STOCK_PART_CHARSET=1 \
RUBY2SHELL_STOCK_TAIL_HEX=00005102 \
bash lab/repro/ruby2shell-stock-rails.sh attack consH20-tail-79
python3 lab/repro/ruby2shell-cons-vis-tabulate.py consH20-tail
```

The driver was smoke-tested (`RUBY2SHELL_RETARGET_COUNT=2
RUBY2SHELL_RETARGET_TAIL=0`); `xargs` exit 123 from pre-response SIGABRTs is
expected and recorded, not a driver failure.

### Wire-only heap disclosure through the 404 params reflection — measured, live-classified (2026-11-25, direct-session push)

The owner asked again for full rung-5. The named next experiment was executed
first: with the two untried knobs (drain part count 48 and
`RUBY2SHELL_STOCK_ORDER=filler-first`), the attack aborts pre-response in
**6/6 fresh processes** — `Fatal glibc error: malloc.c:2599 (sysmalloc):
assertion failed …` (tags `stock-rails-consH20-reflect-*`). At 48×1024-byte
drain parts the first case buffer no longer pops the boot-recycled
0x240-class chunk; it carves the top chunk and the 0x53 byte lands on the
top size field. The count knob overshoots the surviving class, so the named
arm is a bounded negative.

The reflection channel was then measured directly with a new committed
byte-scanner, `lab/repro/ruby2shell-reflect-scan.py`, which unescapes the
dev routing-error page's `PP.pp(filtered_parameters)` block and byte-diffs
every reflected multipart value against the request body. Bulk-scanning all
492 saved stock-Rails 404 responses (416 parameter-bearing) found **20 files
whose reflected drain bodies carry raw pointer-shaped qwords** — including
17% (8/47) of the surviving stage2d responses, arms that had previously been
mtrace-tabulated but never byte-parsed. The corruption signature inside a hit
value (parts d8/d11/d13/f) is post-parse allocator/Ruby metadata, e.g.
`[0x77441, 0x25, PTR, 0x100000001, 0x20, 0x91, <pattern>]`: a fake 0x20
chunk size (0x25), the PREV_INUSE'd 0x90 pattern qword (0x91), and one or
two pointers eight bytes apart. The writer is a bin insertion whose chunk
overlaps the live reflected drain string — glibc performing a free whose
range covers live wire-chosen data, the arrangement the six wire-shaped
grooming blockers hunted, observed here in the surviving class.

Live classification used a second new committed pair:
`lab/repro/ruby2shell-stock-leakclass.sh` replays the exact consH20-tail
wire body (the saved `stock-rails-rails-stage2d-n524-r238.body`) against a
fresh unmodified `rails new --minimal` process per run and snapshots
`/proc/PID/maps` from outside the request path whenever the process is
still alive after the 404 response; `lab/repro/ruby2shell-leak-maps.py`
classifies every reflected pointer against that snapshot. 266 runs were
launched 6-way on loopback (the final wave truncated by a harness
timeout); 25–26 surviving responses carried maps snapshots, and one live
leak instance landed:

- **The request-thread glibc arena region base leaks wire-only.** The
  mtrace B lines put the attack victim in an unlabeled anon mapping — a
  Puma worker thread's glibc arena whose unsorted-bin head is in-region
  (`fd=0x…000090 bk=0x…000090`, i.e. region+0x90) — and the reflected
  pair partner is an in-region pointer at one of three near-constant
  offsets: region+0x8c660 (×5), region+0x8c760 (×5), region+0x8cdb0 (×1)
  across the 11 consH/stage2d instances (13 PTR_B values total including
  the fuzz-geometry variant +0x4d1f0), same region prefix as the victim
  in 11/11. One leaked value therefore pins the arena region base —
  the tcache safe-link key and any in-arena target address become
  wire-known. This is the first missing oracle of the harness chain,
  now measured wire-only on the unmodified app.
- **A Ruby GC-page pointer leaks wire-only.** The live instance
  (`stock-rails-lc-lc-75.html`, `.maps`) resolves to
  `[anon:Ruby:GC:default:heap_page_body_allocate] +0x43a6c8` — the other
  pointer class is GC-page addresses, which can substitute
  `ObjectSpace.dump` as a GC-heap discovery mechanism.
- **No libc pointer class exists in this channel.** The corrupted chunks
  live in the worker-thread arena; its bin heads are in-region, not in
  libc's `main_arena`, so unsorted/smallbin fd/bk can structurally never
  leak libc through this route. Across the 416 parameter-bearing
  historical responses plus the live survivors, zero libc, ruby-binary
  or code pointers were reflected. The harness's `system` finalizer
  therefore stays oracle-blocked on a stock app.
- **No attacker-chosen upcase bytes ever reach a reflected body**: a
  byte-exact scan of all 432 historical parameter-bearing values found
  zero `0x53`-run deviations — the reflected corruption is exclusively
  allocator/Ruby metadata, not a wire-shaped Stage-B analog.
- **A second attack request on a leak survivor aborts 3/3** (live batch
  wave-1, `h2=000`), so leak-then-attack chaining on one process is
  blocked at this geometry, corroborating the persistence blocker.

Boundary: this is new rung-4-class disclosure evidence — wire-only
information disclosure of arena-region and GC-page addresses on the
unmodified production stack, ~13% of surviving responses (9/72 across the
historical stage2d survivors and the live batch). No command, no libc
oracle, no attacker-chosen write and no persistence exist; stock/oracle-
free/persistent rung 5 remains **NOT ACHIEVED**. Veria's page was
re-checked at the dated trigger (stamp still 2026-11-21T03:52Z, PoC
unpublished) and durendal.sh still publishes no mechanics; nothing
external was adopted as fact.

### Main-arena libc-oracle lead — bounded NEGATIVE (2026-11-25, this wake)

Item 10 named main-thread-arena geometry as the first lead for the missing
libc/code-base oracle. New driver `lab/repro/ruby2shell-mainarena-leak.sh`
replays the saved consH20-tail wire body against a fresh unmodified
`rails new --minimal` process per run with `MALLOC_ARENA_MAX=1` (lab-only
environment tuning, not an app edit), snapshots `/proc/PID/maps` outside the
request path for survivors, and classifies reflected params with the
committed scanner/classifier pair. Loopback only; analysis only.

- **Arm A (saved N=524 body, 12 fresh processes):** 4 survivors returned 404
  with maps; every victim sat in `[heap]` (4/4), i.e. the main arena rather
  than a Puma worker arena. Two victims carried
  `fd=bk=0x79d399204b20` / `0x7d9644404b20`; both map to
  `/usr/lib/x86_64-linux-gnu/libc.so.6` at file offset `0x203000`
  (`libc+0x203b20`). So a genuine libc pointer does exist in the victim's
  metadata under this geometry. It never crosses into the wire: all four
  responses were byte-clean (136 reflected parts, zero deviations, zero
  pointer-shaped qwords), and `ruby2shell-leak-maps.py` reported
  `with-leaks=0`.
- **Arm B (N=532, otherwise identical 32x1024 pattern-drain/filler geometry
  and `00005102` tail, 12 fresh processes):** 12/12 survived with maps, all
  victims again in `[heap]`, 408 reflected parts byte-clean, zero pointers.
  The +8 shift moved the request's chunk size (`first_request=0x238` →
  `0x240`), not the write offset: mtrace still shows the byte landing on
  the victim SIZE field (`0x2d0`→`0x253`, `0x5f964ed8920d`→`0x5f964ed89253`).
  fd/bk is therefore unreachable by the length knob alone.
- **Arm C (48x1024 drain parts, `ORDER=filler-first`, N=524, 12 fresh
  processes):** 11/12 aborted pre-response and one survivor returned 404
  with maps; its 50 reflected parts were byte-clean with no pointers. The
  count/order knobs left untried by item 10 are therefore closed on both
  geometries — they overshoot the surviving class.
- A default-geometry re-run of `ruby2shell-stock-leakclass.sh` (24 fresh
  processes) yielded one survivor with maps; its 34 reflected parts were
  byte-clean with no reflected pointers, consistent with item 10.

Boundary: this closes the main-arena variant of the libc-oracle hunt. The
default multi-arena channel still leaks only arena-region and GC-page
addresses (item 10); no libc/code base, attacker-chosen write or persistence
is observed. Stock/oracle-free/persistent rung 5 remains **NOT ACHIEVED**;
the witness-ESTABLISHED harness-condition rung-5 cell is unchanged. No grade
change. The driver is committed; evidence lives in
`lab/build/evidence/stock-rails-mainarena{,-fd,arena48}-*`.


### Multi-request substrate and chosen-header coverage — two measured positives (2026-11-25, direct session, second batch)

Item 10's "second-request survival (3/3 aborts)" is now SUPERSEDED with
bytes: those wave-1 runs sent the second ATTACK immediately. Three new
request-sequence measurements on the unmodified app (consH20-tail N=524
geometry, case-probe preload pinned, loopback only) show the exploited
process is USABLE after a surviving attack:

- **Benign multipart second request survives 2/2** (tags
  `stock-rails-bq-13`, `bq-17`): after a surviving attack (404), a full
  33-part multipart body with NO `_method` part parsed cleanly (404),
  the process stayed alive, and a later `GET /up` returned 200.
- **A complete second ATTACK survives after a benign interlude 3/3**
  (tags `stock-rails-tq-19`, `tq-1`, `tq-7`): attack → benign multipart →
  a second full `_method` attack all returned 404 on ONE process, which
  then served `GET /up` 200. The immediate second-attack abort therefore
  depends on the arrival order, not on a per-process one-shot limit; a
  benign parse re-flows the damaged bins enough for another corruption to
  pass. This is the substrate a leak-then-poison chain needs: request 1
  leaks the arena region base (item 10), request 2 grooms benignly,
  request 3 carries content computed from the leak.
- **The arena→libc constant-delta hope is closed**: across 28 live
  survivor maps snapshots, `libc_base − arena_region_base` took 21
  distinct values spanning +0x25600000…+0x29400000 (2 MiB quantized,
  ~62 MiB spread — GC-page mmaps between them vary per boot), so the
  leaked region base does not pin libc.

The write primitive was then re-measured beyond the one fixed byte. The
second case buffer's capacity grows as `remaining×2+20`, so its
attacker-chosen output window at the corrupted victim extends to
~0x240 bytes — past the next chunk's header. A four-arm sweep
N ∈ {540, 556, 572, 588} (24 fresh processes each, otherwise the
consH20-tail geometry, case probe armed) measured:

- **Chosen content covers the next-chunk header across the corrupted
  boundary.** Covered runs show the boundary qwords reading
  `next_prev=0x535353535353…` (the upcase output bytes) and
  `next_size=0x251` (the planted `00005102` tail) — a FULLY chosen
  16-byte chunk header at the split position, plus ~0x230 bytes of
  chosen content behind it. N=540: 2 covered runs (binned victims);
  N=588: 6 covered runs, **one of which SURVIVED** (`cov-n588-18`:
  404 + later `/up` 200 with the forged `[0x5353…, 0x251]` header in
  place). The tail design generalizes: the planted size qword is
  attacker-chosen through the same four body bytes.
- The covered successors in the sampled runs were split-fresh (top or
  remainder) rather than linked bin chunks; malloc re-canonicalized the
  region before any consumer read the forged header. The un-consumed
  forge is preserved as a measured positive for allocator control, not
  upgraded.

Boundary: wire-only chosen-bytes-over-chunk-header is now measured on
the stock app with a surviving instance, and multi-request chains on one
process are measured possible. Still missing for stock/oracle-free/
persistent rung 5: a consumer that reads the forged header into a
controlled overlap or tcache poison, the `PROTECT_PTR` position
ambiguity (the successor's page is only known ±0x8000 from the leak),
the libc/code oracle (no wire channel; the main-arena variant is closed
above), and a second COMMAND. Full rung 5 remains **NOT ACHIEVED**; no
grade change.

The coverage band is bounded by two further arms (24 runs each): N=508
produced 5 survivors and zero covered boundaries (the `remaining×2+20`
window is too short), and N=604 produced 22/24 survivors with zero
covered boundaries — its B/A lines show the 0x53 byte landing in
live-object slack (garbage fd/bk reads like `0x66000010062`, sizes
`0x35→0x53` inside object data), a benign-land class rather than a
corruption. Wire-only chosen-header coverage is therefore pinned to the
N ∈ [540, 588] band at this geometry.

### Cross-request chunk plants — measured partials plus a STRUCTURAL pairing negative (2026-11-25, direct session, third batch)

The multi-request substrate invites engineered plants: a benign request
whose parse buffers become the attack's victim population. Three facts
were measured first:

- **Plant parts below Ruby's embed threshold are a malloc no-op.** 620-
  and 500-byte parts produced ZERO matching mallocs (the ~809-byte VWA
  embed rule applies to multipart values too — the Stage A `embedprobe`
  lesson). Plants must be ≥ 809 bytes, so the smallest plantable class
  is 0x330.
- **Embed-legal plants allocate as measured:** 946-byte parts yield
  `0x3bb` value buffers plus fixed `0x400` parser slices; 809-byte parts
  yield `0x332` values (Rack 3.2.8: value = content+9, slice = fixed
  1024). Plant→attack at N=892 survived 8/18 (404 + alive), and the
  upcase demonstrably tolerates a broken pairing (buffer1 popped the
  plant frontier at 0x…8675160 while buffer2 fell back to a distant
  boot chunk at arena+0x3e80).
- **Sequential POSTs share one worker thread/arena 3/3** (`tq-19`,
  `tq-1`, `tq-7`: plant, benign and attack allocations all on one tid,
  one region) — the per-thread-tcache blocker does NOT apply to this
  request pattern, so cross-request plants via the thread's own tcache
  are real.

**The pairing triangle is then closed STRUCTURALLY.** For a planted
victim V to give buffer2 the corrupted-boundary pop AND full successor
`next`/`key` coverage: buffer2's class is `align16(N+30)`, the content
span is `N−22`, the 0x53 growth is at most +0x52 (LSB 0x01), so
`V ∈ [N−52, N−46]` — a 6-byte window spanning residues 8–14 (mod 16),
which never contains a 16-aligned chunk class. No N works. This also
explains the natural N=524 class: its 10-byte shortfall of the
successor's fd is structural, not layout luck. Chosen-header coverage
of `[prev_size, size]` (measured at N=588) is the ceiling of this write
family.

**Named next lead (Einherjar family, no next/key needed):** the covered
boundary carries a chosen `prev_size` and a chosen successor `size`
whose PREV_INUSE bit can be cleared; the upcase content behind the
boundary can itself plant a fake chunk header inside the covered span.
A later free/consolidation reading that forged `prev_size` would
backward-consolidate onto the content-planted fake chunk and yield an
overlapping allocation over the live successor region (a reflected
drain string or a binned chunk) — the overlap write then serves the
poison stage, with the leak (item 10) supplying the arena base. The
`PROTECT_PTR` ambiguity drops out of the critical path for this family.
Boundary unchanged: no command, no persistence, no grade change;
stock/oracle-free/persistent rung 5 remains **NOT ACHIEVED**.

### Dual-instrument N=588 timelines — a second corruption family measured (2026-11-25, direct session, fourth batch)

Running the same N=588 consH20-tail wire input with BOTH instruments
live (`MTRACE_CASE_REQUEST=0x278` plus the arm file, `case_only` unset —
the case snapshots write directly, so the B/A/V lines and the full M/F
stream coexist; 6 fresh processes, excerpts preserved as
`lab/build/evidence/stock-rails-td588-*.excerpt.txt`) resolves the
internal bookkeeping and finds a SECOND corruption family:

- **Shrink family (5/6 dual runs):** the tracked upcase hits a BINNED
  UNSORTED victim (`fd=bk=region+0x90`) of class 0x171/0xbf1/0x191/
  0xf31/0xaa1, and the 0x53 byte SHRINKS it — `0x171→0x153`,
  `0xf31→0xf53`, `0xaa1→0xa53` (LSB 0x?1→0x53). Buffer2 (nb 0x270)
  then SKIPS the too-small chunk (no pairing; the case-C never fires),
  the shrunk chunk re-bins at the smaller class, and the victim's tail
  region is recycled by tiny pops (`M 0x3`/`M 0x10` at victim+0x170)
  plus a 0x409-class allocation at victim+0x190. A shrunk free chunk
  re-binned small leaves overlapping chunk records against the original
  successor at +0x170 — the classic shrink-free-chunk overlap, now
  measured wire-only on the stock app.
- **Pairing family (pure-trace runs, e.g. `tr588-6`):** when the
  frontier instead hands buffer1 a chunk followed by a 0x270-class
  tcache entry, buffer2 = buffer1+0x280 pops it and the result string
  lands at buffer2+0x270 — the ideal Stage-A pairing that produced the
  surviving chosen-header forge (`cov-n588-18`).
- Both families arise from the SAME request bytes at N=588; which one
  fires depends on the frontier population (boot/thread timing), not
  on any knob.

Boundary: two measured corruption families (pairing/forge and
shrink/overlap), exact timelines on record, reproduction command above.
Neither family yet yields a controlled allocation — that engineering
(Einherjar backward-consolidation on the pairing family; re-bin
consumption on the shrink family) is the next work package. No command,
no persistence, no grade change; stock/oracle-free/persistent rung 5
remains **NOT ACHIEVED**.


### Shrink-family claim experiment — bounded NEGATIVE; a live
### corrupted-binned-chunk substrate measured; the claim lane closes
### STRUCTURALLY on IS_MMAPPED (2026-11-25, direct session, fifth batch)

The named work package — claim the 0x53-corrupted chunk with a
matched-class benign request — ran as the committed driver
`lab/repro/ruby2shell-shrink-claim.sh`: per fresh process on the
unmodified `rails new --minimal` app, an optional benign PLANT
multipart (parts ≥809B), the consH20-tail ATTACK body (byte-identical
to the cov-n588 geometry at N=588), a benign CLAIM multipart with
matched-class parts, then `/up`; case probe and full M/F stream live
together; 48 runs in four arms (`stock-rails-sc{588,588np,892,988}-*`,
excerpts preserved, bulk trimmed):

- **N=588 + plant (24×946B):** plant value/slice frees land before the
  upcase, but the plant churn moves buffer1's pop into the fresh
  frontier — victims are tiny (0x25–0x55) or fresh-region chunks
  (`fd=bk=nil`), 9/12 survive all three requests, 0 claims. One run
  shows the pairing family live end to end: buffer2 (0x262) pops the
  fresh victim itself, the upcase output `SS…` plus the planted
  `00005102` tail lands interior to buffer2 (V line:
  `next_prev=0x535353535353`, `next_size=0x251`), and the 0x30 growth
  overshoots into more top memory.
- **N=588 unplanted:** the big binned victims return
  (0x991/0xe71/0xdd1/0xa81/0x1571 → 0x953/0xe53/0xd53/0xa53/0x1553),
  but 7/7 big-victim runs abort DURING the attack at the request's own
  unsorted consumers (`malloc(): invalid next size (unsorted)`,
  `mismatching next->prev_size`); the five survivors' corrupted
  classes are all below the ~809B plant floor (0x50/0x150/0x250) —
  structurally unclaimable. 0 claims.
- **N=892 + plant:** victims tiny again (0x10–0x155), 8/12 survive
  (matching the third batch's 8/18), 0 claims.
- **N=988 + plant (40×920B with a chosen `[0][0x91]` strip qword at
  content offset 848):** buffer1's class now equals the parser-slice
  class (0x410). A B/A-pairing correction (the driver's first table
  matched the last B with the last A independently, splicing pairs from
  different phases) shows the REAL attack upcase pairs are: big
  planted-band victims `0x411→0x453`, `0x471→0x453`, `0x601→0x653`
  (runs sc988-12/7/9 — ALL aborting during the attack at the request's
  own bin scans), plus tiny LIVE victims (`0x95→0x53` in sc988-3,
  `0x35→0x53` in sc988-11) in the runs that survive.
  **sc988-3 and sc988-11 complete attack, claim AND `/up` 200 carrying a
  corrupted IN-USE small chunk (class 0x50, IS_MMAPPED) that nothing
  consumed — a live stock process with an untriggered corruption
  surviving two later requests, but NOT a binned corrupted chunk; the
  earlier "0x453-class still binned" wording is corrected here.**
  Four runs die inside the CLAIM request (its own churn consumes the
  corrupted small chunks first). 0 matched-class claims in every arm.

**Structural closure of the claim lane.** The 0x53 byte always sets
IS_MMAPPED (0x53 = 0x50|0x3), so ANY consumer that `free()`s the
corrupted chunk — including every claimed value buffer at request-end
GC — takes the `munmap_chunk` path and aborts
(`munmap_chunk(): invalid pointer`, measured). A matched-class claim
can therefore never be a surviving consumer on this allocator: it is
either aborted earlier by the request's own bin scans (big unplanted
victims, 7/7), sub-floor and unclaimable (small victims), or
claimable only into a teardown abort (grown planted-band victims).
The only consumers that survive are consolidations in which the
corrupted chunk participates as a NEIGHBOR — backward consolidation
reads `prev_size` from the freed chunk's own header and unlinks the
corrupted chunk through its intact bin links; the corrupted chunk's
own header is never passed to `free()`. **The Einherjar family is
therefore structurally the only surviving consumer of a
0x53-corrupted chunk here, not merely the next idea.**

Boundary: the claim question is answered as a bounded negative with
the consumer measured; the sc988-3/11 state (live process, binned
corrupted chunk, two requests served after the corruption) is the
measured input condition for it. No command, no persistence, no
grade change; stock/oracle-free/persistent rung 5 remains
**NOT ACHIEVED**.


### Poison-arm engineering — planted-victim GROWTH measured on a live
### chunk; the frees-timing blocker sharpened to sweep persistence; two
### law corrections (2026-11-25, direct session, eleventh push)

The named Einherjar-input experiment ran as a new `poison` mode of
`lab/repro/ruby2shell-shrink-claim.sh` (per fresh process: benign plant
multipart → optional benign small-part churn → consH20 attack body →
matched-class claim → probe, dual instrument, loopback only), 48 more
fresh processes in four arms. One driver defect found and fixed first:
the case-arm file was shared across parallel runs (`$TAGP`), so the
first run to finish disarmed every later run's attack probe — the arm
file is now per-run, and the builder is guarded by body-file existence
checks (one arm was voided by a builder crash before the guard).

- **Thread-split measured systematically, then pinned:** in the
  unpinned arm the plant request and the attack landed on different
  Puma worker threads with different arenas 12/12 — planted chunks are
  invisible cross-arena. `RAILS_MAX_THREADS=1` at server launch (a
  deployment env, app code untouched — the same condition class as the
  main-arena arm's `MALLOC_ARENA_MAX=1`) pins all requests to one
  thread/arena, and the arms after it are single-thread throughout.
- **Parse-slice law corrected:** the multipart parse slice is
  content-sized — `max(1024, content+9)`-class — not the fixed
  `0x400` measured earlier on ~1KB parts. 1816B parts allocate
  `0x730`-class slices (invisible to an 0x410-class buffer1);
  1008B-content parts allocate slice AND value both `0x410`-class.
- **Planted-victim growth measured:** with the corrected geometry
  (40×1008B + 9×976B plants, N=988, thread-pinned), the attack's upcase
  lands buffer1 on a PLANTED chunk (buf1-is-plant=True) and grows the
  adjacent planted chunk `0x415→0x453` in 3/12 runs — the
  planted-band victim with a fully chosen unsorted-scan forgery
  (`[0x450][0x91]` at the neighbor's content +0x40) exists and
  survives the request.
- **The binding blocker is sweep persistence, sharpened:** the
  planted chunks are NOT swept at request end. Across arms only ~8 of
  129 planted chunks free early (uncorrupted); the rest stay LIVE
  through the attack, the claim, and 30 benign churn requests, and are
  finally swept by a later major GC still carrying the corrupted size
  — measured end to end: the victim's free fires during a later
  request with sizefield `0x453` and aborts in
  `munmap_chunk(): invalid pointer` (the IS_MMAPPED closure above,
  now observed on the stock app as the corrupted chunk's own death).
  The 0x53 therefore always hits LIVE planted chunks; a freed,
  still-unsorted victim never exists at the upcase, so the grown
  chunk is never re-binned at its grown class and the 0x450-class
  exact-fit claim never finds it (0 matched-class claims in every
  arm). The benign-churn lever (30 sub-embed-floor requests — zero
  big allocations, zero scans) did NOT force the sweep, and
  render-bearing churn pollutes tcache[0x410] with render chunks,
  which is the same pool buffer1 needs.

Boundary: the poison chain's first half is measured live
 (planted-chunk adjacency, growth to the target class, chosen scan
 forgery in place) and its remaining blocker is named precisely — the
 plant population must be freed (unsorted, un-binned) between the
 plant request and the upcase, against Ruby's sweep persistence. No
 command, no persistence, no grade change; stock/oracle-free/
 persistent rung 5 remains **NOT ACHIEVED**.

### Sweep-pressure arms — the frees-timing barrier PARTIALLY broken;
### freed victims measured; the sweep's class/order dependence named
### (2026-11-25, direct session, twelfth push)

Four more arms of the poison driver (48 fresh processes,
N ∈ {988, 1516}, thread-pinned, filler pressure via sub-embed-floor
parts in the attack body) attacked the sweep-persistence blocker
directly:

- **Filler pressure works for the small classes:** with 200×400B
  filler parts before the `_method`, the attack's parse triggers a GC
  that frees part of the PREVIOUS plant request's population before
  the upcase — address-matched frees of the 980B-parts' 0x411 slices
  and 0x3E1 values land pre-B (4-13 per run), and for the first time
  the upcase hits FREED chunks: victims with `fd=bk` = the arena
  unsorted-bin head (the freed signature), previously unseen in any
  arm.
- **But the sweep is class/order-dependent:** in the alternating
  big/small plant arm (1548B parts interleaved with 980B parts), the
  0x410/0x3E0-class small parts' chunks free, while the 0x620-class
  big parts' slices/values NEVER do — zero `0x621`-sizefield frees in
  24/24 runs across two arms, with the planted 0x620 pool therefore
  empty and buffer1's tcache pops landing on rack chunks (the
  honeypot drain pops fresh allocations). The freed victims that do
  materialize are rack/small chunks whose physical successors carry
  unforgeable rack data, so the grown chunks die at the request's own
  unsorted scans (10/12 attack aborts,
  `mismatching next->prev_size`/`invalid next size`).
- **Two driver defects found and fixed by body audit:** a builder edit
  dropped the `_method` part entirely (one arm was vacuous — 12/12
  healthy processes with no upcase; caught by dumping the built
  body), and the in-driver analyzer's CLAIM_LIST parse rejected the
  new per-part forge spec (`size@hdr:neigh_size`). Both fixed; the
  builder now takes per-part claim forge parameters, honeypot parts
  (pool drainers), and the plant forge covers three check-qword
  offsets.

Boundary: the frees-timing barrier is now PARTIALLY broken with the
small classes proven sweepable pre-upcase and freed victims measured;
the named question is why the 0x620-class planted chunks are never
swept (GC page-visit order, allocation order, or object-graph
positioning) — the next arm varies plant part ORDER (all-big-first vs
all-small-first vs interleaved, same classes) and watches which
population frees. No command, no persistence, no grade change;
stock/oracle-free/persistent rung 5 remains **NOT ACHIEVED**.

### Sweep-order arms through sacrificial shields — the parse model
### corrected, the "never swept" claim falsified, the upcase's own
### result allocation identified as the deterministic victim-splitter,
### and the first stock-app Ruby-VM segfault (2026-11-25, direct session,
### thirteenth–sixteenth pushes)

Roughly 200 fresh processes across eleven arms
(poBF/poSF/poIF order arms, poDR* drain arms, poP40*, poNX, poCH*,
poDK*, poSH, poSG, poS5K, poSAC), all loopback, stock `rails new
--minimal` app, `RAILS_MAX_THREADS=1` (labeled deployment condition),
analysis instrumentation only. New tooling: the `--drain-parts` /
`--plant-spec`-aware tabulator `lab/repro/ruby2shell-sweep-order.py`
(complete M/F/R stream address-matching; first-free-after-allocation
semantics — reuse-noise-safe), the driver's optional pre-plant drain
request, `ATTACK_CHAIN`, `POISON_NEXT`, and a four-offset plant forge.

- **Corrected per-part parse model (measured on raw M streams):**
  each embed-legal part allocates TWO content+9 slices plus ONE
  next-pow2(content+1) value buffer — 1548B parts: 2x req 0x615
  (chunk 0x620) + 1x req 0x800 (chunk 0x810); 980B parts: 2x req 0x3dd
  (chunk 0x3f0) + 1x req 0x400 (chunk 0x410); 1527B parts: 2x 0x600
  (chunk 0x610) + 1x 0x800. The eleventh push's "max(1024, content+9)"
  slice law is corrected: sub-1024 slices are content+9 exactly.
  Sub-embed-floor parts allocate only a value buffer. CRITICAL
  correction: glibc's tcache covers only chunk sizes <= 0x420 — the
  0x610/0x620/0x650/0x810 classes have NO tcache; every "LIFO pop" of
  planted chunks previously attributed to tcache is the unsorted list's
  tail-first exact-fit return (glibc 2.39 malloc.c:4070,4132, fetched
  and read from sourceware).
- **Order arms (36 runs) falsify the twelfth push's closure:** planted
  big slices DO sweep pre-upcase — big-first order freed 32 planted
  big-slices across 3/12 runs (10-12 per run), small-first freed 22
  smalls across 2/12, interleaved freed BOTH classes (one run freed all
  32 slices, 16+16). "Zero 0x621 frees in 24/24" was an arm artifact,
  and the twelfth's "address-matched 0x411/0x3E1 planted frees" were
  mostly render garbage (the 0x3f0-slice class was misread as 0x3e0).
  The sweep is stochastic (~25-60% of runs fire) and page-order-driven,
  not class-gated.
- **Drain arms are a bounded NEGATIVE:** a pre-plant drain request's
  own 60 slices are as young as the plant's, sweep with them, and
  buffer1 lands on forge-free drain slices ("buf1=other" 24/24,
  ~90 0x625/0x624 sizefield frees per run pre-B). The drain idea is
  closed; the folded 1548x40 plant replaced it.
- **poP40H4-4 delivered the chain's target event:** buffer1 on a
  planted slice, victim = a planted freed-in-unsorted slice
  (B line fd=bk = arena unsorted head), grown 0x621->0x653 with the
  forged [0x650][0x91] successor in place — aborting at glibc's THIRD
  unsorted check, `malloc(): invalid next->prev_inuse` (malloc.c:4087):
  a freed-in-unsorted victim's forged successor size must carry
  PREV_INUSE CLEAR. Fix: POISON_NEXT=0x90.
- **poNX-5 with the 0x90 forge: the grown victim PASSES the unsorted
  checks** (no scan abort) — then the upcase's OWN result allocation
  (req 0x602 = N+22, nb 0x610) deterministically splits the re-binned
  victim: the binmap best-fit search takes `last(bin)` (malloc.c:4361)
  = the first-binned chunk, and the victim — the unsorted tail at the
  scan — is always the first binned into the 0x650 band. The split's
  remainder cascade then corrupts the successor's header and the
  request dies at its free ("free(): invalid pointer").
- **Merged-pair law (measured):** adjacent freed slice pairs
  consolidate into 0xC20-class giants bounded by the LIVE old-gen
  value chunks (values are promoted and free only mid-attack). The
  standalone plant population is the hole-slices plus pair edges; the
  honeypot and buffer1 pops are giant SPLITS — buffer1 lands on a
  split front at a planted address and the victim is the split
  remainder at the pair-mate's address with sizefield 0x611 (poS5K-9
  B line), grown to 0x653. The value-victim family (victim = the part's
  live value, 0x815->0x853) is structurally fatal: the value frees
  mid-attack carrying IS_MMAPPED and the adjacent consolidation aborts
  ("corrupted size vs. prev_size"/"munmap_chunk").
- **poSH-8 and poS5K-9: the first stock-app Ruby-VM SEGFAULTS from
  this chain** — the split-cascade corruption is dereferenced by the
  dev-404 render's prettyprinter (full VM backtrace terminating at
  `prettyprint.rb:404` during `pp` of the request environment). A new
  crash family beyond glibc aborts: wire-driven heap corruption
  consumed by application code on the unmodified app. Honest label:
  a crash from corruption, not a steered allocation.
- **Sacrificial shields (poSAC, N=1500):** plant classes sized so the
  intermediate consumers find exact-fit chunks — 1517B parts (slice nb
  0x600, the upcase result's exact) and 1521B parts (nb 0x5f0,
  buffer2's exact) — produced 6/12 runs completing the FULL sequence
  (attack=404 claim=404 probe=404 up=200 alive, vs 0-2/12 in every
  prior arm), with the claim parts' slices popping giant-split fronts
  AT PLANTED ADDRESSES (4 claim-pops at plant addresses in survivors,
  chosen raw claim bytes landing on groomed addresses). The shield's
  causality is partial: some sacrificial slices merge into giants or
  are consumed by the honeypot pops; the buf1-on-plant runs still
  mostly hit the fatal value-adjacent parity. Honest boundary: the
  exact-fit pop of the GROWN victim by the claim has NOT yet been
  observed; the binmap first-binned pick rule and the pair parity are
  the named open mechanics.

### In-process bin-chain dump closes the 0x650-band claim path — the
### upcase's own result allocation always splits the grown victim
### (2026-11-25, direct session, seventeenth push)

The analysis-only preload gained `MTRACE_DUMP_BINS` (driver knob
`RUBY2SHELL_CLAIM_BINDUMPS=1`): at the upcase's A snapshot it walks the
worker arena's unsorted list and largebins 71/72/73/96 and emits `L`
lines (bin index, chunk address, sizefield). The arena head is captured
from any large free's post-`__libc_free` fd. A debugger route was tried
and abandoned (the preload's SIGSTOP was swallowed by gdb; SIGTRAP went
to a forked Puma child — the throwaway script was removed); the
in-process dump gives the same evidence without a tracer.

Measured on poBD3/poF3/poF3H{4,6,8,10} (~90 fresh processes): at every
upcase the arena holds ONE unsorted chunk (the grown victim), one 0x5c0
chunk in bin71, one 0xc20 merged-pair giant in bin96 — **bin72 and
bin73 are empty** in the great majority of runs. poF3H10-6 is the
decisive run: the victim is the planted slice remainder
(`size=0x611 -> 0x653`, `fd=bk=arena`, forged
`next_prev=0x650 next_size=0x90` in place — the checks are satisfied),
the L lines show exactly `[unsorted: victim 0x653] [bin71: 0x5c1]
[bin96: 0xc21]` with bin72/73 empty. The upcase's own result allocation
(req 0x5f2, nb 0x600) scans the unsorted victim (checks pass — no
abort), re-bins it at 0x650/bin73, then its search finds bin72 empty,
bin73 non-empty: `last(bin73)` is the victim, so the result splits it
(the M line returns the victim's address). The claim POST never sees
the grown chunk.

Boundary: the poison chain's claim step is STRUCTURALLY CLOSED at this
geometry — the grown class (0x650 from a 0x610 victim), the result's
nb (0x600 from N=1500), and the empty bin72 combine deterministically.
Shifting N to put the result into the reliable 0x5c0 band makes the
pool class 0x5f0, where the 0x53 byte SHRINKS the victim (0x5f5->0x553)
and no phantom extent exists for an overshoot. Value-adjacent victims
remain fatal. No command, no persistence, no grade change; the earlier
stock-app segfaults (corruption consumed by prettyprint) stand as the
strongest demonstrated impact, and stock/oracle-free/persistent rung 5
stays **NOT ACHIEVED**.

   poisoning from the Stage B overlap: the second same-class
   allocation returns an attacker-nominated address (chosen bytes
   written there, read back through the live host string), 5/5 +
   control 3/3. The report's optional pointer-control lane is closed.
2. **Witness acceptance (tape #65, 2026-11-20): both HTTP sections —
   Sinatra and Rails — ESTABLISHED at rung 4 request-reachable.** The
   witness independently re-ran the committed scripts, confirmed the
   readbacks, controls, marker-at-V attribution and the chosen-byte
   counterexample over HTTP, and confirmed the CSRF 422 ordering
   directly. With tape #51 (in-process Stage B), the target's rung-4
   witness-ESTABLISHED on both claimed default stacks.
3. **Witness acceptance (tape #89, 2026-11-20): Stage C — ESTABLISHED
   at rung 4, strengthened pointer control, as honestly scoped.** The
   witness re-ran the committed driver (5/5 attack, 3/3 control),
   independently parsed every mtrace trace, recomputed the
   PROTECT_PTR splice, reproduced a target-move counterexample
   (f+0x180 variant), and audited the build environment for hidden
   flags; no contradiction, no repair owed. With tapes #51, #65 and
   #89, every rung-4 claim in this report is witness-ESTABLISHED. The
   advisory is public since 2026-11-18/19, so the standing watch item
   is now live: when Veria's PoC drops (2026-11-25, or later while
   major vendors lag), compare its mechanics against this report's
   honest gaps (request-shaped grooming, control-flow hijack,
   musable-safe popped headers) and record agreements and
   contradictions here. Until then nothing else is owed unless a
   counterexample appears.
4. **Done this wake (2026-11-21): HTTP Stage C depth — CLOSED with
   bytes.** The request-thread chain (musable-safe headers, poisoned
   pops, readback at the nominated address in the HTTP response) is
   observed 3/3 with clean controls 2/2; the process aborts in glibc
   worker-thread tcache teardown after the readback (exact gdb frames
   in the new section above). No grade change and no repair owed:
   rung 4 remains witness-ESTABLISHED. With the copy-out lane also
   closed (commit 7c6dfac), no investigation lane is open; wait for
   the Veria PoC signal or the 2026-11-25 dated trigger.
5. **Closed this wake (2026-11-22): independent rung-5 witness ESTABLISHED.**
   The clean-archive replay of `8b9d8f9` reproduced two varied-command attacks
   and both controls, independently scanned every target pop and audited the
   address oracles and absence of direct command/marker calls. No repair is
   owed. Broader request-shaped grooming, oracle-free ASLR reach and process
   survival remain explicit UNKNOWNs, not silently included in the grade.

6. **Done this wake (2026-11-25, second push):** the victim-region
   consumer provenance is closed (0x21c/0x1f8 fixed-size, not
   wire-shaped); the carve-landing sweep found no reflected corruption in
   11 survivors; and wire-shaped victim grooming is closed as a bounded
   negative with six measured blockers — boot-recycled victim identity,
   zero in-request parse frees (225 allocs / 0 frees at 112 parts),
   cross-request GC timing, Puma's per-thread tcaches plus render churn
   eating deterministic casemap plants, the monotone-consumption
   frontier, and the aligned-size sweep (N≡12 mod 16 reconfirmed, N=1024
   lands off the size field). The strongest measured stock lever remains
   the surviving unsorted-split overlap (consH-20 class). Named next: a
   stock route running MethodOverride without the debug-page render,
   same-thread pacing, or Veria's PoC mechanics when published. Rung 5
   stock/oracle-free/persistent: still NOT ACHIEVED.

7. **Done this wake (2026-11-25, third push):** the harness rung-5 chain
   was re-smoked end to end (attack marker + `rce=OBSERVED` + target pop;
   safe affected and fixed 3.4.13 both clean). The new measurement is that
   a stock Sinatra 500 page leaks 20 GC-heap object addresses via env
   `to_s`/`inspect` (12 boot-stable in-process; 0/20 low-bit overlap across
   fresh processes; 20/20 in Ruby GC pages, none in glibc heap or code),
   but it is not wire-reachable on a route-less app and Rails filters it;
   it replaces only `ObjectSpace.dump`, not mtrace or maps. Stock/oracle-
   free/persistent rung 5 stays NOT ACHIEVED. Veria's PoC remained
   unpublished at the dated trigger; the disclosure writeup confirms RCE
   but gives no mechanics.
8. **Done this wake (2026-11-25): keep-alive same-thread pairing closed at
   the Rails configuration.** With Puma `min=3/max=3` (the `rails new`-relevant
   pool), five GETs on one reused connection rotated across all three worker
   threads in 3/3 fresh processes; the default `min=0/max=5` pool did share a
   thread for sequential requests, which is a configuration property, not a
   usable opening. Per-thread-tcache blocker #4 stands, and blockers #2/#3
   (no in-request parse frees; post-upcase GC frees) still prevent a plant
   transfer. Stock/oracle-free/persistent rung 5 stays NOT ACHIEVED.
9. **Done this wake (2026-11-25): consH-20 low-byte tcache retarget closed —
   bounded NEGATIVE.** The committed case probe
   `lab/repro/ruby2shell-consH20-retarget.sh` ran 144 fresh processes (24
   without the tail qword, 120 with it) on the unmodified `rails new --minimal`
   app: 11 survivors, 52 expansions, but only ONE window `P`/`Q` survivor.
   In that survivor the overflow byte changed the victim size `0x201`→`0x253`
   (not the fake `0x20` chunk's tcache `next`), and the three window pops were
   C-internal fixed-size allocations (`0x3`, `0x10`, `0x28` requests) carrying
   no attacker-shaped bytes; victim content was the fixed `0x53` byte. No
   steered allocation with attacker bytes, so no oracle-free Stage-B analog.
   Stock/oracle-free/persistent rung 5 stays NOT ACHIEVED. Named next: shape
   the carve into a reflected drain-string body — vary drain part count and
   part order (the untried knobs of the closed 60-run sweep), then scan the
   dev 404 response for forged-window qwords; a wire-visible glibc-heap
   pointer is the first oracle still missing.

10. **Done this direct-session push (2026-11-25): the named reflection
   lead is ANSWERED — the first missing oracle is now measured.** The
   48-part/filler-first arm aborts 6/6 (top-chunk pop → sysmalloc), but
   byte-scanning the saved and fresh 404 responses with the new
   `ruby2shell-reflect-scan.py` found the channel already firing in the
   32-part consH20-tail geometry: 20 historical responses and one live
   maps-confirmed instance reflect arena-region pointers
   (region+{0x8c660,0x8c760,0x8cdb0} — the arena base, hence the tcache
   key, leaks wire-only) plus Ruby GC-page pointers (replacing
   `ObjectSpace.dump`). Structurally absent: any libc/code pointer (the
   worker-thread arena's bin heads are in-region), attacker-chosen upcase
   bytes (0 S-runs in 432 responses) and second-request survival (3/3
   aborts). Named next: hunt a libc/code-base oracle on a different
   surface (main-thread-arena geometry, GC-page content spill, or a
   production-mode render) and steer which drain part gets hit — the
   landed window now has a measured detector.
11. **Done this wake (2026-11-25): main-arena libc-oracle lead closed —
    bounded NEGATIVE.** With `MALLOC_ARENA_MAX=1` the victim lands in
    `[heap]` and two runs even held a maps-confirmed libc pointer
    (`libc+0x203b20`) in victim `fd=bk`, but 16 survivors across the N=524
    and N=532 arms reflected 544 byte-clean parts and zero pointers: the
    metadata never crossed into the wire body, and the +8 length shift only
    changed the chunk size class (`0x238`→`0x240`), not the write offset;
    a 48-part/filler-first arm added 11/12 aborts and one byte-clean
    survivor. Named next: abandon the count/order knobs (closed on both
    geometries) and hunt a different surface that carries the main-arena
    victim's fd/bk qword into a reflected string — a production-mode
    no-debug render, or the GC-page content spill; classify any hit
    against `libc+0x203b20`. Stock/oracle-free/persistent rung 5 stays
    NOT ACHIEVED.

12. **Done this direct-session push (2026-11-25, second batch): the
    process is multi-request-usable and the write is a chosen header.**
    A benign 33-part multipart (no `_method`) survives on an attack
    survivor 2/2, and a complete second ATTACK survives after a benign
    interlude 3/3 (`tq-19`, `tq-1`, `tq-7`) — item 10's immediate
    second-attack abort is arrival-order-specific, superseding that
    blocker and opening the leak→groom→poison chain substrate. The
    arena→libc constant-delta oracle is closed (21 deltas in 28 live
    snapshots). The N ∈ {540,556,572,588} coverage sweep measured chosen
    content plus the `00005102` tail covering the next-chunk header at
    the corrupted boundary — a fully chosen `[prev, size]` forge — with
    one surviving N=588 instance (`cov-n588-18`); covered successors were
    split-fresh and re-canonicalized before consumption. Named next:
    make a linked bin chunk land at the covered boundary (steer the
    carve across a binned successor — the drain part the leak runs hit
    is now a measurable detector), then chase the consumer; the
    `PROTECT_PTR` page ambiguity (±0x8000) and the libc oracle remain the
    named blockers after that. Stock/oracle-free/persistent rung 5 stays
    NOT ACHIEVED.
    Boundary arms: N=508 (5 survivors, window short of the boundary) and
    N=604 (22/24 survive because the byte lands in live-object slack,
    zero coverage) pin the chosen-header band to N ∈ [540, 588].

13. **Done this direct-session push (2026-11-25, third batch): the
    planted-victim pairing is STRUCTURALLY closed; the Einherjar family
    is named next.** Measured: plant parts below the 809-byte embed
    threshold never malloc (plants must be ≥809B, class ≥0x330);
    embed-legal plants allocate as `content+9` values plus fixed
    `0x400` slices; plant→attack survives 8/18 at N=892 with the
    pairing visibly broken (buffer1 on the plant frontier, buffer2 on a
    distant boot chunk); sequential POSTs share one worker thread/arena
    3/3, so cross-request tcache plants are real. Closed on paper: the
    pairing triangle (buffer2 `align16(N+30)`, content `N−22`, growth
    ≤ +0x52) admits no 16-aligned victim class at any N — the natural
    class's 10-byte fd shortfall is structural. The chosen
    `[prev_size, size]` header forge at the covered boundary is the
    ceiling of this write family; the Einherjar route (content-planted
    fake chunk + forged prev_size + cleared PREV_INUSE → backward
    consolidation onto the fake → overlap allocation over the live
    successor) is the named next experiment, with the arena-base leak
    feeding any address stage. Stock/oracle-free/persistent rung 5
    stays NOT ACHIEVED.

14. **Done this direct-session push (2026-11-25, fourth batch): the
    N=588 dual-instrument timelines are on record and a SECOND
    corruption family is measured.** With the case snapshots and the
    full M/F stream live together, 5/6 runs show the 0x53 byte SHRINKING
    binned unsorted victims (`0x171→0x153`, `0xf31→0xf53`) — buffer2
    skips the too-small chunk, it re-bins small, and the tail region is
    recycled (tiny pops + a 0x409-class allocation), leaving overlapping
    chunk records — the shrink-free-chunk overlap family. The pure-trace
    runs confirm the sibling pairing family (buffer1 → victim at +0x280
    → result at +0x270) that produced the surviving chosen-header forge.
    Same wire bytes, two families, frontier-dependent. Named next: turn
    either family into a controlled allocation — Einherjar
    backward-consolidation on the pairing family (content-planted fake
    chunk, forged prev_size, cleared PREV_INUSE), or re-bin consumption
    on the shrink family (claim the shrunk chunk with a matching-class
    request and observe the overlap against the original successor).
    Stock/oracle-free/persistent rung 5 stays NOT ACHIEVED.

15. **Done this direct-session push (2026-11-25, fifth batch): the
    shrink-family claim question is ANSWERED — bounded NEGATIVE with a
    structural closure, and the Einherjar input condition is measured
    live.** The committed `lab/repro/ruby2shell-shrink-claim.sh` ran 48
    fresh processes in four arms (N=588 planted/unplanted, N=892
    planted, N=988 planted with 40×920B chosen-strip plants). No
    matched-class claim ever popped a corrupted chunk: the plant
    churn moves victims to tiny/fresh classes (unplanted: 0 claims),
    big unplanted binned victims abort during the attack at the
    request's own unsorted consumers (7/7), survivors' corrupted
    classes are below the 809B plant floor, and the planted-band
    grown victims (0x453) sit in their original 0x410-band bin where
    matched claims fit without overshoot. Two N=988 runs
    (sc988-3, sc988-11) complete attack, claim AND `/up` 200 carrying
    an untriggered corrupted IN-USE small chunk (real attack pairs
    `0x95→0x53`/`0x35→0x53` after a pairing correction — not a binned
    0x453 chunk; the big planted-band victims of that arm all abort
    during the attack). Structural
    closure: 0x53 always sets IS_MMAPPED, so every consumer that
    `free()`s the corrupted chunk aborts in `munmap_chunk` (measured);
    only neighbor-consolidations survive — Einherjar is structurally
    the only surviving consumer. Named next: Einherjar on the
    fresh-region pairing family — craft the `_method` tail so the
    chosen boundary qwords forge `prev_size` plus a PREV_INUSE-clear
    successor size inside the upcase output span, and let the
    request's own teardown consolidation consume the corrupted chunk
    as a neighbor. Stock/oracle-free/persistent rung 5 stays NOT
    ACHIEVED.

16. **Done this direct-session push (2026-11-25, eleventh batch): the
    Einherjar-input poison chain is engineered and its binding blocker
    is named with bytes.** The committed `poison` mode of
    `lab/repro/ruby2shell-shrink-claim.sh` ran 48 more fresh processes
    (four arms): thread-split measured 12/12 unpinned and pinned via
    `RAILS_MAX_THREADS=1` (labeled deployment condition); the parse
    slice law corrected to content-sized `max(1024, content+9)`-class;
    planted-chunk adjacency achieved with 1008B-content plants; the
    0x53 growth on a planted chunk measured (`0x415→0x453`, buf1 from
    the planted pool, chosen `[0x450][0x91]` scan forgery in place);
    and the sweep-persistence blocker sharpened: planted chunks stay
    LIVE through the attack, claim and 30 benign churn requests
    (~8/129 early frees), dying only at a later major GC with the
    corrupted sizefield (`munmap_chunk(): invalid pointer`, measured
    end to end) — so a freed unsorted victim never exists at the
    upcase and the 0x450-class exact-fit claim never fires. Named
    next: free the plant population pre-upcase against sweep
    persistence — candidate levers: request shapes whose params die
    young (per-request re-parse patterns), GC-pressure sequences that
    do not touch the 0x410/0x3F0 pools, or an in-request plant (the
    attack body itself planting earlier parts whose sweep lands
    mid-parse). Stock/oracle-free/persistent rung 5 stays NOT
    ACHIEVED.

17. **Done this direct-session push (2026-11-25, twelfth batch): the
    frees-timing barrier is PARTIALLY broken — freed victims measured
    for the first time.** Filler pressure (200×400B sub-embed-floor
    parts in the attack body) makes the attack's parse GC free part of
    the previous plant population before the upcase: address-matched
    0x411/0x3E1 planted frees land pre-B (4-13/run) and the upcase
    now hits FREED chunks (victims' `fd=bk` = the unsorted-bin head).
    But the sweep is class/order-dependent: in the alternating
    big/small plant arm the small parts' chunks free while the
    0x620-class big parts' slices/values NEVER do (zero 0x621 frees
    in 24/24 runs) — buffer1 keeps landing on rack chunks and the
    freed rack victims die at the request's own unsorted scans
    (10/12 attack aborts, their successors' rack data unforgeable).
    Two driver defects found by body audit and fixed (a builder edit
    had dropped the `_method` part — one vacuous arm; the analyzer's
    CLAIM_LIST parse). Named next: vary the plant part ORDER at fixed
    classes (all-big-first / all-small-first / interleaved) to
    isolate what the sweep visits, then re-run the honeypot drain
    against the measured rack-top count. Stock/oracle-free/persistent
    rung 5 stays NOT ACHIEVED.

18. **Done this direct-session push (2026-11-25, thirteenth–sixteenth
    batches): the order question is ANSWERED, the parse and tcache
    models corrected, the deterministic splitter found, and the chain
    survives to the claim in 6/12 sacrificial-shield runs.** The sweep
    visits planted slices stochastically in every order (the twelfth's
    class-gated closure falsified); the corrected parse model (two
    content+9 slices + one pow2 value per part, no tcache above 0x420)
    explains every pop; poP40H4-4 measured the freed-in-unsorted grown
    planted victim and named the third unsorted check
    (prev_inuse-of-successor, fixed with POISON_NEXT=0x90); poNX-5
    measured the passing scan and the upcase's own result allocation
    as the deterministic splitter (the binmap search's first-binned
    pick); poSH-8/poS5K-9 measured the first stock-app Ruby-VM
    segfaults (prettyprint consuming the split-cascade corruption);
    poSAC's sacrificial classes shielded the intermediates and 6/12
    runs completed the full request sequence with claim-pops at
    planted addresses. Open mechanics: the exact-fit claim pop of the
    grown victim, the pair parity (value-adjacent victims are fatal),
    and the sweep firing rate. Named next: a debugger observation of
    the unsorted/largebin chains at the B line of a poSAC-geometry run
    (gdb, one process) to settle the binmap pick rule with bytes, then
    the honeypot-count parity knob at the N=1500 geometry.
    Stock/oracle-free/persistent rung 5 stays **NOT ACHIEVED**.

19. **Done this direct-session push (2026-11-25, seventeenth batch): the
    binmap pick rule is settled WITH BYTES and the 0x650-band claim path
    is closed.** The analysis-only in-process L-line bin dump
    (MTRACE_DUMP_BINS) shows at every upcase one unsorted grown victim,
    one 0x5c0 chunk in bin71, one 0xc20 merged-pair giant in bin96, and
    EMPTY bins 72/73. poF3H10-6 gave the exact intended victim (planted
    slice remainder, 0x611->0x653, fd=bk=arena, forge
    [0x650][0x90] in place, checks PASS) — yet the upcase's own 0x600
    result allocation re-binned it at bin73 and then split it there,
    because bin72 was empty (binmap best-fit takes last(bin73)). Shifting
    N to the 0x5c0 result band makes the pool 0x5f0-class, where the
    0x53 byte shrinks rather than grows the victim (no phantom extent).
    Named next: the GIANT-POP claim — a 3095B claim part (slice req
    0xc20) exact-fits the bin96 merged-pair giant in the separate claim
    POST; its raw bytes write over both slices and across the live
    value's header at giant+0xc20, with chosen forgery qwords. Observe
    the value's mid-attack free and the C/P window lines. This route
    avoids the 0x650-band closure entirely. Stock/oracle-free/persistent
    rung 5 stays **NOT ACHIEVED**.

20. **Done this direct-session push (2026-11-25, eighteenth batch): the
    GIANT-POP claim route is closed on paper before another run.** The
    3095B claim part (slice req 0xc20) does exact-fit the bin96 merged
    giant, but its usable write is exactly 0xc18 bytes — the giant's
    physical usable size — so NO chosen byte crosses into the live
    value at giant+0xc20. The overshoot requires a sizefield that
    claims more than its physical extent (the 0x53 poison), and every
    such grown victim on this stock app is now accounted for: live or
    value-adjacent victims abort at their own frees, and freed-in-
    unsorted victims are re-binned then split by the upcase's own
    result allocation (poF3H10-6, L-line dump, bin72 empty). The
    12-run poGP arm confirmed the attack rarely even reaches the claim
    POST (1/12) and produced no claim-overlap. Conclusion: the poison
    chain is STRUCTURALLY CLOSED for stock/oracle-free/persistent rung
    5 after ~300 fresh processes today. The earlier low-byte tcache
    retarget negatives were run under the WRONG class model — glibc
    tcache covers only <=0x420, so the small classes DO have tcache.
    Named next: redo the tcache-poison consumer on a <=0x410 class with
    the corrected model and the measured arena-region-base reflection
    oracle (Stage-C-style readback of chosen bytes at a nominated
    address on the unmodified app). Stock rung 5 stays **NOT ACHIEVED**.

21. **Done this wake (2026-11-25, honeypot-parity arms): the pair-parity
    knob is a bounded negative for the grown-victim claim; the
    0x648 claim pops that do occur are benign exact-fits of merged
    value chunks, not the upcase victim.** Two 12-process arms at the
    exact poSAC wire geometry (reconstructed from the surviving
    `lab/build/evidence/stock-rails-poSAC.*.body` because its server
    logs were gone): plant `1527x40,1517x6,1521x3,1529x1`, filler
    `400x200`, claim
    `1599@0x610:0x815,1599@0x620:0x815,1599@0x61f:0x815,1607@0x618:0x825`,
    probe `1527x5,1535x1`, churn `400x20`, N=1500, grown `0x650`,
    next `0x90`, `RAILS_MAX_THREADS=1`; only `HONEYPOT_SPEC` changed
    (`1527x3` vs `1527x5`, baseline `1527x4`). Driver:
    `lab/repro/ruby2shell-shrink-claim.sh`; raw logs/summaries
    `lab/build/evidence/{poPAC3,poPAC5}.run.txt` and
    `stock-rails-poPAC{3,5}.summary`; tabulations
    `lab/build/evidence/poPAC{3,5}.tab.txt` via
    `ruby2shell-sweep-order.py --plant-spec
    1527x40,1517x6,1521x3,1529x1`.
    - Survival (full `attack=404 claim=404 probe=404 up=200
      alive=YES`): poPAC3 8/12, poPAC5 7/12, baseline poSAC 6/12 —
      no parity-driven step change; all arms retain the stochastic
      ~50-65% survival seen with sacrificial shields.
    - `0x648` claim pops of planted addresses: poPAC3 1 (run 9),
      poPAC5 3 (runs 2 and 4); each pop address was a MERGED VALUE
      chunk (original plant `0x800` value, freed `0x815`, then `C`
      `0x9e0`/`0xc00`/`0xed0`), never the B snapshot's grown victim
      (e.g. poPAC3-9 B victim `0x7d8bdcc23af0 size=0x25` grew to
      `0x53`, while the pop address was `0x7d8bdca49310`). The
      0x648 allocation exact-fits a re-binned split front; no chosen
      byte crossed into a live value and the process survived in
      poPAC3-9 and poPAC5-2.
    - Both arms show 12/12 growth at the A snapshot and 0/12
      address-matched pre-B frees of the B victim; aborts 4/12
      (poPAC3) and 5/12 (poPAC5), mostly `corrupted size vs.
      prev_size`, plus one value-adjacent `0x815->0x853` family
      (poPAC3-10). Conclusion: neither honeypot parity nor the
      0x648 pops reopen the grown-victim claim path; the exact-fit
      claim pop of the grown victim itself remains UNOBSERVED and
      item 20's structural closure stands. Boundary unchanged:
      no command, no persistence, no grade change.

22. **Done this wake (2026-11-25, corrected-model tcache consumer): the
    corrected class model restores the tcache consumer but not the stock
    chain.** The named experiment replayed the tcache poison on the class
    that genuinely has glibc tcache (<=0x420) with both threads and their
    no-overflow controls, loopback only, analysis instrumentation only:
    - `bash lab/repro/ruby2shell-stageC.sh` (`stageC-correctedmodel-
      20261125.run.txt`): 5/5 attack runs `verdict=poisoned` with an mtrace
      `M … 3e9 <target>` pop at the forged target; 3/3 controls
      `verdict=clean`, `NO-ABORT`, zero pop at target.
    - `bash lab/repro/ruby2shell-stageC-http.sh 3 2`
      (`stageC-http-correctedmodel-20261125.run.txt`): 3/3 request-thread
      attacks returned HTTP 200 with
      `F-readback-hex=7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a` (16 chosen bytes
      at the nominated address), `f-pre=4646…` unchanged, forged-size
      field intact, and a pop line at the nominated target; 2/2 controls
      clean, alive. All three attack processes ABORTED at teardown
      (`alive=NO`) — the known harness-condition fingerprint, not a
      wire-only success. Grade unchanged.
    - Why this does not reopen stock rung 5: Stage C needs four things the
      unmodified app does not supply together — (a) a tcache-member chunk
      physically adjacent to the grown victim (`[V][T tcache][A
      tcache]`), (b) an 8-byte marker overlap that reaches T's
      safe-linked `next` field, (c) a fake `malloc_usable_size`-safe
      header at the nominated target, and (d) both forged qwords computed
      in-request. The wire-only reflection oracle does supply the arena
      region base, hence the tcache key, but the consH-20 one-byte
      overflow writes `0x53` onto the victim *size* field (q38 never
      `0x251` in the 144-process retarget batch), not onto a tcache
      `next`. A corrected class alone therefore cannot steer a stock
      claim: the missing ingredient is a wire geometry that puts a
      tcache-class neighbor under an 8-byte chosen-byte overlap, not the
      consumer itself. Stock/oracle-free/persistent rung 5 stays **NOT
      ACHIEVED**.
    - Named next: parameterize Stage C across the tcache cutoff (0x400 /
      0x410 vs 0x430 victim) and record the class boundary with bytes,
      then search the stock multipart geometry for a tcache-class
      neighbor plus an 8-byte overlap; control pairs stay mandatory.

23. **Fresh stock reflection-classification batch — bounded NEGATIVE for a
    wire-nominated tcache target (2026-11-25, this wake).** Twelve fresh
    `rails new --minimal` processes, unmodified app, loopback only, replaying
    the saved consH20-tail/stage2d wire body with the 4-page case-probe
    preload (`RUBY2SHELL_LEAKCLASS_COUNT=12 bash
    lab/repro/ruby2shell-stock-leakclass.sh`; the driver's tag is hardcoded
    `leakclass-`, so `RUBY2SHELL_LEAKCLASS_TAG` has no effect). Tabulations:
    `lab/repro/ruby2shell-cons-vis-tabulate.py leakclass` and
    `ruby2shell-{reflect-scan,leak-maps}.py leakclass-`.
    - 12 runs: 1 real expansion (leakclass-4, B `0xc31` → A `0xc53`),
      2 with second-buffer consumption at the victim (leakclass-4,
      leakclass-11), **0** with `q38=0x251` (the tcache-`next` byte never
      landed), **0** window `P` allocations and **0** window `Q` frees.
    - Only one survivor had both a maps snapshot and a response
      (leakclass-11): `reflect-scan` reports 34 reflected parts with 0
      deviations and 0 pointer-shaped qwords; `leak-maps` reports no
      reflected pointers (victim in `[anon]`). No arena-region base, hence
      no tcache key, crossed the wire in this batch.
    - Combined with item 22: the corrected model restores the tcache
      consumer on a real tcache class, but on the unmodified app neither the
      8-byte `next` overlap nor the wire-nominated target is available in
      12 fresh processes. Grade unchanged; stock/oracle-free/persistent
      rung 5 remains **NOT ACHIEVED**.

24. **Stock small-class overlap search — bounded NEGATIVE, with the missing
    consumer geometry named (2026-11-25, direct session).** The analysis
    preload gained `MTRACE_CASE_WIDE=1` (P/Q coverage across the whole grown
    victim) and P lines now include `next`/`key`; the claim driver gained
    `RUBY2SHELL_CLAIM_{PLANT,DRAIN}_ROUTE` and `_METHOD`, allowing benign
    multipart plants to use `POST /up` plus `_method=GET` and avoid the dev
    404 render. Both changes were built and smoked (`plant=200`).
    - A 144-process wide consH-20 survey produced 13 survivors and 54 runs
      with window P/Q activity, but no attacker-shaped tcache `next` and no
      target pop. The one-byte write remained a size-field rewrite.
    - The final `rb_str_new` copy is a second possible overlap writer, not
      just the second mapping buffer. Geometry enumeration gives N=1036 /
      victim `0x801→0x851` / final `0x820`, and N=1052 /
      `0x815→0x853` / final `0x840`, where the final copy can cross the
      physical successor. Planted arms did not produce the required FREE
      victim: `n1036av2` never showed B `0x801`; one N=1052 run
      (`svbatch2-14`) showed B `0x815→0x853` with live `P`-filled fd/bk, but
      the final `0x834` allocation went elsewhere and the process aborted.
    - A useful stock consumer was then observed directly:
      `n524p400full-1` (N=524, plant `1000x80`, filler `400x400`) shows B
      `0x405→0x453`, a later `M 0 3f8 <victim>` / C-at-victim, and a real
      physical successor at victim+`0x400` with P/Q activity. This proves a
      later request can consume the corrupted small-class chunk. It does
      **not** yet poison tcache: a same-bin request is bounded by the
      original physical extent, so its chosen bytes stop before the
      successor's `next`. The useful overshoot requires the victim to enter
      unsorted (tcache saturation) and a LARGER request to split the
      corrupted extent.
    - Routed plants and tiny (`1x2000`) pressure improved placement but not
      the required state: `n972routed` put both buffer1 and victim at planted
      slice addresses, while `n972clean`/`n972smallplant` put buffer1 on a
      planted slice but the victim in a consolidated giant. No command,
      persistence or grade change; stock/oracle-free/persistent rung 5 stays
      **NOT ACHIEVED**.
    - Named next: saturate tcache `0x400` with seven dummy chunks, route a
      four-part `1000` plant through `/up` with `_method=GET`, use tiny
      pressure, and attack at N=972. The payoff is adjacent
      `[A 0x400][V 0x400 unsorted→0x450][T 0x410 tcache]`, followed by a
      `0x420` claim (content 1039) whose chosen bytes cross V's physical
      end into T's `next`. Observe P `next`/`key`; controls stay mandatory.

25. **Tcache-saturation follow-up — bounded NEGATIVE; boundary forge repaired
    (2026-11-25, same direct session).** The item-24 recipe was exercised with
    routed drains/plants and tiny pressure. `n972sat` (drain `1000x4`, plant
    `1000x4`, 22 completed summaries before the 300 s tool timeout) produced
    five B `0x411` victims, all with successor size `0x404`, but zero C-at-
    victim and zero window P. `n972sat410` (drain `1000x7` to fill both
    `0x400` slices and `0x410` values, 12/12) produced one full-sequence
    survivor, `n972sat410-11`: true B `0x405→0x453`, followed by repeated
    false probe matches as later `0x3f8` requests reused the same victim, but
    no `0x418` claim at that victim and no poisoned `next`. The claim head
    `0x4141…/0x4242…` appeared only in a different later chunk. No command,
    persistence or grade change.
    - The driver's per-part forge now clips `next`/`key` writes at the exact
      content boundary instead of shifting `base` or extending the bytearray.
      Smoke: content 1039 stays 1039 bytes; offset `0x3f8` is size `0x411`,
      offset `0x400` is `next=0x4141414141414141`, and exactly seven key bytes
      fit. `bash -n` passes.
    - Escaped multipart disposition names were then tested directly
      (`escaped-name`, `escaped-sweep`, full M streams): no parser allocation
      of request `0x238` appeared before a `0x3f1` slice. The many descending
      `0x25b…0x220` M lines were dev-render prettyprint traffic, not a wire
      primer. This closes the escaped-disposition lever.
    - Named next: use one full-trace routed run to enumerate the actual free
      order and physical neighbors of the eight `1000`-part slices/values,
      then choose dummy/plant counts that leave the single unsorted V
      immediately after the tcache A. Do not rerun the closed count or
      escaped-name arms unchanged.

26. **Full free-order map of routed `1000`-byte plants — geometry measured,
    immediate payoff still NEGATIVE (2026-11-25, this wake).** The named
    experiment was one full-trace process at N=972 with drain `1000x7` and
    plant `1000x4` both routed through `GET /up`, filler `1x1200`, claim
    `1039@0x400:0x411,1015`, 20 benign `400x20` churn requests, one thread:
    tag `n972map2`, log `lab/build/evidence/stock-rails-n972map2-1.server.log`
    (483,759 lines, M=173146, F=223762, D=5499).
    - A tracer regression was found and repaired first: commit `c7beffe5`
      dropped `free_dump = getenv("MTRACE_FREE_DUMP")` while adding
      `case_wide`, so `MTRACE_FREE_DUMP=1` silently emitted no D lines
      (`n972map`, 463,477-line log, D=0). The line is restored in
      `lab/preload/mtrace.c`; the tracer is rebuilt with the documented
      `gcc -shared -fPIC -O2 lab/preload/mtrace.c -o lab/preload/mtrace.so`.
      D lines print the chunk's user qwords immediately BEFORE free, so they
      carry content patterns, not post-free tcache links; tcache vs unsorted
      is read from free rank and later reuse, not from D directly.
    - `lab/repro/ruby2shell-freeorder-map.py` tabulates the trace into
      `lab/build/evidence/n972map2.freeorder.txt`: all 22 slice allocations
      (`0x3f1` requests, `0x400`-class chunks) and 11 value allocations
      (`0x400` requests, `0x410`-class chunks) appear, split 14+7 drain and
      8+4 plant. Drain frees run 113586..113626, plant frees 113994..114017;
      both classes free last-allocated-first, so tcache capacity 7 puts drain
      slices ranks 1-7 in tcache and ranks 8-14 in unsorted, while all four
      plant values fit tcache `0x410`.
    - Physical successors of the eight planted slices were measured. Three
      slices sit immediately before a planted value (`0x945f40→0x946340`,
      `0x946be0→0x946fe0`, `0x947970→0x947d70`), i.e. the wanted
      `[V 0x400][T 0x410]` adjacency exists. But two of those slices were
      consumed before the attack by the churn requests (`0x946bf0` reused at
      L115269 as request `0x78d`; `0x947980` at L132698 as `0xa7e`), and the
      attack's `0x3f8` mapping buffer allocated fresh at `0x7f7520c00b60`
      (L430945), not on any planted slice. Its physical neighbor was `0x35`,
      so the upcase wrote `0x53` onto a small in-use chunk (B L467634 `0x35`
      → A L467637 `0x53`) and the process aborted with
      `munmap_chunk(): invalid pointer`: `drain=200 plant=200 attack=000`,
      zero claim pops at the victim.
    - Interpretation: the blocker is not adjacency but tcache depth. The 20
      post-plant churn requests free/reuse `0x400`-class chunks after the
      plant, leaving a render chunk at the head of tcache `0x400` when the
      attack parses. Plant chunks are already free before churn (113994..
      114017), so churn is not needed to release them. Named next: rerun the
      same full-trace geometry with `RUBY2SHELL_CLAIM_CHURN=0`, and check
      whether the attack's `0x3f8` buffer lands on a planted slice whose
      physical successor is a planted `0x410` value. No command, persistence
      or grade change: stock/oracle-free/persistent rung 5 stays
      **NOT ACHIEVED**.

27. **Churn-free arm — bounded NEGATIVE on tcache depth (2026-11-25, same
    wake).** The item-26 prediction was tested directly: identical full-trace
    geometry with `RUBY2SHELL_CLAIM_CHURN=0` (no 20 post-plant churn requests),
    tag `n972nochurn`, log `lab/build/evidence/stock-rails-n972nochurn-1.server.log`
    (203,951 lines, M=70205, F=103339, D=3546; tabulation
    `lab/build/evidence/n972nochurn.freeorder.txt`). The process survived all
    requests (`drain=200 plant=200 attack=404 claim=404 probe=404 up=200
    alive=YES`) and the upcase still expanded a small chunk
    (B L171136 size `0x95` → A `0x1253`), but the attack's `0x3f8` mapping
    buffer allocated at `0x7b336c722ff0` (M L171138) — that chunk was freed
    earlier in the SAME attack request (F L63899, sizefield `0x405`), not on
    any planted slice (plant slices live at `0x7b336c970b60`..`0x7b336c9737c0`).
    The 1,200 tiny filler parts themselves recycle `0x400`-class chunks ahead
    of the upcase, so removing churn does not put a plant slice at tcache
    `0x400` head. No claim/pop at a planted address, no command or grade
    change. This closes the churn-count lever; the next arm must change the
    attack body's own part sizes or ordering so the mapping buffer is the
    tcache head over a planted slice.

28. **Thread attribution and live tcache head — same-thread result, planted
    slice REACHED by the upcase, successor still wrong (2026-11-25, this
    wake).** The named experiment took the "same tid" branch of item 27.
    `lab/preload/mtrace.c` gained an opt-in `MTRACE_TID=1` field on M/F/C/R/D
    lines (no field without the env, so all earlier traces stay parseable);
    rebuilt with `gcc -shared -fPIC -O2 lab/preload/mtrace.c -o
    lab/preload/mtrace.so`. Eight fresh N=972 full-trace processes reused the
    exact `n972nochurn` wire bodies (drain `1000x7` and plant `1000x4` routed
    `GET /up`, filler `1x1200`, claim `1039@0x400:0x411,1015`, CHURN=0,
    `RAILS_MAX_THREADS=1`, `MTRACE_FREE_DUMP=1`, `MTRACE_TID=1`), tags
    `n972tid4-1..8`; logs under `lab/build/evidence/`.
    - Seven processes survived (`drain=200 plant=200 attack=404 ... up=200
      alive=YES`). In `stock-rails-n972tid4-3.server.log` (205,024 lines) all
      22 planted `0x3f1` slice allocations, all 22 of their frees, the last
      `0x400`-class free before the upcase (L168061), and the `0x3f8` upcase
      allocation (L171242) all carry tid `2783247`. The 271 boot-era D lines
      of size `0x411` carry the main-thread tid `2777216`; no request-path
      free is on a different thread. Thread attribution is CLOSED: forcing
      old-gen frees onto the request thread would not change this arm.
    - A `MTRACE_DUMP_BINS=1` replay (`n972tidb-1..4`) was unusable: all four
      processes returned `attack=000` with no B snapshot and no L lines;
      preserved as a bounded negative, not retried unchanged.
    - The live-tcache probe `MTRACE_DUMP_TCACHE=1` (same wire geometry, tags
      `n972tc-1..4`) read the real tcache at the B snapshot. In
      `stock-rails-n972tc-3.server.log` tcache bin 62 (`0x400`) held five
      planted-size slices; head `0x7b0d2c9e5b10` was a planted slice freed at
      L76757. The upcase's `0x3f8` mapping buffer at L183068 was **another
      planted slice**, `0x7b0d2c9e5f10` (allocated L17091, freed L76759) —
      the one LIFO rank newer than the head, exactly the "later-freed wins"
      prediction. The earlier-freed slice stayed at the head after the pop.
    - Payoff still blocked: the popped slice's physical successor
      `0x7b0d2c9e6310` had been reused as a `0x35` chunk by B time (it had
      freed as `0x415` at L161423); the upcase wrote `0x53` onto it
      (H/A lines), then `munmap_chunk(): invalid pointer` aborted with
      `attack=000`. No claim pop, no command, no grade change. Stock/oracle-
      free/persistent rung 5 stays **NOT ACHIEVED**; the blocker is now the
      successor's identity at B time, not thread attribution or tcache depth.
    - Named next: keep the tcache-head arm and vary only the plant geometry so
      the slice the upcase pops has a *live planted 0x410 value* as its
      physical successor at B (candidate: pair-edge slices whose value was
      not consumed by the 1,200-part filler); verify with `S`/`E` lines and
      the B physical pointer before spending on claim forging. Safe/fixed
      controls remain mandatory for any impact claim.
29. **Corrected plant identity, live tcache/occupancy measurement, and the
    stock-Sinatra A/V/T geometry — bounded NEGATIVE at the claim (2026-11-25,
    this wake).** No command, persistence or grade change; stock/oracle-free/
    persistent rung 5 stays **NOT ACHIEVED**.
    - `lab/repro/ruby2shell-freeorder-map.py` was fixed to classify a chunk by
      its pre-free D qwords (`0x6464…` drain, `0x7070…` plant) instead of by
      allocation rank. The old split-by-rank table mixed drain traffic into the
      plant phase; item 28's identification of `n972tc-3`'s tcache head and
      upcase buffer as planted slices is therefore **retracted** — those rows
      carry drain bytes. The corrected table for the same log puts the real
      plant chunks at `0x7b0d2ca86…`/`0x7b0d2ca87…`, not at `0x7b0d2c9e5…`.
    - `lab/preload/mtrace.c` gained opt-in direct reads of the request thread's
      glibc tcache struct (`MTRACE_DUMP_TCACHE=1`, `S`/`E` lines for bins 61–63),
      pre-free occupancy at plant/drain chunks (`MTRACE_TCACHE_FREE_DUMP=1`,
      `Y` lines), a fastbin walk (`MTRACE_DUMP_FASTBINS=1`, `N` lines), and
      bin dumps at a chosen request size (`MTRACE_DUMP_REQUEST=0x43f` plus
      `MTRACE_DUMP_BINS=1`, `L` lines). The real tcache cutoff on this host is
      `0x410` (bin 63); `0x420` is not tcache-managed. At B, fastbins were
      empty in the sampled runs.
    - Rails occupancy is a hard blocker at the value class: with drain
      `1000x7`, tcache bin 63 is already full (7) before the first planted
      `0x410` value is freed, so every planted value enters unsorted. Adding
      live `1000`-byte consumers before the filler and moving `_method` before
      the filler did not change that occupancy in the measured runs.
    - `lab/repro/ruby2shell-shrink-claim.sh` now supports
      `RUBY2SHELL_CLAIM_STACK=sinatra` (stock classic Sinatra app, same body
      builder and evidence format), plus `CONSUMER_SPEC` and `METHOD_FIRST`
      analysis knobs. Stock Sinatra has no dev-param render and puts the four
      planted values in bin 63. With `N=972`, drain `984x7`, plant `1000x6`,
      filler `1x1200`, `CHURN=0`, `POISON_NEXT=0x91`, claim content 1078 at
      `0x400:0x414`, the B snapshot in `stock-sinatra-allbin-1.server.log`
      shows the exact wanted state: buffer1 is a planted `0x400` slice, its
      physical successor V is a planted `0x401` unsorted chunk grown to
      `0x453`, and the next physical chunk T is a planted `0x414` tcache
      entry. The upcase's second `0x3e2` mapping buffer was served from the
      `0x3f0` shield head, so V survived the immediate splitter.
    - The payoff still fails: the later `0x43f` claim request allocated at
      `0x7fdb0402bba0`, not at V, and the all-bin dump immediately before it
      no longer showed V in unsorted. The probe then popped T and printed
      `P request=0x401 … key=0` with the old `fd`, not the claim's forged
      `0x4141…` bytes. Fastbins were empty, so the leading hypothesis is the
      large-request `malloc_consolidate` path consuming/rebinning V before the
      smallbin/largebin lookup; it is not yet byte-confirmed. No claim pop,
      no chosen-byte write at T's `next`, no command, no persistence.
    - Veria's page is unchanged (stamp 21 Nov 03:52Z, PoC still unpublished);
      the independent public `evenomn/CVE-2026-132825` repository documents
      local crash/corruption only and explicitly no remote delivery path.
      Named next: identify the exact post-upcase large allocation that removes
      V (dump bins at `0xc00` and other intermediate large requests in the
      same geometry), then shield that class before repeating the claim.

### Named "what removes V" arm: exact stock-Sinatra A/V/T reached; V still
### binned at the last pre-claim dump; claim allocation still misses
### (2026-11-25, twentieth-plus push)

The wall's named experiment was rerun on stock Sinatra with the exact
geometry from item 29 (`N=972`, drain `984x7`, plant `1000x6`, filler
`1x1200`, `CHURN=0`, one thread, `POISON_NEXT=0x91`,
`MTRACE_DUMP_TCACHE=1`, `RUBY2SHELL_CLAIM_BINDUMPS=1`,
`MTRACE_DUMP_REQUEST=0xc00`). Evidence: `stock-sinatra-victimstep-*.server.log`,
`stock-sinatra-victimstep.summary`. A concurrent same-role process used the
same tag with `COUNT=6`; the logs and summary hold six runs from both
invocations, so tag `victimstep` is not a clean single-process sample.

Run 6 (`stock-sinatra-victimstep-6.server.log`) reproduces the exact state:
```
43977:B ... victim=0x78ce8c0a6740 size=0x401 ... physical=0x78ce8c0a6b30
       physical_prev=0x400 physical_size=0x414
44004:A ... victim=0x78ce8c0a6740 size=0x453 ...
44006:L 0 1 78ce8c0a6730 453
44272:L 0 1 78ce8c0a6730 453
44424:L 0 1 78ce8c0a6730 453
44940:M 0 43f 78ce8c02cee0 0
44943:M 0 43f 78ce8c0695e0 0
```
The `L 0 1` lines are the worker arena's unsorted bin: the grown V is still
there at the last `0xc00`-triggered dump (44424), 516 lines before the
claim's first `0x43f` allocation. Those exact-fit claim allocations take
other chunks. The probe eventually pops the planted successor T:
`P tid=3575983 request=0x401 ptr=0x78ce8c0a6b40 size=0x414
next=0x78c900e2b7f6 key=0` — its old `fd` and `key=0`, not the claim's
forged bytes — and the process aborts with `corrupted size vs. prev_size`.

Boundary: in this run no observed M/F line between A and the claim names V;
the interval 44424..44940 was not dumping at the claim size, so the exact
consumer that stops the `0x43f` request from taking V stays UNKNOWN. The
earlier `stock-sinatra-allbin-1` trace is different (V absent from all its
pre-claim `L` dumps). Next arm repeats with `MTRACE_DUMP_REQUEST=0x43f` and
`MTRACE_TID=1` under tag `vstepfine` to place a bin dump immediately before
each claim-size allocation and to label threads. No command, no persistence,
grade unchanged.

### B/A/claim bin dumps identify the real claim blocker: a competing exact-fit
### 0x450-class chunk, not removal of V (2026-11-25, this wake)

`lab/preload/mtrace.c` now emits a bin dump immediately after the B snapshot
when `MTRACE_DUMP_BINS=1` (new `L` group between B and its `M` line), so the
same trace shows V's bin at B, at A and immediately before each claim-size
malloc. Rebuild: `gcc -shared -fPIC -O2 lab/preload/mtrace.c -o
lab/preload/mtrace.so` (atomic rename; `mtrace.so` is untracked).

Exact-geometry arm (`N=972`, drain `984x7`, plant `1000x6`, filler `1x1200`,
`CHURN=0`, `POISON_NEXT=0x91`, `MTRACE_DUMP_REQUEST=0x43f`, `MTRACE_TID=1`,
tag `vstepfine2`) produced three exact A/V/T processes. In run 2
(`stock-sinatra-vstepfine2-2.server.log`) V was already absent from the A
dump; in run 3 (`stock-sinatra-vstepfine2-3.server.log`) V is present and
grown, and every dump including the two immediately before the claim shows
it:
```
43987:B ... victim=0x730a8c0a5bb0 size=0x401 ... physical_size=0x414
44013:L 0 1 730a8c0a5ba0 401 3719069        (B bin dump)
44118:A ... victim=0x730a8c0a5bb0 size=0x453
44120:L 0 1 730a8c0a5ba0 453 3719069        (A bin dump)
44833:L 0 1 730a8c0a5ba0 453 3719069        (pre-claim dump)
44927:M 0 43f 730a8c0776b0 0 3719069        (claim allocation)
```
The bin dump at 44834 also contains `L 0 2 730a8c0776a0 451`: a *different*
0x450-class exact-fit chunk. The claim's returned pointer `0x730a8c0776b0`
is that chunk's user address. V was never removed — the allocator preferred
an exact-fit chunk in the other 0x450 bin while V stayed in unsorted. This
revises item 29's "large-request malloc_consolidate removes V" hypothesis:
it fits some runs (`vstepfine2-2`, `allbin-1`) but is falsified as a universal
step by `vstepfine2-3`.

Arm `vstepB` (same geometry, B bin dumps enabled,
`stock-sinatra-vstepB-3.server.log`) independently reproduces the same
competition: `L 0 1 730a8c0a5ba0 401` at B, `453` at A and at both pre-claim
dumps, plus `L 0 2 730a8c0776a0 451`; the first `M 0 43f` again returns
`0x730a8c0776b0`, not V.

A bounded repair attempt consumed a 0x400-class part before `_method`
(`CONSUMER_SPEC=1078x1`, tag `vstepcons`, 4 processes). In the one exact
geometry survivor (`stock-sinatra-vstepcons-2.server.log`) the consumer's
allocation is `M 0 400 70e2ec07a520` (43997); V is unlinked at B, the
competing 0x450 chunk still occupies the other bin, and the claim still
returns `0x70e2ec06c3f0` / `0x70e2ec02bc50`, never V. Bounded NEGATIVE: this
consumer neither shields the competing class nor preserves V.

Next named experiment: consume the *specific* competing 0x450-class chunk
before the claim without taking V — the pre-claim `L 0 2` address identifies
it — or arrange V to be the first-binned chunk of that bin. Safe/fixed
controls remain mandatory for any impact claim. No command, no persistence,
grade unchanged.

### Stock-Sinatra claim sweep: keep-alive, bin-class and forge levers all
### bounded NEGATIVE (2026-11-25, direct session, twenty-first push)

About 60 fresh loopback processes on the unmodified stock Sinatra app,
analysis instrumentation only. New tooling:
`lab/repro/ruby2shell-keepalive-post.py` sends the whole chain on ONE TCP
connection; `lab/repro/ruby2shell-shrink-claim.sh` gained
`RUBY2SHELL_CLAIM_KEEPALIVE=1`. `lab/preload/mtrace.c` gained opt-in
`MTRACE_LARGEBIN_DETAIL=1` (`D2` lines: bin head and V's fd/bk/nextsize
links immediately before a chosen request size); rebuilt with
`gcc -shared -fPIC -O2 lab/preload/mtrace.c -o lab/preload/mtrace.so`.

- `stock-sinatra-victimstep-6`: V's header `0x78ce8c0a6730` was in unsorted
  at A (`size=0x453`) and at both `0xc00`-triggered dumps, 516 lines before
  the claim's two `0x43f` allocations; those allocations returned other
  chunks. Probe popped T with its old `fd` and `key=0`; process aborted.
  "V removed by a large allocation" is therefore not universal.
- `stock-sinatra-claimdump-2`: V (`0x7a7a500a5310`, `size=0x453`) was the
  ONLY unsorted chunk immediately before both `0x43f` allocations
  (`L 0 1 ... 453` at lines 44713 and 44811), yet malloc returned
  `0x7a7a500eb840` / `0x7a7a5001888c0`.
- `stock-sinatra-tidsplit-2` with `MTRACE_TID=1`: B, A and both `0x43f`
  allocations all carry tid `3881676`; the thread/arena split does not
  explain that arm. Its V was already absent from unsorted at A, so the
  exact A/V/T state is geometry-dependent between processes.
- `kachain` (one connection, six processes): runs 2 and 5 reproduce B
  `0x401` → A `0x453` with the same tid across all requests; at both claim
  dumps V is listed in bin `0x40`, and neither claim nor probe takes it
  with chosen bytes. One-connection pacing alone is not the blocker.
- glibc 2.39 source (`lab/build/glibc-2.39-src/malloc.c`) constrains the
  mechanics: tcache covers `nb <= 0x410`, so a `0x401` claim is served from
  tcache bin 63; `largebin_index_64(0x430)` is 64 and
  `largebin_index_64(0x450)` is 65; the unsorted loop checks
  `prev_inuse(next)` before exact fit (line 4087); `unlink_chunk` checks
  `chunksize(p) == prev_size(next_chunk(p))` (line 1610).
- `bin40claim` (claim `0x401`): V sat in bin `0x40` at claim in the exact
  geometry, but both claim allocations came from tcache bin 63.
  `bin40split` (claim `0x421`, `nb=0x430`, bin 64, forge at content offset
  `0x410`): three exact-geometry survivors (`bin40split-{3,6,7}`) still
  showed V in bin `0x40` at both pre-claim dumps and never returned it.
- `prevclear` (`POISON_NEXT=0x90` clears the neighbour's PREV_INUSE, removing
  the `invalid next->prev_inuse (unsorted)` abort seen with `0x91`): in
  `prevclear-7` V was consumed by a framework `calloc` request `0x3c0`, and
  T's tcache entry was corrupted with framework bytes
  (`P request=0x401 ptr=...a4090 size=0x35 next=0x4b key=0`), ending in
  `malloc(): unaligned tcache chunk detected`. No chosen claim byte crossed
  into T.
- `inchain` (`ATTACK_CHAIN=1`, claim parts appended after `_method`): the
  exact-geometry run aborted in the attack's unsorted scan before any
  `0x43f` claim allocation; no in-request pop.
- `prevclear430` (`POISON_NEXT=0x90` + `0x430` claim): exact run 2 had V in
  bin `0x40` at claim and the claim allocated elsewhere; T was corrupted by
  framework traffic, not by the claim.
- `linkdiag` (`MTRACE_LARGEBIN_DETAIL=1`): exact runs 2 and 6 show stale
  links — run 2's V has `vsize=0x453`, `vfd=0x77b014000480` (the unsorted
  head), `vbk=0x77b014086bb0`, `vfdnext=vbknext=0x77b014087d00`, while the
  bin-`0x40` head is self-linked; run 6's V had already been downgraded to
  `0x3d5`. A chosen-byte write into T was never observed.

Verdict: stock/oracle-free/persistent rung 5 remains **NOT ACHIEVED**. No
command, no chosen-byte write, no surviving second command; the witness-
ESTABLISHED harness-condition rung 5 and rung 4 grades are unchanged.
The remaining UNKNOWN is the exact bin-transition that keeps a grown V
unavailable to a matching claim; the new `D2` trace constrains it but does
not resolve it. Next: replay `MTRACE_LARGEBIN_DETAIL=1` at
`MTRACE_DUMP_REQUEST=0x43f` (rather than `0x421`) with `POISON_NEXT=0x90` and
compare V's links with the bin-`0x41` head at the exact-fit claim; only a
measured pop at V justifies another impact arm. Safe/fixed controls remain
mandatory for any impact claim.

- `d2exact` (`MTRACE_DUMP_REQUEST=0x43f`, `POISON_NEXT=0x90`, one connection,
  eight processes) ran the wall's named follow-up. Four runs reached
  `0x401/0x411 → 0x453`; none returned V to the `0x43f` claim. In
  `stock-sinatra-d2exact-1.server.log` the claim-time `D2` reads
  `vsize=0x450 vfd=0x79c1bc000480 vbk=0x79c1bc072e60
  vfdnext=vbknext=0`, while the bin head `0x79c1bc000880` is self-linked at
  `0x79c1bc000870`: V's size grew after it was linked, so its bin identity
  is stale and the claim's bin-`0x41` search cannot see it. The tabulator
  initially reported one false `claim 1` for that run: a boot-era
  `M 0 400 79c1bc08a7e0` at line 16118, long before the B snapshot at
  41797. `lab/repro/ruby2shell-shrink-claim.sh` now counts pops only after
  the last B line; re-checking the log yields zero post-B claim-size hits
  at V. No chosen-byte write, no command, no persistence; grade unchanged.
  Next: emit `D2` at every post-A malloc in `0x400..0x460` to catch the
  exact unlink/rebin transition of V, then forge only that transition.

### D2 range dumps expose a wrong-arena bin view — exact-fit claim still NEGATIVE (2026-11-25, twenty-second push)

The named experiment extended `D2` to every post-A malloc in `0x400..0x460`
(`MTRACE_DUMP_RANGE=1`, `lab/repro/ruby2shell-vtransition.py`), twice with
eight fresh stock-Sinatra processes (`vtransition2`, `vtransition3`),
one connection, geometry identical to `d2exact` (body SHA256 prefixes
`attack 92a21cc4a514`, `plant f00612ae80df`, `claim fc4e8ed6412f`,
`N=972`, drain `984x7`, plant `1000x6`, filler `1x1200`, claim
`1078@0x400:0x414,1015`, `POISON_GROWN=0x450`, `POISON_NEXT=0x90`).
Tabulations: `lab/build/evidence/vtransition{2,3}.states.txt`, summaries and
logs alongside them.

- V's own header fields changed in some runs at the claim: `vtransition3-7`
  `vsize 0x450→0x3d0`, `vfd=0x26 vbk=0`; `vtransition3-4` likewise;
  `vtransition3-8` `vbk 0x...7bfd0→0x...530` after the claim. No `0x43f`
  claim returned V in any of the sixteen processes. Survivors
  `vtransition2` 3/8, `vtransition3` 0/8 (one boot-fail each): stochastic.
- **Instrumentation correction.** The old `bin_detail` read bin heads at
  `current_tcache()-0x460`, but a per-thread tcache can belong to a different
  arena than V: `vtransition4-3` has V's unsorted head at `0x75aca8000480`
  but the D2 bin head at `0x75ac9c000480`; `vtransition5-8` with
  `RAILS_MAX_THREADS=1` has V at `0x7d08cc..` but the D2 bin head at
  `0x7d08c0..`. The self-linked "bin head" and the garbage-looking
  `binfd/binbk` values in `d2exact`, `linkdiag` and `vtransition3` therefore
  describe the WRONG arena. The earlier conclusion that V's bin identity is
  stale because its links point into a self-linked head is **retracted as
  instrumentation evidence**; V's freshly read `vsize/vfd/vbk` fields remain
  valid. `lab/preload/mtrace.c` now derives the bin head from V's own `fd`
  at B, uses the rounded malloc chunk size for the bin index, and
  `build-mtrace.sh` builds `mtrace.so` atomically.
- `vtransition4` (corrected size rounding, still wrong arena) and
  `vtransition5` (one thread, still wrong arena), eight processes each,
  confirmed the grade: no `0x43f` claim pop. Both produced one new
  observation: an exact-geometry `0x400` claim DID pop V three times
  (`vtransition4-3`, `vtransition5-8`, both survivors). In
  `stock-sinatra-vtransition4-3.server.log`, V `0x75aca8073ea0` goes
  `0x401→0x453` at A (line 43995), is allocated by `M 0 400` at line 44603,
  then shows attacker-pattern qwords (`q0=0x4141414141414141`,
  `q8=0x4242424242424242`, `q10=0x5a5a5a5a5a5a5a5a`) at line 45197, frees
  at line 45199 with sizefield `0x415`, and is allocated again by
  `M 0 400` at line 45326. Those bytes are the attacker's own multipart
  content in a buffer that reused V after the overflow — an ordinary
  allocator reuse, NOT a chosen-pointer write into a live object's metadata.
  No command, no persistence; rung 4 and harness-condition rung 5 grades
  unchanged, stock/oracle-free/persistent rung 5 remains NOT ACHIEVED.

`vtransition6` (eight processes, same one-thread geometry, now with V's own
`fd` as the bin head) is a bounded NEGATIVE: no `0x43f` claim returned V,
three processes survived, one boot-fail. Logs/summary
`lab/build/evidence/stock-sinatra-vtransition6-*` and
`vtransition6.{states.txt,run.txt}`. In `vtransition6-8` the bin reads now
land in V's arena (`0x772a5c000870` vs V `0x772a5c0a3f90`), confirming the
arena fix; V still went `0x401→0x453` and its `0x43f` claim allocated
`0x772a5c07adb0` instead. The D2 bin slot remains one entry off (a bin's
`fd` self-link reads at `bin-0x10`), so exact bin occupancy is UNKNOWN, not
a re-pinned "stale link" claim. `vtransition6-6` again shows chosen-pattern
bytes `0x5151...` in V's links after it was reused; no command or persistence.
Grade unchanged. Next: correct the bin-slot offset against glibc's
`bin_at()` definition, or abandon D2 bin occupancy as an oracle and test a
different consumer of the measured `0x400` overlap pop.

### Framework `0x3c0` consumer identified; production config gives a surviving `0x400` overlap pop but no command (2026-11-25, twenty-third push)

The D2 range gate was rerun on the exact `d2exact` geometry
(`vtransition2/3`, 16 fresh stock-Sinatra processes, one connection,
`N=972`, `POISON_NEXT=0x90`, claim `0x43f,0x400`), with the bin view corrected
to V's arena and request→chunk-size rounding. No `0x43f` claim returned V.
The transition is now pinned to a specific consumer in
`stock-sinatra-vtransition3-7.server.log`: V `0x74a4ec0a3f20` grows
`0x401→0x453` at A (line 43984); `C 0 3c0 74a4ec0a3f20` at line 44241 —
a framework `calloc` request `0x3c0` — allocates V *inside the attack
request*, before the claim POST (first POST completes line 44413). At the
claim D2 lines V reads `vsize=0x3d0 vfd=0x26 vbk=0`: the framework split it.
The exact-fit claim therefore never sees an intact grown V. A tcache
snapshot arm (`tcsnap`, 3 usable processes) found bin 61 full (7 entries),
bins 62/63 empty at B, so the upcase's own `0x410`-class buffer cannot
provide an unsorted shield via tcache overflow in this geometry.

A deployment-config arm removed that consumer. With `RACK_ENV=production`
and otherwise byte-identical wire inputs, `prodenv` (8 processes) and
`overlap1` (8 processes) produced two surviving instances where the growth
overlap was claimed:

- `stock-sinatra-prodenv-2.server.log`: B `size=0x415`, A `size=0x453`
  (physical next chunk at V+`0x400` was live, `sizefield=0x121`);
  `C tid=... request=0x400 ptr=0x70734c05f160 size=0x453` at line 46008 and
  `M 0 400 70734c05f160` at 46009: the claim's `0x400` allocation popped the
  corrupted V. The later D2 shows V's user qwords
  `0x4141414141414141 / 0x4242424242424242 / 0x5a5a…` — the claim part's
  own chosen bytes. All POSTs and `GET /up` returned 404/200 with the
  process alive. No `C 0 3c0` calloc appears anywhere in that log.
- `stock-sinatra-overlap1-1.server.log` reproduces the same family:
  B `0x415` → A `0x453`, `C tid request=0x400 ptr=0x74da1406fdd0 size=0x453`
  at line 46183, process alive after claim/probe/`/up`.

The mechanism by which production mode removes the `0x3c0` consumer is
UNKNOWN (candidate: the dev 404-page render); this is an association across
arms, not a controlled differential of only that variable. The write is
chosen bytes into the *popped free chunk's own user area*, not into a live
object's metadata: the claim's 0x400-byte write ends at V+0x3ff, while the
glibc-created 0x40 remainder header sits at V+0x400 and is glibc-written.
Three `0x43f` claim parts (`overlap3`, production config, 7 completed
processes) produced **zero** exact-fit `0x43f` pops; run 5 had the exact
`0x401→0x453` geometry and still missed, and one process hung to the tool
timeout. A repeated-claim arm therefore does not yield a full-extent chosen
write over the overwritten neighbor header.

Verdict: stock/oracle-free/persistent rung 5 remains **NOT ACHIEVED** — no
command, no chosen-byte write into a live object, no second distinct
command. The measured `0x400` pop plus process survival is a new rung-4-class
mechanic under a labeled `RACK_ENV=production` condition, not an impact
grade change. No safe/fixed control was run for these analysis arms; any
later impact claim needs the full control pair. Named next: test the `0x400`
pop without mtrace in the request path and whether a wire-shaped allocation
can consume the `0x40` remainder at V+`0x400`; otherwise close this lane as
bounded negative and open the jemalloc allocation lane noted by durendal.sh.

`remainder1` (production config, 8 processes, ten extra 40-byte claim parts,
`MTRACE_DUMP_RANGE_LOW=0x20` so the `0x31`-request allocations also emit D2)
is a bounded NEGATIVE for remainder consumption: zero `0x400` pops, one
survivor, and no allocation at the `0x40` remainder address (V+`0x400`)
after the pop window. The extra small parts change the request shape enough
that only one run reached a `0x43`-class growth (`0x431→0x453`, run 6) and
it still missed the claim. The D2 lower/upper bounds are now env-configurable
(`MTRACE_DUMP_RANGE_LOW`/`_HIGH`, default `0x400`/`0x460`).

`untrace1` checks the no-instrumentation condition: the same production-config
wire chain with `RUBY2SHELL_CLAIM_NO_MTRACE=1`, so the server starts with
no `LD_PRELOAD` and no `MTRACE_*` variable in its environment. Eight fresh
processes: 2/8 (`untrace1-6`, `untrace1-8`) served drain, plant, attack,
claim, probe and `/up` with 404/404/404/404/404/200 and stayed alive; 6/8
aborted (`corrupted size vs. prev_size` in five). Without the tracer the pop
is not directly observable, so survival is only consistent with, not proof
of, the measured `0x400` pop path. No command side effect exists in this
arm and no safe/fixed control was run; stock/oracle-free/persistent rung 5
remains NOT ACHIEVED. The remaining prerequisite for any full-rung-5 claim
is a wire-observable target action (a request-carried marker) driven by a
pop whose chosen bytes reach a live object's metadata, plus a code-pointer
source that does not use mtrace, ObjectSpace.dump, /proc/self/maps or a
debugger.