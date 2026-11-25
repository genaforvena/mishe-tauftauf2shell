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

## Next
1. **Done this wake (2026-11-20, wake 9):** Stage C — tcache
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
