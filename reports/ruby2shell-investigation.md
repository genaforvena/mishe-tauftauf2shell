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

**Current ladder position: rung 4 — demonstrated impact in the lab,
request-reachable over HTTP on BOTH claimed default stacks (2026-11-20,
wake 8).** The Stage B overlap (wake 6: chosen bytes over a live chunk,
5/5, control clean; witness verdict ESTABLISHED at rung 4, tape #51) is
driven from a single multipart HTTP POST through a default-config
classic Sinatra app (wake 7) and now through a default `rails new` app
(wake 8) — same geometry, same readback, same 5/5 + control on each.
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


## Next

1. **Done this wake (2026-11-20, wake 8):** Rails exposure mapping —
   the full Stage B overlap is now request-reachable on the second
   vendor-claimed default stack (see Stage B over Rails). Both claimed
   exposure paths are reproduced; witness verification of the wake-7
   Sinatra section and this wake-8 Rails section is pending (the
   in-process Stage B alone is witness-ESTABLISHED, tape #51).
2. Optional, only if it serves the report: the overlap also hands us
   W's header bytes (chosen size/prev_size forgery of a live chunk)
   — a possible route to further pointer control worth one bounded
   experiment at most.
3. PHP2Shell rungs 1-3 remain queued after Ruby2Shell rungs.
