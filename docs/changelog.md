# Dated research updates

Chronological log preserved verbatim from the former README "What it has achieved so far" section, including contradictions and negative results. Current scope and limits live in [docs/results.md](results.md); counts in the front page come from `research-manifest.json`.





## 2026-11-28 09:0xZ — Ruby W375 wire-confirms all 14 writable charsets

Replaced the three literal multipart `_method` charset shapes in
`lab/repro/ruby2shell-w371-wire.py` with one table of all 14 SHARP_s
single-byte encodings patched in ruby/ruby@d582f8f, then replayed the trace
and valgrind arms on loopback. All 14 tags reach `rack/method_override.rb:36`
as odd `upcase` operands on unmodified 3.4.12 Sinatra and full Rails; the 11
new tags each write one byte past a 66-byte block (11 writes / 1 read / 11
`case_map` frames per vulnerable app), while bootable patched Rails 3.4.13
stays 0/0/0. Prediction supported, falsifier not met. Still one stock caller,
no chosen address, marker or command: R4 COMPLETE, harness R5 ESTABLISHED,
full stock/oracle-free/persistent R5 NOT ACHIEVED.

## 2026-11-28 08:4xZ — Ruby W374 falsifies the single-encoding prediction

Commit added two opt-in multipart `_method` shapes (`charset=ISO-8859-15`,
`charset=windows-1252`) to `lab/repro/ruby2shell-w371-wire.py` plus the W374
report tail and matching task/reproducibility sections. On unmodified 3.4.12
Sinatra and full Rails the wire-tagged operands reach
`rack/method_override.rb:36` and valgrind observes one-byte heap writes in
`case_map iso_8859_15.c:267` and `case_map windows_1252.c:224` (0 bytes after
a 66-byte block), while bootable patched Rails 3.4.13 stays clean. The fix
changes the same guard in all 14 SHARP_s single-byte case maps; W373's
"only ISO-8859-1" was scoped to the tags it tested. No grade moved: R4
COMPLETE, harness R5 ESTABLISHED, full stock/oracle-free/persistent R5 NOT
ACHIEVED.

## 2026-11-28 08:2xZ — Ruby W373 closes the upcase encoding-tag matrix

Commit `c097903f` added five `upcase_*` modes to
`lab/repro/ruby2shell-rung3-utf8-tag.rb` and a 20-arm odd/clean matrix to
`lab/repro/ruby2shell-utf8-tag-matrix.sh`, plus the W373 report tail; the
author also updated the matching `docs/task.md` and
`docs/reproducibility.md` sections. This answers W372's named anomaly check:
across 3.4.12 / 3.4.13 × five tags × N=21 (odd) / N=20 (clean), exactly one
arm writes — ISO-8859-1-tagged raw 0xDF `upcase` on vulnerable 3.4.12 at
N=21, one invalid 1-byte write at `case_map (iso_8859_1.c:293)` via
`rb_str_upcase` and one copy-out read, 0 bytes after a 66-byte block. N=20
and all ten fixed 3.4.13 arms are clean. W372's mechanism claim is refined:
a UTF-8-tagged raw 0xDF operand raises `ArgumentError: input string invalid`
with no `case_map` frame, so it never reaches the fold. Docs replayed the
committed recipe on the pinned plain builds: syntax checks passed and all 40
valgrind arms returned rc 0 — 3.4.12 `latin_arg` N=27/43 and `upcase_latin`
N=21 each wrote once and read once, the last at `case_map (iso_8859_1.c:293)`
via `rb_str_casemap (string.c:7839)` / `rb_str_upcase (string.c:8017)`, 0 bytes
after a 66-byte block with output `A`+42 `S`; N=20, every other tag on both
builds and all ten 3.4.13 arms were 0/0, and UTF-8-invalid operands raised
`ArgumentError`. Raw logs stay gitignored under
`lab/build/evidence/casemap-chain/w373/`. Grade unchanged: one writable wire
fold, no chosen address, marker or command; no rung cell, count, manifest
entry or `established` flag moved. Recipe in `docs/reproducibility.md`
§08:2xZ.

## 2026-11-28 08:0xZ — Ruby W372 closes charset-tagged JSON/form bodies

Commit `d31e335c` added four `charset=ISO-8859-1` JSON/form request shapes with
raw 0xDF keys/values to `lab/repro/ruby2shell-w371-wire.py` and the W372 report
tail; the author also updated the matching `docs/task.md` and
`docs/reproducibility.md` sections. The report's all-fold traces logged 0 odd
operands on Sinatra (423 folds) and full Rails (2824 folds) for those shapes,
with 0 invalid writes / 0 reads / 0 `case_map` frames under valgrind; only the
opt-in controls reached odd `upcase` operands at `rack/method_override.rb:36`,
the urlencoded UTF-8-tagged one writing 0 bytes. Bootable patched 3.4.13 /
Rack 3.2.8 gave 0/0/0 with the same JSON-key parse 500; fixed Sinatra and
full-Rack 3.4.13 cannot boot, so their zeros stay UNTESTED. Docs did not replay
these arms here; they remain report observations with a pinned regeneration
recipe. Grade unchanged: one writable wire fold, no chosen address, marker or
command; no rung cell, count, manifest entry or `established` flag moved.
Recipe in `docs/reproducibility.md` §08:0xZ.

## 2026-11-28 07:4xZ — Ruby W371 closes remaining wire surfaces

Commit `ee9adc49` added `lab/repro/ruby2shell-w371-wire.py`, the W371 report
tail and the matching `docs/task.md` / `docs/reproducibility.md` sections. The
report's 12-surface sweep logged 540 folds on Sinatra with one odd operand —
the opt-in `_method` upcase at `rack/method_override.rb:36` — and four odd
operands on full Rails: three `downcase` calls on an ASCII-8BIT 0xDF
`Content-Type` at `mime_negotiation.rb:27` plus `_method`. Valgrind saw 0
invalid accesses and 0 `case_map` frames for those surfaces (ASCII-8BIT's
ASCII-only `case_map` at `enc/ascii.c:57` cannot expand 0xDF), while a
`_method`-only arm wrote once, so the harness was live; bootable patched
3.4.13 stayed clean and the two unbootable fixed builds stay UNTESTED. Docs
did not replay these arms here; they are report observations with a pinned
regeneration recipe. One wire fold per request, no chosen address, marker or
command; full stock/oracle-free/persistent R5 NOT ACHIEVED. Grade unchanged;
no rung cell, count, manifest entry or `established` flag moved. Recipe in
`docs/reproducibility.md` §07:4xZ.

## 2026-11-28 06:2xZ — Ruby W370 closes Rack boundary token and header tagging

Commit `d3bc12a4` added three `lab/repro/ruby2shell-w370-*` scripts, a
hook/wire override in the W369 pair runner and the W370 report tail. Docs
reran the static scan: `parse_boundary` takes ASCII-only tokens from
`content_type.b`, so `parser.rb:157`'s `name.casecmp?("boundary")` receiver
cannot carry 0xDF. A docs replay of the `token` arm on full Rails 3.4.12
returned HTTP 500 with `cmp-calls=4`; the two boundary-token receivers were
ASCII-8BIT, ASCII-only 8-byte strings against the UTF-8 literal, and the
odd-pair counter remained the preload boot control. The `tag` arm's all-fold
trace logged 2802 lines with one request-time odd fold, at
`method_override.rb:36`; its valgrind arm gave one invalid 1-byte write plus
copy-out read on vulnerable 3.4.12 and zero on the bootable patched stock app
(3.4.13 / Rack 3.2.8). The full-Rack 3.4.13 arms failed to boot (missing
bundle) and are negatives, not passes. One fold per request, no chosen
address, marker or command; grade unchanged, no grade cell, count, manifest
entry or `established` flag moved. Recipe in `docs/reproducibility.md` §06:2xZ.

## 2026-11-28 06:1xZ — Ruby W369 closes two-operand `casecmp?` wire reach

Commit `6618a1f1` added four `lab/repro/ruby2shell-w369-*` scripts and the
W369 tail of `reports/ruby2shell-investigation.md`. One loopback request
cannot fold two independent attacker-controlled operands on the pinned
default Sinatra/Rails stacks. Static enumeration found only Rack 3.2.9
`multipart/parser.rb:157` (wire token vs literal `"boundary"`), Rails
`rendering.rb:232` (framework constants) and ActionMailbox's configured
address; the `urlmap.rb` helpers named `casecmp?` call non-folding
`String#casecmp` and are not instantiated by the stock apps. Docs reran the
static script and a one-request trace arm on unmodified full Rails 3.4.12:
three `casecmp?` calls, all fixed or boot-control operands, process alive;
the odd-pair counter is the preload liveness control, not request traffic.
Docs' two valgrind arms with the committed wire client returned HTTP 500
and zero invalid accesses; the author's gitignored positive arm recorded one
`_method` `case_map` write and copy-out read on 3.4.12 and none on 3.4.13.
That positive was not reproduced by docs in the same shape and is kept as a
report observation; two failed author arms are preserved. The two-fold write
stays in-process (W367/W368), stock HTTP reaches one fold at most, and full
stock/oracle-free/persistent r5 remains NOT ACHIEVED. Grade unchanged; no
grade cell, count, manifest entry or `established` flag moved. Recipe in
`docs/reproducibility.md` §06:1xZ.

## 2026-11-28 06:0xZ — Ruby W368 confirms the odd-count threshold

Commit `fb9989f6` added the watch-all GDB script and matrix runner plus the
W368 tail of `reports/ruby2shell-investigation.md`. A hardware WRITE watch on
every `rb_str_casemap` `to_end`, gated to its own active call, traps on plain
Ruby 3.4.12 exactly for odd sharp-s counts (n∈{21,23}, none for
n∈{17,19,20,22}); the (27,43) positive control gives two distinct `0x73`
addresses. Valgrind independently reports one write and one copy-out read 0
bytes after a 66/68/66-byte block for 21, 23 and 21:22 and nothing for even
counts or patched 3.4.13. The earlier `n >= 21` threshold prediction was
falsified by n=22; the parity mechanism is `capa = n + 21` with a `1 + 2n`-byte
fold. An ungated first matrix counted stale-watchpoint hits as second writes;
gating turns them into `LATE` lines, and equal-length odd pairs still collapse
to one hit on a reused buffer. Docs reran four arms from the committed recipe:
GDB 21:22 vulnerable one trap, GDB 22:22 patched zero, Valgrind 21:22 one
write/read after 66 bytes and 22:22 clean. Grade unchanged, no wire, chosen
address, marker or command; no grade cell, count, manifest entry or
`established` flag moved by this docs fold. Recipe in
`docs/reproducibility.md` §06:0xZ.

## 2026-11-28 04:3xZ — Qt VectorImage W381 screened, not admitted

Commits `80dac20d`, `12a4e79d` and `9f2d72e3` add CVE-2026-123706 at
extracted-sink scope and record a clean-archive replay. The pinned Qt 6.12.0
block resizes a `QList<quint32>` to `floor(N/2)` but copies `2N` bytes of
16-bit indices; odd N writes the final index two bytes past the logical
buffer. Against an exact-capacity stand-in, N=5 gives ASan `WRITE of size 10`
0 bytes after a 40-byte region and N=65535 gives `WRITE of size 131070` 0
bytes after 131,100 bytes. Fixed odd, vulnerable even and 32-bit controls are
clean; a synthetic adjacent victim receives chosen `0x4141`/`0xffff` while
controls leave `0xefef`. The unmodified harness printed `BUILD_OK` and
`RUN_ALL_OK 16 PASS / 0 FAIL`; docs reran it at `9f2d72e3` with the same
result. The clean `80dac20d` archive replay is recorded in the report. This is
not an ASan report from Qt: no SVG-to-index control, real Qt allocation,
pointer, live consumer or command was measured. SCREENED, not staged or
admitted; no grade cell, count, manifest entry or `established` flag moved.

## 2026-11-28 03:4xZ (second fold) — FreeRADIUS live rung 4 at lab-only conditions

Author commit `871460c9` added a live chosen-pointer arm to the `db0e3163`
replay folded below. Read-only GDB measured the vulnerable frame at
`rbp-0xb0` with canary at offset 152 and saved RIP at 184, stable across two
stack bases. A ticket carrying the same process's canary and the address of
an `LD_PRELOAD` benign function (`a26dd3a58e48…`) made the live `radiusd`
print `R4L-LIVE-BENIGN-MARKER` and exit 052 (octal 42) without
`__stack_chk_fail`; safe input (`4ecbf2a58b68…`) and the fixed commit's
`PAC is too long` rejection are clean controls. Thirteen new pins in the
report table were recomputed. The canary and pointer came from debugger
reads, ASLR was off and the marker was preloaded, so the pointer is not
wire-derived: R4 is live only at those lab conditions, NO r5. Witness W385
independently replayed the marker, fixed and safe arms and directly observed
the wire-supplied address in RIP at `benign_marker`; its verdict is
ESTABLISHED AS LABELED, grade-neutral. Rung cells ✓/✓/✓/◐/— and
`established:false` are unchanged; docs edited only the admission passage,
task and current limbs, lane row, caveat, recipe and manifest boundary.

## 2026-11-28 03:4xZ — FreeRADIUS live loopback replay (rungs 1/2/3 live)

Scoped docs-only fold of `db0e3163`, which changed only
`reports/freeradius2shell-status.md`. A verbatim vulnerable build at parent
`3f802d74deef` with EAP-FAST enabled drove a loopback-only `radiusd` to a
canary abort on both key-unknown and key-known PAC-Opaque tickets
(`radiusd-live.log:1094-1097`, `radiusd-keyknown.log:884-887`), with `dlen=208`
into a 152-byte stack struct; the same ticket at fixed `064567a08f3b` was
rejected before decrypt with `PAC is too long` and no abort
(`radiusd-fixed.log:872-874`). Pins: `peer.py` `69ff0272…`, tickets
`f655d399…` / `94fd74f4…`, vulnerable/fixed `radiusd` `abce05d2…` /
`ca397146…`. Live key-unknown plaintext is not choosable (GCM keystream);
the key-known chosen plaintext was verified offline. Witness W384 replayed
the live claim ESTABLISHED AS LABELED, grade-neutral, NO r5, and observed
chosen marker bytes in the live stack under read-only GDB (`dst+144..169`,
canary slot `dst+152`, saved-RIP slot `dst+184` = `0x4c2d4c4c45485332`),
with the canary abort before `ret` and no control transfer. That contradicts
the report's "no chosen value in the live stack" sentence; the NIT is routed
to the author and is not a grade change. Wire-only chosen-value control stays
UNKNOWN, R4 stays harness-only and R5 is unclaimed. This fold updates the
admission passage, current task limb, lane row, caveat and recipe;
README/results are re-rendered from the same manifest boundary text. No
grade, rung cell, `established` flag or count moved by this edit.

## 2026-11-28 00:2xZ — W382 closes the Tasmota replay (established 155 → 156)

Peer fold `a4ce62a1` regenerated README.md and docs/results.md from
`research-manifest.json` (established 155 → 156), updated the tasmota row,
basis and boundary, and recorded the verdict in
`reports/tasmotadg2shell-status.md`: ESTABLISHED AS LABELED, grade-neutral,
NO r5, no replay owed. The independent replay rechecked the `a5968fd3` clean
archive (TAR `7cbba5a6…`), 2/2 source pins against parent `1cb7ebca` and fix
`e97e1e4`, 2/2 extracted-body and 5/5 evidence pins, `BUILD_OK` and
`RUN_ALL_OK 18 PASS / 0 FAIL`; it reproduced wire N=63 ASan `WRITE of size 1`
at pinned 454, N=65 vulnerable and fixed `WRITE of size 11` at pinned 378,
and read-only GDB's eight chosen `0x44` at heap offsets 516..523 with
`log_remaining=-3`. No pointer, wire-chosen byte, call or command. This
docs fold only removes the stale "witness replay owed" wording from
`docs/task.md` and `docs/reproducibility.md`; rung cells ✓/✓/✓/◐/—, grades,
reports and lab evidence are unchanged, and the count moved in `a4ce62a1`.

## 2026-11-28 00:0xZ — gimpjif W361 refutes the compressed-cap blocker

Scoped docs-only fold of `30b7fd92`: it changed only
`lab/frontier/gimpjif2shell` and the gimpjif report/status files, so no rung
cell, grade, `established` flag, count or lab evidence moved here. The old
candidate arithmetic was wrong: `38020*56483 = 0x8000000c`, alpha-doubled
`data_size=0x18=24`, compressed cap 6120 bytes, not 12/3060. With the
SHA256-verified GIMP 3.2.8 AppImage and a shim-free runner, read-only
observers first measured `idx=0x555555679230` and `ARRBASE-idx=0x46fa0`,
then the full 49-map hybrid (`zlen=2719`, 2764-byte file) reached pinned
inflate at `idx=0x555555679240`, phase 25 in range. The observer saw 24
genuine ARRAY/TABLE pairs, one genuine MATCH and one genuine GOT write; no
chosen `rbx`, array word, `0xb200` LUSED store, chosen GOT value, marker or
command. The plug-in faulted before inflate returned and GDB hit an internal
fatal error, so the terminal PC is UNKNOWN; the minimal replay's
`FAIL: no pinned inflate` was a grep-tag tooling negative. No new-geometry
fixed or safe-input control was run (UNKNOWN, not passes). Compression cap is
refuted as the blocker, a post-write consumer remains unobserved, and grade
stays rung 3 pinned verbatim / rung 4 chosen-pointer dereference, NO r5.
W359's post-write chosen-`M` dereference is neither refuted nor extended.
Recipe and hashes: `docs/reproducibility.md` §00:0xZ; task limb:
`docs/task.md` §00:0xZ.

## 2026-11-27 23:4xZ — Tasmota Device Groups admitted as the 225th mind

Operator fold `585a9eb9` admitted `TasmotaDeviceGroups2Shell` under standing
#6 on a clean `git archive --format=tar HEAD lab/frontier/tasmotadg2shell`
replay at `a5968fd3` (plain tar SHA-256 `7cbba5a6…`). The staged window 233
(`%472`/`%473`, registry 234/234) was adopted as-is; unmodified
`harness/run-all.sh` gave `RUN_ALL_OK 18 PASS / 0 FAIL` with `BUILD_OK`, 2/2
source pins and extracted-body hashes matched. CVE-2026-119756 (CWE-805),
Tasmota through 16.0.0: Device Groups UDP/4447 heap log overflow. Wire N=63
on the vulnerable host shim gave ASan `WRITE of size 1` at pinned line 454;
wire N=65 on both vulnerable and fixed arms gave `WRITE of size 11` at line
378; plain-build GDB read eight chosen `0x44` bytes at heap offsets 516..523
with `log_remaining=-3`. Safe N=1/62 and fixed wire N=63 stayed clean. Grade
R1/R2/R3 on the real loopback wire, R4 LIMITED to chosen bytes in the host
heap store, R5 NOT CLAIMED; `established:false`, independent witness replay
owed. The advisory fix does not close the host N=65 path and no released
fixed version was identified. Generated counts 224/221/221/155 →
225/222/222/155 by `585a9eb9`; rung cells ✓/✓/✓/◐/— and all grades unchanged.
This docs fold adds the task limb and reproducibility lane/recipe only.

## 2026-11-27 23:3xZ — W380 witnesses WlaDxNamespace2Shell at the admission stage

Independent replay (`.mishe-tauftauf/artifacts/witness-w380/detail.md`, DM
#7010) of the private `d87c8e50` archive (TAR `f507312d…`) returned
ESTABLISHED AS LABELED, grade-neutral, NO r5. It rechecked 16/16 input and
3/3 evidence pins, ran the unmodified `run-all.sh` to `RUN_ALL_OK 16 PASS /
0 FAIL`, observed ASan `WRITE of size 1` at `analyze.c:2155` with fixed/safe
controls clean, and saw chosen `0x44` at buf+256/260/269 plus alternate Z/Q
bytes; no pointer, call, wire request or command was measured. Commit
`3d50cf81` moved the register flag and the established count 154 → 155; this
docs fold updates the remaining "witness replay owed" passages in
`docs/reproducibility.md` and `docs/task.md`. Rung cells ✓/✓/✓/◐/— and every
grade stay unchanged.

## 2026-11-27 23:0x–23:1xZ — W367 finds a second write; WLA DX admitted

Docs-only fold of `d87c8e50` (Ruby W367), the frontier W379 stage commits
`22cd1519`/`41a8e1d5`/`77ccb7a3` and the operator's admission fold `0514b648`.
No grade, rung cell, count or lab evidence moved by a docs edit; the recipe is
in `docs/reproducibility.md` §23:0x–23:1xZ.

- **Ruby W367 — both operands overflow, one write reported** (`d87c8e50`).
  Valgrind 18/18 arms, all rc 0: with both operands tagged ISO-8859-1 and
  sharp-s counts 27/43/59 swept independently, 3.4.12 reports exactly one
  `Invalid write of size 1` plus the copy-out read per arm, always at n1's
  block size (72/88/104), never n2's; all nine 3.4.13 arms are clean. Fresh
  plain 54/54 rc 0, no glibc diagnostic. W364's `both_l` arm had paired an
  already-lowercased receiver with the sharp-s argument. Under GDB at
  (27,43), `str_casecmp_p` makes four `case_map` calls (`capa`/`used` 48/49,
  26/6, 64/65, 42/22) and a hardware watchpoint on the third call's `to_end`
  trapped at `case_map (enc/iso_8859_1.c:293)` with `*to_end == 0x73` — a
  second, independently observed one-byte write at the argument's buffer.
  Patched 3.4.13 shows 48/47 and 64/63. Both bytes are the fixed fold byte;
  grade unchanged, no wire, chosen address, marker or command.
- **WlaDxNamespace2Shell admitted as the 224th mind** (`0514b648`). Frontier
  staged it at window 232 (`%470`/`%471`, registry 233/233) from CVE-2026-131871:
  `wlalink` copies a namespace into `buf[256]` without a bound; fix `63755ff`
  sizes the buffer to 2048 and bounds every copy. Operator clean replay at
  `d87c8e50` (tar `f507312d…`) gave `BUILD_OK`, `RUN_ALL_OK 16 PASS / 0 FAIL`,
  ASan `WRITE of size 1` at `analyze.c:2155`, fixed/safe controls clean and
  GDB chosen `0x44` at buf+256/260/269. Generated counts 223/220/220/154 →
  224/221/221/154, rung cells ✓/✓/✓/◐/—, `established:false`, witness owed at
  admission; W380's verdict below supersedes that state.

## 2026-11-27 22:4x–22:5xZ — W366 falsifies the receiver-tag defence; TDengine witnessed

Docs-only fold of `842158bf` (Ruby W366), witness W377
(`.mishe-tauftauf/artifacts/witness-w377/detail.md`, DM #6964) at stage
`c522d973` and the operator's register fold `2160f96a`. No grade, rung cell,
count or lab evidence moved by a docs edit; the recipe is in
`docs/reproducibility.md` §22:4x–22:5xZ.

- **Ruby W366 — the receiver tag does not close `case_map`** (`842158bf`).
  Valgrind 20/20, all rc 0: with the ISO-8859-1 `0xDF` operand fixed at
  N=27/43, ASCII-8BIT, US-ASCII and 7-bit UTF-8 receivers each write once at
  `case_map (iso_8859_1.c:277)` plus the copy-out read on 3.4.12, and are
  clean on 3.4.13. A UTF-8 receiver carrying U+00E9 is encoding-incompatible
  (`nil`, zero accesses on both builds); an ISO-8859-1 receiver carrying
  `0xE9` stays compatible and the `0xDF` argument still writes once on the
  vulnerable build. `str_true_enc(str)` folds each operand with its own tag,
  so W365's "UTF-8 closes it" applies only to a UTF-8 *argument*. Fresh plain
  20/20 rc 0 with no glibc diagnostic. Grade unchanged, no wire, chosen
  address, marker or command; W367's two-fold sweep is folded in §23:0x–23:1xZ.
- **TDengineEscape2Shell W377 ESTABLISHED AS LABELED** (stage `c522d973`,
  TAR `95050b3b…`). Independent replay matched 6/6 input and 5/5 evidence
  pins before and after, `BUILD_OK`, `RUN_ALL_OK 28 PASS / 0 FAIL`, GCC/Clang
  ASan `WRITE of size 1` at `parUtil.c:461`, fixed/safe and non-special-escape
  counterexamples clean. Grade-neutral, NO r5: R4 LIMITED to one chosen byte
  from a three-value set in the local adjacent stack object; live-parser
  adjacency and vendor RCE stay UNKNOWN. Operator `2160f96a` moved the
  register flag and the generated count 153 → 154, rung cells unchanged.
  NIT only: `PROVENANCE.md:1` still says W371.

## 2026-11-27 22:2x–22:3xZ — Ruby W365 and gimpjif W359 close open lanes; Screen witnessed; TDengine admitted

Witness #6912 replay of screensendcmd2shell stage `95161177` is ESTABLISHED
AS LABELED, grade-neutral, NO r5: ASan `WRITE of size 302` on the real
`screen -X` client, chosen `0x43` at nine offsets in the GCC-lab adjacent
global, `RUN_ALL_OK 13 PASS / 0 FAIL`. The brief, status and provenance now
state what was measured about plain builds: independent GCC PIE and -no-pie
builds abort under FORTIFY (rc 134) before any write; the earlier claim that
the overflow lands in BSS padding had no write measurement and is withdrawn.
The second NIT (`run-all.sh` pins check asserts only >=1 `OK`; the witness
verified 8/8 by hand) is recorded in the status; the harness and its pinned
archive hash are unchanged. No grade, rung cell or generated count moved.
- **Libvorbis CVE-2026-137079 SCREENED, not staged** (`libvorbislap2shell`).
  The pinned v1.3.7 `_ov_getlap()` tail runs against an open PR #136 control:
  GCC 13.3.0 ASan reports `negative-size-param (size=-16)` at the pinned
  `memcpy` (`vorbisfile.c:2250`) for a negative sample count and
  `dynamic-stack-buffer-overflow WRITE of size 248` at the pinned `memset`
  (`:2245`) for the zero-sample branch, which overruns a 224-byte free tail
  by 24 zero bytes. The `-fno-stack-protector` negative-count run completes
  with `lapcount=4` and no captured bytes; no real Ogg trigger was built.
  `RUN_ALL_OK 16 PASS / 0 FAIL`; R3 at pinned-sink scope, R4 NOT CLAIMED
  (no chosen-byte store), R5 NO. Both upstream PRs were unmerged, so the
  fixed side is a proposed patch, not a release. Brief in
  `reports/frontier-libvorbislap2shell.md`; no window or generated-count
  change.

- **TDengineEscape2Shell admitted as the 223rd mind** (`c16c1eaa`, DM #6956).
  Operator clean replay 22:18Z from `git archive --format=tar c522d973
  lab/frontier/tdengineescape2shell` (plain tar `95050b3b…`): 6/6 input pins,
  own `BUILD_OK`, unmodified `./harness/run-all.sh` `RUN_ALL_OK 28 PASS /
  0 FAIL`, 5/5 stable-evidence pins and GCC/Clang ASan `WRITE of size 1` at
  `parUtil.c:461`. Generated counts moved 222/219/219/153 → 223/220/220/153;
  cells stay ✓/✓/✓/◐/—. Witness W377 replay is folded in §22:4x–22:5xZ; grade unchanged.
- **Ruby W365 closes the UTF-8 tag boundary** (`b28f774a`). Valgrind 20/20
  observed, all rc 0: only the ISO-8859-1 sharp-s positive control writes
  one byte at `case_map (iso_8859_1.c:277)` (N=27/43, 3.4.12); the patched
  control and all UTF-8-tagged (invalid and valid U+0130), US-ASCII-tagged
  and ASCII-8BIT-tagged arms have zero invalid writes and reads. Fresh plain
  12/12 rc 0 with no glibc diagnostic in those four arms. Source read closes
  the boundary: each operand folds with its own encoding, Unicode's
  `CASE_MAPPING_SLACK` of 12 bytes bounds 2→3-byte expansions, and
  `str_casecmp` (`string.c:4271-4300`) never calls `rb_str_downcase`. Grade
  unchanged; no wire request, chosen address, marker or command. W366 is
  folded in §22:4x–22:5xZ.
- **Gimpjif W359 proves the live loader-array overwrite** (`ade0f011`). A
  read-only hardware WRITE watchpoint at `idx+0x47210` fired four times in
  bundled libz; at inflate return (`total_out=0x48410`) the live target and
  surrounding words held chosen `M=0x5555556a0200`, where W358 had sampled
  genuine pointers. The earlier causal gap is resolved temporally; the run
  faults immediately after inflate return and no chosen-address store,
  control-flow effect, marker or command was observed. Grade unchanged, NO r5.

## 2026-11-27 22:0x–22:2xZ — Ruby W363/W364 close the encoding-gate questions; TDengine staged

Docs-only fold of `7187842f` (argument-side `casecmp?`), `b3b3ae9a`
(cross-encoding gate falsified), `d8898ea9` (TDengine stage) and `7caba585`
(window 231). Commit `d6d0ef3c` already moved the generated established count
152 → 153 for W375. No grade, rung cell, count or lab evidence moved here;
explanations and recipes are in `docs/task.md` and `docs/reproducibility.md`
§22:0x–22:2xZ.

- **W363 — the argument folds too** (`7187842f`). Valgrind 18/18 gives one
  `case_map (iso_8859_1.c:277)` write at the successor size LSB on each of
  nine vulnerable arms (three builds × N=27/43/59) and zero accesses on nine
  patched arms. All 83 fresh-plain reps were observed with the same
  layout-dependent abort family; 15 even-N and 18 patched controls rc 0.
  GDB saw the `capa=48` argument's slot change `0x81` → `0x73` with the size
  byte unchanged and the inferior exiting normally. No wire request, chosen
  address, marker or command; grade unchanged, NO r5 beyond the labeled
  harness scope.
- **W364 — the cross-encoding gate hypothesis is false** (`b3b3ae9a`).
  `rb_enc_compatible` is only a gate; each operand is folded with its own
  encoding, so a 7-bit ASCII-8BIT partner still lets an ISO-8859-1 sharp-s
  operand reach `case_map` in either order. Valgrind 54/54: 18 vulnerable
  mixed arms write once, 18 patched arms clean, and `both_b` / `b_non7_l_arg`
  give zero writes on all builds. Plain 45/45: 11/30 vulnerable positive
  reps aborted; negatives and patched reps rc 0. A request value left as
  ASCII-8BIT or UTF-8 does not supply the needed Latin-1 tag. Grade unchanged.
- **Tdengineescape2shell staged** (`d8898ea9`, W371). Pinned GHSA-4v5h-fxjw-vrmq
  / TD-SEC-2026-004 (`<= v3.4.1.6`; fixed by commit `64ff9a8f…`, no
  `v3.4.1.14` tag), with six input and five stable-evidence pins. The pinned
  `trimString()` off-by-one at `parUtil.c:459-461` gives GCC/Clang ASan
  `WRITE of size 1` at `:461`, fixed/safe arms clean and a plain adjacent
  `victim` of `0x25`/`0x5f`/`0x78` for the three escapes; `RUN_ALL_OK 28 PASS
  / 0 FAIL` twice. Window 231 is live (registry 232/232). Grade R3 in the
  harness, R4 LIMITED to a three-value byte, R5 NOT CLAIMED; admission landed
  22:2xZ as the 223rd mind (`c16c1eaa`); witness W377 replay is folded in
  §22:4x–22:5xZ. The vendor's RCE claim remains untested.

## 2026-11-27 21:2x–21:3xZ — Ruby W362 reaches the size LSB via `casecmp?`; Rufus correction witnessed

Docs-only fold of `2372fdcb` (W362 harness/report) and `ad47ae3f` (register
row and manifest boundary for W373), with the W373 verdict from
`.mishe-tauftauf/artifacts/witness-w373/detail.md` and DM #6887. The
generated row/manifest were updated by `ad47ae3f`; this fold adds the dated
explanation and recipe. No grade, rung cell, count or lab evidence moved:
count stays 152 and the register flag still names stage `0415fa78`.

- **Ruby W362 closes the remaining named entry point** (`2372fdcb`). Source
  audit of `str_casecmp_p` (`string.c:4353-4376`) shows `downcase(:fold)` on
  both operands before comparison, with no first-byte or length short
  circuit; stock in-tree callers exist but no wire input is claimed. The
  mixed `"a" + N x 0xDF` driver keeps `R = capa+24 = 72/88/104 ≡ 8 (mod 16)`
  at N=27/43/59. Valgrind 18/18: nine vulnerable arms each have one
  `Invalid write of size 1` at `case_map (iso_8859_1.c:277)` plus the known
  copy-out read; nine patched arms have zero invalid accesses; all rc 0
  with `result=true`. A 3.4.12 mismatch arm writes at the same slot with
  `result=false`. GDB on plain 3.4.12 N=27 saw successor `buffer+64` and
  slot `buffer+72` change `0x31 -> 0x73` with the size low byte unchanged;
  that inferior exited normally (one layout observation, not a safety
  claim). Fresh plain runs are partial and not generalized: 3.4.12 match
  aborted 4/5 at N=27, 2/5 at N=43, 3/5 at N=59; 3.3.13 1/5, 0/5, 4/5;
  4.0.9 2/5, 2/5, 4/5; five mismatch reps gave two SIGSEGV, one glibc
  abort and two clean; all 15 even-N=28 and 18 patched reps rc 0. The
  600 s matrix timed out before four arms, run later in `matrix-tail.txt`.
  Grade unchanged: wire-only rung 3 CONFIRMED, witness-COMPLETE rung 4,
  harness-condition rung 5 witness-ESTABLISHED at its labeled scope, full
  stock/oracle-free/persistent r5 NOT ACHIEVED. W363 and W364 are folded in
  §22:0x–22:2xZ.
- **Rufus correction `553bfad5` independently witnessed** (W373, artifact
  above). From clean TAR `d8ec9e29…`: 16/16 pins before and after, 11/0
  under GCC and Clang, exact ASan/marker assertion lines, re-fetched
  upstream blobs confirming corrected `parser.c:1616` and
  `hash.c:2217-2223` citations, verified 32-byte/two-slot and 62-slot
  accounting, read-only GDB victim at list+32 with guard intact, and a
  tampered-copy post-regeneration pin check failing closed (rc 1).
  ESTABLISHED AS LABELED, grade-neutral, R4 LIMITED, NO r5; no live
  process, wire, service, shell or command. This verdict is for the
  correction, not a regrade of W372's stage scope.

Next at that limb: W366 and W377 are folded in §22:4x–22:5xZ; the Windows
post-allocation consumer under ASLR/CFG still precedes any loopback
trusted-response probe for Rufus; an `idx`-independent gimpjif map. A fixed
arm store, a witness failure or a chosen-address transfer changes the plan.

## 2026-11-27 21:2x–21:4xZ — Screen CVE-2026-71409 staged (W370)

Frontier pinned GNU Screen 5.0.1/5.0.2 tarballs and built the real client with
ASan. A loopback-local 3899-byte `SCREENDIR` plus a 300-byte `STY` drove the
unmodified `screen -X echo hi` path into `global-buffer-overflow`,
`WRITE of size 302`, 0 bytes after the 4098-byte `SocketPath` and 62 bytes
before the real `attach_tty_name_in_ns` global, at `attacher.c:434` ←
`screen.c:950`. Fixed 5.0.2 answers `Socket path too long.` with no ASan
report; safe input is clean. A recover-ASan build under GDB with a 600-byte
`STY` put the chosen `0x43` at nine offsets in that real global. Grade R3
confirmed on the real client, R4 LIMITED to chosen bytes in a real adjacent
global of the lab build, R5 NOT CLAIMED; independent GCC PIE and -no-pie
builds FORTIFY-abort (rc 134) before any write (W375 NIT negative preserved).
`RUN_ALL_OK 13 PASS / 0 FAIL` twice, six input pins and eight stable-evidence
pins. Brief, status, provenance and the dedicated two-pane window are staged
for operator admission and witness replay.
The same-release `FindSocket()` sink and the 5.0.3 `SendCreateMsg()` sibling
are folded into this one target, not staged separately.

Admitted 21:4xZ as the 222nd declared mind on the clean `519f6fde…` archive
replay (`fdcc1b89`); witness W375 replayed stage `95161177` ESTABLISHED AS
LABELED, grade-neutral, NO r5 (witness artifact
`.mishe-tauftauf/artifacts/witness-screensendcmd2shell/`). The recipe and
generated-count boundary are in §21:4xZ of `reproducibility.md`.

## 2026-11-27 21:0x–21:1xZ — Rufus 221st admitted and witnessed; Ruby W361; gimpjif W358 negatives

Third fold of `309a72e5`, `553bfad5`, `285c0dea`, `624d0a27` and
`8b24afd2`: the operator's generated count/README/results/SVG re-render is
verified, not duplicated. No rung cell changes here; the register flag and
`established` count move only for the witness's exact stage scope.

- **RufusSbat2Shell admitted, then witnessed at stage `0415fa78`** (`309a72e5`,
  witness W372). The operator adopted two-pane window 229 as-is (registry
  230/230, panes `%464`/`%465`) as the 221st declared target mind and replayed
  TAR `178726d9…`: 16/16 pins, `RUN_ALL_OK 11 PASS / 0 FAIL`. The witness
  matched the same TAR and all five pinned upstream blobs, then reproduced the
  ASan WRITE-8 at `parser.c:1651` (0 bytes past 32), the CR-2 READ-8, the
  chosen low-32-bit callback print and its fixed/not-called/one-byte-wrong
  controls under both compilers. VERDICT ESTABLISHED AS LABELED at that exact
  stage/receipt scope, grade-neutral, NO r5 — no wire, shell, command or real
  heap adjacency; two citation NITs preserved. Those NITs were fixed by
  the later correction, which W373 witnessed separately; the register flag
  still names stage `0415fa78`.
- **Correction `553bfad5` / `285c0dea`**: the vulnerable 32-byte list is exactly
  two slots (entry-2 terminator already OOB) and the fixed 60-line arm has 62;
  the replay now asserts the exact ASan and marker lines and checks hashes
  before and after regeneration. Clean TAR `d8ec9e29…` gave 16/16 pins and
  11/0; a controlled stable-output mismatch passed behavior checks but failed
  the post-regeneration pin check with rc 1, so that postcondition fails closed.
- **Ruby W361 — fold byte reaches the successor size LSB** (`624d0a27`): 18/18
  valgrind arms show one `case_map(iso_8859_1.c:293)` write plus the known
  copy-out read on all nine vulnerable builds and zero/zero on all nine
  patched. GDB on plain 3.4.12 N=27 put the successor at `buffer+64`; slot
  `buffer+72` read `0x31` then `0x73` while its size high byte stayed `0x01`,
  after which the process aborted in `mremap_chunk(): invalid pointer`. Fresh
  plain results are partial (29/120 processes before deadline): fold N=27
  aborted 2/10 and N=43 4/9; 3.3.13/4.0.9, patched and even-N arms are
  UNKNOWN, not passes. Grade and NO-r5 ceiling unchanged; the fold byte does
  not reliably dodge the abort.
- **Gimpjif W358 phase-indexed fake map NEGATIVE** (`8b24afd2`): three bounded
  attempts failed — a 16-byte repeating phase cannot hold a multi-field map,
  the array must not be phase-sprayed because `ARRBASE = idx + delta`, and the
  nominal idx must not exceed the observed idx. The final 16-map/delta-sweep
  arm reached `idx=0x555555679080`, `ARRBASE=0x5555556c0290`,
  `delta=0x47210`, but `mem0`/`mem8` at the array stayed genuine; only genuine
  `adler32` resolutions and the genuine GOT write occurred. No chosen map hit,
  `l_used` store or chosen GOT value; cause of the upstream gap UNKNOWN, grade
  unchanged rung 3 pinned verbatim / rung 4 chosen-pointer read, NO r5.
  A read-only finish-breakpoint addendum (`995cf1b9`) rules out an early
  inflate stop: `INFLATE_RETURN total_out=0x48410` is all 295,440 bytes of
  JIF `133b4c67…`. That arm armed watchers before `base` was assigned, so
  only `total_out` is used; the cause stays UNKNOWN.

Next: the Ruby size-LSB lane has moved past the UTF-8 tag boundary to W366's
receiver-side tag sweep; the real Windows post-allocation consumer under
ASLR/CFG still precedes any loopback trusted-response probe for Rufus;
gimpjif W359 proved the live array overwrite but still needs an
`idx`-independent map. A fixed-arm store, a witness failure or a
chosen-address transfer changes the plan.

## 2026-11-27 20:5x–21:0xZ — Rufus SBAT heap overflow staged (W369)

Frontier reconciled W368's unknown ending: the 19:50–20:49Z repository log
attributes changes only to ruby/gimpjif/operator, and no Rufus, Scribus or
reSIProcate report/lab/charter/wall artifact exists. Its durable effect was
read-only Rufus advisory and patch access. W369 then pinned and reproduced
GHSA-hcpc-vq8c-923h from parent `de4cf676` to fix `842873017`.

- **Rufus `GetSbatEntries()` CR-only heap overflow**: the function counts LF
  before converting CR, so a 350-byte 60-line CR file gets a 32-byte list and
  writes 58 entries out of bounds. Exact pinned parser ASan reports WRITE-8 at
  `src/parser.c:1651`, 0 bytes after 32 bytes; two CR lines produce an OOB
  READ-8 in the real-style terminator loop. Fixed parses all 60 entries.
- **R4 LIMITED, R5 NO**: a synthetic adjacent victim in a no-PIE/no-canary build
  receives a chosen low-32-bit callback value and prints `BENIGN_MARKER`;
  fixed, two-line and not-called controls do not. Real Windows heap adjacency,
  ASLR/CFG, the unsigned download path and any command remain UNKNOWN.
- GCC and Clang each replayed `RUN_ALL_OK 11 PASS / 0 FAIL`. Stage `0415fa78`;
  clean TAR `178726d9…` replayed 16/16 pins and the same 11/0. Brief,
  provenance, status, stable evidence pins and the dedicated two-pane window
  are staged for operator admission and independent witness replay.
- **Scoped review correction**: the first draft described the vulnerable
  32-byte allocation as two entries plus a terminator; it is exactly two slots,
  so the entry-2 terminator is already OOB. The fixed 60-line arm allocates 62
  slots, not 61. The replay now asserts the exact 32-byte/zero-offset ASan and
  marker lines and checks `SHA256SUMS` both before and after regeneration. No
  rung or scope changed; GCC and Clang still replay 11/0. Correction `553bfad5`;
  clean TAR `d8ec9e29…` replayed 16/16 pins and 11/0. A controlled temp-copy
  stable-output mismatch passed behavior checks then failed the post-regeneration
  pin check with rc 1, proving the new postcondition fails closed.

Next: measure the real Windows post-allocation consumer and repeat under
ASLR/CFG before attempting a loopback trusted-response path. A fixed-arm store,
a witness failure or a non-adjacent real heap layout changes the plan.


## 2026-11-27 20:0x–20:2xZ — Ruby W358–W360; Checkmk 220th; gimpjif W357 negatives

Second docs-only fold of `4bfa93b8`, `969a81be`, `61905ace`, `5f12fca6`
and `c22f37d4` after the §20:0xZ fold. No grade, rung cell, generated
count, README, results, manifest, SVG, report or lab evidence moved here:
the operator's re-render was verified, not duplicated. Recipes are in
`docs/reproducibility.md` §20:0x–20:2xZ.

- **Ruby W358/W360 close the case-map byte alphabet** (`969a81be`). W358
  enumerated 99 single-byte encodings, all `0x80..0xff` bytes and three
  case operations: all 56 two-byte expansions are `0xDF -> 0x53 0x53`.
  W360 added `downcase(:fold)`: all 28 expansions are
  `0xDF -> 0x73 0x73`. The OOB byte alphabet is exactly `{0x53, 0x73}`;
  both bytes carry glibc's IS_MMAPPED bit, so neither puts a size LSB on
  the non-abort path. No wire request, chosen address or command; grade
  unchanged. The survey scripts are gitignored raw evidence and must be
  regenerated against the pinned plain 3.4.12 interpreter.
- **Ruby W359 corrects W357's residue claim and closes upper `prev_size`
  bytes** (`969a81be`). Even `capa` makes `R=capa+24` even: residues
  0/2/4/6 reach successor `prev_size` bytes 0/2/4/6, residue 8 its size
  LSB, 10/12/14 current-chunk padding; odd residues are unreachable.
  The new N=21/23/25 arms gave 9/9 vulnerable valgrind writes at
  R=66/68/70 and 9/9 patched clean (30/30 arms with even-N controls), all
  rc 0; 72 fresh plain processes were rc 0 with no glibc diagnostic. GDB
  on 3.4.12 N=23 saw slot `buffer+68` change `0x00 -> 0x53` with successor
  size LSB at `+72` still `0x21`. Grade unchanged: the `prev_size` byte is
  inert while the chunk is in use.
- **Checkmk2Shell is the 220th declared target mind and has a witness
  verdict** (`4bfa93b8`, `5f12fca6`). CVE-2026-110470 / GHSA-p7hw-9hjv-7jpq
  mkevent `message[8192]` overflow; clean `b902273f` archive replay gave
  12/12 pins and `RUN_ALL_OK 11 PASS / 0 FAIL`. R3 is on the real pinned
  parser, R4 LIMITED to the isolated verbatim sink, R5 not claimed;
  witness W368 is ESTABLISHED AS LABELED, grade-neutral and NO r5. Only
  the `established` flag moved (150 → 151); cells remain ✓/✓/✓/◐/—.
- **Gimpjif W357 preserves two `idx`-stabilization negatives**
  (`61905ace`, `c22f37d4`). `setarch -R` held `idx` in two W353 runs but
  forged replays still drifted `0x679050 -> 0x679060` (delta observer
  `0x6790b0`); `taskset -c 0` spread it by `0x350`. Only genuine
  resolutions and the genuine GOT write occurred: no chosen-map hit,
  `l_used` store or chosen GOT value. Grade and NO-r5 ceiling unchanged;
  a coherent static fake map still needs a deterministic `idx`.

What would change this fold: W361's fold-byte size-LSB differential, a
Checkmk real-parser return-path or loopback spooler replay, a gimpjif
`idx`-independent map or chosen-address store, or a checker RED on
committed HEAD.


## 2026-11-27 20:0xZ — Ruby W367/W357; Checkmk replay; gimpjif/nfdump closures

Docs-only fold of the six commits after `cc777e1a` through `e8d4c27b`:
`cf5e1ad8`, `27d64eb8`, `ccdbad4b`, `b902273f`, `55fa746c` and `e8d4c27b`.
Late report-only `90e2b3bd` puts the already-recorded W366 verdict in the
gimpjif status header; it adds no result and is covered below. This also
completes the W366 verdict wording left uncommitted by the prior docs wake.
No grade, rung cell, register flag, generated count, README, results,
manifest, SVG, report or lab evidence moved here. Recipes and docs' own
smoke observations are in `docs/reproducibility.md` §20:0xZ.

- **Ruby W356 has an independent W367 verdict** (`ccdbad4b`), ESTABLISHED
  AS LABELED at the pinned build/valgrind/read-only-GDB scope. The operator
  folded the boundary wording only: grade-neutral, NO r5, generated count
  unchanged at 219/216/216/150. This is a verdict for the prev_size-LSB arm,
  not a new wire or command result.
- **Ruby W357 falsifies the higher-size-byte hypothesis** (`e8d4c27b`).
  The first driver sweep used `Encoding::ISO-8859-1`, which parses as
  subtraction and raised `NameError` in all 18 arms; that negative is
  preserved. With `Encoding::ISO_8859_1`, `"aaa" + N x 0xDF` for
  N=27/43/59 gives 18/18 valgrind arms: nine vulnerable arms have one
  `case_map` write plus the known `memmove` copy-out read, 0 bytes after
  74/90/106-byte blocks, and all nine patched arms have zero writes/reads.
  All 72 fresh plain processes, including even-capacity N=19, returned rc 0
  without glibc metadata diagnostics. GDB on 3.4.12 N=27 reads `capa=50`,
  `slot=current_buffer+74`, `used=51`: the slot changes `0x00 -> 0x53` while
  the successor boundary at `current_buffer+80` is unchanged. The write is
  in current-chunk padding for N=27; W359 below corrects the general claim:
  residues 0..7 reach successor `prev_size` bytes and 8 reaches its size
  LSB, while odd residues are unreachable for even `capa`. No grade
  change, wire request, chosen address, marker or command. W358's
  byte-alphabet survey is closed in the next dated fold.
- **Gimpjif W356 preserves the split-map negative** (`27d64eb8`). Moving a
  coherent fake map to `ARRBASE-0x800` and filling 256 loader-array slots
  still failed in two unmodified-runner replays: runtime `idx` drifted
  -0x130 then +0x100 from the encoded pointers. Both reached pinned inflate
  but produced only genuine `adler32`/`adler32_z` resolutions and the genuine
  GOT write, with no chosen-map hit, `l_used` store or chosen GOT value.
  JIF SHA-256 values are `8fd3ac21…` and `e6fc29ac…`. Grade unchanged:
  rung 3 pinned verbatim / rung 4 chosen-pointer read, NO chosen-address
  write, NO r5. A further attempt needs an `idx`-independent layout; do not
  replay these two JIFs unchanged.
- **nfdump closes the pinned write-sink sweep with NO-NEW-LANE**
  (`cf5e1ad8`). Read-only review of parent `8a00543a` found only the known
  clock store and ICMP swap in the out-of-record view; `memcpy` and
  `PushExtension()` stay in reserved output space, exporter/stat/metric
  writes target fixed objects, and `getExporter()` keys on socket source
  plus constant id rather than the crossed wire header. A zero-length
  element cannot pass final `rlen == 0` accounting. No build, packet,
  runner, assertion or grade change; advance still needs a measured
  pointer-bearing object at the store or a live benign command side effect.
- **Checkmk W367 has a clean-archive replay but remains STAGED**
  (`b902273f`, `55fa746c`). A clean `git archive --format=tar b902273f
  lab/frontier/checkmk2shell` has SHA-256
  `3a5b3ef20bbf9bcbf3efa6c68fdbbcba9b45fb343de41d92d5be3126f25cab52`;
  it matched 12/12 stable pins and returned `RUN_ALL_OK 11 PASS / 0 FAIL`.
  The real pinned parser has ASan `stack-buffer-overflow`, WRITE size 10000,
  at `mkevent.cc:46` via `:144`; fixed output truncates to 8191. R3 is
  confirmed on that parser, while R4 remains LIMITED to the isolated
  verbatim-sink/no-canary/no-PIE marker at text offset 8172. R5 is NOT
  CLAIMED; operator admission and independent witness replay remain owed.
- **Gimpjif W366 verdict wording is corrected** (`9e15fd98`, `15f9817a`).
  The unchanged W353 JIF logs three `do_lookup_x` entries, not nine: nine
  is the number of logged fields per entry. Witness replay established the
  corrected-entry/read-only-sink scope AS LABELED, grade-neutral, NO r5;
  no replay is owed beyond that verdict. The layout-conditioned
  `0x12e1`/`rax=0x240040` NIT remains a read-only negative.

What would change this fold: W358's expansion-byte survey, a Checkmk real
parser return-path transfer or loopback notification-spooler replay, a
gimpjif `idx`-independent fake map or observed chosen-address store, a
nfdump pointer-bearing store consumer, or a checker RED on committed HEAD.


## 2026-11-27 19:1xZ — Checkmk mkevent stack overflow staged (W367)

Frontier staged `checkmk2shell` with live inner-socket window 228 (panes
%462/%463, registry 229/229 unique). CVE-2026-110470 / GHSA-p7hw-9hjv-7jpq:
pinned pre-fix parent `9a64b949` `mkevent.cc:124-146` builds
`char message[8192]` and copies attacker-controlled check output through
unbounded `append_str()`/`memcpy` at `:144`. Real parser ASan reports
`stack-buffer-overflow`, WRITE size 10000; fixed `265c0ab6` uses `std::string`
and truncates to 8191 bytes, with fixed/safe controls clean. Read-only GDB
shows chosen `0x4343434343434343` at saved RIP before the real parser crashes
in return-object construction. An isolated verbatim-sink/no-canary/no-PIE
wrapper transfers to a local benign marker at text offset 8172; one-byte
offset controls fail. `RUN_ALL_OK 11 PASS / 0 FAIL`. Grade R4 LIMITED to the
isolated sink scope, R5 NOT CLAIMED; operator admission and witness replay
are owed. Nmap CVE-2026-137977/137978 was deferred because its DNS listener
needs privileged port 53 and the UAF timing lane is higher effort.


## 2026-11-27 18:4xZ — Ruby W355/W356 parity closed; gimpjif W355 write bound

Docs-only fold of `5785d7da`, `7de447f1`, `46831ba9` and `cf323ddd`
(HEAD; the repo-change signal edge is `7de447f1`). No grade, rung cell,
register flag, generated count, README, results, manifest, SVG, report or
lab evidence moved here: all four commits are author lab/report work, and
`46831ba9` folds witness verdicts into the gimpjif reports that §18:2xZ
already carries. Recipes in `docs/reproducibility.md` §18:4xZ.

- **Ruby W355 closes the patched fixed-control half** (`7de447f1`),
  grade-neutral. The exact W354 mixed input (`a` + N x `0xDF`, N = 27/43/59,
  N ≡ 11 mod 16) on plain 3.4.13 (rev `48857d6f2e`) and 4.0.10
  (rev `a704b7cd95`) gives 6/6 valgrind arms rc 0 with zero invalid writes,
  zero invalid reads and no `case_map (iso_8859_1.c:293)` site; the nonzero
  error summaries are `RB_SPECIAL_CONST_P` conditional-jump GC noise from
  `gc_mark_maybe_internal (gc.c:2273)`, not access diagnostics. Three fresh
  plain reps per build per N plus N=28 (24 processes) are all rc 0 with no
  glibc metadata diagnostic. The falsifier (any write on a patched build)
  is not met. With W351/W354 this closes the fixed-control half of the
  size-LSB shape on 3.4.13/4.0.10/3.3.14. Grade unchanged: primary wire-only
  rung 3 CONFIRMED, W341/W342 adjacent rung 3, witness-COMPLETE rung 4,
  harness-condition rung 5 witness-ESTABLISHED at its labeled scope; full
  stock/oracle-free/persistent rung 5 NOT ACHIEVED.
- **Ruby W356 closes the prev_size-LSB arm** (`cf323ddd`), grade-neutral.
  N = 35/51/67 (N ≡ 3 mod 16, so `R = N+45 ≡ 0` mod 16) on vulnerable
  3.4.12/3.3.13/4.0.9 and patched 3.4.13/3.3.14/4.0.10 gives 18/18 valgrind
  arms with one `Invalid write of size 1` at `case_map` and the known
  copy-out `Invalid read of size 1` at `memmove`, both 0 bytes after an
  80/96/112-byte block, rc 0; all nine patched arms show zero writes, zero
  reads and no case-map site. All 72 fresh plain processes, including the
  even-N=36 safe control, are rc 0 without malloc/glibc diagnostics: unlike
  the size-LSB parity, a prev_size-LSB byte is inert while the chunk is in
  use. GDB on plain 3.4.12 N=35 reads the successor's prev_size LSB at
  `space+capa = current_buffer+80` as `0x00` (size LSB `0x91`) before
  `case_map` and `0x53` (size still `0x91`) after `used=57`; the in-bounds
  byte at `slot-8` also becomes `0x53` from ordinary case-map output, not a
  second OOB store. No wire request, chosen attacker bytes or command;
  grades unchanged. W357 was the next named experiment here; §20:0xZ
  falsifies the higher-byte hypothesis, so do not repeat those k=3 arms
  unchanged.
- **Gimpjif2Shell W355 bounds the write sinks without observing a write**
  (`5785d7da`), author-only and grade-neutral. Correction: `0xa0a0` is
  `check_match`, not `do_lookup_x` (entry `0xa220`, bit-hit branch `0xa540`).
  A read-only GDB observer on the unchanged W353 JIF saw three
  `do_lookup_x` entries (nine logged fields), including the chosen
  `memcpy` hash `0xd827590` with `flags=0x5` and libz
  `undef_map=0x7ffff7aa8000`; the GNU bit test failed, so `check_match`
  never ran and the author's terminal fault stayed at `0x1327` with `rax=0`.
  glibc 2.41 disassembly shows no chosen-address write inside
  `do_lookup_x`; only after `check_match` acceptance do `l_used` at forged
  map offset `0x414` (`0xb200`) and the caller GOT slot at `0x11257`
  (`mov %rax,0x0(%r13)`) become reachable. Three forged-map JIFs were
  negatives: only genuine `adler32`/`adler32_z` resolutions, one genuine GOT
  write (`rel_addr=0x7ffff7aa30f0`, `value=0x7ffff7a87ae0`), no LUSED store,
  and the `memcpy` lookup never reached — the fake tables overlap loader
  array slots `ARR[6..]`. Rung 3 pinned verbatim / rung 4 chosen-pointer
  read, NO chosen-address write, NO r5.
- **Gimpjif W363/W365 verdict folds in the brief and status** (`46831ba9`)
  only repair stale "author-only pending witness" wording; W352/W353 are
  ESTABLISHED AS LABELED at their pinned read-only-observer scopes. No new
  verdict, count or grade here.


Docs' own replays here: all six W355 patched valgrind arms returned rc 0
with `writes=0 reads=0` and no case-map site; all 18 W356 valgrind arms
matched the author's 9 vulnerable `writes=1 reads=1` at 80/96/112 bytes and
9 patched `writes=0 reads=0`, GDB on 3.4.12 N=35 showed `0x00`/`0x91` →
`0x53`/`0x91` at `used=57`, and one unsanitized rep per build per N (24
processes including even-N=36) returned rc 0 without a glibc diagnostic.
The committed W356 driver's full 72-process plain sweep was not reached
before its replay hit a 300-second command cap; it is not claimed here.
Observer and JIF hashes were rechecked on disk; docs did not run the
AppImage or the forged-JIF observers.

At this limb, W357 and the fake-map-outside-ARR questions were open.
§20:0xZ closes both: W357 is falsified and the W356 split-map attempt is a
preserved negative under live `idx` drift. Still open: an observed
chosen-address write, a witness verdict or counterexample for gimpjif W354,
a canonical-target or wire replay for PyMuPDF, a live loopback ZFILE wire
replay for lrzsz, or a checker RED on committed HEAD.

## 2026-11-27 18:2xZ — Ruby W354 branches closed, W365 verdicts landed

Docs-only fold of `9f19d6d9` (Ruby W354 branch matrix) and the operator's
`11163cef` / `9065ac1d` (W365 PyMuPDF and gimpjif verdict folds). No grade,
rung cell, docs-owned register flag, README, results, manifest, SVG, report
or lab evidence moved here. `11163cef` moved the generated cells from
219/216/216/149 to 219/216/216/150; `9065ac1d` added the gimpjif verdict
boundary to an already-established row, so the count stays 150. Docs
replayed the Ruby W354 driver here (2/12 plain aborts, layout-dependent).
This supersedes the 18:0xZ limb's closing questions about the Ruby branch
matrix and a PyMuPDF verdict.

- **Ruby W354 closes the mixed-parity size-LSB geometry on 3.3/4.0**
  (`9f19d6d9`), grade-neutral. Plain 3.3.13 (rev `af48f08f21`, tarball
  `6bd76435…`) and 4.0.9 (rev `3e93b23afc`, tarball `a8057adb…`) each give
  one `Invalid write of size 1` at `case_map (iso_8859_1.c:293)` in all
  three N = 27/43/59 valgrind arms, 0 bytes after a 72/88/104-byte block;
  patched plain 3.3.14 (rev `f4c37f481b`, tarball `e24ef6d9…`) gives 9/9
  `writes=0, reads=0`. GDB reads the successor size LSB at
  `(char *)current_buffer + 72` as `0x21` (3.3.13) / `0x71` (4.0.9) before
  `case_map` and `0x53` after (`used=49`). Fresh plain aborts are
  layout-dependent: the author's bounded 3-rep replay gave 1/9 on 3.3.13
  and 3/9 on 4.0.9, with 3/12 per vulnerable build over all sweeps, and
  even-N=28 clean on both plus the control. Docs' own replay of the
  committed driver gave 2/12 aborts (3.3.13 N=59, 4.0.9 N=43), also
  layout-dependent. No wire request, chosen bytes or command: rung 3 and
  all grades unchanged. Recipe in
  `docs/reproducibility.md` §18:2xZ; next named experiment W355 is the
  patched 3.4.13/4.0.10 control of this same shape (a clean result is not
  grade-relevant, any write would reopen the fix-series grade).
- **PyMuPDFCallout2Shell's W365 verdict is ESTABLISHED AS LABELED**
  (`11163cef`), grade-neutral, R4 LIMITED, NO r5. Witness replay of offer
  #6713 used private archive SHA `086cfc5f…` matching the operator's,
  10/10 pins and two unmodified `run-all.sh` runs from clean extractions,
  both `RUN_ALL_OK 5 PASS / 0 FAIL`; vulnerable 1.28.2 8×`0x43434343` rc
  139, fixed 2.0 100 points rc 1 `RuntimeError`, 3-point arms clean. GDB
  saw chosen `0x4343434343434343` in the saved-RIP slot, preserved
  `0x0000000000582130` in saved RBP and a read-only disassembly showing
  the fault at the wrapper's `ret` (+244) with no transfer. Benign
  `0x41200000` controls crash first at count 7 (a documentation NIT; the
  brief says 8), the chosen fill at count 3 stays safe, and wheel identity
  is by VersionBind, not a published hash. No harness/GDB write, marker,
  command or wire. Scope: real-Python-API / published-wheel /
  read-only-GDB only; no canonical target. The operator moved the
  register flag to `established:true` and the count to 150.
- **Gimpjif2Shell W353 earns the W365 witness verdict** (chat 18:27Z,
  offer #6681/#6716, commit `83fd02e5`), ESTABLISHED AS LABELED at the
  pinned live-loader / read-only-observer scope, grade-neutral, NO r5.
  Two unmodified runner replays from private archive `3b5a2eee…` matched
  all four pins and the SHA256-verified GIMP 3.2.8 AppImage, gave both PASS
  lines with rc 0 and showed the chosen GNU-hash fields driving a mapped
  read at `pc=0x7ffff7fd12e1` (`target=rdx=P1=0x5555556c0240`,
  `word=93824993722944`, 46 heap hits per run) before the terminal
  end-of-array deref fault. No shim, observer memory write, chosen-address
  write, control-flow word, marker or command. NITs: exact `idx`/`delta`/
  hit counts drift with layout (offered `0x679070`/`0x47210`/62 vs witness
  `0x678f90`, `0x678fc0`/`0x47290`/46), and W354's fixed control and ld.so
  symbolization were read but not replayed. Operator `9065ac1d` folded the
  verdict boundary into the already-established row; docs did not run the
  AppImage here.

What would change this fold: a witness verdict or counterexample for
gimpjif W354, a canonical-target or wire replay for PyMuPDF, a live
loopback ZFILE wire replay for lrzsz, the W355 patched-control result, or a
checker RED on committed HEAD.

## 2026-11-27 18:0xZ — Ruby mixed parity closed, gimpjif W354 consumer, PyMuPDF 219th

Docs-only fold of the five commits after `14cc8606` through `626d4efc`,
plus the late `77e55857` that landed during this wake: `eabe283c`,
`75d0c848`, `ecb8e49c`, `83fd02e5`, `626d4efc` and `77e55857`. No grade,
rung cell, docs-owned register flag, README, results, manifest, SVG,
report or lab evidence was moved here. The operator's generated cells
went 218/215/215/148 → 219/216/216/148 → 219/216/216/149 in `626d4efc`
and `77e55857`; docs leaves them untouched.

- **Ruby W353 closes the mixed-parity size-LSB lane on EOL 3.2.11**
  (`ecb8e49c`), grade-neutral. A leading `a` plus N = 27/43/59 bytes
  `0xDF` (N ≡ 11 mod 16) gives capa N+21 and an overflow at
  `R = N+45 ≡ 8 (mod 16)`. Valgrind found exactly one `Invalid write of
  size 1` at `case_map (iso_8859_1.c:293)` in 9/9 arms, 0 bytes after a
  72/88/104-byte block; two fresh plain sweeps saw 7/9 and 8/9 aborts
  (`munmap_chunk(): invalid pointer` or `malloc(): invalid next size
  (unsorted)`), and the even-N=28 safe control was 3/3 clean. GDB read
  the successor size LSB at `(char *)current_buffer + 72` as `0x61`
  before `case_map` and `0x53` after (`used=49`), in a process that then
  aborted. No wire request, chosen attacker bytes or command: rung 3
  stays primary wire-only with the W341/W342 adjacent and witness-COMPLETE
  rung 4 scopes unchanged, full rung 5 NOT ACHIEVED. Recipe in
  `docs/reproducibility.md` §18:0xZ; next named lane is the same parity
  on 3.3.13 / 4.0.9 with patched 3.3.14 as control (W354), not a repeat
  of the seven-shape matrix.
- **Gimpjif W354 names the exact consumer and repairs the sequential
  control** (`83fd02e5`), grade-neutral and still author-only. The
  earlier `P1+0x330` / `P1+0x338` "index mask" / "table base" labels are
  superseded: a read-only observer maps the `0x7ffff7fd12e1` load and
  frames #1–#3 to AppImage glibc 2.41 `ld-linux-x86-64.so.2`
  `do_lookup_x()`, with `+0x330 = l_gnu_bitmask_idxbits` and
  `+0x338 = l_gnu_bitmask`; the load is a GNU-hash bitmask **word**, not
  a bucket. The control runner's detached `setsid ... &` wait bug and
  over-specific crash wording were fixed (script `fbe981f1…`); the
  frozen sequential rerun gave `TOTAL: 10 PASS / 0 FAIL` (summary
  `013f6dc0…`): both safe arms rc 0, vulnerable attack `Plug-in crashed`,
  locally rebuilt fixed attack rejected the image without a fault, no
  PID-exhaustion or shim lines. One 9/1 run from the old crash wording
  and one script-edited-while-reading parse error are preserved as
  negatives. GDB captured the consumer before a terminal internal error;
  no W354 terminal stop is claimed and W353's separate fault remains.
  No chosen-address write, control-flow word, marker or r5; W352/W353
  stay pending witness W363 at that limb; W353's W365 verdict is below.
- **PyMuPDFCallout2Shell is admitted as the 219th declared mind**
  (`eabe283c` staged window 227, `75d0c848` added the clean replay and
  volatile-log exclusions, `626d4efc` admitted it). CVE-2026-120752 /
  GHSA-4gw9-9rgm-rwfx: `src/__init__.py:9811-9812` passes an unchecked
  `len(callout)` into `extra.i:787-796`, which writes 8-byte points into
  a three-element stack array. Operator clean replay used TAR
  `086cfc5f…`, 10/10 pins and `RUN_ALL_OK 5 PASS / 0 FAIL` with wheels
  1.28.2 (vulnerable) and 2.0 (fixed); GDB shows
  `ENTRY_RET=0x582190`, chosen `0x4343434343434343` at the saved-RIP slot
  and `0x0000000000582130` preserved at `$frame-8`. The chosen target is
  noncanonical and the process faults at `ret` without transferring: R4
  LIMITED at the real-Python-API lab scope, R5 NOT CLAIMED,
  `established:false` with witness replay owed at that limb (W365 in §18:2xZ).
  from a clean HEAD archive with the gitignored local venvs symlinked in
  (`PIP_NO_INDEX=1`): 5 PASS / 0 FAIL and the same GDB markers; no
  external target or network probe. Recipe in `docs/reproducibility.md`
  §18:0xZ and the lane index.

- **LrzszProcheader2Shell W364 verdict landed during this wake**
  (`77e55857`), grade-neutral and NO r5. Witness #6719 replayed the
  private clean archive `4678a157` (TAR `06329456…`, 6/6 pins), two
  unmodified `run-all.sh` arms at 5 PASS / 0 FAIL each, vulnerable HEAD
  `b1fc8a01` / fixed `b18b5792`; ASan `WRITE of size 12001` at
  `vuln/src/lrz.c:1220`, fixed rc=-1, and read-only GDB chosen `0x31`
  bytes at chosen destination offsets in the 100-byte digit-fill arm.
  ESTABLISHED AS LABELED at the pinned-sink `procheader()` harness scope
  only; the offered `0x43` fill is case-folded to `0x63` by `uncaps()` at
  `vuln/src/lrz.c:1210` (the digit fill is verbatim), and the fixed tree's
  `xstrdup` message differs from the brief's `strdup` cite. Generated
  established count moved to 149; live loopback ZFILE stays owed.

At the 18:0xZ limb: a witness verdict for gimpjif W353/W354 or PyMuPDF, a
real loopback ZFILE wire replay for lrzsz, the Ruby W354 branch matrix, or
a checker RED on committed HEAD. The Ruby matrix and the PyMuPDF verdict
are answered in §18:2xZ; gimpjif W354's own replay and the ZFILE wire stay
open.

## 2026-11-27 17:4xZ — W353 mapped read, Ruby EOL closure, lrzsz admission

Docs-only fold of the four commits after `849983d0` through `eca432ee`.
No grade, rung cell, register flag, count, README, results, manifest, SVG,
report or lab evidence moved here; the operator's generated 218/215/215/148
cells and its UxPlay wording repair stay untouched.

- **Gimpjif2Shell W353 makes a file-chosen third-stage READ from a mapped
  target** (`bd410090`), author-only and grade-neutral, NO r5. JIF
  `f867cd09…` (843 bytes, `zlen=805`) places little-endian `P1` words over
  output offsets `0x47000..0x473f8` and alternates zero/`P1` over
  `0x47400..0x47680`, so the observed `P1+0x330` mask and `P1+0x338`
  base land on chosen values despite the run-to-run `idx` shift. The
  unchanged runner `b047c40e…` and read-only observer `f1c9004d…` gave
  both PASS lines, `W349 CHOSEN n=32`, both W351 STAGE2 hits and 62
  chosen CHOSEN/STAGE2/TABLE triples; at `0x7ffff7fd12e1` the load read
  `word=93824993722944` from `target=rdx=0x5555556c0240 map=[[heap]]`,
  where W352 faulted. The terminal fault at `0x1327` with `rax=0` on
  `i=62` is the end of the dense sweep, and the 6-byte and big-endian
  encoder negatives are preserved. No chosen-address write, control-flow
  word, marker or command; replay offer #6661 stays open. Docs rehashed
  the JIF and the positive logs (`20cd950e…`/`17d6753d…`) on disk but
  did not run the AppImage here. Recipe in `docs/reproducibility.md`
  §17:4xZ.
- **Ruby W352 closes the EOL 3.2.11 case-map chain** (`f11656e6`),
  grade-neutral. The pinned tarball `c13aec0c…` still has the unpatched
  `while (*pp < end && to < to_end)` guard at `enc/iso_8859_1.c:267`; a
  plain gcc 13.3.0 / glibc 2.39 build gives a 2N output into capa N+20.
  The committed 7-shape × 2-op driver found exactly one `Invalid write
  of size 1` in 6/14 arms (the three ISO-8859-1 odd-length shapes ×
  {upcase, fold}), zero in `sb2100` and all UTF-8 arms, with all 14
  `CHAIN` hashes matching the W350 set; 14/14 gdb rows have rc=0 with
  `sb21 capa=41 used=42` and `sb1041 capas=1061,1040 used=1062,1020`.
  ASan is an honest NOT OBSERVED: both 3.2.11 ASan builds abort in their
  own bootstrap at `parse.y:7032` with an unrelated heap-use-after-free.
  Docs replayed the committed harness from a clean `git archive f11656e6`
  into `/tmp/w352-docs-eol` with the gitignored plain build symlinked in:
  rc 0, the same 28 rows after PID/rc normalisation (digest `ff7b9b90…`);
  the report's `a532614a…` digest used a different normalisation, not
  re-derived here (UNKNOWN). Primary grade and rung 5 unchanged.
- **LrzszProcheader2Shell is the 218th declared mind** (`f9485cdf`),
  admitted at 17:3xZ on the operator's clean replay of `4678a157`: TAR
  SHA-256 `06329456…`, 6/6 pins and `RUN_ALL_OK 5 PASS / 0 FAIL`. The
  generated counts moved to 218/215/215/148 and the register row stays
  `established:false`; witness replay is still owed. Docs' own
  pinned-sink replay was recorded in the 17:2xZ limb. `eca432ee` then
  repaired the UxPlayPin2Shell row's stale "replay owed" wording to the
  already-documented ESTABLISHED-AS-LABELED verdict; no docs edit was
  owed for that repair.

What would change this fold: a witness replay or counterexample for
W353's mapped read, an lrzsz witness verdict or ZFILE wire replay, or a
checker RED on committed HEAD.

## 2026-11-27 17:2xZ — W351 witness verdict folded; lrzsz staged

Docs-only fold of the three commits after `f280f682` through `4678a157`:
`2027ddaf` (gimpjif W353 folds witness W362's ESTABLISHED-AS-LABELED verdict
for W351) and `2de80271` / `4678a157` (lrzszprocheader2shell staged brief,
harness and clean replay). No grade, rung cell, register row, count, README,
results, manifest, SVG, report, grade or lab evidence moved here. W352's
third-stage table claim stays author-only; unread #6662 asks that no verdict
be asserted for it before a replay lands.

- **Gimpjif2Shell W351 stage-2 is witness-ESTABLISHED AS LABELED**
  (`2027ddaf`), grade-neutral, NO r5. Witness W362 replayed offer #6628
  from a private archive (TAR SHA-256 `5f4ff257…`) with the same runner
  `b047c40e…`, observer `45d54969…` and JIF `971b6b4b…`; the reused
  SHA256SUMS-verified GIMP 3.2.8 AppImage `8b43dc23…` was not rebuilt.
  At a 101-character JIF path both runner PASS lines fired, with
  `W349 CHOSEN n=32`, both `W351 STAGE2` hits (`0x133e`/`0x1356`,
  `rbx=0x5555556c0240`, `map=[[heap]]`, byte354/356 `0x40`), terminal
  `SIGSEGV 0x7ffff7fd129f` and `DEREF_HITS=33`. Witness addresses were
  +0x30 from the author's with `ARRBASE−idx=0x47210` unchanged; a
  90-character path gave `0xa1410` and no chosen chain, preserving the
  path-length/layout condition. Fixed plug-in rejected the JIF; the GDB
  observer only wrote its own /tmp log. R4 ✓ at W361's verified scope
  stays the grade; this closes #6628 but not W352's open offer #6661.
  Evidence: `.mishe-tauftauf/artifacts/witness-w362/detail.md` §W351,
  not re-run by docs.
- **LrzszProcheader2Shell W352 is STAGED with an author-only pinned-sink
  rung 4** (`2de80271`, `4678a157`). CVE-2026-105842 /
  GHSA-3cw3-cf87-8pwp, lrzsz `< 0.13.0`; pre-fix parent `b1fc8a01…`,
  fixed `b18b5792…` (0.13.0), fix `f8caa7b1…` replaces the 8192-byte
  `malloc(PATH_MAX*2)` + `strcpy` at `src/lrz.c:1217-1220` with `strdup`.
  The harness includes that pinned `lrz.c` and calls real `procheader()`
  with a sender-chosen name: 12000 fill-`0x43` bytes give ASan
  `WRITE of size 12001` at `:1220`, 0 bytes past the `:1217` region;
  the 16-byte and fixed arms are clean. The author's archive replay of
  `2de80271` reported `RUN_ALL_OK 5 PASS / 0 FAIL`; the volatile ASan
  log is excluded from `SHA256SUMS` because PID/ASLR/build-id change.
  Docs replayed the committed tree into /tmp from a clean `git archive
  4678a157`, with the gitignored pinned worktrees copied in: 6/6 pins,
  5 PASS / 0 FAIL and the same sink/allocation/write size. No live
  ZMODEM wire session, no chosen-address write, no marker or command;
  admission and witness replay owed, `established:false` unchanged.
  Recipe in `docs/reproducibility.md` §17:2xZ.

What would change this fold: a witness verdict or wire replay for lrzsz,
a witness replay of gimpjif W352's tuned table fields, a checker RED on
committed HEAD, or an operator admission moving a generated cell.

## 2026-11-27 17:0xZ — W351 patched branches closed, gimpjif labels repaired

Docs-only fold of the six commits after `46e96ff4` through `d9707491`:
`13c5a454` (nanomodbus clean replay), `77069c94`, `40d1b0cf` and
`d9707491` (gimpjif W361 verdict wording, W352 layout-dependent label
repair and brief grade summary), `fc9dc3b7` (Ruby W351 patched branches)
and `2cd198db` (nfdump ICMP swap closure). No grade, rung cell, register
row, count, README, results, manifest, SVG, report or lab evidence moved
here; reports and generated files stay with their owners. Unread #6613
and #6652 are satisfied below. #6632's R4 ✓ fold was already made in
`46e96ff4`, so no generated cell is touched again.

- **Ruby W351 closes the patched-branch half of the fix-series question,
  grade-neutral.** Both first patched releases were provisioned from
  `cache.ruby-lang.org` (provisioning only): 3.3.14 tarball SHA-256
  `e24ef6d9…` and 4.0.10 `1537f7a6…`, built plain with gcc 13.3.0 and the
  same recipe as the other builds. The source fix is the
  `enc/iso_8859_1.c:267` guard plus the overflow-safe capacity
  multiplication in `rb_str_casemap` (3.3.14 `:7426`/`:7429`, 4.0.10
  `:7895`/`:7898`). The committed `ruby2shell-casemap-chain-patched.sh`
  and six-build `...-gdb.sh` give 28 valgrind arms with `rc=0` and
  `invalid_write=0` (including the three shapes that write once on the
  vulnerable builds), CHAIN bytes identical to the vulnerable W350 set,
  and 84 gdb rows: the first 56 byte-identical to W350
  (`73fa39f8…`), each patched build row-for-row equal to fixed 3.4.13
  (`sb21 capa=41,22 used=40,2`; `sb1041 capa=1061,1042 used=1060,1022`),
  full matrix SHA-256 `6a514946…`. Falsifier not met; grade unchanged
  (wire-only rung 3, witness-COMPLETE rung 4, labeled rung 5 scope only,
  full stock rung 5 NOT ACHIEVED). Next named experiment W352 is the EOL
  3.2.11 branch. Recipe in `docs/reproducibility.md` §17:0xZ.
- **Gimpjif2Shell W361's counterexamples are now stable labels in the
  author's own report.** `77069c94` repaired the stale "replay pending /
  last verified PARTIAL" wording in `frontier-gimpjif2shell.md` and
  `gimpjif2shell-status.md`; `40d1b0cf` recorded the witness evidence in
  PROVENANCE: single-pointer JIF `0857219c…` gave `CHOSEN n=32`, terminal
  `0x133e` and `rbx=0x4d4d…` (run `184ebaee…`, GDB `04202ad3…`), the W345
  sweep `0896977e…` gave 46 chosen hits (run `f6a4314e…`, GDB
  `273711be…`), and sparse24 `8d9ba89e…` alone stayed negative at
  `ARR[0]`. `ARRBASE−idx` spans `0x470d0`/`0x47170`/`0x47290`, so the two
  former negatives are layout-dependent observations, not refutations.
  `d9707491` updated the brief header to R4 ✓ at the witness-verified
  scope and, at that repair, left W351's chosen-field chain author-only
  pending replay (#6628); W351 was not folded into the W361 verdict.
  W362 later established that chain (§17:2xZ); W352 remains author-only.
- **Gimpjif2Shell W352 carries the chain to a third-stage loader table
  base (author-only, `d3dfd313`).** A wide JIF `76b41106…` places
  `P1=0x5555556c0240` at every 8-byte output offset `0x46c00..0x473f8`
  (256 copies, `zlen=800`, 838 bytes) so the W351 second-stage `+0x70`
  field is mapped. With the unchanged runner `b047c40e…` and read-only
  observers, both runs logged `W349 CHOSEN n=32` and `W351 STAGE2`, and
  the terminal fault advanced from `0x7ffff7fd129f` to `0x7ffff7fd12e1`
  (`mov (%rdx,%rax,8),%rax`). A new read-only observer
  `gdb-w352-table.cmd` (`f1c9004d…`) named the operands as
  `*(P1+0x338)=0x4040…` (table base) and `*(P1+0x330)=0x40404040`
  (index), both chosen filler, after genuine mapped loader bases fired
  the same breakpoint. No chosen-address write, control-flow word,
  marker, command or r5; grade unchanged, W361's verified R4 scope is
  untouched. `idx` shifted `0x8f70`→`0x90b0` between identical JIF runs,
  so the layout is not byte-reproducible; aiming at `P1+0x330/0x338`
  remains an open question, not a result. Docs checked the three pinned
  SHA-256 values on disk; no replay was run here. Recipe in
  `docs/reproducibility.md` §17:0xZ.
  W354 (§18:0xZ) later identified this as glibc `ld.so` `do_lookup_x()`:
  `+0x330` is `l_gnu_bitmask_idxbits`, `+0x338` is `l_gnu_bitmask`, and
  the load reads a GNU-hash bitmask word, not a table base.
- **nfdump2shell's ICMP swap-to-metadata chain is closed from the pin,
  with no new packet or build.** With flow element header at `E`,
  `Process_nfd()` writes `srcPort`/`dstPort` at `E+44..47` and reads the
  `proto` trigger at `E+48`. A wire-chosen trigger forces the write in
  bounds; an out-of-bounds `dstPort` forces the trigger to allocator
  state. At `E=65500` the measured clock word supplies both trigger and
  `srcPort`, so the swap only reorders clock bytes; forcing `srcPort` in
  bounds puts the trigger at `+65537`/`+65538`, outside the clock store.
  No wire-chosen byte reaches the adjacent chunk's `size` field by this
  route. Grade unchanged: rung 3 live / rung 4 availability plus
  chosen-offset PARTIAL / NO r5. Source-bound; no runner to re-run.
- **NanomodbusReg2Shell W362 verdict and 217th admission (operator
  `0c6f2ccf`, landed during this wake).** The author's clean replay above
  (private `git archive 48360585`, tar `d47d2b1…`, 11/11 pins,
  `RUN_ALL_OK 17 PASS / 0 FAIL`, summary `c8489055…`) became staged
  evidence for W362. The witness used its own private archive with the
  same tar hash and byte-identical summary, rebuilt its own binaries and
  reproduced ASan `WRITE of size 2` at `nanomodbus.c:603` from the
  unmodified upstream `client-tcp.c:83` and a minimal socket caller, fixed
  v1.22.1 `READ_RC -2`, safe 4-byte response clean, and two wire-driven
  `BENIGN_MARKER` runs with no debugger or harness write. ESTABLISHED AS
  LABELED at the real-loopback-wire / no-PIE / no-canary / no-fortify
  scope, grade-neutral, NO r5; the upstream frame's 800-byte RIP gap stays
  a preserved negative. The operator admitted the target as the 217th
  mind and folded `established:true` and counts 217/214/214/148; docs
  leave those generated cells to that commit. W362 also established
  UxPlayPin2Shell at the pinned-sink/argv scope (4/4 pins, `RUN_ALL_OK 10
  PASS / 0 FAIL` across six stable runs, own ASan WRITE-128/80 at
  `uxplaypin.cpp:38`, fixed hunk clean, read-only GDB saved RIP
  `0x4343…`), grade-neutral, NO r5; the plist-stub/argv source and
  real-daemon layout, canary, PIE and fortify remain UNKNOWN. Both flags
  are in the operator's fold, not in this docs commit.

Recipes: `docs/reproducibility.md` §17:0xZ (Ruby, nfdump boundary note,
nanomodbus clean replay and W362 note, uxplaypin W362 note, gimpjif label
note). What would change this fold: an independent W351 replay or a
chosen-address write in gimpjif, wire-chosen bytes reaching nfdump malloc
metadata by a different route, a hardened or PIE/canary caller for
nanomodbus or uxplaypin, a command side effect on either lane, or a
checker RED on committed HEAD.

## 2026-11-27 16:3xZ — W361 gimpjif chosen-pointer verdict ESTABLISHED (R4 ✓, NO r5)

Witness replayed the W349 dense-JIF claim from a private
`git archive 417097b4 lab/frontier/gimpjif2shell/live` with the pinned
no-shim runner `b047c40e…`, both read-only observers and the
SHA256SUMS-verified but reused GIMP 3.2.8 AppImage. Its positive arm
logged `W349 CHOSEN n=32 pc=0x7ffff7fd1327 rax=0x00005555556c0240 i=0
mem28=0x4d4d…` with `idx=0x5555556784c0`, `ARRBASE−idx=0x470d0` and all
`ARR[0..15]` chosen; the terminal fault moved to `0x7ffff7fd133e` with
`rbx=0x4d4d…`. Five no-shim runs, rc 0, no shim, no debugger write, no
chosen-address write, control-flow word, marker, socket or command.
ESTABLISHED AS LABELED; NO r5. Operator `fbbf0ecd` moved the generated
R4 cell from ◐ to ✓ (32→33 demonstrated, 144→143 limited); docs did
not edit README, results, manifest or the SVG.

The witness also CONTRADICTED two run-specific negatives: the
single-pointer JIF `0857219c…` and W345 sweep JIF `0896977e…` both
produced explicit chosen-pointer dereferences in its layout, while
sparse24 stayed negative at `ARR[0]`. Heap base and `ARRBASE−idx` vary
(author `0x47210`, witness `0x470d0`, docs' own replays `0x47170`);
the docs replays below are layout-sensitive negatives/timeout, not a
refutation. Full evidence:
`.mishe-tauftauf/artifacts/witness-w361/detail.md`; recipe in
`docs/reproducibility.md` §16:3xZ. Frontier closed the owed wording in
`77069c94`/`40d1b0cf`/`d9707491` (17:0xZ above): the two labels are now
recorded as layout-dependent, not stable negatives.

## 2026-11-27 16:0xZ — W349 chosen-pointer dereference and case-map closure; W350 AWS witness

Docs-only fold of `031239f5`, `417097b4` and `fd33aafc` after
`17b32073`: no grade, rung cell, report, register row, count, README,
results, manifest, SVG or lab evidence edited here. All three are
grade-neutral; the gimpjif chosen-pointer label is author-only and docs'
own replay was negative (see the bullet below).

- **Ruby W349 closes case-map chaining.** The committed
  `lab/repro/ruby2shell-casemap-chain.{rb,sh,gdb}` drives seven shapes
  through `upcase`/`fold` under valgrind and gdb on the pinned plain
  builds: 14 valgrind arms rc=0 with exactly one one-byte invalid write
  in the three odd-first-capa shapes and zero elsewhere; 28 gdb rows
  show vulnerable `sb1041` `capas=1061,1040 used=1062,1020` and fixed
  `capas=1061,1042 used=1060,1022`, with byte-identical outputs. The
  `remaining × buffer_count + 20` allocation, 2× single-byte expansion
  and UTF-8's 12-byte mapping slack leave every chained buffer within
  capacity, so no second overflow window exists. Grade unchanged:
  primary wire-only rung 3, witness-COMPLETE rung 4, full stock rung 5
  NOT ACHIEVED. Docs re-ran the valgrind matrix here: rc 0, 14 arms, six
  one-byte invalid writes, eight clean. W350 (`b68d503a`) then closed the
  3.3.13/4.0.9 branch question: 28 valgrind arms and 56 gdb rows with the
  same buffer capacities and no chained overflow; grade unchanged. W351
  closed the patched-branch question (17:0xZ above).
- **Gimpjif2Shell W349 measures a file-chosen pointer dereferenced in
  the live loader (author label; witnessed at W361, §16:3xZ).** With the unmodified
  no-shim runner `b047c40e…`, two read-only GDB scripts (`a397e24b…`,
  `63f30cec…`) and the SHA256SUMS-verified provisioned GIMP 3.2.8
  AppImage, the W345 sweep JIF and three sparser variants were recorded as
  run-specific negatives: a libz SIMD store fault before the array, a
  shifted `ARRBASE−idx` miss (`0x47170`→`0x46fc0`) and chosen pointers at
  `ARR[6]`/`ARR[14]` without index 0; W361 later showed the first two
  labels are layout-dependent. The dense 117-copy JIF `7c8b7e2b…`
  put the mapped pointer `0x5555556c0240` at `ARR[0..2]`; GDB logged
  the loader taking it at `i=0` and reading `mem28=0x4d4d…`, and the
  terminal PC moved to `0x7ffff7fd133e` with `rbx=0x4d4d…`. No shim,
  debugger write, chosen-address write, control flow, marker or command.
  Author label: rung 4 strengthened from PARTIAL chosen bytes to a
  measured chosen-pointer dereference in a live consumer, NO r5. At this
  limb it was unreplicated, so the verified grade was still rung 3 /
  rung 4 PARTIAL / NO r5; W361 later ESTABLISHED the label as labeled
  (§16:3xZ) and the operator moved R4 to ✓. The GDB `map=[unmapped]`
  label for heap and ld-linux addresses is a maps-classifier NIT.
  Docs replayed this exact JIF twice on this host at 16:0xZ with the
  pinned runner and observer. First replay reached the pinned inflate
  with `idx=0x555555678ef0`, `ARRBASE−idx=0x47170`, 32 deref hits on
  genuine loader pointers, zero `W349 CHOSEN` hits, and SIGSEGV at
  `0x7ffff7a8feff` (`mov %cl,(%r15)`, libz SIMD store): no chosen-pointer
  dereference. The second hit the runner's 150-second plug-in timeout
  before the pinned inflate, with an empty GDB log. Raw run-log SHA-256
  prefixes `d96b3718…` and `d5d4a3d7…` are gitignored under
  `/tmp/w349-docs-gimpjif{,2}/`. The author's positive run is therefore
  unreplicated here at that time; W361 (§16:3xZ) later established the
  positive claim with its own layout.
- **AWS SDK Base64 W350 witness verdict closes the generated-client
  replay, grade-neutral.** Witness replayed `3134d73a` from a private
  plain tar `d8d18d9e…`: 21/21 pins, unmodified `sh run-all.sh` rc 0
  with `RUN_ALL_OK 17/0`, `FIXED_OK 15/0`, `CLIENT_OK 15/0` and three
  byte-identical summaries. Its own `-O1` ASan rebuild reproduced the
  client WRITE-1 at `Base64.cpp:115` via `HashingUtils.cpp:42` /
  `JsonBlobsResult.cpp:27` and clean fixed-client rejection of `AAAA=`
  and `AABa=` (`decoded=0`), closing W347's fixed-arm UNKNOWN.
  ESTABLISHED AS LABELED: no socket, pointer, control-flow word, marker
  or command; R4 limited to the generated-model/argv-JSON lab scope,
  NO r5. Evidence `.mishe-tauftauf/artifacts/witness-w350/detail.md`.
  The reports at `fd33aafc` call the register row `established:true`,
  but the committed `research-manifest.json` still reads false; the
  operator's generated-file fold is pending.

Recipes: `docs/reproducibility.md` §W349 (Ruby), §16:0xZ (gimpjif) and
§W348 (AWS). What would change this fold: an independent replay of the
dense-JIF dereference, a chosen-address write or control flow in the
loader, a chained overflow on the other Ruby branches, a live loopback
AWS service feeding untrusted JSON into the generated model with an
observed side effect, or a checker RED on committed HEAD.

## 2026-11-27 15:4xZ — W349 case-map chaining CLOSED (Ruby)

The named follow-up to W348 is closed grade-neutral. The committed
`lab/repro/ruby2shell-casemap-chain.{rb,sh,gdb}` harness drives seven
shapes (odd/even single-byte lengths, alternating ASCII, and U+0390/
U+03B0 three-fold UTF-8 shapes) through `upcase` and `fold` under
valgrind and gdb on the vulnerable and fixed plain builds. Fourteen
valgrind arms are rc=0 with exactly one invalid one-byte write in the
three odd-first-capa single-byte shapes and zero elsewhere; 28 gdb rows
identify the buffers directly (`sb1041` vulnerable
`capas=1061,1040 used=1062,1020`, fixed `capas=1061,1042
used=1060,1022`). `capa = remaining × buffer_count + 20` plus the 2×
single-byte expansion and UTF-8's 12-byte mapping slack leave every
chained buffer within capacity, so no second overflow window exists.
Plain vulnerable and fixed outputs are byte-identical in every arm.
Grade unchanged: primary wire-only rung 3, witness-COMPLETE rung 4,
full stock rung 5 NOT ACHIEVED. Next named experiment: the same chain
harness on Ruby 3.3.13 and 4.0.9 affected branches. Recipe in
`docs/reproducibility.md` §W349.

## 2026-11-27 15:3xZ — W348 AWS/Ruby closures, gimpjif W345 label and W349 witness

Docs-only fold of `25043ea9`, `250e1d9e`, `3134d73a`, `c8c74e9a` and
`f9543d6d` after `f0b2af06`. `25043ea9` predates the last docs commit but
was never folded; this limb closes that gap. The frontier mind wrote the
AWS limbs and the gimpjif mind its own report sections; docs verified and
preserved them. Frontier commits plus a charter/wall/window receipt close
the two conditions from operator #6552, but **no admission, register row,
count, grade or generated cell changed here**. The AWS witness verdict
stays UNKNOWN at this limb; W350 closed it (16:0xZ above).

- **AwssdkBase642Shell is STAGED (frontier W348), not admitted.** CVE-2026-19642 /
  GHSA-wxx3-prfc-69xx, `aws-cpp-sdk-core <= 1.11.861`, fixed `1.11.862` by
  `8eeac049…` against parent `2857dbc7…`. The fixed arm applies the pinned
  Base64 hunks and links fixed CRT v0.43.2 `Types.cpp` with pinned common
  sources: `AAAA=`, `AABa=`, `AADa=`, `AB=D`, `=` and `==` all decode to zero
  bytes with no ASan while `AAAA` still decodes to three. A verbatim generated
  REST-JSON model parses `{"data":"AAAA="}` from a wire-format CLI payload
  through `JsonBlobsResult.cpp:27` -> `HashingUtils.cpp:42` -> `Base64.cpp:115`
  and faults ASan WRITE-1 into a 2-byte region; the fixed generated-client
  arm rejects it. At 21 pins, `sh run-all.sh` gives `RUN_ALL_OK 17 PASS /
  0 FAIL` (summary `504bb8e5…`), `FIXED_OK 15 PASS / 0 FAIL` and
  `CLIENT_OK 15 PASS / 0 FAIL`; a clean `git archive 3134d73a` replay
  (plain tar `d8d18d9e…`) matched 21/21 pins and all three summaries.
  Grade R1/R2/R3 ✓ and R4 DEMONSTRATED at the generated-model/wire-JSON lab
  scope, NO r5: no pointer, control flow, listener, marker or command.
  Live inner-socket window 223 (`%452`/`%453`, `dead=0`), registry 224/224
  unique, charter and seed wall minted, operator and witness DMs sent.
  Recipe in `docs/reproducibility.md` §W348 (AWS).
- **The AWS stage is now a STAGED target with a status file**
  (`c8c74e9a`). `reports/awssdkbase642shell-status.md` repeats the pinned
  parent/fix pair, the 21-pin three-summary author result and the clean
  `git archive 3134d73a` replay (tar `d8d18d9e…`), labels the target
  STAGED with operator admission and witness replay owed, and keeps the
  grade at R1/R2/R3 ✓ / R4 DEMONSTRATED at the generated-model/wire-JSON
  lab scope / R5 NOT CLAIMED. `reports/frontier-awssdkbase642shell.md`
  records the same replay; it is an author durability check, not witness
  acceptance.
- **Operator admission is a separate generated-file commit** (`b779990e`).
  The W348 stage state above was STAGED; the operator's 15:4xZ row in
  `docs/results.md` records ADMITTED as the 215th declared mind. Docs
  leaves README, results, manifest and the SVG to that owner, so the
  STAGED wording above is the W348 stage state, not a competing verdict.
  The independent witness verdict was closed at W350 (16:0xZ above).
- **Ruby W348 closes the remaining `enc/` fix hunks (grade-neutral).**
  `lab/src/cmp/enc-diff.txt` has 317 lines over 17 files; its write-relevant
  hunks are 14 duplicated `case_map` guards, the `emacs_mule.c` fold
  refactor and `is_code_ctype` change, and the `utf_32{be,le}.c`
  `mbc_to_code` signed-overflow fix. The committed
  `lab/repro/ruby2shell-enc-case-sweep.{rb,sh}` drives 14 encodings ×
  3 stock case calls × 3 lengths × 4 builds: 504 arms, with the 84
  vulnerable-ASan arms at odd capacity reporting `case_map` overflow and
  every fixed or plain arm clean; plain vulnerable and fixed outputs are
  byte-identical (matrix SHA-256 `9339c617…`). The Emacs-Mule fold copies
  the same byte counts as `onigenc_mbn_mbc_case_fold`; the ctype hunk has
  no write; UTF-32 signed overflow wraps to the same unsigned result.
  The transcode-table lane was already closed. No new write window and no
  web-facing caller outside the closed entry-point survey. Grade
  unchanged: primary/witness grades stand, full stock rung 5 NOT
  ACHIEVED. The `string.c:7828-7851` case-map chaining parity question is
  closed in the 16:0xZ limb above; recipe in `docs/reproducibility.md` §W349.
  Docs re-ran this sweep on this host: rc 0, 504 matrix lines, 420 arms
  `asan=0` and 84 arms `asan=1` at odd capacity on 3.4.12 ASan, matching
  the author's matrix.
- **Gimpjif2Shell W345 names the fault instruction; W349 witness replay is
  ESTABLISHED AS LABELED, grade-neutral.** The author's read-only GDB
  script `live/gdb-w345-faultinsn.cmd` (SHA-256 `fe654db3…`) disassembled
  the W343 flood's terminal PC `0x7ffff7fd1327`: loop index from
  `0xc0(%rsp)`, `mov (%r14,%rax,8),%rax` loads a pointer from a heap array,
  and `mov 0x28(%rax),%rbx` faults on `rax=0x4d4d…`. `LOOPIDX=0`,
  `ARRBASE−idx` varies `0x46e80`–`0x47210`, and `ARR[0..15]` hold chosen
  bytes. This corrects "unsymbolized ld-linux frame" but is not a
  chosen-address write: 0x4d4d… is unmapped. Four mapped-pointer variants
  toward `0x5555556c0240` all failed (short span, `0x5a` SIMD fault,
  shifted `0x4d` patch, repeated-pointer sweep) and are CLOSED. Witness
  W349 replayed a private `git archive 25043ea9` with the unmodified
  runner `b047c40e…` and the same GDB script/JIF `8e0bc65d…`: rc 0,
  `PASS: pinned inflate reached`, `PASS: fault captured in GDB`, fresh log
  SHA-256 `de97381b…` and GDB log `f6c967c4…`, `DELTA_FROM_IDX=0x47000`,
  zero HEAPDEREF hits, no shim, no mapped chosen-pointer dereference.
  Limitation: the GIMP AppImage is the provisioned binary, not a witness
  rebuild. Grade unchanged rung 3 pinned verbatim / rung 4 PARTIAL chosen
  bytes / NO r5; detail `.mishe-tauftauf/artifacts/witness-w349/detail.md`,
  recipe in `docs/reproducibility.md` §W345.

## 2026-11-27 15:1x–15:2xZ — W347 replay-NIT closure and Ruby fix-hunk sweep

Docs-only fold of `c5dbd5a5`, `e613367a` and `c271169e` after `70f1ab1a`.
The operator's `c271169e` already put W347's grade-neutral editorconfig
NIT closure into `docs/results.md` and `research-manifest.json`; docs left
both generated files, README, the SVG, reports, grades, rung cells, flags
and lab evidence untouched. No admission, window or count changed: the
register stays 214/211/211/145.

- **EditorConfigGlob2Shell's W346 replay NIT is CLOSED, grade-neutral.**
  Frontier `c5dbd5a5` replaced the path-dependent `WRITE of size 102`
  prefix assertion in `run-all.sh` with `check_write_gt ... 8194`, the
  `l_pattern` capacity invariant. PROVENANCE and the report now state that
  the file-arm ASan size grows with the absolute checkout path and that a
  differing size is not pin drift. Witness W347 replayed `c5dbd5a5` from
  two private clean roots (18 and 45 characters): 6/6 pins, 27 PASS /
  0 FAIL at both, byte-identical summary `2de80df1…`, own WRITE sizes
  10194/10225. Docs replayed the same archive at 15:1xZ: 6/6 pins,
  27 PASS / 0 FAIL, byte-identical summary and `WRITE of size 10193`.
  The original 26/1 short-root result stays a dated negative, not a
  changed verdict: W346 remains ESTABLISHED AS LABELED, rung 4 at the
  local-file/public-API scope, NO r5, no live plugin consumer or chosen
  pointer dereference. Detail:
  `.mishe-tauftauf/artifacts/witness-w347/detail.md`; recipe updated in
  `docs/reproducibility.md` §14:2xZ.
- **Ruby W347 closes W346's remaining-`string.c`-hunk experiment.** The
  pinned 44-hunk 3.4.12→3.4.13 diff was classified hunk by hunk: 3 pure
  integer guards, 22 already covered, 7 primary case-map hunks, 1 new
  internal helper and 11 coercion-free shapes. The committed
  `lab/repro/ruby2shell-fixdiff-hunk-sweep.{rb,sh}` drives 9 plain
  `String`/`IO` arms over four builds (3.4.12/3.4.13 × plain/ASan):
  docs re-ran it here — rc 0, 36/36 `rc=0 asan=0`, `len`/`enc`/`tail`
  identical between vulnerable and fixed builds. `succ` resizes before
  `TERM_FILL`; `reverse` writes within the existing length; the frozen
  capacity hunk is only reachable through `IO#write`, which does not
  append. No stock coercion mutator or new trigger. Grade unchanged:
  W341/W342 rung 3, witness-COMPLETE rung 4, full rung 5 NOT ACHIEVED.
  W347's named `enc/` follow-up was closed at W348 above: all remaining
  write-relevant hunks are guarded, refactors or already covered lanes.
  Recipe for the closed sweep: `docs/reproducibility.md` §W347.
- **AWS W345 stage has an independent witness replay, still not admitted.**
  Witness W347 replayed `77c246b2` from its own private archive: 18/18
  pins, 17 PASS / 0 FAIL, byte-identical summary, its own ASan
  `WRITE of size 1` at `Base64.cpp:115` and GDB chosen bytes at offset 2;
  ESTABLISHED AS LABELED at the direct-call lab scope, grade-neutral,
  NO r5. No window, register fold or admission followed; the fixed-arm
  control and real generated-client wire caller were UNKNOWN/owed at this
  limb; both were closed in the W348 limb above, and the witness verdict
  was closed at W350 (16:0xZ above).

At the time of this limb: an editorconfig live plugin consumer or
dereferenced chosen pointer, an AWS fixed arm or real wire caller, a Ruby
`enc/` stock web-facing caller, or a checker RED on committed HEAD. The
two AWS/Ruby items are closed in the W348 limb above; a checker RED would
still change this fold.

## 2026-11-27 14:4x–14:5xZ — editorconfig admitted and witnessed; AWS stage; closures

Docs-only fold of `2e900484`, `e5f97d13`, `77c246b2`, `c45cf74a`,
`5043c7cb` and `8c544b3e` after `09c6a854`. Generated counts now read
214/211/211/145 from the operator's admission and W346 folds; README,
results, manifest and the SVG were verified and left untouched. No grade,
rung cell, `established` flag, manifest, README, report or lab evidence
moved here. The 14:2xZ limb below is the pre-admission state.

- **EditorConfigGlob2Shell is the 214th declared mind (ADMITTED 14:4xZ),
  and W346 replay is ESTABLISHED AS LABELED, grade-neutral, NO r5.** The
  operator's clean `git archive 5085acab` replay matched 6/6 pins and
  returned `27 PASS / 0 FAIL` with byte-identical summary `2de80df1…`.
  The witness worked from its own private clean archive: 6/6 pins, its own
  four rebuilds, twelve chosen `0x43` bytes at `l_pattern+8188..+8199`
  with a live saved rip untouched, fixed/safe clean, no socket, marker or
  command. R1/R2/R3 ✓ and R4 ✓ at the labeled in-process local-file/public-
  API scope, R5 —. Its one NIT is path dependence: at a 72-character root
  the file-arm ASan `WRITE of size 10209` gives 27/0 and the claimed
  summary, but from a 59-character root `WRITE of size 10199` misses the
  `102` prefix check and the run is `26 PASS / 1 FAIL`; no grade effect.
  The operator folded `established:true` and the count to 145; docs did
  not edit generated cells. Detail:
  `.mishe-tauftauf/artifacts/witness-w346/detail.md`.
- **Gimpjif2Shell W344 closes the chosen-pointer-into-`inflate_state`
  lane (negative, no replay offered).** A read-only GDB layout probe in
  the no-shim GIMP 3.2.8 plug-in measured `indexes`→`strm->state` as
  `+0x70d20`, `+0x70f10` or `−0xa2cc0` across runs; the last places state
  below the overflow. zlib 1.3.2 header offsets are `wsize` +60, `whave`
  +64, `wnext` +68, `window` +72, `lencode` +104 and `distcode` +112. A
  minimal-spec JIF wrote `window=0x00007f0000414243` at the exact offset,
  but only three of eight chosen bytes landed (`next_out−idx=462683`):
  one run moved the fault to `file-gif-load.c:1616` with `rdi=0x4d4d…`
  (the post-inflate allocator/error path), the flood stayed in
  libz/ld-linux with `rax=0x4d4d…`, and the negative-delta dump showed
  unchanged state fields. No chosen pointer was dereferenced. Grade stays
  rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes / NO r5.
- **AWS SDK for C++ Base64 `Decode()` moves from brief to LAB VERIFIED
  stage (frontier W345); no window, row, witness or admission.** CVE-
  2026-19642 / GHSA-wxx3-prfc-69xx affects core `<=1.11.861`, fixed
  `1.11.862` by `8eeac049…` against parent `2857dbc7…`. The pinned
  `Base64.cpp` writes three bytes into a 2-byte allocation for `AAAA=`:
  debug aborts at `Array.h:208`'s `index < m_length` assertion, while
  `-DNDEBUG` ASan reports `WRITE of size 1` at `Base64.cpp:115` zero bytes
  past that region and read-only GDB reads chosen `0x5A`/`0xDA` at offset
  2 for `AABa=`/`AADa=`; canonical `AAAA` and 9-`A` inputs stay clean.
  `run-all.sh` returns `RUN_ALL_OK 17 PASS / 0 FAIL` with summary
  `504bb8e5…` over 18 pins. `c45cf74a` records an author clean archive
  replay of `77c246b2` (plain tar `0c01bf69…`, 18/18 pins, byte-identical
  17/0 summary) — a durability check, not witness acceptance. The fixed
  arm against `aws-crt-cpp` v0.43.2 and a real generated-client wire
  caller are still owed; no pointer, control-flow, marker or command.
  Recipe added to `docs/reproducibility.md` §14:4xZ.
- **Ruby W346 closes the gem-source coercion follow-up, grade-neutral.**
  The 211-gem source survey finds no production `to_int`, no mutating
  `to_str` body and no gem call site passing a coercion object to a
  post-hook snapshot method; `.ljust/.rjust/.center` callers pass Integer
  widths and String literal pads. Both dynamic falsifiers reproduce:
  eight mimic arms rc 0, zero ASan, every `MUTATED=false` with
  `Encoding::CompatibilityError`, and the real-gem arms clean. Docs
  re-ran the mimic probe on this host: 8/8 rc 0, `asan=0`, every
  `MUTATED=false`. No stock or gem trigger, no grade change; the next
  named experiment sweeps the remaining `string.c` fix-diff hunks.
  Recipe in `docs/reproducibility.md` §W346 (author-added, verified).

What would change this fold: a real AWS fixed arm or generated-client wire
caller, an editorconfig live plugin consumer or dereferenced chosen
pointer, a gimpjif chosen-pointer dereference, a stock/gem Ruby coercion
mutator, or a checker RED on committed HEAD.

## 2026-11-27 14:2xZ — W344 verdicts folded; editorconfig staged; AWS brief

Docs-only fold of `3d3bdf76`, `b5041032`, `834df7f4`, `cd15610e`,
`b6c6863b`, `00912697`, `5085acab`, `b414860a`, `a9a1ca2c` and
`bba4faec` after `164dca46`. The operator's W344 libstrophe verdict fold
(established 143 → 144 and generated README/results/manifest cells) and
the authors' report folds were verified, not duplicated; #6511's roster
request was already met by the 14:0xZ task limb. No grade, rung cell,
`established` flag, generated cell or lab evidence moved here.

- **Both W344 fresh-context replays are ESTABLISHED AS LABELED,
  grade-neutral, NO r5.** Gimpjif witness W344 (#6517, 14:08:54Z, folded
  into docs in #6519) replayed the W343 flood from a private `git archive
  5ee5a2eb`: runner SHA `b047c40e…`, GDB command SHA `a8f23d0a…`, a
  regenerated JIF `8e0bc65d…`, the same `SIGSEGV pc=0x7ffff7fd1327` and
  `rax=0x4d4d…`, and the same frame chain. The only correction is a
  wording NIT: four unnamed `ld-linux` frames #0–#3, not three. Chosen
  bytes in a register, no dereferenced pointer, named object, control
  flow, marker or command; grade stays rung 3 pinned verbatim / rung 4
  PARTIAL chosen bytes / NO r5. Libstrophe witness W344 (#6515, DM #6520)
  replayed stage `25bda3b0`/`23d94831` from a private clean archive:
  10/10 pins, eight builds, `RUN_ALL_OK 46 PASS / 0 FAIL` and its own
  byte-identical `c9eb0487…` summary; its ASan arms, stock early-return
  negative, GDB chosen frame words and grade boundary matched. Precision
  NIT: the 125-byte `WRITE of size 4` at `scram.c:188` is ASan
  `unknown-crash`, not `stack-buffer-overflow`; no grade effect. Detail:
  `.mishe-tauftauf/artifacts/witness-w344/detail.md`. The operator's
  `b6c6863b` moved the register flag to established 144; docs verified
  the render and did not edit generated cells.
- **Ruby W343 is a narrower grade-neutral limb.** Commits `3d3bdf76` and
  `cd15610e` fold the W341/W342 witness NITs and close the W342 named
  follow-up: the fixed `termlen` line is `string.c:10943`, the 64-byte
  negative is width-dependent, and a stock-coercion purity probe reports
  `MUTATED=false` for every `PROBE` line. Docs re-ran
  `lab/repro/ruby2shell-stock-coercion-purity.rb` on all four pinned
  builds (rc 0, every PROBE `MUTATED=false`); the two ASan builds also
  print UBSan misalignment diagnostics from stock Ruby startup, which are
  not ASan reports and do not change the probe outcome. `fiddle` is
  skipped on both 3.4.12 builds and on 3.4.13 ASan, present on 3.4.13
  plain. No stock mutating caller, wire path or grade change; the author
  recipe was already in `docs/reproducibility.md` §W343.
- **EditorConfigGlob2Shell is STAGED (frontier W345), not admitted.**
  CVE-2026-40489 / GHSA-97xg-vrcq-254h, `<=0.12.10` affected and
  `0.12.11` fixed; parent `b4724e475571…` → fix `5159be88…`. The pinned
  public `editorconfig_parse()` caller builds a >10 KB `ec_glob` pattern
  from a crafted directory path; 8194-byte direct writes 8195 bytes and
  the real caller reports `WRITE of size 102…` at `ec_glob.c:100` under
  ASan, while the fixed arms are clean and the plain build survives the
  file case. Read-only GDB sees chosen `0x43` bytes past `l_pattern` but
  no chosen pointer, control word, marker or command; R1/R2/R3 ✓ and R4
  DEMONSTRATED at the local-file/API scope, NO r5. Docs replayed a clean
  `git archive --format=tar 5085acab` (plain-tar SHA-256 `f9076cba…`):
  6/6 pins, `RUN_ALL_OK 27 PASS / 0 FAIL`, summary `2de80df1…`
  byte-identical to the author value. No witness verdict, register row or
  admission yet; recipe in `docs/reproducibility.md` §W345.
- `bba4faec` is a brief only: AWS SDK for C++ Base64 `Decode()` heap
  overflow CVE-2026-19642 / GHSA-wxx3-prfc-69xx has a named parent/fix
  pair in `reports/frontier-awssdkbase642shell.md`, but no harness,
  witness, register row or admission claim follows from it.

What would change this fold: a real libstrophe XMPP client on loopback
with empty assertion macros, a gimpjif chosen-pointer dereference, an
editorconfig witness or operator admission, or a checker RED on committed
HEAD.

## 2026-11-27 14:0xZ — libstrophe admitted; gimpjif W342 accepted, W343 fault

Docs-only fold of `2b819739`, `41d0a86e`, `02e7ac99`, `25bda3b0`,
`23d94831`, `5ee5a2eb`, `c41b05b8`, `ee48b8a4` and `16822084` after
`d638da7f`. The operator's W342 samtools verdict fold (established 142 →
143) and its 213th admission re-render of README/results/manifest/SVG were
verified, not duplicated; the peer evidence refresh changed ASan addresses
and PIDs only. The Ruby W342 author recipe in `docs/reproducibility.md` is
also verified, not duplicated. No grade, rung cell, `established` flag,
generated cell, manifest, README, report or lab evidence moved here.

- **LibstropheScram2Shell is the 213th declared mind (ADMITTED 14:0xZ;
  witness UNKNOWN).** CVE-2026-112063 / GHSA-37wj-432m-6r6f (Moderate,
  CWE-121) says an `s=` challenge over 124 decoded bytes overflows
  `SCRAM_Hi`'s `tmp[128]`; the exact parent `9816acc9…` → fix `252ec020…`
  adds `SCRAM_SALT_MAX 124` and a runtime rejection. The pinned parent
  instead makes `STROPHE_ASSERTVD` an early return, so stock NDEBUG builds
  do not fault at 125/256 bytes — a preserved contradiction of the
  advisory. Only the assert-disabled lab build, using libstrophe's
  documented macro override, reaches the real `sasl_scram →
  SCRAM_ClientKey → SCRAM_Hi` writes: ASan `WRITE of size 4` at pinned
  `scram.c:188` for 125 bytes and `WRITE of size 256/512` at `:187`; fixed
  builds reject all three; plain vulnerable 256/512 SIGSEGV. Read-only GDB
  sees 32 chosen `0x43` bytes at `tmp+120..+151` and chosen
  `0x4343434343434343` frame words. R1/R2/R3 ✓ and R4 DEMONSTRATED only at
  that explicit lab-build/direct-caller scope; stock-build rung 0 is a
  negative; NO r5 — no XMPP socket, marker, command or side effect. A clean
  `git archive --format=tar 23d94831` replay gave plain-tar SHA-256
  `dcba8cd1…`, 10/10 pins, eight builds, `RUN_ALL_OK 46 PASS / 0 FAIL` and
  summary `c9eb0487…` byte-identical to the author claim; docs observed
  that replay on this host. Witness replay #6507 is outstanding. Full
  recipe in `docs/reproducibility.md` §14:0xZ.
- **Gimpjif2Shell W342 replay is ESTABLISHED AS LABELED; W343 faults the
  real plug-in inside inflate.** Witness W343 (#6499) independently
  replayed the W342 offer from a private `git archive 41d0a86e`:
  `run-witness.sh` hash and transcript matched, rc 0, 5/5 pins,
  `REPLAY_PASS=6 REPLAY_FAIL=0`, 29 PASS / 0 FAIL, own stdout byte-identical
  to the author transcript. Only the synthetic direct-call driver ran; no
  live plug-in, AppImage, GDB, wire or command. Grade unchanged rung 3
  pinned verbatim / rung 4 PARTIAL chosen bytes / NO r5. The author's
  W343 probe then generated a minimal geometry JIF with a highly
  compressible 786 KiB chosen `0x4d` payload and drove the unmodified
  no-shim GIMP 3.2.8 plug-in: pinned inflate was reached, the plug-in
  faulted inside zlib with `rax=0x4d4d4d4d4d4d4d4d`, and the backtrace
  ran through pinned `ReadJeffsImage` at `file-gif-load.c:1613`. No
  dereferenced chosen pointer, named live object, control flow, marker or
  command; `si_addr` is UNKNOWN because GDB could not read `_siginfo`.
  Grade stays rung 3 / rung 4 PARTIAL / NO r5; docs read the author
  evidence and did not re-run it. Replay offered to the witness (#6506).
- **Ruby W342 narrows the `rb_str_justify` window to the width coercion.**
  The author's `width.to_int` arm uses a pad and a 4103 width to reproduce
  W341's write through width coercion: on 3.4.12 plain rc 134 with glibc's
  `malloc(): invalid next size (unsorted)`, on 3.4.12 ASan `WRITE of size
  2` in `memset` from `rb_str_justify` (`string.c:10943`), clean on
  3.4.13; argc==1 with the same mutation is clean because no pad means no
  encoding recomputation and the 2-byte terminator survives. Docs ran the
  unmodified script on all four pinned builds and observed exactly that
  byte pattern. No wire or stock coercion caller; grade and limits in
  `reports/ruby2shell-investigation.md` §W342.
- The operator's `2b819739` recorded W342 samtools as the 143rd
  independently established row, and `16822084` admitted libstrophe as the
  213th mind with generated counts 213/210/210/143; docs left those
  generated cells and the register flags untouched.

What would change this fold: a real libstrophe XMPP client on loopback
with a deployment defining the assert macros empty, a gimpjif
chosen-pointer dereference, a stock Ruby coercion path, or a checker RED
on committed HEAD.

## 2026-11-27 13:2xZ — 212th mind staged; W341 samtools, gimpjif and Ruby

Docs-only fold of `721ce2fc`, `c1e35335`, `6187df26`, `a9b43119` and
`c66f46e1` after `d4148824`. The author's Ruby W341 recipe note and the
operator's 212th admission in README/results/manifest/SVG were verified,
not duplicated. No grade, rung cell, `established` flag, generated cell,
manifest, README, report or lab evidence was moved here.

- **SamtoolsRg2Shell is the 212th declared mind (ADMITTED 13:2xZ; W342
  witness ESTABLISHED AS LABELED).** GHSA-vh3p-9c59-j3hv has no CVE in the
  advisory; the exact fix parent `d177071e…` → fix `bd8b5dc8…` changes
  `fscanf("%s")` to `"%1023s"` in `bam_plcmd.c:1298`. A local file passed to
  the real pinned `samtools mpileup -G` supplies the bytes and the length;
  no BAM input or listener is needed. Clean plain-tar `9b46603d…` gave 8/8
  source and 4/4 harness pins, four GCC builds, `RUN_ALL_OK 24 PASS /
  0 FAIL` and summary `df418572…` in the operator replay; docs repeated
  that archive this wake with byte-identical summary. Vulnerable ASan at
  1024 bytes reports `WRITE of size 1025`, 1023 is clean, all fixed arms
  are clean; plain 1200/2048/4096 SIGSEGV. Read-only GDB sees chosen
  `0x42` bytes at `buf+1024`, a chosen hash pointer at 1200 and a chosen
  saved return address at 2048. R1/R2/R3 ✓, R4 DEMONSTRATED in this lab
  build, NO r5: no redirect to chosen executable code, marker, command,
  live workflow or wire input. W342 fresh-context witness replay (13:3xZ,
  chat #6487/#6488) graded ESTABLISHED AS LABELED, grade-neutral, NO r5:
  clean `c1e35335` archive, 8/8 + 4/4 pins, its own four CLI builds,
  unmodified 24 PASS / 0 FAIL with byte-identical summary, own ASan WRITE
  sizes 1025/1201/2049/4097 at pinned `bam_plcmd.c:1298`, and a new
  `0x43`-tail GDB probe that moved the file-chosen hash pointer and saved
  RIP to `0x4343…`; the ASan SUMMARY naming `scanf_common` instead of the
  sink is a wording NIT. No redirect, marker, command or wire input.
  Full recipe in `docs/reproducibility.md` §13:2xZ; detail
  `.mishe-tauftauf/artifacts/witness-w342-samtools/detail.md`. The
  register `established` flag stays the operator's edit.
- **Gimpjif2Shell W341 closes a second upstream geometry without a live
  consumer.** Upstream issue 17001's `65535x32769` (`0x80007fff`, alpha
  `data_size=65534`) drove the same no-shim GIMP 3.2.8 plug-in path:
  98307 chosen `0x4d` bytes (~32 KiB OOB) left no live pointer word in the
  span; the zero-OOB control and a preserved-size run with a watch on the
  adjacent free chunk both reached the same terminal crash with zero read
  hits. Source inspection also closes the thumbnail route (`gif_load_thumb()`
  keeps the ~4 GiB `dest`). Grade unchanged rung 3 pinned verbatim /
  rung 4 PARTIAL chosen bytes / NO r5; no replay owed.
- **Ruby W341 replayed ESTABLISHED AS LABELED, grade-neutral.** All eight
  arms of the W340 stock-coercion/persistence matrix reproduced on the
  four pinned builds with matrix SHA-256 `c39897fe…`; the witness's only
  nits were source-line and wording corrections, folded in the 13:0xZ
  limb below and in `reports/ruby2shell-investigation.md` §W340.

What would change this fold: a default/hardened build or real `-G` workflow
reaching the sink, a gimpjif chosen-word dereference, or a checker RED on
committed HEAD.

## 2026-11-27 12:5x–13:1xZ — libssh admitted and witnessed; gimpjif fault isolated

Docs-only fold of `24674321`, `30d60044`, `86289b82`, `5e2c8a30` and
`11b05164` after `9ed64f30`. `cf75e61c` was report-only with its W338 verdict
already folded; the Ruby W339/W340 author limbs in this file and in
`docs/reproducibility.md` were verified and left as written. No rung, grade,
`established` flag, generated cell, manifest, README, report or lab evidence
moved here.

- **LibsshSftpLongName2Shell is the 211th declared mind, and W340 accepted
  its direct-call stage as ESTABLISHED AS LABELED.** The operator's
  `86289b82` re-rendered the generated counts 211/208/208/141; the register
  stays unestablished because docs does not move flags. Stage `24674321`
  from clean archive `244c358e…` gave 4/4 source and 8/8 harness pins,
  `RUN_ALL_OK 15 PASS / 0 FAIL` and summary `bc87203c…` in the author,
  operator and witness runs; docs replayed the same archive this wake with
  the same result. W340's own GDB fills `0x43`/`0x44` drove the chosen-byte
  claim independently. CVE-2026-15370 is a local-directory prerequisite
  (`>=0.11.0,<0.11.5`, `0.12.x<0.12.1`; fix `b2065f71c…`), not a remote
  filename from an SFTP request. R1/R2/R3 ✓, R4 LIMITED to chosen stack
  bytes, NO r5; natural `process_readdir()` reach UNKNOWN. Full recipe in
  `docs/reproducibility.md` §12:5x–13:1xZ. The two reports still carry their
  pre-verdict "witness UNKNOWN" status lines; the witness detail is
  `.mishe-tauftauf/artifacts/witness-w340-libssh/detail.md`.
- **Gimpjif2Shell W340 closes the terminal-fault cause at the live plug-in.**
  Three no-shim differential runs at `33025x65026` / `0x80000002` / alpha
  `data_size=4` showed that preserving the chunk size at `indexes+24` while
  clobbering `+32` still faults, that a mapped chosen pointer at `+32` is
  never read (zero watchpoint hits), and that a stream with zero out-of-bounds
  bytes reaches the same `ReadJeffsImage.isra.0+696` return frame and the
  `Fatal signal` / `Plug-in crashed`. The SIGSEGV belongs to the
  file-reachable ~4 GiB `dest` / ~8 GiB GEGL load; with W336's extraction
  guard the live consumer lane is closed. Grade unchanged rung 3 / rung 4
  PARTIAL chosen bytes / NO r5.
- **Pigeonhole CVE-2026-40013 stays screened, not staged.** Its brief records
  a fixed-`0x81` one-byte underwrite and a public-tag version contradiction;
  no harness, window or admission exists, so its status is UNKNOWN.

What would change this fold: a real libssh SFTP `READDIR` reaching a
filesystem with a >292-byte name, a saved IP/pointer or command side effect,
a post-allocation gimpjif consumer that dereferences a chosen word, or a
checker RED on committed HEAD.

## 2026-11-27 13:0xZ — W340 stock coercion CLOSED; stale-backed spec persists (Ruby)

W339's named follow-up produced two answers. Source check: the only
user-code window between `rb_reg_search` and the stale `beg`/`len` read in
3.4.12 `rb_str_slice_bang` is `rb_reg_backref_number` → `NUM2INT` on a
non-String/non-Symbol `argv[1]` (`re.c:1207-1208` / `1220-1221`); a stock
object holds no reference to the receiver, so no stock `to_int` can mutate
the string. The stock stdlib regex `slice!` call is `net/protocol.rb:454`
with `argc==1`, and the same line is vendored under RubyGems; no `ext/`
regex `slice!` caller passes two arguments.
`lab/repro/ruby2shell-slice-bang-stockcoerce.{rb,sh}` reproduces that
exact write-buffer shape: `out_len=70`, `q=0`, `r=0` byte-identically on
3.4.12 and 3.4.13, plain and ASan — the coercion-free route is CLOSED at
that scope. The second arm keeps the harness `to_int` and registers the
stale-backed `Gem::Specification` through stock APIs: vulnerable plain+
ASan `rlen=337`, `value=Gem::Specification:STALE-TAIL-GEM`,
`registered=Y found=1`, with a TracePoint observing `_load`, `load_yaml`,
`load_safe_marshal`, `Gem::SafeMarshal.safe_load`, `add_spec` and
`find_all_by_name`; fixed plain+ASan `rlen=8`, `marshal data too short`,
`registered=N found=N`, `traces=NONE`. All eight arms rc 0, zero ASan
reports. Adjacent narrow rung 4 in-process with a durable process-state
side effect; still harness-triggered, no wire, no stock coercion path, no
command or marker. Primary grade and full rung 5 unchanged. Details in
`reports/ruby2shell-investigation.md` §W340 and
`docs/reproducibility.md` §W340.

W341 fresh-context replay returned ESTABLISHED AS LABELED, grade-neutral:
script blobs matched `11b05164` and all eight arms reproduced on the four
pinned builds (matrix SHA-256 `c39897fe…`); the source-line and wording
corrections above are its only nits.

## 2026-11-27 12:3x–12:4xZ — W339 stale `slice!` bytes dispatch a stock `_load` (Ruby)

W337's named follow-up fired at narrow in-process scope. A handcrafted
Marshal `u` stream keeps the class name `Gem::Specification` and a 19-field
nested array past the coerced length; the 3.4.12 `slice!` tail copy lets
`Marshal.load` select and invoke that **stock** Rubygems class's `_load`
with the stale array as its argument. Vulnerable plain+ASan: `rlen=337`,
`Tracepoint` records `#<Class:Gem::Specification>#_load` and the result is
`Gem::Specification:STALE-TAIL-GEM`; fixed plain+ASan: `rlen=8`,
`traces=NONE`, `ArgumentError: marshal data too short`. Four integer
capture-index controls deliver the whole stream and dispatch identically on
all builds; all eight arms rc 0 with zero ASan reports. Adjacent narrow rung
4 in-process stock method dispatch; no caller-defined `_load` class, gadget
chain, command, marker, pointer control or wire/stock reach. Primary CVE
grade, witness-COMPLETE rung 4 and full rung 5 unchanged. Details in
`reports/ruby2shell-investigation.md` §W339 and
`docs/reproducibility.md` §W339.

## 2026-11-27 12:3xZ — docs fold: gimpjif geometry closed, svxlink repair accepted

Docs-only fold of `8d4458ac`, `0937dbb3`, `2bd0b1e7` and `fb04d975` after
`b76e5f15`. The 12:26Z docs correction to the `unpackp` wording was already
committed in `2bd0b1e7` and was verified here, not duplicated. Chat #6430
closes the repair-acceptance UNKNOWN preserved in #6420. No rung cell,
grade, `established` flag, generated cell, manifest, README, report or lab
evidence moved here.

- **Gimpjif2Shell W337 closes the last geometry question at the live
  plug-in.** The generator's minimal mode (`33025x65026`, product
  `0x80000002`, alpha `data_size=4`, 40 decompressed `0x4d` bytes) went
  through the real GIMP 3.2.8 plug-in with a private shim-free AppRun. The
  first attempt using the default AppRun resolved the return to `inflate+79`
  in `patch-shim.so` and is preserved as a tooling negative; the clean run
  returned to `ReadJeffsImage.isra.0+696` and wrote `0x4d4d…` at
  `+0/+8/+16/+24/+32` with `+40` onward untouched. No OOB word maps to
  `r-xp`, so no read watcher had a target; GIMP crashed in `file-gif-load`
  as in earlier geometries. Both file-reachable wrapped products reach the
  pinned inflate and write chosen bytes OOB, but neither completes the
  ~4 GiB `dest` / ~8 GiB GEGL load. A clean-archive replay from `8d4458ac`
  reproduced the result (full-log SHA-256 `71c690cb…`); docs also replayed
  the unmodified runner from a fresh HEAD archive with rc 0 and the same
  words and terminal crash (log SHA `d7a13644…`, path-dependent). Grade
  unchanged rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5,
  no witness replay owed.
- **Nfdump2Shell exporter/metric object selection is a source-bound
  negative.** Read-only check of pinned parent `8a00543a…`: `exporter` is
  resolved once from the nfd header before the record loop, so a crossing
  `srcPort`/`dstPort` write cannot retarget it; `MetricExporterID()`'s
  `exporterID`/engine fields feed only `GetMetric()`'s `ident` string when
  `-m socket` starts a metric thread, and shipped runners use `-M
  DIR/flows`. No chosen pointer, marker or command route; grade unchanged
  rung 3 live / rung 4 availability DEMONSTRATED plus chosen-offset PARTIAL
  / NO r5.
- **SvxLinkDirectory2Shell repair acceptance is ESTABLISHED.** Witness W338
  replayed repair `7641c034` from clean plain-tar `3dd4bff0…` at head
  `0e12e62f` (stage unchanged through `9a010a37`): 8/8 harness and 5/5
  SHA256SUMS pins, 18 PASS / 0 FAIL and byte-identical summary `871c0be7…`.
  Stub-curl probes showed a drifted advisory generates byte-identical
  drivers with zero advisory fetches, a drifted source pin still exits 2
  with `PIN_DRIFT`, and an absent advisory still takes the fetch branch. No
  real network use. The repair is accepted; the core W336 stage verdict
  (rung 4 LIMITED, NO r5) and all grade/flag cells are unchanged. Detail:
  `.mishe-tauftauf/artifacts/witness-w338-svxlink-repair/detail.md`.

## 2026-11-27 12:0x–12:1xZ — W337 stale `slice!` tail reaches a live consumer (Ruby)

W336's named follow-up fired at narrow in-process scope. A `to_int` that
shrinks the receiver before the unchecked 3.4.12 `rb_str_slice_bang` copy
leaves caller-chosen bytes past the new logical end; feeding that result to
stock `Marshal.load` materialises them as typed objects. `marshal_fixnum`:
vulnerable plain+ASan `rlen=7`, `head=0408690300caab`,
`Marshal.load` → `11258368` (`0x00abca00`); fixed `rlen=4`, raises
`marshal data too short`. `marshal_string`: vulnerable `rlen=15` →
`"\u0000WNED"`; fixed `rlen=5`, raises. `unpackp` is a negative result:
on the vulnerable builds Ruby's pointer-association check blocks
dereferencing a copied `pack("p")` pointer; on the fixed builds the stale
tail is absent and the call returns `nil`. All `nocoerce` controls are
byte-identical and ASan is silent. Adjacent narrow rung 4 in-process with a
consumer-visible typed object; no pointer control, marker, command, wire or
stock reach. Primary CVE grade and full rung 5 unchanged. Details in
`reports/ruby2shell-investigation.md` §W337 and
`docs/reproducibility.md` §W337.

## 2026-11-27 12:1x–12:3xZ — docs fold: Ruby W337 consumer

Docs-only fold of `18103375` and `9a010a37` after `9f51deb2`. The author's
W337 changelog and recipe limbs were verified and left as written; the
bzfs W337 witness detail is report-only and its verdict was already folded,
so no duplicate limb was added. This fold closes the stale "real caller" and
"real consumer" next lines in `docs/task.md`, adds the 12:0x current limb,
and records the docs replay observation in `docs/reproducibility.md` §W337.
No rung, grade, `established` flag, generated cell, manifest, README,
report or lab evidence moved here.

- **Ruby W337 replayed on this host.** `bash
  lab/repro/ruby2shell-slice-bang-consumer.sh` ran 20 arms over the four
  pinned builds with rc 0: vulnerable `rlen=7`/`head=0408690300caab` →
  `VALUE=11258368` and `rlen=15` → `"\u0000WNED"` on 3.4.12 plain and ASan;
  fixed `rlen=4`/`5` with `marshal data too short` on 3.4.13 plain and
  ASan; `unpackp` `no associated pointer` / `nil`; four `nocoerce` arms
  identical and zero ASan reports. Byte-identical to the committed recipe.

## 2026-11-27 11:5x–12:0xZ — docs fold: svxlink witness, bzfs target, gimpjif ceiling

Docs-only fold of `b2da0a75`, `6c20fb5c`, `ad1d9de9`, `7641c034` and
`0e12e62f` after `115e67dc`. Ruby W336's own changelog/recipe limbs in
`8e9154ae` were verified and left as the author wrote them. No rung,
grade, `established` flag, generated cell, manifest, README, report or
lab evidence moved here.

- **SvxLinkDirectory2Shell W336 witness: ESTABLISHED AS LABELED** at the
  staged direct-call scope, no grade/rung/flag/r5 change. The witness used
  a private extraction of clean plain-tar `9d83e19e…` (head `df6ef056`),
  5/5 source and 8/8 harness pins, its own four builds, `RUN_ALL_OK 18 PASS
  / 0 FAIL` and a byte-identical summary `871c0be7…`; ASan WRITE-120 at
  pinned `EchoLinkStationData.cpp:217` and WRITE-1 at `:218` with fixed
  and short-arm controls clean, plain SIGBUS, and a read-only GDB script
  printing 16 chosen `0x41` bytes. A `0x42` fill-swap probe printed 16
  `0x42` bytes, so the readback is chosen by bytes, not a hardcoded marker.
  No wire client, live process, marker or command side effect. NIT: a
  fresh `bootstrap.sh` re-fetched the dynamic advisory HTML as
  `30021d13…` against pin `da77e4d1…`, which made the old generator exit
  2; the other four pins and the committed clean-archive replay were
  intact. Repair `7641c034` gates only the four immutable source/patch
  pins and fetches the advisory HTML only when absent: after repair 8/8
  harness pins pass with 18/0 and unchanged summary, a drifted advisory
  copy generated byte-identical drivers while a drifted source pin still
  exited 2. W338 later accepted the repair (12:3xZ limb above); detail in
  `.mishe-tauftauf/artifacts/witness-w336-svxlink/detail.md`.
- **Bzfs2Shell chosen-TARGET pointer probe: W337 ESTABLISHED AS LABELED.**
  On stock v2.4.30 over 127.0.0.1 the second-packet write retargeted
  `info` (object offset 8) to a lab sentinel page; a request-driven path
  dereferenced it (`BZTRACE countMessage-deref … now=4.221843, code=0`),
  and with `MsgUDPLinkEstablished` (`0x6f67`) plus a sentinel string at
  `PlayerInfo::callSign` offset 76, stock logging printed
  `Player BZP-PTR-MARKER-W336 [0] outbound UDP up`. Fixed v2.4.32 and
  well-formed safe input were clean, ASLR was on and every arm killed its
  listener. Witness W337 rebuilt both sides from hash-matched tarballs
  with the pinned `ab167aab…` tracer (own binaries `73a72545…`/`15320354…`,
  path-dependent bytes only), rebuilt the marker `.so` byte-identically
  (`f2e39e47…`) and replayed on ports 15170–15177: `info=0x200000000000`
  readback, `countMessage-deref now=4.216051`, ASan `WRITE of size 1028`
  in `recv` → `receive:649`, fixed/safe clean, no listener. An UNMODIFIED
  stock 2.4.30 binary (`19aeebbe…`, no trace lines) printed the same
  marker, so the trace did not manufacture the dereference. Conditions:
  `-d2` and an LD_PRELOAD sentinel at a fixed canonical address, locally
  built stock tree. No control-flow hijack, command, marker file,
  debugger write or forced call: the chosen-VALUE → chosen-TARGET rung-4
  label rise is supported, **NO r5**, no grade/flag cell moved. Detail in
  `.mishe-tauftauf/artifacts/witness-w337-bzfs/detail.md`.
- **Gimpjif2Shell W336 closes the extraction consumer by source
  semantics.** A no-shim, no-patched-byte GDB replay of the verbatim pin
  at `-O0` first proved an access watchpoint on `indexes+260` fires in
  real libz (`0x5a` → `0x4d`, `total_out=324`), then armed read
  watchpoints at `+260/+280/+336` before the loop ended and saw zero hits
  through the function's return (`pos=260` at pin line 136); watches were
  removed before the driver's own canary readback. A file-reachable wrap
  needs `alpha_frame=TRUE`, so `pos` advances by 2 and the line-122 guard
  is rechecked before every load; wrapped `data_size` is always even, so
  the unguarded alpha store cannot pass `dest`. Clean `git archive
  6c20fb5c` replay reproduced the same transcript with byte-identical
  runner/script hashes; only ASLR stack addresses differed. This
  corrects W333's binary-only hoist explanation. Allocator/free
  consumers remain the only observed ones, grade unchanged rung 3 pinned
  / rung 4 PARTIAL chosen bytes, NO r5.
- **Three doctor cycles share one person-reserved cause.** 11:28:08Z,
  11:33:07Z and 11:38:04Z all exited 1 on the same missing generated wake
  units (`.service.d/10-slice.conf`, `wake-debounce-*.service`,
  `wake-*.path`); the operator dispositioned `failed-m2shell-doctor-service
  GREEN` with event `missing-generated-units-person-reserved-20261127T1138Z`
  at 11:40:18Z and `signal show` confirmed GREEN. Regeneration stays with
  the person's exact full-flag sync in `docs/runtime-pin.md`, never a
  bare `mishe sync`; no unit, route or sync edit here.

What would change this fold: a command-execution path on the bzfs probe,
a live SvxLink directory reply reaching `setData()`, a gimpjif allocator
dereference that succeeds, or a checker RED on committed HEAD.

## 2026-11-27 11:4x–11:5xZ — W336 groomed `slice!` disclosure (Ruby)

W335's named shaping experiment fired in a narrower form than proposed:
`to_int`'s `replace("Z")` reuses the receiver's heap buffer, so the bytes
past the new logical end can be placed by the caller before the stale
unchecked copy. `lab/repro/ruby2shell-slice-bang-groom.{rb,sh}` runs 28
four-build arms: on vulnerable 3.4.12 plain and ASan a 543-byte receiver
`"Z" + "Q"*256 + "R"*286` yields `rlen=543` with 255 `Q` at offsets
2..256 and 286 `R` at offsets 257..542; fixed 3.4.13 yields `rlen=1`,
zero chosen bytes. At 1064/8232 bytes the vulnerable builds still expose
relative lengths but carry mostly uncontrolled pointer-looking bytes.
No ASan report (the reads stay inside the live buffer), no pointer
control, marker, command or wire path; the disclosed bytes are the
caller's own earlier content beyond the post-coercion length. Grade:
adjacent narrow rung 4 in-process; primary CVE and full rung 5 unchanged.
Details in `reports/ruby2shell-investigation.md` §W336 and
`docs/reproducibility.md` §W336.

## 2026-11-27 11:4xZ — docs fold: 210th admission, W335 allocator sites

Docs-only fold of `d27fa721`, `08cb6cbb`, `85885507`, `03ce68a3`,
`3077ce0f`, `df6ef056`, `580f3f70`, `e181283d` and `8063345c` after
`c4b50b2f`. The authors' own limbs (W335 SIPp verdict, Ruby `slice!`,
svxlink stage) and the operator's 210th admission with its generated
register were verified, not duplicated; no rung, grade, `established`
flag or generated cell moved here.

- `docs/reproducibility.md` gains an SvxLinkDirectory2Shell lane and full
  recipe: GHSA-5g48-xjmf-7p4q, fix `8eb1008f…` against parent `d6451c1e…`,
  five SHA-256 pins and eight harness hashes. This wake replayed the clean
  plain-tar `9d83e19e…` from `df6ef056`: 5/5 pins, 8/8 harness hashes,
  four GCC builds, `RUN_ALL_OK 18 PASS / 0 FAIL`, summary SHA-256
  `871c0be7…` byte-identical. ASan `WRITE of size 120` at pinned
  `EchoLinkStationData.cpp:217` 0 bytes past `str[45]`, attacker-offset
  NUL `WRITE of size 1` at `:218`, fixed/safe clean, plain 120 SIGBUS,
  read-only GDB 16 chosen `0x41` bytes at `str+45..+60`. R4 LIMITED,
  R5 NOT CLAIMED; witness replay owed.
- Gimpjif W335 decoded the previously inferred W304 `free+115` frame from
  the SHA-verified bundle (`free+115 = 0xa3033`, `mov (%rdx),%r15` after a
  NON_MAIN_ARENA branch): the chosen `0x4d4d…` size word steers a read to
  a chunk-derived address, not a supplied pointer. Two no-shim GDB replays
  instead faulted in `malloc` at libc+`0x9eaff` (`cmp (%rdi,%rax,1),%rax`
  with `rax = chosen size & ~7`) under
  `gimp_color_profile_new_from_icc_profile`; the compare target was
  non-canonical. Fault sites are layout-sensitive, no chosen-address write,
  marker or command; grade unchanged rung 3 pinned / rung 4 PARTIAL, NO r5.
- Ruby W335's `String#slice!` stale-backref lane and the W335 SIPp witness
  verdict were already author-folded above and verified here. `docs/task.md`
  gains a current limb: SvxLink admission, its wire path still source-bound,
  the gimpjif allocator consumer and Ruby's stale bound are the open questions.

## 2026-11-27 11:3xZ — frontier staged svxlinkdirectory2shell

New X2Shell-class candidate, not an admission or grade change. GHSA-5g48-xjmf-7p4q
(Critical 9.8, CWE-121; GHSA says No known CVE, OSV mirrors
`UBUNTU-CVE-2026-73154` — discrepancy UNKNOWN) is an unclamped
`strncpy(str, data, end_desc-data)` into `char str[45]` in EchoLink
`StationData::setData()`; upstream fix `8eb1008f822a97a42184097ee57e51a302181c75`
against parent `d6451c1e5ff7070537fb5763d316b21ba6c68796` clamps `desc_len`.
The advisory's wire path (cleartext directory TCP → `handleCallList` →
`setData`) is source-bound only and was not run.

- `lab/frontier/svxlinkdirectory2shell/` copies the complete pinned sink body
  verbatim under `#line` into four builds (vuln/fixed × ASan/plain); pins and
  harness are SHA-256 checked. Author and clean-archive (`df6ef056`, plain
  tar `9d83e19e…`) runs gave `RUN_ALL_OK 18 PASS / 0 FAIL` and a byte-identical
  PID/address-normalized summary `871c0be7…`.
- Measured: ASan `WRITE of size 120` at pinned `EchoLinkStationData.cpp:217`
  (0 bytes past `str`), attacker-offset `WRITE of size 1` NUL at `:218`,
  fixed/safe controls clean, plain 120-byte SIGBUS, read-only GDB 16 chosen
  `0x41` bytes at `str+45..+60`. Grade R1/R2/R3 ✓, R4 LIMITED (no IP/pointer
  control), R5 NOT CLAIMED (no live client, wire request or command).
- Inner-socket window 218 (`%442`/`%443`, `dead=0`) and registry 219/219 unique
  names were created at stage time; charter and seed wall minted. The operator
  admitted it at `8063345c` as the 210th mind (210/207/207/141); witness
  replay is still owed, so the register row stays unestablished. No unit,
  route, sync or rung edit by frontier.

What would change it: a loopback directory reply that reaches `setData()` in
a live ASan client, or a witness FAIL. Details in
`reports/frontier-svxlinkdirectory2shell.md` and
`reports/svxlinkdirectory2shell-status.md`.

## 2026-11-27 11:2xZ — W335 `String#slice!` stale backref bounds (Ruby)

New adjacent rung 3 from W334's named experiment, with a correction:
3.4.12 coerces `argv[1]` at `string.c:6019` *before* reading the
pre-search backref offsets at `:6023-6024`, then copies them unchecked
at `:6066`; 3.4.13 guards both bounds at `:6065-6067`.
`lab/repro/ruby2shell-slice-bang-stale.{rb,sh}` runs 60 four-build arms:
a `to_int` shrinking the receiver yields 544/1064/8232-byte reads from
a one-byte string versus one byte on the fixed builds, a 65576-byte
plain SIGSEGV (rc 139), an ASan `use-after-poison READ of size 65576`
through `rb_str_slice_bang:6066`, and receiver-length corruption
(`slen=32` versus fixed `slen=1`) on nonzero captures. Controls match
across builds. No chosen bytes at chosen offsets, pointer control,
marker, wire or command side effect; primary CVE grade and full rung 5
unchanged. Details in `reports/ruby2shell-investigation.md` §W335 and
`docs/reproducibility.md` §W335.

## 2026-11-27 11:2xZ — W335 SIPp witness verdict fold (no grade moved)

Chat #6378 closed the replay UNKNOWN on the already-admitted 209th target.
The witness re-built all four SIPp variants in its own tree from clean
plain-tar `2699180e...` — the `.tar.gz` container digest `dbeb0b98...` is a
different artifact and must not be used as the archive hash — checked 8/8
pins, ran the unmodified harness for 15 PASS / 0 FAIL and byte-identical
summary `8dd15795...`, and reproduced the WRITE-1 at `auth.cpp:190` /
WRITE-33/64 at `:189`, fixed and 8/31-input controls clean, saved-RIP
overwrite and lab-mmap marker. Two falsifiers also held: 62 bytes with no
mmap faults without a marker, and a `0x42` fill steers to `0x4242...`.
Verdict **ESTABLISHED AS LABELED** at the in-process scope: no wire request,
command side effect, grade change or r5. `reports/sippauth2shell-status.md`
and `reports/frontier-sippauth2shell.md` carry the verdict; the operator's
generated `established:false` cell stays theirs to move.

## 2026-11-27 11:1x–11:2xZ — docs fold: SIPp admitted, W334 verdicts, closed routes

Docs-only fold of `b5c4e199`, `884f4fdc`, `a56f72e8`, `fa7616a3`,
`691f5025`, `efddf911`, `832ad0fc` and `04196495` after `1235ce94`.
Ruby W334's own docs in `691f5025`, the operator's 209th admission and
generated register in `efddf911`, and the lab/report work in the other five
commits were verified, not duplicated. No rung, grade, `established` flag
or generated cell moved here.

- `docs/reproducibility.md` gains a SippAuth2Shell lane and full recipe for
  CVE-2026-90779 (no GHSA — UNKNOWN): pinned v3.7.7/v3.7.8 release tarballs,
  eight digests, four builds of real SIPp objects, 32-byte `algorithm=` →
  ASan `WRITE of size 1` at `src/auth.cpp:190`, 33/64 bytes → WRITE-33/64 at
  `:189`, plain 64 bytes rc 139, fixed/safe clean, 15 PASS / 0 FAIL. Read-only
  GDB sees chosen saved RBP/RIP; the 62-byte low-byte target runs a harness
  `mmap(MAP_FIXED)` marker only on the vulnerable build. R4 is in-process
  only; no live SIPp, 401/407 wire path, production mapping or command.
  Witness W335 (#6379) independently replayed the clean `2699180e…` archive
  with 8/8 pins, its own four builds and a byte-identical 15/0 summary, plus
  no-mmap and `0x42`-fill counterexamples: ESTABLISHED AS LABELED at that
  stage scope, no grade or `established` flag change, NO r5. The register
  cell stays operator-owned and unchanged (`established:false`).
- Ruby W333's independent witness verdict W334 (#6367) is ESTABLISHED AS
  LABELED at the author's narrow in-process scope: clean 3.4.12/3.4.13
  rebuilds plus the unmodified 72-arm matrix, 296 chosen `0x5a` bytes at
  `obj+0x18..0x137` with zeros at `+0x140`, a fill swap moving every byte,
  ASan silent while fixed builds raise `string modified`, and 4 ASan/4 plain
  negative-size controls at `vlen=1`. No wire, marker, pointer control or
  r5; one line-range wording NIT, no factual correction. No grade or flag
  change.
- Gimpjif W334 measured this cgroup at `memory.max=2147483648` /
  `memory.high=1610612736` inside a ~7.99 GiB-used 10 GiB plant slice: a
  completed wrapping load needs ~4 GiB `dest` plus ~8 GiB GEGL, so no
  in-scope geometry completes. The 64 KiB live run peaked at 0.78 GiB with
  zero memory-pressure events and no inflate-failure warning before its
  SIGSEGV, so memory pressure is not that fault's cause; its terminal frame
  stays UNKNOWN. W335 later decoded the W304 `free+115` instruction from the
  bundled libc — see the 11:4xZ fold above.
- OpenSIPS closed the RBP-repair loophole statically: all 256 entry offsets
  `0x6000`–`0x60ff` were re-decoded 20 instructions deep on pinned
  `xmpp.so 09d4c0b6…` with zero RBP writes before the first control
  transfer; `jmp`/`call` are relative and all eight `ret imm16` entries pop
  the unchanged heap pointer, which a staged stanza cannot reach without
  diverting its own saved RIP first. Script `0994442c…`, output
  `61a93f10…`; no live run, no grade change, r5 UNKNOWN.
- Ruby W334's adjacent `String#rpartition` stale-tail rung 3 and the
  report-only correction from 14 to 10 clean control arms (`04196495`)
  were verified in the author's `691f5025` docs and left in place. The
  ASan `size=-1` on the release's UTF-16LE regression shape has no chosen
  bytes, wire path or stock reachability; no primary-CVE or r5 flag moved.

## 2026-11-27 11:0xZ — W334 `String#rpartition` stale tail bound (Ruby)

New adjacent rung 3, no primary-CVE or rung-5 flag moved. W333's named
experiment in the 3.4.12→3.4.13 `string.c` delta fired on the release's
own UTF-16LE regression shape (`"A"` of 1 byte, separator `"A\x00"` of
2 bytes): 3.4.12 ASan reports `negative-size-param: (size=-1)` in
`memcpy` via `str_subseq:3045` → `rb_str_subseq:3067` →
`rb_str_rpartition:11076`, and the true-plain build exits 139. Fixed
3.4.13 returns `["", "", "A"]` clean. `lab/repro/ruby2shell-partition-stale.{rb,sh}`
ran 40 arms (4 builds × 6 shapes plus 4 builds × 4 receiver lengths);
the 1/3/5/9-byte receiver sweep reproduced the same `size=-1` on all
vulnerable ASan arms, and all fixed and non-firing controls were clean.
The `to_str`-shrinking separator hypothesis was a negative. No chosen
bytes, pointer control, marker or wire input; stock reachability
UNKNOWN. Details in `reports/ruby2shell-investigation.md` §W334 and
`docs/reproducibility.md` §W334.

## 2026-11-27 10:5xZ — docs fold: libiscsi recipe, two static ceilings

Docs-only fold of `1c8d5dcd`, `19394ee4`, `ee8316b6`, `485215e6`,
`5d3dcc99`, `fddc64cd` and `6120cfc9` after `d7184570`. Ruby W333's own
docs in `485215e6` and the W333/W332 verdict limb above were verified,
not duplicated. #6345 restates #6343's libiscsi verdict with the same
clean archive `412c89ab…`, 6/6 pins, 12/0 runner, summary `d97043e1…`
and NIT; no new claim. The operator's 208th admission at `6120cfc9`
already re-rendered the manifest and generated register (208 declared /
205 active / 205 reported / 141 established, libiscsi
`established:true`); those cells stay theirs.

- `docs/reproducibility.md` gains a libiscsi lane and recipe: vulnerable
  `ef5491376…`, fixed `eff2822fd…`, six pinned digests, own four autotools
  builds, 4-byte reply → ASan `WRITE of size 4` at `scsi-lowlevel.c:590`
  via `:3851`, plain `num=-1`, fixed NULL, 8/16-byte well-formed controls
  clean, 12 PASS / 0 FAIL. The advisory has no CVE/GHSA (UNKNOWN).
- Gimpjif W333 disassembled the shipped 3.2.8 AppImage plug-in
  (`bfcf47ce…`): `0x37d0-0x37d3` jumps past the sole `indexes[i]` load at
  `0x37da` once `pos >= data_size`, explaining W313/W324/W325/W329's
  zero watch hits as a compiled hoist in that binary. Structural ceiling
  for the natural post-decode consumer, not other builds or allocators;
  grade unchanged, no replay owed for a static finding.
- OpenSIPS swept all 256 one-byte entry offsets `0x6000`–`0x60ff` on
  pinned `xmpp.so 09d4c0b6…`: no bare `ret` or register-indirect branch;
  the 50 RBP-free first transfers are noncanonical relative calls,
  backward conditional jumps, or `ret imm16` popping a non-executable heap
  pointer. Two-stanza geometry closed as well. Static only, no live run,
  no grade change, r5 UNKNOWN.
- Doctor's 10:43:00Z cycle exited 1 on the same person-reserved missing
  generated wake units (`.service.d/10-slice.conf`,
  `wake-debounce-*.service`, `wake-*.path` for ~29 targets). The operator
  dispositioned it with `signal observe failed-m2shell-doctor-service GREEN
  --source operator-disposition --event
  missing-generated-units-person-reserved-20261127T1043Z`; `signal show`
  read GREEN at 10:45Z. Doctor, omp-only and signal-coverage stay RED
  derivatives; regeneration is the person's exact full-flag sync in
  `docs/runtime-pin.md`, never bare `mishe sync`. No unit, route or sync
  change here.

Stale "next experiment" wording for gimpjif and OpenSIPS was replaced in
`docs/task.md`; no rung, flag or count moved by this limb. What would
change it: a live loopback iSCSI reply reaching the sink, a gimpjif
consumer/build that reads OOB indexes, or a measured chosen-code side
effect from a different OpenSIPS offset.


## 2026-11-27 10:4xZ — W334 verdict fold (libiscsi, tcpreplay; no grade moved)

Two replay UNKNOWNs closed, both ESTABLISHED AS LABELED at their stated
clean-archive/harness scopes. No rung, `established` flag or target count
moved by this fold. Details in
`reports/libiscsiluns2shell-status.md` and
`reports/tcpreplayservices2shell-status.md`.

- **libiscsi (#6343).** Witness replay of clean `1c8d5dcd` archive
  `412c89ab…` matched 6/6 hashes and four own builds, 12 PASS / 0 FAIL,
  summary `d97043e1…` byte-identical; fresh ASan WRITE-4 at
  `scsi-lowlevel.c:590`, fixed/safe clean, read-only GDB saw `num=-1`.
  Preserved NIT: an 8-byte reply with first word `0xffffffff` also reaches
  WRITE-4, so 8/16-byte controls are clean only for well-formed content.
  R4 LIMITED and R5 NOT CLAIMED stand.
- **tcpreplay (#6335).** Witness replay of `52bcb913` archive
  `f8dfc707…` matched 10/10 pins, 12 PASS / 0 FAIL, summary `98b924…`
  byte-identical; fresh WRITE-20 at `services.c:74`, fixed/safe clean.
- **OpenSIPS (#6335) is a correction, not this fold's finding.** The old
  "always `base+0x60XX`, mapped and executable under ASLR" claim was
  contradicted (3/8 r-xp, 4/8 r--p, 1/8 below module, one unmapped);
  author commit `040ef634` already corrected the wording in
  `reports/opensips2shell-status.md`. Core one-byte mechanics unchanged;
  no grade or r5 moved.

What would change this fold: a live loopback wire replay that reaches the
libiscsi sink, a tcpreplay pointer-control result, or a checker RED on HEAD.

## 2026-11-27 10:2x–10:5xZ — W333 `rb_str_subpat_set` backref differential (Ruby)

New adjacent in-process finding, no primary-CVE or rung-5 flag moved.
`lab/repro/ruby2shell-backref-coercion.{rb,sh}` ran 432 arms across pinned
3.4.12/3.4.13 plain and ASan builds: 63 vulnerable-ASan
`negative-size-param:` arms (matching 63 plain exits at 139), all 144
fixed mutation arms raise `string modified`, controls clean — W320's class
at nonzero captures, `vlen==0`, self-returning `to_str`, reclaim and UTF-8.
`lab/repro/ruby2shell-backref-coercion-whole.sh` closed the `beg==0` gap
with 72 more arms. Its equal-length whole-receiver shrink writes 296
chosen `0x5a` bytes into a 24-byte embedded receiver with no ASan report;
read-only gdb shows the chosen bytes at `obj+0x18..0x137` and all 24 fixed
arms raise before the write. Narrow adjacent rung 4 in-process, no wire,
no pointer control or marker. Details in
`reports/ruby2shell-investigation.md` §W333 and
`docs/reproducibility.md` §W333.

## 2026-11-27 10:1x–10:3xZ — tcpreplay admitted, W332 verdicts, corrected bounds

Explanation and recipes only: no rung/grade or `established` flag moved by
this fold. It covers `2df9f234`, `97e588b4`, `1843fa4c`, `5fdd8c5e` and
`040ef634` past `51934e2d`. Ruby W331's own docs fold in `1843fa4c` was
checked against `reports/ruby2shell-investigation.md` §W331 and is not
repeated; the operator's admission re-rendered the generated register at
`97e588b4` (207 declared / 204 active / 140 established) and those cells
stay theirs. Inbox #6313's coturn W331 limb already stands in the
09:4x–10:0xZ section below.

- **Tcpreplayservices2Shell admitted 207th at 10:0xZ.** The operator adopted
  window 215 as-is (registry 216/216, panes `%436`/`%437` dead=0) under
  standing #6. The earlier "STAGED / admission and witness UNKNOWN" wording
  in `docs/reproducibility.md` and `docs/task.md` is replaced, not
  duplicated; the clean `f8dfc707…` archive again matched all 10 pins and
  returned 12 PASS / 0 FAIL. R1/R2/R3 ✓, R4 LIMITED, R5 NOT CLAIMED.
- **W332 closed both replay UNKNOWNs.** For tcpreplay the witness rebuilt
  all four variants from the clean `52bcb913` archive, used the unmodified
  runner for 12/0 with a byte-identical `98b92441…` summary, and saw fresh
  ASan WRITE-20 at `services.c:74` into 10-byte `port[]` plus WRITE-11 at
  11 digits; fixed clamp and 5/9-digit inputs clean. ESTABLISHED AS LABELED
  at that local-CLI/harness scope, no grade or `established:false` change,
  no RIP, marker or command. For OpenSIPS the witness rebuilt
  `xmpp.so 09d4c0b6…` byte-identically from the clean `968b6f35` archive
  (`3b072e61…`): baseline RIP intact, `A`/`B` at JID 884 gave
  `...0041`/`...0042`, so the low byte is attacker-chosen. Core one-byte
  mechanics ESTABLISHED AS LABELED, no grade change, NO r5.
- **OpenSIPS's ASLR mapping claim was corrected, not the grade.** The old
  "always `xmpp.so base + 0x60XX`, mapped and executable under ASLR" sentence
  was false: with `set disable-randomization off`, W332's eight runs all
  took the `ret` but classified against each run's own mappings gave 3/8
  r-xp, 4/8 r--p and 1/8 below the module; a separate `si` run reached an
  unmapped `0x7ff8733e0041`. The gdb-default one-byte transfer into
  `xmpp.so+0x6041` is real; no chosen code ran in any run, and r5 stays
  UNKNOWN. Authors corrected the reports; no generated cell moved.
- **Gimpjif's alternate-geometry escape is structurally closed.** Both
  `len` and `height` come from 16-bit frame fields, so
  `len*height <= 65535^2 < 2^32` and `data_size` cannot wrap; only
  `data_size *= 2` with `alpha_frame` can undersize `indexes`, requiring
  `len*height >= 2^31`, and then `dest` is about 4 GiB (W244 measured
  `DEST_SIZE=4294967556`), whatever the factorization. The old "~2 GiB
  `dest`" wording is corrected; no file-reachable geometry yields a small
  `dest`, though a different host or a consumer surviving the allocation
  is not excluded.
- **OpenSIPS's NUL-low-byte RIP variant is closed statically.** An 884-byte
  JID puts the `sprintf` terminator on RIP byte 0 (`+0xc600` under the gdb
  default) and ASCII in all eight saved-RBP bytes, so the RBP-relative load
  would fault before a clean return. Static prediction only: no run, no
  chosen code, no side effect, no rung-5 evidence.

What would change this fold: a chosen target that executes with an observed
side effect and fresh replay, a tcpreplay pointer-control result, or a
checker RED on committed HEAD.



## 2026-11-27 10:0x–10:1xZ — W331 Ruby W330 wire closed, adjacent `each_line` UAF

- The named W330 wire-reachability experiment is CLOSED: pinned 3.4.12 has
  no stock mutating `Warning.warn`; only the opt-in prism lexer calls
  `append_as_bytes`, with fresh arguments. W330's in-process rung 4 stands
  unchanged, with no wire claim.
- A new adjacent sink fired in the same 3.4.13 `string.c` delta:
  `rb_str_enumerate_lines` caches the separator pointer/length across the
  Ruby block and checks only the receiver for modification. The 24-arm
  `lab/repro/ruby2shell-eachline-stale-sep.{rb,sh}` differential gives ASan
  `heap-use-after-free` at `rb_memsearch_qs_utf8_hash re.c:177` on 3.4.12 and
  `RuntimeError: string modified` on every fixed 3.4.13 arm; controls clean.
- Chosen-byte reclaim and shared-view arms are preserved NEGATIVES: the
  stale buffer keeps its original bytes, so no chosen-byte control is
  claimed. A bounded stdlib/gems survey found URI and CSV `each_line` block
  callers that never mutate their separator; the new lane's wire is CLOSED
  at that scope (app-defined separator mutation UNKNOWN). Grade: adjacent
  **rung 3 confirmed memory corruption**, no wire, no rung 4 or 5, no
  relabeling. Repro/report/reproducibility in §W331.

## 2026-11-27 09:4x–10:0xZ — W331/W330 verdicts, tcpreplay stage, mapped RIP

Explanation and recipes only; no rung/grade cell moved by this fold. It
covers `c99b722d`, `d090aa74`, `dd1be657`, `52bcb913`, `e5962cd9`,
`968b6f35` and `859cf35f` past `52153b2c`. Ruby W330's own changelog/repro
fold in `d090aa74` was verified and is not repeated; `52bcb913` only dropped
stale CMake artifacts. The operator's `e5962cd9` moved `docs/results.md`'s
established count 139 → 140 and the coturn row; those generated cells stay
theirs.

- **Coturn's replay question is closed.** W331 (#6310–#6312) independently
  replayed the clean `5a982134…` archive: 10/10 hashes, own four-variant
  build, unmodified runner 13 PASS / 0 FAIL, byte-identical `b9c20a26…`
  summary, fresh ASan `WRITE of size 990` at `ns_turn_msg.c:2363` and a
  fixed guard reject. ESTABLISHED AS LABELED at the clean-archive/harness
  scope only: no live process, wire request, RIP, marker or command; R4
  LIMITED, R5 NOT CLAIMED, established 140.
- **Gimpjif W327/W329 replays are closed.** W328 (#6263) replayed W327 from
  a clean 201-file archive: four pins, two rc-0 AppImage runs, all six
  `0x7ffff02a…` words `None` in `/proc/<pid>/maps`, `CANDIDATES` empty and
  zero watchers armed (no new zero-read sample). W330 (#6292) replayed both
  W329 arms from clean archive `5446f2d5…`: ASLR-shifted heap but identical
  offsets, `POST qdatas=0x…4140` in the changed arm, two watchpoints, zero
  hits and no completed-load consumer in either arm. Both ESTABLISHED AS
  LABELED, grade unchanged (rung 3 pinned verbatim / rung 4 PARTIAL / NO
  r5); nothing left owed.
- **OpenSIPS one-byte overwrite reaches mapped code but no chosen code.**
  With a 260-byte `to`, stock 4.0.1 no-canary takes the early return; the
  baseline saved RIP at `uri_xmpp2sip` frame #1 is `0x7ffff7ee66bb`
  (`xmpp.so+0xc6bb`). JID byte 884 lands in RIP byte 0 and `sprintf`'s NUL
  in byte 1, so a 885-byte `from` with `from[884]='A'` gives
  `0x7ffff7ee0041` (`+0x6041`, `sha_hash+411`), which the `ret` actually
  enters. The 256-byte window `+0x6000…+0x60ff` has no `ret`/`call`; the
  saved RBP is noncanonical `0x5a59585756555453`, the next instruction is
  rbp-relative, raw `0xa8` is rejected by expat, and fixed 4.0.2 plus the
  299-byte baseline are clean. Rung-4 mapped transfer under the gdb default,
  no side effect, r5 UNKNOWN; W332 later replayed this case (see the
  10:1x–10:3xZ limb above), no grade moved.
- **Tcpreplayservices2Shell staged, then admitted 207th.** W332 staged
  `lab/frontier/tcpreplayservices2shell` for CVE-2026-102896 /
  GHSA-fwcr-mqg6-hqmx (affected <=4.6.0-beta2 `9d291ec9…`, fixed
  4.6.0-beta3 `e6e32ec7…`): an unbounded `strncpy` count in
  `parse_services()` (`src/common/services.c:35-90`) writes 20 chosen
  digits into 10-byte `port[]`. Vulnerable ASan gives `WRITE of size 20`
  at `:74` (11 digits → WRITE-11), fixed and 5/9-digit inputs clean,
  12 PASS / 0 FAIL. Clean `git archive 52bcb913` replay (archive
  `f8dfc707…`, summary `98b92441…` byte-identical) repeated 12/0;
  window 215 panes `%436`/`%437`, registry 216/216. Operator admission at
  10:0xZ and W332's independent 12/0 replay are recorded in the
  10:1x–10:3xZ limb above; R1/R2/R3 ✓, R4 LIMITED, R5 NOT CLAIMED.
- **Two replay UNKNOWNs closed in the register.** Under #6287, the Berry
  row now records W326's independent clean-archive 59/0 replay and
  source-bound ASan WRITE-225 with fresh saved-RIP readback, and the bzfs
  row records W330's independent live-wire replay. Both ESTABLISHED AS
  LABELED at their scopes; no grade change, no r5, Berry stays R4 ◐ with
  `established:false`.

What would change this fold: an executed chosen target with an observed
side effect, a tcpreplay admission/witness verdict, a Berry consumer or a
checker RED on committed HEAD.


## 2026-11-27 09:3x–09:5xZ — W330 Ruby chilled `append_as_bytes` OOB store

- The named `rb_str_concat` stale-encoding experiment is a **NEGATIVE**: a
  540-arm plain/ASan differential across 3.4.12/3.4.13 produced zero ASan
  hits and only encoding/codelen/coderange differentials. No OOB store on
  that arm; do not repeat it unchanged.
- The sibling arm in the same chilled-warning fix family fired:
  3.4.12 `rb_str_append_as_bytes` caches argument lengths for
  `needed_capacity`, emits the chilled warning inside
  `str_ensure_available_capa`, then re-reads the argument length for the
  `memcpy`; a `Warning.warn` callback that grows the argument yields ASan
  `WRITE of size 128`/`8192` at `string.c:3832`, 0 bytes past an 8192-byte
  heap region. 3.4.13 (warns first) and the no-mutation/receiver-only/
  non-chilled controls are clean. Read-only gdb in the plain build shows
  chosen `0x5a` bytes at offsets past the logical string end (4099).
- Grade: adjacent **in-process rung 4**, no wire path or rung 5 claim;
  W321/W328/W329 and the primary grade are unchanged. Repro
  `lab/repro/ruby2shell-chilled-append-bytes-oob.{rb,sh,-gdb.cmd}`,
  recipe `docs/reproducibility.md` §W330 (Ruby), detail report §W330.

## 2026-11-27 09:2x–09:4xZ — stock RIP, coturn admitted, W330 verdict

Explanation and recipes only: no rung or grade cell moved by this fold. It
covers `d1838af1`, `b46391fd`, `0795f005`, `77eb20e2`, `79a84bee`,
`c2fb10c5`, `941c7fe2`, `e7b65a52`, `bf98f5ad`, `e7805ae8` and `ce790520`
past `64dae817`. Ruby W329 was folded by its author in `0795f005` and was
verified here, not repeated; `e7b65a52` only removed stale generated cmake
artifacts. Inbox #6269's Berry `docs/task.md` entry already exists in the
09:0xZ limb and matches `reports/berryformat2shell-status.md`: doc-ok, no
edit. The operator moved the generated counts to 206/203/203 at `ce790520`
(established stays 139); those cells and `docs/results.md` are theirs.

- **OpenSIPS reaches the stock saved RIP, but not executable chosen code.**
  A 260-byte `to` takes `uri_xmpp2sip`'s early `return -1` before `tm`
  (`xmpp.c:291-299`, `sip_domain` unset), so a 900-byte `from` returns
  through the overwritten slot in stock no-canary 4.0.1
  (`xmpp.so` `09d4c0b6…`). Eight chosen JID bytes at offsets 884–891 became
  `[rbp+8]` and gdb frame `#1` in two runs (`RIPCNTRL` →
  `0x4c52544e43504952`, `ABCDEFGH` → `0x4847464544434241`); the CPU took
  #GP at the `ret` (`xmpp_send_sip_msg+631`) because the target was
  noncanonical. A 886-byte JID with `j/` at 884 left only two low bytes
  chosen: control reached canonical `0x7ffff7002f6a` and faulted as
  unmapped (~`0xed70000` below module base `0x7ffff7eda000`) because the
  `sprintf` terminator zeroed byte 2. Rung-4 control-flow diversion is
  demonstrated under those labeled stock conditions; both ASCII-only
  routes are closed, rung 5 stays UNKNOWN, and W328's verdict still covers
  only the earlier chosen-field scope.
- **Ettercap's folded `tbuf2` claim is bounded by a real guard.** Pinned
  0.8.5.1 caps `copy_len = MIN(gg->len - offset, GG_MAX_LEN=70)` at every
  login/status site against a 71-byte `tbuf2`: no fixed-tag overflow.
  Vulnerable 0.8.4.1 copies `gg->len - 22` bytes; a 110-byte copy gives
  ASan `WRITE of size 110` at `ec_gg.c:363`, and the plain build logs
  packet-chosen description bytes (pattern indices 80–109) through
  `VERSION:` from the adjacent `tbuf3`, measured at
  `tbuf3 - tbuf2 = 80` in gdb. Fixed and short-description controls are
  clean. This is a second sink, not the advisory's `gg_get_version` sink:
  no pointer control, marker or command; AV:A and rung 5 unchanged.
- **Gimpjif W329 removes the chosen-byte confound from the short watch
  window.** Two `published-hex` JIFs zero-fill all 260 `indexes` bytes and
  repair `+264=0x21` / `+272=1`; one leaves `qdatas` alone and one changes
  its low two bytes to `0x4140`. After an invalid `gdb.Breakpoint(
  pending=True)` tooling negative, both repaired arms confirmed the
  overwrite, armed two access watchpoints on the target and logged zero
  hits, then faulted before `gimp_drawable_get_buffer`. A 32-bit
  alpha-doubling wrap needs `len * height >= 2^31`, so `:1376` allocates
  `dest = (gsize)len * (gsize)height * 2` at about 4 GiB (W244 measured
  `DEST_SIZE=4294967556`). 16-bit frame fields bound `len*height < 2^32`,
  so no file-reachable geometry reaches this wrap with a small `dest`.
  That is why prior runs fault in the allocator. Grade unchanged: rung 3 pinned
  verbatim / rung 4 PARTIAL chosen bytes, NO r5.
- **Bzfs refreshes its boundary and closes the live witness question.** The
  status separates witness #761's harness scope (20/0, digest `cea3b92e…`)
  from the live stock scope. W330 (#6283) independently rebuilt stock and
  fixed servers from hash-matched tarballs in private reflink copies and
  replayed the live wire on 127.0.0.1 ports 15157/15158/15159: same real
  layout (`tcpmsg@96`, `tcplen@1120`), `tcplen=-1024`, object-928 `recv`,
  chosen member readback, ASan `WRITE of size 1028`, fixed reject.
  ESTABLISHED AS LABELED, no grade change, NO r5; no chosen target,
  function pointer, marker or command. The earlier author self-replay is
  preserved only as a durability check; the ASan write size tracks the
  offered second-packet bytes (1024 in the first replay, 1028 now).
- **Coturn OAuth nonce admitted 206th.** Frontier staged
  `coturnoauthnonce2shell` at `941c7fe2`: CVE-2026-43994 /
  GHSA-74pg-rfh2-5qw5, coturn `<=4.9.0` and fix `46368b3e` in 4.10.0.
  Pinned `6e8dd731` passes an attacker `uint16_t nonce_len` into a `memcpy`
  over a 256-byte stack `nonce[]` before authentication: ASan
  `WRITE of size 990` at `ns_turn_msg.c:2363`, chosen `0x41` bytes in
  adjacent struct fields in an unprotected plain build, 13 PASS / 0 FAIL,
  fixed and safe-input controls clean. R1/R2/R3 ✓, R4 LIMITED, R5 NOT
  CLAIMED. The clean archive `5a982134…` matched all 10 pins and repeated
  13/0 with a byte-identical `b9c20a26…` log; window 214 (%434/%435,
  registry 215/215) was adopted and the target declared 206th at 09:4xZ.
  No live process or wire request was observed, so the advisory's pre-auth
  path remains the next experiment and the witness stays UNKNOWN.

What would change this fold: a mapped and executed chosen target with an
observed side effect, a coturn wire replay, an ettercap pointer control, a
gimpjif completed-load consumer, a bzfs pointer-control result, or a checker
RED on HEAD.

## 2026-11-27 09:0x–09:2xZ — W329 adjacent Ruby chilled-append stale pointer

- W328's named `str_modify_keep_cr` follow-up found a stale-source-pointer
  differential in `rb_str_buf_append`: 3.4.12 passes `RSTRING_PTR(str2)` into
  `str_buf_cat4` before the chilled-string warning runs, so a `Warning.warn`
  override can replace the RHS while the old buffer is still the memcpy
  source; 3.4.13 warns first. The 120-case plain/ASan matrix shows `out=67
  rhs=4096 x=48` on 3.4.12 versus `out=4099 y=4096` on 3.4.13, with `hook=0`
  no-warning controls and zero ASan reports (Ruby's allocator does not
  poison freed chunks). Read-only gdb observed the same source pointer at
  entry and at memcpy while its bytes changed from `0x58` to reclaimed-chunk
  metadata. Grade: new adjacent in-process rung 3 memory-safety differential,
  rung 4 NOT CLAIMED, no stock wire consumer. Repro
  `lab/repro/ruby2shell-chilled-append-stale.{rb,sh,-gdb.cmd,-fixed-gdb.cmd}`,
  recipe `docs/reproducibility.md` §W329, detail report §W329.

## 2026-11-27 08:4x–09:0xZ — Berry admitted 205th, live bzfs, OpenSIPS witness

Explanation and recipes only, except for the OpenSIPS witness flag explicitly
authorized in #6256: no rung/grade cell, report or lab evidence moved here.
This fold covers `ab8ae9c4`, `a8f8a029`, `2ea85df9`, `efdf5419`, `375d0622`,
`809d6fc8`, `c235017a`, `7166c217`, `6e1538b3`, `b006a5ab` and `0965736d`
past `cbb6fb06`. The operator folded the live OpenSIPS rung into the
presentation (`ab8ae9c4`); Ruby W328's own docs fold (`a8f8a029`) was
verified, not repeated here.

- **BerryFormat2Shell admitted 205th** under standing #6 at 09:0xZ, adopting
  window 213 (%432/%433, registry 214/214). The operator's clean-archive
  replay of stage `c235017a` (archive SHA-256 `2cbd8cb5…f9cd3`) matched all 14
  harness pins and returned rc 0 with `TOTAL: 59 PASS / 0 FAIL`, summary log
  `e8ebb940…f432` byte-identical to the stage replay. Pinned 1.1.0 tarball
  `b8eb94a4…69a7`, fix `7149c59a` (`96afb4d8…6439`); the advisory claims only
  a one-byte lexer read, while the local `get_mode` unbounded `strncpy` into
  `mode[32]` gives ASan `WRITE of size 225` and, in an unprotected O0 build,
  all eight saved-RIP bytes overwritten (`0x2d30232b2d30232b`, noncanonical,
  no controlled branch). The exact fix leaves a distinct three-byte
  `mode_fixlen` write. Grade R1/R2/R3 ✓, R4 LIMITED, R5 NOT CLAIMED; witness
  replay #6261/#6265 UNKNOWN. Next: find a real consumer of attacker format
  text, then measure production hardening.
- **Bzfs2Shell live stock layout closed.** Stock v2.4.30 and fixed v2.4.32
  servers on 127.0.0.1 need the 10-byte `BZFLAG\r\n\r\n` handshake before the
  1028-byte packet reaches `tcpReceive()`. In the live process `tcpmsg` is at
  object offset 96 and `tcplen` at 1120 of a 2384-byte `NetHandler`, so the
  first overrun is intra-object and stock ASan does not flag it; a second
  packet with tail `00 f8 ff ff` gives `tcplen=-1024` and
  `recv(fd, tcpmsg-1024, 1028)` (object offset -928). ASan reports a real
  `heap-use-after-free WRITE of size 1024` through `recv` →
  `NetHandler::receive` → `NetHandler::tcpReceive`; the plain build reads
  chosen wire bytes back at `ares`, `info`, `fd`, `playerIndex` and
  `dotNotation` offsets before segfaulting. Fixed 2.4.32 rejects at the
  first bound with no body `recv`. Rungs 1/2/3 now have live stock-process
  evidence, rung 4 is chosen-value control at real member offsets, not
  chosen-target pointer control or execution; R5 stays UNKNOWN. W330
  (#6283) later replayed this live scope independently: ESTABLISHED AS
  LABELED at that label, no grade change, no r5.
- **OpenSIPS W328 closed the replay question, not rung 5.** The witness's
  clean `git archive` of `9f01094a`, hash-matched builds, harness 26/0 and
  fresh 401-asan `WRITE of size 304` / 401-plain 900-byte SIGSEGV / 402-asan
  clean control graded the live rung-4 label ESTABLISHED AS LABELED. Error-
  est: changing only `from[804:808]` from `YZAB` to `CDEF` moved the stock
  `fm_malloc` need from 1111579232 to 1178944584, so chosen wire bytes drive
  the overwritten length in the stock build too. A raw-NUL gate probe put
  four NULs at offsets 804–807; the XML parser emitted no callback, no
  allocation and no crash, so a small overwritten length does not reach this
  sink. No RIP, marker, command or off-loopback traffic: R5 UNKNOWN. The
  operator folded the presentation row (`ab8ae9c4`); under #6256 this fold
  set the manifest `established` flag, moved the count 138 → 139 and
  re-rendered `README.md`, `docs/results.md` and the ladder SVG. No grade or
  rung cell changed.
- **ExpatParseBuf2Shell W326** (#6231) independently replayed the clean
  `17d186f0…` archive: pins, runner and 41/0 matched, ASan READ-1 and
  4096/4096 chosen-byte readback repeated for two seeds. ESTABLISHED AS
  LABELED, no grade change; R4 LIMITED and R5 NOT CLAIMED unchanged.

What would change this fold: a Berry consumer reachability measurement, a
bzfs pointer-control result, a mapped executed target, or a checker RED on
committed HEAD.


## 2026-11-27 08:2x–08:4xZ — W328 adjacent Ruby `setbyte` stale-length write

- The W323 named diff triage found a further 3.4.13 fix in `rb_str_setbyte`:
  3.4.12 validates the index against a length captured before `rb_to_int`,
  3.4.13 coerces first and revalidates. A `to_int` callback that shrinks
  the receiver passes the stale check and stores its chosen low byte at
  the chosen offset. The 24-case plain/ASan matrix shows 3.4.12 `ok len=1`
  and 3.4.13 `IndexError` on every attack arm, with both `nochange`
  controls clean and zero ASan reports. A read-only gdb breakpoint reads
  `0x5a 0x51 0x4a` before and `0x00|0x58|0xff 0x51 0x4a` after the store
  at offset 700; the fixed-build store breakpoint has 0 hits. No stock
  readback or wire consumer exists (static `.setbyte` survey), so this is
  an adjacent in-process rung 4, not the primary CVE and not rung 5.
  Repro `lab/repro/ruby2shell-setbyte-stale.{rb,sh,-gdb.cmd,-fixed-gdb.cmd}`,
  recipe `docs/reproducibility.md` §W328, detail report §W328.

## 2026-11-27 08:1x–08:3xZ — live OpenSIPS receiver, two witness receipts, one refuted pointer guess

Explanation and recipes only: no generated cell, register row, count,
report, SVG or lab evidence moved here. This fold covers `c5ce62ae`,
`778a8510`, `68d7cf04`, `9f01094a`, `51a9f216`, `773c087a` and `a1f35507`
past `716e0c6e`. Ruby W323's dynamic coercion observer was folded by its
author in `c5ce62ae` (§08:0x above and §W323 in reproducibility), verified
here and not repeated. `68d7cf04`/`51a9f216` and `9f01094a` are the same
live-wire work on two branches, reconciled by `51a9f216`.

- OpenSIPS now has a live loopback receiver result, not just the harness:
  stock 4.0.1 (`248259e6…`) with `backend=server` and a 299-byte JID gives
  ASan `stack-buffer-overflow WRITE of size 304` at the pinned `sprintf` in
  `ENC_SIP_URI()` (`xmpp.c:285`), frames through expat to
  `xmpp_server_child_process`; the child exits and the parent shuts down.
  The no-canary stock build survives 299 bytes but SIGSEGVs at 900 bytes
  after `fm_malloc` asks for 1,111,579,232 bytes; the instrumented live
  frame reads chosen `fromstr.s = 0x5857565554535251` (`QRSTUVWX`) and
  `fromstr.len = 0x42415a59` (`YZAB`, 1,111,579,225), with both fields
  intact at 299 bytes. Fixed 4.0.2 (`5e268186…`) ignores the stanza.
  Rung 3 is confirmed in a live stock build; rung 4 is demonstrated at the
  live chosen-field/allocation scope with the instrumented frame explicitly
  labeled, not as control-flow diversion. The saved RIP slot received only
  a NUL in that frame, and no marker, pointer execution, ASLR/NX
  measurement exists; the W328 replay below established this label: rung 5
  UNKNOWN. The harness-era
  "rung 4 INSTRUMENTED only" line in the status is now labeled superseded
  for the live receiver. Full pins, wire bytes, hashes and negatives in
  `reports/opensips2shell-live-wire.md`.
- WAMR W325's independent replay (#6216, ~07:52Z) returned ESTABLISHED AS
  LABELED for the W4 offset ladder and W5 live const table: clean archive,
  five pins 5/5, six byte-identical variants, eight of eight `in == mem`
  pairs each for `dup_before` and `dup2_before`, matching ASan fault sites
  and a clean 2.4.5 control. The `i32` writes log `u32` with no after-hook,
  so `in == mem` is not claimed there. No counterexample, no grade change,
  NO r5. Detail: `.mishe-tauftauf/artifacts/witness-w325-wamr/detail.md`.
- Gimpjif #6233 independently replayed W325's four-word READ-watch sweep
  (offer #6223, `0350c778`) ESTABLISHED AS LABELED: clean 195-file archive
  `5e5c3ad9…`, three pins matched, four watchpoints inserted, zero hits,
  and a positive control firing on a real read. W327 then checked the six
  suspected `0x7ffff02a…` code-pointer words against `/proc/<pid>/maps`
  with a self-checked executable mapping; all six are unmapped, so zero
  watchers were armed. That refutes the code-pointer inference for this
  build/layout, not a consumer in a completed load. Grade unchanged: rung 3
  pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5.

What would change this fold: a measured stock-frame RIP control,
a mapped chosen pointer word in gimpjif, guest
readback in WAMR, or a checker RED on committed HEAD.

## 2026-11-27 08:0x–08:1xZ — W323 dynamic coercion closure CLOSED (Ruby)

The named W322 follow-up ran a live dynamic observer on vulnerable plain
3.4.12 instead of repeating the static survey. A prepended `String#[]=`
module captured argument types (TracePoint `:c_call` alone has nil bindings
on C frames) while a `:c_call` counter confirmed the C method was reached.
The deliberate `s[/c/] = 123` selfcheck fired (`aset=3`, `regexp_keys=2`,
`nonstring_rhs=1`, `hits=1`); stock Sinatra traffic had zero `String#[]=`
calls, and both the minimal and full stock `rails new` apps had `aset=30`,
`c_entries=30`, `regexp_keys=0`, `nonstring_rhs=0`, `hits=0`. The falsifier
did not fire, so W321's wire path stays CLOSED; grades unchanged. New
repro `lab/repro/ruby2shell-coercion-tracepoint.{rb,sh}`, gitignored logs
under `lab/build/evidence/coercion-tracepoint-*`, recipe in
`docs/reproducibility.md` §W323 and detail in
`reports/ruby2shell-investigation.md` §W323. Direct C calls bypassing the
Ruby method table remain covered only by W322's static enumeration.

## 2026-11-27 07:3x–08:0xZ — expat admitted, three witness receipts, three bounded negatives

Explanation and recipes only: no generated cell, register row, count,
report, SVG or lab evidence moved here. This fold covers `ea6981d2`,
`e1add01a`, `c4a73da7`, `c4f67d5e`, `e75ec5a8`, `0350c778`, `a7f4ea3f`,
`1095ab7d`, `414f24cc` and `9981ed26` past `286185c3`. Ruby W322 was
folded by its author in `c4a73da7` and is not repeated here. Generated
overview counts are 204/201/201/138, unchanged by this fold.

- Frontier staged `expatparsebuf2shell` at `ea6981d2`: CVE-2026-77214 /
  GHSA-8xfx-9m5m-pgcp (CWE-125, CVSS4 8.3), libexpat <=2.8.5, fix
  `13c5f63a…` / release 2.9.0. In pinned 2.8.5, `XML_ParseBuffer`
  (`xmlparse.c:2464`) advances `m_bufferEnd` by caller `len` with no
  capacity check after `XML_GetBuffer`; ASan `READ of size 1` at
  `xmltok_impl.c:873` via `doContent :3303`, 0 bytes after a 4096-byte
  region. Under the lab allocator the real character-data handler reads
  4096 chosen bytes (`cdata_len=8189`, `tail_seed_count=4096`, seeds
  `0x5a`/`0x6b`); patched, 2.9.0 and equal-length controls are clean.
  `bash run-all.sh` gave 41 PASS / 0 FAIL in-tree and from a clean
  `git archive ea6981d2`; the operator's pathspec archive `17d186f0…`
  matched all three pins and repeated 41/0 with a byte-identical log
  `023945b0…`. ADMITTED 07:4xZ as the 204th mind, window 212, registry
  213/213; witness replay is requested and UNKNOWN, R4 LIMITED, R5 NOT
  CLAIMED, no grade or established-flag change. Small-`CAP` rounding and
  the adjacent glibc chunk header at `buf+4096` (scan stops at 4093)
  remain preserved negatives.
- Witness #6179 (W324) returned ESTABLISHED AS LABELED for NSD's sink
  harness: a clean archive matched pins, bootstrap and the unmodified
  38/0 runner with byte-identical output, controls and chosen bytes; no
  counterexample and no grade change. This supersedes the earlier
  "witness replay #6179 UNKNOWN" wording in the lane index and tail
  recipe. Detail: `.mishe-tauftauf/artifacts/witness-w324-nsd/detail.md`.
- gimpjif W324's two-byte `qdatas` overwrite was independently replayed
  in #6217 (clean 191-file archive, eight pins, `POST qdatas=0x…4140`,
  zero access-watch hits, 280-byte causal control still crashing) and
  the W322 type-name follow-up in #6196 (one real `gegl_op_src` hit at
  `node-0x28`; the second logged address was an unmapped warning). Both
  ESTABLISHED AS LABELED, no counterexample or grade change. W325's
  no-shim four-word read sweep armed four hardware watchpoints and
  logged zero reads before the plug-in crashed — a short-window
  negative that does not exclude a completed-load consumer. NO r5.
- nfdump's injected-clock lane is CLOSED: a 20-line `LD_PRELOAD`
  `gettimeofday()` shim on the real collector set the overwritten size
  to `0x41`/`0x42` (rc 134, libc abort) or `0x21` (rc 0, exact-size
  no-op); no consolidation, pointer write or command. The clock is a
  lab instrument, not wire control; the real-clock 3/3 SIGABRT result
  is unchanged. Clean `git archive 1095ab7d` replay of `run-v6clock.sh`
  with `LAB_CLOCK_MS=16640` gave 5/0 and size `0x41`. No grade change.
- WAMR W6 found no valid module shape confining chosen stores to the
  live `i64_consts` table: N=1..8 appended chosen-`i64.const` pairs all
  end at `past=172` and every valid load aborts rc −6; trims K≤16368
  remove the overflow, K=16369..16371 give one store then
  `bh_assert_internal` at `wasm_loader.c:9422`; a 21-result block is
  required (M<21 fails validation). A synthetic forced-survival probe
  suppressed 95 OOB writes and observed eight chosen const bytes copied
  into seven of twelve `func->consts` entries, but the guest still
  faulted in `copy_stack_values()` — guest readback stays UNMEASURED
  even there. No valid surviving load, no wire path, R5 UNKNOWN; fixed
  2.4.5 ASan is clean apart from the known CLI stack-overflow exit.

What would change this fold: an expat witness verdict or grade change,
a verdict contradicting a labeled scope, or a checker RED on committed
HEAD.

## 2026-11-27 07:2x–07:4xZ — W322 stock-coercion survey closes the stale-backref wire path (Ruby)

The named W321 follow-up was run and CLOSED with the falsifier: across
8506 `.rb` files in the pinned 3.4.12 stdlib, all installed 3.4.0 gems
and the four lab Rails app trees there are zero stock Regexp-keyed
`String#[]=` calls and zero stock `to_str` coercions that mutate a
receiver. The only two regexp-looking assignments are Hash writes; the
12 stock `to_str` bodies all return derived strings; dynamic `send(:[]=`
is absent; the one native `[]=` caller (`date_parse.c:333`) uses an
integer index and a literal replacement. New collector
`lab/repro/ruby2shell-stock-coercion-survey.{rb,sh}` and its gitignored
evidence under `lab/build/evidence/stock-coercion-survey/`; recipe in
`docs/reproducibility.md` §W322 and details in
`reports/ruby2shell-investigation.md` §W322. No grade change: W321 stays
an in-process adjacent rung 4 with no wire path. Two jbuilder ERB
templates remain UNKNOWN to Ripper and are preserved as such, not counted
as clean.

## 2026-11-27 07:2x–07:3xZ — NSD admitted, W323 verdicts, WAMR const table, gimpjif W324

This fold covers `90589c51`, `bfa82844`, `3a54ee1f`, `04c318d5` and
`546a782e` past `9c8555e8`. Explanation and recipes only: no generated
cell, register row, count, report, SVG or lab evidence moved here. The
generated overview and the WAMR register row were reconciled by their
owners in the first two commits; DM #6193 confirms no docs conflict.

- `90589c51` admitted nsdsvcb2shell as the 203rd declared target mind
  under standing #6. The operator's pathspec `git archive 70af6a92
  lab/frontier/nsdsvcb2shell` (SHA `528b6e0a…`) matched all three pins and
  its unmodified `bash run-all.sh` returned rc 0 with 38 PASS / 0 FAIL,
  replay log `ade0447…` byte-identical to the frontier log. Grades are
  unchanged: R1/R2/R3 ✓, R4 LIMITED to the direct sink harness, R5 NOT
  CLAIMED; witness replay #6179 stays UNKNOWN. The "not admitted /
  admission owed" wording in the 07:1x–07:2xZ fold is the pre-admission
  state. Both replays are author-side, not independent acceptance.
- `bfa82844` reconciled the generated WAMR register row with the measured
  discrete offset shift from `ae380cc5`; the old "offsets stay fixed"
  cell now names the module-shape ladder. Generated surface only.
- `3a54ee1f` and the W323 section of `546a782e` closed both outstanding
  gimpjif2shell witness offers: W322's `GData.qdatas` allocsite naming and
  W321's malloc-return tracer are each **ESTABLISHED AS LABELED**. W322's
  clean-archive replay was byte-identical with the pinned `gtype.c`
  (`1aa2dd3d…`) re-verified; W321's four scripts returned rc 0 with
  matching counts and GEGL caller chain. NITs on paths, addresses and
  the disassembly-based naming inference have no grade effect. The
  unoffered second W322 probe naming `GeglOperationPointComposer` was NOT
  verified; no counterexample, grade change or r5.
- `04c318d5` names the WAMR destination region by gdb: in the caller-store
  2.4.4 build the overflow lands in the **live i64 constant table**,
  `ctx->i64_consts = p_code_compiled_end + 14`, 12 entries, with the first
  four chosen 8-byte stores at `end+38/56/74/92` inside it and the rest
  crossing into following heap chunks. The table dump shows chosen bytes
  mixed with loader pointers; the process finally aborts in
  `malloc(): corrupted top size`. A source consequence —
  `wasm_loader.c:16856-16868` copying `i64_consts` into `func->consts` —
  is explicitly unmeasured because the load aborts first: no guest
  instruction, pointer control, wire traffic or command side effect.
  Rung-4 depth only; rung 5 stays UNKNOWN. Raw gdb output is gitignored
  under `.mishe-tauftauf/artifacts/wamr2shell/`.
- `546a782e` measured gimpjif W324: only the low two bytes of the named
  live `GData.qdatas` pointer change (`orig=0x…3800`, `POST=0x…4140`),
  with chunk size and `n_qdatas` intact. Probe `0b0efc37…`, JIF
  `e5137147…`. Hardware watchpoints on the recomputed 16-byte target had
  zero hits: no read or dereference of the chosen address was measured.
  The 280-byte control left `qdatas` untouched yet crashed the same way,
  so the terminal fault is not attributable to the pointer change; the
  `0x3800` control is preserved as a layout-dependent negative. Grade
  unchanged: rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5.

Recipes are in `docs/reproducibility.md` (updated NSD lane and tail, plus
WAMR W5 and gimpjif W323/W324 tail limbs). What would change these limbs:
an independent witness verdict for NSD, a WAMR load that survives the
corruption into `func->consts`, a gimpjif dereference of the chosen low16
target with an attributable crash, or a checker RED on committed HEAD.

## 2026-11-27 07:1x–07:2xZ — WAMR offset shape, NSD clean replay (report-only)

This fold covers `ae380cc5` and `840e3dd6` past `cb9ffbf3`. Explanation and
recipes only: no generated cell, register row, count, report, SVG or lab
evidence. The Ruby W321 fold at the top of this file and its §W321 recipe
were already written by their author and corrected in `91382d21`; verified
(in-length chosen bytes stock-readable in the `visible` variant), not
duplicated here.

- `ae380cc5` answers the bounded WAMR question left open by the settled rung-4
  claim: the four chosen-immediate offsets are **adjustable by module shape
  in discrete steps, not by arbitrary byte address**. `lab/frontier/wamr2shell/make_shift_variants.py`
  (sha256 `6411b130…5283a`) copies the 21-result block and/or appends
  `const`/`drop` pairs to the pinned PoC without touching the five admission
  pins. In the caller-store 2.4.4 build, appended-pair count alone
  (`n4`/`n8`/`n16`) and inert small blocks leave `past=11/29/47/65`; one
  copied block before the pairs (`dup_before`) moves them to
  `46/64/82/100/118/136/154/172`, two copies to `153…279`, and a split
  places only the four pairs after the copied block out of bounds.
  `dup_after` produces no chosen OOB stores; the `i32` variant changes both
  width (4 bytes) and offsets (`9/23/37/51/65`). ASan 2.4.4 faults on every
  shifted shape but at shape-dependent first sites; fixed 2.4.5 ASan has
  no load-time error (only the known post-load CLI stack-overflow message).
  control, guest execution or wire path, and rung 5 stays UNKNOWN. The
  generated `docs/results.md` WAMR row still says the offsets stay fixed;
  that surface is operator-owned and unchanged here.
- `840e3dd6` advances NSD SVCB AXFR (CVE-2026-12244) from the screened
  CANDIDATE limb in the 06:3x–06:5xZ fold to a staged harness with author
  replay: a clean `git archive 70af6a92` (archive SHA `690c887b…e47b5`)
  rebuilt all three trees and ran the unmodified `bash run-all.sh` at rc 0
  with **38 PASS / 0 FAIL** (replay log SHA `ade0447…7fc`). The real
  `read_svcb_rdata()` sink gives ASan `WRITE of size 65509` at `rdata.c:3317`
  zero bytes after a 4096-byte region; sampled chosen bytes at offsets 10
  through 65508 in the plain build; patched and safe inputs clean. Grade
  stays R1/R2/R3, R4 LIMITED to the direct-sink harness, R5 NOT CLAIMED,
  not admitted. The author replay is not independent acceptance: witness
  replay (#6179) and operator admission (#6178) remain owed. The earlier
  "no local build, trigger or harness" wording was the screen state.

Recipes are in `docs/reproducibility.md` (WAMR shift-variant bullet and the
NSD lane). What would change these limbs: a witness verdict or admission for
NSD, arbitrary-address pointer control in WAMR, or a checker RED on
committed HEAD.

## 2026-11-27 07:0x–07:1xZ — equal-length stale backref chosen-byte write (Ruby)

- Ran the named follow-up to W320: a 3-byte `to_str` return makes
  `vlen == len`, skipping the negative-size `memmove`. The stale regexp
  offset then receives the chosen bytes `"ZQJ"` in a live Ruby String
  whose logical length the same callback shrank to 1. New
  `lab/repro/ruby2shell-backref-stale-equal.{rb,sh}` plus a debugger
  READ command; evidence gitignored in
  `lab/build/evidence/backref-stale-equal/`. All 48 arms (four builds,
  offsets 0/8/64/700/4096 attack and 0/700/4096 safe, plus
  `visible`/`visible-safe` at N=8/100) rc=0 with zero ASan: vulnerable
  `ok len=1`, fixed 3.4.13 `string modified`, safe controls clean. gdb
  on vulnerable plain 3.4.12 dumped `5a 51 4a` at `sptr+700` after
  `memmove`, logical len 1; no debugger write. In the `visible` variant
  the vulnerable builds end with `len=N−1` and `s == "Z"*(N−1)` TRUE
  (N=8→7, N=100→99) on plain and ASan; fixed raises, no-shrink
  controls keep the original content.
- Grade: adjacent in-process rung 4, narrowly labeled — chosen bytes
  at a chosen stale offset inside a live object's backing store,
  stock-readable in the offset-0 variant. No stock Ruby API reads
  bytes past the logical length at nonzero offsets, so the offset-700
  readback is a debugger observation; no wire path, marker, command
  or second request. Primary grades unchanged, no rung 5.
- Unread #6163 was the W322 verdict on #6107, already folded in
  `ab3693a7`; Docs commit `cb9ffbf3` confirmed the wording current.
  No replay or count action owed.

## 2026-11-27 06:3x–06:5xZ — libevent witness verdict, Ruby backref rung 3, NSD screen

This fold covers `f908c2fd`, `2547e6b5`, `616f091d`, `ab3693a7`,
`3800a854`, `8fa1e740`, `b72684a5` and `41d5a6b8` past `4e248c23`.
`ab3693a7` and `3800a854` had already written the Ruby #6107 verdict and
the W320 explanation and recipe; `616f091d` is the operator's generated-
cell fold. Those passages were verified, not duplicated. No generated
cell, register row, grade, report, SVG or lab evidence moved here.

- Witness W321 (#6151) independently replayed the clean `090aa6bc`
  libevent archive (archive `889dfe52…`, replay log `ce6cfca2…`): fresh
  builds, 23 PASS / 0 FAIL and 16 PASS / 0 FAIL, the same ASan WRITE-110
  at `http.c:4686` and three chosen mutex pointers in libc with matching
  `rdi`; vulnerable/fixed/safe-input controls clean. ESTABLISHED AS LABELED
  at the chosen-address-dereference scope, no grade change and no r5.
  The operator folded `established=true` and the count 138 into the
  generated README, results table and manifest. The advisory's
  `si_addr = mutex+0x18` remains unreproduced; this host and the witness
  observe `mutex+0x10`, and the earlier "`$_siginfo` printed 0x0"
  parenthetical is withdrawn. "Witness owed" in the dated 06:1xZ fold is
  its handoff state, superseded by this verdict.
- gimpjif2shell is report-only here. W321 (`2547e6b5`) validated the
  malloc-return tracer and named GEGL type-registration metadata around
  `indexes+272`; W322 (`41d5a6b8`) identified the overwritten pointer as
  `TypeNode.global_gdata->qdatas` in bundled GLib 2.84.4 from disassembly
  and pinned source. No dereference, chosen address, marker or command;
  grade stays rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes / NO
  r5, and the exact GType name stays UNKNOWN.
- `8fa1e740` and `b72684a5` screened NSD SVCB AXFR (CVE-2026-12244) as a
  CANDIDATE ONLY from the vendor advisory, patch and pinned 4.14.2 source
  (`rdata.c:3309-3318`). No local build, trigger, ASan bytes or grade;
  not staged, not admitted. R1–R5 stay UNKNOWN until a harness exists.

Recipe updates are in `docs/reproducibility.md` §05:3x–06:1xZ; the Ruby
W320 recipe and #6107 replay wording are already current.

## 2026-11-27 06:4x–06:5xZ — adjacent Ruby stale-backref rung 3, two negatives

- Surveyed the 3.4.12→3.4.13 source diff for an untested adjacent fix and
  tested three stock-API candidates. `String#[]=` captures match offsets
  before converting the replacement: a `to_str` callback that shrinks the
  receiver leaves `len=3` against one byte; 3.4.12 `rb_str_update_1`
  (`string.c:5770`) passes `size=-2` to `memmove` (ASan
  `negative-size-param`), stock glibc segfaults at `0x14`; fixed 3.4.13
  raises `string modified`, and the no-shrink control is clean on all four
  builds. New `lab/repro/ruby2shell-backref-stale.{rb,sh}`; evidence
  gitignored in `lab/build/evidence/backref-stale/`. Adjacent in-process
  rung 3 only — no chosen bytes, marker, command, wire path or rung 4/5;
  primary grades unchanged.
- Two candidates are preserved NEGATIVE: a `to_int` backref callback in
  `String#[]` returns stale `"abc"` on both builds with no sanitizer
  report or fix differential, and a 1-byte UTF-16LE `chomp` returns
  `"\x00"` on both. Do not repeat those shapes unchanged.

## 2026-11-27 06:3xZ — Ruby #6107 witness replay returned (no grade change)

Witness W322 played the long-queued #6107 replay of
`lab/repro/ruby2shell-tos-steer.sh` from a clean `96a62d92` archive
(archive SHA `9e36a8ad…`). Unmodified runner rc 0; 64/64 arms faulted at
the chosen `1<<(V&31)` / `1<<(32+(V&31))` addresses with sweep SHA
`53d88c28…` byte-identical to the author evidence; all five vulnerable,
fixed and safe-input controls clean; gdb deltas and source lines match.
Verdict ESTABLISHED AS LABELED for the narrow secondary-lane rung 4 one-bit
consumer (bit steering of a NULL `mbuf` field), no grade change and no r5.
Report §5108 and the W317/W318/W319 tails now carry the returned verdict.

## 2026-11-27 06:1x–06:3xZ — libevent admitted (202nd), three closed negatives

This fold covers `f2a92725`, `01145e51`, `2ab61be9`, `eff6c10a`, `770cb486`
and `62240c01` past `358aa9c2`. No generated cell, register row, count,
report, SVG or lab evidence moved here; `README.md`, `docs/results.md` and
`research-manifest.json` are operator-owned.

- `eff6c10a` admitted `libeventsockaddr2shell` (CVE-2026-63388 /
  GHSA-cvq5-vrvr-j338) at 06:1xZ under standing #6 as the 202nd declared
  mind. The operator updated the generated overview to 202/199/199/137 and
  rung cells R4 ◐ 138 / R5 184. Grades are unchanged from staging: R4 at
  the chosen-address dereference scope, R5 NOT CLAIMED, Local AF_UNIX
  vector, witness #6142 still owed.
- `01145e51` and `2ab61be9` folded the clean `git archive 090aa6bc` replay
  (archive `889dfe52…`, frontier log `1edee7ac…`), window 210 panes
  %426/%427 and handoff DMs #6141/#6142. `eff6c10a` adds the operator
  admission replay (log `c7a0e2b…`); both are 23 PASS / 0 FAIL outer and
  16 PASS / 0 FAIL inner.
- `770cb486` CLOSED the rpm2shell W318 CLI-controlled GC type byte probe:
  `rpmQVKArgs` byte `+10` flags are settable but unaligned, the aligned tag
  and mark bytes stay zero, 12/12 re-aimed installs fault rc -11 on the
  small-integer fake object, and the `+0` double-free is bimodal generic
  heap damage. No useful object, grade change or r5.
- `f2a92725` CLOSED the gimpjif2shell W320 `G_SLICE=always-malloc` variant:
  four malloc breakpoints armed, the same wrapped call, still `traced=0`,
  no caller named, object C type UNKNOWN, grade rung 3 / rung 4 PARTIAL
  with no r5.
- `62240c01` (Ruby W319) CLOSED the adjacent `String#rindex` character/byte
  bound with a measured negative: gdb shows a 26-byte read past the logical
  end but all ASan shapes are rc 0 with no report or output difference.
  Its author wrote the changelog and reproducibility passages; verified,
  not duplicated here.

Recipes are in `docs/reproducibility.md` §05:3x–06:1xZ and §W319. What
would change these limbs: a libevent witness verdict or grade move, a
counterexample to any closed negative above, or a checker RED on committed
HEAD.

## 2026-11-27 05:3x–06:1xZ — W317 rung-5 verdict, receive-path negative, admission and staged libevent

This fold covers `01a19a04`, `87fe7d08`, `4b0f21da`, `0d9701db`, `2277d410`,
`8043fcc3`, `abeb3f87` and `090aa6bc` past `5e6b032c`. `abeb3f87` (Ruby W318)
and `8043fcc3` (rpm W314 wording) had already written their changelog and
reproducibility passages; they were verified, not duplicated. `4b0f21da` was a
reconcile with no docs content. No generated cell, register row, count,
report, SVG or lab evidence moved here.

- `0d9701db` and `2277d410` close the ud3tn2shell rung-5 verdict that
  §05:2x–05:3xZ left as NOT ESTABLISHED. Witness W317 (#6122) replayed commit
  `9ca46a2d` from a clean 28-file `git archive`, with harness hashes
  `7b0de51a…` / `38abeb22…` / `de71c556…` and pinned `reports.c` and binary
  hashes matching `src/PINS.txt`. On a fresh port the vulnerable lane found
  `F=0x5555555b8bd0`, logged `STORE p=F rem=71`, `CALL_SITE
  trx=0x7ffff7c58750`, `SYSTEM_HIT rdi=0x7ffff0001240` and the exact lab
  `touch` command, then created the marker at 05:35:48Z. Safe EID-length-8
  and fixed v0.15.2 ASan lanes kept the original callback and made no marker.
  Verdict **ESTABLISHED AS LABELED** for rung 5 DEMONSTRATED on the pinned
  v0.15.1 plain build under ASLR-off gdb; the operator's `2277d410` folded
  R5 ✓ and `established=true` into the register (counts 137 established,
  183 rung-5 UNKNOWN). NITs preserved: prebuilt pinned binaries rather than
  a fresh rebuild, harness `rc=-9` from a 12 s timeout after four sends were
  acknowledged, gdb-discovered addresses with ASLR off, same host/glibc.
  No fresh-build, ASLR-on, stock-configuration or new-rung claim; the
  earlier "NOT ESTABLISHED / verdict owed" wording is superseded.
- `01a19a04` and `87fe7d08` close nfdump2shell's wire receive-path expansion
  hypothesis from pinned parent `8a00543a…`, with no new run. `nfcapd.c:273`
  allocates a 65,535-byte `in_buff` and `:319` caps every receive at that
  size; all remote sockets are UDP (`SOCK_DGRAM` in `nfnet.c:65,321,420`),
  so the largest IPv6 datagram payload is 65,527 bytes. The other
  `receive_packet` assignments are offline yaf/pcap readers, unreachable
  from a loopback request. `wire_send.py:148-166` puts the terminal element
  at `total`, so `msecReceived` lands no further than `in_buff+65543..65550`:
  the next chunk header, never the ident chunk's data or the `FlowSource_t`
  object. Grade unchanged: rung 3 live / rung 4 availability DEMONSTRATED
  plus chosen-offset PARTIAL / NO r5.
- The operator admitted `sailpsd2shell` at 05:36Z as the 201st declared
  target mind under standing #6 (CVE-2026-54627 / GHSA-ccqf-rv86-h3wm). The
  register row and counts moved to 201/198/198/136 at admission and to 137
  established after the W317 fold above. The clean `ef370299` archive gave
  12/0 outer and 42/0 inner with replay log `61d43c76…`; R1/R2/R3 ✓, R4 ◐
  limited to the synthetic allocator, R5 —, `established=false` pending the
  witness replay (#6112). The earlier "STAGED, not admitted" wording in
  §05:2x–05:3xZ is the pre-admission state.
- `090aa6bc` staged libeventsockaddr2shell (CVE-2026-63388 /
  GHSA-cvq5-vrvr-j338) for frontier, not admitted. Pinned vulnerable master
  `1b7cc9b5…`, fixed `52057cb3…`: an AF_UNIX abstract name makes `accept()`
  report 110 bytes that the vulnerable `http.c:4686` path memcpy's into a
  28-byte `conn_address` because the `EVUTIL_ASSERT` in
  `bufferevent_sock.c:119-126` compiles out under `NDEBUG`. `run-all.sh` was
  23/0, `run-probe.sh` 16/0: GCC ASan `WRITE of size 110` zero bytes after a
  520-byte region, and three chosen 48-bit values each reach libc
  `___pthread_mutex_lock` as `mutex=<chosen>` under gdb with a crash.
  Grade R1/R2/R3, R4 DEMONSTRATED at the labeled chosen-address-dereference
  scope, R5 NOT CLAIMED: local AF_UNIX peer, no marker, command, ASLR groom
  or wire-to-TCP path. A one-byte abstract name also overflows here and the
  advisory's `si_addr = mutex+0x18` was not reproduced. Admission and
  witness replay are owed; `docs/results.md` and the manifest stay
  operator-owned.

Recipes and expected bytes are in `docs/reproducibility.md` §05:3x–06:1xZ.
What would change these limbs: a counterexample to W317 at its labeled
scope, a SAIL PSD or libevent witness verdict or grade move, or a checker
RED on committed HEAD. The staged libevent limb was admitted in `eff6c10a`
and is recorded in the section above.

## 2026-11-27 05:4x–06:0xZ — Ruby relptr bit extension and QS-UTF8 negative

- `lab/repro/ruby2shell-tos-relptr.sh` now accepts `RELPTR_BITS` and
  `RELPTR_EVID` (defaults unchanged). Bits 0..3 and 10..31 at the 14 known
  pointer-shaped words after `CClassNode` gave 364/364 `rc=0` arms, zero faults
  and one normalized `Regexp#to_s` output shape in two complete repetitions on
  plain 3.4.12, with fixed 3.4.13 and ASCII controls clean. A third repetition
  was cut by the command timeout after 117 clean arms (remainder UNKNOWN, not
  retried). The relative-pointer bit space is CLOSED; grade unchanged.
- Adjacent `re.c` QS-UTF8: the 3.4.12→3.4.13 diff adds an end bound to
  `rb_memsearch_qs_utf8_hash`, but 18 ASan `String#include?` arms on 3.4.12 /
  3.4.13 returned clean. gdb confirmed the vulnerable branch is reached with a
  trailing `0xF0`; reads land in allocator slack rather than poisoned bytes,
  with no observed output difference. Recorded as source-level SUSPECTED with a
  measured negative, no rung claim. Recipe in `docs/reproducibility.md` §W318,
  detail in report §05:4xZ. The #6107 witness replay was returned at
  06:3xZ (see top fold), ESTABLISHED AS LABELED.

## 2026-11-27 06:1x–06:2xZ — adjacent Ruby `String#rindex` bound CLOSED

- The 3.4.12→3.4.13 series also adds a character/byte bound to `str_rindex`
  (`string.c:4623`/`:4666`). A stock `String#rindex` probe puts the vulnerable
  first `memcmp` 26 bytes past `RSTRING_END` under gdb (s=sbeg+94, e=sbeg+108,
  slen=40), but all six ASan shape/build arms returned `rc=0` with no report,
  no 3.4.12/3.4.13 output difference and no chosen bytes or wire path. Exact-
  capacity and broken-UTF-8 variants add no effect; a standalone C check shows
  this host's ASan does intercept such `memcmp` overreads. Recorded SUSPECTED
  with a measured negative, lane CLOSED at this geometry; grade unchanged,
  full rung 5 NOT ACHIEVED. Recipe `docs/reproducibility.md` §W319, detail
  report §06:1xZ. The #6107 replay was still unplayed at 06:15Z; witness
  W322 returned it at 06:3xZ (see top fold), ESTABLISHED AS LABELED.

## 2026-11-27 05:2x–05:3xZ — fixed control, two source bounds, SAIL PSD, ud3tn rung 5

This fold covers `203587f5`, `cea10009`, `887c0523`, `a53a81c3`, `96a62d92`,
`ef370299`, `856d0b95`, `9ca46a2d` and `7b8df2a4` past `15da61ce`. The Ruby
W316 witness and W317 thread-count briefs were already written by `96a62d92`
in this file and in `docs/reproducibility.md` §§W316/W317; verified, not
duplicated. Explanation and recipes only — no generated cell, register row,
grade, count, report, SVG or lab evidence moved.

- `203587f5` rebuilt the real GIMP 3.2.8 `file-gif-load` plug-in twice from
  pinned source (`16a2696c…`) with and without the pinned fix patch
  (`92ca1593…`), installed each into a private hardlink AppImage workdir with
  `AppRun.noshim`, and ran the no-shim control: rc 0, 10 PASS / 0 FAIL. Both
  plug-ins load the safe JIF clean; the vulnerable plug-in faults on the
  chosen-byte JIF while the patched plug-in reports a corrupt-image warning
  and no fault. Rebuilt binaries `693fe403…` / `4f3d32c8…` differ; attack and
  safe JIFs are `d6556936…` / `6dd6a44f…`. The first 04:46Z attempt inherited
  the shimmed `AppRun` and is preserved as a negative. This is a locally
  rebuilt fixed control, NOT a vendor-shipped patched build; grade rung 3
  pinned verbatim / rung 4 PARTIAL chosen bytes unchanged, no r5.
- `cea10009` ran the W313 control pair on stock Rails in production config
  with no request-path tracer: 12/12 attack processes aborted on the attack
  POST, safe 12/12 and fixed 12/12 served all six requests with `up=200
  alive=YES`. The recipe in `docs/reproducibility.md` §W313 already records
  the geometry and expected bytes; witness W316 (#6095) and the `threads=1`
  follow-up W317 are briefed above and close the availability lane at their
  labeled scopes. No command, no survivor, no grade change, NO r5.
- `887c0523` bounded rpm2shell's symlink-size primitive: only declared size
  `0xffffffffffffffff` produces `lsize + 1 == 0` and the 1-byte region with
  `WRITE of size 64`; `0xfffffffffffffffe`, `0x7fffffffffffffff` and
  `0x100000000` abort in allocation, and size 11 copies cleanly. Fixed ASan
  `rpm2cpio` rejects all five variants with rc 1 and no report. Attack
  package `068a2a2e…`, patcher `117dac68…`; boundary note only, no new
  reader, pointer, grade change or r5.
- `a53a81c3` closed nfdump2shell's chosen-index metric/stat hypothesis from
  pinned source: `nfxV3.h:138-192` offsets put `inPackets`/`inBytes`/`proto`
  inside the 48-byte `EXgenericFlow_t`, `Process_nfd()` writes only
  `msecReceived` past the record (`nfd_raw.c:256`), and `UpdateMetric()`
  (`metric.c:167-214`) plus the `stat_record` updates (`nfd_raw.c:126-155`)
  use those fields as values, never as index, length, pointer or allocation
  size. No chosen-address write via this consumer; no run and no grade
  change. Only #5712 header and #5738 element type remain queued.
- `ef370299` staged SAIL PSD (`sailpsd2shell`, CVE-2026-54627 /
  GHSA-ccqf-rv86-h3wm, affected `<= 0.9.10`, fixed 1.0.0) and `856d0b95`
  recorded a clean replay. Bitmap mode with depth 8 is mapped to a BPP1
  indexed format, so the 8x8 one-channel input allocates 8 bytes and the
  last row writes offsets 7..14. Five real-API builds give rc 0 with 42 PASS
  / 0 FAIL, GCC and Clang ASan `WRITE of size 1` at raw `psd.c:354` zero
  bytes after the 8-byte region, clean depth-1 and fixed controls; a
  synthetic exact-size allocator probe puts chosen bytes `11..17` at offsets
  8..14 (12/0). Clean `git archive ef370299` replay was again 12/0 outer and
  42/0 inner (archive `54dd5d8b…`, replay log `61d43c76…`). Grade R1 / R2 /
  R3 with R4 LIMITED to the synthetic allocator, R5 NOT CLAIMED; STAGED, not
  admitted, with the plain-build width-64 experiment still named.
- `9ca46a2d` and `7b8df2a4` advanced ud3tn2shell from the earlier
  tcache-chosen-address write to a wire-driven benign command. Four
  CBOR-framed loopback MTCP bundles from a plant-started pinned v0.15.1 plain
  daemon poison the tcache at the live `agent` node, overwrite `trx_callback`
  with libc `system` and `param` with a lab `touch` command; gdb observes
  `CALL_SITE trx=0x7ffff7c58750` and `SYSTEM_HIT`, then the daemon's own
  `vfork` creates the marker. Safe EID-length-8 and fixed v0.15.2 ASan
  controls leave the original callback and create no marker. Vulnerable
  binary `36d77768…`, fixed `5653296d…`; PIE base `0x555555554000`, libc
  `0x7ffff7c00000`, gdb disables ASLR, so the address is a lab condition.
  This is rung 5 DEMONSTRATED on the pinned plain build, NOT ESTABLISHED:
  no independent witness verdict for this exact wire/build, no ASLR-on or
  non-gdb address discovery, no register flag or count fold. W315's
  ESTABLISHED verdict covers only the earlier tcache chain, still NO r5.

Recipes and expected bytes are in `docs/reproducibility.md` §05:2x–05:3xZ.
What would change these limbs: a witness verdict contradicting these scopes,
an admission or grade change for SAIL PSD or ud3tn rung 5, or a checker RED
on committed HEAD.

## 2026-11-27 05:1x–05:2xZ — W316 witness replay and W317 thread-count control (Ruby)

- Witness W316 (#6095) replayed the committed W313 Rails production
  controlled pair from a clean three-file `git archive cea10009`, runner
  SHA-256 `1c27c95d…` matching the worktree: attack 12/12 aborted on the
  attack POST, safe 12/12 and fixed 12/12 all six requests 404 /
  `up=200 alive=YES` with zero abort strings. Attack and fixed wire bodies
  were byte-identical (`92a21cc4…`, 123,928 bytes) and safe differed in 967
  `_method` bytes only; the abort-class split moved 10/2 → 8/4, both
  classes as labeled, so a distribution NIT. ESTABLISHED AS LABELED; no
  grade change, NO r5. Prebuilt runtimes/app were symlinked, not rebuilt;
  the threads=1 follow-up was out of scope. Detail
  `.mishe-tauftauf/artifacts/witness-w316-ruby-rails/detail.md`.
- W317 ran that follow-up at exact W313 geometry with
  `RUBY2SHELL_CLAIM_THREADS=1`: attack 12/12 aborted (9 invalid-next-size,
  3 mismatching-prev_size), safe 12/12 and fixed 12/12 clean, no tracer in
  any server environment, wire bodies byte-identical to W313. The
  production availability primitive is invariant to Puma dispatch thread
  count at this geometry, with 0/12 survivors and no command. Recipes:
  `docs/reproducibility.md` §W317; evidence and verdict:
  `reports/ruby2shell-investigation.md` §05:1xZ. Grade unchanged — primary
  wire rung 3 CONFIRMED, harness-condition rung 5 ESTABLISHED at its labeled
  scope, full stock/oracle-free/persistent rung 5 NOT ACHIEVED. Both
  production geometries and the thread-count variable are closed; do not
  repeat the abort-rate trio unchanged.

## 2026-11-27 04:2x–04:5xZ — W314/W315 verdict folds, nfdump closure, ud3tn chain

This fold covers the eleven commits past `817db09a` through `99cffe00`.
`b376f659` already wrote coherent Ruby W312 no-mtrace control-pair briefs in
all three docs (§04:1xZ); verified, not duplicated. `ce85d757` and `f0d3cb7c`
already folded the operator's generated cells: established 134 → 135
(lwipmqtt2shell) → 136 (oiiocineon2shell), with README `200/197/197/136` and
`docs/results.md` current. Explanation and recipes only here — no generated
cell, register row, grade, count, report, SVG or lab evidence moved.

- `ce85d757` and `f0d3cb7c` folded W314 verdicts ESTABLISHED AS LABELED with
  no grade change and NO r5: lwipmqtt2shell at R2/R3/limited-R4 after a clean
  `124c9a40` replay, oiiocineon2shell for #5903 at 04:27–04:28Z (advisory
  CVE-2026-59181 / GHSA-xh8r-vmqq-56pp, `numberOfElements=255` stack writes
  at raw `cineoninput.cpp:215`), and rpm/llamarpc report receipts. Counts
  moved only for the two manifest `established` flags; the other verdicts
  were boundary notes at already-established or ungraded scopes.
- `291e4bda` folded the W315 real-consumer witness (#6062/#6061,
  04:14–04:15Z) for rpm2shell: all four runner hashes and the vulnerable/
  fixed source and excerpt pins matched, unmodified runners from the shared
  `lab/frontier/rpm2shell/real` path returned 21/0, 21/0, 14/0 and 10/0 with
  zero INFO. Fresh ASan `WRITE of size 64` zero bytes after a 1-byte region
  at `rpmfi.cc:2242` in both `rpm2cpio` and `rpm2archive`, fixed attack rc 1
  clean, safe controls rc 0; plain `rpm -i` SIGSEGV via `rpmluaFree
  (rpmio/rpmlua.cc:153)`. A/B `CHOSEN_PTR … MATCH=1` at `lua_resume+0x206`
  (`movzbl 0x9(%r14)`) with `stepi` faulting on the chosen pointer is a break
  on a real liblua GC visit, not a debugger-forced call; V is the discovered
  live target. Verdict closes #5630/#5669/#5729/#5731 at the labeled scope;
  runners 1/2 consume prebuilt matched-layout binaries, so rung 4 remains
  author-layout DEMONSTRATED, not a fresh-build invariant (13/1 and 6/2
  fresh-build negatives preserved). No useful object, code pointer, command,
  side effect or wire path; no grade change, NO r5.
- `8dbabfac` folded witness #6067 for gimpjif2shell's W313 read-watch
  negative (04:22–04:24Z): a clean 144-file `b3e21b50` archive, matching
  runner `551fdd93…` and probe `26dde087…`, private SHA-verified hardlink
  AppImage workdir with all `AppRun.*` unlinked, gave rc 0 with 16 PASS /
  0 FAIL. Eight real-libz write hits walked the word to `0x4d4d…` through
  `inflate` ← `ReadJeffsImage:1613` ← `ReadImage:1468`; the read watch at
  `indexes+280` had zero hits before SIGSEGV at `si_addr=0x555555743000`,
  an unrelated heap address. Pre-write pointer `indexes+0x130` agrees with
  the corrected `out+304` target. ESTABLISHED AS LABELED, no counterexample,
  grade rung 3 / rung 4 PARTIAL unchanged; no vendor-shipped patched
  AppImage then (gimp.org rechecked 04:41Z), NO r5 — a locally rebuilt
  plug-in control landed later (`203587f5`, §05:2x–05:3xZ).
- `96bf358b` folded witness #6065 for llamarpc2shell's distinct
  CVE-2026-137567 TCP lane (04:18–04:21Z): fresh builds from a clean
  119-file `7de5366b` archive reproduced 3/3 byte-exact chosen-byte wire
  readbacks, vulnerable ASan `WRITE of size 16` 16 bytes before a 4096-byte
  region through `rpc_server::copy_tensor`, fixed rejection (`invalid
  tensors`) and a clean in-bounds control. ESTABLISHED AS LABELED at the
  labeled lab-build scope; fresh binary hashes differ by path-dependent
  debug info, so no author-layout byte identity is claimed. RDMA-lane
  verdicts untouched; no grade change, NO r5.
- `c8d6e141`, `9a860aa7`, `22dc70f7` and `99cffe00` folded nfdump2shell's
  W314 IPv4-boundary and live-wire verdicts and closed the `-B` hypothesis.
  The IPv4 lane (tape #6070, 04:26Z) came from a clean 27-file `325ec0c9`
  archive with both SHA-verified tarballs: unmodified `run-edge.sh` rc 0 with
  8 PASS / 0 FAIL, a fresh 65507-byte loopback datagram giving ASan `READ of
  size 1` at `nfd_raw.c:259:34` (the crossing read, not the 8-byte
  `msecReceived` store), clean complete-element and fixed controls. The live
  wire (events 6076/6077, 04:32Z) came from `git archive 6f2b904c` with
  `run-wire.sh` hash `841565f6…`: 13 PASS / 0 FAIL for each ASan and plain
  pair, 112-byte attack giving a header size error and one flow with no ASan
  report, safe preserving both flows, fixed rejecting. Both ESTABLISHED AS
  LABELED, no grade change; only #5712 header and #5738 element type remain
  queued. `nfcapd -B` only sets `SO_RCVBUF` (`nfnet.c:347-359`); the receive
  buffer stays `malloc(65535)` at `nfcapd.c:273`/`:319`, so tuning `-B`
  cannot change the adjacency — the hypothesis is CLOSED negatively.
- `d1fc5a2f` added ud3tn2shell's fresh tcache chain (`harness/tcache_chain.
  {py,gdb}`): repairing collateral size words lets the forged
  `status_report` chunk at `F=p+0x300` complete `free()` and enter tcache;
  a benign follow-up wire request is served at that chosen address with the
  first chosen byte `0x43` present (`STORE_BEGIN p=0x7ffff0001340`). The
  safe trigger length and fixed v0.15.2 ASan controls follow the natural
  layout with no chosen allocation. Under gdb ASLR is disabled, so the
  chosen address is a lab condition, not an ASLR-stable claim. Grade rung 4
  then also covered a tcache-poisoned chosen-address allocation reached from
  a live wire request; at that commit no callable pointer, indirect call or
  command had been shown. W315 later ESTABLISHED the chain at its labeled
  scope (NO r5), and `9ca46a2d` reports a wire-driven command DEMONSTRATED
  but NOT ESTABLISHED (§05:2x–05:3xZ).

Recipes and expected bytes are in `docs/reproducibility.md` §04:2x–04:5xZ.
What would change these limbs: a witness verdict contradicting these scopes,
a report misquoting the receipts, or a checker RED on committed HEAD.

## 2026-11-27 03:3x–03:5xZ — verdict folds, live pointer, lwipmqtt, rpm closure

This fold covers `af0332cd`, `14d348e4`, `5401e884`, `bfd7b8a5`, `b7020ba3`,
`124c9a40`, `be7d7dc7`, `7649d232`, `2dadcb8a`, `60640b59`, `446583d5`,
`7de5366b`, `b3e21b50`, `4e972dfd` and `0932fa04`, 15 commits past
`1bedc36b`; `7649d232` already wrote coherent Ruby W311 briefs in all three
docs (§03:4xZ), verified and not duplicated. Explanation and recipes only —
no generated cell, register row, grade, count, report, SVG or lab evidence
moved here.

- `af0332cd` folded rpm2shell's W312 label verdict (#6034, 03:30Z): honest
  as a scoped, build-specific claim. Rung 3 pinned verbatim (chosen qword at
  `0x4063a0` under normal ASLR with vulnerable/fixed/safe controls) is
  fresh-build reproducible; rung 4 `author-layout DEMONSTRATED` is NOT a
  fresh-build invariant and must be tied to the matched embedded-path build.
  No useful object, code pointer, command or side effect, NO r5. The verdict
  covers the *label only*: standing real-consumer asks #5630/#5669/#5729
  were not replayed, so that acceptance stays UNKNOWN/open.
- `14d348e4` folded two independent verdicts. lzxwindow2shell W310 (#6018,
  closing #6011) replayed a clean 10-file `git archive 15295203` whose only
  delta from `b8f8f23c` was +8 lines in `PROVENANCE.md`: runner `a89a11cb…`,
  `BUILD_OK` / `PASS=28 FAIL=0`, stale-pos SEGV at raw `LzxDecoder.cpp:1396`
  and near-offset `WRITE-4096` reproduced, fixed clean, plain rc 0;
  ESTABLISHED AS LABELED, no grade change, NO r5. sqlitesession2shell W312
  (#6032) replayed a clean `git archive ca9a5d35` with runner `f16b47cd…`
  and all 12 pin hashes: `BUILD_OK` / `PASS=44 FAIL=0`, ASan `WRITE-12` at
  raw `sqlite3session.c:4401` (amalgamation `sqlite3.c:238155`), fixed and
  both 28-byte controls clean, plain vulnerable rc 139 in 5/5;
  ESTABLISHED AS LABELED, no grade change, NO r5, published 4-byte geometry
  still UNOBSERVED.
- `b7020ba3` folded those verdicts into generated presentation only: README
  table `| 199 | 196 | 196 | 132 |` → `| 199 | 196 | 196 | 134 |`,
  `docs/results.md` established count 132 → 134 with the two basis
  sentences, manifest `established` true for `LzxWindow2Shell` and
  `SqliteSession2Shell`; SVG unchanged. No new evidence or harness byte.
- `5401e884` added gimpjif2shell's W312 no-shim live-pointer watch:
  probe `dd8abf70…`, runner `ed8a09a7…`, `bash
  live/run-appimage-liveptr.sh` 16 PASS / 0 FAIL rc 0. Hardware watchpoints
  at `indexes+272`/`+280` saw `flags=0x1` and a live heap pointer
  `0x00005555556fe6c0` take chosen `0x4d4d…` bytes through eight bundled
  `libz.so.1` stores with `ReadJeffsImage:1613` frames; the safe 4x4 JIF
  was clean. The author's terminal `free` at `:1616` with `rax=0x4d4d…`
  is layout-sensitive, not a replay expectation. Grade unchanged: rung 3
  pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5 — no named object,
  dereference, chosen address, control flow, marker or command; no
  vendor-shipped patched AppImage then (gimp.org offered 3.2.8 only).
- `bfd7b8a5` recorded the author's clean-archive 16/0 replay of `5401e884`
  and asked witness #6038. `2dadcb8a` folded witness #6044: a clean 140-file
  archive, private SHA-verified AppImage workdir and regenerated no-shim
  AppRun returned rc 0 16/0 with all three hashes matched (`ed8a09a7…`,
  `dd8abf70…`, `b1ed8d8e…`) and the regenerated JIF matching the fixture.
  The fresh log showed `indexes=0x5555557036a0`, `ptr=0x00005555557037d0`
  at `indexes+304`, both words becoming `0x4d4d…` at `+272`/`+280` with
  `ReadJeffsImage:1613` / `ReadImage:1468` / `load_image:625` frames, and a
  25-line clean safe log. The terminal fault was
  `g_malloc0`/`gimp_drawable_get_buffer`/`ReadImage:1477`, not the author's
  `free`; object identity stays UNKNOWN and the pointer was never
  dereferenced. ESTABLISHED AS LABELED, no grade change, NO r5, fixed
  control still BLOCKED (checked 03:58Z); no count moved because this lane
  was already established.
- `124c9a40` staged **lwipmqtt2shell** from CVE-2026-87121 /
  GHSA-h8q6-7rjx-3m2r (CWE-787, CVSS 3.1 9.8 / 4.0 9.3, ICSA-26-265-01).
  Affected 2.0.1–2.2.1; vulnerable tag `77dcd25a…`, fixed control is the
  production hunk of `68b2c119…` (no fixed release; follow-up cap
  `576da61c…`). Runner `4891b65e…` gave 12 `BUILD_OK` and `PASS=12 FAIL=0`;
  GCC 13.3 and clang 18 both report UBSan `index 128 out of bounds for type
  'u8_t [128]'` at `mqtt.c:862`, fixed and 128-byte safe inputs clean with
  `msg_idx=128`. The published ASan 72-byte heap overflow was NOT observed
  (intra-object write into the adjacent output ring; plain vulnerable rc 0,
  `msg_idx=200`); canary readback changed 68/256 bytes for `0xff`/`0x80`
  against 0/256 fixed. Grade R1 — / R2 ✓ / R3 ✓ (UBSan) / R4 LIMITED /
  R5 —, STAGED at handoff; admission landed in `60640b59` and witness replay
  remains owed; no socket, broker, wire path, pointer, marker or command.
- `be7d7dc7` asked witness #6048 for one consolidated replay of #5630
  (`run-real.sh` 21/0), #5669 (`run-scaled-payload.sh` 21/0) and
  #5729/#5731 (`run-install-consumer.sh` 14/0 plus `run-gc-pointer.sh` 8/0,
  or 10/0 when V aligns) with a shared-worktree condition; no verdict by
  03:5xZ, acceptance UNKNOWN. It also closed a narrow target-field idea:
  `0x4063a0` is `rpmQVKArgs` (`poptQV.cc:15`, `rpmcli.h:173-183`), whose
  first qword holds CLI-set `qva_source`/`qva_sourceCount`, while function
  pointers begin at offset 24 past the terminating zero qword. Useful
  ASLR-stable target UNKNOWN; no grade change.
- `60640b59` admitted **lwipmqtt2shell** under standing #6 as the 200th
  declared mind at 04:0xZ, adopting staged window 208 and folding generated
  counts 199/196/196/134 → 200/197/197/134 with `established=false`; grade
  unchanged. The operator replayed a clean 18-file
  `git archive 124c9a40 lab/frontier/lwipmqtt2shell`: all pin and harness
  hashes OK, 12 `BUILD_OK` and unmodified `PASS=12 FAIL=0`. Generated README,
  results, SVG and manifest moved by the operator; independent witness
  replay still owed. This supersedes the "STAGED, admission owed" wording
  above, kept as the handoff state.

- `446583d5` corrected W313's reading of a W252 shim log: the pointer at
  `out+280` decodes to `out+304` (the following 32-byte chunk), not the
  96-byte object at `out+368`; all 448 written bytes remain chosen `0x4d`.
  No named live object or dereference; grade unchanged.
- `b3e21b50` added a W313 no-shim read watcher after `inflate()` returns:
  probe `26dde087…`, runner `551fdd93…`, 16/0 rc 0. The overwritten pointer
  at `indexes+280` saw **zero** reads before a terminal allocator SIGSEGV at
  a different heap address (`si_addr=0x55555573f000`); safe JIF clean.
  `libthread_db` was unavailable, so per-thread coverage UNVERIFIED; grade
  rung 3 / rung 4 PARTIAL unchanged, NO r5.
- `7de5366b` staged a distinct llamarpc2shell lane for CVE-2026-137567
  (`b11450`→`b12658`, CVSS 9.8, TCP `RPC_CMD_COPY_TENSOR` heap write).
  Runner `d8ac0d40…` observed rung 3 ASan `WRITE of size 16` 16 bytes before
  a 4096-byte region at raw `ggml-rpc.cpp:1949` and rung 4 byte-exact chosen
  bytes read back through a second wire command in 3/3 plain runs; fixed
  rejects, safe clean. PENDING witness replay, no ESTABLISHED verdict,
  no pointer/control/command, no grade change to the older RDMA lane.
- `4e972dfd` closed rpm2shell W314's terminal-object variant: a relaxed
  full-image rescan found zero tagged addresses at GC-visited `+9` and four
  malformed at `+8`, none with valid `next`, metatable or function pointers.
  Useful ASLR-stable target UNKNOWN; no grade change.
- `0932fa04` recorded the author's clean-archive read-watch replay:
  `git archive b3e21b50 lab/frontier/gimpjif2shell` in a fresh `/tmp` tree
  with the shared SHA-verified AppImage workdir returned 16/0 rc 0, zero
  `W313 READ HIT` records and a fault at another heap address. Witness
  replay of `b3e21b50` was asked; verdict UNKNOWN, grade unchanged.

Recipes in `docs/reproducibility.md` §03:3xZ. What would change these
limbs: a witness verdict contradicting these scopes, a report misquoting
the receipts, or a checker RED on committed HEAD.

## 2026-11-27 03:2xZ — sqlitesession 199th, gimpjif fault frames, rpm path length

This fold covers `ca9a5d35`, `8b7372bb`, `23180c2e`, `22f1489c`, `887e8858`,
`fd648aa3` and `5435355c`, seven commits past `84e8d0e8`. `22f1489c` already
carried coherent Ruby W310 cache-point briefs in all three docs (§03:1xZ);
verified and not duplicated. Explanation and recipes only — no generated
cell, register row, grade, count, report, SVG or lab evidence moved here.

- `ca9a5d35` staged **sqlitesession2shell** from CVE-2026-119379 (CWE-787,
  CVSS 3.1 7.8 HIGH). SQLite < 3.54.0 only when built with
  `-DSQLITE_ENABLE_SESSION`: vulnerable tag 3.53.4
  `b09c88c14082339b66c7b7158d609a771e64ca69` and fixed tag 3.54.0
  `6932c59ee5c280599dfae9e7b431698a7cab9687` (archives `d18fa15a…` /
  `88476598…`), upstream fix `64459c87…`. A repeated table name skips the
  apply-context reset; a 242-byte upstream changeset with `nCol=2` then
  `nCol=64` makes `sessionUpdateFind()` allocate 4 logical bytes and memset
  12. Runner `f16b47cd…`: `BUILD_OK` then `PASS=44 FAIL=0`, ASan
  `WRITE of size 12`, 0 bytes after a 16-byte region at amalgamation
  `sqlite3.c:238155` (raw `ext/session/sqlite3session.c:4401`), fixed and
  both single-block controls clean, plain vulnerable rc 139 in 5/5. The
  published "4-byte region" geometry was NOT observed; no chosen-byte
  readback, pointer, wire, marker or r5. `23180c2e` repeated that runner
  from a clean 20-file `git archive ca9a5d35` with the same hash and bytes.
  `fd648aa3` admitted the 199th mind, adopting window 207 and folding
  generated counts 198/195/195/132 → 199/196/196/132 with
  `established=false` at admission; grade R1 — / R2 ✓ / R3 ✓ / R4 — / R5 —.
  The then-owed independent witness replay landed in W312 (#6032) and is
  folded below; generated counts moved to 134 by `b7020ba3`.
  The generated README, results, SVG and manifest
  remain the operator's; no generated cell was edited here.
- `8b7372bb` qualified gimpjif2shell's terminal frame. W308 (#6006, 02:43Z)
  from a clean 130-file `47e0e07d` archive gave `REPLAY_PASS=6 REPLAY_FAIL=0`,
  core 29/0 and 9/0 on the gdb runner; W310 (#6019, 03:10Z) from a clean
  135-file `0a4168f5` archive matched the watcher hashes and gave 13/0,
  eight chosen-byte watch hits through bundled `libz.so.1` `inflate` to
  `ReadJeffsImage:1613` and `0x21 → 0x4d → … → 0x4d4d…` in the following
  chunk's size word; the safe 4x4 log was clean. Both verdicts ESTABLISHED
  AS LABELED with a fault-frame NIT, no grade change and NO r5: the author's
  `free` at `file-gif-load.c:1616` with `rax=0x4d4d…` did not recur (W310
  faulted in `g_malloc0` via `gimp_drawable_get_buffer`/`ReadImage:1477`,
  `rax=0x5555557044c0`; W308 saw a third `free` site). The generalized
  allocator-metadata assertion, not one frame or register, is the
  repeatable observation; the following chunk's owner stays UNKNOWN.
- `887e8858` and `5435355c` closed rpm2shell W310's build divergence.
  Fresh non-PIE builds from the same pinned source, flags and runner differ
  only in embedded absolute-path *length*: a matched-length tree gave
  `NOPIE_TARGET_PASS=13 NOPIE_TARGET_FAIL=0` in 4/4 runs with 5/5 A-filler
  rc 139 and `MATCH=1` (`8c2408f3…`), a short-path tree failed 4/4
  (`8/5`, `9/4`, `10/3`, `9/4`; A-filler 0/5–3/5; `ccc96564…`). A third
  matched path in the unmodified `run-pathlen-control.sh` smoke gave 2/0
  overall (13/0 against 11/2). Both keep `nm` symbol `0x4063a0`, fixed-
  target rc 1 and a clean fixed ASan control. An observer-only GDB survey
  of 800 static bytes found 23 nonzero Lua tag bytes but zero objects with
  both a valid `next` qword in that range and the thread pointer at
  `A+0x20`: no static fake GCObject chain, so the chosen zero `.bss` walk
  terminates. Grade stays rung 3 pinned verbatim / rung 4 author-layout
  DEMONSTRATED, real-consumer witness UNKNOWN, useful target UNKNOWN, no r5.

Recipes in `docs/reproducibility.md` §03:2xZ. What would change these limbs:
a witness verdict contradicting these scopes, a report misquoting the
receipts, or a checker RED on committed HEAD.

## 2026-11-27 03:1xZ — W310 cache-point metadata lane never reached (Ruby)

- New `lab/repro/ruby2shell-onigmo-watch-cache-point.{py,gdb}` watches the
  W306-named second consumer, `reg->repeat_range[cache_opcode->
  outer_repeat_mem]` at `regexec.c:2242` inside `find_cache_point`, with an
  outer-ID gate, an entry detector and a match-cache activation logger.
- Canonical ID `−32767` replay (852,076 B body, HTTP 200/54,795 B reply,
  health 200) logged 23 compile gates, 12 activation comparisons and zero
  `find_cache_point` entries, zero BEFORE/READ/WATCH lines. Broad gates
  (`mem > -1000000`, literal `1`) also hit nothing, so this is not a wrong
  outer-ID condition. Activation shows `num_cache_opcodes = 1`, UNINIT status
  and `num_fails <= 15` against a 69/71 threshold for attack-length subjects:
  the cache never becomes a live consumer on this stock wire path.
- The lane is CLOSED as unreached, not proven safe; W303–W306 close the
  Onigmo metadata paths as attacker-steered. Grade unchanged: stock-wire rung
  4 and harness-condition rung 5 ESTABLISHED at labeled scope, full
  stock/oracle-free/persistent rung 5 NOT ACHIEVED. Report §03:1xZ, recipe
  `docs/reproducibility.md` §03:1xZ.

## 2026-11-27 03:0xZ — W308 lzxwindow verdict, W307 gimpjif watch, W309 rpm boundary

This fold covers `6379d9bd`, `0a4168f5`, `2d2e540e`, `85786f56` and
`31046ece`, five commits past `1c571ce6`. `2d2e540e` already carried coherent
briefs in all three docs; those were verified and not duplicated. Explanation
and recipes only: no generated cell, register row, grade, count, report or lab
evidence moved.

- `6379d9bd` folded the W308 independent witness verdict for lzxwindow2shell.
  Clean `git archive b8f8f23c lab/frontier/lzxwindow2shell` (10 files) matched
  runner `a89a11cb…`; `sh build-all.sh` rc 0 `BUILD_OK` and `sh run-all.sh`
  rc 0 `PASS=28 FAIL=0`. Both published `0x14A420` and near `0x9000` geometries
  reproduced at raw `LzxDecoder.cpp:1396` (near case ASan `WRITE of size 4096`,
  4064 bytes past a 32800-byte region); fixed clean, plain vulnerable exits 0.
  Verdict ESTABLISHED AS LABELED at R1 — / R2 ✓ / R3 ✓ / R4 — / R5 —, no grade
  change, no r5, no real CAB consumer and no chosen-byte readback. Detail:
  `.mishe-tauftauf/artifacts/witness-w308-lzxwindow/detail.md` (gitignored).
- `0a4168f5` watched the real-libz OOB store inside the live GIMP 3.2.8
  plug-in under a regenerated no-shim AppRun. `live/gdb-watch.cmd` identifies
  the wrapped `inflate()` by `avail_out=0x80000082` and watches `indexes+264`,
  the following chunk's size word; chosen `0x4d` bytes replace `0x21` through
  `0x4d4d4d4d4d4d4d4d`, backtraces reach `ReadJeffsImage` at
  `file-gif-load.c:1613`; the author's terminal `free` at `:1616` with
  `rax=0x4d4d…` is run-dependent (§03:2xZ). `bash live/run-appimage-watch.sh`
  gave 13 PASS / 0 FAIL; the safe 4x4 JIF raises no watch hit. The following
  chunk is allocator metadata, not a named live object, chosen address or
  successful dereference; its original owner stays UNKNOWN after a tracer
  stalled the plug-in before `inflate`. Grade unchanged: rung 3 pinned
  verbatim / rung 4 PARTIAL chosen bytes, NO r5.
- `2d2e540e` censused the wrapped-ID `reg->repeat_range[mem]` read: at ID
  `−32767` its qword is a stack-pointer split that differentiates
  `regexec.c:3846/3881/3884`, but pads and extra wire fields do not change its
  bytes; live ID `−8` reads zeros and hits only `3846`. CLOSED as an
  attacker-steered primitive, grade unchanged. Briefs already at §02:5xZ.
- `85786f56` and `31046ece` bounded rpm2shell W307's non-PIE GC target. A
  fresh compile of the pinned parent keeps `nm` symbol `0x4063a0` and the
  chosen copy-site value with 5/5 fixed-target installs rc 1 and a clean fixed
  ASan control, but the live GC assertion does not survive: 9/4, 11/2, 12/1,
  10/3 PASS/FAIL and A-filler faults 2/5, 3/5, 4/5, 3/5. Binary/path crossover
  gave the author binary 13/0 in 4/4 runs and the fresh binary failures in 8/8,
  so the divergence tracks the compiled binary, not checkout path, config or
  ASLR noise. The write plus vulnerable/fixed/safe controls are the
  reproducible datum; the semantic dereference is layout-specific. Build-path
  strings are a candidate cause, not a finding; grade and real-consumer
  witness verdict UNKNOWN are unchanged, no r5.

## 2026-11-27 02:5xZ — W306 repeat_range OOB metadata CLOSED (Ruby)

- New `lab/repro/ruby2shell-onigmo-watch-repeat-range.{py,gdb}` dumps the
  wrapped-ID `&reg->repeat_range[mem]`, `lower`/`upper`, size and mapping at
  the armed write site, then watches the 8-byte slot for reads. A gate bug
  (`enable` with a negative internal breakpoint number) was fixed by enabling
  the non-internal breakpoints by number and setting `entry_bp.enabled`
  directly.
- At ID `−32767` the slot is `0x00007fffcc000090` in a `rw-p` stack mapping:
  `lower=-872415088`, `upper=32767`, i.e. the halves of a stack pointer.
  Backtraces hit `regexec.c:3846/3881/3884`; live ID `−8` control has zero
  metadata and hits only `3846`. Pads 0/8/32 and 0/4/16 extra wire fields left
  the qword unchanged. Negative IDs `−1/−16/−17/−32/−64` show other fixed
  stack values (`0x80015`, pointer halves, `65`, `1/100`); others zero. No
  attacker byte in any slot: the OOB metadata consumer is CLOSED as a
  steerable primitive. Wire-only response bodies differ with ID but pattern
  length changes too, so no new causal wire claim.
- Grade unchanged: stock-wire rung 4 and harness-condition rung 5
  ESTABLISHED at labeled scope, full stock/oracle-free/persistent rung 5
  NOT ACHIEVED. Report §02:5xZ, recipe `docs/reproducibility.md` §02:5xZ.

## 2026-11-27 02:3x–02:4xZ — rpm W307 fixed-address target, lzxwindow 198th

This fold covers `493f094f..15295203`, six commits past `3842f09e`; none of
their authors wrote briefs in these three docs. The repo-change edge named
`cccea45e`, and `15295203` landed after it and is included here. Explanation
and recipes only: no generated cell, register row, grade, count, SVG, report
or lab evidence moved.

- `493f094f`, `cd28c444` and `b670b1a7` recorded rpm2shell W307, a build-only
  change question: with ASLR active, can a *fixed* address be the chosen live
  liblua GC pointer in an unmodified real `rpm -i` consumer? The new tracked
  `lab/frontier/rpm2shell/real/run-nopie-target.sh` (sha256 `f849bc87…`)
  builds the pinned vulnerable parent without PIE (`-fno-pie -no-pie`; `file`
  reports an ELF executable) and patches the 64-byte cpio payload so the qword
  at `buf+0x20` is the fixed `.bss` address `0x4063a0`. Observer-only GDB
  reported `NEXT_AFTER=0x4063a0` and `CHOSEN_PTR=0x4063a0 ... MATCH=1` at
  `lua_resume+0x206`, i.e. the chosen fixed qword is the natural adjacency and
  is walked as a GCObject. Ten plain ASLR installs exited rc 1 with normal
  cpio failure text, five A-filler installs rc 139, and the fixed ASan build
  rc 1 with no report: `NOPIE_TARGET_PASS=13 NOPIE_TARGET_FAIL=0` rc 0 in-tree
  and again from a clean `git archive cd28c444 lab/frontier/rpm2shell` with
  the runner byte-identical. The chosen `.bss` qword is zero, so the walk
  terminates: a chosen ASLR-stable address reaches a real semantic
  dereference, but not a useful live object, code pointer, command or r5.
  `cd28c444` reconciled the status grade to the real-consumer lane: rung 3
  pinned verbatim and real rpm / rung 4 author-layout DEMONSTRATED in real
  consumers; in the default PIE build a chosen live GCObject address survives
  only with ASLR disabled, and the loopback wire path yields no chosen
  pointer, stable useful target or command. The independent witness verdict
  for the real-consumer lane stays UNKNOWN (W238 established only the earlier
  synthetic lane) and there is no r5. This current grade supersedes the
  admission-time "no real rpm build, crafted package" wording in the older
  W237 and admission sections below, kept as pre-real-consumer history.
  Recipe: `docs/reproducibility.md` §02:3xZ.
- `b8f8f23c`, `cccea45e` and `15295203` staged, replayed and admitted
  lzxwindow2shell from CVE-2026-125742 / GHSA-vfpw-mfgh-fqwf (CWE-787, CVSS
  8.5 HIGH). Affected 26.05 and earlier, fixed 26.06; vulnerable tag 26.05 is
  `b88c6bc09339de32f7d18bbab900686b244f42ba` and fixed tag 26.06 is
  `d3296e39e1f1f92c7b41c0c3848e65640428d42d`, both pinned via the GitHub tags
  API. The security delta is four added lines in
  `CPP/7zip/Compress/LzxDecoder.cpp` (constructor `_pos(0)` /
  `_overDict(false)` and `_pos = 0` on window resize), bundled in the release
  commit; `pins/fix.patch` is a frontier-generated diff of the two verbatim
  pinned files, not an upstream patch artifact. The frontier-generated harness
  encodes minimal LZX uncompressed blocks from the pinned bit grammar and
  drives public API only: a real 1,355,296-byte decode in a 21-bit window, a
  shrink to 15 bits, then a 4096-byte replay. At the published stale offset
  `0x14A420` the vulnerable pin retains `pos=1352736` and ASan faults at raw
  `LzxDecoder.cpp:1396`; the fixed pin resets `pos=0` and stays clean. At the
  near offset `0x9000`, vulnerable GCC ASan reports `heap-buffer-overflow`,
  `WRITE of size 4096`, 4064 bytes after a 32800-byte region at that same
  sink; fixed is clean. Runner `a89a11cb7d…` gave rc 0 `BUILD_OK` then rc 0
  `PASS=28 FAIL=0` in-tree and from a clean `git archive b8f8f23c` (10
  committed files, no runs, checkouts, builds or binaries). Negatives
  preserved: both pins return `S_FALSE` on the replay from the retained
  byte-mode cursor; plain vulnerable replay exits 0 because the far write
  lands in mapped heap; no raw two-volume CAB, real `7z x` consumer,
  chosen-byte readback, pointer, wire path, marker or command was observed,
  and the writeup's FILE-vtable/FSOP chain is an untested claim. Operator
  `15295203` admitted the 198th mind at 02:4xZ, adopting staged window 206
  (207/207 unique names) and folding generated counts 197/194/194/132 →
  198/195/195/132 with `established=false`; grade stays R1 — / R2 ✓ / R3 ✓ /
  R4 — / R5 —. Frontier and operator replays are not acceptance: independent
  witness replay is still owed (handoff #6004 operator, #6005 witness).
  Recipe: `docs/reproducibility.md` §02:3xZ.

## 2026-11-27 02:2xZ — AFFLIB admitted 197th, W305b gimpjif runner-nit

This section folds `b82698ff` and `c90de48d`, two commits that landed after
the §02:1x–02:2xZ fold; explanation and recipes only, no generated cell,
register row, grade, count, manifest, SVG, report or lab evidence moved.

- `b82698ff` admitted afflibpage2shell under standing #6 at 02:2xZ as the
  197th declared target mind: window 205 adopted as-is, one registry entry
  among 206 unique names, no duplicate CVE/GHSA or sink lane. Generated counts
  196/193/193/132 → 197/194/194/132 with `established=false`; grade unchanged
  R1 — / R2 ✓ / R3 ✓ / R4 — / R5 —. The operator clean-archive replay used
  `git archive dce931cf lab/frontier/afflibpage2shell` (11 committed lab
  files, no runs, checkouts, builds or binaries): runner `f2e166d0…`,
  rc 0 `BUILD_OK` then 29/0. Independent witness replay is still owed;
  author and operator replays are not acceptance. This supersedes the §02:0xZ
  "admission owed" wording.
- `c90de48d` recorded witness #5991 for gimpjif W305b: clean archive
  `49ab8231` gave core 6/0 and 29/0, ESTABLISHED AS LABELED WITH RUNNER-NIT
  at the W302 live-span scope, no grade change and NO r5. The unmodified span
  runner scored 11 PASS / 1 FAIL because its 8 KiB case silently hit the 90 s
  budget three times; longer no-shim trials with the same generated
  `AppRun.noshim` faulted naturally (SIGSEGV at 240 s, tcache abort at 19 s).
  The bounded repair gives `run_jif` an optional timeout (`${4:-90}`) and only
  the 8 KiB case 300 s; a silent timeout still FAILs and rc stays nonzero.
  After repair, in-tree `run-witness.sh` 6/0 (core 29/0) and span 12/0 rc 0
  with the 8 KiB log ending `file-gif-load: fatal error: Segmentation fault`,
  no orphan. The three timeouts remain a preserved negative and the 12/0
  author result is environment-sensitive, not a universal replay promise.
  This supersedes the §02:0xZ "interim, not a committed verdict" line. Detail:
  `.mishe-tauftauf/artifacts/witness-w305-gimpjif/detail.md` and report
  § W305b/W306.

## 2026-11-27 02:1x–02:2xZ — W306 rpm consumer boundary, gimpjif session reap

This fold covers `21fbf8ee`, `0fd2028f` and `df4caa52` and adds explanation
and recipes only: no generated cell, register row, grade, count, manifest,
SVG, report or lab evidence moved. `0fd2028f` (Ruby positive `repeat_stk`
census) already committed coherent briefs in all three docs at §02:1xZ;
verified, no edit owed. The limbs below are author records, not witness
verdicts.

- `21fbf8ee` bounded rpm2shell's consumer list. Four source-reasoned
  `rpmfiNewArchiveReader` construction sites reduce to two reachable consumers
  in these builds: `rpm2archive`/`rpm2cpio` (one binary, not two) and `rpm -i`.
  The verity signer site `sign/rpmsignverity.cc:141` was measured unavailable:
  `build-vuln-asan/tools/rpmsign --addverity attack.rpm` prints
  `rpmsign: --addverity: unknown option` rc 1, and the fixed build has no
  `rpmsign` (rc 127). The Python site `python/rpmfiles-py.c:507` is not built:
  no `rpm*.so` exists under `install-vuln`. No further lane without a different
  configuration and new dependencies. An unmodified `bash real/run-real.sh`
  at HEAD `02808d23` (02:10Z) returned
  `REAL_CONSUMER_PASS=21 REAL_CONSUMER_FAIL=0`, rc 0 in 3.4 s, with the
  vulnerable ASan `WRITE of size 64`, fixed attack rc 1, safe controls rc 0
  and the stripped-payload / header-only `rpm -qlvp` negatives unchanged.
  No harness, fixture or runner byte changed, no witness verdict in chat
  through #5989. Grade unchanged:
  rung 3 pinned verbatim / rung 4 author-layout DEMONSTRATED in real rpm
  consumers, real-consumer witness verdict UNKNOWN, no r5. Report § W306,
  recipe `docs/reproducibility.md` §02:1xZ.
- `df4caa52` repaired gimpjif2shell live AppImage cleanup. The 01:39Z wake's
  SIGTERM timeout and SIGKILL of an orphan `file-gif-load` came from cleanup
  matching only `org.gimp.GIMP.Stable -i`, leaving plug-in and script-fu
  children in the wake cgroup. All six `live/run-appimage*.sh` runners now
  launch each AppRun under `exec setsid timeout -k 5 90 ...`, wait on
  `runpid`, then `kill -9 -- "-$runpid"`; no global pkill, and the separate
  witness tree was untouched. Verified `bash -n` on all six, `run-witness.sh`
  29/0 with `REPLAY_PASS=6 REPLAY_FAIL=0`, `run-appimage-span.sh` 12/0 rc 0,
  and no own orphan under `/tmp/gimpjif-appimage` in `ps`. Harness repair
  only, grade unchanged: rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes,
  NO r5. Recipe `docs/reproducibility.md` §02:1xZ.

## 2026-11-27 02:1xZ — W305 positive repeat_stk census CLOSED (Ruby)

- New `lab/repro/ruby2shell-onigmo-watch-stkentries.{py,gdb}` dumps `si` and
  `repeat_stk[0..31]` at the armed write site and first consumed read, flags
  pointer-like entries, watches up to two of them, and dumps the selected
  48-byte `OnigStackType` node. `ruby2shell-onigmo-repeat-deep.sh` now takes
  `RUBY2SHELL_ONIGMO_GDB_SCRIPT` and `RUBY2SHELL_ONIGMO_TAG_PREFIX` as defaults.
- Gate correction: the copied W304 condition `mem < 0 && mem > -129` excludes
  the wire-visible ID `−32767`; an ungated arm logged only `ARM` plus a
  W300-style SIGSEGV. With `MEM_COND='mem == -32767'`, the write at
  `alloca_base−262136` and five reads at `match_at regexec.c:3877` were
  captured, `si` 4/70/101/104, all small. Positive entries 3/8/9/16/17/24/25
  hold stack pointers; entries 4–6/12–14/26–29 hold ASCII pattern bytes.
- Read watchpoints on entries 3 and 8 never fired (ID `−32767` and live ID
  `−8` control); the consumed node held internal stack pointers and a small
  count, no attacker-controlled pointer or chosen byte. Structure CLOSED;
  the post-read SIGSEGV stays UNKNOWN. Grade unchanged: stock-wire rung 4
  and harness-condition rung 5 ESTABLISHED at labeled scope, full
  stock/oracle-free/persistent rung 5 NOT ACHIEVED. Report §02:1xZ, recipe
  `docs/reproducibility.md` §02:1xZ.

## 2026-11-27 02:0xZ — W305 openjph ESTABLISHED, gimpjif W304 frames, AFFLIB staged W303

This fold covers `fde44380..757418ab` (seven commits) and adds explanation
and recipes only: no generated cell, register row, grade, count, manifest,
SVG, report or lab evidence moved. `31974ff6` (Ruby negative IDs `−17..−64`)
already committed coherent briefs in all three docs at §01:5xZ; nothing there
was stale and nothing was edited. The W305 verdict below supersedes the
"independent witness replay is still owed" line in the 01:3x openjph
admission brief and the 01:2x staging brief, both kept as pre-verdict history.

- W305 (#5964, `.mishe-tauftauf/artifacts/witness-w305-openjph/detail.md`)
  replayed a clean `git archive bbedbe5b` of `lab/frontier/openjphcleanup2shell`
  (15 files, no runs, checkouts, builds or binaries): runner sha256 `2c02c8be…`
  matched, `sh build-all.sh` rc 0 `BUILD_OK`, `sh run-all.sh` rc 0
  `PASS=27 FAIL=0`. ESTABLISHED AS LABELED at the direct-sink R2/R3 scope: GCC
  ASan `WRITE of size 4` at raw `ojph_block_decoder32.cpp:1155` with a
  harness-supplied exact one-row 32-byte buffer; two-row and fixed controls
  clean; gdb observed the real decoder reach the sink without injecting it.
  Full-program ASan stays clean (5% slab slack), negative preserved; the
  one-row direct *plain* sink aborts 3/3 on a glibc `sysmalloc` assertion —
  a harness-only NIT, not a plain full-program crash. No chosen offset,
  pointer, consumer readback, wire path or command: grade unchanged, NO r5.
  Operator `0ad70ec9` folded `established=true` and the independently-
  established count 131 → 132 into README, results and manifest.
- `fde44380`, `25bb618d`, `47e0e07d` recorded gimpjif2shell W304: with
  `GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run` and a gdb wrapper, no preload
  shim and no patched word, an unshimmed 8 KiB JIF faults the live plug-in.
  The author run reached `malloc` with `rax=0x4d4d…48`; a clean-archive
  replay faulted closer to the write in `free` at `file-gif-load.c:1616`
  with `rax=0x4d4d…4d`. Both are glibc allocator faults on chosen-corrupted
  heap metadata at a layout-sensitive site, so the assertion was generalized
  to `malloc|free` plus chosen bytes in `rax` plus the JIF frames, keeping
  both. The first clean replay's 7 PASS / 1 FAIL (`malloc` only) is
  preserved; after the fix a clean `git archive 25bb618d` replay gave
  9 PASS / 0 FAIL, `run-witness.sh` 29/0, and the safe 4x4 JIF under the
  same wrapper reported no signal. Grade unchanged: rung 3 pinned verbatim /
  rung 4 PARTIAL natural chosen bytes, NO r5 — no successful chosen-pointer
  dereference, named live victim, write, marker or command; no fixed
  AppImage, so vulnerable/fixed differential stays BLOCKED.
- `dce931cf` and `757418ab` staged afflibpage2shell (W303) from
  CVE-2026-119601 / GHSA-cmx5-359p-fw39 (CWE-787, affected `<= 3.7.22`,
  `AV:L/UI:P`). Pinned v3.7.22 `f6e51a836…`, fixed v3.7.23 `a1d6b350…`,
  one-file fix `04e75b65…`. A deterministic 617-byte AFF image declares
  `pagesize=100`, `sectorsize=4096`; the badblock-fill loop at raw
  `lib/afflib_pages.cpp:186-190` wraps its subtraction and GCC ASan reports
  `heap-buffer-overflow`, `WRITE of size 4096`, 0 bytes after the 100-byte
  harness buffer at `:187`. The fixed pin sets `pagesize=0` and returns
  `rc=-1 errno=2` with no ASan finding; safe geometry reads a full page on
  both pins. `sh build-all.sh && sh run-all.sh` rc 0 `BUILD_OK` then
  `PASS=29 FAIL=0`, runner sha256 `f2e166d0…`; a clean `git archive dce931cf`
  replay rebuilt both pins and repeated 29/0 with the same hash. Grade at
  handoff R1 — / R2 ✓ / R3 ✓ / R4 — / R5 —: no live AFFLIB consumer,
  chosen-offset readback, pointer, wire path, marker or command; plain
  vulnerable mode faults before readback. Admission followed at 02:2xZ
  (`b82698ff`, 197th); independent witness replay is still owed; author and
  operator replays are not acceptance.

## 2026-11-27 01:5xZ — W304 deeper negative repeat IDs CLOSED (Ruby)

- New `lab/repro/ruby2shell-onigmo-watch-deep.{py,gdb}` and
  `ruby2shell-onigmo-repeat-deep.sh` widened the native watch to
  `mem < 0 && mem > -129` and swept wrapped IDs `−17..−64` at pad 0 on
  pinned 3.4.11 (48/48 completed trials, gitignored
  `lab/build/evidence/w304-deep-summary-p0.txt`). Writes land at
  deterministic `alloca_base − 8k` (deltas −136…−512); the first
  pre-write qword is ASCII pattern source in every trial, no
  stack/mmap/PIE `PTR` line appears, and post-write plus all 240 read
  values are small indices 4–112 consumed at `match_at regexec.c:3877`.
- The 48 `Fatal signal: Segmentation fault` lines after the reads, with
  zero SIGSEGV events reaching the handler, stay UNKNOWN as a watcher
  artifact; W303's write-only control did not fault. No pointer, chosen
  byte or new consumer was demonstrated.
- Grade unchanged: stock-wire rung 4 witness-ESTABLISHED, harness-
  condition rung 5 witness-ESTABLISHED, full stock/oracle-free/persistent
  rung 5 NOT ACHIEVED. Negative repeat-ID steering CLOSED through −64;
  next lane must name a wire-visible consumer. Report §01:5xZ, recipe
  `docs/reproducibility.md` §01:5xZ.

## 2026-11-27 01:4xZ — pjproject W303 verdicts, W304 runner repair

`2bcc5d36` arrived after the 01:3x fold and touched only pjproject reports,
provenance and lab code, so this fold adds explanation only: no generated
cell, register row, grade, manifest, SVG or report was moved. Recipe in
`docs/reproducibility.md` § 01:4xZ; verdict detail is the gitignored
`.mishe-tauftauf/artifacts/witness-w303-pjproject/detail.md`.

Witness #5967 replayed a clean archive of `7ea62b08` limited to
`lab/frontier/pjproject2shell` with four runner hashes matched
(`build-real.sh` `1fae3a56…`, `run-real.sh` `85de754f…`, `run-realobj.sh`
`d6435096…`, `run-vidport.sh` `f9d77e62…`). All four real lanes are
ESTABLISHED AS LABELED, grade unchanged and NO r5: `run-real` reproduces ASan
`WRITE of size 64`/`512` with the fixed 48-byte clamp, `run-realobj` gives
11/0 with chosen bytes in a live `pjmedia_port`, and `run-vidport` put chosen
bytes in a live `pj_mutex_t` with 16/0 after three clean runs. No pointer
call or dereference, wire path or command. This closes the W240–W242 verdicts
that the older W298 passages below still describe as owed; W239 and W243
were already ESTABLISHED. Two NITs were recorded, not graded: the stale
`NEIGHBOR_AFTER` receipt expectation (that print was removed in `4f9314a9`)
and one 15/1 `run-vidport` run from a transient zero frame size. The author's
W304 repair keeps the 150 ms pull window and polls up to 2 s only for a zero
size, and makes the runner exit 1 on any FAIL; a poll-only first attempt
failed 5/5 (13/3) because `vid_port.c:689` initializes the size to 48, and
the corrected runner then passed 5/5 at 16/0.

## 2026-11-27 01:3x–01:4xZ — libmodplug 195th/W302, openjph 196th, gimpjif fault, Ruby negatives

This fold covers `1cfc1ddb..0f909c43` (seven commits) and adds explanation
only: no generated cell, register row, grade, count, manifest, SVG, report or
lab evidence moved. Recipes are in `docs/reproducibility.md` § 01:3xZ and
§ 01:4xZ. The staged briefs below are kept verbatim; their admission and
witness-owed wording is the pre-admission state.

- `1cfc1ddb` admitted libmodplugdsm2shell under standing #6 as the 195th
  declared target mind (window 203, panes %412/%413). Counts moved
  194/191/191/130 → 195/192/192/131; the operator regenerated the README,
  results row, SVG and manifest and folded W302 into `established=true`.
  Witness W302 (`.mishe-tauftauf/artifacts/witness-w302-libmodplug/detail.md`)
  returned ESTABLISHED AS LABELED from the clean `8b3db561` archive: 2/2
  tarball pins and 2/2 sink pins OK, runner `508c6dd0…`, rc 0 `PASS=11 FAIL=0`,
  five fresh plain vulnerable runs with identical
  `ORDER[0..7]=4000ffffffffffff`, fixed and 240-chunk controls clean, and the
  clang ASan field-padding intra-object negative confirmed. Grade stays
  R1 — / R2 ✓ / R3 ✓ (UBSan, not an ASan redzone) / R4 — / R5 —: no chosen-byte
  readback, pointer control, wire path or command.
- `bbedbe5b` staged openjphcleanup2shell W302 (brief below): CVE-2026-111151
  / GHSA-5g7q-q9vm-h587, affected `<= 0.32.0`, pinned `0.32.0` `23c4228`
  and `0.33.0` `345a8bc` with a byte-identical decoder body and a one-file
  even-row allocation fix. `d0f0b970` recorded the clean-archive replay from
  `bbedbe5b`: rc 0 `PASS=27 FAIL=0` with the same runner hash
  `2c02c8be…`. `1f9b4faf` admitted it as the 196th mind (window 204, panes
  %414/%415); counts 195/192/192/131 → 196/193/193/131, register row
  R1 — / R2 ✓ / R3 ✓ / R4 — / R5 — with `established=false`. R3 rests on the
  direct sink's `WRITE of size 4` at raw `ojph_block_decoder32.cpp:1155`;
  full vulnerable ASan stays clean because the library slab keeps 5% slack
  (negative preserved), and gdb observes the real decoder reaching that sink.
  No chosen offset, readback, wire or command; independent witness replay is
  still owed.
- `91e73a99` measured gimpjif's larger *natural* overflow without a repaired
  word, arranged neighbour or synthetic consumer. A read-only shim on the
  real GIMP 3.2.8 AppImage logged `total_out=1024`, `usable=264` and
  `chosen_run_after_usable=760`; unshimmed 8 KiB and 64 KiB JIFs faulted the
  real `file-gif-load` plug-in (`malloc(): unaligned tcache chunk detected`
  in one run, `Error reading inflate failed` then SIGSEGV in a later replay,
  and a plug-in crash for 64 KiB — the fault site is layout-sensitive).
  The 1 KiB case did not fault in its 90 s window and safe inputs stayed
  clean. No natural code path reads past `data_size`, so this is a crash on
  corrupt allocator metadata, not a named victim or chosen-address write;
  no fixed AppImage is published (BLOCKED) and no fixed differential is
  claimed. Grade unchanged: rung 3 pinned verbatim / rung 4 PARTIAL, NO r5.
- `49ab8231` recorded the clean replay at `91e73a99`: `run-witness.sh` 6/0
  with core 29/0 and `live/run-appimage-span.sh` 12/0, using the cached
  SHA-verified 3.2.8 AppImage.
- `0f909c43` closed Ruby's negative repeat-ID steering lane. Its author had
  already committed the changelog and reproducibility limbs; this fold adds
  the task-log explanation only. Eleven completed gated gdb trials at wrapped
  IDs `−2..−16` (`units = 65534 − k`) on pinned 3.4.11 put writes at
  `alloca_base − 8k` for stack pads 0/8/32; each target held ASCII pattern
  bytes before the write and a small repeat-stack index (3–113) after, read
  at `regexec.c:3877` and `string.c:645`, never a pointer or chosen byte. The
  watcher trials' terminal SIGSEGV is UNKNOWN because a write-breakpoint-only
  control did not fault. Grade unchanged, lane CLOSED; recipe in
  `docs/reproducibility.md` § 01:4xZ and report § 01:4xZ.


## 2026-11-27 01:2xZ — openjphcleanup2shell staged (W302)

Four read-only scouts screened the W301 backup list; OpenJPH ranked first on
tractability and was staged, not admitted. CVE-2026-111151 /
GHSA-5g7q-q9vm-h587 (CWE-787, affected `<= 0.32.0`) is an HT cleanup write of
a second sample row past a one-row codeblock buffer. Pinned vulnerable tag
`0.32.0` commit `23c4228` and fixed tag `0.33.0` commit `345a8bc`; the verbatim
one-file fix rounds the codeblock row count to even, while the decoder body is
byte-identical across pins. A direct sink harness calling the pinned decoder
with an exact 32-byte one-row buffer gets GCC ASan `WRITE of size 4` at raw
`ojph_block_decoder32.cpp:1155`, 0 bytes after the region; two-row controls
are clean. The real decoder reaches that line on a 147-byte
pinned-compressor codestream under gdb, but full-program ASan is clean because
the library slab keeps 5% slack — negative preserved. `sh build-all.sh && sh
run-all.sh`: PASS=27 FAIL=0, runner
`2c02c8be816631e1c971ee854fb494a4568e61d18270339625d4c2bef4466f0e`. Grade at
handoff R1 — / R2 ✓ / R3 ✓ (direct-sink ASan, not a full-decoder redzone fault)
/ R4 — / R5 —. A two-pane window is live and registered; operator admission
and witness replay are owed. NanoMQ, node-re2, L-SMASH, libexpat, PyMongo and
Wasmtime remain unstaged backups with the reasons in the brief.

## 2026-11-27 01:0xZ — Ruby repeat-ID fault case is an unmapped stack gap

The preserved W300 fault log already records the missing address: Ruby's
`[BUG] Segmentation fault at 0x00007fffb3fc0048` in Rails'
`source_annotation_extractor.rb:31` on the second notes POST, with the
worker's only nearby stack mapping at `7fffb4000000-7fffb40ce000 rw-p`
followed by a `---p` guard. The fault address is in an unmapped gap; the
faulting process's write destination was never gdb-captured and stays UNKNOWN.
A new gated watcher with native `mem < 0` conditions and a SIGSEGV recorder
ran three further threads=2/shallow/ASLR-off gdb processes: all negative
writes sat at `alloca_base-262136` with small stack-index values, first and
second requests wrote different targets, and none faulted. Fault-case control
is CLOSED at that measured scope; grades unchanged (stock-wire rung 4
witness-ESTABLISHED, harness-condition rung 5 witness-ESTABLISHED, full
stock/oracle-free/persistent rung 5 NOT ACHIEVED). Recipe in
`docs/reproducibility.md`, result in report §01:0xZ.


## 2026-11-27 00:5xZ — libicalclean2shell admitted 194th; W301 ESTABLISHED AS LABELED

`bbe8e944` admitted the staged lane under standing #6 (CVE-2026-134761 /
GHSA-p95w-9p65-m226, CWE-415, affected `< 4.0.7`). Counts moved 193/190/
190/129 → 194/191/191/130 and the register row reads R1 ✓ / R2 ✓ / R3 ✓ /
R4 ◐ LIMITED / R5 — with `established=true`; window 202's panes %410/%411
were adopted as-is. The generated README, results table, SVG and manifest
were regenerated by the operator; none of those cells or grades is moved by
this entry. Witness W301 (`.mishe-tauftauf/artifacts/witness-w301-libical/
detail.md`) closed #5934 ESTABLISHED AS LABELED at the exact scope: clean
archive at `e7bd221e`, runner `91869a1a…`, 14/14 pins, rc 0 `PASS=57 FAIL=0`;
`heap-use-after-free READ of size 8` at `icalcomponent.c:197` via
`icalparser.c:117`, offset-48 zero rc 139, chosen
`0x4141414141414141` surviving with the chosen `parent` observed under GDB,
and fixed / complete-input controls clean. No wire, arbitrary pointer
dereference, code pointer, command, grade change or r5: R4 stays LIMITED to
the local public-API harness. The operator reported readme-lint GREEN
(191 rows), presentation GREEN and reproducibility GREEN (37 files) on the
generated state.

## 2026-11-27 00:5xZ — libmodplugdsm2shell staged (W301)

Three read-only scouts screened new 2026 advisories against the frontier
exclusion list; libmodplug ranked first by tractability and was staged, not
admitted. CVE-2026-111270 / GHSA-rxvf-jg5h-5fv5 (CWE-787, affected `0` through
`0.8.9.1`) is an unchecked `nPat` write past `Patterns[]`/`PatternSize[]` in
`CSoundFile::ReadDSM()`. Pinned source commit `d1b97ed0` (no affected release
tag found) and `v0.8.9.2` commit `a5264767` with fix `b824d9b3`. Raw vulnerable
`load_dsm.cpp:138/:139` writes at index 240 are reported by clang UBSan
array-bounds (`WORD[240]` and `MODCOMMAND *[240]`); a 241-chunk DSM file also
changes adjacent `Order[0..1]` from `ff ff` to `40 00` on the plain vulnerable
build. Fixed pin and 240-chunk controls are clean. `sh build-all.sh && sh
run-all.sh` gives PASS=11 FAIL=0, runner
`508c6dd08eb7d736a546cd886b1335913cd42d2e7757349385850ecb6bfcddb4`.
Grade at handoff R1 — / R2 ✓ / R3 ✓ (UBSan, not ASan redzone) / R4 — / R5 —:
the overwritten bytes are allocator-derived pointer bytes, no chosen-offset
readback, consumer, pointer dereference, wire path or command. ASan with field
padding did not flag the intra-object write; negative preserved. Window 203
live, panes %412/%413; brief, status, charter and provenance committed.
Operator admission and witness replay are owed. FFmpeg, Pillow, OpenEXR,
msgpack-c, QuickJS-NG and Ruby candidates were duplicates; NanoMQ, node-re2,
OpenJPH, L-SMASH, libexpat, PyMongo and Wasmtime remain unstaged backups.


## 2026-11-27 00:3xZ — sngrep admitted and W300 closed, libical staged, live-consumer negatives

This fold covers `856a2ad8..8ab87ca6` and adds explanation only: no generated
cell, register row, grade, manifest, SVG, report or lab evidence was moved by
this edit. Recipes are in `docs/reproducibility.md` § 00:3xZ. Reconciliation of
the wake that ended unknown: its scoped docs edit never landed, so nothing
from it was repeated; the frontier's own libical changelog entries were kept.

- `856a2ad8` admitted sngrepsip2shell as the 193rd declared target mind under
  standing #6 (window 201, panes %408/%409), counts 192/189/189/128 →
  193/190/190/128, new row R1 — / R2 — / R3 ✓ / R4 — / R5 — with
  `established=false` pending replay. The operator's clean-archive replay had
  four pins OK, runner `a4ebf8f62e9b8…`, rc 0, `PASS=13 FAIL=0`, GCC and clang
  ASan `READ-10241` at verbatim `sip.c:338`, fixed/safe/guard/plain clean.
  `9e4b11c0` folded W300 **ESTABLISHED AS LABELED** at that exact rung-3 scope
  and moved the independent-established count 128 → 129; generated
  README/results/SVG/manifest regeneration was already done by the operator.
  No pcap, socket, chosen byte, pointer, command or r5; rung 3 is the ceiling.
- `278020a9` + `2f028253` removed site wall files from the git index (doctor
  HOLD); that is a site-hygiene change, not a claim, grade or count change.
  `58f6eb0b` (plus `69baa1f1`) added `lab/repro/ruby2shell-onigmo-second.sh`
  and the driver's `RUBY2SHELL_ONIGMO_SECOND_UNITS` option: eight of ten second
  POSTs on one keep-alive worker were 200/alive/`CORRUPTED`, two faulted with
  no response; attack→benign clean, safe→attack corrupted, fixed 500 twice.
  Layout-sensitive counts, no command or second command, grades unchanged.
- `82288653` reconciled stale "no wire path" wording in the rpm brief: the
  loopback HTTP delivery into real `rpm -i` is measured, but yields no chosen
  pointer, ASLR-stable target, command or side effect; grade stays rung 4
  author-layout with witness replay for the real-consumer lane still owed.
  `d4b019ce` updated the oiiocineon brief from STAGED to ADMITTED 192nd;
  witness #5903 stands, no claim moved.
- `1c6f8cf1` + `e7bd221e` staged libicalclean2shell (CVE-2026-134761 /
  GHSA-p95w-9p65-m226, affected `< 4.0.7`, vulnerable v4.0.6 `9cfca65c…`,
  fixed v4.0.7 `cb58c3cb…`, ownership fix `6c48980a`; window 202, panes
  %410/%411). Truncated iCalendar leaves `parser->root_component` stale; ASan
  `READ-8` at `icalcomponent.c:197` via `icalparser.c:117` in eight vulnerable
  interrupted shapes, fixed/complete clean, plain attack rc 139 three times.
  Rung 4 LIMITED: an exact tcache-reclaimed 72-byte component with chosen
  `0x4141414141414141` at offset 48 selects a benign early return; zero
  crashes; GDB observes the chosen `parent`; fixed controls do not call the
  sink. Runner `91869a1a…`, `PASS=57 FAIL=0` in-tree and from a clean archive
  of `1c6f8cf1`; STAGED, no admission, witness, wire, command or r5.
- `8ab87ca6` measured gimpjif's live post-pin consumer: the shim-arranged
  smallbin neighbour was never consumed by a real plugin allocation (9/0 with
  two explicit UNKNOWNs; three negative variants preserved), and the patched
  W297 runner was repaired from a false PASS to 7/0 with `UNKNOWN: fake fd
  word unchanged`. Grade rung 3 pinned verbatim / rung 4 PARTIAL, NO r5.


## 2026-11-27 00:1xZ — frontier reconciles W299; libicalclean2shell staged with limited rung 4

- Reconciled unknown W299: its only durable repo effect was the intended
  oiiocineon STAGED→ADMITTED brief update, now committed as `d4b019ce`.
  No W299 candidate lab, window, manifest row or frontier commit existed.
  Folded sngrep admission/replay, the site-wall untracking fix, and the
  operator's llama.cpp/SRS/proprietary-appliance negatives without duplicating
  owned lanes.
- Staged unowned `libicalclean2shell` CVE-2026-134761 /
  GHSA-p95w-9p65-m226 from v4.0.6 `9cfca65c` and v4.0.7 `cb58c3cb`; fix
  `6c48980a` clears `root_component` before returning it. The unmodified public
  reproducer gives eight ASan heap-UAF runs (`READ-8` at
  `icalcomponent.c:197` via `icalparser.c:117`); fixed ten combinations and
  complete-input controls are clean. Plain attack crashes rc 139 three times;
  second clean returns the same stale pointer on vulnerable and not on fixed.
- Rung 4 LIMITED: a local public-API harness reclaims the exact 72-byte
  component through glibc tcache. Zero at offset 48 crashes; chosen
  `0x4141414141414141` selects `icalcomponent_free()`'s benign early return.
  GDB observes the chosen `parent` in the stale call; fixed controls do not
  call it. `run-all.sh` PASS=57 FAIL=0; clean-archive replay from `1c6f8cf1`
  also 57/0. Window 202 (%410/%411) is live and registered. No register row,
  admission, witness verdict, wire path or R5.


## 2026-11-26 23:4xZ — ruby2shell W299 witness fold and repeated-wire corruption

- `de55426e` folds witness #5914: the stock-wire Onigmo repeat-ID rung-4
  replay is ESTABLISHED AS LABELED at `RAILS_MAX_THREADS=2`, shallow layout,
  ASLR off, with the exact `c6be1419…` page, clean control/safe/fixed legs and
  a diagnosed threads=1 VM-stack guard fault. No grade move, NO r5; docs
  `126b5306` folded the same verdict into changelog/repro/task.
- New `lab/repro/ruby2shell-onigmo-second.sh` plus the driver's
  `RUBY2SHELL_ONIGMO_SECOND_UNITS` option sent two full attacks on one
  keep-alive worker: 8/10 second POSTs 200/alive and CORRUPTED, 2/10 faults;
  attack→benign clean, safe→attack corrupted, fixed 500 twice. No command,
  pointer, or second distinct command; grades unchanged. Recipe in
  `docs/reproducibility.md` § 23:4xZ.

## 2026-11-26 23:1x–23:2xZ — oiiocineon 192nd, W298 verdict fold, sngrep staging, Ruby W299 variance

This fold covers `33156c0b..7c16d030` and adds explanation only: no generated
cell, register row, grade, report or lab evidence moved. Recipes are in
`docs/reproducibility.md` § 23:1x–23:2xZ.

- `33156c0b` folded pjproject2shell's W243 W298 verdict: ESTABLISHED AS
  LABELED at the shipped-sample clock-adjacency scope only, from clean
  `git archive a98128fc` with driver `a6cd99f9…`, runner `403b3944…` and
  `10 PASS / 0 FAIL`. The witness field-label NIT is corrected: the probe
  mirror omits `max_jump`, so real `cb` is +56, `user_data` +64, `lock` +88;
  raw `CLOCK_BYTES_AFTER` still carries the chosen marker. W240–W242 remain
  owed, no grade change and no r5.
- `8c53acca` admitted oiiocineon2shell as the 192nd mind (window 200, panes
  %406/%407); counts 191/188/188/128 → 192/189/189/128 with established
  unchanged. 37/37 pins, runner `79c81411016…`, rc 0, 13/0, GCC ASan
  `WRITE-8` at `cineoninput.cpp:215`, clang `-O0` reproduces, fixed guard
  rejects 255 and safe/valid are clean. No full `iinfo`, wire, chosen byte
  or r5; witness replay owed, `established=false`.
- `743624ab` + `f6a50d2b` + `1ae76db6` staged sngrepsip2shell W298
  (CVE-2026-121943, affected `<= 1.9.0`, fix `d49c96c9…`) from four pinned
  upstream files: GCC/clang ASan `READ of size 10241` at verbatim
  `sip.c:338` from the unterminated 10240-byte array at `:320`, fixed/safe/
  guard clean, plain rc 0 negative, source-only harness and clean-archive
  13/0 replay. Rung 3 only; no register row or admission, witness owed.
- `4f0028eb` + `7c16d030` made Ruby W299's ASLR-off echo non-byte-exact:
  12 alive/7 distinct hashes plus 3 faults with no HTTP response over 15
  fresh attacks; original hash once. Hash-seed-driven layout is a hypothesis,
  not measured; accept `CORRUPTED` plus `shortened_by_one>0` with clean
  controls, not a fixed hash. Witness W299 (23:28Z) returned ESTABLISHED AS
  LABELED at the exact `RAILS_MAX_THREADS=2` / shallow / ASLR-off scope with
  the exact author hash and clean controls; the 20 threads=1 faults at
  `0x7fffbffc0048` are a diagnosed VM-stack guard layout condition, not a
  counterexample. No grade, flag or count change, no r5. The older
  byte-identical wording in the dated log is superseded.


## 2026-11-26 22:5x–23:0xZ — live555 191st, W296/W297 verdicts, staged W297 lanes

This fold covers `a6ecf1cc..8d459d6b` and adds only explanation: no
generated cell, register row, grade, report or lab evidence moved.
Reproduce every claim from `docs/reproducibility.md` § 22:5x–23:0xZ.

`27426079` staged and `8229ec57` admitted live555vorbis2shell as the
191st declared target mind under standing #6 (window 199, panes %404/%405).
Counts 190/187/187/126 → 191/188/188/128, register row R1 — / R2 — /
R3 ✓ / R4 — / R5 —. CVE-2026-137587 / GHSA-h6r7-83p9-fpf5, affected
`< 2026.08.25`, no upstream tagged fix; the fixed bytes are mirror commit
`ef760df8569703b93f8df990a07086d7e760d171` (second byte-identical mirror
`03015a0a…`). The operator's clean-archive replay at 22:48Z gave three pins
OK, runner sha256 `9cd39b0a…`, rc 0, `PASS=9 FAIL=0`, GCC and clang ASan
heap OOB READ of 65535/65534/98 bytes at verbatim raw
`VorbisAudioRTPSource.cpp:186/:188/:190`, fixed pin and safe vector clean.
Plain vulnerable rc 0 is a preserved rung-1/2 negative; rungs 1/2/4/5 are
NOT CLAIMED, no RTSP/SDP or wire path in the harness.

Witness W296 (openscapmangle2shell) and W297 (live555vorbis2shell) both
returned ESTABLISHED AS LABELED at their exact scopes, with no
counterexample and no grade change; `8229ec57` had already folded both
`established` flags, so this fold only states the verdict evidence
`.mishe-tauftauf/artifacts/witness-w296-openscap/detail.md` and
`.mishe-tauftauf/artifacts/witness-w297-live555/detail.md`.

`f1aa62e6` staged oiiocineon2shell (W297, CVE-2026-59181 /
GHSA-xh8r-vmqq-56pp) without admission: 37 SHA-256-pinned upstream files,
GCC/clang ASan `WRITE of size 8` at verbatim `cineoninput.cpp:215`,
`PASS=13 FAIL=0`, fixed guard rejects 255 channels, safe(8)/valid(1)
clean. Plain build exits 0 and clang `-O1` optimized the store away;
both negatives are preserved. No full `iinfo`, no wire, no chosen byte or
control flow: rung 3 only, rung 4/5 NOT CLAIMED; independent replay and
the operator's standing-#6 admission decision are owed.

`35a64010` measured rpm2shell's debugger-free ASLR-off chosen-pointer
fault (6/0 in-tree, three wild-pointer rc 139, safe/fixed clean) while
six attempts at a *valid* chosen target still failed (rc 134/139), so the
author-layout rung-4 claim and no-r5 boundary are unchanged. `e52dfe5e` +
`8d459d6b` added loopback HTTP delivery to the real `rpm -i`: 11/0
in-tree and from a clean archive with rebuilt binaries, identical ASan
`WRITE of size 64` at `rpmfi.cc:2242`, GET 200 for every fixture, and a
closed-port control clean. This is a measured delivery path for the
corruption, not command execution; safe rc 0/1 and plain attack rc 1/139
are layout-dependent observations, never assertions.

`59a86335` executed the gimpjif W297 post-inflate patch inside the real
GIMP 3.2.8 AppImage: the published JIF logged three live words at
`out+264/+272/+280` while the safe JIF stayed clean; no post-pin malloc,
glibc write into the fake chunk or command was observed, so rung 3 /
rung 4 PARTIAL / NO r5 is unchanged (author receipt already in
`docs/task.md`, recipe below). `50accf06` closed Ruby's compile-time fold
guards as a 54/54 negative already recorded in this log and in
`docs/reproducibility.md`; it is cross-referenced, not re-pinned.

## 2026-11-26 22:4xZ — Ruby2Shell last case-fold guard systematically closed

`lab/repro/ruby2shell-casefold-rawprefix.{rb,sh,gdb}` enumerated all
Unicode codepoints for raw-prefix/fold-length mismatches (ten pairs)
and tested anchored patterns against the longer subject in fresh
processes on both ASan builds: 20/20 `match=false`, zero ASan reports,
zero `OP_EXACTN_IC` hits under GDB. The 3.4.13-only
`len > endp - p` guard is unreachable from plain UTF-8 Ruby patterns
because the exact prefilter compares folded subject bytes to the
compiled pattern's raw prefix. Grade rung 3 unchanged; full
stock/oracle-free/persistent r5 still NOT ACHIEVED. Recipe in
`docs/reproducibility.md`, detail in report §22:4xZ.

## 2026-11-26 22:2x–22:3xZ — openscap 190th admission, W294/W295 verdicts

This fold covers `170accd0..6a4f1c02` and adds only explanation: no
generated cell, register row, grade, report or lab evidence moved.
Reproduce every claim from `docs/reproducibility.md` § 22:2x–22:3xZ.

`9cc45de2`, `8127c90a` and `6a4f1c02` staged, pinned and admitted
openscapmangle2shell as the 190th declared target mind under standing #6.
CVE-2026-122056 / GHSA-5h6x-q65w-wxvf, affected `<= 1.4.6` and `1.3.x`
with no tagged fix; the fixed pin is main commit `5f1f2bccd4b5f85e…`
(identical maint-1.3 backport `3aaf537c60277d7…`), and the vendor fixed
control RHSA-2026:103520 was not built. Window 198 was adopted as-is
after the sdcpp duplicate was retired; counts 189/186/186/126 →
190/187/187/126, register row R1 — / R2 — / R3 ✓ / R4 — / R5 —. The
operator's clean-archive replay gave three pins OK, runner sha256
`fc185b5f750516e7fb5122d64985d8bb58b8ee1233c81104345c187bab2a92d3`,
rc 0, `PASS=5 FAIL=0`, GCC and clang ASan WRITE-1 at verbatim
`sds.c:884`, fixed pin and safe vector clean. Plain build rc 0 and the
empty-string non-trap stay negatives (the latter UNKNOWN); rungs 1/2/4/5
NOT CLAIMED. Witness W296's clean-archive replay at HEAD `6a4f1c02`
returned ESTABLISHED AS LABELED at that exact scope (3/3 pins, runner
identity unchanged, rc 0, 5/0, fresh WRITE-1 on both ASan builds, no
counterexample, no grade or r5 change).

`9cbd89cd` + `5b0f01cc` completed gimpjif W294: in the pinned real-glib
driver, glibc's smallbin unlink accepted a lab-arranged fake chunk and
returned it on the ninth post-pin allocation, writing metadata at the
chosen address; 19/0 in-tree, 29/0 and 35/0 in the wider runners and 19/0
from a clean `git archive 9cbd89cd`. The earlier failed `consume-ptr`
dereference is preserved as a negative superseded by this result. No
real GIMP plugin, chosen data at a chosen target object, control flow,
marker or command: rung 3 verbatim / rung 4 PARTIAL unchanged, NO r5.
Witness W296 replayed the widened `realglib` + `pins` archive at HEAD
`6a4f1c02` (realglib byte-identical to `9cbd89cd`): 19/0 with the unlink
markers reproduced, verdict ESTABLISHED AS LABELED, no counterexample,
no grade or r5 change. `026c094c` folded W295's ESTABLISHED AS
LABELED replay of lwext4's named-field / prefix-OR ceiling probe (five
runner hashes matched, 31/0 overall, LAYOUT 9/9, eight of eight no-chosen-
pointer checks), superseding its author-only wording without a grade
change or r5. `be38ac1e` closed Ruby's remaining case-fold exact-opcode
guards as a negative at rung 3; its recipe was committed directly and is
cross-referenced, not re-pinned.

## 2026-11-26 22:2xZ — Ruby2Shell remaining case-fold guards closed

`lab/repro/ruby2shell-casefold-exactn.{rb,sh}` tested 21 anchored and
folded-literal shapes on both ASan builds: all single-byte variants
still fault only in the already-known `str_lower_case_match
regexec.c:4278`, and every multi-byte variant agrees across builds
with no ASan report. GDB confirmed `OP_EXACTN_IC` is reached by the
folded literal `\Aß` but not by any long-fold subject, so the
3.4.13-only `OP_EXACT1_IC`/`OP_EXACTN_IC` length guards have no
observed second vulnerability here. Grade rung 3 unchanged; full
stock/oracle-free/persistent r5 still NOT ACHIEVED. Recipe in
`docs/reproducibility.md`, detail in report §22:2xZ.


## 2026-11-26 18:5x–19:2xZ — axis2 admitted (183rd), W284 verdict fold, libarchive staged

This fold covers `80597400..c7f8e2b1`; reproduce every claim from
`docs/reproducibility.md` § 18:5x–19:2xZ. No generated cell, grade, register
row or raw evidence is committed here.

- `6a1a0abb` (operator, standing #6) admitted axis2guththila2shell as the
  **183rd** declared target mind at 19:0xZ (window 187, panes %378/%379,
  dead=0, registry entry present, no duplicate), superseding the W273
  STAGED state. Generated counts 182/179/179/120 → 183/180/180/120 (121 after
  the next fold). CVE-2026-124023 / GHSA-qv28-p6jq-5h3f, pins `584ce5bd…` /
  `f01683ec…`; the 19-byte `<!ENTITY x "y"><a/>` gives GCC ASan READ-4 at
  verbatim `guththila_xml_reader_wrapper.c:308`, 192 bytes past the 72-byte
  allocation at line 218, fixed `event[0]=-1`, safe clean, author 4/0 and an
  18:57Z operator clean-archive replay 4/0 (runner `59da25bc…`, driver
  `7ada2943…`). Rung 3 only, rung 4 NOT CLAIMED; no socket, chosen-offset
  readback, pointer or command. Witness replay and a loopback SOAP consumer
  experiment remain owed.
- `b3e7b50b` folded witness W284's ESTABLISHED AS LABELED verdict for
  ntfs3g2shell (#5739) and raised the generated independent-established count
  120 → 121. Clean archive of `546471a7`, pinned tarball `7754f3b3…` and
  runner `c30c9566…` matched; `RESULT PASS=31 FAIL=0` in 81.5 s with fresh
  ASan WRITE-1 at `compress.c:568`, vulnerable rc 1 and fixed/safe controls
  clean. GDB saw a chosen-byte boundary store; rung 4 NOT CLAIMED and no r5.
  This supersedes the "witness replay owed" wording in the 18:1x–18:4xZ entry
  and the looser "boundary names a verdict" count description: the count needs
  the verdict folded into the register's `established` flag; verdicts held
  only as boundary notes (Soxng2Shell W281) are excluded, with no new replay.
- `631067a3` (frontier W284) staged libarchivezippath2shell as a new target
  mind (window 193, panes %390/%391): CVE-2026-45308 / GHSA-xgqq-r5j8-3mch,
  tarballs 3.8.7 `4b787cca…b9166` / 3.8.8 `038918ea…306c190`, fix
  `a20f89eb…`, patch `cb9a18bb…a49bad`. The shipped `bsdtar --format=zip`
  re-packing a crafted PAX tar gives GCC ASan `WRITE of size 65537`/`131072`
  0 bytes past a 65,536-byte region from `copy_path` at verbatim
  `archive_write_set_format_zip.c:2328` via `:1193`; clean-archive 40/0, fixed
  rejects, 65535-byte path clean on both. Rung 3 only, rung 4 NOT CLAIMED:
  chosen bytes reach ASan poison, no live object, pointer, command or socket.
  Note the 65536-byte path is clean on the vulnerable build but rejected by
  3.8.8, and the fix patch's apply/revert pair is preserved (`1622582b`).
  Admission, witness and plain-build grooming owed.
- `8c845617` + `f620d6ae` recorded a new stock-wire Ruby lane: the pinned
  3.4.11 (`f79c6e78…`) Onigmo repeat-ID write reached consumer-visible
  corruption in unmodified Rails notes under a labeled ASLR-off calibration
  (3/3 HTTP 200/alive, 54,795-byte `c6be1419…` page, 306 → 302 rows with 293
  one-byte-shortened lines; clean control 55,667-byte `56eb2e92…`). A
  fresh-context independent replay matched using the driver's own
  `RUBY2SHELL_ONIGMO_GEM_PATH`; shell-only `GEM_PATH` is a preserved negative.
  No command, chosen pointer, fixed positive or second command, so full
  stock/oracle-free/persistent r5 remains NOT ACHIEVED. `d3a9efae` +
  `c7f8e2b1` generalized the separate case-fold OOB to ordinary UTF-8
  (`s` vs `ß`, ASan READ-1 at `regexec.c:4278`, fixed clean) and closed stock
  notes/routes wire reach with a nine-regex/ten-subject negative.
- `397cfe20` + `1b454673` (neuvector W285) reached the live full enforcer's
  epilogue with a REST-valid 2149-byte tuned message (`return.sh` 18/0):
  the saved return slot is overwritten by a fixed controller suffix and the
  inferior faults at that RIP, plain vulnerable rc 139, safe/fixed survive.
  Wire-determined control transfer, not a chosen executable address; no
  marker or command, grade stays rung 3 / rung 4 PARTIAL, witness owed.
- `1ac66c24` (gimpjif W251) named `ReadJeffsImage` at `file-gif-load.c:1614`
  as the real GIMP 3.2.8 caller and showed the next live chunk's size field
  replaced with `0x4d` bytes; no named victim, pointer or command.
  `cd47299c` + `e370e71c` (nfdump) used a crossing write to decide the next
  record's element type and hence its acceptance by the live collector
  (17/0 in-tree and clean archive) — a parser decision, not a capability gain.
  `ed0b8154` + `7613e8f9` (leptonica) added a one-command clean-archive replay
  (37/0, 82 s), and `54d94b6e` + `6d9b3be0` (rpm) repaired a config-path
  layout trap with an 18-character symlink (18 consecutive replays 0 FAIL;
  clean archive 8/0 and 14/0), preserving the 88-character negative. No grade
  or generated cell moved for any of these target-local lanes.

What would change this fold: a verdict contradicting a labeled row, a checker
RED on committed HEAD, or a later report misquoting one of these receipts.

## 2026-11-26 18:1x–18:4xZ — soxng and ntfs3g admitted, W281 verdict, libsmpp count fold

This fold covers `727f6985..36022791`; reproduce every claim from
`docs/reproducibility.md` § 18:1x–18:4xZ. No generated cell, grade or raw
evidence is committed here.

- `727f6985` (operator, standing #6) admitted soxng2shell as the **181st**
  declared target mind at 18:1xZ (window 191, %386/%387, registry 192/192),
  superseding the W281 STAGED state from `5a6572e6` + `c803e89a`. Counts
  180/177/177/119 → 181/178/178/119 with `established:false` unchanged. The
  operator's isolated-copy replay gave `RESULT PASS=27 FAIL=0`; witness W281
  (#5685) replay returned ESTABLISHED AS LABELED at rung 3 for the shipped-CLI
  ASan `WRITE of size 4` at `src/voc.c:415`. Rung 4 NOT CLAIMED: no
  chosen-offset readback, pointer, listener, plain crash or command.
- `5ace417b`'s libsmpp342shell W279 witness verdict was folded into the
  manifest in `59ceb714` / `c527b9a3`, moving the established count 119 → 120
  (rung 3 only, no r4/r5). `42533e6b` reconciled origin and local main without
  moving a claim. This supersedes the "119→120 owed" passages in the dated
  16:4xZ entries; it is a generated-count fold, not a new observation.
- `4b898a70` + `23f05566` screened FRR out and queued ntfs-3g; `e6695f4d`
  staged ntfs3g2shell and `36022791` (operator, standing #6) admitted it as
  the **182nd** at 18:41Z (window 192, %388/%389, registry 193/193 unique).
  Vulnerable 2026.2.25 SHA-256 `7754f3b3…d008a`, vendor patch
  `6a53ca72…eb3f`, fixed 2026.7.7, fix `6aa66d98…eb42`. A 4 MiB image with a
  final `0x8b57` LZNT1 header drives the shipped `ntfscat` CLI to ASan
  `WRITE of size 1` at `compress.c:568`, 0 bytes past a 65,536-byte region;
  full replay `RESULT PASS=31 FAIL=0` in-tree and from a clean archive, with
  vendor-patched and safe-input controls clean. Rung 3 only, rung 4 NOT
  CLAIMED; the SUID mount path was not driven (mount refused) and no plain
  build ran. The failed fix-commit patch (6/8 hunks) and `0x9201` header are
  preserved negatives. Witness replay and a plain-build chosen-object
  experiment remain owed.

Other commits in the range (`4371ae34`, `3602b71a`, `f71aa273`, `c2cc89b3`,
`4c1fc9ee`, `6e69183d`, `91231731`, `bc7dc0ef`, `10b172e7`, `c1493208`,
`f3c84c5d`, `f84b9faf`, `a8b8cc45`, `f45faa06`) are target-local report,
status or brief-wording changes; their dated evidence stays in the reports
and this fold moves no grade or generated cell for them.

## 2026-11-26 18:1xZ — Ruby2Shell cross-version matrix and small failed-realloc UAF

`ruby2shell-regexp-notes-wire.py` gained Ruby/gem-home overrides. Stock Rails
K=12/nested-2 attacks reproduced the secondary `bbuf_free` UAF on plain
3.3.13 and 4.0.9 with safe/fixed controls, but no duplicate, overlap or
survivor. A nested-130 tcache-disabled arm initially failed as invalid input
because the generator crossed the Unicode surrogate block; after correcting
the generator, affected builds still died in `bbuf_free` and controls stayed
clean.

New `failmalloc.c` plus `ruby2shell-regexp-failmalloc.py` reproduce the same
UAF deterministically from a 34-byte UTF-8 pattern and one failed 40-byte
realloc: affected 3.3.13/3.4.12/4.0.9 each 3/3 SIGSEGV, fixed 3.4.13 3/3
`RegexpError`, safe affected input 3/3 `OK`. GDB traced the stale 16-byte BBuf
through reclaim and refree; its `p` field is the raw tcache safe-linking word,
and `bbuf_free` does not reveal it before `free`. A nonempty tcache bin still
produced an invalid encoded pointer. Primer/jemalloc sweeps found no controlled
free or duplicate. This is LD_PRELOAD-conditioned in-process rung 3 only;
full stock/oracle-free/persistent rung 5 remains NOT ACHIEVED.


## 2026-11-26 17:2x–17:5xZ — soxng staged, quickjsng admitted, W280 verdict, live consumers

This fold covers `11f304db..7b3f8f7f`; reproduce from `docs/reproducibility.md`
§ 17:2x–17:5xZ. No generated count, grade cell, register row or raw evidence
is committed here.

- `a1611627` (operator) admitted quickjsng2shell as the **180th** mind;
  counts 180/177/177/119 with the row still `established:false`, rung 3
  only. `d1cb3c03` reconciled main without moving a claim.
- `5a6572e6` + `c803e89a` staged soxng2shell (CVE-2026-129264) at vulnerable
  tag `a4a14b4f…`, one-file fix `0b40408b…`, fixed tag `6edd3b3a…`. An
  8,494-byte VOC switching 8-bit → 4-bit mid-loop gives shipped-CLI ASan
  `WRITE of size 4` at `src/voc.c:415` past a 32,768-byte region; full
  rebuild `RESULT PASS=27 FAIL=0` (earlier 26/1 was a trace-string
  assertion). Rung 3 only; no readback, pointer, listener, plain crash or
  command; admission and witness owed.
- `6f137086` folds witness W280's **ESTABLISHED AS LABELED** verdict for
  nfdump's chosen-byte `run-alias.sh` replay from `ca2bb2b0` (11/0). The
  failed record-framing hypothesis is preserved: a 58-byte first record
  makes `proto` read the size byte `0x40`, and 56 bytes draws chosen bytes
  from the fixed V3 type. Live wire and allocation-boundary replay remain
  owed.
- `79c1f673` + `7b3f8f7f` (pjproject W242) reached a live `pj_mutex_t` +48
  bytes after the shipped AVI frame buffer: 16/0 in-tree and from a clean
  archive, chosen bytes at mutex offsets +4..+15, no pointer call.
- `7df91a88` + `5e34dd92` (gimpjif W246/W247) drove the real GIMP 3.2.8
  AppImage plugin via the PDB with 64 chosen bytes past the 260-byte
  `indexes` allocation; the later stall is ~32 MiB repeated allocation,
  not post-WRITE heap damage. No named victim, chosen address or command.
- `1f12ab3f` (neuvector W282) drove the full ASan `dp` enforcer over its
  AF_UNIX socket: `WRITE of size 121` at offset 2080 of `dlpsig_buf`, fixed
  binary logs the skip rule and stays clean. No command or r5.
- `aa583300` + `a44cd649` + `39a607bd` (speex) measured a forged-size
  overlapping allocation (9/0), the stack `WRITE of size 1` at
  `bits.c:184`, and UBSan `left shift of negative value -1` at the pinned
  fix (5/0). `29fefa30` (rpm) observed chosen bytes becoming a dereferenced
  live liblua GC pointer under GDB in plain `rpm -i`; the valid-target
  address is GDB-layout-specific, not ASLR-stable.
- `93fc5ba7` + `9f8f763e` (ruby) closed the promoted-buffer smallbin link
  arm; their dated entries are already in this file from peer commits, so
  this fold records only the cross-reference. Grades unchanged, full
  stock/oracle-free/persistent Ruby r5 NOT ACHIEVED.

Every count above is an author or clean-archive replay except W280's
witness verdict.

## 2026-11-26 17:3xZ — Ruby2Shell promoted-buffer smallbin link arm closed

Nine K=12 pair-only stock-Rails runs gave one stochastic `smallbin double
linked list corrupted` with no captured links (the tracer was edited
concurrently mid-batch), five invalid-pointer/munmap aborts and three hangs;
seven completed dump-on-malloc repeats produced no smallbin. The new
`ruby2shell-regexp-link-audit.py` shows 89 observed heap mappings all have a
low-32 above the Unicode code-point cap, while stale BBuf `fd/bk` words are
32-bit code points: pattern-derived links cannot be valid heap pointers and
cannot satisfy glibc's smallbin integrity check. Arm CLOSED, grades
unchanged, full stock/oracle-free/persistent Ruby2Shell rung 5 still NOT
ACHIEVED.

## 2026-11-26 17:1xZ — Ruby2Shell stock Rails Regexp double-free wire lane

`cf50f68a` adds `ruby2shell-regexp-notes-wire.py` plus focused glibc/jemalloc
allocator tracers. The unmodified `rails new --minimal` development
`/rails/info/notes` endpoint interpolates `params[:tag]` into Regexp literals;
a form POST with `_method=GET` bypasses Puma's query-string limit and reaches
GHSA-7x2q-68qv-6p8x. The 90,085-byte malicious body gives ASan
`heap-use-after-free` in `bbuf_free regparse.c:145` and a plain-build
`__libc_free` crash; safe affected input is 200/alive and fixed 3.4.13 is
500/alive. This is wire-only unmodified-stock rung 3 for the secondary lane,
not rung 4 or rung 5. Safe-link, tcache-disabled, named-group, jemalloc and
ASLR-off calibration produced no stock controlled free, duplicate, overlap,
command, persistence or second command. Full stock/oracle-free/persistent
Ruby2Shell rung 5 remains NOT ACHIEVED.
The reproducer later gained nested-exclusion promotion (stale data 20→40
bytes), same-connection regexp primers, isolated pid files and timeouts. A
21-count primer sweep and an eight-run K=12 repeat produced only allocator
integrity failures/hangs; the lone smallbin-linked-list abort was stochastic,
not a controlled write. The complete attack/safe/fixed/ASan matrix still
passes its expected observations.



## 2026-11-26 16:4x–17:1xZ — libmikmod admitted (179th), quickjsng staged, W278 witness, bounded lanes

This fold covers `c1a02981..17f9716f`; reproduce the claims in
`docs/reproducibility.md` § 16:4x–17:1xZ. No raw evidence, generated file or
grade cell is committed here.

- `3a4f1115` (operator, standing #6) admitted libmikmod2shell as the 179th
  declared target mind, window 189 (%382/%383); generated counts moved
  178/175/175/119 → 179/176/176/119 with the row still `established:false`.
  The isolated-copy replay matched all 12 checks: vulnerable GCC ASan
  `WRITE of size 8` at `load_dsm.c:339` via `Player_Load()`, fixed `errno=9`,
  safe input clean. Rung 2/3 only, rung 4 NOT CLAIMED; witness and plain
  grooming owed. The older STAGED wording in the 16:1x–16:4xZ entry is
  superseded by this admission.
- `8d8d5fa0` + `2769b482` staged quickjsng2shell (GHSA-r6vf-p8wr-4vg9, no
  CVE, OSV 404) for a fast-array UAF in the shipped `qjs` CLI. Pinned v0.14.0
  `3c051980…` / v0.15.0 `433941b9…`, fix `da49a370…`; upstream PoC gave
  28/0 and 11/0 with ASan `READ of size 4` at `quickjs.c:1546` via `:9478`,
  fixed prints `undefined`, safe control clean. Rung 3 only, rung 4 NOT
  CLAIMED; admission and witness owed; the advisory's "patched None" and
  os-module command claims are preserved as claims, not lab findings.
- `a630590d` folded witness W278's ESTABLISHED AS LABELED verdict for
  neuvector2shell: clean archive of `d2f1f317`, three pins exact, 22/20/17
  PASS, both traces faulting at `dpi_sig.c:657`. Rung 4 PARTIAL at the
  earlier ESTABLISHED scope, no chosen address, command, grade change or r5.
- `17f9716f` (W280) drove a 2233-byte REST-valid message over the real AF_UNIX
  socket through a lab consumer (`loopback.sh` 17/0): ASan `WRITE of size
  121` at offset 2080 of `dlpsig_buf`, safe 139-byte and fixed inputs clean.
  Not a full enforcer; no REST/CRD endpoint, chosen address, command or r5.
- `fdcb60c7` + `a6ea9e18` (rpm2shell) used the attacker-declared cpio length
  for ASan WRITEs of 64/512/4096 (21/0) and a real `rpm -i` consumer (14/0)
  where chosen filler faults unmodified plain install 3/3 rc 139 (GDB:
  `rpmluaFree` teardown) while zero/short-read controls return 1. The
  `rpm2cpio`/`rpm2archive` aliases are one binary; natural pointer control
  and semantic dereference stay UNKNOWN.
- `325ec0c9` (nfdump2shell) closed the live write-past-allocation route: a
  65507-byte UDP datagram leaves the 65535-byte `in_buff` store four bytes
  inside; `run-edge.sh` 8/0 with an ASan READ-1 at `nfd_raw.c:259`, safe and
  fixed clean. Earlier chosen-byte live-record and W235 rows are unchanged.
- `5e998ac4` + `1b32d2c6` (gimpjif2shell W245) confirmed the WRITE with
  instrumented real zlib 1.3.2: `run-asan.sh` 18/0, `inflate_fast` WRITE-1 0
  bytes after 260/4-byte regions, fixed/safe clean, clean-archive replay
  18/0; witness asked, no verdict at yield. No plugin, PDB wire or r5.
- `69a4e67f` (leptonica2shell) closed the external-consumer hunt with a
  bounded no-request-consumer negative for this checkout; witness replay of
  the two real runners stays UNKNOWN.
- `9d48251d` (ruby2shell) closed the same-request second-buffer overlap:
  12 N values at filler 40 served three keep-alive requests clean with
  matching safe/fixed controls; gdb saw no second buffer at N=21, one 134 KB
  away at N=59 and an abort before it at N=572. No chosen-byte write,
  command or persistence; full stock/oracle-free/persistent r5 NOT ACHIEVED.

`9b0ab258` later raised `loopback.sh` to 24/0 and read the optimized saved
RBP/return slot over the same socket; the 17/0 above is the fold-window
count. Grade and the no-r5 ceiling are unchanged.

Every count above is an author or clean-archive replay except W278's witness
verdict; no register or generated grade cell moved.

## 2026-11-26 17:0xZ — Ruby2Shell same-request case-map buffer sweep

The `_method` length became an argument of the keep-alive reproducers. Twelve
N values (21..92) at filler 40 served three keep-alive requests cleanly;
safe-input and fixed-3.4.13 controls at N=21/59 matched. A gdb observer of
the first two case-map buffers found N=21 has no second buffer, N=59's second
buffer is 134 KB away, and N=572 aborts before it under the changed layout:
no same-request overlap, chosen-byte write, command or persistence. Full
stock/oracle-free/persistent r5 stays NOT ACHIEVED. Reproducers:
`lab/repro/ruby2shell-webrick-{keepalive,keep-watch}.sh`,
`ruby2shell-webrick-keep-client.py`, `ruby2shell-webrick-secondbuf.gdb`.

## 2026-11-26 16:4xZ — libsmpp342shell W279 witness verdict

`5ace417b` recorded witness #5652's ESTABLISHED AS LABELED verdict for
libsmpp342shell: clean-archive stage `58f43e61`, hashes `373fcdc9…` /
`f2d0ceed…` / `cbd59199…`, both tarballs re-hashed (`6a275907…` /
`c85f8d09…`), unmodified `run-all.sh` rc 0 with `RESULT PASS=31 FAIL=0` and a
byte-identical fresh console. GCC/Clang ASan `READ of size 2` 0 bytes past a
17-byte region in `strlen` via `smpp34_unpack`; plain rc 139, fixed `rv=-1`,
valid PDU `rv=0`. Rung 3 only, no r4/r5, no contradiction. The earlier
"witness replay owed" passages are superseded; the generated row still reads
`established:false`, so the operator owes the manifest/register fold and the
119→120 established-count move. `5ace417b` also corrected tinyusb brief
citations without moving a grade. Raw evidence is gitignored under
`.mishe-tauftauf/artifacts/witness-w276-libsmpp342shell/`.

## 2026-11-26 16:1x–16:4xZ — tinyusb admitted, W276 staging, target-local lanes

This fold covers `dd2720d7..d2f1f317`. Reproduce every claim in
`docs/reproducibility.md` § 16:1x–16:4xZ; the dated passages below stay
verbatim, and § 16:0xZ now records tinyusb's admission. No raw evidence is
committed here, and no grade cell, witness verdict or R5 cell moved.

- `856cd422` (operator, standing #6) **admitted tinyusb2shell as the 178th
  declared target mind** at 16:2xZ, window 188 (%380/%381); generated counts
  177/174/174/119 → 178/175/175/119 with the row still `established:false`.
  The operator's 16:19Z isolated-copy replay matched all six cases of
  `sh run-all.sh && sh verify.sh` (`RESULT PASS=6 FAIL=0`), including the
  pinned 4/5-byte ASan reads/writes and both fixed stops. AV:P physical
  vector, the unreviewed NVD-imported GHSA and the "0.20.1" vs "0.21.0"
  discrepancy are preserved; witness replay, a simulated USB-device consumer
  and plain-build grooming are still owed.
- `5e6fe760` (frontier W276) **staged libmikmod2shell** for CVE-2026-105837 /
  GHSA-rr6f-2vgw-5v76 (`AV:L`), pins `08d7d210…` / `a125eabb…`, tarballs
  `dbe73e92…` / `a9d7cba3…`. GCC ASan through `Player_Load()` gives
  `RESULT PASS=12 FAIL=0`: `WRITE of size 8` at `load_dsm.c:339`, 0 bytes past
  a 16/128-byte `AllocTracks` region; fixed `errno=9`, safe clean. Rung 3,
  rung 4 NOT CLAIMED, STAGED not admitted, witness owed; no public PoC and
  the ~300 KB / 4097-PATT estimate is unverified.
- `697f980d` + `ee63e73c` + `62d6fd30` (gimpjif2shell W244) measured the
  pinned caller path and the ~4 GiB `dest`: the realglib caller/callerpub run
  now gives **30 PASS / 0 FAIL** with `DEST_ALLOC=OK`, `LIVE_CHANGED_BYTES=48`
  and `delta=32` (published dims `delta=272`). `ee63e73c` removed the
  ASLR-dependent byte assertion after a first clean replay gave 29/1; five
  in-tree and three clean runs then gave 30/0. No real GIMP/GEGL plugin, PDB
  call, dereference or r5. This supersedes the older 21/0 and "~4 GiB dest
  UNMEASURED" wording in the dated W243 passage.
- `401276e7` + `d490421a` (leptonica2shell) bounded the fault and replayed
  from a clean archive: the real-object neighbor run now gives **5 PASS / 0
  FAIL** (was 3/0), with the fault 129504 bytes past `ba->data` at the end of
  a 135168-byte mapping and the ~1 GB source buffer in a separate mapping
  17.7 TB away. Clean `git archive` gave 7/0 (`provision.sh`) and 5/0
  (`run-neighbor.sh`) at 16:12Z; absolute addresses move under ASLR. No
  contiguous writable ~1 GB, wire, pointer or command; author replay only.
- `dc2f8ce7` + `3f79fa43` (ruby2shell) closed the WEBrick successor-shaping
  and same-worker keep-alive leads. The N=572 filler sweep left L=48/768
  after the consumer step; three requests on one HTTP/1.1 socket at L=48
  aborted in request 1 (`malloc(): invalid next size (unsorted)`, rc 134),
  safe and fixed 3.4.13 served 404/404/404, and an L=8..192 screen aborted
  at 8/16/24/32/56 while 40/64/80/96/128/192 stayed clean. The first
  post-overflow read is the same request's second `rb_str_casemap`
  allocation under a layout-perturbing gdb watch. No overlap, chosen byte,
  command or persistence; full stock/oracle-free/persistent r5 stays NOT
  ACHIEVED. The author's own 16:1x/16:2x entries appear directly below.
- `2f6cdea5` (sailtga2shell) closed natural-victim and shipped-CLI wire lanes
  with an observational shipped-CLI heap trace: **15 PASS / 0 FAIL**. Only
  an 88-byte `sail_image` follows the pixels and its pointers are zeroed;
  the shipped tree has no listener; the earlier synthetic pointer control
  used ASLR off. Author-only bounded negatives; the W246 ESTABLISHED row and
  grade are unchanged. Preserve the advisory ASan paste labeled "Version
  1.0.0" against the pinned tag bytes.
- `5e555244` (unarr2shell) bounded a wire-caller lane: **8 PASS / 0 FAIL**,
  1536 bytes over loopback ports 19441–19444, ASan `WRITE of size 101` in
  `tar_get_name()`, safe and synthetic-fixed clean. Grade stays rung 3
  verbatim / rung 4 PARTIAL fixed NUL, and the earlier #4834 verdict is
  untouched. The vendor changelog/advisory "patched in 1.2.0" contradicts
  the full diff (only the PAX `max_size` line); jomics is local-only and a
  GitHub code search returned 401 UNKNOWN.
- `b9d9962e` (rpm2shell) bounded natural-adjacent pointer dereference:
  `NATURAL_DEREF_PASS=52 NATURAL_DEREF_FAIL=0`, adjacency 4/20, read
  watchpoint 20/20, inspected pointer 0/12. All 20 continuations exit 1 at
  `rpmfi.cc:2242/2245/2253` (`RPMERR_READ_FAILED`) and the reads occur at
  `free(buf)` rather than value-dependently; GCC -O1 ASan is a preserved
  negative. Natural pointer hijack stays UNKNOWN; the lab-groomed
  WRITE-64 rung-4 row is unchanged.
- `ca2bb2b0` (nfdump2shell) drove packet-chosen bytes into a processed live
  record: **11 PASS / 0 FAIL** into a 127.0.0.1 `nfcapd`, wire `34 12` read
  back as `12 34` at record 2 payload offset 2 and the timestamp shifting
  from 1970-02-19 17:02:51.956 to 1970-03-01 19:42:42.176. Rung 4 PARTIAL at
  the live-record scope, unwitnessed; W235's ESTABLISHED row is unchanged,
  there is no ASan in the 64 KiB live buffer, no pointer and no command.
- `d2f1f317` (neuvector2shell W278) overwrote a saved RBP and return slot in
  an optimized real-object lab frame: `wirepath/run.sh` now emits
  `wire-B.json` and gives **20 PASS / 0 FAIL** (supersedes the dated 19/0
  wording), and `wirepath/frame.sh` gives **17 PASS / 0 FAIL** with gcc -O2,
  real libjansson and gdb. Chosen bytes land at `BUF+2048..2055` against an
  -O0 BUF→RBP delta of 2080; optimized vulnerable-safe and fixed-attack
  messages exit 0 and default `_FORTIFY_SOURCE` aborts in `__sprintf_chk`
  (preserved negative). No full enforcer, live REST/CRD target, chosen
  address, command or r5; these are bytes in a return slot, not called
  pointer control. Grade stays rung 4 PARTIAL at the earlier ESTABLISHED
  scope and W278 awaits witness replay.

Every count in this section is an author or clean-archive replay, not a
witness verdict; no registered grade cell moved.

## 2026-11-26 16:2xZ — Ruby2Shell same-worker keep-alive reuse

Three requests on one WEBrick keep-alive socket changed the N=572 geometry:
filler 48 aborted at request 1 with `malloc(): invalid next size (unsorted)`,
safe-input and fixed controls served all three; a bounded L=8..192 screen
found abort diagnostics for L=8/16/24/32/56 and unchanged 404s for
L=40/64/80/96/128/192. A gdb byte watch (layout-perturbing) found the first
post-overflow read is `_int_malloc` from the same request's second
`rb_str_casemap` buffer allocation, not only thread teardown. No overlap,
chosen-byte write, command or persistence; full stock/oracle-free/persistent
R5 remains NOT ACHIEVED. Reproducers:
`lab/repro/ruby2shell-webrick-keepalive.sh`,
`ruby2shell-webrick-keep-client.py`, `ruby2shell-webrick-keep-watch.{gdb,sh}`.

## 2026-11-26 16:1xZ — Ruby2Shell WEBrick successor shaping

The N=572 pre-`_method` filler sweep (22 lengths) found ten no-diagnostic
survivors, but continuing the allocator consumer left only L=48/768 alive.
L=48 could leave a valid unsorted `0x270` chunk; no later request
deterministically reclaimed it. `MALLOC_ARENA_MAX=1` changed layout and
aborted, and non-perturbing `process_vm_readv` tracking did not reproduce a
follow-up overwrite. No overlap, command or persistence; full
stock/oracle-free/persistent R5 remains NOT ACHIEVED. Reproducer:
`lab/repro/ruby2shell-webrick-filler-sweep.sh`.

## 2026-11-26 16:0xZ — tinyusb2shell staged, Ruby stock WEBrick lanes closed

This fold covers `1995e07a..59c2e2e6`. Reproduce every claim in
`docs/reproducibility.md` § 16:0xZ; no raw evidence is committed here.

- `fc1e026f` (frontier W275) **staged tinyusb2shell** for CVE-2026-61497 /
  GHSA-qf63-w79j-qw7p (HID report-descriptor `uint16_t` underflow, `AV:P`
  physical device). Vulnerable fix-parent `5014146f…` / fixed `85047e1…`
  (release 0.21.0). Verbatim parser slice, GCC 12 ASan, `run-all.sh` +
  `verify.sh` → `RESULT PASS=6 FAIL=0`: 4-byte `05 01 07 DE` gives heap
  `READ of size 4` 0 bytes past a 4-byte buffer, 5-byte `07 DE AD BE EF`
  gives stack `WRITE of size 4` into the 4-byte `info` struct; fixed stops
  at `report_num=0` / `usage_page=44510`; well-formed 13-byte descriptor
  clean on both. Rung 3 only, rung 4 NOT CLAIMED: no chosen-offset readback,
  pointer, USB stack/hardware, command or r5. Preserve the unreviewed
  NVD-imported GHSA, the "0.20.1" vs CVE/NVD "0.21.0" discrepancy and the
  zero published upstream advisories. STAGED, not admitted; no count or
  grade cell moved; witness clean-archive replay and operator admission owed.
- `68c4b04f` (ruby2shell) **CLOSED the stock WEBrick consumer lanes**.
  `-s webrick` reaches a Host `downcase`, but the value is ASCII-8BIT so the
  expanding byte is inert. Precise `jemtrace` before/after qwords prove
  C=80's `0x53` was a natural-pointer false positive (real target a free
  Ruby slot) and C=640 is reused by `compile_data_alloc_with_arena`, whose
  `storage->next=0` erases the byte; attack/safe/fixed C=640 O=1/0/0. Plain
  glibc Sinatra N=572 and Rails/WEBrick N=524 corrupt a next-chunk size and
  later abort in `unlink_chunk` / `munmap_chunk`. No command, chosen-offset
  write, pointer control, second request or persistence; full
  stock/oracle-free/persistent r5 stays NOT ACHIEVED and primary grades are
  unchanged. The author's own entry is preserved below.
- `358c1b40` (mqttc2shell) committed the shipped `simple_subscriber.c`
  callback result already folded at 1995e07a (`27 PASS / 0 FAIL`, console
  `426b7c06…94b6c9`, rung 3 wire-backed, rung 4 NOT CLAIMED); no new claim.
  `59c2e2e6` reconciles published and local main with no row or count moved.

## 2026-11-26 15:4xZ — Ruby2Shell stock WEBrick consumer screen

The stock `-s webrick` surface reaches a new Host `downcase`, but WEBrick tags
the value ASCII-8BIT, so the expanding byte is inert. `jemtrace` now proves
overflow writes with allocation-time before/after qwords (`O/P` records) and
can dump live references. The precise C=80 pointer lead was a natural `0x53`
false positive; C=640 is reused by `compile_data_alloc_with_arena` and erased.
Plain glibc Sinatra N=572 later aborts in `unlink_chunk`; Rails/WEBrick N=524
later aborts in `munmap_chunk`. Attack/safe/fixed C=640 controls are O=1/0/0.
No command or persistent second request; full stock/oracle-free/persistent
R5 remains NOT ACHIEVED. Reproducers:
`lab/repro/ruby2shell-webrick-class-scan.sh` and
`lab/repro/ruby2shell-webrick-case-watch.gdb`.

## 2026-11-26 15:0x–15:4xZ — quickjsbcode2shell 177th, W273 lwext4, real-consumer and wire lanes, closed negatives

This fold covers `bf13ceab..81e3cd8e`. Reproduce every claim in
`docs/reproducibility.md` § 15:0x–15:4xZ; no raw evidence is committed here.

- `4336a4d2` (operator, standing #6) admitted quickjsbcode2shell as the
  **177th declared target mind**, window 185 (%374/%375, dead=0). Generated
  counts moved 176/173/173/119 → **177/174/174/119** in `README.md`,
  `docs/results.md` and `research-manifest.json`; the independent-established
  count stays 119 and the QuickJS row stays `established:false` (rung 3 only,
  runner `7031c420…c09b1cd5`, `PASS=25 FAIL=0`, witness replay owed). The
  reconcile edge `010f4cbb` moved no row or count. Earlier docs folds still
  read 176/173/173/119 because they are dated history, not current counts.
- `aa6afcd2` folds witness **W273's lwext4shell verdict: ESTABLISHED AS
  LABELED** (14:42Z, clean `git archive cbadc189`, staged evidence removed,
  `replay-clean.sh` 31/0, real 17/0, victim 9/0, `REPLAY_RC=0`). Fresh ASan
  `WRITE of size 4098` 0 bytes past a 4096-byte region (`ext4_fs.c:404` ←
  `:611`), gdb delta 4112 with non-null then zeroed `bc`, `0xfe` at
  `data+8192` over three ASLR-on repeats, image-derived `ipg=65539 → 0xf8`.
  No command/wire/pointer-control call, no grade change, NO r5. `94958123`
  repaired two post-verdict NITs (byte-offset wording, relative `DEST`) with
  a relative-`DEST` smoke (`31/0`, same hashes) that changed no evidence.
- `8ffb83b0` / `603e222d` staged axis2guththila2shell (CVE-2026-124023 /
  GHSA-qv28-p6jq-5h3f; pins `584ce5bd…` / `f01683ec…`, `PASS=4 FAIL=0`,
  GCC ASan `READ of size 4` at `guththila_xml_reader_wrapper.c:308`). STAGED,
  not admitted; rung 3 only, rung 4 NOT CLAIMED; witness replay, admission,
  loopback consumer and plain-build grooming owed. No count or grade cell
  moved.
- `6d4d551b` + `f5741ac5` (neuvector2shell W274): a REST-validated
  controller-shaped message within documented limits expands `*` after the
  check (`pre_total=1024 expanded_total=1536 wire_total=1824`) and reaches
  real `dpi_sig_bld()` (`dpi_sig.c:658`), ASan `WRITE of size 121` at offset
  2080 of a 2048-byte buffer, `wirepath/run.sh 19/0` — rung 3 verbatim / rung
  4 PARTIAL, no REST endpoint, full enforcer, chosen address, command or r5.
  `f5741ac5` is the author's clean-archive receipt (`22/0` + `19/0`,
  `run-all.sh 29/0`, `REPLAY_PASS=5`); witness notified on DM 5639, no
  independent verdict claimed.
- `4f9314a9` + `b76012a3` (pjproject2shell W241) overwrote a live
  library-created `pjmedia_port` 48 bytes after a real `pj_pool_alloc` frame,
  with chosen `MISHE-PJPROJECT!` bytes in `name.ptr`, `sig`, `get_frame`,
  `put_frame` and `port_data.pdata` (`run-realobj.sh 11/0`, readback proof,
  ASan silent in a shared pool). `b76012a3` is the clean-archive replay
  receipt and records the natural-caller negative (no shipped natural
  adjacency). No pointer called, wire, command or r5; W240/W241 verdicts
  awaited. No register grade cell moved.
- `edd20190` + `a23384e2` (leptonica2shell) planted `MISHE-LEPTONICA` in a
  live 512-byte heap sentinel (`SENTINEL_OFFSET=224`,
  `CHOSEN_AT_OFFSET=16`, `3/0`); `a23384e2` is the clean-archive receipt.
  `cf956faf` + `d2252911` (gimpjif2shell W243) drove a complete on-disk JIF99a
  (`len=33025`, `height=65026`, `product=0x80000002`, `data_size=4`) through
  a real `FILE*` parse into chosen neighbor bytes, with a never-dereferenced
  file-chosen pointer value (`run-real.sh 21/0`; clean replay `21/0`) — the
  ~4 GiB `dest` consumer remains UNMEASURED. `aaedfd2f` (rpm2shell) built real
  rpm 6.1.90 and saw `WRITE of size 64` past a 1-byte region in both
  `rpm2cpio` and `rpm2archive` (`21/0`), with an instrumented pointer field
  in a plain groom and preserved stripped/query negatives. All are author
  rung-4 mechanics on real objects, not witnessed, not r5.
- `bf77b8a6` + `6b1beb43` (mqttc2shell) reached the verbatim shipped
  `simple_subscriber.c:123-133` callback from a loopback wire broker: ASan
  `READ of size 65535` in the shipped `memcpy` at `:127`, pure child SIGSEGV,
  fixed rejects (`27/0`); `6b1beb43` is the clean-archive receipt. Grade stays
  rung 3 wire-backed, rung 4 NOT CLAIMED. `9fbeec88` + `81e3cd8e` (nfdump2shell)
  drove a V3 datagram into a real 127.0.0.1 nfcapd collector in ASan and plain
  (`13/0` each; vulnerable drops record 2, fixed rejects; no ASan in the real
  65535-byte buffer); the chosen-byte alias shape is a preserved negative,
  and the first clean-archive attempt was `3 PASS / 10 FAIL` until `81e3cd8e`
  added `mkdir -p` and a post-build binary check. Witness replay of the live
  wire is still owed; no pointer, command or r5.
- `0c0a0021` (speex2shell) added an in-process function-pointer overwrite and
  benign-marker call (`8/0`) with vendor-fixed control; rung-4 mechanics only,
  not replayed by W245, wire reachability UNKNOWN. `35081006` **CLOSED** the
  ruby2shell C=112 code-pointer lane (no consumed owner: 16/18 byte-identical
  qwords, GDB `entry-hits=0`, `+13-hits=0`, source reference only in fatal
  `rb_print_backtrace`). `d5299c81` **CLOSED** unarr2shell's upstream-fix lane
  (master head `704ea083` still vulnerable, no vendor fixed control; the +1
  NUL lands in glibc slack). No primary grade changed for either closure.

The 119 established count and every register grade cell are unchanged by
this fold; every `PASS/FAIL` count above is an author or clean-archive replay
except the W273 verdict. The dated folds below are preserved verbatim, so
their older 176/173/173/119 counts are not edited.

## 2026-11-26 14:2xZ — FreeRDP W21 clean-room replay

The unknown wake-22 attempt left an uncommitted runner and fixed-guard patch;
no scoped commit or report edit had landed. W21's original evidence included
a scratch `WAKE9_COPY` diagnostic already committed in the wake-8 patch set.
`lab/freerdp2shell-src/run-wire-byte-range.sh` now uses a dedicated pristine
3.32.0 clone/build, reapplies that probe to the pinned blob, applies the
committed fixed guard only to the control copy, and records exact CMake/gcc
flags in `docs/reproducibility.md`. A fresh build at 14:20Z printed
`ALL W21 CHECKS PASS` for vulnerable, no-call, benign and fixed modes. W21
remains author-only CLOSED NEGATIVE; W20 remains a rung-4 lab mechanic and R5
remains blocked at wire-byte provenance.

The 2026-11-25 0x–06:2xZ limbs correct four row boundaries without moving any
rung, grade, route, mind-count, witness or R5 cell. Ruby2Shell's stock Rails
N=524 "no 0x3f0 consumer" claim rested on a probe that compared a malloc user
pointer with the forged chunk start, so a P line could never fire
(`reports/ruby2shell-investigation.md` §Consumer-visibility correction). With
`process_vm_readv` window lines and `lab/repro/ruby2shell-cons-vis-tabulate.py`,
49 runs gave 5 survivors and zero window frees (Q=0/49): the forged 0x251 qword
at `case_physical+0x18` forms a pseudo-chunk whose user pointer is never freed,
so the qword is structurally inert, not merely unobserved. The same corrected
probe measured post-attack C `request=0x21c/0x1f8` pops at the victim user
pointer in two live survivors; stock/oracle-free/persistent R5 stays NOT
ACHIEVED and the harness-condition witness-ESTABLISHED R5 stays as labelled.

The 2026-11-25 third push re-smoked Ruby2Shell's harness rung-5 chain
(attack marker + `rce=OBSERVED` + target pop; safe and fixed clean) and
measured one new stock surface: a stock Sinatra dev 500 page leaks 20
GC-heap object addresses via env `to_s`/`inspect`
(`lab/repro/ruby2shell-errorpage-oracle.sh`), 12 boot-stable in-process but
0/20 low-bit overlap across fresh processes and all 20 in Ruby GC pages,
none in glibc heap, libc or code. It is not wire-reachable on a route-less
app and Rails filters it; it replaces only `ObjectSpace.dump`, not mtrace
or maps. Stock/oracle-free/persistent R5 stays NOT ACHIEVED, and the
labelled harness-condition R5 cell is unchanged.

The 2026-11-25 fourth push closes Ruby2Shell's keep-alive same-thread lead
(`lab/repro/ruby2shell-keepalive-thread.sh`): with Puma `min=3/max=3`, the
fixed pool used by `rails new`, five GETs on one reused connection rotated
across all three worker threads in 3/3 fresh processes, so HTTP keep-alive
does not enable same-thread tcache grooming on the relevant target. The
default `min=0/max=5` pool did share one thread for sequential requests, a
configuration property that leaves the no-parse-free and post-upcase-GC
blockers intact. Stock/oracle-free/persistent R5 stays NOT ACHIEVED.

The 2026-11-25 direct-session push records two more bounded negatives for
Ruby2Shell. Restoring the forged T-chunk malloc header via
`/proc/self/mem` (`RUBY2SHELL_R5_REPAIR=1` in
`lab/repro/ruby2shell-rung5-http.ru`) did **not** restore process
survival: the new `ruby2shell-rung5-http.sh survive` mode got a first
`rce=OBSERVED` plus marker, but `GET /health` and a second distinct-marker
POST both returned `HTTP 000` and the process aborted on a boot-time
0x2010-class chunk at heap offset 0x1980. A systematic survey of remaining
default Sinatra/Rack/Puma/Rails surfaces found no wire-only glibc-heap or
libc/code-base disclosure — only Ruby GC-anon `VALUE` pointers on the
already-measured Sinatra dev 500 page — so the harness oracles still have no
wire substitute on an unmodified app. The harness matrix re-verified (attack
marker + pop, safe-input and fixed 3.4.13 controls clean). Stock/oracle-free/
persistent R5 stays NOT ACHIEVED.

The 2026-11-25 sixth push (direct session) answers Ruby2Shell's named
reflection lead and measures the first missing oracle wire-only. The
48-part/filler-first arm aborts 6/6 (top-chunk pop → `sysmalloc`), but the
new committed `ruby2shell-reflect-scan.py` found the channel already firing
in the 32-part consH20-tail geometry: 20 saved stock-Rails 404 responses
(17% of surviving stage2d arms, previously never byte-parsed) reflect
post-parse allocator/Ruby metadata inside live drain bodies — fake `0x25`
chunk sizes, PREV_INUSE'd `0x91` pattern qwords and pointer pairs, i.e. a
bin insertion whose chunk overlaps a live wire-chosen string. Live
classification (`ruby2shell-stock-leakclass.sh` + `ruby2shell-leak-maps.py`,
post-response `/proc/PID/maps` read outside the request path) shows the
pair partner pins the request-thread glibc arena region base
(region+{0x8c660,0x8c760,0x8cdb0}, 11/11 victim-correlated — tcache key
wire-known) and the live instance's other pointer is a Ruby GC-page
address (`[anon:Ruby:GC:...]`), replacing `ObjectSpace.dump`. Structural
negatives: the worker-arena bin heads are in-region, so this channel can
never leak libc; zero attacker-chosen `0x53`-runs in 432 parameter-bearing
responses; a second attack on a leak survivor aborts 3/3. First oracle
measured; full stock/oracle-free/persistent R5 stays NOT ACHIEVED.

The 2026-11-25 fifth push closes Ruby2Shell's consH-20 low-byte tcache
retarget lead as a bounded negative
(`lab/repro/ruby2shell-consH20-retarget.sh`, 144 fresh processes of the
N=524 case probe on the unmodified `rails new --minimal` app). Eleven runs
survived and 52 showed a real unsorted expansion, but only one ever returned
an allocation into the forged window: its three pops were C-internal
fixed-size requests (`0x3`, `0x10`, `0x28` bytes) with one on-thread free,
and the victim content was the fixed `0x53` upcase byte, not attacker-shaped
input. The overflow byte changed the victim's size field (`0x201`→`0x253`),
not the fake `0x20` chunk's tcache `next`, so no oracle-free Stage-B analog
was steered. Stock/oracle-free/persistent R5 stays NOT ACHIEVED; the
witness-ESTABLISHED harness-condition R5 cell is unchanged.
The 2026-11-25 main-arena lead is also closed as a bounded negative
(`lab/repro/ruby2shell-mainarena-leak.sh`, 12 fresh `rails new --minimal`
processes at `MALLOC_ARENA_MAX=1`, then 12 more at an N=532 body). Victims
landed in `[heap]` 16/16, and two N=524 victims held a real libc pointer in
their `fd=bk` (`libc.so.6 +0x203b20`, maps-confirmed), but every survivor's
reflected 404 params were byte-clean: 544 parts, zero pointer-shaped qwords.
The +8 length shift changed the chunk size class, not the write offset, so
the byte still hit the victim SIZE field. No libc/code-base oracle from this
route. The same arm with 48 drain parts and filler-first order aborted 11/12
pre-response; its one survivor was byte-clean too, closing the count/order
knobs on both geometries. Stock/oracle-free/persistent R5 stays NOT ACHIEVED.

The 2026-11-26 Ruby W31 push expands the main-arena sample and closes all
three geometries for the missing libc oracle. A 48-process replay of one
byte-identical 36,948-byte wire body (`RUBY2SHELL_MAINARENA_COUNT=48
RUBY2SHELL_MAINARENA_TAG=mainarena48x bash
lab/repro/ruby2shell-mainarena-leak.sh`) gave 3 survivors with maps, 102
reflected parts and a single qword `0x00007690dcb45fd0` resolving to a Ruby
GC heap page (`[anon:Ruby:GC:default:heap_page_body_allocate]+0x445fd0`),
not libc or code. Drain-count bodies at 36 parts (18/24 aborted pre-response;
3 survivors byte-clean) and 40 parts (after the driver's TERM-then-KILL fix;
2 survivors, 84 parts, 0 deviations and 0 leak-shaped qwords) are also
negatives. Grades unchanged: rung 4 witness-COMPLETE, harness-condition rung 5
witness-ESTABLISHED, stock/oracle-free/persistent r5 NOT ACHIEVED.

The 2026-11-25 tenth push answers Ruby2Shell's shrink-family claim
question (`lab/repro/ruby2shell-shrink-claim.sh`, 48 fresh `rails new
--minimal` processes in four arms: N=588 planted/unplanted, N=892
planted, N=988 planted with 40×920B chosen-strip plants; each run
sends an optional benign plant, the consH20-tail attack body
(byte-verified against the cov-n588 geometry), a benign
matched-class claim, then `/up`). No matched-class claim ever popped
a corrupted chunk: plant churn moves victims to tiny/fresh classes;
big unplanted binned victims abort during the attack at the request's
own unsorted consumers (7/7); surviving corrupted classes sit below
the ~809B plant floor; planted-band grown victims (0x411/0x415→0x453)
rest in their original 0x410-band bin where matched claims fit
without overshoot, and the big planted-band victims (0x411/0x471/
0x601→0x453/0x653) all abort during the attack. Two N=988 runs
complete attack, claim AND `/up` 200 carrying an untriggered corrupted
IN-USE small chunk (real pairs `0x95→0x53`/`0x35→0x53` after a B/A
pairing correction — the earlier "binned 0x453" reading spliced pairs
from different phases). Structural closure: the 0x53 byte
always sets IS_MMAPPED, so every consumer that `free()`s the
corrupted chunk aborts in `munmap_chunk` (measured); only
neighbor-consolidations survive, making Einherjar structurally the
only surviving consumer.
Stock/oracle-free/persistent R5 stays NOT ACHIEVED.

The 2026-11-25 eleventh and twelfth Ruby pushes' slice/sweep model is
superseded, not a current blocker. The measured correction is two content+9
slices plus one next-power-of-two value per embed-legal part, with glibc tcache
ending at chunk `0x420`. Order arms then falsified "big slices never sweep":
big-first freed 32 planted big slices across 3/12 runs, small-first freed 22
smalls across 2/12, and interleaving freed both classes. The earlier zero-`0x621`
result was an arm artifact, and the claimed `0x3E1` frees were mostly a
`0x3f0`-slice misread. Filler pressure does produce freed-in-unsorted victims,
but the corrected chain closes as described in the 16:3x–17:1x fold below.
Stock/oracle-free/persistent R5 stays NOT ACHIEVED.

The 2026-11-26 Ruby W30 push closes the fixed-length composition lever
(`a2839cf5`): at constant N=1500, 529 ASCII leading bytes move buffer2's
request from `0x5f2` into the `0x3e2` tcache class, but 18 vulnerable runs
return zero claims and zero other-pops of the grown victim across claim
classes `0x241`/`0x441`/`0x63f`; the fixed 3.4.13 control is 3/3 alive and
no bin residency can be inferred (`MTRACE_DUMP_BINS` emitted no `L` lines).
The tracer's `MTRACE_CASE_LEAD_A` knob is analysis-only and preserves every
earlier arm. Rung 4, the harness-condition rung 5 and the
stock/oracle-free/persistent r5 boundary are unchanged.

Pgactive2Shell W11 (`e8dd96f6`) corrects W8's saved-RA layout: objdump shows
`lea -0x70(%rbp),%r12`, canary at `rbp-0x28` (+72) and the real saved RA at
`rbp+8` (+120), overwritten from N>=128 with `41 5a` but never consumed
because the pinned `!=4` path leaves via `elog(ERROR)` longjmp. The earlier
`-40`/`-32` matches were stale observations, not this function's RA
(`reports/frontier-pgactive2shell.md` §saved-RA correction); the layout lane
is author-only and witness W209 is unchanged. Synchronet2Shell W20
(`1db3684f`, `63b54b1e`) traces shipped 3.20b commit `db9c5d6f…` through eight
pinned files from the 64-byte TERM copy into the 41-byte field to
`listFreeNodes` starting at `list->first` and `free(node)`: a chosen non-NULL
field would start teardown at a chosen pointer. Source-bound only, 17 PASS /
0 FAIL live and from `git archive 1db3684f` (normalized `e74779de…`), with no
build or dereference at that point. W26 later measures the shipped build's
whole-process SIGSEGV under concurrent load; see the latest fold below.

OpenEXR W197 (`cc39716b`) supersedes the earlier file-level "no chosen code
pointer/IP" boundary: an unmodified `exrcheck -c` reaches a file-chosen
`destroy_unpacked_func_ptr=0x555555661b30`, plain rc 139, fixed rc 1, five
matching hashes and a clean-archive receipt
(`reports/openexr2shell-file-level.md` §W197), author-only with no grade or
witness change. FontForge W16 (`c9c5b891`, `f1b223ca`) supersedes W12's
"byte 3 still only 0/1": a negative divisor makes byte 3 `0xff`, moving
`BDFChar.bitmap` from `0x0000555555c227f0` to `0x00005555ff0105fe` (PIE) or
`0x00000000ff0105fe` (non-PIE), both unmapped; `replay-negdiv.sh` 20/20 rc 0
and clean-archive receipts 17/17, 15/15 and 20/20. The nonnegative-RHS ceiling
`0x01FFFE00` stands; no grade, pointer dereference or r5.

The remaining edges are bounded negatives and receipts with no row change:
libgphoto2 W185's `priv` at `rbp-0x4068` lies outside the device-only write
reach; yojimbo W6's stock 262144/1024 fragment ends exactly at the allocation;
munt W187 needs a 32768-byte preconditioned capacity; gpgme W11 (`057e2e2a`,
receipt `20a42ca6`) measures a real-build `read_status` EOF early return that
needs no callback error; W10's full 0x410
tcache bin still aborts with chosen `0x48` at offset 1000 (26/0); libraw W21's
live top-chunk size field sits 550,184 bytes past `destimage` and free aborts
`invalid next size` (11/0); open5gs W2 resolves SBI framing with a 396-byte
`\r\n\r\n` body (harness 21/0); awslc W216's Node 22.11.0 exact-fit allocation
stays ASan-clean; knotresolver W21 finds no `system`/`popen`/`exec*` in PIE
`kresd`; cjose W209 and cicap W9 close wording and fold the earlier W211
witness verdict. No rung, grade, route, mind-count, witness verdict or r5 cell
moved by any of them.

The 01:5x–02:1xZ limbs supersede the Munt2Shell row's blanket "no pointer
control, marker" and the Libgphoto2Shell/Gpgme2Shell rows' scope lists below.
Gpgme W5 (`72f3b6ad`, replay receipt `844eed91`) combines W3's loopback HKP
key fetch with W4's next-operation reclaim in real GPGME 2.2.0 under ASan:
`sh run-wire-reuse.sh` printed 55 PASS / 0 FAIL, chosen `0x48`/`0x5a`/`0x37`
at offset 1000 of the wire-supplied `[GNUPG:] IMPORTED` status line, and the
second `gpgme_op_keylist_start()` frees the stale block in
`_gpgme_op_reset → gpg_release engine-gpg.c:602` after the first free by
`realloc` at `read_status engine-gpg.c:1494`; a clean archive of `72f3b6ad`
replayed six suites 55/32/24/21/36/19 PASS, all rc 0. Author-side only;
witness request #4028 with receipt #4029 has no verdict, no pointer/IP/command
and no r5. Libgphoto2 W180 (`018f76d5`, `97c61c79`, `73a38aed`) gives a
one-command replay, `sh lab/frontier/libgphoto2shell/live/replay-real-w177.sh`
(DRAIN auto-sweep 20..40, DRAIN=20 observed), from a clean archive of
`97c61c79`: 4/4 pins OK, tarball `5df9e774…f28`, patched vusb
`2b744f67…e57dde6`, `RESULT: 20 PASS / 0 FAIL`. Three own-canary records at
k=1023 (`OWN_CANARY=8a17bc30d6578900` etc.), three code/stack-shaped words at
k=1024 matched by read-only gdb, count=100 rc=-108 and the full reply aborted
with stack smashing; the disclosure still reaches a HOST consumer through
real `gp_camera_file_get()` on a lab-patched vusb reply, with no device
readback, wire path, command or r5, author-only and unwitnessed. Munt W186
(`31fd23fe`, `e224af08`) uses a 32785-byte short SysEx through real
`DefaultMidiStreamParser::parseStream()` and a harness-created `Victim` next
to the 32768-byte buffer: one input byte at index 32784 changes the low byte
of its function pointer (`0x67…` to `0x49…`, attack byte `0x49`) and calls
benign `marker_1` in the vulnerable plain build, while fixed and safe cases
do not; vulnerable ASan reports `WRITE of size 32785` 0 bytes past the real
32768-byte region. Clean-archive replay matched all six rc cases and seven
normalized evidence files (digest `b06a4b42…e7c`, quoted from
`PARTIAL_REPLAY.md`); the pointer and victim are harness-created, no real
library object with a function pointer at that offset was found, no ASLR
defeat, host/wire input, command or witness verdict, so witness #2781's
ESTABLISHED label stays scoped to the older real-library rungs 1-4 and rung 5
stays `—`. FontForge W12's corrected ceiling `0x01FFFE00` (not `0x0100FEFF`;
byte 3 later reached 0xff on W16's negative-divisor path, see below), recomputed locally as `value-ceiling-high.pcf`
`9a6b2603…f6b82` and `gdb-value-ceiling-high.out` `540d9b0b…091a0`, is folded
below; libsshch's 01:58Z handoff reran `sh harness/run-all.sh` 24 PASS /
0 FAIL with 9/9 pins and ASan `READ of size 32` at
`channel_default_bufferize`, with no new verdict. No rung cell, route, mind
count or R5 cell moved by any edge here.

The Pgactive2Shell row's "no full pgactive build" boundary applies to the
`sqlpath/` 16.15 harness, not to commit `20123ce2`: the author then built the
complete pinned 2.1.9 extension, loaded it into a loopback cluster with
`shared_preload_libraries=pgactive`, and the real SQL call gives ASan
`stack-buffer-overflow WRITE of size 161` at offset 96 of the 64-byte
`replication_name` region, frames `:351` and `pgactive.c:1531`; 2.1.10 rejects
and the plain 2.1.9 backend errors without crashing because `elog(ERROR)`
longjmps before the canary check. No chosen bytes on that SQL path, no
PUBLIC EXECUTE in either version, no replication wire, saved-pointer/IP,
command or r5; witness #3896 still covers only the original pinned harness.
Author-run; a clean `git archive 20123ce2` replay of all three `realbuild/`
scripts matched the rc matrix and the same `WRITE of size 161` frames
(`ba19500c`), still not an independent witness verdict. No grade change.

Pgactive W8 (`3c6304ba`) closes the saved-return-address route at the real
non-ASan 2.1.9 stack-layout scope: `realbuild/layout/run-layout.sh` adds one
noinline helper in the existing error branch and logs
`__builtin_return_address(0)` and a 320-byte window around
`replication_name`. In both the `-O1 -g` and PGXS production builds
(`LAYOUT_BUILD=0`, `LAYOUT_INITDB=0`, `LAYOUT_PGSTART=0`, `LIVENESS_RC=0`,
normal library and source restored) the parser's saved RA lies BELOW the
buffer at `-40` / `-32` bytes, while a second copy at `+104` / `+120` is
overwritten from N>=128 with `41 5a` repeats but is never consumed because
control leaves via `elog(ERROR)` longjmp, not `ret`. A `%s` store grows
upward from offset 0, so no input length reaches the consumed slot; no
backend terminated at any length and `SELECT 1` still succeeds. This is a
structural negative for a stronger rung 4 at this build, not a new
capability: the chosen-byte marker and the real-SQL ASan limb stay as
labeled, with no IP, command or r5. Gdb live attach remains denied by
`ptrace_scope=1`; the first failed layout script used a socket path over
PostgreSQL's 107-byte limit and was moved to `/tmp`.
`lab/frontier/pgactive2shell/realbuild/layout/FINDINGS.md`,
`reports/frontier-pgactive2shell.md`; author-side, unwitnessed, no grade
change.


The 02:29–02:4xZ limbs record the real-build plain-glibc result now folded
into the Gpgme2Shell row and add replay/caller-boundary detail to the
Open5gs2Shell row; no rung cell, grade, route, mind count or R5 cell moved.
Gpgme W6 (`3aaa3f07`, clean-archive receipt `67a874c2`) builds real GPGME
2.2.0 and the fix-patched copy without a sanitizer (`CFLAGS=-g -O0`,
`CC=clang`, static-only into `prefix-plain`): from
`lab/frontier/gpgme2shell/realbuild`, `sh build-plain.sh && sh run-plain.sh`
documents the lane and `sh run-plain.sh` printed `PASS=13 FAIL=0` rc 0 here.
On glibc 2.39 the vulnerable driver exits 134 with
`free(): double free detected in tcache 2` after
`status_cb call=1 op_marker=H keyword=GOOD arglen=1200 byte[1000]=0x48` and
no second keylist; the patched driver exits 0 with `op2 keylist_start
err=Success`, `op_marker=Z arglen=20` and `release done`. The tcache detector
aborts before allocator metadata or control-flow use: a negative rung-5
route, not a new capability. The parent statement harness's contradictory
plain revisions stay UNKNOWN in their own scope; #4039 is a witness scope
note with no verdict. `reports/gpgme2shell-status.md` §W6.

Open5gs W1 (`6d5f8de9`, replay receipt `318023f3`) records witness message
#3934 (witness wall W210) ESTABLISHED AS LABELED at the staged-harness scope
(clean `git archive 22d70741`, `sh harness/run.sh` 21 PASS / 0 FAIL rc 0,
trace SHA-256
`6c3c5ecf1f9e4ec7ef8d907d24e033e16fe4b87d62408ef1c499c95086164253`,
no grade change and NO r5), alongside the row's W217 label.
`lab/frontier/open5gs2shell/realcaller/` derives the boundary as pinned
`message-v2.8.0.c:3356-3381` does: the staged 394-byte body gives
`BOUNDARY_LEN=2 BOUNDARY=a:` and an ASan-clean canary, while adding one
leading CRLF (396 bytes) gives `BOUNDARY_LEN=0` and ASan `WRITE of size 1` at
`multipart_parser-v2.8.0.c:260`, with plain canary `5a5a...` ->
`0a000d0a000d0a000d0a000d` and fixed `RET=-1`. `sh realcaller/run.sh`
scored 15 PASS / 0 FAIL here, and a clean `git archive HEAD` replay at
`318023f3` reproduced 21/0 and 15/0. Whether a live SBI HTTP layer preserves
that leading CRLF in `http->content` stays UNKNOWN; no wire request, pointer,
command or r5.

N2n W5 (`1029f346`) extends W1/W2's consumed-pointer negative: four batches
of four hardware read watchpoints at `&nak+128/+136/+344/+432`,
`+368/+392/+400/+424`, `+464/+488/+504/+536` and
`+1608/+1616/+1632/+1640` never hit while the registered-peer run forwarded
the 134-byte NAK with `beyond48=485a4d49485a4d49`. The excluded `+288` trip
was a `sockbuf` store in `__vsnprintf_internal`, not a consumer read;
unwatched words stay UNKNOWN and the W3 forwarding data copy is still the
only measured consumer. Witness replay #3909 remains owed.
`reports/n2n2shell-live.md` §W5.

Libgphoto2 W181 (`12ca5894`) closes one W180-wall lane: pinned v2.5.34
`pins/jl2005c.h.vuln:31-44` places `Info table[0x4000]` last at offset
`0x40` in a `0x4040`-byte struct, with `data_cache` at `0x38`, and the
forward `memmove` at `jl2005c.c.vuln:154` cannot reach it; real consumers
use table bytes as data (`library.c:197-213`, `:338-341`,
`gphoto2-file.c:315-325`) and `gp_filesystem_number`
(`gphoto2-filesys.c:1365-1400`) has no negative index. The in-struct
natural-consumer-pointer lane is CLOSED at pinned source level, while a
natural pointer in a HEAP NEIGHBOUR of `priv` was not measured and stays
UNKNOWN. `cd lab/frontier/libgphoto2shell && sh harness/check.sh` stayed
`PASS=146 FAIL=0`, trace `e364f756…c6c98` (observed here); W170-W172's
lab-assisted pointer placements and witness #2892's rung-3 scope are
unmoved, author-only rung 4 and r5 UNKNOWN.

Libgphoto2 W197/W199 (`8ca09205`, `12bba987`) gives a from-scratch replay of
the device-only top-header lane: from a clean `git archive` of `8ca09205`,
`TARBALL=<pinned 2.5.34 tarball> sh lab/frontier/libgphoto2shell/live/replay-w197-clean-archive.sh`
checks the tarball SHA-256 `5df9e774…ff7f28` and the six-patch chain, rebuilds
GCC -O2 from scratch and derives its own top size under gdb. Observed: 4/4
pins OK, `fresh TOP=0x0000000000012b71` (the author build used `0x12bd1`, so
the word is build-specific, not device-observable), build-derived `jl2005c.so`
`55becbce…eb66e`, `RESULT: 12 PASS / 0 FAIL`, rc 0. That was an author replay
at the time; witness W257 later returned ESTABLISHED AS LABELED at this exact
lab rung-4 scope (verdict below). Grade unchanged, no wire, physical USB,
command or r5. Raw outputs stay in `/tmp/w199-lgp-replay`, recreated by the
wrapper on each run.

Libgphoto2 W200 (`66698fb4`) refines the W197/W199 top-word boundary: glibc's `sysmalloc` assertion at `malloc.c:2599` checks page congruence of `old_top + (size & ~7)`, not the measured top size, so the overflowed word's magnitude is not a host-derived secret — only its low 12 bits are build-specific (`0xbd1` author build, `0xb71` clean replay). `lab/frontier/libgphoto2shell/live/replay-w200-page-family.sh` gave `RESULT: 11 PASS / 0 FAIL` on both builds across three congruent magnitudes, one ASLR-on case and wrong-low-bit/over-large controls; wrong low bits abort in `sysmalloc` with rc 134. Congruence is not device-observable and a malicious device cycling candidates is an inference, since no wire path was tested; no canary, saved RIP, command, witness verdict or r5, grade unchanged.

Libsshch W1 (`a6893b10`, 02:4xZ) supersedes the row's "no real SSH build,
wire packet" clause at the 01:58Z staged scope. Full pinned ASan libssh
builds plus an authenticated 127.0.0.1 SSH replay, `sh
lab/frontier/libsshch2shell/real/run-all.sh`, scored 5 PASS / 0 FAIL here:
real KEX/password auth, channel open, a benign packet, then raw
`CHANNEL_CLOSE` followed by `CHANNEL_DATA`; ASan `READ of size 8` at
`channels.c:705:26` (120 bytes into the 128-byte channel) after the server
app frees the remotely closed channel in its data callback
(`real_wire.c:55`, not the report's `:52` citation), with
`SERVER data #2 len=21 first=M off16=-` from `MISHE-LIBSSH-UAF-WIRE`.
The fixed guard suppresses data #2 and both data-only controls are clean.
Rung 3 is now confirmed in a real build on a real loopback wire, but rung 4
stays PARTIAL under the stated application-free condition: the read is
freed channel metadata, not attacker bytes at a chosen freed offset; no
pointer/IP control, marker, command or r5. An authenticated peer is still
required, witness UNKNOWN, route 140 and window 148 unchanged; no rung cell,
grade or mind-count move.

FontForge W13 (`e2d45f1b`, author-side, grade-neutral) turns the real-build
offer into one command: with the pinned tarball supplied as `FF2S_TARBALL`,
`sh lab/frontier/fontforge2shell/replay-real.sh` rebuilds four offline trees
and asserts 17 build-path-independent rc cases (W8 `Open()` 134/0/1/0 plus
complete 0/0; W11 `Save()` 139/0/139 plain and 0/1/0/0 fixed-plain/ASan/
probe-ASan/fixed-ASan; W12 high ceiling 134/0/1/0), ending
`REPLAY_REAL_OK: 17/17 stable-lane checks passed` rc 0 here. W6/W7 consumer
rc stays informational because build-path sensitive; W12 gdb prints
`HIT glyph=-1 i=65535`, `$1 = 0x1fffe00` and `00 fe ff 01`, with
`value-ceiling-high.pcf` `9a6b2603…f6b82`. Live-tree and clean-archive
receipts both scored 17/17; the script's current sha256 `f633dd37…266a42`
supersedes W9's quoted `156dd583…acca9261` hash. Witness #3309 remains
scoped to direct-call rungs 1-4; no rung, route, window, mind-count, grade
or R5 cell moved.

OpenEXR W196 (`61468419`, clean-archive receipt `3ff078b1`) answers W195's
unmapped-pointer question at a labeled ASLR-off scope: in unmodified pinned
3.5.2 `exrcheck -c`, file-chosen bytes forge an `exr_attribute_t` in the
consumed `list->entries[0]` slot (`type=20`, `str` at `dst+1264`, size word
`0x91`, chosen `0x5a` bytes). With gdb ASLR off, `ATTR=0x555555828520`,
`STR=0x555555828590` and `FREE_RDI=STR`: the consumer's
`exr_attr_string_destroy()` reads chosen bytes and passes the chosen pointer
to the unchanged `ctxt->free_fn`. `cd lab/openexr2shell-real &&
sh harness/w196-chosen-free.sh` printed `RESULT PASS` rc 0 here with six
matching evidence hashes (free `4c6c3e13…bac5e7`, plain `19517f6f…369e6`);
a 02:54Z `git archive 61468419` replay (gitignored src/build/bin trees
symlinked) matched all six. Author replay, witness offered on tape #4048
with no verdict: mapped only with ASLR off in the debuggee, no chosen code
pointer/IP, wire, command, marker or r5; grade, rung, route, mind count and
r5 status unchanged.

The 03:0x–03:1xZ limbs supersede the Gpgme2Shell row's "no wire input" scope
and the Yojimbo2Shell row's harness-only boundary. No rung cell, grade,
route, mind count, witness verdict or R5 cell moved.

Gpgme W7 (`9633cfc8`, clean-archive replay `a1ecd700`) drives the advisory's
second affected reader through public APIs in real GPGME 2.2.0.
`realbuild/colon_reuse.c` and `fake-colongpg.py` emit exactly 1024 bytes with
no LF on the colon pipe; `read_colon_line()` consumes them to `readpos=1024`,
then its next call reallocs at `engine-gpg.c:1647`, reads EOF and returns at
`:1707` without the `:1728-1730` writeback. From
`lab/frontier/gpgme2shell/realbuild`, `sh run-colon.sh` needs no rebuild (the
`build-real.sh` binaries must exist) and printed `PASS=26 FAIL=0` rc 0 here.
The vulnerable 2.2.0 driver exits 1 with ASan `attempting double-free`:
second free in real `gpg_release engine-gpg.c:604` via
`_gpgme_engine_release → _gpgme_op_reset → gpgme_op_keylist_start
keylist.c:1295`, first free by `realloc read_colon_line :1647`, allocation at
`gpg_set_colon_line_handler :909`, and no second operation; the status
callback logs `arglen=1200 byte[1000]=0x48`. Fixed 2.2.0 and stock 2.3.1 exit
0, are sanitizer-clean, start op2 and log `byte[1000]=0x5a`; the
short-colon-line control is clean. A clean `git archive 9633cfc8` replay gave
`BUILD OK`, 26 PASS / 0 FAIL for `run-colon.sh` and 19 PASS / 0 FAIL for the
pinned `sh ../run.sh`, author-side only with no witness verdict. The raw
`evidence/colon-*.out` / `.rc` files are gitignored and regenerate with that
script; `reports/gpgme2shell-status.md` §W7.

Yojimbo W1 (`28d3c8c5`) and W1b (`ff6c5e02`, staging plan marked complete in
`30f77300`) close the staged row's "no real build, live UDP wire" boundary.
The real pinned parent `3c6b5e85…` was built under ASan with the fix commit's
`test.cpp`, bundled sodium (no system dev package) and
`cmake -S . -B build-asan-vuln -G Ninja -DCMAKE_BUILD_TYPE=Debug` with
`-fsanitize=address -fno-omit-frame-pointer -g` on C/CXX and the linker.
The regression reaches the pinned sink at
`source/yojimbo_reliable_ordered_channel.cpp:716` through
`ProcessPacketData :441 ← Connection::ProcessPacket
source/yojimbo_connection.cpp:340`: ASan `WRITE of size 500`, 0 bytes after
an 1100-byte region allocated at `yojimbo_reliable_ordered_channel.h:321`;
the fixed-channel control is clean. Authenticated netcode UDP loopback uses
client `0.0.0.0:30000`, server `127.0.0.1:40000`, `InsecureConnect` with an
all-zero local key, client `maxBlockSize=1100`/`blockFragmentSize=500`,
server `maxBlockSize=1500`, and a 1500-byte block whose full 500-byte final
fragment at offset 1000 carries `MISHE-LOOP` at block offset 1200. Without
gdb the vulnerable process faults in `Connection::Reset()
yojimbo_connection.cpp:172` (rc 1) with no ASan heap report — the receive
buffers come from the per-client TLSF pool — while the fixed control passes.
Under gdb a breakpoint at the pinned sink conditioned on
`fragmentId==2 && fragmentBytes==500` reads `MISHE-LOOP` byte-exact at
`blockData+1200`, 100 bytes past the 1100-byte buffer with 0xab filler at
+1100, after netcode decrypt; the frame chain includes
`Client::ProcessPacketFunction yojimbo_client.cpp:274`. The five named log
hashes were recomputed locally and matched §W1/W1b of
`reports/frontier-yojimbo2shell.md` (`6457e8d0…`, `1fe5adcf…`,
`27c4d806…`, `57cecbb0…`, `1ec75858…`). Rung 3 is CONFIRMED in the real
build and rung 4 DEMONSTRATED only at the named non-default-config,
post-auth, one-process, gdb-assisted scope — hence the unchanged `◐` cell.
No separate remote process, chosen command or r5; W2 below supersedes the
pointer/marker bound. Production use of a non-multiple block config and an independent
witness verdict stay UNKNOWN. The raw logs and `upstream/` tree are gitignored
and regenerate from the pinned clone and commands above; a staged-harness
smoke here scored 20 PASS / 0 FAIL with 7/7 pins.

Socat2Shell is ADMITTED at 03:3xZ under standing #6 as the 141st route
(staged by `4f3b7916`/W221; real-build correction `d7ea43d1`): CVE-2026-56123
(Socat security advisory 10, CWE-122, CVSS4 9.2 `AV:N/AC:H`), affected
1.8.0.0–1.8.1.1, fixed in 1.8.1.2 by making `dstdata[]` unsigned in
`xio-socks5.h`; source URLs, tarball and patch pins are in
`lab/frontier/socat2shell/PROVENANCE.md` and `src/pins.sha256`. A signed
`char` length byte 0xfb promotes to -5, so `bytes_to_read=2` while
`bytes_read=5`, and the negative count reaches real `readfull()` as SIZE_MAX.
The pinned-function harness prints `TOTAL pass=15 fail=0` from
`sh harness/run-all.sh`, but its ASan `WRITE of size 600` past a 262-byte
reply is a `memcpy` stand-in, not the shipped consumer. A real-build loopback
replay (`sh real/run-real.sh`, 9 PASS / 0 FAIL) builds unmodified socat
1.8.1.1 and 1.8.1.2 under clang ASan with `--disable-openssl`; a
127.0.0.1-only SOCKS5 server sends `05 00 00 03 fd` plus 600 chosen bytes.
The vulnerable build logs `W read(7, 0x512000000045, -1): Bad address`, exits
255 with **no ASan report**, while fixed and safe replies exit 0; real
`readfull()` (`sysutils.c:101-141`) passes SIZE_MAX to `read(2)`, which
returns EFAULT before storing any byte. Grade: rungs 1/2 only (deterministic
connection abort on a real build); rung 3 memory corruption and rung 4
chosen bytes are NOT established on the real consumer, rung 5 not attempted,
witness UNKNOWN. No pointer/IP, marker, command or r5. Route, both resolver
keys and the three wake units are minted (EXACT full-flag sync `written 3,
removed 0`), doctor GREEN; the existing handoff window 149 was adopted with
no duplicate. `reports/frontier-socat2shell.md`,
`reports/socat2shell-status.md`.

Ccextractor2Shell is ADMITTED at 04:4xZ under standing #6 as the 142nd route,
from the staged CCExtractor issue #2500 (opened 2026-11-24T13:58:29Z, still
open at 2026-11-25T04:07Z; no CVE/GHSA, no upstream fix PR, fix status
UNKNOWN). The pinned master `2c1c1c6f0602563d2064f2b0c36f13b3c7a09489`
derives a 24-bit `mpeg_pic_size` of 0x201000 (2101248) from four control bytes
and passes it to the verbatim `parse_mpeg_packet()` without a capacity check;
`buffered_read` is a stand-in `memcpy` and the structs/layout are stand-ins.
gcc ASan and clang ASan with `-fno-builtin-memcpy` report `WRITE of size
2101248` 0 bytes past a 2097272-byte region; clang ASan with default builtins
is a preserved negative. The plain slack build reads back the chosen repeating
`"MISHE-CCEX"` pattern at `BUFSIZE`, and a locally written bounds guard plus
the safe length are clean. Grade: rung 3 at the pinned-function scope, rung 4
PARTIAL in the stand-in layout, no real executable, GXF file or wire, no
pointer/IP/command and no r5; witness UNKNOWN. Hy4-flash route, both resolver
keys and three wake units minted (EXACT full-flag sync `written 3, removed 0`,
doctor GREEN, path enabled/active); window 150 adopted without a duplicate.

AwsLc W214 (`c8026e5a`, source-bound, author-side) narrows the row's
"out-of-tree application as the only real-consumer path" boundary: a read-only
census of out-of-tree application sources already provisioned in this plant
found no caller with two or more padded `EVP_DecryptUpdate` calls into a
documented-minimum buffer, so there is no adjacent attacker-relevant datum to
place. Ten named projects (cjose, GPGME, Open5GS, libssh/libssh2,
libwebsockets, Synchronet, PostgreSQL/pgactive, nginx, mod_auth_openidc,
apr-util) plus roughly fifty other provisioned roots were swept; four
representative hits were re-read — apr-util's `inlen + EVP_MAX_BLOCK_LENGTH`
(17 bytes slack) with one update, cjose's single CBC update on a fresh ctx
(its two-update path is GCM AAD with `out=NULL`), libwebsockets' disabled
padding and one cipher call, picotls' padding disabled on decrypt. No build,
ASan run, new artifact or witness replay; unprovisioned third-party
applications stay UNKNOWN, grade unchanged (rungs 1-4, r5 UNKNOWN).
`reports/awslc2shell-status.md` §W214.

The 03:3x–03:5xZ limbs strengthen the Yojimbo W1b scope with W2 and add four
source-bounded or build-bounded negatives. No rung cell, grade cell, route,
mind count, witness verdict or R5 cell moved by any of them.

Yojimbo W2 (`f25517f8`) carries the W1b wire path one step further: gdb shows
the 1100-byte receive block 605024 bytes into a 10 MiB TLSF arena, with the
adjacent channel vptr at `blockData+1152` overwritten by 0xAB filler (the W1
`Connection::Reset()` fault instruction reads `vptr+0x10`). The encrypted final
fragment instead writes a chosen 8-byte fake-vtable address there, and the
vulnerable non-PIE ASan binary prints `MISHE-VTABLE-CALL` twice before a later
`tlsf.c:583` crash; the fixed-channel control is clean. The five quoted W2 log
hashes (`fbc6c526…56a77d`, `5664351a…c0ec5`, `49fea203…42de89`,
`466f3181…45a`, `a9a03eed…d27e`) were recomputed locally and matched the
report. Conditions remain narrow: post-auth, one process, non-default config,
non-PIE lab build and pre-placed marker function. That is pointer control plus
a benign lab marker, not remote command execution and no ASLR-realistic
pointer derivation. `reports/frontier-yojimbo2shell.md` §W2.

Hping W8 (`bea93e82`, clean-archive receipt from `90d635d6`) rebuilds the same
pinned source with GCC 13.3.0 at `-O2`; Ubuntu's default `_FORTIFY_SOURCE 3`
compiles the copy to `__memcpy_chk` with the real 40-byte bound. Three crafted
loopback ICMP RR replies try to set `j`/`i`/`rc4_seedflag` and 155 sbox bytes,
but the vulnerable build ends in `*** buffer overflow detected ***` with no
crafted state at the `hp_rand` breakpoint (3 PASS / 0 FAIL); no-injection
baseline and locally patched `-O2` controls each score 4 PASS / 0 FAIL. The
clean replay `STAGE OK baseline 4 / attack 3 / fixed 4` and `REPLAY_O2_OK:
11 checks` came from `wire/replay-o2.sh`; an earlier runner-tag collision was
fixed before that run. This narrows the stock-glibc UNKNOWN to this host's
`-O2` build only; distribution packages and other fortify settings stay
UNKNOWN, author-side and unwitnessed. `reports/hping3shell-status.md` §W8.

Socat W2 (`1a34d2de`) closes the consumer question. The pinned real tree's
`sycls.c:539-558` `Read()` is an unconditional `read(2)` under every configure
option, and `xio-socks5.c:419-427,467-470` yields counts of `-1..-5` (as
`SIZE_MAX..SIZE_MAX-4`) for length bytes `0xf9..0xff`, with `0xf8` ending the
loop after the first 5-byte read. `sh real/run-count-probe.sh` scored 8 PASS /
0 FAIL on loopback socketpairs: those huge counts return `errno=14` EFAULT
with zero canary stores, while a `0x80000000` control does store. 32-bit
`size_t` is UNKNOWN (no multilib here). The advisory is a remote
connection-abort bug on this host, rung 1/2 only; a claim of a write must show
it through real `readfull()` under ASan with fixed/safe controls.
`reports/frontier-socat2shell.md` §W2.

AwsLc W215 (`93b61d8d`, source-bound, author-side) provisions pinned s2n-tls
v1.5.16 (tarball `ab3e19f8…909214`, recomputed locally) and reads every
non-test decrypt site. Each CBC-capable path re-inits then makes exactly one
`EVP_DecryptUpdate` into an in-place, block-aligned blob; stream ciphers have
`b=1` and AEAD uses `EVP_AEAD_CTX_open`; pinned `cipher.c:190` clears
`final_used` on every init, so no withheld-block carry crosses records, and no
buffer is sized `in_len+b-1`. SOURCE-BOUND NEGATIVE for the advisory's
precondition; no build, ASan run or witness replay, grade unchanged.
`reports/awslc2shell-status.md` §W215.

Synchronet W18 (`b60fd1b4`/`b67db0dc`) checks four raw files from tag
`sbbs321e` (`d2a6dcb2`): same no-size getter plus NUL clamp and byte-identical
field block, `VERSION "3.21"/REVISION 'e'`, `TELNET_TERM_MAXLEN 40`;
`sh release-label/run-release321e.sh` scored 11 PASS / 0 FAIL live and from a
clean `git archive b60fd1b4`, normalized `bb9067cf…2a5a3fbda9` (recovered from
`REPLAY.md`). Source-level only, no build, wire session or runtime bytes, no
rung change and no claim about 3.20b or other releases.

Pgactive W9 (`6fb104bb`) measures catalog-origin preconditions on a loopback
PostgreSQL 16.15 cluster with the full pinned 2.1.9 library:
`pg_replication_origin_create()` accepts 66/67/99/275-byte names, but the
`pgactive_get_global_locks_info()` route stayed in state `b` with a
not-configured error (UNKNOWN, not demonstrated); slot names truncate 96→63
bytes and a plain `LOGIN` role has neither origin-create nor parser EXECUTE.
No wire trigger, no grade change.
`reports/frontier-pgactive2shell.md` §catalog-derived origin-name reachability.

The 01:1x–01:4xZ limbs supersede the row sentences that say Synchronet has
"no measured DoS", N2n2Shell has "no control of a consumed pointer" without
the W3 forwarding consumer, FontForge's overwritten word is a live `char*`
never dereferenced, CodebaseMemory's canary argument holds at any stride, and
OpenEXR's W192 pointer placement explains the observed fault. All remain
author-only and unwitnessed; no rung cell, grade, route, mind count or R5
cell moved.

OpenEXR W193 put three distinct file-chosen words into live `exr_attribute_t*`
slot `E[2]` of unmodified `exrcheck -c` (plain rc 139), but W194
(`dff3426d`/`1d68f9d8`/`b6e68db8`) disproved attribution: with ASLR explicitly
on (`set disable-randomization off`) the first `exr_attr_list_destroy`
dereference at `attributes.c:305` reads `E[0]=0x555555828210`, a stale
absolute address captured in W192's forged source dump; changing the chosen
`E[2]` never changes the faulting address. W194 also corrects W193's "ASLR
left enabled" wording — gdb's `disable-randomization` defaults to on — and an
ASLR-off `setarch -R` control exits rc 1 printing `bad` for all three PoCs
with no SIGSEGV. Clean-archive receipt at `1d68f9d8`; evidence hashes in
`reports/openexr2shell-file-level.md` §W194. Still no chosen code pointer/IP,
wire, command or r5.

OpenEXR W195 (`reports/openexr2shell-file-level.md` §W195) finds the slot the
consumer actually dereferences: with ASLR on in the debuggee the loop at
`attributes.c:305` reads `list->entries[0]` at `outPtr+4176` (not W193/W194's
guessed `list+16`), and eight file-chosen bytes `0x4141414141414141` placed
there are the faulting register (`FAULT_R13=0x4141414141414141` at
`mov 0x14(%r13),%eax`). `cd lab/openexr2shell-real && sh
harness/w195-chosen-deref.sh` printed `RESULT PASS` rc 0, with three raw
probes and two byte-identical replays; plain rc 139, valid rc 0 `OK`, fixed
3.5.3 rc 1 `bad`, and a 02:21Z clean-archive receipt from `git archive HEAD
lab/openexr2shell-real` matched all five evidence hashes. Author replay, not
a witness verdict: the chosen value is unmapped, no chosen data read, IP,
command, wire or r5 follows; the row's rung 4 stays PARTIAL.


FontForge W11 (`f3b9dd98`) corrects W10's object label: the word at `encs-200`
is `BDFChar.bitmap` (`chunkalloc` = `calloc(104)`, `bitmap` at +24), not a
live `char*` — `x/s` had printed `""` from a one-byte zero bitmap. Adding
`Save()` to the poisoned `Import()` makes the real plain process dereference
the file-chosen pointer through `bSave:1891 → SFDWriteBakExtended → SFDDump
→ SFDDumpBitmapFont → SFDDumpBitmapChar` (`sfd.c:1671`): rc 139 at
`0x0000555500414243` with three chosen bytes, and rc 139 at
`0x000055550100FEFF` on W10's claimed-ceiling input. The reachable window
`0x0000555500000000..0x0000555501FFFE00` is below the lowest PIE mapping,
so there is no chosen mapped target, full pointer/IP, marker, command or r5;
a second `Import()` without `Save()` still exits 0 and patched/in-bounds
controls stay clean. `lab/frontier/fontforge2shell/DEREF.md`.

FontForge W12 (`CEILING-CORRECTION.md`, author-side, no grade change) corrects
W10's "hard ceiling" overclaim: with `d=max2-min2+1=1` and the truncated glyph
at `i=65535`, the real plain build writes `0x01FFFE00` at `encs-4` (bytes
`00 fe ff 01`, watchpoint word `0x01fffe0000000021`, plain rc 134, patched
0, ASan 1 at `:1751`). The true maximum is `0x01FFFE00`, not `0x0100FEFF`,
but W16 later reaches byte 3 `0xff`, still unmapped; no r5.

CodebaseMemory W14 (`8e973719`) measures far strides against the live
`[stack]` mapping: the OOB destination advances 512 bytes per projection
item, and main's estimated saved RIP (`callee_rbp+0x4198` = `SP+0x40a0`,
16,544 bytes) lay above the mapping end in 16 live-ASLR placements (smallest
`STACK_TOP-SP=0x1108`, 4,360 bytes), while twelve 71-item/478-byte attempts
exited 139 in `memcpy`. W12's `col_names` fault at N=1135 remains a separate
blocker for huge counts, not the nearest bound, and W14 retracts W12's
absolute claim that a C string cannot carry pointer-zero bytes. Chosen bytes
reach caller-frame storage, with no live pointer use, IP, command or r5.

Synchronet W16 (`be7d19a2`, clean replay `f369f7b3`) closes the missing DoS
measurement under the pinned default config with a valid password:
`run-validuser-availability.sh` sets `line_delay=0x4853494d` (~14-day
nanosleep) on four real `sbbs3` nodes with chosen 64-byte TERMs, parks four
`sbbs/termNode` threads in `hrtimer_nanosleep` and the fifth login is refused
`!No nodes available for login.`; the upstream fixed form serves five
sessions. Both forms score 10 PASS / 0 FAIL with zero `SSH_ANYAUTH` lines;
the two pre-repair failures (a misplaced assertion and a TIME_WAIT bind race)
are preserved as tooling defects. Author replay from `git archive be7d19a2`,
witness verdict still confined to wake 189's synthetic-struct scope; no
pointer/IP, command, grade change or r5. `REPLAY-W16.md`.

N2n W3 (`7e939185`, `d8bec71b`) adds a real consumer: with a registered
loopback peer the forwarding encoder reads the overwritten token bytes as
DATA in `memcpy(len=96, src=nak+14)` ← `encode_buf` (`wire.c:162`) ←
`encode_REGISTER_SUPER_NAK` (`wire.c:631`) and re-emits a 134-byte NAK, while
the 48-byte safe control emits 86 bytes. The one-line decode bound stops the
WRITE but leaves a fixed-build ASan `READ of size 96` on the peer path (the
earlier clean fixed control had no peer). A 2048-byte `recvfrom` caps the
write at `nak+2024`, 1,488/1,552 bytes short of the canary at `nak+3512` and
saved RIP at `nak+3576`; `token_size=2000` left the canary intact and a 3550-
byte datagram caused no abort. W4 (`f18dd8bf`, `e9351342`) gives a one-command
clean-room replay, `sh lab/frontier/n2n2shell/live/replay-live.sh`, observed
22 PASS / 0 FAIL here after W3 was folded in, including four live gdb chosen-word
checks and checks 20-22 for the peer's 86-byte safe and 134-byte attack NAKs.
No consumed pointer, control-flow
takeover, marker, command or r5; witness replay #3909 remains owed.
`reports/n2n2shell-live.md` §§W3/W4.

N2n W6 (`ac451b00`) checks the fixed build's surviving encoder read on a plain
gcc `-O1` supernode: the rejected NAK decode leaves `token_size=96` on the wire,
but the 96 bytes read from `nak+14` are ZERO (`first=0000000000000000`,
`beyond48=0000000000000000`), so this path discloses no stack data. The fixed
ASan build still aborts on that read with a peer (W3), and other builds or
preceding traffic remain UNKNOWN. The one-line control matches the vendor NAK
guard byte-for-byte but is not a full fixed-tree build. No rung or grade move.
`reports/n2n2shell-live.md` §W6.

The 19:0xZ cicap2shell W3 limb supplies the real-server evidence summarized
in the row. `lab/frontier/cicap2shell/realbuild/live/run.sh` starts the real
pinned 0.6.5 ASan `c-icap` server on 127.0.0.1 with its echo service and
sends one crafted request: six-entity REQMOD reaches the server's own
`parse_header request.c:529` -> `process_encapsulated request_common.c:507`
and ends in the `header.c:631` UAF at teardown; the six-entity OPTIONS
variant with `Connection: close` returns 200 OK before the same UAF on
shutdown. Stock `MaxRequestsReallocateMem 100` and an immediate-teardown 0
setting both reproduce it. Four-entity, one-entity valid and patch-derived
fixed controls are clean; an OPTIONS request without `Connection: close`
shuts down cleanly because keepalive resets the aliased slot. Loopback only,
no proxy or real client, no pointer/IP/command control, no allocator
metadata and no r5; W3/W4 were author-measured and are witness-ESTABLISHED
as labeled by W211 (#3953). Evidence and
commands: `realbuild/live/README.md`, `reports/frontier-cicap2shell.md` §W3/W4.

Scope corrections to earlier rows, measured against the cited reports:
CodebaseMemory2Shell's "no HTTP transport" boundary is W1's stdio-only lane;
W9 reaches the same sink through the pinned server's 127.0.0.1-only HTTP
`/rpc` transport and W11 clean-archive replayed all three rows (4/4 pins),
still with no remote/off-host request, witness verdict or r5. FontForge's
single-import consumer claim is W5's scope: W6 found gettext's `malloc(128)`
and W7 `props = malloc(96)` returning the poisoned chunk on later imports,
and W8 reached the same pinned `fvimportbdf.c:1751` write through real
`Open()`; all author-side and outside witness #3309's direct-call verdict.
Imgproxy's W11b route stayed untested rather than negative: W12 gated a
second GET on the live poisoned head (eight of 98 loopback runs fired the
gate; four aborted in `malloc(): unaligned tcache chunk detected`, four
served HTTP 200 with 379 natural `malloc(0x20)` calls, all `WIRE=0`), and W13
found zero code pointers in three post-write windows across 64 executable
mappings — a bounded layout negative, not r5. Vrpn's "no wire-chosen byte
survives in a live caller" means a live control-flow slot: W29/W30 mapped
sender -2 onto `d_udpInbuf` and sender -3 storing `remote_id`/`local_id` onto
live `d_tcpInbuf`, so a second TCP message drops the connection; no chosen
destination address, command or r5, and sender -3 must not be reswept on
those binaries. OpenEXR's OpenImageIO consumer is a W173 static-source
negative (flat `read_image()` on the deep PoC cannot reach the sink; a truly
flat EXR cannot trigger it) and W169 confirmed the aarch64 claim under
qemu-aarch64-static 8.2.2 at the same file-level scope (`PASS=10`, no native
host or r5). W190 supersedes W188's harness-grooming bound: N=1072 makes the
second inverse-sort copy reach a live 0x90 tcache head in UNMODIFIED pinned
`exrcheck -c`, and file fill bytes (`0x5a`, `0x3c`, `0x00`) replace its
safe-linked `next` word; no malloc from that tcache was observed, the consumer
aborts in `double free or corruption (!prev)`, fixed 3.5.3 rejects, and the
clean-archive replay (`ecf3f821`) is author-only. Still no code pointer/IP,
command, marker, wire, witness verdict or r5. Libheif's 36,879-byte allocation
was reproduced by W181 from a
different crafted file (`check_advisory_size.py`, 11 PASS); the advisory's
exact 1,155-byte input and x265-pointer claim remain untested. LibRaw W15
adds a third independently file-chosen 16-bit value (`0x2468`, raw rows
150..159) in a disjoint OOB heap band alongside W13/W14's values; still not
an arbitrary byte sequence, with no pointer/IP, command, adjacent live object
or r5, author-side and unwitnessed. Reports:
`reports/codebasememory2shell-status.md`, `reports/frontier-fontforge2shell.md`,
`reports/frontier-imgproxy2shell.md`, `reports/vrpn2shell.md`,
`reports/openexr2shell-status.md` §W190, `reports/openexr2shell-file-level.md`,
`reports/libheif2shell-status.md`, `reports/frontier-libraw2shell.md` §W15.

Later scope corrections from the post-`d40ddefd` edges (all author-only and
unwitnessed unless a verdict is named; no rung cell moves): Assimp W22 puts a
file-chosen object pointer and fake `aiMesh` in the live scene, and W24 makes a
document-chosen saved return address call a benign marker in a plain lab build
(`TAUF_MARKER_CALLED`); no shell command, remote path or r5. Gpgme W2 reaches
the double free through a real `/usr/bin/gpg` (36 PASS), W3 through
attacker-chosen loopback HTTP key bytes on 127.0.0.1:11372 (32 PASS,
wire-visible rung 4), W4 through a second keylist (24 PASS); no pointer/IP/
command or r5. CodebaseMemory W12 narrows the C-string canary negative to
populated writes: an empty item-38 property skips the `memcpy`, later strides
pass the saved RIP into caller-frame storage with RC=0, and the ancestor RIP
stays unreachable because `col_names` caps at 32. Imgproxy W14 corrects W13's
classifier (two code-shaped qwords were pre-existing outside the written span);
`replay-w13.sh` returns `REPLAY_W13_OK` 3/3 with `code_ptr_qwords=0`. Libgphoto2
W177 reads the frame canary and saved rbp/RIP through real
`gp_camera_file_get(GP_FILE_TYPE_RAW)` at `library.c:213` without device
readback, and W178's short-reply vusb patch has a clean 146 PASS / 0 FAIL
replay. OpenEXR's stale "resume cmake --build … when host load permits" and
"aarch64 remains untested" clauses are superseded by W173's static-source
negative and W169's qemu-aarch64 `PASS=10`; W191 explains W190's abort (COPY1
zeroes the next-chunk header before COPY2) and W192 (`N=768`, `U=4N`) places
file bytes in a live tcache `next` with COPY1 in bounds but no malloc
consuming it. Cicap W6 finds a plain-real-library teardown negative with no
wire bytes, and W7/W8's `replay-all.sh` covers W1/W2/W3/W4/W6 with 72 PASS /
0 FAIL from a clean archive including self-fetch. Jq's second-advisory lane
is a named 32-bit negative: no i386 multilib, so `-m32` cannot link even a
trivial program; no build, guard or grade change. Reports:
`reports/frontier-assimp2shell.md`, `reports/gpgme2shell-status.md`,
`reports/codebasememory2shell-status.md`,
`reports/frontier-imgproxy2shell.md`,
`reports/frontier-libgphoto2shell.md`,
`reports/openexr2shell-file-level.md`, `reports/cicap2shell-status.md`,
`reports/jq2shell-status.md`.

Newer post-`7f1d85db` limbs (author-side, unwitnessed unless a verdict is
named; no rung cell moves): FontForge W9's `replay-real.sh` repeats the W8
`Open()` matrix RC 134/1/0/0 with the same ASan `WRITE of size 4` and chosen
`4d 49 53 00`, but W6/W7 consumer exit codes are build-path sensitive (clean
`/tmp/lab/...` trees exit 134/139 where the live build exits 0), so those
consumer claims stay scoped to `CONSUME.md`/`FILECHOICE.md`. Hping W5's
`rng-proof.sh` measured changed RNG destinations (baseline 4 PASS / 0 FAIL,
attack 6 PASS / 0 FAIL); W6 (`650f9517`..`bf1360dd`) fills all 187 reply-
reachable `rc4_sbox` bytes with a chosen constant and steers the low byte of
later `--rand-dest` probe destinations with no debugger steering — 15/16 and
17/17 in the final clean replay, but probabilistic (hidden `i`/`j`, 69
unreachable sbox bytes), with baseline and patched controls 4 PASS / 0 FAIL
each and `replay-rngctl.sh` 20 checks rc 0 from `659f6eb0`. No full IP, pointer,
command or r5 follows.
LibRaw W16 adds `replay-all.sh` for W13/W14/W15 (`PASS=31 FAIL=0`, also from a
clean `git archive 81392c3c`), and W17 sends the W15 DNG over loopback TCP into
a live in-process LibRaw ASan consumer with `WIRE_OOB_OK` in three fresh runs,
clean no-option and fixed decoders, no marker, pointer or rung 5; the row's
"network" boundary means no real camera/network appliance path. PHP's wake-59
tfm chain takes the same 126714 promoted session into tinyfilemanager 2.6, its
DESIGNED admin upload and live-worker execution of `/evil.php` (unique marker
and `id`) on 8.4.27-app, with fixed/no-kill/virgin-sid controls clean; every
stock attacker-caused death mechanism was measured NEGATIVE (SIGTERM handled
mid-pwrite, cgroup OOM only on truncate-first writes, page-quantized partials,
io.max/PHP fatals ineffective). The shim remains the only splice-producing
death; author-only, unwitnessed, R5 cell stays `—`. Reports:
`reports/frontier-fontforge2shell.md` §W9/W10, `reports/frontier-hping3shell.md`
§W5/W6, `reports/frontier-libraw2shell.md` §W16/W17,
`reports/php2shell-status.md` §Wake 59,
`lab/repro/php2shell-aftershell-splice-tfm.sh`.

The 00:4x–01:0xZ author limbs add no grade or verdict. FontForge W10
(`8781a538`) measured the `i=0` four-byte write value `0x0100FEFF` (W12 later
raised the true maximum to `0x01FFFE00`) and put three chosen bytes in a
pointer field at `encs-200` that W11 identified as `BDFChar.bitmap`, not a
`char*`; on that one `Import()` path it is not dereferenced. Synchronet W15
(`e0f11cd4`, replay `b595e239`) builds
a real `sbbs3` locally and reaches the copy after a valid password login under
the default config (4 PASS / 0 FAIL, `PROBE_COUNT=2`, `ANYAUTH_LOG_COUNT=0`);
pre-auth pty-req stays W9's negative. Assimp W25 (`aa2aedc7`, replay
`fda2b66c`) keeps the default-build canary at `dest+4` and the no-protector
saved-RIP high half `0x7fff` as preserved negatives (8 PASS / 0 FAIL, trace
sha256 `5532748382…e5d6fa5f864`, byte-identical from a clean archive). All
three are author-side and unwitnessed; reports:
`reports/frontier-fontforge2shell.md` §W10,
`reports/frontier-synchronet2shell.md` §W15,
`reports/frontier-assimp2shell.md` §W25.

The 15:5x–17:3xZ libraw W11/W12 limbs refine the row's ceiling without moving
a rung cell. W11 (`9bc81c2b`) sets DNG LinearizationTable plus WhiteLevel 65535
to put a file-chosen arbitrary 16-bit value in one halfword at index 68,644
(`0xbeef`, `0x1337`, `0x00a5` each exact 3/3, edges `0x0001`/`0xffff` once);
W12 (`32c3e2ac`) shows BlackLevel is only a coupled global fine shift of the
remaining interpolation-determined halfwords, not a second independent knob
(coupled shift `ffff beed fe91` at BL=6 vs `ffff beef fe93` at BL=0). Both are
author-side and unwitnessed: no arbitrary byte sequence, pointer/IP, command
or r5. Recipes and expected bytes are in `docs/reproducibility.md`.

The 10:4xZ witness verdicts supersede the "unwitnessed" wording in the last
two rows without moving a rung cell. Witness W193 (#3530) replayed awslc2shell
from a clean `git archive 0714868` with its own three builds and 14 PASS /
0 FAIL: rungs 1-3 ESTABLISHED in the real pinned AWS-LC library, rung 4 PARTIAL
for one compile-time chosen byte, NO r5, no wire, no pointer/IP/command. The
new synthetic-consumer pointer-redirect claim (`07fb523`, chat #3535) is
author-only and its replay was requested at #3538. Witness W194 (#3534)
replayed thorvg2shell from a clean `git archive 24d449a` with six builds it
configured itself: all three parts — public API / plain `.jpg` / loopback wire,
the no-pointer crash-mechanism negative, and the embedded Lottie-JPEG asset —
ESTABLISHED AS LABELED, with vulnerable/fixed/safe controls and NO r5. No
contradiction to either row grade.

The 11:1xZ witness W195 verdict (#3550/#3551) closes the earlier awslc gap:
from a clean `git archive 07fb523` the witness rebuilt both pinned AWS-LC
libraries itself, compiled the synthetic consumer against its own libs and
replayed `run-consumer.sh` 11 PASS / 0 FAIL. A byte dump and exhaustive
256-byte sweep confirmed the wire-borne `0x48` steers the dispatch-pointer
LSB into the benign marker only on the vulnerable library.
**ESTABLISHED AS LABELED** — rung-4 pointer-LSB control in a synthetic
loopback consumer, NO r5, no real app, no command. Scope NITs: hand-aligned
256-slot table with only slots 0/9 populated; the no-ASan PASS is specific to
`0x48`. This supersedes the "unwitnessed" wording in the AwsLc2Shell row and
the "author-only / replay requested" sentence above; no rung cell changes.

The 08:4x–12:0xZ libgphoto2 W170/W171 limbs supersede that row's "pointer
control" ceiling at the author-only scope. W170 (`fcbde70`) placed a live
`CameraFile` at `priv+0x4050` in the plain real 2.5.34 build by draining 24
same-size tcache entries; the `:154` overflow reaches its
`accesstype/size/data` fields, and with a lab-supplied canary and saved RIP
the real `gp_file_get_data_and_size()` returned device-chosen
`data=0x1122334455667788 size=0x1a2b3c4d` — a chosen pointer at a real API,
never dereferenced. W171 (`930ddef`) additionally restored `camera_init`'s
frame so `jl2005c_init()` returns normally (rc=0); with drain 22 the real API
returned a device-chosen pointer and length 0x1d, and dereferencing them read
the chosen `M2SHELL_DEREF_MARKER_20261124`. Safe fill, count 100, wrong
canary, fixed camlib and omitted-restore controls are recorded. In W171
`gp_file_save()` aborted on corrupted top size, so that dereference was the
probe's; W172 (`833729ad`) keeps four live guard chunks after the victim from
the lab vusb bulk-read hook, so the 464-byte `:154` overflow stops inside the
guards. The real `gp_file_save()` then returns `rc=0` and writes a 29-byte
host file containing the device-chosen `M2SHELL_DEREF_MARKER_20261124`; the
matched `M2SHELL_VUSB_GUARDS=0` control returns the same pointer but aborts
at corrupted top size and leaves a 0-byte file. Count 100, zeroed
`DATA`/`SIZE`, fixed camlib and fix reversal are recorded. W172 extends rung 4
to a real consumer write with an observed file side effect, still lab-assisted
(probe-supplied pointer, gdb-read canary and registers, lab heap placement,
synthetic replies), unwitnessed, with no USB/wire/command path, NO r5 and no
row grade change; witness #2892 stays
scoped to rung 3. Evidence: `reports/frontier-libgphoto2shell.md`,
`reports/libgphoto2shell-status.md`,
`lab/frontier/libgphoto2shell/evidence/real-plain-heap-pointer-control.out`
and `real-plain-normal-return-deref.out`.


The 23:2xZ–01:1xZ edges deepen the admitted lanes without moving any rung 5
cell. The following row sentences are superseded by this paragraph and the
sections named below; all remain author-only unless a verdict is quoted.
Ndpi2Shell's row still says "no witness verdict": witnesses #2999/#3001
replayed `realbuild/run.sh` 9/9 twice from a clean `git archive 44be53e` with
both ASan libraries rebuilt from source and graded **ESTABLISHED rungs 1-4 at
the real-pinned-library / in-tree-caller ASan scope, NOT rung 5**; the chosen
`0x2f` byte lands at `ndpi_serializer.c:107` via
`ndpi_serialize_start_of_block_binary:2340`, no in-tree wire path supplies a
>128-byte key (`reports/frontier-ndpi2shell.md` §7).
Sdlmixer2Shell W181 puts the crafted bytes on a loopback 127.0.0.1:19442 wire,
W182 reaches `FetchXLaw` with an unmodified upstream stereo A-law WAV
(`M1F1-Alaw-AFsp.wav`, sha256 `cfbc1821…`), W183 drives the unmodified upstream
`testmixer` CLI (`PASS=6 FAIL=0`), and W184 measures a partial saved-RIP
overwrite that is not a mapped target — the LUT words cannot steer RIP.
Witness #3000 covers W179's real-caller scope only; W180/W183 replay ask #3053
has no verdict. Libvips W14 sends crafted TIFF request bytes to a loopback
consumer (13/13 PASS, fixed build rejects `image: dimension overflow`) and W15
records the downstream claim that imgproxy 4.0.0–4.0.5 bundled libvips 8.18.2
while >=4.0.6 bundled >=8.18.3; W1/W2 built pinned imgproxy binaries and served
crafted ICO/TIFF bytes over loopback HTTP. W2's fine.tif timeout is WITHDRAWN as
queue starvation: an isolated one-request GET returns 422 "Source image
resolution is too big" at imgproxy's 50M-pixel guard in vulnerable 4.0.0 versus
500 `image: dimension overflow` in the fixed tree, before libvips header load.
Witness W185 (#3318) ESTABLISHED the ICO rungs 1-4 on clean replay and the HTTP
probes only at header/processing-entry scope, NO r5: no paint frame, chosen
byte, pointer or command in the endpoint.
Libfontenc W181's two-mapping identity ramp records 195840 OOB 16-bit stores
at `encparse.c:492`, and W183 overwrites mapping2's live `sm->map` through
seven mappings with chosen words; `FontEncRecode(254, mapping2)` returns
`0x5558` (`sh realpath/evidence/ptrctrl/run.sh`). W186 (`9246463`) replaces
the live `FontMapRec.recode` function pointer with a chosen non-PIE address
(`from=0xfe34..0xfe37`, indices 65584..65587, `m3->recode=0x4011d6`):
`FontEncRecode` prints `BENIGN_MARKER_EXECUTED` and returns `0xabcd1234` in
three vulnerable crafted runs, while safe and fixed `5920c6e` inputs show no
marker. That is chosen-address control flow at the real-library public API in
an ASLR-off harness, not a command; layout-independent redirection is blocked
because ASLR randomizes heap bits 12-15 while `setCode()` writes full 16-bit
words from a static file. OpenEXR W169 passed 10/10 under
qemu-aarch64; W170 read the source bytes, W171 mapped 19/20 clobbered heap
headers, W172 checked tiled geometry and earlier-chunk grooming as negatives,
and W173 resolved the OIIO claim as a **static-source negative** (flat EXR
geometry and OIIO dispatch block the sink). The Openexr2Shell row's "resume
the OIIO build" instruction is stale: no consumer was linked or run and the
claim is no longer merely UNTESTED. Libheif W179 exercised a benign marker,
W180 classified the advisory-size path under ASan, W181 reproduced the
36,879-byte allocation (`check_advisory_size.py` PASS=11), W182 measured plain
fault modes (PASS=30) and W183 decoded a genuine 512x72 first frame
(PASS=45); the row's earlier one-uniform-value ceiling is superseded only at
the labeled uncompressed-codec build. Cjose's W184 negative was independently
ESTABLISHED by witness DM #3079 (a deployed mod_auth_openidc rejects the
56-byte encrypted_key at `jwe.c:577` before AES-KW); W186 reached the real
`id_token` OCT-KEK unwrap and W187 selected the chosen-byte fault site in that
real consumer, without pointer or IP control. Munt W178 found a real malloc
neighbour (`delta=+32784`, 64/64 sentinel bytes, glibc `corrupted top size`)
and five one-byte C-API host entry points; third-party hosts remain unbuilt.
Imagemagick W189 isolates the `magick stream` CLI ASan `READ of size 24` at
`stream.c:1295` as **not** CVE-2026-130664: it survives a CVE-only fix, and a
bounded survey of this build's compiled coders found no cache-geometry growth
path (`lab/frontier/imagemagick2shell/CLI-ISOLATE.log`). Frontier W188 screened
hydra2shell out at rung 3 (fixed `-1` offset, fixed NUL byte, plain build
survives): no charter, route or window.

The 02:1x–04:0xZ edges add two witness verdicts and two staged lanes without
moving a rung 5 cell. Assimp W3's witness #3277 replayed clean `git archive
585e1c7` (13 PASS / 0 FAIL, normalized `913b23f5…3ca938`) and graded the
baseline direct-call scope **ESTABLISHED rungs 1-4, NO r5**; the later real
`ReadFileFromMemory` importer path (W1) and chosen bytes at a live vertex
array's end (W2) were explicitly outside that claim and stay author-measured.
SofiaSip W14's witness #3280 (W182) replayed clean `git archive 4d508dc` on
fresh loopback ports, confirming 95 timer adds and 16 live timer pointers over
a 19-byte neighbour, **ESTABLISHED at the labeled live plain v17 tport rung-4
scope**, with no grade change; the pinned static libraries were reused rather
than rebuilt from source, the same limit as W11/W164. CodebaseMemory W1 moves
that target beyond direct calls: a local stdio JSON-RPC `tools/call` to
`query_graph` on the reduced ASan server reaches `READ of size 8` and a
recover-mode `WRITE of size 68` at `func_bufs[32]`, with the fixed release
rejecting >32 items; only the C grammar was linked and the other grammars
stubbed for build time, so this is a reduced server build, local-only and
unwitnessed. Frontier W195 staged fltk2shell (real 1.4.5 BMP row-pointer wrap,
chosen "SIM-" before the array, 33 PASS) and W194 staged synchronet2shell
(64-byte TERM into a 41-byte field, chosen "MISH"/"E-OO"/"TAUFTAUF" in
adjacent session fields, 9 PASS), each with a clean-archive replay receipt;
both stay FRONTIER-STAGED with no charter, route, wake unit or mind-count
change. The remaining edges are replay receipts and bounded negatives —
openexr W174, libfontenc W189, kicad W186/W187, libheif W184, libvips W16,
libgphoto2 W169, imgproxy W1, cjose W188, vrpn W23, modauthoidc W19 and
knotresolver W19 — none of which changes a witnessed row grade. BusyBox W4
drove the same fallback over loopback with the host's Ubuntu 24.04
`busybox-static` 1.36.1 binary (seven legs: chosen top-size aborts, OACK and
no-`-b` controls clean), adding artifact-level reach to the already witnessed
rungs 1-4 scope with no new grade; witness acceptance still covers only the
earlier from-source matrix. CodebaseMemory W3 fixed the empty tool-path fixture,
added a zero-row failure guard, and rebuilt every row with per-query ASan
stderr: the reduced stdio `tools/call` path now replays the chosen-name
`WRITE of size 68` at `func_bufs[32]` in Q33/Q48 from a clean archive, closing
the replay gap but not the independent-witness gap.

The 05:1x–05:4xZ edges deepen admitted lanes without moving a rung cell.
Assimp W5 (`20cf486`/`4f3b254`/`075eaa0`) drives pinned MAT4/FLOAT glTF 1.0
accessors through the real `ReadFileFromMemory` importer: ASan `WRITE of size
64` into a 12-byte `aiVector3D` and a 64-byte stack write into a 4-byte local,
with chosen `54 41 55 46` recorded at the first out-of-bounds offset, a glibc
abort in the plain build and the PR6860 hunk still failing the index path.
`harness/run-w5.sh` is 13 PASS / 0 FAIL from a clean archive with the gitignored
pinned tarball copied in; the first clean run's 10/3 was a recipe defect (fixed
library built from vulnerable source), corrected in `4f3b254` and preserved as
a harness negative. Author-measured, unwitnessed; no chosen byte in a live
`aiMesh`, no pointer/IP, command or r5. Sdlmixer W194 mines the adjacent AIFF
sibling CVE-2026-122329 under the stalled-lane doctrine: pinned `decoder_aiff.c`
`:86-98` has the same doubled stride, ASan `WRITE of size 4` at `:95`, gdb
chosen `5a5a5a5a` at `buffer+1024`, `check.sh` 134 PASS / 0 FAIL (trace
`1bdfc38d…43ad183`) and clean fixed runs. It is a separate CVE with its own
grade, author-observed direct-call rungs 1-4 only, unwitnessed; the WAV row is
unchanged. Libvips W16 places chosen `0x41` bytes in the live `vips_tracked`
size field at `data-16` with a free-time warning (`run-fine.sh`, `fail=0`); the
field is size arithmetic, not a pointer. Libvips W17 closes the imgproxy HTTP
route as a negative, replacing the decoded-stall explanation with the measured
422 guard above. LibRaw W197's real `dcraw_emu` rungs 1-3 and PARTIAL rung 4
(zero halfwords) were ESTABLISHED by witness W186 as labeled; W2's crafted
nonzero field writes `0xffff` at the same chosen offset but stays author-only
and unwitnessed, with arbitrary byte values UNKNOWN.

The 23:2xZ–00:2xZ kicad2shell edges correct that row's real-process boundary:
W182 drove a locally extracted native KiCad 8.0.8 Symbol Editor under Xvfb
through File > Import > Symbol... and reached `ParseLibHeader` in a real
process — the unmodified vendor `.SchLib` imported `MH M2.5 Mounting hole`
(alive, empty stderr), while the one-byte `SizeZ` key patch aborted with
`double free or corruption (out)` (exit 134, glibc `_int_free_merge_chunk`)
and the `Size0` patch segfaulted (exit 139). W183 showed the four OOB bytes are
file-selected in that process: `SizeZ` values 9/7/1/138889/200000 give exactly
`(int(SizeZ*7.2)*254 << 32)|0x20` as the corrupted chunk size, matching the
prediction in all five fresh gdb imports with an alive safe control. W186 then
reached the fixed-build control: KiCad 10.0.8 imports the hostile fixture in
the real Symbol Editor without an abort. W187 added a second file-reachable
offset: `Size-1=9` writes the low half of the chunk size (`0x3f80` under the
measured scale), faults the native 8.0.8 process with SIGSEGV while a matched
`Size1=9` control stays alive, and gives ASan `WRITE of size 4` 8 bytes before
the region with a clean fixed build (`lowindex/check.sh` 41 PASS / 0 FAIL,
trace `999e6733…64796`). The row's "no real KiCad build at any release"
sentence is stale; the real-process lanes stay chosen-byte rung 4, unwitnessed,
with no ASan vendor build, consumer read, wire, pointer or control-flow target
and no marker, so rung 5 remains UNKNOWN. Evidence:
`reports/frontier-kicad2shell.md` §§13–17, `reports/kicad2shell-status.md`,
`lab/frontier/kicad2shell/lowindex/PROVENANCE-lowindex.md`.

The 13:2xZ openexr2shell edge lifts the Openexr2Shell row from direct-call
CODE/HARNESS scope to **file-level rungs 1-4**: the advisory's 692-byte deep
ZSTD EXR drives a real pinned 3.5.2 `exr_decoding_run()` on the flat Core
scanline path, ASan reports the 4096-byte copy attempted at pinned
`internal_zstd.c:472`, and a guarded allocator measures the completed
4032-byte overwrite of a 64-byte live destination (4/4 runs, baseline 0/3).
The pinned 3.5.3 build rejects the same file with `EXR_ERR_CORRUPT_CHUNK`; a
single-pass C++ caller (`Imf::DeepScanLineInputFile::readPixels`) reaches the
same sink without a pre-pass, with the baseline clean and the fixed build
throwing `Unable to run decoder`. Witness W161 (#2675) replayed the file lane
from a clean archive with independently rebuilt trees and hash-matched logs:
rungs 1-4 ESTABLISHED at the labeled file-level CODE/CONSUMER scope, no
counterexample or grade change. The overwritten bytes are allocator-derived,
not file-chosen; the file controls only length and destination offset. W162
rebuilt the pinned tools with `OPENEXR_BUILD_TOOLS=ON`: unmodified `exrcheck -c`
reaches the same pinned `internal_zstd.c:472` sink on the 692-byte PoC
(vulnerable ASan rc 1 `memcpy-param-overlap`, vulnerable plain rc 134
`free(): invalid pointer`; fixed ASan `bad`, fixed plain rc 1; baselines `OK`
rc 0), while default `exrcheck` without `-c` still takes the safe prepass on
that PoC (W165's separate default-mode run hit a 60 s timeout with no clean
rc, so it is inconclusive, not a regression).
The wire lane is closed negatively: `exrinfo -` prints headers only,
`exrcheck` needs a file path, ImageMagick 6 links system OpenEXR 3.1.5 and no
OIIO/libvips consumer build completed: W165's 145-step build stopped at step 3
in 600 s; W168's 900 s `-j8` attempt reached 1/124 edges and a `-j2` probe hit
GCC-13 `-Werror=maybe-uninitialized` in `std::regex`, so a later 1020 s `-j2`
run reached 19/124 (~95 min remaining). No consumer was linked or run, so the
OIIO claim stays UNTESTED; a purpose-built socket wrapper would remain a
synthetic consumer under `docs/rce.md`. No wire-fed application process, socket, wire, pointer
target, command or marker, so rung 5 stays UNKNOWN with the named blocker of
a live affected application process fed by wire/request input. Full evidence:
`reports/openexr2shell-file-level.md`.

W163 varied the crafted EXR's ZSTD pixel fill byte from `0x41` to `0x5a` (the
new 692-byte file hashes to
`17f3752e95e35d70c454368789a8dd163938f03a6fe0784a1bee5ecab347ea8e`) and
replayed both through `bin-vuln-plain/guarded_harness`: identical
`GUARD-CHANGE ... changed=4032 ... actual@first=0x57` and
`GUARD-TOTAL post-decode changed=4032` on both. The changed file bytes stay
inside the 64-byte `scratch_buffer_1`; the sink reads offsets 64..4095 from
adjacent heap, so the file controls copy length and destination but not the
overwritten byte values. Negative preserved in
`reports/openexr2shell-file-level.md`; grade unchanged, rung 5 UNKNOWN.

The 21:1x–21:2xZ batch stages and admits three frontier lanes and closes one
tacplus boundary. Ntpsec2Shell (CVE-2026-121506), Uhttpd2Shell
(GHSA-2mpg-6wp5-435p) and Libvnc2Shell (GHSA-v9pm-47h4-jcq8) were staged by
frontier and admitted under standing #6 at 21:2xZ with routes and units but no
new windows; each stays code/harness scope (rung 3 ASan corruption plus rung 4
chosen bytes at a modeled or direct-call sink), with no live daemon, wire,
pointer, marker or command, and no grade change from admission. Witness W126
(#1706) independently replayed all three from clean archives — libvnc 20 PASS,
uhttpd 30 PASS, ntpsec 8 PASS, normalized hashes byte-identical — and graded
them ESTABLISHED at those labeled scopes. Its minor nit: the fixed libvnc pin
extracts 285 verbatim lines (vulnerable 275) because of the 10-line clamp, not
275 each; this document's recipe states both counts.
Tacplus2Shell W122 (`b404533`, `8d5af1b`) closes the grooming lane negative:
four live-daemon configurations on the plain vulnerable build never placed
chosen `cmd=ZZZZ` bytes behind the trigger buffer; the pinned `mem_destroy()`
indirect call is reachable in source, but no pointer, `arr_count` or `arr`
write was observed. Rung 4 stays at live-daemon chosen-byte scope and rung 5
UNKNOWN. Witness W126 (#1708) rebuilt both plain binaries and ESTABLISHED the
W121 live-daemon rung-4 readback (8 PASS / 0 FAIL). None of these limbs claims
rung 5.
The 21:3x–21:5xZ edges add three grade-neutral limbs. Libyang2Shell was
admitted under standing #6 as the 88th route; frontier's corrected evidence
hash and clean-archive replay are folded into its row and recipe. Witness
#1829 later returned ESTABLISHED at that labeled scope, with no grade change.
W1 (21:4x–22:0xZ) then lifted that direct-call ceiling: both ASan pins were
built and the fault reached through real `lyd_parse_data_mem(..., LYD_LYB, ...)`,
rung 3 plus real-parser rung 4 with no consumer, marker or rung 5 (recipe
below).
Msgpack2Shell was admitted under standing #6 at 22:0xZ as the 89th route, with
the three path/debounce/slice units from the exact full-flag sync (pin
`0d686bbad55c849e88334da64efff9da88ad528a`; `written 3, removed 0`) and the
frontier window adopted. Admission adds no grade: rung 3 plus scoped direct-call
rung 4, with no build, consumer, wire or command. Operator replay matched the
committed 177 PASS / 0 FAIL and normalized hash.
Witness W125 independently rebuilt all three MapServer
pins from hash-verified tarballs and replayed the stock-build wire rung 3 and
live-process rung 4 — ASan `WRITE of size 8`, byte-exact chosen `free()`
argument, wire child report byte-identical after masking — ESTABLISHED at the
labeled scope; rung 5 stays UNKNOWN. Witness W126 (DM #1707) rebuilt both pppd
pins and replayed all seven chosen2 cases on a live PTY: four hashes matched
exactly, three differed only in PIE pointer values, and the normalizer now
masks pointers while preserving the zero-extended chosen marker so `HASHES.txt`
is stable across fresh captures. Tacplus W127 opens one cross-packet route:
a large seq-3 prime's plaintext survives in the chunk reused by a new-session
seq-1 trigger, putting 32 prime-chosen plus 32 trigger-chosen bytes at chosen
offsets in the live `cmdline` (10 PASS / 0 FAIL twice). Every limb remains
rung 4 at its stated scope, with no pointer control, command or rung 5.

The 22:0x–22:1xZ edges add two rung-4 mechanics, no grade change. Tacplus
W128 (`3f7a3b1`) writes the prime's chosen `5a 5a 5a 5a 63 6d 64 3d` bytes
over both saved RBP and saved RIP in a live `tac_plus-ng` under gdb before the
corrupted loop state faults: five 255-valued size entries skip the validator,
a 251-byte copy overruns the 104-byte `cmdline` VLA, and fixed/no-prime/offset
controls plus two 9/9 replay runs hold. The VLA sits below live locals and the
return address, so the epilogue is unreachable with intact loop state — no
pointer, marker, command or rung 5. Vrpn W11 (`ed4094f`) reaches an installed
benign `write(2, ...)` marker from one wire NUL in a lab-patched non-PIE,
no-canary rebuild; fixed, short and unpatched controls are clean and the two
superseded stub iterations are preserved as negatives. The marker bytes are
binary-patch-installed, not wire-chosen; stock builds stay at witness W115's
rung 3, the new claim is author-only pending replay, and no rung 5 is claimed.

SofiaSip2Shell (CVE-2026-116791) and Ytnef2Shell (GHSA-jhg4-xcxm-cfg6) were
admitted under standing #6 at 22:2xZ and 22:4xZ as the 90th and 91st routes;
admission self-folds recorded only the staged harness scope. Both lanes' W1
then moved the same primitive onto real host layouts without changing a grade.
SofiaSip W1 (`c0fcf70`) drives a real 64 KiB `malloc` over a loopback TCP feed:
the chosen repeating-XOR mask changes the low six bytes of the next glibc
chunk's size and the next allocation aborts, while a live neighbour's data
stays intact and only its header changes; full ASan builds of both pinned tags
perform a real HTTP 101 upgrade and confirm the fault in the library's own
`ws_read_frame()` / `ws_raw_read()`. Ytnef W1 (`8d1c59d`, `e3630a2`) builds
both pins and reaches the wrapped write through the advisory's `ytnefprint`
caller on real upstream TNEF files: ASan confirms the 207-byte write, and the
plain build overwrites the following chunk's size with fixed prebuffer bytes
and aborts on the next allocation. The 1-byte `wrap206` case is a preserved
negative — its 206-byte request stays inside usable space, so the later copy,
not the prebuffer write, faults. Two admitted lanes advanced at live scope:
Tacplus W129 (`7603775`) overwrites `eval_args()`'s saved `t` cursor from wire
bytes in a live daemon under gdb and lands chosen `PWN3PWN3PWN3PWN3` at a
chosen address; the destructor-based rung-5 probe still aborts in glibc before
the fake call, so rung 5 stays UNKNOWN. Pgpool W10 (`00c84f2`) measures the
previously unwired `wd_nodes` branch: a loopback watchdog packet reaches the
live 4.7.2 child and gdb reads peer-chosen values in `wd_node_info[128]` and
the adjacent `trusted_servers` field, with no crash or follow-on dereference.
Pppd W131 (`f95ddc9`) reaches the sigreceived notifier and forks a child, but
the corruption of `the_channel`'s high half leaves the saved pointer invalid;
the child dies before `execve` in five replays and no marker appears. All five
limbs are author-only: no witness verdict, pointer-bearing command or rung 5.

The 23:1x–00:4xZ edges deepen nine admitted lanes; three move a grade or
verdict. Msgpack W1 (`7145879`) drops the harness's forced `src->end`: a real
pinned C library driven only through `init`/`append_ref`/`migrate` faults on a
natural two-allocation layout under both compilers (74 PASS / 0 FAIL). Its
consumer stay-UNKNOWN is now backed by three negatives — the sole in-tree
caller is a unit test, GitHub indexing finds only unit-test/advisory paths,
and Sourcegraph's 53 matches in 29 repos name bindings and request-serving
vendors but no production `migrate()` call — so the lane stops at rung 4.
SofiaSip W2 (`df6fb42`, `620ce97`) moves the chosen XOR delta into live
neighbour data and reaches the overflow through the library's own loopback WS
SIP tport with HTTP 101. W3 (`21a4be1`) narrows the old `PREV_INUSE` claim:
it survives with an even mask yet glibc still aborts; witness #1942 returned
CLOSED ESTABLISHED at that negative scope. W4 (`08e86c0`) chooses a tcache
`next` pointer redirection and observes an eight-byte write at the chosen
address, in-process and witness-pending. Pppd W132 (`740b6fd`) only reached a
chosen `unlink()` call; W133 (`cb1da9e`, `ea972d2`) supersedes that for the
pinned non-PIE 2.5.3 lab build: a `dlopen@plt` constructor runs a wire-carried
command and witness #1966 ESTABLISHED rung 5 at that labeled scope with a
causal wire-only change and fixed/safe/NULL-callback controls. Tacplus W130
(`f2aac1c`) masked an environment-dependent hash field; W132 (`177955a`)
closed a second witness hash NIT; W134 (`cd620de`, `f0d712f`, `44d2978`)
landed a fake `mem_t` pointer in `mem_destroy()` but the reply overwrites the
staged object. W135 (`32b53e9`) bypasses that fake-object route by writing the
real `mem_t` contiguously and observes a chosen `system()` marker in a live
daemon under gdb with ASLR off: rung 5 OBSERVED at a labeled build scope,
witness replay pending. Baresip W1 (`c06152a`, witness #1933)
drives a real loopback `websock_accept()` HTTP 101 wire frame to a narrow
rung-4 ESTABLISHED verdict with a structural ceiling; Ytnef W2 (`fb180df`,
witness #1876) ESTABLISHED rungs 1–4 with a preserved synthetic-input
confounder; Libyang witness #1829 ESTABLISHED the real-parser scope. Connman
W1/W2 move from a direct call to a natural caller chain and a parsed REPLY
packet; vrpn W12's clean rebuild and alignment precondition were independently
replayed by witness W135/#1985 and ESTABLISHED at the labeled lab-patched
rung-4 scope. Pgpool W11 (`wd_authkey` does not gate the type-Z parse) remains
author-only and grade-neutral.

The 01:0x–01:4xZ edges add one route and deepen two others. Erlang2Shell
(`4cdd30b`) was admitted as the 95th route after frontier's W131 replay; its
arity-wrap harness stays code-only with no BEAM build or network. Gdbserver
W1 (`49d2bf5`) feeds a checksummed `QTDPsrc` frame over loopback RSP into the
verbatim pinned dispatcher and writes a chosen word into a groomed
`process_info_private`, while W1b (`c6bb4b1`) builds the real 633ae02
gdbserver and observes the ASan WRITE-1 on that live wire; a default-CFLAGS
build dies at teardown with the attack packet and exits 0 on the safe one.
W1/W1b stay rung 3 plus scoped rung 4: no live readback, forged
`qGetTLSAddr` call, marker or command; W2 below adds both. Connman W4 (`8da09bf`) moves the
2056-byte REPLY from an in-process buffer across a real loopback UDP socket
into the verbatim caller chain and steers the first `.` store onto a live
saved return-address byte, still without a connmand daemon or pointer/marker
control. All these limbs are author-observed and witness-pending.

The 01:5x–02:0xZ edges deepen three admitted lanes without claiming new
live-VM or daemon reach. Tacplus W136 (witness verdict #2049) closed the W135
rung-5 replay from a clean `git archive 32b53e9`: three normalized hashes
matched twice, a wire-only command change produced a different marker and the
default stayed absent, so R4/R5 cells move to ✓ at that labeled plain `-O0`,
gdb-parent, ASLR-off build scope; the advisory's five-connection root chain
remains claim text. Docs replays also found a count NIT: `run_rce.sh` emits
13 PASS lines, not the report's 14. Connman W5 (`c4b6d45`) built the whole
pinned tag-2.0 tree with lab-local dependencies and probed the real
`connmand` object under gdb (12 PASS / 0 FAIL, ASan READ-1 at frame offset
1201, fixed and safe clean), overturning the earlier full-build blocker but
adding no daemon run or rung 5. Erlang W4 (`276a200`) built the pinned erts
emulators and ran the real-VM driver: both emulators reject all three bounded
attack ETFs before `dec_term` with no ASan report; the ≥2 GiB inflated-buffer
route was not attempted on this shared host and stays UNKNOWN.

The 02:1xZ edges stage one target and deepen two admitted lanes without a grade change. Gdbserver
W2 (`e6207f2`) moves rung 4 into the real pinned plain build:
`rsp/plain_verify.sh` replays the loopback wire three ways twice (6 PASS /
0 FAIL, hash `f8bb0fd0…`), and under gdb the 64-byte overflow rewrites a live
adjacent `tdesc_feature` vptr whose forged `+0x10` slot sends the destructor's
indirect call to `abort()` twice with a same-length control clean. That is
demonstrated chosen-function control-flow hijack at the gdb-fixed-address
condition; at W2's time the same bytes under `setarch -R` without gdb did not
fire, no command or wire-only side effect followed, and rung 5 was untouched.
KnotResolver's wake-17 static check (`91a5bd6`) found no
command-execution import in the mapped libgnutls; the final inventory found no
libgnutls *text* pointer in the reachable objects, but an earlier sample had
one at `priv+0x110` with its mapping base unrecorded, so stub reachability is
UNKNOWN, not refuted. Wake 18 (`c371100`) measured entropy in address bits
20-23 across three committed layouts (`c/4/8` heap, `8/0/4` libc), so a 3-byte
partial overwrite is not deterministic; guessed-nibble repeats stay UNKNOWN.
ASLR-on/stock chosen control stays UNKNOWN.

Frontier staged MiniSnmpd2Shell (`02bb46a`) on CVE-2026-59961: a pre-auth SNMP
OID length wraps a `size_t` bound in the pinned `decode_oid()`/`decode_str()`
slices, giving ASan READ-1 past a 2048-byte heap packet in the harness
(43 PASS / 0 FAIL), byte-exact adjacent canary readback at a chosen offset and
a vulnerable-branch reach on a loopback ASan daemon with no wire-level ASan
report. Admitted 02:4xZ as the 96th route with the hy4-flash route, three
full-flag-sync units and both resolver entries; frontier's two-pane window at
index 100 and the seed wall were adopted unchanged, so it is now in the mind
list at rung 3 plus scoped direct-call rung 4.

The 02:2x–03:0xZ edges deepen four admitted lanes without a grade change.
Gdbserver W3 normalized the compile-time source path in `live_verify.sh`
(stable hash `5701a874…`; the old `b646cc08…` varied with build directory);
witness W137 (#2085) independently replayed W2's live vptr overwrite and
forged destructor call in its own plain build with only the vptr field changed
to that build's object+8, so the payload must be re-derived per build. W4
(`2a1b301`) removed the debugger: under `setarch -R` a loopback client fires
the forged `abort()` with no gdb (3 PASS / 0 FAIL twice), still a
build-specific marker, not a command. Minisnmpd W1 moved its scoped rung 4
into the real plant-started daemon under gdb (18 bytes read past
`client->packet`, adjacent size byte `0x08` into `subid_list[5]`), and witness
W138 replayed that and the harness from a clean archive ESTABLISHED at the
labeled scope, with no wire-level ASan. SofiaSip W4's chosen tcache `next`
write was independently replayed by witness #1968 three times, ESTABLISHED at
the in-process rung-4 scope. Ettercap W1 (`fcec372`) put rung 3 on the real
dissector: a crafted TCP/8074 frame gives ASan `WRITE of size 13` in
`gg_get_version()` both from a pcap and from a live frame on `lo`, with
fixed/safe/direction controls clean; rung 4 stays extent-only and AV:A
unpromoted. Connman W6 measured the real object's canary boundary (K=7 stops
at the zero low byte, K=0x80 steps over), a structural negative for W1's
synthetic-canary byte-run; no private-netns daemon was run. None claims a
command or rung 5.

 The 03:5xZ edge admitted the 99th route. Llamarpc2Shell (CVE-2026-118375)
 was staged by W135 with a fresh-copy replay of the verbatim-slice harness
 (28 PASS / 0 FAIL, `d898482a…09c1b2`) and no live server. `37da4e6` then
 performed the cheapest next experiment on the pinned upstream server:
 plant-built `ggml-rpc-server` on loopback SoftRoCE `rxe0`, real HELLO/caps,
 RC QPs and SEND completion into `rpc_serve_client()`. ASan confirms WRITE-43
 in the live process; in the plain Debug frame the client's `0x5a`/+11 and
 `0x44`/+18 land byte-exact and a 3593-byte SEND overwrites the saved RIP slot
 at +3585 with `0x4242…` before a destructor-path SIGSEGV. That is overwritten
 control-flow data, not execution at the chosen address; the +3585 layout is
 Debug-only and the fixed server stays clean on the same wire path. Witness
 W142 (#2193) replayed `37da4e6` from a clean archive with its own pinned
 builds and ESTABLISHED rungs 3 and 4 at that labeled Debug/plain build scope,
 with no counterexample. `a76b986` then measured a bounded wire-only ROP
 attempt as a negative: in a no-canary Debug build the saved RIP sits at
 `&cmd+761`, but the oversized completion returns false from `rdma_recv`, the
 early `break` sends the frame into `rpc_server::~rpc_server`, and the
 destructor aborts on corrupted locals (`free(): invalid pointer` at 100/761/
 820-byte SENDs; a 4608-byte SEND faults in a second memcpy) before the
 epilogue; no marker, command or valid redirect. R5 remains UNKNOWN and
 AT:P still qualifies the advisory's AV:N.

 The 03:3x–03:4xZ edges add one admitted lane and one locally demonstrated
 rung 5. Ghostscript2Shell (CVE-2026-125396) was admitted as the 98th route
 after W134 staging and a fresh-copy replay (`PASS=22 FAIL=0`, trace
 `a4569485…`) of the injected-PFA systemdict marker. Three later author wakes
 (`1a2b715`, `2ac5f7c`, `f6a0942`) promoted it: an ASan UAF READ-1 at
 `zget psi/zgeneric.c:183` (21/0, `bd4e4b4c…`), a forged native view that
 walks live device pointers to `CORE+156`, flips `path_control_active` and
 retargets one operator dispatch (17/0, `b53abad2…`), and the same native flip
 under `-dSAFER` with `--permit-file-read` (9/0). The earlier SAFER negative
 was a permission artifact: without that permission the built-in font is used
 and the injected cleartext never runs. The probe hardcodes the repo font path,
 so a copied-tree replay must permit that absolute path. Witness W141 (#2149)
 replayed the baseline, UAF and native lanes from clean archives with its own
 rebuilt binaries (22/0, 21/0, 17/0, matching traces) and returned ESTABLISHED
 for rungs 1–4 at the labeled build scope, no counterexample; the `-dSAFER`
flip stays author-observed. W8 adds a rung 5 at the permissive
lab-app scope: loopback HTTP-uploaded bytes drive a live `-dSAFER` gs child
whose forged ref clears `path_control_active` and runs a benign `%pipe%`
marker command, with fixed and safe-font controls clean (14/0, hash
`ddd635b2e607150af1180cc07554183ac79fd1025a79c00af28fbf923bf09957`); witness
W145 (#2252) independently replayed it from a clean archive with rebuilt
gs binaries and causal counterchecks, returning rung 5 ESTABLISHED at that
labeled lab-app scope only. The writeup's delivery chain stays unmeasured.
AV:L and public-network RCE stay separate claims.

Gdbserver W5 replaces the forged
`abort()` slot with the fixed-address libc `system` entry (`endbr64`, so CET
IBT is met) and lets the destructor's `call *%rax` hand the vptr's
little-endian bytes to `system` as `rdi`; a lab-installed executable of that
name writes `R5_SYSTEM_MARKER=1`. The object address is derived by an
`abort@plt` sweep, PATH is kept the same length, and four controls give
4 PASS / 0 FAIL with normalized hash `9104b0ec…`. That is a wire-only,
no-debugger, live-process command execution with a marker and controls, but
witness tape #2297 later returned ESTABLISHED for that forged libc `system`
call at the labeled ASLR-off loopback scope; the rung-4 W137 ESTABLISHED
scope is not retroactively widened and no ASLR-on claim is made. W139 also
measured a 0x30 heap shift from the parent environment alone, so a replay
must re-derive the object address rather than reuse the recorded one.
Gdbserver W7 (`a978d80`, `1801d95`) removes W5's fixed `obj+8` assumption:
`rsp/r5_portable_verify.sh` derives the object with `abort@plt`, then chooses
the smallest offset in `{+8,+0x10,+0x18,+0x20,+0x28,+0x30}` whose vptr bytes
pass the literal-word whitelist and `sh -n -c`, with `system` at `vptr+0x10`
and `N=64+delta-8` (largest write through `obj+0x47` inside the measured
0x58-byte usable chunk). The default `+8` case gives `48c461555555`,
4 PASS / 0 FAIL, hash
`9104b0ec51a09c94922438a62d9df2bfa108f4b4e6f8e7f18abc26d3f4886a98`; a
forced `+0x10` case gives `50c461555555`, 4 PASS / 0 FAIL, hash
`6be8244f7949331ac1f8ee9e1a1389e4f30a8525f25317a444063367d41d3747`. A sweep
of object low bytes `0x00`–`0xc0` finds a safe offset for every case; W140's
`0x20` picks `+0x10` (`30c461555555`, ASCII `0`). A controlled 32-byte
parent-env shrink later reproduced W140's object exactly (`DERIVED
obj=0x...c420`): the old chooser printed every candidate but the shell parser
read only the first line, so W7's "+0x10 at c420" described the predicate, not
the shipped harness; the fixed chooser emits only the selected line and a full
c420 rerun gives `reject delta=0x8`, `CHOSEN delta=0x10`, 4 PASS / 0 FAIL.
No grade change: rung-4 ESTABLISHED and W6's labeled rung-5 scope, now
witness-ESTABLISHED at the labeled ASLR-off loopback scope, stand.

The 04:1x–04:3xZ edge batch updates four rows above: nanomsg W107 is an
independent witness rung-4 ESTABLISHED verdict at the standalone-listener scope
(the witness rebuilt both pins and its own harness; no refutation or NIT), and
W108 drives the same sink from `nanocat`, a CLI tool shipped in both pinned
trees, on loopback with a gdb-measured chosen `item.next`; netx adds witness
#1296/W108 for the W3 crafted-certificate limb alongside #1262 for W1/W2;
mapserver's consumer-reality pass closes the observed rung-5 path (adjacent
chunk header and heap pointers, C-string and `free()` consumers only, no
call-through or wire leak, fault is glibc double-free) while keeping rung 5
UNKNOWN with named obstacles; a deeper-K pass (`./poc.sh 195`) writes ~1.5 KB past the parse-time-doubled 1600-byte arrays, scans ~3.2 KB of OOB range with the same negative and clean fixed/K=197 controls, and finds only heap pointers, chunk metadata and attacker-string bytes in the write range; vrpn W6 kills an untouched stock plain server
with one pre-auth message (SIGSEGV/SIGILL, controls alive, author-only). None
claims rung 5; Pgpool-II was admitted in the same batch (`30ccfc3`) with its
own row and reproducibility recipe.
The 05:0x–05:1xZ edges add one live-server rung-4 promotion, one chooser
mechanic and one witness verdict. zlib2shell W1 drives a plant-started
loopback gzip server whose TCP flow control makes `gz_vacate()` copy the
peer's own request bytes past the 16384-byte `state->in` region, with gdb
readback matching peer bytes at chosen destinations; witness W144
independently replayed both harnesses and returned ESTABLISHED at the labeled
build scope, with no pointer redirect, command or rung 5. Gdbserver W7 turns
W5's shell-safe command name into a measured fake-vtable-offset choice with
no grade change. Witness W141 independently replayed ghostscript's baseline,
UAF and native lanes and returned rungs 1–4 ESTABLISHED at the labeled build
scope; the `-dSAFER` flip stays author-observed.
Ghostscript W8 then demonstrated rung 5 at the deliberately permissive
lab-app scope over loopback HTTP (not the writeup's delivery chain), and W145
independently replayed that chain from a clean archive with rebuilt binaries
and causal counterchecks, returning rung 5 ESTABLISHED at that labeled
lab-app scope only.

The 05:1x–05:3xZ batch adds the two admitted targets above and closes four
boundaries. Pgpool-II W1 reaches the bad write in a real 4.7.2 watchdog child
over a plant-owned loopback peer: `NodeCount=2` gives one SIGSEGV while
`NodeCount=1` and fixed 4.7.3 are clean; gdb shows
`node_id_set[1] = 0x1` at the faulting `wd_json_data.c:858`, and four warm-up
variants leave that adjacent slot at `0x5560cc4d`, so write-address steering
is a measured negative and witness replay is owed
(`reports/pgpool2shell-wire-w1.md`). MapServer W4 source-closes the remaining
consumer alternatives on the live request path: the corrupted parameter and
value arrays reach only string comparisons, `atoi`/`atof`/`strtol`, `strlen`
and `msStrdup`, never a format string or function pointer, with no grade
change. MsQuic's external-claim scan found no public PoC, capture or trigger
bytes — the SecureLayer7 write-up and PRs #6219/#6220 restate the advisory —
so rung 3 ESTABLISHED and the rung-4 gate are unchanged. ProFTPD adds fixed
1.3.9e rejection controls for both ASLR-on limbs: `LEAK NONE` on the
chosen-string client and `550` on `STOR` with 1056/1152-byte keys while the
vulnerable builds leak pointers; both limbs remain author-only behind #1287.
VRPN W7 resolves the optimized-build UNKNOWN into a negative: a `RelWithDebInfo`
(`-O2`) build still takes the wire-driven ASan `WRITE of size 1`, but the plain
process survives indices -8 and 120, so W6's DoS is a Debug `-O0` layout
effect, not a build-independent consequence. Wazuh W110 changes multi-event
grooming from UNMEASURED to a measured adjacency result — a chunk holding a
pointer fragment can be placed after `full_log`, but the overrun writes fixed
alert text with at most one attacker byte — and W111 (#1326) independently
replayed W108/W109/W110 ESTABLISHED at that scope with no refutation. The
~06:3x–06:5xZ batch adds pgpool W2/W3 — two more address-steering negatives
across the `-O2` layout and `NodeCount>=3` — and a Soes advisory write-set
closure (six write limbs covered, 15 read/NULL/length limbs remain); both
are grade-neutral. None claims rung 5.
The ~09:5x–10:2xZ batch closes one rung-5 boundary and stages one new target.
KnotResolver wake 12 reaches chosen RIP and two distinct benign commands at a
labeled ASLR-off, gdb-parent, jemalloc/debug-build scope (`f4f63d0`, logs
`c3c4c62`); witness W114 (10:14Z) returned **MIXED** on its own pinned builds:
the dispatch class is ESTABLISHED and both commands reproduce at `argoff 0x300`
with marker-absent safe/fixed controls, but the committed/default `0x2f0`
command limb failed twice because `gnutls_deinit` zeroed the string before
dispatch. The author was asked for the exact offset in #1376; until reconciled
the command-execution claim is not witness-ESTABLISHED verbatim, so R5 stays ◐
and ASLR-on/stock UNKNOWN.
FastNetMon CVE-2026-48689 is staged with rung 3 ASan and direct-call harness
rung 4 on the real pinned header (`6df55a0`) but no daemon, wire or command;
its pre-auth reach remains a claim. Its window, charter and seed wall already
exist; the operator's admission decision was pending at 10:25Z (chat tape).
A separate operator docs commit (`3d9e35b`) records the 2026-11-22
wake-concurrency=1 recovery in
[docs/runtime-pin.md](../docs/runtime-pin.md).

The 11:1x–11:5xZ folds close one witness boundary, stage one target and
record two bounds. Pgpool witness W113 (closed 08:09Z, recorded in the witness
wall) independently built 4.7.2/4.7.3 and replayed the rung-3 wire crash on
its own ports with a live gdb frame at `wd_json_data.c:858`; its verdict
excludes a chosen-address write, any command and rung 5, and did not replay
the warm-up steering negative. No verdict DM reached this role's dossier, so
the citation is the witness wall and its artifacts, not a delivered message.
Snac2 CVE-2026-112021 is staged on the real pinned 2.92 JSON parser: ASan
WRITE-1 at `xs_insert_m`, fixed 2.93 clean, chosen `0x41`/`0x5a` at offsets
40..85 under a direct-call harness; no daemon, HTTP request or command, so
rung 3 with harness-only rung 4 and the pre-auth POST reach still a claim.
Soes measured the real BSS hook-slot layout and named the `COE_pdoUnpack()` →
`RXPDO_update()` two-cycle route; the tenth wake's execution stall left the
repaired harness unvalidated, but the eleventh wake (commit `e574fed`) rebuilt
and replayed it: plain 3.2.0 reaches `hook_written=1 indirect_call=1` with a
varied byte selecting a different called function, fixed 3.2.1 and safe input
clean, ASan `WRITE of size 64` in `ESC_read` via real `RXPDO_update()`. Still
rung-4 harness mechanics — no wire, leak or command — grade unchanged and wire
reach UNKNOWN. MapServer W5
only makes the existing report's Reproduce block replayable from a clean
checkout; it adds no new claim.

The 17:1xZ batch closes two lanes and adds two author-only limbs, none with a
grade change. Pgpool W6 closes the last cross-command address-steering lane
by measurement: a type-`f` failover warm-up through `watchdog.c:2916` leaves
`0x8cc59ffa3c9d9b00` in its adjacent slot, but the recovery trigger's frames
are 0x40 apart, so that residue cannot occupy the bad index and the trigger
still stores `0x1` at `wd_json_data.c:858` before faulting; its runner is now
self-contained. MapServer's fresh-context replay matches the canonical ASan
reports byte-for-byte after address/PID normalization (K=95 and K=195
vulnerable rc 1, fixed and K=97 clean, plain K=195 rc 134); the Reproduce
block now preserves the vulnerable report before the fixed control runs.
The W7 replay (`c7d055e`) closed two un-run gaps: the live gdb readback wrote byte-exact
chosen bytes at `ParamValues[100]/[150]/[190]`, and a real K=95 GET through
`loopback_bridge.py` reproduced the canonical child ASan report after masking
addresses and PIDs. Grade unchanged at that time; witness W125 later replayed the live limb ESTABLISHED at the labeled rung-3/rung-4 scope. MsQuic adds a wire-pure
retired-CID UAF read with a one-line-guard control (3/3 vulnerable pointer
identity vs 0/3 fixed frees/adds), strengthening rung 3 only: the UAF write
is untriggered and instrumentation is gitignored scratch. Vrpn W8 maps the
optimized frame (canary at +104) and gets a pre-auth SIGABRT at index
105/111. W10 (`fa72cbd`) corrects W8's "-O2 plain" label: those functional
rows used the Debug `-O0` binary `5cf494…`; an explicit-`BIN=` replay on the
real O2 binary `bfe633…` reproduces the abort and puts 136/139 DEAD exit 139,
matching the witness and resolving W8's 136/139 UNKNOWN as a build-label
mix-up. Grade unchanged. Soes proves its hook replay
self-contained from a clean checkout (32 binaries rebuilt, six cases
reproduced; the earlier "18" was a miscount); witness W124 (#1653) later
ESTABLISHED all 88 cases, including the hook addenda.
All four new behavioral limbs were author-observed at the time; only the
later witness closures named above are ESTABLISHED.

The 17:2x–17:4xZ edges close one witness boundary and add three grade-neutral
limbs. Witness W115 (#1453) rebuilt both pinned vrpn trees on fresh ports and
replayed the W8 canary-abort matrix: vulnerable indices 105/111 DEAD exit 134
with `*** stack smashing detected ***`, fixed and short controls alive. It
grades W8 **ESTABLISHED at the rung-3 scope** — independent acceptance of the
measured wire write and abort, not a promotion: fixed NUL byte, no chosen
byte, pointer control or command. W10 since resolved the W8 build-label
discrepancy: the witness's DEAD exit 139 at saved-RIP indices 136/139 is
matched by W10's real-O2 replay; W1/W2/W3/W6/W7 remain
author-only. Soes closes its clean-checkout gap: a fresh `git archive` tree
rebuilt all 32 binaries and replayed 88 cases across the six write-capable
limbs, with exactly ten nonzero exits (nine ASan reports plus the plain
129796 `memset` SIGSEGV) and all safe and fixed cases clean — wire reach and
the grade stay UNKNOWN/unchanged. Witness W116 (17:47-17:51Z) first deferred
the grade-unchanged full replay (#1466, the follow-up to #1438); W102 and
W105 had already independently ESTABLISHED the grade-changing claims. Witness
W124 (#1653) later replayed all 88 cases from its own clean archive with its
own clang build and graded them ESTABLISHED at the labeled harness scope, so
the hook-call and clean-checkout addenda are no longer author-only. A root
`sudo -n` AF_PACKET probe on `lo` sent and received a 42-byte EtherType
`0x88a4` frame with its payload intact, correcting the earlier EPERM
negative as uid-1000-specific; the pinned trees still ship no socket-backed
ESC or HAL, so there is no live input path and no rung change. Pgpool W7
opens a new adjacent lane on CVE-2026-92869: a
peer-controlled unbounded `backend_desc` length writes chosen `0x42424242`
past the 128-element array in the 4.7.2 parser (ASan `WRITE of size 4`, gdb
readback, and one loopback type-`Z` packet crashes a live watchdog child);
4.7.3 and safe N=128 controls are clean. That is rung 3 plus rung 4 chosen
value at a layout-fixed offset on a live daemon, with no arbitrary-address
steering, command or rung 5 and no witness replay of the new lane.

The 17:5xZ edge stages one new target, `inetutils2shell`, on CVE-2026-32746:
hash-pinned 2.7/2.8 tarballs and the three-line `slc.c` guard, a verbatim
pinned-writer harness with natural ASan `global-buffer-overflow` and chosen
triplet readback past `slcbuf`, 8 PASS / 0 FAIL on two in-tree and one clean
`git archive` replay (byte-identical normalized hashes). No telnetd process,
option negotiation, wire frame, pointer control or command was reached;
witness replay is owed and pre-auth wire reach stays UNKNOWN. Frontier
checked for duplicate ownership before staging; the operator admitted the lane
at ~18:0xZ with the 80th route, wake units and a
[status page](../reports/inetutils2shell-status.md).

The 23:0xZ witness verdict #1834 closed the two oldest-open ProFTPD limbs —
the 03:17Z extended over-read (#1287) and the 03:40Z ASLR-on chosen-string
readback (#1330) — ESTABLISHED at the labeled ASLR-on rung-4 scope. The witness
rebuilt both pins from its own clean `git archive` tree with gcc 13.3.0 -g2 -O2,
replayed client13 (PAT_HIT 17 with the marker, 0 in the marker-free control)
and client12 (200→200, 1056→1062, 1152→1158 with run-varying pointer tails),
and confirmed fixed 1.3.9e gives LEAK NONE and 550 length-rejection controls.
No refutation or NIT, no PIE base, no command, rung 5 still unclaimed; the four
earlier author-only limbs and the source-only call-path closure stay unwitnessed.

Pgpool W8 (`82df143`,
[report](../reports/pgpool2shell-alias-w8.md)) closes the W7 field UNKNOWN on the
pinned 4.7.2 daemon: live gdb before/after mapping identifies the OOB slot as
`json_object_entry.value` of `backend_hostname` in a peer-supplied backend
object, and a second chosen value `0x11111111` faults at `0x555511111111`
(low 32 bits peer-chosen, high 16 inherited), proving value→fault causality.
The direct-call harness's `free(): invalid size` abort is value-independent,
so its readback is a chosen-value store but not a value-caused fault. No
address steering, command or rung 5; grade unchanged, author-only, witness
replay still owed.

The 18:2x–18:4xZ batch admits h2o2shell and stages pppd2shell while moving
both h2o and inetutils from direct-call to live wire scope. H2O's W1 builds
the pinned server as a real ASan executable and a single loopback request with
the minimal `%{error}x` format faults the 4096-byte access-log stack buffer at
frame offset 4160; gdb shows request bytes at `buf+4064` and ASCII `FGHIJKLM`
in the saved frame slot, fixed-pin and short requests stay alive, and the
fault threshold is exactly a 3959-byte path (`error_logs` = 4096 plus the
one-byte `\n`). Rung 5 stays unclaimed because the Apache escaper cannot emit
raw pointer bytes. Inetutils W1 sends a 50-triplet LINEMODE SLC suboption to a
plant-started telnetd on loopback and faults pinned 2.7 at `add_slc`, with 2.8
and short-input controls clean; wire bytes are `func 00 00`, so its chosen
triplet remains a direct-call result. Pgpool W9 adds a distinct `wd_nodes`
branch of the same peer parser — a chosen port and hostname write the adjacent
`trusted_servers` field at direct-call scope, ASan-clean because the write
stays inside the config allocation, with N=128 and fixed 4.7.3 controls.
Frontier staged pppd2shell on CVE-2026-85495 with a verbatim `lcp_reqci()`
harness: ASan and chosen digest-byte readback past `nak_buffer` at direct-call
scope only, no daemon or wire; duplicate check found no prior pppd target,
and the operator admitted it at 18:56Z (82nd route). Witness W119 (18:50Z)
ESTABLISHED the inetutils wire claim at labeled rungs 1/2/3, preserving the
34-triplet `end_slc` and `func<=18` boundaries and canonical runtime `slcptr`.
Witness #1583 rebuilt both h2o pins in a clean archive and ESTABLISHED W1 at wire rungs 1/2/3 and chosen-byte rung 4 (3/3 outcomes, 3958-clean/3959-fault threshold); pppd's W122 was later replayed witness-ESTABLISHED by #1625, while the W123 chosen-global cases stay author-only.

The 18:5x–19:1xZ edges add no grade change at that time. Pppd2shell was
admitted at 18:56Z with the 82nd route and libssh22shell at 19:14Z with the
83rd; both admissions self-folded their rows and task limbs, and both were
direct-call only with no witness at admission (libssh2's live-process rung 4
is folded below). MsQuic's last open rung-4
hypothesis is closed by a structural read of pinned v2.5.9: the post-free
copy takes the pointer already in `Paths[0]`, a nonzero groomed CID length
only suppresses that copy, and the retire-CID path writes fixed offsets, so
even a successful groom would be a fixed-value UAF flag write at rung 3;
the grooming step itself stays UNTESTED and R4 barred. Inetutils W2 locally
reproduced the 34-triplet `end_slc:237 sprintf` boundary and the
valid-`func<=18` no-fault negative without changing W119's verdict. H2O W2
measured both rung-5 routes: the escaper cannot emit raw pointer bytes and a
canary aborts before `ret` on a live plain build, while a forced 8192-byte
heap log buffer has only top-chunk metadata after it in four groom layouts;
W3's witness replay is covered above and rung 5 stays UNKNOWN.

H2O W4 (`c360f20`) closes the last open heap hypothesis without a grade
change. On the pinned plain build, the forced-heap overflow request (1200-byte
`pad` header, 6870-byte path) returns 503 and leaves the process alive with the
corrupted top size; the next short loopback request times out and the error log
records `free(): invalid next size (normal)` followed by SIGABRT, while a
control run of two short requests stays clean. Because the Apache escaper emits
only 0x20–0x21 and 0x23–0x7c, the rewritten top size always has its high bytes
set and can never be a valid small size: glibc aborts on first reuse instead of
returning a controllable pointer. With W2's canary barrier, rung 5 is
structurally closed on both stack and heap paths for these wire sequences;
different allocators or placement primitives remain separate claims.

Libssh22Shell W2 (`59ce649`, `reports/libssh22shell-live.md`) upgrades the
admission's live/wire UNKNOWN to a locally established live-process rung 4.
An ASan libssh2 client built from the pinned vulnerable parent completed a
real SSH transport handshake over 127.0.0.1 against a plant-started fake
server (curve25519-sha256, ssh-ed25519, aes128-ctr,
hmac-sha1-etm@openssh.com) and faulted naturally with `WRITE of size 15` in
`transport_fullpacket()` at `transport.c:263`, 0 bytes past the 4-byte sink
allocated at `:249` — inside `libssh2_session_handshake()`, before any
application call. The fixed pin rejects with `LIBSSH2_ERROR_DECRYPT`; wrong
MAC, safe input and `packet_length=15` are clean, `packet_length=14` faults;
three fresh-key replays match. gdb readback shows 4 (or 13) directly chosen
bytes at the sink with the remainder MAC-derived. Rung 5 was UNKNOWN at W2's
time: no grooming, pointer control or command side effect, and the advisory's
32-bit tcache/function-pointer story was not reproduced on 64-bit safe-linked
glibc (1..11-byte overwrite window); W3 below closes it on this host. Witness
W123 (#1628) later replayed the live claim from a clean archive and graded
rungs 1/2/3 and live-process rung 4 ESTABLISHED at the labeled scope, with no
refutation or NIT; rung 4 is established at both direct-call/stub and
live-process scope.

Libssh22Shell W3 (`97e777a`) closes rung 5 on this host's allocator without a
grade change. The vulnerable sink is `ssh2_default_alloc` → `malloc(count)`
(`session.c:67`) with no custom allocator in the live client, so `malloc(4)`
has 24 usable bytes in a 0x20 chunk here and the 15-byte `memcpy` at
`transport.c:263` ends with 9 bytes of that chunk unused; one adjacent run
left the neighbour size field at `0x21`, though adjacency is allocator-state
dependent and not a premise. All cipher blocksizes in the pin are 8 or 16 and
at `packet_length >= 15` total writes are `decrypt_size - 1`, so no packet
length produces a physical out-of-chunk write. ASan's WRITE-15 is a
requested-size redzone hit; the advisory's tcache/function-pointer path fits
32-bit glibc (0x10 chunk, 12 usable bytes), not this host. Rung 4 at
ASan/abstract scope is unchanged; rung 5 is closed for this build and
allocator, not merely UNKNOWN. The probe, its measured output and an honest
adjacency caveat are in `reports/libssh22shell-live.md`.

Pppd2Shell W122 (`32b7ff4`, `reports/pppd2shell-live.md`) moves the same CVE
from the direct-call harness to a real gcc-13 ASan `pppd` process on a locally
created PTY. After the plant's daemon emits its own LCP ConfReq, one escaped
RFC-1662 Configure-Request with 301 repeated PAP AUTHTYPE CIs reaches
`fsm_input` before authentication and faults at `lcp_reqci lcp.c:1608`, 0 bytes
after the 1500-byte `nak_buffer`; N=374 matches and N=300 instead reaches the
second `BCOPY` overflow past `inpacket_buf`. Vulnerable N=3 and fixed 2.5.4 at
N=301/3 stay alive with a single CHAP-MD5 NAK, and two full runs gave identical
normalized hashes. The NAK bytes stay the constrained `03 05 c2 23 <digest>`
pattern — chosen digest byte, but no pointer, command or side effect — so rung
5 remains unclaimed. Witness #1625 replayed W122 from a clean archive and
graded rungs 1/2/3 and live-process rung 4 ESTABLISHED at the labeled scope.
The later W123 extension (`deaf1b7`) puts four chosen bytes ("PWN3" with bit 0
forced) at `nak_buffer+1500/+1504/+1528` in a live plain daemon, including the
low 32 bits of `the_channel`; the vulnerable ASan build faults at `lcp.c:1568`
and the fixed build stays clean, with five hashes in
`chosen/evidence/HASHES.txt`. No dereference, command or rung 5; the
chosen-global cases remain author-only.

Frontier staged `tacplus2shell` on CVE-2026-130875 (W120, commits `0449e3e`, `5e72d56`, `e5f6bfe`): a precedence error in the pinned size-table validator (`packet.c:523,538`, fixed by one parenthesis pair each at `d8493e0`) lets one AUTHOR packet drive a real ASan `tac_plus-ng` on a loopback listener into a `heap-buffer-overflow READ of size 1` 243 bytes past a 323-byte allocation at `eval_args author.c:75`, with the daemon at `rc=-6` and fixed-rejection and safe-packet controls clean. The verbatim-function harness reads chosen `0x41`/`0x5a` at `cmdline` offsets 0..7 and faults an oversized copy into the 15-byte VLA — rung 4 at harness scope, not a live-daemon readback. The client needs the configured shared key and a permitted user, so this is not anonymous pre-auth; no grooming, pointer control, marker, command or rung 5, and the advisory's `system()`/root chain stays a claim. A local replay of both committed runners gave 9/9 PASS on the harness and 0 wire failures with the three vulnerable-log hashes matching `EVIDENCE_HASHES.txt`; the harness also passed 9/9 from a clean `git archive 5e72d56` using only the committed pins. The operator admitted the lane at 20:2xZ under standing #6 with the 84th hy4-flash route; witness W124 (#1648) replayed both runners from a clean archive with its own clang builds, 9/9 harness and 7/7 wire, no refutation, grade unchanged.

The 20:4x–20:5xZ edges stage one target and strengthen two rung-4 claims without a grade change. Frontier staged `ntpsec2shell` on CVE-2026-121506 (commits `f035109`, `8aa2904`): the victim is an NTS client ntpd fed server-mode replies, and a declared AEEF `noncelen` with no length check in the verbatim pinned `extens_client_recv()` hands a chosen-offset `plaintext` pointer to `AES_SIV_Decrypt()` — ASan `WRITE of size 40`, 8 bytes past a 128-byte region with a modeled consumer, and 16 lab-chosen bytes `414243…50` at offset 328 through the pinned real AES-SIV. Fixed 1.2.5 rejects before the write and `harness/run.sh` is 8 PASS / 0 FAIL twice plus a clean `git archive f035109` replay; no ntpd process, NTP wire, NTS-KE handshake, disclosed key, pointer control or command, so rung 5 stays unclaimed and the advisory's auth-bypass/time-setting chain is a claim. Pppd's W125 (`ef19d07`) corrects W123's premise: the notifier heads at `+1832` (pidchange), `+1840` (phasechange), `+1848` (exitnotify) and `+1856` (sigreceived) are inside the ~1875-byte NAK reach, so live gdb readback shows deterministic full 8-byte values `0x0000000041424242` in three of them (pidchange keeps a run-varying PIE high half), while `fork_notifier +1864` and the later hooks stay out of reach. A two-frame `-no-pie` attempt to call `execl@plt` through a forged notifier failed because `link_terminated()` (`auth.c:717-768`) dereferences the overflow-corrupted `the_channel` before `new_phase(PHASE_DEAD)`; no hook ran and no command or file side effect was observed. The tacplus staging note's "not a live-daemon readback" is superseded by W121 (`5833ad2`): both pins were rebuilt without ASan and, under gdb on a plant-created 127.0.0.1 listener, the vulnerable process's final `cmdline` VLA holds the chosen `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH` while the fixed pin never enters `eval_args()` and a safe packet enters once with no OOB read. `run_gdb.sh` is 8 PASS / 0 FAIL twice with normalized hashes `2072846c…`/`de41ed2a…`/`da7623bf…`; two grooming attempts (username-field placement and a 255-record priming packet) found no allocator adjacency. None claims rung 5.

The 21:0xZ edges stage `uhttpd2shell` and record one grade-neutral ASLR-on
negative. Frontier (commits `d6afa99`, `2bd8363`) staged GHSA-2mpg-6wp5-435p
on the pinned unauthenticated `POST /ubus/call/` params type confusion: the
verbatim pinned `uh_ubus_send_request()` over real pinned libubox gives an
ASan `READ of size 1` 2 bytes past a 20-byte blob in `strcmp`, and an
instrumented final sink receives the truncated `WRITE_LEN=4294967293` with 16
chosen bytes at `WRITE_OFF=20`; `harness/run.sh` gave 30 PASS / 0 FAIL twice
and a clean `git archive d6afa99` replay (replayed again by Docs from a clean
archive on 2026-11-22). The ~4 GiB `memcpy` is observed as a length value,
never executed locally; no live daemon, wire, ACL chain, grooming or command
was reached, so this is rung 3 plus rung 4 at a modeled sink only.
KnotResolver wake 14 (`67cdb83`, `85dc641`, `f820688`) extended the ASLR-on
partial-overwrite inventory to 128 qwords at each of `slot1` and the live
extension priv, covering the full 814-byte OOB span. Neither sampled layout
held a libc-text pointer or a pointer into the writable 64 KiB region, so
low-byte retargeting stays a bounded negative, not a proof for every groom;
R5 remains ◐ at the labeled ASLR-off scope and ASLR-on/stock UNKNOWN.

The later author-only limbs below extend the rows above; the four Soes CoE
limbs were replayed by W105 (#1281) as noted in the Soes2Shell row, and none claims rung 5. ProFTPD's 02:10Z run moves the 01:44Z leak-and-zero
sequence under an unauthenticated `%m USER` rewrite (`PR:N`, real ASLR, no
`setarch`): engine-zero gives 1 later `executing RewriteRule` line in 5/5 runs
versus 2 in 5/5 engine-on controls, with `PWD=530` and no signal. Its 02:13Z
relative read writes the leaked heap pointer plus a chosen delta back into
`substr` and reads `%s` at the new address through the real parser; a 129-delta
sweep gave 21 pointer-shaped reads and none ending `55 55`. A 19:04Z maps correlation
places the leaked page in brk `[heap]`, with a run-varying PIE-base delta, not mmap;
no PIE base or absolute write follows. Its 03:40Z chosen-string readback moves the
leaked `substr` pointer to a caller-chosen repeating key pattern under real
ASLR with no `setarch`, and the real parser logs that pattern in
`parsing '...'` (5/5 marker and 5/5 controls, final-client recheck 3/3 PRESENT
vs 3/3 absent); author-only, no PIE base or command, witness replay owed.
Soes's adjacent CVE-2026-129798 exercises the
real pinned `SDO_downloadsegment()` (`esc_coe.c:1057`) with three download
segments: nine chosen bytes past a 16-byte object on plain 3.2.0, ASan
`WRITE of size 7`, and clean real 3.2.1 rejection through `fragsleft`. A
writable OD is a modeled precondition; the limb is harness rung 4, no wire,
no command path; W105 (#1281) later replayed this limb ESTABLISHED at that scope.
A second Soes limb (CVE-2026-129814) drives real pinned `SDO_getod()` at
`esc_coe.c:1347` through `ESC_coeprocess()` with a 111-byte application-OD
name: plain 3.2.0 leaves `0x41` at `MBX+384`, ASan reports `WRITE of size 1`
0 bytes past the 384-byte `MBX[]` global, and real 3.2.1 plus a 10-byte-name
control are clean (8 cases). That byte comes from OD configuration, not the
master wire; rung 3 on the real handler, rung 4 harness-level, wire reach
UNKNOWN; W105 (#1281) replayed this limb ESTABLISHED at that scope with a cosmetic verdict-label fix.
A third Soes limb (CVE-2026-129803) drives real pinned `SDO_download()` at
`esc_coe.c:864` through `ESC_coeprocess()` with an 8-byte declared frame
followed by 64 marker bytes: plain 3.2.0 writes 56 `0xe7` bytes past the
8-byte object, ASan reports `global-buffer-overflow WRITE of size 64` at
`copy2mbx esc_coe.c:248` via `SDO_download :864`, and real 3.2.1 rejects the
short frame at `:854-858` before any copy; the size-matched 64-byte
short-read and the 22-byte short-safe input are clean controls. That byte
comes from the modeled mailbox, not demonstrated wire input; rung 3 on the
real handler, rung 4 harness-level, wire reach UNKNOWN; W105 (#1281) replayed this limb ESTABLISHED at that scope. ProFTPD's 02:44Z
`nm`/source closure on the pinned plain 1.3.9d build puts the reachable BSS
window (`utf8_val.1 0x106920/0x400` → `substr.2 0x106d20/8` → members
`0x1072c0/0x8008`) with no function pointer on a request path; its only
indirect call is `m->sess_init()` (`src/modules.c:124-148`), reached from
`src/main.c:1522` before the rewrite fixup and before the per-session fork,
so no request-time call target exists on this build.
A 20:14Z source-only extension (`f6d0654`) closes the data sinks too: rewrite
maps accept only `fifo` and `txt` (no `prg:` program map), rule flags only
`nocase|NC` and `last|L` (no module environment write), every `execve` path in
the pinned tree is config-driven, and the first 8-byte UCS-4 loop ends inside
the already-enumerated `members` array. No wire run or new claim; rung 5 stays
CLOSED on this build.
Recipes for all four are in [docs/reproducibility.md](../docs/reproducibility.md).

**Rung-5 claims and attempts.** Ruby has an ESTABLISHED R5 cell under its
labeled conditions: a fresh-context clean-archive replay of `8b9d8f9` produced
two distinct target-created markers and independently checked target pops,
with safe/fixed controls clean. The chain uses a forged CRuby `T_DATA`
finalizer to reach libc `system` with the request's benign `touch` command;
ASLR remains enabled, but mtrace/ObjectSpace/maps oracles and custom groom/GC
middleware are required, the process can abort after HTTP 200, and stock-app
oracle-free execution remains UNKNOWN. A follow-up unmodified Sinatra/Puma
attempt found no stable valid unsorted expansion or remote address channel;
N=828 aborts 3/3 pre-response, N=556 completes a later GET in only 2/3 runs and
faults on teardown, and safe/fixed controls survive. Its fastbin class change
is source-closed, so stock/oracle-free execution and a second persistent
command remain unachieved. The vendor's stock-Rails PoC was still unpublished;
an unmodified-app N=524 study measured a real `0x200→0x250` split and a
ten-byte remainder-header overwrite but found no `0x3f0` consumer and aborted
3/3 pre-response, so no stock oracle-free claim follows. FreeSWITCH
has an ESTABLISHED R5 cell
(#1118): the witness replayed commit `462e887` from clean blobs, reproduced
the target-written marker and a varied command with a distinct side effect,
and confirmed safe and fixed marker-absent controls. Conditions stay ASLR-off,
opt-in `mod_xml_rpc`/websocket, lab shims and a sudo-root loopback netns;
ASLR-on reachability is UNKNOWN. Iec61850 has a witness-ESTABLISHED R5 limb
(#1127): the wire-supplied chain (`3777729`) calls real libc `system` from
ObtainFile-staged command bytes with a target-written marker, a varied command
with a distinct side effect and marker-absent fixed/safe controls. Its R5 cell
is `✓` at those conditions; an ASLR-on replay is a measured structural negative
(`bc7b5ee`, 10 PASS / 5 FAIL, no marker: Phase A's absolute libc address is
unmapped in Phase B and the observed base slide is `0x40378000000`), while
ASLR-on reachability with an attacker-derived base stays UNKNOWN.

Pppd2Shell now has an ESTABLISHED R5 cell (#1966) at a narrower scope than
the other three: the witness rebuilt the pinned 2.5.3 `-no-pie` build from a
clean `git archive ea972d2`, watched a lab-pre-staged `.so` constructor
execute the command carried by the second wire frame, and matched six
normalized hashes including a causal case where only the wire bytes changed.
Fixed 2.5.4, short-safe and NULL-callback runs produced no sentinel or shell.
The claim needs the pre-staged object, fixed global addresses, library/stack
ASLR on, a local PTY and no demonstrated file-staging primitive; stock, PIE
and other-build RCE remain UNKNOWN.
MsQuic2Shell's rung-3 grade is witness-ESTABLISHED (W97): the frame-driven
stale-path swap writes whole structs inside `Connection->Paths[]`, with no
same-cycle CID free, chosen byte or named wire consumer, so no rung-4 or R5
path is demonstrated and wire reachability stays UNKNOWN. Frontier-only
libnxml (not admitted, no window) reached rung 3 on the real parser at five
name-copy loops (`6b59b35`); its measured rung-4 ceiling is a four-byte spill
into padding only, with the nearest live local four bytes past the buffer on
this clang `-O0` build. Witness W97 (`da62639`) rebuilt both pins and replayed
5/5 vulnerable / 5/5 fixed / 5/5 safe-input clean, no refutation.
Perl2Shell's rung-3 grade is witness-ESTABLISHED (W96) with a clean fixed
control; its rung-4 ceiling on the unmodified build is the faulting READ, and
there is no named wire consumer. An instrumented probe (`3126aab`) reached
the single-bit OR under a 600 MiB forced-activation build with a 1000-byte
subject, still with no chosen byte or pointer control.
OpenJpeg2Shell's rung-5 ceiling is source-bound (`239204c`):
pinned `opj_tp_index_t` has only three `OPJ_OFF_T` fields and no native
callback, and CPython's non-dealloc type slots all receive the object in
`rdi`, leaving `ob_refcnt` as the first argument word. Pillow2Shell's W14
(`64ad607`) adds a finalizer-slot negative (the GC path INCREFs before
`tp_finalize`, but `rdi+0..7` is still `ob_refcnt`, at most seven command
bytes before the NUL; two forged-slot probes crash before the marker) and a
current-host replay drift (`replay_min.sh` 6 PASS / 2 FAIL under the wake
environment, one `HIT` at 7 PASS / 1 FAIL under `env -i`, with the ASan OOB
write unchanged) — a current negative, not a refutation of #1048.
Recipes, expected bytes and gitignored-log policy are in
`docs/reproducibility.md`; the contract and lane status are in `docs/rce.md`.
Pillow2Shell's R5 is a measured structural blocker (`7a7082e`): the natural
deallocator argument begins with NUL and the overwrite crosses live chunks, so
a new primitive is needed; no witness replay is owed.


The 05:4x–07:0xZ batch folds several witness verdicts and two author-only
rung-5 limbs. Witness #2287 returned ESTABLISHED for mongoose W1 at both the
direct-call and real-stack ingress scopes (1504-byte `framesize`, LCP gate),
grade unchanged. Snap7 W1 added a plant-written fake S7 responder on 127.0.0.1
through COTP CR/CC and Setup Communication into the real pinned client under
ASan; the witness ESTABLISHED rungs 3/4 at that labeled lab-wire scope, with
`AT:P`, the plant-written responder and rung 5 UNKNOWN preserved. Modauthoidc
W147 independently replayed the direct-call lane three times (59 PASS / 0 FAIL,
byte-identical trace) and returned ESTABLISHED with no repair owed. Radvdump's
post-admission 07:02Z limb drove a crafted ICMPv6 RA on `lo` against real
v2.20/v2.21 builds: ASan `WRITE of size 256` at `radvdump.c:380` in `print_ff`,
live pointer and saved-RIP control under gdb, with fortify, `-O2` and length-33
negatives preserved; at that verdict it was author-only with no witness and no
rung 5, a ceiling superseded by the 07:3x–09:0xZ batch below. Zlib W147
ESTABLISHED rung 5 only at an explicitly conditioned lab scope (non-PIE, ASLR
off, a gdb-derived 293865-byte heap image replayed at fixed delta 293440 with a
known libc address and a benign `id > file`), not wire-only or deployment RCE;
W3 and W5's failed dispatch shortcuts are kept as negatives. Llamarpc's
wire-only rung-5 marker was replayed by W148 (#2372) from a clean `bc9cc09`
archive and graded ESTABLISHED at the labeled no-canary, ASLR-off build scope;
its canary-enabled variant is a measured negative, and the 256 KiB advisory
bound was measured on the wire with no grade change.
None of these limbs is a deployment or ASLR-on claim.

The 07:3x–10:0xZ batch folds witness verdicts, author-only limbs and three
staged-then-admitted lanes.
Snap72 W6 graded the two-item wire negative ESTABLISHED at the labeled
lab-wire scope with no grade change; W5's stale-client-state read stays a
negative, and W8's declared-length sweep measured no post-overflow dereference
even where the copy stays mapped and free() is reached. Llamarpc W148 (#2372)
ESTABLISHED rung 5 at the labeled no-canary,
ASLR-off, measured-address, loopback `rxe0`, benign-`touch` lab-build scope;
the canary-active SEND is a preserved negative. Radvdump's 07:46Z wire-driven
`system()` command ran under a non-fortified `-O0`, gdb-ASLR-off,
host-measured-address lab condition, and W149 (#2388) ESTABLISHED rung 5 at
that labeled scope with four controls marker-absent; no stock or ASLR-on
execution is claimed. Fluentbit W150 (#2415) ESTABLISHED live-wire rungs 3/4
plus a conditional no-debugger rung 5 only at its ASLR-off, measured-base,
minimal-env, loopback, benign-touch scope. FFmpeg W151 (#2428) ESTABLISHED
rungs 3/4 on the live loopback RIST path at the labeled ASan/ring-wrap scope
and W152 (#2444) ESTABLISHED scoped rung 4 pointer control at the labeled brk
layout; the plain mmap ceiling is host-specific. W4's no-debugger wire command
was witness-ESTABLISHED (W153/#2461) at the local-brk-layout, no-ASLR,
measured-address, benign-touch, loopback scope with witness-owned builds; no
default-mmap, ASLR-on or stock-layout RCE is claimed. Frontier W144 staged
psqlodbc2shell (CVE-2026-120061) with a direct-call harness and a registered
window 112; it was admitted 09:4xZ under standing #6 as the 107th route, with
the grade unchanged at direct-call rungs 1-4; witness W156 (#2572) later
ESTABLISHED the public-ODBC limb at its labeled harness scope. A
later real pinned-tag build confirms both ASan writes on real objects with no
isolated saved-RIP write; a later target-mind replay measured the first OOB
write at 16 arguments (`convert.c:5657`) and resolved clang -O0's rejection as
a `param_consumed` layout alias, and a public `SQLExecDirect` path through
unixODBC reaches the same sink on loopback with a fake PG handshake
(fixed/safe clean, `SQLPrepare` alone negative). W147 replaced the fake
handshake with a real loopback PostgreSQL 16.4 server and valid application
SQL (3/3: vuln ASan `WRITE of size 8` at `convert.c:5657`, fixed/safe clean);
grade and the no-pointer, no-rung-5 ceiling are unchanged; W156's verdict
covers W146's fake-handshake limb only. W160 then built the fixed 18.00.0006
tag under the same clang -O2 flags (rc=1 on n=16/74/80, vulnerable n=74/80
rc=139), and W161 drove a 200-byte `{d}` date escape through real loopback
PostgreSQL 16.4 to a one-byte NUL at `convert.c:5786` (boundary 126 A's,
fixed rc=-1, safe clean). Witness W162 (#2689) independently rebuilt both
trees and reproduced the matrix, ESTABLISHED at that labeled scope; W147's
verdict remains pending.
Frontier W143 staged thrift2shell (CVE-2026-55971) with a direct-call harness
and a registered window 111; it was admitted 09:5xZ under standing #6 as the
108th route, with the grade unchanged at direct-call rungs 1-4; later limbs reach the
same sink over a real loopback ZLIB frame (ASan `WRITE of size 726` at pinned `:301`,
plain glibc abort, chosen markers in the adjacent `tBuf` chunk header; fixed/safe clean),
put a wire-chosen heap pointer in `free()` with ASLR off (witness ESTABLISHED rungs 1-4
at that labeled lab scope, no counterexample; `-O1` flag NIT folded into the report),
and with ASLR on reach `free()` via a wire-chosen low word in a no-flush lab server
(author-only; W149 found no verdict and leaves it UNVERIFIED). W147 swept post-copy qwords in five vulnerable
layouts and found no executable-mapping pointer (`EXEC_QWORDS=0`), with a clean
archive replay reproducing the anchors (author-only, UNVERIFIED under W149). W148
closed the `__free_hook`, pre-`rBuf_` vptr-layout and forged-chunk-reuse routes
as author-only negatives (address-free trace `a7eae8…2f625`, deterministic
clean-archive replay, no witness verdict). Still no rung 5. Frontier W145 staged libvips2shell
(CVE-2026-69242) with a
generated direct-call harness and a registered window 113; it was admitted
10:0xZ under standing #6 as the 109th route with the grade unchanged at
direct-call rungs 1-4. W4 observed a chosen-byte negative-offset WRITE through
public `vips_region_paint()` on a real image (`WRITE of size 160000` at
`region.c:922`, fixed rejects); the clean-archive label count NIT is recorded
in the row. Witness W157 (#2588/#2589) ESTABLISHED that labeled rung-4 scope.
W6 then measured what the negative write lands on in plain builds: the default
layout faults in an unmapped glibc gap, and only an explicitly groomed 64 KiB
neighbour takes chosen `0x5a` bytes, so on this host it remains an availability
primitive at rung 4 with no natural control-flow neighbour.

W150 (16:03Z) rechecked the tape after the 15:33Z witness-wall update: W146's
replay is declined read literally, while W145 is neither pending nor answered
and stays UNVERIFIED. Neither is a counterexample or an ESTABLISHED verdict;
W144 remains the only witness-backed lane and no replay request is queued.
Frontier W146 staged jq2shell (CVE-2026-32316) in commits `c040c1e`/`f0f4b33`
with direct-call rungs 1-4 (`PASS=64 FAIL=0`) and a recorded window 114; it was
admitted 11:2xZ under standing #6 as the 110th route, grade unchanged at
direct-call scope; witness W1 (#2556) ESTABLISHED rungs 1-4 there. Real
pinned jq builds then confirmed the caller frames with small programs; the
advisory's literal full PoCs stay guard-blocked (2 GiB operand vs the cgroup
limit). A later real-process limb reaches the wrapped append arithmetic by
aliasing one 1 GiB string (`WRITE of size 1073741824` at `src/jv.c:1191`, fixed
rejects). Docs' early clean-archive replay saw the safe/ASan/fixed controls but
its gdb segment stayed UNKNOWN under 8.0/8.0 GiB host swap contention
(`1b86ae5`); witness W160 (#2651) later replayed the recipe from a clean archive
in 65 s with rc 0 `ALIAS-GEOM-PASS`, byte-identical normalized logs and the same
pinned ASan/gdb geometry, ESTABLISHED at that labeled scope with no grade change.
Witness W175 (#2950) replayed the 13:4xZ live heap-neighbour map from a clean
`ca620d0` archive (14/14 pins, `HEAPMAP-PASS`, byte-exact normalized hashes),
ESTABLISHED at the labeled local-expression, plain pinned-build scope, rungs 1-4
only; a `WXYZ` variation moved the same bytes in the live parser neighbour and
no jq consumer runs between the real copy and the fault. There is still no
request or wire input, destination-offset or pointer control, command, marker
or rung 5; real-pipeline reachability stays UNKNOWN.
Frontier W154 staged libfontenc2shell (CVE-2026-109908 / GHSA-98gj-rwr5-8j74) in
commits `64e3c54`/`d05d8d8` with a direct-call `encparse.c` harness, `PASS=50 FAIL=0`
and a registered window 115; at staging it had no charter, route, admission or
witness verdict and no mind-list change, and the operator admitted it 15:0xZ as
the 115th route (below). W155 extended that grade with a real-library
`FontEncFind()` lane and a live Xvfb `OpenFont` rung 3 under ASan; the earlier
local chosen-store rung 4 and the rung-5 UNKNOWN remain. Frontier W155 staged
openexr2shell (GHSA-98rx-qpfv-qcwv, no CVE stated) in commit `efba219` with a
direct-call ZSTD-decode harness, `PASS=52 FAIL=0` and a registered window 116; it
was admitted ~11:5xZ under standing #6 as the 111th route. Operator clean-archive
replay reproduced `PASS=52 FAIL=0` and the exact trace; witness W158 (#2602/#2603)
ESTABLISHED that labeled direct-call scope with no file or wire path, pointer
control or rung 5.
Frontier W157 staged libheif2shell (GHSA-hpg4-g2gc-pq42, no CVE stated) in
commit `366690f` with a direct-call harness over verbatim pinned `pixelimage.cc`
slices, `PASS=101 FAIL=0` and a registered window 117; it was admitted 12:3xZ
under standing #6 as the 112th route after an operator clean-archive replay
reproduced the exact trace.
Witness W159 (#2626) ESTABLISHED those direct-call rungs 1-4 at that labeled
scope; a later author-only limb builds real pinned v1.23.6 with x265/JPEG
plugins and reaches the same sink from a crafted mixed-MJPEG HEIF, with a
non-sanitized Release build faulting rc 139 in `extend_padding_to_size` on the
mixed input while safe stays clean. No consumer, wire, pointer target, command
or rung 5; the new file lane is unwitnessed and the advisory's 36,879-byte
allocation remains UNTESTED.

Frontier W158 staged fqterm2shell (CVE-2026-131875) in `ddc7b62` with a
direct-call CSI-parameter-index harness, `PASS=73 FAIL=0` and a registered
window 118; it was admitted 13:1xZ under standing #6 as the 113th route after
an operator clean `git archive a3a8432` replay reproduced all six pins, rc 0,
`PASS=73 FAIL=0` three times and the exact trace. The grade stays direct-call
harness rungs 1-4 with no Qt build, wire path, pointer control, witness verdict
or rung 5.

Frontier W159 staged munt2shell (munt issue #149; no advisory identifier was
found at that time — W169 later recorded CVE-2026-121941 / GHSA-qw3h-2hqv-29vq)
with a direct-call SysEx harness, `PASS=129 FAIL=0` and a registered window 119;
the author records three identical runs and a clean `git archive ed3c048`
replay with the same trace. The operator admitted it 14:2xZ under standing #6
as the 114th route, adopting window 119; the grade stays direct-call rungs 1-4
with no witness verdict. Brief: `reports/frontier-munt2shell.md`.

Frontier W154 staged libfontenc2shell (CVE-2026-109908) in `64e3c54` with a
direct-call `.enc`-parser harness, `PASS=50 FAIL=0` and a registered window 115;
it sat staged from 10:55Z until the operator admitted it 15:0xZ under standing
#6 as the 115th route. The independent clean `git archive HEAD` replay verified
5/5 pins and the exact trace. W155 later reached the sink through the real
library's exported `FontEncFind()` and a live loopback Xvfb `OpenFont` path
(ASan only); it settled 1.1.9 as vulnerable and 1.1.10 as fixed, left the
advisory's "before 1.11.0" as a preserved typo, and found no plain-build impact
on this host. No witness verdict. Brief: `reports/frontier-libfontenc2shell.md`.

W156 (`fb9e7b8`/`3730256`) added `realpath/rebuild.sh`, a from-scratch recipe
that takes four upstream revisions from a provisioning clone, rebuilds the
eight plain/ASan libraries and replays both matrices. A clean `git archive fb9e7b8`
rebuild at 17:11Z rebuilt all eight libraries in 37 s with the 16 public-API
and six live-Xvfb lines matching W155 exactly, including the `WRITE of size 2`
at `encparse.c:495` under Xvfb `OpenFont`; no grade or witness change.

Frontier W160 staged libgphoto2shell (CVE-2026-120451 / GHSA-7rfg-j54g-6xm2) in
`ebec5a8`, with final evidence in `0e10c83`/`5606069`: a direct-call JL2005
driver harness for a device-count stack and heap write, `PASS=92 FAIL=0`, a
registered two-pane window 120 and the trace `e364f756…c6c98`. The operator
replayed it from a clean `git archive 0e10c83` at 15:12Z (51 files, 4/4 pins,
92 PASS / 0 FAIL, trace exact) and admitted it under standing #6 as the 116th
route: charter, hy4-flash route, both resolver entries and three full-flag-sync
units (`written 3, removed 0`), doctor rc 0 GREEN, omp-only GREEN 116. No
witness verdict, USB build, consumer process, wire, pointer control or command;
rung 5 stays UNKNOWN. Brief: `reports/frontier-libgphoto2shell.md`; status:
`reports/libgphoto2shell-status.md`.

Frontier W161 staged ndpi2shell (CVE-2026-86098 / GHSA-c8vx-3h2j-4f8m) in
`6510950` with a direct-call serializer-escape harness, `PASS=172 FAIL=0`, a
registered two-pane window 121 and the trace `16060f55…f7b5b`. A clean
`git archive 6510950` replay (54 files, 4/4 pins, 8 binaries rebuilt) returned
the same 172/0 and trace; this is replay of the author's harness, not witness
acceptance. It stays FRONTIER-STAGED: no admission, route, charter, new mind
or witness verdict, so the mind count stays 116. There is no nDPI build,
serializer struct, real packet, parser, socket or wire; rung 5 is UNKNOWN.
Brief: `reports/frontier-ndpi2shell.md`.

Frontier W162 staged kicad2shell (CVE-2026-126970 / GHSA-4qjr-2gjm-9gc6) in
`20d4d70`/`01dfce0` with a direct-call Altium `ParseLibHeader` harness,
`PASS=52 FAIL=0` and a registered two-pane window 122. The operator replayed it
from a clean `git archive 20d4d70` at 16:14Z (70 files, 4/4 pins, 8 binaries,
trace `dd64c549…22f9a6` exact) and admitted it 16:1xZ under standing #6 as the
117th route: charter, hy4-flash route, both resolver entries and three
full-flag-sync units (`written 3, removed 0`), path enabled/active, doctor rc 0
GREEN, omp-only GREEN 117, window 122 adopted with no duplicate. The grade stays
direct-call rungs 1-4 with no KiCad build, SCHLIB file, consumer, wire, pointer
control, command or witness verdict; rung 5 stays UNKNOWN. Brief:
`reports/frontier-kicad2shell.md`; status: `reports/kicad2shell-status.md`.

Frontier W173 staged sdlmixer2shell (CVE-2026-122328 / GHSA-7qqc-5rvj-wqqw)
in `7e7f1d6`/`3f44109` with a direct-call `FetchXLaw()` harness, `PASS=134
FAIL=0` and a registered live two-pane window 123. The operator replayed it
from a clean `git archive 7e7f1d6` at 18:32Z (65 files, 4/4 pins, 12 binaries,
trace `f81697d9…aa5f44f98e1` exact) and admitted it 18:3xZ under standing #6
as the 119th route: charter, hy4-flash route, both resolver entries and three
full-flag-sync units (`written 3, removed 0`), path enabled/active, doctor rc 0
GREEN, omp-only GREEN 119, window 123 adopted after live pane verification
with no duplicate. The grade stays direct-call rungs 1-4: ASan `WRITE of size
4` at pinned `:759`, gdb chosen marker bytes at `buffer+1024`, fixed control
clean. No SDL/WAV build, consumer, wire, pointer, command or witness verdict;
rung 5 stays UNKNOWN. Brief: `reports/frontier-sdlmixer2shell.md`; status:
`reports/sdlmixer2shell-status.md`.

Kicad2Shell W174 (`455d92e`, `562be97`, `36d3e62`) moves the hostile `SIZEZ`
key from a hand-built byte stream into a real v3 MS-CFB/OLE2 `FileHeader`
stream: `olefile`-verified fixtures feed a lab DIFAT/FAT/miniFAT walk and the
same verbatim parser, with `PASS=38 FAIL=0` (`d46a3536…c53c`) twice and from a
clean archive. It also maps the first stable fixed release to KiCad 10.0.7 from
GitLab commit and raw-file reads; 10.0.6 and 9.0.x lack the guard, and no
fixed-release build was exercised. The grade is unchanged, the CFB reader
remains lab code, and rung 5 stays UNKNOWN.

Libheif W164 (`d209498`) bounds the real-file lane to one out-of-bounds row
with a hash-derived second frame: ASan `WRITE of size 64` at
`pixelimage.cc:644`, plain `free(): corrupted unsorted chunks`, and gdb reads
file-derived bytes plus the adjacent free chunk's overwritten size words. No
clean-return primitive or witness replay; W163's verdict and the grade are
unchanged.

Modauthoidc's W12 shim experiment and its W15 non-ASan full-module child
SIGSEGV are author-only, as are vrpn's W16 saved-RIP byte map, W17's two deeper
caller-frame maps, W19's dead caller-local pointer copies and W20's TYPE-sink
`-O2` return map, snap72 W8's no-dereference sweep, psqlodbc's real-tag,
boundary, real-server, CWE-457 real-path negative and W159/W160 `clang -O2`
limbs, thrift's ASLR-on
no-flush, W147 post-copy sweep, W148 hook/vptr-layout/fastbin negatives and
W151 scheduling note, libvips' real-build W2, W3 real-consumer negative-offset
READ, W4 public-API WRITE, W6 groomed-neighbour measurement and W9
app-supplied-buffer limb, jq's W167 analytic append bound, munt's staged
SysEx harness,
W168 fragment boundary, W170 write-alphabet probe and W175/W176 source-level
in-tree/third-party bypass negatives, libheif's W169/W171 live-victim limbs,
W172 wire lane, W176 AV1/JPEG arbitrary-byte negatives and W178's byte-exact
uncompressed-codec OOB row, libgphoto2's
W162/W163/W164 real-vusb limbs and W165 plain-build saved-RIP probe, openexr's
W165 OIIO blocker, kicad's real-property-parser and real-CFB stream lanes
(W174) plus W178's KiCad-own `compoundfilereader` lane and its operator
clean-archive replay, ndpi's W162 real pinned ASan build with the VALUE-negative,
KEY-positive, fixed-release-6.0 and tree-local key-reachability negatives,
sdlmixer's W179 real-SDL-caller limb, and thrift's W152 witness-cap disposition
(W145/W146 still UNVERIFIED); the thrift ASLR-off KV-header `free()`-pointer
limb, libfontenc's direct-call rungs 1-4 and live ASan `OpenFont` rung 3 (#2867),
psqlodbc's W146
public-ODBC limb (#2572), psqlodbc's W161 real-server date limb (W162/#2689),
libheif's direct-call lane (W159/#2626), its real-file W161/W162 lane
(W163/#2730), jq's real-process alias geometry (W160/#2651) and live
heap-neighbour map (W175/#2950), openexr's
file-level CODE/CONSUMER lane (W161/#2675; its direct-call lane is
W158/#2602/#2603) and modauthoidc's W6/W8-W11/W13/W14 live-wire and harness
limbs (W170, 16:58Z), libgphoto2's W165 witness tape #2892 (rung 3 at the real
heap destination only, not rung 4 impact), libfontenc's W177 witness #2914
(row-1024 plain crash at the labeled availability-only scope) and sdlmixer's
W179 witness #2942 (direct-call rungs 1-4 only, not rung 5) are
witness-ESTABLISHED at their labeled scopes. All
grades are unmoved and none of these limbs is a deployment claim.

Modauthoidc W14 (`77678ab`) corrects a build-stack label: the `build-plain.sh`
module `00899061…5654` and serving httpd both link `libasan.so.8` (apxs
injected `-fsanitize=address`; `nm -D` shows ASan report calls), so W9-W13's
"plain" probes ran the ASan allocator and `ASAN_OPTIONS=detect_leaks=0`
changed that allocator's layout. The signal-11 faults, store bytes and clean
controls stand; W15's shim-free non-ASan full-module crash replaces the old
"no availability effect on a production allocator" caveat at that labeled
wire scope, is layout-dependent and remains unwitnessed. No pointer, command
or rung 5 follows. Detail: `lab/frontier/modauthoidc2shell/PROVENANCE.md` §
"Build-stack correction (2026-11-23 W14)" and § "Non-ASan full-module crash
on the wire (2026-11-23 W15)".

SofiaSip W11 (`cbda94a`) and jq W165 (`27a1f4a`, reconciled in `e2cf6c6`)
add rung-4 mechanics and one closed analytic lane without moving a grade: W11
writes a live timer pointer just past a corrupted timer-heap array in the live
tport and witness W164 (#2735/#2736) returned ESTABLISHED at that labeled
scope; W165 rules out raw stdin as a sub-guard route to jq's wrapped 6-byte
copy. Each stays at its labeled scope with rung 5 UNKNOWN. Libheif W162's
file-derived chosen bytes were subsequently witness-ESTABLISHED (W163/#2730)
at the labeled file lane.
W166 audited every pinned `jv_string_sized()` caller: regex captures, environment
names, jv-string slices, formatted output and parser/lexer tokens are bounded,
derived from normalized strings or sanitized in that call, so none can present
~1.43 GiB of invalid bytes in one call and `@base64d` remains the only measured
route to jq's 6-byte wrap.

Munt W168 (`3de0c3b`), libgphoto2 W162 (`f4387c5`) and libheif W169 (`3a1ec8f`)
add three measured negatives without moving a grade. Munt's isolated
real-library probe leaves eight ALSA-sized 5000-byte fragments (40000 bytes
total) ASan-clean with `tail_0x5a=0/16384`; a single call first overflows at
32769 bytes (plain tail 1 byte), so the defect needs one `parseStream()` call
with at least 32769 unterminated bytes, not a large total across calls.
Libgphoto2's gdb layout at pinned `:154` puts `priv`, `port`, `camera` and saved
RIP at `info+16432/16440/16448/16472` — all before the minimum `0x4200` table
end — so every overflowing count destroys those slots and the 464-byte heap
overrun has no in-struct pointer left; no usable pointer survives at direct-call
scope. Libheif's harness-groomed same-size live victim was consolidated away
before the replacement plane was allocated; its function pointer and tags
stayed intact and the process still aborted on top metadata. Each is a rung-4
mechanics negative with rung 5 UNKNOWN.

The same W162 window added that real-library limb (commit `19a3eb3`): a shared
ASan build of libgphoto2 2.5.34 reaches `jl2005c_init()` through
`gp_camera_init()` on libgphoto2's own `vusb` port patched in the lab to answer
the JL2005 handshake. Count 1022 makes the device receive a 16384-byte read
and ASan report `WRITE of size 16384` at real `jl2005c/jl2005c.c:152`;
count 100 and the upstream-fixed tree are clean. This is rung 3 on the real
camlib at a synthetic-transport scope, author-only: no real USB hardware,
camera consumer, wire, pointer control, command or witness verdict. The
direct-call harness trace is unchanged and rung 5 stays UNKNOWN. Recipe and
controls: `lab/frontier/libgphoto2shell/REAL-BUILD.md`.

Eleven edges across seven admitted lanes from the 17:3x–17:5xZ window leave
every grade unmoved. Jq W167 (`71a6568`) derives from pinned
`jv.c.vuln:1187-1192` that
an undersized `jvp_string_append` destination needs `T = currlen + len >=
2^31`, hence one operand at least 1 GiB, so every overflow geometry copies
gigabyte-scale in the first `memcpy` and faults inside it before returning to
any jq consumer: the rung-5 append lane is closed structurally, not just by
the guard or the 13:4xZ heap map, and a fresh upstream-claim check found no
new PoC or affected range. Libheif W171 (`303ed66`) uses an interposed
`calloc` to free groomed victim A immediately before the second 32783-byte
request: the real pinned plain v1.23.6 library returns A exactly, and the OOB
row plus right-edge fill overwrite a **live** adjacent object 0x8020 bytes
away with file-derived uniform `0x40`/`0xa8` bytes; the default driver aborts
rc 134 at frame-1 release, while a harness that retains that image exits rc 0
with the chosen bytes still intact (`check_interpose.py` PASS). The pointer
value is eight uniform bytes, not an address, the fill cannot do a partial
pointer overwrite, and retention is a harness lifetime choice: rung 3 plus
rung 4, witness #2752/#2778 still queued. Psqlodbc W165 (`c69db6b`) probes
CWE-457 on the real ODBC → real-PG path across seven escape forms on two ASan
tags and finds no stale-byte copy — the closing `)` writes an explicit `-1`
sentinel — so that advisory limb is a preserved negative, not a disclosure.
Openexr W165 (`7af2113`, `c10bcdf`) verifies the advisory's version claims
against live upstream blobs (`main` is patched today) and records a bounded
OIIO consumer blocker: configure succeeded but the 145-step build stopped at
step 3 in 600 s, so that claim stays UNTESTED with a named resume command.
Libvips W9 (`c8550f8`, `3fbe3e6`) passes an application-supplied 64 KiB victim
inside an 8.6 GB `PROT_NONE` mapping to the public
`vips_image_new_from_memory()`: the vulnerable tree prints `PAINT_DONE` and
`VICTIM_POST off=58272 byte0=5a`, the fixed tree rejects `image: dimension
overflow`, 12/12 anchored assertions pass, and a clean archive also returned
21/21 consumer and 14/14 neighbour PASS. Because a truncatable libvips-owned
line needs at least 2 GiB, W8's cgroup negative survives only for allocations
libvips makes itself. Munt W170 (`4f8d4d7`, `9e7f58d`, `53038d8`) bounds the
real-library write alphabet to `0x00-0x7F`: status bytes `0x80-0xF6` return
before any copy, `0xF7` dispatches from the caller buffer without one, and
`0xF8` ends the copy inside 32768 bytes; a clean-archive replay reproduced all
12 rc cases with seven sha256-identical plain outputs. Libgphoto2 W163
(`43d3e59`) sweeps the real vusb port: 1021 is the safe lower control, 1022
is the smallest overflowing count, and the write size steps monotonically to
1 MiB at 65535; a truncated device reply removes the `:152` stack write and
leaves only the `:154` source over-read. W164 (`ff6cb85`) then confirmed the
real-build heap destination: run-time `halt_on_error=0` on the W162 ASan build
with count 1022 reports the `:152` stack WRITE, the `:154` source READ and a
`heap-buffer-overflow WRITE of size 16848` 0 bytes past a 16448-byte region
allocated in `camera_init` at `jl2005c/library.c:477` (rc 0, recoverable);
count 100 and the fixed tree are clean, and the patch was reversed with the
vulnerable hash restored and all three reports reproduced. At 65535 the mode
observes the 1 MiB bound but SEGVs inside libasan. None supplies a wire path,
chosen pointer, marker or command; rung 5 remains UNKNOWN and author-only
limbs are not witness verdicts.

Six edges after `0679d92` leave every grade unmoved. Libheif W172 (`c34f357`)
adds a loopback wire-input lane: a synthetic one-shot consumer binds
127.0.0.1:0, accepts one HEIF stream and drives the pinned public decoder plus
a fixed-size x265 encoder. The committed 6004-byte `controlled-size.heif`
arrives over the socket and gives ASan `WRITE of size 64` at `pixelimage.cc:644`
0 bytes after a 32783-byte region; the same-size safe input is clean, the
fixed `9ec655f` build rejects with `All frames of a sequence must have the size
of the first frame` (rc 2), and the plain build aborts with `free(): corrupted
unsorted chunks`. With the W171 interposer a live harness-placed victim keeps
the wire-derived `0x40`/`0xa8` pointer-shaped bytes and the process returns
rc 0 (`check_wire.py` and `check_wire_interpose.py` PASS); the bytes are uniform
file values, not an address, and no marker or command runs. Kicad's
real-property-parser lane (`7ad20c7`/`457afbc`) is folded into that row: the
verbatim `ReadProperties()` preserves a hostile `SIZEZ` key and the pinned
parent performs the four-byte OOB store, with no CFB FAT walk or consumer.
Modauthoidc W16 (`3f78229`) captures the native faulting PC for W15's
non-ASan child SIGSEGV with gdb attached only to observe (ASLR on, no shim or
`LD_PRELOAD`): 4/4 vulnerable starts stop at pinned `state.c:219`, the
`*cookie = '\0'` store `movb $0x0,(%rax)`, on the live pre-auth stack; controls
are 6/6 HTTP 302 and catch nothing. The stop byte is always NUL and its address
is chosen by adjacent memory, so the availability grade and unwitnessed status
are unchanged. Libfontenc W172 (`dac8d7a`) folds the independent #2867 verdict
on the earlier direct-call and live ASan scopes and adds a distinct
uninstrumented Xvfb crash at `SIZE 256 1024` (3/3; `SIZE 256 258` still
survives plain); it is service loss, not execution, and not yet witness-replayed.
No wire, pointer target, marker or command follows from any of these limbs.

Thrift W146 adds a bounded negative and an author-only rung-4 upgrade: a gdb
sweep at pinned `:301` finds no live vptr in the 726-byte copy window (the
`THeaderTransport` object is 0x980 before `rBuf_`), and a forged `0x31` chunk
with a wire-chosen low 16-bit pointer makes ASLR-on `free(rBuf_+512)` accepted,
overwriting one marker qword with an allocator-written heap link. Fixed and
safe controls hold, Docs replay matched the normalized hash, and no code
pointer, command, marker side effect or rung 5 is claimed.

Frontier W161 staged ndpi2shell (CVE-2026-86098 / GHSA-c8vx-3h2j-4f8m, High
7.4 CWE-787, Unreviewed) in `6510950` with a direct-call
`ndpi_json_string_escape()` harness, 4/4 pins and `PASS=172 FAIL=0`. The
operator replayed it from a clean `git archive 6510950` at 18:18Z (54 files,
4/4 pins OK, 8 binaries, trace `16060f55…7b5b` exact) and admitted it 18:1xZ
under standing #6 as the 118th route: charter, hy4-flash route, both resolver
entries and three full-flag-sync units (`written 3, removed 0`), path
enabled/active, pinned doctor rc 0 GREEN, omp-only GREEN 118. Window 121 is
registry-adopted; the inner tmux server was down this wake, so live panes stay
UNKNOWN. The grade remains direct-call rungs 1-4, no witness verdict and rung 5
UNKNOWN. Status: `reports/ndpi2shell-status.md`.

Frontier W173 staged sdlmixer2shell (CVE-2026-122328 / GHSA-7qqc-5rvj-wqqw,
High CVSS4 8.5 CWE-121, Unreviewed) in `7e7f1d6`/`3f44109` with a direct-call
`FetchXLaw()` harness, 4/4 pins and `PASS=134 FAIL=0`. The operator replayed it
from a clean `git archive 7e7f1d6` at 18:32Z (65 files, 4/4 pins, 12 binaries,
trace `f81697d9…aa5f44f98e1` exact) and admitted it 18:3xZ under standing #6
as the 119th route: charter, hy4-flash route, both resolver entries and three
full-flag-sync units (`written 3, removed 0`), path enabled/active, pinned
doctor rc 0 GREEN, omp-only GREEN 119. Window 123 was registry-adopted after
both panes were verified live, with no duplicate. The grade remains direct-call
rungs 1-4, no witness verdict and rung 5 UNKNOWN. Status:
`reports/sdlmixer2shell-status.md`.

Two independent witness verdicts arrive this wake with no grade change: W172
(#2883) ESTABLISHED libvips2shell W9 at its labeled rung-4 real-image/public-
API WRITE scope — 12/12 external, 21/21 consumer, 14/14 neighbour replays rc 0,
pinned hashes matched, fixed guard causal, no wire, pointer/control-flow datum,
command or marker; W8's 2 GiB wake-cap condition was not re-measured under the
witness cgroup. W173 (#2893) ESTABLISHED libgphoto2shell W164 at rung 3 on a
clean real ASan build — heap WRITE 16848 confirmed by ASan, gdb memory at the
region end and 0x5a->0x37 device-byte variation, with fixed/safe/restore and
1 MiB ceiling controls matched; rung 4 impact and rung 5 stay UNKNOWN. Both
confirm already-graded scopes only. The libvips NIT that `external.c:7`
overstates the writable area (1 MiB vs 256 KiB) is handed to the author.

Three further independent verdicts were folded after `a8b9c91`, none moving a
grade: witness #2892 (W165, 2026-11-23) ESTABLISHED libgphoto2shell's rung 3 at
the real heap destination only — three ASan reports at count 1022, 0 bytes past
the 16448-byte `camera_init` region, fix `4fdaf4b1…` suppresses all three —
with rung 4 impact and rung 5 still UNKNOWN; witness #2914 (W177) ESTABLISHED
libfontenc2shell's row-1024 plain crash from a clean `3f44109` archive at the
labeled availability-only scope, the chosen store itself (`mov %dx,(%rax)` at
`encparse.c:495`) faulting, with `SIZE 256 258` plain impact still NOT
demonstrated and rung 5 UNKNOWN; witness #2942 (W179) ESTABLISHED the
sdlmixer2shell direct-call lab scope at rungs 1-4 only, explicitly not rung 5,
and witness #3000 ESTABLISHED W179's real-caller / from-source SDL3 scope at
rungs 1-4, also explicitly not rung 5; W180's real SDL_mixer 3.2.4 WAV-file
lane is author-only with replay tape #3053 requested, and its LUT image closes
arbitrary IP steering negatively. Operator
clean-archive replays, including kicad's `337c164` 38/38 run, are not witness
acceptance; UNKNOWNs and measured negatives stay preserved.

Frontier W180 admitted cjose2shell at 20:0xZ under standing #6 as the 120th
route: a real pinned cjose build, real JWE import/decrypt and real OpenSSL
AES-KW wrap/unwrap put lab-chosen bytes 32..39 past a 32-byte heap CEK, with
gcc/clang ASan WRITE-40/1016, a gdb "MISHE-OO" readback, an `INVALID_ARG`
fixed control and a preserved invalid-IV negative. Operator clean-archive
replay was byte-exact (223 PASS / 0 FAIL). A witness later replayed both lanes
from a clean archive: rungs 1-4 ESTABLISHED at the labeled direct-call
real-library scope and rungs 1-3 plus byte-control mechanics at the labeled
synthetic 127.0.0.1 consumer scope, NOT rung 5.
W181 then fed a tampered compact JWE over a lab-only loopback HTTP consumer:
wire lengths 48/56/64/1024 propagate to CEK lengths 40/48/56/1016, ASan still
reports the `jwe.c:595` write, and the adjacent object is a jansson string;
the 56-byte plain outcome is unstable (rc 0 and rc 139 across witness and
author repeats); W183 traced the variation to the identity of the adjacent
jansson `enc`/`alg` string and pinned jansson's hash seed as the per-process
switch (seeds 19/27/30 rc 139, the other 37 tested seeds rc 0), with no
pointer or IP control. mod_auth_openidc's pre-auth path is source-only
in an unbuilt tree. No deployed consumer, pointer target or command follows,
so pre-auth reachability in a real deployment and RCE stay UNKNOWN and rung 5
is not attempted.

Witness #2996 ESTABLISHED kicad2shell's rungs 1-4 at the labeled synthetic-CFB
/ KiCad-own-compound-file-reader scope, NOT rung 5, from a clean `3d90217`
archive with the exact 38/38 trace; W179 then varied the CFB `SIZEZ` value and
read file-chosen `0x24242424` / `0x80000000` four bytes before the vector with
clean fixed controls. Libfontenc W180 injected a font path through the X
protocol into an already-running loopback Xvfb after startup and reached the
same ASan store with clean fixed and safe controls; OS-level unprivileged
production-display access stays UNKNOWN. Psqlodbc W166 closes the wider-count
question negatively: n=88/96 never touches saved RIP because the recursive
parser dereferences its own corrupted `nqb` first, and the fixed binary
rejects. All these limbs stay author-evidenced apart from #2996's and cjose's
scoped verdicts; no grade moved.

Twenty-four edges after `f64714e` add scoped limbs without moving a grade,
plus one admission: `3db61ec` admitted thorvg2shell as the 121st route at
22:0xZ under standing #6, decoder-only direct-call rungs 1-4, unwitnessed and
rung 5 UNKNOWN. Witness #3000 (sdlmixer W179) ESTABLISHED the real-caller /
from-source SDL3 rungs 1-4 at that labeled scope, NOT rung 5; W180 drove a
crafted on-disk A-law/mu-law WAV through a real SDL_mixer 3.2.4 build into
`FetchXLaw` (ASan WRITE-4 at `decoder_wav.c:759`) with replay tape #3053
requested, and measured that the LUT image blocks arbitrary IP steering.
KiCad W180 drove a real vendor Altium `.SchLib` through KiCad's own reader
(two same-length one-key patches fault at `sch_io_altium.cpp:5919`, fixed
clean, 23 PASS/0 FAIL twice, trace `42db33cb…`), with `SizeZ=9/7/1` reading
file-chosen `0x40/0x32/0x07` at `data()-4`. Cjose W184 corrected the
mod_auth_openidc key-path claim and measured a real 2.4.15.1 module rejecting
a 56-byte encrypted_key at `jwe.c:577` before AES-KW (all three POSTs HTTP 400).
Modauthoidc W17 put a wire-chosen NUL on the non-ASan production allocator
stack (all five padding lengths 302, parent 5/5 vs released 0/5); sofiasip W14
wrote 15 out-of-bounds live timer pointers (rc 134, controls clean) holding
heap pointers, not chosen data. Libgphoto2 W167 executed a chosen marker in a
plain real build only when the local vusb device supplies the process canary
— author-only and unwitnessed, while #2892 stays scoped to rung 3, with replay
ask #3081. OpenEXR W168's OIIO build blocker and munt W177's 404/403 PoC
availability negatives leave their UNKNOWNs unchanged; vrpn W21's large-index
exit-139 rows were mapped by W23 to the NUL store with
`si_addr == sender_name + index` in the ASLR layout, not an outside-stack
assertion; the gdb-fixed-layout SIGBUS remains a layout artifact.

CodebaseMemory2Shell and Assimp2Shell were admitted 02:3xZ/02:2xZ as the 125th
and 124th routes with charters, routes, wake units and adopted windows; their
rows are ADMITTED, not FRONTIER-STAGED. Frontier's fltk2shell W195 and
synchronet2shell W194 were admitted at 05:4xZ as the 128th and 129th routes
with charters, routes, wake units and adopted windows 131 and 130; FLTK's
witness W195 ESTABLISHED rungs 1-4 at the labeled scope is folded into its row. The
same window recorded three ceilings without moving a rung 5 cell: libfontenc W187/W188 overwrote a live `FontMapRec.recode` inside Xvfb to a chosen benign-marker address, but libXfont2 recodes only the mapping allocated before the buffer, so the hijacked pointer is never invoked — control-flow diversion in the live server is blocked by consumer behaviour, not grooming (W186's public-API marker stands at its own scope). Sdlmixer W191 checked all 712 LUT-derived saved-RIP address forms against the live no-SSP process's 33 mappings and found none mapped, closing the non-PIE variant. BusyBox W3 measured glibc's `av->system_mem = 0x21000` top-size guard, which rejects the `-1` wraparound, while a guard-passing value only returns `rbuf+80` inside the overflow; that primitive supplies no code pointer. These are negative results, not downgrades: the three rows' witnessed grades stand at their labeled scopes.

The 04:1x–05:4xZ edges staged two further candidates and recorded several
measured negatives without moving a rung 5 cell. Frontier W196 staged
fontforge2shell (CVE-2026-135295, FontForge <= 20251009, fix `65e80b5`) and the
operator admitted it 05:4xZ as the 126th route: a truncated PCF BDF_ENCODINGS
table makes `getformint16()` return `glyph=-1`, bypassing the lower bound and
writing a file-derived word before `encs`; pinned verbatim function, gcc ASan
WRITE-4 at `harness.c:126`, plain abort 134, fix and complete-table controls
clean, gdb `4d 49 53 00` ("MIS\0") at `encs-4` with the top byte structurally
zero. 5/5 expected RCs. A docs NIT claimed the quoted normalized hash
`56fd8ada…5633bb` was unreproducible (`320bc5f7…940094`); operator resolved it
05:3xZ: REPLAY.md documents `grep -E '^asan-|plain-|normalized gdb' … |
sha256sum` with `plain-` UNANCHORED, which reproduces `56fd8ada…5633bb` exactly
on the tracked `evidence.log`, while anchoring `^plain-` gives
`320bc5f7…940094`. The negative is preserved as a grep-anchor procedure
difference, not a hash contradiction.
LibreCAD W196 (CVE-2026-135294) was screened out from the pinned v2.2.1.6 DXF1
filter and fix `4e51048`: a ~4 GiB sparse file narrows to a fixed NUL
underwrite before an 8-byte buffer; no build, trigger, bytes, window or
witness, and no row. Assimp W4 closed the live-aiMesh placement lane
negatively: the overrun is always four bytes onto glibc chunk metadata,
fourteen forged size values abort, no grooming or clean-import control; the
rung-4 write and witness #3277 stand. Munt W179 forged a plausible top-chunk
size in the copied SysEx tail; real glibc accepted it, the next harness malloc
returned `buf+32784` and rewrote the size, while watchpoints saw zero
in-library reads — allocator metadata, not an upstream object, grade
unchanged. Imgproxy W2's fine TIFF over loopback HTTP timed out on the
vulnerable leg and returned 500 on the fixed leg with no paint path (above);
cjose W189 measured no wire route into W188's groomed hole: state-cookie CEKs
are consumed before the vulnerable CEK, which stays in top chunk with no live
pointer behind it, under full ASLR and a PIE module. Modauthoidc W20 attributed
the harness :219 PC from the kernel's own SIGSEGV record (four faults in six
trials, `addr2line` mapping to pinned `state.c:219`, `Code:` bytes matching
objdump) — debugger-free attribution only; the live-wire PCs stay
debugger-observed and the byte stays NUL.

The 04:5x–05:0xZ edges close one owed witness verdict and add one bounded
negative on an existing admitted lane; neither moves a rung 5 cell.
Imagemagick W181's independent witness DM #3204 replays the real-library
direct-call scope from clean `git archive a073540`: 5/5 pins, the author's
`REPLAY.log` hash `385bbe95…c01667a` (recomputed here) and witness
`evidence.log` `5547d698…ce40d3`, normalized diff empty except build path and
BuildId. ASan `WRITE of size 1` at `stream.c:1576` via `:1279`/`:2778`, clean
same-size and fixed controls, plain-build gdb bytes `0x42..0x48`; the verdict
is **ESTABLISHED rungs 1-4 at the labeled in-process scope, NO r5**. The
witness excluded file/coder reachability and the CLI `-extract` READ, and
flagged as a labeling NIT that those bytes are the harness's `0x41+(i%26)`
pixel pattern with harness-forced geometry growth: write-content/destination
control in-process, not attacker-chosen bytes or pointer/IP control. The
Imagemagick2Shell row's "unwitnessed" wording is superseded; the advisory's
"crafted images" path stays UNKNOWN. Vrpn W24 sends the shortest possible
framed message — a 24-byte header declaring `header[0]=24`, so `payload_len`
is zero — and measures a `size_t` underflow in the `strncpy` length at pinned
`vrpn_Connection.C:4548` (SENDER) and `:4476` (TYPE); the fix leaves that
expression and clamps only the later index write. ASan reports
`negative-size-param (size=-4)` on both sinks (exit 1); the plain vulnerable
server faults at the stale huge index (`:4554`, SIGBUS/SIGSEGV), not in the
copy. With glibc 2.39 a 512-byte groom leaves all 48 dumped destination bytes
unchanged (zero-store), so there is no chosen byte and no rung 4 promotion;
behavior on another libc is UNKNOWN. Fixed-binary, safe-28 and vulnerable
groom-with-zero-index controls survive; `out-w24-plain-safe/` declared 28
bytes without a body, never reached the handler and is preserved only as a
malformed-harness negative. Author self-observation, no independent replay
and no new rung.

The 05:4x–06:0xZ edges admit one real Contiki-NG lane and deepen four admitted
lanes without moving a rung cell. Frontier W198 staged it and operator
`2f48681` admitted `contiki2shell` under
CVE-2026-135292 with a pinned `release/v5.2` tarball (`78133c77…70819c95`) and
PR #3312 still open: a short S=3 MPL HBHO seed option passes the 16-byte seed
read, and the trickle-time header rebuild copies 1232 bytes 16 past the
1280-byte global `uip_aligned_buf` (`mpl.c:981`, ASan global-buffer-overflow
WRITE). A gdb readback shows chosen `MISHE-OO-TAUF!!\0` bytes at offsets
1280..1295; fixed and complete-option controls are clean and `run-all.sh`
reports 9 PASS / 0 FAIL. The injection is in-process with no tun device, so
the advisory's remote route stays UNKNOWN and rung 4 is PARTIAL. At staging
time window 134 had no charter; the operator's admission added a charter,
route, mind and the three wake units from the exact full-flag sync.
Fltk W195's witness #3296 (ESTABLISHED rungs 1-4 at the direct-call scope) is
already in its row; the pin correction and clean replay now point at `072dc75`.
An author-measured, unwitnessed extension drives the same crafted BMP through
`fl_register_images()` and `Fl_Shared_Image::get()` in a headless consumer: the
vulnerable `plus1632` tree still aborts at `Fl_BMP_Image.cxx:490` with ASan
`2 bytes before 4294967298-byte region`, the fixed tree is clean, and the
FLTK row's "ICO UNKNOWN" sentence is superseded by a clean negative — the
8-bit IconDirEntry width/height override the crafted DIB (`:201-205`), so
both truncated and complete crafted ICOs stay ASan-clean. No GUI, wire,
pointer/IP, command or new rung; the shared-image lane needs witness replay.
Imgproxy W3 puts the primitive into a live loopback HTTP consumer: a 54-byte
ICO with `data_size=0xfffffff5` kills three fresh imgproxy 4.0.0 processes in
19-72 ms (`rc=2`, `malloc(): corrupted top size`, Go frames through
`vips.(*Image).Load` at `vips.go:293` and `initialLoadImage` at
`processing.go:161`), a valid favicon returns 200 and the pinned v4.0.16
loader replacement returns 500 `ICO image data is too large`. A clean
`7ec6de8` replay matched; an ASan-built imgproxy returned HTTP 500 with no
ASan report with and without `libasan.so` preload, a preserved toolchain
negative. No live C write-site frame, chosen-byte readback, pointer, command
or r5; the endpoint limb is now a live crash, not just header/entry.
Synchronet W1 (`d0c1a2c`) replaces the harness stub with the vendored cryptlib
built from the pinned `42f586d7` parent: ASan `WRITE of size 64` 0 bytes past
an exact 41-byte heap destination through `cryptGetAttributeString` →
`attributeCopyParams` → `memcpy`, and the real getter writes chosen values at
session offsets 44/48/52 (40-byte control clean). A loopback SSH pty-req probe
failed to deliver TERM (`-43` poll, broken pipe, protocol errors), so wire
reach, the claimed DoS and r5 stay UNKNOWN; the row's no-BBS/no-wire boundary
holds and witness replay is still owed.

Operator `2f48681` admitted Contiki2Shell as the 130th route with nine PASS /
zero FAIL re-verified at admission and no grade change. Witness #3309 returned
ESTABLISHED for FontForge's direct-call rungs 1-4 at the labeled scope with NO
r5; the later real headless `Import()` path (`REACHABILITY.md`, truncated PCF
`0c8dc0fe…528703`, ASan `WRITE of size 4` at `fvimportbdf.c:1751`) is author
evidence only. LibRaw W2's `craft_nonzero_poc.py` makes the OOB halfwords
nonzero (`0xffff` at index 68,644) from a real decode, but the value saturates
and witness W186 covered only the original zero-valued claim. CodebaseMemory
W3's per-query ASan stderr closes the tool-path clean-archive replay gap.
Ruby's unmodified-Rails N=524 matrix measured a genuine allocator split while
every safe, fixed and seeded-search control held; it produced no address
oracle, surviving exploit process or second command. None of these edges moves
a rung cell.
Fltk's plain-build metadata probe puts the file's chosen `53 49 4d 2d` bytes
in the high half of a live glibc mmap chunk size (`0x2d4d495300001002`), but
the truncated-input destructor reaches `munmap_chunk()` and exits 0 with no
diagnostic — a preserved negative for an observable allocator failure.

Cjose W190 checked the remaining jansson length-corruption pointer-source idea
against the pinned object layout and the W183 heap log: `value` sits at object
offset 16 and `length` at offset 24, so the sequential AES-KW write must
replace the ASLR-randomized pointer before reaching the length. No lab input,
build, byte, witness, command or rung; rung 5 stays NOT ACHIEVED and no row
changes.

Assimp W6 (`62466f7`) enumerated two unchecked glTF 1.0 accessor sites on the
real importer path: MAT4/FLOAT TEXCOORD_0 reaches the same `ExtractData` write
(`glTFImporter.cpp:289-290`, ASan WRITE-64 past a 12-byte `aiVector3D`, plain
rc 139), and a TEXCOORD/POSITION count mismatch drives a separate 4-byte OOB
READ in the Y-flip loop (`:299-302`) that PR6860 leaves and PR7090 does not
address. `harness/run-w6.sh` reports 18 PASS / 0 FAIL with a clean
matched-count control; no chosen byte in a live `aiMesh`, no pointer/IP,
command, witness or grade change.

The 06:3x–07:0xZ edges add one real-file lane, three boundary measurements,
two author clean-archive receipts and two screened candidates; no rung cell,
verdict or mind count (130) moves. BusyBox W5 (`659b379`/`a27d4bc`) closed the
last post-overflow allocation hedge on the stock 1.37.0 client: an 84-byte
DATA TFTP block still overwrites the top-size word at `rbuf+72`, yet the DATA
consumer never allocates after the overflow (rc 0, 80-byte file), while the
ERROR consumer aborts rc -6. `python3 lab/frontier/busybox2shell/data_probe.py`
logs `8d22cfe3…b11e6267e22c7aa3c` (three legs, two identical runs); a clean
`git archive 659b379` replay is byte-identical. Assimp W6's clean
`git archive 62466f7` replay (`7d8495b`) rebuilt all libraries, ran
`run-w5.sh` 13/0 and `run-w6.sh` 18/0, and matched all nine normalized traces
(`b4dd27d1…3054e0a`); still author-only and outside witness #3277's baseline
scope. Contiki W199 measured `/dev/net/tun` opening successfully but
`TUNSETIFF` returning EPERM, so the row's "no tun device" sentence is stale:
the ioctl, not device absence, blocks the route. In a lab-only 1400-byte build
the truncated option overwrites live `uip_appdata`/`uip_sappdata` globals with
chosen ASCII words `0x4847464544434241`/`0x504f4e4d4c4b4a49` while the
complete option leaves them intact; the bytes are not valid addresses, and
there is no wire deliverer, witness verdict or rung 5.

FLTK's wake-4 probe (`9cc8dd4`) reaches `array-16` with a 77-byte BMP
(`faef54c9…fb506c`, geometry w=8, h=0x0aaaaaaab), writing chosen file bytes
into both glibc mmap chunk-header words; plain rc 139 versus fixed rc 0, with
a preserved unmapped-page negative from the first `array-24` attempt. The row's
"ICO ... UNKNOWN" phrase is superseded: ICO is a measured negative at the
tested geometry, and wake-3's silent `munmap_chunk()` plus wake-4's free-path
variance stay author-only. Synchronet W2 (`78328ad`) drove a real loopback
OpenSSH handshake with `none` auth, pty-req and shell accepted against a
sequencing cryptlib server, but the TERM attribute reads -43
(`CRYPT_ERROR_NOTFOUND`) for channel IDs 0–7, so the 64-byte cap and chosen
offsets are not wire-measured; the row's "no SSH handshake or wire" is stale,
and no pre-auth `sbbs3` path, DoS or rung 5 follows; W15 later reached the copy
after valid password login in a real `sbbs3` build (author-only). Sdlmixer W195
(`1292e08`/`11adba7`) fed real AIFF-C files through three new AIFF-enabled
real SDL_mixer 3.2.4 builds: ASan `WRITE of size 4` at `decoder_aiff.c:95`
through `MIX_DecodeAudio` and the playback thread, fixed build returns 1024
bytes clean, gdb chosen LUT word `0xbae001c0`, `check-real.sh` 51 PASS/0 FAIL
(trace `4d96b2b6…d101f9ffc8`), one-command `sh harness/aiff/run-real.sh`
given provisioned `deps/`. This is author-only rungs 1-4 for the separate AIFF
CVE, unwitnessed, with no wire listener, pointer/IP or command. Frontier
screened out MediaInfoLib (CVE-2026-135440, a stale-read UAF; two ASan build
attempts reached 32/293 objects in 420 s and 37/293 in 600 s, no report) and
libgsf (CVE-2026-116124, a source-derived 16 GiB file-size floor; no build or
trigger): both rung UNKNOWN with no charter, window, witness or mind-count
change.

Libheif W186 (`40ff079`) enumerated every `extend_padding_to_size` call site
in pinned v1.23.6: one public wrapper and six encoder plugins, zero decoders,
so a decode-only consumer cannot reach the write. Source-only negative, no
new build, bytes or grade change.

The 07:1x–07:4xZ edges deepen ten admitted lanes without moving a mind count
(130) or adding a rung 5. Munt W180 (`e4430ca`) audited every non-test
`parseStream()` call length in the pinned 2.8.3 tree: ALSA (5572 measured),
OSS (1024), Win32 ring (32760) and Win32 `MIDIHDR` (4096) stay below the
one-call threshold, but `CoreMidiDriver.cpp:34-36` forwards 16-bit
`packet->length` and `winmm_drv.cpp:320-324` forwards `midiHdr->dwBufferLength`
with no Munt-side clamp. Both are local, unbuilt on this Linux host, and
whether they can emit >32768 bytes stays UNKNOWN; the row's earlier
"all in-tree call sites are non-network" claim is narrowed accordingly. Vrpn
W25 (`ed9d7c7`) swept -1..-128 negative indices on stock plain `-O0` loopback
processes: only -4 and -8 fault (exit 139), with -4 gdb zeroing byte 4 of the
live `endpoint` pointer (`0x5555556f3220` → `0x5500556f3220`) at `:4560`, the
same W3 primitive at a different byte; fixed -8/-16, safe 4 and all other
indices stay ALIVE, and the -128 gdb continuation timed out UNKNOWN. Codebase
Memory W4 (`ff10d85`) explains the WITH negative structurally:
`with_add_vbinding_var()` (`cypher.c:3585-3591`) stores only while
`vb->var_count < CYP_BUF_16` (16), and both WITH executors call it, so items
17+ are dropped and the 48-item query returns 1 row / 1 column; no WITH-side
WRITE was reproduced. All three are source/author-only with no witness,
command, pointer, new rung-4 boundary or rung 5.

LibRaw W3 (`949f138`/`be36dec`) changed one DNG WhiteLevel u32 at `0x102` to
steer the OOB store at index 68,644 to three distinct non-saturated halfwords
(`ffff ea99 ffff 0000`, `afdf 7544 9c55 0000`, `57ec 3a9f 4e27 0000`,
`2bf5 1d4f 2712 0000`); all four inputs were regenerated by the witness in a
clean room (DM 3413), after W187 (DM 3405) had already upgraded rung 4 from
PARTIAL to a demonstrated chosen-nonzero write — that verdict is the one rung
cell that moved. Synchronet W3 (`fe8cb5c`/`559d495`) showed W2's TERM `-43`
was a probe artefact: a real loopback OpenSSH pty-req TERM=64 reads
`status=0 len=64` and writes chosen `0x54` at 44/48/52 with ASan WRITE-64,
clean 40-byte and fixed-form controls, and `run-wire-proof.sh` 10 PASS / 0
FAIL. Witness wake 189 (DM #3427, `86ed83c`) rebuilt `libcl.a`
(`584494ac…952e3c2`) and graded rungs 1-4 at the synthetic-struct scope
ESTABLISHED with byte-varied `MISH`/`E-OO`/`TAUFTAUF`; W4's follow-up
  (`0e66d24`) records an unprovisioned real `sbbs3` build failing on missing
  `zip`, autoconf-2.13 and libarchive/NSPR headers, a tooling negative; W15
  (`e0f11cd4`) provisions those deps locally and does build and drive `sbbs3`.
OpenEXR W177
(`4a66f9f`/`2f1554d`/`40aeb08`) closed the partial-overwrite escalation
hypothesis negatively: 264-byte copies rc 1 `DECODE rv=31`, 268-byte copies rc
134 `free(): invalid pointer` (3/3 each), guarded deltas exactly `copy-64`,
and gdb showing only the destination itself among live pointers and unchanged
words at `dst+272`/`dst+304`; `RESULT PASS` three times in-tree and once from
a clean `2f1554d` archive. W173 had already closed OIIO as a static-source
negative, superseding the row's "resume the OIIO build" wording.

FLTK W5 (`67436e5`) reached a real X11 FLTK 1.4.5 app on private Xvfb :177
(all four cases `draw_count=1`) and faults at image load, before draw, in the
vulnerable ASan tree with `WRITE of size 1` at `Fl_BMP_Image.cxx:490` and rc
134 versus rc 0 for safe/fixed; author-measured and UNWITNESSED, outside
#3296's four-tree scope. FontForge W2 (`1f26ade`) measured three chosen bytes
(`4d 49 53 00`) at `encs-4` in the real plain `Import()` process with a
hardware watchpoint, plus rc 134 `double free or corruption (out)` against
patched and complete-table rc 0; also author-measured and UNWITNESSED, outside
#3309's direct-call scope. W3 (`88d6c5e`) then identified the consumer in the
real plain build: the four bytes at `encs-4` are the high half of `encs`'s own
glibc chunk size, which changes `0x21` → `0x0053494d00000021`, and
`free(encs)` at `fvimportbdf.c:1770` was caught reading the corrupted header
just before the abort while patched and complete controls keep `0x21`.
Metadata corruption, not a pointer primitive; a zero-valued variant
(`0912800`) keeps the size word at `0x21` and the plain build clean while ASan
still reports `WRITE of size 4`, so impact depends on the file-derived value
and some other plausible chunk size is UNKNOWN. Author-only, unwitnessed, no
grade change. The FLTK GUI receipt's hash NIT was repaired in `27ef17b`: its
README now quotes `gui.cxx` as `b84e070c…853bc`, matching `inputs.sha256` and
a fresh `sha256sum -c` (3/3 OK); witness replies to #3359/#3379/#3391/#3423
have not landed, so no verdict or grade changed.
Jq's operator DM #3419 (`2bcdde2`) screened the
adjacent GHSA-cfh2-vwfq-qfmm NOT admitted (file-facing `--rawfile`, no RCE
claim, ~4.2 GB peak RSS against the 2 GiB guard): a named disposition, with
14/14 pins rechecked from the lane directory and no build, replay or grade
change. Cjose W191 (`32b39fa`) re-delivered the three still-unwitnessed replay
offers (#3105/#3141/#3232 as chat #3429) once; no experiment, build, verdict
or grade change — author reports are never acceptance.


The 07:1x–09:2xZ edges stage one new target and deepen four admitted lanes
without moving a rung 5 cell. Frontier staged StbVorbis2Shell (`e6ef1fc`,
brief `reports/frontier-stbvorbis2shell.md`) on CVE-2026-89266:
`setup_malloc()` truncates a `size_t` product of file-derived codebook
dimensions to `int`, so a 205-byte OGG asks for 8 bytes and then writes floats
through it. Through the real upstream `stb_vorbis_open_memory()` public API
ASan reports `WRITE of size 4` at `stb_vorbis.c:3889`, the dev-branch fixed
control is clean, and gdb reads four file-chosen bytes `4b 43 41 48` ("HACK")
at the first out-of-bounds float (`run-all.sh`, 9 PASS / 0 FAIL). That is rung
4 PARTIAL at the repeating-word, single-offset scope: no per-offset arbitrary
bytes, measured write count, pointer, command, real consumer or wire, and no
witness verdict. Two-pane window 135 is live and registered, but there is no
charter or wake unit yet, so it stays FRONTIER-STAGED and the mind count stays
130. OpenEXR W180 (`9f42ba6`/`c13625c`) adds file-steered destination offsets
to the mixed-channel lane, and Imgproxy W5 (`4c4937d`/`2b0cc2e`) reaches a
live tcache `next` pointer under stochastic grooming; both are folded into
their rows above and remain author-only, unwitnessed rung 4 with no r5. Cjose
W192 (`b113a99`) replayed the W188 groomed-fptr lane from a clean `git archive
1212b10` (`PASS=223 FAIL=0`, four outputs matched after address normalization,
5/5 vulnerable marker calls and 0/3 fixed); CodebaseMemory W5 (`1a69ceb`)
fixed `mcp-tool/replay.sh` to extract before verifying pins and replayed all
three tool rows from a clean tree with canonical hashes after normalizing
volatile tokens. Neither closed an independent-witness gap at that edge; the
Cjose gap was closed later at W194 (#3566): the witness replayed the W188
groomed-fptr limb independently from clean `git archive 8c717a2` (7/7 pins,
`REPLAY_W188_OK`, `PASS=223 FAIL=0`, exact trace
`455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7`) and
graded it ESTABLISHED AS LABELED at the lab-known-address direct-call rung-4
scope — no wire path, no ASLR defeat, no command, no r5. CodebaseMemory W5's
replay stays author-only. FontForge W3's
silent zero-value variant (`zero-write.pcf`, unchanged `0x21` chunk size in
the plain build, ASan still `WRITE of size 4` at `fvimportbdf.c:1751`) and
FLTK W6's repaired `gui.cxx` hash (`b84e070c…853bc`, `sha256sum -c` 3/3 OK)
are replay receipts, not verdicts or grade changes.
LibRaw W6 (`a62418d`) calibrated DNG WhiteLevel 11,036 to hit one pre-chosen
halfword `0x4141` exactly at index 68,644 in the real `dcraw_emu` frame;
bracketing WL 11,035/11,037 and a failed `0xdead` target are preserved, so no
arbitrary 16-bit alphabet, pointer, wire or r5, author-side and unwitnessed.

The 12:1xZ author-side limbs deepen two admitted lanes without moving a rung
cell. AwsLc W204 (`0d3fc55`) put a one-byte tag ahead of scratch in a naturally
aligned struct, so the OOB byte lands on a pointer LSB; W205 (`6702e15`) added
`natural_call`, with `scratch[31]` at offset 1 and a table-slot pointer at
offset 32 and no `#pragma pack`. Vulnerable: low byte `0x00` -> `0x48` and the
following indirect call executes `BENIGN_MARKER_EXECUTED`; fixed and
safe-input (`00`) call the normal handler. `run-consumer.sh` -> 31 PASS /
0 FAIL, `run-all.sh` -> 14 PASS / 0 FAIL. The 256-byte-aligned dispatch table
is still lab grooming and a throwaway GCC 13.3.0 stack-layout probe found a
9-byte gap between OOB index 31 and the canary, so no natural stack-canary hit
was observed. W204/W205 are author-measured with no independent replay of
these limbs (W195's consumer verdict covered the earlier scope); rung 4 stays
the witnessed synthetic-consumer scope, r5 UNKNOWN. LibRaw W8 (`5fe148e`)
measured the plain `-O0` heap extent on this host: the D=1024 exact-hit input
starts at `destimage=0x55555573abc0` in a 2,147,632-byte chunk with one
134,944-byte free top chunk before the `[heap]` edge `0x555555968000`; stores
continue 17,378 indices before faulting at `0x555555968bf0`, and three crafted
inputs exit 139 with empty stderr outside gdb. No live neighbour or pointer
lies on that path, so it is a structural negative, not a new primitive;
arbitrary bytes, pointer/IP, wire and r5 stay UNKNOWN. CodebaseMemory W7
(`0f98a70`) only folded the already-published local stdio `query_graph`
tool-path reach into the stage brief: no published claim was stale (doc-ok).

Two bounded negatives landed at 12:3xZ. Imgproxy W6 (`314fa5d`) measured the
glibc 2.39 safe-linking bound on W5's live tcache pointer: `next` is stored as
`ptr ^ (pos >> 12)`, so W5's raw wire value `0x4141414141414141` decodes to a
noncanonical address and cannot itself name an allocation. Under gdb a mapped
heap-derived chosen target makes the first `malloc(0x20)` return the victim and
the second return the chosen address (`0x7fff700580e0` / `0x7fffa4058400`),
but the encoding and target are computed under gdb, not from wire bytes;
addresses varied between runs and the layout is stochastic. An unmapped target
faulted in `tcache_get_n` (a target-selection error, not a bypass), and the
fixed control answers HTTP 500 with zero breakpoint hits. No write through the
chosen address, marker or command; witness W200 later replayed W3–W6 from a
clean archive and ESTABLISHED them AS LABELED; W7 stays author-only, and the
row's rung-4 ceiling and r5 UNKNOWN stand. Munt W182 (`baa31e6`/`ee30755`)
measured and clean-archive replayed the post-overflow second-call reuse
negative: a second 40,001-byte `parseStream()` call writes zero new bytes
because the parser already holds `streamBufferSize=40001` with capacity 32768
and takes the discard branch; each `0xF7` increments the debug counter without
dispatch, while a later complete SysEx still dispatches, with all six modes
rc=0. No held-state reuse or new consumer of the forged tail; rungs 1-4
ESTABLISHED and r5 UNKNOWN are unchanged.

The 12:5x–13:0xZ edges deepen four admitted lanes and stage one new runtime
without moving a rung cell or the mind count. Imgproxy W7 closes the
wire-only derivation of the safe-link key on the wrapped ICO path: pinned
`vips_foreign_load_read_full` (`vips.c:1302-1315`) returns 1 only after
consuming the whole requested length, so a short 0xfffffff5-byte source exits
`icoload.c:161-164` before the PNG test or BMP reconstruction; four loopback
probes (pattern, complete PNG, IHDR-only, lying IDAT) abort in 13-17 ms with
`rc=2` and no HTTP response, and an error-path source review found no heap-byte
reflector. A clean `git archive 6f8581a7` replay reproduced the pattern and
PNG legs; author-only, unwitnessed, rung 4 unchanged and no r5.
Openexr W184 makes the *whole* second-stage OOB copy file-chosen: with N=64,
`split=128` and `unpacked_size=256` the first inverse-sort copy fits exactly,
and the second writes 128 bytes at `decode.unpacked_buffer+256`; the guarded
allocator and gdb read back all 128 bytes as `0x3c` or `0x5a`, fixed 3.5.3
rejects with `EXR_ERR_CORRUPT_CHUNK`, and `sh harness/mixed-full-check.sh`
replayed `RESULT PASS` 3x with nine byte-stable logs whose aggregate
`sha256sum evidence/full-oob-*.out | sha256sum` is `d04f151a…946f` (recomputed
here). A clean `git archive aad2c431` replay matched. Author-only and
unwitnessed: the unguarded ASan build aborts on the first copy's OOB source
READ, so the WRITE is guard-and-gdb measured, not ASan-observed.
Libheif W188 found a source-level sequence consumer in ImageMagick 7's HEIC
coder (`coders/heic.c:2076`, `:2202-2205`, `:2230-2349`): the track takes the
first frame's dimensions but later frames keep their own, with no size check.
W189 tested that hypothesis with a real ImageMagick 7.1.2-34 build linked to
the pinned libheif v1.23.6 static library: a two-frame 512x64 / 64x65 input
(SHA-256 `73590bbd…f392d`, recomputed here) encoded `.heic` as two still
images and `.avif` as two mixed frames, both rc 0; `check_im_consumer.py` gave
7 PASS / 0 FAIL. The sequence branch is AVIF-only (`heic.c:2516-2547`) and
selects AV1 (`heic.c:2141-2142`), whose pinned encoder never calls
`extend_padding_to_size`; no crash, chosen bytes at the sink, pointer or grade
change. The gdb padding breakpoint is not a clean negative (two static copies
of libheif were linked). Author-only, unwitnessed, rung 5 UNKNOWN.
Frontier staged Lwnode2Shell (CVE-2026-135746 / GHSA-mvm7-rjgq-6j36, PR base
`b3de7be5`) on the one-byte `WriteOneByte()` capacity overflow: the verbatim
pinned loop under ASan reports `WRITE of size 1` 0 bytes past an 8-byte
destination, the plain build reads back chosen `0x48`/`0x5a` at `byte8`, and
`sh run.sh` gives 12 PASS / 0 FAIL, matched from a clean `git archive ba01845c`.
No lwnode/Escargot build, JS trigger or real API call; witness #3720 replayed
clean `git archive ba01845c` with 12 PASS / 0 FAIL, exact pin and loop hashes,
ASan `WRITE of size 1` 0 bytes past an 8-byte region, chosen byte at slot 8 and
clean fixed/safe controls: ESTABLISHED AS LABELED, no grade change, NO r5.
FRONTIER-STAGED only — no charter, route, wake unit or mind
count. The duplicate llamarpc2shell staging was reverted in `8eaf510f` and
`e5ae3bd9`, leaving its admitted row unchanged.
Assimp W12 audited the optimizer flags: the W10/W11 "`-O1`" plain libraries
actually ended at `-O3`, because CMake's `Release` flags are appended after
the requested `-O1`. `bash harness/run-w12.sh` rebuilds pinned v6.0.6 with
explicit `-O{0,2,3}` and gives 17 PASS / 0 FAIL: both chosen fault addresses
(`0x41414141`, `0x42424242`) survive gcc -O2/-O3 at `glTFImporter.cpp:475`,
while -O0 aborts on a stack canary before the dereference; the safe input
stays clean and the normalized trace `f2f6d6ee…c7d8af` was byte-identical in
a clean `git archive 3f540a2e` replay. Author-only and unwitnessed; W11's
clang negative stands, no valid object or code pointer, no marker, command
or r5.

The 13:2x–13:4xZ edges deepen five admitted lanes without moving a rung cell
or the mind count. Witness W200 (tape #3635) replayed Imgproxy W3/W4/W5/W6
from `git archive 314fa5d` with only the two gitignored CLI binaries
symlinked: the live HTTP vulnerable process aborted at W3, W4's 32 chosen
bytes and symbolised `read_full` write site matched, W5's PRE live pointer was
overwritten with `0x4141414141414141`, and two of seven W6 attempts returned
the encoded chosen tcache target. All four are now ESTABLISHED AS LABELED at
their existing LIVE rung-4 scope; the key was gdb-derived, no write through the
chosen address, marker or command, and r5 stays UNKNOWN. W7 itself was not
replayed and remains author-only.
Cjose W195 widened the real-consumer forward scan from 2 KiB to 8 KiB: of
1024 words after the CEK only three sat in libc mappings at `cek+32/+112/+136`,
with `cek+40` holding the top-chunk size `0x1bd41`, so they are stale
FILE/vtable remnants in free space, not a live pointer; the run-specific W188
"all 512 words outside mappings" wording is corrected, not the ceiling.
Openexr W185 tested whether W184's 128 fully chosen bytes could replace a
live pointer: the flat harness's `exr_decode_pipeline_t` is stack-resident,
both scratch pointer fields lie outside the window and are unchanged, and
unmodified `exrcheck -c` has `PTR-HITS total=0`, prints `bad` and exits rc 1
while fixed 3.5.3 rejects earlier with `EXR_ERR_CORRUPT_CHUNK`; a clean
`git archive 22a8eeec` replay matched, author-only and no grade change.
LibRaw W9 found the plain-build heap reach is allocator-config dependent: at
D=512 the default environment leaves ~135,968 bytes to the `[heap]` edge and
faults at index 85,640, but `MALLOC_TOP_PAD_=0` makes `destimage` mmap-backed
and moves the fault to index 172,038 (D=512, libgcc_s read-only page) or
533,510 (D=1024, libc page). That knob is a lab environment setting, not a
crafted-image field: no pointer, marker, wire or r5. CodebaseMemory W8's
read-only gdb frame map shows `vals[]` immediately below `func_bufs` and the
upward OOB write starting 16,408 bytes above the last row pointer, so a
direct overwrite of the projection row pointers is structurally excluded for
this pinned gcc `-O1` build; higher-stride placement stays UNKNOWN, and no
source, pin or grade changed.

The 14:0x–14:1xZ edges add two real-consumer mechanics and two bounds
without moving a rung cell or the mind count. Imgproxy W8 (`a9309b1c`) uses
a 20-byte ICO body to change only the low 16 bits of a live safe-linked
tcache `next` from wire bytes while preserving the `0x35` victim size; in
three of six gdb runs the decoded relative pointer became the live
allocation head, but the key and absolute destination are unmeasured and no
later allocation through that head was proved in a plain process. A
clean-archive replay (`59d008f6`) returned `W8_RESULT PASS=4 FAIL=0
PARTIAL_NEXT=2 PLAIN_SURVIVAL=3` with fixed controls clean. Witness W201
(#3660) replayed that clean archive with both probe hashes and all seven W8
log hashes matching and graded the claim ESTABLISHED AS LABELED
(`PASS=4 FAIL=0 PARTIAL_NEXT=4 PLAIN_SURVIVAL=3`, layout is stochastic): the
high six bytes of `next` stay intact, the decoded relative head equals the
post-malloc tcache head, and a `LOW=0x1234` counterexample confirms the bits
follow wire bytes rather than a natural zero. No later allocation through
the wire head, key derivation, absolute address, code-pointer write or r5;
grade stays rung 4 and W7's no-wire-only-key boundary stays closed.
FontForge W5 (`7cbb2502`) writes the
low half of the chunk size word (`0x21` → `0x91` at `encs-8`) in the real
headless `Import()` process; glibc accepted the corrupted 16-byte chunk into
tcache bin 7 at `free(encs)`, while high-half and zero-value controls abort
and a conditional malloc breakpoint after the free never hit. No GUI build
was attempted (GTK-3 dev packages absent), no pointer/IP or command was
observed, author-only and no grade change. Cjose W196 (`01f4c677`) dumps the
CEK at `free()` entry with `--wrap=free`: all 40 chosen attack bytes were
already zeroed by `_cjose_release_cek()`, so tcache `next`/`key` never see
chosen bytes, and RFC 3394's 8-byte write granularity rules out partial
pointer overwrites on 16-byte-aligned glibc objects; structural negative,
no new rung.

The 14:1x–14:3xZ edges add one live allocator-metadata observation and two
bounds without moving a rung cell or the mind count. OpenEXR W186
(`5ebbfdf8`, `c2321f17`) watches unmodified `exrcheck -c` write a fully
file-chosen `0x41` into the live adjacent chunk's size word at `dst+264`
(`0x31` before) while its `prev_size` becomes eight chosen bytes; eight other
chosen words and a uniform control all give the same rc 1 `bad` under one
fixed-length filename, while the same bytes under a longer argv abort with
`munmap_chunk(): invalid pointer` — heap layout, not the chosen word, decides.
One-command replay `sh harness/chunk-header-check.sh` prints `RESULT PASS`
with nine byte-stable evidence hashes (aggregate sha256 `f878197c…1755e01`,
recomputed locally) and a clean-archive receipt; no pointer, wire, marker or
command, file-level rungs 1-4 only, author-side and unwitnessed, rung 5
UNKNOWN. AwsLc W206 (`145bd6c2`) closes the heap-metadata lane in plain,
non-ASan builds: on glibc 2.39 `malloc_usable_size(31)=40`, so the CVE byte
at offset 31 lands 9 bytes short of the next chunk's size word and 17 short
of a following `malloc(16)` object; vulnerable byte31 `0xab`→`0x48`, fixed
stays `0xab`, and both headers and neighbours are unchanged in 10 PASS /
0 FAIL locally replayed. ASan redzones poison those slack bytes, which is why
a plain build is needed; stack layouts, embedded structs and other
allocators stay UNKNOWN, grade unchanged, no witness. LibRaw W10
(`4c550617`) adds DNG BlackLevel as a second file-controlled integer knob:
a 441-point WhiteLevel/BlackLevel grid reaches two further pre-chosen
halfwords exactly at index 68,644 — `0xdead` at WL=3,230/BL=6 and `0x2222`
at WL=21,084/BL=1 — each 3/3 stable under unmodified `-O0` gdb with ASan,
fixed and no-option controls clean. A first grid that passed `"-n 1"` as one
argv element produced a false `0xdead` candidate and is preserved as a
negative; many targets remain unreachable at this granularity. Author-only,
unwitnessed, no arbitrary 16-bit alphabet, pointer/IP, command or r5.

The 15:4x–17:3xZ edges add two witness verdicts, a new staged lane and three
bounded limbs without moving a rung cell or the mind count. Assimp W14's
partial low-32-bit MAT2 index overwrite of a live `aiMesh` vector slot was
independently replayed by witness #3722 from a clean `git archive 22b1740f`
(7 PASS / 0 FAIL, normalized trace `72c2a6be…d4198`): ESTABLISHED AS LABELED
at that narrow scope, with high 32 bits inherited from the heap pointer, an
unmapped chosen address and no clean import from W14's file; W18 (`5424cec5`) later measured a document-own-begin restore control, author-only and unwitnessed. W1–W13 importer legs stay
author-only. Lwnode's staged `WriteOneByte` off-by-one was likewise
ESTABLISHED AS LABELED by witness #3720 (clean `ba01845c`, 12 PASS / 0 FAIL),
still with no Escargot build, JS trigger or real API call. AwsLc W208
(`8d17d6da`) removes the need for a tagged record: in an ordinary static
`struct { uint8_t buf[31]; uint8_t state; void (*handler)(void); }` the
compiler puts `state` at offset 31 and the handler at 32, so the pinned byte
changes `state` `0xa5 → 0x48` (and `0xa5 → 0x01`) while the handler LSB stays
`0x29`; fixed `0x48` and safe `0x00` leave it unchanged, 15 PASS / 0 FAIL,
author-only. Cjose W198 (`018a79a9`) closes the fixed-library control on the
real `id_token` consumer: with the same loopback POST, the vulnerable build
reaches `raw_len=56` and aborts on the follow-up GET while the fixed build
rejects at `jwe.c:599` and returns HTTP 302; no pointer, leak or command,
witness not replayed. Frontier staged Cicap2Shell (CVE-2026-136126) on a
sixth `Encapsulated` entity aliasing `trash_entities[0]`: 19 PASS / 0 FAIL,
clean-archive `58435874` replay equal, staged at that point with no charter or window and admitted 17:5xZ as the 132nd route; witness W205 (#3753) later graded it ESTABLISHED AS LABELED at the pinned-function scope. Vrpn W29 (`85c17f4e`) retires W26's "freshly allocated" wording: the
sender -2 slot aliases the endpoint's live `d_udpInbuf`, and the record's +8
word aliases the low half of `d_NICaddress`; author-only, grade unchanged.


The 17:5x–18:3xZ limbs add two scoped witness verdicts, stronger author-only
wire/allocator limbs and several bounded negatives without moving a rung cell,
admission or the mind count. AwsLc W209 (`5de96965`/`3e102c7c`) shows AWS-LC's
own PKCS#7 cipher BIO is immune by its 4081-byte sizing into a 4096-byte `buf`:
a direct call into the pinned vulnerable no-ASM library measures `n1=0`,
`n2=4096` on both vulnerable and fixed builds, with no control datum after the
last struct field. Cjose W199 (`43bd6d3e`) puts a wire-derived `0x4141…` pointer
into a live jansson string dereferenced by `_cjose_jwe_calc_auth_tag` in the
loopback consumer (8/40 plain runs; fixed rejects before the write); the value
is a recognizable non-address, author-only and unwitnessed. OpenEXR W187/W188
bound the file-level pointer story: W187 steers a live malloc address in a
`-no-pie`, ASLR-off harness, while W188 finds no tcache `next` in the
unmodified consumer's copy window, so the steering is harness-groomed rather
than file-only. CodebaseMemory W8/W10 (`8e4893c8`) correct the canary to
`rbp-0x38` and show the canary check blocks saved-register use before saved RIP,
a structural negative for that build. Cicap W205 (#3753) was ESTABLISHED AS
LABELED at the pinned-function scope and Imgproxy W204 (#3734) at W9's loopback
allocator-blocker scope, both with no grade change or r5; Imgproxy W10 also
attributes W9's abort to a natural free from `g_hash_table_unref` and measures
no consumption after a size-preserving body.

The 18:2x–18:3xZ edges close one synchronet residual and replay one real
libgphoto2 consumer write. Synchronet W11 (`a0050050`, `ce0a0208`, `90ad0c88`)
records the exact pty-req TERM length at the encryption boundary (6 PASS /
0 FAIL), preserves the first replay's 5 PASS / 1 FAIL port-settling race and
replays clean `git archive ce0a0208` with matching digests; it excludes
client-side truncation at that measured boundary but is not a ciphertext
capture. Libgphoto2 W174 (`2ac219c2`) replays W172's real `gp_file_save()` write
from clean `git archive 833729ad` and finds layout, not the primitive, as the
sensitivity: `DRAIN=22` missed `priv`, `DRAIN=23` restored the victim and the
29-byte marker. Assimp W18 (`5424cec5`) measures a document-own-begin restore
control and corrects W14's over-broad "no clean import" wording. AwsLc
W210/W211 (`3826ca48`, `e9b02506`) generalize the in-tree BIO bound to `B=kb+r`
and confirm the OOB with 3DES-EDE-CBC (`b=8`) into `malloc(15)`, 11 PASS /
0 FAIL. Frontier staged Gpgme2Shell on CVE-2026-129975 (GPGME status `realloc`
double free): 19 PASS / 0 FAIL from the pinned-statement harness with chosen
`0x48`/`0x5a` in the stale allocation; rung 3 confirmed, rung 4 PARTIAL,
author-only at staging. The operator later admitted it as the 133rd route, and
witness #3796 later ESTABLISHED the pinned-statement scope with its bounds NIT
fixed; the W1-W5 real-build and wire limbs stay author-side, no grade change.
All other limbs stay author-side/unwitnessed except the named witness verdicts;
rung 5 stays UNKNOWN throughout.
The 02:0xZ operator wake admitted the three frontier-staged families under
standing #6 as routes 138–140 (`open5gs2shell`, `yojimbo2shell`,
`libsshch2shell`), each with a hy4-flash route, both resolver entries, three
wake units from the EXACT full-flag sync at pin `0d686bba…d528a`
(`written 9, removed 0`), its existing two-pane window (146/147/148), and a
row above. The trace below is the staged evidence the admissions were checked
against; the new rows are the current record.
`open5gs2shell`: CVE-2026-116543 / GHSA-25v2-v588-jq8g, pinned Open5GS v2.8.0
empty-boundary SBI multipart parser, ASan `WRITE of size 1` 0 bytes after a
65-byte region, plain state-machine-forced `00 0d 0a` in an adjacent object,
21 PASS / 0 FAIL; witness W217 replayed from clean `git archive 22d70741`
with a matching trace hash, ESTABLISHED AS LABELED, no grade change or r5.
`yojimbo2shell`: CVE/GHSA-UNKNOWN, upstream fix `d3d4f339…`, pinned
`ProcessPacketFragment` final-fragment `memcpy` before the `blockSize` check,
ASan `WRITE of size 500` 0 bytes after a 1100-byte region, chosen `MISHE-OO`
at canary offset 300, 20 PASS / 0 FAIL with 7/7 pins, post-authentication,
witness UNKNOWN. `libsshch2shell`: CVE-2026-59850 (fixed 0.12.1/0.11.5),
pinned `channel_rcv_data()` closed-channel UAF, ASan heap-use-after-free
`READ of size 32` 0 bytes inside a 64-byte region, chosen `M` /
`MISHE-LIBSSH-UAF` at freed offset 16, 24 PASS / 0 FAIL, authenticated peer
required, witness UNKNOWN. At that 02:0xZ admission scope no real builds,
listeners, wire paths, pointer/IP control, commands or r5 in any of the
three; the 03:0x–03:1xZ lane above supersedes this boundary for yojimbo,
and the later open5gs/libsshch lanes supersede it for those two. Evidence:
`reports/frontier-open5gs2shell.md`, `reports/frontier-yojimbo2shell.md`,
`reports/frontier-libsshch2shell.md` and each `-status.md`.

The 07:0x–07:3xZ limbs add one staged family, two scoped witness verdicts and
two build-scope corrections without moving a rung cell, grade cell, route,
mind count or R5 cell. Drwav2Shell is FRONTIER-STAGED with a charter and live
window 152 but no route or admission: CVE-2026-11316, real public
`drwav_init_memory_with_metadata()` on pinned dr_libs 0.14.5, ASan WRITE through
a file-low-half pointer and 25/0 under GCC and Clang, with fixed 0.14.6 and
`safe` controls clean (`reports/frontier-drwav2shell.md`). Witness W213 (#4132)
returned ESTABLISHED AS LABELED for Yojimbo2Shell's rung-5 MECHANICS only at
the non-default, post-auth, `-no-pie`, lab-trampoline ceiling, with NO full r5;
W214 (#4161) did the same for Libsshch2Shell's five clean-archive real-build
suites, explicitly NOT ESTABLISHED as remote execution. N2n2Shell W9/W10 put a
wire-chosen consumed pointer in a clang `-O2` spill slot (valid value from a
debugger pre-read with ASLR off, both outcomes crashes, no marker, IP or
command); Open5GS W3 feeds a 396-byte body from a real 127.0.0.1 HTTP/2
listener into the pinned parser shim (13/0, 57/0 across four suites), still
not an Open5GS NF. Munt W188 is an author clean-archive determinism replay,
not a verdict. Frontier screened aribb24 CVE-2026-112280 out (AV:L, no fix
commit, crash-only claim); no row or mind was added. The earlier "no wire
request" and "no consumed pointer" sentences in the Open5GS/N2n rows are
superseded at those named build scopes by the row text above.

Peer edge `7a02ca45` (Synchronet W21) builds the shipped 3.20b release
(`db9c5d6f…`), sends a 64-byte chosen TERM over a loopback SSH pty-req and
observes `savedlines.first=0x465541544f4f2d45` /
`savedlines.last=0x5a5a5a5a46554154`; a separate gdb replay faults in
`listFreeNodes` (`link_list.c:78`) from that chosen list head. The 40-byte
control leaves both pointers nil; 4 PASS / 0 FAIL, author-only, no chosen IP,
shell, command, ASLR defeat, fixed-release control or r5. This strengthens the
earlier source-bound W20 teardown claim to a live shipped-build availability
result at the labeled scope; the witness verdict and rung cells are unmoved.

The 07:4x–08:5xZ limbs add one live real-NF availability result, a measured
pre-auth consumer path and a set of bounded negatives; no rung cell, grade,
route, mind count or R5 cell moved here. Open5gs2Shell W4 re-read the W3 wire
path in source (`wire.go` reads the h2 body into the child's stdin; `want`
checks received length, it is not a parser fixture) and replayed four suites
from `git archive dd55be12` (13/15/21/8 PASS, 0 FAIL); its "no NF available"
line was too narrow, and W5 provisioned a lab-local NRF: 21 `.deb`s extracted
under `lab/`, v2.8.0 tarball `a04d66f6…b56ab`, unmodified `open5gs-nrfd`
built 1886/1886 on 127.0.0.1:18777. A 396-byte h2c POST (fixture sha256
`0c46e003…e0ba`, one leading CRLF before the staged 394 bytes) kills the
vulnerable NF (curl rc 56, nrf rc 134, SIGABRT in `ogs_talloc_free` via
`parse_multipart` `message.c:3498` → `nrf_state_operational` `nrf-sm.c:78`);
the patched build, safe and staged bodies and a 396-byte `ABC` counterexample
all answer HTTP 400 with the NF alive. The author calls this rung 4
DEMONSTRATED process termination and asks for witness replay (pending); a
`git archive 56363d35` rebuild reproduced the four CASE lines with hashes
`71b4b7e2…7c8e` / `2b31633e…41a7`. The cell stays `◐`: the effect is
count-controlled, with no chosen pointer, IP or command and r5 UNKNOWN.

Cjose2Shell W212 measures the advisory's pre-auth claim inside the lab Apache
consumer: an unauthenticated `GET /private` with `Authorization: Bearer`
compact JWE (56-byte `encrypted_key`) reaches real `cjose_jwe_import()` and
`AES_unwrap_key` through pinned mod_auth_openidc 2.4.15.1 and logs
`W2B_AES_UNWRAP_KEY_REACHED`; with the lab 16-byte KEK, gdb at `jwe.c:602`
reads 48 chosen bytes in `cek[0..47]` while the patched module rejects with
`CJOSE_ERR_INVALID_ARG`. `sh lab/frontier/cjose2shell/w2/run-oauth-bearer.sh`
scores 9 PASS / 0 FAIL live and from a clean `git archive 35e02887` with the
four provisioned build trees copied in; deployed reachability, ASLR defeat
and witness replay stay out of scope. W213's private gdb probe finds only the
next `0x41` chunk's size word changed (`0x41` → `0x4853494d2d323132`) with no
live pointer adjacent; its two logs hash to `dc77299a…4ec49` and
`74fcd254…e387cb4` (recomputed here). N2n2Shell W11 removes W9/W10's debugger
pre-read: a non-PIE clang `-O2` supernode dereferences wire-chosen `0x42f3e8`
at token+1682 as `comm` and stays alive on a zeroed `.bss` target, while
garbage bytes fault at `sn_utils.c:2324`; `sh live/w11_fixed_pointer.sh`
scores 13 PASS / 0 FAIL. The address is binary-known only, not an ASLR-defeating
leak, with no marker, control-flow hijack, command or witness verdict (#3909
still owed). Ccextractor2Shell W5 closes the truncated-MEDIA hypothesis with
4160/64-byte GXF inputs (`669ad202…0745`, `e2b32bf3…4ee2`) that produce only
an ASan `READ of size 3` at `boundary+3973` through `memmove` → `process_data`,
no `read()` WRITE, no write primitive and no rung change.

Pgactive2Shell W12 checks the shipped non-instrumented 2.1.9 `.so`
(`3177a37c…162998`) without starting a cluster: the parser inlines at
`0x16290`, the consumed saved RA sits at `rbp+8`, and the cold `elog(ERROR)`
path longjmps; a glibc probe returns 4 for the only accepted conversion set
with the `%s` destination untouched and 5 for any non-empty tail, so the
pinned `!=4` test cannot be passed by an overflowing store. Libraw2Shell W24
forces the top-size field to `0x21001` under gdb and watches it and the OOB
halfword through `border_interpolate()` — neither changes and the inferior
exits normally; the setup is debugger-forced, no report grade moved.
Libgphoto2Shell W189 rechecks the GitHub and advisory APIs at 08:17Z: newest
tag still v2.5.34 (`a4ec9cc8…`), GHSA patched versions still Unknown, no
numeric fixed version.

Ruby2Shell's 08:1x–08:2xZ limbs close the consumer-provenance question:
shaping wire headers (L=0/60/120/240) and routes (+100/+300) leaves the
post-attack `request=0x21c/0x1f8` pops unchanged in ten survivors, so those
consumers are fixed-size framework allocations, not a request-shaped Stage-B
analog. A surviving `consH-20` geometry does carve a fake 0x20 chunk that the
request thread recycles with an on-thread free (Q), and a dev error page
reflects about 169 KB of params, but the first 60-run carve-landing sweep
(N=508/524/556 × drain 1024/1152/1280) found 11 survivors and zero reflected
corruption — an unproven oracle preserved as a negative. Stock, oracle-free
and persistent r5 stays NOT ACHIEVED; the harness-condition witness label is
unchanged.

Synchronet2Shell W22 applies the pinned `cb6d77dbca` fixed-form hunk to the
same shipped 3.20b build and replays the 64-byte TERM: 5 PASS / 0 FAIL twice,
`off41=00`, nil `first`/`last` and completed teardown, with an author
`git archive 7d3a0088` receipt (`evidence/CLEAN-ARCHIVE.md`); no measured DoS
rate, pointer/IP, command or witness verdict. Drwav2Shell's witness DM #4189,
folded at `f5dce89c`, replayed 25/0 with 3/3 pins and graded the chosen
target-bytes / same-size-class scope ESTABLISHED AS LABELED; the
different-size-class `CHOSEN_WORD_PRESENT=0` counterexample and the no-grade,
no-r5 boundary stay. Xschem2Shell's window 154 is registered 155/155 unique
and the clean archive of `6081c45b` replays 25/0 with both pin hashes. All
limbs above are author-side unless a witness marker is named; none moved a
rung cell, grade, route, mind count or R5 cell.


The 2026-11-25 10:5xZ fold admits StbVorbis2Shell as the 147th route and
supersedes its earlier FRONTIER-STAGED note above: the charter, hy4-flash
route, both resolver keys and three wake units now exist, and window 135 was
adopted without duplication. The exact full-flag sync reported `written 3,
removed 0` and the pinned full-flag doctor returned PASS / GREEN rc 0. The
staged real-library grade is unchanged: rung 3 ASan and rung 4 PARTIAL at a
repeating file-chosen word written past an 8-byte allocation, with NO r5 and
no witness verdict. No grade, rung, witness or R5 cell moved by admission.

The 2026-11-25 11:2xZ fold admits Ctranslate22Shell as the 148th route and
supersedes its earlier FRONTIER-STAGED note above: the charter already
existed, the hy4-flash route and both resolver keys were added, and the exact
full-flag sync reported `written 3, removed 0`; path enabled/active and the
pinned full-flag doctor returned PASS / GREEN rc 0. Window 155 was already
live and registered and was adopted without duplication. The staged grade is
unchanged: rung 3 pinned functions with ASan `WRITE`, rung 4 PARTIAL
file-chosen bytes at one offset of a stand-in 16-byte region, NO r5 and
witness UNKNOWN. No grade, rung, witness or R5 cell moved by admission.

The 2026-11-25 08:5x–13:0xZ fold covers 98 author edges and corrects the
Open5gs2Shell, Mcuboot2Shell, Xschem2Shell, StbVorbis2Shell and
Ctranslate22Shell rows above; rung cells, the route/mind count and the R5
cells stay put. Xschem2Shell W2 is the one new independent verdict in this
window: witness W216 replayed a clean `git archive 42e0f33f` (25/0 harness,
3/0 real unrenamed `main`, same ASan `WRITE of size 8` at pinned `:130`,
allocator-derived readback, fixed rejecting) and graded ESTABLISHED AS
LABELED with no grade change; the row's earlier "witness UNKNOWN" is
superseded. Cjose2Shell W216 and Gpgme2Shell W15 only verified queued replay
offers and corrected a stale verdict line; neither returned a new verdict.
Gpgme2Shell's #4333 W11 offer is UNKNOWN (wake started 12:33:50Z, no settled
output at 12:49Z), not GREEN and not declined.

Drwav2Shell W4 (`0a16d1ef`) adds a file-chosen control-flow diversion in a
non-PIE `libsndfile` consumer: six consecutive cue-desync u32 writes take
`libsndfile__sf_close`/`sf_readf_short`/`sf_readf_int` at `0x41e118..0x41e130`
and call an `LD_PRELOAD` benign marker at `0x50000000`, observed in a gdb
backtrace; fixed 0.14.6 and a safe loop count produce no marker, 14 PASS /
0 FAIL, author-only, no wire or r5. Libsshch2Shell W12 (`d9ef7b38`) derives
the callee address from the compiled ELF symbol table and drives a separate
client process (7/0) while a source-level survey closes the
library-internal close-free shortcut; Synchronet2Shell W24 (`3e681d41`,
clean-archive receipt `3c85349e`) shows the W21 faulting load reads
`0x20(%rax)` with `rax` equal to the wire-chosen `savedlines.first`, 7/0,
with the direct `si_addr` cross-check preserved as a negative because gdb
returned `(nil)`. Open5GS W6 and Mcuboot W1/W2/W3 moved their evidence into
real NF / real pinned decryptor lanes as recorded in their rows, still
without a witness verdict on those new scopes.

Stbvorbis2Shell W203 supersedes the staged "~1.07e9 writes" loop-bound
description with a measured bounded extent (corrected by W204 to 30 words /
120 bytes below); Ctranslate22Shell W1/W2 add a
real-source ASan consumer and a bounded real-heap pointer-control negative.
Vtkdicom2Shell W3/W4 localize the plain-build SIGSEGV to a stale OOB
`Value.V` decref that a nine-size OB sweep leaves unchanged, not file bytes
or a file-influenced pointer. OpenEXR W200 scans the modules loaded by the
pinned `exrcheck` and finds no `rsi`→`rdi` one-gadget route to an `exec*`
call from the W197 shape (bounded negative, receipt `d5aef12d`). Hping3 W11
surveys six more rebuild layouts and extends the chosen `i`/`j` replay to
clang `-O2` without finding a pointer or GOT entry in the 251-byte span.
Ruby2Shell closes the named stock leads — keep-alive same-thread pairing at
Puma `min=3/max=3`, T-header repair, consH-20 tcache retarget, main-arena
libc oracle, 48-part/filler-first, and a Sinatra 500-page GC-address oracle —
and pins wire-only chosen-header coverage to `N ∈ [540,588]`; stock,
oracle-free and persistent r5 stays NOT ACHIEVED and the labelled
harness-condition R5 cell is unchanged. Libraw W26, Munt W189, OpenEXR W200,
Libsshch W10–W12, Open5GS W6, Mcuboot W1–W3 and Synchronet W24 add
clean-archive receipts. Solanum2Shell was staged by frontier W230 with a
clean-archive 18/0 receipt and was subsequently admitted as the 149th route;
see `docs/task.md` and `docs/reproducibility.md`. No grade, rung, route, mind
count, witness cell (except Xschem's verdict text) or R5 cell moved by this
fold.

The 2026-11-25 13:1x–15:3xZ fold covers the 39 author edges after the solanum
admission and corrects the StbVorbis and Hping3 rows above. No commit in this
window carries an independent witness verdict: every replay offer asked for
one (Ctranslate2 W3/W4, Solanum W1/W2, Cjose W217/W218, Gpgme #4333, Codebase
W19/W20, Synchronet #4421, Drwav #4238, Mcuboot #4236, Stbvorbis #4336,
Vtkdicom #4276) stayed UNKNOWN, and the witness wake at 14:02Z failed to
start for the known person-owned engine-cap reason. No rung cell, grade,
route, mind count or R5 cell moved.

The row corrections are the real-consumer and real-build boundaries.
Stbvorbis2Shell W204 sets the guarded extent to 30 words / 120 bytes and
shows all 30 file-chosen words in an
adjacent live object's canary and pointer-typed field (`run-object.sh` 9/0,
pointer read back but never dereferenced); W206 drives the crafted OGG through
real SDL_mixer's public `MIX_LoadAudio_IO()` into its vendored v1.22 header
with ASan `WRITE of size 4` at `stb_vorbis.c:4040`, clean fixed and safe
controls, 12/0 live and from a clean archive. Hping3Shell W12 provisions the
Ubuntu 24.04 `3.a2.ds2-10build2` package: its source `display_ipopt.c` is
byte-identical to the pin, but the shipped binary imports `__memcpy_chk` and
aborts before the store under the crafted long RR (rc 134, valid-RR control
clean, `wire/replay-distro.sh` 5 checks from a clean archive) — a
build-dependent DoS on that package only, not a fix and not a grade change.

Other author limbs deepen admitted lanes without a new capability. Mcuboot W4
drives a real loopback SMP image-upload packet through the real
`boot_serial_input()`/`bs_upload()`/TinyCrypt path into the pinned OOB sink
and reads 16 wire-chosen bytes at the OOB destination (6144/7168) while 4104
SIGSEGVs and 2048 is in-bounds. Solanum W1/W2 move the ASan
`WRITE of size 564` and the plain chosen-byte readback into a real ASan IRCd
over authenticated loopback S2S KILL. Pgactive W-W crashes both apply workers
with an ASan `WRITE of size 8` in a two-node 2.1.9 conflict race; the 2.1.10
library is clean and the earlier crash proved to be a harness bug. Cjose
W217/W218 measure 144 chosen bytes in a real bearer lane and identify the far
object as OpenSSL's 56-byte RNG `CRYPTO_RWLOCK`, written at +0x18 with no
dereference. Ctranslate2 W4 sees a file-derived value in a live
`StorageView._size` but the `size != _size` guard blocks the copy, and its
`sysmalloc`-prev_size redirect hypothesis is disproved. PHP wake 61 repeats
the tinyfilemanager exec chain with two changed attacker constants (8.4.27
marker/id, 8.4.28 clean), still conditioned on the shim SIGKILL. The rest are
bounded negatives and receipts: FontForge W23's tcache-disabled sweep finds
no code pointer, Drwav W5/W6 finds a network-facing metadata caller only on
patched 0.14.6, Libraw W27/W28, Vtkdicom W5, Libsshch W13, Libgphoto2 W192,
Synchronet W25 (19/0 one-command replay of W21–W24), CodebaseMemory W19/W20
and the roughly 300-process Ruby result chain (order arms answered,
deterministic splitter measured, 0x650-band and giant-pop claims closed,
honeypot parity negative) leave stock/oracle-free/persistent R5 NOT ACHIEVED.
Recipes and pins are in `docs/reproducibility.md` and `docs/task.md`.

The 2026-11-25 16:1x–16:2xZ fold covers the 19 commits after `913d0415`
(signal head `a3321f38`, live head `624df6c1`). None touched README or
`docs/*`; none carries an independent witness verdict. No rung cell, grade,
route, mind count or R5 cell moved. The Solanum row above is corrected in
place: its "no real ircd build, S2S wire path" boundary was stale after W1/W2.

Openexr W202 reaches a command in the unmodified pinned 3.5.2 `exrcheck -c`
(`reports/openexr2shell-file-level.md` §W202). The file chooses `memcpy` as
the indirect-call target and a 104-byte source whose bytes 96..103 hold libc
`__libc_system`, so `memcpy(ctxt, …)` overwrites `ctxt->free_fn` and the
trailing `attr_destroy()` call runs `system("touch /tmp/w202m")`; the PoC
sha256 is `7f3eda1b00f54b56ec75108f9012be6b035c8b6393ec1d7c2241f94be91e412e`.
Under gdb the arguments, the overwritten pointer and the command string were
read at the call, with the debugger forcing neither pointer nor call. Plain
`setarch -R` runs give vulnerable rc 139 plus marker, fixed 3.5.3 rc 1 `bad`
with no marker, and a valid baseline rc 0 with no marker; the ASan build
reports `heap-buffer-overflow READ of size 3072` at `internal_zstd.c:472`.
`sh harness/w202-benign-command.sh` printed `RESULT PASS` twice with five
byte-identical evidence hashes, and a clean `git archive 043a0d41` repeated
them. This is rung-4 mechanics at the rung-5 boundary, not R5: every run has
ASLR off for file-carried absolute addresses, the input is a local path, the
command is a benign `touch`, and the process then faults. The row's W188
"no command" sentence is scoped to that earlier steering limb.

Stbvorbis W207 observes the full OOB run in a real SDL_mixer consumer built
without ASan: `evidence/chosen.ogg` aborts rc 134 with
`malloc(): invalid size (unsorted)` and the safe input exits 0. gdb snapshots
all 30 file-chosen `0x4b434148` words at `c->multiplicands+8..+124`; the word
at `+24` rewrites the next free chunk's size from `0x91` to `0x4b434148`, and
no live allocation occupies the range. Padding the file to 4096, 65536 or
1048576 bytes leaves the address, neighbour and clobber unchanged.
`sh lab/frontier/stbvorbis2shell/run-consumer-heap.sh` passes 11 shell and
14 heap-word checks with the 12/0 ASan and fixed controls replayed. This is
chosen bytes in allocator metadata, still not a chosen word in a live
consumer-owned field; no pointer, command, wire or witness verdict.
A clean archive of `624df6c1` (SDL/SDL_mixer dependencies symlinked read-only
from the live lab) replayed every committed script at 16:27Z: 11/0 plus 14/0
heap-word, 12/0 consumer controls, 9/0 `run-all.sh`, 4/0 `run-seq.sh`, 12/0
`run-guard.sh`, 9/0 `run-object.sh` and 9/0 `run-neighbor.sh`, all rc 0. An
earlier archive of `0c8b7c75` failed because the gitignored safe input was
absent; `624df6c1` regenerates it inside the replay. Author receipt only.

Hping3 W13 writes a linear permutation to 187 reachable sbox bytes through
the crafted RR reply. The first RNG output byte is reply-chosen only when the
hidden `j` lands the index inside that reach: `j=222` gave index 5, `S[5]=4`
and observed low byte 4 (counterfactual 22), a clean run with `j=92` gave
index 131, `S[131]=130` and byte 130 (counterfactual 237), and `j=156` sent it
to index 195 outside the reach. A `127.0.x.x` template moved the destination
off `127.0.0.1` and was rejected by `waitpacket.c:94`; a full chosen IP is
not available. `sh wire/replay-perm.sh` runs baseline 3, attack 5 and fixed 3
checks (`REPLAY_PERM_OK: 3 stages`) from a clean archive of `feb3f33f`.

The remaining limbs are bounded negatives and receipts. Open5GS W8 proves
the OOB values are forced `00 0d 0a` repeats: arbitrary 36-byte suffixes
write nothing, substitutions break the chain, and CRLF injection only
re-arms it (`harness/bytechoice/run.sh` 11/0; clean-archive receipt at
`0a6c868d` gives 11/0 plus 21/0). Cjose W219/W219b sweep the real pre-auth
bearer lane over `enc`-selected CEK sizes: two plain builds fault in
`OPENSSL_sk_dup` and `_cjose_release_cek`, a 168-byte write replaces
pointer-shaped fields at `cek+0x80..0xa8` with `0x4141…`, but no vulnerable
case faults on the written value and all return HTTP 401 (18/0 and 11/0
receipts). Awslc W223 synthesizes W213–W216: no checked real caller has both
the withheld-block carry and the documented-minimum destination, W216's Node
22.11.0 has one slack byte, and unprovisioned applications stay UNKNOWN.
N2n W16 adds `sh live/replay-all.sh` with seven passing lanes from a clean
archive of `a2284de2`; its first 4/3 run was a missing gitignored
`community.list`, fixed by reading the pinned tarball. Solanum W3 reads the
post-buffer window in a plain real ircd: `buf` sits at vaddr `0x5220`, size
`0x200`, in `.bss` ending at `0x5420`, with no writable object following it
(18/0 harness, 6/0 ASan controls). All replay offers stayed UNKNOWN.

The 2026-11-25 16:3x–17:1xZ fold covers the author/config edges after
`827436b5` (signal and live head `4e5ec955`). No independent witness verdict
arrived; no rung cell, grade, route, mind count or R5 cell moved. The signal's
vrpn correction is already present: W23 maps the large-index exit-139 rows to
the NUL store at `sender_name + index`, not an outside-stack assertion.

Ruby2Shell's stock-app allocator model was corrected again: glibc tcache ends
at chunk size `0x420`; each embed-legal multipart part makes two
content+9 slices and one next-power-of-two value buffer. Order arms falsified
the earlier "never swept" closure, but the upcase's own result allocation
deterministically splits the forged grown victim. Sacrificial-shield runs
completed the full sequence 6/12; honeypot-parity arms survived 8/12 and 7/12,
yet every `0x648` claim pop landed on a merged value chunk, never the grown
victim. The exact-fit giant-pop claim has no physical overshoot, so the poison
chain is structurally closed for stock/oracle-free/persistent R5 after roughly
300 fresh processes. Two arms produced the first stock Ruby-VM SIGSEGVs when
prettyprint consumed the split-cascade corruption: a wire-driven crash, not a
steered allocation, command or grade change.

Cjose W220 identifies W219b's far object as the live Jansson header hashtable
`jwe->hdr`, not an unknown allocation. The overflow replaces its type and
buckets, but pinned `value.c:106-113` checks `json_is_object()` before
`hashtable_get`; the first post-unwrap lookup fails closed and returns HTTP 401.
The identity/use replays scored 7/0 and 11/0. Libsshch W14 removes the harness
trampoline from the callee path: an authenticated loopback client selects real
libc `system()` and its `channel->session` argument from recycled wire bytes,
creating the benign marker in 6 PASS / 0 FAIL. The command string remains an
app-chosen static global and the addresses are fork-peer ASLR-local; this is
unwitnessed rung-5 mechanics, not established remote execution.

Synchronet W26 measured shipped 3.20b under four concurrent loopback SSH
pty-req probes. The imported node-exhaustion prediction failed (7/3, preserved):
the process instead SIGSEGVs at first teardown and the fifth client is refused.
After correcting only the fixed-control assertion, the replay and a clean
archive both scored 13/0; the fixed form served all five sessions. Openexr W203
closes W202's fixed-address staging route: all ten ASLR-on PIE/non-PIE runs
faulted without a marker, and no file-filled fixed-address staging buffer was
found. W202 remains an ASLR-off, local-file, benign-command rung-4 limb.

The remaining edges are replay/provenance work: Solanum W4 adds one-command
18/0 harness plus 6/0 real-ircd controls; CodebaseMemory W21 repairs witness
wrapper assertions and TERM/INT/HUP evidence restoration, with 44/0 assertions
checked lane-by-lane but no uninterrupted final-wrapper run; Munt W191 resolves
the second CISA exploit-tagged link as the same inaccessible note, whose mirror
contains only an unexecuted, truncated illustrative trigger. Route policy now
keeps exactly one `opencode-go/hy4-flash-free` candidate per role at
`max_parallel: 5`; the same-day hungerg-free fallback was retired after rate
limiting, and `docs/runtime-pin.md` carries the exact allowlist and limits.


The 2026-11-25 17:1x–17:4xZ fold covers the ten author edges after
`869e8435`. Only one carries an independent verdict: witness W219 (#4481)
returned **ESTABLISHED AS LABELED** for Solanum2Shell W5, replaying
`bash lab/frontier/solanum2shell/replay-all.sh` from a clean `b8885fcc`
archive (18 PASS / 0 FAIL, then 6 PASS / 0 FAIL), hash-checking both pins and
rebuilding them into its own prefixes. Its unauthenticated-peer counterexample
got `Incompatible TS version`, no KILL and zero ASan, confirming the PR:H
prerequisite. The published grade is rung 3 confirmed in a real ircd process
and rung 4 PARTIAL with chosen length and bytes at a known global offset; no
pointer, command or r5. This verdict text supersedes the row's earlier
"witness UNKNOWN"; no rung cell, grade, route, mind count or R5 cell moved.

Ruby2Shell's corrected-model tcache consumer was confirmed, but the stock
chain stays closed. On the class that genuinely has glibc tcache (`<=0x420`),
`bash lab/repro/ruby2shell-stageC.sh` got 5/5 `verdict=poisoned` with an mtrace
pop at the forged target and 3/3 clean controls. The HTTP replay
`lab/repro/ruby2shell-stageC-http.sh 3 2` got 3/3 request-thread attacks with
16 chosen bytes at the nominated address (`7a` repeated) and a pop line there,
2/2 clean controls, and all three attack processes aborting at teardown. The
wire-only class probe then failed in 12 fresh unmodified processes
(lab/repro/ruby2shell-stock-leakclass.sh with
`RUBY2SHELL_LEAKCLASS_COUNT=12`): 0 `q38=0x251` tcache-`next`
landings, 0 window `P` allocations, 0 window `Q` frees, and no arena base on
the wire in the one surviving response pair. Stock/oracle-free/persistent r5
remains NOT ACHIEVED; the harness-condition r5 cell is unchanged.

Hping3Shell W14 extends chosen-byte control from W9's zero fill to two measured
nonzero values: with `S[0]=0x7e` or `0xc3` and `i=0x20`, `j=0x10` in the clang
`-O0` build, 8/8 attack checks passed with 16/16 chosen low bytes and
counterfactual bytes `e7`/`e3`, against 4/4 clean no-inject and locally patched
controls. `bash lab/frontier/hping3shell/wire/replay-target-byte.sh` scores 4
baseline, 8 attack, 4 fixed checks, rc 0; the same frames also passed 8/0 under
clang `-O2` (author-side rebuild). This is one IP octet, no full IP, pointer,
command or grade change.

The remaining limbs are bounded negatives and replay receipts. PHP W62's
deployment-style `RLIMIT_FSIZE` at the calibrated cut K=1019 makes the kernel
write exactly 1019 of 1892 bytes with no SIGXFSZ, but the live FPM worker stays
alive and the splice is gone at consume time: no promotion, takeover or marker
on 8.4.27-app, 8.4.28-app clean, full r5 still UNCLAIMED. Libraw W31 withdraws
W29's causal claim that a file-chosen, glibc-plausible top-chunk size caused the
clean exit: watchpoints show the file-written `0x00c0` halfword, but the field
reads `0x11` at `__libc_free` entry, and a standalone control exits cleanly with
`0x11` whether PREV_INUSE is set or clear. Grade stays rung 4 on W13/W14/W15
(chosen halfwords at chosen offsets) and W17 (loopback); no overlapping
allocation, pointer, command or r5. Gpgme W19 records witness W222's
ESTABLISHED AS LABELED verdict on #4333 (W11 EOF replay) and #4487 (the clean
archive wrapper: `BUILD OK`, 25 PASS / 0 FAIL, rc 0, exact pins, fixed/2.3.1/
short-line controls clean). Its newline-terminated counterexample is consistent
with EOF as the differentiator, and the chosen-byte print is debugger-only; no
grade or r5 move. KiCad's redundant 302243840-byte AppImage tar was removed after both
tar and extracted hashes were verified; the extracted binary hash and replay
recipe are unchanged.

The 2026-11-25 18:1xZ operator wake admits Aspell2Shell and FreeImage2Shell
as declared target minds under standing #6 after replaying both staged
harnesses: Aspell 14 PASS / 0 FAIL and FreeImage 9 PASS / 0 FAIL, with the
primary advisories, pins, fixes, charters, walls and live two-pane windows
157/158 checked. Both lanes keep their staged grade and witness UNKNOWN.
Both resolver-key pairs are registered. Engine-route registration and the
generated path, debounce and per-role slice units remain missing because
engine-config changes and full-flag sync are person-reserved. The route
registry therefore remains at 149 roles while 151 target minds are declared;
the repository OMP-only checker is RED for exactly those two missing routes,
and doctor is RED for the six missing unit files. No route or operational
unit delivery is claimed. The pinned single-model OMP checker also remains
stale against the owner-directed two-model routes; it is not hand-greened.

The 2026-11-25 18:0x–18:5xZ fold covers the 30 author edges after
`77a552ce`; only the operator admission `fde6f94e` touched docs paths and
self-folded its two rows. No edge outside that admission carries an
independent witness verdict. The new verdict is Openexr2Shell W204, already
folded into its report: witness wake W218 (#4457) returned ESTABLISHED AS
LABELED for the benign `touch` through an unmodified `exrcheck -c`, matching
all five committed hashes from a clean `34832cb6` archive; ASLR was off, the
EXR was local, no wire target existed, full r5 stays UNKNOWN and the verdict
does not cover W203's ASLR-on negative. PHP2Shell W63 extends the preserved
W62 short-write negative: a native `RLIMIT_CPU=1s`/`RLIMIT_FSIZE=1024` chain
(`DEATH_MODE=rlimit PREBURN=1`, ASLR on, no phase-2 LD_PRELOAD) reaches the
author-side rung-5 gates 1–5 in a live 8.4.27 FPM worker, with marker
`php2shell-r5-w63-final-1837` and output hash `7df36e9a…`; the fixed 8.4.28
build leaves exactly 1024 bytes and no marker. Gate 6 stays OPEN: without a
clean-checkout replay that varies the command, full r5 is NOT ESTABLISHED.
Libsshch2Shell W16 puts a wire-resident `touch` string at a probe-derived
slot and calls the real libc `system()` (6 PASS / 0 FAIL, marker side effect,
fixed and bad-callee controls clean); a stale hard-coded slot scored 2 PASS /
4 FAIL, and the callee address remains forked-peer ASLR-local, so this is
author-only rung-5 mechanics, not r5.

The remaining limbs are chosen-byte reaches, replay receipts and negatives,
all with unchanged grades. Stbvorbis2Shell W208 drives file-chosen bytes
into a live glibc `_IO_save_base` in a real consumer (17/0; `_IO_save_base`
`0x4b4341484b434148` at k=27, plain rc 139, fixed and safe rc 0) but only
rung 4 PARTIAL. Vtkdicom2Shell W6 pins the exact VTK 9.5.2 bundled source,
ASan `WRITE of size 4` 32 bytes past a 136-byte region, and W7's
predecessor-item grooming yields only stale `Value` headers, no pointer.
Openexr2Shell W205 finds no libc-resident alternate `ctxt` victim under
ASLR on (`COMMAND_PLT_CALLS=0`), W206 finds no same-mapping command call
among the eight function-pointer slots; Fontforge2Shell W24's third PIE
build and W25's late Save state both score `CAND_COUNT 0` for a code pointer.
Libgphoto2Shell W193 overwrites 16 bits of `priv` with one ASLR-on fork-sweep
hit (16/0) but no absolute target or command. Pgactive2Shell's
`local==NULL` delete/delete conflict aborts with signal 6 live (fixed clean,
clean-archive replay exact) with a fixed boolean, not an attacker byte.
Synchronet2Shell W27 finds a 52-byte wire TERM threshold (13/0) on shipped
3.20b; the 48-byte arm corrupts only `line_delay`. Hping3 W15, N2n W17,
Openexr W205/W206, Fontforge W24/W25, Libsshch W16 and Pgactive receipts
were replayed from clean archives, and Ruby's free-order map, tcache
saturation, escaped disposition and stock small-class overlap arms remain
bounded negatives: no claim/pop, command or persistence, and stock RCE
stays NOT ACHIEVED. No rung cell, grade, route, mind count or R5 cell moved
by any of these limbs.

The 2026-11-25 18:56–19:2xZ fold covers the eleven author edges after
`f777c40d` (through `08e18012`); none touched docs paths and none carried an
independent witness verdict. Vtkdicom2Shell W8 only re-points both reports at
the exact-source replay material in DM #4503 (unanswered; #4276 is the earlier
W3 offer), leaving its witness UNKNOWN. PHP2Shell W64 extends W63's native
`RLIMIT` chain with a two-pool `RLIMIT_FSIZE=1024` unlock gap: a size-limited
FPM producer stays alive while a second, unlimited pool consumes the session,
so no CPU freeze, SIGKILL or phase-2 `LD_PRELOAD` is needed. The armed wire
request creates `php2shell-r5-w64-gap-chain` under `uid=1000(mesh-home)`
(hash `91a18f97…`); a varied SID creates `php2shell-r5-w64-gap-varying`
(`6bd15181…`); fixed 8.4.28 leaves a 78-byte session and no marker
(`2a38515d…`). Author-side rung-5 gates 1–5 are reached, gate 6 stays OPEN
and full r5 is NOT ESTABLISHED.

Libsshch2Shell's pinned-tree survey finds five callback registrations and no
in-callback channel free in any of them; `ssh_channel_close()` itself does not
free, so the in-callback free remains harness/app-owned. Ruby2Shell adds opt-in
`MTRACE_TID=1` tracing: in seven surviving N=972 processes all 22 planted
`0x3f1` allocations and frees, the last `0x400` free and the `0x3f8` upcase
allocation carry one worker tid, closing same-thread attribution; the tcache
arm's upcase took a newer planted slice, wrote `0x53` and aborted in
`munmap_chunk(): invalid pointer`, with no claim pop or command. Hping3Shell
W16 makes `--rand-dest 127.T.T.T` emit three chosen octets (the first fixed by
the template): T=1 predicted 20/20 destinations and got 15/16 `127.1.1.1`,
T=`0x2a` got 10/16 `127.42.42.42`, and a clean-archive replay scored
`REPLAY_MULTIOCTET_OK: 12 checks`; no pointer, command or witness.

Openexr2Shell W207 tests the file-to-argv address-leak lead and returns
NEGATIVE: all 12 ASLR-on `exrcheck -c` cases have `CASES_WITH_HEX_OUTPUT=0`,
`sh lab/openexr2shell-real/harness/w207-leak-negative.sh` gives `RESULT PASS`
with hash `d5d7b448…`, and a clean `git archive 2f12c2e5` replay with the
gitignored cases symlinked is byte-identical; `-s` on a FIFO timed out at 40 s
and stays UNKNOWN. Drwav2Shell W8 replays three exact consumer headers:
Moondust, Sphaira and Yup each keep `CHOSEN_WORD_PRESENT=1` and rc 0 for the
chosen metadata, fault the bad arm at `drwav__read_cue_to_metadata_obj:2281`
and leave the safe arm clean. Sphaira's mount-to-browser-to-audio path is
user-driven remote-file playback, not a listener, and its build is
switch-only; no exactly-0.14.5 consumer was found (absence unproved), so no
r5. This supersedes the Drwav2Shell row's earlier no-application boundary at
the exact-source-header level only; no running Linux application or listener
was exercised. Aspell2Shell's full release ASan build dumps 255–511-byte
words at rc 0, with complete NUL-terminated bytes and no ASan report or
crash; the `aspell -a` suggestion probe is UNKNOWN.
No rung cell, grade, route, mind count or R5 cell moved by any of these
limbs; all offers remain unanswered.

Three further author edges landed while this fold was in progress and are
recorded here rather than left as new stale boundaries. Hping3Shell W17
replaces W16's repeated-octet fill with a 187-byte reply-chosen pattern that
puts three **distinct** octets into one loopback packet: `127.11.22.33` and
`127.44.55.66` were each seen with all 20 full destinations predicted from
read-only GDB state and 1/16 post-attack hits, and a 500,000-trial search
found no swap-stable pattern for repeated packets. A clean `git archive
266144f0` replay scored `REPLAY_PATTERN_OK: 3 stages` (baseline 4, attack 5,
fixed 4 PASS) with the pinned source hashes rechecked; still no full IP,
pointer, command or witness verdict. FCEUX2Shell W233 is **staged, NOT
admitted**: CVE-2026-136918's UNIF `MAPR` chunk wraps a malloc argument at
`0xffffffff`, and the pinned `SetBoardName()` harness scores 14 PASS /
0 FAIL with ASan `WRITE of size 19` just past a 1-byte region and file-chosen
bytes through rc 42; no row, route, live emulator, command or verdict follows
from staging. No rung cell, grade or R5 cell moved by these limbs either.


The 2026-11-25 21:4xZ operator wake admits Nfdump2Shell as the 152nd declared
target mind under standing #6 after replaying the staged claim
(GHSA-gpgq-hv9x-7mqj, public endpoint HTTP 404, no CVE/CVSS), both hash-pinned
`nfdump` revisions (`8a00543a` / `32b9cbe7`), the 10 PASS / 0 FAIL GCC+Clang
ASan harness and the live two-pane window 160 (frontier W234, 21:26Z, adopted
without duplication). The grade is unchanged: rung 3 pinned verbatim, rung 4
PARTIAL packet-chosen offset with harness-chosen value, no wire/pointer/command,
no r5, witness UNKNOWN. No route, resolver key or unit was added: the owner's
standing approvals reserve engine-config changes, systemd units and the
full-flag sync to the person
(`.mishe-tauftauf/operator/standing-approvals.md:47-51`). The route registry
therefore stays at 152 roles while 153 roles are declared in the OMP checker
(which also counts staged Fceux2Shell); `check-omp-only.py` is RED for
`nfdump2shell: no route` and the 21:34Z doctor run lists twelve missing unit
files (nine for aspell/fceux/freeimage, three for nfdump2shell). The
`failed-m2shell-doctor-service` RED was re-observed GREEN on a refreshed
person-owned disposition, not because the units exist. No operational delivery
is claimed here; the person's exact full-flag sync and witness replay remain
owed.

The 2026-11-26 06:0x–06:5xZ limbs fold three commits. `8e35aa10` split the
front page into a generated presentation: `README.md` now holds a manifest-
rendered overview and short orientation, the seven-column evidence register
is generated into [results.md](results.md), and
`research-manifest.json` drives the counts, ladder graphic and register.
`python3 tools/render-presentation.py --check` found all three generated
files current; `python3 tools/check-readme.py .` stays GREEN.

Ruby2Shell W32 (`0631fcd6`) closes three leads as bounded NEGATIVEs. A rescan
of the four-arm chosen-header coverage band (N∈{540,556,572,588}, 24 surviving
responses) gives `files=24 parts=816 deviations=0 leakshapes=0`: the chosen
header is not reflected. An initial `0x250`-as-decimal pattern produced
363/198/132/99 deviations that were a scanner-argument mismatch, not
corruption; the bodies' first drain qwords are
`5002000000000000 9000000000000000`. A 12-fresh-process inter-request GAP arm
at N=972 (plant `1000x4`, claim `1039@0x400:0x411,1015`, 5 s idle) aborts
12/12 at the attack with 0 claim pops and 0 survivors. Six processes at
N=1500 with `METHOD_LEAD_A=529` leave 2 survivors whose claim-size bin is
still unobserved: `fd=0 bk=0` at the sampled bins, no `M 63f` allocation, so
bin residency stays UNKNOWN. Veria's promised 25 November stock-Rails RCE
still has no mechanics or link. Grades unchanged: rung 4 witness-COMPLETE,
harness-condition rung 5 witness-ESTABLISHED, stock/oracle-free/persistent
r5 NOT ACHIEVED.

Drwav2Shell W21 (`c5877121`) reconciles W20's unknown-ending wake (732
objects, no `bin/gnubase`, no drwav/reports dirt; its background ninja died
with the one-shot wake) and closes the research lane at a documented source
ceiling. GNUBase's only HTTP route is `POST /mcp`, JSON-RPC with a Bearer
token on loopback (`mcp/transport.h:23-28`, `transport.cpp:93-115,143-145`);
its only `base64()` call is PNG image output (`server.cpp:63-66,287-289`), and
a request-byte file-sink sweep found only engine-local writers. Even a linked
GNUBase is a request-reachable file-path caller, not a wire-byte caller, so
r5 stays UNMET. Two bounded build chunks made zero compiles after the
`VerifyGlobs.cmake_force`/`RERUN_CMAKE` regeneration was removed; 179 ninja
steps remained and the probe was never run. This is a source-level ceiling,
not an execution result: no process, request, ASan report, marker or side
effect. Final grade: rung 3 staged harness ESTABLISHED AS LABELED by witness
W215, rung 4 file-chosen lab marker author-observed in W1-W4 with no
independent verdict, r5 UNMET/UNKNOWN; W1-W4 verdicts stay UNKNOWN and the
again chain is retired. No rung cell, grade, route, mind count, witness
verdict or R5 cell moved by any limb in this fold.

The 2026-11-26 07:0x–07:1xZ limbs fold six commits: one bounded Ruby
negative, one independent witness verdict, one research closure, one staged
target, its witness request and its raw run-all traces. No rung cell, grade,
route, mind count, witness verdict or R5 cell moved.

Ruby2Shell W33 (`025480e3`) closes the never-exercised
`Transfer-Encoding: chunked` knob (`lab/repro/ruby2shell-stock-rails.sh:78-80`)
at N=588 as a bounded NEGATIVE. Seven fresh vulnerable 3.4.12 processes (one
timing probe plus `ch588-1..6`) used `DRAIN=1024:32` fake-pattern drain bytes,
`FILL=256` of `[0x250, 0x90]`, `PART_CHARSET=1` and tail `00005102`, with the
unchunked N=588 coverage band as control. Six of seven aborted during body
parsing with `malloc(): invalid next size (unsorted)` (HTTP 000, process dead);
the one survivor (`ch588-1`) returned a clean 404 whose 34 reflected parts had
0 deviations and 0 leak-shaped qwords. Fixed 3.4.13 controls under the same
chunked wire survived 2/2 with the same clean 34-part page, so the abort is
attributed to the vulnerable one-byte overflow, not to chunked parsing. No
reflected `0x53` run, chosen-byte write into a live value, libc/code pointer,
command or second command. Grades unchanged: rung 4 witness-COMPLETE,
harness-condition rung 5 witness-ESTABLISHED, stock/oracle-free/persistent
r5 NOT ACHIEVED.

Witness W251 (`9cace3e0`) supersedes W26's "unwitnessed plain lane" wording:
offer #4774 is ESTABLISHED AS LABELED with no contradiction, no grade change
and NO r5. The unmodified `real/run-syswire-plain.sh` (SHA-256 `247db414…`,
identical at the worktree, introducing commit `669b1dbd`, HEAD `c5877121` and
the clean `git archive 669b1dbd` replay tree) ran three times: 6 PASS / 0
FAIL, rc 0, `match=1` recycled slot equal to the in-run published address,
wire-sent command armed server-side, chosen
`target_after=0x41414141414141c1` and marker created, with no trampoline and
no sanitizer; the fixed lane stayed clean and an invalid callee gave status
`0x8b` with no marker. Both pinned tarballs were re-fetched by SHA. Heap
addresses differed per build/path, as the in-run handoff predicts.

N2n2Shell W24 (`3d46fd31`) closes research at the documented ceiling and
retires the `--again 2h` chain. It supersedes the older "rung 4 PARTIAL" and
"cheapest next experiment" framing: rungs 1-4 are established on the real
pinned supernode over one loopback UDP `REGISTER_SUPER_NAK`, including W10's
wire-chosen `comm` dereference and W11's fixed non-PIE address, bounded by
W22 under PIE and by W23's rejection on the complete upstream fixed tree. The
new source check finds `0x42f3e8` = `mgmt_event_subscribers+8`; `mgmt_req_t`
(`src/management.h:42-57`) has no function pointer, the callable tables
(`mgmt_handler_t.func`, `mgmt_events[]`) are separate, `mgmt_event_post`
(`src/edge_management.c:336-341`) selects by topic independently of `comm`,
and W11's 632-byte zero run is pre-existing `.bss`, not overflow bytes. No
marker execution, canary/RIP hit, control-flow takeover, command or r5.
Witness #3909 and the consolidated #4445 stay UNKNOWN, not passes; neither
replay is repeated without a verdict. Reopen only on an addressed verdict or
a measured wire-to-callback/command path.

Pcre2dfa2Shell is STAGED by frontier W248 (`b3f2ad2e`, brief amended in
`57cc216e`, raw run-all traces kept in `4eebc8b0`) as a new target mind; at
those commits it was not yet an admitted route — admission is a separate,
later operator action: charter
`charters/pcre2dfa2shell.md`, brief `reports/frontier-pcre2dfa2shell.md`,
status and pinned harness under `lab/frontier/pcre2dfa2shell/`.
CVE-2026-86145 / GHSA-3r4p-g7gg-ppmf affects PCRE2 10.32-10.47 and is fixed
in 10.48 by `c932e704…`; the advisory-cited `3979bb90…` does not resolve
(404), and that discrepancy is preserved. Pinned tarballs 10.47 `409c4435…`
and 10.48 `38c2a449…` build a public-API consumer that reaches ASan
`WRITE of size 4` at verbatim `src/pcre2_dfa_match.c:686` through
`pcre2_dfa_match_8` over six `(?R)` frames, while plain 10.47 faults rc 139
and all 10.48 controls return `rc=-63` (`PCRE2_ERROR_HEAPLIMIT`). Author run
6 PASS / 0 FAIL; the six per-tag/per-compiler raw receipts in `4eebc8b0` match
those cells. Rung 3 verbatim, rung 4 PARTIAL (DFA state integers, not
chosen bytes at chosen offsets), no pointer primitive, wire path, command or
r5. Replay was requested by DM after staging and is NOT a verdict; no
independent replay has been observed. Two neighbouring candidate screens are
preserved as negatives: libpng CVE-2025-65018 produced no ASan report or
canary change in five builds, and libtiff CVE-2026-18495 needs a >4 GiB
`StripByteCounts` and a matching multi-gigabyte `memset()` before its sink, so
neither was staged.

The 07:1x–07:2xZ limbs supersede the staging-only wording above: pcre2dfa2shell
was admitted and independently replayed while the fold was in flight, and Ruby
closed one more chunked signature question. No rung cell, grade, route,
mind-count claim beyond the operator's admission, witness verdict or R5 cell
moved by these limbs.

Ruby2Shell W34 (`74e10bb9`) sweeps the attacker-supplied fake-chunk size
qword directly under the chunked N=588 wire. Nine fresh vulnerable 3.4.12
processes, three per `FILL_SIZE ∈ {0x91, 0x93, 0x251}`, used the same
`DRAIN=1024:32`, `FILL=256`, `PART_CHARSET=1`, tail `00005102` and
`RUBY2SHELL_STOCK_DRAIN_FAKE=1`. The strict falsifier ("all sizes abort
identically to `0x90`") was not met: `0x91` gave 1/3 `sysmalloc` assertion and
2/3 clean 404s, `0x93` gave 2/3 aborts (one
`malloc(): mismatching next->prev_size (unsorted)`, one `sysmalloc`) and 1/3
clean 404, and `0x251` gave 3/3 aborts (two
`malloc(): invalid next size (unsorted)`, one `sysmalloc`). The size bytes are
consumed by whichever glibc check fires; reflect scans on the three survivors
(`--pattern` matched to each size) read 2 files/68 parts at `0x91` and 1
file/34 parts at `0x93`, with 0 deviations and 0 leak-shaped qwords; `0x251`
produced no HTML. Fixed 3.4.13 controls under the identical chunked wire at
`0x93` (2/2) and `0x251` (2/2) stayed alive with clean 404s. This is a
signature control, not a primitive: no chosen-byte write into a reflected
value, no claim pop, no libc/code pointer, no command. Grades unchanged;
the next bounded experiment is `FILL_PREV` coherence with `FILL_SIZE` at
`0x91`/`0x93` to test the unlink gate.

Operator (`56491145`) admitted pcre2dfa2shell under standing #6 as the 164th
declared target mind at 07:2xZ, adopting window 172 (panes %346/%347, no
duplicate); manifest, README, `docs/results.md` and the ladder SVG were
rendered in the same commit. The clean-git-archive replay of the unmodified
`run-all.sh` (SHA-256 `110f17e8…986b1aa`) printed `RESULT PASS=6 FAIL=0`,
rc 0; the row records rung 3 verbatim / rung 4 PARTIAL with witness pending at
that moment. This supersedes fold 1's "staged, admission owed / no
evidence-register row" wording; route and generated wake units were still
missing in the omp-only/doctor readings at admission and are person-reserved.

Witness W252 (`76c5b864`) then returned ESTABLISHED AS LABELED for pcre2dfa2shell
W248, no contradiction, no grade change and NO r5, superseding fold 1's "no
independent replay observed". The unmodified `run-all.sh` SHA-256
`110f17e8…986b1aa` is identical at the worktree, `b3f2ad2e`, `57cc216e`,
HEAD and the clean archive. Three serial replays — one from
`git archive 57cc216e` with only the two pinned tarballs symlinked and all six
builds fresh (184.51 s), then cached clean (2.91 s) and in-tree (3.01 s) —
each gave 6 PASS / 0 FAIL, rc 0. Both 10.47 ASan lanes report the same
`WRITE of size 4` at verbatim `pcre2_dfa_match.c:686` through
`pcre2_dfa_match_8` at `:4027`; the plain lane faults at the same sink under
gdb (`si_addr=0x5551555a6ae4`, `rlevel=9`, not stack exhaustion); all three
10.48 controls return `-63` with no report. Benign patterns against the same
10.47 ASan library stay clean, so the regex is the trigger. Both tarballs and
the fix patch were independently re-fetched. Rung 3 and the rung-4 PARTIAL
ceiling stand; no chosen bytes, pointer control, wire path or r5.

## 2026-11-26 07:2x–07:4xZ — register count, Ruby W35 negatives, libde265shell staging, W253 verdict

Signal head `8b4caaf9`, live HEAD `9d1ff99a`. Five commits folded; no rung
cell, grade, route, witness verdict or R5 cell moved by docs, and no replay
was rerun in this wake.

`aa6ba868` (operator) folded witness W252's pcre2dfa2shell verdict into
`research-manifest.json` and the generated presentation: independently
established findings moved 107→108 while the 161 register rows and the rung 3
verbatim / rung 4 PARTIAL boundary stayed put. README, `docs/results.md` and
the ladder SVG are generated artifacts, not edited by this fold; the W252
replay recipe is already in `docs/reproducibility.md`.

`df5d82ba` (Ruby W35) closes the fake-chunk `prev_size` coherence lead as a
bounded NEGATIVE. At chunked N=588 with `FILL_PREV ∈ {0x90,0x91,0x250,0x251}`
against `FILL_SIZE ∈ {0x91,0x93}` (three fresh vulnerable 3.4.12 processes
each, 24 runs), 9 survived with HTTP 404 and 15 aborted: the `prev_size`
qword selects whether glibc reports `mismatching next->prev_size`,
`invalid next size (unsorted)` or a `sysmalloc` assertion, but the nine
survivors' reflect scans found 0 deviations and 0 leak-shaped qwords in 306
parts. Two survivors printed `corrupted size vs. prev_size` only at graceful
shutdown, a corrupted-heap observation rather than a write primitive. Fixed
3.4.13 controls (2+2 runs) stayed alive and clean. Self-coherent `prev ==
size` (`0x53`, `0x93`, `0x250`, `0x251`, plus the existing `0x91/0x91`)
produced 3/15 survivors with 0 deviations, and a second unchunked request on
12 corrupted-survivor processes was served in 4/12 with 0 deviations across
136 reflected parts. No `fd`/`bk` pointer, libc/code base, chosen-byte write
or second command. The fake-chunk lane is CLOSED; grades stand at rung 4
witness-COMPLETE, harness-condition rung 5 witness-ESTABLISHED and
stock/oracle-free/persistent r5 NOT ACHIEVED. The next bounded experiment,
only if reopened, is forged chunks below the unsorted band
(`FILL_SIZE ∈ {0x21,0x41,0x53}`, `FILL_PREV=0x53`).

`8b4caaf9` staged libde265shell as a new target mind (CVE-2026-33165 /
GHSA-653q-9f73-8hvg, libde265 <=1.0.16, fixed 1.0.17 by `c7891e412…`): a
stale `ctb_info.log2unitSize` after an SPS change makes
`set_SliceHeaderIndex()` write 2 bytes past a 2496-byte heap array. The
advisory's unmodified 254-byte reproducer and public-API `poc.c`, pinned
alongside both tagged tarballs, give clang/gcc ASan `WRITE of size 2` at
verbatim `libde265/image.h:741` from `slice.cc:2866`; fixed and benign
controls are clean, and the plain vulnerable build exits 0 silently.
`RESULT PASS=12 FAIL=0` at staging. `4a9c64b9` records an author
clean-archive replay of the unmodified `run-all.sh` (SHA-256
`acf09b51…d62d19d1b`) from `git archive 8b4caaf9` at
`.mishe-tauftauf/replays/libde265shell-w249`, again 12 PASS / 0 FAIL with the
same frames. That is an author receipt, not an independent verdict. Grade:
rung 3 verbatim / rung 4 PARTIAL, no chosen bytes, pointer control, wire
path, command or r5. `fc907f63` later admitted the lane as the 165th declared
target mind; witness replay was then owed (closed by W254 below). Both build
path negatives (autotools absent on the CMake-only fixed tag; a C++ driver
rejects the advisory's C source) are preserved in `PROVENANCE.md`.

`9d1ff99a` (witness W253) returned ESTABLISHED AS LABELED for aspell2shell's
75820 consecutive-offset sweep, no contradiction, no grade change and NO r5.
Three serial replays of the unmodified `75820-pattern-sweep.sh` (SHA-256
`8319cf0d…2287597d`) — fully fresh clean git archive, clean archive with a
fresh vulnerable build, and in-tree with a fresh work dir — each gave
8 PASS / 0 FAIL rc 0 with 41 GDB stores and the same `0xbe → 0x01..0x1a,
0x01..0x0e` dump at verbatim `suggest.cpp:1469/1483-1485`; fixed and
targeted-fix builds rejected the word (rc 1) and a benign 250-byte word was
clean on the same fresh ASan binary. All three tarballs were re-fetched and
the release trees diffed clean. This supersedes the status report's "all
75820 claims verifier-UNKNOWN" wording only for this sweep; W263 later
established the separate #4566/#4568 read lane at rung 3, while the
single-offset write lane stays verifier-UNKNOWN. Full detail:
`.mishe-tauftauf/artifacts/witness-w253-aspell2shell/detail.md` and
`.mishe-tauftauf/artifacts/witness-w263-aspell75820/detail.md`.

## 2026-11-26 07:5xZ — libde265shell admitted, Ruby W17 negatives, presentation gate

`fc907f63` admitted libde265shell as the 165th declared target mind at 07:5xZ
under standing #6; window 173 was adopted with panes %348/%349 live and no
duplicate, while the hy4-flash route and three generated wake units were still
missing in the operator reading (person-reserved). The generated overview moved
164/161/161/108 to 165/162/162/108 in `README.md`, `docs/results.md` and the
ladder SVG; all 162 register rows and every rung cell held (rung 3 verbatim,
rung 4 PARTIAL, no r5). The operator's clean-archive replay of the unmodified
wrapper from `git archive 8b4caaf9` printed 12 PASS / 0 FAIL with digest
`acf09b51…d62d19d1b`; that is an author-side receipt, not an independent
witness verdict; W254 below later established the row at its labeled scope.

`944b3d10` (witness W254) independently replayed the unmodified `run-all.sh`
from a clean `git archive 8b4caaf9`, re-fetching all three pinned inputs, in
187.45 s rc 0: 12 PASS / 0 FAIL, both vulnerable ASan traces matching the
quoted frames, fixed/benign controls clean and two extra benign inputs clean.
Verdict ESTABLISHED AS LABELED at rung 3 verbatim / rung 4 PARTIAL, no
contradiction, no grade change and NO r5. The independently established count
moved 108→109; 165 declared / 162 active / 162 rows and all rung cells held.
Detail: `.mishe-tauftauf/artifacts/witness-w254-libde265shell/detail.md`.

`f209d6fa` (Ruby W17) closed both leads left open by W35. Forged tcache-sized
chunks below the unsorted band (`FILL_SIZE ∈ {0x21,0x41,0x53}`,
`FILL_PREV=0x53`, N=588, 3 runs each) gave 2/9 survivors and 7 known glibc
aborts; both survivors served 404 and a later `/up` 200, one printed
`corrupted size vs. prev_size` only at shutdown, and a matching-pattern
reflect scan found 0 deviations and 0 leak-shaped qwords in 68 parts. A GET
query value was then used as a fresh post-overflow reflected allocation: at
`0x250`/`0x90`, N=524, 24/24 vulnerable processes aborted; at the two
surviving geometries 2/12 lived with `q0` still exactly 1024 `A` bytes and 0
deviations in 70 parts, and a fixed 3.4.13 control stayed clean. No forged
chunk reached a reflected allocation and no pointer crossed the wire. Grades
unchanged: rung 4 witness-COMPLETE, harness-condition rung 5
witness-ESTABLISHED, stock/oracle-free/persistent r5 NOT ACHIEVED. Raw evidence
is gitignored `lab/build/evidence/stock-rails-chs*` and `stock-rails-qgetv-*`
files; the commands in `docs/reproducibility.md` regenerate it.

`1ebd6601` makes generated presentation drift an explicit failure: a
pre-commit hook re-renders and stages `README.md`, `docs/results.md` and the
ladder SVG whenever `research-manifest.json` is staged, and
`tools/check-readme.py .` now goes RED on any stale generated file. The hook
only replaces one it installed; `docs/operations.md` records the installer and
check commands. No harness, pin, grade, rung cell or r5 moved with it. No
replay was rerun in this fold; counts and bytes above are quoted from the
committed receipts.

## 2026-11-26 08:0x–08:2xZ — Ruby W18 adjacent lanes, mongoosemip2shell staged then admitted

Signal head `05c7b6c4`, live HEAD `43e3a514`. Five commits folded. No rung
cell, grade, witness verdict or R5 cell moved by docs, and no replay was
rerun here; bytes and counts are quoted from the committed receipts. The
operator's `43e3a514` changed the generated presentation and register count;
docs did not touch those files.

`516812e4` (Ruby2Shell W18) closes the transcode `max_output` lead as a
bounded NEGATIVE and reproduces two adjacent GHSAs from the same 2026-11-18
Ruby fix series. The write-bound changes (cp50220 5→9, to_utf_16 4→6,
to_utf_32 4→8) are real in the abstract, but a 288-case length sweep and a
3000-case mixed-character/option fuzz on both `ruby-3.4.12-asan` and
`ruby-3.4.13-asan` gave zero ASan heap/stack reports and byte-identical
marshalled output: `transcode.c:1878` grows the destination to `dlen + len +
max_output`, so no 4-byte window opens for the 6/8-byte write. Lane CLOSED.
The committed reproducer `lab/repro/ruby2shell-adjacent-ghsas.rb` with driver
`lab/repro/ruby2shell-adjacent-ghsas.sh` then measured:
GHSA-7x2q-68qv-6p8x gives ASan `heap-use-after-free ... READ of size 8 ...
#0 bbuf_free regparse.c:145` on 3.4.12 (rc 1; allocation `regparse.c:1795`,
free `:4977`, reread `:5072`) and `RegexpError` on 3.4.13 (rc 0) — confirmed
corruption, rung 3. GHSA-7whj-cfh7-xgm4 gives the upstream regression pattern
named in the committed script a rc 139 `[BUG] Segmentation fault` at `re.c:2`
on 3.4.12 via `rb_reg_to_s → rb_reg_str_with_term (re.c:628) → onig_new →
onig_parse_make_tree (regparse.c:6773)`, with no ASan heap report before the
SIGSEGV, and the expected `(?-mix:...)` string on 3.4.13 (rc 0) — reproducible
crash, rung 2. Both are secondary lanes: each needs an application that
compiles attacker-controlled regex patterns, so neither is a stock-Rails/
Sinatra rung-4/5 path. The 08:04Z trigger watch found the vendor page
unchanged (stamped 2026-11-21T03:52Z, PoC promised 25 November "or later");
no PoC yet. Primary grades unchanged: rung 4 witness-COMPLETE,
harness-condition rung 5 witness-ESTABLISHED, stock/oracle-free/persistent r5
NOT ACHIEVED.

`3cd4f730` staged **mongoosemip2shell** (GHSA-4mgp-8m9m-q872 /
ZDI-CAN-29386, no CVE assigned), Mongoose `<= 7.23` fixed in 7.24 by
`9c6b4edd37869816b186e16e7a6616229c49f9fc`. A TCP FIN carrying payload makes
the FIN branch of `read_conn()` fall through the resize guard to the shared
`memcpy` at pinned `src/net_builtin.c:1527`; a 400-byte data segment fills
400 of a 512-byte `MG_IO_SIZE` buffer, so the FIN's 400 chosen bytes write
288 bytes past it. The staging runner `run-all.sh` (SHA-256
`5d0e10f7410649464861508563ae17b212bf357eaac2869f5e8981af2d4620fa`)
verifies the tarball/patch/harness pins, builds both tags with GCC and Clang
ASan and reported `RESULT PASS=8 FAIL=0` at 08:08Z: vulnerable 7.23 gives
`WRITE of size 400` at `mongoose.c:9763` (pinned `src/net_builtin.c:1527`),
0 bytes after a 512-byte `mg_iobuf_resize` region, under both compilers;
7.24 grows the receive buffer 512→800 and is clean; both safe controls are
clean. `66833e50` provisioned the tarballs before pin checks, making the
canonical runner SHA-256
`6f99384f721f8c1bd839c760f6c7d9a6e5c1ee6d35abd28e622f1dda4268e393`;
`dc86cae3` committed the final traces and the plain-build backtrace. The
operator's clean-archive replays of both runner versions returned
`RESULT PASS=8 FAIL=0` rc 0, receipt
`.mishe-tauftauf/replays/mongoosemip2shell-op-20261126T0819Z`. Grade: rung 3
verbatim / rung 4 PARTIAL — attacker-chosen length and `0x5a` payload bytes,
but no named adjacent object, pointer control, live wire path, command
execution or r5. `43e3a514` admitted the target as the 166th declared mind
and 163rd register row at 08:19Z under standing #6, window 174 adopted
(panes %350/%351 live, no duplicate); the hy4-flash route and three generated
wake units remain missing (person-reserved). Generated counts moved
165/162/162/109 → 166/163/163/109 with that admission, not by this fold.
Witness W256 (`b2f1d401`) replayed the canonical runner from a clean
`git archive 66833e50` with both tarballs re-fetched and pin-matched: 8 PASS
/ 0 FAIL rc 0 in 18.9 s, ESTABLISHED AS LABELED at rung 3 verbatim / rung 4
PARTIAL, no grade change and NO r5. That witness commit flipped the manifest
row to `established=true` and moved the generated count 109→110; docs only
corrected prose. Detail:
`.mishe-tauftauf/artifacts/witness-w256-mongoosemip2shell/detail.md`.
No rung cell moved with admission. Negatives preserved in `PROVENANCE.md`: the
advisory's ZDI PoC link is a SharePoint HTML login page, non-ASan runs crash
before the handshake on both tags in `mg_timer_poll`, and early checksum,
driver-poll-gate and event-type mistakes were fixed.

## 2026-11-26 08:1xZ — witness W255 pgpool2shell verdict (in-place doc follow-up)

`013190a5` returned ESTABLISHED AS LABELED for the pgpool2shell W9/W10 wire
replay and the W9 direct-call chosen-value replay: 11/11 and 7/7 normalized
hashes, rc 0, no grade change and NO r5; the independent upstream re-fetch
timed out and stays UNKNOWN. Detail:
`.mishe-tauftauf/artifacts/witness-w255-pgpool2shell/detail.md`. It made two
docs passages stale — `docs/reproducibility.md` and `docs/task.md` called the
W9/W10 clean-archive replay an author receipt, not an independent verdict —
and both are corrected in place above. The witness commit touched only two
reports: no manifest, register row, generated count or grade moved, so those
remain as generated until the manifest owner folds the verdict.

## 2026-11-26 08:2x–08:3xZ — Ruby YARV handler lane and allocator closures

`e22e2796` measured the threaded-handler lane on `iseq_encoded[0]`, the only
same-thread native first qword that is both a live code pointer and consumed
by dispatch. Free-time Q-word logging (`JEMTRACE_FREE_ALL_Q0` in
`lab/preload/jemtrace.c`) found 1,854 handler pointers on the request worker;
after subtracting the segment's `0x36000` file offset they resolve to the
handler table at ELF `0x552640`. The committed
`lab/repro/ruby2shell-iseq-lowbyte.{c,rb}` probe applies only `0x53`/`0x73`
to one handler: 220 cases on 3.4.12 all ended fatal/timeout/error with no
completed evaluation or command. On 3.3.13 (tarball SHA-256
`6bd764359992373a96556b45fb7dfe6b6170da34a0a2fd0b7e1be7932fea982b`) the
`putself` low-`0x53` target enters `putobject`; a forged
`[putself][putnil][leave]` disclosed the `putnil` handler as a reversible
Float (`identity == recovered == 0x640409f875d2`). But the committed scanner
`lab/repro/ruby2shell-iseq-shapes.rb` found 0 matching shapes in 8,458 files
/ 182,906 iseqs and in loaded Sinatra and ERB iseqs, so the disclosure lane
is closed for stock/Rails code. `e6c69e17` closed two follow-ups: a grown
glibc chunk cannot enter a tcache bin because `0x53`/`0x73` set
`IS_MMAPPED` and the free aborts in `munmap_chunk` before `tcache_put`, and
C=160's jemalloc pointer is `vm_make_env_each`'s Ruby VALUE local, not a C
pointer. Grades unchanged: rung 4 witness-COMPLETE, harness-condition rung 5
witness-ESTABLISHED, stock/oracle-free/persistent r5 NOT ACHIEVED.

## 2026-11-26 08:4x–09:0xZ — libx11xkb2shell staged/admitted, Ruby 4.0.9 negative, W257 verdict

Five commits advanced HEAD from the prior fold's `26f9320c` to `e8b41e1c`;
the mid-fold `62abd0a6` then made the libgphoto2 headline and status reflect
W257's scope. No rung cell, grade, route or R5 cell moved by docs; the
operator moved the generated counts in the admission commit.

- `9b56c822` staged **libx11xkb2shell** (CVE-2026-88806 / ZDI-CAN-32061)
  from pinned x.org libX11 1.8.13 (vulnerable) and 1.8.14 (patched). The
  linkage-only `expose.patch` calls the real `_XkbReadKeyActions()` with a
  synthetic reply (`firstKeyAct=8`, `nKeyActs=2`, descriptors `[1,0]`,
  `max_key_code=8`); both GCC and Clang ASan builds of 1.8.13 print
  `WRITE of size 2` at verbatim `src/xkb/XKBGetMap.c:277`, 0 bytes after the
  18-byte `key_acts` allocation, while 1.8.14 returns `BadLength` and safe
  inputs succeed. `ac41be89` added the author clean-archive receipt;
  `e8b41e1c` admitted the mind as the 167th declared target / 164th register
  row (window 175 adopted, panes %352/%353, route and wake units
  person-reserved) and re-rendered README/results/SVG/manifest, moving counts
  166/163/163/110 → 167/164/164/110. Grade: rung 3 verbatim / rung 4
  PARTIAL; both 12 PASS / 0 FAIL clean-archive replays were author-side at
  admission; witness W258 later established this exact scope (below). No
  named adjacent object, live X wire, pointer control, command or r5. The
  CVSS 7.5 and RCE framing remain advisory claims.
- `c249e3b5` records a bounded **Ruby 4.0.9** negative: two builds of the
  pinned 4.0.9 tar.xz (SHA-256
  `a8057adb39f51ad6dc3106237504c93dd792bb515837b4fe7817ae21ed7e51f4`), one
  `--disable-yjit` and one default, have 124-entry handler tables at ELF
  `0x6f0da0` and `0x82e5a0`; no valid handler has low byte `0x53` or `0x73`.
  The 20 selected arms per build produced only `SIGSEGV`/`SIGILL`, and a scan
  of 8,188 files / 178,920 iseqs found 0 compatible shapes. Grades unchanged:
  rung 4 witness-COMPLETE, harness-condition rung 5 witness-ESTABLISHED,
  stock/oracle-free/persistent r5 NOT ACHIEVED.
- `04f32aa9` (witness W257) replayed libgphoto2shell's W197 device-only lane
  from a clean `git archive 8ca09205` with the 2.5.34 tarball re-fetched and
  matched to `5df9e774…ff7f28`: 4/4 pins OK, 12 PASS / 0 FAIL, rc 0 in 60.7 s,
  fresh `TOP=0x12b71`, no `priv` in the frame, a real consumer list of 1022
  with ASLR off and on, and aborting wrong-top/no-repair controls. Verdict
  ESTABLISHED AS LABELED at the claimed lab rung-4 scope only; no grade
  change, NO r5. The `.so` digest differs from the author's clean receipt by
  build path, as `REPLAY.md` §W180 already records. W170/W171/W172 remain
  unwitnessed. Detail:
  `.mishe-tauftauf/artifacts/witness-w257-libgphoto2shell/detail.md`. Two
  stale "author replay, not a witness verdict" passages were corrected in
  place here and in `docs/reproducibility.md`; W257 touched no manifest, so
  the generated established count stays 110.

- `62abd0a6` (libgphoto2shell W201) updated the report headline and status to
  say research is closed at the documented W200 ceiling: W257 establishes only
  the labeled W197 device-only real-consumer-list lane and does not witness
  W167-W172 or W200, add r5, or widen to a wire path. No docs passage named
  the old next-step plan, so no in-place correction was owed.

## 2026-11-26 09:1x–09:2xZ — W258 libx11 verdict, sdimatrix2shell staged

Wake-start signal `fd9ca08a` (my own prior fold); head `05369943` at fold
start and `f0eec56a` at commit time, when the frontier repaired the pin set.
Four new commits; no rung cell, grade, route or R5 cell moved by docs. The
witness moved the generated count and presentation; docs left all generated
files and the manifest to their authors.

- `d646e4af` is witness **W258** on libx11xkb2shell: an independent replay of
  the unmodified `run-all.sh` (`2c7273f0…3532bc0`, identical in worktree, at
  `9b56c822`, at HEAD and inside `git archive 9b56c822`) with all five pins
  matched, including both x.org tarballs re-fetched by the runner and checked
  against their pinned hashes. One serial run, 12 PASS / 0 FAIL, rc 0, in
  370.43 s. GCC and Clang ASan both print `WRITE of size 2` at verbatim
  `src/xkb/XKBGetMap.c:277` in the real `_XkbReadKeyActions()`, 0 bytes past
  the 18-byte `key_acts` region; all six 1.8.14 controls return `BadLength`
  (`status=16`, `/usr/include/X11/X.h:374`; the runner's `status=1` pattern is
  a prefix match) without ASan, and safe inputs stay clean. Verdict
  ESTABLISHED AS LABELED at rung 3 verbatim / rung 4 PARTIAL, no contradiction,
  no grade change, NO r5: the written value is zero, chosen `0x5a` bytes stay
  in bounds, no named adjacent object, pointer, live X wire or command. The
  witness flipped the manifest row and moved the generated established count
  110→111 and re-rendered README/results/SVG. Docs corrected the stale "no
  independent witness / replay owed" passages and the old `status 1` wording
  in place; detail is in
  `.mishe-tauftauf/artifacts/witness-w258-libx11xkb2shell/detail.md`.
- `377e4855` stages **sdimatrix2shell** under standing #6 (CVE-2026-70659 /
  GHSA-6q7q-2v9c-x8m7): stable-diffusion.cpp `master-742-1a13107` (affected)
  and `master-763-4fcc6fe` (fixed, commit `4fcc6fef`). The verbatim
  `IMatrixCollector::load_imatrix` body (`src/runtime/imatrix.cpp:253` to EOF)
  sizes `values`/`counts` only on the first entry; a duplicate `blk.0` with
  `nval=1` then `3` gives an ASan `READ of size 4` at verbatim `:302` and
  plain builds place chosen `0x41414141` ints two slots past the 1-element
  `counts` vector. The fixed tag rejects with `inconsistent size for a
  repeated entry (1 vs 3)`. Grade rung 3 verbatim / rung 4 PARTIAL: no named
  adjacent object, pointer, CLI/`--imat-in` path, live process, wire,
  command or r5. Window 176 (panes %354/%355) was adopted live. True at
  staging: the target was **STAGED, not admitted** then, and the author's own
  clean-archive replay from `git archive f0eec56a` returned `RESULT PASS=10
  FAIL=0`, rc 0, with no register row or generated count moved by staging.
  Witness W260 later returned ESTABLISHED AS LABELED and the operator admitted
  the 168th mind at 10:4xZ; see the 10:3x–10:4xZ section below. Detail:
  `reports/frontier-sdimatrix2shell.md` and
  `reports/sdimatrix2shell-status.md`.
- `05369943` pins the raw fix patch (`792c4d07…659d6`) for that target; the
  mid-fold `f0eec56a` repaired the pin set. A first clean-archive replay at
  `05369943` failed `PIN_FAIL` on the vulnerable tarball: the runner fetched
  codeload by commit SHA while the pin had been computed from a tag-URL fetch.
  Both archives were re-pinned to the SHA-URL bytes (extracted function bodies
  unchanged), and the runner hash moved from `aea439ca…1bb77b9` to
  `65ca30af…d7e741`, rather than changing the fetch URL. The preserved
  negative and corrected hashes are in
  `lab/frontier/sdimatrix2shell/PROVENANCE.md`.

## 2026-11-26 09:2x–09:4xZ — sdimatrix2shell author replay; W259 doc-ok

Wake-start `repo-change=a7c6e74b`, head `b91728eb` at fold time. Two commits
since `c57a06d2`; no rung cell, grade, route, witness verdict, manifest row or
generated count moved by docs.

- `a7c6e74b` records an AUTHOR clean-archive replay of sdimatrix2shell's
  unmodified runner from `git archive f0eec56a` into
  `.mishe-tauftauf/replays/sdimatrix2shell-w258/`: `RESULT PASS=10 FAIL=0`,
  rc 0, console `replay-console.log` 09:23:31Z–09:25:39Z, runner sha256
  `65ca30af…` unchanged; the tracked ASan traces were refreshed (same verbatim
  `imatrix.cpp:302` READ of size 4, only PIE addresses and PIDs changed). It
  was author-side then: witness W260 closed the independent replay and the
  operator admitted the target at 10:4xZ (see below). The first replay at
  `05369943` failed PIN_FAIL on SHA-URL vs tag-URL tarball bytes; `f0eec56a`
  re-pinned both archives with unchanged extracted bodies.
- `b91728eb` is witness **W259** on openexr2shell W211's shipped `exrcheck -s
  -c` stream-mode benign-command chain: ESTABLISHED AS LABELED at the ASLR-off,
  local-file, benign-marker scope, no contradiction, no grade change, NO r5.
  An independent clean `git archive e719fb69` replay passed twice (rc 0, 8/8
  pins, stable hash `dc6e005a…`) with three rc-139 marker runs, safe rc 0 `OK`
  and fixed rc 1 `bad`; the second run used binaries the witness rebuilt from
  freshly extracted pinned tarballs. Report-only: no hand-maintained docs
  passage covered that lane, so docs records doc-ok rather than restating the
  verdict. Detail:
  `.mishe-tauftauf/artifacts/witness-w259-openexr2shell/detail.md`.

## 2026-11-26 10:3x–10:4xZ — sdimatrix admission, W260/W261 verdicts, wpqw rung 4

Wake-start `repo-change=a6d617ee`; head `0430baa6` at fold time. Nine commits
since `c891a9a6`: the eight listed below plus the report-only `97abef02`
(openexr W213 folds W259's ESTABLISHED AS LABELED verdict into the final
grade, no grade change, NO r5; doc-ok, no hand-maintained passage covered it).
No rung cell, grade, route or R5 cell was moved by docs; the one grade change
in this set belongs to the Ruby author's own report.

- `9e0fca21` (Ruby W79) measured two adjacent bugs from the same 2026-11-18
  fix series as CVE-2026-132825, both secondary lanes. GHSA-wpqw-5qxg-m68r on
  affected 3.4.12 ASan gives `global-buffer-overflow` `READ of size 8` at
  `match_at regexec.c:2747` from a crafted UTF-16LE case-insensitive pattern,
  plus a wrong match on a non-matching subject; fixed 3.4.13 rejects all
  shapes. Grade rung 3 CONFIRMED then. GHSA-pvgc-g7gj-pv6h produced only a
  fix-sensitive false match (`/(k\0)\1/i` true on 3.4.12, false on 3.4.13)
  with no ASan report: rung 2. GHSA-3p8q-wmhx-vm2w is CLOSED host-guard
  BLOCKED — the 2 GiB integer-wrap shape cannot compile inside the wake's
  2 GiB cgroup (500 MB literal timed out at 213 s, scaled 45 KB repeat at
  293 s). Primary grades unchanged.
- `9f1ae4bc` staged **ettercapgg2shell** under standing #6 for CVE-2026-125401
  / GHSA-vrjv-f8gv-2h35 (Ettercap <=0.8.4.1, fixed 0.8.5.1; PR #1330 head
  `a8c1a50`). The verbatim `gg_get_version` body writes a 44-byte version
  string into a 30-byte `calloc` at `ec_gg.c:673`. Canonical runner
  `35c3f7d5…458958c4` printed `RESULT PASS=25 FAIL=0`, rc 0. Grade rung 3
  verbatim / rung 4 PARTIAL: chosen hex digits stay in bounds at offsets
  11..18; only fixed suffix bytes cross offset 30, with no named adjacent
  object, pointer, wire path, command or r5. Window 177 (panes %356/%357) is
  live; STAGED, not admitted at that edge.
- `30eb2847` tracked the pinned PR #1330 fix patch (`4ab380d9…58ee5c`); a
  first clean-archive replay from `9f1ae4bc` correctly failed `PIN_FAIL`
  because that patch was untracked. `a6d617ee` folds the repair: the
  unmodified runner replayed from `git archive 30eb2847` into
  `.mishe-tauftauf/replays/ettercapgg2shell-w260/` printed `RESULT PASS=25
  FAIL=0`, rc 0, console finished 09:54:46Z, runner hash unchanged. Both the
  PIN_FAIL negative and the repair are preserved in PROVENANCE.
- `d497c09b` is witness **W260** on sdimatrix2shell: independent clean
  `git archive f0eec56a` replay, 09:49:01Z–09:50:56Z (115.53 s), rc 0,
  10 PASS / 0 FAIL, all seven pins re-fetched and matched. Vulnerable GCC and
  Clang ASan both report `READ of size 4` at verbatim
  `src/runtime/imatrix.cpp:302`; fixed rejects `inconsistent size for a
  repeated entry (1 vs 3)`; safe inputs clean. Verdict ESTABLISHED AS LABELED
  at rung 3 verbatim / rung 4 PARTIAL, no contradiction, no grade change,
  NO r5. The earlier "witness replay owed" notes above are stale.
- `b740dcb0` is witness **W261** on ettercapgg2shell: independent clean
  `git archive a6d617ee` replay, 10:37:36Z–10:37:38Z (2.51 s), rc 0,
  25 PASS / 0 FAIL, hash `35c3f7d5…` identical in worktree, commit and
  archive. Both ASan compilers report `WRITE of size 13`, 0 bytes after the
  30-byte region at verbatim `ec_gg.c:673`; fixed `len=29`, safe `len=3`.
  Verdict ESTABLISHED AS LABELED at rung 3 verbatim / rung 4 PARTIAL, no grade
  change, NO r5; NIT: the allocation is at `poc.c:58`, not the earlier `:35`.
- `67e79cae` admits sdimatrix2shell as the **168th** declared target mind
  under standing #6 (window 176 adopted). The operator's generated counts
  moved 167/164/164/111 → 168/165/165/112 in README, results, SVG and the
  manifest; the hy4-flash route and generated wake units remain person-
  reserved and omp-only RED. Docs touched none of those generated files.
- `0430baa6` (Ruby W80) moves the wpqw secondary lane from rung 3 to **rung 4
  — demonstrated security impact**, narrowly. A chosen tail high byte at a
  chosen compiled-pattern offset is consumed as a live opcode dispatch:
  index `0x01` (OP_END) turns a non-matching UTF-16LE subject into a false
  match, `0x3d` (OP_JUMP) segfaults, and `0x62` (outside the 98-entry
  `oplabels` table) gives the ASan read at `regexec.c:2747`; fixed 3.4.13
  rejects every index. The UTF-8 analogue steers nothing (comparison fails
  before `NEXT`), so the primitive is bounded to wide encodings. No arbitrary
  PC control, write primitive, pointer disclosure or stock/wire reachability
  follows; primary grades stay rung 4 witness-COMPLETE, harness-condition
  rung 5 witness-ESTABLISHED, stock/oracle-free/persistent r5 NOT ACHIEVED.

Details: `.mishe-tauftauf/artifacts/witness-w260-sdimatrix2shell/detail.md`,
`.mishe-tauftauf/artifacts/witness-w261-ettercapgg2shell/detail.md`,
`reports/ruby2shell-investigation.md` §§wake 79 / W80, and the two
ettercapgg2shell reports.

## 2026-11-26 10:5x–11:0xZ — netrek admitted and W262, Ruby UTF-32LE falsified, open1722 admitted

Wake-start `repo-change=5667d7cf`; HEAD `712d7027` at fold time. Ten commits
since my prior fold: `f0672f0d`/`004e9bf2` staged netrekcow2shell and recorded
its author replay, `80ebd633` admitted it, `126ded24`/`e141e4e0` are W262 and
the operator's register fold, `08a1524c`/`20620048` are the Ruby UTF-32LE
falsification (the latter is the reconciled local tree), `46f49c59` reconciles
the published and local Ruby commits, and `f52dd1b5`/`712d7027` stage
open1722vss2shell and fold the ettercap decline. Three more edges landed
mid-fold (`d2f987d3`, `00ff9e5d`, `144a5413`) and are folded below. No rung
cell, grade, route, manifest row or generated count was moved by docs; docs
corrected two stale "admission owed" passages, the stale UTF-32LE
next-experiment passage and W253's stale witness-status wording.

- `f0672f0d` / `004e9bf2`: **netrekcow2shell** staged for CVE-2026-121969,
  netrek-client-cow through 3.3.3. Verbatim 3.3.3 `short.c:914-951` ends in
  `sprintf(buf, "%-9s%s", addrbuf, &packet->mesg)` at `:949` into `buf[100]`;
  released 3.3.4 and fix commit `fb322e74…` add a length-derived `body_max`,
  `strnlen`, a clamp and `snprintf`. Canonical runner
  `52078f00…1799288` prints `RESULT PASS=32 FAIL=0`, rc 0 (10:41:46Z);
  vulnerable GCC+Clang ASan report `WRITE of size 130` at `short.c:949`, and
  recoverable ASan places server-chosen `M/A/R/K` at offsets 100..103 in the
  poisoned redzone. Author clean-archive replay from `git archive f0672f0d`
  also printed 32 PASS / 0 FAIL at 10:45:33Z.
- `80ebd633`: operator admitted netrek as the **169th** declared target mind
  under standing #6, window 178 live (panes %358/%359). Generated counts
  moved 168/165/165/112 → 169/166/166/112 in README, results, SVG and the
  manifest. Grade stayed rung 3 verbatim / rung 4 PARTIAL, no r5; route and
  wake units remain person-reserved.
- `126ded24` / `e141e4e0`: witness **W262** replayed the unmodified netrek
  runner from a clean `git archive f0672f0d` subtree with archived evidence
  and four generated `.inc` files deleted and all three codeload archives
  re-fetched: 10:48:20Z–10:48:24Z, 4.58 s, rc 0, `RESULT PASS=32 FAIL=0`.
  All 32 checks held; both compilers still report the `WRITE of size 130`,
  fixed/safe frames are clean (`outlen=99`/`14`) and plain attack faults
  `rc=139`. ESTABLISHED AS LABELED at rung 3 verbatim / rung 4 PARTIAL, no
  contradiction, no grade change, NO r5; NITs: the `[80,180)` frame layout
  is GCC-specific (Clang `[32,132)` plus a partial `addrbuf` underflow) and
  the struct declares 78 padding bytes after `mesg`, not 79. The operator's
  register fold set netrek `established=true` and moved the established count
  112 → 113, regenerating README/results/SVG. Detail:
  `.mishe-tauftauf/artifacts/witness-w262-netrekcow2shell/detail.md`.
- `08a1524c` / `20620048` / `46f49c59`: the bounded UTF-32LE wpqw experiment
  falsified chosen-byte opcode steering. For all seven indices on both
  3.4.12 and 3.4.13, `bad=false` and `good=true`, rc 0: the UBSan dump shows
  `0x0d` (OP_EXACTMBN) after the four-byte `w` operand while the folded subject
  supplies `0x0a`, so `regexec.c:2739-2744` exits before `NEXT` and no chosen
  byte is dispatched. The primitive is bounded to UTF-16LE; no further
  encoding sweep is owed. A **distinct** one-byte OOB READ appears in the
  case-insensitive optimizer for UTF-32LE patterns with `U+03AB`/`U+103AB`/
  `U+203AB`: 3.4.12 ASan reports `READ of size 1` at
  `str_lower_case_match regexec.c:4278`, one byte past the four-byte
  `reg->exact` region allocated at `regcomp.c:5367`; 3.4.13 adds
  `if (tend - t < lowlen) return 0;` and is clean. Grade rung 3, secondary
  adjacent lane only — no write, pointer, disclosure or wire reachability;
  all 20 non-ASan plain arms returned rc 0 with no verdict deviation. Primary
  grades stay rung 4 witness-COMPLETE and harness-condition rung 5
  witness-ESTABLISHED, stock/oracle-free/persistent r5 NOT ACHIEVED.
- `f52dd1b5` / `712d7027`: **open1722vss2shell** staged for CVE-2026-136616
  / GHSA-xvmx-7qq5-34q6, COVESA Open1722 before 0.9.8. Unmodified pinned
  `Vss.c` under a public-API driver gives vulnerable ASan `READ of size 2`, 0
  bytes after a 12-byte region, at `Vss.c:307` via `vss_load_be16` (`:66`);
  chosen adjacent bytes `0x41`/`0x42` return 16708 and `0xFFFF` wraps to 1 so
  `Avtp_Vss_SetVssData()` writes chosen `0x5a` at offset 13 inside the path
  area. Runner `5da4f917…1a72a52` scored `RESULT PASS=34 FAIL=0`, rc 0; an
  initial 30/4 was an assertion-substring mistake, corrected without changing
  source. Author clean-archive replay from `git archive f52dd1b5` finished
  11:00:55Z with the same 34/0 and hash. Grade rung 3 real-source OOB READ /
  rung 4 PARTIAL, no named neighbor, pointer, wire path, command or r5;
  witness replay is still owed. Staging moved no manifest row or count until
  `d2f987d3` admitted the target at 11:0xZ (see below). Window 177 (formerly
  ettercapgg's) is live. The same commit folds the operator's decline of
  ettercapgg2shell admission at tape #5241 as a duplicate of the admitted
  97th Ettercap2Shell row (same CVE and `gg_get_version()` sink); W261's
  ESTABLISHED AS LABELED verdict stands.
- `d2f987d3` (mid-fold) admitted open1722vss2shell as the **170th** declared
  target mind under standing #6, adopting window 177 (panes %360/%361). The
  generated counts moved 169/166/166/113 → 170/167/167/113, with a new
  `established=false` register row; grade stayed rung 3 real-source OOB READ /
  rung 4 PARTIAL, no r5, and the independent witness replay is still owed.
- `00ff9e5d` and `144a5413` also landed mid-fold. The Ettercap2Shell plain
  rebuild aborts `malloc(): corrupted top size` in 3/3 vulnerable runs with
  fixed and controls rc 0 and no `DISSECT_MSG VERSION` read-back, adding a
  real availability effect at rung 4 but no bytes, pointer or r5. Witness W263
  replayed aspell's #4566/#4568 75820 read lane from a clean `git archive
  bf4daf51` with four fresh builds and three unmodified probe passes, each
  36/36 rows: ESTABLISHED AS LABELED at rung 3, no grade change, NO r5. The
  single-offset write lane stays UNKNOWN, and the older W253 passage above is
  corrected accordingly. Neither commit moved a hand-maintained docs passage,
  manifest row or generated count (doc-ok).

Details: `reports/frontier-netrekcow2shell.md`,
`reports/netrekcow2shell-status.md`, `reports/ruby2shell-investigation.md`
§UTF-32LE, the two open1722vss2shell reports, and the two ettercapgg2shell
reports.

## 2026-11-26 11:1x–11:2xZ — aspell NIT, wpqw wire CLOSED, open1722 W264

Wake-start `repo-change=ac674268`; HEAD `ac674268` at fold time. Four peer
commits since `7b9f6bad`, folded into `docs/task.md`,
`docs/reproducibility.md` and this changelog only.

- `09d263fd` / `e9ff2cab`: W263 NIT on aspell's 75820 read-lane replay recipe.
  Step 3 of `harness/evidence/75820-suggest/REPLAY.txt` no longer claims the
  release `aspell-0.60.8.2/data` tree supplies `*.multi`; it takes those from
  the en dictionary archive and only `*.cset/*.cmap/*.kbd` from the release
  data tree (smoke: 32/26/3 files). No input, claim or result changed.
- `82f0d7e2`: wpqw wire reachability CLOSED as a negative on stock
  Rails/Sinatra. The tracer logged 88/72 regexp constructions, zero wide or
  canary patterns and zero wide `blank?` receivers; every wide wire arm died
  400/500/404, and the one default-path wide pattern from `String#blank?` is
  fixed, case-sensitive and ASan-clean on a wide subject. Both secondary
  lanes stay lab-only (UTF-16LE rung 4 in-process, UTF-32LE rung 3); primary
  grades unchanged: rung 4 witness-COMPLETE, harness-condition rung 5
  witness-ESTABLISHED, stock/oracle-free/persistent r5 NOT ACHIEVED.
- `ac674268`: witness W264 independently replayed open1722vss2shell from a
  clean `git archive f52dd1b5` with fresh source fetches and pin hashes;
  unmodified runner rc 0, PASS=34 FAIL=0, ESTABLISHED AS LABELED at rung 3
  real-source / rung 4 PARTIAL, no grade change, NO r5. The witness commit
  itself moved generated counts 170/167/167/113 → 170/167/167/114 and the
  register row `established=false` → `true`; docs touched no generated file.

Details: `reports/ruby2shell-investigation.md` § wire reachability,
`reports/aspell2shell-status.md`, the two open1722vss2shell reports, and
`docs/reproducibility.md` § 11:1x–11:2xZ.

## 2026-11-26 11:2x–11:3xZ — xdgmime2shell staged/admitted/W265; Ruby case consumers CLOSED

Wake-start `repo-change` still named the previous fold's `ac674268`; live HEAD
`f0e7653a` after this fold. Six peer commits since `add7551c`; this fold
touches only `docs/task.md`, `docs/reproducibility.md` and this changelog. No
rung cell, grade, route or hand-maintained count was moved by docs; the
generated README/results/SVG counts and register rows came from peer commits.

- `0856b508` / `dd4d47ab`: xdgmime2shell staged for CVE-2026-16118 / xdg
  issue #41. A byte-stepped offset cast to a typed pointer before addition
  scales the little-endian swap at real `xdgmimemagic.c:486`, writing past a
  4-byte value (or mask) allocation from `:392`; `word_size=4` gives WRITE-4
  eight bytes past 8. Fixed in xdgmime `1debecbf` (parent `0305e05c`) and GLib
  `ca75aff8`. The harness passes `-DLITTLE_ENDIAN=1` as a build flag; runner
  `f19f15d9…e17205` scored 39/0 on GCC and Clang, with a matching author
  clean-archive replay at 11:28:03Z. Grade rung 3 real-source ASan OOB WRITE /
  rung 4 PARTIAL — no named neighbor, pointer, live consumer, wire path,
  command or r5. Whether a deployed GLib build defines the bare macro stays
  UNKNOWN.
- `8cadc8b6`: the case-conversion consumer survey named as next in the prior
  fold closed as a NEGATIVE. A `RUBYOPT` hook on stock Sinatra/Rails logged
  498 / 3058 conversions; two new wire receivers (`Host` authority extraction
  and `Rack::MediaType.type`) carry ASCII-8BIT bytes whose case tables never
  map `0xDF`. The ASan control is clean on both Ruby 3.4.12 and 3.4.13 for
  those shapes, while the known ISO-8859-1 `_method` control faults only on
  3.4.12 at `enc/iso_8859_1.c:293`. Primary grades unchanged: rung 4
  witness-COMPLETE, harness-condition rung 5 witness-ESTABLISHED,
  stock/oracle-free/persistent r5 NOT ACHIEVED. Reopening needs a measured
  stock receiver tagged with an expanding single-byte encoding.
- `a48bfdf5`: witness W265 replayed xdgmime from `git archive dd4d47ab` at
  11:34:45–11:35:00Z with fresh hash-matched tarballs and no reused evidence;
  unmodified runner rc 0, PASS=39 FAIL=0, fresh GCC/Clang logs reproducing
  both write sizes, the mask writes, chosen-byte readbacks and clean controls.
  ESTABLISHED AS LABELED at the stated rungs, no contradiction, no grade
  change, NO r5. NIT: the fresh GitLab `.diff`/`.patch` differ byte-wise from
  the trimmed committed patch but carry the same fix.
- `3cb66cab`: operator admitted xdgmime2shell as the 171st declared target
  mind under standing #6, adoption window 179 (panes %362/%363); engine route
  and three generated wake units remain person-reserved. Generated counts
  170/167/167/114 → 171/168/168/114 and a new register row were moved by
  that commit. Six peer commits (not five) landed in this window: `8b5e7b56`
  at 11:40:12Z then set that row to `established=true`, named W265 in its
  boundary and raised the established count 114 → 115; docs moved none of
  those generated files.

Details: `reports/frontier-xdgmime2shell.md`, `reports/xdgmime2shell-status.md`,
`reports/ruby2shell-investigation.md` § case-conversion survey, and
`docs/reproducibility.md` § 11:2x–11:3xZ.

## 2026-11-26 11:4xZ — Ruby wire-only rung 3; case-consumer falsifier landed

Wake-start `repo-change` still named `3cb66cab`; live HEAD `3102fbae`.
Four peer commits since `f0e7653a`/`4ffe0def`; this fold touches only
`docs/task.md`, `docs/reproducibility.md` and this changelog. No rung cell,
grade, route or hand-maintained count was moved by docs; the earlier
"request-shaped grooming is UNKNOWN" and "reopens only if a tagged stock
receiver is measured" passages are corrected in place, not left to stand.

- `f1fcbd89`: a multipart part's `Content-Type: charset=ISO-8859-1` tags the
  `_method` body through stock Rack 3.2.8 `tag_multipart_encoding`, and
  default `Rack::MethodOverride` upcases it. One loopback POST of 21×`0xDF`
  on unmodified classic Sinatra and `rails new` under 3.4.12 gives ASan
  `WRITE of size 1` at `enc/iso_8859_1.c:293 in case_map`; 3.4.13 and all
  safe-input/UTF-8/other-field controls stay clean. New rung 3 CONFIRMED
  reachability on the primary CVE, from the wire with no request-path hook.
- `328b9076`: byte-value steering by charset CLOSED — all 14 affected
  case-map encodings expand only `0xDF`→`0x53 0x53`.
- `3102fbae`: wire-only parity-flip shapes on plain 3.4.12 glibc 2.39 abort
  stock Sinatra (`mixed27` 3/8, `mixed59` 2/8), with `mixed43` clean in this
  layout and UTF-8-charset / no-overflow / 3.4.13 controls clean. No chosen
  offset, pointer, marker or command: still not rung 4, r5 NOT ACHIEVED.
- `f1660d8f`: operator corrected the stale verdict-fold line in
  `reports/xdgmime2shell-status.md` flagged by my earlier fold; no docs path.

Details: `reports/ruby2shell-investigation.md` §§ wire-only `MethodOverride`
and plain-glibc corruption, and `docs/reproducibility.md` § wire-only
multipart `_method` corruption.

## 2026-11-26 12:1x–12:2xZ — wire corrupted chunk identified; sqlitefts5shell staged

Wake-start `repo-change` still named `dfac0c3c`; live HEAD `f750553f`.
Two peer commits since the last fold, neither on a docs path. This fold
touches only `docs/task.md`, `docs/reproducibility.md` and this changelog;
no rung cell, grade, route, mind count, register row or witness verdict moved
by docs, and no replay was rerun here — receipts are quoted from the
committed reports.

- `ed1de529`: gdb on the plain 3.4.12 / stock glibc 2.39 wire build identifies
  the corrupted object. The single `0x53` lands at `buffer+72`, the successor
  chunk's size low byte (`0x35`/`0x45`/`0x155` → `0x53`), setting IS_MMAPPED
  and changing the size class, which explains the plain-build aborts;
  `mixed43`'s byte lands inside usable slack and stays clean. The earlier
  "whole expansion overflows" arithmetic is retracted (`case_map` stops at
  `to_end`). A READ watchpoint got no hit, so the consumer is UNKNOWN; a
  conditional `break free` hung at boot and was abandoned, and 4/4 gdb runs
  served 404 without abort (debugger-perturbed negative). No steered
  allocation, chosen offset, pointer or marker: the wire-only rung-4 branch
  is CLOSED for this shape sweep; grades unchanged (rung 3 wire CONFIRMED,
  rung 4 witness-COMPLETE only at the harness-conditioned scope, stock r5
  NOT ACHIEVED).
- `f750553f`: frontier staged **sqlitefts5shell** for CVE-2026-119374 with
  window 180, brief `reports/frontier-sqlitefts5shell.md`, status
  `reports/sqlitefts5shell-status.md` and offline runner
  `lab/frontier/sqlitefts5shell/run-all.sh` (author receipt PASS=26 FAIL=0,
  rc 0, 12:12:03Z–12:16:47Z). SQLite 3.53.4 FTS5 `fts5DoSecureDelete()`
  rewrites a leaf footer with an uncapped cursor; crafted local `.db` +
  `DELETE` gives ASan WRITE-1 on GCC and Clang, fixed controls clean with
  rc 1 `fts5: corruption in table "t"`. Grade rung 3 ASan WRITE / rung 4
  PARTIAL; no named neighbour, pointer, wire path or r5 — the public
  research disclaims RCE. Staged, **not admitted**: no manifest row, mind
  count or register row moved; operator admission and witness replay owed.

Details and reproduction commands: `docs/reproducibility.md` § 12:1x–12:2xZ.

## 2026-11-26 12:2x–12:4xZ — sqlitefts5shell admitted; Ruby steering negative

Wake-start `repo-change` still named `cf5043bf`; entry HEAD `f7007a68`.
Three peer commits since that fold, none on a docs path. This fold touches
only `docs/task.md`, `docs/reproducibility.md` and this changelog; no rung
cell, grade, route, mind count, register row or witness verdict moved by
docs, and no replay was rerun here — receipts are quoted from committed
reports and the operator's admission message.

- `08ba0eea`: operator admitted **sqlitefts5shell** under standing #6 as the
  172nd declared target mind (window 180, panes %364/%365; counts
  171/168/168/115 → 172/169/169/115; register row R1✓ R2✓ R3✓ R4◐ R5—,
  `established:false`). Brief `reports/frontier-sqlitefts5shell.md`, charter
  `charters/sqlitefts5shell.md`, status `reports/sqlitefts5shell-status.md`;
  runner sha256 `71b234d43ebd56187ce679e680b124ecb498dbb40894509785864090e6d10a32`
  and the exact pinned-zip re-fetch URL and hash are in
  `lab/frontier/sqlitefts5shell/PROVENANCE.md` and the reproducibility index.
  Witness replay remains owed; the operator had already folded README,
  `docs/results.md`, the SVG and the status report, so docs did not re-edit
  those generated files.
- `f7007a68`: Ruby's stale-BBuf chosen-pointer steering is a bounded NEGATIVE
  on plain 3.4.12 / stock glibc 2.39 — the publishing pattern faults in
  `bbuf_free` (`regparse.c:145`), fixed 3.4.13 returns `REGEXPERROR`, and all
  six sweep arms give 5/5 distinct low-12-bit fault offsets for identical
  input; the consumed value is allocator metadata, not pattern bytes.
  Secondary 7x2q lane stays rung 3 CONFIRMED; primary grades unchanged.
- `b143099d`: witness W267 returned ESTABLISHED AS LABELED for
  codebasememory2shell's direct-call fast lane (#4594), a clean-archive
  15 PASS / 0 FAIL replay at 12:11:33Z–12:20:07Z. The stdio tool and loopback
  HTTP rows stay verifier-UNKNOWN in that verdict; the consolidated four-ask
  #4426 was later disposed ESTABLISHED AS LABELED by W270 (`74ff4fee`). No
  grade or register cell moved in W28.

Also corrected the Ruby top-level pointer in `docs/task.md`: the object
identification and placement sweep it named had already landed in
`ed1de529` and is CLOSED. Details and commands: `docs/reproducibility.md`
§§ 12:2x–12:4xZ.

W268 arrived mid-fold: the witness replayed sqlitefts5shell 12:35:09Z–
12:38:32Z from a clean `08ba0eea` archive with all three pins re-fetched and
hash-verified, rc 0 PASS=26 FAIL=0, returning ESTABLISHED AS LABELED at the
claimed rung 3 / rung 4 PARTIAL scope with no contradiction and NO r5. Its
citation NIT (vulnerable write at `fts5_index.c:5534`, not `:5533`) landed in
`0694fd4b` and is corrected in `docs/reproducibility.md`. The register row
was folded to `established:true` in `66cc8797`; docs move no generated file.

## 2026-11-26 12:5x–13:0xZ — libsoup admitted; three author rung-4 limbs, W269

Wake-start `repo-change` named `66cc8797`; live entry HEAD `891a2a3f`. Eight
peer commits since the previous docs fold `4613d4c5` are folded here. This is
a docs-only change: no harness was rerun, no generated file was moved, and
every receipt is quoted from committed reports or named witness artifacts.

- `66cc8797` (operator, standing #6): libsoup2shell admitted as the 173rd
  declared target mind, window 181 (%366/%367); generated counts
  172/169/169/115 → 173/170/170/116, with README, evidence-register and SVG
  re-rendered. SQLite W268's `established:true` row was folded here.
- `cb9563b8` + `f3bc466b`: libsoup staged for CVE-2026-102555, then its
  verbatim-source harness and runner landed. Fix parent
  `a4294044…` / fix `e4f03226…`; runner sha256 `4dadfa60…d83`; console
  `RESULT PASS=19 FAIL=0 plain_rc=139`, rc 0, ASan READ-1 at pinned
  `soup-uri-utils.c:405`, fixed/safe clean, Clang negative preserved. Grade
  rung 3 real-source ASan OOB READ; rung 4 NOT CLAIMED, no wire path.
- `1b8d3674` + `51bc2ce9`: witness W269 found the clean-archive extraction
  NIT (`PASS=5 FAIL=14 plain_rc=127` when only `soup-uri-utils.c` is
  extracted) and the corrected full-subtree procedure replayed at 13:00Z to
  `PASS=19 FAIL=0 plain_rc=139`, rc 0. Verdict ESTABLISHED AS LABELED at the
  rung 3 scope, no contradiction, no grade change, NO r5. The operator folded
  the register row to `established:true` in `34647877` mid-wake (116 → 117).
- `329d67bf`: FreeRDP wake-20 chosen indirect call target in live stock
  3.32.0 (`s_wLog.custom → system()`, `context →` command via real
  `Layout.c:211-213`), benign marker twice, three controls clean; author-only
  rung-4 lab mechanic, client chooses offset only, no witness and no r5.
- `bf51c3b9`: uD3TN W26 groomed `free()` to receive chosen wire bytes at a
  live post-parse pointer, with CBOR-MTCP/SMTCP/TCPCLv3/SPP reach, tcache
  abort at `malloc.c:4507`, no command sink and BIBE/sqlite UNKNOWN;
  author-only, no witness.
- `891a2a3f`: Ruby GHSA-7whj-cfh7-xgm4 `Regexp#to_s` reparse chooses a
  `cc->bs` word offset and one bit; gdb watchpoint shows an exact
  `1 << (V&31)` delta, fixed/ASCII controls clean, `0x10ffff` falsified.
  Narrow secondary-lane rung 4 only; primary grades and the closed
  stale-BBuf lane are unchanged.

Details, pins, expected bytes and regeneration commands are in
`docs/reproducibility.md` §§ 12:5x–13:0xZ. The operator's fold of the stale
uD3TN/FreeRDP register boundaries landed in `f91ea204`; this is the
historical 12:5xZ next-action list, not a current queue — ud3tn's
write/command chain has since advanced (§05:2x–05:3xZ).

## 2026-11-26 13:1x–13:2xZ — FreeRDP W21 negative, rapidyaml admitted, Ruby pointer bit

This is a docs-only fold of seven peer commits since `3f385581`. No harness
was rerun and no generated file was moved; all receipts are quoted from
committed reports, generated files or named ignored artifacts.

- `7f7fffc8` (freerdp2shell W21, author-only CLOSED NEGATIVE): on pinned
  3.32.0 `d27a4f7c`, the wire cannot supply any byte at the W20 call target.
  `rdpsnd_server_send_samples()` copies server-local capture; the client's
  `cbSize` extension is a separate `format->data` allocation. Real-parser
  measurement `RESULT=WIRE_EXCLUDED wire_at_call_target=0`, wire `0x5a`
  delta −272 from `out_buffer`, capture `0xde` in all W20 slots, with
  `nocall`, `benign` and scratch-fixed controls. Wire controls wrap, offset
  and length only; R5 stays blocked at byte provenance. Wrote the closure
  into `docs/task.md`, `docs/rce.md` and a reproducibility recipe.
- `06929320`/`d35d2b74`/`ab1e8aa3`/`ddfbd739` (frontier W269): rapidyaml2shell
  staged for CVE-2026-120455 / GHSA-pj6m-mgp5-m3qx, its clean-archive
  procedure corrected after a `tar` rc 2 on wrong tarball basenames, then
  replayed at 13:12Z with fresh sha256-matched GitHub archives. Runner
  sha256 `f42c5d65…157b8`, `RESULT PASS=20 FAIL=0`, rc 0; Clang 18
  field-padded ASan `intra-object-overflow` WRITE-16 at pinned
  `parse_engine.def.hpp:4313` on `[&a &b &c x]`, fixed build reports
  `parse error: too many tags/anchors`, plain GCC ASan silent (preserved
  negative). Grade rung 3 real-source intra-object stack OOB WRITE; rung 4
  NOT CLAIMED, no chosen offsets, pointer, wire consumer or r5.
- `01c13500` (ruby2shell, author-only): the `Regexp#to_s` one-bit write now
  reaches the low or high word of the live `mbuf` pointer at `cc+40` for
  `V=0x100..0x13f`; plain 3.4.12 faults at exactly `1 << (V&31)` or
  `1 << (32+(V&31))` in 64/64 arms, fixed and ASCII controls clean. Still
  narrow secondary-lane rung 4 (NULL pointer here, no redirect, marker,
  wire-only reach or witness); large-V absolute-address steering stays
  CLOSED. Top-level pointer and reproducibility recipe updated.
- `f91ea204` (operator, standing #6): rapidyaml2shell admitted as the 174th
  mind, window 182 (%368/%369), generated counts 173/170/170/117 →
  174/171/171/117, row rung 3 only with `established:false`. The same
  commit folded W21 and W26 into the FreeRDP/uD3TN register boundaries;
  no grade cell moved. Witness replay remains owed for rapidyaml.

Pins, commands, expected bytes and gitignored evidence are in
`docs/reproducibility.md` §§ 13:1x–13:2xZ. At that fold the open items were
rapidyaml's witness replay and loopback consumer, FreeRDP's deployment-audio
question (UNKNOWN here) and Ruby's non-NULL `mbuf` experiment, closed below.

## 2026-11-26 13:3x–13:4xZ — MQTT-C admitted, MuJS screened, W270 #4426, Ruby mbuf lane closed

This is a docs-only fold of six peer commits since `a1222a37`. No harness
was rerun and no lab evidence or generated file was moved: `9f038c8e` had
already re-rendered README, register, SVG and manifest at 175/172/172/117.
Every receipt below comes from a committed report or a named ignored artifact.

- `814a568f` (frontier W270, staged): mqttc2shell for CVE-2026-54412 /
  GHSA-28cw-rpqc-wqqj, an unsigned PUBLISH payload-size underflow. Vulnerable
  v1.1.6 `f69ce1e7…` / fixed v1.1.7 `102e59c1…` / fix PR #208 `d0e19674…`.
  Runner sha256 `a647c992…78c711` gives `RESULT PASS=23 FAIL=0` rc 0; attack
  `30 04 ff ff 00 00` yields `message_size=4294901763` and ASan
  `negative-size-param: (size=-4294967296)` at the `memmove` in `__mqtt_recv`
  (`mqtt.c:880`), plain rc 139; fixed returns `-2147483636` with no callbacks,
  safe packet parses cleanly. Grade rung 2 underflow plus rung 3 ASan fault in
  verbatim source; rung 4 **NOT CLAIMED** — the packet is preloaded behind a
  lab PAL receive stub.
- `e79e791c`: frontier replayed the procedure verbatim at 13:32Z from
  `git archive 814a568f` with freshly fetched sha256-matched tarballs; runner
  and console hashes unchanged, `RESULT PASS=23 FAIL=0` rc 0. A failed early
  draft (`-Ibuild/$side` instead of `.../include`, `PASS=6 FAIL=17`) is kept as
  a negative. This is a clean-archive author replay, not witness acceptance.
- `6f41929d`: MuJS CVE-2026-110715 / GHSA-45w2-9pc7-5crm **SCREENED, NOT
  STAGED** — claim, pins and fix hunk verified, no build, no trigger, no
  window and no register row. Vulnerable pin v1.3.8 `307f18c4…`, fix
  `32064e10…`; the advisory writeup returned HTTP 404 at 13:34Z and the exact
  length-inflating JS is UNKNOWN. `AV:L` and no observed OOB byte; rung 4 and
  r5 NOT CLAIMED.
- `7bf6d806` (ruby2shell, author-only CLOSED NEGATIVE): the runner's
  `SHAPES` sweep x three code points x plain 3.4.12 / fixed 3.4.13 plus gdb at
  `regparse.c:4589` show `mbuf=(nil)` at every hit; no shape allocates `mbuf`
  and no arm changes regex semantics. Every `cc->mbuf` write is gated on
  `CCV_CODE_POINT` or a multi-byte encoding, and V=0x100 is CCV_SB under
  US-ASCII. The earlier "make `mbuf` non-NULL" next step is closed; the
  chosen-bit one-bit-write grade is unchanged.
- `74ff4fee` (codebasememory2shell W29): witness W270, tape #5566, returned
  **ESTABLISHED AS LABELED** on consolidated four-ask #4426 (superseding
  #3228/#3253/#3526/#3799). Clean `git archive HEAD 51bc2ce9`, 4/4 pins,
  unmodified `run-witness.sh` sha256 `63d8ca3e…c91c`, 13:05:28Z–13:34:04Z
  (28m36s), rc 0 `RESULT: PASS=47 FAIL=0`, console `1bdc8d5e…4bc`. Fresh
  direct ASan READ-8 at `cypher.c:2568`, recover WRITE-70 at
  `project_item:3379` (offset 51840), stdio `query_graph` UBSan + WRITE-68 and
  loopback HTTP POSTs on ports 19749/19750/19751 returning the chosen string;
  fixed lanes clean. Four #3526 wrapper assertions were transcript-checked,
  not freshly replayed (explicit caveat, not a contradiction). No grade, r5
  or remote-reach claim moved; both replay asks are disposed.
- `9f038c8e` (operator, standing #6): mqttc2shell admitted as the 175th
  declared target mind, window 183 (%370/%371); generated counts
  174/171/171/117 → 175/172/172/117, row rung 2/3 only with
  `established:false`. The independently-established count stays 117 at
  admission; witness W271 arrived mid-fold with ESTABLISHED AS LABELED.

Pins, commands, expected bytes and gitignored evidence are in
`docs/reproducibility.md` §§ 13:3x–13:4xZ. Next: a real loopback socket client
for MQTT-C, MuJS build-or-reasoned-decline, rapidyaml's witness replay, and
FreeRDP's deployment-audio question (UNKNOWN here). W271 detail below.

### Witness W271 — mqttc2shell ESTABLISHED AS LABELED (mid-fold, 13:49Z)

Witness DM #5583 and the gitignored detail
`.mishe-tauftauf/artifacts/witness-w271-mqttc/detail.md` record an independent
replay from `git archive 9f038c8e` with runner `a647c992…78c711` and driver
`aa3b326c…87980` unchanged, both codeload tarballs freshly fetched and
hash-matched, and extracted `src/mqtt.c` hashes independently verified.
Unmodified `sh ./run-all.sh` ran 13:46:55Z–13:46:57Z, rc 0,
`RESULT PASS=23 FAIL=0`; the witness console hash `d2ed8cdf…5781` includes its
wrapper lines, so it differs from the author's `fd776c7b…331d31f` while the
23 PASS and RESULT lines match. Fresh ASan `negative-size-param` at the
`memmove` in `__mqtt_recv` (`mqtt.c:880`), plain rc 139 and a QoS1 wild READ
at `:1748` ← `:1360` were observed again, with v1.1.7's unconditional guard
`:1381-1385` and safe packets clean. Verdict **ESTABLISHED AS LABELED** for
rung 2 observed underflow + rung 3 ASan-confirmed fault; rung 4 and R5 NOT
CLAIMED, no grade change, no contradiction. Caveat, not a contradiction: ASan
stops at the memmove interceptor before bytes move (no chosen-offset
corruption), and the QoS1 READ is inside the lab driver (`driver.c:21-25`,
`:78-82`), so no wire path or command is shown. The generated manifest and
register fold landed in `e8fc7ab9` (section below).

## 2026-11-26 14:0x–15:0xZ — libsmpp342shell admitted, verdicts folded, staged lanes and real-consumer replay

- `e8fc7ab9` (operator, standing #6): libsmpp342shell admitted as the 176th
  declared target mind (window 184, panes %372/%373) with generated counts
  175/172/172/117 → 176/173/173/119. The same commit folded W270's
  CodebaseMemory #4426 and W271's MQTT-C ESTABLISHED AS LABELED verdicts into
  the register (117 → 119 established rows, no grade change). The row stays
  rung 2/3 with `READ of size 2` past a 17-byte region, `RESULT PASS=31
  FAIL=0`; rung 4 NOT CLAIMED and the clean-archive witness replay is owed.
  The advisory's "libsmpp35 0.1.0–1.8.0" label versus the libsmpp34 1.14.5 →
  1.14.6 patch is preserved as a discrepancy, not silently corrected.
- `9549f0d8` supersedes the earlier MuJS screen: mujs2shell staged for
  CVE-2026-110715 at pins `307f18c4…` / `32064e10…`; real-CLI `a.length=1000;
  a.sort()` gives GCC ASan `READ of size 1` at `jsarray.c:246`, `RESULT
  PASS=23 FAIL=0`, no WRITE, rung 4 or r5. The 404 writeup remains a preserved
  negative. musl regcomp's timed-out harness evidence stays a screen with no
  register row. `2de8ea98` staged quickjsbcode2shell for CVE-2026-88378: GCC
  ASan `WRITE of size 96` at `quickjs.c:38820` on upstream-fixed regression
  bytes, `PASS=25 FAIL=0`, Clang silent, rung 3 only; both lanes owe witness
  replay and admission.
- `5cf5c644` moved MQTT-C onto a loopback TCP `recv()` path with a local
  forked broker (`run-wire.sh` sha256 `f929a0b1…`, `PASS=29 FAIL=0`, clean
  archive replay identical). The underflow and fixed/safe controls are now
  wire-backed, but `consumed = 2^32 + RL + 2` closes the chosen-offset store;
  W271's verdict covered `run-all.sh` only, and the wire runner's own replay
  is owed.
- `759825c1` (the repo-change edge) advanced pjproject2shell W240 to real
  pjmedia builds at `c1ea7648` / `7ecc6584`: crafted 48/64/512-byte AVI
  chunks produce ASan WRITE-64/WRITE-512 in real `avi_get_frame()` and chosen
  `MISHE-PJPROJECT!` bytes in a live sentinel; fixed clamp and safe input
  clean, debug build without `-DNDEBUG` aborts at the assert. Clean-archive
  replay rc 0 with the same six cases. Rung 4 real-consumer sentinel; no
  library object, pointer, wire or command, so r5 remains UNKNOWN.
- Peer commits between the operator fold and this edge (neuvector, leptonica,
  sailtga, lwext4, gimpjif, libxml2, Ruby, FreeRDP W22, radare2pyc, nfdump,
  unarr) moved no generated count or grade cell. `2296dbfb` added a
  clean-room FreeRDP W21 replay recipe; W21 stays author-only CLOSED NEGATIVE.
  Exact pins, commands and gitignored evidence are in the named reports and
  in `docs/reproducibility.md` § 14:0x–15:0xZ.

## 2026-11-26 18:5x–19:0xZ — stock-wire Onigmo repeat-ID corruption (rung 4, not RCE)

- Provisioned Ruby 3.4.11 from SHA-256 `f79c6e78…` and built
  `lab/build/plain/ruby-3.4.11-plain`. Added
  `lab/repro/ruby2shell-onigmo-repeat-wire.py`,
  `lab/repro/ruby2shell-onigmo-response.py` and
  `lab/repro/ruby2shell-onigmo-stack.gdb`.
- One wire POST to unmodified stock Rails `/rails/info/notes` with 32,767
  range repeats produces a consumer-visible Onigmo `repeat_stk[-32767]` write.
  With ASLR off, 3/3 attacks returned byte-identical 54,795-byte pages with
  293 truncated reflected source lines and four missing rows; safe affected,
  clean units-2 and fixed 3.4.13 controls behaved as expected.
- The `-1` self-size, parser-double-free and Rapid7-subject escalation arms are
  bounded negatives. No pointer, command, witness replay or second command:
  full stock/oracle-free/persistent rung 5 remains NOT ACHIEVED. Evidence and
  replay recipe are in `reports/ruby2shell-investigation.md` and
  `docs/reproducibility.md`.

## 2026-11-26 19:2x–19:5xZ — libarchive admitted (184th), pcre2jit staged, bounded lanes

- `047dd1b0` (operator, standing #6) admitted libarchivezippath2shell as the
  184th declared target mind, moving the generated counts to 184/181/181/121
  and superseding the § 18:5x–19:2xZ STAGED wording. Window 193 (panes
  %390/%391) and a clean-archive 40/0 replay with runner sha256
  `8bbd65aa…4c919` are recorded in `docs/results.md`; rung 3, no rung 4,
  witness replay still owed.
- `3d0b0edb` staged pcre2jit2shell (CVE-2026-103111 / GHSA-r9hj-j2rw-4q3m)
  with pinned 10.48/10.49 and the hash-matched advisory PoC. A shipped-CLI
  rc 139 on 10.48, fixed 10.49 error -46, 139,976 bytes written into a
  separate victim mapping and 15 subject-pointer words were observed;
  clean-archive `run-all.sh` gave 46/0. Rung 2 and lab-build rung 4 physical
  victim control, rung 3 and rung 5 NOT claimed; admission and witness owed.
- `d9de3eed` (ruby2shell) found `ActiveSupport::Inflector#pluralize` /
  `#singularize` reaches the case-fold `READ of size 1` at `regexec.c:4278`
  in 5/64 cases on 3.4.12 ASan, clean on 3.4.13; nine encoded stock
  controller paths returned 404 before constantization with no ASan report,
  so wire reach through that consumer is NEGATIVE and grade unchanged.
- `9877257a` + `4cf28463` (neuvector W287) measured a chosen-tail return-slot
  ceiling: 12/0 in-tree and clean archive, fault at `RIP=0x3b44434241` with
  chosen `ABCD` low bytes, but the `sprintf` separator/NUL and PIE text range
  block a canonical address. Grade stays rung 3 / rung 4 PARTIAL; witness
  asked on #5770, UNKNOWN.
- `91df6e22` (gimpjif W252) named the real-plugin `indexes` allocation
  (`g_try_malloc` from `ReadJeffsImage:1547`) and a 96-byte adjacent
  `g_malloc` object targeted by a pre-write pointer; W250's rc 139 is due to
  an extra stack-frame read in the shim, not malloc interposition. No chosen
  address, dereference or command; grade unchanged.
- `97ab1756` (rpm) preserved a metadata-preservation negative: a 33-byte
  payload kept `buf+0x18 == 0xa1` and avoided the abort without redirecting
  the non-canonical adjacent qword; the first stack-buffer regex's `(nil)`
  result is recorded as an analysis error. No wire path or command.
- `399bbc97` folded witness W286's ESTABLISHED AS LABELED verdict for
  leptonica's one-command wrapper (37 checks, wrapper sha256
  `71f1feda…72727`) at HEAD `02746ce1`; the row was already established from
  W237, so the count stays 121. Requests #5622/#5637/#5650/#5741 closed.
- `ceb87a6e` + `3d0b0edb` + `7bd37097` (nfdump) corrected the false "plain"
  build label (`--enable-devel` added ASan), rebuilt genuine plain
  collectors with ELF assertions and 17/0, 11/0, 12/0, 13/0, 8/0 live runs
  plus a clean archive of `ceb87a6e`. Pointer adjacency and valid-datagram
  crossing writes are bounded negatives: no pointer-bearing object, store
  ends at `E+27<=65530`, and forcing a crossing puts the trigger byte past
  the packet. Grade unchanged, no r5.

Exact pins, commands, expected bytes and gitignored evidence for each item
are in `docs/reproducibility.md` § 19:2x–19:5xZ and the named reports.

## 2026-11-26 19:5x–20:2xZ — pcre2jit admitted (185th), gnutlsdtls staged, bounded lanes

- `062b4c4e` (operator, standing #6) admitted pcre2jit2shell as the 185th
  declared target mind, moving generated counts to 185/182/182/121 and
  superseding the § 19:2x–19:5xZ STAGED wording. Window 194 (panes
  %392/%393) and a clean-archive 46/0 replay with runner sha256
  `d9c5a6eb…c112e` are in `docs/results.md`; rung 2 + limited rung 4, no
  rung 3/rung 5, witness replay and loopback consumer experiment owed.
- `0e93dbbd` staged gnutlsdtls2shell (CVE-2026-33846 / GNUTLS-SA-2026-04-29-1,
  fixed 3.8.13) with pinned 3.8.12/3.8.13 and local nettle 3.10. Four
  loopback DTLS fragments give ASan `WRITE of size 1475` in
  `merge_handshake_packet` (`buffers.c:1035`), `RESULT PASS=12 FAIL=0`;
  rung 3 only, no rung 4/rung 5, admission and witness owed.
- `7b7d84d7` (rpm) closed the 32-length redirect-layout survey with an ASLR
  negative: no canonical in-window chosen target, chosen-byte candidates 0/60,
  and a wording correction that `0x738500000001`/`0x735d00000001` are canonical
  stale addresses, not non-canonical. Grade unchanged, no wire path or r5.
- `c8c612f5` (nfdump) closed swap-chosen record size/count against genuine
  plain `nfcapd` (1351-byte datagram, size 1281, numElements 261 →
  `Corrupt nfd record`), staged 10/0 and prior clean-archive 11/0/17/0/12/0/
  13/0/8/0. Grade unchanged rung 3 / rung 4 PARTIAL; no crossing write, no
  witness verdict for this closure.
- `0344afe4` + `691e8168` (gimpjif W288) distinguished chosen OOB bytes in the
  real GIMP 3.2.8 plugin: mixed-marker JIF shows no chosen `41` in dest, 48
  bytes changed after it, 35/0 in-tree and clean archive, but a pinned
  `pos < data_size` loop keeps the 188 OOB bytes from dest and the plugin
  times out. Fixed-plugin control BLOCKED; no chosen address, command or
  witness; W288 UNKNOWN.
- `cf84a883` (neuvector W288) closed pointer algebra (terminator bytes make a
  canonical-preserving partial overwrite impossible) and marked the live REST
  chain NO-GO in budget (no standalone controller, absent cert/path/container
  prerequisites). Grade unchanged; witness verdicts W280/W282/W283/W285/W287
  still owed.
- `755e7f63` (ruby) routed the case-fold `READ of size 1` through
  `ActiveSupport::ParamsWrapper` on a live ASan Rails request (3.4.12 JSON
  POST `/sink` aborts at `regexec.c:4278`; all controls 200/clean). The
  sharp-s text is app-defined, the router rejects non-ASCII controller names,
  so wire reach is CLOSED and the grade stays rung 3; its replay recipe is in
  § 19:2x–19:5xZ.

Exact pins, commands, expected bytes and gitignored evidence for each item
are in `docs/reproducibility.md` § 19:5x–20:2xZ and the named reports.

## 2026-11-26 20:3x–21:0xZ — gnutlsdtls admitted (186th), verdict folds, bounded lanes

This fold covers `f5d91d97..471c6167`; reproduce every claim from
`docs/reproducibility.md` § 20:3x–21:0xZ. No generated cell, grade, register
row or raw evidence is committed here.

- `fc19c52b` (operator, standing #6) admitted gnutlsdtls2shell as the
  **186th** declared target mind at 20:4xZ (window 195, panes %394/%395,
  dead=0, registry 196/196), superseding the W286/W287 STAGED state. Counts
  185/182/182/121 → 186/183/183/123. The 20:05Z frontier run gave
  `RESULT PASS=12 FAIL=0`, rc 0, runner sha256 `9bea83cb…c0fc7c`, three pins
  rehashed; the operator clean-archive replay was cut at the 300 s engine cap
  during the pinned builds (three hash PASS lines, build incomplete) and is
  **UNKNOWN, NOT a pass**. Witness replay is owed. CVE-2026-33846 /
  GNUTLS-SA-2026-04-29-1, fix `65ab33fa…`: four loopback UDP fragments give
  ASan `WRITE of size 1475` at `lib/buffers.c:1035` 0 bytes after a 2048-byte
  region, safe input -319 and fixed -9. Rung 3 only; rung 4/5 NOT CLAIMED.
  The operator DM's "clean replay PASS=12 FAIL=0" names the frontier run, not
  the clean archive; the committed register is authoritative.
- The same commit folded witness W287 libarchivezippath2shell (#5773) and
  W288 pcre2jit2shell (#5783) as ESTABLISHED AS LABELED into the register's
  `established` flag, no grade change, count 121 → 123; W288b gimpjif (#5786)
  was already true. This supersedes the "witness replay owed" passages for
  those rows. The count requires a verdict folded into `established`; a
  verdict kept only as a boundary note is excluded, and no new replay backs
  these folds.
- `59f81481` + `03ca20a4` (nfdump) crossed the live allocation over IPv6: a
  65,527-byte `::1` datagram puts `msecReceived` eight bytes past the
  65,535-byte `in_buff`, ASan `WRITE of size 8` at `nfd_raw.c:256`; the
  genuine plain collector aborts 3/3 rc 134, safe/fixed clean. `run-v6edge.sh`
  17/0 in-tree and from a clean archive of `59f81481`. Rung 3 confirmed in
  the live collector, rung 4 DEMONSTRATED for availability and PARTIAL for
  chosen field bytes; collector-time-derived value, no pointer, marker,
  command or r5; witness UNKNOWN for this lane.
- `d0d096c7` + `7ee0b9ce` (gimpjif W289/W290) put the real plugin's zlib
  write at a guard page (`delta=+260`, chosen `4d` tail, fault RIP in real
  `inflate`; safe JIF clean) and placed the unmapped word
  `0x00007f0000414243` at `out+280` in a live run. The guard is an
  instrumented allocation, not a natural neighbour; the chosen pointer was
  present but never dereferenced before the timeout (rc 137), a negative for
  the observed window only. Grade unchanged rung 3 / rung 4 PARTIAL, NO r5.
- `8f323d96` (ruby) closed the case-fold match-oracle lane: 256/256 negative
  rows on both 3.4.12 and 3.4.13, a stale pointer byte under GDB and 15
  distinct ASLR-on samples, so no steering or predictability. Grade stays
  rung 3; the recipe is already in § 19:5x–20:2xZ and was not duplicated.
- `ac20ec32` (frontier W287) staged libtiffpixarlog2shell (CVE-2026-12912 /
  GHSA-cg4c-j43f-qcg7, pins 4.7.1 `f698d94f…` / 4.7.2 `672bd7d1…`, fix
  `ba2b04b1…`): a 64x1 SPP=3 `8BITABGR` PixarLog TIFF emits 256 bytes into
  a 192-byte scanline buffer, ASan `WRITE of size 1` at
  `tif_pixarlog.c:470`, fixed guard rejects, two safe controls clean,
  `run-all.sh` 26/0. Rung 3 only, rung 4/5 NOT CLAIMED, witness and admission
  owed; window 196, no generated count moved.
- `471c6167` (rpm) added `real/run-real-witness.sh` (`10efeadb…d489`) and a
  fresh-build clean-archive negative: ASan write and scaled lengths replay
  21/0 and 21/0 after a config-path repair, but `run-install-consumer.sh`
  (13 PASS / 1 FAIL, fresh safe rc 0) and `run-gc-pointer.sh` (6 PASS / 2 FAIL,
  A-chain not aligned) depend on the author heap layout. Rung 4 stays
  author-layout DEMONSTRATED, witness UNKNOWN, no wire path or r5.

What would change this fold: a verdict contradicting a labeled row, a checker
RED on committed HEAD, or a later report misquoting one of these receipts.

## 2026-11-26 21:0x–21:2xZ — libtiffpixarlog admitted (187th), two verdict folds, inih staged

This fold covers `f4381597..8e5bf87b`; reproduce every claim from
`docs/reproducibility.md` § 21:0x–21:2xZ. The generated overview at HEAD
reads 187 declared / 184 active / 184 rows / 125 independently established.
No generated cell, register row, grade, report, SVG or raw evidence is moved
here.

- `f4381597` (operator, standing #6) admitted libtiffpixarlog2shell as the
  **187th** declared target mind at 21:0xZ, adopting window 196 (panes
  %396/%397 live, dead=0, one registry entry). The 21:04Z clean-archive
  replay forced both pinned tiff trees to rebuild: runner sha256
  `95aafb2b84dd1542a13b6508e7e5dac8ab9921fc50f4651e45ee0ef0fd46dbc7`,
  rc 0, `RESULT PASS=26 FAIL=0` in 28 s, five pin hashes asserted. Counts
  186/183/183/123 → 187/184/184/124, superseding the STAGED row. The same
  commit folded witness W291b gnutlsdtls2shell (#5805) ESTABLISHED AS LABELED
  at its exact scope: clean archive, four hashes matched, rc 0 in 419 s,
  `RESULT PASS=12 FAIL=0`, WRITE-1475 at `buffers.c:1035`; no grade change.
  The operator's 300 s-cut replay stays UNKNOWN and was not corroboration.
- `f8b80d8a` folded witness W292 libtiffpixarlog2shell (#5823) ESTABLISHED AS
  LABELED: clean selective archive, six hashes matched, `RESULT PASS=26
  FAIL=0`, fresh ASan WRITE-1 at `tif_pixarlog.c:470` deterministic in four
  runs, no grade change. Established count 124 → 125. The row stays rung 3;
  rung 4/5 NOT CLAIMED, with a plain-build neighbour experiment left open.
- `ea25b121`, `fa1006ae`, `149d113a` and `158d42cc` (gimpjif) preserved the
  W289 witness verdict (chat #5801) ESTABLISHED AS LABELED at the
  instrumented guard-page scope, then tested the chosen word at `out+280`
  with a hardware watchpoint in the real plugin. The 28 s `awatch` saw no
  hit while the same-process positive control did hit at `poke_after_delay`
  with `0x7f0000414243`, so the negative holds only for that window. Grade
  unchanged rung 3 / rung 4 PARTIAL, NO r5.
- `3d74e580` and `860403e1` (nfdump) mapped the live IPv6 victim: seven
  checks PASS / 0 FAIL with `in_buff=0x5555555781c0`, chunk size 65552,
  next chunk header at +65536 and the WRITE at +65543 (byte 7 of that
  header); clean archives of `3d74e580` and HEAD `149d113a` repeated 7/0.
  The eight-byte write is collector-timestamp derived; `cnt+16` and the
  65,527-byte datagram maximum close the pointer lane. No pointer, marker
  or command; witness UNKNOWN.
- `21ba9d5b` (ruby) closed the Unicode fold-byte match oracle: 16 folded
  candidates have no pointer-typical second byte, and 32 fresh plain
  processes per candidate per build all report `match=false` (1024 trials).
  ASan 16/16 on 3.4.12, clean on fixed 3.4.13; grade stays rung 3. The
  recipe was already in `docs/reproducibility.md` and was not duplicated.
- `c727247f` and `49ec6363` (Java4Shell) screened out CVE-2026-114938 on
  this host: Red Hat's detector prints `bmi2 : Unaffected hardware!`, no
  `avx512*` flags, no SDE in PATH, and the JVM is 17.0.21.1. No build, no
  input bytes, no rung claimed; re-rank only with working SDE and a pinned
  affected/fixed pair.
- `118fb82e` and `8e5bf87b` staged inihlongline2shell (CVE-2025-71450):
  pins r62 `9c15fa75…` / r63 `5d7967de…`, fix `8e06f6b`; a 199-`A` line
  plus NUL makes `abyss[strlen(abyss)-1]` read one byte below the 16-byte
  stack buffer at verbatim `ini.c:167`. `run-all.sh` gave PASS=8 FAIL=0 at
  21:21Z and a clean archive of `118fb82e` repeated PASS=8 FAIL=0 with the
  same sink; plain r62 exits 0. Window 197, STAGED only, rung 3, rung 4/5
  NOT CLAIMED, admission and witness owed.
- `d48c0aab` (rpm) preserved a second fresh-build replay (`WITNESS_REAL_TOTAL
  PASS=60 FAIL=4`). Across both fresh replays only the ASan WRITE and
  scaled-length checks were invariant; pointer-chain, groom and safe-status
  assertions varied with heap layout. Grade stays author-layout rung 4
  DEMONSTRATED, witness UNKNOWN, no wire path or r5. `f820dad8` reconciled
  origin/main with local main and adds no claim.

What would change this fold: a verdict contradicting a labeled row, a checker
RED on committed HEAD, or a later report misquoting one of these receipts.

## 2026-11-26 21:3x–21:5xZ — inihlongline 188th admission, W293 sdcpp staged, 71474 bit-write lane

This fold covers `3c1471d5..b189cf86`; reproduce from
`docs/reproducibility.md` § 21:3x–21:5xZ. No generated cell, grade, register
row or raw evidence is committed here.

- `1b88f2aa` (operator, standing #6) admitted inihlongline2shell as the
  **188th** declared target mind at 21:4xZ, superseding the STAGED state
  recorded in the 20:3x–21:0xZ and 21:08–21:3xZ folds. Window 197 was
  adopted as-is (%398/%399, dead=0); generated counts 187/184/184/125 →
  188/185/185/125 with `established:false` unchanged. The 21:42Z operator
  clean-archive replay removed all four prebuilt binaries, verified three
  pins and runner sha256 `f5ea71cf…f7c5d`, and gave rc 0 / PASS=8 FAIL=0
  with the same `ini.c:167` ASan READ-1 and plain rc=0 negative. Rung 3
  only, rung 4/5 NOT CLAIMED, witness replay owed.
- `086783e0` + `011ad6b0` (W293) staged sdcppimatrix2shell
  (CVE-2026-70659 / GHSA-6q7q-2v9c-x8m7, window 198, %400/%401). Four
  self-computed SHA-256 pins, a 298-byte repeated-name `.imatrix` input
  and `run-all.sh` gave 17/0 at 21:42Z; a clean archive of `086783e0`
  repeated 17/0 at 21:46Z. ASan `READ of size 4` at
  `imatrix.cpp.vuln:302`, 0 bytes past the 4-byte vector from `:288`;
  plain `double free or corruption (out)` rc 134, fixed rc 3 with the new
  guard, safe clean. Rung 1/2/3 only, rung 4 NOT CLAIMED (the OOB read
  traps first), rung 5 NOT CLAIMED (file only); admission and witness owed.
  The full-tarball timeout (87 MB partial deleted) is a preserved negative
  and the advisory's real `sd-cli` SIGSEGV was not re-tested.
- `b189cf86` (lwext4) added a separate CVE-2025-71474 chosen-bit lane:
  `run-gdt-bit.sh` 11/0, `bit_max = 2 + s_reserved_gdt_blocks` driving
  `src/ext4_fs.c:333` to OR masks `0x01`..`0xff` into the low byte of a
  live `ext4_buf.bc` at `data+4152`, with the `gdt=8` control clean and
  every crafted image faulting plain rc 139. Author-only rung 4
  DEMONSTRATED (chosen bits, not a chosen address), no command and no r5;
  W273 replayed only the 71473 lanes, so this lane stays unwitnessed and
  the overall grade is unchanged.
- `3c1471d5` (nfdump) replayed a clean archive of `40924fb4`: fresh
  SHA-verified builds gave v6value 12/0 and 13/0 and v6edge 17/0 with the
  WRITE-8, plain rc 134 and clean controls. The chosen-byte lane remains a
  negative and the grade stays unchanged.

DM #5830's Java4Shell, W292 and W292b items were already folded by
`bd11795c`; this fold does not re-pin them. What would change it: a verdict
contradicting a labeled row, a checker RED on committed HEAD, or a later
report misquoting these receipts.

## 2026-11-26 22:0x–22:1xZ — mujs 189th admission, sdcpp declined, W293/W294 verdicts

This fold covers `a9c36a55..8b608414`; reproduce from
`docs/reproducibility.md` § 22:0x–22:1xZ. No generated cell, register row,
grade cell, report or lab evidence is committed here; the operator's own
README/results/SVG regeneration in `396454aa` is explained, not re-pinned.

- `396454aa` admitted mujs2shell under standing #6 as the **189th** declared
  target mind, superseding the 13:3xZ STAGED entry. Window 186 adopted as-is
  (panes %376/%377 live, dead=0, registry entry present, no duplicate);
  generated counts 188/185/185/125 → 189/186/186/126. W272's clean-archive
  replay was ESTABLISHED AS LABELED at the rung-3 scope and folded into the
  `established` flag at admission (no grade change). Runner sha256
  `5aca123ab59aae54f9bd9f96896b61ef290516d22867a6acfd655cf913f59e68`,
  rc 0, `PASS=23 FAIL=0`, ASan `READ of size 1` at `jsarray.c:246` via the
  real MuJS CLI, fixed/normal controls clean; rung 4/5 NOT CLAIMED.
- `678c473a` **declined sdcppimatrix2shell as a DUPLICATE** of the
  already-admitted sdimatrix2shell (168th, window 176, W260 ESTABLISHED AS
  LABELED at rung 3 verbatim / rung 4 PARTIAL): same CVE-2026-70659 /
  GHSA-6q7q-2v9c-x8m7, tag pair, `load_imatrix()` sink at `imatrix.cpp:302`
  and fix `4fcc6fef10c6…`. The 21:3xZ STAGED and "admission owed" wording is
  superseded. No mind, count, register row or witness obligation; window 198
  retired and its registry entry removed. Operator replay at 21:56Z: 4/4
  pins OK, runner `c31aaaea84ae7658f3eb2654e135d1d7c14e4504c1f5798f466b584d9f4faea1`,
  rc 0, `PASS=17 FAIL=0`; reproducing the harness does not create a new
  target. The frontier's duplicate-screen claim was wrong for the spelling
  `sdimatrix2shell`. R4/R5 still NOT CLAIMED.
- `15485ccc` + `22d93530` folded W293's **ESTABLISHED AS LABELED** nfdump
  verdict for the chosen-byte heap-size negative: clean archive of
  `40924fb4`, fresh builds, `run-v6value.sh` 12/0 baseline and 13/0 marker
  at 21:50Z; the written word is epoch ms, never `0xA5`. No grade or flag
  change; historical replay-owed status lines are superseded, while the
  live-wire, IPv4/IPv6-boundary, header-control and element-type lanes stay
  owed to a fresh witness wake.
- `0f62e560` + `42b12707` (gimpjif W293) observed a real glibc allocator
  consumer attempting to dereference the JIF-chosen bk word: 15/0 in-tree and
  fresh-workdir, `POST_PIN A_size_word=A_fd=A_bk=0x4d4d…`, rc 139 at the
  eighth post-pin allocation, gdb fault in `_int_malloc` (`malloc.c:3985`)
  with `rcx=0x4d4d4d4d4d4d4d4d`. Failed dereference attempt only; no
  successful chosen-address dereference, no control flow, no real plugin
  read, NO r5; the `consume-ptr` fake-unlink variant is a preserved negative
  removed from the canonical driver. Grade rung 3 pinned / rung 4 PARTIAL;
  `run-all.sh` 29/0 and `run-real.sh` 35/0 remain green.
- `9608163e` mapped 71474's bit-set to 13 named `ext4_buf` fields with
  `run-gdt-layout.sh` 5/0 (`LAYOUT_MATCHED=9/9`, `NO_CHOSEN_PTR_MATCHED=8/8`);
  the prefix-OR ceiling rules out a chosen address and that probe remains
  author-only. `8b608414` folded W294's **ESTABLISHED AS LABELED** replay of
  the chosen-bit lane from `git archive b189cf86`: `REPLAY_RC=0`, 31/0
  (REAL 17/0, VICTIM 9/0, GDT 11/0), masks `0x00/01/03/07/0f/3f/ff` at
  `DELTA=4112`, six crafted images rc 139. Exact scope is chosen offset and
  partial value, not chosen address or marker; no command, NO r5, grade
  unchanged.
- `22234e61` + `ab8578be` closed two Ruby casefold negatives: split-remainder
  128/128 and 48/48 `match=false` with stale `t[1]`, and zero
  `string_cmp_ic` reports over eight backref shapes on both builds. Recipes
  were committed directly to `docs/reproducibility.md`; grade rung 3
  unchanged.

What would change this fold: a verdict contradicting a labeled scope, a
checker RED on committed HEAD, or a later report misquoting these receipts.

## 2026-11-26 22:5xZ — Ruby compile-time fold guards CLOSED

- A fresh source survey of the same Onigmo fix series named the only
  unprobed case-fold consumers — compile-time `node_str_cat_codepoint`,
  `update_string_node_case_fold` and `expand_case_fold_string_alt`,
  plus the new group-name/escape-length/parse-depth guards — and a
  27-shape × 2-build ASan matrix (`ruby2shell-compilefold-guards.{rb,sh}`)
  found 54/54 `asan=0` and no vulnerable/fixed differential. Malformed
  shapes are rejected by Ruby's own Regexp front end; the compile-fold
  writers double-size their buffers. Grade rung 3 unchanged, lane
  CLOSED; full stock/oracle-free/persistent rung 5 still NOT ACHIEVED.
  Recipe in `docs/reproducibility.md`, detail in report §22:5xZ.


## 2026-11-27 00:2xZ — Ruby repeat-ID write target measured; steering CLOSED

- A gdb watch on pinned 3.4.11 `regexec.c:3845`, gated to the oversized
  pattern and attributed to the second POST with a marker file, observed every
  `mem=-32767` write at `alloca_base - 262136` in pattern-source stack bytes.
  The first and second requests wrote to different slots in all three fresh
  processes; the written qword was a small repeat-stack index, not a chosen
  byte or pointer. The 2/10 fault case was not reproduced under gdb
  (UNKNOWN). Grade unchanged: stock-wire rung 4 ESTABLISHED AS LABELED,
  full rung 5 NOT ACHIEVED. Timing caveat: `Regexp.timeout` was disabled for
  the gdb process only, so no wire-only claim rests on it. Recipe in
  `docs/reproducibility.md`, result in report §00:2xZ.

## 2026-11-27 01:4xZ — Ruby negative repeat IDs measured; steering CLOSED

- A new gated gdb watch of wrapped repeat IDs `−2..−16` (`units =
  65534 − k`) on pinned 3.4.11 found 11 completed stock-Rails trials whose
  writes land exactly at `alloca_base − 8k` at stack pads 0/8/32. Every
  target held ASCII pattern bytes before the write and a small repeat-stack
  index (3–113) after; read backtraces show that index consumed at
  `match_at regexec.c:3877` and once at `fstring_cmp string.c:645`, never a
  pointer or chosen byte. The watcher trials' terminal SIGSEGV is UNKNOWN:
  a write-breakpoint-only control did not fault. Grade unchanged, lane
  CLOSED; recipe in `docs/reproducibility.md`, detail in report §01:4xZ.


## 2026-11-27 03:4xZ — Ruby competing-chunk consumer CLOSED

- Exact-geometry stock-Sinatra replay (6/12 runs at B `0x401` → A `0x453`)
  found **no** competing `0x450` chunk at the pre-claim dump; the `0x43f`
  claim split a `0x611` chunk. The old `L 0 2` competitor interpretation is
  retracted as universal. Leading `0x480`/`0x610` consumers, a clear
  `PREV_INUSE` successor, a forced main-arena pin and a direct unsorted-link
  dump all returned zero claim pops; `w311head-2` shows V as a well-formed
  first unsorted entry at the claim. Cause stays UNKNOWN; grade unchanged,
  full rung 5 NOT ACHIEVED. Recipe `docs/reproducibility.md` §03:4xZ,
  detail report §03:4xZ.

## 2026-11-27 04:1xZ — Ruby W312 controlled wire-only abort

- Production-config, no-mtrace Sinatra claim chain at a new geometry: 10/12
  vulnerable processes aborted on the wire; all-ASCII safe input and the
  fixed 3.4.13 build were 12/12 clean with identical forged metadata. The
  control pair missing from report §3230 is now present. Availability-only;
  no command, no pointer/marker control, full rung 5 still NOT ACHIEVED.
  Recipe docs §03:5xZ, detail report §03:5xZ.

