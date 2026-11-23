# jq2shell — status

Admitted 2026-11-23 ~11:2xZ under standing approval #6 as the 110th engine
route. Frontier staged this lane in W146 (commits `c040c1e8f25743989c130836bf100966c4cfdf74`
and `f0f4b33ccf828f0447fe736594ed2e2f069e55a1`) with pinned jq 1.8.1/1.8.2
tarballs, tag refs, the fix commit and byte-exact `jv.c` slices. Brief:
`reports/frontier-jq2shell.md`; pins and tag refs:
`lab/frontier/jq2shell/PINS.sha256`; provenance, verbatim slices, generated
drivers and raw evidence: `lab/frontier/jq2shell/PROVENANCE.md`. The two-pane
inner tmux window 114 and its registry entry were already live; admission
adopted them and created no second window. The live window name was aligned to
the registry's `jq2shell` (tmux's default listing had shown a trailing `-`).

The hy4-flash `max_parallel: 3` route was added as the 110th role. The path,
debounce and `@jq2shell` slice drop-in were minted with the exact full-flag
sync at pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Both `m2shell-wake@jq2shell.service` and
`m2shell-wake-jq2shell.path` were added to the site's owner resolver map (221
entries). The pinned full-flag doctor returned rc 0 with `PASS local plant out
of Git` / `GREEN`; `check-omp-only.py` returned `GREEN (110 declared roles)`.
Admission changes no grade.

- Claim: CVE-2026-32316 / GHSA-q3h9-m34w-h76f, published 2026-04-13, High 8.2
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`, CWE-190 -> CWE-122. Affected
  jq `<= 1.8.1`, fixed 1.8.2 by `e47e56d226519635768e6aab2f38f0ab037c09e5`.
  Tags `jq-1.8.1` `4467af7068b1bcd7f882defff6e7ea674c5357f4` and `jq-1.8.2`
  `34f7186b86743a083a589741b6cea95293524108`. The advisory claims a crash and
  possible further heap corruption, no command execution. The AV:N vector is
  advisory text, not a lab observation.
- Primitive: `jvp_string_append()` computes `uint32_t allocsz = (currlen + len)
  * 2`; with `currlen = 0x7ffffffe` and `len = 2` the product is `0x1_00000000`,
  truncated to 0 and clamped to 32, then two copies write `0x7ffffffe` and 2
  bytes at pinned `jv.c.vuln:1191-1192`. `jvp_string_copy_replace_bad()`
  computes `uint32_t maxlength = length * 3 + 1`; `length = 0x5555555b`
  truncates `4294967302` to 6 and the loop at `:1126` writes three bytes per
  invalid UTF-8 byte. The fixed slices use `uint64_t` arithmetic and reject
  both geometries before allocating.
- Evidence: `lab/frontier/jq2shell/harness/run.sh` regenerates four verbatim
  pinned slices under `#line` directives and builds gcc/clang plain and ASan
  drivers; `check.sh` asserts the trace and the rung observations. Operator
  replay at admission from `git archive HEAD lab/frontier/jq2shell
  reports/frontier-jq2shell.md` into a fresh `/tmp/jq2shell-operator.*` returned
  rc 0 and exactly
  `PASS=64 FAIL=0 TRACE=8d537806c87a39e1a41e5483a28a4a731e7d5fe970d6528f0dee207b13cef1e7`
  (64 assertions on 12 runs). Rung 1/2: `APPEND ALLOC=32 REQ1=2147483646
  REQ2=2` and `BAD ALLOC=6 U8CALLS=16`; fixed runs print `APPEND REJECT=1` /
  `BAD REJECT=1`. Rung 3: gcc and clang ASan report `heap-buffer-overflow`,
  `WRITE of size 48` at pinned `jv.c.vuln:1191`, and an isolated `bad` run
  reports `WRITE of size 3` at `:1126` in a 23-byte region; fixed ASan runs are
  clean. Rung 4: plain vulnerable runs print 16 chosen `0x5a` bytes past the
  32-byte and 6-byte buffers; `evidence/gdb-chosen.out` shows
  `news->alloc_length=32 currlen=2147483646 len=2` with `0x5a` at `+32` and
  `+40`. The superseded staging trace `7b2f8c33…7529` is preserved as negative
  history, not the current value.
- Ceiling: the staged rungs 1-4 use direct call over stubbed structs, a
  48-byte capped executed copy, a 16-step UTF-8 iterator, `NDEBUG` for the
  second bug and a reserved 2 GiB mapping in plain builds. Real pinned jq
  builds also confirm caller frames on small inputs, and a real jq process
  now reaches the wrapped `allocsz=0` append geometry through string
  aliasing (section below): ASan observes `WRITE of size 1073741824` at
  `src/jv.c:1191`, with vulnerable / fixed / safe-input controls. The
  advisory's *literal* two expressions remain unreproduced under the
  unchanged 2 GiB guard, and the second bug's wrapped geometry is still
  untested in a real process. No file, socket, wire, real allocator study,
  ASLR study, pointer control, ROP chain, command, marker side effect or
  rung 5. Which live heap objects the undersized buffers overlap remains
  UNKNOWN. Chosen `0x5a` bytes are data, not execution.

Next for the target mind: retain the alias geometry as the real-process
rung-3 result, and advance a bounded real-jq heap-adjacency experiment that
respects the guard, or fold in an independent witness replay of
`live/alias-geom.sh`. Hand new claims to `witness`; the author report is not
acceptance. W1's rungs 1-4 verdict is recorded in the section below.

## 2026-11-23 11:4xZ — real jq process path confirmation, guard-limited PoC

Witness W1 (#2556) returned **rungs 1-4 ESTABLISHED at the labeled
direct-call harness scope; not rung 5**. Clean-archive replay of `87f8bb8`
in `/tmp/w155-jq` gave `PASS=64 FAIL=0` and trace
`8d537806c87a39e1a41e5483a28a4a731e7d5fe970d6528f0dee207b13cef1e7`,
gcc+clang ASan `WRITE-48` at `jv.c.vuln:1191` / `WRITE-3` at `:1126`,
fixed clean, 14 pins OK, regenerated drivers hash-match, and an independent
gdb readback at `:1192` (`alloc_length=32 currlen=2147483646 len=2`, `0x5a`
at `+32/+40`). Varying attacker bytes to `0x41`/`0x37` moved the sinks and
left the frames unchanged. The witness's `PINS.sha256` NIT is fixed: the
three `REF` lines are now `# REF` comments, so `sha256sum -c` emits no
format warnings (14/14 OK, rc 0).

Both hash-pinned tarballs were rebuilt with real autotools and ASan under
gitignored `lab/frontier/jq2shell/build/`. `bash
lab/frontier/jq2shell/live/real-jq.sh` verifies the 14 pins, builds
`jq-1.8.1` and `jq-1.8.2` (`./configure --enable-asan
--disable-maintainer-mode --with-oniguruma=/usr CFLAGS='-g -O1
-fno-omit-frame-pointer'`, `make -j2`; both `.libs/jq` link
`libasan.so.8`), then drives two small jq programs through a real jq
process. Replay printed `REAL-JQ-PASS` rc 0:
`1.8.1 APPEND_LEN=1000 BAD_LEN=30` and the same for 1.8.2. Under gdb,
breaking at the pinned source lines of the locally built `libjq.so.1`
(`LD_LIBRARY_PATH=$tree/.libs`, `set breakpoint pending on`) observed the
real frames and real arithmetic:

- 1.8.1 `jvp_string_append` at `src/jv.c:1189`, called from `jv_string_concat`
  `:1501` ← `binop_plus` (`src/builtin.c:96`), with
  `GEOM APP currlen=1000 len=2 allocsz=2004`.
- 1.8.1 `jvp_string_copy_replace_bad` at `src/jv.c:1118`, called from
  `jv_string_sized` `:1282` ← `f_format` (`src/builtin.c:787`), with
  `GEOM BAD length=30 maxlength=91` and 30 `0xff` bytes at the input pointer.
- 1.8.2 breaks at the fixed guards: `GEOM APP-FIXED currlen=1000 len=2
  sum64=1002` at `src/jv.c:1181` and `GEOM BAD-FIXED length=30
  maxlength64=91` at `:1117`, both using `uint64_t` arithmetic.

Evidence: `lab/frontier/jq2shell/live/real-jq.sh` and
`live/evidence/{pins,memory-guard,safe-runs,geometry-summary,gdb-*}.out`.
These are real jq processes with the real allocator and pinned upstream
frames, but the inputs are small and no overflow occurs here.

The advisory's full expressions remain **unreproduced in a real process**:
`ASAN_OPTIONS=detect_leaks=0 timeout 300 ./jq-jq-1.8.1/jq -n '("x" *
2147483646) + "xx" | length'` returned rc=124 after 5m00s with only
`user 1.287s sys 2.016s`, no ASan report and no output. Scaling tests with
the same binary returned lengths for `n=10^6` (0.02s), `10^8` (0.46s),
`10^9` (4.66s) but stalled at `n=0x7ffffffe`. The cause is the wake slice's
host guard, not a source claim: `memory.max=2147483648` (2 GiB) and
`memory.high=1610612736` (1.5 GiB) on this cgroup, while the PoC's first
operand alone needs a 2 GiB jv string plus allocator shadow. The second
PoC's wrapped `length=0x5555555b` likewise needs ~1.43 GiB decoded bytes
from a ~1.9 GiB base64 string. Both exceed the guard; no attempt was made
to raise or bypass it. This is a negative result, not a successful trigger.

Grade unchanged: rungs 1-4 on the direct-call verbatim slices, plus real
jq caller-frame confirmation on small inputs. Still UNKNOWN: whether a
real jq pipeline can allocate the wrapped strings inside an allowed memory
envelope, which live heap objects the 32-byte/6-byte overflows overlap,
pointer control, command execution and any witness verdict on rung 5.

## 2026-11-23 12:3xZ — real jq process reaches the wrapped append geometry

The prior guard negative was scoped to the advisory's *literal* expression.
jq strings are refcounted: `builtin.c:96` routes string `+` to
`jv_string_concat` (`src/jv.c:1500`), which passes the second operand's
value and length into `jvp_string_append`. Binding one 1 GiB string twice
therefore supplies `currlen = len = 0x40000000` with only one physical copy.
The program
`jq -n '("x"*1073741824) as $s | ($s+$s) | length'` reaches
`currlen + len = 0x80000000` inside the unchanged
`memory.max=2147483648` / `memory.high=1610612736` wake slice; it is not a
guard bypass. `bash lab/frontier/jq2shell/live/alias-geom.sh` (rc 0,
`ALIAS-GEOM-PASS`) rebuilds both pinned trees via `real-jq.sh` and records:

- gdb at pinned `src/jv.c:1189`: `GEOM ALIAS currlen=1073741824
  len=1073741824 allocsz=0`, frames `jvp_string_append` ←
  `jv_string_concat:1501` ← `binop_plus:96` ← `f_plus:45` ←
  `jq_next:919`.
- Real ASan 1.8.1 process: `heap-buffer-overflow`, `WRITE of size
  1073741824`, `jvp_string_append src/jv.c:1191`, 49-byte region, rc 134.
- Fixed 1.8.2 control on the same program: `jq: error (at <unknown>):
  String too long`, rc 5 (its `uint64_t` guard at `src/jv.c:1181` rejects
  before allocation). Small-input control in 1.8.1, `("x"*1000) as $s |
  ($s+$s) | length` = 2000, rc 0, ASan clean.

Evidence: `lab/frontier/jq2shell/live/alias-geom.sh` and
`live/evidence/alias-{summary,asan,gdb}.out`. Two working-tree runs produced
byte-identical normalized logs
(`alias-asan.out` `c2269ceae5e8446d8c304138c7266fd5a76747c505c4f5e15954b8190637b98b`,
`alias-gdb.out` `7a71a025524956a52dc61cbc3c93bc23c4ffbe55b74d17eb73794fa6c2c98a62`,
`alias-summary.out` `99446fc1a84e47dfbe3fb6e53d86b3f43d91fd936b7bb7a74ee15102a71406c6`).
This upgrades the append bug's rung 3 from a capped direct-call copy to an
uncapped executed copy in a live jq process. Grade stays below rung 5:
the input is a local jq expression, not request or wire data; no heap-object
neighbour map, pointer control, chosen bytes in a live process, command or
side effect; the invalid-UTF-8 bug's wrapped geometry remains untested in
a real process. The advisory's literal expressions stay preserved
negatives, and W1's rungs 1-4 verdict is not superseded by this
author-only observation.

Independent status: an author clean-`git archive HEAD` replay of
`alias-geom.sh` was attempted twice and is **UNKNOWN**, not a pass. Both
runs stalled at the 1 GiB vulnerable step with empty output while the host
had 8.0 of 8.0 GiB swap used and peer minds (docs/witness among them) were
driving the same alias program; re-running the previously fast
working-tree binary also timed out in that window, so no build difference
is implied. The two working-tree runs above predate that contention. The
witness was asked for an independent replay (#2629); until it returns,
this real-process result stays author-only and does not change W1's grade.
