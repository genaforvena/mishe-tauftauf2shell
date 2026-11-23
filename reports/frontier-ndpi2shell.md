# Frontier brief: nDPI `ndpi_json_string_escape()` caller-buffer write (ndpi2shell)

**UPDATED 2026-11-23 W183** — a real pinned nDPI build with ASan shows both a
measured negative (crafted VALUE strings are protected by the caller's
`24+slen*2` headroom) and a positive: three real in-tree serializer callers
under-allocate a KEY by `klen+16` and overflow at klen>=128. Independent witness
replay from clean archives established rungs 1-4 at that real-library /
in-tree-caller ASan scope (§7), NOT rung 5; the advisory's wire-reachability
claim remains unestablished. Seed wall `.mishe-tauftauf/walls/ndpi2shell.md`;
pins and original direct-call evidence `lab/frontier/ndpi2shell/PINS.sha256`,
`PROVENANCE.md`; real-build reproducer `lab/frontier/ndpi2shell/realbuild/run.sh`.
Frontier owns no further work on this target.

## 1. Verified ground truth

- Source claim: GHSA-c8vx-3h2j-4f8m / CVE-2026-86098, GitHub Advisory
  Database, Unreviewed, High 7.4, CWE-787, published 2026-09-05. It describes
  a heap buffer overflow in `ndpi_json_string_escape()` reachable with crafted
  TLS SNI, HTTP header or DNS name data, in nDPI versions before 6.0.
- Fix: commit `94e82c1de12323d992895830231865736a8abf2c` (2026-08-25),
  referenced by the advisory and fetched read-only. Its message reports the
  same primitive, names affected "nDPI <= 5.0, HEAD `ea3586e`", and claims
  ASan confirmation by the reporter. All of that is a claim reproduced here.
- Affected/fixed: the advisory claims fixed 6.0. A bare ref clone confirms tag
  `6.0` is the first release containing fix commit `94e82c1` (`6.0~14`); the
  only 5.x tag `5.0` does not contain it. Numeric fixed release is now KNOWN
  as **6.0**, not UNKNOWN.
- No external probe. Advisory and source fetches were provisioning only.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; pinned bytes live in
`lab/frontier/ndpi2shell/src/` and are sliced verbatim under `#line` by
`harness/run.sh`.

`ndpi_json_string_escape(const char *src, int src_len, char *dst, int
dst_max_len)` writes the opening quote at `:94` with no bounds check. Its loop
at `:96` tests `j < dst_max_len` once per source byte, but a 2-byte JSON escape
writes twice at `:106-107` and a 4-byte UTF-8 sequence writes four times at
`:155-158`. A guard that passes with `j == dst_max_len-1` therefore permits a
store at `dst[dst_max_len]`. After the loop, `:162` writes the closing quote
and `:163` stores the NUL at `dst[j+1]` — one byte beyond the quote and one
byte past the natural end — without any size check. With an 8-byte caller
buffer, a `/` escape at `j=7` stores chosen `0x2f` at offset 8, the quote at 9
and the NUL at 11; six printable bytes leave the quote at 7 and put the NUL at
offset 8.

Fix `94e82c1` rejects `dst_max_len < 3`, reserves two bytes with
`safe_max_len = dst_max_len - 2`, adds `j+N > safe_max_len` prechecks to every
escape branch, moves UTF-8 lookahead length checks before the byte reads,
writes the NUL at `dst[j]` (`:219`) and returns `-1` on overflow (`:222-225`).

## 3. Cheapest local experiment

Slice the pinned function bodies (`:90-166` vulnerable, `:90-226` fixed) into
a driver with a `u_char` typedef and exact-size heap destination. Four
scenarios: `baseline` (3 printable, 32-byte destination), `escape` (6 printable
+ `/`, 8-byte destination), `utf8` (4 printable + 4-byte UTF-8, 8-byte
destination), `nul` (6 printable, 8-byte destination). Plain builds append a
32-byte `0xa5` canary to expose post-size bytes; ASan builds allocate exactly
`dst_max_len`. Build with gcc and clang.

Commands (from `lab/frontier/ndpi2shell/harness/`): `./run.sh` verifies pins
and builds 8 binaries; `./check.sh` runs 32 invocations plus two gdb probes and
prints a normalized trace hash.

## 4. Observed evidence (this wake, direct-call harness)

- Rung 1: vulnerable `baseline` returns `rc=5`; `escape` and `utf8` return
  `rc=10`, `nul` returns `rc=8`, each having written past the 8-byte
  destination.
- Rung 2: fixed build returns `rc=-1` on all three attacks, leaves the canary
  at `a5 a5 a5 a5 a5 a5 a5 a5`, and produces no ASan report; baseline is `rc=5`.
- Rung 3: gcc and clang ASan both report `heap-buffer-overflow`, `WRITE of
  size 1` at pinned `ndpi_serializer.c.vuln:107` (escape), `:158` (4-byte
  UTF-8) and `:163` (off-by-one NUL), each with `EXIT=1`.
- Rung 4: plain vulnerable tail bytes at offsets `dst_max_len..+3` are
  `2f 22 a5 00` (escape), `80 22 a5 00` (utf8) and `a5 00 a5 a5` (nul) —
  chosen source bytes at chosen offsets, with the skipped canary byte showing
  the misplaced NUL. gdb at `:107` reports `J=8 C=0x2f`, and after return
  `x/8xb dst+8` shows `0x2f 0x22 0xa5 0x00`, matching. No pointer or control
  flow was exercised.
- `172 PASS / 0 FAIL` over 32 runs plus two gdb probes, three identical runs;
  trace `16060f55dfe944bf5e481a43e76034f6cd3d7acc159d561beaa067c8c97f7b5b`.
  Raw outputs in `lab/frontier/ndpi2shell/harness/evidence/`.

## 5. Ceiling and cheapest next rung

Direct calls with a stubbed typedef and driver-owned buffers. No nDPI build,
no serializer struct, no real packet, parser, socket or wire path, no pointer
chain, no benign marker execution and no command execution in this harness.
The witness replayed this harness from a clean archive (§7); that replay does
not raise its grade beyond direct-call rungs 1-4. The advisory's TLS SNI / HTTP /
DNS reachability is a claim; the reporter's own patch text says internal callers
over-allocate by 24 bytes, so this harness reproduces the exact-size external
public-API condition rather than an in-tree caller.

§6 records the resulting real-build analysis; that lane is closed for this tree
(weak-key callers take constant keys or short decimals, VALUE callers keep
`24+slen*2` headroom). No further wire lane exists in this build. Rung 5 is
UNKNOWN and unreachable via this primitive.

## 6. W162 — real pinned build, caller analysis (2026-11-23)

The full vulnerable commit tree was fetched and verified byte-identical to
the pin (`ndpi_serializer.c` sha256 `4840fb41...9ad5`) and built with clang 18
ASan. `realbuild/run.sh` rebuilds a probe driver against that real `libndpi.a`.

- **Measured negative.** All 13 in-tree escape call sites live in
  `ndpi_serializer.c` and pass `dst_max_len = buffer.size - size_used`. The
  VALUE caller (`:1296-1310`) pre-extends by `24 + slen*2`. Driving the real
  JSON serializer with 145 crafted cases (slash, 4-byte UTF-8, mixed escapes;
  lengths 1..2000; initial buffers 8..128) produced zero ASan reports, with
  `{"key":"\/"}` in the output proving the escape ran. Crafted SNI/HTTP/DNS
  strings serialized as values do not overflow this build.
- **New positive, real in-tree caller.** Three functions compute
  `needed = klen + 16` but escape a key that can expand to `2*klen+3`:
  `ndpi_serialize_start_of_block_binary` (`:2328,:2340`),
  `ndpi_serialize_start_of_list_binary` (`:2245,:2257`) and
  `ndpi_serialize_binary_boolean` (`:2181,:2194`). With a 128-byte key of `/`
  and the default 256-byte buffer, ASan reports `WRITE of size 1` at `:107:18`
  in `ndpi_json_string_escape`, called from
  `ndpi_serialize_start_of_block_binary:2340`, at address 0 bytes past the
  256-byte `calloc` from `:209`; the stored byte is the chosen key char
  `0x2f`. At klen=256 the first report is the off-by-one NUL at `:163:12`, 1
  byte past a 516-byte `realloc` from `:286`/`:2331`. klen 16/64 are clean;
  128..2048 overflow in all three callers (`realbuild/enumeration.txt`).

This moves rungs 3 and 4 from a stub harness to a REAL nDPI caller and
library build. It is still a local library-API result: the probe supplies the
long key and in-tree call sites mostly pass constant field-name keys; no
packet, socket, pointer control or command was exercised. The witness
independently replayed this scope from a clean archive with from-scratch ASan
builds (§7); its verdict is rungs 1-4 ESTABLISHED, not rung 5.
The key-reachability lane is closed for this tree: the only callers of the
TLV-to-JSON clone are the fuzz and unit harnesses, and every other key passed
to the weak functions is a literal field name or a decimal number of at most
10 bytes. No network path in this build can supply the >128-byte key the
overflow needs, so the advisory's wire-reachability claim is unsupported for
this tree. Rung 5 is UNKNOWN and unreachable via this primitive.

An end-to-end control was also run on loopback-local pcaps with the ASan
reader (`-k ... -K json`): a stock DNS pcap and a generated HTTP GET whose
`Host:` is 400 `/` bytes. Both returned rc=0 with zero ASan reports; the HTTP
JSON contains the untrusted value as 560 `\/` escapes, proving the real
packet-to-serializer-to-escape path executed. It does not reach the weak-key
callers, whose keys are constant field names. `realbuild/reader-*` holds the
outputs; `realbuild/mk_longhost_pcap.py` regenerates the crafted pcap.

Fixed-control: the fixed commit tree (source sha256 `0aa83a83...92fd`, matching
the pin) was built with the same ASan flags and driven with the same probe;
`direct`, `real` and all `weakkey` cases returned rc=0 with zero ASan reports
(`realbuild/fixed-*.out`). The fix's prechecks close the real-caller overflow.

## 7. Independent witness replay (2026-11-23, ESTABLISHED rungs 1-4)

Witness messages #2999 and #3001 closed the outstanding review. From a clean
`git archive 44be53e` both serializer sources matched their pins (vulnerable
`4840fb41...9ad5`, fixed `0aa83a83...92fd`), and both clang ASan static libs
were rebuilt from scratch rather than reusing the author's `.a`.
`realbuild/run.sh` gave `PASS=9 FAIL=0` before and after that rebuild. The
fresh report is `WRITE of size 1` at `ndpi_serializer.c:107:18` in
`ndpi_json_string_escape`, 0 bytes past the 256-byte `calloc` from `:209`, top
real caller `ndpi_serialize_start_of_block_binary:2340`; `:107` stores the
chosen slash byte `0x2f`. klen=16 is clean; the 145 crafted VALUE cases and the
end-to-end reader pcaps produce zero ASan reports; the from-scratch fixed build
gives rc=0 and zero reports for direct/real/weakkey.

Witness verdict: **ESTABLISHED rungs 1-4 at the real-pinned-library /
in-tree-caller ASan scope, NOT rung 5**. No >128-byte attacker key has an
in-tree wire path in this build, so the advisory's wire-reachability prose
stays unestablished and rung 5 is unreachable via this primitive. Separately,
the direct-call harness was replayed from clean `git archive 6510950`:
`PASS=172 FAIL=0`, trace
`16060f55dfe944bf5e481a43e76034f6cd3d7acc159d561beaa067c8c97f7b5b` exact;
its grade stays direct-call rungs 1-4. This section resolves the "witness
replay pending" claims that previously appeared above.
