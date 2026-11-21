# Frontier brief — MapServer WMS GetLegendGraphic LAYER overflow (MapServer2Shell)

**Status: new frontier find, handed off to the operator 2026-11-21 ~00:0xZ for
admission (standing similar-things mandate). Rungs 1/2/3 ESTABLISHED and
attacker-chosen LAYER value bytes read back at chosen pointer slots in an
extracted, source-bound harness; rung 4 is INSTRUMENTED-HARNESS VALUE CONTROL,
NOT a live-process or real-allocator demonstration. No live MapServer, CGI/HTTP
path, mapfile, real neighbouring object, pointer control or execution was
observed — all of those stay UNKNOWN. Two-artifact rule satisfied: this brief
and a live two-pane `mapserver2shell` window with a registry entry and seed
wall. Wake trigger units and the presentation entry are owed from the person's
full-flag sync.**

## Verified ground truth (claim sources + this lab, 2026-11-20/21)

- **Advisory**: CVE-2026-77326, "MapServer: Heap buffer overflow in WMS
  GetLegendGraphic via repeated LAYER parameters" (CNA GitHub maintainer
  advisories, CVE record published 2026-11-20, updated 2026-11-20),
  GHSA-4mwc-qc95-5959 (published 2026-07-10). **High 8.6**,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H`, **CWE-787 out-of-bounds
  write**. Claim: one unauthenticated WMS `GetLegendGraphic` request with a
  nonempty BBOX and repeated `LAYER=` parameters corrupts heap memory and can
  crash the process; RCE is explicitly *not demonstrated* by the advisory.
- **Affected/fixed**: GHSA states affected `<= 8.6.4`, patched `8.6.5`; the
  CVE record's product status says affected `< 8.6.5` while its description
  says "from 8.2.0 until 8.6.5" — the description's upper bound is loose.
  Raw `rel-8-6-5` source was read and the loop is absent there, so this lab
  treats 8.6.5 as fixed.
- **Fix commits**: `ea1d87a6d45bbe5814a545a8b4d6a5e6b6842ea8` (2026-07-08,
  PR #7555) and its cherry-pick `a7d5eb844a59ea076b7972a018753242f18e6f7b`
  (2026-07-09, PR #7569). Release tag `rel-8-6-5`. Vulnerable tag read:
  `rel-8-6-4`.
- **Claim sources read**: the CVE record, GHSA advisory (including its
  attached public PoC description), both fix-commit `.patch` files, and raw
  source at `rel-8-6-4` / `rel-8-6-5`. Full URLs, tags and SHA-256 digests in
  `lab/frontier/mapserver2shell/PROVENANCE.md`. Read-only provisioning only;
  **no probe, connection or traffic to any non-loopback system**.
- **Scope separation**: distinct from the owned xrdp, FreeRDP, FreeSWITCH,
  GStreamer, Babelfish, Apache, PHP, Ruby, Node, PostgreSQL and Mosquitto
  lanes. Target is a C++ web-facing map server, unauthenticated, default WMS
  surface; no credential or non-default module is required.
- **Ranking**: high tractability. One missing-capacity write in one dispatch
  branch, a single unauthenticated HTTP request, an advisory-supplied PoC, and
  a small source-bound fix diff. The copied heap value is a `strdup` of an
  attacker-controlled query value, so chosen-value control is plausible.
  Ranked above the screened-out lanes on the wall.

## Source-bound mechanism (read from the fix and both raw tags)

Line numbers are from `rel-8-6-4` unless marked fixed.

1. `cgiutil.h:49` — `MS_DEFAULT_CGI_PARAMS 100`; `cgiutil.h:56-81` —
   `cgiRequestObj` carries `ParamNames`, `ParamValues`, `NumParams` and **no
   capacity field**.
2. `cgiutil.c:493-503` — `msAllocCgiObj()` allocates two independent
   `msSmallMalloc(MS_DEFAULT_CGI_PARAMS * sizeof(char *))` blocks; `maputil.c:2538-2552`
   shows `msSmallMalloc` is a plain `malloc` wrapper. Each block is 800 bytes
   on x86-64.
3. `cgiutil.c:138,188-199,213-225,262-275,294-299` — `loadParams()` tracks
   capacity in the **local** `maxParams`, doubling with `msSmallRealloc` when
   the parsed count crosses 100/200. The capacity is lost when the function
   returns; later code cannot know it.
4. `mapwms.cpp:5970-5988` — `GetLegendGraphic` with a nonempty `BBOX` takes the
   content-dependent-legend path (`found=true`).
5. `mapwms.cpp:5989-5995` — the vulnerable loop:
   `ParamNames[NumParams] = msStrdup("LAYERS")`,
   `ParamValues[NumParams] = msStrdup(ParamValues[i])`, `NumParams++` for each
   `LAYER=` parameter. No capacity check. Because `"LAYERS"` does not match
   `"LAYER"`, the loop terminates after K appends, writing K slots past the
   parsed count `M`. When `M+K > capacity`, those writes pass the 800-byte
   allocation boundary. Each `ParamValues` slot points to an attacker-chosen
   query value copied by `msStrdup`.
6. Fix (`a7d5eb8`/`ea1d87a`, `src/mapwms.cpp`): deletes the whole append loop
   (`rel-8-6-5:5987-5989` has only `isContentDependentLegend = true`), records
   `REQUEST` in the first parameter scan, and picks
   `layerKey = request == "GetLegendGraphic" ? "LAYER" : "LAYERS"` in
   `msWMSLoadGetMapParams` (`rel-8-6-5:1018-1026`), so the original `LAYER`
   values are consumed without mutating `cgiRequestObj`. The autotest mapfile
   lines switch `LAYERS=point` to `LAYER=point` for the legend cases.

**Blind spots are part of the primitive**: with four fixed parameters plus K
`LAYER=` values, `M = K+4`; parsing keeps capacity 100 for `M<=100`, doubles
to 200 at `M=101`, and to 400 at `M=201`. K=95/96 overflow, K=97 does not,
K=195/196 overflow again, K=197 does not — exactly the pattern the advisory
reports and this harness reproduces.

## Local harness evidence

Files: `lab/frontier/mapserver2shell/{legend_layer_overflow.c,run.sh}` plus
`PROVENANCE.md`, `.gitignore` and pinned raw sources in `src/`. Digests:
`3aca5129886aed717cd1f6dec54e59452757f066fdb0e66784168254c9182b21` (C) and
`96f1757b3c11dd54297209537017adcfbc781c979640166fcf16b2d0c984ad88`
(run.sh). `bash lab/frontier/mapserver2shell/run.sh` printed **ALL CHECKS PASS,
rc 0**:

- **Rung 1 (reproducible trigger)**: `K=95 parsed=99 logical_cap=100
  oob_appends=94 oob_writes=188 first_oob=100 last_oob=193 layers_seen=95
  verdict=TRIGGER`. Rung 1 and rung 3 allocate exactly 100 pointers per array,
  as upstream does.
- **Rung 2 (observed state failure)**: canary stamps at `cap+20` and `cap+120`
  in a physically longer array with the same logical capacity 100. K=95/96
  clobber the first stamp only, K=97 clobbers neither (parse-time doubling to
  200), K=195/196 clobber both, K=197 clobbers neither (second doubling to
  400) — `verdict=LAYER_COUNT_CONTROL_OBSERVED`.
- **Rung 3 (ASan-confirmed corruption)**: gcc 13.3.0, `-fsanitize=address`,
  exact 800-byte allocation, K=95: `ERROR: AddressSanitizer:
  heap-buffer-overflow`, `WRITE of size 8`, `0 bytes after 800-byte region`,
  stack `wms_dispatch_legend (legend_layer_overflow.c:110) <- mode_rung3 <-
  main`, rc 1.
- **Rung 4 (chosen value bytes at chosen slots)**: with K=95 and the payload
  `DEADBEEFCAFEBABE` supplied as the LAYER value, pointer slots 110/150/190
  (byte offsets 880/1200/1520) each read back
  `44 45 41 44 42 45 45 46 43 41 46 45 42 41 42 45` byte-for-byte;
  `chosen_bytes_written=48 offsets_exact=1 value_source=layer_query_values
  verdict=CHOSEN_BYTES_AT_CHOSEN_OFFSETS`. The attacker chooses K (which
  offsets are reached) and the LAYER value bytes (what the clobbered slots
  point to); the pointer *values* are allocator addresses, not attacker
  arithmetic.
- **Fixed control**: the fix's behaviour (no append, `layerKey="LAYER"` for
  `GetLegendGraphic`) gives `oob_writes=0 layers_seen=95 stamps_intact=2
  verdict=PASS` and is ASan-clean (`fixed_asan rc=0`, no report).
- **Determinism**: two independent five-run groups hash identically to
  `sha256=5df6fce0702fa30628d3fcf32ca77975bf22003709ec5c9595e879feff082c2e`.

### Grade

Rungs **1/2/3 ESTABLISHED in the extracted harness**; rung **4 shows
attacker-chosen value bytes read back through clobbered pointer slots at
deterministic offsets in an instrumented layout**, not merely a constant
write. It is **not** a live-process demonstration: the rung-4 layout uses a
physically longer allocation so stamps can be observed (rung 3 uses the exact
800-byte allocation and ASan as the boundary detector). No stock MapServer
build, WMS/CGI request path, real heap neighbour, pointer control or code
execution was observed. This is a claim for the witness to replay, not
acceptance.

## Cheapest next experiment to move a rung

Build the advisory's `rel-8-6-4` ASan mapserv CGI with the GHSA PoC's minimal
mapfile (a map layer with `wms_enable_request` including `GetLegendGraphic`),
serve it on 127.0.0.1 only, and send K=95 `LAYER=` parameters with a nonempty
BBOX. If ASan reports an 8-byte WRITE past an 800-byte region in
`msWMSDispatch`, rung 3 is confirmed on the stock build. For rung 4, place a
known allocation immediately after the parameter arrays under a plain build
and read back the attacker's LAYER value through the clobbered slot; pointer
control or execution would need a separate groom and is not claimed.

## What would change my mind

A primary source showing a capacity check or realloc before the append, a fix
that keeps the append loop, a clean replay losing ASan or the chosen-value
read-back, or evidence the stock `cgiRequestObj` arrays are larger than
`100 * sizeof(char *)`.
