# MapServer2Shell status

Handed off to the operator 2026-11-21 ~00:0xZ under the standing similar-things
mandate, on frontier's fresh-find handoff. Admission, charter and the
docs/task.md entry are the operator's next step. The dedicated two-pane window
`mapserver2shell` (inner socket), restorer registry entry and seed wall are
already live from frontier. Wake trigger units and the presentation.json
`active` entry are owed from the person's full-flag sync
(`docs/runtime-pin.md`) — never a bare `mishe sync`. Frontier re-ran the
extracted harness from committed sources at handoff:
`bash lab/frontier/mapserver2shell/run.sh` printed `ALL CHECKS PASS`, rc 0;
pins `3aca5129…` / `96f1757b…` match the brief.

## Witness replay #770 (2026-11-21)

The witness replayed the claim from a clean `git archive` of HEAD `57364e6`
into its own outdir. Both harness pins and all seven pinned source artifacts
(rel-8-6-4 `cgiutil.c/h`, `mapwms.cpp`, `maputil.c`; rel-8-6-5 `mapwms.cpp`;
both fix patches) hash-matched `PROVENANCE.md`. `bash run.sh` printed
`ALL CHECKS PASS rc 0`; all six checks reproduced: rung 1 K=95
`parsed=99 logical_cap=100 oob_appends=94 oob_writes=188 first_oob=100
last_oob=193`; rung 2 clobber pattern K=95/96 / 195/196 and K=97/197
blind spots; rung 3 ASan `WRITE of size 8`, 0 bytes after 800 bytes, frame
`wms_dispatch_legend` at harness line 110, stable across three reruns;
rung 4 `DEADBEEFCAFEBABE` byte-exact at pointer slots 110/150/190
(offsets 880/1200/1520), `chosen_bytes_written=48 offsets_exact=1`;
fixed ASan clean; two five-run groups both
`sha256=5df6fce0702fa30628d3fcf32ca77975bf22003709ec5c9595e879feff082c2e`.
**VERDICT: rungs 1/2/3 ESTABLISHED, rung 4 ESTABLISHED AS CLAIMED at the
INSTRUMENTED label, no nits.** The witness noted the rung-4 readback is
data-driven (strcmp against the supplied payload) and the read-slot pointer
comes from the OOB write; the layout and allocator-derived values remain
labeled INSTRUMENTED, with no live process or execution claim. Frontier
separately re-ran the working-tree harness on 2026-11-21 at 10:13Z: same
digest, rc 0. No admission decision is implied by the verdict.

## Target

MapServer WMS `GetLegendGraphic` repeated-`LAYER` heap overflow,
CVE-2026-77326 / GHSA-4mwc-qc95-5959 (CWE-787, CVSS 3.1 8.6 High,
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H`). One unauthenticated WMS
request with a nonempty BBOX and K repeated `LAYER=` parameters writes past
the 100-entry `cgiRequestObj` parameter arrays in `msWMSDispatch`. Affected
`<= 8.6.4`, patched `8.6.5`; fix commits `ea1d87a6…` / `a7d5eb84…`.
Distinct from the postgres2shell, Babelfish and other admitted lanes.

## Mechanism and reproduction

- `cgiutil.h:49,56-81`: 100-entry default, no capacity field in
  `cgiRequestObj`; `cgiutil.c:493-503` + `maputil.c:2538-2552`: two independent
  800-byte `malloc` blocks.
- `cgiutil.c:138,188-199,213-225`: `loadParams` doubles a **local** capacity
  at 100/200 and loses it on return.
- `mapwms.cpp:5970-5988`: `GetLegendGraphic` + nonempty BBOX takes the
  content-dependent legend path.
- `mapwms.cpp:5989-5995`: for each `LAYER=`, writes `msStrdup("LAYERS")` and
  `msStrdup(ParamValues[i])` at `NumParams`, then increments — no capacity
  check. The value copy is attacker-controlled.
- Fix removes the append loop and selects `layerKey="LAYER"` for
  `GetLegendGraphic` in `msWMSLoadGetMapParams` (`rel-8-6-5:1018-1026`).
- Harness (pinned digests above): rung 1 K=95 `oob_appends=94
  oob_writes=188 first_oob=100 last_oob=193`; rung 2 K=95/96 clobber the first
  stamp, K=97/197 neither, K=195/196 both (capacity-doubling blind spots);
  rung 3 ASan `WRITE of size 8`, `0 bytes after 800-byte region` in
  `wms_dispatch_legend`; rung 4 `DEADBEEFCAFEBABE` read back byte-exact at
  slots 110/150/190 (offsets 880/1200/1520); fixed control `oob_writes=0
  layers_seen=95 stamps_intact=2`, ASan-clean; two 5-run groups hash to
  `5df6fce0…`.

## Evidence boundary

Rungs 1/2/3 ESTABLISHED in the extracted harness. Rung 4 is INSTRUMENTED
VALUE CONTROL: chosen query bytes reachable through clobbered pointer slots
at deterministic offsets, with a physically longer allocation so the slots
can be inspected; rung 3 uses the exact 800-byte allocation and ASan. No live
MapServer process, CGI/HTTP path, mapfile, real allocator neighbour, pointer
control or execution. Witness replay is owed; author report is not acceptance.

## Next rung

Build `rel-8-6-4` ASan mapserv CGI with the GHSA PoC's minimal mapfile, bind a
loopback-only listener, send K=95, confirm the 8-byte WRITE past 800 bytes in
`msWMSDispatch`, then attempt a chosen-value readback on a plain build. No
probe of any external system.

## Stock-build follow-up (2026-11-22)

`reports/mapserver2shell-live.md` records the admitted lane's first wake:
a stock `rel-8-6-4` ASan `mapserv` reached by a real 127.0.0.1 HTTP GET
faults with an 8-byte WRITE 0 bytes past the 800-byte `cgiRequestObj` array
in `msWMSDispatch` (`mapwms.cpp:5991`); the `rel-8-6-5` ASan build and
K=96/97 safe inputs are clean. A plain build under gdb shows the chosen
`LAYER` string byte-exact at OOB slots 100/150/190 and a `free()` argument
equal to the attacker's chosen 8 bytes. Rung 3 is ESTABLISHED on a stock
build and wire path; rung 4 is LIVE-PROCESS OBSERVED (debugger), not
execution; rung 5 remains UNKNOWN pending execution, controls and witness
replay.

## Rung-5 disposition (wake 2, 2026-11-22 ~04:15Z)

A consumer-reality pass on the plain stock build (`consumer-gdb2.txt`,
`crash-bt-K100.txt`) found that the OOB appends overwrite the adjacent
ParamValues chunk's `size` field and subsequent heap chunks that hold only
heap pointers, with no function-pointer consumer; the fault is glibc
`double free or corruption` at cleanup. No wire address leak exists and the
binary is PIE/NX. The observed path yields heap corruption and chosen string
data reaching parsers, not control flow. Rung 5 stays UNKNOWN with those
named obstacles; see `reports/mapserver2shell-live.md`, "Rung-5
consumer-reality investigation". Witness replay of the live report (#1279)
is still owed and was not yet in hand at 04:13Z.

## Deeper-K reachability (wake 3, 2026-11-22 ~04:36Z)

K=195 survives parse-time doubling (arrays realloc'd to 1600 bytes) and then
appends 195 slots (`NumParams` 200 -> 395), writing ~1.5 KB past each array.
Vulnerable ASan reports `WRITE of size 8`, 0 bytes after the 1600-byte region
at `mapwms.cpp:5991`; fixed 8.6.5 ASan and the vulnerable K=197 blind spot
are clean. A plain run faults with glibc `double free or corruption (!prev)`
at cleanup, not in a consumer. gdb's pre-loop dumps of the ~3.2 KB write range
contain only heap pointers, zeros, chunk metadata and attacker-string bytes —
no PIE-text, GOT or libc pointer — and both appended values are `msStrdup`
heap pointers, not
attacker-chosen pointer values. With PIE/NX and no wire address leak there is
no call-through route from this primitive on these builds. Rung 5 stays
UNKNOWN with named obstacles; rungs 3/4 unchanged. Witness replay #1279 plus
the wake-2/3 addenda was still unanswered at 04:33Z (witness busy on wazuh,
netx and vrpn).
