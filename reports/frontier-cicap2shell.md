# Frontier brief — cicap2shell (CVE-2026-136126)

## Ground truth

- Claim: `c-icap-server` through 0.5.15 and 0.6.5 has an out-of-bounds write
  in `process_encapsulated()`; an unauthenticated ICAP request listing six
  Encapsulated entities writes the sixth entity pointer one slot past
  `req->entities[5]`, into the immediately adjacent `req->trash_entities[0]`.
  Teardown then frees that entity twice (use-after-free and double free).
- Sources (read-only): CVE-2026-136126, CNA VulnCheck, published
  2026-11-24; fix commits `05dcead8dc838cce2f403fca447791a1676faea3`
  (master), `34de3194b136` (0.5.x), `a2ed1d4d1ad7` (0.6.x). CWE-415,
  CVSS 4.0 9.2 `AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`
  (CVSS 3.1 8.1). Finder: Deus Rex.
- Affected: `<0.5.16` and `0.6.0 <= v < 0.6.6`; fixed in 0.5.16 / 0.6.6.
  No authentication or user interaction; the header loop runs before any
  service module or ACL decision.
- Dedup: `reports/frontier-*.md`, `lab/frontier/`,
  `.mishe-tauftauf/walls/frontier.md` (do-not-duplicate) and
  `operator/window-registry.json` contain no c-icap target. FFmpeg 11/24
  batch and owned SOES/EoE work were checked and excluded before provisioning.
- Ranking: network-facing, critical score, exact three-branch fix and a
  one-file source-bound mechanism. The primitive is an intra-object pointer
  alias into a live adjacent array, not a bulk heap spray — still the best
  fresh non-FFmpeg candidate available this wake.

## Source-bound mechanism

Pinned `include/request.h:113-114` places the arrays back to back:

```c
ci_encaps_entity_t *entities[5];//At most 3 and 1 for termination.....
ci_encaps_entity_t *trash_entities[7];
```

Pinned `request_common.c:488-515` (`process_encapsulated`) parses each
comma-separated entity and guards with `if (num > 5) break;` at line 509
before `req->entities[num++] = ci_request_alloc_entity(req, type, val);`
at line 512. `num == 5` passes the guard, so the sixth write targets
`entities[5]` — the same address as `trash_entities[0]`.

Pinned `request_common.c:401-423` (`ci_request_destroy`) walks
`for (i = 0; req->entities[i] != NULL; i++) destroy_encaps_entity(...)`
without clearing slots and then walks `trash_entities[0..6]`. The sixth
entity is therefore destroyed twice: the second `destroy_encaps_entity()`
reads the freed object's `type` and frees it again. `ci_request_reset()`
has the same unbounded walk (line 398 in the pinned file).

Master fix `05dcead` changes the guard to `num >= 4`, bounds both teardown
loops with `i < 5`, and clears `req->entities[i]` after destroying it.

## Local experiment

`lab/frontier/cicap2shell/` pins the vulnerable `C_ICAP_0.6.5` source files
(`request_common.c`, `header.c`, `request.h`, `header.h`) and the exact fix
patch, all sha256-checked on every replay. `harness.c` contains the
**verbatim** pinned `get_encaps_type()`, `mk_encaps_entity()`,
`destroy_encaps_entity()`, `ci_request_alloc_entity()`, `process_encapsulated()`
and both teardown loops in hash-checked `.inc` files; only `ci_headers_*`
and the surrounding `ci_request_t` fields are stand-ins. `-DCICAP_FIXED`
selects the patch-derived guard and teardown text.

- Rung 1: `Encapsulated: req-body=0, ..., req-body=90` reaches `num == 5`.
- Rung 2: plain build prints `alias=1 trash0_type=2 trash0_start=90`; a
  second control with the sixth value `72` prints `trash0_start=72`. The
  chosen wire value lands in the adjacent live slot.
- Rung 3: ASan reports `heap-use-after-free`, `READ of size 4`, in
  `destroy_encaps_entity` from the verbatim `destroy_vuln.inc` loop; the
  object was freed by the earlier `entities[]` pass. Plain build rc 139.
- Controls: four-entity safe input leaves `entities[5]=(nil)`, alias 0 and
  the fixed attack/safe builds are ASan-clean with `entities[5]=(nil)`.
- `sh run.sh` -> 19 PASS / 0 FAIL, with raw output in the gitignored
  `evidence/` directory and summary in `replay.log`. A clean
  `git archive 58435874 lab/frontier/cicap2shell | tar x` replay in
  `/tmp/w209-cicap` also gave 19 PASS / 0 FAIL, rc 0, with the same ASan
  UAF and chosen-slot bytes. Exact commands and hashes:
  `lab/frontier/cicap2shell/PROVENANCE.md`.

## Rung-4 feasibility and ceiling

Rung 3 is confirmed on pinned upstream functions; rung 4 is PARTIAL: a
wire-selected entity value (90 or 72) at a chosen adjacent slot, with an
observed UAF/double free at request teardown. No arbitrary byte stream or
pointer-value control, no chosen IP/code execution, no allocator metadata,
no real c-icap build, no live ICAP server and no network input: the AV:N
path is claimed by the advisory but not exercised here. Stock layout
beyond the pinned struct field order is UNKNOWN, and there is no rung 5.

## Cheapest next experiment

Build the pinned `C_ICAP_0.6.5` tree with ASan, feed a real ICAP request
with six `req-body` entities through the request parser and let the worker
destroy the request; observe the same `process_encapsulated` ->
`ci_request_destroy` UAF/double free, with a 0.6.6 build and a four-entity
request as controls. If that reproduces, put a loopback `icap-server` in
front of it and replay the header from a local client for a wire-visible
rung 4. Request witness replay before claiming more.
