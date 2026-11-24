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

Rung 3 is confirmed on pinned upstream functions, in a real ASan c-icap
0.6.5 library (W1/W2) and now in a real ASan `c-icap` server (W3); rung 4 is
PARTIAL: a wire-selected entity value (90, 72 or 4242) lands in the live
adjacent `trash_entities[0].start` slot. No arbitrary byte stream or
pointer-value control, no chosen IP/code execution, no wire-shaped allocator
metadata (W6), and no r5. W3 drives the server's own
`parse_header()`/`process_request()` from a loopback TCP request, so the
earlier "no ICAP server / no network socket / no AV:N path" boundary is
withdrawn for 127.0.0.1: an OPTIONS
request with six entities and `Connection: close` returns 200 OK before the
UAF fires at teardown. No traffic left loopback, no proxy or real client
consumed it. W4's observing-only gdb breakpoint prints the wire-selected
value in the live aliased slot inside that same server (below). Stock layout
is no longer UNKNOWN in the
pinned release (real `request.h:113-114` confirms the adjacency); wider
deployment reach stays UNKNOWN, and there is no rung 5.

## Real-build result (W1) and cheapest next experiment

A pinned `C_ICAP_0.6.5` tarball
(`6ac51b6d…bab1e5`) was built under ASan; its four source files hash-match
the lab pins. `lab/frontier/cicap2shell/realbuild/real_api_harness.c` links
the built `libicapapi.so.6.0.5` and calls the exported functions on a real
`ci_request_t`: sixth values 90/72/4242 each give `alias=1`, a matching
`trash0_start`, and ASan `heap-use-after-free` `READ of size 4` at
`header.c:631` from `ci_request_destroy request_common.c:417`; the four-entity
safe input and the upstream-patched fixed control are clean (rc 0). GitHub
publishes no 0.6.6 tag, so the fixed control is patch-derived, not a released
0.6.6 binary. Recipe, raw outputs and scope limit:
`lab/frontier/cicap2shell/realbuild/README.md` and
`PROVENANCE.md` §"Real c-icap build".

Next: feed a complete ICAP request from a loopback socket through
`process_request()`/`parse_header()` into this build, then put a real
`icap-server` in front for a wire-visible rung 4. Witness replay (#3753)
returned ESTABLISHED AS LABELED for the original pinned-function claim:
clean-archive `58435874` replay 19 PASS / 0 FAIL, no contradiction, no grade
change, no r5; the real-build lane is author-measured and unwitnessed.

W2 extends this to socket-fed bytes: `realbuild/wire_api_harness.c` writes a
complete `REQMOD ... ICAP/1.0` request into an `AF_UNIX` socketpair and reads
it with the library's exported `ci_connection_read_nonblock()`, then uses
exported `ci_headers_unpack()` and `process_encapsulated()` on the parsed
header. Values 90/4242 again give `alias=1`, the chosen `trash0_start` and the
`header.c:631` UAF; safe and patch-derived fixed controls are clean. The
hidden `ci_read_icap_header()` and `ci_wait_for_data()` are bypassed, so this
is neither the full `parse_header()` path nor a network socket: wire reach
stays UNKNOWN for that harness lane; W3 below closes the server and
loopback-socket gap. The W1/W2 lanes remain author-measured and unwitnessed.

## W3 — full parse path in a live loopback server (19:0xZ)

`realbuild/live/run.sh` starts the real pinned 0.6.5 ASan `c-icap` binary
with the echo service on 127.0.0.1, sends one crafted request and reports
whether ASan fired. REQMOD with six `req-body` entities (offset 90 or 4242)
returns 400 but reaches `parse_header request.c:529` ->
`process_encapsulated request_common.c:507`, and the `header.c:631` UAF
appears at teardown. OPTIONS with six entities, value 4242 and
`Connection: close` returns **200 OK** and then the same UAF on graceful
shutdown at `mpmt_server.c:211`; with `MaxRequestsReallocateMem 0` the same
free pair fires immediately at `mpmt_server.c:689`. The same OPTIONS request
without `Connection: close` returns 200 OK and shuts down cleanly because
keepalive calls `ci_request_reset()` and clears the alias; that negative is
preserved. Four-entity REQMOD (400), one-entity REQMOD (200 OK) and the
patch-derived fixed build are clean. Raw server output in gitignored
`evidence/w3-*.out`; recipe, exact commands and the live-server ceiling in
`lab/frontier/cicap2shell/realbuild/live/README.md`. W3 is author-measured
and unwitnessed; witness replay of W1/W2/W3 is outstanding.

## W4 — wire value observed in the real server's live alias (21:0xZ)

`realbuild/live/observe.sh` breaks at `request_common.c:513`, one line after
the sixth `req->entities[num++]` store in the *unmodified* ASan 0.6.5 server,
and prints the two adjacent slots before continuing. Breakpoints print only;
no memory write, no forced call. An OPTIONS request with six entities over
loopback TCP and `Connection: close` returns 200 OK, and gdb reports
`e5=0x5020002690b0 t0=0x5020002690b0`, `e5_start=4242 t0_start=4242
alias=1`; repeating with wire value 90 gives `e5_start=90 t0_start=90
alias=1`. Both runs end in the same `header.c:631` ASan UAF with
`MaxRequestsReallocateMem 0`. Four-entity REQMOD gives `e5=(nil) t0=(nil)`
and no sanitizer; the patch-derived fixed build with the same OPTIONS input
also gives `e5=(nil) t0=(nil)` and no sanitizer. Raw outputs in gitignored
`evidence/w4-*.out`. This closes the W3 measurement gap: rung 4's wire value
is now seen in the live aliased slot of the real server, not just the pinned
harness and socket-fed library. Still no pointer/IP/command control, no
wire-controlled allocator metadata, no proxy or real client, no r5;
author-measured and
unwitnessed at this scope.

## W6 — plain-build teardown consumer: no pointer steering (22:2xZ)

The pinned 0.6.5 tree was rebuilt without ASan in
`/tmp/cicap-real/build-plain`. `realbuild/consumer_probe.gdb` prints every
`destroy_encaps_entity()` call on a real `ci_request_t`: for wire values
90, 72 and 4242 the sixth call carries the chosen `start` and
`entity=(nil)`, while the seventh (the aliased slot destroyed again) reads
`type=21840 start=42031 entity=<varying pointer>` in all three runs. The
wire-chosen `start` is gone; the pointer handed to the second `free()` is
glibc free-list metadata written into the freed 16-byte entity, not wire
input. `free(e->entity)` at `header.c:634` faults in `__GI___libc_free`
(SIGSEGV, rc 139), matching the plain harness and a plain real server on
loopback (200 OK OPTIONS, then `server_rc=139`,
`MaxRequestsReallocateMem 0`). `realbuild/malloc_window.gdb` enables a
`malloc` breakpoint between destroy calls 6 and 7 and sees zero hits; the
pinned teardown loops (`destroy_vuln.inc:5-11`) are adjacent, so this
build offers no window to reallocate the freed entity with attacker bytes.
Four-entity safe input destroys four entities once and exits 0. This is a
negative rung-5 result for the stock glibc consumer, not a capability
claim; other allocators/builds stay UNKNOWN. Raw output in gitignored
`evidence/w6-*.out`; author-measured and unwitnessed.
