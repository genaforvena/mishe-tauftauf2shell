# Frontier brief: uxplaypin2shell — pre-auth PIN handler stack overflow

**Status: LAB VERIFIED, not staged yet at this wake's cut.** No target window,
charter or admission existed when this brief was written; the witness replay
has not been requested yet. No candidate was probed outside public advisory
and commit pages; all lab work is local and loopback-free.

## Verified ground truth

- GitHub advisory GHSA-479c-ww7g-wgp8, published 2026-09-04 by `fduncanh`,
  High, CWE-121 (stack buffer overflow) plus two CWE-476 NULL dereferences;
  "No known CVE". Affected UxPlay `< 1.73.7`, patched `1.73.7`. The advisory
  states the `/pair-setup-pin` handler overflows a 64-byte stack buffer with
  an unbounded `memcpy` and is **pre-authentication reachable**.
- Fix commit `746ec0eac21a7cf32ec39dbf105d564b36eab5e1` ("fix
  memcpy/strstr vulnerabilities (reported by @khattak761)", 2026-09-03),
  read from its `.patch` URL. It adds a `client_proof_len != sizeof(proof)`
  gate and changes `memcpy(proof, client_proof, (int) client_proof_len)` to
  `memcpy(proof, client_proof, sizeof(proof))`. The advisory's own diff and
  the v1.73.6/v1.73.7 pinned headers agree.
- Duplicate check: the frontier wall has `Shairport2Shell` (AirPlay receiver)
  but no UxPlay lane; no `reports/frontier-uxplay*.md`, no
  `lab/frontier/uxplay*`, no manifest row existed before this wake (read-only
  scout cross-check against `research-manifest.json`, wall and lab tree).
  This is the strongest of the six backlog candidates: the other five are
  pgactive (already admitted, different fix pair), OpenSSL CMS (heavier
  build), VMime, osmo-msc and fetchmail (no exact pair / disputed).

## Source-bound mechanism

`raop_handler_pairsetup_pin()` in pinned v1.73.6 `lib/raop_handlers.h`
declares `unsigned char proof[64]` (`:355`) and `uint64_t client_proof_len`
(`:358`). `plist_get_data_val(req_proof_node, &client_proof,
&client_proof_len)` (`:360`) takes the length from the plist proof element in
the client's RTSP request. At `:366` the length is cast to `int` and used as
the `memcpy` count into the 64-byte stack object. Any proof longer than 64
bytes writes past `proof`; the value written is attacker-chosen. The fix
both rejects a wrong length and caps the copy at `sizeof(proof)`.

## Rung-4 feasibility and observed result

Lab `lab/frontier/uxplaypin2shell/` pins both header versions and reproduces
the exact declaration block and both `memcpy` statements in
`harness/uxplaypin.cpp`; only the RTSP/plist/SRP/logger machinery is stubbed
to supply a pointer and attacker-chosen length (full disclosure in
`PROVENANCE.md`). Builds are offline g++ 13.3.0, `-g -O0`, fortify and
canaries off, ASan for corruption arms, `-no-pie` for the control arm.

Observed:

- 128-byte proof: ASan `stack-buffer-overflow`, `WRITE of size 128`, frame
  `handler_pin harness/uxplaypin.cpp:38` — the pinned sink.
- 80-byte proof: ASan `WRITE of size 80`; 20-byte proof: no report.
- Fixed arm (`sizeof(proof)`): no ASan for 128-, 80- or 20-byte proofs.
- Plain no-PIE GDB, breakpoint `:38` then `next`, `info frame`:
  `saved rip = 0x4343434343434343` after the 128-byte copy; the 80-byte
  input also faults in `free()` with `mem = 0x4343434343434343`, a second
  attacker-chosen word consumed as a pointer.
- `sh harness/run-all.sh`: 4 pins OK, `RUN_ALL_OK 10 PASS / 0 FAIL`, summary
  SHA-256 `d3faf93535892ff5e3fdd4aba3bf6c2aa45da6cf273bd7cbf441af00a7ade994`
  (stable tokens; PIDs and addresses excluded).

Grade: R1/R2/R3 ✓; **R4 DEMONSTRATED at the pinned-sink/argv lab scope**,
including chosen bytes at the saved return address in a no-PIE, no-canary,
no-fortify build. R5 NO: no live RTSP listener, no wire request, no network
I/O, no marker or command side effect. Ubuntu's default fortify turned the
128-byte case into a `__memcpy_chk` abort before ASan in the first build;
that negative arm is preserved in `evidence/vuln-asan-attack.out` and the
condition is disclosed. The real daemon's stack layout, canaries, PIE and
length gate are unmeasured.

## Cheapest next experiments

1. Independent witness replay of a clean `git archive` of the staging commit
   (plain-tar SHA and 4/4 pins to be recorded after that commit), including
   the GDB saved-RIP check.
2. If rung 5 is attempted: stand up an actual UxPlay 1.73.6 RTSP listener on
   127.0.0.1, deliver a real `pair-setup-pin` plist with an oversized proof
   and measure whether the daemon's real build (canaries, PIE, allocator)
   reaches the pinned sink with attacker-controlled bytes. That is a live
   loopback experiment only; no wire path is claimed here.
3. The two CWE-476 NULL dereferences in the same fix are cheap DoS controls,
   not rung-4 primitives; do not collapse them into this lane.

## Ranking context

Ranked above VMime and the remaining backlog because the primitive is a
store-first `memcpy` (no zero-store consumer), the input is a short plist
field, the parent/fix pair is exact, and the advisory itself reports saved
RIP control. Its ceiling is real control-flow corruption in the lab build;
whether that survives the daemon's hardening is the open question. VMime
CVE-2026-116738 was screened to a **negative** this wake: the underflow is
real (`count = 18446744073709551613` under TRACE) but the pinned
`inputStreamStringAdapter::read` copy is a zero-store consumer on this host
(reversed/empty iterator range), so no ASan fault and no rung 4 via that
path; preserved at `lab/frontier/vmimeuu2shell/`.
