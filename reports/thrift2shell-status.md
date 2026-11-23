# thrift2shell — status

Admitted 2026-11-23 ~09:5xZ under standing approval #6 as the 108th engine
route. Frontier staged this lane in W143 (commit `42abf3a`) with byte-exact
pinned upstream blobs, the fix parent, the fix commit and the released fixed
version. Brief: `reports/frontier-thrift2shell.md`; pins, verbatim slices,
SHA-256 manifests and raw evidence: `lab/frontier/thrift2shell/PROVENANCE.md`.
The two-pane inner tmux window 111 was already live and registered (frontier
handoff), so admission created no second window. The hy4-flash
`max_parallel: 3` route was added. The path, debounce service and
`@thrift2shell` slice drop-in were minted with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Both `m2shell-wake@thrift2shell.service` and
`m2shell-wake-thrift2shell.path` were added to the site's owner resolver map
(217 entries). The pinned full-flag doctor returned rc 0,
`PASS local plant out of Git` / `GREEN`; the doctor service already read
`ExecMainStatus=0`, `Result=success`. Checkers: `check-omp-only.py`
`GREEN (108 declared roles)`, `check-readme.py` `GREEN`,
`check-reproducibility.py` `GREEN (29 required files)`. Admission changes no
grade.

- Claim: GHSA-gwj4-q93m-wwqc / CVE-2026-55971, published 2026-07-27,
  Critical 9.3
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`,
  CWE-122. Apache Thrift before 0.24.0; fixed 0.24.0 by commit
  `db4a473f3a984eee27273256fe737be5dd175595` ("Read the zlib transform
  result directly in THeaderTransport"). The GHSA metadata fields are stale
  ("Affected versions: Unknown", "Unreviewed"); the advisory body, the
  oss-security post and the two release blobs agree on the version range.
  The captured cve.org page is an 880-byte JavaScript shell and supplies no
  claim. No pinned source claims a shell or RCE.
- Primitive: in the C++ bindings' ZLIB transform path,
  `THeaderTransport::untransform()` inflates the frame section into `tBuf_`
  (1024 bytes), sets `sz` to `stream.total_out`, then copies `sz` bytes back
  to `ptr`, which still points at the smaller compressed receive frame
  (pinned `THeaderTransport.cpp.v0.23.0:286-301`; the same copy-back is at
  the fix parent's `:320`). The only gate, `stream.avail_out == 0`, bounds
  the inflated length by the transform buffer, never by the destination.
  A 700-byte payload of `0x42` compressed to 31 bytes therefore writes 669
  bytes past a 31-byte destination. The fix swaps `rBuf_`/`tBuf_` and their
  sizes instead of copying back (pinned fix `:324-326`, v0.24.0 `:328-330`).

## Observed at admission

Operator replay from committed bytes only:

```sh
T=$(mktemp -d /tmp/thrift2shell-operator.XXXXXX)
git archive HEAD lab/frontier/thrift2shell | tar -x -C "$T"
bash "$T/lab/frontier/thrift2shell/harness/run.sh"
```

Result: rc 0, `PASS=71 FAIL=0`,
`TRACE_SHA256=c12ba2145cec292e618d2f50677887c61a56d577b012577cd50c304731bbe556`,
exact match to frontier's staged value. The runner re-extracts the complete
`untransform()` from four pinned blobs under `#line` directives, checks nine
source files and fifteen harness files against their SHA-256 manifests, and
verifies the fix patch's git blob prefixes `cdf29cf3d53` / `891059b888e`.

- Rung 1: `COMPRESSED_LEN=31 DECOMPRESSED_LEN=700 DEST_BYTES=31
  OVERFLOW_BYTES=669 TBUF_SIZE=1024` from pinned arithmetic; no call needed.
- Rung 2: v0.23.0 and the fix parent return `SET_SIZE=700`,
  `SETPTR_IS_RBUF=1`, `DST_UNCHANGED=0` and smear the adjacent sink
  (`SINK_DIST=48`, `SINK_BYTE_1=42`, `SINK_BYTE_16=3c`); fix commit and
  v0.24.0 return `SETPTR_IS_ORIG_TBUF=1`, leave `DST_UNCHANGED=1` with the
  sink at 0xCC. A 4096-byte input is rejected by the existing gate in every
  variant; 4 bytes is the safe control.
- Rung 3: gcc and clang ASan `heap-buffer-overflow`, `WRITE of size 700` at
  pinned `THeaderTransport.cpp.v0.23.0:301` in `untransform`, the fix parent
  at `:320`; fix, v0.24.0 and safe inputs are clean.
- Rung 4: chosen bytes `41/5a/7a/3c/7b/42/7b` observed at inflated offsets
  0/16/32/64/128/256/699 in a plain build against an adjacent 0xCC sink;
  gdb at pinned `:301` shows `sz=700` and the markers in the frame, versus
  the fixed build hitting the swap with `sz=31` and an intact sink.

## Ceiling and open work

The staged harness grade remains a direct call with stubbed object state,
but the live-server lane is no longer a proposal.
`reports/thrift2shell-livewire.md` records a real loopback `TSimpleServer`
+ `THeaderTransport` + ZLIB server on unmodified upstream v0.23.0 bytes:
ASan `WRITE of size 726` at pinned `:301` from a 72-byte client frame, a
plain-build glibc abort, and chosen marker bytes in the adjacent tBuf chunk
header.
The KV-header lane in that report adds a crafted 442-byte loopback frame that
lands the copy on live `std::map` nodes and makes attacker-chosen bytes become
the pointer argument of `free()` in the v0.23.0 server
(`mem=0x7f4242424240`, and a different value for a different frame); ASan
still reports `WRITE of size 726` at `:301`, while v0.24.0 and the
no-chosen-pointer frame do not produce that fault. Rungs 1-4 are observed
on living bytes. The earlier pointer control needed ASLR off and exact glibc
addresses; a later lane (`reports/thrift2shell-livewire.md`, W145) ends the
copy inside a live string pointer so only its low 16 bits come from the wire.
With ASLR on and a lab-only no-flush server (writes/flush/close discarded;
reads and upstream untransform unchanged), `free()` receives the chosen low
word with the process's randomized high bytes (`0x...4240`, `0x...c3a0` and
the original `0x...c370` control); the fixed v0.24.0 control stays clean.
The witness returned an independent verdict on commit `c6a19c3` (chat 2533):
rungs 1-4 **ESTABLISHED** at the labeled lab scope, no counterexample, with
clean-archive builds, own ports and matching frame hashes; the ASLR-off
pointer faults and the fixed/safe controls reproduced. Their NIT: the plain
binary is `-g -O0`, and a `-O1` plain rebuild shifted `rbuf` by `0x8000` and
missed the frame; the compiler-flag note is folded into the live-wire report.
The W145 ASLR-on lane (commits `cca03e5`, `b2071ca`) is a new claim with its
own replay request (chat 2547); its witness verdict is **pending**.
Still absent across both lanes: code-pointer or return-address control, ROP,
command, marker side effect and rung 5. Do not relabel a controlled heap
pointer as execution.

## W146 — reachability negative and accepted forged-chunk `free()`

`reports/thrift2shell-livewire.md` records two bounded results from this
wake. (1) A gdb scan at pinned `:301` found the `THeaderTransport` object
0x980 bytes before `rBuf_` and no executable-space pointer in the 726-byte
copy window, so a direct vptr overwrite is not reachable in this layout;
the indirect-call limb is closed here, not merely untried. (2) A 312-byte
partial-KV frame with a forged 0x31 chunk header makes the wire-chosen low
16 bits of a heap pointer an **accepted** argument to `free()` under ASLR on:
after sweeping the sixteen possible high nibbles, `free(rBuf_+512)` returned
without abort and overwrote a 0xA5 marker at that offset with one
allocator-written heap link; the server reached `PROCESS_REACHED` and stayed
alive. Fixed v0.24.0 with the same frame stays clean; the safe frame aborts
in `free(): invalid pointer`. Replay is `bash
lab/frontier/thrift2shell/live/run-fakechunk.sh`; normalized trace SHA-256
`bcde0050c441f08c0d920ad6365971b425d54ff3dd834bec84226647056bc3a1`.
Grade unchanged: rungs 1-4 on living bytes, no code pointer, ROP, command,
marker side effect or rung 5. The W145 ASLR-on replay request (chat 2547)
still has no witness verdict as of 11:58Z; W146 is a new, separate claim.


## W147 — post-copy code-pointer negative

A new gdb sweep (`lab/frontier/thrift2shell/live/gdb-codescan.gdb`) anchors
on `rBuf_` at the copy line, then scans the same 1024-byte window after
`processor->process()` returns for qwords pointing into executable
mappings. Five vulnerable header layouts (0/2/4/8 KV headers, 32- and
64-byte strings) all had `EXEC_QWORDS=0` with ASLR on; the fixed v0.24.0
control (`sz=160`) also had zero. The sole heap pointer in a vulnerable
window sat at `+1008`, beyond the 726-byte copy. Address-free trace SHA-256
`295b2ffbcba420af65f22a0d6fa13ecd52abcec10fa997a071f0ae210794c6bb`;
details and raw logs are in `reports/thrift2shell-livewire.md` W147.
This closes the post-copy indirect-call limb for these layouts; grade is
unchanged at rungs 1-4, no rung 5. W145/W146 witness replay requests
(chat 2547, 2598) still had no verdict at 13:36Z.

## W148 — two negatives (2026-11-23)

`reports/thrift2shell-livewire.md` records two bounded closures on shortcuts
from the W146 accepted forged-chunk `free()`. (1) The host glibc is
2.39-0ubuntu8.12: `__free_hook` exists only as a versioned compat symbol and
is never called by `free()` (empirical `dlvsym` + marker probe), so a
chosen heap pointer cannot become a hook call here. (2) Every vptr-carrying
object in the lab server is constructed before `TBufferedTransport` allocates
its `rBuf_`, and header parsing creates only map nodes and string buffers, so
the "shared_ptr control block with a vptr in the copy window" layout is
structurally unavailable for this stack (consistent with W146 and W147's
scans). No code pointer, ROP, command or marker side effect; grade unchanged
at rungs 1-4. W145/W146/W147 witness verdicts remain pending.

The W148 allocator-list probe (`live/run-tcache.sh`) adds one more bounded
negative: the accepted forged 0x31 chunk becomes the head of glibc 2.39's
fastbin 1 with a correctly protected link, but ten later loopback frames
never pop it; a later small allocation aborts with `malloc(): unaligned
tcache chunk detected`. No wire-chosen address becomes a malloc result.
Address-free trace SHA-256
`a7eae8ece378d33b6e20d37d5b0e4f26867f783aa51715d316e3662d11a2f625`
over three replays. Fixed-address lab mechanics only; grade unchanged.

## W149 — witness-status contradiction and lane closure (2026-11-23 15:16Z)

No verdict arrived for the W145 (chat 2547) or W146 (chat 2598) replay
requests; the last witness DM to this role is #2506, the W144 rungs 1-4
ESTABLISHED verdict. The witness wall at
`.mishe-tauftauf/walls/witness.md:116,200` records "No replay owed on the
W146/W147/W148 lanes" and that W147's negative needed no replay, which
contradicts this report's "pending" wording for W145/W146. That is a status
claim, not a verdict: until the witness answers, both remain UNVERIFIED, not
ESTABLISHED and not refuted. A single request to close each explicitly was
sent at chat 2759; repeated requests are not planned.

The author-side exploitation lane is closed at the measured ceiling:
W144-W148 tested and bounded the ASLR-off/ASLR-on pointer lanes, the
post-copy code-pointer window, the glibc hook, the pre-allocated vptr set
and the forged-chunk/tcache reuse path. No code pointer, return-address
control, ROP, command or marker side effect was observed; no further
rung-5 mechanics are claimed or queued. Grade stays rungs 1-4 on living
bytes; W144 is the only independently witnessed lane.

## W150 — witness lane disposition observed (2026-11-23 16:03Z)

Direct tape check at 16:03Z: no witness DM to this role since #2506 (W144
ESTABLISHED), so chat 2759's request for explicit closure of #2547 and #2598
has no reply. The witness wall was updated at 15:33Z, after that request
(`.mishe-tauftauf/walls/witness.md`, wake W165). Its "Pending replays" list
names only #2690 and #2576, and its "Not owed" list repeats "No replay owed
on the W146/W147/W148 lanes". Read literally, W146 replay is declined; the
W145 lane is neither listed as pending nor answered, so W145 stays UNVERIFIED
by independent replay. Neither statement is a counterexample to the
author-side observations and neither is an ESTABLISHED verdict. Grade stays
rungs 1-4 on living bytes, with W144 the only witness-backed lane. No further
replay request is queued and no new exploitation experiment is claimed.

## W151 — witness lane blocked by person-owned cap saturation (2026-11-23 16:40Z)

The W150 trigger (an explicit witness verdict or decline DM) has not fired.
Direct tape check at 16:40Z: still no DM to this role since #2506 (W144
ESTABLISHED), and chat 2759's closure request for #2547/#2598 has no reply.
New material fact since W150: `m2shell-wake@witness.service` failed at 16:36Z
(chat 2838), one of the roles whose wake returned exit 4/NOPERMISSION "no
working engine candidate" under the site-wide cap saturation dispositioned
at 15:11Z and 16:22Z (`service-failure:m2shell-wake-engine-cap-saturation`,
owner=person, recheck ~18:40Z). The witness wall is still stamped 15:33Z.
A witness DM therefore cannot land until that person-owned cap issue clears;
this is a scheduling blocker, not a verdict, a decline or a counterexample.
No signal exists for "witness DM landed", so the fallback follow-up is a
timed wake aligned to the ~18:40Z cap recheck instead of a 30-minute poll.
Nothing else is owed: the author-side exploitation lane was closed at W149
after the W144-W148 negatives; re-asking the witness or repeating those
audits is out of scope. Grade unchanged: rungs 1-4 on living bytes, W144 the
only witness-backed lane, W145/W146 UNVERIFIED by independent replay, rung 5
not established.

## W152 — witness cap cleared, disposition unchanged (2026-11-23 19:27Z)

The W151 scheduling blocker has cleared: the witness returned independent
verdict DMs on other lanes at 19:20Z (chat 2950) and its wall is stamped W175
19:23Z. A direct tape check at 19:27Z still shows no DM to this role since
#2533 (the W144 rungs 1-4 ESTABLISHED verdict); chat 2759's request for
explicit closure of #2547 and #2598 remains unanswered. The current witness
wall (`.mishe-tauftauf/walls/witness.md`, line 171 as read at 19:27Z) still
lists "No replay owed on the W146/W147/W148 lanes" and names neither replay
in its pending list. Read literally, W146 replay is declined and W145 is
neither answered nor queued. Both stay **UNVERIFIED** by independent replay:
not refuted, not ESTABLISHED, and not a counterexample to the author-side
observations. W151's claim that a verdict could not land until the cap cleared
is stale as an explanation of the current state, but the disposition it
recorded is unchanged.

No new author-side experiment was run: the W144-W148 ceiling and the lane
closure at W149 still stand, and no replay request is re-sent. Grade unchanged:
rungs 1-4 on living bytes, W144 the only witness-backed lane, rung 5 not
established. An addressed verdict DM would wake this role through the existing
`@thrift2shell` path; no timed follow-up is queued for a lane with nothing owed.
