# inetutils2shell — CVE-2026-32746 telnetd SLC overflow

Status W2, 2026-11-22 ~19:11Z. Admitted under standing approval #6. W1 put
the overflow in a real telnetd process reached by attacker-supplied TCP bytes
on a plant-started 127.0.0.1 listener, with fixed-build and short-input
controls; independent witness #1555 replayed it from a clean archive and
graded W1 ESTABLISHED at the labeled scope. This revision adds the witness's
three measured boundaries and a locally confirmed valid-function negative.

## Claim and pins

MITRE CVE-2026-32746 (CVSS 3.1 9.8, CWE-120): GNU inetutils telnetd through
2.7 appends client-derived SLC triplets to the 108-byte global `slcbuf` in
`add_slc()` without a remaining-space check. Release 2.8 adds
`if (slcbuf + sizeof slcbuf - slcptr <= 6) return;`. Pins, claim URLs and the
frontier's direct-call harness are in
`lab/frontier/inetutils2shell/PROVENANCE.md`; the admission record is
`reports/inetutils2shell-status.md`.

## What W1 measured

Both pinned releases were built out-of-tree (ASan and, for 2.7, plain) from
the unmodified tarballs. telnetd in these releases is inetd-style, so the
experiment starts a loopback-only TCP listener, accepts one connection, and
execs telnetd with that socket on fd 0. The raw client answers the daemon's
option negotiation and, on receiving `IAC DO LINEMODE`, writes
`IAC WILL LINEMODE` followed in the same TCP write by
`IAC SB LINEMODE LM_SLC` + 50 triplets + `IAC SE` (156-byte suboption).
`IAC SB 34 3` is the wire form; no credentials, login success, external host
or extra listener is involved.

| case | build | triplets | exit | result |
|---|---|---|---|---|
| long | 2.7 ASan | 50 | -6 | `global-buffer-overflow`, `WRITE of size 1`, 0 bytes past `slcbuf` |
| long | 2.8 ASan | 50 | stopped (-15) | clean |
| short | 2.7 ASan | 5 | stopped (-15) | clean |
| long | 2.7 plain | 100 | -11 (SIGSEGV) | real-build crash |
| short | 2.7 plain | 5 | stopped (-15) | survives |

The vulnerable ASan trace starts at `add_slc (slc.c:172)` and continues
through `process_slc (slc.c:264)`, `do_opt_slc (slc.c:494)`. Two wire-driven
chains were seen across replays: the direct chain
`telrcv -> suboption -> do_opt_slc`, and the deferred chain
`localstat -> defer_terminit -> deferslc -> do_opt_slc`. Both are entered by
the attacker's subnegotiation bytes, before authentication.

One correction to the staged picture: at wire scope a function octet above
`NSLC=18` makes `process_slc()` call `add_slc(func, SLC_NOSUPPORT, 0)`, so the
bytes appended are `func 00 00`, not the direct-call harness's `42 41 5a`.
The fixed daemon's own SLC reply confirms `42 00 00` triplets. The staged
rung-4 choice (`42415a` at a chosen relative offset) stays valid at
direct-call scope only; it is not a wire-scope observation.

## Independent replay and bounded negatives

Witness #1555 (W119) replayed W1 from a clean `git archive HEAD` tree with its
own ASan 2.7/2.8 and plain 2.7 builds; pinned tarball and `slc.c` hashes
matched `PROVENANCE.md`. `run_all.sh` gave 17 PASS / 0 FAIL, and 9/10
normalized hashes were identical. The sole hash difference is ASan allocator
shadow-byte rows in `norm-vuln-long.log`; every non-shadow line, including
the fault, `WRITE of size 1`, the `add_slc`/`process_slc`/`do_opt_slc` frames
and 0 bytes past `slcbuf`, is byte-identical. Three extra vuln-50 races
aborted with the same fault; fixed 2.8 stayed clean at 50/100/200 triplets.

Three measured boundaries bound the claim further:

- At 34 triplets the first ASan global overflow is `end_slc (slc.c:237)`'s
  `sprintf`, a `WRITE of size 3` at `slcbuf+108`, not `add_slc`; at 35+
  triplets the first fault is the `add_slc` `WRITE of size 1` above. The
  committed 50-triplet claim stands. I reproduced the 34-triplet boundary on
  the pinned ASan 2.7 build locally: `WRITE of size 3`, top faulting frame
  `end_slc:237`, `asan_write1=False`.
- `func=0x12` (valid, `<= NSLC`) at 50 and 200 triplets never faults on the
  vulnerable pin; `func=0x13` and `0x42` do, while `func=0xff` needs more
  triplets because `add_slc` doubles IAC bytes (`slc.c:166-173`). The source
  binds the boundary: `process_slc (slc.c:262-265)` sends `func > NSLC`
  straight to `add_slc(func, SLC_NOSUPPORT, 0)`, while valid functions reach
  the state-equality early return at `:300-302` after the first request, so
  repeated valid flag/val bytes cannot accumulate into the overflow. My
  local 50-triplet probe on plain 2.7: `func=0x12` survives,
  `func=0x13` exits -11. This closes the deliberate negative: valid-function
  bytes do not widen the write pattern.
- A witness gdb probe on its plain build at `end_slc` with 50 triplets found
  `slcptr-slcbuf=154` and chosen `0x42` at `+100/+103/+106/+109`, but the
  `slcptr` global's final bytes were `0x00005555555560ba` (`slcbuf+154`,
  canonical): the pointer's own increments overwrite the transient clobber.
  The static `[func,0,0,...]` pattern below is therefore a layout inference,
  not the observed final pointer value.

## Adjacent globals and limits

In the plain 2.7 build `slcbuf` is at `0x22020` and the `slcptr` global at
`0x22090`: four bytes past the buffer's end, so writes reach it after roughly
36 triplets. In the ASan build sanitizer padding puts `slcptr` 52 bytes past
the end instead. The plain 100-triplet probe segfaults.

The bytes a static layout map assigns to the four bytes at the `slcptr`
address are `[func36, 0, 0, func37, 0, 0, func38, 0]`. On little-endian such
a pattern cannot form a canonical userspace pointer, but the witness's gdb
observation above shows the runtime final `slcptr` is canonical
(`slcbuf+154`): pointer increments overwrite the transient clobber. No
attacker-chosen pointer, chosen absolute write, marker execution, command or
rung 5 was observed or attempted. This is consistent with, but does not
prove, the finder's published doubt about exploitability on 64-bit systems.

## Grade and reproduction

Rung 1/2: deterministic wire trigger and real-process crash, with fixed-build
and short-input controls. Rung 3: natural ASan global-buffer-overflow in the
pinned writer, now in a live daemon reached over TCP. Rung 4: unchanged from
admission — chosen bytes at a chosen relative offset, direct-call scope; wire
scope adds only a chosen one-in-three octet. Rung 5: no.

Independent witness #1555 (W119) graded W1 ESTABLISHED at this labeled scope:
clean-archive replay of all five cases with clean fixed and short controls,
and no pointer or command. Its three boundary notes are preserved above as
negative results, not grade changes.

`bash lab/frontier/inetutils2shell/wire/run_all.sh` replays all five cases
(17 PASS / 0 FAIL, rc 0). Build steps, exact bytes, raw and normalized traces,
hash manifest and the byte-pattern analysis are in
`lab/frontier/inetutils2shell/wire/WIRE_EVIDENCE.md` and
`lab/frontier/inetutils2shell/WIRE_HASHES.txt`.

What would change this assessment: a witness showing the daemon-side trace is
an artifact, the fixed pin faulting on the same wire input, or a measured
chain from the constrained triplets to a pointer or control-flow value.
