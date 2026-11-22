# inetutils2shell — CVE-2026-32746 telnetd SLC overflow

Status W1, 2026-11-22 ~18:23Z. Admitted under standing approval #6; this
report records the first bounded step after admission: the overflow is now
observed in a real telnetd process reached by attacker-supplied TCP bytes on
a plant-started 127.0.0.1 listener, with fixed-build and short-input controls.

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

## Adjacent globals and limits

In the plain 2.7 build `slcbuf` is at `0x22020` and the `slcptr` global at
`0x22090`: four bytes past the buffer's end, so writes reach it after roughly
36 triplets. In the ASan build sanitizer padding puts `slcptr` 52 bytes past
the end instead. The plain 100-triplet probe segfaults.

The bytes written at `slcptr` in the plain layout are
`[func36, 0, 0, func37, 0, 0, func38, 0]`. On little-endian that pattern
cannot form a canonical userspace pointer: bytes 1, 2, 4, 5 and 7 stay zero
and the rest are function octets. No pointer control, chosen absolute write,
marker execution, command or rung 5 was observed or attempted. This is
consistent with, but does not prove, the finder's published doubt about
exploitability on 64-bit systems.

## Grade and reproduction

Rung 1/2: deterministic wire trigger and real-process crash, with fixed-build
and short-input controls. Rung 3: natural ASan global-buffer-overflow in the
pinned writer, now in a live daemon reached over TCP. Rung 4: unchanged from
admission — chosen bytes at a chosen relative offset, direct-call scope; wire
scope adds only a chosen one-in-three octet. Rung 5: no.

`bash lab/frontier/inetutils2shell/wire/run_all.sh` replays all five cases
(17 PASS / 0 FAIL, rc 0). Build steps, exact bytes, raw and normalized traces,
hash manifest and the byte-pattern analysis are in
`lab/frontier/inetutils2shell/wire/WIRE_EVIDENCE.md` and
`lab/frontier/inetutils2shell/WIRE_HASHES.txt`.

What would change this assessment: a witness showing the daemon-side trace is
an artifact, the fixed pin faulting on the same wire input, or a measured
chain from the constrained triplets to a pointer or control-flow value.
