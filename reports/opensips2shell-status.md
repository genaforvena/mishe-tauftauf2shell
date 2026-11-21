# opensips2shell — status

Admitted 2026-11-21 ~06:2xZ by the operator under standing approval #6 on
frontier's handoff #606 (commits `b4bc31a`, `92a9c15`, `41818af`; brief
`reports/frontier-opensips2shell.md`). Claim source: maintainer advisory
GHSA-5gm5-wj62-p234 (2026-09-28, High 8.6
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H`); no CVE ID visible at fetch
time (UNKNOWN, not asserted). Affected `>=4.0.0,<4.0.2` and
`>=3.6.0,<3.6.9`, patched `4.0.2` and `3.6.9`; upstream fix
`ec24165bc25fa462e08cdb33ee8071f58e166d36`. Claim: unbounded `sprintf` of an
XMPP JID `from` into `buf_from[256]` in `ENC_SIP_URI()` at pinned tag `4.0.1`
`xmpp.h:73-82` / `xmpp.c:280-285`, via an unauthenticated `<message/>` at
`xmpp_server.c:361-382`. Reachability gate: server mode needs
`modparam("xmpp","backend","server")`; the default component backend is not a
raw listener. The advisory claims a reliable receiver crash and RCE only as
possible depending on canary/ASLR/NX. Brief:
[frontier-opensips2shell.md](frontier-opensips2shell.md). Pins and raw URLs:
`lab/frontier/opensips2shell/PROVENANCE.md`.

- Harness: `bash lab/frontier/opensips2shell/run.sh <outdir>` — 26 PASS /
  0 FAIL, `ALL CHECKS PASSED rc 0`, canonical trace SHA-256
  `a69657bb243b83b850b332a4307996f5705d6b0bd6b3cdefbccba022c0c78b06`.
- Operator replay ~06:19Z from a clean `git archive HEAD` extraction of
  `7674a58` into two separate absolute output directories: 26 PASS / 0 FAIL
  and `ALL CHECKS PASSED rc 0` in both, trace
  `sha256=a69657bb243b83b850b332a4307996f5705d6b0bd6b3cdefbccba022c0c78b06`
  — byte-identical between directories and to the brief.
- Rungs 1/2/3 on verbatim pinned upstream lines from tags `4.0.1` and
  `4.0.2`: a 299-byte `from` writes 304 bytes (48 past `buf_from[256]`);
  with `/` at offset 10 the stored length is 14 while the write is still
  303 bytes past the prefix; ASan reports `stack-buffer-overflow`,
  `WRITE of size 304`, frame `xmpp.c:285`. Fixed helper `snprintf`s into a
  1025-byte buffer, guards the length and rejects a 1500-byte JID.
- Rung 4 INSTRUMENTED only: 16 bytes at `buf_from + 256` are byte-identical
  to the attacker pattern from `from[252]` (`CHOSEN_MATCH=1`) in the
  no-canary test frame. No return address, pointer or marker was touched;
  no daemon, socket, XMPP stream, XML parser, shipping stack layout,
  canary, ASLR or NX was exercised.
- UNKNOWN: live OpenSIPS `4.0.1` receiver, `backend=server` listener on
  127.0.0.1, real stanza wire bytes, real stack frame, control-flow impact.
  No security impact beyond the claimed availability crash is demonstrated.

Cheapest next rung: build stock OpenSIPS `4.0.1` with the `xmpp` module under
ASan plus a no-canary build, bind only 127.0.0.1 with `backend=server`, send
one stream header and one `<message from="…299 chosen bytes…">` stanza, and
record the real receiver's report, crash, wire bytes and post-overflow stack.
If chosen bytes reach a saved return address or function pointer, attempt a
benign marker before claiming rung 4; otherwise keep the instrumented label.
Repeat with tag `4.0.2` as the control.
