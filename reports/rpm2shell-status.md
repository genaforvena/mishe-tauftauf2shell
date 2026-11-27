# rpm2shell — admitted status (2026-11-26 02:3xZ)

**ADMITTED 02:3xZ by the operator under standing #6 as the 155th declared
target mind.** Window 163 was already live and was adopted, not duplicated.
No hy4-flash route, resolver key or generated wake unit was added: those and
the full-flag sync remain person-reserved. Brief:
`reports/frontier-rpm2shell.md`, harness `lab/frontier/rpm2shell/`, seed wall
`.mishe-tauftauf/walls/rpm2shell.md`, charter
`.mishe-tauftauf/charters/rpm2shell.md`.

Claim: `CVE-2026-95520` (Red Hat, CWE-787, CVSS 3.1 7.1, published
2026-09-29): rpm `iterReadArchiveNext()` allocates one byte for a symlink
whose header size is `UINT64_MAX` and then copies payload bytes past it via
`rpmcpioRead()`. Upstream fix `5bc8705e0`, parent `c36e85503`; no tag at the
provisioned HEAD contains the fix, so upstream version boundaries are UNKNOWN.

Pins: full `lib/rpmfi.cc` from parent and fix, plus byte-exact excerpts of
`rpmfiSetFound`, `rpmfiFound` and `iterReadArchiveNext()` (hashes in
`PROVENANCE.md`). Header `lsize = -1` as int64; `xmalloc(lsize + 1)` wraps to
a 1-byte region; the stand-in `rpmcpioRead()` copies 64 chosen bytes.
GCC and Clang ASan both report `heap-buffer-overflow`, `WRITE of size 64`,
0 bytes after the 1-byte region, in the pinned function. Plain readback:
`CANARY_AFTER=495348452d52504d2121414141414141`. Fixed build rejects the
mismatch (`RET=-15`), safe input is clean (`RET=0`). `run-all.sh`:
28 PASS / 0 FAIL in-tree and from a clean git archive.

Current grade (2026-11-27, superseding the admission-time assessment):
**rung 3 pinned verbatim and real rpm / rung 4 author-layout DEMONSTRATED
in real rpm consumers**. A crafted RPM makes real `rpm2cpio`/`rpm2archive`
write 64 chosen bytes past `xmalloc(0)`'s 1-byte region; plain `rpm -i`
makes chosen bytes decide a live liblua teardown fault, and GDB traces a
chosen qword into a dereferenced GC `next` pointer. A chosen live GCObject
address survives only with ASLR disabled in the default PIE build; a
deliberately non-PIE build lets a fixed `.bss` address be walked under ASLR,
but it is only a terminating object. A loopback wire delivery path is
measured but yields no useful stable target or command. No r5.
The independent witness verdict for the real-consumer lane is UNKNOWN;
W238 established only the earlier synthetic lane. Negative preserved:
GCC 13.3 ASan at `-O1` misses the overflow after inlining; ASan builds use
`-O0`. Full evidence and ceilings: `reports/frontier-rpm2shell.md`.

## Next

1. Done: witness W238 replay ESTABLISHED AS LABELED for the staged synthetic
   lane and operator admission under standing #6.
2. Done: real rpm builds at both pins, crafted package, 64/512/4096-byte
   controlled writes, plain `rpm -i` chosen-byte teardown fault, GDB
   pointer-chain observation and loopback wire delivery, each with
   vulnerable/fixed/safe controls. See the brief and
   `lab/frontier/rpm2shell/PROVENANCE.md`.
3. Open: independent witness replay of the real-consumer lane (verdict
   UNKNOWN). Every low-byte, short-write, metadata, layout and alternate
   consumer hypothesis is closed for these builds; an ASLR-stable live
   target or a live benign command side effect would be needed to move
   beyond the current ceiling. No r5.

## Receipts

- Clean-archive replay 2026-11-26 01:54Z: `git archive 815a1b0a
  lab/frontier/rpm2shell` into `/tmp/w237-rpm-clean`; unmodified
  `run-witness.sh` returned `WITNESS REPLAY PASS`, four pins exact,
  `TOTAL: 28 PASS / 0 FAIL` in-tree and from the clean archive.
- Witness W238 replay 2026-11-26 02:04Z: clean `git archive 815a1b0a`
  (wrapper byte-identical) and in-tree `run-witness.sh` both `WITNESS REPLAY
  PASS`, 28 PASS / 0 FAIL rc 0; raw upstream full-file and excerpt hashes
  match all four pins; GCC 13.3.0 `-O1` ASan negative reproduced (no report,
  `RET=-13`). Verdict ESTABLISHED AS LABELED, no grade change, NO r5;
  detail in `.mishe-tauftauf/artifacts/witness-w238-rpm2shell/detail.md`.
- Window created 2026-11-26T01:55:05Z on the inner tmux socket: index 163,
  session `mishe-tauftauf2shell-current`, panes `%328`/`%329`, `dead=0`,
  captures 700/244 bytes, both non-empty. Registered in
  `.mishe-tauftauf/operator/window-registry.json` (164 windows / 164 unique
  names). Witness W238 replayed ESTABLISHED AS LABELED; operator admission
  02:3xZ under standing #6. No route, resolver key or wake unit added:
  engine config and the full-flag sync stay person-reserved.
- W306 (2026-11-27 02:10Z): unmodified
  `bash lab/frontier/rpm2shell/real/run-real.sh` at HEAD `02808d23` returned
  21 PASS / 0 FAIL (vulnerable ASan `WRITE of size 64`, fixed attack rc 1,
  safe controls rc 0); no real-consumer witness verdict in chat through
  #5998. This status grade and its Next list were reconciled with the brief.
- W307 (2026-11-27 02:2xZ): new tracked
  `real/run-nopie-target.sh` (commit `493f094f`) returned
  `NOPIE_TARGET_PASS=13 NOPIE_TARGET_FAIL=0` rc 0 in-tree and from a clean
  `git archive cd28c444`: fixed `.bss` chosen address visited by liblua
  under ASLR, 10/10 plain rc 1 versus 5/5 A-filler rc 139, fixed ASan rc 1
  clean. Additive rung-4 mechanics only; no command, no grade change.
