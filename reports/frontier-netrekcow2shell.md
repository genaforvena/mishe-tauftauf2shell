# frontier-netrekcow2shell — SP_S_MESSAGE stack OOB WRITE (CVE-2026-121969)

## Claim source and scope

- NVD CVE-2026-121969: "netrek-client-cow through 3.3.3 contains a
  stack-based buffer overflow vulnerability in `handleSMessage()` in `short.c`
  that allows malicious servers to overflow a 100-byte stack buffer by sending
  oversized `SP_S_MESSAGE` packets. A malicious Netrek server or
  man-in-the-middle on the plaintext TCP connection can send overlong or
  unterminated message bodies to write server-controlled bytes onto the stack
  and crash the client."
  https://nvd.nist.gov/vuln/detail/CVE-2026-121969
- Upstream anchors: source pin
  https://github.com/quozl/netrek-client-cow/blob/3.3.3/short.c#L949,
  issue https://github.com/quozl/netrek-client-cow/issues/11, and fix commit
  `fb322e74abee3b0b76a9c5a31df6aab5585d3127` ("Fix SIGSEGVs", 2026-11-04).
  `git ls-remote --tags` gives `3.3.3 = 9395a07b0b25c036a3f706b188a38656adbde983`
  and `3.3.4 = 40616ada0630f9051575c03232dea5886ee93805`; the released 3.3.4
  hunk is byte-identical to the fix commit. No GHSA ID was found for this CVE.
- The server/man-in-the-middle and crash claims are advisory prose, not local
  results. This lab used no socket, pcap, live client or external system.

## Source-bound mechanism

Verbatim 3.3.3 `short.c:914-951` declares `char buf[100]` and `char addrbuf[9]`.
For `m_from == 255` it writes `"GOD->"` into `addrbuf`; the default flag branch
appends `"ALL"`. Then `short.c:949` executes

```c
sprintf(buf, "%-9s%s", addrbuf, &packet->mesg);
```

with no bound on the message body and no NUL guarantee. The pinned
`packets.h:1170-1181` layout has `unsigned char length` at offset 4,
`char mesg` at offset 5 and 78 declared padding bytes after it (79 bytes
including `mesg` through the 84-byte struct's end).
`length` is attacker-supplied. A body with no NUL in the struct makes
`sprintf` read past the declared packet and write an unbounded string into the
100-byte stack buffer.

Released fix 3.3.4 `short.c:916-965` replaces that line with a length-derived
`body_max = packet->length - offsetof(struct mesg_s_spacket, mesg)`,
`strnlen(&packet->mesg, body_max)`, a clamp to `sizeof(body) - 1` and
`snprintf(buf, sizeof(buf), "%-9s%s", addrbuf, body)`; it also bounds the
`m_recpt >= MAXPLAYER` index in the MINDIV branch. This is a missing-bounds
fix, not a documented feature.

## Local experiment (rung 3 observed, rung 4 PARTIAL)

`lab/frontier/netrekcow2shell/run-all.sh` pins three codeload archives (3.3.3,
3.3.4, fix commit), the upstream patch and the driver by SHA-256; extracts the
verbatim `handleSMessage` bodies (`short.c:914-951` / `:916-965`) and
`struct mesg_s_spacket` (`packets.h:1170-1181`) with `#line` directives; then
builds vulnerable 3.3.3 and fixed 3.3.4 with GCC and Clang under ASan,
recoverable ASan and plain modes. The driver casts a 256-byte protocol-shaped
frame to the pinned struct; it supplies only the stubs the verbatim function
needs (`players`, `me`, `teamlet`, `shipnos`, `teamshort`, `debug`, `dmessage`).

Observed with runner sha256
`52078f004e10bc89c0faa96c8755287c7afd6adc92f1c123e7697b5ce1799288`:
**RESULT PASS=32 FAIL=0, rc 0** (author run 2026-11-26 10:41:46Z). Vulnerable
GCC+Clang ASan: `stack-buffer-overflow`, `WRITE of size 130`, frame
`handleSMessage ... short.c:949` past `buf[100]` (line 916). GCC's frame
describes `buf` at `[80, 180)` with "Memory access at offset 180 overflows
this variable"; Clang's puts it at `[32, 132)` and reports offset 132
partially underflowing `addrbuf`. Recoverable ASan
(`halt_on_error=0`) observes `outlen=129` and chosen bytes
`b99=41 b100=4d b101=41 b102=52 b103=4b b128=42 b129=00`: the server-chosen
`M`, `A`, `R`, `K` land at buffer offsets 100..103. Unprotected plain attack
runs fault with `rc=139`; safe frames (`outlen=14`) are clean on both tags;
fixed attack frames are clean with `outlen=99`. Full pins, hashes and
preserved negatives are in `lab/frontier/netrekcow2shell/PROVENANCE.md`.

Grade: **rung 3 verbatim / rung 4 PARTIAL**. ASan confirms a deterministic
30-byte stack overflow driven by server-controlled bytes at the pinned sink,
and chosen bytes are observed at chosen offsets past the 100-byte buffer. The
byte capture is in ASan's **poisoned redzone**, not a named adjacent object;
no pointer, control-flow, live-wire, command or r5 result exists. The
advisory's "crash the client" is consistent with the plain `rc=139`, but that
is a local harness crash, not a demonstrated remote impact.

## Author clean-archive replay (W261, 2026-11-26 10:45:33Z)

Unmodified `run-all.sh` sha256 `52078f00…1799288` was replayed from
`git archive f0672f0d` into
`.mishe-tauftauf/replays/netrekcow2shell-w261/`. The generated includes and
evidence were deleted, the three codeload archives were fetched fresh by tag
and commit SHA, and the runner was then invoked unmodified: rc 0,
**RESULT PASS=32 FAIL=0** (10:45:16Z–10:45:33Z), runner hash unchanged. Every
pin, both start-line assertions, the fix-commit/release hunk identity check
and all compiler-mode observations held. Console:
`.mishe-tauftauf/replays/netrekcow2shell-w261/lab/frontier/netrekcow2shell/evidence/replay-console.log`.
This is an author replay, not independent acceptance.

## Witness verdict (W262, 2026-11-26 10:48Z, #5245)

**ESTABLISHED AS LABELED** at the rung 3 verbatim / rung 4 PARTIAL scope; no
contradiction, no grade change, **NO r5**. Witness checked the canonical
runner hash `52078f00…1799288` in the worktree, at `f0672f0d` and in a clean
`git archive f0672f0d` subtree, deleted all archived evidence logs and four
generated `.inc` files, re-fetched the three codeload archives fresh by tag
and commit SHA, then ran the unmodified wrapper: rc 0, `RESULT PASS=32 FAIL=0`
in 4.58 s (10:48:20Z–10:48:24Z). All 32 checks held: eight input/body pins,
both start lines 914/916, the 3.3.4/fix-commit hunk-identity check, both
verbatim marker checks, ten builds and all compiler-mode observations. Fresh
GCC and Clang logs show `WRITE of size 130` at `short.c:949` past `buf[100]`;
the recoverable runs capture `outlen=129` and `M/A/R/K` at buffer offsets
100..103 in ASan poison, fixed and safe frames are clean (`outlen=99`/`14`),
and plain vulnerable attacks fault (`rc=139`). No named adjacent object,
pointer, live wire, command or r5. Two wording corrections from this replay:
the `[80,180)` frame description is GCC-specific (Clang reports `[32,132)`
and a partial underflow of `addrbuf`), and the struct declares 78 padding
bytes after `mesg`, not 79. Detail:
`.mishe-tauftauf/artifacts/witness-w262-netrekcow2shell/detail.md`.

## Cheapest next rung-moving experiment

Wire the pinned `handleSMessage` into the real short-packet receive path for a
loopback-only Netrek client/server pair and replay the same frame over TCP,
comparing 3.3.3 crash with 3.3.4 rejection. For rung 4 specifically, arrange
a plain build where the overflow reaches a named adjacent stack object (or a
saved pointer) rather than ASan poison; measure the actual stack layout first
instead of assuming one. Would also change the assessment: a fixed-tag ASan
report, a witness counterexample, or observed pointer/control-flow influence.
