# Frontier brief — Kermit2Shell (C-Kermit, CVE-2026-129126 / GHSA-c5px-7h4c-gj8p)

Status: **frontier find, UNADMITTED** (research only; operator owns admission).
Brief and harness written 2026-11-21T10:30Z. Harness `lab/frontier/kermit2shell/`.

## Verified ground truth (primary sources, fetched 2026-11-21)

- CVE record `CVE-2026-129126` (CNA VulnCheck, published 2026-11-13, updated
  2026-11-16; pin `6c43f2b7…`). Title: **C-Kermit before 11.1.515 heap buffer
  overflow via `putsrv()` packet decoding**, CWE-122. Affected `0` up to
  (excluding) `11.1.515`, package `pkg:github/OpenKermit/ckermit`.
  CVSS 4.0 `9.2 CRITICAL`
  (`AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`), CVSS 3.1 `8.1`.
- Vendor advisory `GHSA-c5px-7h4c-gj8p` (pin `96477695…`): malicious peers
  write past `srvcmd` by sending crafted packets; **Kermit repeat-count
  compression** in server-command, GET or file-header packets yields
  attacker-chosen bytes beyond the heap buffer on servers or receiving
  instances.
- Fix commit `37e54720779237897bc6887efac42fe138817897` (2026-10-25, pin
  `2f25c8d7…`), titled "Bound the server command buffer in putsrv()". It adds
  `if (srvptr - srvcmd >= srvcmdlen) return(-1);` in `putsrv()`, changes non-
  DYNAMIC `srvcmdlen` from `0` to `MAXRP+3`, and propagates `-1` from
  `decode()` in `ckcpro.w` (`<serve>G`, REMOTE, `sgetinit()`) and `rcvfil()`.
  Changelog says the bug dates from C-Kermit 3.0 (1984). Release tag
  `v11.1.515` is the fixed version; `v11.0.514` is the pinned vulnerable tag.
- Claimed primitive: one crafted packet whose repeat-compressed data decodes
  to more characters than `srvcmd` holds, writing attacker-chosen bytes past
  the buffer. Network-facing server/receiver, pre-auth. Treat advisory prose
  (including RCE claims) as claims to reproduce.

## Source-bound mechanism (pinned bytes)

Pins and hashes in `lab/frontier/kermit2shell/PROVENANCE.md`. Verbatim:

- `ckcfns.c.vuln:461-462`:
  `*srvptr++ = c;` then `*srvptr = '\0';` — no bound on `srvptr - srvcmd`.
- `ckcfns.c.fixed` `putsrv()` adds the `srvcmdlen` check before both writes.
- `ckcker.h.vuln:366`: `#define MAXRP 9024`; `ckcmai.c.vuln:1003`:
  `srvcmdbuf[MAXRP+4]`. Repeat-count decode at `ckcfns.c.vuln:1357-1359`,
  `:1405`, `:1420`: `rpt = xunchar(*xdbuf++)` then `rpt` calls to `putsrv(a)`
  — a three-byte wire triplet (`#`, count, data) can emit up to 94 chosen
  bytes, so a packet far shorter than the buffer can overflow it many times.
- A different, earlier C-Kermit issue is not conflated here; only `putsrv()`
  boundedness is exercised.

## Local harness and observed rungs

`gen_driver.py` verifies every pin hash, extracts both `putsrv()` bodies
verbatim under `#line`, and aborts on drift. `./run.sh` builds ASan and plain
drivers and writes a normalized trace (ASan pid/address/path text excluded).
Full command: `cd lab/frontier/kermit2shell && ./run.sh out`.
Latest: **18 PASS / 0 FAIL**, trace
`sha256=f74a088605aba49a48108705fafe151d61d283c04e248836a81f6ca8e4978cc5`.

- **Rung 1 — reproducible trigger.** Vulnerable tight build, 98 repeat
  triplets × 94 = 9212 decoded chars into an exact `MAXRP+1 = 9025`-byte
  buffer: deterministic ASan abort; exactly 9024 chars is clean, one more
  triplet (9118) faults.
- **Rung 2 — accounting failure.** `emitted=9212 srvcmdlen=9024 oob=188`,
  `decode_rc=0`: the decoder reports success while 188 characters were
  written past the command buffer. Fixed build returns `decode_rc=-1` at
  `first_reject=9024` with `oob=0`.
- **Rung 3 — ASan-confirmed corruption.** `heap-buffer-overflow`,
  `WRITE of size 1`, frame `putsrv pins/ckcfns.c.vuln:461`, `0 bytes after
  9025-byte region`. Fixed and benign builds are clean.
- **Rung 4 — INSTRUMENTED.** With a 1 MiB zeroed collaborator as the command
  buffer, chosen `0x5a` appears at offsets 9024–9211 and `0x41` reproduces
  the same offsets (pattern differential); benign decode (9024 chars) writes
  zero bytes; a guard page faults. No pointer, return address, function
  pointer, allocator metadata or control-flow diversion was observed or
  attempted — collaborator/guard pages are instrumentation.

## Feasibility assessment

High tractability: named function, explicit fix commit, explicit version
range, a repeat-count primitive with attacker-chosen bytes, and a small C
source file to pin. The harness proves pinned C logic in a synthetic frame,
not a built `wermit` server; real packet-length limits, `xunchar()` encoding
limits, DYNAMIC vs static buffer allocation and live-daemon reachability are
UNKNOWN here. Status: **rungs 1/2/3 established locally, rung 4
INSTRUMENTED**. Cheapest next experiment: build vulnerable `v11.0.514`
`wermit` with ASan, start a loopback Kermit server, send a server-command
packet with `set send packet-length 4000` and repeat-compressed payload, and
capture the daemon ASan frame at `putsrv`, then repeat against `v11.1.515`.
