# Frontier brief — Synchronet2Shell (CVE-2026-133646)

Status: **locally staged, rungs 1–4 by direct call; candidate, not admitted.**
Brief authored 2026-11-24 in wake W194. Lab: `lab/frontier/synchronet2shell/`.

## Claim ground truth (provisioning, never a probe)

- CVE-2026-133646, INCIBE-2026-937, published 2026-11-23 by INCIBE-CERT
  (<https://www.incibe.es/en/incibe-cert/notices/aviso/out-bounds-write-synchronet-bbs-synchronet>).
  CNA text: Synchronet BBS 3.20b–3.21e with the SSH service enabled; `answer()`
  calls `cryptGetAttributeString()` without limiting the copy to the destination
  size; 41 bytes of the destination are used; an unauthenticated remote client
  can send a TERM value up to 64 bytes and overwrite adjacent fields of the
  session object, blocking connection threads and enabling socket-exhaustion DoS.
  CVSS 4.0 8.7 `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H` — **availability only**,
  no RCE claim. NVD record is `Deferred`, exploitation metadata `none`.
- Fix: upstream commit `cb6d77dbca0d24fbffc2154a8437113196582810` ("Fix bounds
  when reading the SSH terminal type", author Antonio Rodriguez, committer Rob
  Swindell, 2026-11-19), parent `42f586d70792e46b4934176976bc7949b312dede`.
  One file, `src/sbbs3/answer.cpp`, +6/−6. Advisory recommends 3.22 build B or
  later, or a 3.22a build dated after 2026-11-19. The upstream GitLab commit page
  requires sign-in; the **GitHub mirror** `SynchronetBBS/sbbs` carries the same
  commit and was used for pinned source (hashes in `PINS.sha256`).
- Class fit: a network-facing BBS server (SSH service), unauthenticated wire
  trigger by claim. No language runtime. Ranked above 2026-11-23/24 alternatives
  (LibreCAD DXF, FontForge PCF, LibRaw xtrans, Contiki-NG MPL) because those are
  desktop/embedded parsers with no server control path, and above the 11/24
  CivetWeb HPACK item (already owned, out-of-bounds *read*).

## Source-bound mechanism (pinned bytes, not advisory prose)

- Vulnerable `src/sbbs3/answer.cpp` at parent `42f586d7` lines 542–548:
  `l = 0; cryptGetAttributeString(ssh_session, CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL,
  terminal, &l)`, then only a NUL terminator is clamped with
  `terminal[sizeof(terminal)-1] = 0`. The copy happens inside the callee.
- Fix `cb6d77dbca` lines 542–549 replaces it with
  `get_binary_crypt_attribute(...)` + `SAFECOPY(terminal, ssh_terminal)` and
  `free_crypt_attrstr(...)`, with the source comment "cryptGetAttributeString()
  does not take a destination size."
- Why the callee overflows: pinned cryptlib `cryptapi.c:2649-2710` sets
  `cmd.strArgLen[0] = RETURN_VALUE(MAX_ATTRIBUTE_SIZE)` at line 2685 and dispatches
  `COMMAND_GETATTRIBUTE` with `cmd.strArg[0] = value`; the caller's array size is
  never passed. The pinned fixed helper `ssl.c:34-61` first queries the length
  with a NULL destination, then allocates `len+1` — proof that the caller cannot
  rely on the one-call form.
- Destination layout: pinned `telnet.h:109` defines
  `TELNET_TERM_MAXLEN 40`; pinned `sbbs.h:702-705` declares
  `char terminal[TELNET_TERM_MAXLEN+1]`, then `uint line_delay`, `uint console`,
  `char wordwrap[TERM_COLS_MAX+1]` (`sbbsdefs.h:644` = 999). With x86-64
  alignment the fields land at offsets 0..40, 44..47, 48..51 and 52..1051:
  bytes 41..43 are intra-object padding, then 64 attacker bytes reach 23 bytes
  into the session's adjacent fields.

## Local evidence (direct call into the verbatim pinned statements)

`harness/gen.sh` extracts the vulnerable 543–549, fixed 542–549 and helper
34–61 lines from the pinned files into `.inc` files — the harness never retypes
the copy logic. `harness/run-all.sh` rebuilds g++/clang++ ASan and plain variants
offline and checks nine cases: **9 PASS / 0 FAIL**, `evidence.log` sha256
`9ed3b328ccc0d59a45ebeda9cf51053c7fafc28627e6d574d641914c9403a24e`.

| Rung | Observed | Case |
|---|---|---|
| 1 — trigger | 64-byte TERM supplied to the one-call attribute getter, 41-byte destination | `asan-vuln-g++-term64` |
| 2 — state failure | 23 bytes written past the destination field into padding and three adjacent fields | `plain-vuln-*-term64` |
| 3 — corruption | gcc and clang ASan `stack-buffer-overflow`, `WRITE of size 64`, object `[48,89) 's'` overflows at offset 89, frame `cryptGetAttributeString` ← `vuln.inc:1` | `asan-vuln-{g++,clang}-term64` |
| 3b — control | 40-byte TERM is ASan-clean and leaves all adjacent fields zero | `asan-vuln-g++-term40`, `plain-vuln-g++-term40` |
| 4 — scoped impact | plain builds place chosen `4d 49 53 48` ("MISH") at `line_delay` (44..47), `4f 4f 2d 45` ("E-OO") at `console` (48..51) and `54 41 55 46 54 41 55 46` ("TAUFTAUF") at `wordwrap[0..7]` (52..59) | `plain-vuln-{g++,clang}-term64` |
| fixed control | `cb6d77dbca` hunk + pinned helper: `FIXED_CONTROL_OK`, adjacent fields zero, no ASan report (gcc and clang) | `asan-fixed-*`, `plain-fixed-g++` |

Rung 3 uses a `REDZONE_MODEL` struct containing only the 41-byte destination, so
ASan sees the field boundary; rung 4 uses the full layout from `sbbs.h:702-705`.
Both run the same verbatim vulnerable statement. This distinction is part of the
claim, not a hidden detail.

## Ceiling and cheapest next experiment

Not measured: a real Synchronet build, a real `sbbs_t` object, a real SSH
handshake or SSH channel-request TERM wire, the claimed thread-block/DoS, any
pointer/IP control, command execution, witness replay, or rung 5. The TERM
length cap of 64 and the exact cryptlib attribute semantics on the shipped
build are advisory/source claims; the harness stub reproduces the documented
no-size contract (`cryptapi.c:2685`) rather than linking cryptlib. No claim that
the adjacent-field overwrite yields code execution: the advisory's own impact
vector is availability-only (`VC:N/VI:N`).

`gdb.txt` (sha256 `968fa2093607c70425343fe569fe91ee7bc467d7077dc52ff4914cd24691f128`)
is a batch gdb transcript of the same plain vulnerable binary at the statement
after the copy: `&s.terminal=0x…dd20`, `&s.line_delay=…dd4c` (offset 44),
`&s.console=…dd50` (48), `&s.wordwrap=…dd54` (52), with `4d 49 53 48` at
offsets 44..47, `45 2d 4f 4f` at 48..51 and `54 41 55 46` twice at 52..59.

`REPLAY.md` records an author clean `git archive e5f43ad` replay: 9 PASS /
0 FAIL, normalized trace `66d20f8…414bdd8` identical to the author tree. Raw
hashes differ only in PIDs, ASLR addresses, timestamps, checkout paths and
build ids. Author replay is not witness acceptance.

Cheapest rung-raising step: build `sbbs3` from the pinned parent tree against
the platform cryptlib, instrument `answer()`'s TERM path with ASan, and drive a
loopback SSH client with an oversized TERM; stop at the first measured layer and
keep every negative. The 64-byte TERM and the fixed-commit control are already
the differential. Admission and a dedicated target window belong to the
operator; this brief and the lab are the handoff artifacts.
