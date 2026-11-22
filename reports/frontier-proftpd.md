# Frontier brief — ProFTPD mod_rewrite `int:utf8trans` BSS write (rung 4 chosen-pointer marker under ASLR-off condition)

**Status (2026-11-22 00:1xZ, W95; witness W99 #1207): RUNG 1–4
witness-ESTABLISHED on the real 1.3.9d daemon over a loopback FTP wire, with
paired safe-length and fixed-version controls. A 1030-code-point key redirects
the static `substr` pointer in `rewrite_parse_map_str()` to a chosen `.rodata`
string; the real parser consumes it and the session survives. Rung 4 is
conditioned on ASLR disabled (`setarch -R`) and a non-default `mod_rewrite`
config. The proftpd2shell mind later observed the same marker pre-login under
a `%m USER` condition (witness replay pending) and a SIGSEGV/no-marker negative
with ASLR on. Rung 5 NOT attempted. ADMITTED 2026-11-22 ~00:1xZ by the operator under
standing approval #6 as `proftpd2shell` (window 72; route 67).**

## Verified ground truth

- CVE-2026-119146 / GHSA-wj68-6748-262r, published 2026-10-30. CWE-120.
  Advisory: <https://github.com/advisories/GHSA-wj68-6748-262r>. Affected
  `< 1.3.9e` and `< 1.3.10rc5`; fixed in 1.3.9e and 1.3.10rc5. CVSS 3.1 5.6
  (`AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L`), CVSS 4.0 6.3; the vendor-adjacent
  research rates the authenticated crash 7.5 with `A:H` only.
- Fix commit `502d280b8d0ef72e44c6dd0a35a9405af0a1e301`, "Guard against
  overly-long keys overflowing buffers when the 'utf8trans' builtin
  `RewriteMap` type is used", touching only `contrib/mod_rewrite.c`.
- Git-ref API re-verified this wake: `v1.3.9d` = `f59f248e26bdfa514443e42bf72a145641df635d`
  (affected), `v1.3.9e` = `fc3f908a0d07fa3b17fbe1e3054b7520806bc75a` (fixed),
  `v1.3.10rc5` = `23803950119af8926907c5208d3ca6c92881c64a`.
- Primary research read as a claim, not fact:
  <https://abraxaslabs.tech/research/proftpd-rewrite-utf8trans> and its PoC
  repo `abraxas/proftpd-rewrite-utf8trans` (loopback client, `lab/conf/proftpd.conf`).
  It reports the same ASan signature and classifies the row Crash / Not RCE.
- Pins, fix patch and SHA256SUMS are in `lab/frontier/proftpd2shell/src/`
  (3/3 OK at 23:54Z): tarball SHAs
  `68b094b1c57c775ad00ef469e9a87783dbbf31a85f98f48faf60becc2e84e4ec` (1.3.9d),
  `7db91f229f8c3ad18e233f38a3c1749bd11bf92e1079b6c7f86e51a3fcfce5eb` (1.3.9e),
  patch `07cc6b25e404258daa3f2430b93999cda99412f4af967c8590be01f045e00d79`.

## Source-bound mechanism

`rewrite_map_int_utf8trans()` (pinned `contrib/mod_rewrite.c:2037`) declares two
function-scope `static` buffers, `utf8_val[PR_TUNABLE_BUFFER_SIZE]` (bytes) and
`ucs4_longs[PR_TUNABLE_BUFFER_SIZE]` (unsigned longs); the compiled build uses
1024 slots. The pinned function never caps `strlen(key)`. Two writes follow:

1. `rewrite_utf8_to_ucs4(ucs4_longs, strlen(key), key)` writes one 8-byte
   UCS-4 code point per input UTF-8 character into `ucs4_longs[]`. For ASCII
   `'A'` the stored value is `0x41`, so each 8-byte write is
   `41 00 00 00 00 00 00 00` on little-endian. Overflow begins at index 1024.
2. `for (i = 0; i < ucs4strlen; i++) utf8_val[i] = (unsigned char) ucs4_longs[i]`
   writes **one byte per code point** at consecutive byte offsets. Its low byte
   is fully attacker-chosen (0–255 via UTF-8 encoding), so overflowing this
   buffer yields a byte-granular chosen write into the globals that follow it.

The fix adds `if (key_len >= sizeof(utf8_val)) return NULL;` before either loop
and moves the length computation ahead of the NULL/empty check.

## Local evidence (loopback only; no external probes)

Non-root standalone daemon built from the pinned 1.3.9d tree with
`--with-modules=mod_rewrite --disable-shared`; server binds 127.0.0.1:21874,
config `lab/frontier/proftpd2shell/wire/etc/proftpd.conf`, clients
`wire/client.py` and `wire/client2.py`, runners `wire/run-trigger.sh` and
`wire/run-bounded.sh`. Auth is a local `mod_auth_file.c` file. Non-root cannot
chroot, so `DefaultRoot` is absent (a config error fixed this wake, preserved
in the runner); `setuid/setgid` no-ops are logged but non-fatal.

### Rung 1–3, ASan build (`proftpd-vuln-asan`)

- `clang -g -O0 -fsanitize=address`, real daemon, `RewriteCondition %m STOR`
  and `RewriteRule ^(.*) ${u8:$1}` with `RewriteMap u8 int:utf8trans`.
- 2048-byte `STOR` key: login OK, session child dies, `NOOP` gets EOF. ASan
  reports `global-buffer-overflow`, **`WRITE of size 8`** at
  `rewrite_utf8_to_ucs4 modules/mod_rewrite.c:1670:19`, via
  `rewrite_map_int_utf8trans:2052`, `rewrite_subst_maps_int:1566`,
  `rewrite_subst:961`, `rewrite_fixup:2858`; "0 bytes after global variable
  `rewrite_map_int_utf8trans.ucs4_longs` ... of size 8192". The daemon parent
  stays up; a fresh login succeeds.
- 200-byte control in the same run: `STOR_OK`, `NOOP=200 NOOP command
  successful`, no ASan log.
- Rung 1 ESTABLISHED (deterministic wire trigger); rung 3 ESTABLISHED (ASan
  corruption on the real parser, with a safe-length control; the fixed-version
  control was supplied independently by witness W99 — see Witness replay).

### Non-ASan layout and chosen-byte pointer write (`proftpd-vuln-plain`, `proftpd-instr`)

`nm -n -S` on the plain build (order is authoritative for this binary):

| Symbol | Address | Size |
|---|---|---|
| `ucs4_longs.0` | `0x104920` | `0x2000` (1024 × 8) |
| `utf8_val.1` | `0x106920` | `0x400` (1024) |
| `substr.2` | `0x106d20` | `0x8` |
| `rewrite_rule_matches` | `0x106d40` | `0x58` (`match_string` at +0) |
| `rewrite_cond_matches` | `0x106da0` | `0x58` (`match_string` at +0) |
| `rewrite_conds` | `0x106df8` | `0x8` |
| `rewrite_nrules` | `0x106e00` | `0x4` |
| `rewrite_cond_pool` | `0x106e08` | `0x8` |
| `rewrite_pool` | `0x106e10` | `0x8` |
| `rewrite_logfile` | `0x106e18` | `0x8` |
| `rewrite_engine` | `0x106e20` | `0x1` |

`rewrite_match_t` is `struct { char *match_string; regmatch_t match_groups[10]; }`,
so the first eight bytes of each match struct are a live pointer. `utf8_val[i]`
lands on `rewrite_rule_matches.match_string` at i = 1056–1063 and on
`rewrite_cond_matches.match_string` at i = 1152–1159. The `ucs4_longs` 8-byte
overflow lands on `rewrite_rule_matches` at index 1156 and on `rewrite_logfile`
at index ~1183.

A temporary instrumentation block (added after the `utf8_val` write loop in a
gitignored source copy; original preserved as `src/mod_rewrite.c.orig`, the
instrumented copy as `src/mod_rewrite.c.instr`) dumps the first eight bytes of
both match structs without dereferencing them. Observed over the loopback wire:

| Key length | `rewrite_rule_matches.match_string` bytes | `rewrite_cond_matches.match_string` bytes | Outcome |
|---|---|---|---|
| 200 | `a80e0217d1550000` (valid heap ptr `0x000055d117020ea8`) | `a0510217d1550000` (`0x000055d1170251a0`) | session clean |
| 1060 | `41414141885d0000` = `0x00005d8841414141` | `d0ef6bae885d0000` | SIGSEGV, pr_log_vwritefile |
| 1130 | `4141414141414141` | `1020ce8b535c0000` | SIGSEGV, pr_log_vwritefile |
| 2048 | `4141414141414141` | `4141414141414141` | SIGSEGV, pr_log_vwritefile |

This is byte-granular chosen control of two live pointer fields, including a
partial 1060-byte overwrite that preserves the PIE high 32 bits. Those
cumulative-length cases crash; `addr2line` on the plain build resolves the
dominant crash frame to `rewrite_parse_map_str` at `mod_rewrite.c:688` — the
static `substr` pointer at utf8_val index 1024–1031, not the match structs.
Rung 2 is observed as cross-request static-state corruption (these fields
persist between commands in the same session).

## Rung 4 — chosen-pointer dereference with a benign marker (ESTABLISHED, ASLR-off condition)

`rewrite_parse_map_str()` (`mod_rewrite.c:671`) keeps a file-static
`char *substr` at `0x106d20`, eight bytes past the end of `utf8_val`; it is
dereferenced on every map substitution (`addr2line` puts the crash frame at
`:688`). The alias structure of the two overlapping loops makes the bytes at
`utf8_val[1024+k]` equal the low byte of code point `8*k`, so a 1030-code-point
key sets the low six bytes of `substr` while its top two zero bytes survive
untouched.

`wire/client4.py` sends 1030 code points whose 0th, 8th, 16th, 24th, 32nd and
40th values are U+00AF, U+01D4, '`', 'U', 'U', 'U' (bytes `af d4 60 55 55 55`).
Under `setarch "$(uname -m)" -R` the PIE base is `0x555555554000` and this makes
`substr = 0x000055555560d4af`, the address of the `.rodata` string
"NOOP command successful" (file offset `0xb94af`). Runner:
`wire/run-marker.sh` with `CLIENT=client4.py`.

Observed at 00:06:40Z on the instrumented plain build (the instrumentation only
dumps the two match structs; it does not alter the write):

- STOR dispatch completes; `RewriteLog` gains the line
  `rewrite_parse_map_str(): parsing 'NOOP command successful'` — the chosen
  string was consumed by the real downstream consumer.
- The session survives: `NOOP=200 NOOP command successful`,
  `PWD=257 "..." is the current directory`, no signal 11.
- The Python client reports `UnicodeDecodeError` decoding the STOR reply (the
  reply echoes a raw 0xaf byte). That is a client-side decoding artifact, not a
  server fault; the server log shows the session closing normally.

This is rung 4 at the stated condition: chosen bytes at chosen offsets, a live
pointer redirected to a chosen address, and an observed benign marker side
effect in the real daemon. Conditions for witness replay: ASLR disabled
(`setarch -R`) so the PIE base and target address are fixed; authenticated
`STOR` (PR:L) with non-default `mod_rewrite` config; plain non-ASan build;
marker is a readable `.rodata` string, not executed code.

## What remains open

- Rung 5 NOT established and NOT attempted: the marker is a string consumed by
  a parser, not command execution. No wire-to-shell path is claimed.
- The fixed-address client4 payload under ASLR-on was observed at 00:24Z to
  kill the session child (SIGSEGV in `pr_vsnprintfl`/`pr_log_vwritefile`) with
  no marker line — a concrete negative for that payload. Other ASLR-on routes
  (leak, brute force, partial low-byte redirect) remain UNKNOWN.
- Unauthenticated pre-login rewriting is no longer wholly UNKNOWN: the
  `rewrite_fixup()` PRE_CMD hook runs on `USER`, and a `%m USER` config variant
  reproduced the marker pre-login at 00:26Z under ASLR-off (PR:N). This mind's
  observation only; witness replay pending. The default lab config still uses
  `%m STOR` after login.
- The fixed 1.3.9e control was pinned and hash-checked but not built locally
  by frontier this wake; witness W99 independently built it and observed
  rejection (see Witness replay). The 200-byte safe-length control is the
  observed frontier-local negative.
- Admission: the operator admitted this as `proftpd2shell` at ~00:1xZ under
  standing approval #6, with window 72 already live; the witness verdict W99
  (#1207) is recorded above. Frontier created the window and seed wall; the
  operator created the charter, route and trigger units. Plant-level next work
  belongs to the `proftpd2shell` mind.

## Witness replay (W99, message #1207, 2026-11-22)

Witness W99 independently replayed all committed claims (87aa93a, 3c527a3,
c754960) using its own builds from the pinned tarballs in /tmp/w99-proftpd,
never frontier binaries: ALL ESTABLISHED at the labeled scope, no refutation.
Rungs 1–3: own `clang -g -O0 -fsanitize=address` build from v1.3.9d, over the
loopback wire with the committed `wire/run-trigger.sh`, produced the 2048-byte
STOR `global-buffer-overflow WRITE of size 8` at `mod_rewrite.c:1670:19` via
:2052/:1566/:961/:2858; the 200-byte control was clean. Rung 4: own v1.3.9d
`gcc -O2` plain build (sha `aae1ec303efe...`, NO instrumentation) under
`setarch x86_64 -R` with the committed `wire/client4.py` produced exactly
`rewrite_parse_map_str(): parsing 'NOOP command successful'` in RewriteLog,
then NOOP=200 and PWD=257. The client-side `UnicodeDecodeError` comes from the
echoed 0xaf byte; the server log is normal. Safe-input control logged
`parsing ''` with no marker. W99 independently checked the alias math with an
overlapping-memory simulation (`utf8_val[1024:1032] = af d4 60 55 55 55 00 00`)
and `strings -t x` put the marker at `.rodata` file offset `b94af`.
Fixed-version control supplied by W99: own v1.3.9e ASan build rejects the
2048-byte key with RewriteLog `length (2048 bytes) exceeds maximum allowed
length (1024 bytes), rejecting`, 550 reply, session alive, no fresh ASan file.
Rung 5 stays UNKNOWN/not attempted; ASLR-on and pre-login reach remain UNKNOWN.

## proftpd2shell mind — replay, ASLR-on negative, pre-login extension (2026-11-22 00:23–00:26Z)

All three observations are on this plant's pinned 1.3.9d `proftpd-instr`
binary over 127.0.0.1, with raw output kept under
`lab/frontier/proftpd2shell/wire/evidence/` and not committed.

**Replay (00:23Z).** `CLIENT=client4.py bash run-marker.sh ../proftpd-instr`
reproduced W99 with no drift: `KEY_CODEPOINTS=1030 KEY_BYTES=1032`,
`NOOP=200 NOOP command successful`, `PWD=257`, `FRONTIER_INSTR
keylen=1032 ucs4strlen=1030`, and RewriteLog
`rewrite_parse_map_str(): parsing 'NOOP command successful'`. Evidence:
`w99-replay-proftpd2shell-20261122T0023Z.txt`.

**ASLR-on negative (00:24Z).** Same client, same config, binary launched
without `setarch -R`: `LOGIN_OK`, then `STOR_SUBSTR_FAIL EOFError`,
`NOOP_FAIL EOFError`, `PWD_FAIL BrokenPipeError`. Server log:
`FRONTIER_INSTR keylen=1032 ... rule=90d883f3d45d0000` (PIE base changed),
stack trace through `pr_vsnprintfl`/`pr_log_vwritefile`, `ProFTPD terminating
(signal 11)`; RewriteLog stops after `maps subst'd pattern: 'STOR'` with no
marker line. This is a concrete failure of the fixed-address payload under
ASLR, not proof that all ASLR-on routes fail. Evidence:
`aslr-on-client4-20261122T0025Z.txt`, `marker-server-aslr-on-20261122T0025Z.out`,
`rewrite-marker-aslr-on-20261122T0025Z.log`.

**Unauthenticated pre-login trigger (00:26Z).** Source check: `rewrite_fixup`
is registered `PRE_CMD, C_ANY` (`mod_rewrite.c:3158`), so it runs on `USER`
before login. Config variant `wire/etc/proftpd-prelogin.conf` uses
`RewriteCondition %m USER` (same map and rule, ports 21884–21890, separate
logs); client `wire/client5-prelogin.py` sends the same 1030-code-point key as
the `USER` argument and sends no `PASS`. Observed with `setarch x86_64 -R`:
banner, `USER` → `501 Login incorrect`, `NOOP` → `200 NOOP command
successful`, `PWD` → `530 Please login with USER and PASS` (correct pre-login
state); the session stayed up. RewriteLog shows the condition evaluated on
`USER` (`condition met`), the map invoked with the 1032-byte key, then
`rewrite_parse_map_str(): parsing 'NOOP command successful'`; no signal 11.
Evidence: `prelogin-marker-20261122T0027Z.txt`, runner `wire/run-prelogin.sh`.
This is rung 4 at a PR:N condition and a non-default `%m USER` config,
ASLR-off; it is this mind's observation only and has NOT been independently
witness-replayed. A `.rodata` string pointer is still not command execution:
rung 5 remains unclaimed, and ASLR-on pre-login reach remains UNKNOWN.
