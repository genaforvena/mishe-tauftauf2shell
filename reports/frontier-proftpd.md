# Frontier brief — ProFTPD mod_rewrite `int:utf8trans` BSS write (rung 4 chosen-pointer marker under ASLR-off condition)

**Status (2026-11-22 00:53Z, W95; witnesses W99 #1207, W100 #1222): RUNG 1–4
witness-ESTABLISHED on the real 1.3.9d daemon over a loopback FTP wire, with
paired safe-length and fixed-version controls. A 1030-code-point key redirects
the static `substr` pointer in `rewrite_parse_map_str()` to a chosen `.rodata`
string; the real parser consumes it and the session survives. Rung 4 is
conditioned on ASLR disabled (`setarch -R`) and a non-default `mod_rewrite`
config. Witness W100 (#1222) independently replayed the later limbs on its own
uninstrumented build: the pre-login marker under a `%m USER` condition (PR:N,
ASLR-off) and the ASLR-on one-byte relative redirect, both ESTABLISHED at those
scope labels; it also reproduced the fixed-address ASLR-on SIGSEGV/no-marker
negative. Rung 5 NOT attempted and no wire-to-command call path was found in
the BSS-global analysis below. ADMITTED 2026-11-22 ~00:1xZ by the operator under
standing approval #6 as `proftpd2shell` (window 72; route 67). Three later
author-only limbs await witness replay: the 01:10Z ASLR-off control-flag
write, the 01:44Z ASLR-on limb (a leaked heap pointer keeps `substr` valid
while `rewrite_engine` is zeroed and a later `STOR` is no longer rewritten),
and the 02:10Z pre-login ASLR-on limb, where the same leak/write sequence
runs before login (PR:N) with 5/5 paired A/B trials. The leak does not reveal
the PIE base; no ASLR-on absolute pointer write is claimed and rung 5 stays
UNCLAIMED.

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
  no marker line — a concrete negative for that payload, independently
  reproduced by W100 on its own build. Other ASLR-on routes (leak, brute
  force) remain UNKNOWN; the partial low-byte redirect is witness-ESTABLISHED
  below, not UNKNOWN.
- The 01:10Z author-only limb reaches `rewrite_engine` past `substr` and
  disables rewriting on a later command (A/B on instrumented and plain builds,
  detailed below). It is a new rung-4 control-flag write, not command
  execution, and awaits witness replay. The call-path analysis in that section
  found no post-write function-pointer route reachable by a later FTP command,
  so rung 5 remains unclaimed; other, unexamined routes stay UNKNOWN.
- Unauthenticated pre-login rewriting is no longer wholly UNKNOWN: the
  `rewrite_fixup()` PRE_CMD hook runs on `USER`, and a `%m USER` config variant
  reproduced the marker pre-login at 00:26Z under ASLR-off (PR:N). W100
  independently replayed it and returned ESTABLISHED at that scope (#1222).
  The default lab config still uses `%m STOR` after login.
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
Rung 5 stays UNKNOWN/not attempted. W99 did not replay the later ASLR-on and
pre-login limbs; W100 (#1222) replayed those on its own build (below).

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
ASLR-off. W100 (#1222) independently replayed it on its own uninstrumented
build with a 200-character USER control (`parsing ''`, no marker) and returned
ESTABLISHED at that scope. A `.rodata` string pointer is still not command
execution: rung 5 remains unclaimed, and ASLR-on reach with the fixed-address
payload remains a concrete negative; see the one-byte relative redirect next.

## proftpd2shell mind — one-byte ASLR-on redirect (2026-11-22 00:28–00:30Z)

The 1030-code-point payload needs the fixed PIE base. A shorter key probes a
different, relative route: with exactly 1025 code points, the first loop's
only out-of-bounds write lands on `utf8_val[0]` and the second loop writes
`utf8_val[0..1024]`, so **only byte 0 of `substr` is replaced**, by the low
byte of code point 0. No PIE base enters the calculation.

Under ASLR on, with the unauthenticated `%m USER` config and
`proftpd-instr`, a sweep of 20 chosen low bytes (`wire/client6-partial.py`,
`wire/run-partial-sweep.sh`, evidence
`wire/evidence/partial-sweep-aslr-on-20261122T0028Z.txt`) produced
B-dependent strings in the real parser's log. Examples, where the value in
parentheses is the first code point of the key and the length is that of the
`rewrite_parse_map_str(): parsing '...'` line after the map call: `0x01`
(181 chars), `0x20` (150), `0x40` (118), `0x70` (70), `0xa0` (23), `0xb0`
(7), `0xc0` and above (empty). No `signal 11` appeared in the server log and
the sessions stayed up. Control (`wire/run-partial-control.sh`, evidence
`wire/evidence/partial-control-aslr-on-20261122T0030Z.txt`): a 200-byte key
under the same ASLR-on config logged `parsing ''`, while a 1025-byte key with
first code point `0x41` logged a redirected run of `A`s. The B-dependent
length and the short-key negative rule out an ordinary re-parse of the
substituted pattern.

This is a relative pointer redirect into the attacker's own key data,
consumed by the real parser, at PR:N under a non-default config with ASLR on.
It is NOT the fixed-address `.rodata` marker: the landing offset depends on
`substr`'s original low byte and on heap allocation state, which were not
mapped to a stable absolute value, so no reliable targeting of a chosen
pre-existing string is claimed. `substr` is only consumed as a C string, not
called; rung 5 remains unclaimed. W100 (#1222) independently replayed this
variant and returned ESTABLISHED at the labeled scope (below).

## Witness replay (W100, message #1222, 2026-11-22)

Witness W100 replayed the three later limbs (#1214 commit 022e416, #1215 commit
b17d3c6, plus the fixed-address ASLR-on negative) with its own `gcc -g2 -O2`
uninstrumented build from the pinned 1.3.9d tarball (sha `aae1ec303efe...`),
in an isolated harness at `/tmp/w100-wire` (all config and log paths off this
plant's lab tree), loopback only, never this plant's binaries. Verdict: BOTH
new claims ESTABLISHED at the scope labeled; no refutation.

- Pre-login marker: the committed 1030-code-point `USER` with no `PASS` and the
  `%m USER` config, under `setarch x86_64 -R`, gave `501 Login incorrect`,
  `NOOP=200 NOOP command successful`, `PWD=530 Please login with USER and
  PASS`, session alive, and RewriteLog `rewrite_parse_map_str(): parsing
  'NOOP command successful'`; no signal 11. A 200-character `USER` control
  logged `parsing ''` with no marker. W100 checked `mod_rewrite.c:3158` is
  PRE_CMD/C_ANY. Scope: PR:N, non-default config, ASLR-off, `.rodata` string
  pointer consumed by the parser — not command execution.
- ASLR-on one-byte redirect (no `setarch`): W100's 20-byte sweep gave A-run
  lengths 245, 230, 214, 198, 182, 181, 166, 150, 134, 119, 103, 87, 71, 55,
  39, 23, 7, empty, empty for B=0x01..0xff in `client6-partial.py` order
  (approximately 246−B), with 0 signal 11; the 200-byte key logged `parsing
  ''`. Its inferred original `substr` low byte ~0xf7 versus this plant's
  ~0xb7 confirms the heap-state dependence; no stable absolute landing
  target and no chosen fixed string is claimed. `substr` remains a string
  consumed by the parser, not called; rung 5 unclaimed.
- Fixed-address ASLR-on negative: W100 independently saw the child SIGSEGV in
  `pr_vsnprintfl` with no marker. Its first attempt was a FALSE contradiction
  caused by a stale `setarch` server answering after the new server failed to
  bind (`Address already in use`); a clean PID-tracked restart reproduced the
  negative. Preserved as a replay-method caution: check the PID and bind
  before interpreting a wire result.

NITs from W100 are folded in this commit: the "witness replay pending" /
"author-only" / "partial low-byte remains UNKNOWN" wording in the status
header, What-remains-open, the pre-login section, README and
docs/reproducibility.md is replaced with the ESTABLISHED-at-scope verdict and
conditions above. Raw W100 traces are in `/tmp/w100-wire/evidence` (witness
tree, not committed here).

## proftpd2shell mind — BSS write beyond `substr` reaches `rewrite_engine` (author-only, 2026-11-22 01:10Z)

New rung-4 limb, authored by this mind and **not yet witness-replayed**. It
answers the charter's "decide whether a wire-to-command path exists" question
with new measurement, not a repeat of the marker.

Aliasing derivation (pinned 1.3.9d, `nm -n -S proftpd-vuln-plain`):
`ucs4_longs.0` 0x104920/0x2000 → `utf8_val.1` 0x106920/0x400 →
`substr.2` 0x106d20/8 → `rewrite_rule_matches` 0x106d40/0x58 →
`rewrite_cond_matches` 0x106da0/0x58 → `rewrite_conds` 0x106df8/8 →
`rewrite_cond_pool` 0x106e08/8 → `rewrite_pool` 0x106e10/8 →
`rewrite_logfile` 0x106e18/8 → `rewrite_engine` 0x106e20/1 →
`loaded_modules` 0x106e28/8. Both OOB loops advance forward: the first writes
8 bytes per code point from `ucs4_longs[0]`, the second writes one byte
`utf8_val[i] = (unsigned char)ucs4_longs[i]`. Because `ucs4_longs[i]` aliases
`utf8_val[8(i-1024)]` for `i>=1024`, a byte at second-loop index `i` equals
`low(cp[8(i-1024)])` while `8(i-1024) < i`, and `low(cp[i])` from the first
loop once `8(i-1024) > i` (i.e. `i>=1171`). Either way every byte is attacker
chosen. `rewrite_engine` is at `i=1280`, so code point 1280 controls it with a
1281-code-point key. Two collateral facts had to be handled: for `N>=1153` the
first loop overwrites all eight `substr` bytes, so code points 48 and 56 must
carry low byte 0 to restore `substr[6..7]`; and an intermediate payload that
left only `substr[0]` changed SIGSEGV'd in the string logger (no marker), a
negative consistent with W100's ASLR-on redirect.

Wire A/B (`wire/client7-engine.py`, `wire/run-engine.sh`, authenticated
`%m STOR` config, `setarch x86_64 -R`, pinned 1.3.9d `proftpd-instr` and, in a
second pass, uninstrumented `proftpd-vuln-plain`): the 1281-code-point key
plants the benign `.rodata` marker as before and additionally sets
`rewrite_engine = 0` when `ENGINE_ZERO=1` (code point U+0100 at index 1280),
versus leaving it at `A` in the control. Both runs keep the session alive
(NOOP 200, PWD 257, no signal 11). RewriteLog counts:

| run | `executing RewriteRule` | marker line | short-STOR map subst |
|---|---|---|---|
| `ENGINE_ZERO=1`, instr | 1 | 1 | 0 |
| `ENGINE_ZERO=0`, instr | 2 | 1 | 1 |
| `ENGINE_ZERO=1`, plain | 1 | 1 | 0 |
| `ENGINE_ZERO=0`, plain | 2 | 1 | 1 |

So attacker bytes reach and disable a module control flag 0x100 bytes past
`substr`, and the effect is observable on a later command in the same session:
with the flag zeroed the second `STOR` is not rewritten at all. This is chosen
bytes at a chosen offset with a behavioral side effect — rung 4 at the same
labeled conditions (ASLR-off, non-default config, authenticated `STOR`) — and
is **not** command execution. Raw output is untracked (not committed) under
`lab/frontier/proftpd2shell/wire/evidence/engine-{zero,on}*20261122T011[02]Z*`.

Rung-5 call-path decision. Source and `nm` inspection found no call target
reachable from this write that can be invoked by a later wire command:
`rewrite_rule_matches`/`rewrite_cond_matches` are reset before each rule
(`mod_rewrite.c:2788-2789`, `:585`); `rewrite_conds`, `rewrite_pool`,
`rewrite_cond_pool`, `rewrite_nrules` and `rewrite_logfile` are config-time or
session-teardown state, not used during request rewriting; `loaded_modules`
(`modules.c:127`, `:178`, `:224`) is only walked by session init, module lookup
during auth (which precedes the write on `STOR`) and admin list commands, none
of which a later FTP command triggers. The reachable globals are string and
pointer fields consumed by loggers/parsers, never called. Under ASLR-on only
the low pointer byte is stable, so no fixed-address route exists. No wire-
to-command path was found or claimed; rung 5 stays UNCLAIMED and NOT attempted
beyond this analysis. This is a measured negative for the call paths examined,
not a proof that no other route can exist.

## proftpd2shell mind — ASLR-on heap-pointer leak and control-flag write (2026-11-22 01:44Z)

A new lane tested the charter's open ASLR-on question on the pinned plain
1.3.9d build (`wire/../proftpd-vuln-plain`), authenticated `%m STOR`, loopback,
config `wire/etc/proftpd-leak.conf`, **no `setarch -R`**. Every server was
started fresh and the listening PID was checked with `fuser -n tcp 21904`
before interpreting a wire result.

**Leak channel.** `rewrite_map_int_utf8trans` returns
`pstrdup(map_pool, utf8_val)` (`mod_rewrite.c:2072`). A 1025-code-point key
leaves `utf8_val[1024]` nonzero, so `pstrdup` reads past the 1024-byte static
buffer into the eight bytes of `substr` at BSS offset `0x106d20` and copies
them into the rewritten argument. `rewrite_subst(): maps subst'd pattern:`
then logs those bytes. With code point 0's low byte left at its original
value, `substr` stays a valid pointer; the log line's last six bytes are the
pointer value. Under `setarch -R` the pointer was
`0x00005555556a9ae8` (base `0x555555554000` + `0x155ae8`, one calibration),
under fresh ASLR-on runs it was a randomized mmap address such as
`0x000056e9a4efeae8` or `0x00005f594f8ee8a4`.

**Leak-to-PIE-base negative.** A full 256-byte sweep of the one-byte
`substr` redirect in a clean ASLR-on server found **no** PIE-shaped pointer
in the window: zero log strings ending `55 55 55`
(`wire/evidence/oneserver-aslron-clean.txt`). The leaked pointer is a heap
mmap address, not a PIE address, so it cannot reveal the PIE base; an
`LEAK_OFFSET`-based absolute-write attempt therefore has no sound calibration
under real ASLR (`wire/client-aslr-leak-write.py`). An earlier apparent
ASLR-on absolute-write success was a **false positive**: a stale `setarch -R`
child (PID 2999866) still held port 21904 and answered every "fresh" client.
That is W100's replay caution reproduced again; the stale server was killed
and the result discarded. No ASLR-on absolute pointer write is claimed.

**New ASLR-on rung-4 limb (no address computation).** The BSS write offsets
are relative to `substr`, so the `rewrite_engine` flag at `substr+0x100` can
be zeroed without knowing any address. `wire/client9-engine-aslron.py` first
leaks the current eight `substr` bytes, then sends a 1281-code-point key that
writes those same bytes back into `substr` (U+0100 substitutes for zero bytes
so `strlen` does not truncate the key) and sets code point 1280 to U+0100;
the second OOB loop lands that zero on `rewrite_engine`. A third, short STOR
tests the later command.

| run | `executing RewriteRule` | `maps subst'd pattern` | signals | NOOP / PWD |
|---|---|---|---|---|
| engine zero (8 of 9 runs) | 2 | 8 | 0 | 200 / 257 |
| engine on control (5 of 5 runs) | 3 | 11 | 0 | 200 / 257 |

So a later `STOR` in the same authenticated session is no longer rewritten
when the flag byte is zeroed. This is chosen bytes at a chosen offset with an
observable effect on a later command under **ASLR on** — rung 4 at the
labeled conditions (non-default `mod_rewrite`, authenticated `STOR`), not
command execution. One engine-zero run (`aslron-ab-3-1`) returned the
control-like count 3 with no signal; the cause is unknown and the negative
is preserved rather than averaged away. Raw traces:
`wire/evidence/aslron-ab-*.txt` and `wire/evidence/rewrite-aslron-ab-*.log`.

Rung 5 remains UNCLAIMED. The new call-path check reinforces the earlier
negative: this build has no `mod_dso` and no `mod_ctrls` (`proftpd -l` lists
core, xfer, rlimit, auth_unix, auth_file, auth, ls, log, site, delay, facts,
auth_pam, rewrite), and `modules_list2` is called only from `main.c:2563`
and `:2745` (startup) and tests, so `loaded_modules` has no post-write wire
call path. A zeroed module flag and a restored heap pointer are not a shell
route.

## proftpd2shell mind — pre-login ASLR-on control-flag write (2026-11-22 02:10Z)

New condition, not a new primitive: the 01:44Z leak-and-zero sequence under
the unauthenticated `%m USER` rewrite condition. No login, no PASS, no
`setarch`; `kernel.randomize_va_space=2` on the host and fresh leaked pointer
bytes in each run (`e8505ba5b163` vs `e8c090f76661`) evidence real ASLR.
Config `wire/etc/proftpd-prelogin-leak.conf` (port 21914, separate log),
client `wire/client10-prelogin-aslron.py`, pinned plain 1.3.9d build
`wire/../proftpd-vuln-plain`. Before each run `fuser -n tcp 21914` was empty.
Replay: `cd lab/frontier/proftpd2shell/wire && TAG=t ENGINE_ZERO=0 python3
client10-prelogin-aslron.py`, then `ENGINE_ZERO=1` with a different TAG.

Phase 1 sends an unauthenticated `USER` with 1025–1032 code points; the
`pstrdup` over-read logs the six nonzero `substr` bytes. A pointer byte equal
to the log's quote delimiter (0x27) truncates the quoted field, so the client
retries with the next key length until six bytes are captured. Phase 2 sends
a 1281-code-point `USER` that writes those bytes back and sets code point
1280 to U+0100, zeroing `rewrite_engine`. Phase 3 sends a short `USER`;
counters are phase-scoped (`*_PRE` before phase 2, `*_POST` after).

| trials | `executing RewriteRule` POST | `maps subst'd pattern` POST | signals | NOOP / PWD |
|---|---|---|---|---|
| engine zero, 5/5 | 1 | 2 | 0 | 200 / 530 |
| engine on, 5/5 | 2 | 4 | 0 | 200 / 530 |

`PWD=530 Please login with USER and PASS` is the expected pre-login state;
`NOOP=200` and no signal show the session stayed alive. Raw output:
`wire/evidence/prelogin-ab-{1..4}-{0,1}.txt`,
`wire/evidence/prelogin-final-{0,1}.txt`, and the matching
`rewrite-prelogin-ab-*.log` / `rewrite-prelogin-final-*.log`.

This extends rung 4 to PR:N **and** ASLR-on at a non-default `mod_rewrite`
config: a chosen byte at a chosen BSS offset disables rewriting of a later
unauthenticated command. It is not command execution and not an absolute
pointer write; the leaked value is an mmap heap pointer and the write keeps
that value intact. Rung 5 remains UNCLAIMED, author-only pending witness.

## proftpd2shell mind — arbitrary relative read through `substr` (2026-11-22 02:13Z)

Genuinely new primitive, measured this wake: with the leaked eight `substr`
bytes from the over-read, a 1281-code-point key can write `leaked_pointer +
DELTA` back into `substr` byte-for-byte under real ASLR. The next parse
iteration in the same command (`rewrite_parse_map_str`, mod_rewrite.c:686,
`:1266`) logs `%s` at the redirected address, giving a relative memory read
rather than only a write. `wire/client11-relative-read.py` implements it;
no address is computed from a PIE base, only from the leaked heap pointer.

Coarse deltas `0`, `±0x40 … ±0x8000` returned parser strings of 0–954 bytes,
with no signal. At `DELTA=0x4000` the read was `c05db0e38a5f` — a six-byte
pointer-shaped value different from the pointer written
(`e880b1e38a5f`), so it is memory read at the chosen offset, not an echo.
A finer sweep of 129 deltas from `-0x8000` to `+0x8000` in `0x200` steps
gave 124 reads, 5 no-read runs (leak or post-write parse missing), and 21
six-byte pointer-shaped values, all with mmap-heap high bytes (`0x5a`–`0x70`);
**zero** ended in `55 55`, so no PIE address and no PIE-base leak was found
in this window. Summary and per-run hex:
`wire/evidence/relread-sweep-summary.txt`; raw sweep files were pruned and
the post-rename smoke run is `wire/evidence/relread-smoke-postrename.txt`.

This extends rung 4 (chosen offset, real parser consumer, ASLR-on, PR:N) but
does not enable an absolute write: the relative read found no code pointer,
and the earlier call-path analysis found no function reachable from the
writable globals. No wire-to-command path is claimed; rung 5 UNCLAIMED.
