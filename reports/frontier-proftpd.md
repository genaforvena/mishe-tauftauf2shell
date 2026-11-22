# Frontier brief — ProFTPD mod_rewrite `int:utf8trans` BSS write (rung 3 wire-reproduced; chosen-byte pointer control measured, rung 4 open)

**Status (2026-11-22 00:03Z, W95): RUNG 1–3 ESTABLISHED on the real 1.3.9d daemon
over a loopback FTP wire with a paired safe-length control. Rung 2 (cross-request
state corruption) and a chosen-byte overwrite of two live pointer fields are
observed in a non-ASan instrumented build. Rung 4 is NOT established: no benign
marker has been executed at a chosen target. NOT admitted, no window.** Requires
non-default `mod_rewrite` config; the lab trigger is an authenticated `STOR`
(PR:L), so the advisory's unauthenticated reach is UNKNOWN here.

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
  corruption on the real parser, with fixed-version and safe-length controls).

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
`rewrite_cond_matches.match_string` at i = 1120–1127. The `ucs4_longs` 8-byte
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
partial 1060-byte overwrite that preserves the PIE high 32 bits. Each corrupted
case dies immediately afterwards with SIGSEGV in
`pr_vsnprintfl` → `pr_log_vwritefile` → the module-call chain. That crash is
*consistent with* a `%s` log path dereferencing a corrupted `match_string`, but
the stack trace alone does not prove which corrupted global was dereferenced;
that attribution stays UNKNOWN. Rung 2 is observed as cross-request static-state
corruption (these fields persist between commands in the same session).

## Rung-4 feasibility and the cheapest next experiment

- Rung 4 NOT established. There is no benign-marker execution at a chosen
  address: the two demonstrated pointer values are non-canonical or unmapped,
  and the PIE base is unknown at key-construction time. Chosen bytes at chosen
  offsets and pointer-field control are real; a *controlled dereference to a
  chosen target* is not yet shown.
- Cheapest next step: keep the 1060-byte partial overwrite (preserves the high
  32 bits), run under `setarch "$(uname -m)" -R` to fix the PIE base, compute a
  `.rodata` string's low-32 address from the instrumented binary's symbols, and
  encode that value into the key using the one-byte-per-code-point mapping
  (2-byte UTF-8 encodings for bytes ≥ 0x80). Then send a second command and look
  for that string in `RewriteLog` or the FTP reply. A clean marker makes rung 4;
  a crash at the chosen address without a marker stays pointer control only.
- If that fails, the write may only ever reach `%s` log formatting before a
  useful consumer; record the ceiling and do not retry into existence.
- Admission: this is a stronger candidate than libnxml (wire trigger plus a
  chosen-byte pointer field), but still short of rung 4. Stage it only after the
  marker experiment, with a dedicated mind and window at that point.
