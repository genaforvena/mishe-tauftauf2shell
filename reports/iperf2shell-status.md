# Iperf2Shell status

Admitted 2026-11-21 ~02:2xZ under the standing similar-things mandate (#6),
on frontier's #477 handoff. Claim sources, pinned sources, hashes and URLs:
`reports/frontier-iperf2shell.md` and
`lab/frontier/iperf2shell/PROVENANCE.md`. The two-pane `iperf2shell` window
(inner socket, window 25), registry entry and seed wall were already live
from frontier (capture-verified 02:06Z); wake trigger units and the
presentation.json entry are owed from the person's full-flag sync
(`docs/runtime-pin.md`) — never a bare `mishe sync`.

## Target

iperf3 `decrypt_rsa_message()` oversized-authtoken heap overflow,
CVE-2026-101283 / GHSA-pwcx-5qh6-2pxc (CWE-122, CVSS 4.0 9.2
`AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CNA Anthropic,
published 2026-09-30). Affected 3.20/3.21; fixed 3.22; fix commit
`d08588aceee48fa45832cae5e32616abb33cb0fc` turns the warn-only guard into a
rejection. A base64-decoded client `authtoken` longer than the 256-byte RSA
modulus is passed as the `BIO_read` length into a 256-byte heap buffer. The
server must run with RSA auth enabled; the overflow is still pre-auth.
Preserved conflict: 3.22 release notes label this CVE a use-after-free in
`iperf_server_api.c` and name a separate CVE for the `iperf_auth.c` overflow;
the record, GHSA and fix commit point at `decrypt_rsa_message()`.

## Reproduction and pins

`bash lab/frontier/iperf2shell/run.sh <outdir>` compiles the real pinned
upstream `iperf_auth.c` at 3.21 and 3.22 (gcc 13.3.0, OpenSSL 3.0.13,
`-O0 -g`). Operator replay at admission: 16 PASS lines, `ALL CHECKS PASS rc
0`, deterministic trace
`sha256=bd3efc4cb4720e7fe5cc2e83e79cc7e89010f75a7e93579360a215eb5f029caf`,
matching the brief and its three byte-identical frontier replays.

- Rung 1 — decoded length 336 against a 256-byte modulus, `oob_bytes=80`;
  warn-only guard observed; ASan `WRITE of size 336` starts 0 bytes after the
  256-byte region.
- Rung 2 — the plain build corrupts the next chunk's metadata and glibc
  aborts with `free(): invalid size` at `OPENSSL_free`.
- Rung 3 — ASan `heap-buffer-overflow`, `WRITE of size 336`, `BIO_read` ←
  `decrypt_rsa_message` at `iperf_auth.c.3.21:324`, allocation at `:319`.
- Rung 4 — chosen `IPERF2SHELL!` at offset +8 and
  `0x1122334455667788` at offset +48 past the boundary are supplied in the
  write buffer; INSTRUMENTED only.
- Fixed control — pinned 3.22 rejects before `BIO_read`
  (`exceeds RSA modulus 256; rejecting`), adjacent allocation stays clean.

## Evidence boundary

Rungs 1/2/3 ESTABLISHED on the real pinned upstream function. Rung 4 is
INSTRUMENTED chosen-byte control in the write buffer, not pointer control in
a stock binary. No live `iperf3` process, stock heap layout, useful-pointer
control or execution. The failed plain-build byte-readback expectation and
the recoverable-ASan redzone dead end are preserved in the brief; no claim
came from them. Witness replay is owed; the author's report is not
independent acceptance.

## Probe policy

All replay work is local and file-only. Any future live server binds to
127.0.0.1 only; no public infrastructure is contacted.
