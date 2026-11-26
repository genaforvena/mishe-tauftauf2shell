# frontier-ettercapgg2shell — Gadu-Gadu dissector version-string OOB WRITE (CVE-2026-125401)

## Claim source and scope

- GitHub security advisory GHSA-vrjv-f8gv-2h35 (published 2026-11-06):
  https://github.com/Ettercap/ettercap/security/advisories/GHSA-vrjv-f8gv-2h35
  — `gg_get_version()` in `src/dissectors/ec_gg.c` composes a version string
  with `sprintf`/`strcat` into a 30-byte heap buffer and can emit up to 44
  bytes. Affected `<= 0.8.4.1`, patched `0.8.5.1`. The advisory itself reports
  a verbatim-function-extract ASan `WRITE of size 13`, 0 bytes after the
  30-byte region.
- CVE-2026-125401 is listed in the advisory; High, CVSS 3.1 8.1,
  `AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`, CWE-131/CWE-787. The advisory's
  "process normally runs as root" and exploitability prose are claims, not
  local results.
- Fix proposed in PR #1330 (branch `security/dream-2026-hardening`, patch head
  `a8c1a5085791b38c234be0e4129302fdc36964e0`). The patched release tag
  `v0.8.5.1` carries the bounded helper. Tag SHAs verified with
  `git ls-remote`: `v0.8.4.1 = 0dc8409779f3a09cbfff4434b9a4d7b33480d88d`
  (vulnerable), `v0.8.5.1^{} = 832524f3c4c215f1007fe9f190dbf052ee965b55`
  (fixed).

## Source-bound mechanism

In the vulnerable tag, verbatim `src/dissectors/ec_gg.c:356` allocates
`SAFE_CALLOC(tbuf3, 30, sizeof(char))`. The same `dissector_gg()` casts the
TCP-8074 payload to `gg_login50_hdr`, `gg_login60_hdr`, `gg_login70_hdr` or
`gg_status50_hdr` and passes the fully attacker-controlled `u_int32 version`
to `gg_get_version()` **before** the per-message `if (gg->len < offset)`
guards. Verbatim `:599-678` switches on `version & 0xff`; the default at
`:668-670` runs `sprintf(str, "unknown (0x%X)", version)`, and two flag tests
at `:672` and `:675` append `" + has audio"` (12 bytes) and
`" + eraomnix"` (10 bytes) with `strcat`. Version `0x44000042` misses every
switch case and sets both flags, producing
`unknown (0x44000042) + has audio + eraomnix` = 43 chars + NUL = **44 bytes
into a 30-byte allocation**.

The fixed tag's `gg_get_version` (`:631-717`) composes into a local
`char buf[128]` and hands the caller a bounded copy with
`snprintf(str, size, "%s", buf)` at `:715`; the fixed dissector sizes `tbuf3`
with `GG_TBUF3_SIZE 64` and passes that size. This is a missing bounds check,
not a documented format feature.

## Local experiment (rung 3 observed, rung 4 PARTIAL)

`lab/frontier/ettercapgg2shell/run-all.sh` pins both codeload archives by
commit SHA, extracts the verbatim `gg_get_version` bodies (`:599-678` and
`:631-717`) with `#line` directives naming the real source file, builds
GCC+Clang ASan and GCC+Clang plain, and drives attacker-chosen `version`
values through the exact 30-byte `calloc` allocation. No pcap, socket,
listener, model, external target or command is used.

Observed with runner sha256
`35c3f7d532a62b107f806d7b126e4f76bead860d949ce7b57217e22f458958c4`:
**RESULT PASS=25 FAIL=0, rc 0**. Vulnerable GCC+Clang ASan reports
`ERROR: AddressSanitizer: heap-buffer-overflow`, `WRITE of size 13`,
`0 bytes after 30-byte region`, with frame
`#1 gg_get_version src/dissectors/ec_gg.c:673` and the allocation at
`poc.c:35`. Fixed-tag runs truncate to `len=29` with the same 30-byte buffer
and no ASan report; safe version `0x0000002a` is clean on both tags. Plain
vulnerable builds show the chosen first hex digit `0x34` at offset 11 (in
bounds) and suffix bytes `0x69` at offset 30 and `0x78` at offset 42 (past
the 30-byte allocation); the safe control leaves offsets 30 and 35 zero.
Full pins, hashes and preserved negatives are in
`lab/frontier/ettercapgg2shell/PROVENANCE.md`.

Grade: **rung 3 verbatim / rung 4 PARTIAL**. ASan confirms a deterministic
14-byte heap overflow from a network-controlled `u_int32` at the pinned sink,
and plain builds observe bytes at chosen offsets past the allocation. The
chosen hex digits of `version` always land at offsets 11..18 inside the
allocation; the bytes that cross offset 30 are fixed suffix strings, so
attacker control is over the overflow *length*, not the overflowing bytes.
There is no named adjacent object, pointer control, live wire path, command
execution or r5.

## Cheapest next rung-moving experiment

Build the pinned `dissector_gg()` path and feed a crafted Gadu-Gadu login
packet to a loopback-only instance from a local pcap, comparing the vulnerable
crash with `0.8.5.1` rejection; the same fixed tag adds
`size_t copy_len = MIN(gg->len - offset, GG_MAX_LEN)` around the
`strncpy(tbuf2, description, gg->len - offset)` call, which is a separate,
fully attacker-chosen-byte overflow and is the most direct route to a named
field or pointer target. To advance rung 4 without leaving the advertised
sink, measure a layout where the suffix bytes land in a named adjacent object
rather than the current chunk's tail/next-chunk size field: a 30-byte glibc
chunk has 40 usable bytes and the next object's user pointer is 48 bytes from
the start, while the longest string ends at offset 43. Would also change the
assessment: a fixed-tag ASan report, a witness counterexample, or an observed
wire-path RCE.
