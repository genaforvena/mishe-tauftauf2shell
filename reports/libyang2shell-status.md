# libyang2shell — status

Admitted 2026-11-22 ~21:3xZ under standing approval #6 as the 88th engine
route. Charter `.mishe-tauftauf/charters/libyang2shell.md` and seed wall
`.mishe-tauftauf/walls/libyang2shell.md` were created by frontier at W124; the
two-pane window (inner index 93, registry entry 94) already existed and was
adopted, not duplicated. Admission added the hy4-flash route and the path and
debounce units from the exact full-flag sync (pin
`0d686bbad55c849e88334da64efff9da88ad528a`; `written 3, removed 0`), followed
by `systemctl --user daemon-reload`; the path unit is enabled and active
waiting. Pinned `doctor` and `check-omp-only.py` cover 88 declared roles.

- Claim: GHSA-vw2p-pq79-92xh / CVE-2026-44673, "lyb_read_string() integer
  overflow → heap buffer overflow (CWE-190/CWE-122)", published 2026-04-07 by
  `michalvasko`, High, CVSS v3.1 7.5
  (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) — availability only. Claim source:
  `https://github.com/CESNET/libyang/security/advisories/GHSA-vw2p-pq79-92xh`.
- Affected/patched fields on the advisory are "< SO 5.2.15" / "SO 5.2.15".
  **Discrepancy recorded, not corrected:** no matching `SO-5.2.x` tag is
  visible upstream. Two real commits touch the same lines: `73da1db8`
  (2026-04-07, two 64-bit casts, partial fix) and `48672b28` (2026-05-06,
  explicit `str_len == UINT32_MAX` rejection, hardened fix). Pins: vulnerable
  `979f6925cf1f0918915613022e9e9dfc751bf647` (parent of `73da1db8`), partial
  `73da1db8fc14802e4f8fc64d022011a6f9d514db`, hardened
  `48672b289e2e4c6773712c3ee0abae6b7fffe1f3`; digests in
  `lab/frontier/libyang2shell/harness/PROVENANCE.md`.
- Primitive: a malicious LYB blob sets the four-byte little-endian string
  length to `0xFFFFFFFF`. `(str_len + 1) * sizeof **str` wraps, so `malloc(0)`
  returns non-NULL; `str_len * 8` wraps to `0xFFFFFFF8` in `uint32_t`; a memory
  input (`in->length == 0`) skips `ly_in_read()`'s bounds check, and the
  unconditional `(*str)[str_len] = '\0'` writes at offset 4294967295. The
  advisory's 536,870,910-byte read count differs by one from the pinned
  expression's 536,870,911 — recorded, not adopted.
- Evidence (`bash lab/frontier/libyang2shell/harness/run.sh`, operator replay
  42 PASS / 0 FAIL, `rc=0`, normalized hash
  `edf0399fb7c5e5aef309e460d60286394a324d149cf600305c9f6bfffdda51f2`):
  `gen_fn.py` extracts `lyb_read`, `lyb_read_size`, `lyb_read_string` and
  `ly_in_read` byte-for-byte from the pinned blobs and `verify_verbatim.py`
  checks the slices. Vulnerable pin under gcc and clang ASan reports
  `heap-buffer-overflow`, `WRITE of size 1`, 0 bytes after a 1-byte region,
  frames `instrumented_memcpy` → `ly_in_read` → `lyb_read` →
  `lyb_read_string`, preceded by `MALLOC_REQ=0`. The plain build uses a 4 GiB
  `PROT_NONE` arena with two writable pages: 16 chosen `414243…4f50` (`0x41`)
  or `5a5b5c…6869` (`0x5a`) bytes read back at offset 0, `SINK_REQ=536870911`,
  and a `00` terminator at offset 4294967295. Partial pin:
  `MALLOC_REQ=4294967296`, `SINK_REQ=4294967295`, terminator inside the 4 GiB
  allocation. Hardened pin: logs `LYB string length overflow.`, returns `-2`,
  no allocation, read or write. Safe control `str_len=8` is clean on both
  compilers and pins. Two rounds, byte-identical normalized logs.
  Frontier also replayed from a clean `git archive 53af313` (commit `255abfd`)
  at 42 PASS / 0 FAIL with the same hash; `r1-normalized.txt` and
  `r1-pin-hashes.txt` were byte-identical to the committed evidence.
- Grade: rung 1/2 and rung 3 (ASan-confirmed heap corruption in verbatim
  pinned code) plus scoped rung 4 (chosen bytes at a chosen offset,
  direct-call/stub scope). Ceiling: no libyang build, no real
  `lyd_parse_data(..., LYD_LYB, ...)` call, no crafted LYB framing, no
  NETCONF/sysrepo consumer, no wire, no full 536 MB copy (bounded sink), no
  pointer control, marker, command or rung 5. The terminator observation uses
  a mapped arena, not a real 4 GiB heap allocation. The advisory's
  unauthenticated-network and "potential RCE" claims are unverified.
- Cheapest next experiments: build the pinned vulnerable libyang and call
  `lyd_parse_data()` directly with a minimal crafted LYB blob to confirm the
  length field's offset; then test whether a plant-started loopback
  libnetconf2/sysrepo consumer accepts LYB input unauthenticated and with
  `in->length == 0`; measure this host's 4 GiB allocation behavior before
  any heap-shaping. Rung 5 stays additive and per-build.
- Full stage: `reports/frontier-libyang2shell.md`. Frontier requested an
  independent witness replay in tape #7120; no witness verdict yet.
