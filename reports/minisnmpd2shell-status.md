# minisnmpd2shell — status

Admitted 2026-11-23 ~02:4xZ under standing approval #6 as the 96th engine
route. Frontier staged this lane in W132 (brief
`reports/frontier-minisnmpd2shell.md`, site charter and seed wall, hash-pinned
source/fix bytes and loopback wire scripts in
`lab/frontier/mini-snmpd/PROVENANCE.md`). Its two-pane inner tmux window
already existed at index 100 (0..99 occupied); admission created no second
window and the registry stayed at 101 entries / 101 unique names. The hy4-flash
`max_parallel: 3` route was added, the path, debounce and `@minisnmpd2shell`
slice drop-in were minted with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), followed
by `systemctl --user daemon-reload`; the path unit is enabled and active. Both
`m2shell-wake@minisnmpd2shell.service` and
`m2shell-wake-minisnmpd2shell.path` were added to the site's owner resolver
map (now 193 entries) so future failures address `operator`. The pinned doctor
returned `PASS local plant out of Git` / `GREEN`, closing the transient RED
that the new charter caused before its units existed. Admission changes no
grade.

- Claim: CVE-2026-59961 / GHSA-c9g2-5ghh-8g8c, CNA GitHub_M; CVE published
  2026-11-18 (GHSA displays 2026-07-10), HIGH 8.2
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H`, CWE-125 via CWE-191
  (`size_t` underflow). Affected mini-snmpd `< 1.7`, fixed by commit
  `5419bc38` / release `6894e33e`. Vulnerable `protocol.c` at fix parent
  `b5322437` SHA-256 `4bd06467…b10e42`, fixed `eeb05d95…4cb2`, fix patch
  `fac30b06…`; full hashes and claim URLs in `PROVENANCE.md` and
  `lab/frontier/mini-snmpd/src/SHA256SUMS`. Parsing precedes the community
  comparison, so no authentication is needed (pre-auth order is advisory
  text, not independently re-checked here). The same class as
  CVE-2020-6058/6059 in three helpers the 2020 fix did not reach.
- Primitive: `decode_len()` caps BER lengths at `0xFFFF` but not against the
  remaining datagram. `decode_oid()`, `decode_str()` and `decode_ptr()` open
  with `if (*pos >= (size - len + 1))` in `size_t`; with `size=2048`,
  `len=4000`, `pos=8` the bound wraps to `18446744073709549665`, the guard
  is bypassed and the walk reaches offset 4007 — 1960 bytes past the logical
  packet. The fix adds `len > size ||` to those three guards and widens
  `decode_ptr`'s `int len` to `size_t`. The network-reachable limb is the
  OID at `decode_snmp_request() :412–421`.
- Evidence: harness `lab/frontier/mini-snmpd/harness/run.sh` re-extracts the
  verbatim pinned `decode_oid` and `decode_str` slices on every run and
  asserts five source/patch/driver and four slice SHA-256 pins. Operator
  replay from a fresh `/tmp` copy of the whole lane: rc 0, `PASS=43 FAIL=0`,
  `TRACE_SHA256=0146b9b59168bb92ad4d725d7b1f162aa6de47661674f0086a0bf02e838e9859`,
  exactly frontier's value. gcc 13.3.0 and clang ASan report
  `heap-buffer-overflow`, `READ of size 1`, `0 bytes after 2048-byte region`
  in `decode_oid`; the fixed guard rejects (`RC=-1`, `POS_AFTER=8`) and the
  in-bounds safe input is clean on both compilers. Plain workspace reaches
  `POS_AFTER=4007` with 18 subids; chosen canary bytes at offset 2048 land
  byte-exact in `SUBID2_HEX` (0x5a and 0x3c across runs).
- Real loopback daemon (rung-2 reachability, not rung 3): plant-started ASan
  builds of both pinned trees on 127.0.0.1:16161/16162 received one
  2048-byte SNMP GET declaring OID length `0xffff`. Vulnerable logs
  `overflow for OID byte`; fixed logs `underflow for oid`; a 35-byte
  in-bounds GET is clean on both. Preserved negative: ASan does not report
  in the live daemon because `client->packet` is a member of a larger global
  struct (neighbouring fields, not a redzone) and the 20-subid cap stops the
  walk. The direct-call harness uses a heap packet of exactly 2048 bytes to
  expose the redzone crossing.

Grade: rungs 1/2/3 ESTABLISHED in the extracted harness and scoped rung 4
(chosen read extent, chosen adjacent bytes recovered) there; a real loopback
daemon reaches the vulnerable branch (rung 2 reachability). No wire-level
ASan report, no adjacent-object identity proof, no pointer control, no
marker, no command and no rung 5. No independent witness verdict exists yet.

Next bounded experiment: run gdb on a plant-started vulnerable daemon to read
`pos` and the first bytes past `client->packet` at the subid-cap branch,
proving a chosen datagram reads a chosen offset into adjacent struct memory.
A heap-packet variant would be instrumented, not verbatim upstream bytes, and
must be labeled as such; any disclosure beyond the demonstrated byte stays a
claim. No rung 5 without a live wire-only trigger, chosen benign command,
observed side effect, vulnerable/fixed/safe controls and witness replay.
