# ettercap2shell — status

Admitted 2026-11-23 ~02:4xZ under standing approval #6 as the 97th engine
route. Frontier staged this lane in W133 (brief
`reports/frontier-ettercap.md`, site charter and seed wall, pinned vulnerable
and fixed `ec_gg.c` blobs plus fix patch and raw evidence in
`lab/frontier/ettercap2shell/PROVENANCE.md`). Its two-pane inner tmux window
already existed at index 101 (0..100 occupied); admission created no second
window. The hy4-flash `max_parallel: 3` route was added, the path, debounce
and `@ettercap2shell` slice drop-in were minted with the exact full-flag sync
at pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Both `m2shell-wake@ettercap2shell.service` and
`m2shell-wake-ettercap2shell.path` were added to the site's owner resolver map
(now 195 entries). The pinned doctor returned `PASS local plant out of Git` /
`GREEN` and `tools/check-omp-only.py` reports `GREEN (97 declared roles)`.
Admission changes no grade.

- Claim: CVE-2026-125401 / GHSA-vrjv-f8gv-2h35, GitHub CNA 2026-11-06 and
  OSV 2026-11-09, HIGH 8.1
  `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`, CWE-131 + CWE-787
  (CVE record CWE-122), affected `<= 0.8.4.1`, patched `0.8.5.1`. **AV:A, not
  AV:N**: a passive/adjacent dissector bug on TCP 8074, not a connectable
  service. Fix commit `1d8badb7`; pinned vulnerable `3548c10c` and PR-head
  fix `a8c1a50` (byte-identical to merged and released 0.8.5.1 blobs) with
  SHA-256 pins in `lab/frontier/ettercap2shell/src/SHA256SUMS`.
- Primitive: `dissector_gg()` allocates a 30-byte `tbuf3` and calls
  `gg_get_version()` before the per-message length guards. The helper receives
  only `char *str`, never a size: `sprintf` of an attacker-chosen `u_int32
  version` plus two flag-selected `strcat` literals compose up to 44 bytes.
  `version=0x44000042` gives 43 chars plus NUL — 14 bytes past the 30-byte
  object. The fix composes into `char buf[128]` and finishes with
  `snprintf(str, size, "%s", buf)`, with callers passing size 64.
- Evidence: harness `lab/frontier/ettercap2shell/harness/run.sh` re-extracts
  the verbatim pinned helper slices on each run, SHA-asserts source, patch,
  tag, slice and driver bytes, and compiles plain plus gcc/clang ASan
  variants. Operator replay from a fresh `/tmp` copy of the whole lane: rc 0,
  `PASS=58 FAIL=0`, `TRACE_SHA256=d650b34e3bbc1ea336c60d2cb4b9c7743fdc4657b7d8e0d07c7e1bc1c1027b7a`,
  exactly frontier's value. gcc and clang ASan report
  `heap-buffer-overflow`, `WRITE of size 13`, `0 bytes after 30-byte region`
  in `gg_get_version`; the fixed helper writes 29 chars in 30 and 43 in 64
  bytes and is ASan-clean, and the vulnerable helper with `0x2a` writes 3
  chars cleanly. Plain workspace gives `STR_LEN=43`, `OOB_COUNT=14`.
- Rung 4 (scoped, partial): input bits choose whether and how far the write
  crosses the boundary. Both flag bits give the exact OOB tail
  `69 6f 20 2b 20 65 72 61 6f 6d 6e 69 78 00`; single-bit variants cross
  with just the terminating NUL. Chosen hex digits land byte-exact at offsets
  11..18 **inside** the 30-byte object. Correction to the advisory: the bytes
  crossing the boundary are fixed suffix literals selected by input bits, not
  arbitrary attacker bytes.
- Folded `tbuf2` claim (operator DM #5241, checked 2026-11-27 per DM #6252):
  fixed `v0.8.5.1` caps `copy_len = MIN(gg->len - offset, GG_MAX_LEN=70)`
  against a 71-byte `tbuf2` at every login/status site, so the claimed
  fully-chosen-byte overflow is guarded unreachable there. Vulnerable
  `v0.8.4.1:363` copies `gg->len - 22` bytes; a 110-byte copy lands
  packet-chosen bytes in the adjacent `tbuf3`, read back through the natural
  `VERSION:` logger and measured at `tbuf3 - tbuf2 = 80` in gdb. Fixed build
  and short-description controls are clean. This is a second sink in the same
  dissector, not the advisory's `gg_get_version` sink; no pointer control.

Grade: rung 3 ASan-confirmed out-of-bounds write on verbatim pinned helper
bytes, **now also on the real dissector path**: ettercap v0.8.4.1 and v0.8.5.1
were built with clang ASan (source hashes match the pins) and a crafted
`GG_LOGIN50_CMD` packet with `version=0x44000042` was replayed from a pcap and
injected as a live frame on loopback. `dissector_gg:360` calls
`gg_get_version()` before the length guard; ASan reports `WRITE of size 13`,
`0 bytes after 30-byte region` allocated at `dissector_gg:356`, through
`pcap_loop -> capture`. Extent controls (`0x44000018`, `0x04000042`) give
`WRITE of size 12` at line 676; safe version, wrong type, server-direction
packet and the fixed v0.8.5.1 build are clean. Full report:
`reports/ettercap2shell-livedissector.md`; small artifacts:
`lab/frontier/ettercap2shell/live-evidence/`; commit `fcec372`. Scoped partial
rung 4 over extent and fixed literal tail remains at the advisory sink; no
pointer control, marker, command or rung 5. Experiment D (2026-11-27) adds a
separate, directly measured chosen-byte write at the folded `tbuf2` sink with
a named adjacent field (`tbuf3`) and natural logger read-back, plus a clean
fixed-tag guard. Still AV:A, still no witness verdict.

Next bounded experiment (if resumed): test the AV:A claim with a sender that
is genuinely adjacent rather than the same host. Pointer control / command
execution from either sink remains unmeasured; the natural chosen-byte
consumer question is closed by Experiment D for the `tbuf2` sink. Neither is
a blocker. Keep rung 5 requirements unchanged: live wire-only trigger, chosen
benign command, observed side effect, vulnerable/fixed/safe controls and
witness replay.
