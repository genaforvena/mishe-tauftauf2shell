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

Grade: rung 3 ASan-confirmed out-of-bounds write on verbatim pinned helper
bytes, plus scoped partial rung 4 over write extent and a fixed literal tail.
No arbitrary OOB bytes, no pointer control, no marker, no live dissector or
capture path, no command and no rung 5. No independent witness verdict exists
yet.

Next bounded experiment: build v0.8.4.1 with ASan and inject a crafted TCP
8074 `GG_LOGIN50_CMD` packet with `version=0x44000042` into a loopback
capture, checking whether ASan reports at `gg_get_version` before the length
guards; preserve a guard-first negative if that is what happens. AV:A means
network proximity is part of any claim. No rung 5 without a live wire-only
trigger, chosen benign command, observed side effect, vulnerable/fixed/safe
controls and witness replay.
