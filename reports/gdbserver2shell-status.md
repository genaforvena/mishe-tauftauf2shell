# gdbserver2shell — status

Admitted 2026-11-23 ~01:0xZ under standing approval #6 as the 94th engine
route. Frontier staged this lane at 01:01Z with a brief
(`reports/frontier-gdbserver2shell.md`), site charter, seed wall, hash-pinned
upstream source plus a derived fixed snapshot, and a two-pane inner tmux window
(index 99, created 01:03Z). A stale 2026-11-21 held-proposal window at index 23
had the same name and was still live; frontier's duplicate check missed it. The
fresh index-99 window was adopted and the stale one retired at admission, with
the registry corrected to 99 entries / 99 unique names. Admission added the
hy4-flash `max_parallel: 3` route and the path, debounce and `@gdbserver2shell`
slice drop-in from the exact full-flag sync (pin
`0d686bbad55c849e88334da64efff9da88ad528a`; `written 3, removed 0`), followed
by `systemctl --user daemon-reload`; the path unit is enabled and active. Both
`m2shell-wake@gdbserver2shell.service` and `m2shell-wake-gdbserver2shell.path`
were added to the site's owner resolver map so future failures address
`operator`, not the dead `genome` fallback. Admission changes no grade.

- Claim: CVE-2026-121997 / GHSA-jq36-9pw3-8r4v (Red Hat, 2026-11-05, HIGH 8.1,
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-122). Upstream HEAD
  `633ae02c4ea8f87c670f7192804349860cfa291d`, fetched 2026-11-23, is **still
  vulnerable**; the fix is Andrew Burgess's 2026-11-16 gdb-patches `[PATCH 2/5]`
  (posted, not merged), so there is no tagged fixed release and no upstream
  numeric version range. The "fixed" snapshot is the pinned file with the
  adapted patch applied, not a vendor release. Pins: vulnerable
  `tracepoint-633ae02.cc` SHA-256
  `942306a5b1f96693a64d18819973e7e306faa1481f373615487a5fd2b4df4e2e`, fixed
  `tracepoint-fixed.cc` `c3aa8ac26253ff3fa79d6dd9caa13ae09c5c6471cf3499b22fa5b0926af95f17`,
  fix patch `5b8bc3cb235eb2ced96da42b15c66ec7f2510deace6f5a943b7e567e8a67d43f`;
  full provenance in `lab/frontier/gdbserver2shell/PROVENANCE.md`. The advisory's
  `process_info_private::thread_db` overwrite and `qGetTLSAddr` RIP chain are
  claims, not lab observations.
- Primitive: in the verbatim pinned `cmd_qtdpsrc()`, `unpack_varlen_hex` reads
  `SLEN` from the RSP packet (RSP numbers are hex) and `xmalloc(slen+1)`
  allocates from that declared length, but `hex2bin(packet, src, strlen(packet)/2)`
  writes the actual decoded BYTES length. With `SLEN=1` and N decoded bytes the
  result is an N-2 byte heap overflow of fully attacker-chosen bytes.
- Evidence (`bash lab/frontier/gdbserver2shell/harness/run.sh`): every run
  re-extracts the vulnerable and fixed `cmd_qtdpsrc()` slices and the verbatim
  `ishex`/`unpack_varlen_hex` helpers from saved pinned files and asserts eight
  SHA-256 pins before compiling. Operator replay from a fresh `/tmp` copy of
  the whole lane: rc 0, `SUMMARY=60 PASS / 0 FAIL`, path-independent normalized
  hash
  `0c9b837e5300ac744b133e6668179cda410520177d87b859c99cac9af1c1db73`, exactly
  frontier's clean-archive value. g++ 13.3.0 and clang++ 18.1.3 report
  `AddressSanitizer: heap-buffer-overflow`, `WRITE of size 1`, `0 bytes after
  2-byte region`, frames `hex2bin` → `cmd_qtdpsrc` → `main`, for N=8/32/64/128.
  A plain 64 KiB `0xEE` arena reports `WRITTEN=N-2 FIRST=2 LAST=N-1
  PATTERN_OK=1` at N=32/64: every out-of-bounds byte is the chosen pattern.
  The fixed snapshot returns `RC=0 REPLY=E01 LIST_LEN=0` on the same attack;
  a well-formed packet returns `RC=0 REPLY=OK LIST_LEN=1` on both pins, with no
  ASan report.

Grade unchanged at handoff: rung 3 ASan-confirmed out-of-bounds write in a
verbatim pinned function, plus rung 4 only at the scoped level of chosen bytes
at chosen offsets past the allocation in a direct-call driver. The `hex2bin`
decoder is a faithful reimplementation, not verbatim GDB source; all allocation
and length decisions come from the verbatim slices. No gdb build, no RSP
packet loop, no socket, no daemon, no natural heap layout, no adjacent object
identity, no `process_info_private` pointer, no `qGetTLSAddr`, no marker, no
command and no rung 5.

Cheapest next experiment for the target mind: build the pinned RSP dispatcher
with transport stubs and send one crafted `QTDPsrc` packet through the real
`cmd_qtdpsrc()` under ASan, then check whether the claimed `thread_db` pointer
overwrite and following `qGetTLSAddr` call occur in a natural heap layout, with
fixed and safe controls, before any higher grade. Do not upgrade the grade
from an ASan report alone.
