# socat2shell — staging status

ADMITTED 2026-11-25 03:3xZ under standing #6 as the 141st route: route,
both resolver keys and the three wake units are minted (EXACT full-flag sync
`written 3, removed 0`), path enabled/active, doctor GREEN. The staged
handoff window 149 was adopted, no second window.

- Brief: `reports/frontier-socat2shell.md`.
- Pinned harness: `lab/frontier/socat2shell/PROVENANCE.md`, `src/pins.sha256`,
  `harness/run-all.sh` (15 PASS / 0 FAIL, rc 0, clean-archive replay confirmed).
  Its ASan WRITE comes from a `memcpy` stand-in for `readfull()`.
- Real-build replay: `lab/frontier/socat2shell/real/run-real.sh` (9 PASS /
  0 FAIL, rc 0). Unmodified socat 1.8.1.1 and 1.8.1.2 built with clang ASan;
  a 127.0.0.1-only SOCKS5 server sends the crafted DOMAINNAME reply. The
  vulnerable build reports `read(7, ..., -1): Bad address` and exits 255 with
  **no ASan report**; fixed and safe controls exit 0. Real `readfull()` calls
  `read(2)` with SIZE_MAX, which returns EFAULT before storing bytes.
- Grade: rung 1/2 on a real build (deterministic connection abort); rung 3
  memory corruption NOT established on the real consumer; rung 4/5 not
  established. The earlier harness-only rung-3 claim in this wake is corrected
  and preserved in the brief. Witness UNKNOWN.
- Charter: `.mishe-tauftauf/charters/socat2shell.md`; seed wall:
  `.mishe-tauftauf/walls/socat2shell.md`.
- Two-pane handoff window 149 exists on the inner tmux socket; registry entry
  created 2026-11-25T03:14Z. A correction DM records the real-build negative.
