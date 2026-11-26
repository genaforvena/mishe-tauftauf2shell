# libsmpp342shell — staged status (W271, 2026-11-26)

## What is staged

- Target: Osmocom libsmpp34 `smpp34_unpack()` C-Octet unbounded `strlen`
  heap over-read, CVE-2026-75895 / GHSA-fpm9-38vr-4gp8. Advisory labels name
  "libsmpp35 0.1.0–1.8.0"; the actual patch is in libsmpp34 1.14.5 -> 1.14.6
  (fix commit `af0e2912057551dab97bbe26e6a41f18a75f3bbb`).
- Pins: 1.14.5 peeled commit `d6ac32fde99f08b2019a5ca095471456583dc93a`,
  1.14.6 peeled commit `f93991bd19b6715a6e1782711734cfc52760432e`.
- Brief: `reports/frontier-libsmpp342shell.md`.
- Harness: `lab/frontier/libsmpp342shell/run-all.sh`, `harness/driver.c`,
  `PROVENANCE.md`; tarballs and `build/` are gitignored.
- Window: dedicated two-pane target window created by frontier on the inner
  tmux socket; registered in the site window registry.

## Measured result at handoff

`run-all.sh` sha256 `373fcdc9a182485efc38dbb3b7fa99908a57f80cd4e4977838058be708405637`,
console `evidence-run-console.log`, `RESULT PASS=31 FAIL=0 rc 0` at 13:51Z.
GCC and Clang ASan both report `heap-buffer-overflow`, `READ of size 2`,
`0 bytes after 17-byte region` through the verbatim
`def_frame/bind_transmitter.frame:1` C_OCTET macro. The fixed build rejects
the same 17-byte PDU (`rv=-1`, `len(system_id):2`) cleanly; a complete valid
PDU parses to `rv=0` in both builds; a guard-page plain build faults rc 139.

## Grade and next step

Rung 3 ASan-confirmed heap OOB READ in verbatim pinned source; rung 4 NOT
CLAIMED (one chosen byte supplied; no chosen-offset read-back, pointer
steering, live wire consumer, command or r5). Witness replay from clean
tarballs is owed; operator admission is owed. Cheapest rung-moving experiment:
a local loopback SMPP consumer feeding the 17-byte PDU from a client into
`smpp34_unpack()` under ASan, then heap grooming for chosen-byte read-back.

Preserve the negatives in PROVENANCE.md: the first runner's grep-regex FAIL,
the "safe-short" mode that over-read on the next C-Octet, and the advisory
version-label mismatch. Author reports are never independent acceptance.
