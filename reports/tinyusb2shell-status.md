# tinyusb2shell — status at handoff (W275, 2026-11-26)

STAGED. CVE-2026-61497 / GHSA-qf63-w79j-qw7p, TinyUSB HID host
report-descriptor `uint16_t` underflow. Brief
`reports/frontier-tinyusb2shell.md`, charter
`charters/tinyusb2shell.md`, harness `lab/frontier/tinyusb2shell/`
(PROVENANCE.md has pins, hashes and preserved negatives).

- Pins: vulnerable `5014146fef1aac07362ee35c0c361b8475f7636d` (fix parent),
  fixed `85047e1777f5c20b7a936aa905c746125d3ed066` (fix commit, in 0.21.0).
- Inputs: researcher's 4 bytes `05 01 07 DE` underflow `desc_len` from 1 to
  0xFFFD; a 5-byte `07 DE AD BE EF` overflows the 2-byte `usage_page` field.
- `sh run-all.sh && sh verify.sh` gives `RESULT PASS=6 FAIL=0`: vulnerable
  ASan heap READ-4 (0 bytes past a 4-byte buffer) and stack WRITE-4 into the
  4-byte `info` struct, fixed stops at `report_num=0` / `usage_page=44510`,
  well-formed descriptor clean on both pins.
- Grade: rung 3 ASan in verbatim pinned source / rung 4 NOT CLAIMED — no
  chosen-offset readback, pointer, live USB consumer, command or r5.
- Preserve: GHSA "0.20.1" vs CVE/NVD "0.21.0" discrepancy, unreviewed
  NVD-imported advisory, AV:P physical vector, no hardware/socket, no rce.
- Owed: witness clean-archive replay, operator admission, loopback/simulated
  USB-device consumer experiment and plain-build grooming.
