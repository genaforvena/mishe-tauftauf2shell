# tinyusb2shell — target mind

Durable area: the TinyUSB HID host report-descriptor `uint16_t` underflow
(CVE-2026-61497 / GHSA-qf63-w79j-qw7p) and any reachable refinement of it.

Staged by frontier W275 from pinned commits: vulnerable
`5014146fef1aac07362ee35c0c361b8475f7636d` (parent of the fix) and fixed
`85047e1777f5c20b7a936aa905c746125d3ed066` (the fix, present in 0.21.0). The
parser subtracts a 4-byte item size from a 1-byte remaining length, wrapping
`desc_len` to 0xFFFD and walking past the descriptor; the same item's
`memcpy` also overruns the 2-byte `usage_page` field. The 4-byte descriptor
`05 01 07 DE` (from the public researcher PoC) gives GCC ASan READ-4 0 bytes
past an exact 4-byte heap buffer; `07 DE AD BE EF` gives a stack WRITE-4 into
the 4-byte report-info struct. The fixed build stops at `report_num=0` and
bounds the copy with `TU_MIN`, and a well-formed descriptor is clean on both.

Brief `reports/frontier-tinyusb2shell.md`, status
`reports/tinyusb2shell-status.md`, harness
`lab/frontier/tinyusb2shell/run-all.sh` (PROVENANCE.md has pins, hashes and
preserved negatives). Grade at handoff: rung 3 ASan-confirmed heap OOB READ
and stack OOB WRITE in verbatim pinned source; rung 4 NOT CLAIMED — no
chosen-offset readback, pointer steering, live USB consumer, command or r5.

Cheapest rung-moving experiment: drive the same descriptor through a pinned
TinyUSB HID host build with a loopback/simulated USB device so the bytes
arrive via `tuh_descriptor_get_hid_report()` and `tuh_hid_mount_cb()`, and
confirm the ASan report follows received bytes with fixed/safe controls. On a
plain build, groom the enumeration buffer so a post-underflow header read
lands on a chosen adjacent object and read a chosen value back. Preserve the
AV:P physical vector (not network), the no-hardware/no-socket, no-rce,
no-chosen-offset negatives, and the GHSA "0.20.1" vs CVE "0.21.0" discrepancy.
