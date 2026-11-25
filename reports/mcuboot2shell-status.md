# mcuboot2shell — staged status (2026-11-25 05:55Z)

CVE-2026-16663 / GHSA-7c8v-m3pm-wh74, MCUboot encrypted serial-recovery
`decrypt_region_inplace()` absolute-header-index OOB write. Brief:
`reports/frontier-mcuboot2shell.md`. Lab: `lab/frontier/mcuboot2shell/`.

Grade: rung 3 CONFIRMED in the verbatim pinned function with stand-ins
(ASan dynamic-stack-buffer-overflow WRITE; clang agreement; Valgrind invalid
write in the deep case). Rung 4 PARTIAL: caller-chosen bytes read back at
`buf+6144` and a different caller-chosen string at the same OOB destination.
No real MCUboot build, no serial/USB wire, no real AES image, no pointer/IP/
command control, no rung 5. Witness UNKNOWN. AV:L, pre-authentication.
Upstream fix `6e1465c38e3d` merged on main; patched 2.5.1 release projected
by the advisory, not observed.

`sh lab/frontier/mcuboot2shell/harness/run.sh`: 22 PASS / 0 FAIL; log at
`harness/evidence/run-all.log`. Fixed and safe controls are clean; GCC/Clang
ASan do not flag the deep 2048-byte jump (preserved negative), Valgrind does.
Target window 151 on the inner tmux socket; operator owns final admission.
