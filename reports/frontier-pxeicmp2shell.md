# Frontier brief — pxeicmp2shell (CVE-2026-97631)

Status 2026-11-24 20:48Z: **STAGED**, rung 3 under ASan and rung 4 PARTIAL
(chosen bytes in an adjacent live field); witness replay later ESTABLISHED
AS LABELED (inbox #3852), no grade change. Dedicated
two-pane window 143 (panes 288/289) and seed wall exist; registry 144/144;
operator and witness handoff messages sent. Scoped commit `3a0fda26`; a
clean `git archive 3a0fda26` replay in `/tmp/w214-pxe` gave 31 PASS / 0 FAIL,
rc 0. Final admission belongs to the operator. No EDK2 firmware build, no PXE
wire process, no event forging, no pointer/IP/command execution and no rung 5.

## Verified ground truth (read-only provisioning)

- CVE-2026-97631 / GHSA-99cj-7hg9-mp4m, "Pre-boot RCE in EDK II PXE driver",
  published 2026-10-22, Critical CVSS 4.0 9.5
  `AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`, CWE-120/131/787.
  Affected: EDK II master as of 2026-09-14 (advisory); the pinned reference is
  `edk2-stable202608` commit `2970e5699ba6267f3384ffab20f96647578aebc8`.
  Source: https://github.com/tianocore/edk2/security/advisories/GHSA-99cj-7hg9-mp4m .
- Advisory claim: an unauthenticated network attacker delivering ICMP errors
  to a PXE-booting machine overruns the fixed 504-byte `Mode->IcmpError`
  field in both `PxeBcIcmpErrorDpcHandle()` (IPv4) and
  `PxeBcIcmp6ErrorDpcHandle()` (IPv6), corrupting adjacent private data; the
  writeup further claims DXE event forging and pre-boot code execution. That
  RCE chain is a claim; nothing here exercises it.
- Public fix: PR https://github.com/tianocore/edk2/pull/13302 , merged
  2026-10-15 at `fa789071ff0b29f1e568bfe153ef7f3d76bd60e4`; master hunk
  `7a8aafe4170ec51ab188b53760dca8ec15cdf189`, 4.6 branch hunk
  `daf4910f29e37e2cf0f91aaca78733306fa9df21`. A public PoC repository
  (`Try2Take/CVE-2026-97631-PoC`) exists but was not executed: its bridge-mode
  QEMU/OVMF build and `sudo` requirements exceed this wake's loopback-only
  scope.
- Screened `reports/frontier-*.md` and the frontier wall before provisioning:
  no prior pxeicmp/EDK2 entry. Do-not-duplicate targets (SOES, Assimp,
  FFmpeg, ClamAV, QuickJS-NG, OpenSSL/AWS-LC, Wireshark among them) were not
  touched.

## Source-bound mechanism (pinned bytes)

`lab/frontier/pxeicmp2shell/pins/PxeBcSupport.c.vuln` is verbatim
`NetworkPkg/UefiPxeBcDxe/PxeBcSupport.c` from `edk2-stable202608`, sha256
`cb6ec00f556b07edd2f4e7c70654f81bfa87a945963da45db4c8176bba773918`;
`.fixed` is the same file at the merge commit, sha256
`78c50e389a14595b7eb054ef0f8053be3f852994a8d5611d9a6d899d18096e3c`.
`PxeBaseCode.h` sha256 `5e83eaa8db35518a923fefc3304d9c78a94d14df183b8fe4e1e5ca66ee763469`
fixes `sizeof(EFI_PXE_BASE_CODE_ICMP_ERROR) = 504`.

Vulnerable loop (IPv4 pinned lines 322-342, IPv6 lines 454-474): `CopiedLen`
is the *cumulative* fragment length; when it exceeds 504 the `else` copies
`CopiedLen - 504` bytes from the current fragment, and `IcmpError` is then
advanced by `CopiedLen`, not by the bytes actually written. Three 200-byte
fragments (600 bytes) make the third write start at `IcmpError + 600` and
copy 96 bytes: it begins 96 bytes into the adjacent 128-byte `TftpError`
field and ends 12 bytes past the 720-byte stand-in private structure. The fix
replaces the loop with `FragmentLen = MIN(fragment length, 504 - CopiedLen)`
and zeroes `IcmpError` first; both changes are in the pinned fixed source.

## Lab evidence (`lab/frontier/pxeicmp2shell/`)

`sh harness/run.sh` rechecks four pin hashes, re-extracts both handlers
byte-for-byte from the pins (CRLF preserved), builds plain and ASan binaries
for vulnerable and fixed sources, and reports **31 PASS / 0 FAIL, rc 0**;
a clean-directory replay is one of the checks. Raw results are in
`harness/evidence/*.out` and `lab/frontier/pxeicmp2shell/PROVENANCE.md`.

- ASan vulnerable, both families: `heap-buffer-overflow`, `WRITE of size 96`,
  `0 bytes after 720-byte region`, frame `generated/handlers_vuln.c:97`
  (IPv4) and `generated/handlers_vuln.c:206` (IPv6) — the verbatim pinned
  copy loop; rc 1.
- Plain vulnerable, both families: chosen fragment bytes `48 5a 4d 49`
  ("HZMI") land at `TftpError + 96`, and `54 41 55 46` ("TAUF") at
  canary[0..3], exactly where the pinned arithmetic predicts
  (`sizeof_icmperror=504`, `tftp_off=540`, `write_start_from_priv=636`,
  `past_priv_end=12`). `CHOSEN_BYTES_MATCH=1`.
- Controls: fixed source with the same 600-byte attack leaves `TftpError`
  `a5 a5 a5 a5` and canary `5a 5a 5a 5a`; safe input (3 × 100 = 300 bytes)
  leaves both unchanged; ASan fixed and ASan safe runs exit 0 with no report.

## Rung-4 feasibility and ceiling

Rung 3 is confirmed on the verbatim pinned handlers under ASan in both the
IPv4 and IPv6 paths. Rung 4 is PARTIAL: attacker-chosen fragment bytes land
at a predicted offset in an adjacent live field (`TftpError`) and in a
benign canary in the plain build. ASan redzones poison the bytes beyond the
allocation, so that chosen-byte observation is harness-only. There is no
real EDK2/OVMF build, no loopback ICMP delivery, no live DXE process, no
event-table target, no pointer/IP/command control and no rung 5. Stock DXE
allocator behavior, the advisory's event-forging chain, and whether a real
`PXEBC_PRIVATE_DATA` layout matches the stand-in offsets are UNKNOWN.

## Other candidates screened this wake (no stage)

- SOES/SOEM CVE-2026-129798/129811: already admitted as `soes2shell`, with
  four witness-checked CoE limbs; do not duplicate.
- Wireshark CVE-2026-130446 sACN discovery list (fix `daf4910f29e`): fix
  message states *no universe list wrote past the end*; only
  `_FORTIFY_SOURCE=3` aborts on the oversized `snprintf` bound. Structural
  zero-store consumer: rung 3/4 blocked, screened out.
- ClamAV CVE-2026-76411 (file scanner, previously screened), QuickJS-NG
  CVE-2026-120438/120439 (32-bit host only, `gcc -m32` cannot link here),
  OpenSSL CVE-2026-121481 (open PR, ~2 GiB input, disputed as a CVE),
  Danfoss CVE-2026-129713 (no source/fix bytes): none staged.
