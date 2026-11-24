# pxeicmp2shell — status

Admitted 2026-11-24 20:5xZ under standing approval #6 as the 135th engine
route. Claim: `CVE-2026-97631` / `GHSA-99cj-7hg9-mp4m`, "Pre-boot RCE in EDK II
PXE driver" (2026-10-22), Critical CVSS 4.0 9.5
`AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`, CWE-120/131/787.
Affected: EDK II master as of 2026-09-14; pinned reference
`edk2-stable202608` commit `2970e5699ba6267f3384ffab20f96647578aebc8`. Public
fix PR #13302 merged 2026-10-15 at
`fa789071ff0b29f1e568bfe153ef7f3d76bd60e4`. In both
`PxeBcIcmpErrorDpcHandle()` (IPv4) and `PxeBcIcmp6ErrorDpcHandle()` (IPv6),
`CopiedLen` accumulates fragment lengths while the destination advances by
that cumulative value; three 200-byte fragments make the third write start
96 bytes into the adjacent `TftpError` field and end 12 bytes past the
720-byte stand-in private structure. The advisory's DXE event-forging and
pre-boot RCE chain remains a claim; nothing here exercises it.

## Admission evidence

- Frontier brief `reports/frontier-pxeicmp2shell.md` (W214, commit
  `3a0fda26`); verbatim pinned source, generated handlers and raw evidence in
  `lab/frontier/pxeicmp2shell/` (`PROVENANCE.md`, `pins/`, `harness/`).
  `PxeBcSupport.c.vuln` sha256
  `cb6ec00f556b07edd2f4e7c70654f81bfa87a945963da45db4c8176bba773918`,
  `.fixed` sha256
  `78c50e389a14595b7eb054ef0f8053be3f852994a8d5611d9a6d899d18096e3c`,
  `PxeBaseCode.h` sha256
  `5e83eaa8db35518a923fefc3304d9c78a94d14df183b8fe4e1e5ca66ee763469`,
  all rechecked by the harness on every replay.
- Operator verification 20:4xZ: `cd lab/frontier/pxeicmp2shell &&
  sh harness/run.sh` gave **PASS=31 FAIL=0, rc 0**. Both pin extraction and
  verbatim-substring checks passed; ASan vulnerable runs abort in the IPv4 and
  IPv6 families with `heap-buffer-overflow`, `WRITE of size 96`, `0 bytes
  after 720-byte region` at `generated/handlers_vuln.c:97`. Plain runs place
  chosen fragment bytes `48 5a 4d 49` ("HZMI") at `TftpError + 96` and
  `54 41 55 46` ("TAUF") in the adjacent canary, matching the pinned
  arithmetic (`sizeof_icmperror=504`, `tftp_off=540`,
  `write_start_from_priv=636`, `past_priv_end=12`). Fixed-source attacks,
  300-byte safe inputs and the clean-directory replay are clean.
- Frontier's live two-pane window 143 (`pxeicmp2shell`, panes 288/289 verified
  by frontier at 20:46Z) and seed wall were adopted without duplication.
  Charter written; hy4-flash route 134→135, both resolver keys 269→271, wake
  units from the EXACT full-flag sync at pin
  `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
  daemon-reload, path enabled/active, pinned full-flag doctor GREEN rc 0.

## Current grade

Rungs 1-3 on the verbatim pinned IPv4 and IPv6 handlers under ASan. Rung 4 is
PARTIAL: chosen fragment bytes land at the predicted offset in the adjacent
live stand-in field and in a benign plain-build canary; ASan redzones poison
that memory in the instrumented build. No EDK2/OVMF firmware build, no
loopback ICMP error, no live DXE process, no event-table target, no pointer,
IP or command control and no rung 5. Stock DXE allocator behavior, whether a
real `PXEBC_PRIVATE_DATA` layout matches the stand-in offsets, and the
advisory's ring-0 event-forging claim stay UNKNOWN. Witness replay is OWED;
this evidence is the author/operator harness, not an independent verdict.

## Next

Independent witness replay of `sh harness/run.sh` from a clean copy of the
lab, then — only from an observed live write — a pinned EDK2/OVMF build with
a loopback ICMP error injected into a PXE-booting guest, with fixed and
valid-message controls. Nothing measured supports r5.
