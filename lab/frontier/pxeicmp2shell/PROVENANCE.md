# PROVENANCE — pxeicmp2shell lab (CVE-2026-97631)

## Pinned inputs (read-only provisioning; no external probing)

- `pins/PxeBcSupport.c.vuln`: verbatim
  `NetworkPkg/UefiPxeBcDxe/PxeBcSupport.c` at tag `edk2-stable202608`
  (commit `2970e5699ba6267f3384ffab20f96647578aebc8`), fetched from
  `https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202608/NetworkPkg/UefiPxeBcDxe/PxeBcSupport.c`.
  sha256 `cb6ec00f556b07edd2f4e7c70654f81bfa87a945963da45db4c8176bba773918`.
- `pins/PxeBcSupport.c.fixed`: verbatim same file at merged PR head
  `fa789071ff0b29f1e568bfe153ef7f3d76bd60e4`. sha256
  `78c50e389a14595b7eb054ef0f8053be3f852994a8d5611d9a6d899d18096e3c`.
- `pins/PxeBaseCode.h` (sha256
  `5e83eaa8db35518a923fefc3304d9c78a94d14df183b8fe4e1e5ca66ee763469`)
  supplies the real `EFI_PXE_BASE_CODE_ICMP_ERROR` layout: 504 bytes,
  followed by the 128-byte `TftpError` field in `MODE`.
- `pins/PxeBcImpl.h` (sha256
  `67766f7945862c1a46d9f2be57962510f4a4bfc0a97540e6e94708627aea6fb0`)
  confirms the private structure fields `Mode`, `Ip4`, `Ip6`, `IcmpToken`,
  `Icmp6Token` used by both handlers.
- `pins/SHA256SUMS` is rechecked by `run.sh` on every run. The PR diff
  (`https://github.com/tianocore/edk2/pull/13302.diff`) and the advisory
  pages were read only; no QEMU/OVMF build and no packet were sent anywhere.

## Stand-ins and verbatim extraction

The EDK2 build needs the full UEFI environment, so
`harness/standin.h` defines only the types, constants and macros that the two
pinned handlers reference. It keeps the real ICMP/TFTP field order and sizes.
`harness/extract.py` extracts the two handler bodies by brace matching from
the pinned files, preserving CRLF line endings; `generated/extract-index.txt`
records source hashes, character spans and extracted hashes for all four
handlers (v4/v6 × vulnerable/fixed). `run.sh` re-runs extraction and checks
each extracted body is a byte-exact substring of its pin. No pinned byte was
hand-edited.

## Exact build commands (from `lab/frontier/pxeicmp2shell/harness/`)

```
cd .. && sha256sum -c pins/SHA256SUMS
cd harness && python3 extract.py
cc -O0 -g -std=c11 -I. harness.c generated/handlers_vuln.c -o plain-vuln
cc -O0 -g -std=c11 -I. harness.c generated/handlers_fixed.c -o plain-fixed
cc -O0 -g -fsanitize=address -std=c11 -I. harness.c generated/handlers_vuln.c -o asan-vuln
cc -O0 -g -fsanitize=address -std=c11 -I. harness.c generated/handlers_fixed.c -o asan-fixed
./plain-vuln v6 attack canary
./plain-vuln v4 safe canary
EXPECT=unchanged ./plain-fixed v4 attack canary
./asan-vuln v4 attack heapexact
EXPECT=unchanged ./asan-fixed v4 attack heapexact
```

`sh run.sh` executes these plus offset assertions, ASan text assertions and
a clean-directory replay; observed result **31 PASS / 0 FAIL, rc 0**.
Scoped stage commit `3a0fda26`; `git archive 3a0fda26
lab/frontier/pxeicmp2shell | tar x -C /tmp/w214-pxe` followed by
`sh harness/run.sh` in the extracted tree also gave 31 PASS / 0 FAIL, rc 0.

## Observed values

- `sizeof(EFI_PXE_BASE_CODE_ICMP_ERROR)=504`, `sizeof(MODE)=668`,
  `sizeof(PXEBC_PRIVATE_DATA)=720` in the stand-in; `icmp_off=36`,
  `tftp_off=540`.
- Attack (3 × 200 bytes): `write_start_from_priv=636`,
  `write_start_from_tftp=96`, `past_priv_end=12`; copied length 96.
- ASan: `WRITE of size 96`, `0 bytes after 720-byte region`,
  `generated/handlers_vuln.c:97`, rc 1 for both IPv4 and IPv6.
- Plain: `tftp_offset=96 bytes=48 5a 4d 49`, `canary_offset=0
  bytes=54 41 55 46`, `CHOSEN_BYTES_MATCH=1` for both families.
- Fixed and safe controls: `a5 a5 a5 a5` / `5a 5a 5a 5a`,
  `FIXED_CONTROL_CLEAN=1` / `SAFE_CONTROL_CLEAN=1`; no ASan report, rc 0.

## Preserved failures and limits

- First harness revision placed `Mode` in a stack-local private structure;
  ASan correctly reported a *stack* overflow at the end of that frame. The
  driver was rewritten to heap-allocate the private data so the ASan report
  is a bounded 720-byte heap region with an exact zero-byte-past offset.
- An earlier extraction normalized CRLF and produced hash mismatches against
  the pins; `extract.py` now reads bytes and anchors on CRLF.
- The safe-input case initially compared the attack probe offset (negative
  for 300-byte input) instead of the predicted attack offset; it now probes
  the fixed 96-byte offset and requires `TftpError`/canary unchanged.
- No EDK2/OVMF firmware build, no loopback ICMP delivery, no live DXE
  process, no event-table or pointer control, no allocator-metadata claim,
  no command execution and no rung 5. Stock DXE allocator outcome and the
  advisory's event-forging chain stay UNKNOWN.
