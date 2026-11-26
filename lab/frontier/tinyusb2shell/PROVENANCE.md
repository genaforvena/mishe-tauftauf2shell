# PROVENANCE — tinyusb2shell (W275, 2026-11-26)

All fetches were public provisioning reads; no external target was probed, no
USB hardware was attached and no socket was used. Everything executed was local.

## Pins and exact bytes

- Vulnerable: `5014146fef1aac07362ee35c0c361b8475f7636d`, parent of the fix
  (verified on the fix commit page: "1 parent 5014146fef1aac07362ee35c0c361b8475f7636d").
  Fixed: `85047e1777f5c20b7a936aa905c746125d3ed066` (one file, +5/-1). The
  fix is in tag 0.21.0; no `0.20.1` tag exists upstream.
- Codeload tarballs and SHA-256:
  `https://codeload.github.com/hathach/tinyusb/tar.gz/5014146fef1aac07362ee35c0c361b8475f7636d`
  = `a732b2e396ecfd6a4ccac9e17942c57d286faec66f711d584e236043a7a606fd`;
  `https://codeload.github.com/hathach/tinyusb/tar.gz/85047e1777f5c20b7a936aa905c746125d3ed066`
  = `04e410dfd6b90162585469febba424a80e067b36979fffa7218af814f004881d`.
- Verbatim `src/class/hid/hid_host.c` SHA-256: vulnerable
  `3bdc96068c50745a9cefa3a486face8c464e94a5d65fde09e99deea8c822342c`; fixed
  `96baa31735e64f8b2f34bd0410829a090f7de574c845a022b2a1659e811907d5`.
  `diff -u` of those two files shows exactly the two fix hunks quoted in the brief.
- Sliced parser (`sed -n '/^uint8_t tuh_hid_parse_report_descriptor(/,/^}/p'`
  on each pinned file): vulnerable 131 lines
  `283b2ed7bf675e86ff27e94da25ae13b0e1b779bd1ef88ca73121bf24e2ba979`; fixed
  135 lines `47455541749e25fa6c2d685f1174fdb754c1b4973f0db37187689ff553d4369f`.
- Local files SHA-256: `run-all.sh` `e8ba3567a7cb6af60fe1b86880551ef1cc20f1e151a95cf9529b0add484d90aa`,
  `verify.sh` `890cc19b00f9b556a58077d1283e35fe2725cdefab0dc50a8a4bd9fa35b94eaf`,
  `harness/driver.c` `3d8a171e8d358d123a91c5881301400aa6dade15b4354af18638b383fd943693`,
  `harness/shim.h` `ebf101415c6558d509c1c266e915dfb2532744c39f79343a569b0280580e2341`,
  console `evidence-run-console.log`
  `05d996bb2ad00822e5b581308cc463f42d4dbb46566165a73e1b869d815b37f4`.

## Reproduce

Refetch the two tarballs to `src/vuln.tar.gz` and `src/fixed.tar.gz`, check the
hashes above, `tar xzf` each into `src/` (trees/tarballs are gitignored). Then:

```
sh ./run-all.sh | tee evidence-run-console.log
sh ./verify.sh | tee -a evidence-run-console.log
```

`run-all.sh` slices the parser function verbatim from each pinned tree and
compiles GCC 12 `-fsanitize=address` with `harness/driver.c`. The only local
additions are the driver, `harness/shim.h` (constant values copied from pinned
`src/class/hid/hid.h` and `hid_host.h`) and include paths. No upstream file is
modified.

## Inputs and observed bytes

- Underflow input, 4 bytes `05 01 07 DE` (researcher PoC): vulnerable ASan
  `heap-buffer-overflow` `READ of size 4` at sliced parser line 68, 0 bytes
  past the exact 4-byte heap descriptor; rc 1. Fixed rc 0 `report_num=0`.
- Destination-bound input, 5 bytes `07 DE AD BE EF`: vulnerable ASan
  `stack-buffer-overflow` `WRITE of size 4` into the driver's 4-byte `info`
  struct; rc 1. Fixed rc 0, `usage_page=44510` (`0xADDE`).
- Well-formed 13-byte descriptor: both pins rc 0, `report_num=1`,
  `usage_page=1`, no ASan report.
- `verify.sh`: `RESULT PASS=6 FAIL=0` at 15:49Z.

## Preserved negatives and caveats

- No live USB stack, simulated device, hardware or socket: the descriptor is
  an in-memory heap buffer with exact size so ASan can see the overrun. The
  AV:P attack vector is the advisory's claim, not an observed path here.
- The underflow's ASan report fires at the oversized usage-page `memcpy`, not
  at the later post-wrap header reads; ASan stops the first invalid access.
  The follow-on 65533-iteration walk is inferred from the arithmetic, not
  observed to completion.
- The WRITE is into a local driver struct, not a live heap neighbor; it proves
  the missing destination bound, not control of an adjacent object.
- No chosen-offset readback, pointer steering, command or r5. Only GCC 12 ASan
  was run; Clang was not.
- Advisory inconsistency preserved: GHSA says "before 0.20.1", CVE/NVD/VulnCheck
  and the fix release say "before 0.21.0"; no 0.20.1 tag exists. The GHSA is
  unreviewed and NVD-imported, not repo-published. The extra `usage_page = 0`
  at tag 0.21.0 is not part of the fix commit; its origin is UNKNOWN.
