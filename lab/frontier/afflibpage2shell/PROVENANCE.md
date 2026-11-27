# afflibpage2shell harness provenance (W303, 2026-11-27)

All fetches were read-only provisioning from public GitHub, CVE/GHSA and
VulnCheck pages; no target system was contacted. All runs are local files under
`lab/frontier/afflibpage2shell/`; no sockets or external probes.

## Pins

- Vulnerable archive: `https://github.com/sshock/AFFLIBv3/archive/refs/tags/v3.7.22.tar.gz`
  → `pins/vuln.tar.gz`, SHA-256
  `67481fc520ff927bf61aea0bf2d660feb73e24cc329335bebb064f8f12115dcb`.
  Tag `v3.7.22` is commit `f6e51a8367cff73ea24c0adf09e533483c80ecd4`
  (verified from `https://api.github.com/repos/sshock/AFFLIBv3/tags`, pinned
  as `pins/tags.json`).
- Fixed archive: `https://github.com/sshock/AFFLIBv3/archive/refs/tags/v3.7.23.tar.gz`
  → `pins/fixed.tar.gz`, SHA-256
  `b09334cd690ebe28ef182b00b59a426db662417b90bb9fd4985b11df5654fca4`.
  Tag `v3.7.23` is commit `a1d6b350d283f4f5bff2afece8f5247b0c438a34`.
- Verbatim fix patch:
  `https://github.com/sshock/AFFLIBv3/commit/04e75b65257c8e43cd911cb669b49b26edd4283e.patch`
  → `pins/fix.patch`, SHA-256
  `6efc1a185de1e416887ef40d1e1076ee076c0388c2d6cec4ba8dad9931aa1c70`.
  One file, +13/-1 in `lib/afflib_pages.cpp`.
- Pinned `lib/afflib_pages.cpp` blobs: vulnerable
  `52f803606d850ac49df28491495eb999350abd873a5a0a53b4711776390b3499`, fixed
  `8363ba1c6c636f71dcdbbfefeef9e7d9310ef58ce59e229e117a99eb57f5da74`.

## Input provenance

`gen_aff.py` is frontier code, not a transcription of the reporter's writeup.
It writes a 617-byte AFF container with `badflag`, `sectorsize=4096` and
`pagesize=100` segments. The container framing is read from pinned
`lib/vnode_aff.cpp:112-153` (`aff_write_seg`: 16-byte head with `AFF\0` magic,
big-endian name/data lengths and arg, then name, data and an 8-byte `ATT\0`
tail); the 8-byte file header is `AFF10\r\n\0` from `afflib_i.h:482`. The
public HackMD PoC URLs in GHSA #61 return HTTP 404/403 and the Wayback CDX API
has no capture; no public runtime PoC was recovered. The safe control uses
`sectorsize=512`, `pagesize=4096`, the same framing.

## Build and run

`sh build-all.sh` verifies the pin checksums, extracts each archive only when
its tree is absent, bootstraps/configures it, builds the static library four
times (both pins with GCC ASan and without sanitizers), and compiles
`harness.cpp` against each tree. `sh run-all.sh` regenerates both images,
checks all source/harness/vector pins, asserts the vulnerable loop and the two
fix guards, then runs the ASan and plain controls. Observed 2026-11-27 W303:
rc 0 `PASS=29 FAIL=0`; runner SHA-256
`f2e166d0907e746dfcd2382e51ede996cc8d8269538519ab500896633f9339ff`.
Host: GCC/g++ 13.3.0 with `libasan.so.8`, glibc 2.39, autotools 2.71/1.16.
No ASLR manipulation, LD_PRELOAD, debugger-forced execution or network
service was used.

## Scaffolding vs upstream

No upstream source file was edited. `harness.cpp` calls the pinned library's
`af_open`, `af_update_seg`, `af_close` and the internal `af_get_page`; ASan
frames come from the pinned `lib/afflib_pages.cpp` compiled in-tree. The
caller's 100-byte page buffer is supplied by the harness, so rung 3 is an
invalid write in the verbatim pinned sink but not a stock application call.
The fix guard is exercised by the same harness calling the same symbol on the
fixed library.

## Negatives preserved

- The public PoC writeups are unavailable; our image is constructed from the
  pinned container format, not copied from the reporter.
- The reporter states no runtime exploit was developed; no public sanitizer
  log was found.
- Plain vulnerable `CANARY` mode faults (SIGSEGV) before its readback because
  the unsigned-underflow loop keeps writing; chosen-byte readback is therefore
  NOT claimed. The fixed plain control leaves the canary byte-exact (`0xcc`).
- Safe geometry (`sector=512`, `page=4096`) returns rc 0 with a full 4096-byte
  page on both pins and no ASan finding. The overflow needs the invalid
  geometry, not merely a missing page.
- Advisory CVSS is AV:L/UI:P and covers crafted local forensic images; no
  wire/request-facing consumer was established. Rung 4 and rung 5 are not
  claimed.
