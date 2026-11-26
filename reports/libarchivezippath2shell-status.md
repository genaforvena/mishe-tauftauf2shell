# libarchivezippath2shell — status (ADMITTED 2026-11-26 19:2xZ)

ADMITTED under standing #6 as the 184th declared target mind; staged window 193
adopted (panes %390/%391 live, dead=0, registry 194/194 unique names, no
duplicate). Brief `reports/frontier-libarchivezippath2shell.md`, charter
`charters/libarchivezippath2shell.md`, seed wall
`.mishe-tauftauf/walls/libarchivezippath2shell.md`, harness
`lab/frontier/libarchivezippath2shell/` (`PROVENANCE.md` has pins, hashes,
traces and preserved negatives).

- Pins: vulnerable tarball 3.8.7 SHA-256
  `4b787cca6697a95c7725e45293c973c208cbdc71ae2279f30ef09f52472b9166`; fixed
  tarball 3.8.8 SHA-256
  `038918ea315cdd446cc63acfe880d6011832bbe1711c887de5de5441b306c190`; fix
  commit `a20f89eb9b6eed62ee691b4d36fdf4e1216e0ba1`, patch SHA-256
  `cb9a18bb9e733e6d4063b5f9d762401ce36dfd070b88827dc43774f832a49bad`.
- Claim source: GHSA `GHSA-xgqq-r5j8-3mch` / CVE-2026-45308 (published
  2026-08-24, Low CVSS 3.1 `AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N`, CWE-787,
  affected <= 3.8.7, patched >= 3.8.8). The finder claims memory corruption
  only, no code execution; the advisory prose is a claim, not a result.
- Mechanism: `cd_alloc()` always mallocs a 64 KiB central-directory segment but
  advances its pointer by the unchecked filename length; `copy_path()` then
  memcpy's the whole PAX pathname into it at verbatim pinned
  `archive_write_set_format_zip.c:2328` via `archive_write_zip_header` :1193.
  The fix rejects `filename_length > 0xffff` before allocation.
- Input: deterministic PAX tar with one entry; path 65537 bytes (`A`*65536 then
  `C` of marker `CHOSEN-DEADBEEF!`) or 131072 bytes (marker at every offset
  ≥ 65536); safe control path 65535 bytes. No synthetic caller: sink and caller
  are in verbatim pinned library code reached through the shipped `bsdtar` CLI.
- Author harness `sh run-all.sh`: `RESULT PASS=40 FAIL=0`. Vulnerable GCC ASan
  `WRITE of size 65537`/`131072`, `0 bytes after 65536-byte region`, frames
  `copy_path ...:2328 <- archive_write_zip_header ...:1193`, rc 1. Fixed 3.8.8
  on both oversized paths: rc 0, no ASan, `Pathname too long for ZIP format`,
  22-byte empty ZIP. Both builds accept the 65535 path ASan-clean.
- Operator clean-archive replay 19:2xZ: `git archive HEAD
  lab/frontier/libarchivezippath2shell` with only the ignored pinned
  `src/libarchive-3.8.7.tar.gz`, `src/libarchive-3.8.8.tar.gz` and `src/fix.patch`
  copied in; runner sha256
  `8bbd65aa752ab4364ce50d4bf6b9975a4f1e648f53c277ca41b167313fc4c919`, tarball
  and patch hashes matched PROVENANCE, `sh run-all.sh` rc 0. No author build,
  out or extracted source was reused.
- Grade: **rung 3 ASan in verbatim pinned source via a shipped CLI / rung 4 NOT
  CLAIMED** — chosen bytes are in ASan poison, no adjacent live object, pointer,
  control-flow target, command, socket or r5. Advisory vector is local with
  user interaction; no network listener in this path.
- Preserved negatives: 65536-byte path is ASan-clean on 3.8.7 but rejected by
  3.8.8 (real ZIP name limit is `0xffff`); fix patch was briefly applied to the
  vulnerable tree during provisioning and immediately reversed, then the
  runner re-extracts from pinned tarball and asserts source hash; no plain
  build or adjacent-object readback yet.
- Owed: independent witness clean-archive replay; the named lane experiment —
  build pinned 3.8.7 without ASan, arrange a live heap object immediately after
  the 64 KiB central-directory segment (groom through earlier entries or a
  controlled allocator in a throwaway harness), and read chosen marker bytes at
  chosen offsets out of that object with fixed and safe-input controls; label
  the grooming conditions. A loopback file-conversion service that re-packs
  attacker archives is a separate rung-5 question, not part of this stage.
