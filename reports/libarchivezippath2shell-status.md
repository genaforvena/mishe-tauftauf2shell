# libarchivezippath2shell — status (STAGED W284, 19:0xZ)

Staged by frontier W284 after a clean-archive replay: brief
`reports/frontier-libarchivezippath2shell.md`, charter
`charters/libarchivezippath2shell.md`, seed wall
`.mishe-tauftauf/walls/libarchivezippath2shell.md`, harness
`lab/frontier/libarchivezippath2shell/` (`PROVENANCE.md` has pins, hashes,
traces and preserved negatives). Window 193 on the inner tmux socket, panes
%390/%391, dead=0, tail/python3 live; registry 194/194 unique names. Awaiting
operator admission and independent witness replay.

- Pins: vulnerable tarball 3.8.7 SHA-256
  `4b787cca6697a95c7725e45293c973c208cbdc71ae2279f30ef09f52472b9166`; fixed
  tarball 3.8.8 SHA-256
  `038918ea315cdd446cc63acfe880d6011832bbe1711c887de5de5441b306c190`; fix
  commit `a20f89eb9b6eed62ee691b4d36fdf4e1216e0ba1`, patch SHA-256
  `cb9a18bb9e733e6d4063b5f9d762401ce36dfd070b88827dc43774f832a49bad`.
- Mechanism: `cd_alloc()` always mallocs 64 KiB but advances its pointer by the
  unchecked filename length; `copy_path()` then memcpy's the whole PAX
  pathname into it (verbatim pinned `archive_write_set_format_zip.c:2328` via
  `:1193`). The fix rejects `filename_length > 0xffff` before allocation.
- Input: deterministic PAX tar with one entry; path 65537 bytes (`A`*65536 then
  `C` of marker `CHOSEN-DEADBEEF!`) or 131072 bytes (marker at every offset
  ≥ 65536); safe control path 65535 bytes.
- `sh run-all.sh`: `RESULT PASS=40 FAIL=0`. Vulnerable GCC ASan `WRITE of size
  65537`/`131072`, `0 bytes after 65536-byte region`, frames
  `copy_path ...:2328 <- archive_write_zip_header ...:1193`, rc 1. Fixed 3.8.8
  on both oversized paths: rc 0, no ASan, `Pathname too long for ZIP format`,
  22-byte empty ZIP. Both builds accept the 65535 path ASan-clean.
- Grade: rung 3 ASan in verbatim pinned source via shipped CLI / rung 4 NOT
  CLAIMED — chosen bytes are in ASan poison, no adjacent live object, pointer,
  command, socket or r5. Advisory is AV:L/AC:H/UI:R and claims corruption only.
- Preserved negatives: 65536-byte path is ASan-clean on 3.8.7 but rejected by
  3.8.8 (real ZIP name limit is `0xffff`); fix patch was briefly applied to the
  vulnerable tree during provisioning and immediately reversed, then the
  runner re-extracts from pinned tarball and asserts source hash; no plain
  build or adjacent-object readback yet; no network listener.
- Owed: operator admission, witness clean-archive replay, plain-build
  chosen-offset experiment. Frontier does not duplicate this lane.
