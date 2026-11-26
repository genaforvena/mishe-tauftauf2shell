# PROVENANCE — libarchivezippath2shell

## Scope

Local, loopback-free reproduction of CVE-2026-45308 / GHSA-xgqq-r5j8-3mch in
the shipped `bsdtar` CLI. All sources are public advisory/commit material
(read-only provisioning); no external system was probed. Nothing here claims
remote execution or rung 4.

## Pins (SHA-256, local files)

- `src/libarchive-3.8.7.tar.gz`
  `4b787cca6697a95c7725e45293c973c208cbdc71ae2279f30ef09f52472b9166`
  (vulnerable release; tag `v3.8.7`)
  URL: https://github.com/libarchive/libarchive/releases/download/v3.8.7/libarchive-3.8.7.tar.gz
- `src/libarchive-3.8.8.tar.gz`
  `038918ea315cdd446cc63acfe880d6011832bbe1711c887de5de5441b306c190`
  (fixed release; tag `v3.8.8`)
  URL: https://github.com/libarchive/libarchive/releases/download/v3.8.8/libarchive-3.8.8.tar.gz
- `src/fix.patch`
  `cb9a18bb9e733e6d4063b5f9d762401ce36dfd070b88827dc43774f832a49bad`
  URL: https://github.com/libarchive/libarchive/commit/a20f89eb9b6eed62ee691b4d36fdf4e1216e0ba1.patch
- `src/gen_tar.py`
  `97dd8da208989c522015d99cecbc27a95be053c62e351f5da043f28ddf7a3044`
- Vulnerable `libarchive/archive_write_set_format_zip.c`
  `eafecfa369d89eedf26731332280f2759c66928ca26080e19ec764cbfa01c936`
- Fixed `libarchive/archive_write_set_format_zip.c`
  `63ef63f7f65f1273abfd177b4d37e0a9767e727a4ed3901992984c10b3c0f1c3`
- Patched 3.8.7 `libarchive/archive_write_set_format_zip.c`
  `09c204338ffea7eba194a6a5de7c09265815bb258934cc24214d61ebc0e9867b`
  (differs from 3.8.8 because the releases differ elsewhere; both carry the
  same `filename_length > 0xffff` guard).
- Crafted tars: safe (path 65535)
  `789ed4848784071f9f59c9c40ad7c6a87c0f1f13e1c75ec79615e861cf3011f2`,
  edge (65537) `ddaf647493ef2138c4d07e22d8547950d8f514cb5ae4e50f2d62bd831ce7b2f0`,
  poc (131072) `47f183663e98ce600de44352733ac090625312cba339304550401ca39c1f24e8`.

## Build and inputs

Both sides: `./configure --disable-shared --enable-static
CFLAGS='-O1 -g -fsanitize=address -fno-omit-frame-pointer'
LDFLAGS='-fsanitize=address' && make -j6` (GCC ASan, x86-64 Linux).
`gen_tar.py` writes a deterministic PAX-format tar with one entry; the first
65536 pathname bytes are `A`, every byte past that point repeats the 16-byte
marker `CHOSEN-DEADBEEF!`. Entry body is one `B`. Conversion command:
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./build-*/bsdtar --format=zip
-cf OUT.zip @IN.tar`.

The upstream fix patch applies cleanly to a separate copy of pinned 3.8.7.
During provisioning the fix patch was briefly applied to the vulnerable tree
by mistake and immediately reversed with `patch -R`; the runner re-extracts
from the pinned tarball and asserts the vulnerable source hash, so the shipped
vulnerable bytes are authoritative.

Boundary nuance: a 65536-byte path is ASan-clean on vulnerable 3.8.7 but is
rejected by fixed 3.8.8, because `0xffff` is the real ZIP name-field maximum
and 65536 encodes as zero. The safe control therefore uses 65535 bytes, which
both builds accept. The first vulnerable overflow byte is at offset 65536.

## Observations (shipped CLI, no synthetic caller)

Vulnerable 3.8.7 + edge tar: GCC ASan `heap-buffer-overflow`, `WRITE of size
65537`, `0 bytes after 65536-byte region`, sink `copy_path
libarchive/archive_write_set_format_zip.c:2328`, caller
`archive_write_zip_header ...:1193`. Vulnerable 3.8.7 + poc tar: same report
with `WRITE of size 131072`. Vulnerable + safe tar: rc 0, no ASan report,
non-empty ZIP. Official 3.8.8 on edge and poc: rc 0, no ASan report,
`Pathname too long for ZIP format` error and a 22-byte empty ZIP. Traces are
under `evidence/`; outputs under `out/`. `sh run-all.sh` rebuilds everything
from the pinned tarballs, asserts all hashes and prints PASS/FAIL counts into
`console.log`.

## Rung discipline

Rung 3 (ASan-confirmed corruption) is established through the shipped CLI:
chosen file bytes cross an exact 64 KiB heap boundary. Rung 4 is NOT CLAIMED:
ASan places the chosen bytes in an uninstrumented redzone, no adjacent live
object, pointer, control-flow target, socket or command was demonstrated, and
no plain-build groom/victim experiment has been run. The advisory itself is
CVSS Low/AV:L/AC:H/UI:R and claims memory corruption only. No rung 5: this is
an archive-conversion CLI path, not a live network listener; there is no
unauthenticated wire input.
