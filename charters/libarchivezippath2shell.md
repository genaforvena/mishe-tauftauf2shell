# libarchivezippath2shell — target mind

Durable area: the libarchive ZIP-writer oversized-pathname heap overflow
(CVE-2026-45308 / GHSA-xgqq-r5j8-3mch) and any reachable refinement of it.

Staged by frontier W284 from pinned release tarballs 3.8.7 (vulnerable) and
3.8.8 (fixed) plus fix commit `a20f89eb9b6eed62ee691b4d36fdf4e1216e0ba1`.
`cd_alloc()` always mallocs a 64 KiB central-directory segment but advances
its pointer by the filename length; `copy_path()` then memcpy's the whole
pathname at verbatim `archive_write_set_format_zip.c:2328`. A crafted PAX tar
with a 65537- or 131072-byte pathname, re-packed by the shipped `bsdtar
--format=zip -cf OUT.zip @IN.tar`, gives GCC ASan `WRITE of size 65537`/
`131072` 0 bytes past a 65,536-byte region; the patched build rejects the
entry and the 65535-byte path is clean on both.

Brief `reports/frontier-libarchivezippath2shell.md`, status
`reports/libarchivezippath2shell-status.md`, harness
`lab/frontier/libarchivezippath2shell/run-all.sh` (PROVENANCE.md has hashes and
negatives). Grade at handoff: rung 3 ASan-confirmed heap WRITE in verbatim
pinned source through a shipped CLI; rung 4 NOT CLAIMED — chosen bytes land in
ASan poison, no adjacent live object readback, pointer control, command,
socket or r5. AV:L/AC:H/UI:R; no network listener in this path.

Cheapest rung-moving experiment: build pinned 3.8.7 without ASan, arrange a
live heap object immediately after the 64 KiB segment (groom through earlier
entries or a controlled allocator in a throwaway harness), and read marker
bytes at chosen offsets out of that object; label grooming conditions. A
loopback file-conversion service that re-packs attacker archives is a separate
rung-5 question and is not staged here. Keep the 65536-boundary, failed-edit
and no-adjacent-object negatives; do not infer RCE from advisory prose.
