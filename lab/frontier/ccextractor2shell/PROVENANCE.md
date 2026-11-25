# ccextractor2shell — provenance

## Provisioning

- Upstream: `https://github.com/CCExtractor/ccextractor.git`, cloned to
  `upstream/` on 2026-11-25, shallow depth 1.
- Pinned HEAD: `2c1c1c6f0602563d2064f2b0c36f13b3c7a09489`
  (`2026-11-24T07:50:42-0800`, "Clear the decoders' caption counts after a
  report (#2495)").
- Public claim: `https://github.com/CCExtractor/ccextractor/issues/2500`,
  opened `2026-11-24T13:58:29Z`, still open at staging time. No CVE/GHSA
  found; no upstream fix PR found, so the fix status is UNKNOWN and the
  guarded build below is a local hunk, not a vendor patch.
- Fetching/cloning is provisioning only. No probe touched any external
  target; the harness is local and reads no network.

## Verbatim source, stand-ins, and edits

| Artifact | Origin | Modification |
| --- | --- | --- |
| `harness/parse_mpeg_packet.inc` | `src/lib_ccx/ccx_gxf.c:938-949` at pinned HEAD | none — verbatim function; header comment added above it |
| `harness/parse_media_pin.inc` | `src/lib_ccx/ccx_gxf.c:1146-1151,1199-1221` at pinned HEAD | excerpts only; `...` marks omitted unrelated lines |
| `harness/harness.c` | written locally | stand-in `struct demuxer_data`, `struct ccx_demuxer`, `buffered_get_be32`, `buffered_read`; attacker input assembled from a 4-byte wire header |
| `harness/harness.c` FIXED_BUILD | written locally | local guard `if (data->len + (size_t)len > BUFSIZE) return CCX_EOF;` — NOT an upstream patch |

`BUFSIZE` is verbatim `ccx_common_constants.h:33` (`2048*1024 + ONEPASS`,
`ONEPASS=120` → 2097272). `data->buffer = malloc(BUFSIZE)` is verbatim
`ccx_demuxer.c:452`. The real consumer behind `buffered_read` is
`src/lib_ccx/file_functions.c:376` (`read(2)` into the destination); the
harness stand-in copies the same attacker-supplied bytes with `memcpy` so
the sink's bounds behavior is observable under ASan.

`pins.sha256` records the pinned source files and the verbatim excerpt
files. Rendered source line numbers are claims; the excerpts and hashes are
the evidence.

## Observed results (2026-11-25, this host)

- `gcc -O1 -g -fsanitize=address -DASAN_BUILD`, attack header
  `00 20 10 00` → derived `mpeg_pic_size=2101248`: ASan
  `heap-buffer-overflow`, `WRITE of size 2101248`, `0 bytes after
  2097272-byte region`, stack `buffered_read harness.c:71` →
  `parse_mpeg_packet.inc:10` → `main`. Safe header `00 00 10 00`
  (4096 bytes) is clean.
- `clang -O1 -g -fsanitize=address -DASAN_BUILD` with default builtins did
  **not** report the overflow (preserved negative); adding
  `-fno-builtin-memcpy` produced the same ASan WRITE report.
- Plain build with slack allocation (required to read back bytes past the
  nominal boundary without a segfault): `canary_at_BUFSIZE=` and
  `expected=` both `5348452d434345584d495348452d4343` — the repeating
  `MISHE-CCEX` pattern rotated by `BUFSIZE % 10 == 2`, decoding to
  `SHE-CCEXMISHE-CC`. The label samples bytes at the nominal BUFSIZE
  boundary; the `0xCC` sentinel is at `BUFSIZE+4000`, past the write end.
- Local-guard FIXED_BUILD: attack returns `CCX_EOF` (`ret=1 past=0`), no
  chosen bytes; safe mode clean in every build.

Full matrix: `harness/run.sh`, evidence in `harness/evidence/`.

## Honest ceiling

Rung 3 in the pinned verbatim function with a stand-in read consumer; rung 4
PARTIAL for chosen bytes at a chosen offset in a stand-in allocator layout.
No real ccextractor build, no GXF file or wire path, no live process, no
pointer/IP/command control, no rung 5. Witness verdict UNKNOWN.
