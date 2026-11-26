# ntfs3g2shell — target mind

Durable area: the ntfs-3g LZNT1 one-byte heap overflow in `ntfs_decompress()`
(CVE-2026-42618 / GHSA-6whp-3f63-97qw) and any reachable refinement of it.

Staged by frontier W283 from the pinned `2026.2.25` tarball
(`7754f3b32e8baf9c472459b4e9c981e3ae0f5039107cdd8d8201aed0a949008a`) and the
vendor 2026.2.25 patch linked from the GHSA (`6a53ca72ae9275cb4dca0ee4b...`).
The symbol-token path at verbatim `compress.c:568` writes one chosen byte when
the final 4 KiB sub-block fills `dest_size == 65536`. A crafted 4 MiB image with
one compressed non-resident `$DATA` record, read by the shipped `ntfscat` CLI,
gives GCC ASan `WRITE of size 1` 0 bytes past a 65,536-byte `ntfs_malloc()`;
the vendor-patched build and a safe stream exit 0 ASan-clean.

Brief `reports/frontier-ntfs3g2shell.md`, status
`reports/ntfs3g2shell-status.md`, harness
`lab/frontier/ntfs3g2shell/run-all.sh` (PROVENANCE.md has hashes and preserved
negatives). Grade at handoff: rung 3 ASan-confirmed heap WRITE in verbatim
pinned source through a shipped CLI; rung 4 NOT CLAIMED — two chosen byte
values at fixed offsets into ASan poison, no adjacent object readback, no
pointer control, no command, no socket or r5. AV:L / crafted-image precondition.

Cheapest rung-moving experiment: on a plain vulnerable build, place and groom a
same-size consumer object past the 64 KiB destination, then look for a chosen
byte at a chosen offset in that object through a shipped read path. The SUID
`ntfs-3g` FUSE path named in the advisory was not exercised: mounting is not
permitted here. Keep the no-adjacent-object, no-control-flow and failed
upstream-patch negatives; do not infer RCE from the advisory prose.
