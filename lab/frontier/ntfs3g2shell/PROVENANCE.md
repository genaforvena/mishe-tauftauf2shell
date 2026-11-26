# PROVENANCE — ntfs3g2shell (frontier W283, 2026-11-26)

## Claim and pins

- GHSA `https://github.com/tuxera/ntfs-3g/security/advisories/GHSA-6whp-3f63-97qw`
  (High, AV:L/AC:H, affected 2026.2.25 and earlier, patched 2026.7.7), CVE-2026-42618.
  One chosen heap byte via crafted compressed NTFS image, read through the
  SUID-root `ntfs-3g` binary; no public PoC found. Details in
  `reports/frontier-ntfs3g2shell.md`.
- Vulnerable tarball `2026.2.25`, fixed release `2026.7.7`; fix commit
  `6aa66d98980ac1d966d7977c7b079f4fe380eb42`. The vendor-specific 2026.2.25
  patch linked from the GHSA was provisioned in W282; its exact URL was not
  preserved in the wake record, so this lab labels it only by SHA-256 and does
  not claim a URL. The upstream fix commit's `.patch` failed 6 of 8 hunks on
  the 2026.2.25 tag (negative preserved in the brief); only the vendor patch
  is used for the fixed control.

## Provisioning and hashes (SHA-256)

    src/ntfs-3g_ntfsprogs-2026.2.25.tgz  7754f3b32e8baf9c472459b4e9c981e3ae0f5039107cdd8d8201aed0a949008a
    src/vendor-fix.patch                 6a53ca72ae9275cb4dca0ee4b84a61ff299cbed1225dd582d9092070a358eb3f
    src/gen_image.py                     309b3a9d1239897d66a9c049dbd4b80a2d0061a2db516c595ea184536d80059f
    build/vuln/libntfs-3g/compress.c     003f0ebb258cb40a53677911897d30e1d15c368530083d564a05434ec130ae89
    build/fixed/libntfs-3g/compress.c    c15b75ea36f3ccdf7662b37e6752d37075f54c42453d76a80435bb209fe67771
    out/base.img (pinned mkntfs -T)      c9d04e71517b3f31f7e32eb1d91e3e4745931ad643bb82fe4074a9cf26cd6cef
    out/poc.img                          4b049df8f875be4e0f62d451d592f38a13c8e8a4f4b12fdb5eed63250dea6b62
    out/safe.img                         c4498b789d8bdff57b30d2e500ae72b61a14f27af9f294c9920f1f2c083b0b29

`run-all.sh` re-fetches the tarball only if absent; all other bytes are in
`src/`. No external host was contacted by the exploit runs; the image is a
local file, read-only, with no mount, socket or listener.

## Build and image construction

Both sides: extract tarball, copy tree, apply the single vendor patch to the
fixed tree, configure with `CFLAGS='-O1 -g -fsanitize=address
-fno-omit-frame-pointer' LDFLAGS='-fsanitize=address' ./configure
--disable-shared`, then `make -j4`. The pinned `mkntfs` from the vulnerable
build creates a deterministic 4 MiB base (`-F -f -q -T -c 4096`, MFT at LCN 4).

`src/gen_image.py` patches MFT record 16: $STANDARD_INFORMATION with
`FILE_ATTR_COMPRESSED`, non-resident unnamed $DATA with `ATTR_IS_COMPRESSED`,
compression unit 4, 16 clusters (0..15), runlist `21 01 e8 03 01 0f 00` (one
cluster at LCN 1000, then a 15-cluster hole). The sparse run makes
`ntfs_is_cb_compressed()` take the decompress path. One data cluster holds 15
empty compressed sub-blocks (`00 80 00`, each zero-filling 4096 output bytes)
plus the W282 final sub-block: header `0x8b57`, 1 literal + 7 phrases, 169x
eight phrases, then six phrases that fill output exactly to 4096 and two
literals (`5a 5b`) that write past the 64 KiB destination. The safe image
uses header `0x8b4f` and drops the two final literals.

`ntfscat -f -i 16 IMG` opens the inode directly and reads in 4096-byte chunks:
`ntfscat.c:371 -> attrib.c:1003 -> compress.c:950 -> compress.c:568`. On the
last chunk `decompsz == cb_size == 65536`, so `dest_sb_end == dest_end` and
the symbol token writes into ASan poison. The SUID `ntfs-3g` FUSE path was
NOT exercised (mounting is not permitted in this lab).

## Observed results (clean-archive run, 2026-11-26)

    vuln + poc.img    rc 1, 61440 stdout bytes, ASan WRITE of size 1 at compress.c:568,
                      0 bytes after a 65536-byte region allocated at compress.c:783
    fixed + poc.img   rc 0, 65536 stdout bytes, no ASan report
    vuln + safe.img   rc 0, 65536 stdout bytes, no ASan report
    fixed + safe.img  rc 0, 65536 stdout bytes, no ASan report

`sh run-all.sh` rebuilds both sides and reports PASS=31 FAIL=0; traces are in
`evidence/`. ASan frames name the verbatim pinned sources and the shipped CLI
call loop; the generated image and source hashes are asserted by the runner.

## Limits and preserved negatives

- Rung 3 only. The overflow writes two chosen byte values at fixed offsets
  past a heap allocation; no relative/absolute pointer control, no adjacent
  object overwrite, no control-flow steering, no benign command, no wire
  input. Rung 4 and rung 5 are NOT CLAIMED. AV:L / crafted-image precondition.
- The advisory names the SUID `ntfs-3g` binary; only `ntfscat` was driven here
  (same library function, different shipped consumer). FUSE mounting returned
  `Operation not permitted` in this lab; preserved as an environment limit.
- An earlier scout header `0x9201` exceeded `NTFS_SB_SIZE_MASK` (0x0fff) and
  could never describe a sub-block; the working header is `0x8b57`. The
  upstream-fix-commit patch failing 6/8 hunks is preserved in the brief.
- Source trees, binaries and images under `build/` and `out/` are gitignored;
  the hashes above let a witness rebuild from the clean archive.
