# PROVENANCE — HTSlib2Shell (CVE-2026-62257)

All downloads were read-only provisioning on 2026-11-21 (UTC), from the URLs
below. Every downloaded byte is pinned in `src/SHA256SUMS`; verify with
`cd src && sha256sum -c SHA256SUMS`.

| artifact | URL | SHA-256 |
|---|---|---|
| vulnerable release tarball (1.23.1) | https://github.com/samtools/htslib/releases/download/1.23.1/htslib-1.23.1.tar.bz2 | f8a3f36effeec38f043c53ab1f2d9ed45064f14205c5ef8e3c815763b90803c4 |
| vulnerable tag tarball (codeload 1.23.1) | https://codeload.github.com/samtools/htslib/tar.gz/refs/tags/1.23.1 | 5436c9dc2503890109fdb0c5161cbb53a6eefcb492491825df165f10ac083394 |
| fixed release tarball (1.24) | https://github.com/samtools/htslib/releases/download/1.24/htslib-1.24.tar.bz2 | 28a8de191381c7a97a35675ceac76fa1ea95e7b678d6a2e9d600a7874e4077de |
| fixed tag tarball (codeload 1.24) | https://codeload.github.com/samtools/htslib/tar.gz/refs/tags/1.24 | 8eb66a222472b18ddc01345ae2f7f95eacaf67bf85600f3cb1619e66bbbb79e9 |
| MITRE CVE JSON | https://cveawg.mitre.org/api/cve/CVE-2026-62257 | a21e54045057fd8ac10387126731c6d3de0abf38308c96aae23c1f5e2a800450 |
| OSV JSON | https://api.osv.dev/v1/vulns/CVE-2026-62257 | a29c222749185b2d28ca3ec5c461ddb39d5cf0a9a5a05f7fc72d1b5ba9db3e73 |
| GHSA advisory HTML | https://github.com/samtools/htslib/security/advisories/GHSA-6q7c-m967-9v37 | b193aa966e8b8c2dca158750088fd6b32009fec48602db25b3890c5c40d62fc4 |
| fix patch d66a77d | https://github.com/samtools/htslib/commit/d66a77dbf8f52f7f44efd7929a28b94bbfc17f2.patch | c0107dc3a14d64f693b397bc00403e85bfa8bb77e30d3b6dde3f13f2068030c7 |
| fix patch c0b5037 | https://github.com/samtools/htslib/commit/c0b50372ed133c650fa0a641607da5cde46bcd8c.patch | 47851477b3e3c318a79c99f3f7559004b90cd1656a9960effc3570c80a37271f |
| fix patch a3e8dca | https://github.com/samtools/htslib/commit/a3e8dca14dcfdc6167281721ede6d6ecd3395bad.patch | df045ccdb2bc31ac9397cb721d3c30c16282ca8ff4f93097b3b3fd4eefb5b01c |

## Source-bound line references (raw bytes of the pinned 1.23.1 release tarball)

- `cram/cram_codecs.c:1378` OOB pointer read `cram_block *b = slice->block_by_id[512 + c->codec_id];`
- `cram/cram_codecs.c:1388` OOB pointer write `b = slice->block_by_id[512 + c->codec_id] = cram_new_block(0, 0);`
- `cram/cram_codecs.c:2075` / `:2079` the same read/write in `cram_xrle_decode_expand_char` (not exercised by the harness).
- `cram/cram_codecs.c:3882` `r->codec_id = hdr->ncodecs++;`
- `cram/cram_io.c:4620` `s->block_by_id = calloc(512, sizeof(s->block[0]))` — 512 pointers.
- `cram/cram_structs.h:373-374` `// Total codec count, used for index to block_by_id for transforms`, `int ncodecs;`.
- fixed `1.24`: no `E_XPACK`/`E_XRLE` codec symbols remain in `cram/cram_codecs.c`; commit `a3e8dca` removes CRAM v4.0 support. The harness observes `cram_decoder_init(codec=51)` returning NULL with `Unimplemented codec of type ?`.

## Stand-ins and boundaries

`harness.c` reproduces the exact 512-pointer allocation shape and calls the
real pinned `cram_decoder_init`/`cram_xpack_get_block` path. It does **not**
generate or parse a CRAM file: `hdr->ncodecs` is set directly to model a
compression header that declares codecs, and the source block for the XPACK
sub-codec is allocated in-harness. The 7-byte XPACK parameter stream is
authored by the harness (`nbits=4,nval=2,rmap=0,1,sub=EXTERNAL,sub_size=1,content_id=0`).
No web-facing consumer, CRAM file, listener, pointer target, control-flow
diversion or execution was exercised. Both `0x521000001108` (ASan) and
`0x1011` (plain, adjacent heap junk) are observed values, not chosen values.
The two tag tarballs are byte-different from the release tarballs; only the
release tarballs were compiled.
