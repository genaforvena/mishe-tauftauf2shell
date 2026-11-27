# Provenance — libstrophescram2shell

All sources were fetched as public provisioning; no external host was probed,
no listener was started, every executed harness was local. The six source,
advisory and patch pins are immutable and verified by `SHA256SUMS` before every
run; four harness files and eight built binary hashes are pinned in the same
file. `build-real.sh` uses only the archives and the pinned harness header; it
performs no network I/O.

| Artifact | URL / identifier | SHA-256 |
|---|---|---|
| Advisory HTML | `https://github.com/advisories/GHSA-37wj-432m-6r6f` | `ebe154323852b6169d699b731a4b638f675fb7e3df4d390125ac8366613565fe` |
| Upstream fix patch | `https://github.com/strophe/libstrophe/commit/252ec0208eb9a0d077afcc53351fca99e2efe81f.patch` | `e81e2e8a5c8831341437121488fd93abb8145b1d72084672735697f9e1167bdf` |
| Vulnerable source archive | exact parent `9816acc93cfcf071d6ca952fc5b3a266dcded9ce` | `332516a770e5fe9b15b5ad06ac12c17670fd334f0ed55f5be7b85f19513461a0` |
| Fixed source archive | exact fix `252ec0208eb9a0d077afcc53351fca99e2efe81f` | `71fe987f0d2519217c5b324f1f604a970a61f4c61100af435ca71262db5ccdab` |
| Vulnerable `src/scram.c` | raw at parent commit | `0b3f8094cb07126b6db1453b7261812c7e72d17ab9a023eb04e2d8ba551a5926` |
| Fixed `src/scram.c` | raw at fix commit | `e56cb13e03bf5fbcbd1fdefd34072eaa6583906605c01a16a88b8e352d9634c1` |

Advisory: CVE-2026-112063 / GHSA-37wj-432m-6r6f, Moderate, CWE-121, published
2026-10-18. Advisory affected/patched fields read `Unknown`; description gives
`<=0.14.0`. No fixed release tag was observed. Fix parent/fix pair is exact.

Builds: GCC 13.3.0, glibc 2.39, x86-64, autotools with `--disable-tls
--disable-examples`, `-g -O0`, stack protector off. ASan variants add
`-fsanitize=address -fno-omit-frame-pointer`; plain variants add `-fno-pie`.
Eight consumers are vulnerable/fixed × ASan/plain × stock-assert/assert-disabled.
The assert-disabled variants are built with `-include harness/noassert.h`,
which defines libstrophe's documented user-overridable
`STROPHE_ASSERT`/`STROPHE_ASSERTVD` macros as no-ops. That is a lab build
condition, not a stock build; stock NDEBUG defines them as early returns and
does not reach the overflow.

Harness `harness/scram_challenge.c` base64-encodes the chosen salt into an
`r=…,s=…,i=1` SASL server-first-message and calls the pinned library's
`sasl_scram()`. Only argument handling, salt generation and base64 encoding are
lab-written; challenge parsing, `SCRAM_ClientKey()` and `SCRAM_Hi()` are
verbatim pinned code. GDB uses a read-only breakpoint at `scram.c:191`.

Observed: stock vulnerable builds do not fault (early-return negative);
assert-disabled vulnerable ASan gives `WRITE of size 4` at `scram.c:188` for
125 bytes, `WRITE of size 256/512` at `scram.c:187` for larger salts, with
`SCRAM_Hi → SCRAM_ClientKey → sasl_scram` frames; fixed builds reject all
oversized salts under both configurations; plain assert-disabled vulnerable
builds SIGSEGV at 256/512. GDB observes chosen bytes past `tmp[128]` and
chosen `0x4343434343434343` frame words. No wire socket, command or side
effect was exercised. Runner: `RUN_ALL_OK 46 PASS / 0 FAIL`, summary
`c9eb04879a49462f78d7b3858a95cd79f613011d160b74bc0ddbba00a927a9f9`.
