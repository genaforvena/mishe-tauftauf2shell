# Provenance — MapServer2Shell frontier harness

All network fetches below are read-only provisioning of public sources. No
probe, connection or traffic was sent to any non-loopback system.

## Claim sources

- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-77326
  (CVE-2026-77326, published and updated 2026-11-20, CNA GitHub maintainer
  advisories, CWE-787, CVSS 3.1 8.6).
- GHSA advisory: https://github.com/MapServer/MapServer/security/advisories/GHSA-4mwc-qc95-5959
  (published 2026-07-10; fix 8.6.5; includes the public PoC description and
  the ASan stack quoted in the brief).
- Fix commits:
  - https://github.com/MapServer/MapServer/commit/ea1d87a6d45bbe5814a545a8b4d6a5e6b6842ea8.patch
    (2026-07-08, PR #7555), saved as `src/fix-ea1d87a.patch`,
    sha256 `67b35fa080c81b6adb9133c52f93d461d98922537e8f133cbb80657296116701`.
  - https://github.com/MapServer/MapServer/commit/a7d5eb844a59ea076b7972a018753242f18e6f7b.patch
    (2026-07-09, PR #7569), saved as `src/fix-a7d5eb8.patch`,
    sha256 `f59c5be876f5e38118b1a281c6ba722a5d5d83dd09a1b2e145975cffdea4b7ff`.
  Both patches delete the `LAYER`->`LAYERS` append loop and select `layerKey`
  in `msWMSLoadGetMapParams`; they are functionally identical (main vs branch
  line offsets).

## Raw source snapshots

Fetched from `https://raw.githubusercontent.com/MapServer/MapServer/<tag>/<path>`
at 2026-11-20T23:5xZ. Digests are of the files in `src/`:

| Tag | File | sha256 |
| --- | --- | --- |
| rel-8-6-4 | `src/mapwms.cpp` | `74e0d502d99f5c34bdf15718c47ae48e69e8167f1aed0ef22c4ecdf9c262edf4` |
| rel-8-6-4 | `src/cgiutil.c` | `fd9aac26bee3fd6c18b4a2ab612f3cd97691cc6291aba1fe32f9b681970c5e2a` |
| rel-8-6-4 | `src/cgiutil.h` | `47579d320c3f4266e6961e5461386f5f39adc83bd006035f6ebe59f5524ea13f` |
| rel-8-6-4 | `src/maputil.c` | `1579e659e387d1a4f1df98a8bfb5d81addaf96ddb247b7f81ee97fc859afabc1` |
| rel-8-6-5 | `src/mapwms.cpp` | `cd330d5857d2311317b4251245c8c1602858ec0ae2bc47a7e86da2d96ad22c9e` |

Also stored: `src/rel-8-6-5/cgiutil.c`, `cgiutil.h`, `maputil.c` (same paths,
used to confirm the struct/allocator did not change between tags).

## Harness

- `legend_layer_overflow.c`, sha256
  `3aca5129886aed717cd1f6dec54e59452757f066fdb0e66784168254c9182b21`.
- `run.sh`, sha256
  `96f1757b3c11dd54297209537017adcfbc781c979640166fcf16b2d0c984ad88`.
- Built locally with gcc 13.3.0 (`-O0 -g -Wall -Wextra`, plus
  `-fsanitize=address -fno-omit-frame-pointer` for rung 3 and the fixed ASan
  control). Binaries are gitignored.
- `bash run.sh` -> `ALL CHECKS PASS rc 0`; two five-run groups hash to
  `5df6fce0702fa30628d3fcf32ca77975bf22003709ec5c9595e879feff082c2e`.

## Model boundaries

Only the `cgiRequestObj` parameter arrays and the `GetLegendGraphic` dispatch
branch are reproduced. Rung 1/rung 3 allocate exactly `100 * sizeof(char *)`
per array to model `msAllocCgiObj` and expose the real boundary to ASan.
Rung 2/rung 4 use a physically longer array with the same *logical* capacity
100 so canary stamps and pointer slots can be read back; the vulnerable loop
and write extent are unchanged. Map parsing, libgd/GDAL, the mapfile, the CGI
and HTTP layers are not reproduced. No stock build or loopback server was run
in this wake.
