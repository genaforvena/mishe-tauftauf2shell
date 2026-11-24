# PROVENANCE — Imgproxy2Shell (CVE-2026-123614)

All sources below were fetched read-only from public origins on 2026-11-21;
nothing outside loopback was probed or contacted with a trigger.

## Upstream pins (SHA-256 of the exact bytes stored in `src/`)

| Artifact | Origin | SHA-256 |
| --- | --- | --- |
| `src/icoload.v4.0.15.c` (affected) | `https://raw.githubusercontent.com/imgproxy/imgproxy/v4.0.15/vips/icoload.c` | `2eabd58d1e6c14439af7a7e22196df2ea4f4b2aa82efeb1ea0844962744051dc` |
| `src/icoload.v4.0.16.c` (fixed) | `https://raw.githubusercontent.com/imgproxy/imgproxy/v4.0.16/vips/icoload.c` | `67b4a9c2667743ac757faa59e1f56dc09ed8046dc5efd8c74a24c0f41e795774` |
| `src/fix123614.patch` (upstream fix commit) | `https://github.com/imgproxy/imgproxy/commit/a821b6a4cb07a1bf2bb9077431d1c1e734d79917.patch` | `c5db17e90ab1b9ad103a9a1e2a36d1a6ecd894dd816b79997f57049b136e00b0` |
| `src/advisory123614.html` (GHSA-hff9-5pqw-6w9f) | `https://github.com/imgproxy/imgproxy/security/advisories/GHSA-hff9-5pqw-6w9f` | `d6de60b26ceb5946dda041617a27159f15316791458098c0fbac14b34d5f0e0e` |
| `src/cve123614.json` (CVE Program record) | `https://cveawg.mitre.org/api/cve/CVE-2026-123614` | `ab297c9dda361812ee88996649833b78b9ce7c7fc5d5e1c4c7c297d65c027dc1` |

Fix commit `a821b6a4cb07a1bf2bb9077431d1c1e734d79917` is dated
2026-09-24T17:27:35+03:00 with subject "Fix segfaults during invalid ICO
load"; it adds `MAX_ICO_ENTRY_DATA_SIZE` (10 MiB) and an explicit
`full_data_size` variable, plus regression ICO files and Go tests.

CVE-2026-123614 was published 2026-11-08 by GitHub's CNA, CWE-122,
CVSS 4.0 9.3 Critical `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`,
CVSS 3.1 9.8. Affected `imgproxy` package `pkg:golang/github.com/imgproxy/imgproxy/v4`
from 4.0.0 before 4.0.16; 4.0.16 is unaffected. CVE prose claims heap
corruption, crash or code execution from a crafted `data_size`.

## Source-bound statements copied verbatim by `gen_driver.py`

The generator emits only the loader statements under `#line` markers at their
true line numbers and aborts on any pin drift.

- Affected `icoload.c:154` — `uint32_t data_size` from the ICO directory
  entry; `:158` — `VIPS_MALLOC(NULL, data_size + BMP_FILE_HEADER_LEN)` (14-byte
  allowance, `uint32_t` addition wraps); `:159` — `actual_data = data + 14`;
  `:161` — `vips_foreign_load_read_full(ico->source, actual_data, data_size)`.
- Fixed `icoload.c:162`, `:165-168` — reject `data_size > 10 MiB`; `:172-173`
  — compute `full_data_size` in a 32-bit variable after the guard and allocate
  exactly that; `:179`, `:181` — same read path into the sized buffer.

Harness stand-ins, all outside the copied statements: `VipsPel` is
`unsigned char`, `VIPS_MALLOC` routes to a stand-in returning an exact-size
allocation (ASan mode), a zeroed 1 MiB mmap collaborator at a known offset
(chosen-byte readback), or a 3-byte allocation at the end of a `PROT_NONE`
guard page (fault control); `vips_foreign_load_read_full` copies at most the
locally supplied body bytes to `actual_data`, modelling a short source;
`vips_error` is a no-op. No imgproxy HTTP server, libvips runtime or real ICO
network request is exercised.

## Harness digests and replay

- `gen_driver.py` `f379809cbff319cc56577cffb0c73449c8c9736ef6c30c18242d6edc9db2d5bb`
- `run.sh` `51e7b46cf3e7cf62094e0f7ac83cf6ed1590d6de915de18ccc4e056458ed2c51`
- Generated `driver_vuln.c`
  `874d5784102ad8d5f5e987a2e0db96f3dc220968ea0a9dfa813d016dabededba`
- Generated `driver_fixed.c`
  `7214cf9ecc704dfb1022d630de8f83681b77643f7c723398203f225054528834`
- `bash lab/frontier/imgproxy2shell/run.sh <outdir>`: **10 PASS / 0 FAIL,
  ALL CHECKS PASS rc 0**; two independent five-run groups both
  `sha256=6b0391599520bc899f169268e08699155888f0018274f9c2a2e12bcd31c2dad5`.

Clean replay from `git archive HEAD` at commit `2366ef4` reproduced
10 PASS / 0 FAIL, rc 0 and digest
`sha256=6b0391599520bc899f169268e08699155888f0018274f9c2a2e12bcd31c2dad5`
in a fresh temp directory. ASan PIDs, addresses and build paths are excluded
from the trace digest so clean replays are byte-identical.

## W1 — imgproxy 4.0.0 as a real HTTP consumer of the CVE-2026-69242 TIFF (2026-11-24)

Bounded experiment for DM #3226 (standing #8). No new target, no grade
change; the original CVE-2026-123614 ICO lane above is unchanged.

### Materials and build

- imgproxy v4.0.0 source from codeload
  `https://codeload.github.com/imgproxy/imgproxy/tar.gz/refs/tags/v4.0.0`,
  tarball `sha256=02190571e68cfef01d7c0714654df1042e36b5bffcfa6ce28562bdd2a2e7dc62`,
  extracted to `provision/imgproxy-4.0.0/`. Its `go.mod` requires Go 1.26.0;
  `GOTOOLCHAIN=go1.26.0 go version` auto-provisioned that toolchain in 14 s
  and `go mod download` finished rc 0 in 39 s (provisioning only).
- Built the real CLI (`./cli`, not the root library package) twice against
  libvips2shell's pinned plain trees with
  `CGO_ENABLED=1 GOMAXPROCS=2 go build -p 2`, using the two pkg-config shims
  `provision/pc-vuln/vips.pc` (8.18.2 tree) and `provision/pc-fixed/vips.pc`
  (8.18.2 tree with the pinned v8.18.3 `image.c` fix). Both builds rc 0.
  `ldd` under the matching `LD_LIBRARY_PATH` resolves
  `libvips.so.42` to `build-vuln-plain/libvips` vs `build-fixed-plain/libvips`.
  The two binaries are byte-identical
  (`sha256=ea2317df2a42d30e81f33e0cfd822b49b99996545ffc49026573212b03d8165d`):
  no rpath, so the library tree is selected at run time by `LD_LIBRARY_PATH`.
- `provision/http_probe.py` (`sha256=81154bd5e99251a3f620f0954de8b1f7ec9b8a0b4b5f32ca8932351ae9d1ba7e`)
  starts a source server on 127.0.0.1:18081, launches imgproxy bound to
  127.0.0.1:18080 and issues GET
  `/insecure/rs:fill:16:16/[f:tiff/]plain/<fixture>`. Loopback source address
  is blocked by default, so the lab sets
  `IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES=true`. No non-loopback address
  is contacted. Fixtures: libvips2shell `real/safe.tif` (142 B),
  `real/manyband.tif` (154 B, 10000 bands), and locally generated
  `provision/tiff9999.tif` (`sha256=7e70e5945eb16e9fb6d78ab5774e96b506f2e7c7508d0df97a80e6f0963f3931`,
  60000x2x9999 uint32, line 2,399,760,000 bytes > INT_MAX, width below the
  VIPS_MAX_COORD cap).

### Observations (raw logs `provision/http-*.log`)

- Safe control: HTTP 200 and a 16x16 JPEG in both builds, e.g. `http-vulntiff.log`
  `status=200 ... image_url="http://127.0.0.1:18081/safe.tif"`.
- Vulnerable + default JPEG output, 10000-band TIFF: HTTP 500 in 6.5 ms with
  `error="linear: vector must have 1 or 9999 elements"`, stack
  `vips.(*Image).Flatten ... processing/flatten.go:8`. The 9999-band variant
  gives the analogous 9998-element message. imgproxy's flatten step rejects
  many-band images before any region access; this is an endpoint blocker for
  the default output path, not a libvips fix observation.
- Vulnerable + `f:tiff` output (TIFF supports alpha, so flatten is skipped):
  both crafted fixtures produce no response within a 15 s per-request
  timeout, while the safe control in the same run returns 200 in 0.00 s
  (`http-vulntiff.log`). The requests enter real imgproxy processing and
  do not complete under this wake's 2 GiB cgroup; this is consistent with
  libvips2shell W7/W8's measured multi-GB tile-buffer zero-fill stall, not
  an independently measured stack in this wake.
- Fixed + the same two crafted fixtures: HTTP 500 in <2 ms with
  `error="image: dimension overflow\n\nimage: dimension overflow"` and stack
  `vips.(*Image).Load ... vips/vips.go:298` ->
  `processing.(*Processor).initialLoadImage ... processing/processing.go:161`
  (`http-fixtiff.log`). The fix rejects at image load inside the imgproxy
  process, before processing. `f:png` is rejected earlier in both trees
  (`Resulting image format is not supported: png`) because PNG saving is
  disabled in the pinned libvips build.

### Scope, negatives and grade

This is the first observation of the crafted TIFF reaching header acceptance
and processing entry in an actual imgproxy process over a real HTTP request;
libvips2shell W14 had only lab scaffolding. It is not the negative-offset
write: no TIFF scanline decode, no truncated `bpl`, no region/paint frame,
no chosen-byte write, no pointer, no benign marker side effect, no ASan
report, no witness verdict. Default-output flatten rejection and the
`f:tiff` timeout are endpoint limits, preserved as negative results. The
loopback-source override is a lab configuration, not a claim about default
deployments. Grade unchanged: rungs 1-4 for the ICO lane; rung 5 UNKNOWN.

Clean `git archive HEAD` replay at commit `e062321` extracted only my lab
path to a temp dir, with the two gitignored binaries symlinked in; both probe
legs ran from the extracted tree. Results matched the in-tree run: vulnerable
`safe=200`, `manyband=500`, both `f:tiff` crafted cases timed out at 8 s;
fixed `safe=200` and all crafted cases `500` with `image: dimension overflow`.
The replay output is in `/tmp/imgproxy2shell-replay.mTCwcl/` (throwaway; not
committed). This proves the committed harness reproduces the controls, not
that the fixed build broadly rejects images.

## W2 — fine-geometry TIFF over imgproxy HTTP (2026-11-24, DM #3259)

Bounded response to libvips2shell W16, which moved the negative-offset WRITE
from `bpl=-7296` (unmapped) to `bpl=-16` (the live vips tracked-size field)
using a fine geometry: width 89478485, height 2, 12 bands, 32-bit samples,
`ls=4294967280=2^32-16`. Its `real/fine.tif` (154 B,
`sha256=c3e12050213321d5f4f87b4fcac487a0b6588292c92020611bac33f586157d44`)
was served over the same loopback-only HTTP path as W1; no new target, no
library-side tree was edited.

`provision/http_probe.py` gained `/fine.tif` and a `fine_tiff` case
(`rs:fill:16:16/f:tiff/plain/fine.tif`); new script digest
`sha256=fd47010a936daec8cab90c520079b21d02df7d9952807a39350e60d061dbc63d`.
Both binaries and libvips trees are W1's. Per-request timeout 8 s; both legs
used 127.0.0.1:18080/18081 only.

- Vulnerable 8.18.2 (`http-w2fine-vuln.log`,
  `sha256=e7f4465138f99acdec5a2e2a0eb56b169dea0fb5b5cda545e8b554343c855fd1`):
  `safe=200` in 0.01 s; `manyband=500` in 0.01 s (flatten blocker);
  `manyband_tiff`, `tiff9999_tiff`, `fine_tiff` all `TimeoutError` at 8.06-8.09 s.
- Fixed 8.18.2+patch (`http-w2fine-fixed.log`,
  `sha256=014cafbe13663cc3b25ac14dad431c2d7a4cd225ec58236433a85dec73b3b659`):
  `safe=200`; all crafted cases `500` in <2 ms. For `fine.tif` the log line
  `Completed in 516.009µs ... status=500 error="image: dimension overflow"`
  stacks through `vips.(*Image).Load ... vips/vips.go:298` and
  `initialLoadImage ... processing.go:161`.

Structural endpoint blocker (pinned v4.0.0 source, read-only):
`vips/vips.go:314-334` implements `LoadThumbnail` for HEIC/AVIF only;
`imagetype/defs.go:144-156` sets TIFF `SupportsThumbnail: false`;
`processing/scale_on_load.go:29-42` allows shrink-on-load only for JPEG,
WEBP and thumbnail-capable formats. TIFF has no reduced or lazy load route
through imgproxy, so a line size of `2^32-16` forces the same full memory
image (4,294,967,280 B/line × 2 lines ≈ 8.59 GB) whose zero-fill stall
libvips2shell W7/W8 measured under this 2 GiB wake cgroup. The fine `bpl=-16`
does not make the paint path reachable from the HTTP endpoint here. No
region/paint frame, allocator-field overwrite, pointer, marker side effect,
ASan report or witness verdict was observed in the imgproxy process. Host
memory limits were not changed and no longer-timeout retry was attempted.
Grade unchanged: ICO lane rungs 1-4; TIFF consumer limb rung 4 at header and
processing entry only; rung 5 UNKNOWN. Preserved as a measured negative for
this endpoint route.
