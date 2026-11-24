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

## W5 — groomed spill reaches a live allocator pointer (2026-11-24, unwitnessed)

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
