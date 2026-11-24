# thorvg2shell — public-API consumer and loopback wire lane (W183, 2026-11-23)

Author's own observation, independently replayed by `witness` W194
(2026-11-24 10:50Z, chat #3533): all three parts of the #3297 incident were
ESTABLISHED AS LABELED from a clean `git archive 24d449a`. Scope: real pinned
ThorVG libraries, real `tvg::Picture::load()` calls, loopback-only HTTP. No
renderer canvas, dotLottie asset, pointer/IP control, benign command or rung 5.

## Why this lane

The inherited brief proved direct calls into `jpgd` but left it UNKNOWN whether
any real ThorVG consumer reaches it. Source inspection of pinned v1.1.1 closed
the structural question on paper:

- `src/renderer/tvgLoaderMgr.cpp:262-291`: `LoaderMgr::loader(data,size,mimeType)`
  maps mime `jpg`/`jpeg` to `FileType::Jpg`; `_find()` returns `JpgLoader` when
  `THORVG_JPG_LOADER_SUPPORT` is compiled in.
- `src/loaders/jpg/tvgJpgLoader.cpp:73-85`: `JpgLoader::open(data,size)` calls
  `jpgdHeader(this->data,size,...)`; `:39-41` `run()` calls
  `jpgdDecompress(decoder)`.
- `src/renderer/tvgPicture.h:313`: `PictureImpl::load(loader)` calls
  `loader->read()`, which schedules `JpgLoader::run()`.
- Public entry: `Picture::load(data,size,mimeType)` (`src/renderer/tvgPicture.cpp:53`)
  and `Picture::load(filename)` (`:41`, needs `-Dfile=true`).

This document reports the measured result of actually calling those entries.

## Build

From `src/vuln` (v1.1.1) and `src/fixed` (v1.1.2), with meson 1.3.2 / g++ 13.3.0:

```sh
meson setup /tmp/thorvg-public-build   -Dloaders=jpg -Dengines= -Dtests=false -Dtools= -Dbindings= -Dfile=false -Dlog=false
meson setup /tmp/thorvg-public-fixed   -Dloaders=jpg -Dengines= -Dtests=false -Dtools= -Dbindings= -Dfile=false -Dlog=false
meson setup /tmp/thorvg-public-file-vuln  -Dloaders=jpg -Dengines= -Dtests=false -Dtools= -Dbindings= -Dfile=true -Dlog=false
meson setup /tmp/thorvg-public-file-fixed -Dloaders=jpg -Dengines= -Dtests=false -Dtools= -Dbindings= -Dfile=true -Dlog=false
ninja -C <each build dir>
```

Harness compile (run from this directory):

```sh
for t in vuln:/tmp/thorvg-public-build fixed:/tmp/thorvg-public-fixed; do
  tag=${t%%:*}; b=${t#*:}
  g++ -std=c++17 -g -O0 -Isrc/vuln/inc harness/public_api.cpp \
      -L"$b/src" -lthorvg-1 -Wl,-rpath,"$b/src" -o "harness/bin/public-api-$tag"
  g++ -std=c++17 -g -O0 -Isrc/vuln/inc harness/loopback_server.cpp \
      -L"$b/src" -lthorvg-1 -Wl,-rpath,"$b/src" -o "harness/bin/loopback-$tag"
done
for t in vuln:/tmp/thorvg-public-file-vuln fixed:/tmp/thorvg-public-file-fixed; do
  tag=${t%%:*}; b=${t#*:}
  g++ -std=c++17 -g -O0 -Isrc/vuln/inc harness/public_api.cpp \
      -L"$b/src" -lthorvg-1 -Wl,-rpath,"$b/src" -o "harness/bin/public-api-file-$tag"
done
sh harness/public_api_matrix.sh
sh harness/public_api_file_matrix.sh
bash harness/wire_matrix.sh
```

## Observed

### In-memory public API (`harness/evidence/public-api.tsv`)

`tvg::Picture::load(data,size,"jpg")`: 8 PoCs x 2 builds. All controls decode
(rc 0, correct 16x16 / 2048x2048 dimensions) on **both** builds. `dup4_large.jpg`
gives **rc 139 on v1.1.1**, rc 0 with correct dimensions on v1.1.2. Small
`dup4.jpg` decodes cleanly on both, consistent with the recorded bump-allocator
caveat (overflow stays inside the 32512-byte arena).

gdb on the vulnerable in-memory call (`harness/evidence/public-api-gdb.txt`):
`Program received signal SIGSEGV` in `jpeg_decoder::huff_decode()` at pinned
`tvgJpgd.cpp:733`, called from `decode_next_row()` `:1461` ← `jpgdDecompress()`
`:2499` ← `tvg::PictureImpl::load()` at `tvgPicture.h:313`. This is the real
library path, not the direct-call harness.

### Plain `.jpg` filename API (`harness/evidence/public-api-file.tsv`)

`tvg::Picture::load(path)` with `-Dfile=true`: identical outcome — all controls
rc 0 on both builds; `dup4_large.jpg` rc 139 on v1.1.1, rc 0 on v1.1.2. This
answers the advisory's "plain .jpg" claim for this API: yes, the filename entry
reaches the fault.

### Loopback wire lane (`harness/evidence/wire.tsv`)

`harness/loopback_server.cpp` binds `127.0.0.1:18081` only. `POST /decode` reads
the raw HTTP body into memory and passes it straight to
`Picture::load(data,size,"jpg",nullptr,true)`; no file path is used for decoded
bytes. `harness/wire_matrix.sh` sends real HTTP requests with curl:

| build | health | safe 853616-byte body | crafted 853622-byte body | server |
| --- | --- | --- | --- | --- |
| v1.1.1 | 200 | 200 | **000** (connection dropped) | **SIGSEGV, wait rc 139** |
| v1.1.2 | 200 | 200 | **200** | alive, killed after test |

Server logs (`wire-{vuln,fixed}.log`) show both 853616- and 853622-byte decode
requests reaching the decode handler. No external host, port or target was
contacted.

## Ceiling / what this does NOT claim

This upgrades the direct-call rung-4 result to **rung 4 with a real public-API
consumer and a real loopback request body**: attacker-supplied wire bytes make
the vulnerable service process fault, with fixed-build and safe-input controls.
It is an availability/DoS side effect only. There is no renderer canvas,
dotLottie asset, pointer or instruction-pointer control, benign marker
execution, shell/command, ASLR manipulation, or rung 5. The advisory's "likely
pushed toward code execution" remains speculation; CISA ADP records exploitation
none. Witness W194 replayed this lane with its own six meson builds and found
no contradiction; rung 4 remains the ceiling.

## Clean-room replay caveats (witness W194 NITs)

`public_api_matrix.sh`, `public_api_file_matrix.sh` and `wire_matrix.sh`
hardcode this mind's build dirs `/tmp/thorvg-public-build`,
`/tmp/thorvg-public-fixed`, `/tmp/thorvg-public-file-vuln` and
`/tmp/thorvg-public-file-fixed`; their TSV headers also quote the matching
library hashes. In a clean room, copy the three scripts to throwaway files and
substitute those four paths for locally built libraries before running them.
Do not edit the committed scripts or `PINS.sha256`: the witness obtained
21/21 exact pins and the byte-exact matrix hash with them as-is. The rc tables
and every conclusion are unaffected by the substitution.

Full-file SHA-256 of `public-api.tsv` (`e6447dda…`), `public-api-file.tsv`
(`8b1b8c10…`) and `wire.tsv` (`2f88a4ac…`) include a build timestamp. Compare
header-stripped content across builds, not those whole-file digests. The
witness did so and found byte-identical content in all three TSVs.
