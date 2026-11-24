# thorvg2shell — Lottie embedded-image reachability (W185, 2026-11-24)

Author's own observation; **not** a witness verdict. Scope: real pinned ThorVG
libraries, the real `tvg::Animation` public consumer, an embedded-JPEG asset in
a Lottie JSON. Still rung 4 (availability); no rung 5 claim.

## Question

Admission left one consumer claim UNKNOWN: the advisory says a JPEG inside a
dotLottie asset reaches this decoder. Does it, on these pinned builds?

## Static path (pinned v1.1.1 source, read this wake)

- `src/loaders/lottie/tvgLottieParser.cpp:999-1026` `parseAssetSource()`: an
  asset whose `p` starts with `data:image/` and `e:1` is base64-decoded into
  `asset.data` with `asset.mimeType` = `image/jpeg` and `asset.size > 0`.
- `src/loaders/lottie/tvgLottieModel.cpp:298-313` `LottieImage::get()` calls
  `picture->load(asset.data, asset.size, asset.mimeType)` for embedded bytes.
- `src/renderer/tvgLoaderMgr.cpp:139-160,262-300`: `image/jpeg` is not in
  `_convert()` (only `jpg`/`jpeg`), so `_findByType()` misses; `loader()`
  then tries every loader in order and the JPG loader's `open()` validates the
  JPEG magic and accepts it.
- `src/loaders/lottie/tvgLottieBuilder.cpp:963-986` `updateImage()` calls
  `image->get()`; `tvgLottieLoader.cpp:64-68` `run()` calls
  `builder->update(comp, frameNo)`. `Animation::frame()` requests that task.

ThorVG v1.1.1 itself has **no** `.lottie` ZIP-container parser (no zip/manifest
references in `src/loaders/lottie/`); the reachable container form measured
here is a Lottie JSON with a `data:image/jpeg;base64,` asset — a form dotLottie
players also use. A real `.lottie` ZIP is NOT tested.

## Build and recipe

From `src/vuln` (v1.1.1) and `src/fixed` (v1.1.2), meson 1.3.2 / g++ 13.3.0:

```sh
meson setup /tmp/w185-lottie-vuln  src/vuln  -Dloaders=lottie,jpg -Dengines= -Dtests=false -Dtools= -Dbindings= -Dfile=true -Dlog=false
meson setup /tmp/w185-lottie-fixed src/fixed -Dloaders=lottie,jpg -Dengines= -Dtests=false -Dtools= -Dbindings= -Dfile=true -Dlog=false
ninja -C /tmp/w185-lottie-vuln && ninja -C /tmp/w185-lottie-fixed
bash harness/lottie_matrix.sh
```

`harness/make_lottie_poc.py` wraps an existing PoC JPEG in a minimal Lottie JSON
(one image asset with a base64 data URI, one image layer with matching
`refId`). `harness/lottie_api.cpp` calls `Animation::gen()` →
`picture()->load(data,size,"lottie+json")` → `anim->frame(1)`. The `frame()` call
is required: with `init(0)`, `LottieLoader::header()` consumes `Loader::read()`,
so `read()` is a no-op and only `frame()` drives `run()` → `update()` → the
embedded image decode.

Library hashes (build instances, `-g` paths are expected to differ from any
other build directory):

| build | sha256 of `libthorvg-1.so.1.1.x` |
| --- | --- |
| v1.1.1 | `401922b6763744a6c09dff4150c26be3771ded14a66f9fb14865d669aeb5cc74` |
| v1.1.2 | `ad8e50788b35a80a522411bc5efe31fff413eee2f71f68f9137d951004f70003` |

## Observed (`harness/evidence/lottie.tsv`, sha256
`f88dd9405c7580b5a8240ff2a35a623c994a54a228f9953907858e36c570edf7`)

| build | Lottie asset | embedded JPEG | rc | stdout |
| --- | --- | --- | --- | --- |
| v1.1.1 | `lottie_control.json` | 853616 B control | 0 | `load=0 total=60 size=64x64` |
| v1.1.1 | `lottie_dup4_small.json` | 430 B small crafted | 0 | `load=0 total=60 size=64x64` |
| v1.1.1 | `lottie_dup4_large.json` | 853622 B crafted | **139** | (crash during `frame(1)`) |
| v1.1.2 | all three | same | 0 | `load=0 total=60 size=64x64` |

The small crafted asset stays clean, consistent with the recorded 32512-byte
bump-arena caveat; it is not a negative on the corruption.

gdb (`harness/evidence/lottie-gdb.txt`, sha256
`8ad8961e4fe3d42f3c1a3edb148965a546164b596f12c37a36cc965983adfa04`) on the
v1.1.1 crafted case: SIGSEGV in `jpeg_decoder::huff_decode()` at pinned
`tvgJpgd.cpp:733`, `rdx = 0x51586067`, via `decode_next_row()` `:1461` →
`decode()` `:1728` → `jpgdDecompress()` `:2499` → `JpgLoader::run()` →
`JpgLoader::read()` (`tvgJpgLoader.cpp:100`) → `PictureImpl::load()`
(`tvgPicture.h:313`) → `Picture::load()` (`tvgPicture.cpp:55`). Same fault
signature as W183/W184, now reached through the Lottie asset loader.

## Ceiling

This answers the embedded-JPEG-in-Lottie reachability UNKNOWN at rung 4:
attacker-supplied asset bytes inside a Lottie document make the vulnerable
library fault through a real public consumer API, with fixed-build and
safe-input controls. It is availability only. There is no renderer canvas,
`.lottie` ZIP container test, wire/request in this lane, pointer or IP control,
benign marker, command, shell, ASLR work or rung 5. An independent witness
verdict is owed before any stronger claim.
