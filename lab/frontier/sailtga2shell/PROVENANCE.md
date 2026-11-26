# sailtga2shell — provisioning and evidence provenance (frontier W246)

All fetches were read-only provisioning from public sources on 2026-11-26;
no external system was probed. No source outside the lab was written.

## Claims and exact URLs

- Advisory: `https://github.com/HappySeaFox/sail/security/advisories/GHSA-744p-cqg2-m33h`
  (CVE-2026-54626, published 2026-06-07, affected `<= 0.9.10`, patched `1.0.0`).
  Its PoC recipe and ASan paste were read as claims, then reproduced locally.
- Tarballs: `https://codeload.github.com/HappySeaFox/sail/tar.gz/refs/tags/v0.9.10`
  and `.../refs/tags/v1.0.0`. (The equivalent
  `https://github.com/HappySeaFox/sail/archive/refs/tags/v0.9.10.tar.gz`
  redirect also served bytes; codeload URLs are the recorded pins.)
- Raw sink at four refs, all via
  `https://raw.githubusercontent.com/HappySeaFox/sail/<ref>/src/sail-codecs/tga/tga.c`:
  ref `v0.9.10`, fix parent `2a4c3b7af46af7e244155e305027507e9e7493bd`, fix
  commit `fa24bceb93958ad665dbc3cf6b49a1079ab12559`, and ref `v1.0.0`.
- Fix commit and parent verified through the GitHub commits API for
  `src/sail-codecs/tga/tga.c`. A `.../commit/<sha>.patch` URL returned 404;
  the parent and fix raw files were used instead and their diff is archived as
  `evidence/vendor-fix.diff` by `run-all.sh`.
- Tags verified through `https://api.github.com/repos/HappySeaFox/sail/tags`:
  `v0.9.10` -> `cdd9d5f20bd0bf83683637afee61dd7e954162b2`,
  `v1.0.0` -> `0f969168b9d19d43f448d2237990ec247ba822ca`.

## Pins (SHA-256, computed from fetched bytes)

| artifact | SHA-256 |
|---|---|
| `src-v0.9.10.tar.gz` | `dc0d6fa87cb4fa8b514f450a3fb13cee6e3e60f03250f683564fabbec0f722e3` |
| `src-v1.0.0.tar.gz` | `b6f77d6d451b72202c8e11bd5057b697a21f7b6c4ef713f19a96de5a16c08916` |
| `pinned/tga-v0.9.10.c` | `ca00ecde0ba1ca3e0cbee913bfbd88bdeab24468226aca0446d8ea27ae3a45c7` |
| `pinned/tga-fix-parent.c` | `56467c2fc77995ba561f483e463b08247619f8c4bf6489ba0dc1254351932af7` |
| `pinned/tga-fix.c` | `13add077091532bad66f9c3a2b52d1558c652d15e05cb571912a83f8c91b58d3` |
| `pinned/tga-v1.0.0.c` | `13add077091532bad66f9c3a2b52d1558c652d15e05cb571912a83f8c91b58d3` |
| `harness/driver.c` | `68d083edc106dd7093502ee42123853484820b0cf28186b3feee310ce276f2c9` |
| `harness/make-poc.py` | `e5e1f8aa351c6ab168bf246f12bf19a3ffdfc35c8f2f80527ad47596d892210f` |
| `stubs/libavutil/pixfmt.h` | `b452ef37e3308339924e62eadf0ce7d4674732953927f745423b10ab60dd422e` |
| `harness/run-all.sh` | `e2a111e76a4c875029ebba9d7f8e40cabda001b2bff3e8bc30f92840932abba1` |

The v1.0.0 tag's raw sink is byte-identical to the fix commit's raw sink; the
v0.9.10 tag's sink carries the header-bpp stride and the earlier pixel-count
clamp. Build-environment stub headers for absent optional libswscale are
`stubs/libavutil/pixfmt.h` and `stubs/libswscale/swscale.h`, both empty apart
from a comment; libswscale is forced OFF in every CMake build.

## Builds and commands

`harness/run-all.sh` extracts both tarballs when the trees are missing and
builds static SAIL with `-DBUILD_SHARED_LIBS=OFF -DSAIL_ONLY_CODECS=tga
-DSAIL_BUILD_APPS=OFF -DSAIL_BUILD_EXAMPLES=OFF -DSAIL_BUILD_BINDINGS=OFF
-DBUILD_TESTING=OFF -DSAIL_MANIP_USE_SWSCALE=OFF`: clang ASan v0.9.10, gcc ASan
v0.9.10, gcc plain v0.9.10, clang ASan v1.0.0, gcc plain v1.0.0. The driver
links only public headers and static archives, and calls `sail_load_from_file`.
`harness/make-poc.py` writes three 28-byte local TGA files: attack (indexed
RLE, bpp 32), safe8 (indexed RLE, bpp 8) and safe32 (truecolor RLE, bpp 32).

`bash run-witness.sh` rehashes all ten pins, deletes every build tree and all
evidence, rebuilds from the tarballs and re-asserts the ASan frames, chosen
bytes and vendor-fixed control. Itself not pinned (no self-hash circle).

Observed on 2026-11-26: `run-all.sh` 38 PASS / 0 FAIL rc 0 from a clean tree;
`run-witness.sh` 14/0 outer, 38/0 inner, rc 0 in-tree and from a clean
`git archive` (archive hash recorded in the frontier wall).

## Negative / UNKNOWN

- Advisory's pasted ASan log is labeled `Version: 1.0.0` but the raw v1.0.0 tag
  has the guard and the built v1.0.0 control rejects the PoC. Recorded as a
  claim/version discrepancy, not as an unpatched release.
- At W246 only the file API was exercised; W1 below adds the memory APIs and
  synthetic pointer control. Any live network caller remains UNKNOWN, and
  there is no wire path and no r5.

## W1 additions (2026-11-26, target mind; un-pinned)

The ten pins above are unchanged; `run-witness.sh` still replays 14/0. New
lab-only files, deliberately NOT added to the pin lists:

- `harness/memory-driver.c`, `harness/run-memory.sh` -> `evidence-w1/`
  (10 PASS / 0 FAIL): junior and explicit-codec public memory APIs.
- `harness/run-realapp.sh` -> `evidence-w2/` (9 PASS / 0 FAIL): compiles the
  SHIPPED `examples/c/sail/sail.c` CLI (v0.9.10) and the shipped `advanced.c`
  example (v1.0.0) against the pinned static build trees. The CLI needs
  `-fopenmp` for `libsail-manip.a`. No upstream source byte is modified.
- `harness/victim_preload.c`, `harness/pointer-driver.c`,
  `harness/make-pointer-poc.py`, `harness/run-pointer.sh` -> `evidence-w3/`
  (13 PASS / 0 FAIL): LD_PRELOAD malloc interposer, synthetic live victim,
  ASLR disabled with `setarch -R`, syscall-only benign marker.

`evidence-w*/` is gitignored, like `evidence/`. The extra evidence is local
lab output, not a new claim about the pinned builds or the witness replay.

