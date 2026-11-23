# OpenEXR v3.5.2 / v3.5.3 build log (GHSA-98rx-qpfv-qcwv lab)

All paths below are relative to `lab/openexr2shell-real/` (absolute root:
`/home/mesh-home/mishe-tauftauf2shell/lab/openexr2shell-real`). All commands were
run from that root unless stated otherwise. No commits were made; no files
outside this target directory were modified.

## 1. Source provisioning

Commands:

```sh
mkdir -p src
cd src
curl -L --fail --retry 3 -o v3.5.2.tar.gz \
  https://github.com/AcademySoftwareFoundation/openexr/archive/refs/tags/v3.5.2.tar.gz
curl -L --fail --retry 3 -o v3.5.3.tar.gz \
  https://github.com/AcademySoftwareFoundation/openexr/archive/refs/tags/v3.5.3.tar.gz
sha256sum v3.5.2.tar.gz v3.5.3.tar.gz
tar xzf v3.5.2.tar.gz
tar xzf v3.5.3.tar.gz
```

Extracted trees (GitHub archive naming, no `v` in directory name):
`src/openexr-3.5.2/` and `src/openexr-3.5.3/`.

Tarball SHA-256 (measured; no independent published reference hash was checked):

| File | Size (bytes) | SHA-256 |
|---|---:|---|
| `src/v3.5.2.tar.gz` | 26403944 | `85a291b9b8563fabef1aa3f6e912d744ce1d4b9fd5a8f978eda194cd51b15ae9` |
| `src/v3.5.3.tar.gz` | 26457608 | `ff1de95f4031c1c57c633e647dc97c15282d3aa3bc7fb90745f00f74de4a054f` |

## 2. Pin comparison

Pin file read: `lab/frontier/openexr2shell/PINS.sha256` (read-only; not modified).
Its paths are relative to `lab/frontier/openexr2shell/`. The two
`internal_zstd.c` pins are **full-file pins** (51602 and 54887 bytes), not slices.

Measured against each upstream tree:

| Tree | File | Size (bytes) | SHA-256 | Pin match |
|---|---|---:|---|---|
| v3.5.2 | `src/openexr-3.5.2/src/lib/OpenEXRCore/internal_zstd.c` | 51602 | `736dad696b6263fd5f715ccf1d93ac7104dc5f50994a769046e586af828abcea` | EXACT (pin `src/internal_zstd.c.vuln`) |
| v3.5.3 | `src/openexr-3.5.3/src/lib/OpenEXRCore/internal_zstd.c` | 54887 | `0a2fe7192849399b2620c0b519db4191e82e8963665330c2f7cbd7b8696db751` | EXACT (pin `src/internal_zstd.c.fixed`) |

Additional check (both trees): `src/lib/OpenEXRCore/openexr_errors.h` is
2376 bytes with SHA-256
`1d8b514e0c47209a56563b1dd72d59b6d2827643c1f0181892c180d1612f1880`,
an exact match to pin `src/openexr_errors.h` in both versions. The
`src/7d7fbb1.patch` pin (`1eb9e047…`) was **not** applied or compared: it is
not part of the assigned build verification.

## 3. Configuration

Recipe (per tree; `-j4` used at build step). Exact commands:

```sh
# v3.5.2 ASan + Debug
cmake -S src/openexr-3.5.2 -B build-vuln-asan \
  -DCMAKE_BUILD_TYPE=Debug \
  '-DCMAKE_C_FLAGS=-fsanitize=address -fno-omit-frame-pointer -g -O1' \
  '-DCMAKE_CXX_FLAGS=-fsanitize=address -fno-omit-frame-pointer -g -O1' \
  -DBUILD_SHARED_LIBS=OFF -DOPENEXR_FORCE_INTERNAL_IMATH=ON \
  -DBUILD_TESTING=OFF -DOPENEXR_BUILD_TOOLS=OFF -DOPENEXR_BUILD_EXAMPLES=OFF \
  -DOPENEXR_INSTALL=OFF -DOPENEXR_BUILD_PYTHON=OFF -DOPENEXR_BUILD_OSS_FUZZ=OFF

# v3.5.2 plain Release (same options, different build type/flags)
cmake -S src/openexr-3.5.2 -B build-vuln-plain \
  -DCMAKE_BUILD_TYPE=Release '-DCMAKE_C_FLAGS=-O2 -g' '-DCMAKE_CXX_FLAGS=-O2 -g' \
  -DBUILD_SHARED_LIBS=OFF -DOPENEXR_FORCE_INTERNAL_IMATH=ON \
  -DBUILD_TESTING=OFF -DOPENEXR_BUILD_TOOLS=OFF -DOPENEXR_BUILD_EXAMPLES=OFF \
  -DOPENEXR_INSTALL=OFF -DOPENEXR_BUILD_PYTHON=OFF -DOPENEXR_BUILD_OSS_FUZZ=OFF

# v3.5.3 ASan + Debug
cmake -S src/openexr-3.5.3 -B build-fixed-asan \
  -DCMAKE_BUILD_TYPE=Debug \
  '-DCMAKE_C_FLAGS=-fsanitize=address -fno-omit-frame-pointer -g -O1' \
  '-DCMAKE_CXX_FLAGS=-fsanitize=address -fno-omit-frame-pointer -g -O1' \
  -DBUILD_SHARED_LIBS=OFF -DOPENEXR_FORCE_INTERNAL_IMATH=ON \
  -DBUILD_TESTING=OFF -DOPENEXR_BUILD_TOOLS=OFF -DOPENEXR_BUILD_EXAMPLES=OFF \
  -DOPENEXR_INSTALL=OFF -DOPENEXR_BUILD_PYTHON=OFF -DOPENEXR_BUILD_OSS_FUZZ=OFF

# v3.5.3 plain Release
cmake -S src/openexr-3.5.3 -B build-fixed-plain \
  -DCMAKE_BUILD_TYPE=Release '-DCMAKE_C_FLAGS=-O2 -g' '-DCMAKE_CXX_FLAGS=-O2 -g' \
  -DBUILD_SHARED_LIBS=OFF -DOPENEXR_FORCE_INTERNAL_IMATH=ON \
  -DBUILD_TESTING=OFF -DOPENEXR_BUILD_TOOLS=OFF -DOPENEXR_BUILD_EXAMPLES=OFF \
  -DOPENEXR_INSTALL=OFF -DOPENEXR_BUILD_PYTHON=OFF -DOPENEXR_BUILD_OSS_FUZZ=OFF
```

Configure rc: `0` for all four. Full transcripts:
`build-<name>/build-<name>-configure.log`.

Configure observations: the GitHub source archives contain no Imath directory,
so `-DOPENEXR_FORCE_INTERNAL_IMATH=ON` triggered CMake `FetchContent` of
Imath v3.2.3 from `https://github.com/AcademySoftwareFoundation/Imath.git`
into each build tree's `_deps/imath-src` (all four clones succeeded). Detected
external dependencies: libdeflate 1.19, zstd 1.5.5, zlib 1.3, system threads;
OpenJPH 0.32.0 was vendored. `clang-format not found.` appears in each
configure log (non-fatal, formatting not part of build).

## 4. Build

```sh
cmake --build build-vuln-asan  --parallel 4
cmake --build build-vuln-plain --parallel 4
cmake --build build-fixed-asan --parallel 4
cmake --build build-fixed-plain --parallel 4
```

All four returned rc `0`; full transcripts are
`build-<name>/build-<name>-build.log`. Grep of each build log for
`warning:` / `error:` found 0 lines. Although `OPENEXR_BUILD_EXAMPLES=OFF`
and `BUILD_TESTING=OFF` were set, the `website/src` example-source target is
still added unconditionally by OpenEXR's root CMakeLists and compiled; no test
or tool targets were built. `OPENEXR_INSTALL=OFF` was set: nothing was
installed; use the build-tree paths below.

### Output archives (static, versioned names; "or equivalent" to libOpenEXRCore.a)

| Tree | Archive (relative to lab root) | Size (bytes) | SHA-256 |
|---|---|---:|---|
| v3.5.2 ASan/Debug | `build-vuln-asan/src/lib/OpenEXRCore/libOpenEXRCore-3_5_d.a` | 14185152 | `541d5d01aecd7277a623a30a4fe839d8cdf4dc890fcdf9b51ba1af21420171a3` |
| v3.5.2 plain/Release | `build-vuln-plain/src/lib/OpenEXRCore/libOpenEXRCore-3_5.a` | 11390268 | `d18060bc2428345a70d5332577728d4a270e7e02e9fafc44e31ca385639b2caf` |
| v3.5.3 ASan/Debug | `build-fixed-asan/src/lib/OpenEXRCore/libOpenEXRCore-3_5_d.a` | 14236274 | `7d1402f7e47ffe47958a2c673e367122cfd6f268cd22c8546b5fa480d9a46d16` |
| v3.5.3 plain/Release | `build-fixed-plain/src/lib/OpenEXRCore/libOpenEXRCore-3_5.a` | 11467908 | `c80bc166ecdca9dea69fb42c11830efa0b9af3217c6ceef824eb923844cf5f98` |

The `_d` suffix is CMake's Debug configuration suffix, not a different library.

## 5. Consumer include/link paths (build tree, no install)

For `<name>` in `vuln-asan`, `vuln-plain`, `fixed-asan`, `fixed-plain`, and
`VER` = `3.5.2` for the `vuln-*` trees, `3.5.3` for `fixed-*` trees, the
include directories actually used to compile `OpenEXRCore` are (relative to
lab root):

```
build-<name>/src/lib/OpenEXRCore          # generated core headers
src/openexr-<VER>/src/lib/OpenEXRCore     # in-tree public headers (openexr.h, ...)
src/openexr-<VER>/external/OpenJPH/src/core
build-<name>/cmake                        # OpenEXRConfig.h, IlmThreadConfig.h
build-<name>/_deps/imath-src/src/Imath
build-<name>/_deps/imath-src/src
build-<name>/_deps/imath-build/config     # ImathConfig.h
build-<name>/OpenEXR_ImathIncludeCompat   # <Imath/...> compatibility shim
```

Minimal consumer source (`build-vuln-asan/smoke_core.c`, kept in the build tree):

```c
#include <openexr.h>
#include <stdio.h>
int main(void) {
    printf("OpenEXRCore: %s\n", exr_get_error_code_as_string(EXR_ERR_SUCCESS));
    return 0;
}
```

Smoke compile/link for each tree (run from lab root; `inc` is the list above
as `-I` flags, obtained from
`build-<name>/src/lib/OpenEXRCore/CMakeFiles/OpenEXRCore.dir/flags.make`):

```sh
cc $CFLAGS -D_FILE_OFFSET_BITS=64 -DLIBDEFLATE_DLL $inc \
  build-vuln-asan/smoke_core.c <archive> \
  -ldeflate -lzstd -lz -lpthread -lm -o build-<name>/smoke_core
ASAN_OPTIONS=detect_leaks=0 build-<name>/smoke_core
```

`CFLAGS` = `-fsanitize=address -fno-omit-frame-pointer -g -O1` for the two
ASan trees and `-O2 -g` for the two plain trees. Result for all four: rc `0`,
stdout `OpenEXRCore: EXR_ERR_SUCCESS`. This proves the in-tree core header
(`<openexr.h>`) is includable and each static archive links and runs;
the `<OpenEXRCore/openexr.h>` install-style spelling was **not** tested because
`OPENEXR_INSTALL=OFF` (no install tree exists).

## 6. Negatives / not verified / failures preserved

- Initial hash-check path guess `src/openexr-v3.5.x/src/lib/OpenEXRCore/internal_zstd.c`
  failed with "No such file or directory"; the archives actually extract to
  `src/openexr-3.5.x/`. Corrected paths were then hashed successfully. No build
  or link failures occurred after that.
- No EXR files were crafted and no decode harness/fuzzer was run: that is
  explicitly another worker's slice. No exploit reproduction, ASan crash,
  overflow behavior, or v3.5.2-vs-v3.5.3 runtime difference was attempted or
  observed.
- No tests were enabled or run (`BUILD_TESTING=OFF`, rc-0 builds only); the
  project's test suite and linters were intentionally skipped.
- No `cmake --install`, no shared libraries, no symbol-level diff of the two
  archives, and no independent verification of upstream tarball hashes against
  an out-of-band source were performed. The tarball hashes above are only
  locally measured values.
- The `src/7d7fbb1.patch` pin was neither applied nor validated.
- ASan builds are instrumented but were only exercised by the trivial smoke
  program; no malformed input was passed to them.
