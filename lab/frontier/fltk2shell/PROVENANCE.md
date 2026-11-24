# Provenance — fltk2shell frontier candidate

All network reads were provisioning of public source and advisory pages
(github.com, raw.githubusercontent.com, cve.org); no probe targeted any
external host. All executed code ran locally on this host.

## Pinned upstream material

- `fltk-1.4.5.tar.gz` — `https://github.com/fltk/fltk/archive/refs/tags/release-1.4.5.tar.gz`,
  sha256 in `PINS.sha256`. Expands to `fltk-release-1.4.5/`.
- `Fl_BMP_Image.release-1.4.5.cxx` —
  `https://raw.githubusercontent.com/fltk/fltk/release-1.4.5/src/Fl_BMP_Image.cxx`,
  byte-identical to the tarball copy (`cmp` verified).
- `fix-a28e392.patch` — `https://github.com/fltk/fltk/commit/a28e3927faebaba7d33f740d13e88fa0e22fd64d.patch`,
  the reported fix (two `size_t` row-pointer casts, one file).
- `fix-3a049d8.patch` — predecessor fix for issue #1632 / CVE-2026-116724
  (256-entry colormap bound + `size_t` allocation), applied by hand to the
  1.4.5 trees because the master patch does not apply verbatim at that tag.
- `Fl_Image.release-1.4.5.H` / `Fl_Image.cxx` —
  `FL/Fl_Image.H` and `src/Fl_Image.cxx` at the same tag; `max_size()` defaults
  to `~(size_t)0` (`Fl_Image.cxx:335`).
- Advisory and primary report: CVE-2026-135433 record, GitHub issues #1647
  and #1632. The issue's generator, driver shape and three 118-byte geometries
  were re-created locally in `gen_bmp.py` and `driver.cxx`.

## Builds and trees

- `fltk-release-1.4.5/build-asan` — upstream tag, CMake ASan/Debug build;
  `driver-asan` links its real `libfltk_images.a` and `libfltk.a`. This tree
  demonstrates the allocation-wrap variant of the geometry.
- `fltk-1.4.5-plus1632/` — copy of the tag with #1632's two edits applied by
  hand; isolates the row-pointer wrap named in CVE-2026-135433.
- `fltk-1.4.5-plus1647/` — same plus the two `(size_t)y` row-pointer casts
  from `a28e392`, adapted to the 1.4.5 variable name `bDepth`; fixed control.

CMake options used for every tree: `FLTK_BUILD_TEST=OFF`,
`FLTK_BUILD_EXAMPLES=OFF`, `FLTK_BUILD_FLUID=OFF`, bundled JPEG/PNG/ZLIB,
`CMAKE_CXX_FLAGS=-fsanitize=address -fno-omit-frame-pointer -g -O1`,
`CMAKE_EXE_LINKER_FLAGS=-fsanitize=address`. Configure and build logs are
`configure*.log` and `build*.log`. Run transcript: `evidence.log`.

## Naming and scope

`fltk2shell` is the candidate slug. The name is a research label only: the
CVE is local-file/UI with no remote or code-execution claim. No admission,
charter, wake unit or target window is implied by the lab directory.
