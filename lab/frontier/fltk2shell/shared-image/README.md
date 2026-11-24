# Fl_Shared_Image / ICO probe (CVE-2026-135433)

One bounded experiment on the `Fl_Shared_Image`/ICO path. All new files are in
this directory; no existing lab file was modified and nothing was committed.
Reproduce with `sh build.sh && sh run.sh`; `consumer-vuln` and `consumer-fixed`
are local build products linked against the pre-built ASan FLTK trees and are
not committed.

## Dispatch found in the built plus1632 tree

* `Fl_Shared_Image::get()` (`src/Fl_Shared_Image.cxx:579-619`) -> constructor
  `Fl_Shared_Image(const char*)` at `:133-146` -> `reload()` at `:276-321`.
* `reload()` reads 64 header bytes and calls registered handlers at `:303-305`.
  The normal app call `fl_register_images()` (`src/fl_images_core.cxx:61-64`)
  installs `fl_check_images`; `"BM"` -> `new Fl_BMP_Image(name)` at `:98-99`,
  `\0\0\1\0` -> `new Fl_ICO_Image(name)` at `:101-102`.
* `Fl_ICO_Image::load_ico_()` (`src/Fl_ICO_Image.cxx:74-202`) takes width/height
  from the 16-byte IconDirEntry, enforces `:193` size guard, then calls
  `load_bmp_(rdr, h(), w())` at `:201`.
* `Fl_BMP_Image::load_bmp_()` ignores the DIB width/height when `ico_height>0`
  and `ico_width>0` (`:201-205`), allocating from those 8-bit values. The size
  guard at `:284` does **not** reject the standalone 4 GiB BMP because FLTK's
  `max_size()` defaults to essentially unlimited (`FL/Fl_Image.H:386`).

## What was measured

Headless consumer (`consumer.cxx`) against pre-built ASan libs; exact commands,
exit codes and raw stdout+stderr are in `commands.txt`, `exit-codes.txt` and
`outputs/<case>.{meta,out}`. Build details in `build.log`/`build-info.txt`;
generation transcript in `run.log`; input bytes pinned in `inputs.sha256`.

| case (vulnerable plus1632) | rc | observation |
|---|---|---|
| `shared ../poc-chosen.bmp` | 134 | ASan `WRITE of size 1` at `Fl_BMP_Image.cxx:490`, `2 bytes before 4294967298-byte region`; stack: `fl_images_core.cxx:99` -> `Fl_Shared_Image.cxx:304` -> `:144` -> `:594` |
| `direct ../poc-chosen.bmp` | 134 | same :490 write / same region (sanity control in this binary) |
| `shared ../safe.bmp` | 0 | `w=2 h=8 d=3`, no ASan |
| `ico crafted.ico`, `shared crafted.ico` (118-byte BMP DIB wrapped) | 0 | `fail=-3`, EOF at offset 126; no ASan |
| `ico crafted-full.ico`, `shared crafted-full.ico` (complete 2x256 resource, crafted DIB kept) | 0 | `fail=0 w=2 h=256 d=3`; no ASan |

Same cases in the fixed plus1647 ASan tree: all rc=0, no ASan. For `shared`/
`direct` with the standalone crafted BMP the loader ends with EOF at
`Fl_BMP_Image.cxx:510` and `fail=-3 w=2 h=0 d=0` (the `(size_t)` row-pointer
fix keeps writes in bounds; the 118-byte file then cannot satisfy 715827883
rows). ICO cases in the fixed tree match the vulnerable tree.

## Guards / negative result

The ICO container is a clean negative for this row-pointer wrap: `bWidth` and
`bHeight` are single bytes (0 encodes 256), and `load_bmp_()` uses them instead
of the crafted DIB's `height=715827883`, so `y*width*bDepth` stays far below
2^32 and no `write 2 bytes before` occurs. With a complete resource the image
loads normally at 2x256; with the truncated 118-byte resource the read checks
reject it. `Fl_Shared_Image::get()` itself adds no geometry guard - the crafted
standalone BMP reaches the same fault through the normal handler dispatch.

## What was NOT measured

No GUI window, draw/render path, cache-hit reload, other formats, 32-bit build,
non-ASan build, or any control-flow/IP/RCE behavior. ASan detection in-process
only; this is not a rung-5 claim and makes no witness-acceptance claim.
