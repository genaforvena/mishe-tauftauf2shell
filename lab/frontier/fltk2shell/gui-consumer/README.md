# fltk2shell wake 5 — real X11 GUI consumer / draw path

Scope: author-measured extension to CVE-2026-135433. Does **not** change the
witness ESTABLISHED grade (W195, rungs 1–4 at the direct-call scope) and makes
no rung-5 claim. Hand to `witness` for independent replay; no verdict yet.

## What is exercised

`gui.cxx` is a real FLTK 1.4.5 X11 application, not a synthetic loader: it
calls `fl_register_images()`, loads a benign BMP through
`Fl_Shared_Image::get()`, attaches it to an instrumented `Fl_Box`, maps an
`Fl_Double_Window` on a private Xvfb display and pumps the FLTK event loop
five times so a genuine `draw()` happens (`draw_count=1` in every case).
Only then does it load the second file through the same standard
`Fl_Shared_Image::get()` API while the window is still live.

## Prerequisites and exact commands

The two ASan FLTK trees must already exist; `sh ../run-all.sh` builds them
from the pinned `fltk-1.4.5.tar.gz` (`build-fixed/` in `plus1632` and
`plus1647`). Build and run from this directory:

```
sh build.sh
sh run.sh
cat exit-codes.txt
```

`run.sh` starts its own `Xvfb :177 -screen 0 640x480x24 -nolisten tcp`,
records `display.txt`, `commands.txt`, `inputs.sha256`, four raw outputs in
`outputs/` and `exit-codes.txt`, and kills the display on exit. Refuses to
run if `:177` is already in use, so it cannot disturb another consumer.

## Measured results (ASAN_OPTIONS=abort_on_error=1:allocator_may_return_null=1)

| case | binary / second file | rc | observed |
|---|---|---|---|
| vuln-crafted | `gui-vuln`, `../poc-chosen.bmp` | 134 | `WRITE of size 1`, `2 bytes before 4294967298-byte region`, `Fl_BMP_Image.cxx:490` via `:64` -> `fl_images_core.cxx:99` -> `Fl_Shared_Image.cxx:304` / `:594` -> `gui.cxx:46`; `draw_count=1` before the load |
| vuln-safe | `gui-vuln`, `../safe.bmp` | 0 | no ASan; second image returned |
| fixed-crafted | `gui-fixed`, `../poc-chosen.bmp` | 0 | no ASan; only `[510] unexpected EOF or read error at offset 118` (intentionally truncated pixel area) |
| fixed-safe | `gui-fixed`, `../safe.bmp` | 0 | no ASan |

All four cases printed `GUI RESULT shown draw_count=1 safe=2x8 depth=3`, so
the X11 draw path itself ran with a valid image before the crafted load.

## Receipts (this run)

* `inputs.sha256`: `poc-chosen.bmp` `135edc0a…13008`, `safe.bmp`
  `031fb41f…99cb0a6`, `gui.cxx` `bb7e4c23…da0da0`; `sha256sum -c` passes.
* `exit-codes.txt` sha256 `c360e4ce…557f9bdf`; `commands.txt` sha256
  `293218ba…478be`. Raw output hashes are run-specific (ASLR addresses and
  BuildId): `vuln-crafted.out` `7b94ed77…3916f95e`, `vuln-safe.out` and
  `fixed-safe.out` both `3b9ea4c2…f093f868`, `fixed-crafted.out`
  `78ebee0a…00138958`.

## Ceiling

The crafted image faults **during load, before it can be attached or drawn**;
this closes the live-X11 application-load unknown, not a draw-time exploit.
No cache-hit reload, no network-facing service, no pointer/IP control, no
command execution, no rung 5. The advisory itself is local/UI-only.
