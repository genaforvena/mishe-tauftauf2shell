# kicad2shell — fixed-build provisioning (W184, 2026-11-24)

## What is pinned here

The **fixed** branch of KiCad is available as an official binary; no source
patch of the harness is needed for this control:

- `ppa:kicad/kicad-10.0-releases`, noble/amd64 source package publishing
  history queried through Launchpad's API (`getPublishedBinaries`,
  `binary_name=kicad`, version `10.0.8~ubuntu24.04.1`) showed the binary
  published for noble/amd64.
- Deb:
  `https://ppa.launchpadcontent.net/kicad/kicad-10.0-releases/ubuntu/pool/main/k/kicad/kicad_10.0.8~ubuntu24.04.1_amd64.deb`
  sha256 `38721bf8c584e9191e4f2738a4a7204f0062e4cc2c47e17c7614384d55b87e48`.
- Extracted with `dpkg-deb -x` into `provisioned/apt-kicad10/`; no root, no FUSE,
  no system package installation. `kicad-cli version` → `10.0.8`.
- `FIXED-RELEASE.md` already establishes from GitLab raw bytes that 10.0.7
  carries the backport `if( ind < 1 ) continue;` and 10.0.6 does not.

Runtime libraries absent from the host were fetched as Ubuntu pool debs with
`apt-get download` into `provisioned/apt-debs/` and extracted into
`provisioned/apt-kicad10-deps/`: `libspnav0`, `libsecret-1-0`, `libnng1`,
`libwxgtk-webview3.2-1t64`, `libpoppler-glib8t64`, `libwebkit2gtk-4.1-0`,
`libjavascriptcoregtk-4.1-0`, `libmanette-0.2-0`, `libenchant-2-2`,
`libhyphen0`. `provisioned/gui-import10.sh` sets `LD_LIBRARY_PATH` over all
these trees plus the 8.0.8 wx 3.2 / python 3.13 tree and sets
`KICAD_CONFIG_HOME` to `provisioned/kicad10-config`. A throwaway `dlopen(...,
RTLD_NOW)` probe of `apt-kicad10/usr/bin/_eeschema.kiface` returned OK after
these libraries were added (it previously failed with an explicit missing
library name, each failure preserved above).

## GUI obstacles (observed, not resolved by patching code)

KiCad 10.0.8's first launch in this bare Xvfb environment repeatedly presents:

1. a webview "Google Chrome and ChromeOS Additional Terms of Service" page;
   the driver **declines** it (`Cancel`), never accepts legal terms;
2. a "Welcome to KiCad 10.0" first-run wizard that reappears after the
   wxWidgets-version notice; the driver steps through its `Next >` control;
3. a "Could not determine wxWidgets version. Python plugins will not be
   available." notice, dismissed with `OK`.

The 8.0.8 driver `provisioned/gui-import.sh` did not have to handle any of
these. Screenshots of each stage live in `provisioned/gui10-w184-*.png` and
are deliberately uncommitted lab artifacts. The missing
`/usr/share/kicad/schemas/api.v1.schema.json` is reported by the vendor binary
but did not stop the editor from loading after the kiface dependencies were
resolved.

## Scope

Provisioning and GUI observations only. No external probe, no scan, no
non-loopback target. The fixed source guard is already established in
`FIXED-RELEASE.md` and the harness lanes; this file records the vendor binary
used to attempt a fixed-build *real-process* control. A clean exit of a vendor
binary without ASan is not a pass; only a reached `ParseLibHeader` in the fixed
process with the hostile bytes and a safe-input control counts.

## W184 outcome: fixed binary runs, GUI import not reached

After all kiface dependencies were resolved, the vendor 10.0.8 editor does
load (boot screenshot), but the W182 menu sequence never reached a Symbol
Editor import. Across `gui-import10.sh` runs with the unmodified vendor file
(`w184-safe`, `w184-safe2`, `w184-safe3`, `w184-fixed-safe`, `w184-fixed-safe2`,
`w184-fixed-safe3`, `w184-fixed-safe4`, `w184-fixed-safe5`), the process stayed
alive with empty stderr in every run, yet the final screenshots show either
the Chrome additional-terms page, the first-run wizard, or the plain
schematic editor. No run produced a symbol import, so **ParseLibHeader was not
reached in the fixed build** and there is no fixed-build real-process control.
The Chrome terms page was declined in every run; it was never accepted. The
fixed-build binary's clean exit is NOT a pass and is NOT a negative result for
the vulnerability: it is a failed attempt to construct a control.

The hostile `SizeZ` fixtures were therefore not fed to the fixed build. The
fixed guard remains established only by source bytes and the harness lanes.
The still-missing evidence is unchanged: a fixed KiCad process that actually
imports the same hostile `.SchLib` and leaves its target library intact while
8.0.8 aborts. Preserved as a negative; do not re-run this GUI driver blind —
the first-run wizard/terms interaction needs a different strategy (pre-seeded
complete KiCad 10 profile, or a source-built fixed importer).
