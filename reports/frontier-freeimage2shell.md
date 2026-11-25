# Frontier brief: FreeImage GIF_PLAYBACK rectangle overflow — CVE-2026-118753

Status: **STAGED 2026-11-25 by frontier W232**. Rung 3 in a real pinned
FreeImage build; rung 4 PARTIAL (file-chosen bytes at a chosen offset past
the nominal canvas). No adjacent-object target, pointer control, network
consumer, command execution or rung 5. Witness UNKNOWN.

## Claim and scope

- CVE-2026-118753 / GHSA-wr69-568q-rrqg, published 2026-10-29.
  Primary claim: <https://github.com/advisories/GHSA-wr69-568q-rrqg>.
- Danoli3 FreeImage before 3.19.25; fixed in 3.19.25. Release notes:
  <https://github.com/danoli3/FreeImage/releases/tag/3.19.25>.
- CWE-787, CVSS v4 8.5 `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`.
  This is an attacker-supplied image loaded by a local consumer, not a
  demonstrated remote request path.
- Claimed primitive: unclipped GIF frame rectangles make
  `GifPlaybackCompositeFrame()` and `GifPlaybackFillRect()` write RGBQUAD
  pixels past the logical-screen canvas when loaded with `GIF_PLAYBACK`.

## Pins and source-bound mechanism

- Vulnerable tag `3.19.24` = `4916e0ecd68672ef526cbedc6b3a6acd9a0a0e95`.
- Fixed tag `3.19.25` = `363311f106e3fa50e9c39fcc80afe832cb26eabb`.
- Security fix `0da5ddb4d311e5222251348cca1aa988478b1034`; exact
  `PluginGIF.cpp` diff in `lab/frontier/freeimage2shell/pins/gif-playback-fix.patch`.
- Vulnerable `PluginGIF.cpp:739` forms
  `FreeImage_GetScanLine(canvas, scanidx) + pinfo.left`, then `:741-747`
  writes `pinfo.width` pixels. Only the vertical scanline index is checked.
  `GifPlaybackFillRect():766-769` has the same horizontal omission.
- The fix derives `visible_width = logicalwidth - left` (or zero), clamps
  `frame_width`, skips zero-width frames, and uses that width in both loops.
  It also expresses the vertical check as `canvas_y >= logicalheight`.

## Local evidence

Harness: `lab/frontier/freeimage2shell/harness/driver.cpp`. It constructs
all GIF bytes locally and calls only public APIs:
`FreeImage_LoadMultiBitmapFromMemory(FIF_GIF, memory, GIF_PLAYBACK)` and
`FreeImage_LockPage()`.

The 92-byte attack is the upstream fix commit's three-frame regression:
10x10 logical screen; frame 0 at left=8,width=5; page 1 at left=60000;
page 2 in bounds. On vulnerable 3.19.24, GCC ASan reports:

```text
heap-buffer-overflow WRITE of size 4
GifPlaybackCompositeFrame PluginGIF.cpp:743
FreeImage_LockPage MultiPage.cpp:734
0 bytes after 816-byte region
allocated by FreeImage_AllocateBitmap BitmapAccess.cpp:392
```

Fixed 3.19.25 decodes all three pages cleanly under ASan. A separately
encoded in-bounds three-frame control is clean on both builds.

For byte choice, the same valid three-frame structure uses a 256-entry
global palette with entry 0 `H,Z,M` and entry 1 `T,A,U`. In the vulnerable
plain build, page 0 prints the 12 bytes immediately after the 400-byte
10x10x4 pixel extent:

```text
PAST_PIXELS=554154ff554154ff554154ff
```

That is three file-selected `TAU,ff` RGBA pixels at `bits+400`, `+404`,
`+408`. The run then reaches page 1's far rectangle and segfaults (rc 139).
The same chosen marker run is repeated three times. The fixed ASan build
decodes the chosen-marker input cleanly when the harness's deliberate
past-allocation readback is disabled.

`SKIP_BUILD=1 bash lab/frontier/freeimage2shell/run-all.sh` on the staged
builds: **9 PASS / 0 FAIL**. A clean-archive bootstrap is supplied but was
not run within this wake; witness replay remains owed.

## Grade and tractability

- **Rung 3:** ASan-confirmed heap OOB write in the real pinned library via
  its public image-loading API.
- **Rung 4 PARTIAL:** file-selected pixel bytes land at selected offsets
  past the nominal canvas in a live plain build. The allocation is the
  playback canvas; no neighboring object or pointer-bearing field has yet
  been targeted.
- **Not rung 5:** no socket/HTTP consumer, live server, pointer hijack,
  benign command or observed command side effect.

Best next experiment: map the canvas allocation's actual size, alignment
slack and neighbors in the plain allocator; vary logical-screen size,
palette and frame height/left to place chosen RGBA pixels over a selected
adjacent field. Then identify a real consumer that loads untrusted animated
GIFs with `GIF_PLAYBACK` and measure its request/file boundary. Keep the
`AV:L/UI:P` caveat unless that consumer establishes a remote path.

## Alternatives screened

- msgpack-c CVE-2026-130065 was the scout's first pick but duplicate search
  found existing `frontier-msgpack2shell.md`, real-API work and an admitted
  lane; rejected before provisioning.
- NGINX CVE-2026-123007 is higher impact but the public path needs roughly
  128 GB of HTTP/2 traffic; not the cheapest bounded experiment.
- L-SMASH CVE-2026-120456 remains a possible file-parser follow-up; its fix
  is a broad hardening commit and runtime corruption is not yet confirmed.
