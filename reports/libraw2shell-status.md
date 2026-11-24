# libraw2shell — status

Admitted 2026-11-24 05:4xZ under standing #6 as the 127th route. Claim:
`CVE-2026-135176` (VulnCheck 2026-11-23, CWE-787, CVSS4 5.8,
`AV:L/AC:H/AT:P/PR:N/UI:P/VC:N/VI:H/VA:H`) — LibRaw exactly 0.22.3 has a heap
OOB write in `xtrans_interpolate()` with X-Trans wavelet denoising or chromatic
aberration correction; the advisory says crashes, not RCE. Upstream issue
LibRaw/LibRaw#894 is open with no merged fix, so the fixed control is the
reporter's two lines and fixed status is UNKNOWN. Stage: rungs 1-3 in the real
`dcraw_emu` consumer, rung 4 PARTIAL (chosen offset, zero value); no witness
verdict, no rung 5.

## Admission evidence

- Frontier brief `reports/frontier-libraw2shell.md` (staged W197) pins the
  0.22.3 tarball `7edf96c5…355c`, PoC zip `619e741e…abe61`, extracted input
  `c7940268cfb817adc4d5d42e9327a93fd042d7cd4cda8bc4b4ed6f1c4435dae2`, fix
  patch `32fc61e5…afc9c` and the lab-only `craft_poc.py` in
  `lab/frontier/libraw2shell/PINS.md`. The two-pane window 133 was created by
  frontier at 05:11Z and adopted, not duplicated; registry 134/134 unique,
  seed wall present.
- Operator verification 05:3xZ: `evidence/evidence.log` sha256
  `8ad12e49ac28c2549b87c9707da47e632bcfbf99d5c7eb26716e950b9f874f57`
  matches the staged brief exactly (10 PASS / 0 FAIL), and the PoC input hash
  matches the issue. Author-side transcript on the same host, not a witness
  verdict.
- Minted under the exact full-flag sync from `docs/runtime-pin.md:96-102` with
  pin `0d686bbad55c849e88334da64efff9da88ad528a`: `written 6, removed 0` for
  the two targets admitted this wake; `m2shell-wake-libraw2shell.path` enabled
  and active after daemon-reload; pinned full-flag doctor `GREEN`, exit 0.
  Route count 125→127 (hy4-flash, `max_parallel: 3`); resolver 251→255 (both
  wake keys → operator).

## Current grade

Rungs 1-3 in the real `dcraw_emu` binary built from the pinned tarball with
the real public PoC:

1. Deterministic trigger — `shrink == 1` (from `-n 1`, `-C 1.1 1` or
   `-C 1 1.1`) leaves `iwidth=iheight=256` after `pre_interpolate()` rebuilds
   `image` at 512x512; `xtrans_interpolate()` allocates from the stale pair
   (549,152 bytes) but stores with a 512-pixel stride.
2. Confirmed corruption — ASan reports `heap-buffer-overflow WRITE of size 2`
   0 bytes past a 550,176-byte region at `xtrans_demosaic.cpp:427` ←
   `dcraw_process():184` ← `dcraw_emu.cpp:598`, for all three option forms;
   plain rc 139 (SIGSEGV).
3. Controls — the reporter's two-line fix and a safe input with no triggering
   option are both clean (rc 0).

Rung 4 is PARTIAL: gdb at `:427` fixes the first OOB store at index 68,644,
`row=131 top=3 col=33 left=3 width=512`, destination exactly `destimage +
549152` (delta 0), so the offset is deterministically chosen. The stored
halfwords are zero because the PoC decodes to an all-zero image (`avg={0,0,0,8}`).
Every attempt to make the bytes chosen is preserved as a negative result in
the brief and `craft_poc.py` (constant-0x4d JPEG, DNG tag edits and
uncompressed-strip conversion all failed); no byte control is claimed. A valid
nonzero-pixel X-Trans DNG accepted by LibRaw is an open prerequisite. No real
camera file, GUI consumer, network path, pointer/IP, command,
grooming/ASLR study, witness verdict or rung 5.

## Next for the target mind

1. Independent witness replay of the staged transcript and hash; operator
   requested it at tape. Author replay is not acceptance.
2. Find a valid nonzero-pixel X-Trans DNG to move rung 4 from partial to chosen
   bytes before considering placement control.
3. Never infer RCE from a zero-valued OOB store; hand any new claim to
   `witness`.
