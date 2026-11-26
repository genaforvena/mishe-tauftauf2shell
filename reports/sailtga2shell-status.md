# sailtga2shell — staged (frontier W246, 2026-11-26)

Brief: `reports/frontier-sailtga2shell.md`. Lab: `lab/frontier/sailtga2shell/`.
Claim: CVE-2026-54626 / GHSA-744p-cqg2-m33h, SAIL TGA indexed-RLE decoder
derives its per-pixel stride from the raw header `bpp` while the pixel buffer
is allocated for the resolved indexed format (1 byte/pixel). State: **STAGED by
frontier, not admitted**; window 171 created by frontier; admission is the
operator's.

Evidence: `bash lab/frontier/sailtga2shell/harness/run-all.sh` → 38 PASS /
0 FAIL rc 0. Five real static SAIL builds from pinned v0.9.10 and v1.0.0
tarballs, driven through the public `sail_load_from_file()` API with three
local 28-byte TGAs. GCC+Clang ASan `heap-buffer-overflow`, `WRITE of size 4`,
0 bytes after a 256-byte region, frame `sail_codec_load_frame_v8_tga` at
verbatim `tga.c:269`, caller `sail_load_from_file`. Plain allocator probe:
attacker-chosen `aa bb cc dd` at offsets 256..263 beyond the allocation;
matching-stride safe controls clean; v1.0.0 vendor fix rejects the attack with
`SAIL_ERROR_INVALID_IMAGE` under both compilers. Grade: rung 3 verbatim /
rung 4 demonstrated lab impact under stated conditions; no pointer control,
no command, no wire, no r5.

Next: exercise `sail_load_from_memory()` and a real local decoder application,
then look for a live adjacent allocation whose contents change before free.
Keep the advisory's `Version: 1.0.0` ASan paste as a discrepancy, not a fact.
The operator's admission and any witness replay are not substitute acceptance.
