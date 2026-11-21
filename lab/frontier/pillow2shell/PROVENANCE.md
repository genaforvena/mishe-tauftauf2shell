# Provenance — Pillow FPX/JPEG scanline OOB write (CVE-2026-112398)

All sources were fetched read-only as provisioning on 2026-11-21 ~12:30Z;
nothing was sent to any external host. `gen_driver.py` re-verifies every hash
on each run; on drift it exits 1 (`sys.exit(str)` at `:28`) and `run.sh`
exits 2 (`:23`). Raw bytes, not HTML-rendered readers, are
authoritative for line numbers.

| Pin | SHA-256 | Source |
| --- | --- | --- |
| `src/cve112398.json` | `3632abba025681d0fea450b37bad7e10516ae46029ba0f2628ae4e77dfac98a8` | <https://cveawg.mitre.org/api/cve/CVE-2026-112398> |
| `src/ghsa-5x8w-8jj5-q52h.html` | `3dac6010372a3cca8d67d332d2ea047b7b4009ce4bd30a9a7002d3acc78f8a81` | <https://github.com/advisories/GHSA-5x8w-8jj5-q52h> |
| `src/fix112398.patch` | `dc0e90b2394c856b68cc694ebe279bfed78550216af2bd73de1a9e2af325fa38` | <https://github.com/python-pillow/Pillow/commit/242a059aedc1935097d9aa1dc3f099750467ba75.patch> |
| `src/JpegDecode.v12.2.0.c` | `895fc76b3f04e93fbc8a31f952e168432ecd140ae38fc1bba3c70d5803ed4682` | <https://raw.githubusercontent.com/python-pillow/Pillow/12.2.0/src/libImaging/JpegDecode.c> |
| `src/JpegDecode.v13.0.0.c` | `9c575a6e9e1247f06635047862cca39873e9d888a51b5d592ee0f57965f4c5df` | <https://raw.githubusercontent.com/python-pillow/Pillow/13.0.0/src/libImaging/JpegDecode.c> |
| `src/decode.v12.2.0.c` | `d9d96888c2ca64788acc3f8376567290aa6c8e5beb76779da0498447fd3f08ce` | <https://raw.githubusercontent.com/python-pillow/Pillow/12.2.0/src/decode.c> |
| `src/FpxImagePlugin.v12.2.0.py` | `4fa3a75a4bbca8bb1b6240fe6e2eb76706f894a2f96f2d67eeb5653d3e5eb46a` | <https://raw.githubusercontent.com/python-pillow/Pillow/12.2.0/src/PIL/FpxImagePlugin.py> |

Cross-checks: OSV <https://osv.dev/vulnerability/CVE-2026-112398>; upstream
advisory <https://github.com/python-pillow/Pillow/security/advisories/GHSA-5x8w-8jj5-q52h>;
fix release <https://github.com/python-pillow/Pillow/releases/tag/13.0.0>.
The GHSA HTML pin is a snapshot, not byte-reproducible on re-fetch: fresh GETs
return new fetch-nonce/request-id/visitor-payload/random IDs while every
advisory string stays equal in count (semantically identical). Six of seven
pins were byte-identical on a fresh re-fetch; this is the same
non-byte-stable class as the OSV pin note in witness wake W64.

## Verbatim copied lines

- `driver_vuln.c`: `decode.c` v12.2.0 `:223` (`state->bytes = ...`) and `:226`
  (`state->buffer = ... calloc`), `JpegDecode.c` v12.2.0 `:220-221`
  (JCS_UNKNOWN fallback) and `:252` (`ok = jpeg_read_scanlines(...)`).
- `driver_fixed.c`: the same sizing and fallback lines, fixed v13.0.0 guard
  `:247-253` and scanline `:263` (the affected caller's `:252` statement is
  byte-identical at both tags).

All copied lines carry `#line` markers naming their pin and true line number.
The rest of each driver is stand-in scaffolding: struct definitions, an
in-memory CMYK JPEG built by the host libjpeg, a correctly sized staging row
and a local row-copy shim. System libjpeg is not ASan-instrumented, so the
ASan WRITE is reported in the shim called from the pinned caller line; the
libjpeg stores themselves were not ASan-observed in this harness. No FPX file,
olefile, Pillow build, socket or Pillow process was used.

## Replay record

Commit `f44a538`: `git archive f44a538 lab/frontier/pillow2shell` extracted
into `/tmp/pw2-archive` and replayed with an absolute outdir `/tmp/pw2-out`
gave 10 PASS / 0 FAIL rc 0, two five-run groups both
`sha256=cb758c07f0aec3620c7b0d14c0fd471bf6b1455c410ead291db7a57eb08d818b`.
The seven pins were byte-identical to the direct fetches in the table above.
