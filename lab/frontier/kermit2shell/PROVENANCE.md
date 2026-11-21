# PROVENANCE — kermit2shell

All sources fetched read-only 2026-11-21 from public primary sources; no
off-loopback probing. Pins under `pins/`, hashes verified on every `./run.sh`.

| Pin | sha256 | bytes |
|---|---|---|
| `pins/cve.json` (CVE-2026-129126 record) | `6c43f2b79cf77076ee7e11d3f4052a4d2793bcfb6219d01ea53084ec9576213f` | 3621 |
| `pins/ghsa.html` (GHSA-c5px-7h4c-gj8p advisory) | `96477695d661459d8e7f511d355507046b6e376e67ea555052a4c8956f776faf` | 154915 |
| `pins/fix.patch` (commit `37e54720779237897bc6887efac42fe138817897`) | `2f25c8d7387d3d70d4c1867a0bd1becf60a7ce700956ae77b2ac4ce3706cf2b1` | 6856 |
| `pins/ckcfns.c.vuln` (v11.0.514) | `6afc5e4599777c6b9b2366b55dd9c05f9928c67aed3ab77eb29ed237858cc71f` | 279705 |
| `pins/ckcfns.c.fixed` (v11.1.515) | `7acdefc4ce7300f009a3b75712cb158ef454dfba35081a77abf151796df4abe9` | 292296 |
| `pins/ckcker.h.vuln` (v11.0.514) | `751a1a2270d28e6eeb5d8f11bafd3c5acd16db657d9ff9e8699be9971ba83290` | — |
| `pins/ckcmai.c.vuln` (v11.0.514) | `d704b5f0011df1930e691b09bd3ba4c7cf2e7cfaa25a14615227acd1d1326d8b` | — |
| `pins/ckcmai.c.fixed` (v11.1.515) | `6856a7c08a7acbd2277a129b88919b0660d80a1abe3cb2f93ce7d9b6600ceb6f` | — |

Verbatim ranges: `putsrv()` from `ckcfns.c.vuln:454-466` (write at `:461`,
`*srvptr++ = c;` and `*srvptr = '\0';`) and `ckcfns.c.fixed:464-479` (adds
`if (srvptr - srvcmd >= srvcmdlen) return(-1);`). `gen_driver.py` extracts
those bytes mechanically, aborts on hash drift, and emits them under `#line`.
The `#line` value is start-line minus one to compensate for GCC's `#else`
branch accounting; observed ASan frame is `pins/ckcfns.c.vuln:461`.

Buffer facts pinned: `ckcker.h.vuln:365-367` `#define MAXRP 9024`;
`ckcmai.c.vuln:994-1003` `int srvcmdlen = MAXRP;` (DYNAMIC) / `int srvcmdlen
= 0;` (non-DYNAMIC), `srvcmdbuf[MAXRP+4]`, `*srvcmd = srvcmdbuf`.
`decode()` repeat path pinned at `ckcfns.c.vuln:1357-1359`, `:1405`, `:1420`;
repeat count `rpt = xunchar(*xdbuf++)`, `for (; rpt > 0; rpt--) fn(a)`.

Reproduction: `cd lab/frontier/kermit2shell && ./run.sh out`. Latest:
**18 PASS / 0 FAIL**, trace `sha256=0de1067bc8745bd7641cd66b9aed578151ca3915357bac59a637b25e51706622`.
`out/` is gitignored; generated drivers are reproducible from pins.
