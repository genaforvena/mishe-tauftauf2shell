# PROVENANCE — Firebird2Shell (CVE-2026-33337 / GHSA-89mq-229g-x47p)

All sources below were fetched read-only from public origins on 2026-11-21;
nothing outside loopback was probed or contacted with a trigger.

## Upstream pins (SHA-256 of the exact bytes stored in `src/`)

| Artifact | Origin | SHA-256 |
| --- | --- | --- |
| `src/xdr.v5.0.3.cpp` (affected) | `https://raw.githubusercontent.com/FirebirdSQL/firebird/v5.0.3/src/common/xdr.cpp` | `b28b1aaa56c552240b4cfcbc2c8761ff3888451eadd9d690ee091415b8559096` |
| `src/xdr.v5.0.4.cpp` (fixed) | `https://raw.githubusercontent.com/FirebirdSQL/firebird/v5.0.4/src/common/xdr.cpp` | `426a7a07889b07bba1646b1f77ae0fca0461a6bc78f9e1f7fecab66d3badf168` |
| `src/fix33337.patch` (master fix) | `https://github.com/FirebirdSQL/firebird/commit/2a5303dc9fb2cfc035a6aeb6274377d0e2dd3488.patch` | `9de138c31df40f0baaee0edc09d439e1e8a913012ae98c58597446d92288ce10` |
| `src/fix33337_v504.patch` (v5.0.4-branch fix) | `https://github.com/FirebirdSQL/firebird/commit/62fc37eda82fa1f8120aff7fb0fdd7c72b493a75.patch` | `ccbfd56bb7340f6505d1ec798ad2a9d3ae85969fc5dafd610f4ad544a17ffc98` |
| `src/cve33337.json` (CVE Program record) | `https://cveawg.mitre.org/api/cve/CVE-2026-33337` | `b6ac3a4ff0f4635115dcd943218278892a5ec568c6d9d943c78d6dfd8a9329ef` |
| `src/advisory33337.html` (GHSA-89mq-229g-x47p) | `https://github.com/FirebirdSQL/firebird/security/advisories/GHSA-89mq-229g-x47p` | `451f9b628677eca1ca5f55a66ba4ef5a192779e5226328b643ae44ec019f88b3` |
| `src/protocol.v5.0.3.cpp` (slice consumer) | `https://raw.githubusercontent.com/FirebirdSQL/firebird/v5.0.3/src/remote/protocol.cpp` | `68a0070f23b5fd199845c86542c57f16f58ed256306ea953557acb9ad783edfe` |
| `src/dsc.v5.0.3.h` (descriptor layout) | `https://raw.githubusercontent.com/FirebirdSQL/firebird/v5.0.3/src/common/dsc.h` | `c9a0310ca36b73f029697ce46fd933abb04a8e6d4421e91b7925fc3bc14841e2` |

The v5.0.3 and v5.0.4 git blobs are `555e6e1f40c4cd093710ba90ed7dd2232bdabeaa`
(20198 bytes) and `a5698288419d5fe3be7ca112663f3389f2956ab1` (20236 bytes);
the v5.0.4-branch fix patch is exactly the diff between those two blob IDs
(`index 555e6e1f40c..a5698288419`). The master fix `2a5303dc…` (parent
`be9b171c2846366011424ffdd6729a554cd0b65c`, 2026-03-19) adds the same two
lines to the master branch but is not the commit inside the v5.0.4 tag.

CVE-2026-33337 was published 2026-04-17T18:48:47.953Z by GitHub's CNA
(`GitHub_M`), CWE-120/CWE-502, CVSS 3.1 **7.5 High**
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. Affected: Firebird `>= 3.0.0, < 3.0.14`,
`>= 4.0.0, < 4.0.7`, `>= 5.0.0, < 5.0.4`; fixed in 3.0.14 / 4.0.7 / 5.0.4.
The advisory describes a pre-authentication slice packet to the server and
claims a crash or other security impact; availability-only CVSS, no C/I
impact scored. No code-execution claim is made by the CVE record.

## Source-bound statements copied verbatim by `gen_driver.py`

Pins are recorded below with SHA-256 and copied lines are verbatim (verified
independently by witness replay at tape #818); `gen_driver.py` does not itself
hash-check the pinned files. It emits only
the `dtype_cstring` case of `xdr_datum()` under `#line` markers at their true
line numbers:

- Affected `xdr.cpp:206-221`: `:207` declares `USHORT n`; `:214` reads the
  length from the wire via `xdr_short`; `:216` calls
  `xdr_opaque(xdrs, reinterpret_cast<SCHAR*>(p), n)` with **no bound**; `:219`
  writes `p[n] = 0` on decode.
- Fixed `xdr.cpp:206-223`: identical except `:216` adds
  `n = MIN(n, desc->dsc_length - 1)` before the `xdr_opaque` call at `:218`.

Consumer reality from pinned `protocol.cpp`: `xdr_slice()` reads
`slice->lstr_length` from the wire at `:1813`, allocates
`UCHAR[lstr_length]` at `:1835`, then loops `lstr_length / dsc_length` times
calling `xdr_datum(xdrs, desc, p)` with `p += dsc_length` at `:1884-1889`.
Each `p` is therefore a `dsc_length`-sized slot; the wire-supplied `n` is not
bounded by that slot. Pinned `dsc.h` confirms `dsc_dtype` (`UCHAR`, `:96`),
`dsc_length` (`USHORT`, `:98`) and `dsc_address` (`UCHAR*`, `:101`).

Harness stand-ins, all outside the copied statements: `USHORT`/`SSHORT`/
`SCHAR`/`ULONG`/`BLOB_PTR`/`IPTR`, `dsc`, `xdr_t`, `dtype_cstring = 6` and
`XDR_DECODE = 2` are minimal declarations; `xdr_short` writes the attacker's
16-bit wire length through the pinned call; `xdr_opaque` is a macro expanded
at the pinned call site so the ASan report is attributed to the verbatim
statement, and its decode `GETBYTES` is modelled by `memcpy` from a locally
supplied 256 KiB source; `MIN` is the ordinary ternary macro. Buffer
placement is an exact-size `malloc` (ASan), a known offset in a zeroed 1 MiB
mmap collaborator (chosen-byte readback), or a 32-byte allocation ending at a
`PROT_NONE` guard page (fault control). No Firebird server, wire protocol
stack, allocator neighbour, pointer control or execution is exercised.

## Harness digests and replay

- `gen_driver.py` `13378447b03056e2cdaa8e36b0dfa9497fd6ff7fd1e96646eb40445a0012bdbe`
- `run.sh` `8324ee2e6c701dcb2719563aa66481433f906da12373e4bb636a776053af4c3a`
- Generated `driver_vuln.cpp`
  `2577c0fead68b7108ce6a9ae4619799c39e730d4c299c8d9c1f439b574889af2`
- Generated `driver_fixed.cpp`
  `adb8528363eab71fcfea93beb0bc18adf9aa4b30d3b584ef35395287b50ec679`
- `bash lab/frontier/firebird2shell/run.sh <outdir>`: **10 PASS / 0 FAIL,
  ALL CHECKS PASS rc 0**; two independent five-run groups both
  `sha256=807b47150a58fe88094966b0affed9b35604a7b3730c68f53eeaa61057a25fbf`.
- Verbatim check: 16 affected lines (`:206-221`) and 18 fixed lines
  (`:206-223`) compared byte-for-byte against the pinned sources under their
  `#line` markers; zero mismatches.

Clean replay from `git archive HEAD` at commit
`dd2610f1f7a8f4be8c6f8a9e6b4bafb84b7d2b35`: 10 PASS / 0 FAIL, rc 0 and both
five-run groups
`sha256=807b47150a58fe88094966b0affed9b35604a7b3730c68f53eeaa61057a25fbf`
in a fresh temp directory. ASan PIDs, addresses and build paths are excluded
from the trace digest so clean replays are byte-identical.
