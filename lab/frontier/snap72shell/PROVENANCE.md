# Provenance — snap72shell / CVE-2026-131848

All fetches were read-only provisioning from public sources. No external host
was probed; all experiments run locally and never bind a socket.

## Pinned upstream bytes

Repository: <https://github.com/davenardella/snap7>, commit
`30f37da3114024a71ba93f7fd855c680b97a406f` (current upstream HEAD as of
2026-11-23; dated 2025-07-14). Raw-file URL pattern:
`https://raw.githubusercontent.com/davenardella/snap7/30f37da3114024a71ba93f7fd855c680b97a406f/src/core/<file>`

| File | SHA-256 |
| --- | --- |
| `src/core/s7_micro_client.cpp` → `src/s7_micro_client.cpp.30f37da` | `d42d94c458b6534a1070ee5506ce3f784be3af5bb91de4f88ea4f9dea7c0c486` |
| `src/core/s7_micro_client.h` → `src/s7_micro_client.h.30f37da` | `2c1a9eea0290ad72669d13f3db52883641076285652dbaa39fd7ec9dcb1f897c` |
| `src/core/s7_types.h` → `src/s7_types.h.30f37da` | `bee4013a518284a3199b662b275a683168426cac00708233595068b0b1388987` |
| `src/core/s7_isotcp.h` → `src/s7_isotcp.h.30f37da` | `b5824be72e60b39268c8fc1e5aee7fed05f4a4be93399fa1bac5333147273f6b` |

The pinned `.cpp` is CRLF. Lines 307-431 are `opReadMultiVars()`; the sink
`memcpy(Item->pdata, ResData[c]->Data, Slice);` is line 418.

## Advisory and issue sources

- GHSA: <https://github.com/advisories/GHSA-xr6p-cjp3-pvwg>
- VulnCheck: <https://www.vulncheck.com/advisories/snap7-through-1.4.3-out-of-bounds-write-via-tsnap7microclient-opreadmultivars>
- Reporter issue with PoC recipe and suggested fix:
  <https://github.com/davenardella/snap7/issues/32>
- Commit list checked via `https://api.github.com/repos/davenardella/snap7/commits?per_page=30`:
  HEAD is the pinned commit; no upstream fix commit exists.

## Fixed control (not upstream)

`src/opReadMultiVars.fixed.issue32.cpp` — SHA-256
`a4127166e9274f8fbefbda4f0536ad33808bed7135277ad93593ce02c322b233`. Derived
from the pinned vulnerable function by inserting the guard proposed in issue
#32 immediately before line 418:

- `MaxRecv = IsoSize - (ResHeaderSize23 + sizeof(TResFunReadParams)) - Offset - 4`
- `MaxDest = Item->Amount * DataSizeByte(Item->WordLen)`
- reject with `errCliInvalidPlcAnswer` and `break` when `Slice` exceeds either.

This is a source-bound derivative of a public issue proposal, **not** a patch
merged upstream. It is used only as the fixed control; the rung evidence comes
from the byte-exact vulnerable slice.

## Harness artifacts

| File | SHA-256 |
| --- | --- |
| `harness/driver.cpp` | `f55049233440ce078c62826685d799d4d601414c8608b16be34dafdd34db5c05` |
| `harness/vuln/opReadMultiVars.inc` (generated from pinned lines 307-431 with a `#line 307` directive) | `2ea5cd3d0bb8983cbbfbed4ec46c27d6ca63a3309dd79b53e0e940b49891eec2` |
| `harness/fixed/opReadMultiVars.inc` (copy of the pinned fixed slice) | `a4127166e9274f8fbefbda4f0536ad33808bed7135277ad93593ce02c322b233` |

`harness/run.sh` asserts every hash above, rebuilds all binaries, runs the
ladder, and prints a normalized trace hash. Observed 2026-11-23: 43 PASS /
0 FAIL three consecutive times; `TRACE_SHA256=24c8438c85474ab76ade31d8c9d98e1a510f926b4f97cf6ee8948208427eda59`.

## Negative results preserved

- W136 screened Snap7 out for lack of patch bytes; the reopen rests on issue
  #32's proposed guard, not on a new upstream release.
- Only 32 real bytes are present in the crafted response. Beyond that offset
  the copied source is the zeroed PDU buffer, so `DEST64=00`; chosen-byte
  control is demonstrated at offsets 0 and 17, not past the real payload.
- No fake PLC, no socket and no live snap7 client was exercised in this wake.
  The `isoExchangeBuffer()` stub injects the response locally. The real-wire
  experiment is the proposed next step, not an observation.
- An early 8192-byte plain-mode arena aborted with `double free or corruption`
  because the 65535-byte write crossed the allocation; the arena was enlarged
  to 200000 bytes so the scoped byte-observation mode stays in bounds. The ASan
  rung uses a separate one-byte allocation and is unaffected.
