# Provenance — mongoose2shell harness (W138, 2026-11-23)

## Pinned inputs

All three inputs were provisioned in W137 and re-verified on every run by
`harness/SHA256SUMS`:

| file | sha256 | origin |
| --- | --- | --- |
| `src/l2_ppp.c.8bb65c64926d` | `58512f9c05ab6aebdf106543a5bb917feae5c08a63fc08884beb173c30b6b333` | parent of upstream fix `751f1474` |
| `src/l2_ppp.c.751f14742dea` | `5b115c5d496ea6084bd52783dfe9f9700e833b25465fd38d60a847f2f7d76f4d` | upstream fix commit blob |
| `src/fix-751f1474.patch` | `51befba0de5448f5c247e7b63af1451e4b4811c5d73b5c705e7b0cc6caa5da90` | `git show 751f14742dea` |

## Verbatim slices re-extracted per run by `harness/run.sh`

| slice | vulnerable blob lines | fixed blob lines |
| --- | --- | --- |
| `ppp_structs.inc` | 10-89 | 10-89 |
| `ppp_tx_frame.inc` | 231-236 | 231-236 |
| `find_opt.inc` | 277-290 | 278-291 |
| `ppp_handle_ipv6cp.inc` | 350-416 | 351-418 |

Each slice begins with a `#line` directive naming the pinned blob. SHA-256 of
all 12 pinned and generated files is asserted before any binary is built.
A `#pragma pack(push,1)` pair is inside the extracted struct slice itself;
the driver adds only the host scaffolding (`struct mg_tcpip_if`,
`struct mg_l2addr`, byte-order helpers, log macros, and the two recording
helpers standing in for `ppp_tx_frame_header()` / `ppp_tx_frame_trailer()`).

## Harness inputs and stubs

- `rx`: heap allocation 65540 bytes for plain/safe/asan-write, 14 bytes for
  asan-read. The **declared received length** passed to `ppp_handle_ipv6cp()`
  is 2048 (plain, asan-write) or 14 (safe, asan-read); the allocation is larger
  so the sanitizer WRITE report isolates the destination overflow.
- `tx`: heap allocation 1088 bytes (1024-byte `tx.buf` plus 64-byte canary) for
  ASan modes, 70000 bytes for the plain mode so the 65535-byte copy stays in
  one valid allocation and the overwritten canary can be read safely.
- Chosen bytes: `rx[1020]=0x5a` and `rx[1037]=0x3c` map to canary offsets 0 and
  17 because `pay = tx.buf + 4`.
- Log macros intentionally discard format arguments; no Mongoose logging code
  is executed.

## Observations

- `./run.sh`: 43 PASS / 0 FAIL, three consecutive runs, identical
  `TRACE_SHA256=8c5d62a55be40595f76d3479f05a9ab4652585f07ebae13cd35017d64e3d1cb7`.
- gcc + clang ASan READ at pinned vulnerable line 281 in `find_opt()`;
  gcc + clang ASan WRITE at pinned vulnerable line 234 in `ppp_tx_frame()`.
- Fixed blob: guard `if (len < sizeof(*ipv6cp) || len > ipv6cpsz) return;`
  present once, `TX_CALLS=0`, canary intact, ASan-clean.
- Safe 14-byte frame: normal two-transmit path, canary intact, ASan-clean.

## Ceiling / negatives

No real PPP or PPPoE link, no socket, no listener, no live `mg_tcpip_if`, no
LCP exchange, no framing or CRC path, no pointer control, no command execution.
The `tx.buf` size (1024) is a harness choice, not a measured Mongoose
configuration; the real bound is `ifp->framesize` (~1506). The chosen bytes are
frame bytes copied by `memcpy`, not attacker-controlled addresses. No rung 5.
