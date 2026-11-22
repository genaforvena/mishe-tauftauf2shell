# Provenance — ytnef2shell direct-call harness

## Pins (raw files fetched read-only from GitHub; no probing)

- Vulnerable tag `v2.1.2` = `d9f089144414d3b0912c29ab96f8f1c591d00319`,
  `lib/ytnef.c` saved as `../src/ytnef-2.1.2.c`, sha256
  `f5a74173a560860fa1e19ef2e4e1ac92f0ce4d5a8048ef021f8b1e14291c01e6`.
- Fixed tag `v2.1.3` = `f0ccad7dc2ad0d1c8c3f8676eff4d084eb97d6a3`,
  `lib/ytnef.c` saved as `../src/ytnef-2.1.3.c`, sha256
  `ab757d4067f7c5f70b8e5b322d33b47d35a820d767947d11c5af05a13f5b6363`.
- Fix diff `v2.1.2..v2.1.3` limited to `lib/ytnef.c` saved as
  `../src/fix-2.1.3.patch`, sha256
  `e158ff7beee0d9585214e785155d48a2cd6af9f1e04d1eb709b7effed5db84d8`.
- Advisory: `GHSA-jhg4-xcxm-cfg6`, published 2026-11-20, affected
  `<= 2.1.2`, patched `2.1.3`, no CVE assigned at publication. The advisory
  also names master `5b24cfc` as vulnerable; that pin was not fetched or run.
- All three hashes are re-recorded on every run in `evidence/pin-hashes.txt`.

## Extraction and instrumentation boundary

`gen_fn.py` locates the column-zero `#define RTF_PREBUF` line and the
`DWORD SwapDWord(` / `BYTE *DecompressRTF(` declarations, brace-matches each
function to its closing brace, and writes `fns-<pin>.inc`. `verify_verbatim.py`
asserts each emitted slice is an exact substring of the pinned source on every
run before compilation; a wrong slice aborts the run.

`harness.c` supplies only:

- the public typedefs from pinned `lib/tnef-types.h` (`BYTE`, `WORD`, `DWORD`,
  `ULONG` all unsigned, `ULONG`/`DWORD` are 32-bit) and the pinned
  `ALLOCCHECK_CHAR` macro;
- a packet builder that writes the four 32-bit stream header fields in host
  (little-endian) order, matching the pinned `SwapDWord` on this host;
- for plain mode only, renamed `calloc`/`free` backed by a static 8192-byte
  arena: each slot is 16-byte aligned, prefilled with `0xEE`, and only its
  requested length zeroed, so bytes past a conceptual allocation stay visible;
- a driver that selects the case, calls the verbatim function, and reads back
  the arena.

No TNEF file, email, ytnef build, libytnef consumer, linker symbol from the
library, socket or wire input is used. Advisory reachability claims were read,
not exercised.

## Input cases

| case | magic | `uncompressedSize` | input size | expected sink |
| --- | --- | --- | --- | --- |
| `write` | LZFu | `0xFFFFFF41` | 20 | `calloc(16)`, 207-byte prebuffer memcpy over 16-byte allocation (191 OOB) |
| `write0` | LZFu | `0xFFFFFF31` | 20 | `calloc(0)` → 1-byte ASan region, 207-byte prebuffer memcpy (206 OOB) |
| `write1` | LZFu | `0xFFFFFFFF` | 20 | `calloc(206)`, 207-byte prebuffer memcpy (1 OOB) |
| `mela` | MELA | `64` | 20 | `memcpy(dst, src+4, 64)` reads 44 bytes past 20-byte input |
| `safe` | LZFu | `8` | 25 | one flags byte + 8 literals, no overflow |

The overflow is the pinned `calloc(comp_Prebuf.size + uncompressedSize, 1)`
with 32-bit wrap (prebuffer length is 207). The vulnerable guard
`comp_Prebuf.size >= INT_MAX - uncompressedSize` is unsigned, so
`INT_MAX - 0xFFFFFF41` wraps to `0x800000BE` and the check passes. The fixed
guard `uncompressedSize >= INT_MAX - prebufSize` rejects all four attack
inputs before any allocation.

## Assertion set (240 per run)

Two rounds x two compilers (gcc, clang) x two pins x five ASan cases and four
plain-arena cases. ASan on the vulnerable pin requires `heap-buffer-overflow`,
the exact `WRITE of size 207` / `READ of size 64`, the exact region size
(16, 1, 206 or 20 bytes), `0 bytes after`, a `DecompressRTF` frame and the
unbuffered `PRECALL` line with decimal input values. ASan on the fixed pin
requires rc 0, no report, and `Corrupted file` for the four attack cases. Both
pins require a clean safe stream. Plain mode on the vulnerable pin requires
`CHOSEN_BAD=0`, the exact allocation/overrun lengths, and the fixed RTF
prebuffer bytes at those offsets with the `0xEE` sentinel intact past them;
the fixed pin requires `ALLOC=none` and no write. Normalized evidence strips
PIDs, addresses, paths and whitespace only.

Two consecutive runs were 240 PASS / 0 FAIL with identical normalized content
hash `a2819d82cc5fdf23c88ee65fc4d8eb08a48fe01be80afa092fdf37ac43bce639`
over 72 evidence logs.
