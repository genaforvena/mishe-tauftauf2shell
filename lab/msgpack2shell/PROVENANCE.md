# Provenance — msgpack2shell real public-API harness

Complements `lab/frontier/msgpack2shell/` (verbatim-function direct-call
harness). This tree drives the **real msgpack-c C library build** through the
public `msgpack_vrefbuffer_init` / `append_ref` / `clear` / `migrate` API. No
struct field is written by the harness; only `cap`/`used` are read back from
the public struct for diagnostics.

## Pins (fetched read-only from GitHub; no probing)

- Vulnerable release tag `c-7.0.2`, `src/vrefbuffer.c` sha256
  `9c011c609760beddfce9fb2f65d4ec859db02d116abaac508ed32c2fa64916aa`;
  tarball sha256 `f720af974b72cda874c2c347d4bafef5385c4e7942a27b3c87d6fa482412d08c`.
- Fixed commit `1c47ce020a019a3d4246e6394176779ecdf9d502`, same file sha256
  `05f7fefd924f903dc7edecb8cbff7388e2bf1ba27b8fa6964ed68b4e46f96026`;
  tarball sha256 `0f1cebbd7e5a0edf99ba5d1ae80c3ed9c573038094aa8c75bda8b3e0a935f353`.
- Pinned header `include/msgpack/vrefbuffer.h` sha256
  `6635d65c5cd6b4d1ac7bacd755e5e7f253dedaa6183081a9d192056577bfb395`
  (byte-identical to `lab/frontier/msgpack2shell/src/vrefbuffer.h.pin`).
- `include/msgpack/zone.h` copied from the `c-7.0.2` pin (sha256
  `aeef52c64f38e9914658282581833012b43e8835772fea35749d51cd917a8f92`).
- `include/sysdep.h` is the minimal cmake-generated stand-in for the release
  tarball's missing `cmake/sysdep.h.in` output: stdlib/stddef/stdint/stdbool
  includes, empty `MSGPACK_DLLEXPORT`, `MSGPACK_ENDIAN_LITTLE_BYTE 1`. It
  contains no project logic and is not one of the pins.
- All pin hashes are rewritten to `evidence/pin-hashes.txt` by each run.

## Reproducers (public API sequences, from upstream issue #1197)

`api_repro.c` argv is the number of `append_ref` calls into A between the two
migrates:

- `4` — upstream two-migrate variant. init A and B (both cap 4 on this host);
  five refs into A (A grows to cap 8, used 5); migrate A→B (B grows to cap 8,
  used 5, A reset to used 0); four refs into A (used 4); migrate A→B. The
  cross-object check `to->tail + nused < vbuf->end` compares `B.array+9`
  against `A.array+8`, evaluates false on this natural layout, skips growth,
  and `memcpy`s 4 iovecs (64 bytes) starting at `B.array+5` — one slot past the
  8-slot allocation.
- `2` — equal-capacity safe control: same sequence, B ends at used 7 of cap 8.

`canary_poc.c` is the upstream single-migrate plain-glibc PoC verbatim in
substance: 20 refs into A, 5 refs into B, `clear(B)`, a 256-byte `0xAA`
canary, then migrate A→B (320-byte copy into a 136-byte usable allocation).

## Replay

```
bash lab/msgpack2shell/run.sh
```

gcc 13.3.0 + clang 18.1.3, two pins, ASan and plain modes. Expected:
`TOTAL PASS=74 FAIL=0`, `rc=0`, summary hash
`b8c96187de5cbf66bc53cc1b350d977eab95e5cda5351875c992136880bca022`.
Per-case stdout/stderr is in `evidence/`; `evidence/summary.txt` holds the
allocator-independent facts and is what is hashed. ASan addresses, PIDs and
BuildIDs are never hashed.

Observed 2026-11-22: vulnerable pin faults under both compilers (ASan
`WRITE of size 64`, `0 bytes after 128-byte region`, frame
`msgpack_vrefbuffer_migrate vrefbuffer.c:222`; plain glibc `free(): invalid
size`); fixed pin grows to cap 16 and stays in bounds; both safe controls and
the fixed canary are clean.
