# Provenance — msgpack2shell direct-call harness

## Pins (raw files fetched read-only from GitHub; no probing)

- Advisory release pin: `c-7.0.2` tag,
  `src/vrefbuffer.c` sha256 `9c011c609760beddfce9fb2f65d4ec859db02d116abaac508ed32c2fa64916aa`.
- Vulnerable fix preimage: `8a34070b41827a179e7c4a102f34d8c0a2bd5a77`,
  parent of the fix; `src/vrefbuffer.c` sha256
  `4b03ec0635ac63eaf7a2fb9ae8ff747bc112f916b56c931da92402247001e1c7`.
- Fixed pin: `1c47ce020a019a3d4246e6394176779ecdf9d502`, sha256
  `05f7fefd924f903dc7edecb8cbff7388e2bf1ba27b8fa6964ed68b4e46f96026`.
- Advisory: `GHSA-8pq6-mw7r-9f5g` / `CVE-2026-130065`.
- Fix patch: `https://github.com/msgpack/msgpack-c/commit/1c47ce0...patch`,
  sha256 `493a011370aadead8633fa72f5f1f17be9df2d0b975aaa02f873edd0d0228bd6`.
- Pinned header `vrefbuffer.h.pin` (c-7.0.2) sha256
  `6635d65c5cd6b4d1ac7bacd755e5e7f253dedaa6183081a9d192056577bfb395`.
- All pin hashes are recorded again by each run in `evidence/pin-hashes.txt`.

`c-7.0.2` and `8a34070b` differ only in an unrelated `append_ref` wrap guard;
`msgpack_vrefbuffer_migrate()` is byte-identical in both. `8a34070b` to
`1c47ce0` changes exactly one condition line in that function.

## Extraction and instrumentation boundary

`gen_fn.py` finds the column-zero declaration of `msgpack_vrefbuffer_migrate`,
brace-matches to its closing brace and writes `fns-<pin>.inc`;
`verify_verbatim.py` asserts the slice is an exact substring of the pinned
source. `harness.c` supplies only:

- the pinned struct layouts from `vrefbuffer.h.pin` (`msgpack_iovec` is
  `struct iovec` on Linux, 16 bytes);
- a scripted source buffer of 20 chosen iovecs (`iov_base=0x4141414141414141`,
  `iov_len=0x5a5a5a5a5a5a5a5a`) and a destination buffer with 8 real iovec
  slots;
- `src->end = dst->array`, forcing the buggy cross-object comparison false
  (the advisory's "destination array above the source array" layout). The
  pointer is compared, never dereferenced; the fixed pin never reads it;
- a 512-byte plain-mode destination arena so the 12 iovec entries beyond the
  real 128-byte allocation can be read back without an allocator fault.

No msgpack build, no public `msgpack_vrefbuffer_init`/`append_ref` sequence,
no socket, no consumer. LeakSanitizer is disabled (`ASAN_OPTIONS=detect_leaks=0`)
because the harness intentionally does not free its scripted buffers; the
out-of-bounds detector is unchanged.

## Replay

```
bash lab/frontier/msgpack2shell/harness/run.sh
```

Two rounds, gcc 13.3.0 and clang 18.1.3, three pins, three modes. Expected:
`TOTAL PASS=177 FAIL=0`, `rc=0`, and identical `evidence/r1-normalized.txt`
and `evidence/r2-normalized.txt`. Normalization keeps ASan frames and chosen
bytes while erasing PIDs, addresses, paths and build IDs.

Observed 2026-11-22: both rounds hash
`7edebe0e03a6244e0c659c99763fbf39e3420cd71b0b55e2961e51cb16c9b794`.
