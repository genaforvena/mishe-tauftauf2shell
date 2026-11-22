# Provenance — libyang2shell direct-call harness

## Pins (raw files fetched read-only from GitHub, no probing)

- Vulnerable: `979f6925cf1f0918915613022e9e9dfc751bf647`, parent of the
  2026-04-07 fix `73da1db8fc14802e4f8fc64d022011a6f9d514db`.
- Partial fix: `73da1db8fc14802e4f8fc64d022011a6f9d514db` (64-bit casts only).
- Hardened fix: `48672b289e2e4c6773712c3ee0abae6b7fffe1f3` (explicit
  `str_len == UINT32_MAX` rejection, PR #2513).
- `src/parser_lyb-<pin>.c` is the verbatim pinned file for each pin.
  `src/in.c.pin` is the verbatim `979f6925` `src/in.c`; its `ly_in_read()`
  body is unchanged across the three pins.
- Advisory: `GHSA-vw2p-pq79-92xh` / `CVE-2026-44673`, 2026-04-07.
- Fix patches: `https://github.com/CESNET/libyang/commit/<pin>.patch`.
- File hashes: `evidence/r1-pin-hashes.txt` (identical to r2).

## Extraction and instrumentation boundary

`gen_fn.py` locates each function at column zero, includes its verbatim
declaration line, brace-matches to the closing brace and writes `fns-*.inc`.
`verify_verbatim.py` asserts each generated slice is an exact substring of the
corresponding pinned source. `harness.c` supplies only:

- types/macros (`LY_ERR`, `struct ly_in`, `struct lylyb_parse_ctx`, `LOG*`,
  `LYPLG_BITS2BYTES`, `LY_CHECK_*`);
- a scripted four-byte little-endian length plus 16 chosen data bytes;
- `instrumented_memcpy`, which records the requested count and copies at most
  16 bytes. The real `ly_in_read()` calls this sink, so the count
  (536,870,911 for `str_len=0xFFFFFFFF`) is the pinned value while the copy is
  deliberately bounded;
- `ALLOC_MODE_ASAN`: real `malloc` (with a size log) under AddressSanitizer;
  `ALLOC_MODE_PLAIN`: a 4 GiB + 2 page `PROT_NONE` mapping with two writable
  pages, so the offset-`0xFFFFFFFF` terminator write can be read back without
  allocating 4 GiB.

No library build, no sockets, no loopback server, no external target contact
at run time. ASan sees the offset-0 write before the terminator is reached;
the plain mode observes both writes.

## Replay

```
bash lab/frontier/libyang2shell/harness/run.sh
```

Two rounds, gcc and clang, three pins, two allocation modes, safe control.
Expected: `TOTAL PASS=42 FAIL=0`, `rc=0`, and identical `evidence/r1-normalized.txt`
and `evidence/r2-normalized.txt`. Normalization removes PIDs, addresses and
paths; it retains requested counts, chosen-byte readbacks and ASan frames.

Observed 2026-11-22: both rounds hash
`edf0399fb7c5e5aef309e460d60286394a324d149cf600305c9f6bfffdda51f2f2`.
