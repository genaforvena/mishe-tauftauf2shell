# socat2shell — pin provenance and harness scope

## Provisioning (read-only, no external probing)

```
curl -fsSL -o src/socat-1.8.1.1.tar.gz http://www.dest-unreach.org/socat/download/socat-1.8.1.1.tar.gz
curl -fsSL -o src/socat-1.8.1.2.patch.gz http://www.dest-unreach.org/socat/download/socat-1.8.1.2.patch
gunzip src/socat-1.8.1.2.patch.gz       # served gzip-encoded, original 4455 bytes
curl -fsSL -o src/advisory.html http://www.dest-unreach.org/socat/contrib/socat-secadv10.html
tar xzf src/socat-1.8.1.1.tar.gz -C src/tree socat-1.8.1.1/xio-socks5.c socat-1.8.1.1/xio-socks5.h
```

Every byte is SHA-256 pinned in `src/pins.sha256`; `harness/run-all.sh`
re-extracts from the tarball and re-checks the pins on every run.

## Pin construction

- `src/xio-socks5.inc` = verbatim `xio-socks5.c` lines 414-499 (the complete
  `_xioopen_socks5_read_reply()` body), 86 lines, no edits.
- `src/xio-socks5.h.vuln` = verbatim 1.8.1.1 `xio-socks5.h`.
- `src/xio-socks5.h.fixed` = the same header with the two `char dstdata[]`
  members changed to `unsigned char dstdata[]`, exactly as in the official
  1.8.1.2 patch; the only hunk is shown by
  `diff -u src/xio-socks5.h.vuln src/xio-socks5.h.fixed`.
- `harness/xio-socks5.inc` and `harness/xio-socks5.h` are copies made by
  `run-all.sh` from the pinned blobs immediately before compiling.

## Harness scope

`harness/harness.c` compiles the pinned function against either header and
stands in only the socat infrastructure the function calls: `struct single`,
`SOCKS5_*` constants, `STAT_OK`/`STAT_RETRYLATER`, no-op logging macros,
`Close()`, and a `readfull()` that copies at most the bytes the malicious proxy
actually sent, consuming them as a socket would. A negative count reaches that
function as an implicitly converted `size_t`, exactly as in the pinned source.

The attacker reply is `05 00 00 03 fb` plus 600 server bytes; "MISHE-SOCKS" is
placed at reply offset 262. The ASan variants allocate exactly
`SOCKS5_MAX_REPLY_SIZE` (262) bytes, matching the real caller at
`xio-socks5.c:551`. The plain variants allocate an extra 512-byte canary region
so the chosen bytes can be read back without an ASan report. `safe` uses an
IPv4 reply; `fixed` uses the official patched header.

Build note: with glibc fortify at default `-O1`, an inlined `memcpy` triggers
`*** buffer overflow detected ***` before ASan can report. `run-all.sh` sets
`-D_FORTIFY_SOURCE=0 -U_FORTIFY_SOURCE` and marks the `readfull()` stand-in
`noinline`; this is a harness build condition, not a claim about a shipped
socat binary. Neither a real socat build nor a loopback wire replay was done
in this wake.

## Controls observed 2026-11-25

`sh harness/run-all.sh`: 15 PASS / 0 FAIL. gcc and clang ASan report
`heap-buffer-overflow`, `WRITE of size 600`, 0 bytes after the 262-byte region,
through `readfull` at `harness.c:42` and `_xioopen_socks5_read_reply` at
`xio-socks5.inc:12`. Safe reply and fixed header are ASan-clean with rc 0 in
both compilers. Plain vulnerable build reads back
`canary=4d495348452d534f434b53`; plain fixed build reads back zeros.
