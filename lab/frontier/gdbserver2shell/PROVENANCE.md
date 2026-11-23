# Provenance — gdbserver `cmd_qtdpsrc()` (CVE-2026-121997)

## Provisioning

Read-only fetches on 2026-11-23, no probe of any external system. All runtime
work is local, direct-call, loopback-free; no gdbserver process was started.

- Claim: `https://api.github.com/advisories/GHSA-jq36-9pw3-8r4v` and
  `https://cveawg.mitre.org/api/cve/CVE-2026-121997` (Red Hat, HIGH 8.1,
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-122).
- Mechanism and claimed exploit chain: Red Hat Bugzilla #2565679 XML,
  `https://bugzilla.redhat.com/show_bug.cgi?ctype=xml&id=2565679`.
- Upstream tracker: Sourceware bug 34968 (XML read).
- Fix: Andrew Burgess, `[PATCH 2/5] gdbserver: prevent buffer overrun for
  QTDPsrc packet`, 2026-11-16,
  `https://sourceware.org/pipermail/gdb-patches/2026-November/231917.html`;
  review follow-up `.../232038.html`. The fix requires
  `slen == strlen(BYTES)/2` and even nibble count, then allocates and decodes
  by the actual packet length.
- Vulnerable pin: `binutils-gdb` HEAD
  `633ae02c4ea8f87c670f7192804349860cfa291d` (from `git ls-remote`, fetched
  2026-11-23). `gdbserver/tracepoint.cc:2546` still reads
  `xmalloc (slen + 1)` — the fix is posted but not merged at this pin.
- Fixed snapshot is the pinned file with the upstream check applied by
  `src/fix-head-633ae02.patch`. The posted patch hunk is against a slightly
  older revision; the saved patch adapts the same change to the pinned HEAD
  bytes. It is not a vendor release.

## Saved pinned bytes (SHA-256)

```
942306a5b1f96693a64d18819973e7e306faa1481f373615487a5fd2b4df4e2e  src/tracepoint-633ae02.cc
c3aa8ac26253ff3fa79d6dd9caa13ae09c5c6471cf3499b22fa5b0926af95f17  src/tracepoint-fixed.cc
5b8bc3cb235eb2ced96da42b15c66ec7f2510deace6f5a943b7e567e8a67d43f  src/fix-head-633ae02.patch
641d72c6c756fbc528adaa837c05d987656a4bea9df630d15a46823050ca6692  src/rsp-low-633ae02.cc
872d8e7dfbcc9e0349026b8daa1e77abec6aef875960eb3a4d051e0fc6d24a79  harness/driver.c
99780c047e65cb687800e27b50525e8dd6202bfefecca13f954fae8b1aca6145  vulnerable cmd_qtdpsrc() slice
ec699708715aad2ac60a6316f2fc5beb128544280c6d6e50847ab451f3294f87  fixed cmd_qtdpsrc() slice
b0bcd1a7a1bb77939a92547b01d78dc88e9a4d4a902af3ac63aebb2244a6e5d0  ishex + unpack_varlen_hex slices
```

`run.sh` asserts all eight hashes on every run. Slices are re-extracted from
the saved pinned files with an `awk` range that includes the exact return-type
line; the function bodies are never retyped or patched.

## Toolchain and result

g++ 13.3.0 and clang++ 18.1.3, `-g -O0 -fno-omit-frame-pointer
-fsanitize=address` for ASan variants; the plain canary variant is built
without ASan. **60 PASS / 0 FAIL** on three consecutive runs and one clean
`/tmp` replay, path-independent normalized content hash
`0c9b837e5300ac744b133e6668179cda410520177d87b859c99cac9af1c1db73`.

## Instrumentation boundary

- No gdb build, no RSP server, no socket, no daemon, no network.
- One direct call to the verbatim pinned `cmd_qtdpsrc(own_buf)` with a
  constructed RSP packet `QTDPsrc:1:0:cond:0:1:<hex>`: declared `SLEN=1`
  (2-byte allocation), actual decoded payload `N` bytes chosen from the
  repeating pattern `0x41 + (i & 0x1f)`. `N` = 8, 32, 64, 128.
- **Decoder boundary:** `hex2bin` is a faithful fixed-count two-nibble-per-byte
  decoder written in the driver, not a verbatim GDB slice. All allocation and
  length decisions come from the verbatim `cmd_qtdpsrc()` slice; the decoder
  never varies between vulnerable, fixed and safe cases.
- `unpack_varlen_hex` and `ishex` are verbatim pinned slices; GDB's RSP numbers
  are hex, so the driver emits `SLEN` in hex (`1` for the attack, `0x10` for
  the 16-byte safe packet).
- ASan: `heap-buffer-overflow`, `WRITE of size 1`, `0 bytes after 2-byte
  region [.., ..+2)`, frames `hex2bin` -> `cmd_qtdpsrc`, on both compilers and
  all four lengths.
- Plain canary: a 64 KiB `0xEE` arena backs `xmalloc`; with `N=32/64` the
  bytes at decoded offsets `2 .. N-1` are exactly the chosen pattern
  (`WRITTEN=N-2 FIRST=2 LAST=N-1 PATTERN_OK=1`, twice per length).
- Fixed snapshot on the same attack: `RC=0 REPLY=E01 LIST_LEN=0`, no ASan
  report. Safe packet with `SLEN` equal to the decoded length: `RC=0
  REPLY=OK LIST_LEN=1` on both pins, no ASan report.
- **Not established:** no real gdbserver packet loop, no natural heap layout,
  no adjacent object identity, no `process_info_private::thread_db` pointer,
  no `qGetTLSAddr`, no marker, no command, no rung 5. The reported RIP-control
  chain from RHBZ#2565679 is a claim, not reproduced here.
