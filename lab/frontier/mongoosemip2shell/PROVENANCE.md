# mongoosemip2shell — provisioning provenance

All fetches were read-only public provisioning. No probe, scan or connection to
any external system was made by the harness; frames are crafted in-process and
fed to Mongoose's mock L2 driver.

## Advisory and tags

- GHSA-4mgp-8m9m-q872 / ZDI-CAN-29386, published 2026-11-20:
  https://github.com/cesanta/mongoose/security/advisories/GHSA-4mgp-8m9m-q872
  Affected `<= 7.23`, patched `7.24`. Advisory says "No known CVE". CVSS 9.8
  (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) is the ZDI claim, not a local result.
- `git ls-remote --tags https://github.com/cesanta/mongoose.git 7.23 7.24`
  returned `7.23 = 02bdbb9ed6f0a8f7c42228c6e7cb35d748b60551` and
  `7.24 = 66e877cd973881bca92809a4cf5563cdb7a0fe5e`. A scout note claiming
  7.24 pointed at `91b87a6b…` is WRONG; the tag is authoritative here.
- Fix commit `9c6b4edd37869816b186e16e7a6616229c49f9fc`
  ("handle ACK in FIN, fix ACK to FIN + payload"), raw patch:
  https://github.com/cesanta/mongoose/commit/9c6b4edd37869816b186e16e7a6616229c49f9fc.patch

## SHA-256 pins (verified 2026-11-26)

| artifact | SHA-256 |
| --- | --- |
| `src/mongoose-7.23.tar.gz` (`codeload.github.com/cesanta/mongoose/tar.gz/refs/tags/7.23`) | `93208f164038b05d156935b8b725063e1afb3984a362dbcf3a9ea37b6f1f2255` |
| `src/mongoose-7.24.tar.gz` (`codeload.github.com/cesanta/mongoose/tar.gz/refs/tags/7.24`) | `0b21cc2ac2a094600d58f2bd20d42aa21ce88375adefc32af481fe89997285fb` |
| `src/fix-9c6b4edd.patch` (raw GitHub commit patch) | `70d3b17e9a3d429c7c5c3dcbbc22c54401e9181d2518c8a453901c91c862f822` |
| `poc.c` (local harness) | `50ebb930ac9fc2c84286bfa350243f243495aa1a0e38759b6a856219cfd1a6d9` |
| `src/zdi-poc.try` (advisory's PoC link; HTML login page, NOT a PoC) | `b0928e05b029b38080fc323a080b515392cec1391baac0c1ced472973de59b33` |

The advisory's linked ZDI PoC
(https://trendmicro-my.sharepoint.com/:u:/p/mai_mostafa/IQAO-WYScxG-S46JYPU2GMJyAW9nBb18ZLXQfGat-D6QJhs?e=yAderU)
returns a 144 KiB SharePoint HTML document, not C source. `poc.c` was written
locally from the advisory's algorithm and upstream `test/mip_test.c`; it uses
the same mock-L2 frame injection, full TCP handshake, 400-byte data segment and
FIN carrying 400 bytes.

## Pinned source facts

- 7.23 `src/net_builtin.c:1461` `read_conn()`; FIN branch falls through;
  `:1527` `memcpy(&io->buf[io->len], pkt->pay.buf, pkt->pay.len)`.
- 7.24 `src/net_builtin.c:1588` `read_conn()`; resize check at `:1647-1651`
  is outside the if/else-if chain; `:1679` is the same memcpy.
- The raw fix patch removes `if (pkt->pay.len == 0) return;` from the FIN
  branch and moves the `mg_iobuf_resize()` check after all early returns.
- Aggregate `mongoose.c` line numbers seen in ASan traces are compiler
  artifacts of `#include`-ing sources; pin the split-source line numbers above.

## Negatives and dead ends preserved

- `mongoose.c` sits at the tarball root, not `src/`; first compile with
  `-Isrc/mongoose-7.23/src` failed with `mongoose.c: No such file or directory`.
- Upstream `if_poll` gates link-up on the 1 s timer; with `mg_mgr_poll(mgr, 0)`
  the SYN was never answered (`HANDSHAKE_FAIL flags=2 spins=1001`). Harness
  driver reports link-up unconditionally.
- First crafted frames omitted the IPv4 header checksum; `rx_ip()` dropped
  them silently. `send_seg()` now calls `ipcsum()` before copying the header.
- First application callback treated `MG_EV_READ` data as `struct mg_str *`;
  7.23 passes a byte count, producing ASan `negative-size-param` in `memmove`
  at `poc.c:86`. The final callback is a no-op that leaves 400 bytes in the
  receive buffer, which is the state required for the overflow.
- Verbose logging and `IFRX`/`IFTX` prints were diagnosis scaffolding and are
  removed from the final `poc.c`; their output survives in `evidence/diag*.out`
  and is labeled as intermediate, not runner output. The runner's final traces
  are `evidence/7.{23,24}-{gcc,clang}-asan-{attack,safe}.out`.
- Advisory "no CVE" is kept as UNKNOWN rather than inventing an ID. No
  rung-5 claim: the harness drives crafted frames into an in-process stack,
  not a live network-facing process on loopback.
