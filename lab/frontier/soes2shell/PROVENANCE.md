# SOES2shell harness provenance

All work is local, inside this lab; no external target was contacted.

## Pins

Fetched 2026-11-22 00:16Z from GitHub tags API and codeload:

- `https://codeload.github.com/rt-labs/soes/tar.gz/refs/tags/v3.2.0`
  → `src/soes-v3.2.0.tar.gz`, SHA256 `24c0cb2f8ac366ebfc9de820d05ccfd8b8575479b7269d127a7deb833db2177c`
  (tag commit `6261dbb2d06dc9687389a9e11050c2a6e8d83295`, affected).
- `https://codeload.github.com/rt-labs/soes/tar.gz/refs/tags/v3.2.1`
  → `src/soes-v3.2.1.tar.gz`, SHA256 `301d9f1918142e15ea7133c5bbed2979ee9c23d0ebf838ee4c9143068c7c3621`
  (tag commit `28459b2cb65853fcb67985c83d3e3540a18cdf4a`, fixed).
- `https://github.com/rt-labs/soes/compare/v3.2.0...v3.2.1.diff`
  → `src/fix-v3.2.0-v3.2.1.diff`, SHA256
  `f54bdd7c1170911a9c0eb60dfbd54421233213009a8bb79dda74ffadfd1fdc86`.

`src/SHA256SUMS` is the authoritative pin record; recheck with
`cd src && sha256sum -c SHA256SUMS`.

Primary advisory: <https://docs.rt-labs.com/security/advisories/rrtl-261119-01.html>
(RRTL-261119-01, 2026-11-19) and its CSAF JSON.

## Replay

From the repository root:

```
cd src && sha256sum -c SHA256SUMS && cd ..
./harness/build.sh
./build/eoe_asan_3.2.0 7     # ASan heap-buffer-overflow, write size 96 at esc_eoe.c:797
./build/eoe_asan_3.2.1 7     # clean
./build/eoe_asan_3.2.0 6     # clean, recv_calls=1 last_len=576
./build/eoe_plain_3.2.0 7 canary   # 64 chosen bytes at adjacent heap object +608
./build/eoe_plain_3.2.0 6 canary   # canary_changed=0
./build/eoe_plain_3.2.1 7 canary   # no callback
./build/eoe_plain_3.2.0 7 pool       # pool_next == runtime-chosen marker address
./build/eoe_plain_3.2.0 6 pool       # pool_next unchanged
./build/eoe_plain_3.2.1 7 pool       # no callback
```
The committed canary evidence is from 00:20Z; pool evidence from 00:24Z.
The first argument is the fragment count; `canary` enables the adjacent
heap object used for the plain-build chosen-byte observation; `pool` uses
two contiguous stand-in pbuf objects whose second object's `next` field
receives bytes 16–23 of the last fragment. Seven fragments with a 592-byte
receive buffer are the overflow case; six are the safe-length control. The
pool layout is synthetic, not upstream lwIP, and the marker address is
computed by the harness; no pointer is dereferenced.

## Harness scope

`harness/eoe_overflow.c` links only the pinned `soes/esc_eoe.c` and defines
its four externals itself: `ESCvar`, `MBX`, `MBXcontrol`, `ESC_claimbuffer`.
EoE callbacks are supplied by the harness. Mailbox header fields are
host-order on this little-endian build (SOES `cc.h`: `etohs` = identity);
do not apply `htons()` — that mistake caused an initial false negative.
The harness is not a live EtherCAT slave and does not use an ESC HAL, so
wire reach is UNKNOWN. No rung 5 path is claimed.
