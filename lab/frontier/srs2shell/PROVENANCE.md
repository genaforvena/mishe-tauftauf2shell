# Provenance — srs2shell frontier harness

All external reads were provisioning: GitHub advisory/commit/raw APIs and the
published advisory page. No probe contacted any external system. The harness
uses no socket, daemon, thread, ICE/DTLS/SRTP session or network: it builds
plaintext RTCP datagrams in memory and calls pinned decoder functions.

## Pinned source bytes (fetched 2026-11-21, sha256)

| file | source URL | sha256 |
|---|---|---|
| `pins/advisory.json` | `https://api.github.com/advisories/GHSA-qr8h-p53p-x564` | `5a0d5189bc6cfe5259b36fc73c3d7064c2a154d0a278518996d1b265f14b3281` |
| `pins/commit8.json` | `https://api.github.com/repos/ossrs/srs/commits/ab03c94b0744ab392320253ad1767b21b6c82a59` | `a562c2cbbbc66241a2f48355af82300c1e26d5bba7487c1d00b6c2d0977e07d0` |
| `pins/fix.patch` | `https://github.com/ossrs/srs/commit/ab03c94b0744ab392320253ad1767b21b6c82a59.patch` | `f2c42ce0b276afc98434f0c52896f430a470a61bba7aa8b8bc966f5b0055530e` |
| `pins/rtcp.cpp.vuln` | parent `f7968893cfdefcfa681ed5499c804095daf67469`, `trunk/src/kernel/srs_kernel_rtc_rtcp.cpp` | `1a108163ee650e6ea495bdb04a4e645f317894928931180bc016cafbdf85b942` |
| `pins/rtcp.cpp.fixed` | fix `ab03c94b0744ab392320253ad1767b21b6c82a59`, same path | `6b95dbe792fc1efc6a02f1c416ec890545784d3c92860dddbfc02a8cdf238b31` |
| `pins/buffer.cpp.vuln` | parent, `trunk/src/kernel/srs_kernel_buffer.cpp` | `64cd635d2f6e9d0be85a63898d865d50134913b78c18376f593e7cb384bc6d68` |
| `pins/srs_kernel_rtc_rtcp.hpp` | parent, `trunk/src/kernel/srs_kernel_rtc_rtcp.hpp` | `cf7a415951a785b352184131071f230e32c49550ff58e848bdfb13f7a91f00ba` |
| `pins/srs_kernel_buffer.hpp` | parent, `trunk/src/kernel/srs_kernel_buffer.hpp` | `918f69de0c4047ab5c9c96a0776c349f9754cc9fd18efac084165e415b8874b2` |
| `pins/srs_kernel_error.hpp` | parent, `trunk/src/kernel/srs_kernel_error.hpp` | `645ef6d22a215271daa109eaad6eb0862e7020a84eecf1561410721903a2ffb1` |
| `pins/srs_kernel_error.cpp` | parent, `trunk/src/kernel/srs_kernel_error.cpp` | `66d0b09d4987efdeb4c410af144ec7f7d992ec99211219839f2a81960e89997f` |

`run.sh` rechecks every hash before building. Advisory metadata:
`GHSA-qr8h-p53p-x564`, no CVE assigned at fetch, published
`2026-10-30T14:14:41Z`, severity HIGH, affected `srs >=4.0,<6.0.194`,
`>=7.0,<7.0.214`, `>=8.0,<8.0.73`. Fix commit author date
`2026-10-29T21:18:45Z`, parent `f7968893…`, message
"RTC: Fix crash and heap overflow from a malformed RTCP packet. v8.0.73".
The patch touches five files; only `srs_kernel_rtc_rtcp.cpp` is harnessed.

## Verbatim source ranges

`gen_driver.py` copies these ranges byte-for-byte from the pinned files and
prefaces each with a `#line` directive naming the upstream path, so ASan frames
carry the original line numbers:

- from `srs_kernel_rtc_rtcp.hpp`: `:46-62` (`SrsRtcpHeader` bitfields).
- from `srs_kernel_buffer.cpp`: `:91-98` (`require`), `:242-249`
  (`read_bytes`), `:166-178` (`read_4bytes`).
- parent `srs_kernel_rtc_rtcp.cpp`: `:53-70` (`decode_header`), `:84-98`
  (`SrsRtcpCommon::decode`), `:802-844` (`SrsRtcpTWCC::decode`).
- fixed `srs_kernel_rtc_rtcp.cpp`: `:53-75`, `:89-106`, `:811-856`
  (same three functions).

The fix diff for these functions adds: `length < 1` rejection in
`decode_header`, `length < 2` rejection before each media-SSRC read, and
`payload_len_ > kRtcpPacketSize` rejection before both payload copies.

`srs_assert` semantics were checked on pinned bytes:
`srs_kernel_error.hpp:548` maps it to `SrsCplxError::srs_assert`, whose
`srs_kernel_error.cpp:510-519` calls libc `assert(expression)` — a failed
requirement aborts the process. The harness macro aborts equivalently.

## Harness-owned code (not upstream)

- `driver_pre.cpp`: `srs_error_t` as a formatting string, `srs_error_new` /
  `srs_error_wrap` stubs, `ERROR_RTC_RTCP`, `kRtcpPacketSize`, minimal
  `SrsBuffer` class declaration, `SrsRtcpCommon` / `SrsRtcpTWCC` declarations
  with upstream member names/order, and an aborting `srs_assert` macro.
- `driver_post.cpp`: plaintext datagram construction (BYE `81 cb <length>
  00 00 00 01` + chosen payload; TWCC `8f cd …`), heap / 64 KiB zeroed
  collaborator / guard-page placements of the decoder object, and the mode
  table. The guard mapping puts the object end at a `PROT_NONE` page so the
  first write past the object faults; the collaborator keeps the write inside
  a large zeroed allocation so chosen bytes can be inspected.
- `gen_driver.py`: verbatim-range extractor. `run.sh`: hash gate, builds,
  scenarios, trace and sha256.

## Repairs during construction (kept as evidence)

1. First `run.sh` called `check $? name` with a helper that expected
   `check name rc`; corrected to `rc=$1; name=$2`.
2. `gen_driver.py` named the pinned buffer `srs_kernel_buffer.cpp` but the
   file is `buffer.cpp.vuln`; corrected the mapping and the `#line` names.
3. `offsetof(SrsRtcpCommon, payload_)` cannot be used on a protected member;
   exposed a static `payload_offset()` helper in the harness class.
4. First expected-write arithmetic was 1592 bytes; the pinned formula is
   `(length + 1) * 4 - sizeof(SrsRtcpHeader) - 4` = **1596** for length 400
   (datagram 1604 bytes). All checks were corrected to observed bytes.
5. ASan scenarios lost their pre-decode `printf` fields to stdout buffering;
   `setbuf(stdout, NULL)` makes them survive an abort.

## Result

`./run.sh` builds four binaries and runs eleven scenarios, then writes
`out/trace.txt` and `out/trace.sha256`. Latest: **14 PASS / 0 FAIL**, trace
`sha256=77b6d5500dea19d3c3a8de713d7a37834a3241a62e6a7239d398661e5fea1965`.
Generated drivers, binaries and logs are gitignored.

Rung 1: parent `length=0` computes `payload_len_ = -4`, `read_bytes` aborts
on the pinned `require(size)` assertion; fixed rejects with an error.
Rung 2: the header check only compares `length * 4` with bytes left, so a
1604-byte datagram declaring 1596 payload bytes passes.
Rung 3: parent ASan reports `WRITE of size 1596`, `pinned/srs_kernel_buffer.cpp:246`
(`memcpy`), decode frame `pinned/srs_kernel_rtc_rtcp.cpp:95`, `0 bytes after
1536-byte region`. Both fixed paths (BYE and TWCC) reject before the copy;
benign length 2 is clean.
Rung 4 is **INSTRUMENTED only**: with the object placed in a 64 KiB zeroed
collaborator, chosen `0x5a` (and differentially `0x41`) appears at 96 offsets
starting at the payload-array end (20 bytes of object tail plus 76 past the
object); the benign length-2 control writes none. A guard-mapped object faults
at the first byte past the object (exit 77, `guard_fault=1`); stock plain
malloc was not used to inspect chosen bytes. No pointer, return address,
heap-metadata field, function pointer or control-flow diversion was observed
or attempted.

Boundary: this proves the pinned decoder logic and its local memory effects
in a synthetic C++ frame. WebRTC reachability (ICE/DTLS/SRTP, WHEP/WHIP),
real UDP datagram size, full SRS build, daemon crash and any code execution
stay external/UNKNOWN unless a future wake observes them on a loopback-only
lab build.
