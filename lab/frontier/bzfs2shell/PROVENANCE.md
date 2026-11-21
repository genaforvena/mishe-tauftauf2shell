# Provenance — BZFlag bzfs TCP length overrun (CVE-2026-130849)

Read-only provisioning only. No probe, connection or traffic to any non-loopback
system. Every source below was fetched from its public upstream host and stored
verbatim in `src/`.

## Claim sources

| Source | URL | local file | SHA-256 |
|---|---|---|---|
| OSV/CVE record (JSON) | https://api.osv.dev/v1/vulns/CVE-2026-130849 | — (read via tool) | — |
| VulnCheck advisory | https://www.vulncheck.com/advisories/bzflag-bzfs-before-2.4.32-heap-out-of-bounds-write-via-nethandler-tcpreceive | — (read via tool) | — |
| GHSA advisory | https://github.com/advisories/GHSA-9q5f-g948-c95m | — | — |
| CVE cvelistV5 record | https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/130xxx/CVE-2026-130849.json | — | — |
| v2.4.32 release notes | https://github.com/BZFlag-Dev/bzflag/releases/tag/v2.4.32 | — | — |

Advisory facts: CNA VulnCheck, published 2026-11-17, CWE-122, CVSS 4.0
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` = 9.3 Critical;
affected `< 2.4.32` (all listed 2.x and 1.x releases), fixed in 2.4.32;
credit Landon Rice.

## Pinned source and fix artifacts (verbatim)

| Artifact | URL | local file | SHA-256 |
|---|---|---|---|
| vulnerable `NetHandler.cxx` @ v2.4.30 | https://raw.githubusercontent.com/BZFlag-Dev/bzflag/v2.4.30/src/game/NetHandler.cxx | `src/NetHandler_v2.4.30.cxx` | `19aeebbe615e7d1a8b40b0657542654218c3fa1bcd0e1ce20a2545d287d16617` |
| fixed `NetHandler.cxx` @ v2.4.32 | https://raw.githubusercontent.com/BZFlag-Dev/bzflag/v2.4.32/src/game/NetHandler.cxx | `src/NetHandler_v2.4.32.cxx` | `3abb2fa5e5170eef19c2243309251a45c6159d148f935f5f9330afe4a984d49b` |
| `NetHandler.h` @ v2.4.30 | https://raw.githubusercontent.com/BZFlag-Dev/bzflag/v2.4.30/include/NetHandler.h | `src/NetHandler_v2.4.30.h` | `0951be0fab88b448b8a38a48b78168ebcdb652fec0d9f9b0840671e9972a3b6b` |
| `Protocol.h` @ v2.4.30 | https://raw.githubusercontent.com/BZFlag-Dev/bzflag/v2.4.30/include/Protocol.h | `src/Protocol_v2.4.30.h` | `35df40cab1cea4b1f1db62b64559086219d5d53643060a26465ce6ec5dad98b5` |
| fix patch `8e501d6` | https://github.com/BZFlag-Dev/bzflag/commit/8e501d685aef549090b363260979a4eb93484ea1.patch | `src/fix_8e501d6.patch` | `441efea0348adde9f074af5a3b224c0db9c136a53097f0685996e260d875205a` |

OSV also names fix commit `f11f05485d7406c78159aac00ace3c58b4b17ec2` as the
v2.4.32 tag resolution; the reviewed patch is `8e501d68...`, whose two hunks
are present verbatim in the v2.4.32 source above.

## Harness pins

| Artifact | SHA-256 |
|---|---|
| `tcp_len_overflow.cpp` | `1a16963f64a26b7060a552766485d0de5dfe794d5d3fa57fd763d6289e847a77` |
| `run.sh` | `f2686d5b660dcac17384d739763fc47802806a152e180e3b122c97dfaf6a8e3a` |

Clean replay from committed HEAD: `bash lab/frontier/bzfs2shell/run.sh out`
prints `ALL CHECKS PASS rc 0`, five-run digest
`sha256=cea3b92e3455454ea45ef79232cb49b9e70132134fb8bb6245e5c1ea644ecc89`.
All sockets are in-process `AF_UNIX` socketpairs.

## Source-bound mapping

- `src/Protocol_v2.4.30.h:52-53` — `MaxPacketLen = 1024`.
- `src/NetHandler_v2.4.30.h` — `char tcpmsg[MaxPacketLen]; int tcplen;` adjacent
  input members; `receive(size_t, bool*)` public.
- `src/NetHandler_v2.4.30.cxx:571-623` — `tcpReceive()`: `receive(4)`,
  `len > MaxPacketLen` at 587, `receive(4 + len)` at 594, `tcplen = 0` at 602.
- `src/NetHandler_v2.4.30.cxx:625-669` — `receive()`:
  `recv(fd, tcpmsg + tcplen, length - tcplen, 0)` at 636, `tcplen += size` at 639.
- `src/fix_8e501d6.patch` — hunk 1 changes the bound to `MaxPacketLen - 4`;
  hunk 2 rejects `tcplen < 0`, `tcplen > sizeof(tcpmsg)` and
  `length > sizeof(tcpmsg)` before the `recv`.
- `src/NetHandler_v2.4.32.cxx:590,644` — both hunks present in the fixed tag.

The harness mirrors those lines with a deterministic stand-in prefix for the
opaque `Address`/`std::string` members. It is an extracted, source-bound model,
not a compiled stock `bzfs` process. No live server was started.
