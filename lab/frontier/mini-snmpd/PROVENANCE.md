# Provenance — CVE-2026-59961 / GHSA-c9g2-5ghh-8g8c (mini-snmpd)

Read-only public provisioning on 2026-11-23 ~02:09–02:20Z; all runtime tests
are on plant-started loopback processes or local direct-call binaries. No
external probe, no scan, no bulk/target-list mode.

## Records

- MITRE CVE JSON `https://cveawg.mitre.org/api/cve/CVE-2026-59961`
  (CNA GitHub_M; reserved 2026-07-07, published 2026-11-18T21:15:50Z,
  updated 2026-11-19; HIGH 8.2 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H`;
  CWE-125 via size_t underflow; affected `< 1.7`; CISA SSVC marks `poc`).
- Maintainer GHSA `https://github.com/troglobit/mini-snmpd/security/advisories/GHSA-c9g2-5ghh-8g8c`
  (displayed published date **Jul 10, 2026**; the CVE record's Nov 18 date is
  the new public event. Both dates recorded, neither substituted).
- Fix commit `https://github.com/troglobit/mini-snmpd/commit/5419bc3816a09b7a2ca38c47f0888ad01c8fe897`
  ("Align underflow checks across decode helpers", 2026-06-21); its parent is
  `b532243732609cf7af58ceb1794a0adfe8deeff1`. Release v1.7 is tagged at
  `6894e33e70113f33398fbc0ce0d538db6246759b`.
- Fix patch `https://github.com/troglobit/mini-snmpd/commit/5419bc38....patch`
  (4 insertions / 4 deletions: `len > size ||` added to decode_str,
  decode_oid, decode_ptr and `decode_ptr`'s `int len` made `size_t`).

## Pinned bytes (SHA-256, re-asserted on every harness run)

| File | Commit | SHA-256 |
| --- | --- | --- |
| `src/protocol.c.b5322437` | `b5322437` (fix parent, vulnerable) | `4bd06467a3ac5b1b731567dba0145380acbe0106836fbdbe591be38175b10e42` |
| `src/protocol.c.5419bc38` | `5419bc38` (fix) | `eeb05d95f46430d6e199956666b9281540c378076f85430e56bcb7f74a424cb2` |
| `src/protocol.c.6894e33e` | `6894e33e` (v1.7 release spot check; already fixed) | `b36aed4ae103c576cf808abdcfd0a7eb81be2ad96bf13d26e143e2a38e0c811b` |
| `src/mini-snmpd.h.b5322437` | `b5322437` | `476c9795bb3c6942adf78b048cdad47301da562af9ffdb067adabaedf107c380` |
| `src/fix-5419bc38.patch` | commit patch endpoint | `fac30b06080c4fef9a3e0b0d9d7fa6c8325d26e4578808ad01c8fe897` |

Raw source URL form:
`https://raw.githubusercontent.com/troglobit/mini-snmpd/<sha>/protocol.c`.
The diff between the two pinned `protocol.c` files is exactly the fix patch.

## Verbatim slices re-extracted every run

`harness/run.sh` cuts these line ranges and includes them with `#line` into
the driver; each generated slice hash is asserted:

| Slice | Vulnerable / fixed lines | Vulnerable SHA | Fixed SHA |
| --- | --- | --- | --- |
| `decode_oid` | 190–256 | `4c2653ab…ce16c80b` | `42bf0b13…2f96bdfa51` |
| `decode_str` | 175–187 | `bce2dad1…2b6a9` | `8baf0b2e…dab86` |

Call-path facts read from the pinned vulnerable file, not inferred from the
advisory: `decode_len()` (`:58–133`) accepts two-byte BER lengths up to
0xFFFF; `decode_snmp_request()` decodes the community with `len < 64` at
`:313–322`, then the OID with only `len < 1` at `:412–421`, so the oversized
OID length reaches `decode_oid()` before the community value is compared.
`client->packet` is a 2048-byte member of a global client struct;
`client->size` is the received datagram length (`mini-snmpd.c:102–113`).

## Loopback build and wire evidence

`wire/` contains source trees fetched at the two pinned commits, built with
`autogen.sh && CFLAGS='-O0 -g -fsanitize=address …' ./configure --without-config
&& make`. `wire/mkpkt.py` crafts a 2048-byte SNMPv1 GET whose inner OID TLV
declares BER length `0xffff` (`06 82 ff ff`); `wire/mksafe.py` crafts a
35-byte in-bounds GET. `wire/run_wire.sh`, `wire/run_fixed_wire.sh` and
`wire/run_safe_wire.sh` start/stop plant-owned ASan daemons on loopback ports
16161–16164 and never contact another host.

- Vulnerable daemon, crafted packet: log contains `overflow for OID byte`
  and `Failed UDP request …: Bad address` — the oversized length reaches
  `decode_oid()` and its walk exceeds the 2048-byte logical packet.
- Fixed daemon, same packet: `underflow for oid` / `Invalid argument`; the new
  guard rejects before the walk.
- Safe packet: both daemons handle it with no decoder error.
- **Negative result, preserved:** ASan does not report an overflow in the
  vulnerable daemon. `client->packet` is an array inside a larger global
  struct, so the first bytes past offset 2048 are neighbouring struct fields,
  not an ASan redzone; the walk stops at the 20-subid cap. The direct-call
  harness models a heap-allocated packet of exactly 2048 bytes to get the
  ASan READ-1; do not claim a wire-level ASan report.

## Model boundaries (what the harness is not)

- No SNMP daemon in the harness; the 8192-byte workspace models the packet
  plus adjacent heap and the `oid_t` stub mirrors `mini-snmpd.h` constants.
- Direct call with a 2048-byte logical `size` and declared `len=4000` (not
  the advisory's `0xffff`) keeps the arithmetic and read extent finite while
  preserving the underflow and the redzone crossing.
- The chosen 0x5a / 0x3c canaries are placed past the logical packet; a real
  attacker chooses the BER length and the walk extent, not the heap bytes.
- No pointer control, no command execution, no rung-5 claim.
