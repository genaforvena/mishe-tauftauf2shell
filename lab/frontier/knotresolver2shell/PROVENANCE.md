# KnotResolver2Shell candidate — pin provenance

Provisioned 2026-11-21 ~18:00Z from primary sources only. No target software
was built or run, no external system was probed. Digests are sha256 of the
exact bytes in `src/`, also recorded in `src/SHA256SUMS`.

| File | Source | sha256 |
| --- | --- | --- |
| `src/knot-resolver-6.4.0.tar.gz` | `https://github.com/CZ-NIC/knot-resolver/archive/refs/tags/v6.4.0.tar.gz` | `e8e771deb65e57827e709deb286ca884702e44a6e7ae062d7e01a12c45558fc3` |
| `src/knot-resolver-6.4.1.tar.gz` | `https://github.com/CZ-NIC/knot-resolver/archive/refs/tags/v6.4.1.tar.gz` | `20eb8b31a68e28b7e27e1787e8ba97dafee00efd04894dd777dfbde9ad902950` |
| `src/fix-7eb2e118.patch` | `https://github.com/CZ-NIC/knot-resolver/commit/7eb2e11810966323ed7c2385b8922eb8d57c46d2.patch` | `d40555c4072a351ab000f7c388b8eed00596cd7c8908ec00d84414fa8abd73ce` |

Claim records read this wake: MITRE CVE API `CVE-2026-66374` (published
2026-07-25T00:28:34.320Z, updated 2026-07-27T14:36:16.215Z, "before 6.4.1",
CVSS 3.1 8.1 `AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:L`, CWE-1284), oss-sec
2026-07-23 report at `https://seclists.org/oss-sec/2026/q3/226`, and the
upstream 6.4.1 NEWS at
`https://www.knot-resolver.cz/documentation/v6.4.1/NEWS.html` (release date
2026-07-22, "DNS-over-QUIC (DoQ) had severe issues, allowing even RCE").

Raw pinned-byte verification: only `daemon/quic_conn.c` was extracted from
each tarball into `check-6.4.0/` and `check-6.4.1/`. Vulnerable 6.4.0 has
`stream->pers_inbuf.size += datalen` at `:107`, unbounded `memcpy`s at `:120`
and `:124`, and no FIN length consistency check at `:133–136`. Fixed 6.4.1 has
the offset assert at `:158–161`, split length-prefix parsing with
`wire_buf_reserve()` at `:166–203`, the free-space/`malformed` check at
`:216–224` and the FIN query-size check at `:229–238`; no `size += datalen`
line exists. The GitHub fix patch is the intermediate form of the same repair.

The PoC repository `https://github.com/venglin/knot-doq` was linked by the CVE
and the oss-sec report but was NOT fetched, built or run.
