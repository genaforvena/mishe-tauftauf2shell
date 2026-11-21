# Frontier brief — Apache bRPC empty RESP array write (SCREENED OUT)

**Decision (2026-11-21 12:40Z): SCREEN OUT of the X2Shell chosen-byte lane.**
The bug and fix are real, but the out-of-bounds write is a `StringPiece`
descriptor into an empty vector: attacker-controlled length, arena pointer
plus length as bytes, and a fresh parser's null `_args` data pointer. The
observable local effect is a SIGSEGV/availability failure, not chosen bytes at
a chosen destination. No harness and no window.

## Claim sources

- CVE-2026-56388 / GHSA-57w6-4hvp-7m4g; CNA Apache, CVSS 3.1 9.1
  (scout-reported). <https://cveawg.mitre.org/api/cve/CVE-2026-56388>,
  <https://www.cve.org/CVERecord?id=CVE-2026-56388>,
  <https://lists.apache.org/thread/2pf15ojj0vr7rtx95677kgtl1mx3gdgb>.
- Fix PR #3354 "Fix empty Redis command array parsing",
  <https://github.com/apache/brpc/pull/3354.diff>; fixed release 1.18.0.

## Source-bound mechanism and screen-out reason

Raw `1.17.0/src/brpc/redis_command.cpp` (fetched and read this wake): an
RESP `*0\r\n` header sets `_length = 0` and executes `_args.resize(value)` at
`:506`; a following `$<n>\r\n...\r\n` bulk string reaches the non-aborting
`CHECK(_index < _length)` at `:509`, then `_args[_index].set(d, len)` at
`:537` — an indexed write into a zero-length `std::vector<StringPiece>`.
`StringPiece::set` stores `{d, len}`: the pointer is the parser arena's
address, not attacker-chosen; the bytes are a descriptor, not attacker
content. With libstdc++, a fresh vector's `_args[0]` destination is null, so
the write faults. The scout's rendered reader reported `:512/:515/:543`;
the raw bytes above are authoritative.

The scout reports `crash_on_fatal_log` defaults false in the default build, so
the CHECK does not itself prevent reaching `:537` — but that does not turn the
primitive into a chosen-byte write. The fix rejects `value == 0` and replaces
the CHECK with a parse error before any indexed write. No traffic was sent
anywhere; no local reproduction was attempted for this screened-out candidate.
