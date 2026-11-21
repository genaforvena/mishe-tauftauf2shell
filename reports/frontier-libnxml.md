# Frontier brief — libnxml UTF-8 name overflow (DEFERRED candidate)

**Decision (2026-11-21 12:40Z): DEFERRED behind the admitted-worthy Pillow
find.** Real, fresh, fix-backed chosen-byte stack overflow in a small C XML
parser, but the advisory frames the impact as a crash (CVSS availability only)
and the reachable past-end span is a few bytes. Cheap to harness if a next
frontier wake wants an alternate; no harness and no window here.

## Claim sources

- CVE-2026-123202 / GHSA-mwvf-r58x-mh9m; CNA VulnCheck, published
  2026-11-05. <https://www.cve.org/CVERecord?id=CVE-2026-123202>,
  <https://github.com/advisories/GHSA-mwvf-r58x-mh9m>.
  Scout-reported CVSS 4.0 8.7 `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H`,
  CWE-121, EPSS 0.705%, SSVC exploitation `none`; affected below 0.18.6,
  fixed in 0.18.6 (release tag `a1b63cf1…`).
- Fix commit `fbac242374883edf2ec14127ca6d2accf4704b6a`, patch
  <https://github.com/bakulf/libnxml/commit/fbac242374883edf2ec14127ca6d2accf4704b6a.patch>.

## Source-bound mechanism

Raw affected `src/nxml_parser.c` at commit
`9272d1cd6fee88fe7fd4fd812736d95a6ba25f2f` (fetched and read this wake) has
five loops with the flawed bound at `:194`, `:418`, `:520`, `:838` and `:941`:
`while (__NXML_NAMECHARS && *size && i < sizeof(NAMEBUF) - 1)`. The
`__NXML_NAMECHARS` macro re-runs the UTF-8 width decoder on the *next* input
byte, setting a width of 1–5, and then `memcpy` writes that width starting at
offset `i`, ignoring `i + byte`. At `i = 1022` with a four-byte leading
character, attacker bytes land at offsets 1022–1025 of a 1024-byte stack
buffer, followed by a NUL. The fix changes the bound to
`i + byte < sizeof(NAMEBUF)` in all five loops.

## Feasibility and cheapest experiment

Bytes and length are attacker-controlled from an XML/RSS name; no public PoC
is known and the CNA scores confidentiality/integrity impact as none. A
cheapest harness would copy one loop plus `__nxml_utf8` under `#line` markers,
feed 1022 single-byte name characters followed by a four-byte UTF-8 character,
and expect an ASan stack OOB write with byte-exact readback past the buffer.
Before any marker or pointer claim, check what actually sits past `str` in the
real stack frame — a saved register or return address is layout-dependent.
All of this is UNPROVEN here; sources were fetched read-only, no exploit was
run.
