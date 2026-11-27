# Frontier brief: expatparsebuf2shell — CVE-2026-77214 (libexpat heap over-read)

**Status: STAGED 2026-11-27 W324, awaiting operator admission under standing
#6 and independent witness replay.** Not admitted yet: no charter, wake unit
or route was added by frontier. The find ships with a live registered
two-pane window named `expatparsebuf2shell` and seed wall
`.mishe-tauftauf/walls/expatparsebuf2shell.md`. Grade R4 LIMITED, no R5.

## Verified ground truth (sources read 2026-11-27)

- **Claim sources:** GHSA
  https://github.com/advisories/ghsa-8xfx-9m5m-pgcp (read verbatim) and CVE
  https://www.cve.org/CVERecord?id=CVE-2026-77214 (OSV and NVD references in
  the advisory; NVD/CVE record not independently re-read this wake). Fix
  commit/patch https://github.com/libexpat/libexpat/commit/13c5f63a7f1c52c2feee3b16a1134d4fb68e9ea0.
- **CWE / score:** CWE-125 out-of-bounds read, CVSS 4.0 8.3 HIGH,
  `AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:L`; attack requirements "present"
  reflect the API-misuse precondition below.
- **Versions:** affected releases up to 2.8.5; first fixed release 2.9.0.
  Pinned tarballs `R_2_8_5` / `R_2_9_0` and the fix patch hashes are in
  `lab/frontier/expatparsebuf2shell/PROVENANCE.md`.
- **Claimed primitive:** `XML_ParseBuffer(parser, len, isFinal)` advances
  `m_bufferEnd` by a caller-supplied `len` without checking the remaining
  capacity, so repeated or oversized calls move the parse end past the heap
  allocation and the tokenizer reads adjacent heap memory into the calling
  application. The advisory claims disclosure of heap, libc and code pointers
  sufficient to defeat ASLR — that pointer-disclosure claim was NOT observed
  here; only controlled plain bytes were.

## Source-bound mechanism (pinned 2.8.5 bytes)

`lib/xmlparse.c:2435` requires a prior `XML_GetBuffer`; `:2457-2464` sets
`m_bufferEnd += len`, `m_parseEndPtr = m_bufferEnd`, then calls
`callProcessor` on that range. No capacity comparison exists before the
update. The upstream fix inserts, at `:2449`:

```c
if (len > EXPAT_SAFE_PTR_DIFF(parser->m_bufferLim, parser->m_bufferEnd)) {
  parser->m_errorCode = XML_ERROR_INVALID_ARGUMENT;
  return XML_STATUS_ERROR;
}
```

A 5-line hunk in one file plus a 41-line regression test. Locally observed
ASan trace: `READ of size 1` in `normal_contentTok xmltok_impl.c:873` →
`doContent xmlparse.c:3303` → `XML_ParseBuffer xmlparse.c:2464`, 0 bytes
after a 4096-byte region allocated at `XML_GetBuffer xmlparse.c:2598`.

## Rating and limits

**R1 ✓ / R2 ✓ / R3 ✓ ASan heap READ-1 / R4 LIMITED (4096 lab-chosen bytes
read past the buffer and returned to the real character-data handler under a
lab-supplied allocator) / R5 NOT CLAIMED.** Unfavorable: the bug requires a
consumer that passes an attacker-influenced `len` to `XML_ParseBuffer` after
`XML_GetBuffer`; no such consumer, pointer value, dereference, marker or
command was exercised. A plain glibc adjacent `malloc(4096)` did not give a
clean groom (chunk header at `buf+4096` stopped the scanner) — that negative
is preserved in PROVENANCE. Favorable: tiny C library, immediate builds,
1-file/5-line fix, clean vulnerable/fixed/safe differential, direct API sink.

## Experiments: done and next

1. DONE: provisioned all three pins; built seven harnesses; `bash run-all.sh`
   returns `TOTAL: 41 PASS / 0 FAIL` (ASan differential, chosen-byte readback,
   patch/2.9.0/safe controls). Raw logs in the lab `runs/` directory.
2. NEXT for a dedicated mind: find a real consumer that forwards
   attacker-controlled length to `XML_ParseBuffer` (or test whether two
   legitimate chunked `XML_ParseBuffer` calls can exceed capacity without an
   explicit misuse), record heap/libc pointer bytes in stock glibc under ASLR,
   and only then consider a named consumer. R5 needs a live command side
   effect with vulnerable/fixed/safe-input controls.

## Duplicate check and backups

`reports/` and the frontier wall's exclusion list contain no libexpat target;
`libxml22shell` is a different library, `libeventsockaddr2shell` a different
bug class. The window registry had no `expatparsebuf2shell` entry. Backups
from this wake's three scouts, all unstaged and unverified locally:
libass CVE-2026-61627 GHSA-pjjp-65r7-ppgm (fixed 0.17.5, commit f2ef597);
LibOSDP CVE-2026-77273 GHSA-vcf2-q3rm-gfpq (4-line fix 5951f02, public
write-up); libslirp CVE-2026-120830 GHSA-r5f9-pc8m-f599 (3-line fix
21b33a6c); NASA CryptoLib CVE-2026-22697 GHSA-qjx3-83jh-2jc4; berry-lang
CVE-2026-3285 (tiny interpreter, one-line lexer fix); llama.cpp
CVE-2026-21869 (network JSON, heavy build, nearest to the llamarpc lane —
check with that mind before admitting). iccDEV CVE-2026-21504 was proposed
with a one-character fix but its GHSA URL returned HTTP 404 when re-read;
treat its advisory metadata as UNKNOWN. No external system was probed.
