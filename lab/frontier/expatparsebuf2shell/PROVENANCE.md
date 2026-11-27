# expatparsebuf2shell provenance and observations (2026-11-27 W324)

All fetches were read-only provisioning from public libexpat/GitHub URLs. All
execution stayed in this lab directory; no socket, external target, scan or
probe was used. Harnesses call the REAL pinned `XML_GetBuffer` /
`XML_ParseBuffer` code; no parser function is copied or reimplemented. The
controlled-allocator harness supplies only a lab memory-handling suite through
the public `XML_ParserCreate_MM` API so that bytes past the buffer are known.

## Claim sources and pins

- GHSA https://github.com/advisories/ghsa-8xfx-9m5m-pgcp (read verbatim) and
  CVE https://www.cve.org/CVERecord?id=CVE-2026-77214; CWE-125, CVSS 4.0
  8.3 HIGH `AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:L`. Advisory: a caller-
  supplied `len` in `XML_ParseBuffer` advances `m_bufferEnd` past the
  allocated buffer, disclosing adjacent heap memory including pointers; fixed
  in commit `13c5f63a7f1c52c2feee3b16a1134d4fb68e9ea0`.
- Vulnerable tarball `https://github.com/libexpat/libexpat/releases/download/R_2_8_5/expat-2.8.5.tar.gz`
  → `pins/vuln.tar.gz`, SHA-256
  `920dde485e15eda0cce8d2310b41d492c534e5e3d89ad407a0b4176dd2ff88fe`.
- Fixed tarball `https://github.com/libexpat/libexpat/releases/download/R_2_9_0/expat-2.9.0.tar.gz`
  → `pins/fixed.tar.gz`, SHA-256
  `16afbb9cefead2aa278105cf27d9f597bde7fbf3dbb85015857ca7ca6a4e89ba`.
- Fix patch `https://github.com/libexpat/libexpat/commit/13c5f63a7f1c52c2feee3b16a1134d4fb68e9ea0.patch`
  → `pins/fix.patch`, SHA-256
  `4eb9303e4effff1ad096c8e7d627374982390385fbd5458b66401b3270c1c1df`;
  `patch -p2` applies cleanly to the 2.8.5 tree. The differential control is
  2.8.5 + this patch; the 2.9.0 tarball is an independent fixed control.

## Source-bound mechanism (pinned bytes)

`vuln/lib/xmlparse.c:2414-2465`: after the `XML_INITIALIZED` state check
(`:2435` requires a prior `XML_GetBuffer`), `XML_ParseBuffer` sets
`start = m_bufferPtr` (`:2457`), then `m_bufferEnd += len` (`:2459`) and
`m_parseEndPtr = m_bufferEnd` (`:2460`) with no comparison against
`m_bufferLim`; `callProcessor(parser, start, m_parseEndPtr, ...)` at `:2464`
hands the extended range to `doContent` (`:3303`) and the tokenizer
`normal_contentTok` (`xmltok_impl.c:873`). The upstream fix inserts a
5-line guard before `:2459` returning `XML_ERROR_INVALID_ARGUMENT` (41).

## Reproduction

`bash bootstrap.sh` extracts both tarballs, applies the patch to `patched/`
and builds seven binaries (GCC 13.3, `-O1 -fsanitize=address` for three and
`-O2` for four). `bash run-all.sh` verifies three pin hashes, the source
guard differential, an ASan differential, chosen-byte readback and controls.

Observed on pinned bytes 2026-11-27 W324, all raw logs in `runs/`:

- Vulnerable ASan, `CAP=4096 LEN=8192 SEED=0x5a`: rc 1,
  `heap-buffer-overflow`, `READ of size 1`, stack
  `normal_contentTok xmltok_impl.c:873` → `doContent xmlparse.c:3303` →
  `XML_ParseBuffer xmlparse.c:2464`, `0 bytes after 4096-byte region`,
  allocation frame `XML_GetBuffer xmlparse.c:2598`.
- Vulnerable ASan safe `CAP=4096 LEN=4096`: rc 0, ASan-clean. Patched and
  2.9.0 ASan attacks: rc 0, `error=41`, ASan-clean.
- Controlled-allocator readback (arena slot 4096, chosen slot immediately
  following): vulnerable `LEN=8192`, seeds `0x5a` and `0x6b`: rc 0,
  `cdata_len=8189`, `tail_seed_count=4096` — all 4096 bytes read past the XML
  buffer appear as chosen bytes in the real character-data handler. Safe
  `LEN=4096`: `cdata_len=4093`, `tail_seed_count=0`. Patched and 2.9.0 arena
  attacks: `error=41`, `cdata_len=0`, `tail_seed_count=0`.
- `bash run-all.sh`: `TOTAL: 41 PASS / 0 FAIL`, rc 0.

## Negatives preserved

- With small `CAP` (16, 1024) and `LEN` up to 4096, `XML_GetBuffer` rounds
  allocation up to 2048 bytes, so the scanner stopped inside the allocation
  and ASan stayed clean. The over-read needs `LEN` beyond the *actual*
  allocation, not merely beyond the requested capacity.
- An ordinary glibc `malloc(4096)` placed immediately after the XML buffer is
  NOT a clean chosen-byte groom: the 16-byte chunk header sits at
  `buf+4096`, its first byte is invalid XML and parsing stops at
  `cdata_len=4093` (`delta=4112` observed). R4 therefore rests on the
  controlled-allocator harness, not on a stock glibc layout.

## Rating and limits

R1 ✓ deterministic trigger; R2 ✓ parser pointer invariant broken; R3 ✓ ASan
`READ of size 1` past a 4096-byte region; R4 LIMITED — lab-chosen bytes
disclosed through the real handler under a lab-supplied allocator, no stock
glibc groom, no named consumer, no pointer value dereference; R5 NOT CLAIMED.
The advisory API-misuse precondition (a consumer passing attacker-controlled
`len` to `XML_ParseBuffer` after a prior `XML_GetBuffer`) is unchanged. No
external systems were contacted with probes.

Clean-archive replay 2026-11-27T07:41Z: `git archive ea6981d2
lab/frontier/expatparsebuf2shell` into `/tmp/w324-expat-clean`;
`bash bootstrap.sh` then unmodified `bash run-all.sh` (sha256
`40a6ec229bbe916973771537e9dd42b78b21d583d446b0912430a4c9ebd9c17a`)
returned `TOTAL: 41 PASS / 0 FAIL`, rc 0; log sha256
`023945b0538feaeed4ca5d09c2e3b8a6bd09aff193665ee72eea9d66ac069bc1`.
