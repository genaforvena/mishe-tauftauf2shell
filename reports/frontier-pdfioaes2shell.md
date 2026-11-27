# frontier brief: pdfioaes2shell — PDFio AES-CBC IV-only underflow (screened, R3 only)

Status 2026-11-27: **screened with a live local reproduction; R3 CONFIRMED, R4 NOT
CLAIMED, no target mind/window requested.** Author result is not acceptance.

## Verified ground truth (claim, not assumed)

- Upstream advisory: GHSA-527h-2p2v-g388, published 2026-09-07, "AES-CBC
  decryption integer underflow leads to out-of-bounds read/write". Mirrored in
  GitHub Advisory Database GHSA-8vvg-4p6q-69x4 / CVE-2026-137937, published
  2026-11-27T15:31:38Z, severity MEDIUM. Claim: an AES-encrypted PDF whose
  string/binary value is exactly the 16-byte IV makes `pdfioFileOpen()` decrypt
  zero blocks and underflow the returned length; caller then OOB-reads/writes.
- Affected: PDFio `< 1.6.5`; fix commit
  `bb77255b2832c2b35fe502237ac1b452221e74ff` (v1.6.5). Verified pinned
  vulnerable commit from the advisory: `48b185c650e2e732eed260d63909f4ec68ac9353`.
- Patch is source-readable and small: `pdfio-aes.c:177` adds `if (len == 0)
  return 0;` and `pdfio-aes.c:199` changes `if (last)` to `if (last && outbytes
  > 0)`. Upstream patch text: https://github.com/michaelrsweet/pdfio/commit/bb77255b2832c2b35fe502237ac1b452221e74ff.patch

## Source-bound mechanism

`_pdfioValueDecrypt()` (`pdfio-value.c:173`) passes `len = datalen - ivlen` and
`last=true` to the AES reader. With a 16-byte value, `_pdfioCryptoAESDecrypt()`
(`pdfio-aes.c:168-206`) runs no 16-byte block, so `outbytes` stays 0 and the
output pointer never advances. The unguarded padding step reads `outbuffer[-1]`
and subtracts it from `outbytes`; with the string-buffer struct layout
(`pdfio-private.h:245-250`) that byte is `bufused=true` (1), so the unsigned
length wraps to `SIZE_MAX`. The binary caller passes that value straight to
`memcpy(v->value.binary.data, temp, templen)` at `pdfio-value.c:176`, reached
during `pdfioFileOpen()` → `load_xref()` → `pdfioObjGetDict()` →
`_pdfioObjLoad()` → `_pdfioDictDecrypt()`.

## Local experiment (loopback/file only; no external target)

Harness: `lab/frontier/pdfioaes2shell/harness/{gen,patch,driver}.c` are the
upstream advisory PoC (generator creates an AES-128-encrypted PDF with
`/VFPWN` binary value on the catalog; patcher truncates its hex value to the
IV only; driver opens it with the **public** `pdfioFileOpen()` API and walks
objects). Pinned vulnerable and fixed trees built from the exact commits above
with `./configure --disable-shared CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1"`;
the fixed tree needs the pinned `ttf` submodule `671390aef1f9e81723da164ea4a4a72037abfd52`
and links `-Lttf -lttf -lwebp`. Logs and PDFs: `lab/frontier/pdfioaes2shell/evidence/`.

- `evidence/base.pdf` SHA-256 `54bd94e576f7e0e4f08ec4f98f78ee5c1440d715c3d284bdf7d1c92f2b70b64c`;
  `evidence/evil.pdf` `8b09ddbd8f33727ccc1cec55f48d3d037b5e1dd3fde457eeb66d01117831628f`.
- Vulnerable + safe `base.pdf`: `done, no crash`, rc 0.
- Vulnerable + `evil.pdf`: ASan `negative-size-param: (size=-1)` in `memcpy`
  at `pdfio-value.c:176` (frames through `pdfioFileOpen()` at
  `pdfio-file.c:1230`), rc 1 — `evidence/vuln-attack.out`.
- Fixed commit + `evil.pdf`: `done, no crash`, rc 0 (`evidence/fixed-attack.out`);
  fixed + `base.pdf`: rc 0. Attack/Safe arms differ only in the pinned source.
- Negative preserved: converting the IV-only hex value to a literal string to
  reach `temp[templen] = '\0'` (`pdfio-value.c:201`) produced no fault
  (`evidence/vuln-literal-attack.out`); `gen-string` output is still written as
  a hex/binary value, and the literal-string conversion did not reach the sink.
  Do not claim the string sink from this lab.

## Rung-4 feasibility and ranking

R1 (deterministic file trigger via public API), R2 (underflowed length), and
R3 (ASan-confirmed invalid `memcpy` length) are observed. **R4 NOT CLAIMED**:
the underflow byte is the allocator's `bufused=1`, not attacker-chosen; there
is no chosen byte at a chosen offset, no pointer control, marker or command.
A plain (non-ASan) build can only be expected to fault in a huge `memcpy`; no
measured path to control the destination or length magnitude was found. This
ranks below candidates with an attacker-controlled `strcpy`/`memcpy` payload
(e.g. lrzsz ZMODEM `procheader()`), so it is not staged as a target mind.

Cheapest next experiment if revisited: find a `pdfio` call path where the
scratch `bufused` byte preceding the decrypted output is attacker-writable;
without a measured store there, this file cannot move past R3.
