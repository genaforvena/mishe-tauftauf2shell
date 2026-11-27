# tdengineescape2shell — provenance and pins (W371, 2026-11-27)

## Claim and source pins

- Vendor page: <https://docs.tdengine.com/security-guide/security-advisories/>,
  entry GHSA-4v5h-fxjw-vrmq / TD-SEC-2026-004, published 2026-06-08, High
  CVSS 8.1, CWE-121/CWE-787; affected `<= v3.4.1.6`, fixed `v3.4.1.14`.
  The `https://github.com/advisories/GHSA-4v5h-fxjw-vrmq` URL returned 404
  when re-read; the vendor page is the claim source. Vendor RCE wording is
  a claim, not a lab observation.
- Upstream fix commit `64ff9a8f7583f52c26a1d7cf5057d8f62ab82bb2`
  (2026-06-09, file-history API), parent
  `d91020e5929513d31dc04c3e15d96b0cbd008ea8`. No `ver-3.4.1.14` tag exists
  in the public tag list; the fix hunk is pinned to the commit.
- Provisioning (read-only, loopback irrelevant): codeload tarball of the
  parent SHA-256 `0ccab485902a9cb8ef667bd2688543de2785b0d1838c245b5720ee2e385ec947`;
  only `source/libs/parser/src/parUtil.c` was extracted and the 160 MiB
  tarball plus extracted tree are gitignored.
- Pinned blobs: parent `parUtil.c`
  `6145c20c319c696c01c379da8bc6d78525d06cc88462c01214964944e71c662e`;
  fixed `parUtil.c`
  `68dc252535438f0791b377bd6d619e5c8135511841ba5a9211d62322f96de6c5`.
  All replay inputs are pinned in `SHA256SUMS`; stable observations in
  `evidence/SHA256SUMS`.

## Mechanism and harness

- Vulnerable `trimString()` at parent `parUtil.c:425-476` checks
  `j >= dlen` only at loop top; the `\%`/`\_`/`\x` branch at `:459-461`
  writes two bytes without checking `j + 1 < dlen`. Fixed commit inserts
  a five-line guard; verbatim hunk in `pins/fix.patch`.
- Real exact-size stack caller: pinned `parInsertSql.c:459-464`, a
  `char[TSDB_MAX_BYTES_PER_ROW]` destination passed with the same size.
  Callers passing `sizeof(buf) - 1` (e.g. `parAstCreater.c:72`) leave slack
  and are not the demonstrated frame.
- `pins/parUtil-trimString-{vuln,fixed}.inc` are verbatim function excerpts
  with `#line` pins to upstream line numbers. `harness/driver.c` builds two
  caller-shaped frames: exact-size `char buf[32]` (ASan) and
  `struct { char buf[32]; volatile unsigned char victim; }` (plain chosen-byte
  readback). Input: `'`, 31 `A`, `\` + one of `%`, `_`, `x`, `'`.
- Regenerate from the lab root:
  `cd lab/frontier/tdengineescape2shell && ./harness/build.sh && ./harness/run-all.sh`.
  No network, server, listener or external target is used during replay.

## Observed evidence

- Vulnerable GCC and Clang ASan, all three escapes: `AddressSanitizer:
  stack-buffer-overflow`, `WRITE of size 1`, `SUMMARY ... parUtil.c:461 in
  trimString`. Stable filtered lines in `evidence/vuln-*-stable.out`.
- Vulnerable plain adjacent-object frame: `VICTIM=0x25`, `0x5f`, `0x78` for
  `%`, `_`, `x` respectively; fixed frame leaves the `0x5a` marker.
  `evidence/victim-stable.out`.
- Fixed ASan arm: no report, `TRIM_N=31`; vulnerable safe input: no report,
  `TRIM_N=2`.
- `RUN_ALL_OK 28 PASS / 0 FAIL` twice after evidence pins were recorded.
  Raw logs with PIDs/addresses are gitignored `raw/`.

## Scope limits

R1/R2/R3 confirmed in the pinned caller-shaped harness; R4 **LIMITED** to a
three-value chosen byte in a real adjacent stack object at offset 0. No
control-flow consumer, shell, command or wire request; the full `taosd`
parser path was not built, so the vendor's RCE claim is untested. R5 **NOT
CLAIMED**.
