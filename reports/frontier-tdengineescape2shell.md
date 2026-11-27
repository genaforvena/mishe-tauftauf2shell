# Frontier brief: tdengineescape2shell — `trimString()` escape off-by-one

Status 2026-11-27 W371: **STAGED** by frontier under the standing
similar-things mandate; operator admission and independent witness replay
owed. Claim source: TDengine's own security-advisory page
<https://docs.tdengine.com/security-guide/security-advisories/> entry
**GHSA-4v5h-fxjw-vrmq / TD-SEC-2026-004**, published 2026-06-08, High CVSS 8.1,
CWE-121/CWE-787. The GitHub advisory URL itself returned HTTP 404 at
observation; the vendor page and upstream commit are the ground truth here.
Advisory claim: SQL parser `trimString()` in
`source/libs/parser/src/parUtil.c` writes one byte past a full stack buffer
on escape sequences `\%`, `\_`, `\x`; affected `<= v3.4.1.6`, fixed
`v3.4.1.14`. RCE is *claimed* by the vendor, not established here.

## Verified ground truth (claim, not assumed)

- Upstream fix commit `64ff9a8f7583f52c26a1d7cf5057d8f62ab82bb2`
  ("enh: Enhance security checks for string terminato (TD-SEC-2026-004)",
  2026-06-09), parent `d91020e5929513d31dc04c3e15d96b0cbd008ea8`.
  The public GitHub tag list jumps from `ver-3.4.1.13` to `ver-3.4.2.x`;
  no `ver-3.4.1.14` tag exists, so the fix is pinned by commit, not tag.
- Parent `parUtil.c` SHA-256
  `6145c20c319c696c01c379da8bc6d78525d06cc88462c01214964944e71c662e`;
  fixed `parUtil.c` SHA-256
  `68dc252535438f0791b377bd6d619e5c8135511841ba5a9211d62322f96de6c5`.
  Source tree provisioning: codeload tarball of the parent SHA-256
  `0ccab485902a9cb8ef667bd2688543de2785b0d1838c245b5720ee2e385ec947`
  (gitignored locally, not needed for replay).
- The fix inserts five lines in the `\%`/`\_`/`\x` branch at `parUtil.c:459`:
  `if (j + 1 >= dlen) { dst[j] = '\0'; return j; }` before the two-byte write.
  No other behavioral change in that file.

## Source-bound mechanism

Pinned vulnerable `trimString()` (parent `:425-476`) checks `j >= dlen` only
at the top of the loop. In the escape branch at `:459-461`, a two-byte write
`dst[j++] = src[k]; dst[j] = src[k + 1];` runs when `j == dlen - 1`: the
first byte lands at the last legal index, the second at index `dlen`, one
past the destination. The chosen byte is one of `0x25` (`%`), `0x5f` (`_`)
or `0x78` (`x`); it is attacker-selected from a three-byte set, not an
arbitrary byte.

A real exact-size stack caller exists in pinned `parInsertSql.c:459-464`:
`char tmpTokenBuf[TSDB_MAX_BYTES_PER_ROW];` followed by
`trimString(valueToken.z, valueToken.n, tmpTokenBuf, TSDB_MAX_BYTES_PER_ROW)`.
Other callers (e.g. `parAstCreater.c:72`) pass `sizeof(buf) - 1`, leaving a
slack byte; those are *not* the demonstrated frame.

## Local experiment

`lab/frontier/tdengineescape2shell/harness/` compiles the verbatim pinned
function excerpt (with `#line` pins) into two caller-shaped frames: an
exact-size `char buf[32]` for ASan and a `struct { char buf[32]; volatile
unsigned char victim; }` for chosen-byte readback. Builds: GCC ASan, Clang
ASan, GCC fixed ASan, GCC plain. Input is a quoted SQL-literal shape: quote,
31 `A` bytes, `\%`/`\_`/`\x`, closing quote. No server, network, credentials
or external host is used.

- Vulnerable GCC and Clang ASan: `stack-buffer-overflow`, `WRITE of size 1`,
  `SUMMARY ... parUtil.c:461 in trimString`, for all three escape bytes.
- Fixed build: no ASan report, `TRIM_N=31`; safe short input on the
  vulnerable build: no ASan report, `TRIM_N=2`.
- Adjacent-object frame, plain build: `victim` reads `0x25`, `0x5f`, `0x78`
  for the three escapes respectively; fixed build leaves the `0x5a` marker.
- `./harness/run-all.sh` reported `RUN_ALL_OK 28 PASS / 0 FAIL` twice from
  regenerated evidence, with 6 input pins and 5 stable-evidence pins.
  Raw PID/address logs are gitignored; stable outputs strip addresses and
  absolute paths.

## Rung assessment and scope

- R1: deterministic, reproducible trigger from pinned bytes.
- R2: one-byte write exactly one past the exact-size destination.
- R3: ASan-confirmed stack-buffer-overflow in both GCC and Clang builds.
- R4 **LIMITED**: an attacker-chosen byte from a three-value set lands in a
  real adjacent stack object at its offset 0. No control-flow pointer, callback,
  shell or command was exercised; full `taosd` SQL/wire path not built here.
- R5: **NOT CLAIMED**. No live listener, request input or command side effect.

## Cheapest next experiment for the dedicated mind

1. Build the pinned parser translation unit (or a `taosd` from the parent
   commit) and drive an SQL literal through `parInsertSql.c:464` with the
   destination at its exact size; check ASan and GDB for the real frame.
2. Measure whether the one-byte overwrite can reach a saved frame byte or a
   length field in that real caller; preserve the `sizeof(buf) - 1` callers
   as negatives.
3. Only if a real consumer is measured, test a benign command side effect
   with vulnerable/fixed/safe arms. The vendor's RCE claim remains a claim
   until then.
