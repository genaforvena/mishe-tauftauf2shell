# pppd2shell harness provenance (W118)

## Pins and sources

Both release tarballs and both upstream fix commits were fetched read-only as
provisioning; no external host was probed. Exact SHA256 in `pins/PIN_HASHES.txt`
and re-verified by `sha256sum -c` at the top of `harness/run.sh`.

- Vulnerable: ppp 2.5.3 (upstream snapshot `0cfdb73`).
- Fixed: ppp 2.5.4, containing fix commits `cc8b00c96646f858fbd4e2699077701c72ef9e1c`
  (ignore duplicate configuration options) and `1baf2ac29e4456f095c4ebe15230881201ce4ffb`
  (guard writes to `nak_buffer`). Both patches saved under `pins/`.

## Verbatim bytes vs. local stubs

`harness/gen_lcp.py` extracts, from each pinned `pppd/lcp.c`, (a) the seven
`#define CILEN_*` lines and (b) the complete `lcp_reqci()` definition from its
first line through the brace before `lcp_up`. No line is edited. The generated
`lcp_functions.inc` files live only in the gitignored `harness/gen-vuln/` and
`harness/gen-fixed/` directories; `run.sh` regenerates them on every replay.

Everything else is a local stand-in, deliberately minimal:

- Real pinned headers (`pppd.h`, `pppd-private.h`, `fsm.h`, `lcp.h`, `chap.h`,
  `eap.h`) supply types, the GET*/PUT*/BCOPY/BZERO macros and all constants.
  `pppdconf.h` is the pinned all-`#undef` template copied verbatim, so optional
  features are off on both sides.
- `nak_buffer[PPP_MRU]` is declared exactly as at pinned `lcp.c:221`; the option
  arrays and `lcp_fsm[]` use the pinned declarations at `lcp.c:209-213`.
- Local stubs: `dbglog`, `warn`, `magic`, `multilink`, `chap_mdtype_all`,
  `debug`, plus the driver in `main`. None is part of the vulnerability.
- Builds use `-O0` and `-std=gnu11` for gcc / `-std=gnu89` for clang: the pinned
  function definition has no return type (old-style implicit `int`), which clang
  rejects under a post-C99 dialect. No source line is changed to accommodate it.

## Primitive and controls

`lcp_reqci()` NAKs each 4-byte PAP `CI_AUTHTYPE` with a 5-byte CHAP suggestion
(`03 05 c2 23 <digest>`). With `ao->neg_upap = 0`, `neg_eap = 0`, `neg_chap = 1`,
every duplicate PAP CI is NAKed again in the vulnerable pin; 320 CIs request
1600 bytes into `nak_buffer[1500]`. The 5th byte of each NAK is chosen through
`lcp_allowoptions[0].chap_mdtype` (`MDTYPE_MICROSOFT` -> `0x80`,
`MDTYPE_MD5` -> `0x05`).

Fixed 2.5.4 ignores duplicate CIs (first CI still NAKs once) and bounds-checks
`nakp`, so the same input produces a 5-byte NAK and zero bytes past the sink.

## Replay

`bash harness/run.sh` verifies all four pin hashes, extracts both functions,
builds nine variants (gcc/clang ASan, plain, chosen-alt, short safe input),
asserts twelve properties, and writes nine normalized logs plus
`EVIDENCE_HASHES.txt`. Normalization removes PID, paths, addresses, BuildId and
raw frame prefixes; no PID/address/path-dependent bytes enter the hashes.
Two consecutive in-tree replays produced byte-identical hashes; a clean
`git archive` replay is recorded in the frontier brief.

Scope: direct call into the pinned function only. No pppd process, pty, kernel
PPP device, wire negotiation or command execution. Rung 3 (ASan corruption),
rung 4 (chosen byte at a chosen relative offset) at direct-call scope only;
no rung 5.
