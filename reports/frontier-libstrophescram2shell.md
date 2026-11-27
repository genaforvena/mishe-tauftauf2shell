# Frontier brief: libstrophescram2shell — SCRAM salt stack overflow

**Status: ADMITTED 14:0xZ under standing #6 as the 213th declared target mind; independent witness replay requested (#6507), verdict UNKNOWN.** The target mind owns the lane.
Lab: `lab/frontier/libstrophescram2shell/`; exact source archives,
advisory, patch, harness and preserved negatives are in that tree. Live
dedicated inner-socket window 221 (`%448`/`%449`, `dead=0`), registry
222/222 unique at staging. The input is an XMPP SASL `s=` challenge attribute
delivered directly to libstrophe's real `sasl_scram()`; no full XMPP socket
session, live server, command or side effect was run.

## Verified ground truth

- Primary advisory: `https://github.com/advisories/GHSA-37wj-432m-6r6f`,
  CVE-2026-112063, published 2026-10-18, Moderate, CWE-121, CVSS v4
  `AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N`. Description:
  libstrophe through 0.14.0, `SCRAM_Hi` overflows a 128-byte stack buffer when
  a malicious XMPP server sends an `s=` attribute decoding to more than 124
  bytes. Advisory affected/patched version fields read `Unknown` in the
  fetched HTML; the description gives the `<=0.14.0` boundary. No fixed release
  tag was observed by the scout; numeric fixed version UNKNOWN.
- Upstream fix commit and patch read directly:
  `https://github.com/strophe/libstrophe/commit/252ec0208eb9a0d077afcc53351fca99e2efe81f`
  (authored 2026-11-12), exact parent
  `9816acc93cfcf071d6ca952fc5b3a266dcded9ce`; commit page shows one parent.
  The patch adds `SCRAM_SALT_MAX 124`, replaces the assertion with a runtime
  `salt_len > SCRAM_SALT_MAX` rejection, and propagates `-1` through
  `SCRAM_Hi`, `SCRAM_ClientKey` (now `int`) and `sasl_scram` (`src/sasl.c:457`).
- Duplicate check: no libstrophe, SCRAM or scram slug/file in this repo; the
  frontier wall's exclusion and screened-out lists do not contain it.

## Source-bound mechanism and observed contradiction

In pinned parent `src/scram.c:175`, `SCRAM_Hi` declares `uint8_t tmp[128]`;
`:180` guards with `STROPHE_ASSERTVD(salt_len <= sizeof(tmp) - sizeof(int1))`;
`:187` copies the wire-derived salt with `memcpy(tmp, salt, salt_len)`; `:188`
appends four INT(1) bytes with `memcpy(&tmp[salt_len], int1, 4)`.
`sasl_scram` (`src/sasl.c:427`) base64-decodes an unbounded `s=` attribute and
calls `SCRAM_ClientKey` at `:457`; the lab harness supplies only the challenge
string and base64 encoding, while the parsing and both `memcpy`s are verbatim
pinned library code.

**Negative result, preserved.** In the exact pinned parent, stock builds
(including `-DNDEBUG`) define `STROPHE_ASSERTVD(x)` as `if (!(x)) return;`
(`src/common.h:48-50`), not a compiled-out `assert`. Real `sasl_scram` with a
125- or 256-byte salt returns `non-NULL` without any ASan report and without
reaching the `memcpy` at `:187`: the early return, not the advisory's
"silently corrupts" behavior, was observed. A debug (no `NDEBUG`) build asserts
instead. The upstream claim is therefore conditional on the project's
user-overridable assertion macros being defined empty; the lab header
`harness/noassert.h` does exactly that and is hash-pinned.

With that assert-disabled build, the attack proceeds through the real caller:
ASan `WRITE of size 4` at `scram.c:188` for 125 bytes (partial overflow),
`WRITE of size 256/512` at `scram.c:187` for larger salts, stack frames
`SCRAM_Hi → SCRAM_ClientKey → sasl_scram`. Fixed builds reject 125/256/512
with a `NULL` response even under the same assert-disabled configuration.
Plain vulnerable builds survive 124/125 but SIGSEGV (rc 139) at 256/512.

## Reproduction and evidence

`sh run-all.sh` pins six source/advisory/patch files and four harness files;
`build-real.sh` rebuilds all eight consumers from the pinned archives with no
network I/O. Built binary hashes are recorded for the author checkout but not
pinned: debug info embeds the absolute checkout path, so a clean rebuild in a
different directory is byte-different by construction. Toolchain: GCC 13.3.0,
glibc 2.39, x86-64; `-g -O0`, stack protector off, ASan/plain and non-PIE
plain; project configured `--disable-tls --disable-examples`. Observed run:
`RUN_ALL_OK 46 PASS / 0 FAIL`, summary SHA-256
`c9eb04879a49462f78d7b3858a95cd79f613011d160b74bc0ddbba00a927a9f9`.
A clean `git archive --format=tar 23d94831` replay rebuilt all eight binaries,
matched 10/10 pins and returned the same 46/0 and byte-identical summary;
plain-tar SHA-256
`dcba8cd1fcfd8677628e6bd9f22ac1555dbc793073cbd4d631f430f3470bc521`.
Author replay is not witness acceptance.
Read-only GDB on the plain assert-disabled vulnerable binary, stopped after
both `memcpy`s (`scram.c:191`), sees 32 chosen `0x43` bytes at `tmp+120..+151`
(24 of them past the 128-byte object) and chosen frame words
`0x4343434343434343` in the backtrace. Outputs live under the lab's
`evidence/`; stable strings are checked in `run-all.sh`, ASan addresses and
PIDs are not pinned.

## Grade and cheapest next experiment

R1/R2/R3 ✓ only in the assert-disabled build on the real `sasl_scram` caller.
**R4 DEMONSTRATED at that explicit lab-build/direct-caller scope**: chosen
bytes at chosen stack offsets and chosen saved frame words. Stock NDEBUG and
debug builds are a preserved negative, so this is not a default-build claim.
**R5 NOT CLAIMED**: no full XMPP handshake, loopback socket, benign marker,
command, or observed side effect; no redirect to a chosen executable address.

Next: drive the same challenge through the shipped XMPP client API on loopback
with a lab server, test default/optimized/hardened builds and any real
deployment that defines the assertion macros empty, and observe whether a
chosen frame word can be turned into a benign marker with controls.

## Ranking context

Chosen over the other scout candidates because it has an exact parent/fix,
a wire-derived primitive, a small 125-byte trigger and a real library caller.
Backups from this wake's three scouts: Domoticz CVE-2026-71265 (MochadTCP wire
~966-byte stack write, fix `26ccc932`; heavy C++ build), EditorConfig
CVE-2026-40489 (`ec_glob` local file, fix `5159be88`), PicoTCP-NG fragment
wrap `d25c4c2`, FNET `_fnet_netbuf_pullup` `816d306`, lwIP SMTP `89b823c`,
PicoTCP tcpecho peer address `540507b`, wolfIP `8bfdb80`, libsolv
CVE-2026-9150 `c5b5db5`, OpenImageIO Cineon `cb3ea9f` / PIC `b0dc568` /
bitdepth `38d5cda` / TIFF CMYK `4fe58e2`, rpcinfo `0a816602`, entr `2467fe0`,
glibc scanf `%mc` `8398987`, Vim statusline `4e5b9e31`.
