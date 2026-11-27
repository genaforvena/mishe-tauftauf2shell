# libstrophescram2shell — status (staged 2026-11-27 W341)

State: **FRONTIER-STAGED, NOT ADMITTED; independent witness replay UNKNOWN.**
Brief `reports/frontier-libstrophescram2shell.md`, lab
`lab/frontier/libstrophescram2shell/`, pins and provenance in that lab,
charter `.mishe-tauftauf/charters/libstrophescram2shell.md`, seed wall
`.mishe-tauftauf/walls/libstrophescram2shell.md`. Inner-socket window 221
(`%448`/`%449`, `dead=0`), registry 222/222 unique names. The operator owns
admission under standing #6; wake units, routes and sync are person-reserved.

Claim: CVE-2026-112063 / GHSA-37wj-432m-6r6f, exact parent `9816acc` to fix
`252ec020`, CWE-121. An unbounded `s=` attribute is base64-decoded by
`sasl_scram` and copied into `SCRAM_Hi`'s `tmp[128]` in the vulnerable parent.
**Stock NDEBUG builds do not fault**: this parent's `STROPHE_ASSERTVD` macro
returns early (`src/common.h:48-50`), contradicting the advisory's
"silently corrupts" claim. With libstrophe's documented assertion macros
defined empty via the pinned `harness/noassert.h`, the real caller reaches the
overflow.

Author result: `RUN_ALL_OK 46 PASS / 0 FAIL`; summary SHA-256
`c9eb04879a49462f78d7b3858a95cd79f613011d160b74bc0ddbba00a927a9f9`.
Assert-disabled vulnerable ASan: `WRITE of size 4` at `scram.c:188` for a
125-byte salt and `WRITE of size 256/512` at `scram.c:187`, both through
`SCRAM_ClientKey → sasl_scram`. Fixed builds reject 125/256/512 with a NULL
response under both configurations. Plain vulnerable builds SIGSEGV at 256/512;
GDB sees 32 chosen bytes past `tmp[128]` and chosen `0x4343434343434343` frame
words. Grade: R1/R2/R3 ✓ only in the assert-disabled build; R4 DEMONSTRATED at
that explicit lab-build/direct-caller scope; stock-build rung 0 negative;
R5 NOT CLAIMED (no XMPP socket, command, marker or side effect).

Next: drive the challenge through the shipped XMPP client API on loopback,
measure default/optimized/hardened builds, and look for real deployments that
define the assertion macros empty. No rung 5 without an observed command
side effect in a live target process.
