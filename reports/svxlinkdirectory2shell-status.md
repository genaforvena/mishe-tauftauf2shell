# svxlinkdirectory2shell — status (staged 2026-11-27 W335)

State: **STAGED by frontier W335; operator admission and witness replay
UNKNOWN.** Brief `reports/frontier-svxlinkdirectory2shell.md`, lab
`lab/frontier/svxlinkdirectory2shell/`, provenance/pins in that lab, charter
`.mishe-tauftauf/charters/svxlinkdirectory2shell.md`, seed wall
`.mishe-tauftauf/walls/svxlinkdirectory2shell.md`. Stage commits
`03ce68a3`, `3077ce0f` and `df6ef056`. Author clean replay of `df6ef056`:
`git archive --format=tar` plain-tar SHA-256
`9d83e19e929f2fc603bacbef212bbd10ca9433b1719a20cae1097b1f35f6e5c2`
(NOT a `.tar.gz` container), 8/8 harness hashes, four GCC builds,
`RUN_ALL_OK 18 PASS / 0 FAIL`, summary SHA-256
`871c0be7fdee729bec5c96ce53f31ea577c44680f28b2bcfa71d917a7d75e6bb`
byte-identical to the in-tree run. Author evidence is not acceptance.
Inner-socket window 218 (`%442`/`%443`, `dead=0`), registry 219/219 unique
names.

Finding: GHSA-5g48-xjmf-7p4q (Critical 9.8, CWE-121; **No known CVE** in the
GHSA, OSV mirrors `UBUNTU-CVE-2026-73154` — discrepancy UNKNOWN). Fix
`8eb1008f822a97a42184097ee57e51a302181c75`, parent
`d6451c1e5ff7070537fb5763d316b21ba6c68796`; `MAXDATA=45` in
`EchoLinkStationData.h`, unclamped `strncpy(str, data, end_desc-data)` at
`EchoLinkStationData.cpp:217` and NUL store at `:218`. Advisory source-bound
path: directory-server TCP station list → `handleCallList`
(`EchoLinkDirectory.cpp:534`) → `setData()`; no live client or wire run here.

Grade: R1/R2/R3 ✓ — ASan `WRITE of size 120` at the pinned `:217`, 0 bytes
past the 45-byte `str`; 45-byte input gives attacker-offset `WRITE of size 1`
at `:218`; vulnerable 44/31-byte and all fixed (44/45/120/4096) arms clean.
R4 **LIMITED**: unprotected plain 120-byte input faults (SIGBUS), and a
read-only GDB frame at `:218` shows 16 consecutive chosen `0x41` bytes at
`str+45..+60`. No saved-IP control, marker, pointer target or command.
R5 NOT CLAIMED — no live process, wire request or side effect.

Next (owned by the admitted target mind): a loopback fake EchoLink directory
server and an ASan `qtel`/`ModuleEchoLink` client configured with
`DIRECTORY_SERVERS=127.0.0.1`, answering a station-list request with the
advisory's seven-line response and a 62–120 chosen-byte fourth line. Assert
`setData()` is reached from the request; record the return mapping, crash and
fixed/short-input controls. A wire crash with harness-only control-flow
mechanics is the honest ceiling. Wake units and routes are person-reserved.
