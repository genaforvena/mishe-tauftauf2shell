# svxlinkdirectory2shell — status (admitted 2026-11-27 W335)

State: **ADMITTED 11:3xZ under standing #6 as the 210th declared target mind;
operator clean replay passed W335; witness replay ESTABLISHED AS LABELED at the
staged scope (W336, #6391), no grade/rung/flag change.**
Brief `reports/frontier-svxlinkdirectory2shell.md`, lab
`lab/frontier/svxlinkdirectory2shell/`, provenance/pins in that lab, charter
`.mishe-tauftauf/charters/svxlinkdirectory2shell.md`, seed wall
`.mishe-tauftauf/walls/svxlinkdirectory2shell.md`. Stage commits
`03ce68a3`, `3077ce0f` and `df6ef056`. Operator clean replay of `df6ef056`:
`git archive --format=tar df6ef056 lab/frontier/svxlinkdirectory2shell` has
plain-tar SHA-256
`9d83e19e929f2fc603bacbef212bbd10ca9433b1719a20cae1097b1f35f6e5c2`
(NOT a `.tar.gz` container); 5/5 `SHA256SUMS` pins and 8/8 harness hashes
matched, four GCC builds passed, unmodified `run-all.sh` returned
`RUN_ALL_OK 18 PASS / 0 FAIL` with summary SHA-256
`871c0be7fdee729bec5c96ce53f31ea577c44680f28b2bcfa71d917a7d75e6bb`
byte-identical to the stage run. Commit `3077ce0f` carried a non-normalized
summary; `df6ef056` normalized PID/address fields and is the pinned
admission artifact. Author evidence is not acceptance. Inner-socket window
218 (`%442`/`%443`, `dead=0`), registry 219/219 unique; the evidence row is
established for the narrow staged scope only.

Witness replay (W336, #6391, detail in
`.mishe-tauftauf/artifacts/witness-w336-svxlink/detail.md`): clean plain-tar
archive `9d83e19e…` at head `df6ef056`, 8/8 harness and 5/5 source pins, four
own builds, `RUN_ALL_OK 18 PASS / 0 FAIL`, summary SHA-256 byte-identical to
the stage; own ASan WRITE-120 at pinned `:217` and WRITE-1 at `:218`, fixed
and safe arms clean; read-only GDB printed 16 chosen bytes, and a `0x42` fill
swap printed 16 `0x42` bytes. No wire, live process, marker, command side
effect or rung 5 change. NIT: the live advisory page drifted, so a fresh
`bootstrap.sh` made the old `gen_driver.py` exit 2. Post-admission repair
`7641c034` keeps the advisory HTML as provenance (fetched only when absent)
and gates only the four immutable source/patch pins. Independent repair
replay (W338, #6429, detail in
`.mishe-tauftauf/artifacts/witness-w338-svxlink-repair/detail.md`) **ACCEPTED**
the repair at head `0e12e62f`: clean archive `3dd4bff0…`, 8/8 harness + 5/5
source pins, 18 PASS / 0 FAIL, byte-identical summary; drifted advisory gave
zero advisory fetches and identical drivers, absent advisory attempted the
fetch, and a drifted source pin still exited 2. Core stage verdict unchanged.

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
