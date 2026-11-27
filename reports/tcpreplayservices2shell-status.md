# tcpreplayservices2shell — status (admitted 2026-11-27 W332)

State: **ADMITTED 10:0xZ under standing #6 as the 207th declared target mind;
independent witness replay CLOSED 10:19Z ESTABLISHED AS LABELED.**
`reports/frontier-tcpreplayservices2shell.md`, status
`reports/tcpreplayservices2shell-status.md`, lab `lab/frontier/tcpreplayservices2shell/`, provenance in that lab's
`PROVENANCE.md`, charter `.mishe-tauftauf/charters/tcpreplayservices2shell.md`,
seed wall `.mishe-tauftauf/walls/tcpreplayservices2shell.md`. Author replay
commit `52bcb913`; clean archive SHA-256
`f8dfc7071d456ca0668695f52a653ba42b6e699d4478666e2fc6accbda74af30`, all 10
pin/harness hashes matched, four builds OK, 12 PASS / 0 FAIL, summary log
SHA-256 `98b924412bb7bb7ae7d684ddd52446e0695d94cf9598e181e278f07ca4cc3f41`
byte-identical to the in-tree summary. Live inner-socket window 215
(`%436`/`%437`, dead=0), registry 216/216 unique names.
Operator clean-archive replay of commit `52bcb913` (archive SHA-256
`f8dfc7071d456ca0668695f52a653ba42b6e699d4478666e2fc6accbda74af30`) matched
all 10 harness and 3 pin hashes, built all four variants and returned
`TOTAL: 12 PASS / 0 FAIL` with the same summary SHA-256
`98b924412bb7bb7ae7d684ddd52446e0695d94cf9598e181e278f07ca4cc3f41`.

Witness #6335 replayed the clean `52bcb913` archive with four own builds:
all 10 pin/harness hashes matched, unmodified runner `TOTAL: 12 PASS /
0 FAIL`, summary `98b924…` byte-identical, fresh ASan WRITE-20 at
`src/common/services.c:74` and fixed/safe controls clean. ESTABLISHED AS
LABELED at the local-CLI/harness scope; no grade change, no pointer control
and NO r5. Detail: `.mishe-tauftauf/artifacts/witness-w332-tcpreplay/detail.md`.

Finding: CVE-2026-102896 / GHSA-fwcr-mqg6-hqmx, tcpreplay
`<= 4.6.0-beta2`; `parse_services()` in `src/common/services.c:74` copies an
unbounded `([0-9]+)` regex match into `port[10]` with `strncpy()` using the
match length. Exact fix `e6e32ec70a38c777f8007374c36b40d38baeaf3e`
(v4.6.0-beta3) clamps both copies. Pinned vulnerable `9d291ec9855fbb08271a59c3463ca4dc60787ad6`,
fixed `e6e32ec70a38c777f8007374c36b40d38baeaf3e`.

Grade: R1 / R2 / R3 ✓ — ASan `WRITE of size 20` at `services.c:74`,
`[192, 202) 'port' <== Memory access at offset 202 overflows this variable`,
and `WRITE of size 11` as the minimum excess, from the real `tcpprep` CLI.
R4 LIMITED — chosen digit bytes at a chosen stack offset, no control-flow
state observed. R5 NOT CLAIMED — local CLI file path, no wire request, marker
or command side effect. Fixed ASan and safe-input controls are clean.
Advisory's separate ~1000-digit `strncpy-param-overlap` is not claimed here;
plain build emitted no warning in this layout and that negative is preserved.

Next: the GDB/plain-build experiment showing `proto[10]` corruption and the
resulting `services->tcp[]` accounting change, with the same fixed and
safe-input controls. No rung-5 claim without a measured path from a real
request or file to a lab-chosen command; the witness verdict is not
independent acceptance of an unstated grade.
