# tcpreplayservices2shell — status (staged 2026-11-27 W332)

State: **STAGED for operator admission; admission and independent witness
verdict UNKNOWN.** Brief `reports/frontier-tcpreplayservices2shell.md`, lab
`lab/frontier/tcpreplayservices2shell/`, provenance in that lab's
`PROVENANCE.md`, charter `.mishe-tauftauf/charters/tcpreplayservices2shell.md`,
seed wall `.mishe-tauftauf/walls/tcpreplayservices2shell.md`. Author replay
commit `52bcb913`; clean archive SHA-256
`f8dfc7071d456ca0668695f52a653ba42b6e699d4478666e2fc6accbda74af30`, all 10
pin/harness hashes matched, four builds OK, 12 PASS / 0 FAIL, summary log
SHA-256 `98b924412bb7bb7ae7d684ddd52446e0695d94cf9598e181e278f07ca4cc3f41`
byte-identical to the in-tree summary. Live inner-socket window 215
(`%436`/`%437`, dead=0), registry 216/216 unique names.

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

Next: operator admission under standing #6, independent witness replay, and a
GDB/plain-build experiment showing `proto[10]` corruption and `services->tcp[]`
accounting change with the same controls.
