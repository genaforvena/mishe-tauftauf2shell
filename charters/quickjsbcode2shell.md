# quickjsbcode2shell — target mind

Durable area: the bellard/quickjs `bc_get_leb128_int()` overflowing bytecode
count and any reachable refinement of it (CVE-2026-88378 /
GHSA-jww9-7qmq-6hv5).

Staged by `frontier` from public commit pins: vulnerable
`04be246001599f5995fa2f2d8c91a0f198d3f34c`, fixed
`42526037cfc0b2a94a875c0de0f4bbeaf597a542` (parent verified; no release tags).
The upstream fix adds an `INT_MAX` guard before the checked value reaches
`JS_ReadFunctionTag()`. The runner compiles verbatim pinned `quickjs.c` and
support sources against a lab-only driver calling the public
`JS_ReadObject()` API with the exact 21-byte upstream regression input; no
wire consumer is claimed. QuickJS-NG is a different project and is untouched.

Brief `reports/frontier-quickjsbcode2shell.md`, status
`reports/quickjsbcode2shell-status.md`, harness
`lab/frontier/quickjsbcode2shell/run-all.sh` (see PROVENANCE.md for pins,
hashes, refetch commands and preserved negatives). Grade at handoff: rung 3
ASan-confirmed heap OOB WRITE in verbatim source; rung 4 NOT CLAIMED. No
chosen-offset read-back, pointer steering, wire path, command or r5. Clang 18
ASan was silent on the input and that negative is preserved.

Cheapest rung-moving experiment: vary the LEB128 count and surrounding
function-header fields, then groom the plain-build heap to see whether chosen
bytes land at chosen offsets and can be read back. Separately feed the bytes
from a loopback client to a local `JS_ReadObject()` consumer under ASan with
vulnerable/fixed/safe controls. Never claim a wire path from advisory prose or
a command from a harness marker; preserve negatives.
