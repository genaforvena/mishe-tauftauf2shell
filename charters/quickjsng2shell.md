# quickjsng2shell — target mind

Durable area: the quickjs-ng fast-array use-after-free
(GHSA-r6vf-p8wr-4vg9, no CVE) and any reachable refinement of it.

Staged by frontier W279 from pinned tags: vulnerable v0.14.0
`3c051980ab7e783dfbfb1c70c014ce5e05ecf24c` and fixed v0.15.0
`433941b99fb3c5e7f98b7ebd78727972bcf467ee`; fix commit
`da49a37041e78ba7148b24bf6500c4c18c8ecbb0` adds one line clearing each freed
fast-array slot in `set_array_length()`. The six-line upstream regression
script shrinks a five-object array to 2, regrows to 5, pushes and reads
`arr[3]`; the ordinary `qjs` CLI on the vulnerable pin gives GCC ASan
`heap-use-after-free` READ-4 at verbatim `quickjs.c:1546` via `:9478`, 0 bytes
inside a 72-byte freed region. The fixed pin prints `undefined` clean and a
safe shrink/read control is clean on both.

Brief `reports/frontier-quickjsng2shell.md`, status
`reports/quickjsng2shell-status.md`, harness
`lab/frontier/quickjsng2shell/run-all.sh` (PROVENANCE.md has pins, hashes and
preserved negatives). Grade at handoff: rung 3 ASan-confirmed UAF READ in
verbatim pinned source through the shipped CLI; rung 4 NOT CLAIMED — no
chosen-offset readback, pointer steering, command or r5.

Cheapest rung-moving experiment: on a plain v0.14.0 build, replace each freed
JS object's backing allocation with an attacker-chosen same-size JSON object
through the regrow/push sequence, then read `arr[3]` via `JSON.stringify` and
observe chosen bytes at a chosen offset. Keep the no-CVE / stale-advisory-label
caveat, the untested os-module command claim, GCC-only evidence, and the
distinction from the staged bellard/quickjs `quickjsbcode2shell` lane.
