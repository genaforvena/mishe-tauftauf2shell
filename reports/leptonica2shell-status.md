# leptonica2shell — status (staged 2026-11-25 23:0xZ)

Frontier W235 staged this lane. **Not admitted**: the operator owns admission
and the witness owns independent verification. Brief:
`reports/frontier-leptonica2shell.md`; pins, stand-ins and raw evidence:
`lab/frontier/leptonica2shell/PROVENANCE.md`.

Claim: `CVE-2026-137063` (published 2026-11-25, CWE-122, CVSS 6.8), heap
buffer overflow in Leptonica 1.79.0-1.87.0 `l_byteaInitFromStream()`; upstream
fix `c493a776e6bc6cfb1d8d15152a0b74f3d15b33fd` adds the missing
`nbytes > MaxArraySize` check. No fixed release is named in the feed.

Evidence: byte-identical pinned excerpts of `l_byteaCreate()` and
`l_byteaInitFromStream()` from tag 1.87.0 and the fix commit, driven by a
1,000,000,001-byte sparse file mapped read-only. GCC and Clang ASan report
`heap-buffer-overflow`, `WRITE of size 1000000001`, 0 bytes after the 201-byte
region, with stacks in the pinned excerpts; fixed build rejects
(`stream too large`, `BA=NULL`), a 16-byte stream is clean, and a synthetic
bounded plain consumer shows the chosen `MISHE-LEPTONICA` bytes at
`data+201..215`. `bash lab/frontier/leptonica2shell/run-all.sh`:
17 PASS / 0 FAIL, rc 0.

Grade: **rung 3 pinned verbatim / rung 4 PARTIAL** (file-chosen bytes at
chosen offsets, but observed through a synthetic bounded consumer). No real
library build, adjacent object, pointer, wire, command or r5. Witness
verdict UNKNOWN.

## Next

1. Replay `run-all.sh` from a clean archive and ask the witness to verify the
   labeled grade.
2. Build real Leptonica 1.87.0 and the fixed commit with ASan; call
   `l_byteaInitFromFile()` on the same sparse file and confirm the write in
   the real library.
3. Enumerate real callers of `l_byteaInitFromStream()` and look for a live
   consumer whose heap neighborhood can be measured. Keep the no-pointer,
   no-command ceiling until then.
