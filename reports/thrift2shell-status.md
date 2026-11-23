# thrift2shell — status

Admitted 2026-11-23 ~09:5xZ under standing approval #6 as the 108th engine
route. Frontier staged this lane in W143 (commit `42abf3a`) with byte-exact
pinned upstream blobs, the fix parent, the fix commit and the released fixed
version. Brief: `reports/frontier-thrift2shell.md`; pins, verbatim slices,
SHA-256 manifests and raw evidence: `lab/frontier/thrift2shell/PROVENANCE.md`.
The two-pane inner tmux window 111 was already live and registered (frontier
handoff), so admission created no second window. The hy4-flash
`max_parallel: 3` route was added. The path, debounce service and
`@thrift2shell` slice drop-in were minted with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Both `m2shell-wake@thrift2shell.service` and
`m2shell-wake-thrift2shell.path` were added to the site's owner resolver map
(217 entries). The pinned full-flag doctor returned rc 0,
`PASS local plant out of Git` / `GREEN`; the doctor service already read
`ExecMainStatus=0`, `Result=success`. Checkers: `check-omp-only.py`
`GREEN (108 declared roles)`, `check-readme.py` `GREEN`,
`check-reproducibility.py` `GREEN (29 required files)`. Admission changes no
grade.

- Claim: GHSA-gwj4-q93m-wwqc / CVE-2026-55971, published 2026-07-27,
  Critical 9.3
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`,
  CWE-122. Apache Thrift before 0.24.0; fixed 0.24.0 by commit
  `db4a473f3a984eee27273256fe737be5dd175595` ("Read the zlib transform
  result directly in THeaderTransport"). The GHSA metadata fields are stale
  ("Affected versions: Unknown", "Unreviewed"); the advisory body, the
  oss-security post and the two release blobs agree on the version range.
  The captured cve.org page is an 880-byte JavaScript shell and supplies no
  claim. No pinned source claims a shell or RCE.
- Primitive: in the C++ bindings' ZLIB transform path,
  `THeaderTransport::untransform()` inflates the frame section into `tBuf_`
  (1024 bytes), sets `sz` to `stream.total_out`, then copies `sz` bytes back
  to `ptr`, which still points at the smaller compressed receive frame
  (pinned `THeaderTransport.cpp.v0.23.0:286-301`; the same copy-back is at
  the fix parent's `:320`). The only gate, `stream.avail_out == 0`, bounds
  the inflated length by the transform buffer, never by the destination.
  A 700-byte payload of `0x42` compressed to 31 bytes therefore writes 669
  bytes past a 31-byte destination. The fix swaps `rBuf_`/`tBuf_` and their
  sizes instead of copying back (pinned fix `:324-326`, v0.24.0 `:328-330`).

## Observed at admission

Operator replay from committed bytes only:

```sh
T=$(mktemp -d /tmp/thrift2shell-operator.XXXXXX)
git archive HEAD lab/frontier/thrift2shell | tar -x -C "$T"
bash "$T/lab/frontier/thrift2shell/harness/run.sh"
```

Result: rc 0, `PASS=71 FAIL=0`,
`TRACE_SHA256=c12ba2145cec292e618d2f50677887c61a56d577b012577cd50c304731bbe556`,
exact match to frontier's staged value. The runner re-extracts the complete
`untransform()` from four pinned blobs under `#line` directives, checks nine
source files and fifteen harness files against their SHA-256 manifests, and
verifies the fix patch's git blob prefixes `cdf29cf3d53` / `891059b888e`.

- Rung 1: `COMPRESSED_LEN=31 DECOMPRESSED_LEN=700 DEST_BYTES=31
  OVERFLOW_BYTES=669 TBUF_SIZE=1024` from pinned arithmetic; no call needed.
- Rung 2: v0.23.0 and the fix parent return `SET_SIZE=700`,
  `SETPTR_IS_RBUF=1`, `DST_UNCHANGED=0` and smear the adjacent sink
  (`SINK_DIST=48`, `SINK_BYTE_1=42`, `SINK_BYTE_16=3c`); fix commit and
  v0.24.0 return `SETPTR_IS_ORIG_TBUF=1`, leave `DST_UNCHANGED=1` with the
  sink at 0xCC. A 4096-byte input is rejected by the existing gate in every
  variant; 4 bytes is the safe control.
- Rung 3: gcc and clang ASan `heap-buffer-overflow`, `WRITE of size 700` at
  pinned `THeaderTransport.cpp.v0.23.0:301` in `untransform`, the fix parent
  at `:320`; fix, v0.24.0 and safe inputs are clean.
- Rung 4: chosen bytes `41/5a/7a/3c/7b/42/7b` observed at inflated offsets
  0/16/32/64/128/256/699 in a plain build against an adjacent 0xCC sink;
  gdb at pinned `:301` shows `sz=700` and the markers in the frame, versus
  the fixed build hitting the swap with `sz=31` and an intact sink.

## Ceiling and open work

The staged harness grade remains a direct call with stubbed object state,
but the live-server lane is no longer a proposal.
`reports/thrift2shell-livewire.md` records a real loopback `TSimpleServer`
+ `THeaderTransport` + ZLIB server on unmodified upstream v0.23.0 bytes:
ASan `WRITE of size 726` at pinned `:301` from a 72-byte client frame, a
plain-build glibc abort, chosen marker bytes in the adjacent tBuf chunk
header, and clean v0.24.0 and safe-input controls. Rungs 1-3 are therefore
also observed on living bytes; the byte placement is in heap metadata, not
a code pointer. Still absent: ASLR/grooming study, pointer control, ROP,
command, marker side effect, witness verdict and rung 5. Hand any
live-server claim to the witness before upgrading the row; do not relabel
placed heap bytes as execution.

