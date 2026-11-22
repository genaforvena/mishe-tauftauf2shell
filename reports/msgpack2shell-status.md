# msgpack2shell — status

Admitted 2026-11-22 ~22:0xZ under standing approval #6 as the 89th engine
route. Frontier staged this W125 lane with a brief, charter, seed wall and an
already-live two-pane window (inner tmux index 94, registry entry 95), which was
adopted and not duplicated. Admission added the hy4-flash `max_parallel: 3`
route and the path, debounce and `10-slice.conf` units from the exact full-flag
sync (pin `0d686bbad55c849e88334da64efff9da88ad528a`; `written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Admission changes no grade.

- Claim: GHSA-8pq6-mw7r-9f5g / CVE-2026-130065, "msgpack-c through 7.0.2
  contains a heap buffer overflow", CNA VulnCheck, GHSA published 2026-11-17,
  Moderate CVSS v4 5.8
  (`CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N`), CWE-787.
  The advisory claims a **local** attack vector with high complexity and
  passive user interaction; it makes no remote or unauthenticated claim.
  Claim source: `https://github.com/advisories/GHSA-8pq6-mw7r-9f5g`.
- Affected/patched fields: the advisory says "through 7.0.2" and leaves both
  affected and patched versions UNKNOWN; no fixed release tag is visible. The
  fix is commit `1c47ce020a019a3d4246e6394176779ecdf9d502` on `c_master`,
  parent `8a34070b41827a179e7c4a102f34d8c0a2bd5a77`. The shipped `c-7.0.2` and
  the fix parent have byte-identical `migrate()` bodies, so both are vulnerable
  pins. Pin digests are in `lab/frontier/msgpack2shell/harness/PROVENANCE.md`.
- Primitive: `msgpack_vrefbuffer_migrate()` decides whether to grow the
  destination iovec array by comparing the destination-derived `to->tail`
  against the **source** array's `vbuf->end`. Under an unequal-size migrate the
  growth is skipped and `memcpy()` writes 20 16-byte iovecs from `to->tail`
  regardless of `to->end`, overflowing an 8-slot (128-byte) destination. The
  one-line fix counts free slots in the object actually written
  (`nused > (size_t)(to->end - to->tail)`).
- Evidence (`bash lab/frontier/msgpack2shell/harness/run.sh`): `gen_fn.py`
  extracts the function byte-for-byte from each pin and `verify_verbatim.py`
  checks the slice. Operator replay from a copy of the harness outside the
  checkout: 177 PASS / 0 FAIL, rc 0, normalized hash
  `cbc13d219f85df289efd33aaab66b945cf29ba0d45576bd5ce96e750c9567538`,
  byte-identical to the committed evidence and to frontier's clean
  `git archive 36b8676` replay. Vulnerable pins under gcc 13.3 and clang 18.1
  give ASan `heap-buffer-overflow WRITE of size 320`, 0 bytes after a 128-byte
  region; plain mode reads back 12 chosen entries past capacity with
  `OOB_FIRST_BASE=4141414141414141`,
  `OOB_FIRST_LEN=5a5a5a5a5a5a5a5a`, and an intact tail sentinel. Fixed pin
  `1c47ce0` grows the array to 32 slots (`OOB_PAST_CAP=-12`) with no ASan
  report; the 4-iovec safe control is clean on all pins and compilers.
- Grade: rung 1/2 and rung 3 (ASan-confirmed heap corruption in verbatim pinned
  code) plus scoped rung 4 (chosen `iov_base` pointer and `iov_len` bytes at
  chosen offsets, direct-call/stub scope). Ceiling: no msgpack build, no public
  `vrefbuffer_init` / `append_ref` / `clear` sequence, no crafted serialized
  input, consumer or wire, no naturally observed cross-object layout (the
  comparison is forced by the harness), no dereference of the chosen pointer,
  no marker, command or rung 5. Consumer/wire reach stays UNKNOWN; the parked
  caveats from `reports/frontier-pnet2shell.md` §6 are preserved.
- Cheapest next experiments: build pinned `c-7.0.2` and drive the upstream
  two-migrate ASan variant through the real public API without forcing
  `src->end`; find an in-tree or downstream caller of
  `msgpack_vrefbuffer_migrate()` and decide whether unequal-size migrate is
  reachable from request data; only then test whether a chosen `iov_base`
  lands on a pointer-bearing field of an adjacent object. Rung 5 stays
  additive and per-build.
- Full stage: `reports/frontier-msgpack2shell.md`. No witness verdict yet.
