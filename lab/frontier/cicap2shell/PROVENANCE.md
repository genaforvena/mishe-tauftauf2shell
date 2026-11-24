# PROVENANCE — cicap2shell lab (CVE-2026-136126)

Advisory, upstream source and patch were fetched read-only from cve.org and
GitHub raw/blob endpoints. No external probe, no c-icap build, no network
traffic from the harness. All paths are relative to this directory.

## Pins (sha256, checked by `sh run.sh` on every replay)

- `pinned/request_common.c` `b4988efe47003291ef8fe074a0d37a9504155fcef424940572299def762c37ad`
  — raw `C_ICAP_0.6.5/request_common.c`; vulnerable guard at line 509,
  entity write at line 512, teardown loops at 411-418.
- `pinned/header.c` `fa3fe4efceb985d5aa29cd9238be374490172b1d79f41ba0833710ab6b39219a`
  — pinned `mk_encaps_entity`, `destroy_encaps_entity`, `get_encaps_type`.
- `pinned/request.h` `e953e2f68a839f264255dc50d2b64af20ee48b22fa855e727099aaa2ba1e4619`
  — entities[5] and trash_entities[7] adjacency at lines 113-114.
- `pinned/header.h` `760e573b77139d62418827ed924e554bfb1e72aa5d13c9abbe7b66fd34e13fb3`
  — entity enum at lines 49-52.
- `pinned/fix.patch` `42e414fe70b07cbab0805143569119901d5243e3fc1e5b185d4152df3554b9de`
  — `05dcead8dc838cce2f403fca447791a1676faea3.patch`, master fix.
- `pinned/process_encapsulated_vuln.inc` `05b74ffd1d0abd30fd01b04873cb149006a0de66a1528f96e31cfccb4b45d174`
  — verbatim pinned `process_encapsulated()`.
- `pinned/process_encapsulated_fixed.inc` `17713a3bf1c067f6993bcf13dd1abfcbdc8545be0531f3c29115654bd0846d66`
  — same function with the patch's `num >= 4` guard.
- `pinned/destroy_vuln.inc` `a29d221d97fa4b7334d23e05154f910bf7eee0d5f0b50ee7670123be97aea18c`
  — verbatim pinned teardown loops, with unrelated request fields omitted.
- `pinned/destroy_fixed.inc` `8fb600c252f43d5962b4fad3a744a2fe57e3285b66c8d65f1159c41bb1b8964e`
  — patch-derived `i < 5` bound and `req->entities[i] = NULL`.
- `harness.c` `a1daab80114f2d09124b09d359bf6b32bd831659a3278e76beb466866728bdf4`.

Advisory: CVE-2026-136126 / VulnCheck, published 2026-11-24; affected
`<0.5.16` and `0.6.0 <= v < 0.6.6`; fixed 0.5.16 / 0.6.6; CWE-415,
CVSS 4.0 9.2 `AV:N/AC:H/PR:N/UI:N/VC:H/VI:H/VA:H`.

## Harness and exact build commands

`harness.c` uses the pinned helper functions above verbatim; the surrounding
`ci_request_t` keeps only the two adjacent entity arrays plus `hasbody`, and
`ci_headers_create/destroy/reset` are small stand-ins (the attack uses
`req-body` entities, so the header helpers are not on the triggered path).

`sh run.sh` checks all ten hashes, then runs exactly:

```
gcc -std=gnu11 -O0 -g -fno-omit-frame-pointer -fsanitize=address harness.c -o vuln-asan
gcc -std=gnu11 -O0 -g -fno-omit-frame-pointer harness.c -o vuln-plain
gcc -std=gnu11 -O0 -g -fno-omit-frame-pointer -fsanitize=address -DCICAP_FIXED harness.c -o fixed-asan
gcc -std=gnu11 -O0 -g -fno-omit-frame-pointer -DCICAP_FIXED harness.c -o fixed-plain
```

It then replays vuln/fixed × attack/attack72/safe × ASan/plain as applicable,
recording raw output under gitignored `evidence/` and `.rc` files, summary in
`replay.log`.

## Observed bytes (2026-11-24T17:20Z)

- `./vuln-plain vuln attack`: `alias=1 trash0_type=2 trash0_start=90`, rc 139.
  The sixth entity pointer is the `trash_entities[0]` pointer; its pinned
  `start` field carries the chosen wire value 90.
- `./vuln-plain vuln attack72`: `alias=1 trash0_type=2 trash0_start=72`, rc 139.
- `./vuln-asan vuln attack`: `ERROR: AddressSanitizer: heap-use-after-free`,
  `READ of size 4` in `destroy_encaps_entity` from `destroy_vuln.inc:10`;
  the 16-byte object was freed by `destroy_vuln.inc:6`; nonzero rc.
- `./vuln-asan vuln safe`, `./vuln-plain vuln safe`: `entities[5]=(nil)`,
  `alias=0`, `destroy done`, rc 0, no sanitizer report.
- `./fixed-asan fixed attack`, `./fixed-plain fixed attack`: `entities[5]=(nil)`,
  `alias=0`, `destroy done`, rc 0, no sanitizer report; fixed safe also rc 0.
- `sh run.sh` -> 19 PASS / 0 FAIL, rc 0. Clean-archive replay
  (2026-11-24T17:23Z): `git archive 58435874 lab/frontier/cicap2shell |
  tar x -C /tmp/w209-cicap`, then `sh run.sh` -> 19 PASS / 0 FAIL, rc 0,
  with the same ASan UAF and `alias=1 trash0_type=2 trash0_start=90`.
  The working tree was untouched.

## Known limits / negatives

- The original harness uses extracted functions with stand-in `ci_headers_*`
  and a reduced `ci_request_t`; the real-build lane below supersedes the
  "no c-icap build" part. Still no ICAP server, no wire request, no real
  `ci_request_destroy()` call from a worker, no live process, no pointer/IP
  or command control, no allocator metadata, no rung 5.
- ASan flags the use-after-free read at the start of the second destroy, not
  the intra-object pointer write itself (the two arrays are inside one
  allocation; GCC/Clang default ASan has no intra-object redzones). A clang
  `-fsanitize-address-field-padding=1` probe produced no field-padding
  report, so that negative is preserved here rather than claimed as a pass.
- The advisory is `AV:N` but this lab exercises a parsed header string, not
  a network socket; wire reach stays UNKNOWN.
- Witness replay #3733 returned ESTABLISHED AS LABELED (#3753): clean archive
  `58435874`, 19 PASS / 0 FAIL, hash pins and source-bound guard verified,
  sixth-entity wire value steers the aliased slot; no grade change, no r5.

## Real c-icap build (W1, 2026-11-24 18:3xZ)

Pinned release tarball
`6ac51b6dd39690a6ccc62e807f065e92131498687d4201a69ae9570b68bab1e5`
(`C_ICAP_0.6.5` tag, codeload GitHub), built with
`CFLAGS/LDFLAGS=-fsanitize=address` via `autoreconf -i`, `configure` and
`make -j4`, all rc 0. The four pinned sources hash-match that tarball exactly.
`realbuild/real_api_harness.c` links the built `libicapapi.so.6.0.5` and calls
the exported `ci_request_alloc`, `process_encapsulated` and
`ci_request_destroy` on a real `ci_request_t` (no harness stand-ins).

- Sixth value `90`, `72` and `4242`: `alias=1`, `trash0_type=2`,
  `trash0_start=<value>`; ASan `heap-use-after-free`, `READ of size 4` at
  `destroy_encaps_entity header.c:631` from `ci_request_destroy
  request_common.c:417`, freed at `header.c:635` from `:413`; rc 1.
- Four-entity safe: `entities[5]=(nil)`, alias 0, rc 0, no sanitizer report.
- Fixed control: no `C_ICAP_0.6.6` tag exists (latest tag 0.6.5), so
  `pinned/fix.patch` was applied to a 0.6.5 copy (hunk 2 applied by hand
  because of context drift) and rebuilt: attack and safe both rc 0,
  `alias=0`, no sanitizer report. No released 0.6.6 binary was built.
- Raw outputs in gitignored `evidence/real-*.out`; exact recipe and scope
  limit in `realbuild/README.md`. The header string reaches the exported
  parser function directly, not through `parse_header()` or a socket: no
  wire, no ICAP server, no pointer/IP/command control, no r5.

W2 (18:4xZ): `realbuild/wire_api_harness.c` feeds a complete ICAP request
through an `AF_UNIX` socketpair into the same real build using exported
`ci_connection_read_nonblock`, `ci_headers_unpack`, `process_encapsulated`
and `ci_request_destroy`. Sixth values 90/4242 produce `unpack=0 headers=4`,
`alias=1`, the chosen `trash0_start`, and the same `header.c:631` UAF;
four-entity safe and the upstream-patched fixed control are clean (rc 0).
The hidden `ci_read_icap_header()` and `ci_wait_for_data()` are bypassed, so
this is not `parse_header()`/`process_request()` and not a network socket;
raw outputs in gitignored `evidence/real-wire-*.out`.
