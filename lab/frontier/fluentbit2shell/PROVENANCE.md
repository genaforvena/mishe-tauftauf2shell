# Provenance — fluentbit2shell harness (W141, 2026-11-23)

CVE-2026-61674 / GHSA-jrp8-r9hx-gf73. All provisioning was read-only fetching
of public upstream blobs and advisory pages; no external host was probed. The
harness runs only inside this directory with a direct function call, no socket,
listener, TLS or Fluent Bit process.

## Pinned inputs

| File | SHA-256 | Origin |
|---|---|---|
| `src/forward.c.47db630c` | `406f2d229d805bae08c6570e333f22b3cfc4db361780d21a28725a7dc37c9687` | raw.githubusercontent.com/fluent/fluent-bit/47db630cbfc5/plugins/out_forward/forward.c (parent of the fix commit, advisory-confirmed vulnerable) |
| `src/forward.c.v5.0.7` | `406f2d229d805bae08c6570e333f22b3cfc4db361780d21a28725a7dc37c9687` | raw.githubusercontent.com/fluent/fluent-bit/v5.0.7/plugins/out_forward/forward.c (affected release, byte-identical to vulnerable parent) |
| `src/forward.c.45486556` | `cb2f62d730736827b13e0cc5fde6135d3f1c47c43248913d5d81e7dd1ec71ea7` | raw.githubusercontent.com/fluent/fluent-bit/45486556be9d023e194665e243f156b228e195e0/plugins/out_forward/forward.c (fix commit) |
| `src/forward.c.v5.0.8` | `cb2f62d730736827b13e0cc5fde6135d3f1c47c43248913d5d81e7dd1ec71ea7` | raw.githubusercontent.com/fluent/fluent-bit/v5.0.8/plugins/out_forward/forward.c (patched release, byte-identical to fix commit) |
| `src/fix-45486556.patch` | `3b708e4575c39d65fe7c55ebf73375aecf2d6f2bc0aefbdf1a81cf08a83a4e52` | github.com/fluent/fluent-bit/commit/45486556be9d023e194665e243f156b228e195e0.patch |
| `src/GHSA-jrp8-r9hx-gf73.html` | `0c6621b542b03d18d531c1bb79d925fe771cb14697393618f48f090c0df87b18` | github.com/fluent/fluent-bit/security/advisories/GHSA-jrp8-r9hx-gf73 |

The CVE record (https://www.cve.org/CVERecord?id=CVE-2026-61674) states
affected `>= 0.11.0, < 5.0.8`, fixed in 5.0.8, CVSS 4.0 9.2
`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`,
CWE-121/787/843. The GHSA's "Patched versions: None" field is stale; the CVE
record, fix commit and v5.0.8 release agree on 5.0.8.

`src/SHA256SUMS` pins the six files; `harness/SHA256SUMS` pins the driver,
runner, four generated slices and the six source pins (12 entries).

## Verbatim slices re-extracted per run by `harness/run.sh`

| Slice | Vulnerable source | Fixed source |
|---|---|---|
| `vuln/pong_case.inc` | `forward.c.47db630c:523-574` | — |
| `rel507/pong_case.inc` | `forward.c.v5.0.7:523-574` | — |
| `fixed/pong_case.inc` | — | `forward.c.45486556:540-601` |
| `rel508/pong_case.inc` | — | `forward.c.v5.0.8:540-601` |

Each slice is the **complete upstream `secure_forward_pong()` function**,
re-created with an `echo '#line N "forward.c.<pin>"'` header followed by
`sed -n 'N,Mp'` of the pinned blob, so ASan and gdb attribute the fault to the
pinned line, not the generated file. Only the function's environment is
stubbed (msgpack-c object/unpack types, `flb_forward`/`flb_input_instance`,
`flb_plg_error`, `msgpack_unpack_next`). No socket, TLS, event loop or daemon.

## Harness inputs and stubs

`driver.c` builds a synthetic msgpack array `["PONG", false, <reason>, "h",
"d"]`: `PONG[0]` is a 4-byte STR and `PONG[1]` a false BOOLEAN, so the
verbatim function reaches the unchecked `PONG[2]` branch. `reason` is a
1024-byte global filled with `0x41` plus chosen markers at offsets 0 (41), 17
(5a), 24 (7a), 33 (3c), 40 (7b), 48 (42), 56 (7b) and 57-63 (41). Mode
`attack 1000` sets `PONG[2]` to a 1000-byte msgpack STR; `safe` sets 4 bytes.
`arith` prints the arithmetic without a call.

The 32-byte destination `msg[32]` is the verbatim function's own local.
`flb_plg_error` is a variadic stub that emits `MSG_BYTE31` (0x41 = attacker
byte in the vulnerable copy, 0x00 = the fix's NUL terminator) immediately,
before the function can crash on return. The full smear observation is
compiled only into vulnerable variants (`-DSHOW_SMEAR`), because the fixed
variants copy at most 31 bytes and bytes past that are uninitialized stack;
including them made the normalized trace nondeterministic. ASan builds define
`NO_OOB_READ` so the observer itself never reads past `msg[32]`.

Plain builds use `-O0 -g -fno-stack-protector` (Ubuntu's default stack
protector aborts before observation); sanitizer builds use gcc and clang with
`-fsanitize=address`.

## Observations

- `PASS=65 FAIL=0` three times (`evidence/run1.txt`…`run3.txt`), normalized
  trace `35e7c470871e94379158696aa6899f13db4413b61153d53c4df6296f04061d96`.
  The normalized trace excludes PID, addresses, paths and build IDs; gdb
  output is normalized separately into `evidence/gdb-frame.out`.
- Rung 1: `arith-vuln.out` — 1000-byte reason, 32-byte destination, 968 bytes
  past the buffer.
- Rung 2: `plain-vuln-attack.out` / `plain-rel507-attack.out` — chosen bytes
  at all eight offsets, `MSG_BYTE31=41`, no rejection;
  `plain-fixed-attack.out` / `plain-rel508-attack.out` — bounded copy with
  NUL at 31 (`MSG_BYTE31=00`), no chosen byte past the destination.
- Rung 3: `vuln-gcc-asan.out` / `vuln-clang-asan.out` — `WRITE of size 1000`
  at pinned `forward.c.47db630c:567` in `secure_forward_pong`, object `msg`
  `[256,288)` at line 526; fixed, v5.0.8 and safe ASan outputs clean.
- Rung 4: `gdb-frame.out` — breakpoint at pinned line 568 (after the memcpy)
  shows `saved rip = 0x414141414141417b`, a stack byte `0x5a`, and a fault at
  pinned line 574 with the chosen RIP in backtrace frame 1.

## Ceiling / negatives

Direct call with stubbed msgpack/flb plumbing; no real `fluent-bit` process,
socket, TLS/SRP handshake, HELO/PONG wire exchange, event loop, or attacker
server. No canary (plain builds need `-fno-stack-protector`), no ROP chain,
command, `/tmp/PWNED` side effect, or witness verdict. The advisory's
`--supervisor` BROP path and its RCE claim stay claims; this harness reproduces
the stack smash and byte-precise control only. Fluent Bit was noted as
"rejected: attacker is a malicious server, victim is a client" in an unrelated
earlier frontier brief (`reports/frontier-nanomsg.md`); that one-line note is
overridden here because this plant already stages network-initiator/client
bugs and the rung-4/5 ladder tests attacker-controlled wire bytes into a live
process, which this sink satisfies.

## Re-run

```
cd lab/frontier/fluentbit2shell/harness && bash run.sh
```
Check `PASS=65 FAIL=0` and the `TRACE_SHA256` above. A clean-room replay of
`git archive HEAD lab/frontier/fluentbit2shell` is recorded in
`evidence/git-archive-replay.txt`.
