# Frontier brief: fqterm CSI parameter index heap overflow — CVE-2026-131875 / GHSA-8m6p-6hq3-xcx4 (fqterm2shell)

**STAGED 2026-11-23 W158 — direct-call harness evidence, a live registered
two-pane window (inner socket index 118, name `fqterm2shell`) and a staging DM
to the operator exist; operator admission and an independent witness verdict
are pending.** Byte-exact pins and hashes: `lab/frontier/fqterm2shell/PINS.sha256`;
harness provenance including preserved negative results:
`lab/frontier/fqterm2shell/PROVENANCE.md`. Frontier owns no further work on
this target.

## 1. Verified ground truth

- Advisory: CVE-2026-131875 / GHSA-8m6p-6hq3-xcx4, "fqterm before 0.9.11
  contains a heap out-of-bounds write...", High 8.7,
  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H, CWE-787, published
  2026-11-18, Unreviewed in the GitHub Advisory Database —
  https://github.com/advisories/GHSA-8m6p-6hq3-xcx4 . Credit: Deus Rex research
  team. The advisory's Affected/Patched fields read "Unknown"; the named fix
  commit and the 0.9.11 release tag are the version evidence. The GH field
  values remain UNKNOWN rather than being inferred.
- Affected: fqterm before 0.9.11. Patched: 0.9.11. Vulnerable bytes pinned at
  the parent of the fix commit, `079b6d5`; fixed bytes at `e340b62`.
- Upstream fix `e340b62dcb6e70271459a3665f5b6699b54daebd`, "decode: bound the
  CSI parameter index", is named in the advisory references and its patch was
  fetched and read. The advisory's malicious-server / cleartext-telnet narrative
  is a claim from the advisory, not reproduced in this lab.
- No target by this name appears in the plant's do-not-duplicate list, brief set
  or window registry. A scout also returned Sofia-SIP CVE-2026-116791, but that
  bug is already staged as `sofiasip2shell` and was rejected as a duplicate.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; pinned bytes live in
`src/fqterm_decode.cpp.{vuln,fixed}` and `src/fqterm_decode.h.fixed` and are
included verbatim under `#line` control in the generated drivers.

In `FQTermDecode::nextParam()` at `fqterm_decode.cpp.vuln:697-700`,
`paramIndex_++` runs on every `;` with no upper bound. `param_` is a fixed
`int[30]` member (pinned `fqterm_decode.h.fixed`, declaration
`int paramIndex_, param_[30];`). `FQTermDecode::paramDigit()` at
`fqterm_decode.cpp.vuln:687-695` then writes

```
param_[paramIndex_] = param_[paramIndex_] *10+inputData_[dataIndex_] - '0';
```

so a CSI sequence with more than 30 semicolon-separated parameters walks the
index past the table and writes attacker-derived 32-bit values into whatever
members follow `param_` (`isParamAvailable_`, `textParam_`, `savedMode_`,
`currentMode_`, `termBuffer_`, `server_encoding_`, `leftToDecode_`), then past
the object. Because `param_` is mid-object rather than last, the harness needs
55 slots to reach the object's 280-byte end; the fix closes the table walk at
its root regardless of object shape.

Fix `e340b62` replaces the bare increment with
`if (paramIndex_ < 30 - 1) paramIndex_++;` at
`fqterm_decode.cpp.fixed:703-704`. The pinned header is unchanged by the fix.
Only `fqterm_decode.cpp` is pinned for the direct-call path; the header is
pinned to document the member order the stub layout mirrors.

## 3. Cheapest local experiment

Two generated C++ drivers include the verbatim slices of `clearParam()`,
`paramDigit()` and `nextParam()` from the pinned file. Stubs are the
`FQ_FUNC_TRACE` macro, size-equivalent PODs for the Qt member types (member
order mirrors the pinned header exactly), and a dispatch loop mirroring the
pinned `bracket_state_` table. No Qt build, terminal, socket or network is
involved.

```
cd lab/frontier/fqterm2shell/harness
./run.sh && ./check.sh
```

Three scenarios: `baseline` (three CSI parameters, no overflow), `oob-chosen`
(59 parameters, a chosen `0x5A5A5A5A` dword in the trailing member region and
chosen `0x09` dwords past the object) and the identical input against the fixed
pin. Debugger commands are in `PROVENANCE.md`.

## 4. Rung-4 feasibility and risks

Favorable: the unbounded increment, the table declaration and the vulnerable
write are all in verbatim pinned bytes; both gcc and clang ASan classify the
out-of-range access at `fqterm_decode.cpp.vuln:694`; the fixed pin clamps the
index to 29 and writes nothing past the table; plain builds and gdb show chosen
bytes landing byte-exact in the trailing member region and past the object.
73 PASS / 0 FAIL on three runs; trace
`047e7be305131f1a206216d5208f565bb43d3456285bb5ed8078a7783e7f454e`. A clean
`git archive HEAD` replay (commit `ddc7b62`) regenerated the drivers, rebuilt
all eight binaries and re-ran `check.sh` three times with `PASS=73 FAIL=0` and
the identical trace hash; all six pinned files verify against `PINS.sha256`.
No network or external input was used in the replay.

Limits: the harness calls the three pinned member functions directly with a
stub FSM dispatch, stub Qt types and a stub allocator shape. There is no Qt or
fqterm build, no terminal widget, no telnet/SSH/BBS host, no socket or wire
input, no real QObject layout verification and no process. The object size and
member offsets are those of the size-equivalent POD layout (280 / 60 / 280),
not a measured Qt ABI. ASan classifies the first out-of-bounds access as READ-4
(the load half of the compound assignment); the store is on the same line but
is shown by the plain build and gdb. No pointer control-flow corruption or
command execution was exercised.

## 5. Observations

- Rung 1: vulnerable plain `baseline` gives `paramIndex=2 p0=1 p29=0`;
  `oob-chosen` gives `paramIndex=59 p0=9 p29=9` with `EXIT=0`.
- Rung 2: fixed build under the same input gives `paramIndex=29` and an
  untouched canary — the clamp holds the index at the last valid slot.
- Rung 3: gcc and clang ASan report `heap-buffer-overflow`, `READ of size 4`,
  0 bytes after a 280-byte region, at pinned `fqterm_decode.cpp.vuln:694` in
  `FQTermDecode::paramDigit()`; the fixed ASan build reports nothing.
- Rung 4: plain vulnerable build reports `slot35=5a5a5a5a` and
  `canary: 09 00 00 00 09 00 00 00 09 00 00 00 09 00 00 00` against a zeroed
  region; gdb prints `d.param_[35] = 0x5a5a5a5a` and the same four `0x09`
  dwords past the object.
- Preserved negatives: linker failure with `gcc` (fixed by `g++`/`clang++`),
  a dropped preprocessor guard, a mode-specific assertion error, LeakSanitizer
  noise (fixed by `delete`), and ASan frame misattribution (fixed by a `#line`
  reset). All are recorded in `PROVENANCE.md`.

## 6. Ceiling / handoff

Ceiling measured: direct-call CODE/HARNESS rungs 1-4 only. No witness verdict,
no real fqterm or Qt build, no terminal process, no wire input, no pointer
control, no command execution. Rung 5 is UNKNOWN and unproven. A dedicated
`fqterm2shell` mind would need to drive the CSI byte stream through a real
fqterm build against a loopback telnet/SSH host, then measure whether the
overwritten member region includes a pointer used before the process aborts.
Frontier owns no further work on this target.
