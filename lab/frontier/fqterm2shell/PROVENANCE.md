# fqterm2shell — provenance and preserved negatives

## Provenance

- Candidate found 2026-11-23 by read-only public-advisory provisioning. Advisory:
  https://github.com/advisories/GHSA-8m6p-6hq3-xcx4 (CVE-2026-131875),
  "fqterm before 0.9.11 contains a heap out-of-bounds write...", High 8.7,
  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H, CWE-787, published
  2026-11-18, Unreviewed in the GitHub Advisory Database. Affected/patched
  fields on the advisory page read "Unknown"; the description, the named fix
  commit and the 0.9.11 release tag are the version evidence, so the GH
  field values stay UNKNOWN rather than being inferred as 0/0.9.11.
- Fix commit named by the advisory references:
  `e340b62dcb6e70271459a3665f5b6699b54daebd`, "decode: bound the CSI parameter
  index", reported by Deus Rex research team. Patch fetched from
  https://github.com/mytbk/fqterm/commit/e340b62dcb6e70271459a3665f5b6699b54daebd.patch
- Vulnerable bytes: the parent of that commit,
  `079b6d58c036e4260c5f2c0be48a43e2c2f297a8` (obtained from the GitHub commit
  API), raw `src/terminal/internal/fqterm_decode.cpp`.
- Fixed bytes: the fix commit, same path; the pinned header
  `src/terminal/internal/fqterm_decode.h` is from the fix commit (unchanged by
  the fix). All fetched files hashed in `PINS.sha256`. Only advisory, commit,
  patch and raw-source pages were fetched; no external host was probed.

## Exclusion check

The candidate is not in the plant's do-not-duplicate set. A read-only scout
also returned Sofia-SIP CVE-2026-116791 (ws_read_frame unmask) as a candidate,
but that is already staged as `sofiasip2shell` (wall W128-W126) — REJECTED as a
duplicate. Solanum IRCd CVE-2026-121602 was ranked third (strcpy into
`chptr->chname`, needs PR:H server-to-server) and not pursued this wake.

## What is verbatim and what is a stub

Verbatim upstream bytes, extracted by `awk` from the pinned files by line number
and included under `#line` control by `harness/run.sh`:

| variant | pinned slice | source |
|---|---|---|
| vuln | `fqterm_decode.cpp.vuln:679-700` | parent 079b6d5 |
| fixed | `fqterm_decode.cpp.fixed:679-705` | fix e340b62 |

Both slices contain the complete definitions of `clearParam()`, `paramDigit()`
and `nextParam()`. The source line `param_[paramIndex_] = param_[paramIndex_] *10
+inputData_[dataIndex_] - '0';` is pinned at
`fqterm_decode.cpp.vuln:694`. The fix is the single inserted clamp
`if (paramIndex_ < 30 - 1) paramIndex_++;` at
`fqterm_decode.cpp.fixed:703-704`.

Declared stubs, all in the generated driver header: the `FQ_FUNC_TRACE` macro
(no-op), `StateOptionStub`, `QByteArrayStub` (one pointer, size-equivalent POD
for Qt's implicitly-shared byte array), `FQTermBuffer` (forward declaration),
and the `FQTermDecode` class layout. The layout mirrors the member declaration
order of the pinned `fqterm_decode.h.fixed` exactly — two pointer slots for the
QObject base, then every member through `leftToDecode_` — so `param_[30]` is
mid-object, not at the end. Qt's exact ABI sizes are a claim not verified here;
the 64-bit size-equivalent PODs give `sizeof(FQTermDecode) == 280`,
`offsetof(param_) == 60`, and the object end at offset 280. The FSM dispatch
loop (`feed()`) mirrors the pinned `bracket_state_` entries from the same source
file (digit -> `paramDigit()`, `;` -> `nextParam()`, `[` -> `clearParam()`) but
is generated code, not pinned bytes; a `#line 1 "driver-stub.cpp"` directive
keeps its frames out of the pinned-file attribution.

No Qt build, QObject meta-object, terminal widget, telnet/SSH/BBS connection,
socket, process or network is involved. The attacker-controlled byte stream is
the driver's direct function input.

## Allocation modes

- ASan build (`-DASAN_BUILD`): `Obj` is exactly one `FQTermDecode` (280 bytes).
  Writing at `param_[55]` reaches offset 280, the first byte past the
  allocation, so ASan classifies it. `delete op` avoids leak noise.
- Plain build: `Obj` appends a 512-byte `0xa5` canary, so chosen bytes can be
  read after the store. The real object has no such canary.

## Commands

```
cd lab/frontier/fqterm2shell/harness
./run.sh          # generates driver-{vuln,fixed}.cpp, driver-stub.cpp, 8 binaries
./check.sh        # 16 runs, 73 assertions, normalized trace hash, gdb probe
```

## Results (2026-11-23, this wake)

- `PASS=73 FAIL=0` on three consecutive runs.
- Trace `047e7be305131f1a206216d5208f565bb43d3456285bb5ed8078a7783e7f454e`,
  identical on all three runs; normalization drops PID, addresses, paths and
  build ids, keeping only stable evidence lines.
- Rung 1: vulnerable plain `baseline` gives `paramIndex=2 p0=1 p29=0`; the
  `oob-chosen` CSI with 59 separators gives `paramIndex=59 p0=9 p29=9`.
- Rung 2: fixed build gives `paramIndex=29` under the identical input (the
  clamp holds the index at the last valid slot); no canary byte changes.
- Rung 3: gcc and clang ASan report `heap-buffer-overflow`, `READ of size 4`,
  0 bytes after a 280-byte region, at pinned
  `fqterm_decode.cpp.vuln:694` in `FQTermDecode::paramDigit()`. The first
  out-of-bounds access is the *load* of the compound assignment
  `param_[i] = param_[i] * 10 + digit - '0'`; the store is on the same source
  line. Reported as READ-4, not WRITE-4, because that is what ASan classified.
- Rung 4: plain vulnerable build shows `slot35=5a5a5a5a` (the byte pattern
  1515870810 accumulated from digits) written into the member region past
  `param_[29]`, and `canary: 09 00 00 00` repeated four times: chosen `0x09`
  32-bit values written past the 280-byte object. gdb on the same plain build,
  breaking at `operator delete` and inspecting main's frame, prints
  `d.param_[35] = 0x5a5a5a5a` and the same four `0x09` canary dwords.
- Fixed ASan build: no ASan report, `EXIT=0`, `paramIndex=29`.

## Preserved negatives and corrections

- First driver build failed linking with `undefined reference to 'operator
  new(unsigned long)'`: `gcc` on a `.cpp` file compiles C++ but does not link
  libstdc++. Fixed by building with `g++`/`clang++` and adding `<new>`.
- An early edit accidentally dropped the `#ifdef ASAN_BUILD` guard in
  `run.sh`; rebuilt and re-ran after restoring it.
- The first `check.sh` expected the plain-only `slot35` line in ASan builds
  (2 FAIL); corrected to a mode-specific assertion.
- Plain-build objects were never freed, so the fixed ASan build reported a
  280-byte LeakSanitizer leak alongside a clean overflow result; `delete op`
  removed the noise and the check now asserts LeakSanitizer is absent.
- ASan initially attributed the stub `feed()`/`main()` frames to the pinned file
  because `#line` persisted past the slice; a `#line 1 "driver-stub.cpp"`
  reset fixes attribution, and a physical copy of the stub tail lets gdb
  resolve stub line numbers without a "No such file" warning.
- Intra-object stores at `param_[30..54]` are not reported by default ASan
  (no field-padding instrumentation); only the crossing at `param_[55]` is.
  Chosen-byte writes into the trailing member region are shown by the plain
  build and gdb, not by ASan.
- A single digit per slot keeps chosen values deterministic: at slot 30 the
  write overlaps `isParamAvailable_`, which `paramDigit()` resets to `true`,
  so a multi-digit value there would not accumulate cleanly. The chosen
  32-bit value is placed at slot 35 (inside `savedMode_`), which does not
  overlap that flag.

## Ceiling

Direct-call CODE/HARNESS rungs 1-4 only. No Qt/fqterm build, no terminal
process, no telnet/SSH/BBS stream, no socket or wire input, no pointer
control-flow hijack, no command execution, no marker side effect and no
witness verdict. The advisory's malicious-server claim and its "past the
decoder object" wording are reproduced only at the harness object shape;
rung 5 is UNKNOWN.
