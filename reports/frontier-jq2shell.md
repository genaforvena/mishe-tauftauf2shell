# Frontier brief: jq string-length overflow — CVE-2026-32316 (jq2shell)

**STAGED 2026-11-23 W146 — direct-call harness evidence, a live registered
two-pane window (inner socket index 114, name `jq2shell`) and a staging DM to
the operator exist; at staging, operator admission and an independent witness
verdict were pending.** Byte-exact pins, tag commits and hashes:
`lab/frontier/jq2shell/PINS.sha256`; harness provenance including negative
results: `lab/frontier/jq2shell/PROVENANCE.md`. Frontier owns no further work
on this target. Postscript: the target was admitted at 11:2xZ; witness W1
(#2556) graded rungs 1-4 ESTABLISHED at the direct-call scope and W160
(#2651) graded the real-process alias geometry ESTABLISHED at its labeled
scope, both without a grade change and with rung 5 unclaimed. Current status:
`reports/jq2shell-status.md`.

## 1. Verified ground truth

- Advisory: GHSA-q3h9-m34w-h76f / CVE-2026-32316, published 2026-04-13, High
  8.2, CVSS:3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`, CWE-190 -> CWE-122 —
  https://github.com/jqlang/jq/security/advisories/GHSA-q3h9-m34w-h76f and
  https://www.cve.org/CVERecord?id=CVE-2026-32316
- Affected `<= 1.8.1`; patched `1.8.2`. Advisory PoCs:
  `jq -n '("x" * 2147483646) + "xx" | length'` (append) and
  `jq -n '"////" * 477218589 | @base64d | length'` (invalid-UTF-8 copy).
  Impact claim: attacker-controlled crash, possible further heap corruption
  depending on allocator; no command execution claimed. The CVE record marks
  products commit-based (`< e47e56d`), a cosmetic difference from the
  advisory's affected-version range.
- Upstream fix `e47e56d226519635768e6aab2f38f0ab037c09e5` ("Fix heap buffer
  overflow in `jvp_string_append` and `jvp_string_copy_replace_bad`") adds a
  `uint64_t` guard in each function; `jq-1.8.2` NEWS.md lists the CVE and
  commit. Repo `https://github.com/jqlang/jq.git`, pinned tags `jq-1.8.1`
  (`4467af7068b1bcd7f882defff6e7ea674c5357f4`) and `jq-1.8.2`
  (`34f7186b86743a083a589741b6cea95293524108`). No jq target is in the
  plant's do-not-duplicate list, brief set or window registry.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; the `#line` slices in the harness carry the
raw pinned bytes and the guards.

Vulnerable `jvp_string_append()` (pinned `jv.c.vuln:1174-1198`) computes
`uint32_t allocsz = (currlen + len) * 2` at `:1187`. With
`currlen = 0x7ffffffe` and `len = 2`, the product is `0x1_00000000`, truncated
to 0 and clamped to 32 at `:1188`. The following
`memcpy(news->data, s->data, currlen)` at `:1191` copies `0x7ffffffe` bytes
into the 32-byte string; `memcpy(news->data + currlen, data, len)` at `:1192`
writes at a two-gigabyte offset. Fixed `jv.c.fixed:1181-1184` checks
`(uint64_t)currlen + len >= INT_MAX - sizeof(jvp_string)/2` and returns an
invalid string before allocating.

Vulnerable `jvp_string_copy_replace_bad()` (pinned `jv.c.vuln:1113-1134`)
computes `uint32_t maxlength = length * 3 + 1` at `:1117`. For
`length = 0x5555555b` the true product is `4294967302`, truncated to 6; the
loop at `:1126` encodes each invalid byte into three bytes, writing about
4.3 GiB into the six-byte buffer. The pinned `assert` at `:1127` aborts debug
builds; `NDEBUG` models the release build. The fix computes `maxlength` in
`uint64_t` and rejects `>= INT_MAX` at `jv.c.fixed:1117-1120`.

## 3. Cheapest local experiment

One generated C driver per variant, no jq build, JSON parser, jq process,
file, socket or network. `run.sh` extracts four verbatim slices under `#line`
directives and adds stubs preserving the pinned struct field types. The
`memcpy` macro records the requested length from the verbatim expression and
caps the executed copy at 48 bytes at the pinned call site; the plain
allocator reserves 2 GiB of virtual address space so the pinned second copy
is addressable, while ASan builds use an exact allocation for classification.

Command: `cd lab/frontier/jq2shell/harness && ./run.sh && ./check.sh`.

## 4. Rung-4 feasibility and risks

Favorable: the undersized sizes and requested copy lengths come from the
verbatim pinned arithmetic; both fixed variants reject the crafted geometry;
gcc and clang ASan classify the writes at the pinned lines; plain builds show
harness-chosen `0x5a` bytes beyond the undersized allocation.

Constraints measured here: the executed copy is capped at 48 bytes, the
UTF-8 iterator is bounded to 16 steps, `NDEBUG` is required for the second
bug, and plain builds rely on a reserved 2 GiB mapping; these are scaffolding
limits, not observations of a real jq process. No jq build, JSON input,
allocator grooming, ASLR study, pointer control or command was exercised.
Whether a real jq pipeline can construct the ~2 GiB strings and which heap
objects the overflow reaches remain UNKNOWN. CWE-190 is the asserted root
cause; no vendor RCE claim exists.

## 5. Observations

- Harness `PASS=64 FAIL=0` three times in the working tree; normalized trace
  `8d537806c87a39e1a41e5483a28a4a731e7d5fe970d6528f0dee207b13cef1e7` (no
  PID, address, path or build id).
  A clean `git archive HEAD` replay of the staged paths at commit `c040c1e`
  reproduced `PASS=64 FAIL=0` and the same trace.
- Rung 1/2: vulnerable `APPEND ALLOC=32 REQ1=2147483646 REQ2=2` and
  `BAD ALLOC=6 U8CALLS=16`; fixed runs report `APPEND REJECT=1` and
  `BAD REJECT=1`.
- Rung 3: gcc and clang ASan report `heap-buffer-overflow`, `WRITE of size
  48` at pinned `jv.c.vuln:1191`; an isolated `bad` run reports `WRITE of
  size 3` at pinned `jv.c.vuln:1126` in a 23-byte region. Fixed ASan runs are
  clean.
- Rung 4: plain vulnerable runs report `APPEND SINK=5a...` and `BAD
  SINK=5a...` (16 bytes each, past the 32-byte and 6-byte buffers).
  `evidence/gdb-chosen.out` shows `news->alloc_length=32
  currlen=2147483646 len=2` and `0x5a` at `news->data+32` and `+40` after
  the pinned memcpy.

## 6. Ceiling / handoff

Direct call with stubbed structs, bounded copies and reserved virtual space;
no real jq build, JSON parsing, jq process, file, socket, wire exchange,
network, allocator study, pointer control, ROP chain, command, marker side
effect or witness verdict. The `0x5a` bytes are chosen data, not execution.
A dedicated target mind should first build pinned `1.8.1` and `1.8.2`, drive
the advisory's jq expressions under ASan, confirm the real allocation sizes
and both pinned frames, then measure which heap objects the 32-byte/6-byte
overflows overlap in a full jq process before considering any pointer or
marker test. Only an observed saved pointer or control-flow diversion could
change the ceiling.
