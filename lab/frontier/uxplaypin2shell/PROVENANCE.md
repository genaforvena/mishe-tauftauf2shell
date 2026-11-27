# uxplaypin2shell — provenance (frontier W349, 2026-11-27)

## Claim and pins

- Advisory: GHSA-479c-ww7g-wgp8, published 2026-09-04 by `fduncanh`, High,
  CWE-121 + CWE-476, "No known CVE". Affected UxPlay `< 1.73.7`, patched
  `1.73.7`. `https://github.com/FDH2/UxPlay/security/advisories/GHSA-479c-ww7g-wgp8`
- Fix commit `746ec0eac21a7cf32ec39dbf105d564b36eab5e1` ("fix
  memcpy/strstr vulnerabilities (reported by @khattak761)", 2026-09-03),
  read from `https://github.com/FDH2/UxPlay/commit/746ec0e.patch`. It adds a
  `client_proof_len != sizeof(proof)` gate and changes the sink from
  `memcpy(proof, client_proof, (int) client_proof_len)` to
  `memcpy(proof, client_proof, sizeof(proof))`.
- Pinned vulnerable source `src/raop_handlers-v1.73.6.h`, SHA-256
  `8246b07770fe97c45e93a5a619cea1bfbc1978162e87227700e3549d5e56726f`:
  locals at `:354-358`, vulnerable `memcpy` at `:366`.
- Pinned fixed source `src/raop_handlers-v1.73.7.h`, SHA-256
  `83a8e51f6fb81784e747a3de0de97b568c06a95e894bf1e8c44e3c0686774df0`:
  fixed `memcpy` at `:370`.
- Harness `harness/uxplaypin.cpp`, SHA-256
  `c270551ef57cbc8035935dadcf520e89394006c092fbeb4ec75f8a8b96ed111d`; runner
  `harness/run-all.sh` SHA-256
  `2d96bf8cb2d14b7a8936bd20b511923d5b1039e383efdb7547623a7e12815ed0`.
  No archive is fetched at replay time; the pinned `.h` files and runner are
  self-contained.

## Harness disclosure

The declaration block `char *client_proof = NULL;`,
`unsigned char proof[64] = { '\0' };`, `memset(...)`,
`uint64_t client_proof_len = 0;` and both `memcpy` statements are verbatim
from the pinned headers. The surrounding UxPlay machinery (RTSP request,
plist parser, SRP validator, logger) is replaced by `plist_get_data_val_stub`,
which supplies a pointer and an attacker-chosen length — the exact two
values the pinned handler passes to `memcpy`. The stub allocates 128 bytes
and fills only `data.size()` bytes so the FIXED arm's `sizeof(proof)` copy
cannot over-read its source: only the destination overflow is measured.
The FIXED arm applies the verbatim `sizeof(proof)` hunk; the accompanying
length gate is not modeled because it changes control flow before the sink
without changing the measured destination behavior. The harness is a
generated-model/argv lab caller, not a live RTSP listener.

## Build and observations

Offline replay: `sh harness/run-all.sh` (g++ 13.3.0, `-g -O0
-D_FORTIFY_SOURCE=0 -fno-stack-protector -fno-omit-frame-pointer`; ASan arms
add `-fsanitize=address`; plain arm adds `-no-pie`). Fortify is disabled
because Ubuntu's default `_FORTIFY_SOURCE` turns the 128-byte attack into a
`__memcpy_chk` abort before ASan can report the sink; that abort is preserved
in `evidence/vuln-asan-attack.out` from the first build.

- `vuln-asan0 attack` (128-byte proof): ASan `stack-buffer-overflow`,
  `WRITE of size 128`, frame `handler_pin harness/uxplaypin.cpp:38`.
- `vuln-asan0 rip` (80-byte proof): ASan `WRITE of size 80`.
- `vuln-asan0 safe` (20-byte proof), all three `fixed-asan0` inputs: no ASan.
- Plain no-PIE GDB, breakpoint at `:38`, `next`, `info frame`:
  `saved rip = 0x4343434343434343` after the 128-byte copy; the 80-byte
  case faults in `free()` with `mem=0x4343434343434343`, i.e. a second
  attacker-chosen word is consumed as a pointer before return.
- `RUN_ALL_OK 10 PASS / 0 FAIL`, summary SHA-256
  `d3faf93535892ff5e3fdd4aba3bf6c2aa45da6cf273bd7cbf441af00a7ade994`
  (grep -oE stable tokens only; PIDs and addresses excluded).

## Grade and limits

R1/R2/R3 ✓; R4 DEMONSTRATED at the pinned-sink/argv lab scope, including
attacker-chosen bytes at the saved return address in a no-PIE, no-canary,
no-fortify build. R5 NO: no live RTSP listener, no network request, no wire
parse, no command execution or marker side effect. The real build's stack
layout, canaries, PIE and length gate are not measured; all lab conditions
must be disclosed with any claim.

## Clean replay

Author `git archive` replay is recorded in `reports/frontier-uxplaypin2shell.md`
after the staging commit; witness replay is requested but not yet returned.
