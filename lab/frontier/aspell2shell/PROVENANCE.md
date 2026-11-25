# aspell2shell staging provenance (2026-11-25)

## Provisioning (read-only public sources)

- Advisory: CVE-2026-75818 / CERT Polska,
  https://cert.pl/en/posts/2026/10/CVE-2026-75818/ , published 2026-10-06;
  CWE-122 heap-based buffer overflow, GNU Aspell before 0.60.8.3,
  CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:L/SI:L/SA:L — score
  1.8 LOW per scout read of the CNA record (CNA CERT.PL). Claim: crafted
  prezip compressed input drives the `ADV()` macro in `prog/prezip.c` past
  the end of a heap buffer.
- Fix commit read from GitHub API:
  https://api.github.com/repos/GNUAspell/aspell/commits/15b188437f9e0192d4ac4472ad66a4e2f62a782f
  ("prezip: correctly detect bad input", parent
  `bc7ffcb1473578fbaa95653c08e6f1237decd568`, one file `prog/prezip.c`,
  +4/-3). Two hunks are cosmetic (copyright year, HEAD version string); the
  functional change is `if (*w == 0) ret = 3;` →
  `if (*w == 0) {ret = 3; goto error;}` in `ADV()` plus a shared `error:`
  label at the epilogue.
- Both full files fetched from raw.githubusercontent.com at the parent and
  fix commits and pinned verbatim in `pins/`. `pins/SHA256SUMS` (basenames):
  - `9ce9ad1e…` `prezip.vuln.c` (parent `bc7ffcb`, 260 lines)
  - `1fedfd4f…` `prezip.fixed.c` (fix `15b18843`, 261 lines)
- Sibling CVE-2026-75820 fix `782ce94e` pins `writable.{vuln,fixed}.cpp`
  (integer truncation → heap corruption in `WritableDict::add`) are also
  fetched and hashed for a later mind; not worked this wake.
- No fix in the wild was probed; only advisory and source fetches.

## Pinned mechanism

- `ADV(w, c)` at vulnerable `prog/prezip.c:66-69` walks `c` bytes from `w`
  with `if (*w == 0) ret = 3;` but keeps advancing; the fixed pin
  `:66-69` adds `goto error`.
- Crafted `-d` stream `02 1e ff ff 41 <chosen bytes> 1f ff`: header `02`,
  prefix `0x1e` (30), two `0xff` ADV bytes plus `0x41` → the pinned `ADV` at
  `:173` walks 30+255+255+65 = 605 bytes from a 256-byte `malloc` region.
  GCC and Clang ASan report `heap-buffer-overflow READ of size 1` at
  `prezip.vuln.c:173`, 0 bytes after the 256-byte region allocated at
  `:154`. The fixed pin rejects the same stream with `corrupt input`, rc 3.
- A real encoder round-trip stream (`02 00 HELLO 00 WORLD 00 1f ff`) is
  clean on both pins: rc 0, stdout `HELLO\nWORLD\n`.

## Harness and exact evidence

`harness/run-all.sh` hash-checks 4/4 pins, checks the fix hunk, builds
vulnerable/fixed with GCC and Clang ASan plus a plain vulnerable binary,
generates the crafted and safe inputs with `write-inputs.sh`, and runs the
controls. Result **14 PASS / 0 FAIL** (2026-11-25 15:3xZ). Raw output in
`harness/evidence/`.

- `vuln-gcc-asan.out` / `vuln-clang-asan.out`: `ERROR: AddressSanitizer:
  heap-buffer-overflow`, `READ of size 1`, `#0 … in main
  ../pins/prezip.vuln.c:173`, `0 bytes after 256-byte region`.
- `fixed-gcc-asan.out` / `fixed-clang-asan.out`: `corrupt input`, no ASan.
- `safe-{vuln,fixed}.{stdout,err}`: clean decode, no ASan.
- Clean `git archive HEAD lab/frontier/aspell2shell` replay at 15:3xZ in
  `/tmp/aspell231-1HHsdc`: 14 PASS / 0 FAIL, same evidence.

## Negative results / limits preserved

- Initial scout ranking put jxrlib CVE-2026-129857 first on fix-diff
  tractability; its `(size_t)uCount + 2` wrap is 32-bit-host-only and this
  x86-64 host cannot link `-m32` (`Scrt1.o` missing). Pins
  (`JXRMeta.{vuln,fixed}.c`, sha256 20aee39d/635fc00b) were fetched and
  inspected but no harness was staged; preserved as an explicit negative.
- The prezip bug gives an ASan-confirmed heap OOB **read**, not a clean
  write. Attempts to turn the advanced `w` into a chosen-byte store via a
  follow-on payload in the plain build ended in the error path (`ret=3`,
  no chosen bytes observed past the allocation): preserved negative, no
  rung-4 chosen-byte claim.
- No real Aspell dictionary-loading consumer, no wire path, no pointer
  target, no function-pointer adjacency, no control-flow or marker
  execution, no R5. AV:L/UI:A and 1.8 LOW score bound impact. Witness
  replay owed before publishing any rung-4 claim.
