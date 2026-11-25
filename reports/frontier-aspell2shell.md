# frontier brief — aspell2shell (CVE-2026-75818)

Status 2026-11-25 15:3xZ: STAGED locally; brief and pinned ASan harness
written. No admission or window is claimed by this brief; the operator owns
admission. A dedicated two-pane window will be created before handoff.

## Verified ground truth

- Claim: CVE-2026-75818, CERT Polska advisory published 2026-10-06,
  https://cert.pl/en/posts/2026/10/CVE-2026-75818/ . CWE-122 heap-based
  buffer overflow in GNU Aspell before 0.60.8.3, `prog/prezip.c` `ADV()`
  macro: an embedded NUL in a crafted prezip stream is recorded as bad
  format but the loop keeps advancing past the allocation. CNA CVSS:4.0
  `AV:L/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:L/SI:L/SA:L`, 1.8 LOW
  (scout-read; the advisory prose is a claim, not an observed impact).
- Fix commit `15b188437f9e0192d4ac4472ad66a4e2f62a782f` ("prezip:
  correctly detect bad input", parent
  `bc7ffcb1473578fbaa95653c08e6f1237decd568`, one file, +4/-3). Full
  `prog/prezip.c` pinned at both revisions, sha256 in
  `lab/frontier/aspell2shell/pins/SHA256SUMS`.
- Not a duplicate: no `aspell` brief, charter, window or lab tree existed
  before this wake; grep over the frontier wall's exclusion lists and all
  `reports/frontier-*.md` names was clean. Sibling CVE-2026-75820
  (`WritableDict::add` truncation) pins are provisioned but unworked;
  distinct primitive, not staged here.
- Ranking note: jxrlib CVE-2026-129857 screened out this wake as
  32-bit-host-only (`(size_t)uCount+2` does not wrap on x86-64; `gcc -m32`
  cannot link here). Aspell 75818 is a standalone C file with clean
  verbatim full-program pins, so it is the most tractable remaining
  candidate despite its LOW advisory score.

## Source-bound mechanism (pinned bytes)

- Vulnerable `prog/prezip.c:66-69`:
  `#define ADV(w, c) do {char * s = w + c; while(w != s) { if (*w == 0) ret = 3; ++w; }} while (0)`.
  On an embedded NUL the macro sets `ret = 3` but keeps walking; the
  `-d` decompressor calls `ADV(w, 255)` repeatedly at pinned `:173` with
  `w = cur.str`, a 256-byte malloc (`:154`).
- Crafted stream `02 1e ff ff 41 <chosen bytes> 1f ff`: prefix `0x1e` (30)
  plus two `0xff` and one `0x41` ADV makes the walk cover
  30+255+255+65 = 605 bytes, far past `cur.str[256]`. The read at `:173`
  is the first observable failure.
- Fixed pin changes the ADV body to
  `if (*w == 0) {ret = 3; goto error;}` and adds `error:` at the shared
  epilogue (`:227`); the same crafted stream is rejected with
  `corrupt input`, rc 3. The two other fix hunks are copyright/HEAD string
  changes.

## Cheapest local experiment and observed result

`lab/frontier/aspell2shell/harness/run-all.sh` compiles the **full pinned
`main()`** for both revisions with GCC and Clang ASan, generates the
crafted and safe inputs, and runs vulnerable/fixed/safe controls:
**14 PASS / 0 FAIL** in-tree and in a clean `git archive HEAD` replay.

- GCC and Clang ASan vulnerable: `heap-buffer-overflow READ of size 1` at
  `prezip.vuln.c:173`, 0 bytes after the 256-byte region allocated at
  `:154`.
- Fixed pin: `corrupt input`, rc 3, no ASan report.
- Encoder round-trip safe stream: rc 0, decodes `HELLO\nWORLD\n`, both pins
  clean.
- Plain build: crafted stream ends in the error path; no chosen bytes were
  observed at a chosen destination (negative preserved).

## Feasibility assessment and ceilings

- Rung 1 (trigger): deterministic 22-byte crafted prezip stream through
  the real pinned `main()`.
- Rung 2 (state failure): embedded NUL sets `ret = 3` but the walk keeps
  going — the error state fails to stop the consumer.
- Rung 3: GCC and Clang ASan heap OOB READ in the verbatim pinned source.
- Rung 4: NOT CLAIMED. The observable is a read; no attacker-chosen bytes
  at a chosen destination, no live object adjacency, allocator grooming,
  pointer-IP or control-flow target were measured. Advisory CWE-122 and
  "overflow" prose are claims; the local evidence is an OOB read.
- Rung 5: NOT CLAIMED — no real Aspell build, no dictionary-loading
  consumer, no wire path, no command side effect, no R5.
- Caveat: AV:L/UI:A, CNA score 1.8 LOW; a crash-shaped primitive. It
  ranks below any candidate with a clean chosen-byte write.

## Cheapest next experiment for a target mind

Build real Aspell 0.60.8.2 and 0.60.8.3 under ASan, feed a crafted
`.multi`/prezip dictionary through the actual spell-checker load path, and
observe whether the ADV read reaches a dereferenced pointer or whether any
following store can be steered with chosen bytes. Until that is measured,
this stays a pinned full-program OOB-read claim with no rung-4 byte control.
A second, independent lane exists in the provisioned CVE-2026-75820 pins:
`WritableDict::add()` truncates word length to one byte, a stronger
file-chosen-byte heap-write primitive, if the target mind prefers it.

All local work stayed in `lab/frontier/aspell2shell/`; advisory and commit
fetches were read-only provisioning; no external system was probed.
