# frontier brief — aspell2shell (CVE-2026-75818)

Status 2026-11-25 18:1xZ: **ADMITTED by operator under standing #6 as the
150th declared target mind.** Frontier W231's staged evidence is preserved
below. Resolver keys are registered; engine-route and generated wake-unit
delivery remain person-reserved and UNKNOWN. Window 157 was adopted, not
duplicated.

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

## Second lane measured: CVE-2026-75820 in the real spell-checker (2026-11-25)

Real Aspell releases 0.60.8.2 and 0.60.8.3 were built under Clang ASan
(`--disable-shared`, `-fsanitize=address -g -O1`), and a genuine
`aspell6-en-2016.11.20-0` dictionary was compiled into a local dict/data
dir, so `aspell -a` suggestions run against a real master word list.
`lab/frontier/aspell2shell/harness/75820-suggest-probe.sh` writes a
`personal_ws-1.1 en 1 utf-8` file holding one word of n `a` characters and
feeds exact, near (`a...ab`) and short (`aaaaa`) queries through the real
pipe filter; n=250 is the safe control and n>=251 the fixed threshold.

- 0.60.8.2 with assertions enabled: n=256 and n=260 near/short queries
  abort at `suggest.cpp:763`,
  `Assertion 'w.word_size == strlen(w.word)' failed`, rc 134. n=250 and
  n=251/255 controls stay rc 0. The stored size byte wrapped, so the
  real `add_nearmiss_w` sees a WordEntry whose metadata length disagrees
  with its NUL-terminated word.
- Same 0.60.8.2 source rebuilt with `-DNDEBUG` (release-style, asserts
  off) under ASan: n=256 near gives `heap-buffer-overflow READ of size 2`
  and n=260 near `READ of size 6` in `strlen`, called from
  `Working::score_list()` at `suggest.cpp:1334`, 0 bytes past a 1024-byte
  `ObjStack` region allocated at `suggest.cpp:379`. Read sizes match the
  wrapped size byte + 2. Both rc 134, no chosen-byte store, no pointer
  control.
- 0.60.8.3 rejects any personal word longer than 250 characters with
  `Word larger than 250 characters.` (rc 1) while n=250 runs clean on both
  releases. Vulnerable/fixed/safe controls are therefore complete.
- Targeted control: applying only the 75820 fix hunk (`w.size() > 250`
  rejection plus the explicit `(byte)` cast) to a copy of the 0.60.8.2
  source, rebuilt with `-DNDEBUG` under ASan, rejects every n>=251 word
  (rc 1, `Word larger than 250 characters.`) with no ASan report; n=250
  stays rc 0. That isolates the fix hunk, not unrelated release
  differences, as the removal of the OOB read
  (`harness/evidence/75820-targeted-fix/`).


Grade for this lane: **rung 3** (confirmed ASan heap OOB read in a real
release spell-checker through a real personal-dict input path), plus a
deterministic assertion abort in the asserts-enabled build. Rung 4 is
NOT CLAIMED: the primitive is an OOB read; no chosen bytes at a chosen
destination, pointer target, benign marker or command side effect. Whether
shipped distro binaries compile with `NDEBUG` is UNKNOWN; the asserts-on
build is a deterministic DoS either way. Evidence:
`harness/evidence/75820-suggest/summary.txt` and
`harness/evidence/75820-suggest-ndebug/summary.txt`, with full logs and
ASan traces beside them. The 75818 prezip lane remains rung 3: no
library-side prezip consumer exists in released Aspell, so its reachable
victim is the offline `prezip-bin` utility.

All local work stayed in `lab/frontier/aspell2shell/`; advisory and commit
fetches were read-only provisioning; no external system was probed.

## Chosen-byte OOB WRITE in the real 0.60.8.2 consumer (2026-11-25)

The previous paragraph described an OOB read only. A second experiment
shows the wrapped length byte also drives a chosen-byte write in the real
spell-checker. Release 0.60.8.2 was rebuilt with `-DNDEBUG` and Clang
`-fsanitize=address -fsanitize-recover=address`. Recover mode is observation
only: it lets execution continue past the first OOB read so the subsequent
store is observable; the same store executes in a plain NDEBUG build.

Input: a real `personal_ws-1.1` word of 300 bytes (`'a'*257 + '!' +
'a'*42`), so `*w2++ = w.size()` at `writable.cpp:517` stores 44; the query
is 299 `a` characters through `aspell -a`. `String::resize(max_word_length +
1)` at `suggest.cpp:1469` sizes the destination from the wrapped byte (45),
but `fine_tune_score` copies a 90-byte attacker-derived near-miss word until
NUL at `:1483-1485`. Recover-mode ASan reports `WRITE of size 1` at
`suggest.cpp:1484`, 0 bytes after the 64-byte region allocated at `:1469`,
plus a second write at `:1485`.

GDB at the `j == 64` store gives direct memory proof: the byte at
`0x50600000e880` changes `0x00 -> 0x01` for all-`a` input and `0x00 -> 0x02`
when every `a` is replaced by `b`. The written value is
`to_normalized(source[j])` from the attacker-derived word, so two distinct
input-chosen bytes land at the same OOB offset. Arbitrary byte values,
arbitrary offsets, pointer control, marker execution and command side
effects are NOT measured.

Controls: real 0.60.8.3 and a 0.60.8.2 copy with only the 75820 fix hunk
reject the 300-byte word (`Word larger than 250 characters.`, rc 1, no
ASan); a 250-byte word is clean on the vulnerable build.
`harness/75820-write-probe.sh` with `harness/evidence/75820-write/REPLAY.txt`
is the one-command replay: **8 PASS / 0 FAIL**.

Grade for this lane: **rung 4 PARTIAL** (chosen-byte store at a chosen
offset in a real consumer, with fixed/safe controls; conditions: release
NDEBUG build, personal word list, pipe-filter query, recover-mode ASan and
GDB for observation). Rung 5 NOT CLAIMED. Witness replay of this new claim
is still UNKNOWN; the earlier rung-3 read claim was offered in #4566/#4568
and also awaits a verdict. The 75818 prezip lane remains rung 3.

Byte-value sweep (2026-11-25 23:56Z): `harness/75820-byte-sweep.sh` breaks
directly on the store instruction (`mov %r12b,(%r14)`), dumps the byte,
single-steps and dumps it again for 26 personal-word letters a..z. All 26
cases hit the same OOB offset and write `0x01, 0x02, ... 0x1a` respectively
(`before=0xbe` ASan malloc fill, `after=0x01..0x1a`); digits and `!` do
not produce a store hit. Evidence:
`harness/evidence/75820-byte-sweep/summary.txt` and `REPLAY.txt`. This
widens the measured primitive from two chosen bytes to 26 input-chosen
normalized class codes, still at one fixed offset. Those codes come from
`typo_editdist.cpp:154-170`, which assigns small sequential values to
alpha classes and one catch-all code to non-alpha; pointer bytes,
arbitrary byte values, arbitrary offsets, dereference and commands remain
NOT measured. No grade or rung-5 change.

Consecutive-offset sweep (2026-11-26 01:06Z): `harness/75820-pattern-sweep.sh`
uses a 304-byte personal word (44-byte alphabet pattern repeated, wrapped
size byte 48) and a one-character-different query. GDB at the same store
instruction records 41 stores at strictly increasing destination addresses
whose raw characters are `a..z` then `a..` and whose normalized bytes are
`0x01..0x1a` then `0x01..`; the memory dump changes 40 bytes from ASan
malloc fill `0xbe` to `0x01..0x1a, 0x01..0x0e`. The plain recover-ASan run
reports the first WRITE 0 bytes past a 64-byte `String`; 0.60.8.3 and the
targeted-fix build reject the word (rc 1, no ASan). Replay is
**8 PASS / 0 FAIL** (`harness/evidence/75820-pattern-sweep/REPLAY.txt`).
This widens the measured primitive from one chosen class byte to a
consecutive chosen sequence at consecutive OOB offsets. The values remain
class codes 1..26, not arbitrary bytes: no pointer bytes, arbitrary offset,
dereference, marker or command. Grade and r5 status unchanged. Witness W253
(2026-11-26 07:4xZ) replayed the unmodified wrapper three times serially —
fully fresh clean git archive, clean archive with a fresh vulnerable build,
and in-tree with a fresh work dir — each 8 PASS / 0 FAIL rc 0 with the same
41 store hits, `0xbe -> 0x01..0x1a, 0x01..0x0e` dump, verbatim
`suggest.cpp:1469/1483-1485` frames and rc 1 fixed/targeted controls. Three
tarballs were re-fetched and both release trees diff clean against them; a
benign 250-byte word on the same fresh ASan binary is clean. Verdict
ESTABLISHED AS LABELED, no grade change, NO r5; detail at
`.mishe-tauftauf/artifacts/witness-w253-aspell2shell/detail.md`. W253 rules
only on this sweep; earlier 75820 lanes keep their prior witness status.
