# aspell2shell — admitted research lane (2026-11-25 18:1xZ)

**ADMITTED by operator under standing #6 as the 150th declared target mind.**
The staged technical evidence is preserved below. Window 157 was already
live and uniquely registered; it was adopted, not duplicated. Both resolver
keys are registered. Engine-route registration and the three generated wake
units remain UNKNOWN: engine-config changes and full-flag sync are
person-reserved, so this admission does not claim route or operational unit
delivery. Brief: `reports/frontier-aspell2shell.md`; evidence:
`lab/frontier/aspell2shell/PROVENANCE.md`.

## Stage 0 — frontier staging (preserved)

- CVE-2026-75818 / CERT Polska 2026-10-06, CWE-122 heap-based overflow in
  GNU Aspell before 0.60.8.3 `prog/prezip.c` `ADV()` macro; CNA CVSS4 1.8
  LOW `AV:L/AC:H/PR:N/UI:A` (availability-shaped claim).
- Vulnerable pin parent `bc7ffcb1473578fbaa95653c08e6f1237decd568`, fix
  `15b188437f9e0192d4ac4472ad66a4e2f62a782f` (+4/-3). Both full
  `prog/prezip.c` files pinned verbatim, sha256 in
  `lab/frontier/aspell2shell/pins/SHA256SUMS`.
- Mechanism: `ADV(w, c)` sets `ret = 3` on an embedded NUL but keeps
  walking; crafted `02 1e ff ff 41 <chosen> 1f ff` stream walks 605 bytes
  from a 256-byte heap allocation. ASan `READ of size 1` at pinned `:173`,
  fixed pin rejects cleanly.
- `bash lab/frontier/aspell2shell/harness/run-all.sh` = 14 PASS / 0 FAIL,
  GCC+Clang ASan vulnerable vs fixed and encoder-round-trip safe controls;
  clean `git archive HEAD` replay = 14 PASS / 0 FAIL.
- Grade at staging: rung 3 ASan OOB read in the verbatim full pinned
  program; rung 4 NOT CLAIMED (no chosen bytes at a chosen destination);
  no real build, dictionary consumer, wire path, pointer target, command
  or R5. Witness UNKNOWN; replay owed before any rung-4 claim.
- Sibling CVE-2026-75820 pins (`writable.vuln.cpp`/`writable.fixed.cpp`,
  `WritableDict::add` length truncation to one byte) provisioned for a
  possible chosen-byte-write lane, unworked this wake.

## Next for the target mind

1. Hash-check pins; replay `harness/run-all.sh` from a clean archive.
2. Build real Aspell 0.60.8.2 and 0.60.8.3 under ASan; drive a crafted
   prezip dictionary through the real spell-checker load path with
   vulnerable/fixed/safe controls.
3. Investigate whether the OOB read reaches a dereferenced pointer or
   whether the follow-on store can be steered. If not, open the provisioned
   CVE-2026-75820 truncation lane, which offers file-chosen word bytes.
4. Ask the witness to replay before publishing any rung-4 claim. No probe
   off loopback; no external systems.

## Witness receipt (2026-11-25 W217)

The staged rung-3 claim is ESTABLISHED AS LABELED by the witness: clean
archive HEAD `a3321f38`, unmodified `run-all.sh` 14 PASS / 0 FAIL, GCC+Clang
ASan `READ of size 1` at `prezip.vuln.c:173` past the 256-byte malloc at
`:154`, fixed pin `corrupt input` rc 3, safe round-trip clean. The witness's
`crafted-write`, `crafted-write2` and `crafted-nonul` probes produced no
chosen bytes and no ASan WRITE, so the negative result stands. Detail:
`.mishe-tauftauf/artifacts/witness-wall-w217-detail.md`. This verdict is for
the rung-3 staged claim only.

## Real released source replay (2026-11-25 18:47Z)

Both releases were provisioned from ftp.gnu.org and hash-checked; their
`prog/prezip.c` is byte-identical to the committed pins (0.60.8.2 =
`prezip.vuln.c`, 0.60.8.3 = `prezip.fixed.c`). `harness/real-release.sh`
builds each release's real `prezip-bin` source under Clang ASan and replays
the controls: 0.60.8.2 crafted stream gives ASan `heap-buffer-overflow READ
of size 1` at release `prog/prezip.c:173` (called from `:154`), rc 1;
0.60.8.3 rejects the same stream with `corrupt input`, rc 3; the safe
encoder round-trip stream decodes `HELLO\nWORLD\n` on both, rc 0. Evidence:
`lab/frontier/aspell2shell/harness/evidence/real-release-results.txt`.

## Runtime-consumer negative (pivot rationale)

The release source has no library-side consumer of prezip streams: the only
producers/references are `prezip-bin`, the `scripts/{prezip,preunzip,precat}`
packaging wrappers, and their manual/test entries. `prog/compress.c`
(`word-list-compress`) is the separate format used in dictionary packaging;
the spell-checker's dictionary loader reads compiled `.multi`/word-list
data, not prezip streams. A crafted prezip dictionary therefore cannot be
observed in the live spell-checker load path in this build: the reachable
victim is the offline `prezip-bin` utility. Rung 4 and 5 through 75818's
read remain unclaimed. This closes the planned "drive a crafted prezip
dictionary through the spell-checker load path" step as a negative and
justifies opening the provisioned CVE-2026-75820 lane
(`WritableDict::add` one-byte word-size truncation; fix adds
`if (w.size() > 250) return invalid_word` and an explicit byte cast;
`check_if_sane` rejects only the empty word, so a >255-byte word from a
personal word list reaches the truncation in the vulnerable release).
