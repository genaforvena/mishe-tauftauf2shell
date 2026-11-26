# speex2shell — admitted (frontier W245, operator 2026-11-26)

Brief: `reports/frontier-speex2shell.md`. Lab: `lab/frontier/speex2shell/`.
Claim: CVE-2026-116741 / GHSA-jmfj-jxhf-c4c3, `speex_bits_read_whole_bytes()`
non-owner truncation writes caller-chosen bytes past a `SpeexBits` buffer.
Affected "through 1.2.1"; vendor fix commit `09b569d1b437e5edccf3406a38714ad795e46d38`
(GitLab MR !32). A 2026-11-26 direct refs query found that commit on two
branches and no tag, and both upstream mirrors' newest tag is `Speex-1.2.1`:
no released fixed tag exists as of that query (`lab/frontier/speex2shell/evidence/released-tag-check.txt`).
State: **ADMITTED by the operator under standing #6 as the 162nd declared target mind; window 170 adopted.**

Evidence: `bash lab/frontier/speex2shell/harness/run-all.sh` → 28 PASS / 0 FAIL rc 0.
Four real libspeex builds from the pinned tarball (ASan clang vulnerable and
vendor-fixed, plain gcc vulnerable and vendor-fixed) driven through public
APIs only. GCC+Clang ASan `heap-buffer-overflow WRITE of size 1`, 0 bytes
after a 16-byte region, frame `speex_bits_read_whole_bytes` at verbatim
`libspeex/bits.c:184`, allocation at `harness/driver.c:15`. Plain allocator
adjacency probe: `delta=32`, attacker-chosen `i..p` at canary offsets 0..7,
`changed=8 chosen=1` vulnerable and `changed=0 chosen=0` vendor-fixed. Grade:
rung 3 verbatim / rung 4 demonstrated impact in the lab under stated allocator
conditions. W245 found no pointer control. An **additive, author-observed**
probe this wake
(`harness/ptr-control.sh`, 8 PASS / 0 FAIL) places a function pointer in the
adjacent object and overwrites it with a runtime-chosen address using the same
two reads, then fires a benign in-process marker (`evidence/ptr-vuln-plain.out`:
`vfn` equals the chosen target, `marker_called=1`; fixed control
`marker_called=0`). Still no command, no wire consumer and no r5; the marker
is rung-4 mechanics and was not replayed by the witness.

Next: no bundled decoder reaches the vulnerable append API — every in-tree
consumer uses `speex_bits_read_from` (which resets `nbBits` and writes at
offset 0), so a crafted bitstream cannot reach `bits.c:184` in this tree;
an external consumer using the append API remains UNKNOWN. Allocator metadata
control was answered additively below (forged neighbour `size` → tcache
confusion → overlapping allocation, with a vendor-fixed control, but only
with a deliberately added `free`). The stack path is no longer UNKNOWN
(~17:45Z probe below); the released-fixed-tag question is answered negative as of
2026-11-26 (header); a future release would change that observation.
The operator's admission and any witness replay are not substitute acceptance.

Witness W245 (04:35Z, #4847): independent clean-archive and serial in-tree
replays both `REPLAY_PASS=10/0`, inner `28/0`, rc 0; upstream hashes and MR !32
verified. ESTABLISHED AS LABELED, no grade change, NO r5. Detail:
`.mishe-tauftauf/artifacts/witness-w245-speex2shell/detail.md`.

## Admission receipt (operator, 04:3x–04:4xZ)

- Unmodified `run-witness.sh` sha256
  `1dc5d05c2ff7a6c7ada028003a88178600aeb4d3a865b261400bf10b61a7b84f`.
  Clean `git archive 2daaa4ee` replay: `REPLAY_PASS=10 REPLAY_FAIL=0`, inner
  `TOTAL: 28 PASS / 0 FAIL`, rc 0, six pins exact. In-tree replay first failed
  (`19 PASS / 9 FAIL`: clang ASan builds saw `./autogen.sh: No such file or
  directory` while a concurrent replay deleted the shared build dirs);
  a serial re-run passed `10/0`, inner `28/0`, rc 0. The failure was a
  concurrent-run race on `lab/frontier/speex2shell/`, not staged-evidence
  breakage; no harness or pin was changed. Logs: `/tmp/speex-witness-intree.log`,
  `/tmp/speex-witness-clean.log`, `/tmp/speex-witness-intree2.log`.
- Frontier's two-pane window 170 adopted (registry: 171 windows / 171 unique
  names, panes live); no window was recreated. Charter, seed wall, brief and
  PROVENANCE read. Grade unchanged: rung 3 verbatim / rung 4 demonstrated lab
  impact under stated conditions, no pointer, command, wire or r5.
- Witness W245 (#4847, 04:35Z) independently ESTABLISHED AS LABELED; that
  verdict is scoped to the staged claim and is not a new grade.

Additive wake 2026-11-26: source search over `src-vuln/` found no production
caller of `speex_bits_read_whole_bytes` (definition at `bits.c:156`, header
at `speex_bits.h:88` only), and the pointer-control probe above. Details and
exact observed bytes in `reports/frontier-speex2shell.md` §6.

Additive same-day probe (~17:15Z): `harness/alloc-primitive.sh` (9 PASS /
0 FAIL, rc 0) forges the adjacent chunk's malloc size field to `0x31` with
`p2[0..7]`, then, with a deliberately added `free(v)`, gets `malloc(32)` to
return that chunk (`reuse=1`) and overwrite the following chunk's size field
(`overlap=1`, `csize_after=0xabab…`). Vendor-fixed: `bsize_after=0x21`,
`reuse=0`, `overlap=0`. Lab heap-layout primitive only; different free
conditions from the staged claim, no command/wire/r5, not witness-replayed.

Details in `reports/frontier-speex2shell.md` §6 and `PROVENANCE.md`.

Additive wake 2026-11-26 ~17:45Z: the advisory's stack-corruption claim was
driven (`harness/stack-path.sh`, 12 PASS / 0 FAIL rc 0, five repeats rc 0).
A stack-backed non-owner `SpeexBits` gives ASan `stack-buffer-overflow WRITE of
size 1` at verbatim `bits.c:184` on the vulnerable build (rc 1) and a clean
vendor-fixed control (rc 0, `nbytes=15`); a plain stack canary records
`changed=16 chosen=8` vulnerable vs `changed=0 chosen=0` fixed. Lab rung-3/rung-4
mechanics only — no wire consumer, command or r5, and not witness-replayed.
Details in brief §6 and `PROVENANCE.md`.

Additive wake 2026-11-26 ~17:49Z: the issue #42 already-full-buffer UBSan
observation was measured at the pinned fix commit (`harness/ubsan-fixed-
case.sh`, 5 PASS / 0 FAIL): UBSan `left shift of negative value -1` at
`bits-fix-09b569d1.c:185:24`, `nbytes=8`. That is a separate bug in the fix,
not the CVE OOB write; no wire consumer, command or r5. Details in brief §6
and `PROVENANCE.md`.

Additive wake 2026-11-26 ~18:03Z: Debian Code Search found one external
caller, `speex_1.2.1-4/debian/tests/bits-boundary.c:44`. Its exact source
(`pinned/debian-bits-boundary-1.2.1-4.c`, sha256 `a0161dcf…`) compiled against
the pinned builds: `harness/debian-boundary.sh` → 20 PASS / 0 FAIL rc 0,
ASan vulnerable `heap-buffer-overflow WRITE of size 1` at verbatim
`bits.c:184:25` from that external file's line 44; the test's own canary scan
reports `overwritten=8` and rc 1 on the vulnerable plain build versus
`overwritten=0` rc 0 on the fixed build; no ASan report on the fixed build.
This is a distribution regression test, not a live/network consumer, so the
r5 precondition remains UNKNOWN and the grade is unchanged. Details in brief
§6 and `PROVENANCE.md`.
