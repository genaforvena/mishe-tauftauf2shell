# frontier-pcre2jit2shell — STAGED: growable-JIT-stack underwrite writes subject pointers into a separate mapping (CVE-2026-103111)

Status: **STAGED in W285 (2026-11-26); rung 2 deterministic shipped-CLI crash
and rung 4 physical victim-mapping control exercised in unmodified pinned PCRE2
10.48; rung 5 NOT CLAIMED.** The clean-archive runner
`lab/frontier/pcre2jit2shell/run-all.sh` rebuilt both pinned releases and
reported `RESULT PASS=46 FAIL=0` at 19:31Z (`console.log`; hashes, traces and
negatives in the lab `PROVENANCE.md`). Charter, status report, seed wall and
two-pane window 194 (%392/%393, dead=0, registry 195/195 unique names) are
live; operator admission and independent witness replay are owed.

## Claim source and scope

- GitHub advisory `https://github.com/PCRE2Project/pcre2/security/advisories/GHSA-r9hj-j2rw-4q3m`
  (published 2026-09-28, High, CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L`,
  CWE-787) and CVE-2026-103111 (MITRE, published 2026-09-30). Both re-verified
  read-only on 2026-11-26. Affected `<= 10.48`, patched `10.49`. Advisory
  requires JIT matching with `pcre2_jit_stack_create()` +
  `pcre2_jit_stack_assign()` (a growable stack), attacker-controlled pattern,
  and a large single frame; 8/16/32-bit code units, all JIT platforms.
  Interpreter and DFA matching, and the default machine stack, are unaffected.
- Fix commit `2b4038298072684b0fae29b15bedfb1a75bda46d`
  ("Fix large JIT stack allocation", Zoltan Herczeg). Pinned tarballs:
  `https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.48/pcre2-10.48.tar.gz`
  SHA-256 `ebcc25aa…d46888` and `…/pcre2-10.49/pcre2-10.49.tar.gz` SHA-256
  `929f0b20…e557ae`; local fix.patch SHA-256 `38f740cb…b4165f`.
- Advisory attaches `pcre2_10_48_jit_stack_underwrite_poc.c`, SHA-256
  `2bda01bc0d70ac7888a8205aa9141e4bf8efcc0e7b48cc50eb23adca56756cd4`,
  fetched from `https://github.com/user-attachments/files/32262707/pcre2_10_48_jit_stack_underwrite_poc.c`
  and hashed locally before use. Its claimed result (139,976-byte deepest
  write, ~140k victim bytes changed, 15 subject-pointer words) is treated as a
  claim and reproduced below, not quoted as fact.

## Source-bound mechanism (read from pinned 10.48 bytes)

In `src/pcre2_jit_compile.c` of pinned 10.48, `STACK_GROWTH_RATE` is the
fixed 8192-byte increment (L102). `allocate_stack()` (L3525) subtracts the
whole frame from `STACK_TOP` at L3531 and only then emits a less-than check
against `STACK_LIMIT` (L3543). The shared resize stub at L14088 computes its
target as `STACK_LIMIT - 8192` and calls `sljit_stack_resize()` (L14092); it
never compares the already-lowered `STACK_TOP` with the new limit. A single
frame larger than the increment therefore leaves the bottom of the frame below
the granted stack, and the frame-initialization stores write there. The
advisory measures a 4,205-word (33,640-byte) frame for a recursive pattern
with 1,400 distinct referenced captures; PCRE2 10.47's capture-save
de-duplication makes the earlier repeated-capture trigger stop working, so the
10.48 trigger must use distinct captures.

The fix adds `large_stack_allocation`, set in `allocate_stack()` when
`size > STACK_GROWTH_RATE / (SSIZE_OF(sw) * 2)`, and for those patterns derives
the resize target from the actual `STACK_TOP` rounded down to the increment
boundary with half an increment of spare space. A too-large request then fails
before the generated code writes through the invalid top. The patch also adds
a regression line using `pcre2test`'s `\\=jitstack=192` with the 1,400-capture
pattern; that exact line is the lab's shipped-CLI input.

## Observed local reproduction (unmodified pinned builds, no synthetic caller)

- Shipped CLI, rung 2: `pcre2test evidence/regression-input.txt` on plain 10.48
  prints the pattern then **Segmentation fault (core dumped), rc 139**. The
  same line on plain 10.49 prints `Failed: error -46: JIT stack limit reached`
  and exits 0. `evidence/replay/` and `out/pcre2test-*.out` hold both traces.
- Physical-mode PoC, rung 4: compiled verbatim against the static library from
  the pinned 10.48 tarball. PCRE2 owns a 192 KiB JIT stack mapping; the PoC
  places a separate 1 MiB victim mapping immediately below it with
  `MAP_FIXED_NOREPLACE` (fails closed on collision), fills it with `0xa5`, and
  JIT-matches the 11,237-byte pattern against a 10-byte subject. Repeats:
  `pcre2_match returned -46`, **139,976 bytes clobbered**, **deepest write
  139,976 bytes below the JIT stack mapping**, **15 aligned words holding
  pointers into the subject buffer**. This is the same envelope the advisory
  claims, observed on this host, with a separate mapping, not a synthetic
  in-process marker.
- Controls: 10.48 interpreter (`--no-jit`): match 2 victim clean; 10.48 with a
  100-capture (small-frame) build: match 2, victim clean; pinned 10.49 JIT:
  match -46, victim clean, zero subject pointers; 10.49 interpreter: match 2,
  victim clean. `patch --dry-run` confirms the fix applies to pinned 10.48.

## Rung-4 feasibility and honest limits

Rung 4 is exercised: in the lab build, JIT-generated stores cross PCRE2's own
mapping into a separately mapped allocation at a deterministic depth and leave
15 aligned words pointing into attacker-provided subject data. Conditions: the
victim must be placed directly below the 192 KiB JIT stack (ASLR makes the
`MAP_FIXED_NOREPLACE` reservation fail on some runs; those attempts are
preserved and retried, never counted as passes); the PoC reads SLJIT's private
stack fields via a struct-representation copy solely to find the mapping
boundary, without modifying PCRE2/SLJIT state; the written words are JIT frame
state, so the observed values include subject-buffer pointers rather than
arbitrary attacker-chosen bytes. No control-flow target, command, socket,
live target process or wire request was exercised: **rung 5 NOT CLAIMED**.
Rung 3 (ASan-confirmed corruption) is also not claimed: the escaping stores are
emitted by JIT machine code into mmapped regions, and no ASan report is part of
the evidence. The advisory's network CVSS applies to applications that JIT
attacker-supplied patterns; this lab exercised a CLI and a local harness only.

## Cheapest next experiment

Drive the same pattern through a live loopback-only consumer that JIT-compiles
attacker regexes with a growable stack (for example a PHP-style request path or
a small C HTTP service built in `lab/frontier/pcre2jit2shell/live/`), with a
request-supplied subject and pattern. Observe whether a request crosses into a
second, legitimately allocated request object, then look for a chosen-offset
readback and a benign marker. Keep the current no-jit/small-frame/fixed
controls. No external target and no public probe; loopback only.

## Duplicate and backlog check

No `pcre2jit2shell` mind, brief or window existed before W285; `pcre2dfa2shell`
is a separate admitted PCRE2 DFA target and is not duplicated. The other
preserved candidate, GnuTLS DTLS CVE-2026-33846, remains unstaged. Advisory
prose is a claim; the hash-matched attachment and pinned tarballs are the
authority for this brief.
