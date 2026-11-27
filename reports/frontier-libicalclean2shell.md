# Frontier brief: libicalclean2shell — CVE-2026-134761 (`icalparser_clean()` ownership UAF/double free)

**Status: STAGED W300, 2026-11-27.** Rung 1 reproducible plain crash,
rung 2 parser-ownership state failure, rung 3 ASan-confirmed heap-use-after-free,
and **rung 4 LIMITED** chosen-byte branch control in a local public-API harness.
**Rung 5 NOT CLAIMED.** No wire consumer, remote input, command execution,
arbitrary pointer dereference or independent witness verdict yet.

## Verified ground truth (claim sources read 2026-11-27)

- **Claim sources:** canonical CVE record
  `https://www.cve.org/CVERecord?id=CVE-2026-134761` (CNA VulnCheck, published
  2026-11-22), GitHub Advisory Database
  `https://github.com/advisories/GHSA-p95w-9p65-m226` (unreviewed NVD import,
  published 2026-11-23), upstream issue
  `https://github.com/libical/libical/issues/1444`, fix PR
  `https://github.com/libical/libical/pull/1448`, fix commit
  `https://github.com/libical/libical/commit/6c48980adfda60abba4827ed76c8cfb8e943cb72`,
  and release `https://github.com/libical/libical/releases/tag/v4.0.7`.
- **Versions:** CVE affected `< 4.0.7`; vulnerable representative tag `v4.0.6`
  resolves to `9cfca65c122fa23b9680a28e0c9225a2fd015fc5`; fixed release tag
  `v4.0.7` resolves to `cb58c3cb287bee48aa50cc60753155116a8f9081`. The issue
  reporter says the same code exists from 1.0.0 through 4.0.6 and remains in
  the 3.0 branch; a fixed 3.0-series release is **UNKNOWN**.
- **Claimed primitive:** CWE-415 double free, CVSS 5.8 v4.0 and v3.1
  (`AV:L/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:H`). Truncated iCalendar input ends
  with an open component. `icalparser_clean()` returns that component while
  retaining the same pointer in `parser->root_component`; the documented caller
  frees the return value, then `icalparser_free()` frees it again.
- **Fix mechanism (source-bound):** final merged commit `6c48980a` adds
  `icalcomponent *result = parser->root_component; parser->root_component = 0;`
  after the component-stack loop and returns `result`. Its parent is
  `35ec667d5529c169cce354a9f54fbd2b2d56b08d`, not v4.0.6; intervening 4.0-branch
  commits drifted raw line numbers and added parser-state resets. The precise
  patch pair is fix-parent → fix-commit; v4.0.6 and v4.0.7 are the release
  representatives used for the local differential.

## Source-bound mechanism (verbatim pins)

`lab/frontier/libicalclean2shell/pins/vuln/src/libical/icalparser.c` is the
verbatim file at v4.0.6 (SHA-256
`056c0db94ae7dea08495052730625918a1850ca5f3741553613a10db25e767b2`);
`pins/fixed/.../icalparser.c` is v4.0.7 (SHA-256
`a3025d68a95ae13671bd8889d6e452ffc881707cb146a327496d863f1c3d1dfa`). Also
pinned: both `icalparser.h`, `icalcomponent.c`, and `icalmemory.c`; all hashes
are in `pins/PIN_HASHES.txt`.

- Vulnerable raw `:112-117`: `icalparser_free()` checks
  `parser->root_component` and calls `icalcomponent_free()` on it.
- Vulnerable raw `:1169-1196`: `icalparser_clean()` force-closes components on
  the stack, assigns `parser->root_component = icalpvl_pop(...)`, then
  `return parser->root_component;` at `:1196` without clearing the field.
- Vulnerable raw `:818-820`: the normal completed-input path already does
  `rtrn = parser->root_component; parser->root_component = 0; return rtrn;`.
- Fixed raw `:1195-1204`: `result = parser->root_component`;
  `parser->root_component = 0`; parser state is reset; `return result;`.
- Vulnerable `icalcomponent.c:191-231`: the second free reads `c->parent` at
  raw `:197`. The ASan allocation is a 72-byte component; `parent` is at offset
  48. A zero parent continues into the double free; a nonzero parent returns.

## Local observation (2026-11-27 W300)

Toolchain: Ubuntu clang 18.1.3, CMake 3.28.3, static libical core target,
`-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer`, ICU 74.2,
glibc 2.39. The public issue attachment is preserved verbatim as
`reproducer.zip` (SHA-256
`1c7618d759d321586b83790ac8a768aa7b1b415f3d36f4f15a9c06097e74e1d5`);
`05-uaf-clean-ownership.c` is unmodified (SHA-256 `92c6bd35…`).

`sh run-all.sh` at 00:16Z: **PASS=57 FAIL=0**, rc 0
(`runs/run-all.log`).

- **Rung 1:** plain v4.0.6 `clean-free-destroy` exits **139**. Three additional
  runs also exited 139 (`runs/plain-repeat.log`); the complete-calendar control
  exits 0.
- **Rung 2:** on vulnerable v4.0.6, `clean-inspect-twice` and
  `clean-free-twice` print `second clean returned the same pointer: yes` for
  both truncated and unclosed-child inputs. Fixed v4.0.7 prints `no`. This is
  an observed parser-ownership state failure, not an inference from source.
- **Rung 3:** all eight vulnerable attack combinations (four interrupted-input
  modes × two input shapes) produce ASan `heap-use-after-free`. The canonical
  trace is `READ of size 8` at `icalcomponent.c:197` via `icalparser.c:117`,
  48 bytes inside a 72-byte region allocated at `icalparser_add_line` and freed
  by the caller at reproducer line 95. Fixed v4.0.7 is clean for all ten
  mode/shape combinations; vulnerable complete-input controls are clean.
- **Rung 4 LIMITED:** `rung4_reclaim.c` frees the returned component, then uses
  the next same-size `malloc(72)` to reclaim the exact chunk. The harness prints
  `REUSE=1`. Zeroing offset 48 makes the stale second free crash (rc 139);
  writing chosen `0x4141414141414141` at offset 48 makes it survive (rc 0).
  GDB, without modifying execution, observes the stale call:
  `OBSERVED_FREE c=<same address> parent=0x4141414141414141`.
  Fixed v4.0.7 reclaims the same chunk in both zero and chosen controls but
  never calls the stale sink and exits 0. This demonstrates chosen bytes at a
  chosen offset controlling a benign consumer branch under a named grooming
  condition; it is not arbitrary code execution or a remote primitive.

## Rung-4 feasibility and limits

- **Rung 1 / rung 2 / rung 3 observed** only for the pinned v4.0.6 public-API
  lifecycle and the exact local build above.
- **Rung 4 LIMITED observed** in `rung4_reclaim.c`: glibc tcache returns the
  just-freed 72-byte component to the next same-size allocation; the chosen
  nonzero `parent` at offset 48 selects `icalcomponent_free()`'s early return.
  ASan's quarantine prevents this reuse, so the rung-4 control intentionally
  uses plain builds. GDB observes the bytes; it does not force the branch.
- **Rung 4 full NOT CLAIMED.** No arbitrary read/write, pointer dereference,
  code pointer, chosen offset outside the fixed component layout, or benign
  marker execution was observed. The nonzero-parent branch avoids damage; it
  does not by itself yield exploitation.
- **Rung 5 NOT CLAIMED.** The trigger is a truncated iCalendar document fed to
  the library API. No live server, socket, loopback request, remote process or
  command was exercised.

## Cheapest local experiment that can move this target higher

1. Find or build a real loopback consumer that parses attacker-supplied
   iCalendar and follows the documented `icalparser_clean()` ownership
   contract. Measure vulnerable/fixed crash or reuse differential through that
   consumer; keep all traffic on 127.0.0.1.
2. In that consumer, measure whether attacker-influenced same-size allocations
   between `icalcomponent_free(first)` and `icalparser_free(parser)` reclaim
   the component and which fields are consumed. The current branch control is
   only the first such measurement.
3. A fixed 3.0-series release, if one appears, needs its own pin and replay.
   Do not infer it from the 4.0 fix.

## Ranking note (W300)

CNA and GHSA scouts independently ranked this same unowned candidate first.
Exact release tags, a four-line ownership fix, an unmodified public reproducer,
a small static build and a measured rung-4 branch differential made it more
tractable than the VVdeC read-only backup. PatchHunt also found c-blosc2
CVE-2026-133709 with an upstream regression test, but no local bytes were
observed there this wake. No prior `libical`, `icalparser`, `icalcomponent`,
CVE-2026-134761 or GHSA-p95w-9p65-m226 target/report/charter existed at staging.
