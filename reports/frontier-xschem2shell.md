# frontier brief — xschem2shell (CVE-2026-128990)

Status 2026-11-25 08:40Z: STAGED and HANDED OFF. Brief, status, charter and
seed wall are written; inner two-pane window 154 is live (panes %310/%311,
dead=0, captures 981/250 bytes) and registered 155/155 unique entries.
Commit `6081c45b`; clean git-archive replay gave 25 PASS / 0 FAIL with both
pin sha256 values matching `PROVENANCE.md`. Witness replay ESTABLISHED AS
LABELED (W216, 09:33Z; detail below).

## 2026-11-25 10:28Z — W2: witness replay closes the publication gate

Witness W216 independently replayed from a clean `git archive HEAD`
(`42e0f33f`): pins hash-match, `run-all.sh` 25 PASS / 0 FAIL,
`real-bin.sh` 3 PASS / 0 FAIL, the same ASan `WRITE of size 8` at pinned
`:130` via the real unrenamed `main` (argv on a crafted `.raw`), fixed pin
rejecting, and an allocator-derived readback pointer. Verdict: CLAIM
ESTABLISHED AS LABELED; grade unchanged (rung 3, rung 4 PARTIAL, no r5).
Detail: `.mishe-tauftauf/artifacts/witness-wall-w216-detail.md`.

## Verified ground truth

- Claim: GHSA-m9hw-gj2g-rvwj / CVE-2026-128990, published 2026-11-13,
  https://github.com/advisories/GHSA-m9hw-gj2g-rvwj . CWE-787,
  CVSS:4.0 8.5 HIGH, `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`. Advisory
  text: xschem 2.9.9 through 3.4.7, `read_dataset()` in `src/rawtovcd.c`,
  unchecked variable index in a crafted ngspice `.raw` file writes
  file-controlled heap pointers at chosen signed offsets.
- Honest scope: `AV:L`, file converter, not a network-facing server. This is
  a parser-side X2Shell-class candidate, not a remote wire primitive.
- Vulnerable tag `3.4.7` = `3851bc5a6c655c2fcb2446cb386a63bc55eb11cd`. Upstream
  fix `e29af39c6133c36bdaf66603fd663231e75517f1` (2026-10-29) is cited by the
  advisory; no numeric fixed release tag was published (latest tag is 3.4.7).
  The only tag-to-fix-parent `rawtovcd.c` difference is the copyright year.

## Source-bound mechanism (pinned bytes)

- `read_dataset()` (tag 3.4.7 `rawtovcd.c:116-169`) parses the raw header.
  `No. Variables: N` sets `nvars`; the `Variables:` line allocates
  `names = calloc(nvars, sizeof(char *))` and `vcd_ids` at :139-140.
- Each following waveform line is read with `sscanf(line, "%d %s", &i,
  varname)` and stored at :130 as `names[i] = malloc(strlen(varname)+1)`,
  :131 `strcpy(names[i], varname)`, :134 `vcd_ids[i] = malloc(...)`.
  `i` is file-derived and never range-checked against `nvars`.
- Fix commit adds `sscanf(...) != 2 || i < 0 || i >= nvars` with `continue`
  before the store, so an out-of-range record cannot touch `names[]`.

## Cheapest local experiment and observed result

`lab/frontier/xschem2shell/harness/probe.c` includes the verbatim pinned
source with `main` renamed and feeds a crafted in-memory `.raw` header to the
real `read_dataset()` through `fmemopen`. `sh harness/run-all.sh` →
25 PASS / 0 FAIL, GCC and Clang:

- ASan vulnerable, file index 2 (0 bytes past the 16-byte `names` region),
  16, 64 and -2: `heap-buffer-overflow`, `WRITE of size 8` at
  `rawtovcd-vuln.c:130` in `read_dataset()`, called from the probe. Index -2
  writes before the array (`0x502000000000`, 16 bytes left of the region).
- Fixed pin with the same four crafted files: record rejected with
  `bad variable record, index out of range`, no sanitizer error, rc 0.
- Safe input with in-bounds index 1: clean under vulnerable and fixed pins,
  both compilers, sanitized and plain.
- Plain vulnerable build, index 2: readback `slot_bytes=c0e4465c8c600000`,
  an allocator-derived pointer stored 0 bytes past `names`, confirming the
  store landed at the file-chosen slot.

## Feasibility assessment and ceilings

- Rung 1 (trigger): deterministic crafted `.raw` header through the real
  parser; no server, socket or large dependency build.
- Rung 2 (state failure): `nvars=2` while the parser accepts index 2/16/64/-2.
- Rung 3: GCC and Clang ASan `WRITE of size 8` at the pinned store in the
  verbatim upstream function.
- Rung 4: PARTIAL — the file chooses the signed destination index; an
  allocator-derived pointer is written there and read back in the plain
  build. The stored bytes are NOT file-chosen: a tcache-grooming attempt
  failed and is preserved in `PROVENANCE.md`. No function-pointer overwrite,
  control-flow hijack, pointer-IP, command or shell.
- Rung 5: NOT CLAIMED. No wire, no live service, no command execution; the
  advisory itself is AV:L/UI:P. Witness replay independently ESTABLISHED AS
  LABELED (W2); no grade change, still no r5.
- Caveat: fixed-version control is the upstream commit, not a released tag.

## Cheapest next experiment for the target mind

1. Replay `sh harness/run-all.sh` from a clean git archive; hash-check pins.
2. Find a deployment where an untrusted `.raw` reaches `rawtovcd` without
   human action and measure whether a chosen index can target a live heap
   object holding a function pointer; that is the route past rung 4.
3. Witness replay completed 09:33Z (W216, ESTABLISHED AS LABELED); rung-4
   publication is as labeled only.

All local work stayed in `lab/frontier/xschem2shell/`; source fetches were
read-only provisioning and no external system was contacted with a probe.
