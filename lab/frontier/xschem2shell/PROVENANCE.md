# xschem2shell — provisioning and pin provenance

- Advisory: CVE-2026-128990 / GHSA-m9hw-gj2g-rvwj, published 2026-11-13,
  https://github.com/advisories/GHSA-m9hw-gj2g-rvwj , CWE-787,
  CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H (8.5 HIGH).
  Description names `read_dataset()` in `src/rawtovcd.c` and unchecked
  variable index from a crafted ngspice `.raw` file.
- Upstream: https://github.com/StefanSchippers/xschem.git , read-only clone
  into `/tmp/xschem-probe`, fetched 2026-11-25. No probe against any external
  system; all runs are local in `harness/`.
- Vulnerable pin: tag `3.4.7` = `3851bc5a6c655c2fcb2446cb386a63bc55eb11cd`,
  `src/rawtovcd.c` sha256 `5a9c5fdd27171e5c647b3face0bb02f76b21891ed4d0c3eb1cc88884c7e79314`.
- Fixed pin: upstream master `e29af39c6133c36bdaf66603fd663231e75517f1`
  (2026-10-29, "fix a couple of reported out of bound memory access on
  malformed input files"), `src/rawtovcd.c` sha256
  `1c68aa44851eaf67e4607c594fe10fcd0cd6c09a51e8de109d575108b46a4d85`.
  Between the tag and the fix parent the only `rawtovcd.c` difference is the
  copyright year, so the vulnerable code is byte-identical to the fix parent.
- Fix hunk (`rawtovcd.c:129`): `sscanf(line, "%d %s", &i, varname)` became
  `if (sscanf(...) != 2 || i < 0 || i >= nvars) { warn; continue; }` before
  `names[i] = malloc(strlen(varname) + 1)`. The same commit also hardens
  `src/save.c`; that second site is not exercised here.
- `pins/rawtovcd-vuln.c` and `pins/rawtovcd-fixed.c` are byte-identical `git
  show` extractions. `harness/probe.c` includes one of them verbatim with
  `main` renamed and calls the real `read_dataset()` on a crafted in-memory
  `.raw` header via `fmemopen`; no pinned source line is edited.
- `harness/run-all.sh`: GCC and Clang, ASan and plain, indices 2/16/64/-2
  plus in-bounds safe index 1, vulnerable and fixed pins. 25 PASS / 0 FAIL.
  Evidence in `harness/evidence/`.
- Negative result preserved: an attempt to make the OOB pointer value
  file-chosen by priming three same-size-class tcache chunks failed — glibc
  `calloc(2, 8)` did not consume the primed chunks, so the stored value is an
  allocator-derived heap pointer. The claim below is chosen *index* and
  observed OOB pointer value, not file-chosen bytes.

## W1 additions (2026-11-25 09:14Z)

- `harness/real-bin.sh` compiles `pins/rawtovcd-vuln.c` and
  `pins/rawtovcd-fixed.c` with GCC ASan as the real standalone `rawtovcd`
  (unrenamed `main`) and feeds a crafted `.raw` file through argv.
  3 PASS / 0 FAIL: vulnerable rc=1 with `heap-buffer-overflow`,
  `WRITE of size 8`, `read_dataset ../pins/rawtovcd-vuln.c:130`; fixed rc=0
  with `bad variable record, index out of range: 2 HHH…`, no sanitizer
  error; safe in-bounds input clean. Outputs in `harness/evidence/realbin/`.
- Consumer search in the read-only upstream checkout: `rawtovcd` appears in
  `src/Makefile.in` (standalone CLI build/install), `src/rawtovcd.c` itself
  and one GUI default at `src/xschem.tcl:1682`
  (`rawtovcd -v 1.5 "$n.raw" > "$n.vcd" && gtkwave …`). No unattended
  `.raw` consumer and no socket path were found; AV:L/UI:P ceiling stands.
  The pinned globals (`FILE *fd`, `names`, `vcd_ids`, `values`, doubles)
  place no function pointer adjacent to `names`; the stored pointer is
  allocator-derived, so no function-pointer overwrite was observed.
