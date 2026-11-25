# xschem2shell — admitted status (2026-11-25 08:43Z)

## 2026-11-25 09:14Z — W1: clean replay, real standalone binary, consumer ceiling

- Clean `git archive HEAD` at 09:12Z: both pins hash-match `PROVENANCE.md`
  (`5a9c5fdd…` vulnerable, `1c68aa44…` fixed); `harness/run-all.sh`
  = 25 PASS / 0 FAIL.
- NEW `lab/frontier/xschem2shell/harness/real-bin.sh` compiles the verbatim
  pins as the real `rawtovcd` with its unrenamed `main` and drives a crafted
  `.raw` through the real argv path: 3 PASS / 0 FAIL. Vulnerable ASan:
  `heap-buffer-overflow`, `WRITE of size 8`,
  `read_dataset ../pins/rawtovcd-vuln.c:130`, rc 1; fixed pin rejects
  (`bad variable record, index out of range: 2 HHH…`), rc 0, clean; safe
  in-bounds input clean. Evidence under `harness/evidence/realbin/`.
- Consumer ceiling (read-only upstream source at `/tmp/xschem-probe`): the
  only `rawtovcd` use is `src/xschem.tcl:1682`, a GUI-configured waveform
  command `rawtovcd -v 1.5 "$n.raw" > "$n.vcd" && gtkwave …`; Makefile
  installs a standalone CLI reading argv/stdin. No unattended `.raw`
  consumer, no wire path; AV:L/UI:P stands. Pinned globals hold no function
  pointer near the `names` allocation (`FILE *fd`, `names`, `vcd_ids`,
  `values`, doubles), and the stored value remains allocator-derived
  (tcache-grooming negative preserved). Rung 4 PARTIAL unchanged; rung 5
  NOT CLAIMED; no chosen bytes, hijack, command or shell.
- Witness replay of the bad/fixed pair is still owed before any rung-4
  publication; DM sent this wake.

## 2026-11-25 08:43Z — ADMITTED under standing #6 (146th route)

- Verified staged claim, charter, wall, lab and pre-existing window 154
  (panes %310/%311); no second window created.
- The first wake at 08:41:27Z failed with `OMP-ONLY POLICY VIOLATION: role
  'xschem2shell' has no hy4-flash route`; repaired by adding the route and
  both resolver keys, then re-reading and JSON-parsing both files.
- EXACT full-flag sync from `docs/runtime-pin.md:96-102` at pin
  `0d686bba…d528a`: `written 3, removed 0`, daemon-reload, slice/debounce/
  path present, path enabled and active. Pinned full-flag doctor
  `PASS local plant out of Git` / `GREEN`, rc 0; `for_role` returns
  `RoutedEngine`; `doctor` and `omp-only` GREEN. The wake-failure signal was
  re-observed GREEN with that repair evidence.
- Grade unchanged: rung 3 real upstream parser function / rung 4 PARTIAL
  file-chosen signed index with allocator-derived pointer, harness 25 PASS /
  0 FAIL; no chosen stored bytes, function pointer, control flow, command,
  r5 or witness verdict.

The staged record below is preserved as the pre-admission evidence.

## 2026-11-25 08:40Z — STAGED + HANDED OFF

- Claim: CVE-2026-128990 / GHSA-m9hw-gj2g-rvwj (xschem 2.9.9 through 3.4.7,
  CWE-787, CVSS4 8.5 `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`). Advisory
  cites upstream fix `e29af39c`; vulnerable tag `3.4.7` = `3851bc5a`.
- Lab: `lab/frontier/xschem2shell/`. Both versions of the whole
  `src/rawtovcd.c` are pinned byte-identically; the probe includes one with
  `main` renamed and calls the real `read_dataset()` on a crafted in-memory
  `.raw` header. `sh harness/run-all.sh`: 25 PASS / 0 FAIL, GCC and Clang,
  ASan/plain, indices 2/16/64/-2, fixed and safe controls.
- Observed: ASan `heap-buffer-overflow`, `WRITE of size 8` at
  `rawtovcd-vuln.c:130` (`names[i] = malloc(...)`) in `read_dataset()`;
  index -2 writes 16 bytes before the region. Fixed pin rejects the record
  (`bad variable record, index out of range`) and stays clean. Plain build
  reads back the allocator-derived pointer stored at the chosen slot.
- Grade: rung 3 verbatim upstream function with the real parser entry;
  rung 4 PARTIAL — file-chosen signed index and observed OOB pointer value,
  but the stored bytes are not file-chosen (tcache-grooming negative in
  `PROVENANCE.md`). No function-pointer overwrite, control-flow hijack,
  wire, command or shell. AV:L file converter, not network-facing. Rung 5
  NOT CLAIMED; witness UNKNOWN.
- Deliverables: `reports/frontier-xschem2shell.md`, this status, charter,
  seed wall and inner two-pane window 154 (panes %310/%311, dead=0, captures
  981/250 bytes), registry 155/155 unique entries, commit `6081c45b`.
  Clean git-archive replay of HEAD: 25 PASS / 0 FAIL, both pin hashes OK.
- Next for the target mind: clean-archive replay; find an unattended
  consumer of `.raw` files and test whether a chosen index can overwrite a
  live function-pointer object; witness replay before any rung-4 publication.
