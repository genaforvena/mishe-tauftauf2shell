# PROVENANCE — open1722vss2shell

Staged by frontier W262 (2026-11-26). Sources fetched read-only from
GitHub/codeload; no external target was contacted. All tests are in-process
frame builds; no socket, listener, AVTP wire session or command execution.

## Claim and upstream pins

- CVE-2026-136616 / GHSA-xvmx-7qq5-34q6, published by VulnCheck 2026-11-25:
  COVESA Open1722 before 0.9.8, out-of-bounds read in
  `Avtp_Vss_CalcVssPathLength()` (`src/avtp/acf/custom/Vss.c`), LOW / CVSS 2.3
  / CWE-125. The advisory's "attackers can send frames" wording is a claim;
  the local evidence is an in-process header build.
- `git ls-remote https://github.com/COVESA/Open1722.git`: `v0.9.7 =
  b78c3877bcf0258c76fdaca7f4551e58b708b7ce`, `v0.9.8` and HEAD both
  `714067b0134cf36f89464dbc6ec25529c0e189c7` (lightweight tag = fix commit).
- Both tarballs came from codeload by commit SHA; the patch came from the
  fix-commit `.patch` URL.

## SHA-256 pins

| Artifact | SHA-256 |
| --- | --- |
| `src/vuln.tar.gz` (codeload `b78c3877…`, v0.9.7) | `da6b4636298a065de1d60f602cc80916331306a9dfd26b3aa8f01a6ffcb4867f` |
| `src/fixed.tar.gz` (codeload `714067b0…`, v0.9.8) | `1fad12744011da2b149c2c46b2012c6be72f87acb2995df52040e7e392d29af3` |
| `src/714067b0.patch` (fix commit patch) | `888948c60a3a587e5028df2b86d1aa46507e2071bf66d53ec4d1b3c9fa3917fe` |
| `poc.c` (public-API driver) | `ec04c8a21a900c6f1ce208e2c2931dafb7c88dacdeed21d6fe6fc471a9609a67` |
| extracted vulnerable `src/avtp/acf/custom/Vss.c` | `487900680d54911ff205a9639d693982c8536485b5d62d499dd9852d7e1f7249` |
| extracted fixed `src/avtp/acf/custom/Vss.c` | `6f85ac224b55e83c85e167b714aae01164ccaf2207ecb54149b42be1941ce9b0` |
| `run-all.sh` (canonical replay wrapper) | `5da4f917cc7b5d9e8f04a1d7dfccc6ba6acff132ff3d2cee0eeb73ebc1a72a52` |

The runner rechecks every pin on each invocation, asserts that
`CalcVssPathLength()` begins at `Vss.c:295` (vulnerable) and `Vss.c:294`
(fixed), asserts the vulnerable raw-prefix read and unchecked setter offset,
asserts the fixed clamp/overflow/no-op hunks both in source and in the pinned
patch, and rebuilds with GCC and Clang under ASan and plain.

## Observed results

`evidence/run-all-console.log`: **RESULT PASS=34 FAIL=0**, rc 0, finished
10:57:29Z. Vulnerable GCC+Clang ASan reports `READ of size 2`, `0 bytes after
12-byte region`, at `Vss.c:307` via `vss_load_be16` (`Vss.c:66`) for a
header-only INTEROP frame. Fixed builds return `0` for that frame and for the
`0xFFFF` prefix; vulnerable builds return `16708` for chosen adjacent bytes
`0x41 0x42`, and return `1` for `0xFFFF`, then the setter writes chosen `0x5a`
at offset 13 in the path area. Well-framed safe input gives length 6 and a
write at offset 18 in both builds, with no ASan report.

Author clean-archive replay: `git archive f52dd1b5` (stage commit) unpacked to
`.mishe-tauftauf/replays/open1722vss2shell-w262/`, unmodified runner re-run at
11:00:55Z, rc 0 and `RESULT PASS=34 FAIL=0`, runner SHA-256 unchanged. Witness
replay is still owed; author replay is not independent acceptance.

## Negatives and limits

- First runner invocation scored 30 PASS / 4 FAIL: two plain-build assertions
  searched for `wrap b13=…` but the driver prints `wrap b12=ff b13=…`. The
  logs showed the expected bytes; the assertions were corrected, not the
  evidence. No source or pin changed.
- ASan redzones make the header-only read a fault, so the chosen adjacent-byte
  case uses a 14-byte allocation with the declared ACF length still 12; it
  demonstrates the unchecked read but is not an ASan heap overflow itself.
- The wrap-driven overwrite is inside the allocation (path area), not an
  out-of-bounds write; calling it OOB WRITE would overstate the result.
- No named neighbor object, pointer control, AVTP wire path, loopback service,
  command execution or r5. The 12-byte frame is built in-process from the
  public API.
- Unstaged build output under `src/out/` and extracted trees under `src/vuln/`
  and `src/fixed/` are local and reproducible from the pinned archives.
