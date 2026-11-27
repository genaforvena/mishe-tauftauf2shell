# Frontier brief: tcpreplayservices2shell — unbounded services-file stack write

**Status: STAGED for operator admission (W332, 2026-11-27).** Claim is a
high-severity local stack write in the real `tcpprep` CLI, pinned between
upstream tags `v4.6.0-beta2` and `v4.6.0-beta3`. The reproducible lab is
`lab/frontier/tcpreplayservices2shell/`; a live registered two-pane handoff
window is recorded in `.mishe-tauftauf/operator/window-registry.json` after the
stage commit. Author evidence is not independent acceptance.

## Verified ground truth

- Claim source: GHSA-fwcr-mqg6-hqmx / CVE-2026-102896, published 2026-07-24,
  High 7.8, CWE-121/CWE-787,
  https://github.com/appneta/tcpreplay/security/advisories/GHSA-fwcr-mqg6-hqmx.
  Affected `<= 4.6.0-beta2`; patched `4.6.0-beta3`. Trigger: victim runs
  `tcpprep -s/--services <attacker-influenced file>`; no authentication,
  privileges or network access.
- Pinned bytes: vulnerable tag `v4.6.0-beta2` =
  `9d291ec9855fbb08271a59c3463ca4dc60787ad6`, fixed tag `v4.6.0-beta3` =
  `e6e32ec70a38c777f8007374c36b40d38baeaf3e`. The fix commit
  `e6e32ec70a38c777f8007374c36b40d38baeaf3e.patch` was read directly; it
  bundles three memory-safety fixes, of which the services hunk belongs to
  this GHSA. Advisory claim-source reading is read-only provisioning; no
  external system was probed.
- Grade: R1 / R2 / R3 ✓; R4 LIMITED; R5 NOT CLAIMED.

## Source-bound mechanism

Pinned vulnerable `src/common/services.c:35-90`, inside `parse_services()`:

```c
char service_line[MAXLINE], port[10], proto[10];
...
if ((regexec(&preg, service_line, nmatch, pmatch, 0)) == 0) {
    strncpy(port, &service_line[pmatch[1].rm_so], (pmatch[1].rm_eo - pmatch[1].rm_so));
    strncpy(proto, &service_line[pmatch[2].rm_so], (pmatch[2].rm_eo - pmatch[2].rm_so));
```

The regex is `"([0-9]+)/(tcp|udp)"`: the digit group is unbounded, while the
`strncpy` count is the regex match length, not `sizeof(port)`. A line of 20
digits + `/tcp` writes 20 chosen bytes into the 10-byte `port[]`. The fix
computes `portlen`/`protolen`, clamps each to `sizeof(...) - 1` and writes an
explicit NUL. The second defect in the advisory, `strncpy-param-overlap` for
~1000-digit inputs because the destination range reaches `service_line`, is
distinct and not the pinned claim.

## Locally observed evidence

`bash bootstrap.sh` builds four CMake variants: vulnerable/fixed, ASan/plain.
`bash run-all.sh` invokes the unmodified real `tcpprep` from each extracted
tree on `inputs/digits20.services` (20 `1` digits + `/tcp\n`) with the
project's own `test/test.pcap` supplying the mandatory `-i`.

- Vulnerable ASan: `ERROR: AddressSanitizer: stack-buffer-overflow`,
  `WRITE of size 20`, frame `parse_services ... src/common/services.c:74`,
  `[192, 202) 'port' (line 37) <== Memory access at offset 202 overflows this
  variable`. The 11-digit input gives `WRITE of size 11` at the same site —
  the smallest possible excess. `strncpy-param-overlap` is absent at n=20.
- Fixed ASan on both long inputs: no sanitizer report, rc 0. Safe 5-digit and
  9-digit inputs: no sanitizer report on either pinned tree.
- Plain vulnerable build emitted no malformed-protocol warning in this stack
  layout; the advisory saw one in its 4.5.3 build. Preserved as a negative,
  not treated as safety.
- Pins, harness and inputs are hashed in `HARNESS_SHA256.txt` (10 entries);
  `bash run-all.sh` returns `TOTAL: 12 PASS / 0 FAIL`. Grades: chosen digit
  bytes land at a chosen stack offset, but no saved-RIP value, branch target,
  marker or command was observed. No wire path, canary or ASLR measurement.

Evidence lives in `lab/frontier/tcpreplayservices2shell/runs/` and the full
chain is in that lab's `PROVENANCE.md`.

## Duplicate check and disposition

No tcpreplay target, window or screened entry exists in the wall's do-not-
duplicate or SCREENED OUT lists, nor in `reports/frontier-*.md`. This is a
distinct sink from the staged `tcpreplay`-family entries (none) and from the
other 2026-07-24 tcpreplay fixes in the same commit (ARP rewrite, `--pktlen`),
which are not claimed here. The advisory's other candidate findings from
W332 are preserved as backups, not staged: pmacct `nfacctd` pre-auth IPFIX
stack WRITE (issue #934, merged fix `839d6ea5` caps at 128 and therefore does
not exclude the reported len=50 — fixed control unverified) and vgmstream
`parse_txth()` `sscanf` overflow (CVE-2026-86514, fix `4669d37a`, public fuzz
input).

## Cheapest next rung-4 experiment

Drive the same pinned `tcpprep` binary under GDB or an unprotected build to
show the chosen digit bytes overwriting `proto[10]` and the resulting
`services->tcp[]` accounting change, with fixed and safe-input controls. A
saved-RIP overwrite would additionally require a much longer digit run,
where the advisory observed the separate `strncpy-param-overlap` defect;
do not conflate the two. R5 stays NOT CLAIMED: this is a local CLI file path
with no wire input or command side effect.
