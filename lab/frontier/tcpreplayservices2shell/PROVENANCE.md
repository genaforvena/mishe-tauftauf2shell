# tcpreplayservices2shell — provenance

## Claim sources (read-only provisioning)

- GHSA-fwcr-mqg6-hqmx / CVE-2026-102896, published 2026-07-24, High 7.8,
  CWE-121/CWE-787,
  https://github.com/appneta/tcpreplay/security/advisories/GHSA-fwcr-mqg6-hqmx.
  Claims an unbounded regex digit match copied with `strncpy()` into `port[10]`
  in `parse_services()` when `tcpprep -s/--services <file>` reads a crafted
  services file; reports ASan `WRITE of size 20` at `services.c:74`, offset 202
  past `[192, 202) 'port'`, with attacker-chosen digit bytes.
- Affected `<= 4.6.0-beta2`; patched `4.6.0-beta3`. Exact fix
  `e6e32ec70a38c777f8007374c36b40d38baeaf3e` (also fixes GHSA-5q26-7fxx-v8fh
  and GHSA-m6w7-8497-g9c9), patch read from
  https://github.com/appneta/tcpreplay/commit/e6e32ec70a38c777f8007374c36b40d38baeaf3e.patch.
  The relevant hunk clamps both copy lengths to `sizeof(port)-1` /
  `sizeof(proto)-1` and NUL-terminates each destination.

## Pinned bytes

- Vulnerable tag `v4.6.0-beta2` =
  `9d291ec9855fbb08271a59c3463ca4dc60787ad6`, `pins/vuln.tar.gz` SHA-256
  `6521487d6d7a96037db08cedf07bfd77c6ddee7aa5fb8e67fe1cfaf430b102fd`.
- Fixed tag `v4.6.0-beta3` =
  `e6e32ec70a38c777f8007374c36b40d38baeaf3e`, `pins/fixed.tar.gz` SHA-256
  `c3cea61d75bec87e35bef0ca7a23394418b4e10ca47cce8921344a58469dff1f`.
- Reference hunk `pins/fix.patch` SHA-256
  `96b9561cd665cc3996d7ab0ae3d7088cdac5724185dd0c04fc489a4da1775709`;
  derived from the two pinned trees with `git diff ... -- src/common/services.c`.
  Builds use the fixed tarball directly; no patch is applied at build time.
- All 10 harness, generator, pin and input hashes are in `HARNESS_SHA256.txt`,
  verified by `run-all.sh`.

## Build and observation

`bash bootstrap.sh` extracts both archives without path stripping (the archives
have no root prefix) and configures four CMake 3.28.3 builds with
`-DPYTHON3_EXECUTABLE=/usr/bin/python3`, targeting `tcpprep`. ASan builds use
`-O0 -g -fno-omit-frame-pointer -fsanitize=address -fno-sanitize-recover=all`
plus `-fsanitize=address` at link; plain builds use
`-O0 -g -fno-stack-protector -D_FORTIFY_SOURCE=0`. ASan leak detection is off
in the runner. `generate-inputs.py` writes the four pinned services files.
Inputs are single lines: 20 chosen `1` digits + `/tcp\n`, 11 chosen `2` digits
+ `/tcp\n`, and safe 5-digit/9-digit controls. The runner invokes the real
`tcpprep --services=<file> --port -i test/test.pcap -o <cache>` from each
extracted tree; `test/test.pcap` is the project's own capture and is required
only because `-i` is mandatory.

Observed in `runs/`: vulnerable ASan reports `WRITE of size 20` at
`src/common/services.c:74`, `Memory access at offset 202 overflows this
variable` for `[192, 202) 'port'`; the 11-digit input reports `WRITE of size
11` at the same site, the smallest possible excess. The fixed ASan build and
both safe inputs on both builds are clean. `strncpy-param-overlap`, which the
advisory reports for a ~1000-digit input, is absent at n=20 — a distinct second
defect, not the pinned claim.

`bash run-all.sh` returns rc 0 with `TOTAL: 12 PASS / 0 FAIL`. This is an
author-side reproduction, not independent witness acceptance.

## Grade and limits

R1 ✓ deterministic trigger; R2 ✓ observed ASan accounting failure at the exact
sink; R3 ✓ ASan-confirmed stack write of chosen digit bytes one-to-ten bytes
past `port[10]`; R4 LIMITED — chosen bytes at a chosen stack offset in the
vulnerable build, no saved-RIP value, branch target or marker execution
observed; R5 NOT CLAIMED — the path is a local CLI services file, not a wire
request, and no command side effect was produced. The plain build in this
stack layout emitted no malformed-protocol warning (the advisory saw one in a
4.5.3 build); that difference is preserved as a negative, not a fix. No
canary or ASLR measurements. No external system was contacted by a probe.

## Candidate context

W332 selected this candidate from the W331 scout backups because it has exact
tag pins, a one-file PoC and a clamped-fix control. Other W332 scout finds are
not staged here: pmacct `nfacctd` pre-auth IPFIX stack WRITE (issue #934, fix
`839d6ea5`, merged cap 128 does not exclude the reported len=50 — fixed control
unverified) and vgmstream `parse_txth()` `sscanf` overflow (CVE-2026-86514, fix
`4669d37a`, public fuzz input). They remain candidates for a later wake.

## Clean-archive replay (W332)

Stage commit `52bcb913`; pathspec archive SHA-256
`f8dfc7071d456ca0668695f52a653ba42b6e699d4478666e2fc6accbda74af30`. In a
clean extraction all 10 harness/pin/input hashes matched, unmodified
`bash bootstrap.sh` reported four `BUILD_OK` lines, and unmodified
`bash run-all.sh` returned rc 0 with `TOTAL: 12 PASS / 0 FAIL`. Summary log
SHA-256
`98b924412bb7bb7ae7d684ddd52446e0695d94cf9598e181e278f07ca4cc3f41` was
byte-identical to the in-tree summary. The clean tree needs a `runs/`
directory only for the outer redirection used to capture the summary;
`run-all.sh` creates it itself. Author replay, not witness acceptance.
