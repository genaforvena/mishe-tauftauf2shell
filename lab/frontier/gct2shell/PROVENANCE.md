# PROVENANCE — Gct2Shell (CVE-2026-123975)

All sources below were fetched read-only from public origins on 2026-11-21;
nothing outside loopback was probed or contacted with a trigger.

## Upstream pins (SHA-256 of the exact bytes stored in `src/`)

| Artifact | Origin | SHA-256 |
| --- | --- | --- |
| `src/tokens_f.vuln.c` (affected, fix commit parent `edf946b55460b6730e174f2f68f5340ab2f9bd15`) | `https://raw.githubusercontent.com/gridcf/gct/edf946b55460b6730e174f2f68f5340ab2f9bd15/gsi/gss_assist/source/tokens_f.c` | `469c81f0c614f66587324afba11b508c966e25a462781238539dd9ec6b0d103e` |
| `src/tokens_f.parent.c` (same parent, fetched by explicit SHA) | same URL | `469c81f0c614f66587324afba11b508c966e25a462781238539dd9ec6b0d103e` |
| `src/tokens_f.fixed.c` (fixed, commit `3df2be4834c146bdcec90009a0f2e5771ff63cca`) | `https://raw.githubusercontent.com/gridcf/gct/3df2be4834c146bdcec90009a0f2e5771ff63cca/gsi/gss_assist/source/tokens_f.c` | `176658224d1d5da27ac7382207a4ff9f533aa2450c3f9dc45f7f085988e216ba` |
| `src/fix.patch` (upstream fix commit patch) | `https://github.com/gridcf/gct/commit/3df2be4834c146bdcec90009a0f2e5771ff63cca.patch` | `ae6e79bb7f2c927ea16f99f632fe74d020495021348a849dfdda679f302015cc` |
| `src/cve.json` (CVE Program record) | `https://cveawg.mitre.org/api/cve/CVE-2026-123975` | `0ac50b2d9028b647fe2180f89af6b94d3a2a683c3e96664c4954fbd1211143b6` |
| `src/advisory.html` (vendor advisory, 2026-11-11) | `https://gridcf.org/` | `fe21a3eb97bcb6218d5d417da5fc717577cd4a18735a3d39ab594b2e22662caa` |
| `src/release-notes.html` (fixed release) | `https://github.com/gridcf/gct/releases/tag/v6.2.20261111` | `084f101f7948778d1b94807ab8ffee9a0aa13b5af7f2cf3607d33562d9b6375d` |
| `src/gct-6.2.20190829.tokens_f.c` (independent old-tag cross-check) | `https://raw.githubusercontent.com/gridcf/gct/v6.2.20190829/gsi/gss_assist/source/tokens_f.c` | `6e62c9dc219af9b24399532c28459d5a36eff9cfee0191b22d7f303eacd3c354` |

Fix commit `3df2be4834c146bdcec90009a0f2e5771ff63cca` was committed
2026-11-10T18:17:39Z with parent `edf946b55460b6730e174f2f68f5340ab2f9bd15`
(verified through the GitHub commit API). The parent file carries the bug and
the commit file carries the guard; both were fetched as raw bytes, hashed and
stored. The 2019 tag is an extra source-bound cross-check only: it is not the
harness base and differs from the 2026 parent.

CVE-2026-123975: CNA VulnCheck, published 2026-11-13, CWE-787,
CVSS 4.0 8.7 High `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`,
CVSS 3.1 7.5 High. Affected GCT before 6.2.20261111 / globus-gss-assist before
12.9; fixed in 12.9 / GCT 6.2.20261111. The vendor names globus-gatekeeper and
myproxy as consumers. Credit: Deus Rex research team.

## Source-bound statements copied verbatim by `gen_driver.py`

The generator emits the whole function body (affected `tokens_f.c:49-227`,
fixed `:49-237`) under `#line` markers at their true line numbers and aborts
on any pin drift. Key lines:

- Affected `:92-95` — SSL-token detection, including SSLv2 backward-compatible
  hello `((int_buf[0] & 0x80) && int_buf[2] == 1)`.
- Affected `:120-121` — `dsize = 15-bit record length - 3`; record length 1
  yields `-2`.
- Affected `:160` / `:162` — `size = dsize + 5` (3) and `malloc(size)`.
- Affected `:171-173` — `pp = cp; memcpy(pp, int_buf, 5); pp += 5`, a 5-byte
  write into a 3-byte allocation.
- Affected `:181` — `fread(pp, 1, dsize, fd)` with negative `dsize` converted
  to `size_t`, writing the attacker's body bytes past the same allocation.
- Fixed `:127-131` — `if (dsize < 0 || dsize > (1 << 24))` returns
  `GLOBUS_GSS_ASSIST_TOKEN_ERR_BAD_SIZE` before any allocation or write.

Harness stand-ins, all outside the copied statements: globus debug macros and
error constants are no-ops/values; `malloc` in the copied function is routed to
a stand-in that either returns an exact-size allocation (ASan mode), a zeroed
1 MiB mmap collaborator at a known offset (chosen-byte readback), or a 2-byte
allocation at the end of a `PROT_NONE` guard page (fault control); the hostile
record is supplied through `fmemopen` from local argv bytes. No GSI listener,
gatekeeper, myproxy, TLS stack or stock allocator neighbour is exercised.

## Harness digests and replay

- `gen_driver.py` `03196921329efc89663e438698cc3d91743a94cd7c088557b753097b3f76430b`
- `run.sh` `48a4b37a85e6d64a8cdd91b2a3ca4ae2ff3af0b24fe717049688245c11f1b91d`
- Generated `driver_vuln.c`
  `266ce8a3b30c8737661928d6db9b03ed703353d62eb41022c52c546a91a5577c`
- Generated `driver_fixed.c`
  `c895ac07839722bab15be93807efa6d2ee6287d31b5549e7aeb69a2c6b644752`
- `bash lab/frontier/gct2shell/run.sh <outdir>`: **10 PASS / 0 FAIL,
  ALL CHECKS PASS rc 0**; two independent five-run groups both
  `sha256=e5ca3f256b9fd58bd493ad841286819c2dd8f731874424ab26f3b287af5c6204`.

Clean replay from `git archive HEAD` is recorded in the frontier brief once
performed; ASan PIDs, addresses and build paths are excluded from the trace
digest so clean replays are byte-identical.
