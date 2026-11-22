# p-net CVE-2026-127122 — provenance and harness limits

Pinned 2026-11-22 from primary sources. Tarball URLs:
`https://codeload.github.com/rtlabs-com/p-net/tar.gz/refs/tags/public/v1.0.3`
and `.../public/v1.0.4`; compare diff
`https://github.com/rtlabs-com/p-net/compare/public/v1.0.3...public/v1.0.4.diff`.
SHA-256 of all three artifacts is in `pins/PIN_HASHES.txt` and asserted by
`harness/run.sh` on every replay. Tag commits: vulnerable
`19782d52c56640526156f8db04efe93317f9c530`, fixed
`1c3b0b435b2ee2c6cea86849c14ee98f6ee579f1`.

## What is upstream and what is harness scaffolding

Upstream bytes used verbatim by the harness:

- `src/device/pf_block_reader.c` from each pinned tarball, including the
  exercised `pf_get_mcr_request()` (v1.0.3 lines 785-817).
- `src/pf_types.h`, `src/common/pf_lldp.h`, `src/common/pf_snmp.h`,
  `include/pnet_api.h`, `include/pnal.h` and `pnet_options.h.in` from the same
  tarball, so `pf_ar_t` and `pf_multicast_cr_t` layouts are the pinned ones.

Scaffolding (not upstream): `harness/harness.c` (caller model and input bytes),
`harness/stubs/*` (no-op log macros, opaque OSAL/PNAL types, compiler macros
from OSAL), `harness/gen_options.py` (substitutes the `@...@` values in the
pinned `pnet_options.h.in`). The release tarball has no CMake files and no
external OSAL/PNAL repository is published at the URLs referenced by its
README, so full-library configuration is impossible from these pins. The
harness fixes `PNET_OPTION_MC_CR=1`, `PNET_MAX_MC_CR=1` (vendor-stated default)
and small ordinary values for all other size options; these affect the 49600-byte
`sizeof(pf_ar_t)` but not the presence or stride of the unchecked index.

The fixed build does NOT call the real `pf_cmrpc.c`. It adds the exact bound
condition from the v1.0.4 caller (quoted in `reports/frontier-pnet2shell.md`)
with the session/RPC error reporting elided. Therefore the differential proves
the guard, not the daemon's full block dispatcher.

## Replay

`bash harness/run.sh` from the repository root or this directory: verifies
hashes, extracts tarballs if missing, generates options, builds four cells,
runs 11 assertions and writes `evidence/norm-*.log` plus
`EVIDENCE_HASHES.txt`. Normalization replaces PIDs and raw addresses only.
Two replays, the second after deleting `src/`, generated headers, binaries and
evidence, produced 11/11 passes and byte-identical normalized hashes.

## Not measured

No daemon was built, no socket was opened, no PROFINET/DCE/RPC frame was sent.
Pre-auth ADJACENT reach, the 995-file-equivalent real packet shape, pointer
control and command execution remain UNKNOWN. Absolute destination addresses
depend on the application's `pnet_t` allocation; only relative index and stride
were measured here.
