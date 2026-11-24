# n2n2shell provenance

All provisioning was read-only public fetching; no external target was
probed. SHA-256 values are recorded in `pins.sha256` and checked by
`harness/run.sh` PASS-15.

- Vulnerable parent commit `dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff`:
  - `provision/wire-vuln.c` — `src/wire.c` at that commit.
  - `provision/n2n-vuln.tar.gz` — codeload archive of the full tree at that
    commit. The extracted tree was used for layout checks and is not
    committed; the archive is the durable pin.
  - `provision/n2n_wire.h`, `provision/n2n_types.h`, `provision/n2n.h` —
    header probes from the same commit (informational; the harness's
    stand-ins follow `n2n_typedefs.h` in the archive).
- Fixed commit `854fbbe01bbf131bf4cb88f8450d7084267668e1`:
  - `provision/wire-fixed.c` — `src/wire.c` at that commit.
  - Fix patch read at `https://github.com/ntop/n2n/commit/854fbbe0.patch`.
- Verbatim extraction:
  - `generated/handlers_vuln.c` — `wire-vuln.c` lines 82-97, 112-129,
    169-184, 194-200, 209-215, 637-654.
  - `generated/handlers_fixed.c` — `wire-fixed.c` lines 82-97, 112-129,
    169-184, 194-200, 209-215, 657-679.
  - Line numbers are claims about the pinned bytes; the SHA-256 manifest is
    authoritative. The only added text in each generated file is a one-line
    comment and the `types.h` include.

- Stand-in types in `harness/types.h` reproduce pinned `n2n_typedefs.h`
  lines 282, 334-335 and 404-408 (48-byte token, 6-byte MAC, cookie,
  scheme, token_size). No decoder logic is reimplemented.
- Harness evidence: `harness/evidence/asan-vuln-attack.out` (WRITE-96 at 0
  bytes after 64-byte region), `asan-vuln-safe.out`, `asan-fixed-attack.out`,
  `plain-vuln-attack.out` (chosen `48 5a 4d 49` at `canary[0..3]`),
  `plain-vuln-safe.out`, `plain-fixed-attack.out`, `pins.out`.
- Claim source: CVE-2026-136404 record
  (`https://cve.org/CVERecord?id=CVE-2026-136404`) and advisory references.

## Clean-archive replay (2026-11-24 21:2xZ)

`git archive 2907b7e4 lab/frontier/n2n2shell reports/frontier-n2n2shell.md`
extracted to `/tmp/n2n2shell-replay`; `sh harness/run.sh` from that clean
directory reported `RESULT 15 PASS / 0 FAIL`, rc 0. Pins and verbatim
extraction were checked there as well. Receipt commit follows.
