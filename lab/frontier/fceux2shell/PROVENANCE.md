# Provenance — fceux2shell staged evidence (W233, 2026-11-25)

## Pins (fetched read-only from public GitHub; no external probing)

- Vulnerable: commit `1e1de9b70a4c62d30f197b5741b64968094bd2cf` (direct
  parent of the fix), `src/unif.cpp` → `pins/unif-parent.cpp`.
- Fixed: commit `d9132c2a37bf05e31b8a09f9ad938d46ff193bf1` (upstream
  "Fix heap overflow in UNIF MAPR chunks", 2026-11-16), `src/unif.cpp` →
  `pins/unif-fixed.cpp`.
- Upstream patch: same commit's `.patch` → `pins/unif-fix.patch`.
- SHA-256 for all three pins is in `pins/SHA256SUMS`; `run-all.sh` verifies
  it on every replay and writes the result to `evidence/pins.txt`.
- Advisory claim: CVE-2026-136918, NVD record fetched read-only; CNA says
  CWE-190 with claimed heap OOB write, `AV:L/UI:P`.

## What is verbatim and what is stand-in

- Verbatim in `harness/driver.cpp`: both `SetBoardName()` bodies
  (`unif-parent.cpp:280-290`, `unif-fixed.cpp`) and the four-line MAPR chunk
  header parse (`unif-parent.cpp:501-508`) plus the fixed added size check.
- Stand-in: `FCEUFILE` is a `FILE*`; `FCEU_malloc` = `malloc`,
  `FCEU_fread` = `fread`, `FCEU_read32le` reads four little-endian bytes,
  `FCEU_ftell`/`FCEU_fgetsize` use `ftell`/`fseek`, `FCEU_printf` discards
  diagnostics. All are declared in the harness header, not copied upstream.
- The plain-build SIGSEGV handler is harness-only: it prints 16 bytes from
  the still-live `boardname` pointer after the wild terminator store faults
  and exits 42. It performs no allocation or pointer repair.

## Build and replay

`bash run-all.sh` builds six binaries with GCC and Clang, `-O0 -g
-fno-omit-frame-pointer`, with and without `-fsanitize=address`, in the
`VULN`/`FIXED` and plain/sanitized configurations; generates the 27-byte
attack and 16-byte safe `.unf` inputs; runs all controls; records stdout,
stderr and rc under `evidence/`. Last run: **14 PASS / 0 FAIL**, script rc 0.
The generated binaries, inputs and evidence outputs are gitignored; only
this record, the harness, pins, checksums and the script are committed.

## Boundaries

No FCEUX emulator build was attempted; no real ROM consumer, network
listener, adjacent-object grooming, pointer control, command execution or
remote input path was tested. No rung 5 claim. No claim that the advisory's
CWE-190 label was independently reproduced — only the OOB write was.
