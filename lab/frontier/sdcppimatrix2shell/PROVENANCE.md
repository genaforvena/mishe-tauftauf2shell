# PROVENANCE — sdcppimatrix2shell (CVE-2026-70659 / GHSA-6q7q-2v9c-x8m7)

## Provisioning (read-only public sources, 2026-11-26 W293)

Claim page read: `https://github.com/leejet/stable-diffusion.cpp/security/advisories/GHSA-6q7q-2v9c-x8m7`
(CVE-2026-70659, published 2026-09-27, High 7.8, CWE-787/CWE-1284), saved as
`pins/advisory.html`. Tag SHAs resolved through the GitHub git-refs API:
`master-742-1a13107` = `1a13107bac23…` (affected),
`master-763-4fcc6fe` = `4fcc6fef10c6…` (first fixed). No external system was
contacted beyond these reads; no probes, scans or off-loopback tests.

Pinned blobs (SHA-256 in `pins/PIN_HASHES.txt`, checked by inspection):

| Blob | Source | SHA-256 prefix |
|---|---|---|
| `src/imatrix.cpp.vuln` | `raw.githubusercontent.com/leejet/stable-diffusion.cpp/master-742-1a13107/src/runtime/imatrix.cpp` | `fb09b234ddce…` |
| `src/imatrix.cpp.fixed` | `raw.githubusercontent.com/leejet/stable-diffusion.cpp/master-763-4fcc6fe/src/runtime/imatrix.cpp` | `73c5cbd449f1…` |
| `src/imatrix.h.vuln` | same vulnerable tag, `src/runtime/imatrix.h` | `464a0417fbdd…` |
| `pins/fix-4fcc6fef.patch` | `github.com/leejet/stable-diffusion.cpp/commit/4fcc6fef10c6f686801c6e257b22cd6a3deb906b.patch` | `792c4d07666a…` |

The full release tarballs were attempted as a cross-check but the codeload
download timed out (87 MB partial `vuln.tar.gz`); the partial file was deleted
and is retained only as a negative. The harness compiles the raw pinned
files, which are the checked input set. A future `sd-cli` build must fetch
the two tag tarballs itself.

## Source-bound mechanism

`src/imatrix.cpp.vuln:276` interns each name into `std::unordered_map
stats_`. Lines 287-290 resize `e.values`/`e.counts` **only when `e.values`
is empty**. Lines 301-303 then loop over the current entry's `nval`:

```
for (int i = 0; i < nval; i++) {
    e.values[i] += tmp[i];
    e.counts[i] += ncall;
}
```

A repeated name with a larger second `nval` therefore indexes past the
first entry's vectors. The fix patch is +4 lines after the resize:
`else if (e.values.size() != (size_t)nval) { LOG_ERROR(...); stats_ = {}; return false; }`.
The fixed raw file carries that guard at `:290-292`.

## Harness and exact input

`harness/main.cpp` calls the shipped global `load_imatrix()` entry point,
which calls `IMatrixCollector::load_imatrix()` in the verbatim pinned
`imatrix.cpp`. `harness/stubs/` supplies only the GGML type surface and
logging macros needed to compile that one translation unit; no parser logic
is reimplemented. `harness/make_inputs.py 64` writes:

- `evidence/attack.imatrix` (298 bytes): `n_entries=2`; entry A name
  `blk.0`, `ncall=1`, `nval=1`, one float; entry B the **same** name,
  `ncall=1`, `nval=64`, 64 floats.
- `evidence/safe.imatrix` (298 bytes): same two entries but distinct names
  `blk.0` / `blk.1`, so each resizes its own vectors.

`run-all.sh` builds four binaries (ASan/plain × vulnerable/fixed), runs
eight file-only cases and checks 17 observable assertions.

## Observations (2026-11-26 W293, clock 21:42Z)

`runs/asan-vuln-attack.out`:

```
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4
    #0 IMatrixCollector::load_imatrix(char const*) src/imatrix.cpp.vuln:302
    #1 load_imatrix(char const*) src/imatrix.cpp.vuln:168
0x... is located 0 bytes after 4-byte region [...)
allocated by std::vector<float>::resize  ... src/imatrix.cpp.vuln:288
SUMMARY: AddressSanitizer: heap-buffer-overflow src/imatrix.cpp.vuln:302
```

rc 1. `runs/plain-vuln-attack.out`: `double free or corruption (out)`, rc
134 (SIGABRT): a plain-build, non-sanitizer heap state failure. Fixed build
on the same attack file logs `ERROR inconsistent size for a repeated entry
(1 vs 64)` and returns rc 3; safe input on both pins returns rc 0 with no
ASan report in either ASan or plain builds.
`run-all.sh`: **RESULT PASS=17 FAIL=0** at 21:42Z (`runs/run-all.log`).

## Grade and limits

Rung 1 and rung 2 observed on the plain build (deterministic file trigger,
SIGABRT with glibc heap diagnostic). Rung 3 ASan-confirmed heap-buffer-
overflow on the verbatim pinned sink. **Rung 4 NOT CLAIMED**: ASan traps on
the OOB READ half of `e.values[i] += tmp[i]` before the write half and the
`e.counts[i]` write are separately observed; no chosen bytes at chosen
offsets, no pointer control, no marker, no command. **Rung 5 NOT CLAIMED**:
local file input only, no wire path or live service. Addresses, PIDs and
build IDs in raw traces are run-specific and excluded from trace hashes.

The advisory's own real-binary claim (`sd-cli -M convert --imat-in …`
SIGSEGV at `examples/cli/main.cpp:640`) was **not** re-tested here: this
wake used the raw pinned source and shipped loader entry point. No rung is
claimed from the advisory's un-replayed observation.
