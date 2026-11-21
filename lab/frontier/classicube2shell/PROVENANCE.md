# ClassiCube2Shell candidate — pin provenance

Provisioned 2026-11-21 16:58–17:02Z from primary sources only; no probes of
external systems. All hashes are sha256 of the exact bytes committed under
`pins/`.

| File | Source | sha256 |
| --- | --- | --- |
| `pins/classicube-1.3.9.tar.gz` | `https://codeload.github.com/ClassiCube/ClassiCube/tar.gz/refs/tags/1.3.9` | `5bb62dbb3ad27e1fbb09842f0cb1f4802b2686553b017e0b67ce09b36f908246` |
| `pins/classicube-1.4.0.tar.gz` | `https://codeload.github.com/ClassiCube/ClassiCube/tar.gz/refs/tags/1.4.0` | `8f249f435fcce4dac083664c43077073c32c5382a485de3bcd81badf1816143f` |
| `pins/classicube-fix-c461fa7.patch` | `https://github.com/ClassiCube/ClassiCube/commit/c461fa759f218e3c6bda4642b9af79a98dc84a43.patch` | `3e0b9b1933ddb8db5cdb33589d3d9cc059c027ce7ed5fa11f13c0d74eb6ba6ba` |
| `pins/Bitmap-1.3.9.c` | raw `https://raw.githubusercontent.com/ClassiCube/ClassiCube/1.3.9/src/Bitmap.c` | `de9d89d46c9f5d3818fb5d2480ba67831f2c3d96f2c51998d21fa68b6586d5d6` |
| `pins/Bitmap-1.4.0.c` | raw `https://raw.githubusercontent.com/ClassiCube/ClassiCube/1.4.0/src/Bitmap.c` | `7b37f36ce1b73c105e5a1f873c58c50fc2f5b86e2821a76ca0902b42b93b424c` |

Claim records: MITRE CVE API `CVE-2026-133307` (published
2026-11-19T16:32:29.937Z) and `CVE-2026-133308` (published
2026-11-19T16:32:29.255Z). Patch commit API: `c461fa7…`, committer date
2026-11-18T20:39:04Z. Release API tag `1.4.0`, published
2026-11-18T20:52:20Z. The fix is a **tagged release**, satisfying standing #6.

The two added guards in the patch are present in pinned
`Bitmap-1.4.0.c:442` (`width <= 0 || height <= 0` → `PNG_ERR_TOO_SMALL`) and
`:451` (`if (bmp->scan0)` → `PNG_ERR_MULTI_HDRS`).

## Harness and replay

`build.sh` extracts both tarballs into ignored `src/` and compiles the
unmodified pinned `Bitmap.c`, `Deflate.c` and `Stream.c` with `harness.c` and
the trivial `stubs.c` under clang 18 `-fsanitize=address -g -O0`
(`-DCC_BUILD_MANUAL`, `--gc-sections`). `gen_inputs.py` (Python stdlib only)
generates the six inputs in `inputs/`; their sha256s are asserted in `run.sh`.
No stub parses PNG or inflates bytes; the ASan sinks are in pinned source.

`bash run.sh /tmp/cc-replay` on 2026-11-21: **55 PASS / 0 FAIL**, trace sha256
`e2ffd73365a944ef0b2f95de1cb7a1c5170caca6ed2bef33e16c6d30bd392cb3`, identical
across two clean output directories. Raw ASan reports and the normalized trace
live in the ignored replay output directory, not in Git.
