# Provenance — snac2shell harness (CVE-2026-112021)

Site: `/home/mesh-home/mishe-tauftauf2shell`. Wake W112, 2026-11-22.

## Pins (fetched from public upstream; hashes in `pins/` and `PIN_HASHES.txt`)

| Artifact | Source URL | sha256 |
| --- | --- | --- |
| `pins/snac-2.92.tar.gz` | `https://codeberg.org/grunfink/snac2/archive/2.92.tar.gz` | `cc3d7edb2b960f34c925c00b20553c0c13dbfd65fb5b85765a701c57d0004fa6` |
| `pins/snac-2.93.tar.gz` | `https://codeberg.org/grunfink/snac2/archive/2.93.tar.gz` | `cf27b88ea11699e6ec71a29efc457af9ec4dd1ff3470321c6a7d58d807ebb602` |
| `pins/fix-ec2c5c20.patch` | `https://codeberg.org/grunfink/snac2/commit/ec2c5c2046e0381bc942ec5d0d05ec861fe377e7.patch` | `015bf03d0e01cacd6d117b88fab06ed2548bf95e75deedfaf1fe489dfc3d3bd9` |

Vulnerable tag 2.92 → commit `3d2af2ef63e0b79b0b4fe5398928291df9cb8c24`.
Fix commit `ec2c5c2046e0381bc942ec5d0d05ec861fe377e7` (parent
`04daf694a17f0c3b9462b0b4483674f62ef3819f`), shipped in fixed tag 2.93 →
commit `795355acb496a8a8f015a80edf48f38786894f86`.

## What is real and what is a harness

- `src/vuln/` and `src/fixed/` are the unmodified extracted upstream tarballs
  (only `--strip-components=1`). No source line was edited; the only difference
  between them is the one upstream fix line at `xs_json.h:283`.
- `harness/parse_json.c` is a small driver compiled against the real pinned
  `xs.h`/`xs_json.h`. It opens a file and calls `xs_json_load(f)` — the same
  entry point `activitypub_post_handler()` uses — then frees the result.
- Payloads in `out/poc-{41,5a}.json` are the finder's published JSON shape with
  the post-NUL bytes set to two chosen markers. They are not captured traffic.
- `harness/readback.gdb` breaks at `xs_insert_m` in the **plain** build and
  prints the insert offset, `malloc_usable_size(data)` and the byte being
  written. This is a debugger observation of the real parser, not a simulated
  copy; it is deliberately labeled rung-4 at direct-call harness scope.
- No daemon was built, no socket bound, no network packet sent. The pre-auth
  HTTP reach is a source-observed claim, not a local observation.

## Replay

`bash harness/run.sh` rebuilds all four binaries, generates payloads, runs the
ASan matrix and both gdb readbacks, asserts the vulnerable/fixed conditions,
normalizes volatile fields (ASan PID/addresses/BuildId, gdb process id, lab
path), and writes `evidence/norm-*.log` plus `EVIDENCE_HASHES.txt` and
`PIN_HASHES.txt`. Two back-to-back replays were byte-identical across all eight
normalized logs.

## External claims not verified here

- MITRE/NVD scoring, CISA SSVC, CWE and version range come from the CNA record.
- The finder's real-server crash, AFL++ harness and tcache-poisoning attempt
  were read as published claims; only the parser-level behavior above was
  re-run locally.
- No public upstream issue thread was found (private report likely).
