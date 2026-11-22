# Pgpool2shell frontier lab — provenance

Candidate: CVE-2026-92867, Pgpool-II watchdog `NodeIdList` write-what-where.
Brief: `reports/frontier-pgpool2shell.md`. No target mind, charter or window is
owned by frontier for this candidate; this is screened-in evidence only.

## Pins (locally fetched and hashed 2026-11-22T03:58Z)

| Role | Version | URL | SHA-256 (verified by `sha256sum -c src/SHA256SUMS`) |
|---|---|---|---|
| affected | 4.7.2 | `https://www.pgpool.net/source/pgpool-II-4.7.2.tar.gz` | `e72b9d0ff3620f7da7e33a58dda44b77919d056752dc9bd86b2985c4988d1938` |
| fixed | 4.7.3 | `https://www.pgpool.net/source/pgpool-II-4.7.3.tar.gz` | `4bf9df3e13feb8e64bee486b4ea54c9076296c2d9406165b0b68d32086fce250` |

Published hashes independently corroborated by FreeBSD ports distinfo and the
Yocto `pgpool2_4.7.3.bb` recipe. Tarballs and extracted trees are gitignored;
only this manifest, the upstream fix patch (`src/fix-92867.patch`) and the
harness sources/evidence are tracked. A witness can re-fetch from the URLs
above and verify against `src/SHA256SUMS` before replay.

## Fix provenance

Upstream commit `0388652d1b6f970a18c0b8ccaae9d9c79cece3c9` (master), backport
`a58fe0c708f1a27e3e6c36fcbb483fe03bb1d2b9` (V4_7_STABLE, present in tag
V4_7_3). The whole fix is one character:
`*node_id_set[i] = ...` → `(*node_id_set)[i] = ...` in
`src/watchdog/wd_json_data.c`. Verified against the raw text of both tarballs:
4.7.2 line 858 has the vulnerable form, 4.7.3 line 897 has the fixed form.

## Harness and evidence

`harness/run.sh` rebuilds both pinned trees from `src/*.tar.gz` with
`-g -O0 -fno-omit-frame-pointer`, links `harness/harness.c` against the real
upstream objects, and prints the A/B cases plus a gdb chosen-value readback.
`harness/{asan-ab.txt,plain-ab.txt,gdb-vuln-write.txt,gdb-fixed-write.txt}`
are captured outputs; `harness/EVIDENCE_HASHES.txt` holds SHA-256 of the
PID/address/path-normalized traces. Re-run:

    cd lab/frontier/pgpool2shell/harness && bash run.sh

Everything is local; no probe was sent to any host and no daemon was bound to
a network interface. Scope: rung 3 ASan-confirmed on the real parser, rung 4
chosen-value write at direct-call harness scope. Wire reach, address steering
and any command execution remain UNKNOWN.
