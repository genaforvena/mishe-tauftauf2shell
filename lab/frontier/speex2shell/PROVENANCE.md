# speex2shell — provisioning and evidence provenance (frontier W245)

All fetches were read-only provisioning from public sources on 2026-11-26;
no external system was probed. No source outside the lab was written.

## Claims

- GitHub advisory: https://github.com/advisories/GHSA-jmfj-jxhf-c4c3
  (mirror GHSA-jmfj-jxhf-c4c3); CVE-2026-116741; published 2026-10-27;
  "Speex (libspeex) through 1.2.1 contains an out-of-bounds write in
  `speex_bits_read_whole_bytes()` ... non-owned SpeexBits buffers".
- Upstream reporter issue: https://github.com/xiph/speex/issues/42
  (title "Speex: Out-of-bounds Write in speex_bits_read_whole_bytes
  Non-owner Buffer Truncation", opened 2026-10-22, closed). Its write-up link
  (hackmd.io/@haindpwn/speex-bits-read-whole-bytes-oob-write) was fetched but
  rendered no text through the reader; the causal chain below comes from the
  raw pinned source and the vendor patch, not from that page.
- Vendor fix: https://gitlab.xiph.org/xiph/speex/-/merge_requests/32,
  MR !32 head commit `09b569d1b437e5edccf3406a38714ad795e46d38`
  (one parent; GitLab reports `merge_commit_sha` null).
  Retrieved through
  `https://gitlab.xiph.org/api/v4/projects/xiph%2Fspeex/merge_requests/32/changes`.
- Reference source line: https://github.com/xiph/speex/blob/Speex-1.2.1/libspeex/bits.c#L177
  (vulnerable assignment `nchars=bits->buf_size;`).

## Pins (SHA-256)

| artifact | SHA-256 |
|---|---|
| `src-Speex-1.2.1.tar.gz` (`https://github.com/xiph/speex/archive/refs/tags/Speex-1.2.1.tar.gz`) | `beaf2642e81a822eaade4d9ebf92e1678f301abfc74a29159c4e721ee70fdce0` |
| `pinned/bits-Speex-1.2.1.c` (raw at tag `Speex-1.2.1`) | `bd36b8081282f5a6e9558b2ed8a0acace0a6c3c976587802b466ff8c628a335a` |
| `pinned/bits-fix-09b569d1.c` (raw at fix commit) | `cc326d16a06cf3758fd8c7182d0bae58d09ecf6947c957c820de1ea800f99461` |
| `harness/driver.c` | `39032f087b87502bf7ed4864afd501c8c6cc81cc9541a450e4d369ec4607cdd5` |
| `harness/adjacent.c` | `fbb648978898b0b2ce221c4a335bbe73d0da40990746308a86ff940ca29bcfc8` |
| `harness/run-all.sh` | `a17c1bc65a7eb548fafc5e973cea1affa4a15bcd2fb19983cf549bc1da3435a5` |

The raw fixed commit differs from the vulnerable tag in exactly two hunks:
the security fix at `bits.c:177`
(`nchars=bits->buf_size-(bits->nbBits>>LOG2_BITS_PER_CHAR)-1;`) and an
unrelated signed-shift cleanup at `bits.c:278`
(`d |= (~0u)<<nbBits;` replacing `(-1)<<nbBits`). Both are archived verbatim in
`pinned/`; no local synthetic patch is used in the fixed control.

## Builds and commands

`harness/run-all.sh` extracts the pinned tarball four times and builds real
static libspeex with autotools: two ASan trees (`clang`, one vulnerable, one
with the pinned vendor fix) and two plain trees (`gcc`, one of each). It then
compiles `harness/driver.c` and `harness/adjacent.c` against those libraries
through public headers only and runs the assertions. Outputs are written to
`evidence/`; build logs are gitignored.

`bash run-witness.sh` from `lab/frontier/speex2shell` rehashes the six pins
above, deletes every build tree and all evidence, rebuilds from the tarball
and re-asserts the ASan sink
and adjacent-object bytes. Itself not pinned (no self-hash circle).

Observed in-tree on 2026-11-26: `run-all.sh` 28 PASS / 0 FAIL rc 0;
`run-witness.sh` REPLAY_PASS=10/0 and inner 28 PASS / 0 FAIL. Clean-archive
replay result and its archive SHA are recorded in the frontier wall.

## Negative / UNKNOWN

- The advisory says heap or stack corruption; only the heap path (non-owner
  buffer set up by `speex_bits_init_buffer`) was exercised. Stack reachability
  is UNKNOWN here.
- A follow-up issue comment reports a negative truncated length and UBSan
  left-shift on an already-full buffer at the fix commit. That adjacent bug
  was not used in this harness and is preserved as a separate UNKNOWN.
- No wire/input path from a live network consumer was built; no RCE claim.

## Additive wake 2026-11-26 (author-observed, not part of the W245 witness)

`harness/ptr-control.c` and `harness/ptr-control.sh` are new and unpinned;
the six pins above, `run-all.sh` and `run-witness.sh` are unchanged. The
script compiles the new driver against the existing plain gcc static
libraries in `src-plain-vuln/` and `src-plain-fixed/` and asserts
`delta=32`, vulnerable `marker_called=1` with `vfn` equal to the runtime
chosen target, fixed `marker_called=0`, and an intact 8-byte `tag` field.
Observed 8 PASS / 0 FAIL rc 0; raw outputs in
`evidence/ptr-vuln-plain.out` and `evidence/ptr-fixed-plain.out`. The build
uses the same pinned tarball trees as `run-all.sh`; no new source fetch was
made. The benchmark is an in-process harness marker only, not a wire or
command demonstration.

Read-only source inspection of `src-vuln/` found no production caller of
`speex_bits_read_whole_bytes`; all bundled decoders use `speex_bits_read_from`
(`bits.c:109`), which cannot reach the `bits.c:184` sink. No external
consumer using the append API was identified in this wake.

## Released-tag check 2026-11-26 ~16:40Z (read-only provisioning)

GitHub and GitLab tag listings (both `per_page=100`, 44 tags each) have no
tag newer than `Speex-1.2.1` (`5dceaaf3e23ee7fd17c80cb5f02a838fd6c18e01`).
A direct GitLab refs query for the fix commit
`09b569d1b437e5edccf3406a38714ad795e46d38`
(`GET /api/v4/projects/xiph%2Fspeex/repository/commits/<sha>/refs`) returned
only the branches `fix/read-whole-bytes-oob-write` and `main`, no tags.
Therefore no released tag contains the fix as of this query; the pinned
vendor fix commit stays the fixed control. Exact commands and observed
output: `evidence/released-tag-check.txt`. This is a time-bounded negative
observation, not a claim about future releases.
