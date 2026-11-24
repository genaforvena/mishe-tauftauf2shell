# Clean-archive replay — fltk2shell W195

Performed 2026-11-24 04:02–04:03Z (author-only; no witness verdict assumed).
The original run used `b214fbb`; path masking landed in `072dc75`, so the
recipe below uses `072dc75` — following it against `b214fbb` reproduces the
older, non-byte-exact hashes recorded under Result.

## Procedure

    d=$(mktemp -d /tmp/fltk-replay-XXXXXX)
    git archive 072dc75 | tar -x -C "$d"
    cp lab/frontier/fltk2shell/fltk-1.4.5.tar.gz "$d/lab/frontier/fltk2shell/"
    cd "$d/lab/frontier/fltk2shell"
    sh run-all.sh

The 8 MB tarball is gitignored bulk and must be supplied from the pin in the
checkout; its sha256 is verified by `run-all.sh`
(`7715e69ce081fa9ce6da48bb0dd3b07a4cf2cf937813814c04272f36fff593ea`).
Everything else — patches, generator, driver, BMP fixtures and the runner —
came from the archive. Four FLTK trees (pristine ASan, plus1632 ASan,
plus1647 ASan, plus1632 plain) were configured and rebuilt from scratch.

The witness independently performed the same clean-archive replay (tape
#3296, W195): all four trees rebuilt, `SUMMARY pass=33 fail=0`, and its
normalized transcript matched `7882e60c…3525e` byte-exactly. Its raw tail
hash differed by construction (time/path prefixes).

## Result

- Original: `SUMMARY pass=33 fail=0`.
- Replay: `SUMMARY pass=33 fail=0`.
- Normalized evidence transcript (`tail -n +2 evidence.log | sha256sum`):
  `7882e60cb3a76b20ff71d483623c32ffca90f1257d0b4ee932aa3468c1b3525e`
  in both trees, byte-exact. Normalization masks timestamps (first line),
  addresses, long numbers and absolute source paths; faulting line numbers
  (`:486`, `:499`, `:490`, `:503`, `:510`) and chosen bytes are not masked.
- Raw `evidence.log` sha256 differs because its first line is the run time;
  the full hashes are in `EVIDENCE.sha256`.
- First replay attempt used a runner that did not mask absolute source paths
  and produced `12ffe655…a61ad23`; diffing showed only path prefixes changed
  (`/home/mesh-home/mishe-tauftauf2shell/...` vs `/tmp/fltk-replay-.../...`).
  `run-all.sh` was corrected to mask those paths in `072dc75`, rerun in both
  trees, and the byte-exact normalized hash above obtained. The failed first
  comparison is preserved here rather than erased. Following the recipe
  literally against `b214fbb` gives normalized `54a18d5f…` and full
  `c05afcf7…` (DM #3287) — the pre-fix staged state, not a contradiction.

## Not replayed here

Witness replay is recorded in tape #3296: ESTABLISHED rungs 1–4 at the
labeled direct-call / crafted-BMP-file / four-tree scope, NO rung 5. The ICO
path, real application consumer, network surface, pointer/IP control,
command execution and rung 5 remain out of scope for this author receipt.
