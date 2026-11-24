# W11 author clean-archive replay

Commit `ce0a0208`, replayed 2026-11-24 18:31Z in
`/tmp/w11-replay2` with `git archive ce0a0208 lab/frontier/synchronet2shell`
and the gitignored `src-tree/` and `provision/` symlinked in; the live tree was
untouched during the archive run. The unmodified
`termlen/run-clientlen.sh` rebuilt `term_server` from the recorded verbatim
source and returned rc 0, **6 PASS / 0 FAIL** on loopback. The first replay of
the earlier commit `a0050050` scored 5/1 because of a port-settle race; its
transcripts are preserved in `negative-replay-a0050050/`.

Raw `results.txt` (sha256
`2aadc65b9f2c6a1e6186553741dd30dad55d24ede61032d2d3dc02eaf5625305`)
and `provenance.txt` (sha256
`749f28548a31e25ba2ab3dd82d6902293fe6f1b003a11bca7af8f59ab2e9d277`)
are byte-identical between the live tree and the replay. The six per-case
transcripts differ only in client-relative timestamps and in the timing and
line order of the server's thread-scheduled `CHANNEL TYPE` lines; after
stripping the leading client timestamp and sorting/material-filtering the
server lines with `waits=N` normalized, all six normalized digests match:

| File | Normalized sha256 (first 16 hex) |
|---|---|
| `term64-client.log` | `dc95027d5f547990` |
| `term65-client.log` | `b53b320d7511233f` |
| `term128-client.log` | `e5eb3ef5a3976220` |
| `term64.out` | `4373c1a5aba77176` |
| `term65.out` | `d6abe801f2afd05a` |
| `term128.out` | `d6abe801f2afd05a` |

Material lines are `ACTIVE attempt`, `CHANNEL TYPE`, `COPY status`,
`READER TERM`, `READER COPY` and `TERM sweep`. Client normalization strips the
leading relative timestamp only; every `CLIENT WIRE_PTYREQ term_len=N` and
`PASS exact wire TERM length N` line is otherwise byte-identical.

This is an author replay, not an independent witness verdict.
