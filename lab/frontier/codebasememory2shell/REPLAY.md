# Clean-archive replay — 2026-11-24T01:44Z

Replayed from a fresh `git archive HEAD` at commit `a073540` into
`/tmp/cbm-replay-final` (no files copied from the original lab tree except the
two pinned tarballs, themselves hash-verified). `bash
lab/frontier/codebasememory2shell/bootstrap.sh` fetched nothing because the
pins were present in the replay directory; it verified all four pin hashes,
extracted both pinned trees, rebuilt all four binaries and regenerated the
matrix and the gdb transcript.

- Pin verification: 4/4 OK (two tarballs, two pinned `src/cypher/cypher.c`).
- Builds: 4/4 OK (vulnerable ASan, fixed ASan, recover-mode ASan, plain).
- Matrix: 24/24 rows identical to the original run after normalizing
  `0x…`/`==pid==` tokens (exactly the same exits, query return codes and
  ASan/stack-smash classifications). Original evidence log sha256
  `f8c81a5ccd51fa350c78923ff944f881255c9b94ddf06a448a574268a8b67a6d`;
  replay `1bd04d791e9a6c6e6405e25d1a22bbc87f3388ceb75d21863110017c99fd6277`.
  The hashes differ only because ASan's first-line error text embeds runtime
  addresses and PIDs; no row classification changed.
- Recover-mode WRITE and gdb byte transcript: same `WRITE of size 70` stack and
  the same chosen bytes at `&func_bufs[32]` — replay gdb shows
  `&func_bufs[0]=0x7fffffff5390`, `&func_bufs[32]=0x7fffffff9390` (delta
  0x4000) and `4d 49 53 48 45 2d 4f 4f` ("MISHE-OO") followed by the same
  70-byte pattern.
- WITH-side negative, plain 33-item no-crash and fixed-tree rejection all
  reproduced unchanged.

This is an author replay on the same host, not an independent witness verdict.
No witness claim is made.

## W11 clean-archive replay of the HTTP `/rpc` rows — 2026-11-24T19:22–19:36Z

Replayed from `git archive d582e43a lab/frontier/codebasememory2shell` into
`/tmp/w11-cbm-http`; only the two hash-verified tarballs were copied from
the repository's `pins/` into the archive's absent `pins/` directory.
`bash http-tool/replay.sh all` verified 4/4 pins and rebuilt all three
rows from the extracted pinned trees.

- vuln-asan: HTTP 200 for INDEX/N=1/N=32; N=33 disconnected, RC=1, ASan
  `READ of size 8` at `cypher.c:2568` (`rb_set_columns`).
- vuln-recover: HTTP 200 for INDEX/N=1/32/33/48, RC=0; ASan UBSan index-32
  at `cypher.c:4115` and `WRITE of size 68` at `project_item:3379` ←
  `execute_return_simple:4116`, frame offset 51840 = `func_bufs[32]`.
- fixed-asan: N=33/48 `isError:true` with `failed to parse query`, no ASan.

Raw stderr is preserved as `evidence/http-clean-archive-*-stderr.log`
(sha256 prefixes `b69d4471…`, `cfb8d4e2…`, `f2fb801f…`); the transcribed
stdout and normalized comparison are in
`evidence/http-clean-archive-replay.txt`. Line counts match the canonical
working-tree captures (157/755/57); normalized differences are timing
fields and one ASan-printed pointer byte dump only. Author replay on the
same host, not an independent witness verdict; grade unchanged.
