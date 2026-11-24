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
