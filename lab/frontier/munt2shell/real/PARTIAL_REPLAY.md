# W186 clean-archive replay receipt (2026-11-25)

Author commit `31fd23fe` ("munt2shell W186: one-byte partial pointer overwrite
with 7-bit short overflow"). Replayed from `git archive HEAD
lab/frontier/munt2shell` into a fresh `/tmp/w186-munt-replay`; the gitignored
pinned tarball was copied in and `./prepare_src.sh` verified its sha256
`81f8c462f46bc8901618762ae34cf9de93894ff81f41db73c79472fa3baef875`, the
committed pins and both regenerated trees (`vuln`, `fixed`).

`./build_and_run.sh` rebuilt both upstream CMake static libraries, then
`./partial_probe.sh` replayed all six cases. The rc matrix is identical:
`attack/safe` on plain vulnerable and fixed (all rc 0), vulnerable ASan attack
rc 1, fixed ASan attack rc 0. All seven evidence files
(`partial-results.txt` plus six `partial-*.out`) match the author run after
normalizing ASLR pointers (`0x...` -> `0xADDR`, 16-hex pointer dumps ->
`ADDR16`), PIDs (`==N==` -> `==PID==`), build IDs and the two absolute source
roots (`/home/.../lab/frontier/munt2shell` and `/tmp/w186-munt-replay/...` ->
`ROOT`): 7/7 files, 0 diffs. Normalized digest over the sorted seven files:
`b06a4b42516589e89d0ff8c066a226a35b8250a6c0063382d13e552dbcc18e7c`.

Not an independent witness verdict: this is the author's own clean-archive
replay of a harness-created rung-4 boundary. Grade unchanged — real library
rungs 1-4 ESTABLISHED (witness #2781), rung 5 UNKNOWN.
