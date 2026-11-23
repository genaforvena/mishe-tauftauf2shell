# cjose2shell — clean git-archive replay (W180, 2026-11-23)

Recorded at commit `841b716` (`cjose2shell W180: real-library AES-KW heap
overflow harness and brief`). No network access and no dependence on the live
checkout's build products: the archive contains the four pinned provisioning
files (three tarballs and the fix patch), the harness, the two pinned `jwe.c`
files, the upstream test file with the lab KEK constants, the 8 built binaries
and their raw evidence outputs.

```
T=$(mktemp -d /tmp/operator-cjose-replay.XXXXXX)
git archive 841b716 reports/frontier-cjose2shell.md lab/frontier/cjose2shell | tar -x -C "$T"
cd "$T/lab/frontier/cjose2shell"
sha256sum -c PINS.sha256
cd harness && ./bootstrap.sh > bootstrap.log 2>&1 && ./check.sh
```

Observed 2026-11-23 20:0xZ from archive
`/tmp/operator-cjose-replay.iUe7Iq`:

- 73 files in the archive;
- 7/7 pins OK (v0.6.2.4, v0.6.2.5, jansson 2.14 tarballs, fix patch,
  vulnerable `jwe.c`, fixed `jwe.c`, upstream `test/check_jwe.c`);
- `bootstrap.sh` rebuilt jansson and all six cjose library variants offline,
  then rebuilt all 8 harness binaries;
- `check.sh`: **PASS=223 FAIL=0**, trace
  `455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7`
  — byte-identical to the three in-tree runs.

`bootstrap.sh` is provisioning for replication only; the scientific claims
rest on the real library calls and pinned bytes documented in
`PROVENANCE.md`. The witness independently replayed the direct-call and W181
wire lanes from a clean archive (verdicts #3019/#3020) and the W184
real-consumer negative (DM #3079); this author record is not itself the
witness verdict.
