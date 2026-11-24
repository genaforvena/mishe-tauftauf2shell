# hydra2shell provenance

Frontier candidate: CVE-2026-133274 (THC-Hydra <= 9.7, stack CWE-121 in
`analyze_server_response()`). Full brief: `reports/frontier-hydra2shell.md`.

## Provisioning (read-only external reads, no probes)

- Upstream clone `https://github.com/vanhauser-thc/thc-hydra.git` pulled into
  the ignored `src/hydra-git/`; HEAD `707c822e` (2026-11-15).
- Vulnerable worktree `src/hydra-git/hydra-v9.7` at tag `v9.7`
  (`6c11ce2dff19ce81630c12b001d821dcd4d1567c`).
- Fixed worktree `src/hydra-fixed` at the CVE patch commit
  (`6ab9ad860ff92a18196566172a197070b3977f6e`).
- Advisory text from cve.org and vulncheck.com, read as claims, not facts.

## Rebuild and replay

```
cd lab/frontier/hydra2shell
sh harness/run-all.sh                 # gcc/clang direct-call matrix
cd src/hydra-git/hydra-v9.7
./configure
make -j4 CFLAGS='-O0 -g -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address'
cp hydra hydra-asan
make clean && ./configure && make -j4 CFLAGS='-O0 -g -fno-omit-frame-pointer'
cd ../../../   # back to lab/frontier/hydra2shell
python3 harness/loopback_server.py 18080 attack &
python3 harness/loopback_server.py 18081 safe &
ASAN_OPTIONS=detect_leaks=0 ./src/hydra-git/hydra-v9.7/hydra-asan \
  -l user -p pass -t 1 -f -s 18080 127.0.0.1 \
  http-post-form '/:a=^USER^&b=^PASS^:FAIL'
```

Both servers bind 127.0.0.1 only. Fixed-control build under `src/hydra-fixed`
uses the same configure/make flags. `evidence/wire.log` contains the
PID-normalized key lines from the four wire runs; raw traces are ignored
`evidence/*.out` files. `harness/PINS.sha256` lists the verified input hashes.

## Ceiling

Rungs 1-3 on a real loopback HTTP wire (ASan-confirmed memory error) plus a
direct-call gdb byte observation of a NUL write at `tmpcookie[-1]`. No
attacker-chosen byte, no chosen offset, no pointer/IP, no command, no
witness, no rung 5. Plain v9.7 completes the crafted request without a
crash; that advisory claim is UNREPRODUCED here. Disposition: screen out.
