# W14: long value-less token faults a NON-ASan real-APR process (2026-11-23)

Question left open by the W14 build-stack correction: the full-module W13
crash ran under the ASan allocator; does the OOB scan also fault a genuinely
non-ASan allocator with a real APR pool?

Answer: yes, in a standalone real-object process, above a length threshold.
This is NOT the full module, a listener, a socket or a wire request — the
grade stays rung 4 scoped (harness availability), rung 5 UNKNOWN.

## Build and input

`driver_long.c` is a copy of `driver.c` with one change: `MO_TOKEN_LEN=N`
builds a `mod_auth_openidc_state_` + N `a` token with no `=`;
`MO_TOKEN_EQ=1` appends `=1` as the well-formed control. All parser code is
the same verbatim pinned `state.c.4301b536` slice. `probe-long-token.sh`
builds three plain (no `-fsanitize`) binaries plus one ASan comparison and
sweeps lengths; `raw-by-trial.txt`, `results.txt`, `wellformed.txt`,
`asan.txt`, `results-clean-archive.txt` and `pin-hashes-clean-archive.txt`
are the verbatim transcripts. `driver-sha256.txt` pins the driver.

A plain build here is genuinely non-ASan: `gcc -O0 -g -std=gnu11` with system
APR/APR-util, no `-fsanitize`, no libasan in `ldd`.

## Measured

Value-less token, `pl-vuln`, 5 trials per length, `timeout 15 ./pl-vuln read 0`.
Two independent runs: the working-tree run (`results.txt`,
`raw-by-trial.txt`) and a clean `git archive HEAD` (2ebb69b) replay
(`results-clean-archive.txt`, 4/4 pinned blobs OK in
`pin-hashes-clean-archive.txt`). The script regenerates the verbatim slices
from the pinned blobs, so the archive replay needs no `run.sh` artifacts.

| token bytes | run 1: rc 0 / nonzero | clean-archive replay: rc 0 / nonzero |
| --- | --- | --- |
| 30 / 7800 / 16000 | 5/5 / 0/5 | 5/5 / 0/5 (dispatch 5/5) |
| 20000 / 24000 / 28000 | 5/5 / 0/5 | not replayed |
| 29000 / 30000 / 31000 | 1/5 / 4/5 | not replayed |
| 32000 | 0/5 / 5/5 | 0/5 / 5/5 |
| 48000 | 0/5 / 5/5 | 0/5 / 5/5 |
| 65000 | 0/5 / 5/5 | 2/5 / 3/5 |
| 100000 | 0/5 / 5/5 | 1/5 / 4/5 |

Nonzero is rc 139 ("monitored command dumped core"), i.e. SIGSEGV 11. The
fault is layout-dependent: certain at 32000/48000 in both runs, frequent but
not certain at larger lengths (3-5/5). When it does not fault, the scan found
an `=` in adjacent pool memory, wrote NUL and dispatched
`oidc_state_cookies_process_one` (RC=1, PROCESS_CALLS=1). No tested setting
makes the fault deterministic at every length; it is not a deterministic
per-request primitive.

Controls in the same plain build: `pl-fixed` (upstream fix `8017478`) and
`pl-release` (`v2.4.19.4`) are rc 0 with PROCESS_CALLS=0 in 5/5 trials at every
length in the table. Well-formed `MO_TOKEN_EQ=1` on `pl-vuln` is rc 0 with
PROCESS_CALLS=1 in 3/3 trials at 7800 and 65000. The ASan comparison
`al-vuln` faults at 30/7800/65000 with `AddressSanitizer: unknown-crash`
where the scan reaches an unmapped page; that is a different detector regime,
not the plain result.

## Fault frame

`gdb -q -batch -ex run -ex 'bt 10' --args ./pl-vuln read 0` with
`MO_TOKEN_LEN=65000` (verbatim `gdb-plain-65000.txt`) caught the native
SIGSEGV at pinned `state.c.4301b536:219` in
`oidc_state_cookies_parse_token`, stack `parse` → `do_read` → `main`.
The debugger shows `cookie` pointing at an `=` byte in a read-only mapped
region: the scan read succeeded, the NUL **store** at `:219` faulted. This is
a plain process with no libasan, no LD_PRELOAD and no signal shim; ptrace is
the only instrument, and gdb is not needed to make the fault happen (the
5/5 rc-139 runs had no debugger).

## Limits

No full module, Apache listener, socket or wire request; the token is built
in-process, not sent by a client. No chosen byte (always NUL), no pointer
target chosen, no consumer dereference, no command, no rung 5. The full-module
W13 fault remains ASan-runtime-layout dependent; this harness result does not
upgrade it.

## Replay

```
cd lab/frontier/modauthoidc2shell/realobj && bash probe-long-token.sh
MO_TOKEN_LEN=65000 gdb -q -batch -ex run -ex 'bt 10' --args ./pl-vuln read 0
```
