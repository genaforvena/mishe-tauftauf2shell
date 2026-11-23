# W13: native child SIGSEGV, no shim and no ptrace (2026-11-23)

All traffic is unauthenticated `GET /protected` to 127.0.0.1:18090 with
`Cookie: mod_auth_openidc_state_` + 7800 `a` characters and no `=`. Pinned
plain parent module: `state.c`
`ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa`, module
`008990618887dde66e4371d1a354c64dccf29c40d36d17c4ac1d8e5f8b375654`.
Fixed control: released `v2.4.19.4` on the same plain httpd/APR stack, module
`cd2beedbc3c144440d8b3a76f0a7792a770b66d99134cb23260119d37b9a2911`.

## Result

Two independent six-start measurements gave the same bimodal split in a
different order. First run, in order: `12/12 302, AH00051=0` / `0/12, 11` /
`0/12, 11` / `0/12, 11` / `0/12, 11` / `12/12 302, 0` (`restart-results.txt`).
Committed-script replay, in order: `12/12, 0` / `12/12, 0` / `0/12, 11` /
`0/12, 11` / `0/12, 11` / `12/12, 0` (`vuln_bare-results.txt`). Across the two
runs, 4 of 12 starts were crashing and each killed 11 of 12 children; the
other 8 starts were clean. This is **bimodal per server start**, not a
per-request intermittent fault and not a deterministic primitive that survives
a restart. The likely cause is the allocator/ASLR layout inherited at fork: it
decides whether the OOB scan meets a `=` byte in adjacent memory and stops, or
runs into an unmapped page. That cause is a hypothesis; it was not measured
with a fault address.
In a separate A/B run, default `ASAN_OPTIONS` gave 60/60 HTTP 302 and zero
faults, while `detect_leaks=0` gave 0/60 302 with 59 `AH00051` faults; an
earlier 240-request run in a crashing state logged 240 faults. The safe state
is the same request returning 302 without a fault.

The first `AH00051` in the A/B run is at 15:48:09.717Z after a request logged
at 15:48:08.734Z with the 7800-`a` value-less Cookie, so the crash is on the
live pre-auth request path. No shim, `LD_PRELOAD`, debugger or forced execution
was used in these runs.

## Controls

Under the same `detect_leaks=0` env, across independent fresh starts:

- well-formed `mod_auth_openidc_state_` + 7800 `a` + `=1` on the vulnerable
  module: `8/8` HTTP 302 and zero `AH00051` in each of 4 starts.
- value-less 7800-byte token against released `v2.4.19.4`: `8/8` HTTP 302 and
  zero `AH00051` in each of 4 starts.
- earlier single-start controls: short 30-byte value-less token `20/20` 302,
  well-formed 7800 `20/20` 302, fixed module `20/20` 302.

## Negative lanes — no native frame obtained

- `strace -f -ff -e trace=none -e signal=SIGSEGV` on the foreground daemon:
  54/54 requests across lengths 7800/16000/32000/65000 (lab-only raised
  `LimitRequestFieldSize`) returned 302; no SIGSEGV delivery. LeakSanitizer
  fatal errors under ptrace make this an imperfect instrument.
- gdb, ASLR on, fork-following a single worker: 250/250 302 with default
  `ASAN_OPTIONS`, and 120/120 302 with `detect_leaks=0`. ptrace runs land in
  the safe layout, so no native frame was captured. The only frame
  attribution remains W12's layout-changing SIGSEGV shim at pinned `:219`.
- cores: Apache zeroes `RLIMIT_CORE` in children unless `CoreDumpDirectory`
  is set (`Max core file size 0` in the live child `/proc/<pid>/limits`), and
  `kernel.core_pattern` pipes to apport, so no usable core was produced.

## Grade and limits

Unchanged: rung 3 confirmed on the live pre-auth wire path, rung 4 scoped and
unwitnessed at live-wire scope. This adds a **native** availability observation
to W12: one unauthenticated request can kill an Apache child in a layout
chosen at server start, with clean fixed and well-formed controls. It is not a
deterministic crash across restarts, has no frame without the shim, and the
written byte is still always NUL. No chosen byte, pointer target, consumer
dereference, command or rung 5.

## Replay

```
cd lab/frontier/modauthoidc2shell/full
bash build-plain.sh && bash build-plain-fixed.sh
bash probe-plain-native.sh
```

The committed `ab-*-codes.txt`, `restart-results.txt`, `strace-codes.txt` and
`gdb*-codes.txt` are the small verbatim transcripts; large error logs from the
probe runs remain in the gitignored lab workspace.
