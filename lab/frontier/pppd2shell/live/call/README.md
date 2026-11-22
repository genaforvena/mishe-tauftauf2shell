# W132 — controlled call through the hijacked `sigreceived` notifier

Local PTY replay (vulnerable pinned 2.5.3, `-no-pie`):

```
python3 lab/frontier/pppd2shell/live/rce_call.py \
  --binary "$PWD/lab/frontier/pppd2shell/live/raw/build-vuln-nopie/pppd/pppd" \
  --marker <unique> --mode attack [--strace]
python3 lab/frontier/pppd2shell/live/call/normalize_call.py
```

## What is new

W125 and W131 hijacked notifier pointers but their callbacks dereferenced the
overflow-corrupted `the_channel` before doing anything useful. W132 keeps the
same wire write and uses a **one-argument** callback instead. `notify()` calls
`(*np->func)(np->arg, val)` (`main.c:2155-2163`), so a one-arg libc PLT stub
receives the attacker-chosen `np->arg` in `rdi` and ignores the signal number
in `rsi`.

- NAK frame (same 1498-byte LCP ConfReq as W131) sets `sigreceived` (+1856) to
  `0x46882c`, a fake notifier placed verbatim in `inpacket_buf` by a rejected
  ConfReq body.
- Fake notifier: `next = NULL`, `func = unlink@plt (0x40c4a0)`,
  `arg = 0x468844` (lab sentinel path string in the same body).
- `SIGTERM` reaches `term()` (`main.c:1593-1600`), which calls
  `notify(sigreceived, sig)` with no `the_channel` dereference on that path.
- Live result: `strace` on the target PID shows
  `unlink("/tmp/pppd2shell-r5-…-victim") = 0`; the sentinel file disappears.
  The process then faults later in shutdown on the corrupted `the_channel`
  (`rc -11`), which does not undo the call.

## Controls

| case | result |
| --- | --- |
| vulnerable pin, `unlink@plt`, overflow frame | sentinel deleted; two straced replays byte-identical after normalization |
| vulnerable pin, short safe ConfReq (no overflow) | sentinel intact, daemon alive |
| vulnerable pin, `func = NULL`, overflow frame | SIGSEGV, sentinel intact |
| fixed 2.5.4 pin, identical frames | `LCP: ignoring duplicate configuration option(s)`, sentinel intact, daemon alive |

## Grade

Attacker wire input makes a live process call an attacker-chosen function with
an attacker-chosen string argument, with an observed filesystem side effect.
That is control beyond W123/W126 pointer writes, but `unlink` is a libc call,
not a command: **rung 4, not rung 5**. The pinned binary has no `system`/`popen`
import, and the only exec sites (`device_script`, `run_program`) need a child
path or stack-frame state this primitive cannot supply. Normalized evidence and
hashes are in `evidence/`; raw logs, frames and strace stay in gitignored
`../raw/`.
