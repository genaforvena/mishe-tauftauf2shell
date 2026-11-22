# W131 — sigreceived-notifier hijack (preserved negative)

Replay with the tracked driver (local PTY only):

```
python3 lab/frontier/pppd2shell/live/rce_sigrecv.py \
  --binary "$PWD/lab/frontier/pppd2shell/live/raw/build-vuln-nopie/pppd/pppd" \
  --marker <unique> --command 'echo <text> > /tmp/<sentinel>'
```

`rce_sigrecv.py` differs from the W125 `rce_attempt.py` in two ways: it
targets `sigreceived` (+1856), whose `notify()` call in the SIGHUP/SIGTERM
handlers (`main.c:1576`, `:1600`) bypasses `link_terminated()` entirely, and
it uses pppd's own `device_script()` (`main.c:1817`, `0x42c78b` in the
`-no-pie` pin) as the callback, which reaches
`execl("/bin/sh", "sh", "-c", program, NULL)` at `main.c:1868`.

One frame writes two chosen NAK values (`the_channel` low half at +1528,
`sigreceived` low half at +1856); a second frame places the fake notifier,
command and a zeroed fake channel in `inpacket_buf`. Live gdb confirms all
of those bytes at the intended addresses. The callback is reached — pppd
logs a forked `Child process <command>` — but the child dies with SIGSEGV
before `execve`; no sentinel is created. Cause: the same NAK stream that
reaches +1856 overwrites `the_channel`'s high half at +1532 with PAP-NAK
pattern bytes, so the child's `the_channel->close` test (`main.c:1747`)
dereferences `0x23c20503004688a8`.

A single-frame two-target write cannot keep those high bytes zero, and a
later frame that writes the high half would overlap the low half (ASYNCMAP
NAK values are six bytes apart). This is a structural boundary, not a
grooming failure. No rung 5; see `reports/pppd2shell-live.md`.
