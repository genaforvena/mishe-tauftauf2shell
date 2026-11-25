# W26 first run — failed node-exhaustion prediction (2026-11-25 16:37:28Z–16:38:12Z)

First run of `run-availability320b.sh` on the shipped 3.20b tree
(`db9c5d6fd37ef74b6e6ca647308d351e656de18d`, port 25223/25224) returned
`RESULT: PASS=7 FAIL=3`, rc 1. The prediction imported from W6/W16 was wrong
for this release. Preserved as a negative; do not retry the input into a pass.

Failed assertions, verbatim:

```
AVAIL320B FAIL vulnerable: fifth login refused for node exhaustion (test: grep -q '!No nodes available for login.' '.../evidence/vuln-server.log')
AVAIL320B FAIL vulnerable: a termNode thread parked in nanosleep (test: grep -qiE 'nanosleep|hrtimer' '.../evidence/vuln-threads.txt')
AVAIL320B FAIL vulnerable: four sessions reached teardown (test: test $(grep -c 'destructor begin' '.../evidence/vuln-server.log') -ge 4)
```

Observed instead: all four chosen 64-byte probes landed (`first=0x465541544f4f2d45
last=0x5a5a5a5a46554154 cv=4853494d`), then the server logged `Node 1
destructor begin` and died with `Segmentation fault (core dumped)`;
`vuln-threads.txt` contained only the dead PID marker `*`; the fifth client
recorded `ssh: connect to host 127.0.0.1 port 25223: Connection refused`. No
`!No nodes available for login.` line exists because the listener was gone
before the fifth connection, not because nodes were free. The last log line
was `Node 1 destructor begin`, matching W21's single-session fault and W24's
attribution of that fault's load to the wire-chosen `savedlines.first` pointer.

Conclusion: availability impact on the shipped release is whole-process SIGSEGV
at first teardown, a stronger denial of service than the dev-parent thread-park
mechanism, but NOT the advisory's node-exhaustion path. The revised W26
assertions measure that mechanism and keep the fixed-form control. The
fixed phase of this same run passed all four of its checks: five attaches,
four bounded copies, no refusal and four completed teardowns.
