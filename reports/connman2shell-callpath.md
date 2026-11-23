# ConnMan `get_domains()` — natural caller-chain evidence (CVE-2026-115863)

Date 2026-11-23. This extends the staged frontier brief
(`reports/frontier-connman2shell.md`) from a direct call into the real
three-function caller chain of pinned ConnMan tag `2.0` `gdhcp/client.c`.
No ConnMan build, DHCPv6 socket, daemon, network or remote input is used.

## Harness

`lab/connman2shell/callpath/` includes three functions **verbatim** from
`lab/frontier/connman2shell/src/client-2.0.c` (SHA-256 asserted on every run):

- `get_domains` — `090d8ea2…60a5c2`
- `get_dhcpv6_option_value_list` — `0391d8e7…497414`
- `get_dhcpv6_request` — `b38eb698…4f812`

`driver.c` supplies `NS_MAXDNAME`, option codes, GLib stubs and a stubbed
`dhcpv6_get_option()` that returns a forged REPLY option-24 value of 2048
bytes with byte 1024 = K. `run.sh` extracts and hashes the slices, builds
gcc 13.3.0 at `-g -O0 -fno-omit-frame-pointer`, and runs ASan and plain
variants. `retarget.sh` drives gdb watchpoints.

## Observed

`bash lab/connman2shell/callpath/run.sh` → `37 PASS / 0 FAIL`. The plain
outcome mix is printed as `OBS`, not a pass criterion: a 12-run ASLR sample
can legitimately contain no store or no crash.

- **Reachability** (K=0x80, ASan): `stack-buffer-overflow`, `READ of size 1`
  in `get_domains`, with the full stack `get_domains` ←
  `get_dhcpv6_option_value_list` ← `get_dhcpv6_request` ← `main`.
  `dns_name` at frame `[48, 1074)`, access at frame offset 1201 — delta 127,
  identical to frontier's direct call. A REPLY-shaped option-24 with
  `len=2048` therefore reaches the bug on the real caller layout.
- **Controls**: fixed snapshot and a well-formed short DOMAIN_LIST both give
  `CHAIN DONE STATUS=0` and no ASan report through the same chain.
- **Store landing** (plain, 12 runs, K=0x80): 7 runs show 68–69 `0x2E`
  stores in a 16 KiB `main()` canary (`FIRST` 4..177, `LAST` ~16190..16299);
  4 runs show no canary writes; 1 run aborts. An earlier batch gave 3 store
  / 8 none / 1 SIGSEGV. The first OOB step is attacker-chosen (`K-1` bytes
  past the 1026-byte object), but subsequent strides read ambient stack
  bytes, so the continuation is ASLR-dependent.

`bash lab/connman2shell/callpath/retarget.sh` → `RETARGET_K=0x67 HITS=5/5`.

- gdb computes the first OOB address `dns_name + 1025 + K`; K=103=0x67 lands
  on the saved return-address byte of `get_dhcpv6_option_value_list` in this
  layout. Hardware watchpoint: `BEFORE=33 AFTER=2e` in five ASLR-enabled
  runs. The attacker's first write reaches a live control-flow-relevant byte
  of a real caller frame, not only a synthetic canary.
- Disassembly: `0x…592E` is the `call get_dhcpv6_option_value_list`
  instruction, `0x…5933` the original return point. The corrupted byte
  re-enters `get_domains` once (gdb hit count 2); the harness then exits
  normally. No marker, command or control-flow hijack was observed.
- K is layout-specific: the harness has a `run_chain` wrapper and a 16 KiB
  main canary, so a real connmand build would need a different K.

## Grade

Rung 3 plus scoped rung 4, now with a natural three-function caller layout
and an observed write to a saved return-address byte. **Not rung 4 broadly
and not rung 5**: the written byte is the fixed `.`, the walk continuation
is ambient-dependent, no pointer or marker was controlled, and no live
daemon, socket or remote input exists. The advisory's root-service impact
and REPLY reachability remain claims; the fix is a mailing-list patch, not
an upstream release (upstream HEAD `9e46e4a0` is still vulnerable).
