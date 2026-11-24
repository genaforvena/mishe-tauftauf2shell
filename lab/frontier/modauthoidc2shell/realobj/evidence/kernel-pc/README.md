# W20 — kernel-recorded native PC at the NUL store (2026-11-24)

W14 caught the non-ASan realobj SIGSEGV at pinned `state.c.4301b536:219` with
gdb attached. This probe asks whether the faulting PC can be observed with no
debugger, preload or signal shim. Yes: the kernel's own SIGSEGV report records
it, and the recorded instruction is the pinned NUL store.

## Method

No rebuild. The W14 binaries were run as-is; hashes before and after the run
were identical:

- `pl-vuln` `d9e1f3a3f0e27d8409f4433ff1644000d82b361cc535e36f4467b788d7d15679`
- `pl-fixed` `08e40556a93b238e1f11be1c6746e52ad4c8f28e7d23c308c41c00b0a1a2dc2f`
- `pl-release` `221269266e8dd43ff336294f1fe3a3381d2e9f1fb40cc57c82740f125b34682f`
- `driver_long.c` `eae591b4f5d450379ec57f401350467797844dd0d537cd6c63664bd79273f136`
- `src/SHA256SUMS`: 4/4 pinned blobs OK (`fix-8017478.patch`,
  `state.c.4301b536`, `state.c.8017478`, `state.c.v2.4.19.4`).

At 2026-11-24T04:47:11Z-04:47:16Z: six trials of
`MO_TOKEN_LEN=65000 timeout 15 ./pl-vuln read 0`, then three trials each of
`pl-fixed` and `pl-release`. Direct process execution: no ptrace, no
`LD_PRELOAD`, no shim, no listener, no socket, no wire. `dmesg` is denied in
this container, so the kernel record was read with `journalctl -k`. Raw output:
`run-20261124.txt`, `journal-raw.txt`, `journal-window.txt`,
`symbolization.txt`.

## Measured

`pl-vuln`: rc 139 on trials 1, 2, 5 and 6; rc 134 (glibc abort, after a
dispatch) on trial 3; rc 0 (RC=1, PROCESS_CALLS=1) on trial 4. The kernel
logged one SIGSEGV line per rc-139 trial — four in total — with distinct ASLR
bases:

```
pl-vuln[<pid>]: segfault at <addr>...388 ip 0x...563 sp ... error 7 in pl-vuln[<base>+1000]
```

All four IPs have the same low 12 bits `0x563`; all four fault addresses end
in `0x388` and differ in their upper bits; `error 7` is a user-mode **write**
protection fault. The ELF text LOAD segment starts at vaddr `0x1000`, which is
the mapping base the kernel prints, so the IP is ELF vaddr `0x1563`.
`addr2line -e pl-vuln -f -C 0x1563` returns
`oidc_state_cookies_parse_token` at
`realobj/state.c.4301b536:219`. `objdump` at `0x1563` is
`c6 00 00  movb $0x0,(%rax)`, the pinned `*cookie = '\0'` store. Each kernel
`Code:` line is byte-exact over `0x1550`-`0x1577`, with `<c6>` marking the
faulting byte — the scan's `cmp $0x3d,%al` / `je` loop immediately precedes it.

`pl-fixed` and `pl-release`: 3/3 trials each rc 0 with `PROCESS_CALLS=0`, no
kernel record.

## Scope

This removes the debugger from the **harness** PC attribution: a plain
non-ASan process with a real APR pool and ASLR on writes NUL at an address the
kernel refuses, and the kernel names the exact instruction and its source
line. It adds no wire path, no consumed pointer side effect, no chosen byte
value and no rung 5: the byte is always NUL and its target comes from adjacent
memory. Grade unchanged: rung 4 scoped, author-only.

The live-wire W15/W16/W19 faults remain debugger-observed. On this host Apache
children produce no kernel SIGSEGV lines at all (a `journalctl -k` check of the
W15 window found only `pl-vuln` records), so this is not a native-PC upgrade
for the wire path.

## Replay

```
cd lab/frontier/modauthoidc2shell/realobj
sha256sum pl-vuln pl-fixed pl-release driver_long.c
(cd ../src && sha256sum -c SHA256SUMS)
for t in 1 2 3 4 5 6; do MO_TOKEN_LEN=65000 timeout 15 ./pl-vuln read 0; done
journalctl -k --since '<start UTC>' -g 'pl-vuln'
addr2line -e pl-vuln -f -C 0x1563
objdump -d --start-address=0x1550 --stop-address=0x1580 pl-vuln
```
