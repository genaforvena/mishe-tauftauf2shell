# radvdump2shell — status

Admitted 2026-11-23 ~06:4xZ under standing approval #6 as the 104th engine
route. Frontier staged this lane in W140 (commits `a514b30` and `2352d04`)
with byte-exact pinned upstream blobs, a real fix commit and a released fixed
version. Brief: `reports/frontier-radvdump2shell.md`; pins, verbatim slices,
hashes and raw evidence: `lab/frontier/radvdump2shell/PROVENANCE.md`. The
two-pane inner tmux window 108 was already live and registered, so admission
created no second window and changed no registry entry. The hy4-flash
`max_parallel: 3` route was added; the path, debounce and `@radvdump2shell`
slice drop-in were minted with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Both `m2shell-wake@radvdump2shell.service` and
`m2shell-wake-radvdump2shell.path` were added to the site's owner resolver
map (209 entries). The pinned full-flag doctor returned rc 0,
`PASS local plant out of Git` / `GREEN`, and `check-omp-only.py` returned GREEN
with 104 declared roles. Admission changes no grade.

- Claim: CVE-2026-48715 / GHSA-52px-gh9p-m379 (CNA GitHub_M, HIGH 7.7
  `CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`,
  CWE-121); radvd `<= 2.20`, fixed in `2.21` by commit
  `068bde13e3fd6a5fcdb6859e6a2acd293a325dc5`. The advisory excludes the main
  `radvd` daemon: only the `radvdump` RA-dump utility is affected.
  Byte-exact pinned blobs: vulnerable `radvdump.c.878ca6b` and `v2.20` are
  identical (`0beaaaf74ebf93835331efacac5986769f53388b5e8bed8e65c1999fa086355b`);
  fixed `radvdump.c.068bde13` and `v2.21` are identical
  (`bfe1f0f6800b2955b1ee6994c9f8c6f70e9663f1f318ffc98adbd338b47b48b5`).
- Primitive: `print_ff()`'s `ND_OPT_ROUTE_INFORMATION` case has only a `len >
  1` gate before `memcpy(&addr, &rinfo->nd_opt_ri_prefix, (len - 1) * 8)`
  into a 16-byte `struct in6_addr` (pinned `radvdump.c.878ca6b:379-380`).
  RFC 4191 section 2.3 permits length 1-3; length 33 yields a 264-byte option
  that passes the outer option-length check and a 256-byte attacker-controlled
  copy. The fix rejects lengths outside 1-3 before the copy.
- Evidence: `lab/frontier/radvdump2shell/harness/run.sh` re-extracts four
  verbatim case bodies per run under `#line` directives, checks a 6-file
  source manifest and a 12-file harness manifest, and builds four plain and
  four sanitizer binaries. Frontier recorded 67 PASS / 0 FAIL three times plus
  clean `/tmp` and `git archive HEAD` replays. Operator replay from
  `git archive HEAD lab/frontier/radvdump2shell` in a fresh `/tmp` directory
  returned rc 0, `PASS=67 FAIL=0` and exactly
  `TRACE_SHA256=cf327179a2abca7647a1a8bd3b58259a398c7de94f24a27910f3a356d8d3788a`.

## Grade at admission — 06:4xZ (author-only, no witness verdict)

Rung 1 measures the gate arithmetic: length 33 passes `> 1`, copying 256 bytes
into the 16-byte destination. Rung 2 shows attacker bytes reaching the
destination with no length rejection on the vulnerable and 2.20 slices, while
the fix-commit and 2.21 slices log `Invalid Route Information option length
33` and never reach the copy or formatter. Rung 3 is confirmed with gcc and
clang ASan: `stack-buffer-overflow`, `WRITE of size 256` at pinned
`radvdump.c.878ca6b:380` in `route_case`, with fixed, 2.21 and RFC-conformant
length-2 builds clean. The harness's rung 4 is **scoped**: chosen bytes land
at copy offsets 17/24/33/40/63 in the plain build, and gdb at pinned line 381
reads `saved rip = 0x414141414141417b`; the plain process then faults at
pinned line 382. That verdict came from a direct call with stubbed plumbing.

## Live-binary result — 2026-11-23 07:02Z (author-only, no witness)

The admission wake built the genuine upstream v2.20 and v2.21 trees (tag
tarballs; sources byte-identical to the pinned blobs) with the real
`print_ff`, `recv_rs_ra` and `open_icmpv6_socket`, and fed them a crafted RA
as a **unicast ICMPv6 packet to `::1` scoped to `lo`** from a root raw socket.
All traffic stayed on loopback. Tooling: `lab/frontier/radvdump2shell/real/
send_ra.py` (ra builder/checksum/sender) and `run_live.sh` (driver with a
live-PID check). Raw outputs: `real/evidence/live-*.out`.

- Real v2.20 + ASan, length byte 33: `receiver if_index: 1`, then
  `AddressSanitizer: stack-buffer-overflow`, **`WRITE of size 256` at
  `radvdump.c:380` in `print_ff`**, called from `main` at `radvdump.c:127`
  (`live-vuln-asan.out`). Same binary with the RFC-conformant length byte 2
  parses cleanly with zero ASan (`live-safe-asan.out`). Real v2.21 + the same
  crafted RA logs `Invalid Route Information option length 33 from ::1`,
  prints the RFC 4191 rejection and never copies (`live-fixed21-attack.out`).
- Real v2.20, plain `-O0 -g -fno-stack-protector`, gdb at pinned line 381:
  chosen bytes at copy offset 112 set the live pointer
  `rinfo = 0x1234567812345678` (`live-gdb-pointer-control.out`).
  `defaults.h:23` allows `MSG_SIZE_RECV 1500`, so the length byte is not
  limited to 33: with length byte 40 the copy is 312 bytes (336-byte RA), and
  chosen bytes at copy offset 296 set **`saved rip = 0x1234567812345678`**
  in `info frame` (`live-gdb-saved-rip.out`). `&addr = rbp-288`; saved RIP is
  at `rbp+8` = copy offset 296. Both pointer control and saved-RIP control are
  therefore demonstrated on living bytes, not just in the synthetic harness.

Build matrix on the same pinned source: `-O0` plus ASan faults at the WRITE;
`-O0` plain gives the control above; `-O2 -fno-stack-protector` is stopped by
the host GCC's default `_FORTIFY_SOURCE 3` (`*** buffer overflow detected
***` from `__memcpy_chk`, `live-gdb-O2.out`); `-O2 -fno-stack-protector
-U_FORTIFY_SOURCE` performs the copy but yields no pointer control and no
crash (`live-gdb-O2-nofort.out`). Ordinary distro builds are mitigated.

## Current grade — rung 4 on living bytes (author-only, no witness)

Rung 1-3 are reproduced on real binaries with real wire input. Rung 4 is no
longer scoped to the harness: chosen bytes at chosen offsets control a live
pointer and the saved return address in a genuine `radvdump` process. The
negative results (fortify abort, -O2 no control, length-33 RIP gap) are part
of the grade and must not be erased.

## Ceiling

No rung 5. The process SIGSEGVs at pinned line 382 while dereferencing the
smashed `rinfo` before `print_ff` can return, so the controlled saved RIP is
not reached as control flow. The binary is PIE, ASLR is live, and no address
is known for a usable RIP or a valid `rinfo`; there is no ROP chain, benign
marker, chosen command or witness verdict. The lab sender needs root for
CAP_NET_RAW and injects the RA on the same host's loopback, not from a
network-adjacent neighbour. The fix's root-drop, buffer-zeroing,
jumbo-packet and earlier-loop changes are outside this callpath.

## Next bounded work

Groom `rinfo`/`radvert` to valid readable pointers while keeping the chosen
saved RIP so `print_ff` can return (address knowledge is needed under
PIE/ASLR; the lab may use `setarch -R`), then attempt a benign marker with
vulnerable, safe and fixed controls and an independent witness. What would
change the mind: a return into the chosen RIP without a fault, an independent
witness replay contradicting the above, or a distro configuration where the
overflow is reached without disabling fortify.
