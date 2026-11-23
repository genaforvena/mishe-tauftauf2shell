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

## Current grade — 06:4xZ (author-only, no witness verdict)

Rung 1 measures the gate arithmetic: length 33 passes `> 1`, copying 256 bytes
into the 16-byte destination. Rung 2 shows attacker bytes reaching the
destination with no length rejection on the vulnerable and 2.20 slices, while
the fix-commit and 2.21 slices log `Invalid Route Information option length
33` and never reach the copy or formatter. Rung 3 is confirmed with gcc and
clang ASan: `stack-buffer-overflow`, `WRITE of size 256` at pinned
`radvdump.c.878ca6b:380` in `route_case`, with fixed, 2.21 and RFC-conformant
length-2 builds clean. Rung 4 is **scoped**: chosen bytes land at copy offsets
17/24/33/40/63 past the 16-byte object in the plain build, and gdb at pinned
line 381 reads `saved rip = 0x414141414141417b`, one chosen byte inside the
saved return address; the plain process then faults at pinned line 382.

## Ceiling

The case body is direct-called with stubbed `flog`, `addrtostr` and
`print_preferences`; plain builds use `-O0 -g -fno-stack-protector` because
Ubuntu's default stack protector aborts before observation. There is no live
`radvdump`, raw socket, IPv6 neighbour or crafted RA on the wire, no groomed
allocator, ROP chain, pointer redirect, chosen command, witness verdict or
rung 5. ASan faults on the WRITE before any later control-flow effect, so the
saved-RIP byte is seen only in the plain build under gdb. The fix patch's
root-drop, buffer-zeroing, jumbo-packet and earlier-loop changes are outside
this harness and not reproduced.

## Next bounded work

Build real `radvdump` 2.20 with ASan and send one crafted RA over loopback
inside the lab to confirm the callpath on living bytes; then measure the real
frame layout for a controllable pointer slot. Only a measured, controlled
pointer or command side effect can change the grade. What would change the
mind: the pre-auth callpath is unreachable on the tested configuration, a
clean-archive replay mismatch, or an independent witness verdict
contradicting the scope above.
