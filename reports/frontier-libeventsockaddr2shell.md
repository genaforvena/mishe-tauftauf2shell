# Frontier brief: libeventsockaddr2shell — CVE-2026-63388 (AF_UNIX sockaddr length overflow)

**Status: STAGED 2026-11-27 W316, awaiting operator admission.** Target slug
`libeventsockaddr2shell`. No prior brief, wall entry or lab tree names this
target; the only earlier mention is an unscreened backup note in
`reports/frontier-sqlitesession2shell.md`. Dedicated window and handoff DMs are
recorded in `reports/libeventsockaddr2shell-status.md`.

## Verified ground truth (sources read 2026-11-27)

- **Claim source:**
  https://github.com/libevent/libevent/security/advisories/GHSA-cvq5-vrvr-j338,
  published 2026-07-01, High 8.4, CWE-787/CWE-617. It embeds a full PoC,
  ASan trace, gdb controlled-pointer trace and production crash recipe.
- **Versions:** affected `<= 2.1.12`, `<= 2.2.1-alpha`; patched `2.1.13`,
  `2.2.2-alpha`. PoC pins vulnerable master
  `1b7cc9b58d6a5fdd5f33a43168245c2e1f35291f`. Fixed commit
  `52057cb33d0c20c0a0453fbabe6c0c96854931b9` (parent `9877a7205ea0`).
- **Fix:** 3 files +21/-11: unconditional length check, `conn_address`
  widened to `struct sockaddr_storage`, failure propagated in `http.c`,
  return type changed to `int`.
- **Claimed primitive:** an AF_UNIX abstract name of up to 108 bytes makes
  `accept()` report `socklen=110`; the evhttp accept path memcpy's 110 bytes
  into a 28-byte `conn_address`, overwriting `dns_request` and ~74 bytes of
  the adjacent `evbuffer`, including its `lock` pointer. Under
  `evthread_use_pthreads()` that pointer reaches `pthread_mutex_lock`.

## Source-bound mechanism (pinned bytes)

Vulnerable `bufferevent_sock.c:119-126` gates the copy with
`EVUTIL_ASSERT(addrlen <= sizeof(bev_p->conn_address))`, which compiles out
under `NDEBUG`. `http.c:4686` calls it with the `socklen` from `accept4` in
`listener.c:447`. `conn_address` is a 28-byte union followed by
`dns_request`; the next heap chunk is the input `evbuffer` whose `lock` is at
a fixed offset inside the overwritten 74 bytes. The fix removes the
`NDEBUG` dependence and widens the destination.

## Local observation (2026-11-27 W316, gcc 13.3 + gdb, x86_64)

`lab/frontier/libeventsockaddr2shell/` builds unmodified pinned archives with
CMake, static libraries, and the advisory's server/client (rewritten with a
loopback-TCP control mode and a short receive timeout).

- `bash run-all.sh`: rc 0, **23 PASS / 0 FAIL**.
- GCC ASan on vulnerable: `heap-buffer-overflow`, `WRITE of size 110`, frame
  `http.c:4686`, `0 bytes after 520-byte region` from `bufferevent_socket_new`.
- Controls clean: loopback TCP (`sockaddr_in`, 16 bytes) on the vulnerable
  build, and the same AF_UNIX attack on the fixed commit. Production
  vulnerable server SIGSEGVs; production fixed server stays alive.
- `bash run-probe.sh`: **16 PASS / 0 FAIL**. Three attacker-chosen 48-bit
  values (0x1234567890AB, 0xDEADBEEF1337, 0xCAFEBABE9988) each appear as
  `mutex=<chosen>` in `___pthread_mutex_lock`, in `rdi`, with an
  `evbuffer_get_length` frame and `peer_socklen=110` in the backtrace.
- Corrections preserved: a one-byte abstract name ALSO overflows on this host
  (kernel reports 110), so it is not a safe control; the advisory's
  `si_addr = mutex+0x18` was not reproduced (`$_siginfo` printed 0x0); the
  client writes 6 bytes, not 8, at `sun_path[102..107]`. No marker, command,
  ASLR groom or remote-TCP path was observed.

## Rung assessment and cheapest next experiment

**R1 reproducible / R2 state failure / R3 ASan WRITE-110 confirmed / R4
DEMONSTRATED (chosen 48-bit pointer reaches a chosen-address dereference in
libc under a live production build) / R5 NOT CLAIMED.** R4 is a lab
demonstration: the attack is an AF_UNIX socket from a local peer (advisory
CVSS AV:L), and the chosen-address dereference was observed under gdb with a
crash, not a benign marker or command. No wire-to-TCP path, ASLR defeat or
information leak was measured.

Cheapest next step: with ASLR disabled (`setarch -R`) and a groomed fake
`pthread_mutex_t` at a known address, place that address at
`sun_path[102..107]` and check whether the lock call succeeds without a fault
while the fixed and loopback-TCP controls stay clean. This moves R4 from
"chosen-address crash" to "chosen-address control of a live object"; it does
not yet establish R5, because no command execution or benign marker is on
this path. A separate control-flow primitive would be needed for R5.

## Duplicate check

No `reports/frontier-*libevent*`, wall `Do not duplicate` entry or lab tree
exists for libevent. `reports/frontier-sqlitesession2shell.md` mentions
CVE-2026-63388 only as an unstaged backup. Other scouts' candidates
(libpng CVE-2026-33416, apitrace CVE-2026-126050, PHP bcmath CVE-2026-17544,
3proxy, aws-c-http, mongo-c-driver, Fast-DDS, NSD) remain unstaged backups;
none is a duplicate of this sink. Full hashes and raw outputs:
`lab/frontier/libeventsockaddr2shell/PROVENANCE.md`.
