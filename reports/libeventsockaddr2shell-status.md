# libeventsockaddr2shell — status (staged 2026-11-27 W316, admission pending)

Brief: `reports/frontier-libeventsockaddr2shell.md`. Lab:
`lab/frontier/libeventsockaddr2shell/`. Dedicated inner-socket window 210 is
live with panes %426/%427 (`dead=0`); registry has 211/211 unique names. Claim:
CVE-2026-63388 / GHSA-cvq5-vrvr-j338, CWE-787/CWE-617. An AF_UNIX abstract
name makes the evhttp accept path copy 110 kernel-supplied bytes into a
28-byte `conn_address`, corrupting `dns_request` and the adjacent input
`evbuffer.lock`.

Vulnerable pinned commit `1b7cc9b58d6a5fdd5f33a43168245c2e1f35291f`; fixed
commit `52057cb33d0c20c0a0453fbabe6c0c96854931b9` (parent `9877a7205ea0`).
Fix hash and input pin SHA-256 values are in
`lab/frontier/libeventsockaddr2shell/PROVENANCE.md`.

Author evidence: `bash run-all.sh` rc 0 **23 PASS / 0 FAIL**; `bash
run-probe.sh` **16 PASS / 0 FAIL**. GCC ASan on the vulnerable commit gives
`heap-buffer-overflow`, `WRITE of size 110`, frame `http.c:4686`, zero bytes
after a 520-byte region allocated by `bufferevent_socket_new`. Loopback-TCP
and fixed-commit attack controls are ASan-clean; the production vulnerable
server SIGSEGVs while the fixed one stays alive. Three attacker-chosen
48-bit values (`0x1234567890AB`, `0xDEADBEEF1337`, `0xCAFEBABE9988`) each
appear as `mutex=<chosen>` in libc `___pthread_mutex_lock`, with matching
`rdi`, an `evbuffer_get_length` frame and `peer_socklen=110` from
`accept_socket_cb`.

Grade at staging: **R1 / R2 / R3 ASan WRITE-110 / R4 DEMONSTRATED (chosen
48-bit pointer reaches a chosen-address dereference in libc in a live
production build, observed under gdb with a crash) / R5 NOT CLAIMED.** No
benign marker, command, remote-TCP path, ASLR groom or information leak was
observed; the advisory CVSS vector is Local (AF_UNIX peer).

Clean replay from `git archive 090aa6bc` at 06:04Z: unmodified
`bash run-all.sh` rc 0, **23 PASS / 0 FAIL**, with inner probe **16 PASS / 0
FAIL**; bootstrap rebuilt both pinned source trees from the tracked tarballs.
Archive SHA-256
`889dfe520826993c448f5f90d5e2392f99ec86200ecb946dd203f5eb76239aa2`; replay
log SHA-256 `1edee7ac5316ae8d40d38e01c46a9c3ea7db042bef939765937258a4beaf9abc`.
Replay directory `/tmp/libevent-clean-replay.7gG7Zt`. Author replay is not
independent acceptance; operator admission and witness replay are owed.

Named next experiment: disable ASLR (`setarch -R`), groom a fake
`pthread_mutex_t` at a known address, place that address at
`sun_path[102..107]`, and check whether the lock call succeeds without a
fault while the fixed and loopback-TCP controls stay clean. Preserve the
negative results in `PROVENANCE.md`: a one-byte abstract name also overflows
on this host, the advisory's `si_addr = mutex+0x18` was not reproduced
(`$_siginfo` printed 0x0), and the client writes 6 bytes at
`sun_path[102..107]`.

Handoff: charter and seed wall under `.mishe-tauftauf/`; DMs to operator and
witness sent at 06:0xZ after window creation. Admission and witness verdicts
owed; no grade change already claimed by a peer.
