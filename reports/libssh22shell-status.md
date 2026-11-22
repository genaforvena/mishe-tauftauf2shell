# libssh22shell — status

Admitted 2026-11-22 ~19:1xZ under standing approval #6 as the 79th target
mind and 83rd engine route. Charter `.mishe-tauftauf/charters/libssh22shell.md`,
seed wall `.mishe-tauftauf/walls/libssh22shell.md`; staged by frontier at
commits `9795ecf` (harness/pins) and `547a5c6` (clean-archive replay). Frontier's
DM #1566 recorded the existing two-pane window (inner index 88, registry 89
windows); admission adopted it and added the model route, wake-failure signal
and three units, not a duplicate window.

- Claim: GHSA-v6rf-8q4r-r495 / CVE-2026-66035, "libssh2 through 1.11.1, fixed
  in commit `42e33d8`, contains a pre-authentication heap buffer overflow that
  lets a malicious SSH server corrupt heap metadata in a connecting client by
  sending a packet with `packet_length` smaller than the cipher block size
  during Encrypt-then-MAC (ETM) cipher negotiation" (CWE-122). GitHub advisory,
  High / CVSS v4 7.7
  (`AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`). Affected through 1.11.1; the
  advisory's Patched field is Unknown, so no fixed release number is asserted —
  the fixed pin is commit `42e33d8`. Sources, both raw blobs and the fix patch
  are in `lab/frontier/libssh22shell/PROVENANCE.md`.
- Provenance discrepancy preserved, not smoothed: the fix commit message cites
  `GHSA-6c79-444r-wx26` (currently HTTP 404); the public advisory citing the
  same commit is `GHSA-v6rf-8q4r-r495`. The advisory's 32-bit glibc tcache /
  function-pointer story is an unverified claim; this lab ran 64-bit glibc
  with ASan.
- Primitive: vulnerable `src/transport.c:235-263` `transport_fullpacket()`
  computes `decrypt_size = total_num - mac_len - 4` (attacker-controlled wire
  length), allocates exactly that many bytes with `SSH2_ALLOC`, then executes
  `memcpy(decrypt_buffer, first_block + 1, blocksize - 1)` unconditionally.
  For `TOTAL_NUM=28`, `mac_len=20`, `blocksize=16` this gives
  `decrypt_size=4` and a 15-byte copy: a natural heap overflow whose bytes
  come from the decrypted first block, so they are attacker-influenced.
- Pins: vulnerable parent `edec1cce27a309399a9d174b73fef9b997148fbb`
  (SHA256 `54af80fc…`), fixed `42e33d81577ed4b95d4b4f6f845e5ee8efe5eeb4`
  (SHA256 `cfeb9c18…`). The fixed pin adds a six-line guard before the copy:
  `if(p->total_num < mac_len + 4 + (size_t)blocksize) { ... return
  LIBSSH2_ERROR_DECRYPT; }`. Hashes in `pins/PIN_HASHES.txt`.
- Evidence: `lab/frontier/libssh22shell/harness/` extracts
  `transport_fullpacket()` verbatim (180 vulnerable / 185 fixed lines) over
  minimal stubs. Vulnerable gcc and clang ASan: `heap-buffer-overflow`,
  `WRITE of size 15`, 0 bytes after a 4-byte region, top frame
  `transport_fullpacket`. Plain readback with chosen first-block base `0x41`
  is `4142434445464748494a4b4c4d4e4f…` and base `0x5a` gives
  `5a5b5c5d5e5f606162636465666768…` — 15 chosen bytes at offsets 0..14 (11
  past the sink). Fixed pin returns `LIBSSH2_ERROR_DECRYPT` (`rc=-18`) clean;
  safe `TOTAL_NUM=64` is clean on both pins. 17 PASS / 0 FAIL; nine normalized
  hashes in `EVIDENCE_HASHES.txt` reproduced over two in-tree replays and a
  clean `git archive 9795ecf` replay. Operator replay 19:14Z: rc 0, 17 PASS,
  pins OK, unchanged tracked files.
- Grade: rungs 1/2/3 and rung 4 chosen bytes at chosen relative offsets at
  **direct-call / stub scope only**. No libssh2 process, SSH handshake,
  network wire, allocator grooming, pointer control, command or witness
  replay: **no rung 5**. Copy content is constrained by the decrypted-first-
  block stub; arbitrary bytes at arbitrary heap offsets are not established.
  Admission caveat weighed explicitly: the victim is a **connecting client**
  fed by a malicious server, not a web-facing server; live/wire reach stays
  UNKNOWN regardless of the advisory's pre-auth framing.
- Witness replay owed. Replay from the repo root:
  `bash lab/frontier/libssh22shell/harness/run.sh`, then compare
  `lab/frontier/libssh22shell/EVIDENCE_HASHES.txt` (nine digests) and the 17
  PASS lines. Full stage: `reports/frontier-libssh22shell.md`.
- Next bounded experiment to move up a rung: build pinned libssh2 1.11.1 with
  ASan and drive a real `libssh2_session_handshake()` against a plant-started
  127.0.0.1 fake SSH server that completes KEX, selects an ETM cipher
  (`aes128-ctr` + `hmac-sha1-etm@openssh.com`) and then sends one short
  encrypted packet with `total_num=28` and a valid ETM MAC. Controls: the same
  handshake with `total_num>=40` stays clean; the patched commit rejects with
  `LIBSSH2_ERROR_DECRYPT`; safe input leaves the client alive. A successful
  replay upgrades rung 4 from direct-call to a live client process; it still
  needs chosen-pointer or command side effects for rung 5. All bind to
  loopback only.
