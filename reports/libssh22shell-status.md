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
- Grade at admission: rungs 1/2/3 and rung 4 chosen bytes at chosen relative
  offsets at **direct-call / stub scope only**, with no libssh2 process, SSH
  handshake, network wire, allocator grooming, pointer control or command at
  that time. Copy content was constrained by the decrypted-first-block stub;
  arbitrary bytes at arbitrary heap offsets were not established. No rung 5
  then or now. This admission-time grade is superseded by W2/W3 and witness
  W123 below: rung 4 is ESTABLISHED at live-process scope and rung 5 is closed
  on this host.
  Admission caveat that still holds: the victim is a **connecting client** fed
  by a malicious server, not a web-facing service. Live loopback reach was
  UNKNOWN at admission; W2 established it on this host, witness W123 confirmed
  it, and rung 5 remains structurally closed here.
- Witness replay: W121 independently replayed the direct-call harness from a
  clean archive (17/17 PASS, 9/9 hashes). Witness W123 (#1628) replayed the W2
  live claim from a clean `git archive HEAD` with its own pinned builds,
  controls and gdb readback, grading rungs 1/2/3 and live-process rung 4
  ESTABLISHED with no refutation or NIT; rung 5 stays NOT ESTABLISHED and
  structurally closed on this x86-64 glibc. This page predates W2/W3; current
  scope and controls are in `reports/libssh22shell-live.md`. The staged
  harness replay remains at `bash lab/frontier/libssh22shell/harness/run.sh`,
  comparing `EVIDENCE_HASHES.txt` (nine digests) and the 17 PASS lines.
- Completed experiment (W2/W3, `reports/libssh22shell-live.md`): the pinned
  client drove a real `libssh2_session_handshake()` against a plant-started
  127.0.0.1 fake server through KEX and `aes128-ctr` +
  `hmac-sha1-etm@openssh.com`, sending one short ETM packet with a valid MAC;
  fixed, wrong-MAC and safe-input controls were clean. W3 measured the
  allocator geometry that closes rung 5 on this host. No further bounded
  experiment is owed; rung 5 needs a 32-bit build or a different
  consumer/allocator, neither a live X2Shell path here.
