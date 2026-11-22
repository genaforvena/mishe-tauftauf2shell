# baresip2shell — status

Admitted 2026-11-22 ~23:2xZ under standing approval #6 as the 92nd engine
route. Frontier staged this lane at 23:17Z with a brief
(`reports/frontier-baresip2shell.md`), site charter, seed wall, pinned
v4.8.0/v4.8.1 sources with the fix diff, and an already live two-pane inner
tmux window (index 97, registry 98/98 unique), which was adopted and not
duplicated. Admission added the hy4-flash `max_parallel: 3` route and the path,
debounce and `@baresip2shell` slice drop-in from the exact full-flag sync
(pin `0d686bbad55c849e88334da64efff9da88ad528a`; `written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. `m2shell-wake@baresip2shell.service` was added to the site's owner
resolver map so future failures address `operator`, not the dead `genome`
fallback. Admission changes no grade.

- Claim: GHSA-hvxv-v2gp-v93h / CVE-2026-50161 (sreimers, 2026-05-28, Critical,
  CWE-190/787), affected `<= 4.8.0`, patched `>= v4.8.1`; pins `7ace643f`
  (v4.8.0 vulnerable) and `89aed31f` (v4.8.1 fixed), fix `718b926` (PR #1584).
  Hashes, claim URLs and saved first-party bytes are in
  `lab/frontier/baresip2shell/PROVENANCE.md`. Advisory reachability via
  `websock_accept()` in baresip/SIP-VoIP servers and the stated DoS impact are
  claims read from the advisory, not observations in this lab.
- Primitive: in the pinned `websock_decode()`, `mbuf_get_left(mb) < (4 +
  hdr->len)` is evaluated in unsigned arithmetic with `hdr->len` a `uint64_t`.
  For `len = 0xFFFFFFFFFFFFFFFC` the sum wraps to zero, so the guard passes;
  `for (i=0, p=mbuf_buf(mb); i<hdr->len; i++) p[i] ^= mkey[i%4]` applies an
  attacker-chosen four-byte repeating XOR pattern to about 2^64 heap bytes.
  The fixed pin adds `hdr->len > SIZE_MAX - 4` and returns `ENODATA`.
- Evidence (`bash lab/frontier/baresip2shell/harness/run.sh`): the 54/55-line
  `websock_decode()` slices are re-extracted from the saved pinned bytes and
  SHA-256-asserted on each run; `driver.c` supplies only the struct
  declarations, `mbuf_*` stubs and `sys_ntohll`. Operator replay from a fresh
  `/tmp` copy of the whole lane: rc 0, 43 PASS / 0 FAIL, path-independent
  normalized hash
  `d6a3d40dd5fba54383ccece9e7010a85819737577710854493d90954cb9349fc`, exactly
  frontier's clean-archive value. Vulnerable pin, gcc 13.3.0 and clang 18.1.3:
  `CRAFT_B0=82 CRAFT_B1=ff MASKBIT=1 LENBYTES=fffffffffffffffc KEY=b4b4b4b4`,
  `ERROR: AddressSanitizer: heap-buffer-overflow`, `READ of size 1`, `0 bytes
  after 30-byte region`, top frame `websock_decode` — the load half of the
  read-modify-write. The plain guard-page run observes the store: 32 sentinel
  bytes go from `0xEE` to chosen `0x5A` past the 30-byte region,
  `PLAIN_FIRST_OOB_OFFSET=12`, `PLAIN_FAULT_OFFSET=44`. Fixed pin returns
  `ENODATA` (61) with no key consumed and no writes; a safe 8-byte masked frame
  is clean on both pins.
- Grade: rungs 1/2 and rung 3 (ASan-confirmed out-of-bounds access in the
  verbatim pinned function) plus scoped rung 4: the attacker chooses the XOR
  key and therefore the pattern applied to adjacent harness bytes. Ceiling:
  no libre build, `websock_accept()` server, HTTP upgrade, wire frame, natural
  allocator layout, adjacent heap object, pointer control, marker, command or
  rung 5. The loop is unbounded in realization; ASan and the guard page stop it
  at the first inaccessible byte, so the neat 32-byte overwrite is a harness
  artefact, not a claimed real-world overwrite length. "Chosen" means the
  pattern applied to bytes already present, not an arbitrary absolute value.
- Next experiments: build pinned `v4.8.0` and `v4.8.1` `re` with ASan, start a
  plant-started `websock_accept()` listener on 127.0.0.1, complete the HTTP
  upgrade and send the exact 14-byte masked binary frame (`82 ff` + eight
  length bytes ending `fc` + four mask bytes). Record the real ASan frame
  chain, then run the fixed pin (expect `ENODATA`, no write) and a short masked
  frame (expect clean unmask). All loopback; no external system. Rung 5 remains
  additive and per-build.
- Full stage: `reports/frontier-baresip2shell.md`. No witness verdict yet.
