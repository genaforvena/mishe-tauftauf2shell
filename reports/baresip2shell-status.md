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

## W1 — real-libre wire experiment (2026-11-22T23:47–23:54Z)

- Provisioning and build: pinned source trees fetched read-only at `7ace643f`
  and `89aed31f` under `lab/baresip2shell/src/`; their `websock.c` SHA-256
  values match frontier's saved bytes exactly (`02a4af85...` and
  `1af5a060...`, full values in `lab/baresip2shell/PROVISIONING.md`). Full
  static libre builds succeeded with ASan and without it; `-DUSE_OPENSSL=ON`
  is required (`OFF` fails with `missing HMAC-SHA1 backend`). gcc 13.3.0,
  cmake 3.28.3, OpenSSL 3.0.13, gdb 15.1.
- Real caller and wire: `bash lab/baresip2shell/live/run.sh` starts a
  plant-started `websock_accept()` listener on 127.0.0.1:19015, completes a
  real HTTP 101 upgrade (`UPGRADE_STATUS=HTTP/1.1 101 Switching Protocols`),
  then sends the 14-byte frame `82fffffffffffffffffcb4b4b4b4` over the socket.
  Vulnerable ASan build: `READ of size 1`, `0 bytes after 206-byte region`,
  top frames `websock_decode` at `websock.c:216`, `recv_handler` at
  `websock.c:260`, `tcp_recv_handler`, `fd_poll`, `re_main`; server rc 134.
  The region is allocated by `realloc` in `mem_realloc` -> `mbuf_resize` ->
  `mbuf_trim` -> `tcp_recv_handler`. Evidence: `live/crafted-vuln.server.out`,
  `live/crafted-vuln.server.err`, `live/crafted-vuln.client.out`.
- Controls: fixed pin on the same upgrade and frame gives gdb
  `SEEN_LEN_HEX=fffffffffffffffc`, `LEFT_BEFORE=4`, `DECODE_RETURN=61`
  (`ENODATA`) at the new guard, with no ASan report
  (`live/fixed-enodata.out`, `live/crafted-fixed.*`). A short masked frame on
  the vulnerable pin reaches `SRV_RECV opcode=2 len=1 first=41` cleanly
  (`live/short-vuln.*`).
- Plain-build layout (`live/plain-layout.out`, `live/plain-mem32.out`): no
  ASan, `mem_header_size=192`, malloc chunk 224 bytes (`usable 216`), mbuf
  logical size 14, `p = mb->buf+14`, next chunk begins at `p+3`. With mask key
  `b4b4b4b4`, after 32 XOR iterations the next chunk's size word at `p+10`
  changes from `0000000000002321` to `b4b4b4b4b4b49795` — chosen-delta
  corruption of adjacent allocator metadata, not slack inside the frame
  buffer. The first ASan trap is still the read half; the gdb stop isolates
  the store.
- Plain consequence (`live/plain-crash.out`): the unbounded loop reaches
  SIGSEGV in `websock_decode` at `websock.c:216` with `i=235170` (~229 KiB
  written), same `recv_handler`/`tcp_recv_handler` chain — a measured DoS on a
  plant-started process, matching the advisory's stated impact.
- Grade now: rungs 1/2/3 at real caller and wire scope; rung 4 demonstrated
  security impact at the labeled scope of a plant-started loopback server
  being killed with attacker-keyed corruption of adjacent allocator metadata.
  No pointer control, live-victim object data, benign marker, command or
  rung 5. Advisory reachability through baresip/SIP clients remains a claim:
  only `websock_accept()` itself was driven here. "Chosen" still means the
  XOR delta applied to bytes already in heap memory.
- Reproduce from the repository root: `bash lab/baresip2shell/live/build.sh`,
  `bash lab/baresip2shell/live/run.sh`,
  `bash lab/baresip2shell/live/run-probes.sh`. Source clones, build trees and
  binaries are gitignored. Frontier brief: `reports/frontier-baresip2shell.md`.
  Witness #1872 established the earlier direct-call/stub scope only. Witness
  #1933 independently replayed W1 from clean archive c06152a on 2026-11-23 and
  closed it ESTABLISHED at the labeled real-caller/wire rung-4 scope (see W2).

## W2 — witness replay and structural ceiling (2026-11-23T00:3xZ)

- Witness #1933 rebuilt all four libre.a and four ws_server binaries from the
  pinned tags, replayed `live/run.sh` and `live/run-probes.sh`, and found nine
  evidence files byte-identical to the canonical ones. Their replay reproduced
  the HTTP/1.1 101 upgrade, the crafted-frame ASan trap at `websock.c:216`
  with the `recv_handler`/`tcp_recv_handler` stack, fixed `DECODE_RETURN=61`,
  clean short frame, the allocator-metadata delta `2321 ->
  b4b4b4b49795`, and plain SIGSEGV at `i=235170`. No nit, no counterexample;
  grade adopted as ESTABLISHED for the narrow rung-4 scope.
- Structural ceiling for this build and path (source plus measured crash): the
  vulnerable loop is `for (i=0, p=mbuf_buf(mb); i<hdr->len; i++) p[i] = p[i] ^
  hdr->mkey[i%4]` (`src/re/src/websock/websock.c:215-216`). The wrapped sum
  only defeats the length guard; `hdr->len` itself stays ~2^64, so there is no
  small attacker-selected write length and no break in the loop. Every mapped
  writable byte is XORed until the process faults: ASan at the first redzone
  byte, plain build at SIGSEGV `websock.c:216`, `i=235170` (~229 KiB written,
  `live/plain-crash.out`). `websock_decode()` never returns on the crafted
  frame, so no post-corruption object read or call exists in this path. This
  closes the route to pointer control, benign marker or command execution
  here; it says nothing about a different allocator, a concurrent consumer or
  a build that traps and continues — those stay UNKNOWN and unmeasured.
- Grade after replay: rungs 1/2/3 at real caller/wire scope and rung 4
  demonstrated DoS/security impact at the plant-started loopback server scope
  are ESTABLISHED. Rung 5 is not claimed and was not attempted: no measured
  path from attacker-controlled wire bytes to a lab-chosen command with an
  observed side effect. Advisory reachability through baresip/SIP remains a
  claim; only `websock_accept()` was driven.
