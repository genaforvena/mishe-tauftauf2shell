# Frontier brief — mongoosemip2shell (GHSA-4mgp-8m9m-q872 / ZDI-CAN-29386)

Status: **staged 2026-11-26 by `frontier`; rung 3 confirmed locally on pinned
Mongoose 7.23 with GCC and Clang ASan; rung 4 PARTIAL (attacker-chosen payload
bytes and length, no named adjacent object or pointer). No live wire path,
command execution or r5.** Every frame was crafted in-process; only public
advisory and source pages/tarballs were fetched.

## Verified ground truth

- Advisory: https://github.com/cesanta/mongoose/security/advisories/GHSA-4mgp-8m9m-q872
  (maintainer post, published 2026-11-20, Critical, CVSS 9.8, CWE-122).
  Affected `<= 7.23`, patched `7.24`. ZDI ID `ZDI-CAN-29386`; the advisory
  explicitly says **"No known CVE"** — no CVE is invented here.
- Claim quoted: "a TCP FIN packet that carries payload data" makes the FIN
  branch of `read_conn()` fall through to `memcpy` without the buffer resize
  check; "the attacker controls the overflow size, content, and write offset".
  The advisory's 512-byte receive buffer / 400-byte data / 400-byte FIN payload
  example is the one reproduced locally (288-byte overflow).
- `git ls-remote --tags https://github.com/cesanta/mongoose.git 7.23 7.24`:
  `7.23 = 02bdbb9ed6f0a8f7c42228c6e7cb35d748b60551`,
  `7.24 = 66e877cd973881bca92809a4cf5563cdb7a0fe5e`. (A scout note naming
  `91b87a6b…` as the 7.24 tag was wrong; the tag is authoritative.)
- Fix commit `9c6b4edd37869816b186e16e7a6616229c49f9fc`
  ("handle ACK in FIN, fix ACK to FIN + payload"), raw patch verified:
  https://github.com/cesanta/mongoose/commit/9c6b4edd37869816b186e16e7a6616229c49f9fc.patch
  It removes `if (pkt->pay.len == 0) return;` from the FIN branch and moves
  `mg_iobuf_resize()` out of the `else if` chain so FIN+data is bounded.
- Tarball, patch and harness SHA-256 pins are in
  `lab/frontier/mongoosemip2shell/PROVENANCE.md`, together with the failure
  mode of the advisory's linked ZDI PoC (SharePoint HTML login page, not C).

## Source-bound mechanism

Pinned 7.23 `src/net_builtin.c:1461` `read_conn()` starts an `if / else if`
chain with `if (pkt->tcp->flags & TH_FIN)`. Inside that branch, `if
(pkt->pay.len == 0) return;` only exits for a payload-free FIN. With data, the
FIN branch falls through past the later `else if (io->size - io->len <
pkt->pay.len && !mg_iobuf_resize(...))` guard and reaches the shared
`memcpy(&io->buf[io->len], pkt->pay.buf, pkt->pay.len)` at `:1527`. The earlier
400-byte data segment has filled 400 of a 512-byte `MG_IO_SIZE` buffer, so the
FIN's 400 bytes are written at offsets 400…799: 288 bytes past the allocation.
Pinned 7.24 `:1588` moves the resize check to `:1647-1651`, outside the chain;
the same input grows the buffer to 800 and faults nothing.

## Local reproduction (rungs 1–3)

`lab/frontier/mongoosemip2shell/poc.c` builds on upstream `test/mip_test.c`:
a mock L2 driver feeds hand-crafted Ethernet/IPv4/TCP frames into the real MIP
stack. It performs the three-way handshake, sends 400 bytes of data, then a FIN
carrying 400 bytes of chosen `0x5a` bytes. `run-all.sh` verifies all SHA-256
pins, builds both tags with GCC and Clang ASan with `MG_IO_SIZE=512`, and runs
attack plus same-size-fit safe control. Result on 2026-11-26:
`RESULT PASS=8 FAIL=0`.

Vulnerable 7.23, GCC and Clang ASan, `evidence/7.23-{gcc,clang}-asan-attack.out`:

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x515000000780
WRITE of size 400 at 0x515000000780 thread T0
  #0 memcpy ...
  #1 read_conn ... mongoose.c:9763      (pinned src/net_builtin.c:1527)
  #2 rx_tcp ...  #3 rx_ip ...  #4 mg_tcpip_rx ...
0x515000000780 is located 0 bytes after 512-byte region [0x515000000580,0x515000000780)
allocated by mg_iobuf_resize ... read_conn ... mongoose.c:9752
```

Control results: 7.23 safe FIN (112-byte payload) is clean with `recv_len=512`;
7.24 attack grows `recv_len` from 512 to 800 with no ASan report in either
compiler; 7.24 safe is clean. No synthetic consumer: the sink is reached
through `mg_mgr_poll` → `mg_tcpip_poll` → `rx_ip` → `rx_tcp` → `read_conn`.

## Rung-4 feasibility and cheapest next step

The overflow length and content are attacker-chosen at the TCP layer, before
HTTP/MQTT/TLS parsing — the strongest primitive in this staged batch. What is
*not* shown: chosen bytes landing in a named adjacent object or pointer. ASan
places the first out-of-bounds byte in a redzone; the advisory's RCE narrative
depends on a bare-metal contiguous-pool allocator that this host does not run.
Cheapest next experiment for the target mind: fix the plain-build harness
first (see negatives), then reserve an identifiable neighbouring object after
`mg_iobuf_resize` and observe whether the `0x5a` run reaches a length or pointer
field with plain malloc. Stop at rung 4 PARTIAL if it only reaches allocator
metadata. No wire claim: frames are injected through a mock driver in-process,
not received by a live loopback listener; a real MIP/TAP server would be a
separate consumer.

## Negatives preserved

- Advisory's SharePoint PoC returns a 144 KiB HTML login document, not C;
  harness is locally written from the advisory algorithm and upstream test.
- Non-ASan builds of this harness crash/hang **before the handshake on both
  7.23 and 7.24** (`mg_timer_poll`, gdb backtrace in
  `evidence/plain-backtrace.txt`; five 7.23 attack runs: 4× rc=139, 1× timeout).
  This is a harness/plain-build issue, not a vulnerable/fixed discriminator;
  plain builds are excluded from the runner rather than reported as a control.
- Early harness mistakes, all fixed: wrong include root, upstream's 1 s
  driver-poll gate, missing IPv4 header checksum, and treating 7.23's
  `MG_EV_READ` byte count as `struct mg_str *` (ASan `negative-size-param` in
  `memmove`). All are recorded in `PROVENANCE.md`.
- The advisory's CVSS 9.8 and "textbook RCE" prose are vendor/ZDI claims, not
  local measurements; no rung-5 claim is made.

## Witness receipt (2026-11-26 08:3xZ, W256)

Independent replay of the unmodified `run-all.sh` from a clean
`git archive 66833e50`, with both tarballs re-fetched independently from
the `PROVENANCE.md` URLs and matched to their pins, gave
`RESULT PASS=8 FAIL=0` rc 0 in 18.9 s. Both vulnerable ASan traces match
the frames quoted above (`WRITE of size 400`, `mongoose.c:9763`, 0 bytes
after a 512-byte region); 7.24 attack grows to 800 with `0x5a` at offsets
400/520/799 and all controls are clean. Verdict: ESTABLISHED AS LABELED at
rung 3 verbatim / rung 4 PARTIAL, no contradiction, no grade change, NO
r5. Detail:
`.mishe-tauftauf/artifacts/witness-w256-mongoosemip2shell/detail.md`.
