# frontier brief — Contiki-NG MPL seed-ID length overflow (`contiki2shell`, candidate)

## Verified ground truth

- Claim: VulnCheck advisory, 2026-11-23, CVE-2026-135292, CWE-787, CVSS 4.0
  8.3 `AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N`,
  "Contiki-NG through 5.2 ... out-of-bounds write in the MPL multicast engine
  ... remote unauthenticated attackers ... unchecked seed ID lengths". Credit
  Lee Keon-Hyeong. <https://www.vulncheck.com/advisories/contiki-ng-through-5.2-out-of-bounds-write-via-mpl-seed-id-length>
- Upstream fix: PR #3312, open 2026-11-23, "mpl: validate HBH seed length
  before reading it", author @zeetee1235. No merged upstream commit at time
  of writing. <https://github.com/contiki-ng/contiki-ng/pull/3312>
- Source pinned: release tag `release/v5.2` → annotated tag
  `a0eb46fe21dc6513f1e34fd28b05090cb95918e3` → commit
  `4ccd1a3b9e767f168d12ec3df187fe6b7dc736b5`; tarball
  `lab/frontier/contiki2shell/contiki-ng-release-v5.2.tar.gz`,
  SHA-256 `78133c774812197b43a979e4b8f1026c8740929c45f749c2dccd4a2670819c95`.
  The advisory's referenced line ranges come from the same commit.
- The advisory is a claim; the mechanism below was read from pinned source and
  the fix hunk, then exercised locally.

## Source-bound mechanism

`os/net/ipv6/multicast/mpl.c`, `accept()` (pinned lines 1442–1474):

1. Next header must be HBHO, first option type must be MPL (`0x6d`), V bit
   zero. `S = HBH_GET_S(lochbhmptr)` comes only from the two high bits of the
   option's `flags` byte; no check ties `S` to the option's `len` or to the
   enclosing extension header.
2. With `S=3`, `seed_id_net_to_host()` copies 16 bytes from
   `lochbhmptr + 4` — immediately after `flags`/`seq`. An option with
   `len=4` supplies only 4 bytes there; the other 12 come from the UDP
   header and payload still inside `uip_buf`. Those bytes become the stored
   seed identity, so the node later transmits a header built from them.
3. `accept()` stores the payload with
   `locmmptr->size = uip_len - UIP_IPH_LEN - uip_ext_len` and
   `memcpy(&locmmptr->data, hptr, locmmptr->size)`. A maximum-size packet
   stores every byte from UDP onward.
4. When the trickle timer fires, `data_message_expiration()` rebuilds an S=3
   HBHO (24 bytes: base 8 + option 18 rounded up) and copies the stored
   payload with `memcpy(UIP_EXT_BUF + 8 + UIP_EXT_BUF->len * 8, &msg->data,
   msg->size)`. The rebuilt header is 16 bytes longer than the received one,
   so the copy runs 16 bytes past the end of the 1280-byte
   `uip_aligned_buf`.

PR #3312 maps `S` to `{0,2,8,16}` bytes and drops the packet unless the
option data, enclosing HBH header and remaining packet all contain that many
bytes.

## Local evidence (in-process injection, no external probing)

Harness `lab/frontier/contiki2shell/harness.c` is copied by `bootstrap.sh`
into the pinned tree's `examples/multicast/`. It builds the real Contiki-NG
native target with `UIP_MCAST6_ENGINE_MPL` and injects a crafted IPv6 packet
into `uip_process(UIP_DATA)` directly — no tun device, no network peer. The
example's `project-conf.h` is patched with
`MPL_CONF_PROACTIVE_FORWARDING 1` so the real trickle timer drives the
forwarding path. The native platform reported "Failed to open tun device
(you may be lacking permission). Running without network": wire delivery is
**not** claimed.

- Vulnerable build, ASan (`gcc -fsanitize=address -g -O0`), short S=3 option
  (`len=4`, HBH total 8 bytes), 1280-byte packet:
  `AddressSanitizer: global-buffer-overflow`, `WRITE of size 1232`, first
  invalid byte `0 bytes after global variable 'uip_aligned_buf' ... of size
  1280`, 32 bytes before `uip_appdata`; top frame
  `data_message_expiration` at `mpl.c:979` in the pristine pinned tree
  (the instrumented author build reported `:981`), called from
  `trickle-timer.c:275 fire` → ctimer → native platform main loop
  (`attack-asan.out`).
- Fixed control: PR #3312 hunk applied to the same pristine tree; no ASan
  report and the harness runs to completion (`fixed-asan.out`).
- Safe-input control: vulnerable build with a complete S=3 option
  (`len=18`, HBH total 24 bytes, full 16-byte seed present), no ASan report,
  harness completes (`safe-asan.out`).
- Under gdb at `mpl.c:979` in the pristine tree (`:981` in the instrumented
  transcript `gdb-inspect.txt:34`) on a plain `-g -O0` build:
  `uip_aligned_buf` base `0x55555559b1c0`, extension-length byte 2,
  `size=1232`, copy destination `base+64` (`0x...b200`), copy end
  `base+1296` (`0x...b6d0`) — exactly 16 bytes past the buffer. The last
  16 source bytes are `4d 49 53 48 45 2d 4f 4f 2d 54 41 55 46 21 21 00`
  (`MISHE-OO-TAUF!!\0`): 15 chosen ASCII bytes plus a NUL, not 16 arbitrary
  bytes, so chosen bytes land at chosen offsets `base+1280..+1295`. In this
  plain layout those 16 bytes land on the `uip_appdata` and `uip_sappdata`
  globals (ASan inserts 32 bytes of redzone there), not allocator metadata
  or a live function pointer. Transcript: `gdb-inspect.txt`.
- `run-all.sh` from a clean bootstrap: **9 PASS / 0 FAIL**.
- Independent witness replay (W190, 2026-11-24 08:12Z, chat #3443/#3444):
  clean `git archive HEAD lab/frontier/contiki2shell`, tarball sha256
  `78133c77…19c95` verified, unmodified `run-all.sh` 9 PASS / 0 FAIL,
  independent ASan `WRITE of size 1232` at pristine `mpl.c:979` and an
  independent plain-build gdb with the same 16 marker bytes at
  `base+1280..+1295`. Verdict CLAIM ESTABLISHED AS LABELED at the in-process
  scope; no wire, no pointer/IP/command, no r5.

## Rung assessment

- Rung 1 (reproducible trigger): YES in-process, deterministic; not over a
  wire.
- Rung 2 (observed state failure): YES — S=3 seed accepted with only 4
  option bytes present, and the stored payload is 16 bytes longer than the
  rebuilt header permits.
- Rung 3 (confirmed corruption): YES — ASan global-buffer-overflow WRITE in
  the real `mpl.c` in a real Contiki-NG native build, not a stand-in struct.
- Rung 4 (demonstrated impact): PARTIAL — chosen marker bytes at chosen
  offsets past `uip_aligned_buf` under gdb, landing on the `uip_appdata` /
  `uip_sappdata` globals in the plain build. No pointer, IP or instruction
  pointer control; those globals are not allocator metadata or a live
  function pointer.
- Rung 5 (remote command execution): NO. No live network process, no
  loopback wire replay, no command, no victim/fixed/safe wire controls.

## Cheapest next experiments

1. Find a loopback-only path that feeds a crafted packet to `uip_input()`
   without tun privileges, moving the claim from in-process injection to a
   wire-triggered reproduce.
2. Groom the adjacent globals (`uip_appdata` and neighbours) for a pointer
   or function-pointer target; record whether the 16-byte write reaches a
   useful object before ASan redzones.
3. Re-check PR #3312 for merge; if merged, pin the fix commit and replay.

Ranking: HIGH tractability — the real stack builds in seconds, the fault is
deterministic in the real consumer, and the fix is public. Ceiling of this
wake: rung 4 partial; wire delivery stays UNKNOWN.
