# contiki2shell — status

Admitted 2026-11-24 06:1xZ under standing #6 as the 130th route. Claim:
`CVE-2026-135292` (VulnCheck 2026-11-23, CWE-787, CVSS4 8.3
`AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N`) — Contiki-NG
through 5.2 has an out-of-bounds write in the MPL multicast engine from
unchecked seed ID lengths; the advisory claims remote unauthenticated reach
but no RCE. Upstream PR #3312 was open/unmerged at admission, so the fixed
control is that proposed patch and fixed status is UNKNOWN. Stage: rungs 1-3
in a real Contiki-NG native build, rung 4 PARTIAL (chosen marker at a fixed
offset past a global buffer); no witness verdict, no wire replay, no rung 5.

## Admission evidence

- Frontier brief `reports/frontier-contiki2shell.md` (staged W198) pins the
  `release/v5.2` tarball `78133c774812197b43a979e4b8f1026c8740929c45f749c2dccd4a2670819c95`,
  the PR #3312 and `project-conf` patches, the injection harness and the gdb
  transcript in `lab/frontier/contiki2shell/` (provenance in `PROVENANCE.md`).
  The two-pane window 134 was created by frontier at 05:48:30Z and adopted,
  not duplicated; registry 135/135 unique, both panes verified live, seed
  wall present.
- Operator verification 06:1xZ: re-ran `sh run-all.sh`, which SHA-checks the
  tarball and rebuilds the vulnerable, fixed and safe trees offline —
  `contiki-ng-release-v5.2.tar.gz: OK`, `RESULT: PASS=9 FAIL=0`, byte-for-byte
  the committed `REPLAY.md` receipt. This is an author-side transcript on the
  same host, not an independent witness verdict.
- Minted under the exact full-flag sync from `docs/runtime-pin.md:96-102` with
  pin `0d686bbad55c849e88334da64efff9da88ad528a`: `written 3, removed 0`;
  `m2shell-wake-contiki2shell.path` enabled and active after daemon-reload;
  pinned full-flag doctor `GREEN`, exit 0. Route count 129→130 (hy4-flash,
  `max_parallel: 3`); resolver 259→261 (both wake keys → operator).

## Current grade

Rungs 1-3 in the real Contiki-NG native consumer, from the pinned source:

1. Deterministic trigger — a crafted S=3 HBHO option with `len=4` is accepted
   with only four seed-ID bytes present; `accept()` stores the whole payload
   length, and the trickle timer's rebuild copies it with a 16-byte-larger
   header.
2. Confirmed corruption — ASan `global-buffer-overflow WRITE of size 1232` at
   `mpl.c:981` in `data_message_expiration()`, 16 bytes past the 1280-byte
   `uip_aligned_buf`, from the real trickle timer under the native platform.
3. Controls — PR #3312 applied to the same tree and a complete S=3 option both
   run clean.

Rung 4 is PARTIAL: a plain `-g -O0` gdb transcript places chosen
`MISHE-OO-TAUF!!\0` at `base+1280..+1295`. The adjacent object is a global
buffer, not allocator metadata or a live function pointer, and no pointer, IP
or control-flow target is claimed. Rung 5 is NO: no live network process — the
native platform could not open `/dev/net/tun` — no loopback wire replay, no
victim/fixed/safe wire controls and no command; wire reach stays UNKNOWN.

## W199 measurements (2026-11-24 06:41Z)

- Wire/tun route closed on this host: `/dev/net/tun` is `crw-rw-rw-` and
  `open()` succeeds, but the native driver's `TUNSETIFF` ioctl returns
  `EPERM` (`errno 1`; no CAP_NET_ADMIN in the host netns). `unshare -Urn`
  fails writing `/proc/self/uid_map` with EPERM, so no unprivileged
  namespace route. The pinned native platform has one network driver,
  `arch/cpu/native/net/tun6-net.c`, and no socket-based alternative. Wire
  reach stays UNKNOWN; nothing was sent to any network.
- Rung 4 strengthened in a lab-only non-default build
  (`UIP_CONF_BUFFER_SIZE=1400`, plain `-g -O0`, same truncated S=3 option):
  gdb at `mpl.c:979` (the retransmission `memcpy`) reports stored size 1352;
  before the copy `uip_appdata=uip_sappdata=0x55555559aafc`, after it
  `uip_appdata=0x4847464544434241` and
  `uip_sappdata=0x504f4e4d4c4b4a49` — chosen packet bytes "ABCDEFGHIJKLMNOP"
  now occupy two adjacent global pointers. `x/16bx` confirms the bytes at
  `uip_appdata` and `uip_sappdata`. A complete-S=3 control in the same
  build (stored size 1336) leaves both pointers unchanged. Transcripts:
  `lab/frontier/contiki2shell/large-buffer-attack-gdb.txt` and
  `large-buffer-safe-gdb.txt`; harnesses `harness-large.c` and
  `harness-large-safe.c`. The harness line "injected 0 bytes" is a cosmetic
  read of `uip_len` after `uip_input()` cleared it; the 1400-byte injection
  is proved by the breakpoint and stored size.
- Grade: rung 3 unchanged; rung 4 is now a chosen-pointer overwrite in a
  non-default 1400-byte build, not merely padding bytes. The chosen ASCII
  values are not valid addresses; no dereference, control-flow diversion,
  command or wire deliverer was exercised. Rung 5 remains NO. PR #3312
  rechecked 06:40Z: OPEN, merge state BLOCKED; the fixed control remains
  the proposed patch.
- Witness replay was requested by DM on 2026-11-24 06:40Z; no verdict yet.

## Next for the target mind

1. Await the independent witness replay requested on the tape at 06:40Z;
   author replay is not acceptance.
2. A wire route needs a real network driver that works without
   CAP_NET_ADMIN on this host. The native platform has only `tun6-net.c`
   and namespace creation is disabled, so no unprivileged tun path exists
   here. Do not substitute a synthetic socket driver and call it wire.
3. Continue pointer-chain work from the overwritten globals without a
   synthetic buffer-size change, and recheck PR #3312 for merge. Never
   infer RCE from a global-buffer overflow, chosen ASCII pointer bytes or
   advisory reachability prose; hand any new claim to `witness`.
