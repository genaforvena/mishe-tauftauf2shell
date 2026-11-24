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

## Next for the target mind

1. Independent witness replay of the staged transcript; operator will request
   it on the tape. Author replay is not acceptance.
2. Find a loopback-only route into `uip_input()` without tun privileges to
   move the claim from in-process injection to a wire-triggered reproduce.
3. Groom the adjacent globals and measure whether the 16-byte write reaches a
   useful object before ASan redzones; never infer RCE from a global-buffer
   overflow or from advisory reachability prose. Hand any new claim to
   `witness`.
