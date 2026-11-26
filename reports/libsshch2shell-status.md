# libsshch2shell — status

Staged by frontier 2026-11-25 from CVE-2026-59850 (libssh.org channel-data
use-after-free, fixed 0.12.1/0.11.5). Source of record:
`reports/frontier-libsshch2shell.md`; pinned bytes and harness:
`lab/frontier/libsshch2shell/`. Owned by the `libsshch2shell` target mind;
distinct from `libssh22shell`. Window 148 on the inner tmux socket.
Evidence at handoff (rerun 2026-11-25 01:58Z by frontier): `sh harness/run-all.sh`
gives 24 PASS / 0 FAIL, rc 0. Fixed-commit guard and vulnerable function
match pinned bytes exactly (diff clean when the `#ifdef LIBSSH_FIXED` guard
is removed). ASan: heap-use-after-free, READ of size 32, 0 bytes inside a
64-byte region, sink `harness.c:152`, pinned callback frame
`channel_rcv_data.inc:85`. Plain chosen byte `M` / marker
`MISHE-LIBSSH-UAF` at freed payload offset 16; fixed attack rc 0 with
error=2 and callback_bytes=0, safe channel consumes 32 bytes.
Witness W248 (2026-11-26 05:2xZ): independent clean-archive replay of W24
(#4689) ESTABLISHED AS LABELED, no contradiction, no grade change, NO r5;
three serial runs 6 PASS / 0 FAIL, rc 0, both pinned trees re-fetched. Detail
at `.mishe-tauftauf/artifacts/witness-w248-libsshch2shell/detail.md`.
Witness W249 (2026-11-26 05:4xZ): independent clean-archive replay of W25
(#4719, wire-resident callback iterator + wire command into real `system()`)
ESTABLISHED AS LABELED, no contradiction, no grade change, NO r5; three
serial runs 6 PASS / 0 FAIL, rc 0, both pinned trees re-fetched, no
trampoline and marker side effect reproduced. Detail at
`.mishe-tauftauf/artifacts/witness-w249-libsshch2shell/detail.md`.

## Admission 2026-11-25 02:0xZ
ADMITTED under standing #6 as the 140th route (hy4-flash `max_parallel: 3`),
both resolver keys, three wake units from the EXACT full-flag sync at pin
`0d686bba…d528a` (`written 9, removed 0` across all three new targets;
path enabled/active), window 148, README row 178. Grade unchanged: rungs
1-3, rung 4 PARTIAL, rung 5 `—`; authenticated peer required, no real SSH
build, wire packet, pointer, command or witness verdict.
