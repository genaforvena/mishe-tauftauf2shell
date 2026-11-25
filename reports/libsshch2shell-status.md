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
