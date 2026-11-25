# Replay — shipped 3.20b, same wire TERM, fixed-form control (W22)

Time: 2026-11-25 08:20Z and 08:22Z (two consecutive clean replays). Advisory
CVE-2026-133646. All SSH clients connect only to 127.0.0.1; the source fetch
from the public GitHub mirror is provisioning, not testing.

## What changed

The earlier W21 lane showed the live 64-byte TERM writing chosen bytes into
`savedlines.first/.last` of a real shipped 3.20b `sbbs_t`, then faulting at
teardown. The missing control was the **same release and same wire input with
only the upstream fix applied**. 3.20b already carries
`get_binary_crypt_attribute` / `free_crypt_attrstr` in its own `ssl.c`
(verified byte-identical to `pins/ssl.c:34-61`), so no helper port was needed.

`patch-fixed.py` replaces the no-size block in the ignored exact-release
worktree `src-tree/320b/src/sbbs3/answer.cpp` with statements read verbatim
from `harness/fixed.inc` (pinned `answer-fixed.cpp:542-549`, extracted by
`harness/gen.sh`). The only mechanical adaptation is `client_socket.load()` →
`client_socket` (3.20b uses a plain int). One instrumentation `lprintf` is
inserted after the pinned `SAFECOPY`; it changes no copy logic. The script
then re-reads the file, removes that probe line, restores the atomic spelling
and requires an exact match with the pinned hunk: it printed
`FIXED_HUNK_PINNED_OK lines=8 probe=1`.

## One-command replay

```
bash lab/frontier/synchronet2shell/release-label/term320b/fixed320b/run-fixed320b.sh
```

Prerequisite: the ignored exact-release worktree at `src-tree/320b` and the
lab build prefix from the W5/W21 lanes. The script verifies the worktree HEAD
equals `db9c5d6fd37ef74b6e6ca647308d351e656de18d`, restores `answer.cpp` on
exit, and uses per-PID loopback ports in the 24000 range (W21 uses 23000).

Expected output, observed twice (08:20Z and 08:22Z):

```
PASS vulnerable 3.20b: chosen pointer pair written by 64-byte TERM
PASS vulnerable 3.20b: node thread never reaches destructor end
PASS fixed copy statements are byte-exact pinned cb6d77dbca hunk
PASS fixed 3.20b: 64-byte wire TERM leaves adjacent fields clean
PASS fixed 3.20b: node thread completes teardown
RESULT: PASS=5 FAIL=0
```

Both phases rebuild the real `sbbs3` binary (`provision/build-w5.log` contains
`Compiling answer.cpp`); only `answer.cpp` is patched. Both phases send the
same 64-byte TERM: 41 x A, 3 x B, `MISHE-OOTAUFTAUF`, 4 x Z.

Key live lines from the second replay:

```
vulnerable: REAL_320B_PROBE sizeof=41 l=64 off41=42 cv=4853494d first=0x465541544f4f2d45 last=0x5a5a5a5a46554154
            Node 1 destructor begin                 (no destructor end)
fixed:      FIXED_320B_PROBE sizeof=41 wire=64 len=40 off41=00 cv=00000000 first=(nil) last=(nil)
            Node 1 destructor begin
            Node 1 destructor end
```

The fixed probe reports the same 64 bytes arriving on the wire
(`wire=64`) but `strlen(terminal)=40`, so `SAFECOPY` truncated to the 41-byte
field and byte 41 stayed zero. `cterm_version` and both `savedlines` pointers
stayed clean and teardown completed. The vulnerable phase in the same run
reproduced W21's chosen pointers and missing teardown, so the difference is
the fix hunk rather than a different client or configuration.

Evidence hashes from the second replay (`evidence/`):

- `run.log` sha256 `8825f5e07f8be4cbbfdb5e8f0c36eb525f93cf3369842d1b0e8d1e5c20004e54`
- `pinned-hunk.log` `0b8ac3b45f070e387342a558670135a5e6c6f9bb9a9644d8c0521e2258684f73`
- `server-vuln.log` `d02da63593342ea8e7e4e27cd50403e2ac8ccfa70bc3752335ec3de523b0a59f`
- `server-fixed.log` `0fda182c4a574cf67bafeeacd711a383c995831c7848ff2cf63cb1c29c7a2f7c`

Server logs embed timestamps, ports and PIDs, so these hashes are exact for
the named artifacts, not normalized replay invariants. Client logs for both
phases are in the same directory.

## Honest ceiling

This is a vulnerable/fixed control in a real 3.20b binary with a real loopback
wire TERM. It confirms that the upstream hunk removes the measured adjacent
field overwrite and the teardown fault. An author clean-archive replay from
`git archive 7d3a0088` reproduced 5 PASS / 0 FAIL with the same probe lines;
its receipt is `evidence/CLEAN-ARCHIVE.md`. It is not a witness verdict, not a
measured DoS rate, and not evidence of pointer/IP or command control. No rung
change; the advisory's availability ceiling stands.
