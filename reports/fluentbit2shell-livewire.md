# fluentbit2shell — live-wire PONG overflow in a real Fluent Bit process

**2026-11-23 07:42Z, first target-mind wake.** This upgrades the frontier's
direct-call harness result (`
reports/frontier-fluentbit2shell.md`) to a real `fluent-bit` 5.0.7 process
that receives a crafted Secure-Forward PONG over a loopback TCP connection.
No command, ROP chain, side effect or witness verdict: rung 4 with an
explicit build-configuration caveat, rung 5 stays UNKNOWN.

## 1. Provenance of the running bytes

- Public source fetch (provisioning only): `v5.0.7.tar.gz` SHA-256
  `a760cdce272d6025100346d27315cc03a9b3466e5a8a24aaae6f2ad6a9cda29f`,
  extracted to the gitignored site lab `.mishe-tauftauf/live/fluentbit2shell/fluent-bit-5.0.7`.
- The built tree's `plugins/out_forward/forward.c` was verified byte-identical
  to the pinned vulnerable blob: SHA-256
  `406f2d229d805bae08c6570e333f22b3cfc4db361780d21a28725a7dc37c9687`
  (`lab/frontier/fluentbit2shell/src/forward.c.v5.0.7`). The pinned fix patch
  applied cleanly and produced
  `cb2f62d730736827b13e0cc5fde6135d3f1c47c43248913d5d81e7dd1ec71ea7`
  (`forward.c.v5.0.8`). The patch was reverted afterwards.
- ASan build: `cmake -S fluent-bit-5.0.7 -B build-full -DSANITIZE_ADDRESS=On
  -DFLB_SHARED_LIB=Off -DFLB_EXAMPLES=Off && cmake --build build-full -j2`.
  Binary SHA-256 `6248b3c50ffd9211053bd5964d9d5f6e9df17200e7146fa0384ab19615bd472d`;
  `ldd` shows `libasan.so.8`. Plain build: same configure without
  `-DSANITIZE_ADDRESS=On`, binary SHA-256
  `77087ed88b137310797c507fa3dc19db19cc8f37fcf7d42c208fb02879ebf2d8`.
  Fixed ASan control (same build dir after applying the fix patch): binary
  SHA-256 `696c90fc29742d5e3b20312b045a7038d72579cc6e4cbdfa2198d4bf96ff9eb7`.
- Two build-environment-only edits were needed in the throwaway source tree
  during earlier minimal-config attempts: a generated Monkey `mk_info.h`
  stand-in and an added `#include <fluent-bit/flb_upstream_ha.h>` in
  `src/flb_http_client.c`. Neither touches `out_forward/forward.c` or the
  handshake functions. An aggressive minimal-plugin configuration was
  abandoned after unrelated upstream compile errors; the successful builds
  use upstream-default features.

## 2. Attacker-side mechanism (source-bound)

`secure_forward_handshake()` (`forward.c.47db630c:576-653`) waits for a server
HELO, sends a PING, then reads the PONG with `secure_forward_read()` and calls
`secure_forward_pong()`. The read path goes straight to `fc->io_read` into a
1024-byte stack buffer: there is no wire decryption and no verification of the
PONG's contents. A malicious upstream therefore needs only a well-formed
`["HELO", {"nonce": <bin16>}]` followed by
`["PONG", false, <oversized STR>, "h", "d"]` — no SRP, TLS, matching shared
key, or server-side hash computation. The 1000-byte reason fits the 1023-byte
read with ~9 bytes of msgpack framing to spare.

## 3. Harness (committed, loopback only)

`lab/fluentbit2shell/` contains `malicious_forward.py` (raw msgpack encoder,
127.0.0.1 bind, reason markers at offsets 0/17/24/33/40/48/56/63,
`--authorized` and `--short` controls), `victim.conf.in` (`out_forward` to
127.0.0.1 with `Shared_Key livewire-secret`), `run_live.sh` and the two gdb
scripts. No external host is contacted; every server binds 127.0.0.1 only.

```sh
# from the repo root, with the built binary paths from §1
bash lab/fluentbit2shell/run_live.sh "$PWD/<site>/build-full/bin/fluent-bit" \
     20243 attack v507-attack
FB_BIN="$PWD/<site>/bin-v507-plain" \
     bash lab/fluentbit2shell/gdb_plain.sh 20251
```

Replay from the committed harness reproduced the crash and the frame bytes on
ports 20253/20254; generated evidence is gitignored under
`lab/fluentbit2shell/evidence/`.

## 4. Observations

| Run | Victim bytes | Observed |
|---|---|---|
| attack, ASan build, port 20243 | 1000-byte reason | `AddressSanitizer: stack-buffer-overflow`, `WRITE of size 1000`, thread T3 `flb-out-forward`, `secure_forward_pong forward.c:567` ← `secure_forward_handshake:645` ← `cb_forward_flush:1629`; object `msg` `[256,288)`; rc 134 |
| safe: `PONG[1]=true`, port 20244 | oversized reason present | `handshake status = 0`, no ASan, no crash |
| safe: 4-byte reason, port 20245 | `safe` | `failed authorization: safe`, `handshake status = -1`, no ASan |
| attack, fixed ASan build, port 20247 | 1000-byte reason | bounded 31-byte `failed authorization: AAAA…Z…z…`, `handshake status = -1`, no ASan, no crash |
| attack, plain build, port 20252 | 1000-byte reason | `*** stack smashing detected ***: terminated`, rc 134 (default build keeps a stack canary) |
| gdb, ASan build with `replace_intrin=0`, port 20250 | same attack | breakpoint at `forward.c:568` in T3: chosen bytes at `msg` offsets 0=41, 17=5a, 24=7a, 40=7b, 48=42, 56=7b, 63=41 |
| gdb, plain build, port 20251 | same attack | `&msg = …6ca0`, `$rbp = …6cd0`, `$rbp - &msg = 0x30`; `x/gx $rbp+8` and `x/gx msg+56` = `0x414141414141417b`; backtrace frame 1 = `0x414141414141417b` |

The full ASan report and gdb transcripts were captured in the gitignored site
lab `evidence/v507-attack3.asan.3493173`, `gdb-live.out`, `gdb-plain.out`;
the tables above quote the decisive lines so the result survives without
those local artifacts. Two earlier attempts with a malformed hand-rolled
msgpack encoder stopped at `Invalid HELO type message`; they are preserved in
the site lab under `v507-attack` and `v507-attack2` and are not evidence of the
sink.

## 5. Rung assessment

- **Rung 3 (confirmed memory corruption):** met on living bytes — ASan reports
  the 1000-byte stack write in the real `secure_forward_pong()` of a real
  5.0.7 process reached through the real HELO/PING/PONG wire path, with fixed,
  authorized and short-reason controls clean.
- **Rung 4 (chosen bytes / pointer control):** met in the frame of the real
  flushing thread. The plain-build gdb observation places the chosen bytes at
  both saved-RBP (offset 48) and saved-RIP (offset 56), with the corrupted
  return address visible as backtrace frame 1. **Caveat:** the default build's
  stack canary aborts at function return, so this build never transfers
  control to the chosen address; the frontier's separate direct-call harness
  with `-fno-stack-protector` observed execution reaching the chosen RIP.
  No benign marker or command was executed here.
- **Rung 5:** UNKNOWN. No ROP chain, command, side effect, persistent control,
  or independent witness. The advisory's `system()`→root and `--supervisor`
  BROP claims remain claims.

Threat model: attacker is a malicious or on-path upstream forward destination;
victim is a forwarding agent that connects on first flush with `Shared_Key`
configured. This is not an unauthenticated inbound listener bug.

## 6. Next bounded work

1. Build a real 5.0.7 binary with `-fno-stack-protector` and repeat the gdb
   frame test to see the chosen RIP actually taken in a live process; record
   whether any benign marker can be placed and reached without ASan.
2. Only after (1), consider a witness replay and any rung-5 claim.
