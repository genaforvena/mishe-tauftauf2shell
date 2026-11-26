# W282 — full vulnerable 5.5.x enforcer `dp` under ASan

Command: `bash lab/frontier/neuvector2shell/fulldp/run.sh` → **19 PASS /
0 FAIL**, rc 0. Raw logs, binaries and provisioned dev tree stay in the
ignored `fulldp/out/` and `src/deps/`; this file keeps the normalized,
address-independent facts.

## Build

The pinned vulnerable tree at `src/real/neuvector-48ae8b5c…/` was built
with its own `dp/Makefile`, not a stand-in consumer: `dp/dpi/sig/dpi_sig.c`
(SHA-256 `1fbf0ba4…3072b`), `dp/ctrl.c`, all `dp/dpi` parsers and
`dp/utils`, linked against real `libhs.so.5`, `libjansson`, `liburcu`,
`libpcap`, `libpcre2`, `libjemalloc` and netfilter libraries. Hyperscan and
dev headers were provisioned under `lab/` only (`src/deps/root/`); no host
package was installed and no external target was contacted. Flags:
`-O2 -g -fsanitize=address -fno-omit-frame-pointer -fno-stack-protector
-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0`, as in W278/W280's measured frame.

The fixed build substituted the byte-identical pinned fixed source
(SHA-256 `cc9d9c48…4b08`) into `dp/dpi/sig/dpi_sig.c`, rebuilt `sig.o`
and relinked; the vulnerable source was restored and rebuilt afterwards.

## Live path and result

`dp -s -n 1` binds the pinned enforcer control socket
`/tmp/dp_listen.sock` (`dp/ctrl.c:45`) and serves it in `dp_ctrl_loop()`.
The exact REST-valid W274 datagram (2233 bytes; name 256, 16 patterns of
64 bytes `a*`×32, pre-expansion total 1024 — every documented controller
limit) was sent from a bound `AF_UNIX SOCK_DGRAM` client. In the full
vulnerable enforcer process:

- `AddressSanitizer: stack-buffer-overflow`, `WRITE of size 121`;
- `[32, 2080) 'dlpsig_buf' (line 621) <== Memory access at offset 2080
  overflows this variable` — 0 bytes past the real 2048-byte object;
- write frame `dpi_sig_bld dp/dpi/sig/dpi_sig.c:658`, reached from
  `dp_ctrl_bld_dlp dp/ctrl.c:2191` — the real control handler, not a
  synthetic caller.

Controls over the same socket: the 139-byte safe datagram into the
vulnerable enforcer and the 2233-byte attack datagram into the fixed-commit
enforcer both stayed ASan-clean; the fixed build logs
`exceeds max sig len(2048) at pattern(14), skip rule`, the new bounds check.

## Ceiling

This advances the confirmed memory corruption from a lab consumer to the
**full enforcer binary**, on its real control socket with the real parser
and message path. It does not add a chosen address: the process faults
inside `dpi_sig_bld()` before returning, with ASCII regex bytes in the
overwritten frame words (same bytes as W278/W280's measured real-object
frame). There is no REST/CRD endpoint, no benign command and no rung-5
side effect. Grade remains rung 3 confirmed / rung 4 PARTIAL as labeled.

## W283 — plain optimized full-enforcer frame readback

Command: `bash lab/frontier/neuvector2shell/fulldp/frame.sh` → **22 PASS /
0 FAIL**, rc 0. The same pinned tree is rebuilt by its own `dp/Makefile`
with `-O2 -g -fno-omit-frame-pointer -fno-stack-protector
-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0`, with no ASan runtime (verified by
`nm`: zero `__asan` symbols). Vulnerable binary SHA-256
`8254649ba9d4ab315664c8d36caebb1dfb1c2f8e37a3075a40c5d792ba8c4a64` for
this build. The same 2233-byte REST-valid datagram is delivered over the
real AF_UNIX socket while the real enforcer runs under gdb.

At the real in-loop SIGSEGV (`dpi_sig_bld`, `dpi_sig.c:657`) the live frame
reads `BUF=0x7fffffffccc0`, `RBP=0x7fffffffd4f0`, `BUF→RBP=2096`,
`LEN=2194`. Saved words are chosen wire bytes: `a*` gives saved RBP
`0x2a2e612a2e612a2e` and return slot `0x2e612a2e612a2e61`; `B*` gives
`0x2a2e422a2e422a2e` / `0x2e422a2e422a2e42`. The breakpoint at
`dpi_sig.c:662` is installed but never reached; the fault happens inside
the pattern loop. Controls without gdb: attack datagram faults with
`RC=139`; safe 139-byte datagram and attack into the fixed-commit plain
binary survive to timeout, and the fixed binary skips the rule.

Ceiling unchanged: both saved words contain ASCII regex bytes, not a
chosen address; the process faults before returning. No command, no
side effect, no r5. W283 is the live full-enforcer realization of the
W278/W280 measured frame, not a new primitive.
