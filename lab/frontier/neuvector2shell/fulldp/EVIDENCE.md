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

## W285 — tuned message reaches the epilogue; wire sets the faulting RIP

Command: `bash lab/frontier/neuvector2shell/fulldp/return.sh` → **18 PASS /
0 FAIL**, rc 0, using the same plain `-O2` full enforcer binaries built by
`frame.sh`. The W283 message wrote `LEN=2194`: the caller's `dlpsig`
argument lives at `BUF+2144` (gdb: `BUF=0x7fffffffcc70`,
`dlpsig=0x7fffffffd490`), so that loop destroyed the argument and faulted
at `dpi_sig.c:657` before returning. W285 instead keeps 15 full 120-byte
patterns and shortens the 16th to a 36-byte `pcre` string, so the final
`sprintf` content ends at `BUF+2110`: with `context body` the value is 12
`X` bytes, with `context url` it is 13, both REST-valid (name 256, 16
patterns, pre-expansion totals 972 / 973 B, each pattern <=512 B). The two
datagrams are 2149 B each.

Under gdb (`set disable-randomization` is on by default for the inferior),
`break dpi_sig.c:662` **is reached** for both. Live frame:
`BUF→RBP=2096`, `LEN=2110`; bytes `BUF+2104..2109` are the tail of the
pinned controller wrapper, `BUF+2110` is the `sprintf` NUL and `BUF+2111`
keeps its original zero. The saved return word is `0x3b79646f6220`
(`" body;\0\0"`) for context `body` and `0x3b6c72752074`
(`" url;\0\0"`) for context `url`; continuing from the breakpoint faults at
exactly those RIPs. Plain non-gdb controls: tuned message faults the
vulnerable binary (`RC=139`), the safe 139-B datagram and the tuned message
into the fixed-commit binary survive, and the fixed binary logs
`exceeds max sig len(2048) … skip rule`.

Ceiling, with the causal reason: the last two bytes of any chosen wire
string cannot contain NUL (jansson strings are C strings and `sprintf`
stops at NUL), so a canonical user-space return address must take its
high zero byte(s) from the terminating `sprintf` NUL and the untouched
slot byte. The NUL therefore lands at `BUF+2110` (return byte 6), and the
six bytes below it are the *fixed* `; context body;` / `; context url;`
tail written after the attacker's value. `agent/system.go:1017-1025`
restricts the context to four short constants (`url`, `header`, `body`,
`packet`; `controller/rest/dlp_rule.go:374-380` rejects any other), so
those tail bytes cannot encode an executable address. W285 is a measured
post-overwrite control transfer to a wire-determined unmapped pointer in
the live full enforcer — still rung-4 mechanics, not a chosen address, no
benign marker, no command, no r5. Grade stays rung 3 confirmed / rung 4
PARTIAL as labeled; witness replay is pending.

## W287 — chosen wire tail cannot form an executable return address

Command: `bash lab/frontier/neuvector2shell/fulldp/chosen.sh` → **12 PASS /
0 FAIL**, rc 0. Hypothesis: W285's fixed `; context <allowed>` tail comes
from the upstream controller/agent, not from `dpi_sig_bld()`; a directly
crafted dp-socket message could replace it with chosen bytes. Only one
caller exists in the pinned tree (`dp/ctrl.c:2191`), and
`dpi_sig.c:651-662` writes only `sprintf(...)` strings plus one NUL.

The last pattern was replaced with a 29-byte string ending in `ABCD`
(2148-B datagram). Under gdb the live `-O2` full enforcer reaches
`dpi_sig.c:662` with `BUF→RBP=2096`, `LEN=2109`. The saved return slot at
`BUF+2104..2111` reads `41 42 43 44 3b 00 00 00`: bytes 0-3 are the
chosen wire bytes, byte 4 is the fixed `;` from `sprintf("pcre %s;")`,
byte 5 is its NUL, bytes 6-7 are untouched zero. Continuing faults at
`RIP=0x3b44434241` — chosen low bytes, but a truncated unmapped pointer.
Plain controls: vulnerable `RC=139`, safe survives, fixed survives and
logs `exceeds max sig len(2048) … skip rule`.

Byte algebra of this consumer, independent of the upstream wrapper: the
final `sprintf` always terminates with `;` (0x3b) and a NUL. If that NUL
lands at return byte 5, bytes 0-4 are wire bytes but byte 5 is zero, so
the pointer cannot reach this PIE binary's text at
`0x555555558000..0x555555592000` (which needs byte 5 = 0x55). If it
lands at byte 6 (W285), byte 5 is 0x3b and byte 6 zero — still below the
text range. If it lands at byte 7, byte 6 is 0x3b, producing a pointer
far outside the mapped user range. A NUL inside a jansson string cannot
help: `strlcpy` in `dp_ctrl_bld_dlp` copies only up to the first NUL, and
`sprintf("%s")` stops there, so the `;`/NUL pair still caps the high
bytes. Attempting a six-nonzero-byte PIE address (0x555555561120,
0x555555561160) failed at the harness's own assertion before any run —
preserved here as a negative, not retried into existence.

Conclusion: no chosen executable address, benign marker, command or r5;
the grade remains rung 3 confirmed / rung 4 PARTIAL as labeled. This does
not weaken W285's live control transfer: the wire still determines the
faulting RIP, only its low bytes are now attacker-chosen.
