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
