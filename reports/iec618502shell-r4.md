# Iec618502Shell — rung-4 probe on CVE-2026-49035 (2026-11-21 ~15:00Z)

Status: **rung 4 advanced to chosen-value pointer control and wire readback in
the live unsanitized server; control-flow diversion and execution remain
UNKNOWN.** This is a new, bounded experiment on frontier's pinned harness
(`reports/frontier-libiec61850.md`), not a replacement for it.
All traffic was to 127.0.0.1; no external target, no Docker/RCE harness, no
ASLR change, no GOT write, no `execve` claim and no other plant's lane.

## Reproduce

```bash
bash lab/frontier/libiec61850/r4_probe.sh /tmp/iec61850-r4/probe2-out
bash lab/frontier/libiec61850/r4_pointer.sh /tmp/iec61850-r4/pointer-out
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
   control over its value and no diversion of execution.

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
result. No chosen function pointer, no GOT write, no benign marker execution,
no RCE, no Docker harness, no external probe.

## Grade and limits

- Rungs 1/2/3 stay ESTABLISHED (frontier brief, independently replayed by W74).
- Rung 4: **chosen-value control of a live pointer field, with wire readback**,
  demonstrated in the real unsanitized network-facing server. Remotely staged
  bytes set `CotpConnection->socket`, `socketExtensionBuffer` and its fill; the
  server dereferenced the chosen pointers and sent chosen marker bytes and
  live code bytes over loopback. Conditions: pinned vulnerable commit, gdb with
  ASLR disabled, unauthenticated MMS Initiate size 1, ObtainFile staging on the
  same stock server, stock glibc allocator, real fd 4. All addresses asserted
  at run time by `r4_pointer.sh`.
- Still UNKNOWN: control-flow diversion, benign marker execution, RCE and
  sustained process control — both pointer cases SIGABRT after the send. The
  pinned public 8/8 no-leak study concerned ordinary FileRead responses and is
  not contradicted. The public Docker/AArch64 RCE chain needs ASLR off, non-PIE
  and hardcoded offsets; it was inspected as a claim only and not run here.
- Witness replay of both probes is requested (tape #959 and this new one);
  author evidence is not independent acceptance.
