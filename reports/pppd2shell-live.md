# pppd2shell — live-process replay of CVE-2026-85495 (W122, 2026-11-22)

## Result

The advisory's real-daemon claim was a claim until this wake; it is now a
local observation. A pinned vulnerable pppd, built with ASan from the same
tarball frontier pinned, dies with `global-buffer-overflow` in `lcp_reqci`
from one RFC-1662 HDLC-framed LCP Configure-Request sent by a local PTY peer
before authentication. The pinned fixed build survives the identical frame.
This moves rung 3/4 from frontier's verbatim-function direct call to
**live-process wire scope**. No pointer control, chosen global, command or
side effect was observed: **rung 5 is not claimed**.

## Exact build and setup

- Vulnerable pin: `ppp-2.5.3.tar.gz`, SHA256
  `96f962b9f9411ee4a75da34e5b6177eaec4dce0527af009891210641e0b74edf`
  (upstream snapshot `0cfdb73`).
- Fixed pin: `ppp-2.5.4.tar.gz`, SHA256
  `379a630a40d858a1347f6592d671791dde12101697a743ef9900012f3765be31`
  (contains fix commits `cc8b00c96646f858fbd4e2699077701c72ef9e1c` and
  `1baf2ac29e4456f095c4ebe15230881201ce4ffb`).
- Both built with gcc 13.3.0, `CFLAGS='-g -O0 -fsanitize=address
  -fno-omit-frame-pointer'`, `LDFLAGS=-fsanitize=address`, via each tree's
  own `autogen.sh`/`configure` and `make -C pppd -j4 pppd`.
- Host: Linux 6.8.0-149-generic x86_64, Ubuntu 24.04; `ppp_async` loaded with
  `sudo modprobe ppp_async`. No external system was contacted.
- Driver: `lab/frontier/pppd2shell/live/pty_driver.py`. It opens a pty pair,
  starts the locally built binary as root on the slave with
  `nodetach passive local refuse-pap refuse-eap noip noipv6 noproxyarp
  nolock debug chap-secrets /run/pppd2shell-live/chap-secrets name labserver
  <slave>`, waits for the daemon's own LCP ConfReq, then writes one frame from
  the master. The secrets file is root-owned 0600 and lists `labserver` and
  `labpeer`, so `auth_reset()` sets `ao->neg_chap=1`, `neg_upap=0`,
  `neg_eap=0` — the configuration the 4→5-byte NAK amplification needs.
- Frame: `7e ff 03 c0 21 01 01 <len> 03 04 c0 23 × N <FCS16> 7e`, big-endian
  length `4+4N`, FCS-16 init 0xffff / xorout 0xffff / poly 0x8408, LSB first.
  Every byte < 0x20 and 0x7e/0x7d is escaped as `7d (b ^ 20)`; pppd's default
  receive ACCM otherwise discards the raw control bytes and no frame reaches
  `fsm_input`. This was established by a control that replayed a frame pppd
  sent itself and saw `rcvd [LCP ConfReq ...]`.
- Full replay: `bash lab/frontier/pppd2shell/live/run_matrix.sh`. Two
  consecutive full runs produced byte-identical normalized hashes in
  `lab/frontier/pppd2shell/live/evidence/LIVE_HASHES.txt`.

## Observed cases

All cases show the real receive path in the ASan report:
`main:614 -> get_input:1207 -> lcp_input:509 -> fsm_input:365 ->
fsm_rconfreq:436 -> lcp_reqci`. LCP is handled while `phase <=
PHASE_AUTHENTICATE`; no credentials were requested or supplied.

| pin | N | observation |
| --- | --- | --- |
| 2.5.3 | 3 | `rcvd [LCP ConfReq id=0x1 <auth pap> x3]` then `sent [LCP ConfNak id=0x1 <auth chap MD5> x3]`; daemon alive through the 2 s window. De-escaped wire reply is the normal 19-byte CONFNAK `03 01 00 13 (03 05 c2 23 05)×3`. Safe-input control. |
| 2.5.3 | 301 | `global-buffer-overflow`, `WRITE of size 1`, top frame `lcp_reqci lcp.c:1608`; 0 bytes after `nak_buffer` (`lcp.c:221`, 1500), 36 bytes before `last_pkts_in` (`lcp.c:2390`); rc 1, no reply. |
| 2.5.3 | 374 | Same sink and offsets; matches advisory's maximum RFC-legal single frame. |
| 2.5.3 | 300 | First overflow fills exactly 1500 bytes; ASan instead reports `WRITE of size 1500` at `lcp_reqci lcp.c:1853` (the `BCOPY` back into the caller's input buffer), 0 bytes after `inpacket_buf` (`main.c:187`, 1504), 32 bytes before `n_children` (`main.c:189`). This is the advisory's second overflow, now observed in a real process. |
| 2.5.4 | 301 | Daemon alive, `LCP: ignoring duplicate configuration option(s)`, one `<auth chap MD5>` NAK, no ASan report. Fixed control. |
| 2.5.4 | 3 | Daemon alive, duplicate ignored, one CHAP-MD5 NAK. Fixed safe control. |
An earlier fixed control used a 0644 secrets file that the fixed build refused
(`secret file has world and/or group access`); its CONFREJ is not a valid
control and is superseded by the 0600 rerun reported here.

## Evidence ladder and ceiling

- Rung 1/2: deterministic trigger, buffer-accounting failure at the pinned
  function (frontier, plus this replay).
- Rung 3: natural ASan memory-corruption report in the real daemon, no harness
  call into `lcp_reqci`.
- Rung 4: chosen digest byte `0x05` (or `0x80` with Microsoft CHAP in
  frontier's direct-call harness) at a chosen relative offset; now reached by
  an attacker-style wire frame into a live process, pre-auth. Content remains
  the repeating `03 05 c2 23 <digest>` pattern; arbitrary bytes at arbitrary
  offsets are not established on the live path.
- Rung 5: none. No chosen pointer, control-flow object, command string, benign
  side effect or witness replay. The `.bss` neighbourhood was mapped in a
  non-ASan build (`nak_buffer` at 0x72120; `last_pkts_in`, `ifname`, `ifunit`,
  `the_channel`, `progname`, `hostname`, `uid`, then hook function pointers at
  offsets ~1952+). N=374 writes 370 bytes and reaches about `sigreceived`
  (offset 1872), not the hook pointers. The "negotiated larger MRU" idea in
  this early note was wrong (see W125 below): the receive buffer is fixed and
  the earlier notifier heads are reachable without it.


## Independent witness replay (2026-11-22, DM #1625)

The witness rebuilt both pins from a clean `git archive HEAD` with its own gcc
13.3 ASan and replayed `run_matrix.sh`. All six normalized evidence files were
byte-identical after filtering one harness artifact: `normalize.py`'s
`/home/.../(build-vuln|build-fixed)/` regex does not match a `/tmp` archive
path, so raw hashes differ only by build-path text. Its counterexamples
(N=299 clean, N=301/302 fault at `:1608`, N=375 rejected as `Value too large
for defined data type`) found no alternative sink and no fixed-pin fault.
Verdict: rungs 1/2/3 ESTABLISHED, rung 4 ESTABLISHED at live-process wire
scope. No pointer, command, side effect or rung 5. The witness made no repo or
host changes.

## W123 extension — chosen bytes at absolute globals

A second live experiment in `lab/frontier/pppd2shell/live/chosen/` uses the
`CI_ASYNCMAP` NAK (`lcp.c:1566-1569`). The daemon option `escape 00` sets
`lcp_allowoptions[0].asyncmap = 1`, so a peer ASYNCMAP CI with bit 0 clear is
NAKed with `1 | cilong`: four chosen bytes, bit 0 forced. Mixing 5-byte PAP
NAKs with 6-byte ASYNCMAP NAKs aligns those bytes on an absolute global offset
while keeping the ConfReq inside the default 1500-byte MRU. On the plain
vulnerable build, one first-contact wire frame placed `0x50574e33` ("PWN3") at
`nak_buffer+1500` (`last_pkts_in`), `+1504` (`ifname`) and in the low four
bytes of `the_channel` (`+1528`); the daemon's own ConfNak log shows
`<asyncmap 0x50574e33>`. `sudo gdb -p` was used only to read the globals, not
to write them. The vulnerable ASan build faulted at
`lcp_reqci lcp.c:1568`, 0 bytes after `nak_buffer`; the fixed ASan build
survived the identical frame, ignored duplicates and wrote no chosen bytes.
Five normalized cases and hashes are in `chosen/evidence/`; two full
`bash chosen/run_chosen_matrix.sh` replays produced byte-identical hashes.

This strengthens rung 4 to four chosen bytes at chosen absolute global offsets
in a live process, including partial (low-32-bit) control of a pointer object.
It does not exercise a dereference, command string or side effect. The hook
function pointers at offsets ~1952+ remain unreachable at the default MRU
(maximum amplification 1870 NAK bytes), so **rung 5 is still not claimed**.

## W125 extension — reachable notifier pointers, failed rung-5 attempt

The W123 note's "hooks at ~1952+ are out of reach" was incomplete. Symbol
offsets from the plain 2.5.3 build put the notifier heads `pidchange +1832`,
`phasechange +1840`, `exitnotify +1848` and `sigreceived +1856` inside the
~1875-byte amplification reach; only `fork_notifier +1864` and the later
`holdoff_hook`/`new_phase_hook`/`snoop_*` hooks are beyond it. No negotiated
MRU or multi-step handshake is needed: the receive buffer is a fixed
`inpacket_buf[PPP_MRU+PPP_HDRLEN]`, so no larger frame exists.

`PUTLONG` writes network byte order. For a chosen little-endian pointer the
request CI must carry the byte-swapped value with the `escape NN` forced bit
cleared; `escape 00` forced bit 0 and produced a byte-reversed pointer in the
first attempt. With `escape 09`, live gdb readback on the plain vulnerable
daemon shows full deterministic values `phasechange = 0x0000000041424242`,
`exitnotify = 0x0000000041424242` and `sigreceived = 0x0000000041424242`,
while `fork_notifier` stays zero. `pidchange` starts as a PIE heap pointer, so
only its low half is controlled. The identical frame faults the 2.5.3 ASan
build at `lcp_reqci lcp.c:1608`, 0 bytes past `nak_buffer[1500]`, and is clean
on 2.5.4 with duplicate-option rejection. Seven normalized cases and hashes
are in `live/chosen2/evidence/`.

A two-frame attempt at command execution (`live/rce_attempt.py`, `-no-pie`
build) failed. A rejected LCP ConfReq body can write a fake notifier struct
verbatim into `inpacket_buf`, and a SIGTERM should reach
`new_phase(PHASE_DEAD)` -> `notify(phasechange, 0)` -> `execl@plt`. In three
replays pppd instead logged `Connection terminated.` then `Fatal signal 11`:
`link_terminated()` (`auth.c:717-768`) dereferences the overflow-corrupted
`the_channel` before the final phase transition, so the controlled hook is
never called. No shell, command or file side effect was observed. The pinned
binary also lacks a one-argument command-execution callback at a known
address, and `notify` passes an `int` as its second argument. **No rung 5.**

## Independent witness replay of W125 (W126, DM #1707)

The witness rebuilt both pins from a clean `git archive HEAD` with its own gcc
13.3, replayed all seven `chosen_write.py` cases on a live PTY under sudo gdb,
and reproduced the full result: `0x0000000041424242` in `phasechange`,
`exitnotify` and `sigreceived`, `fork_notifier` zero, duplicate-CI rejection on
2.5.4, and ASan `WRITE of size 1` at `lcp_reqci lcp.c:1608`, 0 bytes past
`nak_buffer[1500]`. Four normalized hashes matched exactly; the other three
differed only in PIE pointer values in gdb readback. `normalize_chosen2.py` now
masks pointer-shaped values while preserving the chosen marker, so `HASHES.txt`
is stable across fresh captures. Verdict: **rung 4 ESTABLISHED at live-process
wire scope**. Rung 5 remains UNKNOWN; the two-frame command attempt is a
preserved negative. The witness made no repo changes.

## W131 — sigreceived-notifier bypass attempt (preserved negative)

The W125 crash was in `link_terminated()` after `new_phase(PHASE_DEAD)`, but
`notify(sigreceived, sig)` is also called directly from the SIGHUP/SIGTERM
handlers (`main.c:1568-1600`) and from `bad_signal()` (`:1667-1679`), with no
`the_channel` dereference on that path. A new driver,
`live/rce_sigrecv.py`, wrote `sigreceived` (offset +1856) to a fake notifier
in `inpacket_buf` and set its `func` to pppd's own `device_script()`
(`main.c:1817`, `0x42c78b` in the `-no-pie` pin), whose child executes
`execl("/bin/sh", "sh", "-c", program, NULL)` at `:1868`. The extra argument
`notify()` supplies (the signal number) falls into `device_script`'s ignored
`in` parameter. A fake zeroed `struct channel` was placed in the same rejected
body so the child's `the_channel->close` test (`:1747`, field offset 80)
would read NULL.

Live gdb confirmed the intended pointers and command bytes. The callback was
reached: pppd logged a forked `Child process <command>`. The child died with
SIGSEGV before `execve`, and no sentinel file appeared, in five replays.
The cause is structural: the NAK stream must pass +1532 to reach +1856, so
the high half of `the_channel` at +1532..+1535 becomes PAP-NAK pattern bytes
(`0x23c20503`); `the_channel` reads `0x23c20503004688a8`, not the intended
`0x00000000004688a8`. A single frame cannot place both halves of an
8-byte pointer at +1528 with this primitive (ASYNCMAP NAK values land six
bytes apart), and a later frame would rewrite the high half again.
Grade stays rung 4. Normalized evidence and hashes are in
`live/sigrecv/evidence/`; raw logs and strace stay in the gitignored `raw/`.

## W132 — controlled call with a chosen argument (rung 4 strengthened)

W131's callback reached `notify()` but died in `device_script`'s forked child
because the overflow had corrupted `the_channel`. W132 keeps the same
`sigreceived` write but uses a one-argument callback: `notify()` calls
`(*np->func)(np->arg, val)` (`main.c:2155-2163`), so a one-arg libc PLT stub
gets the attacker-chosen `arg` in `rdi` and ignores the signal number. The
fake notifier in `inpacket_buf` is `next=NULL, func=unlink@plt (0x40c4a0 in
the -no-pie pin), arg=<sentinel path>`; the same 1498-byte ConfReq from W131
sets `sigreceived` to that notifier's address. On SIGTERM, `term()`
(`main.c:1593-1600`) calls `notify(sigreceived, sig)` directly, with no
`the_channel` dereference on that path.

Live strace of the target PID shows
`unlink("/tmp/pppd2shell-r5-…-victim") = 0` and the sentinel file disappears.
The process still faults later in shutdown on the corrupted `the_channel`
(rc -11); that happens after the call and does not remove its effect.
Controls: short safe ConfReq on the vulnerable pin leaves the sentinel intact
and the daemon alive; `func=NULL` faults without a deletion; the fixed 2.5.4
pin given identical frames logs `LCP: ignoring duplicate configuration
option(s)` and leaves the sentinel intact. Two straced attack replays are
byte-identical after normalization (`live/call/evidence/HASHES.txt`).

Grade: **rung 4**, strengthened from chosen bytes and pointers to a chosen
function call with a chosen string argument and an observed filesystem side
effect in a live process. `unlink` is a libc call, not a command, so this is
**not rung 5**. The pin imports no `system` or `popen`; its only exec sites
(`device_script`, `run_program`) require a fork/child path or a stack frame
this write primitive cannot provide.

## Files

`lab/frontier/pppd2shell/live/` holds the driver, normalizer, matrix runner,
README, tracked normalized evidence and hashes. `live/rce_call.py` and
`live/call/` hold the W132 controlled-call driver, normalizer, README and
evidence. Raw pppd logs, ASan reports, frames and strace output stay in the
gitignored `live/raw/`. `reports/frontier-pppd2shell.md` is frontier's earlier
direct-call brief and is unchanged here.
