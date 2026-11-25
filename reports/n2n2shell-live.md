# n2n2shell — live loopback supernode experiment (2026-11-24 22:1xZ)

Author experiment on the planted loopback only; no external system was
contacted. This is not independent witness acceptance.

## Builds

Pinned vulnerable tree `n2n-dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff`
from `lab/frontier/n2n2shell/provision/n2n-vuln.tar.gz`:

```
sh autogen.sh
CC=clang CFLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1' \
  LDFLAGS='-fsanitize=address' ./configure
make -j4 supernode
```

Plain build: clean extraction of the same archive, `CC=gcc
CFLAGS='-g -O1 -fno-omit-frame-pointer'`, same `autogen.sh`/`configure`/`make`.
Fixed control: a copy of the vulnerable tree with the one-line bound from
`provision/wire-fixed.c` inserted into `decode_REGISTER_SUPER_NAK()`
(`if(nak->auth.token_size > N2N_AUTH_MAX_TOKEN_SIZE) return -1;`), rebuilt
with the same ASan flags. The full fixed commit tree was not built.

All supernodes ran with `-f -v -p 127.0.0.1:<port> -t <mgmt> -c community.list
-F labfed -M`, i.e. loopback bind, the shipped community file (`mynetwork`
allowed), header encryption off (the first unencrypted packet locks the
community to unencrypted headers at `sn_utils.c:1608`), no user/password
auth, and spoofing protection disabled for the test. Privilege drop to
nobody fails on this host and is nonfatal.

## Wire input

`live/send_nak.py` sends one UDP datagram to 127.0.0.1. Wire layout from the
pinned `wire.c`: version 3, ttl 3, flags 8 (`MSG_TYPE_REGISTER_SUPER_NAK`),
20-byte community `mynetwork\0...`, cookie `44332211`, srcMac
`02:00:00:00:00:01`, scheme 0, big-endian `token_size`, then `token_size`
token bytes. Safe input: `token_size=48`, length 86. Attack input:
`token_size=96`, length 134, token bytes `48 5a 4d 49` repeated 24 times.

## Observed

- Vulnerable ASan build, safe datagram: `Rx REGISTER_SUPER_NAK` logged at
  `sn_utils.c:2333`, no ASan report. Attack datagram: `AddressSanitizer:
  stack-buffer-overflow`, `WRITE of size 96`, in `decode_buf`
  (`src/wire.c:179`) <- `decode_REGISTER_SUPER_NAK` (`src/wire.c:651`) <-
  `process_udp` (`src/sn_utils.c:2322`) <- `run_sn_loop` (`sn_utils.c:2664`).
  ASan places the write in the `process_udp` stack frame, in the `nak`
  object at `sn_utils.c:2308`, abutting `nakbuf` at `sn_utils.c:2309`.
  Process aborted; `live/evidence/asan-vuln-live-attack.out`.
- Fixed-control ASan build, same attack datagram: `Rx REGISTER_SUPER_NAK`
  logged, no ASan report, process alive until timeout shutdown;
  `live/evidence/asan-fixed-live-attack.out`.
- Plain vulnerable build under gdb, break after decode at `sn_utils.c:2331`:
  `&nak=0x7fffffffc850`; bytes `48 5a 4d 49` repeat from offset 14 through
  offset 109 of `nak`, i.e. all 96 attacker-chosen token bytes land at their
  chosen offsets in the live supernode's stack. `nak.auth.token` is 48 bytes
  (offsets 14..61), so offsets 62..109 are past the destination. Named
  locals in this plain layout are further away (`mac_buf` at `nak+224`,
  `sockbuf` at `nak+288`); two pointer-shaped stack slots at `nak+96` and
  `nak+104` are inside the overwritten range (next section). No return
  address was reached. `live/evidence/gdb-plain-live-attack.out`.

## Pointer-shaped slots overwritten (plain build, safe baseline)

The same gdb breakpoint with the safe 48-byte input shows the bytes that
the attack replaces: `*(uint64_t *)(&nak+96)` is `0x7fffffffc940`
(`&mac_buf + 16`, a stack address) and `*(uint64_t *)(&nak+104)` is
`0x7ffff7cac295`, which gdb resolves to `_int_malloc+3173` in the host
libc. With the attack input those two eight-byte slots read
`48 5a 4d 49 48 5a` and `4d 49 48 5a 4d 49` — chosen wire bytes. Hardware
read watchpoints set on both slots after decode did not fire during ~11 s
of continued execution on this no-peer NAK path; consumption on other paths
is still UNKNOWN. Evidence: `live/evidence/gdb-plain-live-safe.out`,
`live/evidence/gdb-safe-pointer-slots.out` and
`live/evidence/gdb-watch-pointer-slots.out`.

## Ceiling

Rungs 1-3 now on a real pinned supernode process reached by one UDP
datagram, not just the stand-in harness. Rung 4 is established for chosen
bytes at chosen offsets in that live process's stack under the loopback,
no-auth conditions above, including two pointer-shaped stack slots whose
baseline values were a stack address and a libc `_int_malloc` code address.
It is NOT demonstrated control of a consumed pointer, benign-marker
execution, a canary/return-address hit, or stock-allocator behavior.
No rung 5: no command execution, no IP/control-flow takeover, no
independently witnessed replay. Witness verdict for this live experiment is
UNKNOWN; the earlier witness verdict (#3901) covers only the stand-in
harness. Next bounded step: witness replay of the live datagram and a
determination of whether those slots are read after decode; a rung-5
attempt requires a measured consumed-pointer path first.

## W2 follow-up paths: no consumed-pointer read (2026-11-24 23:32Z)

Bounded experiment on the plain build, one attack NAK followed by three
other loopback datagrams while hardware read watchpoints sat on the two
overwritten slots (`&nak + 96`, `&nak + 104`). The sender, gdb commands and
raw output are `live/w2_followup.py`, `live/gdb-cmds-w2.txt`,
`live/evidence/w2-followups-sender.out`,
`live/evidence/gdb-w2-followups.out` and
`live/evidence/gdb-w2-followups-rip.out`.

- Source check: in `process_udp` the NAK case
  (`sn_utils.c:2307-2368`) reads only in-bounds `nak.srcMac` and re-encodes
  from `nak`; the named locals `mac_buf`/`sockbuf` are at `nak+224`/`+288`.
  It does not read the overwritten region.
- No watchpoint fired for `QUERY_PEER` (message type 11) or for the
  `REGISTER_SUPER_ACK` (7) that followed. The sole trip, at
  `&nak+104`, occurred on the later `REGISTER_SUPER` (5) in
  `decode_REGISTER_SUPER` (`wire.c:456`); the watched value had become 0 and
  RIP was `mov %r8,%rcx` at `decode_REGISTER_SUPER+82`, i.e. the trap
  follows the inlined `memset(reg, 0, sizeof(...))` at `wire.c:454`.
  This is a clearing store that x86 reports to GDB's read watchpoint, not
  a consumer read of the attacker bytes.
- Structural reason: `reg` in the REGISTER_SUPER case is allocated at the
  same stack address as `nak` in the NAK case (`0x7fffffffc850` in this
  build); the stale slots alias `reg.auth.token[38..47]`, which that
  decoder memsets before any field read. With our token_size=0 datagram
  they are not decoded as token either.
- A second experiment that sent a second attack NAK tripped the same
  watchpoint inside the `decode_buf` memcpy (`__memcpy_avx_unaligned_erms`),
  again a re-write of the destination region, not consumption.
- The forwarding branch's `struct peer_info *peer` is register-resident in
  this build: at the post-decode breakpoint GDB rejects `p &peer` with
  "isn't an lvalue" while `&nak` is `0x7fffffffc850`. It is therefore not
  one of the overwritten stack slots; raw output in
  `live/evidence/gdb-w2-peer.out`.

Ceiling unchanged: rung 4 for chosen bytes at chosen stack offsets; no
measured consumed pointer, benign-marker execution, control-flow takeover
or rung 5. Witness replay of the live datagram (#3909) is still owed and
is required before this live experiment is ESTABLISHED.

All nine message-type decoders in the pinned `wire.c`
(`decode_REGISTER` :399, `decode_REGISTER_SUPER` :447,
`decode_UNREGISTER_SUPER` :490, `decode_REGISTER_ACK` :531,
`decode_REGISTER_SUPER_ACK` :585, `decode_REGISTER_SUPER_NAK` :637,
`decode_PACKET` :732, `decode_PEER_INFO` :778, `decode_QUERY_PEER` :817)
memset their destination struct before reading any wire field. So stale
chosen bytes in a reused switch-case object cannot be consumed as a pointer
on a later message: the next decoder clears that storage first.
`decode_common` (:236) does not memset, but it writes `ttl`, `flags`, `pc`
and `community` before reading none of them, so it does not consume stale
fields either. This bounds the negative to reused decoder objects; other
stack slots in the overflow span remain UNKNOWN, and no consumed pointer
was observed for the two measured pointer-shaped slots.

## W3: the forwarding encoder consumes the chosen bytes (2026-11-25 01:16Z)

W2 had no matching peer, so the forwarding branch of the NAK case
(`sn_utils.c:2335-2351`) never ran. `live/w3_peer_forward.py` binds a
loopback UDP socket, registers a peer with MAC `02:00:00:00:00:01` through
a `REGISTER_SUPER` from that socket, then sends the oversized NAK from a
second socket. `live/gdb-cmds-w3.txt` breaks after decode and sets the same
read watchpoints at `&nak+96`/`&nak+104`.

- Plain vulnerable build: the `REGISTER_SUPER` was acknowledged (58-byte
  reply). After the 134-byte attack NAK, watchpoint 3 fired. GDB reports the
  value `0x494d5a48494d` (little-endian `4d 49 48 5a 4d 49`, chosen bytes,
  plus two zero bytes at `nak+110..111` outside the 96-byte write) and the
  backtrace: `__memcpy_avx_unaligned_erms` <-
  `memcpy(len=96, src=0x7fffffffcf7e = nak+14)` <-
  `encode_buf` (`wire.c:162`) <- `encode_REGISTER_SUPER_NAK` (`wire.c:631`)
  <- `process_udp` (`sn_utils.c:2344`). This is a real consumer read of the
  overwritten stack bytes, as DATA, not a pointer dereference.
- The supernode then sent a 134-byte NAK to the registered peer. Its wire
  token is 96 bytes of `48 5a 4d 49` repeated 24 times, including
  `beyond48=485a4d49485a4d49` from offsets past the 48-byte `auth.token`
  array. All attacker-chosen bytes that landed in the stack were read by a
  live consumer and re-emitted on the loopback wire.
- Safe control (`token_size=48`, same peer and ports): forwarded NAK was
  86 bytes with only the 48 in-bounds chosen token bytes; no OOB region
  was read or emitted. `live/evidence/w3-safe-plain{,-sender.out}`.
- Fixed-control qualification: with a matching peer, the one-line decode
  bound prevents the WRITE but the oversized `token_size` survives into the
  encoder. The fixed ASan build aborts with `stack-buffer-overflow`,
  `READ of size 96`, `encode_buf` (`wire.c:162`) <-
  `encode_REGISTER_SUPER_NAK` (`wire.c:631`) <- `process_udp`
  (`sn_utils.c:2344`); ASan places the read just past the 64-byte `nak`
  object (`'nak3533' (line 2308)` at `[11136,11200)`) and reports that it
  partially underflows `nakbuf`. No reply was forwarded. The earlier
  "fixed control clean" result holds only on the no-peer path. Raw output:
  `live/evidence/w3-attack-fixed.log`, `w3-attack-fixed-sender.out`.
- Source corroboration (read-only): `nak` is 62 bytes, so `nak+62..109`
  aliases the REGISTER_SUPER case's `reg.auth.token[2..47]` and
  `reg.key_time[0..1]`; no NAK-case named local, saved register or caller
  frame slot lives there, and the forwarding `peer` pointer is
  register-resident. The two pointer-shaped compiler temporaries at
  `+96`/`+104` have no proven post-decode consumer as pointers; their exact
  provenance remains UNKNOWN.

Raw W3 evidence: `live/evidence/w3-gdb.out`, `w3-sender.out`,
`w3-safe-plain.log`, `w3-safe-plain-sender.out`, `w3-attack-fixed.log`,
`w3-attack-fixed-sender.out`. Ceiling: rung 4 now includes a measured
consumer read and wire re-emission of chosen bytes, not only a stack write.
Still no consumed pointer, benign-marker execution, control-flow takeover
or rung 5; witness replay of #3909 remains owed and is required before this
live experiment is ESTABLISHED.

## W3 addendum: canary and saved RIP are out of wire reach (2026-11-25 01:22Z)

This is the consumer/constraint check before any exploitation mechanics.

- The plain gcc `-O1` `process_udp` loads the stack canary from `%fs:0x28`
  at `0xd0df` into `-0x38(%rbp)` and calls `__stack_chk_fail` at `0x11705`.
  `nak` is at `rbp-0xdf0`, so the canary slot is `nak+3512` and the saved
  return address is `nak+3576`. The original `token_size=96` write ends at
  `nak+109`.
- `run_sn_loop` receives into `pktbuf[N2N_SN_PKTBUF_SIZE]` with a 2048-byte
  `recvfrom` (`sn_utils.c:2585`, `:2643`). A larger datagram is truncated,
  and `decode_buf` (`wire.c:169-184`) returns 0 without copying when
  `*rem < bufsize`. The largest wire-reachable `token_size` is therefore
  2048-38 = 2010, ending the write at `nak+2024` — 1488 bytes short of the
  canary and 1552 short of the saved RIP.
- Measured with `live/send_big_nak.py` under `live/gdb-cmds-canary.txt`:
  `token_size=2000` (2038-byte datagram) put chosen bytes at
  `nak+2000..+2013`, while the canary slot at `nak+3512` still held its
  random value `00 49 8d 86 a7 b2 ad c4`. A 3550-byte datagram
  (`token_size=3512`) produced no stack-smashing abort.

Control-flow takeover through this stack's canary or return address is
structurally closed for this wire path and build, independently of grooming.
The demonstrated consumer effect remains the W3 data copy into the forwarded
NAK; no consumed pointer or command execution. Evidence:
`live/evidence/gdb-canary-2000.out`, `canary-sender.out`,
`canary-plain-3512.log`.

## Clean-room replay entry point (2026-11-25 01:4xZ; W3 added 04:0xZ)

`sh lab/frontier/n2n2shell/live/replay-live.sh` builds the pinned tarball
from scratch in a fresh temporary directory three ways (gcc `-O1` plain,
clang ASan vulnerable, clang ASan plus the single fixed bound), starts each
supernode on 127.0.0.1 ports starting at `PORT_BASE` (default 18700), sends
the committed safe and attack datagrams, and prints `RESULT <n> PASS / <m>
FAIL`. Author run after W3 was added: 22 PASS / 0 FAIL, rc 0. Pins verify
before any build; raw logs stay under the temporary directory printed at the
end (`KEEP=1` retains it). Checks 1-15 cover the ASan stack write, its three
pinned frames, the safe and fixed controls, and the exact chosen wire bytes.
Checks 16-19, run when `gdb` is available (`NO_GDB=1` skips them with a
loud line), break the plain supernode just after decode at
`sn_utils.c:2331` and read the chosen words from the live process:
`SLOT14=0x494d5a48494d5a48`, `SLOT96=0x5a48494d5a48494d`,
`SLOT104=0x494d5a48494d`. Checks 20-22 now replay the W3 peer-forwarding
path inside the same command: a registered peer receives the safe 86-byte
NAK and the attack 134-byte NAK with `beyond48=485a4d49485a4d49`. The
watchpoint-level backtrace and the fixed-build ASan READ still keep their
separate recipe (`live/w3_peer_forward.py` with `live/gdb-cmds-w3.txt`,
`live/evidence/w3-gdb.out`, `w3-attack-fixed.log`).

## W5: pointer-shaped frame slots have no consumer read (2026-11-25 02:3xZ)

One bounded question left open by W2/W3: does any other pointer-shaped slot
in the live `process_udp` frame get read after the NAK decode? Source check
of the pinned case (`sn_utils.c:2306-2363`) shows only `nak`, `nakbuf`,
`encx`, `peer`, `sockbuf`, `mac_buf` as case locals; `peer` is
register-resident (W2), `mac_buf`/`sockbuf`/`nakbuf` are string or packet
buffers, and the function returns immediately after the switch
(`sn_utils.c:2560`). No post-switch code dereferences a frame slot.

Measured layout in the running plain build, relative to `&nak`:
`hash_buf +112`, `mac_buf +224`, `sockbuf +288`, `nakbuf +432`; `cmn` and
`sender` sit below `nak`. A safe-input (48-byte token) 2048-byte dump of
the frame and the classified pointer-shaped words are in
`live/evidence/w5-safe-frame-dump.log`, `w5-frame-object-addrs.log` and
`w5-safe-pointer-words.txt`. Inside the 96-byte attack write
(`nak+14..+109`) the only pointer-shaped words are the two already tested
slots at `+96` (stack address) and `+104` (libc `_int_malloc+3173`).

Four batches of four hardware read watchpoints were installed at the
post-decode breakpoint (`sn_utils.c:2331`) on further pointer-shaped words,
then a registered peer and the 134-byte attack NAK were sent with
`live/w3_peer_forward.py`:

- batch 2: `+128`, `+136`, `+344`, `+432`;
- batch 3: `+368`, `+392`, `+400`, `+424`;
- batch 4: `+464`, `+488`, `+504`, `+536`;
- batch 5: `+1608`, `+1616`, `+1632`, `+1640`.

No watchpoint hit in any batch. All four runs forwarded the 134-byte NAK
with `beyond48=485a4d49485a4d49`; raw GDB and sender logs are
`live/evidence/w5-watch-batch{2,3,4,5}.log` and
`w5-watch-batch{2,3,4,5}-sender.log`. Recipe: break at `sn_utils.c:2331`
in the plain build, set `rwatch *(unsigned long *)($base + OFF)` with
`$base = (char *)&nak`, continue, and run the W3 sender against the same
port.

One excluded first attempt put a read watchpoint on `+288`; it fired with
`Value = 0` and RIP in `__vsnprintf_internal` under `sock_to_cstr` — a
store into `sockbuf`, not a consumer read (the same GDB false-positive
class recorded in W2). That run stopped before forwarding and is not part
of the four negative batches.

Ceiling unchanged: no measured consumed pointer, benign marker, control
flow or rung 5. These 16 slots add to the W1/W2 negative; other frame
words not covered by a watchpoint remain UNKNOWN. The W3 forwarding
encoder's data copy is still the only measured consumer of the overflowed
bytes.

## W6: fixed build's surviving encoder read leaks no chosen data (2026-11-25 03:5xZ)

The one-line fixed control used in the replay was checked against the pinned
vendor patch source: `diff -u provision/wire-vuln.c provision/wire-fixed.c`
adds four independent guards, and the NAK guard is byte-identical to the one
inserted into the control (decode `token_size`, reject `> N2N_AUTH_MAX_TOKEN_SIZE`
before `decode_buf`). The other three guards (REGISTER_SUPER,
UNREGISTER_SUPER, REGISTER_SUPER_ACK token/num_sn) do not act on this path.
So the control is faithful for the tested NAK decode, though it is not the
full fixed tree build.

Bounded question left by W3: the fixed decoder memsets `nak`, stores the
oversized wire `token_size=96`, then returns -1; `process_udp` still calls the
forwarding encoder, which reads 96 bytes from `nak+14`. Does a non-ASan fixed
build put non-zero stack bytes on the wire? Prediction: no visible disclosure,
because the memset clears the struct and this plain layout's adjacent bytes
are also clear. Test: fresh extraction of the pinned tarball, gcc `-g -O1
-fno-omit-frame-pointer`, the same one-line NAK bound, supernode on
127.0.0.1:18740/18750, `live/w3_peer_forward.py` with `safe` and `attack`.

- Safe: registered peer got a 58-byte REGISTER_SUPER ACK, then an 86-byte
  forwarded NAK with 48 chosen token bytes (`485a4d49...`).
- Attack: peer got a 134-byte forwarded NAK whose wire token is 96 bytes of
  ZERO (`first=0000000000000000 beyond48=0000000000000000`). The oversized
  `token_size` survives the rejected decode (wire field `0x0060`), so the
  encoder's out-of-bounds read is still exercised, but it emits no stack
  data on this plain build/path. The fixed ASan build still aborts on that
  read with a peer (W3), so a patched process remains vulnerable to a
  peer-triggered abort; this experiment does not add a disclosure claim.
- Raw: `live/evidence/fixed-plain-safe{,-sender}.log`,
  `fixed-plain-attack{,-sender}.log`. Adjacent bytes in other builds or
  after different preceding traffic remain UNKNOWN.

Ceiling unchanged: rung 4 data-only consumer effect in the vulnerable build,
no consumed pointer, marker, control flow, command or rung 5. Independent
verdict on #3909 is still owed.

## W7: overwritten pointer-shaped slots still have no consumer (2026-11-25 06:1xZ)

W5 installed its read watchpoints on pointer-shaped frame words at
`+128/+136/+344/+432` and other offsets, but sent `token_size=96`.
The 96-byte write ends at `nak+109`, so those watched words were NOT
overwritten: W5 measured original values, not chosen bytes. This wake
closes that gap with a larger token that actually reaches them.

Recipe: `sh lab/frontier/n2n2shell/live/w7_large_token.sh` (loopback only,
plain pinned vulnerable build, no registered peer so the W3 forwarding
`memcpy` cannot read the watched slots as mere data). The script sends one
`token_size=600` datagram (638 bytes) per batch from
`live/send_big_nak.py`, breaks after decode at `sn_utils.c:2331`, sets four
hardware read watchpoints on byte-offset expressions
`*(unsigned long *)((char *)&nak + OFF)`, dumps the watched words, then
continues for 22 s.
The script defaults to the already-built plain tree at
`lab/frontier/n2n2shell/provision/build/n2n-plain`, which is gitignored;
from a clean archive, build the plain branch of `replay-live.sh` first and
pass its tree path as `PLAIN=/path/to/plain-tree`.

- Batch A watched `+128`, `+136`, `+344`, `+432`; batch B watched `+368`,
  `+400`, `+424`, `+464`. In both runs GDB reported `udp_size=638`, and
  every watched word held the chosen pattern `0x5a48494d5a48494d` at the
  post-decode breakpoint — the watched addresses really were overwritten.
- Neither batch hit a read watchpoint during 22 s of continued execution.
  Raw logs: `live/evidence/w7-{a,b}.log` and
  `w7-{a,b}-sender.log`; ports 18600/18610, loopback only.
- Source corroboration: after decode the NAK case in `sn_utils.c`
  writes `mac_buf` via `macaddr_str` and `sockbuf` via `sock_to_cstr`,
  finds the peer from the in-bounds `nak.srcMac`, and (with a peer)
  calls `encode_REGISTER_SUPER_NAK` into `nakbuf`. None of those steps
  dereferences the overwritten words as pointers.

First run of the script was invalid: its dump expressions used
`&nak+OFF` (C pointer arithmetic, `sizeof(nak)=64`), so GDB failed to
access the address and aborted the command file before `continue`. The
run produced no observation and is not part of the result above; the
byte-offset fix was verified by the chosen-pattern dumps in both logs.

Ceiling unchanged: no consumed pointer, benign marker, control flow or
rung 5. W7 covers eight overwritten frame words on the no-peer path;
other frame words and other build/traffic configurations remain UNKNOWN.
Witness replay of #3909 is still owed.
