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

## W8: fixed plain build leaks stale stack words at a larger token (2026-11-25 06:1xZ)

W6 found no disclosure at `token_size=96`: the fixed decoder clears `nak`
and the encoder's 96-byte OOB read emitted only zeros. That read is not
bounded by the struct, so this wake checked a larger token on the same
one-line fixed control (guard verified in the rebuilt source at
`wire.c:651-652`: reject `token_size > N2N_AUTH_MAX_TOKEN_SIZE` before
`decode_buf`). Fresh `gcc -g -O1 -fno-omit-frame-pointer` build of the
pinned tarball plus that single guard; loopback supernodes on
127.0.0.1:18640/18642, peer sockets on 18650/18652. Sender:
`live/w8_fixed_large.py` (register a peer, send a NAK with a chosen token
size, dump the forwarded wire token).

- Safe (`token_size=48`): 86-byte forwarded NAK, 48 chosen token bytes,
  no bytes beyond the request. `live/evidence/w8-fixed-safe{,-sender}.log`.
- Attack (`token_size=600`): 638-byte forwarded NAK. The first 96 wire
  token bytes are zero (the memset struct), but 201 of 600 token bytes are
  nonzero, starting at wire offset 115 (= `nak+129`); full hex is in
  `live/evidence/w8-fixed-attack-sender.log`. A second run gave 205
  nonzero bytes, i.e. the count varies with the process's stack content.
- Seventeen unaligned eight-byte windows in the leaked token are
  user-space stack/libc-shaped values, e.g. wire offset 114 =
  `0x7fffed9a7300`, offset 122 = `0x7785206ac295`, offset 242 =
  `0x7fffed9a7330`, offset 378 = `0x778520a04627`. Because the token
  starts at `nak+14`, those windows correspond to the pointer-shaped frame
  words classified in W5's safe baseline (e.g. `nak+128`, `nak+136`,
  `nak+256`, `nak+392`). These are stale stack words, not proven live
  pointers; the address bytes changed between runs, so ASLR is not
  defeated. No canary or return address is within wire reach (W3 addendum).

W6's "fixed leaks no stack data" is therefore qualified by token size:
it holds at 96, not at 600. Conditions: registered peer, unencrypted
headers, no user/password auth, loopback lab process, and the one-line
control rather than a full fixed-tree build. Ceiling unchanged as to
control: no consumed pointer, marker, control-flow takeover or rung 5.
The newly observed effect is stack-data disclosure from the patched
decoder's surviving encoder read; independent verdict on #3909 is still
owed.

## W10: wire-chosen bytes consumed as a live pointer (clang -O2, 2026-11-25 06:5xZ)

W2/W5/W7 found no consumer read on the pinned **gcc -O1** plain build,
where `peer` and the forwarding arguments stay in registers. That result is
build-specific. `live/w9_spill_layout.sh` rebuilds the pinned tarball four
ways (gcc/clang at -O0/-O2) and reads the live stack addresses at
`sn_utils.c:2331` with gdb; raw offsets from `&nak` are in
`live/evidence/w9-layout-*.log`:

- gcc -O0: `peer` at `-480`, `encx` `-280`, `nakbuf` `+1456` — no pointer
  slot in the forward window; gcc -O2: `peer` optimized out.
- clang -O0: `peer` at `-2068`; the named argument slots are beyond the
  wire-reachable `+2024` end of the write.
- clang -O2: argument spill slots lie **inside** the reachable window:
  `encx +1344`, `sock_size +1524`, `sender_sock +1576`,
  `socket_fd +1604`, `udp_size +1648`, `sss +1672`, `udp_buf +1680`,
  `comm +1696`. The 2048-byte receive cap permits `token_size=1700`, whose
  write ends at `nak+1713`, covering all of them.

`live/w10_large_peer.py` registers a loopback peer and sends that NAK.
Both cases bind only 127.0.0.1 (18900/18910 and 18930/18940 in the author
runs) and use `gcc`-independent pinned source:

- **Garbage chosen pointer.** With the repeating chosen token
  (`48 5a 4d 49`), the clang -O2 supernode takes SIGSEGV at
  `sn_utils.c:2324` (`if(comm->header_encryption ...)`). gdb's stopped
  frame shows `sss`, `sender_sock`, `udp_buf` =
  `0x5a48494d5a48494d` and `sock_size`, `socket_fd` = `0x5a48494d`:
  wire bytes occupy the spilled argument slots that the decoder path
  then uses as pointers/scalars. `live/evidence/w10-clang-o2.log`.
- **Wire-chosen valid pointer.** Calibration at `sn_utils.c:2322` (before
  decode, gdb `set disable-randomization on`) read the live
  `comm = 0x555555587280` (`live/evidence/w10-calibration.log`). Replaying
  the same 1700-byte wire with eight chosen bytes at token offset 1682
  (= `nak+1696`) set to that value moved the fault to
  `sn_utils.c:2344`, in `encode_REGISTER_SUPER_NAK` ->
  `encode_common` -> `encode_uint8` at `wire.c:49`; gdb's RIP is
  `movb $0x3,(%rdi,%rax,1)`, with `idx` and `base` now holding corrupted
  stack addresses. `live/evidence/w10-chosen-comm{,-sender}.log`.

Therefore the overflow reaches a **consumed pointer** on this build:
wire-chosen bytes at a chosen offset are dereferenced in the live process,
and substituting a valid pointer changes which pointer is consumed.
Honest limits: the valid pointer value came from a debugger pre-read with
ASLR disabled, not from a wire leak or an ASLR-defeating primitive; both
outcomes are crashes, with no benign marker at a chosen target, no
control-flow takeover and no command side effect. This raises the rung-4
mechanism from chosen data re-emission to chosen-pointer dereference; the
ceiling stays rung 4 and there is no r5.

One-command replay: `sh lab/frontier/n2n2shell/live/w10_pointer_control.sh`
(build once, then the calibration, garbage and chosen-pointer cases;
all instances loopback only). Author clean run: `RESULT 9 PASS / 0 FAIL`,
raw logs `live/evidence/w10-replay-*.log`. Independent verdict on #3909 is
still owed.

## W11: wire-only chosen pointer at a binary-known address (non-PIE clang -O2, 2026-11-25 07:4xZ)

W10's valid `comm` value came from a debugger pre-read with ASLR disabled.
W11 removes that dependency. The pinned tarball rebuilt with
`CC=clang CFLAGS="-g -O2 -fno-omit-frame-pointer -no-pie" LDFLAGS="-no-pie"`
has a 632-byte zero run in `.bss` starting at the fixed address `0x42f3e8`
(`mgmt_event_subscribers+8`). A fake `struct sn_community` there has
`is_federation = 0`, `header_encryption = 0` and `edges = NULL`.

`live/w11_fixed_pointer.sh` writes that address, little-endian, at token+1682
(= `nak+1696`, the clang-O2 `comm` spill slot from W9) of the same 1700-byte
NAK as W10. Three loopback cases:

- Garbage chosen bytes: SIGSEGV at `sn_utils.c:2324`, with
  `comm = 0x5a48494d5a48494d` in the stopped frame.
- Wire-chosen fixed address: gdb stopped at `:2324` reads
  `comm = 0x42f3e8`, the three bytes at `comm+20` are zero and
  `*(comm+72) = 0`; no SIGSEGV. The pointer value came from the wire plus the
  binary's symbols, not from a read of the live process.
- Plain build, no gdb: after that same attack datagram a fresh
  REGISTER_SUPER gets a 58-byte reply, a following safe 48-byte NAK is
  forwarded with the chosen bytes intact, and the process is still alive.

One-command replay `sh lab/frontier/n2n2shell/live/w11_fixed_pointer.sh`:
`RESULT 13 PASS / 0 FAIL`, rc 0; raw logs `live/evidence/w11-replay-*`.

Honest limits: the address is fixed only in this non-PIE lab build; this is
not a remote ASLR-defeating leak. The chosen pointer selects a zeroed data
area, i.e. a safe control path, not a benign marker or a function. No
control-flow takeover, command side effect or r5. The default-PIE and
fixed-build variants of this exact wire are UNKNOWN; independent verdict on
#3909 is still owed.

## W12: no poisonable indirect call in process_udp (2026-11-25 09:1xZ)

W10/W11 showed chosen bytes consumed as `comm`, a data pointer. To test
whether the same overwrite can redirect execution, I disassembled the exact
non-PIE clang -O2 `supernode` used by W11 (BuildID sha1
`31518559217dab425de97d65e475951084eea218`; `file` reports "ELF 64-bit LSB
executable ... not stripped"). Reproduce that binary with the build block at
`lab/frontier/n2n2shell/live/w11_fixed_pointer.sh:29-35`, then:

    objdump -d --disassemble=process_udp <supernode> | grep -E 'call[[:space:]]*\*|jmp[[:space:]]*\*'
      40be35: 41 ff e0   jmp    *%r8
      40c090: ff e1      jmp    *%rcx
      40dd9d: 41 ff e0   jmp    *%r8

Observed: **zero** indirect calls (`call *`) in the whole function. All three
indirect jumps are compiler switch tables: the bases are `.rodata` at
`0x42b35c` (`ftbl2+0x13c`), `0x42b388` (`ftbl2+0x168`) and `0x42b3b4`
(`ftbl2+0x194`), and each index is a register bounded by `cmp $0xa; ja`
before the table lookup. No jump or call target in `process_udp` is loaded
from the overwritten stack range (`nak+14..+1713` at token_size=1700), and
the canary and saved RIP stay at `nak+3512/+3576` (W3 addendum), beyond the
2048-byte receive cap's 2010-byte token bound. The NAK case's
`packet_header_encrypt` calls (`sn_utils.c:2347`) carry no function pointer
either: `he_context_t` is `speck_context_t`, a round-key array
(`include/n2n_typedefs.h:251`).

This is a bounded structural negative, not a witness verdict: in this build
the chosen bytes reach a data pointer and a forwarded wire copy, not a
benign marker or a control-flow target. Ceiling stays rung 4; no r5. The
same 1700-byte wire against gcc -O1/-O2 and default-PIE clang builds is
UNKNOWN; independent verdict on #3909/#4173 is still owed.

The same check on the pinned plain gcc -O1 PIE build
(`provision/build/n2n-plain/supernode`, BuildID sha1
`27a6f088a7c7f21b587e054d2d44e818c388fd8a`) also gives zero indirect calls:
three `notrack jmp *` at `0xd381`, `0xd6b5`, `0xe2b2`, each a switch table
with a `.rodata` base (`ftbl+0xb4`, `ftbl+0xe4`, `ftbl+0x114`) and an index
bounded by `cmp $0xb; ja`. The negative is therefore not an artifact of the
clang non-PIE build: the gcc -O1 build used for W3/W5/W7 has no poisonable
call target in `process_udp` either.

## W13: the overwritten `sss` spill slot is not consumed (2026-11-25 10:0xZ)

W9 placed `sss` at `nak+1672` in the clang -O2 layout, inside the
1700-byte token write. W11 fixed only `comm` (+1696) to a valid object;
this experiment asks whether the remaining corrupted argument slot is
also consumed after decode.

`live/w13_spill_read.sh` builds the exact W11 non-PIE clang -O2 tree and
runs two gdb cases against 127.0.0.1. The attack wire is `token_size=1700`
with the 8-byte override `1682:0x42f3e8` (comm valid, so the run survives
past the `sn_utils.c:2324` dereference from W10).

- At the post-decode breakpoint (`sn_utils.c:2331`) gdb displays the
  function arguments as garbage chosen from the wire:
  `sss=0x5a48494d5a48494d`, `sender_sock=0x5a48494d5a48494d`,
  `sock_size=1514686797`, `socket_fd=1514686797`,
  `udp_buf=0x5a48494d5a48494d`, `udp_size=6505530258312677709`.
  Direct reads confirm `*(uint64_t *)(&nak+1672) = 0x5a48494d5a48494d`
  and `*(uint64_t *)(&nak+1696) = 0x42f3e8`. The corrupted argument
  display is therefore the overwritten spill slots, not a register value.
- A hardware READ watchpoint on `*(void **)((char *)&nak+1672)`, armed
  after decode and continued through the end of the NAK case, never
  fired: no `Value =` line, and `process_udp` returned normally to
  `run_sn_loop` (`sn_utils.c:2664`). No forwarded NAK appeared with the
  fake `comm`; W11's liveness result used the same wire and remains the
  liveness evidence.
- Control: a gdb `p` of the watched address is NOT a valid control —
  gdb reads memory through ptrace, which cannot trip a hardware
  watchpoint; that first attempt was rejected. The working control is a
  safe `token_size=48` NAK with a registered peer and a read watchpoint
  on `nak+14`: the W3 forwarding encoder reads those bytes and the
  watchpoint fires. Read watchpoints are live in this build and path.

Interpretation: in this build the overwritten argument slots other than
`comm` are dead in the NAK path; a corrupted DWARF argument display is
not evidence of consumption. Combined with W12's zero indirect calls,
there is no second wire-controlled pointer and no poisonable call target
in this `process_udp`. Ceiling unchanged (rung 4, no r5). Other builds
and message paths remain UNKNOWN.

Replay after the control fix: `sh lab/frontier/n2n2shell/live/w13_spill_read.sh`
— 11 PASS / 0 FAIL, rc 0 (author run 10:02:30Z). Raw logs:
`live/evidence/w13-{watch,control}{,-sender}.log`, `w13-build.log`.

## W14: the chosen-pointer object graph carries no function pointer (2026-11-25 11:2xZ)

W12 counted zero indirect calls in the exact W11 `process_udp`; W13 showed
`comm` is its only wire-controlled pointer. This is a source-level check of
the objects reachable through that pointer: if `comm` were aimed at a
forged static object, could any field be used as a call target?

Pinned tree: `provision/n2n-vuln.tar.gz`, sha256
`d3b5465090ac13aca2186c9d7e24cea4d9d450eb11586ef05b919c39d1f12b43`
(matches `pins.sha256`), extracted read-only from the same archive the live
replays use.

- `include/n2n_typedefs.h:791-808` `struct sn_community` holds only bytes,
  four `he_context_t *` cipher contexts, `peer_info *edges`,
  `node_supernode_association_t *assoc`, `sn_user_t *allowed_users`,
  counters, a subnet and `UT_hash_handle`. No function-pointer member.
- `include/speck.h:49-53` (and the AVX2/SSE/scalar variants at `:65-69`,
  `:86`, `:100`, `:109`) define `speck_context_t` as round keys, key words
  and `keysize` only. The cipher contexts reached through `comm` carry no
  callback.
- `include/n2n_typedefs.h:450-472` `struct peer_info`, reachable via
  `comm->edges`, is data plus `UT_hash_handle`; `include/uthash.h:1238-1247`
  `UT_hash_handle` is table/prev/next/key/keylen/hashv pointers only.
- The NAK path's consumer of a found peer, `sendto_peer`
  (`src/sn_utils.c:584-609`), ends in `sendto_sock(...)` — a direct call,
  not an indirect one. `sn_utils.c:2305-2356` shows `comm` used for
  `header_encryption`, `edges`, `is_federation` and `allowed_users` only.

So a wire-chosen `comm` can select data objects and steer which peer gets a
forwarded NAK, but the forged object graph supplies no function pointer to
call and W12 supplies no indirect call instruction to poison. This corroborates
W12/W13 at source level; it is not a runtime marker attempt. Scope: this
pinned build and the REGISTER_SUPER_NAK path. Other builds, messages and
allocator-controlled objects remain UNKNOWN. Ceiling unchanged (rung 4, no r5).

## W15: a third build also has no indirect call in process_udp (2026-11-25 11:2xZ)

W12 surveyed the exact W11 clang -O2 non-PIE supernode and a gcc -O1 PIE
build. This adds the pinned vulnerable tree built with `gcc -g -O2
-fno-omit-frame-pointer -no-pie` / `-no-pie`, from the same archive
(`n2n-vuln.tar.gz`, sha256 `d3b54650...`). Build ID varies with build
timestamps; the replay records it in `evidence/w15-readelf.log` rather than
treating it as a stable pin.

`objdump -d` over the exact symbol extent of `process_udp.isra.0`
(`0x40cbc0`, size 17633 bytes) gives **0 indirect calls** and 3
`notrack jmp *` instructions, all at `0x40cf50`, `0x40d04e`, `0x410043`.
Each is preceded by `cmp $0xb; ja` and an `lea` of a `.rodata` table at
`0x425454`, `0x425484`, `0x4254b4` respectively, with a 32-bit signed
offset loaded from that table. They are bounded message-type switch
tables, not wire-controlled call targets. As in W12, canary and saved RIP
remain out of the 2048-byte receive window.

`sh lab/frontier/n2n2shell/live/w15_indirect_sweep.sh` — clean archive,
7 PASS / 0 FAIL, rc 0 (author run 11:28:53Z): build, symbol extent,
disassembly, zero indirect calls, three bounded jumps. Raw logs:
`live/evidence/w15-build.log`, `w15-readelf.log`, `w15-sections.log`,
`w15-process-udp.asm`, `w15-switch-tables.txt`.

Ceiling unchanged: rung 4, no poisonable call target in any of the three
surveyed builds, no r5. Builds and message paths not surveyed stay UNKNOWN.

## W16: consolidated clean-archive replay (2026-11-25 15:49Z)

Witness wall at 18:07Z: #4445 (this consolidated W16 replay) is the newest
outstanding n2n ask and the witness's named next bounded incident; #4173
(W10 pointer control) remains open but older. #3909 live replay has NO
verdict (UNKNOWN). #4185 and #4242 are FYI. One command now covers
every lane: `sh lab/frontier/n2n2shell/live/replay-all.sh`. From a clean
git archive at commit `a2284de2`:

```
git archive HEAD lab/frontier/n2n2shell | tar x -C /tmp/n2n-archive
REPLAY_LOGDIR=/tmp/n2n-logs sh /tmp/n2n-archive/lab/frontier/n2n2shell/live/replay-all.sh
```

Observed author run at 15:49Z: pins 5 OK; harness `RESULT 15 PASS /
0 FAIL`; live `RESULT 22 PASS / 0 FAIL`; W10 `RESULT 9 PASS / 0 FAIL` with
`CALIB comm=0x555555587280`; W11 `RESULT 13 PASS / 0 FAIL`; W13
`RESULT 11 PASS / 0 FAIL`; W15 `RESULT 7 PASS / 0 FAIL`; overall
`REPLAY_ALL_RESULT 7 PASS / 0 FAIL`, `REPLAY_ALL_OK`, rc 0. All supernodes
bound 127.0.0.1 only, with disjoint port bases per lane. Raw per-lane logs
stayed in `/tmp/n2n-w16-logs` (outside the repo).

Bounded repair recorded, not hidden: the first clean-archive run was
`4 PASS / 3 FAIL` because W10/W11/W13 copied `community.list` from
`provision/build/n2n-plain/`, a gitignored provisioning artifact absent
from an archive. The pinned tarball `n2n-vuln.tar.gz` already contains
`community.list`; commit `a2284de2` removes that redundant `cp` from the
three scripts. Replay from the same clean-archive recipe then passed
7/7. No test assertion, wire input or claimed result was relaxed.

This is an author receipt, not independent witness acceptance. Ceiling
unchanged: rungs 1-4 on a real pinned supernode, no benign-marker
execution, canary/RIP hit, control-flow takeover, command execution or
rung 5.

## W17: witness-shaped clean-archive replay (2026-11-25 18:14Z)

The witness's queue names #4445 (W16 consolidated replay) as its next
bounded incident. To catch any path assumption before that replay, I ran
the wrapper the way a witness would: `git archive HEAD
lab/frontier/n2n2shell | tar x -C /tmp/n2n-witnesspath-*`, then with cwd
`/` and `REPLAY_LOGDIR=/tmp/n2n-witnesspath-logs-*` ran
`sh <archive>/live/replay-all.sh`. No repository cwd, no inherited
`TMPDIR` assumption and no provisioning artifact from the working tree.

Observed: pins `5 OK`; harness `RESULT 15 PASS / 0 FAIL`; live
`RESULT 22 PASS / 0 FAIL`; W10 `RESULT 9 PASS / 0 FAIL` with a freshly
calibrated `comm` value; W11 `RESULT 13 PASS / 0 FAIL`; W13
`RESULT 11 PASS / 0 FAIL`; W15 `RESULT 7 PASS / 0 FAIL`; overall
`REPLAY_ALL_RESULT 7 PASS / 0 FAIL`, `REPLAY_ALL_OK`, rc 0. All lanes
bound loopback only; per-lane logs stayed outside the repo. This checks
the replay path, not the witness verdict: #4445 and #4173 remain without
a verdict and #3909 remains UNKNOWN. Ceiling unchanged: rungs 1-4, no
marker, canary/RIP hit, control-flow takeover, command execution or r5.

## W18: second in-tree caller (edge) survey (2026-11-25 18:4xZ)

All earlier live work used the supernode caller at `sn_utils.c:2322`.
The pinned tree has exactly one other caller of the vulnerable decoder:
`edge_utils.c:2622`, in the edge's `process_udp`. This is a different
threat model (a NAK received by an edge from a supernode, gated by
`eee->sn_wait` and cookie match), but it is a second live stack frame
that could in principle expose a poisonable callback. Surveyed from the
pinned tarball only; no edge process was started and no packet was sent.

Clean build of the pinned vulnerable tarball with
`CC=gcc CFLAGS='-g -O1 -fno-omit-frame-pointer'`, `make -j4 edge`,
then `objdump -d` and `addr2line` on that binary. Observed in the edge
`process_udp` frame:

- `nak` is at `-0x1180(%rbp)`; the canary is loaded from `%fs:0x28` and
  stored at `-0x38(%rbp)` — 0x1148 = 4424 bytes above `nak`. With the
  edge's `N2N_PKT_BUF_SIZE` of 2048 the decoder write ends at about
  `nak+2024`, 2400 bytes short of the canary. Same unreachable-RIP
  result as the three surveyed supernode builds.
- Unlike the supernode build, the edge `process_udp` **does** contain five
  indirect calls: `c132`, `c17e`, `c238`, `c267`, `e03f`. `addr2line`
  maps them to `edge_utils.c:1730`, `:1743`, `:1816`, `:1824` and `:2607`.
  The first four are `handle_PACKET` peer/transform callbacks whose
  targets are loaded from the `eee` heap object (e.g. `call *0x198(%rbx)`),
  not from a stack slot. The fifth is `eee->cb.sn_registration_updated`
  in the `REGISTER_SUPER_ACK` case (`:2606-2607`); the NAK case begins at
  `:2613`. There is one `notrack jmp *` bounded switch-table jump.
- In the NAK case after `decode_REGISTER_SUPER_NAK`, the only stack reads
  are `nak` fields (cookie at `nak+4`, srcMac at `nak+6`) plus `-0x1220`
  and `-0x1260`, which are *below* `nak` and therefore outside the
  upward write. No indirect call occurs on that path; no overwritten
  spill slot is consumed.

Replayable as `sh lab/frontier/n2n2shell/live/w18_edge_caller_survey.sh`
with cwd `/` and `REPLAY_LOGDIR` outside the repo. Author run at 18:4xZ:
`RESULT 10 PASS / 0 FAIL`, rc 0; raw disassembly and line map in
`/tmp/n2n-w18-edge-out`. This is a build-and-disassembly survey, not a
live edge reproduction and not witness acceptance. Only this gcc -O1
edge build was surveyed; other edge builds and the simulated-supernode
wire path stay UNKNOWN. Ceiling unchanged: rungs 1-4 on the live
supernode, no marker execution, canary/RIP hit, control-flow takeover,
command execution or r5.


## W19: the W11 chosen-pointer wire on a full fixed-tree build (2026-11-25 21:2xZ)

W11's limits left the fixed-build variant of its exact wire UNKNOWN. Built
the pinned tarball with the vendor-identical one-line decode guard inserted
(`if(nak->auth.token_size > N2N_AUTH_MAX_TOKEN_SIZE) return -1;` in
`decode_REGISTER_SUPER_NAK`), `CC=gcc CFLAGS='-g -O2
-fno-omit-frame-pointer -no-pie' LDFLAGS='-no-pie'`. This is the same
non-PIE gcc -O2 shape as W15, now with the fix in place. A loopback supernode
registered a peer, then received W11's exact wire: `token_size=1700`,
1738-byte datagram, 8 chosen bytes at `token+1682` carrying the vulnerable
build's fixed `.bss` pointer `0x42f3e8` (`e8f3420000000000`, little-endian).

Observed in `live/evidence/w19-attack-sender.log`: the peer was registered
(58-byte reply), and the forwarded NAK was 1738 bytes with
`first=0000000000000000 beyond48=0000000000000000`. The guard rejects the
oversized token before `decode_buf`; the surviving forwarding encoder still
emits the zeroed `nak`, so no chosen token byte or chosen address returns
on the wire. The process stayed alive with no SIGSEGV or sanitizer report
(`live/evidence/w19-supernode.log`). A subsequent safe 48-byte NAK from a
second peer forwarded 86 bytes with `first=485a4d49485a4d49`, proving the
supernode still serves after the attack wire.

`sh lab/frontier/n2n2shell/live/w19_fixed_wire.sh` (cwd `/`, `REPLAY_LOGDIR`
outside the repo, disjoint `PORT_BASE`) verifies pins, the single guard, the
build, the wire, both forwarded tokens and liveness: `RESULT 14 PASS /
0 FAIL`, rc 0. Raw logs: `live/evidence/w19-{pins,build,supernode,
attack-sender,safe-sender}.log`.

This closes the fixed-build UNKNOWN for that exact wire as a negative: no
chosen-pointer dereference and no chosen-byte re-emission on the fixed
control. It does NOT establish that all fixed builds are safe — the full
upstream fixed tree, the default-PIE build with this wire and ASan on this
1700-byte wire remain UNKNOWN. Ceiling unchanged: rungs 1-4 on the vulnerable
build, no marker execution, canary/RIP hit, control-flow takeover, command
execution or r5. Author experiment only; no witness verdict.

## W20: the W11 wire against the pinned upstream fixed decoder (2026-11-25 22:4xZ)

Correction to the W19 heading: that build did NOT use the full upstream
fixed tree. Its script inserted one guard into `decode_REGISTER_SUPER_NAK`;
the pinned fixed `provision/wire-fixed.c` (commit 854fbbe0) in fact adds
five guards across four decoders — `token_size` bounds in
`decode_REGISTER_SUPER`, `decode_UNREGISTER_SUPER`,
`decode_REGISTER_SUPER_ACK` and `decode_REGISTER_SUPER_NAK`, plus a `num_sn`
bound in `decode_REGISTER_SUPER_ACK`. W20 closes that specific gap: it
replaces `src/wire.c` in the pinned vulnerable tarball with the exact bytes
of the pinned fixed file, then builds `gcc -g -O2 -fno-omit-frame-pointer
-no-pie`. The rest of the tree stays at the vulnerable commit; a build of
the complete fixed commit tree remains UNKNOWN.

A loopback supernode registered a peer (58-byte reply), received W11's
exact wire (`token_size=1700`, 1738-byte datagram, chosen bytes at
`token+1682 = e8f3420000000000` carrying the vulnerable build's fixed
address `0x42f3e8`), and forwarded 1738 bytes with
`first=0000000000000000 beyond48=0000000000000000`. No chosen address or
chosen token byte returned on the wire. The process stayed alive with no
SIGSEGV or sanitizer report; a fresh peer then registered and a safe
48-byte NAK forwarded 86 bytes with `first=485a4d49485a4d49`. Behaviour is
identical to W19: the fixed decoder rejects the oversized token before
`decode_buf`, while the surviving forwarding encoder re-emits the zeroed
`nak`. Raw logs: `live/evidence/w20-{pins,build,supernode,attack-sender,
safe-sender}.log`.

`sh lab/frontier/n2n2shell/live/w20_upstream_fixed_wire.sh` verifies pins,
the five fixed guards, the exact fixed file in place, the build, the wire,
both forwarded tokens and liveness: `RESULT 14 PASS / 0 FAIL`, rc 0 from
the working tree (`/tmp/n2n-w20-out`) and from `git archive HEAD` with cwd
`/`, `REPLAY_LOGDIR=/tmp/n2n-w20-archive-out`, `PORT_BASE=19570`.

This closes the pinned-fixed-decoder variant of W11's wire as a negative.
Still UNKNOWN: a build of the complete upstream fixed tree, the default-PIE
build with this wire, and ASan on this 1700-byte wire. Ceiling unchanged:
rungs 1-4 on the vulnerable build, no marker execution, canary/RIP hit,
control-flow takeover, command execution or r5. Author experiment only;
no witness verdict.

## W21: ASan on the exact 1700-byte W11 wire (2026-11-26 00:1xZ)

W20 left ASan on the 1700-byte wire UNKNOWN. W21 rebuilds the pinned
vulnerable tree with clang `-fsanitize=address -fno-omit-frame-pointer -g
-O1`, starts a supernode on 127.0.0.1:19600, registers a peer and sends
W11's exact 1738-byte NAK (`token_size=1700`, `token+1682 =
e8f3420000000000` carrying the chosen `0x42f3e8` pointer). ASan reports
`ERROR: AddressSanitizer: stack-buffer-overflow`, `WRITE of size 1700`
at `wire.c:179` <- `decode_REGISTER_SUPER_NAK` (`wire.c:651`) <-
`process_udp` (`sn_utils.c:2322`), and the process aborts. The frame
listing places the write start at the end of `nak3533` (`[11136,11200)`,
`sn_utils.c:2308`) and calls it a partial underflow of the following
`nakbuf` at `[11232,13280)`. No `SEGV on unknown address` appears:
ASan stops on the first out-of-bounds store, so the overwritten `comm`
spill slot that the plain clang -O2 build dereferences in W11 is never
reached under this build. This is sanitizer detection of the same wire
that gave W11 live pointer control, not a new rung and not evidence of
control-flow impact.

A fresh process of the same ASan build received a safe 48-byte NAK from
a registered peer, forwarded 86 bytes with
`first=485a4d49485a4d49`, and produced no AddressSanitizer report
(only LeakSanitizer's shutdown summary, unrelated to the wire). Raw
logs: `live/evidence/w21-{pins,asan-build,asan-attack,attack-sender,
asan-safe,safe-sender}.log`.

`sh lab/frontier/n2n2shell/live/w21_asan_wire1700.sh` verifies pins, the
instrumented binary, the exact wire and chosen pointer, the 1700-byte
write and its three frames, abort without a deref SEGV, and the safe
control: `RESULT 14 PASS / 0 FAIL`, rc 0 from the working tree with
`REPLAY_LOGDIR=/tmp/n2n-w21-out`, `PORT_BASE=19600`.

This closes the ASan-1700 UNKNOWN as a positive sanitizer detection.
Still UNKNOWN: a build of the complete upstream fixed commit tree and a
default-PIE build with this wire. Ceiling unchanged: rungs 1-4 on the
vulnerable build, no marker execution, canary/RIP hit, control-flow
takeover, command execution or r5. Author experiment only; no witness
verdict.
