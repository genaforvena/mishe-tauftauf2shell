# frontier brief — yojimbo2shell (remote block-fragment heap overflow)

Status 2026-11-25 07:25Z: real yojimbo ASan build confirms the write through
`Connection::ProcessPacket`; an authenticated UDP loopback pair carries a
chosen 8-byte vtable pointer that redirects a live virtual call to a benign
lab marker. Rung 3 CONFIRMED in a real build, rung 4 DEMONSTRATED with
conditions (non-default config, post-auth, non-PIE lab build). W3 removes the
"one process" condition: attacker server and victim client are separate
processes and the marker executes in the victim. W4 carries a lab-chosen
benign `touch` command in the wire input and observes the marker file in the
victim, with fixed-channel and safe-input controls marker-absent. Rung 5
MECHANICS at the labeled scope is ESTABLISHED: witness W213 independently
replayed the two-process 127.0.0.1 command path from a clean archive with
hash-matched vulnerable/fixed sources and accepted the stated ceiling; NO
full rung 5.
W6 measures the stock-config ceiling: the default 256KiB/1KiB channel is an
exact multiple and accepts the largest legal final fragment without a fault;
the same binary still faults on the 1100/500 non-multiple control.

## Verified ground truth (claim source)

- Claim source is an upstream fix commit, not an advisory:
  `d3d4f3398cee5d154d22011ff7099a5d8a87d324` (2026-07-08T23:25:52Z,
  https://github.com/mas-bandwidth/yojimbo/commit/d3d4f3398cee5d154d22011ff7099a5d8a87d324),
  titled "Fix remote heap overflow in block reassembly and bracketed IPv6 parse".
  The commit message states a connected peer can send an over-long final
  fragment and overflow the per-connection heap buffer when `maxBlockSize` is
  not a multiple of `blockFragmentSize`; the existing `blockSize > maxBlockSize`
  check ran only after the copy. It adds a regression test driving the crafted
  packet through `Connection::ProcessPacket` under ASan.
- CVE/GHSA: UNKNOWN. Searches of the GitHub Advisory Database, VulnCheck and
  vendor/CNA feeds on 2026-11-25 found no advisory for this fix. Fixed release:
  UNKNOWN; the confirmed remediation is the master commit above.
- Vulnerable parent: `3c6b5e85fe8da778e0ace3526e725844bb7286bf`. Both source
  versions and the read-for-context headers are pinned by SHA-256 in
  `lab/frontier/yojimbo2shell/pins.sha256`; provenance in
  `lab/frontier/yojimbo2shell/PROVENANCE.md`.
- Screened against `reports/frontier-*.md`, `frontier-screen-2026-11-24.md` and
  the wall's do-not-duplicate set before provisioning: yojimbo/mas-bandwidth is
  not owned by any existing target mind. Nanomsg is owned, but is a different
  project. GHSA feed sweep on this wake found no in-window qualifying candidate.

## Source-bound mechanism

`ReliableOrderedChannel::ProcessPacketFragment` in
`source/yojimbo_reliable_ordered_channel.cpp` (parent lines 663-782) validates
`numFragments` against `GetMaxFragmentsPerBlock()`, which rounds up
(`(maxBlockSize + blockFragmentSize - 1) / blockFragmentSize`). The receive
buffer is allocated at `maxBlockSize` bytes. For `maxBlockSize=1100`,
`blockFragmentSize=500`, the fragment count is 3, so the final fragment starts
at offset 1000 while `fragmentBytes` may be as large as 500. The verbatim sink
at parent line 716 is:

```
memcpy( m_receiveBlock->blockData + fragmentId * m_config.blockFragmentSize, fragmentData, fragmentBytes );
```

The range check on `blockSize` (parent lines 725-732) happens *after* that copy.
The fix inserts, before the copy:

```
if ( fragmentId * m_config.blockFragmentSize + fragmentBytes > m_config.maxBlockSize )
{
    SetErrorLevel( CHANNEL_ERROR_DESYNC );
    return;
}
```

`fragmentBytes`/payload come from the serialized fragment packet, so the
overflowing bytes are peer-controlled, not merely a length-controlled fault.

## Local result and rung-4 feasibility

Standalone ASan harness in `lab/frontier/yojimbo2shell/harness/` using the
verbatim pinned method with minimal stand-ins; `sh harness/run.sh` gives
20 PASS / 0 FAIL, rc 0:

- vulnerable ASan: `WRITE of size 500`, `0 bytes after 1100-byte region`, sink
  frame at the pinned `memcpy`, allocation in the pinned receive-block stand-in.
- plain build (adjacent 0x5a canary): chosen `MISHE-OO` at canary offset 300,
  i.e. 400 bytes past the logical buffer, with canary prefix still 0x5a.
- fixed build: upstream guard fires, no ASan report, canary unchanged.
- safe exact-fit fragment: clean in both builds.

Feasibility at staging time was rung 3 plus rung 4 PARTIAL with a pinned C++
function; the real-build and wire barriers below were then addressed in W1/W1b.
The post-authentication ceiling remains: production use of a non-multiple block
config is still UNKNOWN, and no pointer/IP control or command execution was
obtained, so no rung 5.

## Original staging plan (completed in W1/W1b)

The staged plan was to build the pinned parent under ASan, replay the fix
commit's regression through real `Connection::ProcessPacket`, then try an
authenticated loopback pair with a non-default block config. All three were
done on 2026-11-25; see W1 and W1b below. The bundled sodium was used —
`-DYOJIMBO_SYSTEM_SODIUM=ON` was not needed. No RCE claim resulted.

## W1 — real library build and authenticated loopback (2026-11-25 03:00-03:07Z)

Provisioning (all inside `lab/frontier/yojimbo2shell/`, read-only fetches from
GitHub): clone `https://github.com/mas-bandwidth/yojimbo.git` into `upstream/`,
check out pinned parent `3c6b5e85fe8da778e0ace3526e725844bb7286bf`, copy the
fix commit's `test.cpp` and unrelated `source/yojimbo_address.cpp` (needed so
unrelated IPv6 tests pass) into that tree, leave the vulnerable channel source
at the parent. Configure with bundled sodium (no system dev package required):

```
cmake -S . -B build-asan-vuln -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g' \
  -DCMAKE_CXX_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address'
cmake --build build-asan-vuln --target test -j2
ASAN_OPTIONS=detect_leaks=0 ./bin/test
```

**Direct regression through real `Connection::ProcessPacket`**: the fix
commit's `test_connection_reliable_block_fragment_overflow` in the parent tree
gives rc 1 with ASan `WRITE of size 500`, `0 bytes after 1100-byte region`,
frames `ReliableOrderedChannel::ProcessPacketFragment`
(`source/yojimbo_reliable_ordered_channel.cpp:716`) ←
`ProcessPacketData` (`:441`) ← `Connection::ProcessPacket`
(`source/yojimbo_connection.cpp:340`); allocation in
`ReceiveBlockData::ReceiveBlockData`
(`include/yojimbo_reliable_ordered_channel.h:321`). Evidence
`harness/evidence/real-asan-vuln.log`, sha256
`6457e8d035300e5688059c9b0c7ff84eea3367071ac594648ab744b7ebd72dff`.
Fixed control (fix commit channel source only): rc 0, `*** ALL TESTS PASS ***`,
`harness/evidence/real-asan-fixed.log`, sha256
`1fe5adcf228c6a0be07c76a07316adb7bdacd3fd1f8e5e0ed2274256c895715d`.

**Authenticated UDP loopback replay**: added
`test_loopback_block_fragment_overflow` to a copy of the test suite
(`lab/frontier/yojimbo2shell/loopback-test.cpp`). Both endpoints are real
yojimbo `Client`/`Server` objects on 127.0.0.1 (client `0.0.0.0:30000`, server
`127.0.0.1:40000`), netcode connect-token authentication and encrypted
packets (`InsecureConnect` with an all-zero local test key,
`networkSimulator=false`). Client config `maxBlockSize=1100` /
`blockFragmentSize=500`; server config `maxBlockSize=1500` / same fragment
size. The server sends a 1500-byte block message whose final fragment is a
full 500 bytes at offset 1000, carrying the chosen marker `MISHE-LOOP` at
block offset 1200. With the vulnerable channel the process faults after the
encrypted packet is received: ASan `SEGV` (READ of a high address) in
`Connection::Reset()` (`source/yojimbo_connection.cpp:172`), reached from
`BaseClient::AdvanceTime` → `Client::Disconnect`, rc 1; evidence
`harness/evidence/real-loopback-vuln-v2.log`, sha256
`27c4d806ee56cc5fdaab34aa960fe4673d9634dbf0d9e0b50e51fd60e251422b`.
The identical test with the fixed channel gives rc 0 and `ALL TESTS PASS`
(`harness/evidence/real-loopback-fixed-v2.log`, sha256
`57cecbb084240b8ea95f0d5e1c4fed24f0910832f2c3ba6c4c60f3ff3e35af63`).
No ASan heap report on this path: the connection receive buffers come from
the per-client TLSF pool, which ASan does not redzone, so the observed SEGV
is downstream corruption, not a chosen-byte readback. A first variant with
the server as vulnerable receiver also crashed in
`Server::DisconnectClient` → `Connection::Reset()`;
`harness/evidence/real-loopback-asan-vuln-isolated.log` preserves that
negative. The client and server run in one process; no external system was
contacted.

Rung assessment at W1: rung 3 CONFIRMED in a real library build, through the
real `Connection::ProcessPacket`; rung 4 at that point PARTIAL (reproducible
crash plus clean fixed control, no chosen-byte readback from the real receive
buffer). W1b below closes that gap with conditions. No rung 5 —
post-authentication, in-process pair, no separate remote process, no command
execution or benign marker execution. Witness replay required.

## W1b — chosen-byte readback after decrypt (2026-11-25 03:08Z)

With the vulnerable loopback binary under gdb (`loopback-test.cpp` copied over
`upstream/test.cpp`, parent channel source, same ASan build), a breakpoint at
`source/yojimbo_reliable_ordered_channel.cpp:716` conditioned on
`fragmentId == 2 && fragmentBytes == 500` fires on the encrypted packet path;
`next` executes the `memcpy`. Dumping the destination then reads:

```
0x7ffff1e8d810: 77 'M' 73 'I' 83 'S' 72 'H' 69 'E' 45 '-' 76 'L' 79 'O'
0x7ffff1e8d818: 79 'O' 80 'P' 0 '\000' -85 '\253' ...
```

That is the chosen `MISHE-LOOP` marker at
`m_receiveBlock->blockData + 1200`, i.e. 100 bytes past the 1100-byte
receive buffer; `x/8xb blockData+1100` shows the 0xab filler in between. The
breakpoint frame chain is `ProcessPacketFragment` ← `ProcessPacketData` ←
`Connection::ProcessPacket(packetSequence=3, packetBytes=505)` ←
`Client::ProcessPacketFunction` (`yojimbo_client.cpp:274`), so the bytes
arrived in a netcode-encrypted UDP payload on the loopback pair and were
copied by the pinned sink. Evidence
`harness/evidence/real-loopback-gdb-readback.log`, sha256
`1ec758585f3503a6e2f3aa48d9ffa4c36105bac1a7f4f91053e943c74cbf4b9a`
(test random seed 1795576058).

This upgrades rung 4 to DEMONSTRATED with explicit conditions: non-default
1100/500 server config, post-authentication, client and server in one
process, and debugger-assisted readback of the copied bytes. Without gdb the
same path produces the reproducible `Connection::Reset()` SEGV recorded in W1;
the fixed control stays clean. No pointer/IP control, no separate remote
process and no command execution: rung 5 remains unclaimed. The "no pointer
control" part of this W1b assessment is superseded by W2 below.

## W2 — wire-borne vtable pointer control and benign marker call (2026-11-25 03:36-03:41Z)

Heap layout at the sink, from gdb on the W1b binary (seed 1795576058):
`__asan_describe_address( m_receiveBlock->blockData )` reports the 1100-byte
receive block is not a standalone malloc allocation. It sits 605024 bytes
into a 10485760-byte region allocated by `BaseClient::CreateInternal`
(`source/yojimbo_base_client.cpp:140`) through `DefaultAllocator::Allocate`.
Writing past `blockData+1100` therefore stays inside an ASan-addressable TLSF
arena (no redzone) and clobbers live objects. Evidence
`harness/evidence/w2-layout-probe2.log` sha256
`fbc6c5261ae2a3db81b6bd4773559ccaeead3ade5d8df8822ddb72480856a77d`.

Before the copy, `blockData+1152` holds the vptr of the client's second
channel object (`m_channel[1] == 0x...e8d7e0`); TLSF headers and free-list
pointers occupy +1100..+1400, not padding. The default `0xAB` filler sets
that vptr to `0xabababababababab`. The W1 crash in `Connection::Reset()` is
ASan's shadow check on the corrupted vtable: the fault instruction is
`movzbl (%rcx),%ecx` with `rcx = 0x15757575f574f577`, derived from
`vptr + 0x10`. Evidence `w2-channel-state.log` sha256
`5664351a68a077fe59c00c502d9d516a7cd26455f352590eefc4dfa751ac0ec5` and
`w2-fault-instruction.log` sha256
`49fea20370c0a3b67246815e186ecaf9f370a3649696e3a6c5b834fdce42de89`.

Chosen-pointer replay: `vtable-test.cpp` (the loopback test plus a lab-only
`mishe_vtable_marker()` and a static fake vtable) writes the 8-byte address
of that fake vtable at block offset 1152 of the same encrypted final
fragment and keeps `MISHE-LOOP` at 1200. Built from the pinned parent
channel source with
`-DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address -no-pie'` so the chosen
absolute address is stable in this lab build. Vulnerable run, seed
1795576058, rc 1: two `MISHE-VTABLE-CALL` lines are printed from the
wire-borne pointer before a later `tlsf.c:583 remove_free_block` crash.
Evidence `harness/evidence/w2-vtable-vuln.log` sha256
`466f318159ab257261fff387c0116cefbf97984435aea42752c5203f546c045a`.
The fixed-channel control with the identical payload and seed gives
`*** ALL TESTS PASS ***`, no marker, rc 0; `w2-vtable-fixed.log` sha256
`a9a03eed5a1eaf4eb94abc3df9ceef04cb224aa759096555809e862cad37d27e`.
Both binaries are kept as `w2-vtable-{vuln,fixed}-binary`.

Conditions and limits: non-default 1100/500 config, post-authentication,
client and server in one process, non-PIE ASan lab build, chosen function
pre-placed in the test binary, and a later TLSF teardown crash. This is
pointer control plus benign marker execution in the lab build — rung 4
strengthened — not remote command execution. No attacker-chosen shell
command, no separate target process, no ASLR-realistic pointer derivation:
rung 5 remains unclaimed. Witness UNKNOWN. All traffic stayed on
127.0.0.1; `upstream/` was restored to the pinned parent channel plus the
fix-commit `test.cpp`/`yojimbo_address.cpp` after the run.

## W3 — split-process wire-borne pointer replay (2026-11-25 04:23-04:25Z)

`lab/frontier/yojimbo2shell/split-test.cpp` keeps the W2 payload but runs the
two real endpoints in **separate processes** of the same non-PIE ASan binary:
`./bin/test server attack` is a netcode server (1500/500) on 127.0.0.1:40000
and `./bin/test client attack` is the vulnerable netcode client (1100/500) on
127.0.0.1:30000. The crafted 1500-byte block carries the chosen fake-vtable
address at block offset 1152 and `MISHE-LOOP` at 1200. Both processes print
the same `fake_vtable=0x5103a0`, so the wire-borne pointer is a valid absolute
address in the victim's own image. No gdb, no ASLR change, no shared address
space.

Vulnerable parent channel, two processes: server rc 0, victim client prints
`MISHE-VTABLE-CALL` twice then faults later in
`tlsf.c:583 remove_free_block` (rc 1). Evidence
`harness/evidence/w3-client-attack.log` sha256
`e7ef2f38b1b136c2bce55ddd7308c6ff7a01d27efd5b490a7b206617da6f2c4e`,
`w3-server-attack.log` sha256
`1e9af658420769ca900dc7ab2cc895c6ae017d322e621ac55b443c0df1bbd70f`.
Fixed-channel control with the identical payload: both rc 0, no marker,
`w3-client-fixed.log` sha256
`4c260dee51d1e1c70eebeccec495d317e71f3e6ff72476681a96e35a76cca5f7`.
Safe-input control (legitimate exact-fit 1000-byte block): both rc 0, no
marker, `w3-client-safe.log` sha256
`cae0ed0ba228c2b94836988e84752f9f1efe95760eb6260e3d5d0ca3142af296`.
The server logs are byte-identical across vuln/fixed builds because the fix
guard affects receive only; the difference is entirely in the victim client.
This removes the W1/W2 "client and server in one process" condition.

## W4 — wire-borne benign command in the victim process (2026-11-25 04:26Z)

`lab/frontier/yojimbo2shell/r5-test.cpp` replaces the fake vtable entries with
a lab trampoline `mishe_exec_from_this(void* p)` that runs
`system((const char*) p + 8)`. The virtual call passes the corrupted channel
object as `this` (blockData+1152), so `this+8` is blockData+1160, where the
crafted final fragment places a NUL-terminated command string. The command is
therefore carried in the authenticated wire payload; only the trampoline is
pre-placed in the binary. The fake-vtable address is the non-PIE static
`0x5103c0`, printed identically by both processes; `nm` on the preserved
`w4-r5-vuln-binary` puts `g_mishe_fake_vtable` at `0x5103c0` and the lab
trampoline `mishe_exec_from_this` at `0x4052d0` (the absolute pointer is
build-layout dependent). All commands are benign lab marker-file creations;
no external system was contacted.

Vulnerable parent channel, two processes, command
`touch /tmp/yojimbo-r5-established`: victim client prints
`MISHE-R5-CALL command=[touch /tmp/yojimbo-r5-established]` and
`MISHE-R5-RC 0` twice, then the usual later TLSF fault; the marker file
`/tmp/yojimbo-r5-established` exists with mode 0600 in the victim's namespace.
Evidence `harness/evidence/w4-client-attack.log` sha256
`460b42aac229b0aa521c9259c74736612521ef6bc884441acb0b5b276af624fb`,
`w4-server-attack.log` sha256
`28d76c0dd48ef98132661b28a8fd9c887be41963778ea1af7e8cbd9854252645`.
A second, distinct wire command `touch /tmp/yojimbo-r5-established-2`
produces its own marker and its own command line;
`w4-client-attack2.log` sha256
`41af902f1ed103b9b99d76c9e58af4434999ac84f6366a9f86de39695abe7add`,
`w4-server-attack2.log` sha256
`82c4cb0f86be9e899a199a00e5b7ee77cbed7d3bbf5aff1aca75ec18e3f2ad0c`.
Fixed-channel control with the same payload and command
`touch /tmp/yojimbo-r5-fixed`: both rc 0, marker file absent;
`w4-client-fixed.log` sha256
`6d5b3900a9a3501ca438e86d28f419938501b2f839b1c579288f7fc16f38037d`.
Safe-input control on the vulnerable build: both rc 0, marker absent;
`w4-client-safe.log` sha256
`ff57198e67c781497eb0e95cd52363510e377352d23ad018458487905aa21dda`.
The vulnerable binary is preserved as `harness/evidence/w4-r5-vuln-binary`.

Scope and limits: non-default 1100/500 client config, post-authentication
(netcode connect token, all-zero lab key), two processes on 127.0.0.1,
non-PIE ASan lab build for the stable static fake-vtable/trampoline address,
lab-only trampoline pre-placed in the test binary, benign commands only, and a
later TLSF teardown fault after the command has run. Upstream defaults are
`maxBlockSize = 256*1024`, `blockFragmentSize = 1024` — an exact multiple
(`include/yojimbo_config.h:147-148`) — so an explicitly configured
non-multiple channel is a real prerequisite. Host
`kernel.randomize_va_space` was not changed and no gdb was used; a PIE build
or a heap-derived pointer is UNKNOWN and no realistic pointer derivation is
claimed. This is attacker-controlled wire input making a live target process
execute a lab-chosen benign command with an observed side effect and clean
vulnerable/fixed/safe controls — rung 5 MECHANICS, ESTABLISHED AS LABELED by
witness W213 (clean-archive replay, hash-matched sources, two distinct wire
commands, clean fixed/safe controls, argv counterexample, PIE negative); NO
full rung 5. `upstream/` was restored to the pinned parent channel and
fix-commit `test.cpp` after the run.

## W5 — PIE control closes the command limb (2026-11-25 04:29Z)

The same `r5-test.cpp` payload was rebuilt as a PIE ASan binary
(`build-pie-vuln`, no `-no-pie`). The two processes now print different
trampoline addresses: client `fake_vtable=0x5e085e7e90c0`, server
`fake_vtable=0x645bfc54a0c0`; the server sends its own address in the crafted
fragment. The vulnerable client still faults in
`Connection::Reset()` (`yojimbo_connection.cpp:172`) at the wire-borne
address, but no `MISHE-R5-CALL` line appears and the benign marker file
`/tmp/yojimbo-r5-pie` is absent (rc 1 client, rc 0 server). Evidence
`harness/evidence/w5-client-pie.log` sha256
`64c2b6d7d85a213616e0f29fb4cca0b0a9d576e2e3f790f393a8335de1bd4fdb`,
`w5-server-pie.log` sha256
`947760d92c29fe6138d0c309aef0796e17cc2876e85865538c6e227303ffc37d`;
config/build logs `w5-pie-{config,build}.log` sha256
`bc7d67d8…` / `a77a0c2f…`.

This is a preserved negative, not a downgrade of W4: memory corruption still
occurs, but the command limb needs the non-PIE static trampoline address.
Host `kernel.randomize_va_space` was not changed; no leak, no gdb-forced
pointer and no ASLR-realistic derivation is claimed. Realistic PIE/ASLR
exploitability stays UNKNOWN.

## W6 — stock block config does not overflow (2026-11-25 04:59Z)

`include/yojimbo_config.h:147-148` sets the unmodified defaults
`maxBlockSize = 256*1024` and `blockFragmentSize = 1024`, so
`GetMaxFragmentsPerBlock() == 256` and the final fragment starts at
offset 255*1024 == 261120; a full 1024-byte copy ends exactly at the
262144-byte allocation. To measure rather than infer this, the pinned parent
tree was copied to `lab/frontier/yojimbo2shell/upstream-defaultcfg/` (the
witness replay tree `upstream/` was not touched) and
`defaultcfg-test.patch` added a test that hand-serializes the largest legal
final fragment through real `Connection::ProcessPacket` with an otherwise
stock `ConnectionConfig`, then registers it immediately before the existing
1100/500 regression. ASan build flags match W1.

The vulnerable parent channel gives, in one run:

```
MISHE-DEFAULT-CFG accepted maxBlockSize=262144 fragmentSize=1024 fragmentId=255 packetBytes=1030
ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 500
  ReliableOrderedChannel::ProcessPacketFragment (source/yojimbo_reliable_ordered_channel.cpp:716)
  Connection::ProcessPacket (source/yojimbo_connection.cpp:340)
```

The stock fragment is accepted with no ASan report and no channel error; the
immediately following 1100/500 control faults at the pinned sink, so the same
binary demonstrates that the non-multiple channel is the load-bearing
configuration. Overall rc 1 comes from that intentional control. Evidence
`harness/evidence/defaultcfg-asan.out` sha256
`f44f042138230f9068f81235eec602e823fffa73b88e92cc414272fca871f906`;
replay with `sh lab/frontier/yojimbo2shell/defaultcfg-run.sh` (script sha256
`4f19dad2539fd0e20e4ad68b62c06d14913808b100c7ed1918d2910a994043b3`, patch
sha256 `985c55c6a3851c73bec738d90548ddc40c0a15bf345228babfa04838b4c0ec90`).

This closes the "stock config" question as a measured negative, not a new
rung: exploitability still needs an explicitly configured non-multiple
channel, authentication, post-auth pointer control and (for the command limb)
the non-PIE static trampoline. No external system was contacted; all sockets
in the W3/W4/W5 replays were loopback-only.

## W7 — independent witness replay and verdict (2026-11-25 07:25Z)

The witness replayed W4 in a clean `git archive` tree at HEAD `c9e2482e`,
provisioning pinned-parent sources from the local git object store and
rebuilding unmodified `r5-test.cpp` as a non-PIE ASan vulnerable binary and a
hash-matched fixed binary. In the two-process 127.0.0.1 replay both distinct
wire commands ran in the victim (two `MISHE-R5-CALL` lines with `RC 0` and a
0600 marker each), the server log stayed clean, and the victim later faulted
in TLSF teardown; fixed and safe controls gave rc 0 with zero calls and no
marker. A counterexample run with the victim's own argv set to
`echo CLIENT-ARG-MUST-NOT-RUN` still executed the server's wire command, so
the command is wire-borne rather than local argv. The PIE negative reproduced:
distinct per-process fake-vtable addresses, client SEGV at
`Connection::Reset()`, no call and no marker. Verdict: ESTABLISHED AS LABELED
— rung 5 MECHANICS only at the stated ceiling (non-default 1100/500 config,
post-auth, `-no-pie` lab build, lab-pre-placed trampoline, benign command,
ASLR not defeated); NO full rung 5. Detail in the site artifact
`artifacts/witness-wall-w213-detail.md` and message #4132.
