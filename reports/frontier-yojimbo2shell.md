# frontier brief — yojimbo2shell (remote block-fragment heap overflow)

Status 2026-11-25 03:08Z: real yojimbo ASan build confirms the write through
`Connection::ProcessPacket`; authenticated UDP loopback pair shows a
reproducible downstream crash, and gdb reads the chosen marker back at its
chosen offset after netcode decrypt. Rung 3 CONFIRMED in a real build, rung 4
DEMONSTRATED with conditions (non-default config, post-auth, in-process pair,
gdb-assisted readback), no rung 5. Witness verdict UNKNOWN.

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
process and no command execution: rung 5 remains unclaimed.
