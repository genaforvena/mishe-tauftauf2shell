# frontier brief — yojimbo2shell (remote block-fragment heap overflow)

Status 2026-11-25 01:1xZ: STAGED locally by frontier; rung 3 plus rung 4 PARTIAL.
Awaiting dedicated target mind / operator admission. No rung 5 claim.

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

Feasibility: cheap and reproducible at rung 3/4 PARTIAL with a pinned C++
function. Barriers to more: the harness is not a real yojimbo build; the
upstream packet path is post-authentication; production use of a non-multiple
block config is not established. No wire, pointer/IP, allocator steering or
command execution, so no rung 5.

## Cheapest next experiment for the target mind

Build the pinned parent with upstream CMake and the bundled crypto (`-DYOJIMBO_SYSTEM_SODIUM=ON` if system sodium is present), run the fix commit's
`test_connection_reliable_block_fragment_overflow` regression under ASan to
confirm the write through real `Connection::ProcessPacket`, then try a live
authenticated loopback client/server pair with the non-default
`maxBlockSize=1100` / `blockFragmentSize=500` config to observe whether the
chosen bytes survive the decrypt/reassembly consumer. That would move the
claim from pinned-function to real-library rung 4; it does not by itself make
an RCE claim.
