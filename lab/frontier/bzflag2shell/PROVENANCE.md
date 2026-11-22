# Provenance — bzflag2shell frontier harness (W116)

## Claim and pins

- CVE-2026-130849 / GHSA-9q5f-g948-c95m. Claim sources: OSV
  `https://osv.dev/vulnerability/CVE-2026-130849`, upstream fix
  `https://github.com/BZFlag-Dev/bzflag/commit/8e501d685aef549090b363260979a4eb93484ea1`,
  release `https://github.com/BZFlag-Dev/bzflag/releases/tag/v2.4.32`.
- Vulnerable: tag `v2.4.30`; fixed: tag `v2.4.32`. Both tarballs are pinned as
  downloaded from codeload.github.com; the patch is the raw upstream `.patch`.

```
29b3b97fa240b2aa681e7935afb3a8aa65831ea7e669813730acfa25810926fb  pins/bzflag-v2.4.30.tar.gz
86a5ded5a039185fee76e6ad65a68554e40cfe7cad5acbd9b1635821a546a7b7  pins/bzflag-v2.4.32.tar.gz
441efea0348adde9f074af5a3b224c0db9c136a53097f0685996e260d875205a  pins/fix-8e501d6.patch
19aeebbe615e7d1a8b40b0657542654218c3fa1bcd0e1ce20a2545d287d16617  src/bzflag-2.4.30/src/game/NetHandler.cxx
3abb2fa5e5170eef19c2243309251a45c6159d148f935f5f9330afe4a984d49b  src/bzflag-2.4.32/src/game/NetHandler.cxx
0951be0fab88b448b8a38a48b78168ebcdb652fec0d9f9b0840671e9972a3b6b  src/bzflag-2.4.30/include/NetHandler.h
35df40cab1cea4b1f1db62b64559086219d5d53643060a26465ce6ec5dad98b5  src/bzflag-2.4.30/include/Protocol.h
32e938657313a08ec8686372dccc4a7b43e73924e9e4e8304b999acad67f0cd8  harness/gen_functions.py
08d578e314626ebc5ccc6a8629873c93c8fa11c07c954fbe3fb77f61a0c5e487  harness/run.sh
```

Pinned constants: `MaxPacketLen = 1024` (`include/Protocol.h:47`),
`MsgUDPLinkEstablished = 0x6f67` (`include/Protocol.h:184`), member order
`char tcpmsg[MaxPacketLen]; int tcplen;` (`include/NetHandler.h:236,238`).

## What the harness executes

`harness/gen_functions.py` extracts `NetHandler::tcpReceive()` and
`NetHandler::receive(size_t,bool*)` verbatim from each pinned
`src/game/NetHandler.cxx`; the extracted recv call is generated file line 69,
pinned vulnerable source line 630. Everything else is a stub: an AF_UNIX
`socketpair` is the wire, a minimal `NetHandler` keeps the pinned member order,
and header parsing uses the pinned big-endian unpack semantics. No bzfs
process, game state machine, authentication or external host is involved.

Wire stage 1: 4-byte header with `len=1024`, then 1024 body bytes whose final
four are little-endian `int32(-4096)`. The vulnerable `tcpReceive()` passes
`len > MaxPacketLen` and asks `receive(1028)`, so `recv(fd, tcpmsg+4, 1024)`
writes four bytes into the adjacent `tcplen`. After `tcplen += size` the
offset is `-3072`; `tcpReceive()` returns `ReadPart` before its `tcplen = 0`
reset. Wire stage 2 supplies 64 chosen bytes; the next `tcpReceive()` calls
`receive(4)` with `tcplen=-3072`, so `recv()` destinations are `tcpmsg-3072`.

- ASan build places `NetHandler` inside a mapped 8192-byte heap allocation and
  explicitly poisons the first 3072 bytes: the genuine negative `recv()` write
  lands in poison and aborts with `use-after-poison`, WRITE of size 64. This is
  instrumented detection, not a natural allocator-redzone report.
- Plain build places `NetHandler` in an mmap arena at +4096 and reads the
  chosen bytes back at `tcpmsg-3072` (arena+1024) in a real adjacent region.
- Fixed v2.4.32 build uses the same driver and rejects `len=1024` with
  `ReadHuge`; its second guard also rejects an out-of-range `tcplen`.

## Observed output (2026-11-22 17:45Z, two replays, byte-identical)

`bash harness/run.sh` rc 0, 14 PASS / 0 FAIL:

```
stage1_status=1 stage1_tcplen=-3072
stage2_status=1 stage2_tcplen=-3008 stage2_offset=-3072
readback+0=5a5a5a5a5a5a5a5a
readback+16=4141414141414141
readback+32=4242424242424242
readback+48=4343434343434343
```

ASan: `ERROR: AddressSanitizer: use-after-poison`, `WRITE of size 64`, frame
`NetHandler::receive` at `gen-vuln/net_functions.inc:69` ← `tcpReceive`.
Fixed ASan clean rc 0; fixed plain `stage1_status=2 stage1_tcplen=4` and no
chosen readback.

Normalized hashes (`EVIDENCE_HASHES.txt`):
Normalization strips PIDs, hex addresses, BuildId and the absolute lab/harness
path prefixes, so a clean git-archive replay produces the same hashes.

```
538c3f33705c51dc51c44e14db7d93283d9ea54b98a9a35428603bcafd7c4ca4  norm-fixed-asan.log
f66e1bb9636eaf243449c4095ca5311f39bb069f1dc6f0fe5b90aec80dd1638e  norm-fixed-plain.log
b8d37ca7b25883f85d6a5af5cfa588221d5ee725b8eb44ea12bc7e8fe2ed33f8  norm-vuln-asan.log
63dd5a864836b4774ff5b84f4a2db6f221e1deeef3a91dcd16e7ee95c2849d48  norm-vuln-plain.log
```

## Limits / unknowns

Rung 4 only at direct-call, explicitly instrumented scope. No real bzfs
listener, no wire-to-socket reproduction beyond the AF_UNIX driver, no live
heap-neighbour control flow, pointer control, command execution or rung 5.
The advisory's pre-auth reach is a claim from primary sources, not measured
here. Whether the exact negative int survives a production compiler's
`recv()` sequencing is source-bound in the pinned body but not tested in a
production bzfs build. Witness replay owed.
