# Provenance — baresip/re `websock_decode()` (GHSA-hvxv-v2gp-v93h)

## Provisioning

Read-only fetch on 2026-11-22 from `https://github.com/baresip/re.git`.
No probe, scan or connection to any external target; all runtime work is
local, direct-call, no network.

- Vulnerable release pin `v4.8.0` =
  `7ace643fef58b0cc0d5d6b3fa434f56f027879f9`
- Fixed release pin `v4.8.1` =
  `89aed31f37449da32004ba608e5d1aa483b8bb21`
- Fix commit `718b92615c7963670d26c1a2b246968b58d782e8` (PR #1584),
  the only `src/websock/websock.c` change between the two tags.
- Advisory: `https://github.com/baresip/re/security/advisories/GHSA-hvxv-v2gp-v93h`
  (CVE-2026-50161, published 2026-05-28, Critical, CWE-190/CWE-787).

## Saved pinned bytes (SHA-256)

```
02a4af85ef7c842c442a5ff8138dea9b849ed5c02216f7aa5dfabadb22516ec0  src/websock-v4.8.0.c
1af5a0603974ee1020af39cc4fa154e93f1956e49991fc4125c785da2e2f861a  src/websock-v4.8.1.c
b382ac56efbe07f334039259c26bd66199e83e5acb145e3b6037b843a3a455ae  src/re_websock-v4.8.0.h
b579bb5e48f6d715010c5a4a06136d6503742fc61d8bd5183b30b4026d4d45ea  src/fix-718b926.patch
```

`run.sh` asserts all three first-party hashes plus the two verbatim function
slice hashes on every invocation:

```
c955a93d51af707518b84f7a72fbdd2cbb6a681f2ee400e165ddca20bfab5e09  v4.8.0 websock_decode() slice (54 lines)
4bf3e7839e0fe1231cfeef58958be8f9028f71cbd2ab2b959947b605fff5e0b1  v4.8.1 websock_decode() slice (55 lines)
```

Slices are extracted with `sed -n '/^static int websock_decode/,/^}/p'` from
the saved pinned `websock.c`; the function body is never retyped or patched.
`driver.c` supplies only the struct declarations, `mbuf_*` stubs and
`sys_ntohll` that the pinned function calls.

## Toolchain and result

gcc 13.3.0 (`gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`) and
clang 18.1.3 (`Ubuntu clang version 18.1.3 (1ubuntu1)`), `-g -O0
-fno-omit-frame-pointer -fsanitize=address` for ASan variants; plain guard-page
variant compiled without ASan. 43 PASS / 0 FAIL on two consecutive runs,
path-independent normalized content hash
`d6a3d40dd5fba54383ccece9e7010a85819737577710854493d90954cb9349fc`
over `harness/evidence/*.out` filtered by `run.sh`.

## Instrumentation boundary

- No libre build, no `websock_accept()`/`websock_accept_proto()`, no HTTP
  upgrade, no listener, no network socket, no baresip binary.
- One direct call to the verbatim pinned `websock_decode()` with a synthesised
  14-byte masked binary frame and a 16-byte payload in a 30-byte heap region.
- The mask key is attacker-chosen (0xB4 repeated); the 64-bit extended length
  is `0xFFFFFFFFFFFFFFFC` so `4 + len` wraps to zero on 64-bit.
- ASan traps the **load** half of `p[i] = p[i] ^ hdr->mkey[i%4]`; the store is
  observed in the separate plain guard-page run (sentinel 0xEE -> chosen 0x5A
  across 32 bytes past the 30-byte region, fault at offset 44 from `p`).
- The vulnerable loop is unbounded in realization (~2^64 iterations); ASan and
  the PROT_NONE page stop it at the first inaccessible byte. No claim is made
  about an orderly 32-byte overwrite in a real heap.
- Nothing here demonstrates an adjacent object, pointer control, benign
  marker, command execution, or rung 5. Advisory reachability and DoS impact
  remain claims until a live loopback server replays the frame.
