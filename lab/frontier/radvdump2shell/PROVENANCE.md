# Provenance — radvdump2shell harness (W140, 2026-11-23)

CVE-2026-48715 / GHSA-52px-gh9p-m379. All provisioning was read-only fetching
of public upstream blobs; no external host was probed. The harness runs only
inside this directory with a direct function call, no socket or listener.

## Pinned inputs

| File | SHA-256 | Origin |
|---|---|---|
| `src/radvdump.c.878ca6b` | `0beaaaf74ebf93835331efacac5986769f53388b5e8bed8e65c1999fa086355b` | raw.githubusercontent.com/radvd-project/radvd/878ca6bc5074b3427a2eb94a4c4a8b1f34b7bfed/radvdump.c (advisory-confirmed vulnerable HEAD) |
| `src/radvdump.c.068bde13` | `bfe1f0f6800b2955b1ee6994c9f8c6f70e9663f1f318ffc98adbd338b47b48b5` | raw.githubusercontent.com/radvd-project/radvd/068bde13e3fd6a5fcdb6859e6a2acd293a325dc5/radvdump.c (fix commit) |
| `src/radvdump.c.v2.20` | `0beaaaf74ebf93835331efacac5986769f53388b5e8bed8e65c1999fa086355b` | raw.githubusercontent.com/radvd-project/radvd/v2.20/radvdump.c (affected release, byte-identical to vulnerable HEAD) |
| `src/radvdump.c.v2.21` | `bfe1f0f6800b2955b1ee6994c9f8c6f70e9663f1f318ffc98adbd338b47b48b5` | raw.githubusercontent.com/radvd-project/radvd/v2.21/radvdump.c (patched release, byte-identical to fix commit) |
| `src/fix-068bde13.patch` | `4c98ac6f886ce321af8bca8304c414d4c0607b288887e20c7a742eab3ed4e3d2` | github.com/radvd-project/radvd/commit/068bde13e3fd6a5fcdb6859e6a2acd293a325dc5.patch |
| `src/GHSA-52px-gh9p-m379.html` | `f3ae63de78473c1409ab6511f56c0eef176cf471785f03dcd4f9edac83f87e53` | github.com/radvd-project/radvd/security/advisories/GHSA-52px-gh9p-m379 |

`src/SHA256SUMS` pins the six files; `harness/SHA256SUMS` pins the driver,
runner, four generated slices and the six source pins (12 entries).

## Verbatim slices re-extracted per run by `harness/run.sh`

| Slice | Vulnerable source | Fixed source |
|---|---|---|
| `vuln/route_case.inc` | `radvdump.c.878ca6b:371-399` | — |
| `rel20/route_case.inc` | `radvdump.c.v2.20:371-399` | — |
| `fixed/route_case.inc` | — | `radvdump.c.068bde13:408-462` |
| `rel21/route_case.inc` | — | `radvdump.c.v2.21:408-462` |

Each slice is re-created with an `echo '#line N "radvdump.c.<pin>"'` header
followed by `sed -n 'N,Mp'` of the pinned blob, so ASan and gdb attribute the
fault to the pinned line, not the generated file. The slice is the complete
`case ND_OPT_ROUTE_INFORMATION:` body including its closing brace.

## Harness inputs and stubs

`driver.c` builds a 280-byte RA in a global buffer: 16-byte
`struct nd_router_advert` (type 134) plus one 264-byte Route Information
option (type 24, length byte 33, prefix length 0, lifetime `0xffffffff`).
Source bytes are `0x41` with chosen markers at copy offsets 17 (`5a`), 24
(`7a`), 33 (`3c`), 40 (`7b`) and 63 (`7e`). The `safe` mode uses length byte 2
(8-byte copy, 32-byte packet). `arith` does arithmetic only, no call.

Stubs: `flog` records the message and count; `addrtostr` records the first 16
bytes and, in plain builds only, reads the next 48 stack bytes to observe the
smear (ASan builds define `NO_OOB_READ` so the observer itself never reads out
of bounds); `print_preferences` is a no-op. All variables the verbatim slice
reads except its own local `addr` are globals, so the overflow cannot corrupt
harness control state. Plain builds use `-O0 -g -fno-stack-protector` because
Ubuntu's default stack protector aborts before observation; sanitizer builds
use gcc and clang with `-fsanitize=address`.

## Observations

- `PASS=67 FAIL=0` three runs (`evidence/run1.txt`…`run3.txt`) and a clean
  `/tmp` replay (`evidence/replay.txt`); normalized trace
  `cf327179a2abca7647a1a8bd3b58259a398c7de94f24a27910f3a356d8d3788a`.
- Rung 1: `arith-vuln.out` — length 33 accepted, 256 copied into 16 bytes.
- Rung 2: `plain-vuln-attack.out` / `plain-rel20-attack.out` — accepted option,
  attacker bytes in destination, no rejection; `plain-fixed-attack.out` /
  `plain-rel21-attack.out` — length rejected, no copy, no formatter call.
- Rung 3: `vuln-gcc-asan.out` / `vuln-clang-asan.out` — `WRITE of size 256`
  at pinned `radvdump.c.878ca6b:380` in `route_case`; fixed/rel21 and safe
  ASan outputs clean.
- Rung 4: chosen markers observed past the 16-byte object in plain builds;
  `gdb-frame.out` shows the pinned-line-381 frame with
  `saved rip = 0x414141414141417b`, followed by a fault at pinned line 382.

## Ceiling / negatives

Direct call with stubbed radvd plumbing; no real `radvdump` process, raw
socket, IPv6 neighbour, live RA or wire input; no groomed allocator; no ROP
chain or command execution; no witness. ASan faults on the WRITE before any
control-flow effect, so the saved-RIP byte is observed only in the plain
`-fno-stack-protector` build under gdb. The fix patch's root-drop, buffer
zeroing, jumbo-packet and earlier-loop changes are not reproduced here.

## Re-run

```
cd lab/frontier/radvdump2shell/harness && bash run.sh
```
Check `PASS=67 FAIL=0` and the `TRACE_SHA256` above. A clean-room replay of
`git archive HEAD lab/frontier/radvdump2shell` at commit `a514b30` ran from an
empty temporary directory with the same result: `PASS=67 FAIL=0`, trace
`cf327179a2abca7647a1a8bd3b58259a398c7de94f24a27910f3a356d8d3788a`
(`evidence/git-archive-replay.txt`).

## Independent witness verdict — 2026-11-23 (W149, DM #2388)

The rung-5 claim was independently replayed from a clean `git archive HEAD
(1f8f9b9)` into `/tmp/w149-radvdump`, using the witness's own binaries, not the
author's. Upstream tarballs were hash-checked and `radvdump.c` verified
byte-exact (`0beaaaf7…086355b` v2.20, `bfe1f0f6…47b48b5` v2.21). Because the
tarballs have no generated `configure`, the witness ran `autogen.sh`, then
built plain `-O0 -g -fno-stack-protector` (sha `723b6ce6…7cc43f6d`), fixed
2.21 (`194ade7c…d73b4d2a`) and fortified `-O2` (`b19eecbf…5f6de72c`,
`__memcpy_chk`).

Witness-only passive measurement: `&addr=0x7fffffffe260`, saved RIP at
`$rbp+8 = &addr+296`, `system=0x7ffff7c58750`, `exit=0x7ffff7c47ba0`,
`usage_str=0x55555555d010`, `x/3i 0x7ffff7d0f84b = pop %rdi; ret`. Its
496-byte RA used the witness-only command
`/usr/bin/touch /tmp/w149-radvdump-witness-marker` at copy offset 336. Four of
four gdb ASLR-off attacks created a fresh root-owned 0-byte witness marker;
the author's default marker was not created. A passive `__libc_system`
breakpoint stopped with `$rdi = 0x7fffffffe3b0` holding exactly the wire
string. Controls all MARKER_ABSENT: safe length byte 2, fixed 2.21 rejection,
ASLR-on SIGSEGV, fortified `-O2` `__memcpy_chk` abort. Verdict: ESTABLISHED at
the labeled lab-build scope (no-canary `-O0`, gdb-inferior ASLR-off,
host-measured addresses, root raw socket to `::1%lo`, benign `touch`); no
repository writes and no processes left by the witness. The "no witness"
ceiling above describes the W140 direct-call harness, not this live lane.
