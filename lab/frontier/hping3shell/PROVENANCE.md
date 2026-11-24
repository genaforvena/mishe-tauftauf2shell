# PROVENANCE — hping3shell lab (CVE-2026-136131)

## Pinned inputs (read-only provisioning, no external probing)

- `pinned/display_ipopt.c`, `pinned/waitpacket.c`, `pinned/hping2.h` copied
  verbatim from `https://github.com/antirez/hping.git` at master tip
  `3547c7691742c6eaa31f8402e0ccbb81387c1b99` (2014 tree, no later fix).
  sha256 respectively:
  `e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b`,
  `f63e229c6d8708a23f29baeebb7e9d18dbefaa9a41db801c15866b07d52279e9`,
  `d3fa609e10355ca1ec2398b6ec9c670ff11574076795e86115ad0e4711699072`.
  `run.sh` rechecks the `display_ipopt.c` hash every run.
- `pinned/fix.patch`: local hunk implementing the fix recommended in
  upstream issue #80 (clamp `i` to `MAX_IPOPTLEN` and to `hlen`); sha256
  `23bb8db3b3d2ee241d355ce1af7c643ae1dc831ae6058c52fbdd2f806f400c92`.
  Patched source sha256
  `70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7`.
- Advisory and issue read through `read` only; no external packet probes.

## Why `standin/` copies

C quoted includes resolve to the source file's own directory before `-I`.
Compiling `pinned/display_ipopt.c` directly picked the full upstream
`pinned/hping2.h` (missing `byteorder.h`) rather than the minimal stand-in.
`run.sh` therefore does `cp pinned/display_ipopt.c standin/display_ipopt.c`
and `cp fixed/display_ipopt.c standin/fixed_display_ipopt.c`: byte-identical
copies, only the include resolution changes. `standin/hping2.h` reproduces
the option constants and `struct myiphdr` from the pinned header verbatim;
`standin/globals.h` is empty because the pinned function uses no globals
from it. `standin/harness.c` supplies the packet buffer, the RR option and
an adjacent `.bss` canary; it never edits the pinned function.

## Exact build commands (from `lab/frontier/hping3shell/`)

```
patch -s -o fixed/display_ipopt.c pinned/display_ipopt.c < pinned/fix.patch
cp pinned/display_ipopt.c standin/display_ipopt.c
cp fixed/display_ipopt.c standin/fixed_display_ipopt.c
gcc -O0 -g -std=gnu99 -Wall -Wno-unused -fsanitize=address -I standin -c standin/display_ipopt.c -o asan/display_ipopt.o
gcc -O0 -g -std=gnu99 -Wall -Wno-unused -fsanitize=address -I standin -c standin/harness.c -o asan/harness.o
gcc -fsanitize=address -o asan/harness asan/display_ipopt.o asan/harness.o
gcc -O0 -g -std=gnu99 -Wall -Wno-unused -fsanitize=address -I standin -c standin/fixed_display_ipopt.c -o asan/display_ipopt_fixed.o
gcc -fsanitize=address -o asan/harness_fixed asan/display_ipopt_fixed.o asan/harness.o
gcc -O0 -g -std=gnu99 -Wall -Wno-unused -I standin -c standin/display_ipopt.c -o plain/display_ipopt.o
gcc -O0 -g -std=gnu99 -Wall -Wno-unused -I standin -c standin/harness.c -o plain/harness.o
gcc -o plain/harness plain/display_ipopt.o plain/harness.o
gap=$(nm -n plain/harness | awk '$3 ~ /^old_rr/ {o=strtonum("0x"$1)} $3=="canary" {c=strtonum("0x"$1)} END{print c-o}')
gcc -O0 -g -std=gnu99 -Wall -Wno-unused -I standin -DCANARY_GAP=$gap -c standin/harness.c -o plain/harness.o
gcc -o plain/harness plain/display_ipopt.o plain/harness.o
```

Each case runs as `asan/harness <attack|attack2|safe|safe-zero>` or
`plain/harness <attack|attack2|safe>`; stdout+stderr and rc are captured in
`evidence/<case>.out`. Final in-tree run: 12 PASS / 0 FAIL, rc 0. A clean
`git archive 7ec6a3bd lab/frontier/hping3shell | tar x -C /tmp/w212-hping`
replay also gave 12 PASS / 0 FAIL, rc 0.

## Observed results (exact values)

- `evidence/asan-attack.out`: `global-buffer-overflow`, `WRITE of size 68`,
  `display_ipopt standin/display_ipopt.c:112`, 0 bytes after `old_rr` (size
  40), rc 1. `evidence/asan-attack2.out`: same with `WRITE of size 86`.
- `evidence/plain-attack.out`: `CANARY_GAP=64`; canary[0..3] =
  `4f 4d 49 53`. `evidence/plain-attack2.out`: canary[0..21] =
  `4f 4d 49 53 48 45 2d 4f 4f` ×2 + `4f 4d 49 53`. The `EXPECT:` line is
  computed independently from packet byte `22 + 64 + offset` and matches.
- `evidence/asan-safe.out`, `asan-safe-zero.out`, `fixed-asan-attack.out`:
  rc 0, no sanitizer error. `evidence/plain-safe.out`: canary all zero.
- `nm -n plain/harness`: `old_rrlen.1` at `0x4040`, `old_rr.0` at `0x4060`,
  `canary` at `0x40a0` (64-byte gap from the overflowed `old_rr.0`).

## Known limits and preserved negatives

- First harness revision failed: `patch -q` is unsupported by this `patch`;
  the local hunk initially had a wrong line count (7 vs 8 context lines),
  and compiling from `pinned/` selected the full upstream header. All three
  were repaired in `run.sh` and `pinned/fix.patch`; the failures are kept
  here rather than erased.
- An early `gap` computation matched `$3=="old_rr"` but the linker emits
  `old_rr.0`, yielding a tautological canary comparison; the check now uses
  `^old_rr` and requires a non-zero packet-derived byte in the canary.
- Stand-in constants/struct, no hping build, no pcap/raw socket, no wire,
  no live hping process, no pointer/IP/command control, no allocator
  metadata claim and no rung 5. ASan redzones poison the adjacent canary,
  so chosen bytes are observed only in the plain build.
- Stock glibc behavior of an overflow in `.bss` stays UNKNOWN; the plain
  harness continues because the chosen canary is a benign array, not an
  active control-flow object.
- The advisory's `AV:N` precondition (`-G`/`--rroute`, matching packet) was
  exercised on loopback in W1 (below); no external system was probed.

## W1 wire stage (2026-11-24 20:3xZ)

`wire/run-wire.sh` is the replayable script; `wire/wire-test.sh` starts a real
`hping3 -D -1 -G -I lo -c 3 -i 1 127.0.0.2` under `sudo -n` (PID is written
by a wrapper shell before `exec`) and `wire/inject_rr.py` sends the crafted
reply from 127.0.0.2 to 127.0.0.1 through an IP_HDRINCL raw socket. The tree
is copied from `provision/hping-src` (HEAD `3547c769`), configured
`./configure --no-tcl`, built with
`make CCOPT='-O0 -g -fsanitize=address -fcommon -Wall -Wno-unused -I../compat'`.
Two build repairs were needed and are kept here: Linux has no `net/bpf.h`
(empty `wire/compat/net/bpf.h` stub; its only use is `#if`-guarded off), and
GCC's `-fno-common` default breaks 2014 tentative definitions in the headers
(`-fcommon` restores the intended linkage). No pinned source was hand-edited.

Input details: IPv4 IHL=15 (60-byte header), RR option `07 ff 48` (type,
length 255, pointer 0x48) plus `OMIS` padding to 40 option bytes, ICMP echo
reply type 0 with 64 bytes of `OMIS` payload. The echo id is packed in host
byte order (x86 little-endian) because hping assigns `getpid() & 0xffff`
without `htons`; a network-order id does not match and produces no abort.

Observed: `WRITE of size 68` at `wire/hping-src/display_ipopt.c:112`, 0 bytes
after `old_rr` (size 40), rc 1; pointer `0x5a` gives `WRITE of size 86` at the
same frame; repeat deterministic; valid RR (length 39, pointer 8) and the
same attack against the patched real build exit 0 with no ASan error and
print the injected RR. Kernel emits ICMP parameter-problem for the malformed
option, but pcap still delivers the original packet to the process.
`sh run-wire.sh`: 9 PASS / 0 FAIL rc 0, repeated from a clean lab copy.

Preserved negatives: AF_PACKET injection on `lo` produced no frames captured
by tcpdump; IP_HDRINCL works. Checksum replacement in the first injector
dropped the ICMP id and produced id 0, which hping ignored. ASan redzones
poison the bytes adjacent to `old_rr` in the real binary, so chosen-byte
control remains observable only in the plain stand-in harness. No pointer,
IP or command control and no r5; witness replay of this stage is UNKNOWN.
