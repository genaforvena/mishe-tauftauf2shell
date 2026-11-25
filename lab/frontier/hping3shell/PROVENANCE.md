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
poison the bytes adjacent to `old_rr` in the ASan binary; W2 below obtained
chosen bytes in the adjacent global from a plain build of the same pinned
tree. No pointer, IP or command control and no r5; witness replay of both
wire stages is UNKNOWN.

## W2 plain-build chosen-byte proof (2026-11-24 20:5xZ)

`wire/plain-proof.sh` copies the same read-only pinned tree to
`wire/plain-src` and builds it without ASan using
`./configure --no-tcl` and
`make CCOPT='-O0 -g -fcommon -Wall -Wno-unused -I../compat'`. It launches a
real `hping3 -D -1 -G -I lo -c 20 -i 1 127.0.0.2` under `sudo -n` and
`wire/inject_rr_plain.py` sends ICMP echo replies from 127.0.0.2 to
127.0.0.1 through an IP_HDRINCL raw socket. The crafted RR option has type
7, length 255, pointer 0xff, 36 unique bytes `0xa0…0xbb` and a pad; the ICMP
payload has 64 unique bytes `0x01…0x40`. `i = 255-4 = 251`, so the copy
spans `old_rr[0..250]`.

`nm -n -S wire/plain-src/hping3` gives `old_rr.0@0x29dc0` (0x28 bytes) and
the adjacent real global `rc4_sbox@0x29e00` (0x100 bytes), `old_rr+0x40`;
two other `rc4_sbox` copies exist at `0x29f20` and later from other objects.
The script reads the PIE base from the first offset-zero mapping in
`/proc/$pid/maps`, dumps 120 bytes at `old_rr` with `gdb -batch -p`, and
`wire/check_plain.py` asserts the offsets. GDB itself labels the dumped line
at `old_rr+64` as `<rc4_sbox>` in the live process.

Observed (repeated runs): attack 4 PASS / 0 FAIL — `old_rr[46..109]` equals
the unique payload bytes `0x01…0x40` and `rc4_sbox[0..45]` equals payload
bytes 18..63 (`0x13…0x40`); `NO_INJECT=1` baseline 3 PASS / 0 FAIL with
`rc4_sbox[0..45]` all zero. Raw output:
`wire/evidence/plain-{attack,baseline}-{gdb,proof,run}.out` and
`wire/evidence/plain-layout.txt`.

Preserved negatives: GDB cannot resolve the static `old_rr` by name here
(`No symbol "old_rr"`), so the dump uses the runtime PIE base plus the link
address from `nm`. `old_rr[0..45]` are subsequently rewritten by
kernel-generated parameter-problem RR replies with `i<=11`, so the shallow
offsets are not asserted; only the deeper bytes that persist are claimed.
The 251-byte copy reaches `rc4_sbox[0..185]`, but only the first 46 bytes
carry our unique marker. No pointer or command control, no r5; the behavior
change from the overwritten sbox is now measured in W5 below; witness replay
OWED.

Patched-build control: `wire/plain-fixed-proof.sh` applies `pinned/fix.patch`
to a copy of `plain-src` (patched sha256
`70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7`),
rebuilds and repeats the same three crafted RR replies. `check_plain.py`
baseline mode gave 3 PASS / 0 FAIL with `rc4_sbox[0..45]` all zero, tying
the chosen bytes in the unpatched build to the unclamped `memcpy`. Raw output:
`wire/evidence/plain-fixed-{gdb,proof,run}.out`.

## W5 — live RNG behavior change (2026-11-24 23:56Z)

`wire/rng-proof.sh` runs the same pinned plain build with
`hping3 -D -1 -G --rand-dest -I lo -c 16 -i 1 127.0.0.x`: every probe stays
in 127.0.0.0/24, local address 127.0.0.1, so the crafted RR reply passes the
`waitpacket.c:94` destination check. `wire/check_rng.py` reads GDB logs taken
at `select_next_random_dest()` entry (read-only: `i.1`, `j.0`, 256 bytes of
`random.c`'s `rc4_sbox`) and predicts the next probe destination from the
live RC4 state. Four `hp_rand()` calls occur per packet; the low byte of the
destination is the first call's output.

- Baseline (`NO_INJECT=1`) 4 PASS / 0 FAIL: 15 states / 16 destinations, all
  predicted, no RR marker in `sbox[0..45]`.
- Attack 6 PASS / 0 FAIL: 12 states / 13 destinations, all predicted; state 4
  carries `sbox[0..45]=0x13…0x40`; observed `127.0.0.79` equals the
  prediction from the overwritten sbox while the unattacked counterfactual
  from the prior state is `127.0.0.179`.
- Raw evidence: `wire/evidence/rng-{attack,baseline}-{gdb,run,proof}.out`.
- Negative preserved: the earlier `--rand-source` variant never delivered a
  crafted reply because `local.sin_addr` was randomized; no marker was seen
  and the checker reported `NO_TAINT`. No pointer, attacker-chosen IP
  without hidden-state observation, command or r5; author-side only.

Clean-archive replay from committed `35891e22` (`git archive 35891e22
lab/frontier/hping3shell` plus the gitignored `provision/` copy) rebuilt
`plain-src` itself and gave 4 PASS / 0 FAIL baseline and 6 PASS / 0 FAIL
attack, rc 0. Observed `127.0.0.251` vs counterfactual `127.0.0.226` there:
the concrete byte varies with `/dev/urandom` seeding, the causal difference
does not. No pinned source edited; all probes stayed in 127/8 on `lo`.

## W6 — chosen RNG output byte (2026-11-25 00:49Z)

New gitignored lab scripts: `wire/inject_rr_const.py` (205-byte ICMP payload:
bytes 0..17 unique marker, bytes 18..204 one chosen constant),
`wire/rngctl-proof.sh` (real plain build, `--rand-dest 127.0.0.x` on `lo`,
read-only GDB state dump, optional `BIN`/`EXPECT`/`RUN_TAG`), and
`wire/check_rngctl.py` (reuses `check_rng.py` parsing and RC4 step). No pinned
source was edited; all traffic stayed in 127/8 on `lo`.

- FILL=0x20: 6 PASS / 0 FAIL, rc 0, state 4 has `sbox[0..186]` at `0x20`,
  16/16 post-attack destinations `127.0.0.32`, counterfactual `127.0.0.70`.
- FILL=0x40: 6 PASS / 0 FAIL, rc 0, 16/16 destinations `127.0.0.64`,
  counterfactual `127.0.0.132`.
- Baseline `NO_INJECT=1`: 4 PASS / 0 FAIL. Patched binary
  (`plain-fixed-src/hping3`, patched source sha256
  `70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7`):
  4 PASS / 0 FAIL, no filled state.
- Raw output: `wire/evidence/rngctl-{attack-baseline,attack-32,attack-64,
  fixed-32}-{gdb,run,proof}.out`. The GDB log is evidence only; a stdout-only
  count shows the same 16-byte trailing run of the chosen fill.
- Clean-archive replay from `git archive HEAD` plus the gitignored
  `provision/` tree and the three new scripts: plain/patched source hashes
  exact, 4/6/6/4 PASS, rc 0, `CLEAN_REPLAY_W6_OK`. First attempt failed
  because `/tmp/w6-hping-clean` did not exist for `tar x`; `mkdir -p` fixed
  it. Two earlier injector assertion failures (28- and 32-byte RR markers)
  sent no frame; checker FAILed correctly; 36-byte marker fixed it.
- Negative: GCC 13 default `-fno-common` cannot link the pinned tree
  (`hping2.h:360` `delaytable` tentative definition in every TU);
  `wire/nocommon-negative.txt` keeps the failure. `-fcommon` is mandatory.
- Ceiling: low byte only; 69 sbox bytes beyond reach, i/j hidden, no pointer,
  command or r5. Author-side; witness replay OWED.
- One-command replay: `wire/replay-rngctl.sh` builds both trees from
  `HPING_SRC` and runs baseline/fill32/fill64/fixed with exact pass-count
  asserts (`REPLAY_RNGCTL_OK: 20 checks`). From clean `git archive bac9ab25`
  plus the gitignored `provision/` copy, expect `STAGE OK baseline 4`,
  `fill32 6`, `fill64 6`, `fixed 4`, rc 0.
