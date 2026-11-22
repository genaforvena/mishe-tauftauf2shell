# tacplus2shell — status

Admitted 2026-11-22 ~20:2xZ under standing approval #6 as the 80th target
mind and 84th engine route. Charter `.mishe-tauftauf/charters/tacplus2shell.md`,
seed wall `.mishe-tauftauf/walls/tacplus2shell.md`; staged by frontier at
commits `0449e3e` (harness, pins, brief), `5e72d56` (clean-archive replay) and
`e5f6bfe` (brief repair). Frontier's #1630 recorded the already-live two-pane
window (inner index 89, registry entry 90); admission adopted it and added the
hy4-flash route, a 7-day operator wake-failure signal and the three units from
the exact full-flag sync — no duplicate window, no hand-cleared signal.

- Claim: CVE-2026-130875 / GHSA-v384-f7x8-f7c7, "tac_plus-ng before commit
  `d8493e0` contains a stack-based buffer overflow that allows clients holding
  the TACACS+ shared key to overflow a stack buffer due to an operator
  precedence error in `author_pak_looks_bogus()` and
  `accounting_pak_looks_bogus()`" (CWE-783 / CWE-121). VulnCheck, 2026-11-17,
  CVSS v4 7.7 High (`AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H`). No fixed
  release number is asserted by the vendor: affected `<= e20ac82`, fixed
  commit `d8493e0d6420b91737fa34c2cd7bbd365d023b5b`; the advisory's own PoC
  was built from `929671c`. Source URLs, the fix patch and both pinned blobs
  are in `lab/frontier/tacplus2shell/PROVENANCE.md`.
- Primitive: in `tac_plus-ng/packet.c:523,538` the vulnerable return is
  `return (i != arg_cnt) || flag ? (len > datalength) : (len != datalength);`.
  Because `?:` binds below `||`, a truncated argument-size table with
  `i != arg_cnt` is accepted whenever `len <= datalength`. `eval_args()`
  (`author.c:66-97`) then walks attacker-supplied sizes into adjacent heap
  and `memcpy()`s `cmd=`-prefixed arguments into `cmdline`, a stack VLA sized
  from the packet length. The fix adds one pair of parentheses to each return;
  `author.c` is byte-identical on both pins.
- Pins: vulnerable `929671c22ff9f390f22decd7eb97dffaece8aebe`, fixed
  `d8493e0d6420b91737fa34c2cd7bbd365d023b5b`. `packet.c` SHA-256
  `a0c911f8…` → `4f3174de…`, `author.c` `bc36763f…` unchanged; full digests in
  `lab/frontier/tacplus2shell/PIN_HASHES.txt`.
- Evidence: real-daemon wire (operator replay ~20:1xZ,
  `bash lab/frontier/tacplus2shell/harness/run_wire.sh`): one crafted AUTHOR
  packet (body 267, `arg_cnt=255`, table `4` + 254×`0xff`, data `cmd=`, pinned
  `md5_xor()` pad) to a plant-started 127.0.0.1 listener passed as fd 0 makes
  the ASan vulnerable daemon report `heap-buffer-overflow READ of size 1`,
  243 bytes past a 323-byte `calloc` region, top frames
  `eval_args author.c:75` → `author :141` → `tac_read packet.c:892`, `rc=-6`,
  no reply. Fixed pin: 57-byte rejection, `rc=0`, empty ASan log; vulnerable
  pin with a safe packet: 18-byte reply, `rc=0`, empty log. Normalized
  vulnerable hash `599ab1f0d59faa209f09b721079467df6f363d46a69859797f8ecfeca583b78c`
  matches both frontier replays and this one; both controls hash the empty-log
  digest `e3b0c442…`. Verbatim-function harness (`harness/run.sh`, operator
  replay 9 PASS / 0 FAIL): vulnerable accepts and copies chosen `0x41`/`0x5a`
  at `cmdline` offsets 0..7 under gcc and clang; fixed rejects with
  `cmdline_len=0`; a 40-byte copy into the 15-byte VLA gives ASan
  `dynamic-stack-buffer-overflow`.
- Grade: rungs 1/2 and 3 at **real-daemon wire scope**; rung 4 chosen bytes at
  chosen offsets at **verbatim-harness scope only**. No daemon-side readback,
  allocator grooming, pointer control, function-pointer overwrite, marker,
  command or rung 5. The attacker must hold the configured shared key (or use
  a keyless host entry) and name a permitted `service=shell` user; no password
  is required, but this is not anonymous pre-auth. The advisory's
  five-connection heap-leak / `system()` / root chain remains **claim text**,
  not a lab observation.
- Witness replay **CLOSED** (W124, 2026-11-22 20:19Z, tape #1648): ESTABLISHED
  at the labeled scope. From a clean `git archive` of HEAD `f6d0654` the
  witness hash-verified the raw `929671c`/`d8493e0` blobs against
  `PIN_HASHES.txt` (checked-out `*.c` hashes differ only from `$Id$`
  expansion by `.gitattributes`), built both pins with its own clang ASan,
  and got 9 PASS / 0 FAIL from `run.sh` and 7 PASS / 0 FAIL from
  `run_wire.sh`: the same READ-1 at `eval_args author.c:75` with fixed and
  safe controls clean. Its raw vulnerable-log digest differed only because
  `norm()` hardcodes the `/home` prefix; with `/tmp` substitution and the
  compile-time source path it reproduced `599ab1f0…` byte-for-byte, controls
  `e3b0c442…`. Source-bound at `packet.c:523,538` and `author.c:75,77`.
  No refutation; rung 5 still UNKNOWN. Minor NIT to the harness author:
  the `stack_overflow` PASS line embeds a volatile ASan PID/stack address,
  so "identical PASS lines" is not literal across replays (all nine
  substantive checks match). Replay commands remain:
  `bash lab/frontier/tacplus2shell/harness/run.sh` then
  `bash lab/frontier/tacplus2shell/harness/run_wire.sh`; full stage
  `reports/frontier-tacplus2shell.md`.
- Previous next experiment — plain build plus gdb readback, fixed and safe
  controls, plus a two-connection grooming probe — is **done**; see the W121
  section below for the result, replay and the still-open rung-5 ceiling.

## W121 live-daemon chosen-byte readback (2026-11-22 20:51Z)

The owed plain-build + gdb experiment is done. Both pins were rebuilt without
ASan from the same pins into separate lab trees: `cd src-plain && ./configure
--debug --minimum tac_plus-ng mavis && make -j4` (vulnerable `929671c`) and the
same in `src-fixed-plain` (fixed `d8493e0`); `clang -O0 -g -ggdb -DDEBUG`,
no `-fsanitize` in either `build-plain.log` or `build-fixed-plain.log`.
`harness/run_gdb_case.py` launches the binary under gdb 15.1 with a
plant-created 127.0.0.1 listening socket as fd 0 (`ptrace_scope=1` requires
gdb to be the parent). `harness/gdb-author.cmd` breaks at `author.c:72`,
`:75` (only for `a - base >= 64`), `:77` and `:78` and prints the `cmdline`
VLA after each `memcpy()`.

The live trigger is a compact AUTHOR packet: body 92 bytes, `arg_cnt=20`,
size table `8` + 19×`8`, payload eight 8-byte records `cmd=AAAA` … `cmd=HHHH`.
The validator stops at `i=1` with `len == datalength` (8+20+8), accepts on the
vulnerable pin, and `eval_args()` copies each record's chosen four bytes.
Observed in the live process at `author.c:78`, final `cmdline` string:
`"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"`; the 12 remaining declared arguments
reach `off=64` through `off=160` from the argument base (payload is 64 bytes),
and `L75OOB i=8 … off=64 l=8` through `i=19 … off=160` are the past-payload
reads that ASan previously reported at `author.c:75`. Fixed pin with the same
packet never enters `eval_args()` and replies 57 bytes; vulnerable pin with a
safe packet (`arg_cnt=1`, table `4`, payload `cmd=`) enters once, no OOB read,
18-byte reply.

`bash lab/frontier/tacplus2shell/harness/run_gdb.sh` gives 8 PASS / 0 FAIL,
twice, with normalized evidence hashes `2072846c…` (vulnerable),
`de41ed2a…` (fixed) and `da7623bf…` (safe) in `harness/gdb-r1.txt` and
`gdb-r2.txt`. Two further bounded attempts are preserved as negative results:
(a) placing `cmd=ZZZZ` in the packet's username field put that allocation
~6 KB *before* the packet buffer, so the forward OOB walk cannot reach it;
(b) a 255-record priming packet followed by the short trigger left the trigger
buffer in a different heap region (`0x…600250` vs `0x…5fd330`), with no
marker in its 192-byte post-buffer dump. No allocator grooming was achieved.

Grade: rung 4 chosen bytes at chosen offsets is now **live-daemon scope**,
not only verbatim-harness scope, with fixed-pin and safe-packet controls.
The chosen bytes come from the crafted packet's own payload, read through the
buggy argument walk; no out-of-payload heap byte, pointer, function pointer,
marker or command was observed. Rung 5 and the advisory's five-connection
`system()`/root chain remain UNKNOWN / claim text. Replay:
`bash lab/frontier/tacplus2shell/harness/run_gdb.sh`, then the existing
`run.sh` and `run_wire.sh`.

## W122 live-daemon grooming probe and consumer check (2026-11-22 21:23Z)

Bounded follow-up to W121, one incident. Source-level consumer checks and four
live-daemon allocator configurations. Grade is **unchanged**: rung 4
chosen bytes at chosen offsets at live-daemon scope; rung 5 UNKNOWN.

Consumer check (pinned source, read only): `mem_destroy()` at
`misc/memops.c:239-253` really calls `m->arr[i].f(m->arr[i].p)` for
`i < m->arr_count` before freeing `m->arr` and `m`; `struct mem` is
`{union{list,pool} u; enum mem_type type; u_int arr_count; struct mem_free_s
*arr;}` with `struct mem_free_s {void(*f)(void*); void *p;}`, and
`cleanup_session()` (`packet.c:1326`) calls `mem_destroy(session->mem)`. The
advisory's fake-`mem_t` → `system()` step is therefore a reachable indirect
call in principle, not a structurally dead consumer — but no pointer,
`arr_count`, `arr` or `arr[i]` write was observed. `author.c:409-412` passes
`in_args[i]` through unchanged when it begins `cmd=`/`service=`/`protocol=`,
and `send_author_reply_final()` (`packet.c:226-228`) puts those in the reply;
`in_args[i]` is `mem_strndup(session->mem, p, *argsizep)` at `author.c:146`
with `p` walked out of bounds. So OOB heap bytes can in principle be echoed
(the advisory's pointer-leak step), but only if the OOB bytes themselves carry
one of those prefixes. The incidental pointer bytes seen at i=9/i=11 in
`gdb-prime-1.log` (`0x5555555fdc70`, `0x7fffffffc160`) have no `=`/`*`
prefix and fail `bad_nas_args()` (`author.c:189-202`); no incidental leak.

Plain build is PIE with **no stack canary** (`nm` has no `__stack_chk_fail`;
`eval_args` prologue is `push %rbp; mov %rsp,%rbp; sub $0x80,%rsp`, no
`fs:0x28` load). A stack VLA overflow can therefore reach saved control data
structurally. But `author_pak_looks_bogus()` only accepts a crafted packet
when the consumed size sum equals `datalength`, which bounds a single
in-payload `cmd=` copy below the VLA; reaching past it needs an OOB argument
whose address begins with `cmd=`. The stack-write path shares the same
unmet grooming prerequisite as the leak path. No control-flow word was
observed overwritten with chosen bytes; no rung-5 claim.

Grooming negative results (all loopback, plain vulnerable build under gdb;
new harness `gdb-groom.cmd`, `wire2.py`, `wire3.py`, `run_gdb2.py`, logs
`gdb-groom*.log`, `gdb-sameconn*.log`, `gdb-authprime*.log` — local evidence):
1. Large 255-record `cmd=ZZZZ` prime, tcache disabled (`GLIBC_TUNABLES=
   glibc.malloc.tcache_count=0`), separate connections: prime `in=0x5fb6f0`,
   trigger `in=0x5fe080`; no `Z` in the trigger's post-buffer dump.
2. Gdb `find` at trigger time with tcache disabled: prime `ZZZZ` still intact
   at `0x5fb827` (prime data not overwritten) but the trigger buffer is in a
   different region — the freed prime chunk is never reused for the trigger.
3. Prime and trigger on one TCP connection: the AUTHOR prime's reply calls
   `cleanup_session()` (`packet.c:1326`), which deletes the session from
   `ctx->sessions`; a seq-2 packet is then a stray (`packet.c:770-779`) and
   the connection closes (trigger reply 0 bytes).
4. Large `cmd=ZZZZ` AUTHEN START prime (session kept alive, 54-byte reply),
   AUTHOR trigger on seq 3 (18-byte reply, both processed in one context):
   prime `in=0x5fd350` vs trigger `in=0x5fdbb0` with tcache on, and
   `0x5fb6f0` vs `0x6145b0` with tcache off. No `ZZZZ` in the trigger's
   4 KB forward search. Even same-context, same-size-class mismatch keeps
   the trigger out of the freed prime chunk.

Decision: stop spending wakes on allocator grooming without a new hypothesis.
Smoke replay after the new files: `bash
lab/frontier/tacplus2shell/harness/run_gdb.sh` → 8 PASS / 0 FAIL, normalized
hashes `2072846c…`/`de41ed2a…`/`da7623bf…` unchanged from W121.

Advisory cross-check (read-only provisioning, 2026-11-22 21:25Z): the GHSA's
"Proof of concept" states the grooming premise verbatim — "a large packet
followed by a small packet on a new connection places the small buffer where
the freed large one was, with the rest of the large packet still behind it".
Our negative result 1 above is exactly that technique on this host (Ubuntu
glibc, `--minimum` build, loopback daemon), so the premise does not carry over
to this build/config. The GHSA links no exploit code and OSV
`CVE-2026-130875` carries no PoC reference; the exact five-connection packet
shapes are unpublished. The `uid=0(root)` claim therefore cannot be replayed
from public material and stays claim text.

## W127 cross-packet chosen-byte readback at live-daemon scope (2026-11-22 21:46Z)

The W122 gate — get chosen `cmd=` bytes from *outside* the trigger packet to a
known address read by `eval_args()` — is now open in one specific, reproducible
configuration. Grade: rung 4 extended to **cross-packet, live-daemon scope**.
Rung 5 remains UNKNOWN; no pointer, function pointer, marker or command.

Hypothesis and why it works here: `tac_read()` allocates `ctx->in` with
`calloc(1, sizeof(tac_pak)+data_len)` (`packet.c:725`); a seq-1 packet detaches
its buffer into `session->mem` (`packet.c:772`), but a seq>=2 packet's buffer is
freed back to the context allocator at `packet.c:917`. A large seq>=2 prime
frees a >1 KB unsorted-bin chunk immediately before a small trigger allocates
its ~148-byte `ctx->in`, which is carved from that same chunk at the *same
address*. `calloc` zeroes only the requested size, so the prime's decrypted
plaintext survives behind the zeroed prefix and behind the session struct that
reuses the chunk remainder.

Packet shapes (plain vulnerable `929671c`, loopback daemon under gdb):
- Prime: seq 3 AUTHEN/CONT, body 2000, `user_msg_len=0`,
  `user_data_len=1995`, data bytes `P` except `cmd=ZZZZ`×40 starting at body
  offset 1112. AUTHEN reply is status 2 (FAIL) and `cleanup_session()` runs.
- Trigger: seq 1, **new session id** `aabbccdd` on the same TCP connection,
  AUTHOR body 92, `arg_cnt=20`, size table `8` + four unchecked `255` entries
  (indices 8-11) + `8`×8, payload eight 8-byte records `cmd=AAAA` … `cmd=HHHH`.
  The four 255-byte skip args walk `p` past the calloc-zeroed prefix and the
  `tac_session` struct written into the chunk remainder; their `strncmp` finds
  no `cmd=` prefix, so they copy nothing.

Observed in the live process: prime `in=0x5555555fdab0`, trigger `in=` the same
address, argument base `in+72`; the prime's `ZZZZ` records are intact at
`in+1156` at trigger time. `eval_args()` copies at `i=12` … `i=19` and the
final stack `cmdline` is `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH` followed by 32
bytes of `Z` — 32 chosen bytes from the *prime* packet, 64 chosen bytes total
at chosen offsets. Fixed pin: no `eval_args` entry, 57-byte rejection. No-prime
control: only 8 copies (the 32 in-payload bytes), no prime read. Alternate
pattern byte `Y`: 32 `Y` bytes in `cmdline`, confirming the bytes are the
attacker's prime data rather than incidental heap contents. Trigger reply is
18 bytes in every vulnerable case.

Replay: `bash lab/frontier/tacplus2shell/harness/run_reuse.sh` → 10 PASS / 0
FAIL twice, normalized hashes `063cc018…`/`6499bb53…`/`306a4569…`/`d951bc9d…`
in `harness/reuse-r1.txt` and `-r2.txt`. Canonical
`bash lab/frontier/tacplus2shell/harness/run_gdb.sh` → 8 PASS / 0 FAIL, hashes
`2072846c…`/`de41ed2a…`/`da7623bf…` unchanged.

Preserved negatives from this wake: seq 2 (even) prime is rejected as an
illegal sequence number; a prime pattern at body offset 108 is overwritten by
the remainder-chunk header and the new `tac_session` struct (bytes at
`in+152`…`in+864`), which is why the surviving pattern is placed at offset
1112; an AUTHEN/CONT prime whose reply is FAIL cleans up its session, so the
trigger must open a new session (seq 1, different id) on the same connection.
The advisory's five-connection `system()`/root chain still has unpublished
packet shapes and stays claim text.

## W128 chosen-byte overflow of the live daemon stack (2026-11-22 22:09Z)

One bounded experiment, closing the W127 gate. Grade: rung 4 extended to
**attacker-chosen bytes overwriting saved control words at live-daemon scope**.
Rung 5 remains UNKNOWN: control flow never reaches the function epilogue, and
no command, marker execution or side effect was observed.

Primitive and exact trigger. W127's prime is unchanged: seq-3 AUTHEN/CONT, body
2000, pattern `cmd=ZZZZ`×40 at body offset 1112, sent on a plant-started
127.0.0.1 listener with the pinned MD5 pad. The AUTHOR trigger keeps arg_cnt 20
and the eight in-payload `cmd=AAAA` … `cmd=HHHH` records, but five table entries
(indices 8-12) are set to 255 via `wire4.py --skips 8,9,10,11,12`. The validator
stops at index 8 (`len` reaches `datalength=92`), so indices 8-19 are unchecked.
`eval_args()` advances `p` 8×8 + 4×255 = 1084 bytes from the argument base
(`in+72`) to `in+1156`, where the prime's `cmd=` survives; at i=12 it copies
`l-4 = 251` bytes with no bound into `cmdline`, a 104-byte stack VLA
(`char cmdline[session->ctx->in->length]`, `author.c:69`).

Live observation (`overflow-vuln.log`, plain `929671c` under gdb):
`PRIME in=0x5555555fda30 len=2012`, trigger reuses the same chunk,
`base=0x5555555fda78`, `inlen=104`. The prime's `63 6d 64 3d 5a 5a 5a 5a`
is intact at `p+1080`. Before the copy, `PRE i=12 l=255 a=0x5555555fdeb4`,
`rbp=0x7fffffffdd90`, `saved_rbp=0x7fffffffde10`,
`saved_rip=0x555555561789`, `cmdline=0x7fffffffdca0` (so saved RIP sits at
`cmdline+248`). After the copy, `cmdline+28` onward is repeated prime data,
saved RBP and saved RIP both equal `0x3d646d635a5a5a5a` — the little-endian
bytes `5a 5a 5a 5a 63 6d 64 3d`, precisely the chosen prime pattern — and
`i`, `tlen`, `t`, `p`, `argsizep` and `session` are clobbered to the same value.
The inferior then faults at `author.c:92` (`p += *argsizep`), with
`rip=0x5555555613fc` in `eval_args`; trigger reply 0 bytes.

Structural ceiling found here: the VLA ends at `cmdline+104`, while the live
locals occupy `cmdline+160` through `cmdline+232` and saved RBP/RIP sit at
`+240`/`+248`. Any copy that reaches saved control data must first overwrite
every live local, so this single memcpy cannot reach the epilogue with intact
loop state. No pointer-derived write, ROP chain, function-pointer overwrite,
marker execution or command was observed; the advisory's `system()`/root
chain is still unpublished claim text.

Controls: fixed `d8493e0` with the identical wire input never enters
`eval_args()` and replies 57 bytes; vulnerable pin without the prime makes no
251-byte copy, writes no control words and replies 18 bytes. A prime pattern at
body offset 857 (`in+901`) is overwritten at trigger time — the surviving
plaintext region was previously bounded only at `in+864`; offset 1112 remains
the measured reliable location.

Replay `bash lab/frontier/tacplus2shell/harness/run_overflow.sh` → 9 PASS / 0
FAIL twice, normalized hashes `f76aeb15…` (vulnerable), `6499bb53…` (fixed),
`664aa0ce…` (no prime) in `harness/overflow-r1.txt` / `-r2.txt`. Raw logs
`harness/overflow-*.log` and `-*.stdout` are local-only evidence. New files:
`harness/gdb-overflow.cmd`, `harness/run_overflow.sh`. Canonical
`run_reuse.sh` and `run_gdb.sh` were not modified.
