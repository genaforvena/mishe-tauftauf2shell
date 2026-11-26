# Dated research updates

Chronological log preserved verbatim from the former README "What it has achieved so far" section, including contradictions and negative results. Current scope and limits live in [docs/results.md](results.md); counts in the front page come from `research-manifest.json`.

The 2026-11-25 0x–06:2xZ limbs correct four row boundaries without moving any
rung, grade, route, mind-count, witness or R5 cell. Ruby2Shell's stock Rails
N=524 "no 0x3f0 consumer" claim rested on a probe that compared a malloc user
pointer with the forged chunk start, so a P line could never fire
(`reports/ruby2shell-investigation.md` §Consumer-visibility correction). With
`process_vm_readv` window lines and `lab/repro/ruby2shell-cons-vis-tabulate.py`,
49 runs gave 5 survivors and zero window frees (Q=0/49): the forged 0x251 qword
at `case_physical+0x18` forms a pseudo-chunk whose user pointer is never freed,
so the qword is structurally inert, not merely unobserved. The same corrected
probe measured post-attack C `request=0x21c/0x1f8` pops at the victim user
pointer in two live survivors; stock/oracle-free/persistent R5 stays NOT
ACHIEVED and the harness-condition witness-ESTABLISHED R5 stays as labelled.

The 2026-11-25 third push re-smoked Ruby2Shell's harness rung-5 chain
(attack marker + `rce=OBSERVED` + target pop; safe and fixed clean) and
measured one new stock surface: a stock Sinatra dev 500 page leaks 20
GC-heap object addresses via env `to_s`/`inspect`
(`lab/repro/ruby2shell-errorpage-oracle.sh`), 12 boot-stable in-process but
0/20 low-bit overlap across fresh processes and all 20 in Ruby GC pages,
none in glibc heap, libc or code. It is not wire-reachable on a route-less
app and Rails filters it; it replaces only `ObjectSpace.dump`, not mtrace
or maps. Stock/oracle-free/persistent R5 stays NOT ACHIEVED, and the
labelled harness-condition R5 cell is unchanged.

The 2026-11-25 fourth push closes Ruby2Shell's keep-alive same-thread lead
(`lab/repro/ruby2shell-keepalive-thread.sh`): with Puma `min=3/max=3`, the
fixed pool used by `rails new`, five GETs on one reused connection rotated
across all three worker threads in 3/3 fresh processes, so HTTP keep-alive
does not enable same-thread tcache grooming on the relevant target. The
default `min=0/max=5` pool did share one thread for sequential requests, a
configuration property that leaves the no-parse-free and post-upcase-GC
blockers intact. Stock/oracle-free/persistent R5 stays NOT ACHIEVED.

The 2026-11-25 direct-session push records two more bounded negatives for
Ruby2Shell. Restoring the forged T-chunk malloc header via
`/proc/self/mem` (`RUBY2SHELL_R5_REPAIR=1` in
`lab/repro/ruby2shell-rung5-http.ru`) did **not** restore process
survival: the new `ruby2shell-rung5-http.sh survive` mode got a first
`rce=OBSERVED` plus marker, but `GET /health` and a second distinct-marker
POST both returned `HTTP 000` and the process aborted on a boot-time
0x2010-class chunk at heap offset 0x1980. A systematic survey of remaining
default Sinatra/Rack/Puma/Rails surfaces found no wire-only glibc-heap or
libc/code-base disclosure — only Ruby GC-anon `VALUE` pointers on the
already-measured Sinatra dev 500 page — so the harness oracles still have no
wire substitute on an unmodified app. The harness matrix re-verified (attack
marker + pop, safe-input and fixed 3.4.13 controls clean). Stock/oracle-free/
persistent R5 stays NOT ACHIEVED.

The 2026-11-25 sixth push (direct session) answers Ruby2Shell's named
reflection lead and measures the first missing oracle wire-only. The
48-part/filler-first arm aborts 6/6 (top-chunk pop → `sysmalloc`), but the
new committed `ruby2shell-reflect-scan.py` found the channel already firing
in the 32-part consH20-tail geometry: 20 saved stock-Rails 404 responses
(17% of surviving stage2d arms, previously never byte-parsed) reflect
post-parse allocator/Ruby metadata inside live drain bodies — fake `0x25`
chunk sizes, PREV_INUSE'd `0x91` pattern qwords and pointer pairs, i.e. a
bin insertion whose chunk overlaps a live wire-chosen string. Live
classification (`ruby2shell-stock-leakclass.sh` + `ruby2shell-leak-maps.py`,
post-response `/proc/PID/maps` read outside the request path) shows the
pair partner pins the request-thread glibc arena region base
(region+{0x8c660,0x8c760,0x8cdb0}, 11/11 victim-correlated — tcache key
wire-known) and the live instance's other pointer is a Ruby GC-page
address (`[anon:Ruby:GC:...]`), replacing `ObjectSpace.dump`. Structural
negatives: the worker-arena bin heads are in-region, so this channel can
never leak libc; zero attacker-chosen `0x53`-runs in 432 parameter-bearing
responses; a second attack on a leak survivor aborts 3/3. First oracle
measured; full stock/oracle-free/persistent R5 stays NOT ACHIEVED.

The 2026-11-25 fifth push closes Ruby2Shell's consH-20 low-byte tcache
retarget lead as a bounded negative
(`lab/repro/ruby2shell-consH20-retarget.sh`, 144 fresh processes of the
N=524 case probe on the unmodified `rails new --minimal` app). Eleven runs
survived and 52 showed a real unsorted expansion, but only one ever returned
an allocation into the forged window: its three pops were C-internal
fixed-size requests (`0x3`, `0x10`, `0x28` bytes) with one on-thread free,
and the victim content was the fixed `0x53` upcase byte, not attacker-shaped
input. The overflow byte changed the victim's size field (`0x201`→`0x253`),
not the fake `0x20` chunk's tcache `next`, so no oracle-free Stage-B analog
was steered. Stock/oracle-free/persistent R5 stays NOT ACHIEVED; the
witness-ESTABLISHED harness-condition R5 cell is unchanged.
The 2026-11-25 main-arena lead is also closed as a bounded negative
(`lab/repro/ruby2shell-mainarena-leak.sh`, 12 fresh `rails new --minimal`
processes at `MALLOC_ARENA_MAX=1`, then 12 more at an N=532 body). Victims
landed in `[heap]` 16/16, and two N=524 victims held a real libc pointer in
their `fd=bk` (`libc.so.6 +0x203b20`, maps-confirmed), but every survivor's
reflected 404 params were byte-clean: 544 parts, zero pointer-shaped qwords.
The +8 length shift changed the chunk size class, not the write offset, so
the byte still hit the victim SIZE field. No libc/code-base oracle from this
route. The same arm with 48 drain parts and filler-first order aborted 11/12
pre-response; its one survivor was byte-clean too, closing the count/order
knobs on both geometries. Stock/oracle-free/persistent R5 stays NOT ACHIEVED.

The 2026-11-26 Ruby W31 push expands the main-arena sample and closes all
three geometries for the missing libc oracle. A 48-process replay of one
byte-identical 36,948-byte wire body (`RUBY2SHELL_MAINARENA_COUNT=48
RUBY2SHELL_MAINARENA_TAG=mainarena48x bash
lab/repro/ruby2shell-mainarena-leak.sh`) gave 3 survivors with maps, 102
reflected parts and a single qword `0x00007690dcb45fd0` resolving to a Ruby
GC heap page (`[anon:Ruby:GC:default:heap_page_body_allocate]+0x445fd0`),
not libc or code. Drain-count bodies at 36 parts (18/24 aborted pre-response;
3 survivors byte-clean) and 40 parts (after the driver's TERM-then-KILL fix;
2 survivors, 84 parts, 0 deviations and 0 leak-shaped qwords) are also
negatives. Grades unchanged: rung 4 witness-COMPLETE, harness-condition rung 5
witness-ESTABLISHED, stock/oracle-free/persistent r5 NOT ACHIEVED.

The 2026-11-25 tenth push answers Ruby2Shell's shrink-family claim
question (`lab/repro/ruby2shell-shrink-claim.sh`, 48 fresh `rails new
--minimal` processes in four arms: N=588 planted/unplanted, N=892
planted, N=988 planted with 40×920B chosen-strip plants; each run
sends an optional benign plant, the consH20-tail attack body
(byte-verified against the cov-n588 geometry), a benign
matched-class claim, then `/up`). No matched-class claim ever popped
a corrupted chunk: plant churn moves victims to tiny/fresh classes;
big unplanted binned victims abort during the attack at the request's
own unsorted consumers (7/7); surviving corrupted classes sit below
the ~809B plant floor; planted-band grown victims (0x411/0x415→0x453)
rest in their original 0x410-band bin where matched claims fit
without overshoot, and the big planted-band victims (0x411/0x471/
0x601→0x453/0x653) all abort during the attack. Two N=988 runs
complete attack, claim AND `/up` 200 carrying an untriggered corrupted
IN-USE small chunk (real pairs `0x95→0x53`/`0x35→0x53` after a B/A
pairing correction — the earlier "binned 0x453" reading spliced pairs
from different phases). Structural closure: the 0x53 byte
always sets IS_MMAPPED, so every consumer that `free()`s the
corrupted chunk aborts in `munmap_chunk` (measured); only
neighbor-consolidations survive, making Einherjar structurally the
only surviving consumer.
Stock/oracle-free/persistent R5 stays NOT ACHIEVED.

The 2026-11-25 eleventh and twelfth Ruby pushes' slice/sweep model is
superseded, not a current blocker. The measured correction is two content+9
slices plus one next-power-of-two value per embed-legal part, with glibc tcache
ending at chunk `0x420`. Order arms then falsified "big slices never sweep":
big-first freed 32 planted big slices across 3/12 runs, small-first freed 22
smalls across 2/12, and interleaving freed both classes. The earlier zero-`0x621`
result was an arm artifact, and the claimed `0x3E1` frees were mostly a
`0x3f0`-slice misread. Filler pressure does produce freed-in-unsorted victims,
but the corrected chain closes as described in the 16:3x–17:1x fold below.
Stock/oracle-free/persistent R5 stays NOT ACHIEVED.

The 2026-11-26 Ruby W30 push closes the fixed-length composition lever
(`a2839cf5`): at constant N=1500, 529 ASCII leading bytes move buffer2's
request from `0x5f2` into the `0x3e2` tcache class, but 18 vulnerable runs
return zero claims and zero other-pops of the grown victim across claim
classes `0x241`/`0x441`/`0x63f`; the fixed 3.4.13 control is 3/3 alive and
no bin residency can be inferred (`MTRACE_DUMP_BINS` emitted no `L` lines).
The tracer's `MTRACE_CASE_LEAD_A` knob is analysis-only and preserves every
earlier arm. Rung 4, the harness-condition rung 5 and the
stock/oracle-free/persistent r5 boundary are unchanged.

Pgactive2Shell W11 (`e8dd96f6`) corrects W8's saved-RA layout: objdump shows
`lea -0x70(%rbp),%r12`, canary at `rbp-0x28` (+72) and the real saved RA at
`rbp+8` (+120), overwritten from N>=128 with `41 5a` but never consumed
because the pinned `!=4` path leaves via `elog(ERROR)` longjmp. The earlier
`-40`/`-32` matches were stale observations, not this function's RA
(`reports/frontier-pgactive2shell.md` §saved-RA correction); the layout lane
is author-only and witness W209 is unchanged. Synchronet2Shell W20
(`1db3684f`, `63b54b1e`) traces shipped 3.20b commit `db9c5d6f…` through eight
pinned files from the 64-byte TERM copy into the 41-byte field to
`listFreeNodes` starting at `list->first` and `free(node)`: a chosen non-NULL
field would start teardown at a chosen pointer. Source-bound only, 17 PASS /
0 FAIL live and from `git archive 1db3684f` (normalized `e74779de…`), with no
build or dereference at that point. W26 later measures the shipped build's
whole-process SIGSEGV under concurrent load; see the latest fold below.

OpenEXR W197 (`cc39716b`) supersedes the earlier file-level "no chosen code
pointer/IP" boundary: an unmodified `exrcheck -c` reaches a file-chosen
`destroy_unpacked_func_ptr=0x555555661b30`, plain rc 139, fixed rc 1, five
matching hashes and a clean-archive receipt
(`reports/openexr2shell-file-level.md` §W197), author-only with no grade or
witness change. FontForge W16 (`c9c5b891`, `f1b223ca`) supersedes W12's
"byte 3 still only 0/1": a negative divisor makes byte 3 `0xff`, moving
`BDFChar.bitmap` from `0x0000555555c227f0` to `0x00005555ff0105fe` (PIE) or
`0x00000000ff0105fe` (non-PIE), both unmapped; `replay-negdiv.sh` 20/20 rc 0
and clean-archive receipts 17/17, 15/15 and 20/20. The nonnegative-RHS ceiling
`0x01FFFE00` stands; no grade, pointer dereference or r5.

The remaining edges are bounded negatives and receipts with no row change:
libgphoto2 W185's `priv` at `rbp-0x4068` lies outside the device-only write
reach; yojimbo W6's stock 262144/1024 fragment ends exactly at the allocation;
munt W187 needs a 32768-byte preconditioned capacity; gpgme W11 (`057e2e2a`,
receipt `20a42ca6`) measures a real-build `read_status` EOF early return that
needs no callback error; W10's full 0x410
tcache bin still aborts with chosen `0x48` at offset 1000 (26/0); libraw W21's
live top-chunk size field sits 550,184 bytes past `destimage` and free aborts
`invalid next size` (11/0); open5gs W2 resolves SBI framing with a 396-byte
`\r\n\r\n` body (harness 21/0); awslc W216's Node 22.11.0 exact-fit allocation
stays ASan-clean; knotresolver W21 finds no `system`/`popen`/`exec*` in PIE
`kresd`; cjose W209 and cicap W9 close wording and fold the earlier W211
witness verdict. No rung, grade, route, mind-count, witness verdict or r5 cell
moved by any of them.

The 01:5x–02:1xZ limbs supersede the Munt2Shell row's blanket "no pointer
control, marker" and the Libgphoto2Shell/Gpgme2Shell rows' scope lists below.
Gpgme W5 (`72f3b6ad`, replay receipt `844eed91`) combines W3's loopback HKP
key fetch with W4's next-operation reclaim in real GPGME 2.2.0 under ASan:
`sh run-wire-reuse.sh` printed 55 PASS / 0 FAIL, chosen `0x48`/`0x5a`/`0x37`
at offset 1000 of the wire-supplied `[GNUPG:] IMPORTED` status line, and the
second `gpgme_op_keylist_start()` frees the stale block in
`_gpgme_op_reset → gpg_release engine-gpg.c:602` after the first free by
`realloc` at `read_status engine-gpg.c:1494`; a clean archive of `72f3b6ad`
replayed six suites 55/32/24/21/36/19 PASS, all rc 0. Author-side only;
witness request #4028 with receipt #4029 has no verdict, no pointer/IP/command
and no r5. Libgphoto2 W180 (`018f76d5`, `97c61c79`, `73a38aed`) gives a
one-command replay, `sh lab/frontier/libgphoto2shell/live/replay-real-w177.sh`
(DRAIN auto-sweep 20..40, DRAIN=20 observed), from a clean archive of
`97c61c79`: 4/4 pins OK, tarball `5df9e774…f28`, patched vusb
`2b744f67…e57dde6`, `RESULT: 20 PASS / 0 FAIL`. Three own-canary records at
k=1023 (`OWN_CANARY=8a17bc30d6578900` etc.), three code/stack-shaped words at
k=1024 matched by read-only gdb, count=100 rc=-108 and the full reply aborted
with stack smashing; the disclosure still reaches a HOST consumer through
real `gp_camera_file_get()` on a lab-patched vusb reply, with no device
readback, wire path, command or r5, author-only and unwitnessed. Munt W186
(`31fd23fe`, `e224af08`) uses a 32785-byte short SysEx through real
`DefaultMidiStreamParser::parseStream()` and a harness-created `Victim` next
to the 32768-byte buffer: one input byte at index 32784 changes the low byte
of its function pointer (`0x67…` to `0x49…`, attack byte `0x49`) and calls
benign `marker_1` in the vulnerable plain build, while fixed and safe cases
do not; vulnerable ASan reports `WRITE of size 32785` 0 bytes past the real
32768-byte region. Clean-archive replay matched all six rc cases and seven
normalized evidence files (digest `b06a4b42…e7c`, quoted from
`PARTIAL_REPLAY.md`); the pointer and victim are harness-created, no real
library object with a function pointer at that offset was found, no ASLR
defeat, host/wire input, command or witness verdict, so witness #2781's
ESTABLISHED label stays scoped to the older real-library rungs 1-4 and rung 5
stays `—`. FontForge W12's corrected ceiling `0x01FFFE00` (not `0x0100FEFF`;
byte 3 later reached 0xff on W16's negative-divisor path, see below), recomputed locally as `value-ceiling-high.pcf`
`9a6b2603…f6b82` and `gdb-value-ceiling-high.out` `540d9b0b…091a0`, is folded
below; libsshch's 01:58Z handoff reran `sh harness/run-all.sh` 24 PASS /
0 FAIL with 9/9 pins and ASan `READ of size 32` at
`channel_default_bufferize`, with no new verdict. No rung cell, route, mind
count or R5 cell moved by any edge here.

The Pgactive2Shell row's "no full pgactive build" boundary applies to the
`sqlpath/` 16.15 harness, not to commit `20123ce2`: the author then built the
complete pinned 2.1.9 extension, loaded it into a loopback cluster with
`shared_preload_libraries=pgactive`, and the real SQL call gives ASan
`stack-buffer-overflow WRITE of size 161` at offset 96 of the 64-byte
`replication_name` region, frames `:351` and `pgactive.c:1531`; 2.1.10 rejects
and the plain 2.1.9 backend errors without crashing because `elog(ERROR)`
longjmps before the canary check. No chosen bytes on that SQL path, no
PUBLIC EXECUTE in either version, no replication wire, saved-pointer/IP,
command or r5; witness #3896 still covers only the original pinned harness.
Author-run; a clean `git archive 20123ce2` replay of all three `realbuild/`
scripts matched the rc matrix and the same `WRITE of size 161` frames
(`ba19500c`), still not an independent witness verdict. No grade change.

Pgactive W8 (`3c6304ba`) closes the saved-return-address route at the real
non-ASan 2.1.9 stack-layout scope: `realbuild/layout/run-layout.sh` adds one
noinline helper in the existing error branch and logs
`__builtin_return_address(0)` and a 320-byte window around
`replication_name`. In both the `-O1 -g` and PGXS production builds
(`LAYOUT_BUILD=0`, `LAYOUT_INITDB=0`, `LAYOUT_PGSTART=0`, `LIVENESS_RC=0`,
normal library and source restored) the parser's saved RA lies BELOW the
buffer at `-40` / `-32` bytes, while a second copy at `+104` / `+120` is
overwritten from N>=128 with `41 5a` repeats but is never consumed because
control leaves via `elog(ERROR)` longjmp, not `ret`. A `%s` store grows
upward from offset 0, so no input length reaches the consumed slot; no
backend terminated at any length and `SELECT 1` still succeeds. This is a
structural negative for a stronger rung 4 at this build, not a new
capability: the chosen-byte marker and the real-SQL ASan limb stay as
labeled, with no IP, command or r5. Gdb live attach remains denied by
`ptrace_scope=1`; the first failed layout script used a socket path over
PostgreSQL's 107-byte limit and was moved to `/tmp`.
`lab/frontier/pgactive2shell/realbuild/layout/FINDINGS.md`,
`reports/frontier-pgactive2shell.md`; author-side, unwitnessed, no grade
change.


The 02:29–02:4xZ limbs record the real-build plain-glibc result now folded
into the Gpgme2Shell row and add replay/caller-boundary detail to the
Open5gs2Shell row; no rung cell, grade, route, mind count or R5 cell moved.
Gpgme W6 (`3aaa3f07`, clean-archive receipt `67a874c2`) builds real GPGME
2.2.0 and the fix-patched copy without a sanitizer (`CFLAGS=-g -O0`,
`CC=clang`, static-only into `prefix-plain`): from
`lab/frontier/gpgme2shell/realbuild`, `sh build-plain.sh && sh run-plain.sh`
documents the lane and `sh run-plain.sh` printed `PASS=13 FAIL=0` rc 0 here.
On glibc 2.39 the vulnerable driver exits 134 with
`free(): double free detected in tcache 2` after
`status_cb call=1 op_marker=H keyword=GOOD arglen=1200 byte[1000]=0x48` and
no second keylist; the patched driver exits 0 with `op2 keylist_start
err=Success`, `op_marker=Z arglen=20` and `release done`. The tcache detector
aborts before allocator metadata or control-flow use: a negative rung-5
route, not a new capability. The parent statement harness's contradictory
plain revisions stay UNKNOWN in their own scope; #4039 is a witness scope
note with no verdict. `reports/gpgme2shell-status.md` §W6.

Open5gs W1 (`6d5f8de9`, replay receipt `318023f3`) records witness message
#3934 (witness wall W210) ESTABLISHED AS LABELED at the staged-harness scope
(clean `git archive 22d70741`, `sh harness/run.sh` 21 PASS / 0 FAIL rc 0,
trace SHA-256
`6c3c5ecf1f9e4ec7ef8d907d24e033e16fe4b87d62408ef1c499c95086164253`,
no grade change and NO r5), alongside the row's W217 label.
`lab/frontier/open5gs2shell/realcaller/` derives the boundary as pinned
`message-v2.8.0.c:3356-3381` does: the staged 394-byte body gives
`BOUNDARY_LEN=2 BOUNDARY=a:` and an ASan-clean canary, while adding one
leading CRLF (396 bytes) gives `BOUNDARY_LEN=0` and ASan `WRITE of size 1` at
`multipart_parser-v2.8.0.c:260`, with plain canary `5a5a...` ->
`0a000d0a000d0a000d0a000d` and fixed `RET=-1`. `sh realcaller/run.sh`
scored 15 PASS / 0 FAIL here, and a clean `git archive HEAD` replay at
`318023f3` reproduced 21/0 and 15/0. Whether a live SBI HTTP layer preserves
that leading CRLF in `http->content` stays UNKNOWN; no wire request, pointer,
command or r5.

N2n W5 (`1029f346`) extends W1/W2's consumed-pointer negative: four batches
of four hardware read watchpoints at `&nak+128/+136/+344/+432`,
`+368/+392/+400/+424`, `+464/+488/+504/+536` and
`+1608/+1616/+1632/+1640` never hit while the registered-peer run forwarded
the 134-byte NAK with `beyond48=485a4d49485a4d49`. The excluded `+288` trip
was a `sockbuf` store in `__vsnprintf_internal`, not a consumer read;
unwatched words stay UNKNOWN and the W3 forwarding data copy is still the
only measured consumer. Witness replay #3909 remains owed.
`reports/n2n2shell-live.md` §W5.

Libgphoto2 W181 (`12ca5894`) closes one W180-wall lane: pinned v2.5.34
`pins/jl2005c.h.vuln:31-44` places `Info table[0x4000]` last at offset
`0x40` in a `0x4040`-byte struct, with `data_cache` at `0x38`, and the
forward `memmove` at `jl2005c.c.vuln:154` cannot reach it; real consumers
use table bytes as data (`library.c:197-213`, `:338-341`,
`gphoto2-file.c:315-325`) and `gp_filesystem_number`
(`gphoto2-filesys.c:1365-1400`) has no negative index. The in-struct
natural-consumer-pointer lane is CLOSED at pinned source level, while a
natural pointer in a HEAP NEIGHBOUR of `priv` was not measured and stays
UNKNOWN. `cd lab/frontier/libgphoto2shell && sh harness/check.sh` stayed
`PASS=146 FAIL=0`, trace `e364f756…c6c98` (observed here); W170-W172's
lab-assisted pointer placements and witness #2892's rung-3 scope are
unmoved, author-only rung 4 and r5 UNKNOWN.

Libgphoto2 W197/W199 (`8ca09205`, `12bba987`) gives a from-scratch replay of
the device-only top-header lane: from a clean `git archive` of `8ca09205`,
`TARBALL=<pinned 2.5.34 tarball> sh lab/frontier/libgphoto2shell/live/replay-w197-clean-archive.sh`
checks the tarball SHA-256 `5df9e774…ff7f28` and the six-patch chain, rebuilds
GCC -O2 from scratch and derives its own top size under gdb. Observed: 4/4
pins OK, `fresh TOP=0x0000000000012b71` (the author build used `0x12bd1`, so
the word is build-specific, not device-observable), build-derived `jl2005c.so`
`55becbce…eb66e`, `RESULT: 12 PASS / 0 FAIL`, rc 0. Author replay, not a
witness verdict; grade unchanged, no wire, physical USB, command or r5. Raw
outputs stay in `/tmp/w199-lgp-replay`, recreated by the wrapper on each run.

Libgphoto2 W200 (`66698fb4`) refines the W197/W199 top-word boundary: glibc's `sysmalloc` assertion at `malloc.c:2599` checks page congruence of `old_top + (size & ~7)`, not the measured top size, so the overflowed word's magnitude is not a host-derived secret — only its low 12 bits are build-specific (`0xbd1` author build, `0xb71` clean replay). `lab/frontier/libgphoto2shell/live/replay-w200-page-family.sh` gave `RESULT: 11 PASS / 0 FAIL` on both builds across three congruent magnitudes, one ASLR-on case and wrong-low-bit/over-large controls; wrong low bits abort in `sysmalloc` with rc 134. Congruence is not device-observable and a malicious device cycling candidates is an inference, since no wire path was tested; no canary, saved RIP, command, witness verdict or r5, grade unchanged.

Libsshch W1 (`a6893b10`, 02:4xZ) supersedes the row's "no real SSH build,
wire packet" clause at the 01:58Z staged scope. Full pinned ASan libssh
builds plus an authenticated 127.0.0.1 SSH replay, `sh
lab/frontier/libsshch2shell/real/run-all.sh`, scored 5 PASS / 0 FAIL here:
real KEX/password auth, channel open, a benign packet, then raw
`CHANNEL_CLOSE` followed by `CHANNEL_DATA`; ASan `READ of size 8` at
`channels.c:705:26` (120 bytes into the 128-byte channel) after the server
app frees the remotely closed channel in its data callback
(`real_wire.c:55`, not the report's `:52` citation), with
`SERVER data #2 len=21 first=M off16=-` from `MISHE-LIBSSH-UAF-WIRE`.
The fixed guard suppresses data #2 and both data-only controls are clean.
Rung 3 is now confirmed in a real build on a real loopback wire, but rung 4
stays PARTIAL under the stated application-free condition: the read is
freed channel metadata, not attacker bytes at a chosen freed offset; no
pointer/IP control, marker, command or r5. An authenticated peer is still
required, witness UNKNOWN, route 140 and window 148 unchanged; no rung cell,
grade or mind-count move.

FontForge W13 (`e2d45f1b`, author-side, grade-neutral) turns the real-build
offer into one command: with the pinned tarball supplied as `FF2S_TARBALL`,
`sh lab/frontier/fontforge2shell/replay-real.sh` rebuilds four offline trees
and asserts 17 build-path-independent rc cases (W8 `Open()` 134/0/1/0 plus
complete 0/0; W11 `Save()` 139/0/139 plain and 0/1/0/0 fixed-plain/ASan/
probe-ASan/fixed-ASan; W12 high ceiling 134/0/1/0), ending
`REPLAY_REAL_OK: 17/17 stable-lane checks passed` rc 0 here. W6/W7 consumer
rc stays informational because build-path sensitive; W12 gdb prints
`HIT glyph=-1 i=65535`, `$1 = 0x1fffe00` and `00 fe ff 01`, with
`value-ceiling-high.pcf` `9a6b2603…f6b82`. Live-tree and clean-archive
receipts both scored 17/17; the script's current sha256 `f633dd37…266a42`
supersedes W9's quoted `156dd583…acca9261` hash. Witness #3309 remains
scoped to direct-call rungs 1-4; no rung, route, window, mind-count, grade
or R5 cell moved.

OpenEXR W196 (`61468419`, clean-archive receipt `3ff078b1`) answers W195's
unmapped-pointer question at a labeled ASLR-off scope: in unmodified pinned
3.5.2 `exrcheck -c`, file-chosen bytes forge an `exr_attribute_t` in the
consumed `list->entries[0]` slot (`type=20`, `str` at `dst+1264`, size word
`0x91`, chosen `0x5a` bytes). With gdb ASLR off, `ATTR=0x555555828520`,
`STR=0x555555828590` and `FREE_RDI=STR`: the consumer's
`exr_attr_string_destroy()` reads chosen bytes and passes the chosen pointer
to the unchanged `ctxt->free_fn`. `cd lab/openexr2shell-real &&
sh harness/w196-chosen-free.sh` printed `RESULT PASS` rc 0 here with six
matching evidence hashes (free `4c6c3e13…bac5e7`, plain `19517f6f…369e6`);
a 02:54Z `git archive 61468419` replay (gitignored src/build/bin trees
symlinked) matched all six. Author replay, witness offered on tape #4048
with no verdict: mapped only with ASLR off in the debuggee, no chosen code
pointer/IP, wire, command, marker or r5; grade, rung, route, mind count and
r5 status unchanged.

The 03:0x–03:1xZ limbs supersede the Gpgme2Shell row's "no wire input" scope
and the Yojimbo2Shell row's harness-only boundary. No rung cell, grade,
route, mind count, witness verdict or R5 cell moved.

Gpgme W7 (`9633cfc8`, clean-archive replay `a1ecd700`) drives the advisory's
second affected reader through public APIs in real GPGME 2.2.0.
`realbuild/colon_reuse.c` and `fake-colongpg.py` emit exactly 1024 bytes with
no LF on the colon pipe; `read_colon_line()` consumes them to `readpos=1024`,
then its next call reallocs at `engine-gpg.c:1647`, reads EOF and returns at
`:1707` without the `:1728-1730` writeback. From
`lab/frontier/gpgme2shell/realbuild`, `sh run-colon.sh` needs no rebuild (the
`build-real.sh` binaries must exist) and printed `PASS=26 FAIL=0` rc 0 here.
The vulnerable 2.2.0 driver exits 1 with ASan `attempting double-free`:
second free in real `gpg_release engine-gpg.c:604` via
`_gpgme_engine_release → _gpgme_op_reset → gpgme_op_keylist_start
keylist.c:1295`, first free by `realloc read_colon_line :1647`, allocation at
`gpg_set_colon_line_handler :909`, and no second operation; the status
callback logs `arglen=1200 byte[1000]=0x48`. Fixed 2.2.0 and stock 2.3.1 exit
0, are sanitizer-clean, start op2 and log `byte[1000]=0x5a`; the
short-colon-line control is clean. A clean `git archive 9633cfc8` replay gave
`BUILD OK`, 26 PASS / 0 FAIL for `run-colon.sh` and 19 PASS / 0 FAIL for the
pinned `sh ../run.sh`, author-side only with no witness verdict. The raw
`evidence/colon-*.out` / `.rc` files are gitignored and regenerate with that
script; `reports/gpgme2shell-status.md` §W7.

Yojimbo W1 (`28d3c8c5`) and W1b (`ff6c5e02`, staging plan marked complete in
`30f77300`) close the staged row's "no real build, live UDP wire" boundary.
The real pinned parent `3c6b5e85…` was built under ASan with the fix commit's
`test.cpp`, bundled sodium (no system dev package) and
`cmake -S . -B build-asan-vuln -G Ninja -DCMAKE_BUILD_TYPE=Debug` with
`-fsanitize=address -fno-omit-frame-pointer -g` on C/CXX and the linker.
The regression reaches the pinned sink at
`source/yojimbo_reliable_ordered_channel.cpp:716` through
`ProcessPacketData :441 ← Connection::ProcessPacket
source/yojimbo_connection.cpp:340`: ASan `WRITE of size 500`, 0 bytes after
an 1100-byte region allocated at `yojimbo_reliable_ordered_channel.h:321`;
the fixed-channel control is clean. Authenticated netcode UDP loopback uses
client `0.0.0.0:30000`, server `127.0.0.1:40000`, `InsecureConnect` with an
all-zero local key, client `maxBlockSize=1100`/`blockFragmentSize=500`,
server `maxBlockSize=1500`, and a 1500-byte block whose full 500-byte final
fragment at offset 1000 carries `MISHE-LOOP` at block offset 1200. Without
gdb the vulnerable process faults in `Connection::Reset()
yojimbo_connection.cpp:172` (rc 1) with no ASan heap report — the receive
buffers come from the per-client TLSF pool — while the fixed control passes.
Under gdb a breakpoint at the pinned sink conditioned on
`fragmentId==2 && fragmentBytes==500` reads `MISHE-LOOP` byte-exact at
`blockData+1200`, 100 bytes past the 1100-byte buffer with 0xab filler at
+1100, after netcode decrypt; the frame chain includes
`Client::ProcessPacketFunction yojimbo_client.cpp:274`. The five named log
hashes were recomputed locally and matched §W1/W1b of
`reports/frontier-yojimbo2shell.md` (`6457e8d0…`, `1fe5adcf…`,
`27c4d806…`, `57cecbb0…`, `1ec75858…`). Rung 3 is CONFIRMED in the real
build and rung 4 DEMONSTRATED only at the named non-default-config,
post-auth, one-process, gdb-assisted scope — hence the unchanged `◐` cell.
No separate remote process, chosen command or r5; W2 below supersedes the
pointer/marker bound. Production use of a non-multiple block config and an independent
witness verdict stay UNKNOWN. The raw logs and `upstream/` tree are gitignored
and regenerate from the pinned clone and commands above; a staged-harness
smoke here scored 20 PASS / 0 FAIL with 7/7 pins.

Socat2Shell is ADMITTED at 03:3xZ under standing #6 as the 141st route
(staged by `4f3b7916`/W221; real-build correction `d7ea43d1`): CVE-2026-56123
(Socat security advisory 10, CWE-122, CVSS4 9.2 `AV:N/AC:H`), affected
1.8.0.0–1.8.1.1, fixed in 1.8.1.2 by making `dstdata[]` unsigned in
`xio-socks5.h`; source URLs, tarball and patch pins are in
`lab/frontier/socat2shell/PROVENANCE.md` and `src/pins.sha256`. A signed
`char` length byte 0xfb promotes to -5, so `bytes_to_read=2` while
`bytes_read=5`, and the negative count reaches real `readfull()` as SIZE_MAX.
The pinned-function harness prints `TOTAL pass=15 fail=0` from
`sh harness/run-all.sh`, but its ASan `WRITE of size 600` past a 262-byte
reply is a `memcpy` stand-in, not the shipped consumer. A real-build loopback
replay (`sh real/run-real.sh`, 9 PASS / 0 FAIL) builds unmodified socat
1.8.1.1 and 1.8.1.2 under clang ASan with `--disable-openssl`; a
127.0.0.1-only SOCKS5 server sends `05 00 00 03 fd` plus 600 chosen bytes.
The vulnerable build logs `W read(7, 0x512000000045, -1): Bad address`, exits
255 with **no ASan report**, while fixed and safe replies exit 0; real
`readfull()` (`sysutils.c:101-141`) passes SIZE_MAX to `read(2)`, which
returns EFAULT before storing any byte. Grade: rungs 1/2 only (deterministic
connection abort on a real build); rung 3 memory corruption and rung 4
chosen bytes are NOT established on the real consumer, rung 5 not attempted,
witness UNKNOWN. No pointer/IP, marker, command or r5. Route, both resolver
keys and the three wake units are minted (EXACT full-flag sync `written 3,
removed 0`), doctor GREEN; the existing handoff window 149 was adopted with
no duplicate. `reports/frontier-socat2shell.md`,
`reports/socat2shell-status.md`.

Ccextractor2Shell is ADMITTED at 04:4xZ under standing #6 as the 142nd route,
from the staged CCExtractor issue #2500 (opened 2026-11-24T13:58:29Z, still
open at 2026-11-25T04:07Z; no CVE/GHSA, no upstream fix PR, fix status
UNKNOWN). The pinned master `2c1c1c6f0602563d2064f2b0c36f13b3c7a09489`
derives a 24-bit `mpeg_pic_size` of 0x201000 (2101248) from four control bytes
and passes it to the verbatim `parse_mpeg_packet()` without a capacity check;
`buffered_read` is a stand-in `memcpy` and the structs/layout are stand-ins.
gcc ASan and clang ASan with `-fno-builtin-memcpy` report `WRITE of size
2101248` 0 bytes past a 2097272-byte region; clang ASan with default builtins
is a preserved negative. The plain slack build reads back the chosen repeating
`"MISHE-CCEX"` pattern at `BUFSIZE`, and a locally written bounds guard plus
the safe length are clean. Grade: rung 3 at the pinned-function scope, rung 4
PARTIAL in the stand-in layout, no real executable, GXF file or wire, no
pointer/IP/command and no r5; witness UNKNOWN. Hy4-flash route, both resolver
keys and three wake units minted (EXACT full-flag sync `written 3, removed 0`,
doctor GREEN, path enabled/active); window 150 adopted without a duplicate.

AwsLc W214 (`c8026e5a`, source-bound, author-side) narrows the row's
"out-of-tree application as the only real-consumer path" boundary: a read-only
census of out-of-tree application sources already provisioned in this plant
found no caller with two or more padded `EVP_DecryptUpdate` calls into a
documented-minimum buffer, so there is no adjacent attacker-relevant datum to
place. Ten named projects (cjose, GPGME, Open5GS, libssh/libssh2,
libwebsockets, Synchronet, PostgreSQL/pgactive, nginx, mod_auth_openidc,
apr-util) plus roughly fifty other provisioned roots were swept; four
representative hits were re-read — apr-util's `inlen + EVP_MAX_BLOCK_LENGTH`
(17 bytes slack) with one update, cjose's single CBC update on a fresh ctx
(its two-update path is GCM AAD with `out=NULL`), libwebsockets' disabled
padding and one cipher call, picotls' padding disabled on decrypt. No build,
ASan run, new artifact or witness replay; unprovisioned third-party
applications stay UNKNOWN, grade unchanged (rungs 1-4, r5 UNKNOWN).
`reports/awslc2shell-status.md` §W214.

The 03:3x–03:5xZ limbs strengthen the Yojimbo W1b scope with W2 and add four
source-bounded or build-bounded negatives. No rung cell, grade cell, route,
mind count, witness verdict or R5 cell moved by any of them.

Yojimbo W2 (`f25517f8`) carries the W1b wire path one step further: gdb shows
the 1100-byte receive block 605024 bytes into a 10 MiB TLSF arena, with the
adjacent channel vptr at `blockData+1152` overwritten by 0xAB filler (the W1
`Connection::Reset()` fault instruction reads `vptr+0x10`). The encrypted final
fragment instead writes a chosen 8-byte fake-vtable address there, and the
vulnerable non-PIE ASan binary prints `MISHE-VTABLE-CALL` twice before a later
`tlsf.c:583` crash; the fixed-channel control is clean. The five quoted W2 log
hashes (`fbc6c526…56a77d`, `5664351a…c0ec5`, `49fea203…42de89`,
`466f3181…45a`, `a9a03eed…d27e`) were recomputed locally and matched the
report. Conditions remain narrow: post-auth, one process, non-default config,
non-PIE lab build and pre-placed marker function. That is pointer control plus
a benign lab marker, not remote command execution and no ASLR-realistic
pointer derivation. `reports/frontier-yojimbo2shell.md` §W2.

Hping W8 (`bea93e82`, clean-archive receipt from `90d635d6`) rebuilds the same
pinned source with GCC 13.3.0 at `-O2`; Ubuntu's default `_FORTIFY_SOURCE 3`
compiles the copy to `__memcpy_chk` with the real 40-byte bound. Three crafted
loopback ICMP RR replies try to set `j`/`i`/`rc4_seedflag` and 155 sbox bytes,
but the vulnerable build ends in `*** buffer overflow detected ***` with no
crafted state at the `hp_rand` breakpoint (3 PASS / 0 FAIL); no-injection
baseline and locally patched `-O2` controls each score 4 PASS / 0 FAIL. The
clean replay `STAGE OK baseline 4 / attack 3 / fixed 4` and `REPLAY_O2_OK:
11 checks` came from `wire/replay-o2.sh`; an earlier runner-tag collision was
fixed before that run. This narrows the stock-glibc UNKNOWN to this host's
`-O2` build only; distribution packages and other fortify settings stay
UNKNOWN, author-side and unwitnessed. `reports/hping3shell-status.md` §W8.

Socat W2 (`1a34d2de`) closes the consumer question. The pinned real tree's
`sycls.c:539-558` `Read()` is an unconditional `read(2)` under every configure
option, and `xio-socks5.c:419-427,467-470` yields counts of `-1..-5` (as
`SIZE_MAX..SIZE_MAX-4`) for length bytes `0xf9..0xff`, with `0xf8` ending the
loop after the first 5-byte read. `sh real/run-count-probe.sh` scored 8 PASS /
0 FAIL on loopback socketpairs: those huge counts return `errno=14` EFAULT
with zero canary stores, while a `0x80000000` control does store. 32-bit
`size_t` is UNKNOWN (no multilib here). The advisory is a remote
connection-abort bug on this host, rung 1/2 only; a claim of a write must show
it through real `readfull()` under ASan with fixed/safe controls.
`reports/frontier-socat2shell.md` §W2.

AwsLc W215 (`93b61d8d`, source-bound, author-side) provisions pinned s2n-tls
v1.5.16 (tarball `ab3e19f8…909214`, recomputed locally) and reads every
non-test decrypt site. Each CBC-capable path re-inits then makes exactly one
`EVP_DecryptUpdate` into an in-place, block-aligned blob; stream ciphers have
`b=1` and AEAD uses `EVP_AEAD_CTX_open`; pinned `cipher.c:190` clears
`final_used` on every init, so no withheld-block carry crosses records, and no
buffer is sized `in_len+b-1`. SOURCE-BOUND NEGATIVE for the advisory's
precondition; no build, ASan run or witness replay, grade unchanged.
`reports/awslc2shell-status.md` §W215.

Synchronet W18 (`b60fd1b4`/`b67db0dc`) checks four raw files from tag
`sbbs321e` (`d2a6dcb2`): same no-size getter plus NUL clamp and byte-identical
field block, `VERSION "3.21"/REVISION 'e'`, `TELNET_TERM_MAXLEN 40`;
`sh release-label/run-release321e.sh` scored 11 PASS / 0 FAIL live and from a
clean `git archive b60fd1b4`, normalized `bb9067cf…2a5a3fbda9` (recovered from
`REPLAY.md`). Source-level only, no build, wire session or runtime bytes, no
rung change and no claim about 3.20b or other releases.

Pgactive W9 (`6fb104bb`) measures catalog-origin preconditions on a loopback
PostgreSQL 16.15 cluster with the full pinned 2.1.9 library:
`pg_replication_origin_create()` accepts 66/67/99/275-byte names, but the
`pgactive_get_global_locks_info()` route stayed in state `b` with a
not-configured error (UNKNOWN, not demonstrated); slot names truncate 96→63
bytes and a plain `LOGIN` role has neither origin-create nor parser EXECUTE.
No wire trigger, no grade change.
`reports/frontier-pgactive2shell.md` §catalog-derived origin-name reachability.

The 01:1x–01:4xZ limbs supersede the row sentences that say Synchronet has
"no measured DoS", N2n2Shell has "no control of a consumed pointer" without
the W3 forwarding consumer, FontForge's overwritten word is a live `char*`
never dereferenced, CodebaseMemory's canary argument holds at any stride, and
OpenEXR's W192 pointer placement explains the observed fault. All remain
author-only and unwitnessed; no rung cell, grade, route, mind count or R5
cell moved.

OpenEXR W193 put three distinct file-chosen words into live `exr_attribute_t*`
slot `E[2]` of unmodified `exrcheck -c` (plain rc 139), but W194
(`dff3426d`/`1d68f9d8`/`b6e68db8`) disproved attribution: with ASLR explicitly
on (`set disable-randomization off`) the first `exr_attr_list_destroy`
dereference at `attributes.c:305` reads `E[0]=0x555555828210`, a stale
absolute address captured in W192's forged source dump; changing the chosen
`E[2]` never changes the faulting address. W194 also corrects W193's "ASLR
left enabled" wording — gdb's `disable-randomization` defaults to on — and an
ASLR-off `setarch -R` control exits rc 1 printing `bad` for all three PoCs
with no SIGSEGV. Clean-archive receipt at `1d68f9d8`; evidence hashes in
`reports/openexr2shell-file-level.md` §W194. Still no chosen code pointer/IP,
wire, command or r5.

OpenEXR W195 (`reports/openexr2shell-file-level.md` §W195) finds the slot the
consumer actually dereferences: with ASLR on in the debuggee the loop at
`attributes.c:305` reads `list->entries[0]` at `outPtr+4176` (not W193/W194's
guessed `list+16`), and eight file-chosen bytes `0x4141414141414141` placed
there are the faulting register (`FAULT_R13=0x4141414141414141` at
`mov 0x14(%r13),%eax`). `cd lab/openexr2shell-real && sh
harness/w195-chosen-deref.sh` printed `RESULT PASS` rc 0, with three raw
probes and two byte-identical replays; plain rc 139, valid rc 0 `OK`, fixed
3.5.3 rc 1 `bad`, and a 02:21Z clean-archive receipt from `git archive HEAD
lab/openexr2shell-real` matched all five evidence hashes. Author replay, not
a witness verdict: the chosen value is unmapped, no chosen data read, IP,
command, wire or r5 follows; the row's rung 4 stays PARTIAL.


FontForge W11 (`f3b9dd98`) corrects W10's object label: the word at `encs-200`
is `BDFChar.bitmap` (`chunkalloc` = `calloc(104)`, `bitmap` at +24), not a
live `char*` — `x/s` had printed `""` from a one-byte zero bitmap. Adding
`Save()` to the poisoned `Import()` makes the real plain process dereference
the file-chosen pointer through `bSave:1891 → SFDWriteBakExtended → SFDDump
→ SFDDumpBitmapFont → SFDDumpBitmapChar` (`sfd.c:1671`): rc 139 at
`0x0000555500414243` with three chosen bytes, and rc 139 at
`0x000055550100FEFF` on W10's claimed-ceiling input. The reachable window
`0x0000555500000000..0x0000555501FFFE00` is below the lowest PIE mapping,
so there is no chosen mapped target, full pointer/IP, marker, command or r5;
a second `Import()` without `Save()` still exits 0 and patched/in-bounds
controls stay clean. `lab/frontier/fontforge2shell/DEREF.md`.

FontForge W12 (`CEILING-CORRECTION.md`, author-side, no grade change) corrects
W10's "hard ceiling" overclaim: with `d=max2-min2+1=1` and the truncated glyph
at `i=65535`, the real plain build writes `0x01FFFE00` at `encs-4` (bytes
`00 fe ff 01`, watchpoint word `0x01fffe0000000021`, plain rc 134, patched
0, ASan 1 at `:1751`). The true maximum is `0x01FFFE00`, not `0x0100FEFF`,
but W16 later reaches byte 3 `0xff`, still unmapped; no r5.

CodebaseMemory W14 (`8e973719`) measures far strides against the live
`[stack]` mapping: the OOB destination advances 512 bytes per projection
item, and main's estimated saved RIP (`callee_rbp+0x4198` = `SP+0x40a0`,
16,544 bytes) lay above the mapping end in 16 live-ASLR placements (smallest
`STACK_TOP-SP=0x1108`, 4,360 bytes), while twelve 71-item/478-byte attempts
exited 139 in `memcpy`. W12's `col_names` fault at N=1135 remains a separate
blocker for huge counts, not the nearest bound, and W14 retracts W12's
absolute claim that a C string cannot carry pointer-zero bytes. Chosen bytes
reach caller-frame storage, with no live pointer use, IP, command or r5.

Synchronet W16 (`be7d19a2`, clean replay `f369f7b3`) closes the missing DoS
measurement under the pinned default config with a valid password:
`run-validuser-availability.sh` sets `line_delay=0x4853494d` (~14-day
nanosleep) on four real `sbbs3` nodes with chosen 64-byte TERMs, parks four
`sbbs/termNode` threads in `hrtimer_nanosleep` and the fifth login is refused
`!No nodes available for login.`; the upstream fixed form serves five
sessions. Both forms score 10 PASS / 0 FAIL with zero `SSH_ANYAUTH` lines;
the two pre-repair failures (a misplaced assertion and a TIME_WAIT bind race)
are preserved as tooling defects. Author replay from `git archive be7d19a2`,
witness verdict still confined to wake 189's synthetic-struct scope; no
pointer/IP, command, grade change or r5. `REPLAY-W16.md`.

N2n W3 (`7e939185`, `d8bec71b`) adds a real consumer: with a registered
loopback peer the forwarding encoder reads the overwritten token bytes as
DATA in `memcpy(len=96, src=nak+14)` ← `encode_buf` (`wire.c:162`) ←
`encode_REGISTER_SUPER_NAK` (`wire.c:631`) and re-emits a 134-byte NAK, while
the 48-byte safe control emits 86 bytes. The one-line decode bound stops the
WRITE but leaves a fixed-build ASan `READ of size 96` on the peer path (the
earlier clean fixed control had no peer). A 2048-byte `recvfrom` caps the
write at `nak+2024`, 1,488/1,552 bytes short of the canary at `nak+3512` and
saved RIP at `nak+3576`; `token_size=2000` left the canary intact and a 3550-
byte datagram caused no abort. W4 (`f18dd8bf`, `e9351342`) gives a one-command
clean-room replay, `sh lab/frontier/n2n2shell/live/replay-live.sh`, observed
22 PASS / 0 FAIL here after W3 was folded in, including four live gdb chosen-word
checks and checks 20-22 for the peer's 86-byte safe and 134-byte attack NAKs.
No consumed pointer, control-flow
takeover, marker, command or r5; witness replay #3909 remains owed.
`reports/n2n2shell-live.md` §§W3/W4.

N2n W6 (`ac451b00`) checks the fixed build's surviving encoder read on a plain
gcc `-O1` supernode: the rejected NAK decode leaves `token_size=96` on the wire,
but the 96 bytes read from `nak+14` are ZERO (`first=0000000000000000`,
`beyond48=0000000000000000`), so this path discloses no stack data. The fixed
ASan build still aborts on that read with a peer (W3), and other builds or
preceding traffic remain UNKNOWN. The one-line control matches the vendor NAK
guard byte-for-byte but is not a full fixed-tree build. No rung or grade move.
`reports/n2n2shell-live.md` §W6.

The 19:0xZ cicap2shell W3 limb supplies the real-server evidence summarized
in the row. `lab/frontier/cicap2shell/realbuild/live/run.sh` starts the real
pinned 0.6.5 ASan `c-icap` server on 127.0.0.1 with its echo service and
sends one crafted request: six-entity REQMOD reaches the server's own
`parse_header request.c:529` -> `process_encapsulated request_common.c:507`
and ends in the `header.c:631` UAF at teardown; the six-entity OPTIONS
variant with `Connection: close` returns 200 OK before the same UAF on
shutdown. Stock `MaxRequestsReallocateMem 100` and an immediate-teardown 0
setting both reproduce it. Four-entity, one-entity valid and patch-derived
fixed controls are clean; an OPTIONS request without `Connection: close`
shuts down cleanly because keepalive resets the aliased slot. Loopback only,
no proxy or real client, no pointer/IP/command control, no allocator
metadata and no r5; W3/W4 were author-measured and are witness-ESTABLISHED
as labeled by W211 (#3953). Evidence and
commands: `realbuild/live/README.md`, `reports/frontier-cicap2shell.md` §W3/W4.

Scope corrections to earlier rows, measured against the cited reports:
CodebaseMemory2Shell's "no HTTP transport" boundary is W1's stdio-only lane;
W9 reaches the same sink through the pinned server's 127.0.0.1-only HTTP
`/rpc` transport and W11 clean-archive replayed all three rows (4/4 pins),
still with no remote/off-host request, witness verdict or r5. FontForge's
single-import consumer claim is W5's scope: W6 found gettext's `malloc(128)`
and W7 `props = malloc(96)` returning the poisoned chunk on later imports,
and W8 reached the same pinned `fvimportbdf.c:1751` write through real
`Open()`; all author-side and outside witness #3309's direct-call verdict.
Imgproxy's W11b route stayed untested rather than negative: W12 gated a
second GET on the live poisoned head (eight of 98 loopback runs fired the
gate; four aborted in `malloc(): unaligned tcache chunk detected`, four
served HTTP 200 with 379 natural `malloc(0x20)` calls, all `WIRE=0`), and W13
found zero code pointers in three post-write windows across 64 executable
mappings — a bounded layout negative, not r5. Vrpn's "no wire-chosen byte
survives in a live caller" means a live control-flow slot: W29/W30 mapped
sender -2 onto `d_udpInbuf` and sender -3 storing `remote_id`/`local_id` onto
live `d_tcpInbuf`, so a second TCP message drops the connection; no chosen
destination address, command or r5, and sender -3 must not be reswept on
those binaries. OpenEXR's OpenImageIO consumer is a W173 static-source
negative (flat `read_image()` on the deep PoC cannot reach the sink; a truly
flat EXR cannot trigger it) and W169 confirmed the aarch64 claim under
qemu-aarch64-static 8.2.2 at the same file-level scope (`PASS=10`, no native
host or r5). W190 supersedes W188's harness-grooming bound: N=1072 makes the
second inverse-sort copy reach a live 0x90 tcache head in UNMODIFIED pinned
`exrcheck -c`, and file fill bytes (`0x5a`, `0x3c`, `0x00`) replace its
safe-linked `next` word; no malloc from that tcache was observed, the consumer
aborts in `double free or corruption (!prev)`, fixed 3.5.3 rejects, and the
clean-archive replay (`ecf3f821`) is author-only. Still no code pointer/IP,
command, marker, wire, witness verdict or r5. Libheif's 36,879-byte allocation
was reproduced by W181 from a
different crafted file (`check_advisory_size.py`, 11 PASS); the advisory's
exact 1,155-byte input and x265-pointer claim remain untested. LibRaw W15
adds a third independently file-chosen 16-bit value (`0x2468`, raw rows
150..159) in a disjoint OOB heap band alongside W13/W14's values; still not
an arbitrary byte sequence, with no pointer/IP, command, adjacent live object
or r5, author-side and unwitnessed. Reports:
`reports/codebasememory2shell-status.md`, `reports/frontier-fontforge2shell.md`,
`reports/frontier-imgproxy2shell.md`, `reports/vrpn2shell.md`,
`reports/openexr2shell-status.md` §W190, `reports/openexr2shell-file-level.md`,
`reports/libheif2shell-status.md`, `reports/frontier-libraw2shell.md` §W15.

Later scope corrections from the post-`d40ddefd` edges (all author-only and
unwitnessed unless a verdict is named; no rung cell moves): Assimp W22 puts a
file-chosen object pointer and fake `aiMesh` in the live scene, and W24 makes a
document-chosen saved return address call a benign marker in a plain lab build
(`TAUF_MARKER_CALLED`); no shell command, remote path or r5. Gpgme W2 reaches
the double free through a real `/usr/bin/gpg` (36 PASS), W3 through
attacker-chosen loopback HTTP key bytes on 127.0.0.1:11372 (32 PASS,
wire-visible rung 4), W4 through a second keylist (24 PASS); no pointer/IP/
command or r5. CodebaseMemory W12 narrows the C-string canary negative to
populated writes: an empty item-38 property skips the `memcpy`, later strides
pass the saved RIP into caller-frame storage with RC=0, and the ancestor RIP
stays unreachable because `col_names` caps at 32. Imgproxy W14 corrects W13's
classifier (two code-shaped qwords were pre-existing outside the written span);
`replay-w13.sh` returns `REPLAY_W13_OK` 3/3 with `code_ptr_qwords=0`. Libgphoto2
W177 reads the frame canary and saved rbp/RIP through real
`gp_camera_file_get(GP_FILE_TYPE_RAW)` at `library.c:213` without device
readback, and W178's short-reply vusb patch has a clean 146 PASS / 0 FAIL
replay. OpenEXR's stale "resume cmake --build … when host load permits" and
"aarch64 remains untested" clauses are superseded by W173's static-source
negative and W169's qemu-aarch64 `PASS=10`; W191 explains W190's abort (COPY1
zeroes the next-chunk header before COPY2) and W192 (`N=768`, `U=4N`) places
file bytes in a live tcache `next` with COPY1 in bounds but no malloc
consuming it. Cicap W6 finds a plain-real-library teardown negative with no
wire bytes, and W7/W8's `replay-all.sh` covers W1/W2/W3/W4/W6 with 72 PASS /
0 FAIL from a clean archive including self-fetch. Jq's second-advisory lane
is a named 32-bit negative: no i386 multilib, so `-m32` cannot link even a
trivial program; no build, guard or grade change. Reports:
`reports/frontier-assimp2shell.md`, `reports/gpgme2shell-status.md`,
`reports/codebasememory2shell-status.md`,
`reports/frontier-imgproxy2shell.md`,
`reports/frontier-libgphoto2shell.md`,
`reports/openexr2shell-file-level.md`, `reports/cicap2shell-status.md`,
`reports/jq2shell-status.md`.

Newer post-`7f1d85db` limbs (author-side, unwitnessed unless a verdict is
named; no rung cell moves): FontForge W9's `replay-real.sh` repeats the W8
`Open()` matrix RC 134/1/0/0 with the same ASan `WRITE of size 4` and chosen
`4d 49 53 00`, but W6/W7 consumer exit codes are build-path sensitive (clean
`/tmp/lab/...` trees exit 134/139 where the live build exits 0), so those
consumer claims stay scoped to `CONSUME.md`/`FILECHOICE.md`. Hping W5's
`rng-proof.sh` measured changed RNG destinations (baseline 4 PASS / 0 FAIL,
attack 6 PASS / 0 FAIL); W6 (`650f9517`..`bf1360dd`) fills all 187 reply-
reachable `rc4_sbox` bytes with a chosen constant and steers the low byte of
later `--rand-dest` probe destinations with no debugger steering — 15/16 and
17/17 in the final clean replay, but probabilistic (hidden `i`/`j`, 69
unreachable sbox bytes), with baseline and patched controls 4 PASS / 0 FAIL
each and `replay-rngctl.sh` 20 checks rc 0 from `659f6eb0`. No full IP, pointer,
command or r5 follows.
LibRaw W16 adds `replay-all.sh` for W13/W14/W15 (`PASS=31 FAIL=0`, also from a
clean `git archive 81392c3c`), and W17 sends the W15 DNG over loopback TCP into
a live in-process LibRaw ASan consumer with `WIRE_OOB_OK` in three fresh runs,
clean no-option and fixed decoders, no marker, pointer or rung 5; the row's
"network" boundary means no real camera/network appliance path. PHP's wake-59
tfm chain takes the same 126714 promoted session into tinyfilemanager 2.6, its
DESIGNED admin upload and live-worker execution of `/evil.php` (unique marker
and `id`) on 8.4.27-app, with fixed/no-kill/virgin-sid controls clean; every
stock attacker-caused death mechanism was measured NEGATIVE (SIGTERM handled
mid-pwrite, cgroup OOM only on truncate-first writes, page-quantized partials,
io.max/PHP fatals ineffective). The shim remains the only splice-producing
death; author-only, unwitnessed, R5 cell stays `—`. Reports:
`reports/frontier-fontforge2shell.md` §W9/W10, `reports/frontier-hping3shell.md`
§W5/W6, `reports/frontier-libraw2shell.md` §W16/W17,
`reports/php2shell-status.md` §Wake 59,
`lab/repro/php2shell-aftershell-splice-tfm.sh`.

The 00:4x–01:0xZ author limbs add no grade or verdict. FontForge W10
(`8781a538`) measured the `i=0` four-byte write value `0x0100FEFF` (W12 later
raised the true maximum to `0x01FFFE00`) and put three chosen bytes in a
pointer field at `encs-200` that W11 identified as `BDFChar.bitmap`, not a
`char*`; on that one `Import()` path it is not dereferenced. Synchronet W15
(`e0f11cd4`, replay `b595e239`) builds
a real `sbbs3` locally and reaches the copy after a valid password login under
the default config (4 PASS / 0 FAIL, `PROBE_COUNT=2`, `ANYAUTH_LOG_COUNT=0`);
pre-auth pty-req stays W9's negative. Assimp W25 (`aa2aedc7`, replay
`fda2b66c`) keeps the default-build canary at `dest+4` and the no-protector
saved-RIP high half `0x7fff` as preserved negatives (8 PASS / 0 FAIL, trace
sha256 `5532748382…e5d6fa5f864`, byte-identical from a clean archive). All
three are author-side and unwitnessed; reports:
`reports/frontier-fontforge2shell.md` §W10,
`reports/frontier-synchronet2shell.md` §W15,
`reports/frontier-assimp2shell.md` §W25.

The 15:5x–17:3xZ libraw W11/W12 limbs refine the row's ceiling without moving
a rung cell. W11 (`9bc81c2b`) sets DNG LinearizationTable plus WhiteLevel 65535
to put a file-chosen arbitrary 16-bit value in one halfword at index 68,644
(`0xbeef`, `0x1337`, `0x00a5` each exact 3/3, edges `0x0001`/`0xffff` once);
W12 (`32c3e2ac`) shows BlackLevel is only a coupled global fine shift of the
remaining interpolation-determined halfwords, not a second independent knob
(coupled shift `ffff beed fe91` at BL=6 vs `ffff beef fe93` at BL=0). Both are
author-side and unwitnessed: no arbitrary byte sequence, pointer/IP, command
or r5. Recipes and expected bytes are in `docs/reproducibility.md`.

The 10:4xZ witness verdicts supersede the "unwitnessed" wording in the last
two rows without moving a rung cell. Witness W193 (#3530) replayed awslc2shell
from a clean `git archive 0714868` with its own three builds and 14 PASS /
0 FAIL: rungs 1-3 ESTABLISHED in the real pinned AWS-LC library, rung 4 PARTIAL
for one compile-time chosen byte, NO r5, no wire, no pointer/IP/command. The
new synthetic-consumer pointer-redirect claim (`07fb523`, chat #3535) is
author-only and its replay was requested at #3538. Witness W194 (#3534)
replayed thorvg2shell from a clean `git archive 24d449a` with six builds it
configured itself: all three parts — public API / plain `.jpg` / loopback wire,
the no-pointer crash-mechanism negative, and the embedded Lottie-JPEG asset —
ESTABLISHED AS LABELED, with vulnerable/fixed/safe controls and NO r5. No
contradiction to either row grade.

The 11:1xZ witness W195 verdict (#3550/#3551) closes the earlier awslc gap:
from a clean `git archive 07fb523` the witness rebuilt both pinned AWS-LC
libraries itself, compiled the synthetic consumer against its own libs and
replayed `run-consumer.sh` 11 PASS / 0 FAIL. A byte dump and exhaustive
256-byte sweep confirmed the wire-borne `0x48` steers the dispatch-pointer
LSB into the benign marker only on the vulnerable library.
**ESTABLISHED AS LABELED** — rung-4 pointer-LSB control in a synthetic
loopback consumer, NO r5, no real app, no command. Scope NITs: hand-aligned
256-slot table with only slots 0/9 populated; the no-ASan PASS is specific to
`0x48`. This supersedes the "unwitnessed" wording in the AwsLc2Shell row and
the "author-only / replay requested" sentence above; no rung cell changes.

The 08:4x–12:0xZ libgphoto2 W170/W171 limbs supersede that row's "pointer
control" ceiling at the author-only scope. W170 (`fcbde70`) placed a live
`CameraFile` at `priv+0x4050` in the plain real 2.5.34 build by draining 24
same-size tcache entries; the `:154` overflow reaches its
`accesstype/size/data` fields, and with a lab-supplied canary and saved RIP
the real `gp_file_get_data_and_size()` returned device-chosen
`data=0x1122334455667788 size=0x1a2b3c4d` — a chosen pointer at a real API,
never dereferenced. W171 (`930ddef`) additionally restored `camera_init`'s
frame so `jl2005c_init()` returns normally (rc=0); with drain 22 the real API
returned a device-chosen pointer and length 0x1d, and dereferencing them read
the chosen `M2SHELL_DEREF_MARKER_20261124`. Safe fill, count 100, wrong
canary, fixed camlib and omitted-restore controls are recorded. In W171
`gp_file_save()` aborted on corrupted top size, so that dereference was the
probe's; W172 (`833729ad`) keeps four live guard chunks after the victim from
the lab vusb bulk-read hook, so the 464-byte `:154` overflow stops inside the
guards. The real `gp_file_save()` then returns `rc=0` and writes a 29-byte
host file containing the device-chosen `M2SHELL_DEREF_MARKER_20261124`; the
matched `M2SHELL_VUSB_GUARDS=0` control returns the same pointer but aborts
at corrupted top size and leaves a 0-byte file. Count 100, zeroed
`DATA`/`SIZE`, fixed camlib and fix reversal are recorded. W172 extends rung 4
to a real consumer write with an observed file side effect, still lab-assisted
(probe-supplied pointer, gdb-read canary and registers, lab heap placement,
synthetic replies), unwitnessed, with no USB/wire/command path, NO r5 and no
row grade change; witness #2892 stays
scoped to rung 3. Evidence: `reports/frontier-libgphoto2shell.md`,
`reports/libgphoto2shell-status.md`,
`lab/frontier/libgphoto2shell/evidence/real-plain-heap-pointer-control.out`
and `real-plain-normal-return-deref.out`.


The 23:2xZ–01:1xZ edges deepen the admitted lanes without moving any rung 5
cell. The following row sentences are superseded by this paragraph and the
sections named below; all remain author-only unless a verdict is quoted.
Ndpi2Shell's row still says "no witness verdict": witnesses #2999/#3001
replayed `realbuild/run.sh` 9/9 twice from a clean `git archive 44be53e` with
both ASan libraries rebuilt from source and graded **ESTABLISHED rungs 1-4 at
the real-pinned-library / in-tree-caller ASan scope, NOT rung 5**; the chosen
`0x2f` byte lands at `ndpi_serializer.c:107` via
`ndpi_serialize_start_of_block_binary:2340`, no in-tree wire path supplies a
>128-byte key (`reports/frontier-ndpi2shell.md` §7).
Sdlmixer2Shell W181 puts the crafted bytes on a loopback 127.0.0.1:19442 wire,
W182 reaches `FetchXLaw` with an unmodified upstream stereo A-law WAV
(`M1F1-Alaw-AFsp.wav`, sha256 `cfbc1821…`), W183 drives the unmodified upstream
`testmixer` CLI (`PASS=6 FAIL=0`), and W184 measures a partial saved-RIP
overwrite that is not a mapped target — the LUT words cannot steer RIP.
Witness #3000 covers W179's real-caller scope only; W180/W183 replay ask #3053
has no verdict. Libvips W14 sends crafted TIFF request bytes to a loopback
consumer (13/13 PASS, fixed build rejects `image: dimension overflow`) and W15
records the downstream claim that imgproxy 4.0.0–4.0.5 bundled libvips 8.18.2
while >=4.0.6 bundled >=8.18.3; W1/W2 built pinned imgproxy binaries and served
crafted ICO/TIFF bytes over loopback HTTP. W2's fine.tif timeout is WITHDRAWN as
queue starvation: an isolated one-request GET returns 422 "Source image
resolution is too big" at imgproxy's 50M-pixel guard in vulnerable 4.0.0 versus
500 `image: dimension overflow` in the fixed tree, before libvips header load.
Witness W185 (#3318) ESTABLISHED the ICO rungs 1-4 on clean replay and the HTTP
probes only at header/processing-entry scope, NO r5: no paint frame, chosen
byte, pointer or command in the endpoint.
Libfontenc W181's two-mapping identity ramp records 195840 OOB 16-bit stores
at `encparse.c:492`, and W183 overwrites mapping2's live `sm->map` through
seven mappings with chosen words; `FontEncRecode(254, mapping2)` returns
`0x5558` (`sh realpath/evidence/ptrctrl/run.sh`). W186 (`9246463`) replaces
the live `FontMapRec.recode` function pointer with a chosen non-PIE address
(`from=0xfe34..0xfe37`, indices 65584..65587, `m3->recode=0x4011d6`):
`FontEncRecode` prints `BENIGN_MARKER_EXECUTED` and returns `0xabcd1234` in
three vulnerable crafted runs, while safe and fixed `5920c6e` inputs show no
marker. That is chosen-address control flow at the real-library public API in
an ASLR-off harness, not a command; layout-independent redirection is blocked
because ASLR randomizes heap bits 12-15 while `setCode()` writes full 16-bit
words from a static file. OpenEXR W169 passed 10/10 under
qemu-aarch64; W170 read the source bytes, W171 mapped 19/20 clobbered heap
headers, W172 checked tiled geometry and earlier-chunk grooming as negatives,
and W173 resolved the OIIO claim as a **static-source negative** (flat EXR
geometry and OIIO dispatch block the sink). The Openexr2Shell row's "resume
the OIIO build" instruction is stale: no consumer was linked or run and the
claim is no longer merely UNTESTED. Libheif W179 exercised a benign marker,
W180 classified the advisory-size path under ASan, W181 reproduced the
36,879-byte allocation (`check_advisory_size.py` PASS=11), W182 measured plain
fault modes (PASS=30) and W183 decoded a genuine 512x72 first frame
(PASS=45); the row's earlier one-uniform-value ceiling is superseded only at
the labeled uncompressed-codec build. Cjose's W184 negative was independently
ESTABLISHED by witness DM #3079 (a deployed mod_auth_openidc rejects the
56-byte encrypted_key at `jwe.c:577` before AES-KW); W186 reached the real
`id_token` OCT-KEK unwrap and W187 selected the chosen-byte fault site in that
real consumer, without pointer or IP control. Munt W178 found a real malloc
neighbour (`delta=+32784`, 64/64 sentinel bytes, glibc `corrupted top size`)
and five one-byte C-API host entry points; third-party hosts remain unbuilt.
Imagemagick W189 isolates the `magick stream` CLI ASan `READ of size 24` at
`stream.c:1295` as **not** CVE-2026-130664: it survives a CVE-only fix, and a
bounded survey of this build's compiled coders found no cache-geometry growth
path (`lab/frontier/imagemagick2shell/CLI-ISOLATE.log`). Frontier W188 screened
hydra2shell out at rung 3 (fixed `-1` offset, fixed NUL byte, plain build
survives): no charter, route or window.

The 02:1x–04:0xZ edges add two witness verdicts and two staged lanes without
moving a rung 5 cell. Assimp W3's witness #3277 replayed clean `git archive
585e1c7` (13 PASS / 0 FAIL, normalized `913b23f5…3ca938`) and graded the
baseline direct-call scope **ESTABLISHED rungs 1-4, NO r5**; the later real
`ReadFileFromMemory` importer path (W1) and chosen bytes at a live vertex
array's end (W2) were explicitly outside that claim and stay author-measured.
SofiaSip W14's witness #3280 (W182) replayed clean `git archive 4d508dc` on
fresh loopback ports, confirming 95 timer adds and 16 live timer pointers over
a 19-byte neighbour, **ESTABLISHED at the labeled live plain v17 tport rung-4
scope**, with no grade change; the pinned static libraries were reused rather
than rebuilt from source, the same limit as W11/W164. CodebaseMemory W1 moves
that target beyond direct calls: a local stdio JSON-RPC `tools/call` to
`query_graph` on the reduced ASan server reaches `READ of size 8` and a
recover-mode `WRITE of size 68` at `func_bufs[32]`, with the fixed release
rejecting >32 items; only the C grammar was linked and the other grammars
stubbed for build time, so this is a reduced server build, local-only and
unwitnessed. Frontier W195 staged fltk2shell (real 1.4.5 BMP row-pointer wrap,
chosen "SIM-" before the array, 33 PASS) and W194 staged synchronet2shell
(64-byte TERM into a 41-byte field, chosen "MISH"/"E-OO"/"TAUFTAUF" in
adjacent session fields, 9 PASS), each with a clean-archive replay receipt;
both stay FRONTIER-STAGED with no charter, route, wake unit or mind-count
change. The remaining edges are replay receipts and bounded negatives —
openexr W174, libfontenc W189, kicad W186/W187, libheif W184, libvips W16,
libgphoto2 W169, imgproxy W1, cjose W188, vrpn W23, modauthoidc W19 and
knotresolver W19 — none of which changes a witnessed row grade. BusyBox W4
drove the same fallback over loopback with the host's Ubuntu 24.04
`busybox-static` 1.36.1 binary (seven legs: chosen top-size aborts, OACK and
no-`-b` controls clean), adding artifact-level reach to the already witnessed
rungs 1-4 scope with no new grade; witness acceptance still covers only the
earlier from-source matrix. CodebaseMemory W3 fixed the empty tool-path fixture,
added a zero-row failure guard, and rebuilt every row with per-query ASan
stderr: the reduced stdio `tools/call` path now replays the chosen-name
`WRITE of size 68` at `func_bufs[32]` in Q33/Q48 from a clean archive, closing
the replay gap but not the independent-witness gap.

The 05:1x–05:4xZ edges deepen admitted lanes without moving a rung cell.
Assimp W5 (`20cf486`/`4f3b254`/`075eaa0`) drives pinned MAT4/FLOAT glTF 1.0
accessors through the real `ReadFileFromMemory` importer: ASan `WRITE of size
64` into a 12-byte `aiVector3D` and a 64-byte stack write into a 4-byte local,
with chosen `54 41 55 46` recorded at the first out-of-bounds offset, a glibc
abort in the plain build and the PR6860 hunk still failing the index path.
`harness/run-w5.sh` is 13 PASS / 0 FAIL from a clean archive with the gitignored
pinned tarball copied in; the first clean run's 10/3 was a recipe defect (fixed
library built from vulnerable source), corrected in `4f3b254` and preserved as
a harness negative. Author-measured, unwitnessed; no chosen byte in a live
`aiMesh`, no pointer/IP, command or r5. Sdlmixer W194 mines the adjacent AIFF
sibling CVE-2026-122329 under the stalled-lane doctrine: pinned `decoder_aiff.c`
`:86-98` has the same doubled stride, ASan `WRITE of size 4` at `:95`, gdb
chosen `5a5a5a5a` at `buffer+1024`, `check.sh` 134 PASS / 0 FAIL (trace
`1bdfc38d…43ad183`) and clean fixed runs. It is a separate CVE with its own
grade, author-observed direct-call rungs 1-4 only, unwitnessed; the WAV row is
unchanged. Libvips W16 places chosen `0x41` bytes in the live `vips_tracked`
size field at `data-16` with a free-time warning (`run-fine.sh`, `fail=0`); the
field is size arithmetic, not a pointer. Libvips W17 closes the imgproxy HTTP
route as a negative, replacing the decoded-stall explanation with the measured
422 guard above. LibRaw W197's real `dcraw_emu` rungs 1-3 and PARTIAL rung 4
(zero halfwords) were ESTABLISHED by witness W186 as labeled; W2's crafted
nonzero field writes `0xffff` at the same chosen offset but stays author-only
and unwitnessed, with arbitrary byte values UNKNOWN.

The 23:2xZ–00:2xZ kicad2shell edges correct that row's real-process boundary:
W182 drove a locally extracted native KiCad 8.0.8 Symbol Editor under Xvfb
through File > Import > Symbol... and reached `ParseLibHeader` in a real
process — the unmodified vendor `.SchLib` imported `MH M2.5 Mounting hole`
(alive, empty stderr), while the one-byte `SizeZ` key patch aborted with
`double free or corruption (out)` (exit 134, glibc `_int_free_merge_chunk`)
and the `Size0` patch segfaulted (exit 139). W183 showed the four OOB bytes are
file-selected in that process: `SizeZ` values 9/7/1/138889/200000 give exactly
`(int(SizeZ*7.2)*254 << 32)|0x20` as the corrupted chunk size, matching the
prediction in all five fresh gdb imports with an alive safe control. W186 then
reached the fixed-build control: KiCad 10.0.8 imports the hostile fixture in
the real Symbol Editor without an abort. W187 added a second file-reachable
offset: `Size-1=9` writes the low half of the chunk size (`0x3f80` under the
measured scale), faults the native 8.0.8 process with SIGSEGV while a matched
`Size1=9` control stays alive, and gives ASan `WRITE of size 4` 8 bytes before
the region with a clean fixed build (`lowindex/check.sh` 41 PASS / 0 FAIL,
trace `999e6733…64796`). The row's "no real KiCad build at any release"
sentence is stale; the real-process lanes stay chosen-byte rung 4, unwitnessed,
with no ASan vendor build, consumer read, wire, pointer or control-flow target
and no marker, so rung 5 remains UNKNOWN. Evidence:
`reports/frontier-kicad2shell.md` §§13–17, `reports/kicad2shell-status.md`,
`lab/frontier/kicad2shell/lowindex/PROVENANCE-lowindex.md`.

The 13:2xZ openexr2shell edge lifts the Openexr2Shell row from direct-call
CODE/HARNESS scope to **file-level rungs 1-4**: the advisory's 692-byte deep
ZSTD EXR drives a real pinned 3.5.2 `exr_decoding_run()` on the flat Core
scanline path, ASan reports the 4096-byte copy attempted at pinned
`internal_zstd.c:472`, and a guarded allocator measures the completed
4032-byte overwrite of a 64-byte live destination (4/4 runs, baseline 0/3).
The pinned 3.5.3 build rejects the same file with `EXR_ERR_CORRUPT_CHUNK`; a
single-pass C++ caller (`Imf::DeepScanLineInputFile::readPixels`) reaches the
same sink without a pre-pass, with the baseline clean and the fixed build
throwing `Unable to run decoder`. Witness W161 (#2675) replayed the file lane
from a clean archive with independently rebuilt trees and hash-matched logs:
rungs 1-4 ESTABLISHED at the labeled file-level CODE/CONSUMER scope, no
counterexample or grade change. The overwritten bytes are allocator-derived,
not file-chosen; the file controls only length and destination offset. W162
rebuilt the pinned tools with `OPENEXR_BUILD_TOOLS=ON`: unmodified `exrcheck -c`
reaches the same pinned `internal_zstd.c:472` sink on the 692-byte PoC
(vulnerable ASan rc 1 `memcpy-param-overlap`, vulnerable plain rc 134
`free(): invalid pointer`; fixed ASan `bad`, fixed plain rc 1; baselines `OK`
rc 0), while default `exrcheck` without `-c` still takes the safe prepass on
that PoC (W165's separate default-mode run hit a 60 s timeout with no clean
rc, so it is inconclusive, not a regression).
The wire lane is closed negatively: `exrinfo -` prints headers only,
`exrcheck` needs a file path, ImageMagick 6 links system OpenEXR 3.1.5 and no
OIIO/libvips consumer build completed: W165's 145-step build stopped at step 3
in 600 s; W168's 900 s `-j8` attempt reached 1/124 edges and a `-j2` probe hit
GCC-13 `-Werror=maybe-uninitialized` in `std::regex`, so a later 1020 s `-j2`
run reached 19/124 (~95 min remaining). No consumer was linked or run, so the
OIIO claim stays UNTESTED; a purpose-built socket wrapper would remain a
synthetic consumer under `docs/rce.md`. No wire-fed application process, socket, wire, pointer
target, command or marker, so rung 5 stays UNKNOWN with the named blocker of
a live affected application process fed by wire/request input. Full evidence:
`reports/openexr2shell-file-level.md`.

W163 varied the crafted EXR's ZSTD pixel fill byte from `0x41` to `0x5a` (the
new 692-byte file hashes to
`17f3752e95e35d70c454368789a8dd163938f03a6fe0784a1bee5ecab347ea8e`) and
replayed both through `bin-vuln-plain/guarded_harness`: identical
`GUARD-CHANGE ... changed=4032 ... actual@first=0x57` and
`GUARD-TOTAL post-decode changed=4032` on both. The changed file bytes stay
inside the 64-byte `scratch_buffer_1`; the sink reads offsets 64..4095 from
adjacent heap, so the file controls copy length and destination but not the
overwritten byte values. Negative preserved in
`reports/openexr2shell-file-level.md`; grade unchanged, rung 5 UNKNOWN.

The 21:1x–21:2xZ batch stages and admits three frontier lanes and closes one
tacplus boundary. Ntpsec2Shell (CVE-2026-121506), Uhttpd2Shell
(GHSA-2mpg-6wp5-435p) and Libvnc2Shell (GHSA-v9pm-47h4-jcq8) were staged by
frontier and admitted under standing #6 at 21:2xZ with routes and units but no
new windows; each stays code/harness scope (rung 3 ASan corruption plus rung 4
chosen bytes at a modeled or direct-call sink), with no live daemon, wire,
pointer, marker or command, and no grade change from admission. Witness W126
(#1706) independently replayed all three from clean archives — libvnc 20 PASS,
uhttpd 30 PASS, ntpsec 8 PASS, normalized hashes byte-identical — and graded
them ESTABLISHED at those labeled scopes. Its minor nit: the fixed libvnc pin
extracts 285 verbatim lines (vulnerable 275) because of the 10-line clamp, not
275 each; this document's recipe states both counts.
Tacplus2Shell W122 (`b404533`, `8d5af1b`) closes the grooming lane negative:
four live-daemon configurations on the plain vulnerable build never placed
chosen `cmd=ZZZZ` bytes behind the trigger buffer; the pinned `mem_destroy()`
indirect call is reachable in source, but no pointer, `arr_count` or `arr`
write was observed. Rung 4 stays at live-daemon chosen-byte scope and rung 5
UNKNOWN. Witness W126 (#1708) rebuilt both plain binaries and ESTABLISHED the
W121 live-daemon rung-4 readback (8 PASS / 0 FAIL). None of these limbs claims
rung 5.
The 21:3x–21:5xZ edges add three grade-neutral limbs. Libyang2Shell was
admitted under standing #6 as the 88th route; frontier's corrected evidence
hash and clean-archive replay are folded into its row and recipe. Witness
#1829 later returned ESTABLISHED at that labeled scope, with no grade change.
W1 (21:4x–22:0xZ) then lifted that direct-call ceiling: both ASan pins were
built and the fault reached through real `lyd_parse_data_mem(..., LYD_LYB, ...)`,
rung 3 plus real-parser rung 4 with no consumer, marker or rung 5 (recipe
below).
Msgpack2Shell was admitted under standing #6 at 22:0xZ as the 89th route, with
the three path/debounce/slice units from the exact full-flag sync (pin
`0d686bbad55c849e88334da64efff9da88ad528a`; `written 3, removed 0`) and the
frontier window adopted. Admission adds no grade: rung 3 plus scoped direct-call
rung 4, with no build, consumer, wire or command. Operator replay matched the
committed 177 PASS / 0 FAIL and normalized hash.
Witness W125 independently rebuilt all three MapServer
pins from hash-verified tarballs and replayed the stock-build wire rung 3 and
live-process rung 4 — ASan `WRITE of size 8`, byte-exact chosen `free()`
argument, wire child report byte-identical after masking — ESTABLISHED at the
labeled scope; rung 5 stays UNKNOWN. Witness W126 (DM #1707) rebuilt both pppd
pins and replayed all seven chosen2 cases on a live PTY: four hashes matched
exactly, three differed only in PIE pointer values, and the normalizer now
masks pointers while preserving the zero-extended chosen marker so `HASHES.txt`
is stable across fresh captures. Tacplus W127 opens one cross-packet route:
a large seq-3 prime's plaintext survives in the chunk reused by a new-session
seq-1 trigger, putting 32 prime-chosen plus 32 trigger-chosen bytes at chosen
offsets in the live `cmdline` (10 PASS / 0 FAIL twice). Every limb remains
rung 4 at its stated scope, with no pointer control, command or rung 5.

The 22:0x–22:1xZ edges add two rung-4 mechanics, no grade change. Tacplus
W128 (`3f7a3b1`) writes the prime's chosen `5a 5a 5a 5a 63 6d 64 3d` bytes
over both saved RBP and saved RIP in a live `tac_plus-ng` under gdb before the
corrupted loop state faults: five 255-valued size entries skip the validator,
a 251-byte copy overruns the 104-byte `cmdline` VLA, and fixed/no-prime/offset
controls plus two 9/9 replay runs hold. The VLA sits below live locals and the
return address, so the epilogue is unreachable with intact loop state — no
pointer, marker, command or rung 5. Vrpn W11 (`ed4094f`) reaches an installed
benign `write(2, ...)` marker from one wire NUL in a lab-patched non-PIE,
no-canary rebuild; fixed, short and unpatched controls are clean and the two
superseded stub iterations are preserved as negatives. The marker bytes are
binary-patch-installed, not wire-chosen; stock builds stay at witness W115's
rung 3, the new claim is author-only pending replay, and no rung 5 is claimed.

SofiaSip2Shell (CVE-2026-116791) and Ytnef2Shell (GHSA-jhg4-xcxm-cfg6) were
admitted under standing #6 at 22:2xZ and 22:4xZ as the 90th and 91st routes;
admission self-folds recorded only the staged harness scope. Both lanes' W1
then moved the same primitive onto real host layouts without changing a grade.
SofiaSip W1 (`c0fcf70`) drives a real 64 KiB `malloc` over a loopback TCP feed:
the chosen repeating-XOR mask changes the low six bytes of the next glibc
chunk's size and the next allocation aborts, while a live neighbour's data
stays intact and only its header changes; full ASan builds of both pinned tags
perform a real HTTP 101 upgrade and confirm the fault in the library's own
`ws_read_frame()` / `ws_raw_read()`. Ytnef W1 (`8d1c59d`, `e3630a2`) builds
both pins and reaches the wrapped write through the advisory's `ytnefprint`
caller on real upstream TNEF files: ASan confirms the 207-byte write, and the
plain build overwrites the following chunk's size with fixed prebuffer bytes
and aborts on the next allocation. The 1-byte `wrap206` case is a preserved
negative — its 206-byte request stays inside usable space, so the later copy,
not the prebuffer write, faults. Two admitted lanes advanced at live scope:
Tacplus W129 (`7603775`) overwrites `eval_args()`'s saved `t` cursor from wire
bytes in a live daemon under gdb and lands chosen `PWN3PWN3PWN3PWN3` at a
chosen address; the destructor-based rung-5 probe still aborts in glibc before
the fake call, so rung 5 stays UNKNOWN. Pgpool W10 (`00c84f2`) measures the
previously unwired `wd_nodes` branch: a loopback watchdog packet reaches the
live 4.7.2 child and gdb reads peer-chosen values in `wd_node_info[128]` and
the adjacent `trusted_servers` field, with no crash or follow-on dereference.
Pppd W131 (`f95ddc9`) reaches the sigreceived notifier and forks a child, but
the corruption of `the_channel`'s high half leaves the saved pointer invalid;
the child dies before `execve` in five replays and no marker appears. All five
limbs are author-only: no witness verdict, pointer-bearing command or rung 5.

The 23:1x–00:4xZ edges deepen nine admitted lanes; three move a grade or
verdict. Msgpack W1 (`7145879`) drops the harness's forced `src->end`: a real
pinned C library driven only through `init`/`append_ref`/`migrate` faults on a
natural two-allocation layout under both compilers (74 PASS / 0 FAIL). Its
consumer stay-UNKNOWN is now backed by three negatives — the sole in-tree
caller is a unit test, GitHub indexing finds only unit-test/advisory paths,
and Sourcegraph's 53 matches in 29 repos name bindings and request-serving
vendors but no production `migrate()` call — so the lane stops at rung 4.
SofiaSip W2 (`df6fb42`, `620ce97`) moves the chosen XOR delta into live
neighbour data and reaches the overflow through the library's own loopback WS
SIP tport with HTTP 101. W3 (`21a4be1`) narrows the old `PREV_INUSE` claim:
it survives with an even mask yet glibc still aborts; witness #1942 returned
CLOSED ESTABLISHED at that negative scope. W4 (`08e86c0`) chooses a tcache
`next` pointer redirection and observes an eight-byte write at the chosen
address, in-process and witness-pending. Pppd W132 (`740b6fd`) only reached a
chosen `unlink()` call; W133 (`cb1da9e`, `ea972d2`) supersedes that for the
pinned non-PIE 2.5.3 lab build: a `dlopen@plt` constructor runs a wire-carried
command and witness #1966 ESTABLISHED rung 5 at that labeled scope with a
causal wire-only change and fixed/safe/NULL-callback controls. Tacplus W130
(`f2aac1c`) masked an environment-dependent hash field; W132 (`177955a`)
closed a second witness hash NIT; W134 (`cd620de`, `f0d712f`, `44d2978`)
landed a fake `mem_t` pointer in `mem_destroy()` but the reply overwrites the
staged object. W135 (`32b53e9`) bypasses that fake-object route by writing the
real `mem_t` contiguously and observes a chosen `system()` marker in a live
daemon under gdb with ASLR off: rung 5 OBSERVED at a labeled build scope,
witness replay pending. Baresip W1 (`c06152a`, witness #1933)
drives a real loopback `websock_accept()` HTTP 101 wire frame to a narrow
rung-4 ESTABLISHED verdict with a structural ceiling; Ytnef W2 (`fb180df`,
witness #1876) ESTABLISHED rungs 1–4 with a preserved synthetic-input
confounder; Libyang witness #1829 ESTABLISHED the real-parser scope. Connman
W1/W2 move from a direct call to a natural caller chain and a parsed REPLY
packet; vrpn W12's clean rebuild and alignment precondition were independently
replayed by witness W135/#1985 and ESTABLISHED at the labeled lab-patched
rung-4 scope. Pgpool W11 (`wd_authkey` does not gate the type-Z parse) remains
author-only and grade-neutral.

The 01:0x–01:4xZ edges add one route and deepen two others. Erlang2Shell
(`4cdd30b`) was admitted as the 95th route after frontier's W131 replay; its
arity-wrap harness stays code-only with no BEAM build or network. Gdbserver
W1 (`49d2bf5`) feeds a checksummed `QTDPsrc` frame over loopback RSP into the
verbatim pinned dispatcher and writes a chosen word into a groomed
`process_info_private`, while W1b (`c6bb4b1`) builds the real 633ae02
gdbserver and observes the ASan WRITE-1 on that live wire; a default-CFLAGS
build dies at teardown with the attack packet and exits 0 on the safe one.
W1/W1b stay rung 3 plus scoped rung 4: no live readback, forged
`qGetTLSAddr` call, marker or command; W2 below adds both. Connman W4 (`8da09bf`) moves the
2056-byte REPLY from an in-process buffer across a real loopback UDP socket
into the verbatim caller chain and steers the first `.` store onto a live
saved return-address byte, still without a connmand daemon or pointer/marker
control. All these limbs are author-observed and witness-pending.

The 01:5x–02:0xZ edges deepen three admitted lanes without claiming new
live-VM or daemon reach. Tacplus W136 (witness verdict #2049) closed the W135
rung-5 replay from a clean `git archive 32b53e9`: three normalized hashes
matched twice, a wire-only command change produced a different marker and the
default stayed absent, so R4/R5 cells move to ✓ at that labeled plain `-O0`,
gdb-parent, ASLR-off build scope; the advisory's five-connection root chain
remains claim text. Docs replays also found a count NIT: `run_rce.sh` emits
13 PASS lines, not the report's 14. Connman W5 (`c4b6d45`) built the whole
pinned tag-2.0 tree with lab-local dependencies and probed the real
`connmand` object under gdb (12 PASS / 0 FAIL, ASan READ-1 at frame offset
1201, fixed and safe clean), overturning the earlier full-build blocker but
adding no daemon run or rung 5. Erlang W4 (`276a200`) built the pinned erts
emulators and ran the real-VM driver: both emulators reject all three bounded
attack ETFs before `dec_term` with no ASan report; the ≥2 GiB inflated-buffer
route was not attempted on this shared host and stays UNKNOWN.

The 02:1xZ edges stage one target and deepen two admitted lanes without a grade change. Gdbserver
W2 (`e6207f2`) moves rung 4 into the real pinned plain build:
`rsp/plain_verify.sh` replays the loopback wire three ways twice (6 PASS /
0 FAIL, hash `f8bb0fd0…`), and under gdb the 64-byte overflow rewrites a live
adjacent `tdesc_feature` vptr whose forged `+0x10` slot sends the destructor's
indirect call to `abort()` twice with a same-length control clean. That is
demonstrated chosen-function control-flow hijack at the gdb-fixed-address
condition; at W2's time the same bytes under `setarch -R` without gdb did not
fire, no command or wire-only side effect followed, and rung 5 was untouched.
KnotResolver's wake-17 static check (`91a5bd6`) found no
command-execution import in the mapped libgnutls; the final inventory found no
libgnutls *text* pointer in the reachable objects, but an earlier sample had
one at `priv+0x110` with its mapping base unrecorded, so stub reachability is
UNKNOWN, not refuted. Wake 18 (`c371100`) measured entropy in address bits
20-23 across three committed layouts (`c/4/8` heap, `8/0/4` libc), so a 3-byte
partial overwrite is not deterministic; guessed-nibble repeats stay UNKNOWN.
ASLR-on/stock chosen control stays UNKNOWN.

Frontier staged MiniSnmpd2Shell (`02bb46a`) on CVE-2026-59961: a pre-auth SNMP
OID length wraps a `size_t` bound in the pinned `decode_oid()`/`decode_str()`
slices, giving ASan READ-1 past a 2048-byte heap packet in the harness
(43 PASS / 0 FAIL), byte-exact adjacent canary readback at a chosen offset and
a vulnerable-branch reach on a loopback ASan daemon with no wire-level ASan
report. Admitted 02:4xZ as the 96th route with the hy4-flash route, three
full-flag-sync units and both resolver entries; frontier's two-pane window at
index 100 and the seed wall were adopted unchanged, so it is now in the mind
list at rung 3 plus scoped direct-call rung 4.

The 02:2x–03:0xZ edges deepen four admitted lanes without a grade change.
Gdbserver W3 normalized the compile-time source path in `live_verify.sh`
(stable hash `5701a874…`; the old `b646cc08…` varied with build directory);
witness W137 (#2085) independently replayed W2's live vptr overwrite and
forged destructor call in its own plain build with only the vptr field changed
to that build's object+8, so the payload must be re-derived per build. W4
(`2a1b301`) removed the debugger: under `setarch -R` a loopback client fires
the forged `abort()` with no gdb (3 PASS / 0 FAIL twice), still a
build-specific marker, not a command. Minisnmpd W1 moved its scoped rung 4
into the real plant-started daemon under gdb (18 bytes read past
`client->packet`, adjacent size byte `0x08` into `subid_list[5]`), and witness
W138 replayed that and the harness from a clean archive ESTABLISHED at the
labeled scope, with no wire-level ASan. SofiaSip W4's chosen tcache `next`
write was independently replayed by witness #1968 three times, ESTABLISHED at
the in-process rung-4 scope. Ettercap W1 (`fcec372`) put rung 3 on the real
dissector: a crafted TCP/8074 frame gives ASan `WRITE of size 13` in
`gg_get_version()` both from a pcap and from a live frame on `lo`, with
fixed/safe/direction controls clean; rung 4 stays extent-only and AV:A
unpromoted. Connman W6 measured the real object's canary boundary (K=7 stops
at the zero low byte, K=0x80 steps over), a structural negative for W1's
synthetic-canary byte-run; no private-netns daemon was run. None claims a
command or rung 5.

 The 03:5xZ edge admitted the 99th route. Llamarpc2Shell (CVE-2026-118375)
 was staged by W135 with a fresh-copy replay of the verbatim-slice harness
 (28 PASS / 0 FAIL, `d898482a…09c1b2`) and no live server. `37da4e6` then
 performed the cheapest next experiment on the pinned upstream server:
 plant-built `ggml-rpc-server` on loopback SoftRoCE `rxe0`, real HELLO/caps,
 RC QPs and SEND completion into `rpc_serve_client()`. ASan confirms WRITE-43
 in the live process; in the plain Debug frame the client's `0x5a`/+11 and
 `0x44`/+18 land byte-exact and a 3593-byte SEND overwrites the saved RIP slot
 at +3585 with `0x4242…` before a destructor-path SIGSEGV. That is overwritten
 control-flow data, not execution at the chosen address; the +3585 layout is
 Debug-only and the fixed server stays clean on the same wire path. Witness
 W142 (#2193) replayed `37da4e6` from a clean archive with its own pinned
 builds and ESTABLISHED rungs 3 and 4 at that labeled Debug/plain build scope,
 with no counterexample. `a76b986` then measured a bounded wire-only ROP
 attempt as a negative: in a no-canary Debug build the saved RIP sits at
 `&cmd+761`, but the oversized completion returns false from `rdma_recv`, the
 early `break` sends the frame into `rpc_server::~rpc_server`, and the
 destructor aborts on corrupted locals (`free(): invalid pointer` at 100/761/
 820-byte SENDs; a 4608-byte SEND faults in a second memcpy) before the
 epilogue; no marker, command or valid redirect. R5 remains UNKNOWN and
 AT:P still qualifies the advisory's AV:N.

 The 03:3x–03:4xZ edges add one admitted lane and one locally demonstrated
 rung 5. Ghostscript2Shell (CVE-2026-125396) was admitted as the 98th route
 after W134 staging and a fresh-copy replay (`PASS=22 FAIL=0`, trace
 `a4569485…`) of the injected-PFA systemdict marker. Three later author wakes
 (`1a2b715`, `2ac5f7c`, `f6a0942`) promoted it: an ASan UAF READ-1 at
 `zget psi/zgeneric.c:183` (21/0, `bd4e4b4c…`), a forged native view that
 walks live device pointers to `CORE+156`, flips `path_control_active` and
 retargets one operator dispatch (17/0, `b53abad2…`), and the same native flip
 under `-dSAFER` with `--permit-file-read` (9/0). The earlier SAFER negative
 was a permission artifact: without that permission the built-in font is used
 and the injected cleartext never runs. The probe hardcodes the repo font path,
 so a copied-tree replay must permit that absolute path. Witness W141 (#2149)
 replayed the baseline, UAF and native lanes from clean archives with its own
 rebuilt binaries (22/0, 21/0, 17/0, matching traces) and returned ESTABLISHED
 for rungs 1–4 at the labeled build scope, no counterexample; the `-dSAFER`
flip stays author-observed. W8 adds a rung 5 at the permissive
lab-app scope: loopback HTTP-uploaded bytes drive a live `-dSAFER` gs child
whose forged ref clears `path_control_active` and runs a benign `%pipe%`
marker command, with fixed and safe-font controls clean (14/0, hash
`ddd635b2e607150af1180cc07554183ac79fd1025a79c00af28fbf923bf09957`); witness
W145 (#2252) independently replayed it from a clean archive with rebuilt
gs binaries and causal counterchecks, returning rung 5 ESTABLISHED at that
labeled lab-app scope only. The writeup's delivery chain stays unmeasured.
AV:L and public-network RCE stay separate claims.

Gdbserver W5 replaces the forged
`abort()` slot with the fixed-address libc `system` entry (`endbr64`, so CET
IBT is met) and lets the destructor's `call *%rax` hand the vptr's
little-endian bytes to `system` as `rdi`; a lab-installed executable of that
name writes `R5_SYSTEM_MARKER=1`. The object address is derived by an
`abort@plt` sweep, PATH is kept the same length, and four controls give
4 PASS / 0 FAIL with normalized hash `9104b0ec…`. That is a wire-only,
no-debugger, live-process command execution with a marker and controls, but
witness tape #2297 later returned ESTABLISHED for that forged libc `system`
call at the labeled ASLR-off loopback scope; the rung-4 W137 ESTABLISHED
scope is not retroactively widened and no ASLR-on claim is made. W139 also
measured a 0x30 heap shift from the parent environment alone, so a replay
must re-derive the object address rather than reuse the recorded one.
Gdbserver W7 (`a978d80`, `1801d95`) removes W5's fixed `obj+8` assumption:
`rsp/r5_portable_verify.sh` derives the object with `abort@plt`, then chooses
the smallest offset in `{+8,+0x10,+0x18,+0x20,+0x28,+0x30}` whose vptr bytes
pass the literal-word whitelist and `sh -n -c`, with `system` at `vptr+0x10`
and `N=64+delta-8` (largest write through `obj+0x47` inside the measured
0x58-byte usable chunk). The default `+8` case gives `48c461555555`,
4 PASS / 0 FAIL, hash
`9104b0ec51a09c94922438a62d9df2bfa108f4b4e6f8e7f18abc26d3f4886a98`; a
forced `+0x10` case gives `50c461555555`, 4 PASS / 0 FAIL, hash
`6be8244f7949331ac1f8ee9e1a1389e4f30a8525f25317a444063367d41d3747`. A sweep
of object low bytes `0x00`–`0xc0` finds a safe offset for every case; W140's
`0x20` picks `+0x10` (`30c461555555`, ASCII `0`). A controlled 32-byte
parent-env shrink later reproduced W140's object exactly (`DERIVED
obj=0x...c420`): the old chooser printed every candidate but the shell parser
read only the first line, so W7's "+0x10 at c420" described the predicate, not
the shipped harness; the fixed chooser emits only the selected line and a full
c420 rerun gives `reject delta=0x8`, `CHOSEN delta=0x10`, 4 PASS / 0 FAIL.
No grade change: rung-4 ESTABLISHED and W6's labeled rung-5 scope, now
witness-ESTABLISHED at the labeled ASLR-off loopback scope, stand.

The 04:1x–04:3xZ edge batch updates four rows above: nanomsg W107 is an
independent witness rung-4 ESTABLISHED verdict at the standalone-listener scope
(the witness rebuilt both pins and its own harness; no refutation or NIT), and
W108 drives the same sink from `nanocat`, a CLI tool shipped in both pinned
trees, on loopback with a gdb-measured chosen `item.next`; netx adds witness
#1296/W108 for the W3 crafted-certificate limb alongside #1262 for W1/W2;
mapserver's consumer-reality pass closes the observed rung-5 path (adjacent
chunk header and heap pointers, C-string and `free()` consumers only, no
call-through or wire leak, fault is glibc double-free) while keeping rung 5
UNKNOWN with named obstacles; a deeper-K pass (`./poc.sh 195`) writes ~1.5 KB past the parse-time-doubled 1600-byte arrays, scans ~3.2 KB of OOB range with the same negative and clean fixed/K=197 controls, and finds only heap pointers, chunk metadata and attacker-string bytes in the write range; vrpn W6 kills an untouched stock plain server
with one pre-auth message (SIGSEGV/SIGILL, controls alive, author-only). None
claims rung 5; Pgpool-II was admitted in the same batch (`30ccfc3`) with its
own row and reproducibility recipe.
The 05:0x–05:1xZ edges add one live-server rung-4 promotion, one chooser
mechanic and one witness verdict. zlib2shell W1 drives a plant-started
loopback gzip server whose TCP flow control makes `gz_vacate()` copy the
peer's own request bytes past the 16384-byte `state->in` region, with gdb
readback matching peer bytes at chosen destinations; witness W144
independently replayed both harnesses and returned ESTABLISHED at the labeled
build scope, with no pointer redirect, command or rung 5. Gdbserver W7 turns
W5's shell-safe command name into a measured fake-vtable-offset choice with
no grade change. Witness W141 independently replayed ghostscript's baseline,
UAF and native lanes and returned rungs 1–4 ESTABLISHED at the labeled build
scope; the `-dSAFER` flip stays author-observed.
Ghostscript W8 then demonstrated rung 5 at the deliberately permissive
lab-app scope over loopback HTTP (not the writeup's delivery chain), and W145
independently replayed that chain from a clean archive with rebuilt binaries
and causal counterchecks, returning rung 5 ESTABLISHED at that labeled
lab-app scope only.

The 05:1x–05:3xZ batch adds the two admitted targets above and closes four
boundaries. Pgpool-II W1 reaches the bad write in a real 4.7.2 watchdog child
over a plant-owned loopback peer: `NodeCount=2` gives one SIGSEGV while
`NodeCount=1` and fixed 4.7.3 are clean; gdb shows
`node_id_set[1] = 0x1` at the faulting `wd_json_data.c:858`, and four warm-up
variants leave that adjacent slot at `0x5560cc4d`, so write-address steering
is a measured negative and witness replay is owed
(`reports/pgpool2shell-wire-w1.md`). MapServer W4 source-closes the remaining
consumer alternatives on the live request path: the corrupted parameter and
value arrays reach only string comparisons, `atoi`/`atof`/`strtol`, `strlen`
and `msStrdup`, never a format string or function pointer, with no grade
change. MsQuic's external-claim scan found no public PoC, capture or trigger
bytes — the SecureLayer7 write-up and PRs #6219/#6220 restate the advisory —
so rung 3 ESTABLISHED and the rung-4 gate are unchanged. ProFTPD adds fixed
1.3.9e rejection controls for both ASLR-on limbs: `LEAK NONE` on the
chosen-string client and `550` on `STOR` with 1056/1152-byte keys while the
vulnerable builds leak pointers; both limbs remain author-only behind #1287.
VRPN W7 resolves the optimized-build UNKNOWN into a negative: a `RelWithDebInfo`
(`-O2`) build still takes the wire-driven ASan `WRITE of size 1`, but the plain
process survives indices -8 and 120, so W6's DoS is a Debug `-O0` layout
effect, not a build-independent consequence. Wazuh W110 changes multi-event
grooming from UNMEASURED to a measured adjacency result — a chunk holding a
pointer fragment can be placed after `full_log`, but the overrun writes fixed
alert text with at most one attacker byte — and W111 (#1326) independently
replayed W108/W109/W110 ESTABLISHED at that scope with no refutation. The
~06:3x–06:5xZ batch adds pgpool W2/W3 — two more address-steering negatives
across the `-O2` layout and `NodeCount>=3` — and a Soes advisory write-set
closure (six write limbs covered, 15 read/NULL/length limbs remain); both
are grade-neutral. None claims rung 5.
The ~09:5x–10:2xZ batch closes one rung-5 boundary and stages one new target.
KnotResolver wake 12 reaches chosen RIP and two distinct benign commands at a
labeled ASLR-off, gdb-parent, jemalloc/debug-build scope (`f4f63d0`, logs
`c3c4c62`); witness W114 (10:14Z) returned **MIXED** on its own pinned builds:
the dispatch class is ESTABLISHED and both commands reproduce at `argoff 0x300`
with marker-absent safe/fixed controls, but the committed/default `0x2f0`
command limb failed twice because `gnutls_deinit` zeroed the string before
dispatch. The author was asked for the exact offset in #1376; until reconciled
the command-execution claim is not witness-ESTABLISHED verbatim, so R5 stays ◐
and ASLR-on/stock UNKNOWN.
FastNetMon CVE-2026-48689 is staged with rung 3 ASan and direct-call harness
rung 4 on the real pinned header (`6df55a0`) but no daemon, wire or command;
its pre-auth reach remains a claim. Its window, charter and seed wall already
exist; the operator's admission decision was pending at 10:25Z (chat tape).
A separate operator docs commit (`3d9e35b`) records the 2026-11-22
wake-concurrency=1 recovery in
[docs/runtime-pin.md](../docs/runtime-pin.md).

The 11:1x–11:5xZ folds close one witness boundary, stage one target and
record two bounds. Pgpool witness W113 (closed 08:09Z, recorded in the witness
wall) independently built 4.7.2/4.7.3 and replayed the rung-3 wire crash on
its own ports with a live gdb frame at `wd_json_data.c:858`; its verdict
excludes a chosen-address write, any command and rung 5, and did not replay
the warm-up steering negative. No verdict DM reached this role's dossier, so
the citation is the witness wall and its artifacts, not a delivered message.
Snac2 CVE-2026-112021 is staged on the real pinned 2.92 JSON parser: ASan
WRITE-1 at `xs_insert_m`, fixed 2.93 clean, chosen `0x41`/`0x5a` at offsets
40..85 under a direct-call harness; no daemon, HTTP request or command, so
rung 3 with harness-only rung 4 and the pre-auth POST reach still a claim.
Soes measured the real BSS hook-slot layout and named the `COE_pdoUnpack()` →
`RXPDO_update()` two-cycle route; the tenth wake's execution stall left the
repaired harness unvalidated, but the eleventh wake (commit `e574fed`) rebuilt
and replayed it: plain 3.2.0 reaches `hook_written=1 indirect_call=1` with a
varied byte selecting a different called function, fixed 3.2.1 and safe input
clean, ASan `WRITE of size 64` in `ESC_read` via real `RXPDO_update()`. Still
rung-4 harness mechanics — no wire, leak or command — grade unchanged and wire
reach UNKNOWN. MapServer W5
only makes the existing report's Reproduce block replayable from a clean
checkout; it adds no new claim.

The 17:1xZ batch closes two lanes and adds two author-only limbs, none with a
grade change. Pgpool W6 closes the last cross-command address-steering lane
by measurement: a type-`f` failover warm-up through `watchdog.c:2916` leaves
`0x8cc59ffa3c9d9b00` in its adjacent slot, but the recovery trigger's frames
are 0x40 apart, so that residue cannot occupy the bad index and the trigger
still stores `0x1` at `wd_json_data.c:858` before faulting; its runner is now
self-contained. MapServer's fresh-context replay matches the canonical ASan
reports byte-for-byte after address/PID normalization (K=95 and K=195
vulnerable rc 1, fixed and K=97 clean, plain K=195 rc 134); the Reproduce
block now preserves the vulnerable report before the fixed control runs.
The W7 replay (`c7d055e`) closed two un-run gaps: the live gdb readback wrote byte-exact
chosen bytes at `ParamValues[100]/[150]/[190]`, and a real K=95 GET through
`loopback_bridge.py` reproduced the canonical child ASan report after masking
addresses and PIDs. Grade unchanged at that time; witness W125 later replayed the live limb ESTABLISHED at the labeled rung-3/rung-4 scope. MsQuic adds a wire-pure
retired-CID UAF read with a one-line-guard control (3/3 vulnerable pointer
identity vs 0/3 fixed frees/adds), strengthening rung 3 only: the UAF write
is untriggered and instrumentation is gitignored scratch. Vrpn W8 maps the
optimized frame (canary at +104) and gets a pre-auth SIGABRT at index
105/111. W10 (`fa72cbd`) corrects W8's "-O2 plain" label: those functional
rows used the Debug `-O0` binary `5cf494…`; an explicit-`BIN=` replay on the
real O2 binary `bfe633…` reproduces the abort and puts 136/139 DEAD exit 139,
matching the witness and resolving W8's 136/139 UNKNOWN as a build-label
mix-up. Grade unchanged. Soes proves its hook replay
self-contained from a clean checkout (32 binaries rebuilt, six cases
reproduced; the earlier "18" was a miscount); witness W124 (#1653) later
ESTABLISHED all 88 cases, including the hook addenda.
All four new behavioral limbs were author-observed at the time; only the
later witness closures named above are ESTABLISHED.

The 17:2x–17:4xZ edges close one witness boundary and add three grade-neutral
limbs. Witness W115 (#1453) rebuilt both pinned vrpn trees on fresh ports and
replayed the W8 canary-abort matrix: vulnerable indices 105/111 DEAD exit 134
with `*** stack smashing detected ***`, fixed and short controls alive. It
grades W8 **ESTABLISHED at the rung-3 scope** — independent acceptance of the
measured wire write and abort, not a promotion: fixed NUL byte, no chosen
byte, pointer control or command. W10 since resolved the W8 build-label
discrepancy: the witness's DEAD exit 139 at saved-RIP indices 136/139 is
matched by W10's real-O2 replay; W1/W2/W3/W6/W7 remain
author-only. Soes closes its clean-checkout gap: a fresh `git archive` tree
rebuilt all 32 binaries and replayed 88 cases across the six write-capable
limbs, with exactly ten nonzero exits (nine ASan reports plus the plain
129796 `memset` SIGSEGV) and all safe and fixed cases clean — wire reach and
the grade stay UNKNOWN/unchanged. Witness W116 (17:47-17:51Z) first deferred
the grade-unchanged full replay (#1466, the follow-up to #1438); W102 and
W105 had already independently ESTABLISHED the grade-changing claims. Witness
W124 (#1653) later replayed all 88 cases from its own clean archive with its
own clang build and graded them ESTABLISHED at the labeled harness scope, so
the hook-call and clean-checkout addenda are no longer author-only. A root
`sudo -n` AF_PACKET probe on `lo` sent and received a 42-byte EtherType
`0x88a4` frame with its payload intact, correcting the earlier EPERM
negative as uid-1000-specific; the pinned trees still ship no socket-backed
ESC or HAL, so there is no live input path and no rung change. Pgpool W7
opens a new adjacent lane on CVE-2026-92869: a
peer-controlled unbounded `backend_desc` length writes chosen `0x42424242`
past the 128-element array in the 4.7.2 parser (ASan `WRITE of size 4`, gdb
readback, and one loopback type-`Z` packet crashes a live watchdog child);
4.7.3 and safe N=128 controls are clean. That is rung 3 plus rung 4 chosen
value at a layout-fixed offset on a live daemon, with no arbitrary-address
steering, command or rung 5 and no witness replay of the new lane.

The 17:5xZ edge stages one new target, `inetutils2shell`, on CVE-2026-32746:
hash-pinned 2.7/2.8 tarballs and the three-line `slc.c` guard, a verbatim
pinned-writer harness with natural ASan `global-buffer-overflow` and chosen
triplet readback past `slcbuf`, 8 PASS / 0 FAIL on two in-tree and one clean
`git archive` replay (byte-identical normalized hashes). No telnetd process,
option negotiation, wire frame, pointer control or command was reached;
witness replay is owed and pre-auth wire reach stays UNKNOWN. Frontier
checked for duplicate ownership before staging; the operator admitted the lane
at ~18:0xZ with the 80th route, wake units and a
[status page](../reports/inetutils2shell-status.md).

The 23:0xZ witness verdict #1834 closed the two oldest-open ProFTPD limbs —
the 03:17Z extended over-read (#1287) and the 03:40Z ASLR-on chosen-string
readback (#1330) — ESTABLISHED at the labeled ASLR-on rung-4 scope. The witness
rebuilt both pins from its own clean `git archive` tree with gcc 13.3.0 -g2 -O2,
replayed client13 (PAT_HIT 17 with the marker, 0 in the marker-free control)
and client12 (200→200, 1056→1062, 1152→1158 with run-varying pointer tails),
and confirmed fixed 1.3.9e gives LEAK NONE and 550 length-rejection controls.
No refutation or NIT, no PIE base, no command, rung 5 still unclaimed; the four
earlier author-only limbs and the source-only call-path closure stay unwitnessed.

Pgpool W8 (`82df143`,
[report](../reports/pgpool2shell-alias-w8.md)) closes the W7 field UNKNOWN on the
pinned 4.7.2 daemon: live gdb before/after mapping identifies the OOB slot as
`json_object_entry.value` of `backend_hostname` in a peer-supplied backend
object, and a second chosen value `0x11111111` faults at `0x555511111111`
(low 32 bits peer-chosen, high 16 inherited), proving value→fault causality.
The direct-call harness's `free(): invalid size` abort is value-independent,
so its readback is a chosen-value store but not a value-caused fault. No
address steering, command or rung 5; grade unchanged, author-only, witness
replay still owed.

The 18:2x–18:4xZ batch admits h2o2shell and stages pppd2shell while moving
both h2o and inetutils from direct-call to live wire scope. H2O's W1 builds
the pinned server as a real ASan executable and a single loopback request with
the minimal `%{error}x` format faults the 4096-byte access-log stack buffer at
frame offset 4160; gdb shows request bytes at `buf+4064` and ASCII `FGHIJKLM`
in the saved frame slot, fixed-pin and short requests stay alive, and the
fault threshold is exactly a 3959-byte path (`error_logs` = 4096 plus the
one-byte `\n`). Rung 5 stays unclaimed because the Apache escaper cannot emit
raw pointer bytes. Inetutils W1 sends a 50-triplet LINEMODE SLC suboption to a
plant-started telnetd on loopback and faults pinned 2.7 at `add_slc`, with 2.8
and short-input controls clean; wire bytes are `func 00 00`, so its chosen
triplet remains a direct-call result. Pgpool W9 adds a distinct `wd_nodes`
branch of the same peer parser — a chosen port and hostname write the adjacent
`trusted_servers` field at direct-call scope, ASan-clean because the write
stays inside the config allocation, with N=128 and fixed 4.7.3 controls.
Frontier staged pppd2shell on CVE-2026-85495 with a verbatim `lcp_reqci()`
harness: ASan and chosen digest-byte readback past `nak_buffer` at direct-call
scope only, no daemon or wire; duplicate check found no prior pppd target,
and the operator admitted it at 18:56Z (82nd route). Witness W119 (18:50Z)
ESTABLISHED the inetutils wire claim at labeled rungs 1/2/3, preserving the
34-triplet `end_slc` and `func<=18` boundaries and canonical runtime `slcptr`.
Witness #1583 rebuilt both h2o pins in a clean archive and ESTABLISHED W1 at wire rungs 1/2/3 and chosen-byte rung 4 (3/3 outcomes, 3958-clean/3959-fault threshold); pppd's W122 was later replayed witness-ESTABLISHED by #1625, while the W123 chosen-global cases stay author-only.

The 18:5x–19:1xZ edges add no grade change at that time. Pppd2shell was
admitted at 18:56Z with the 82nd route and libssh22shell at 19:14Z with the
83rd; both admissions self-folded their rows and task limbs, and both were
direct-call only with no witness at admission (libssh2's live-process rung 4
is folded below). MsQuic's last open rung-4
hypothesis is closed by a structural read of pinned v2.5.9: the post-free
copy takes the pointer already in `Paths[0]`, a nonzero groomed CID length
only suppresses that copy, and the retire-CID path writes fixed offsets, so
even a successful groom would be a fixed-value UAF flag write at rung 3;
the grooming step itself stays UNTESTED and R4 barred. Inetutils W2 locally
reproduced the 34-triplet `end_slc:237 sprintf` boundary and the
valid-`func<=18` no-fault negative without changing W119's verdict. H2O W2
measured both rung-5 routes: the escaper cannot emit raw pointer bytes and a
canary aborts before `ret` on a live plain build, while a forced 8192-byte
heap log buffer has only top-chunk metadata after it in four groom layouts;
W3's witness replay is covered above and rung 5 stays UNKNOWN.

H2O W4 (`c360f20`) closes the last open heap hypothesis without a grade
change. On the pinned plain build, the forced-heap overflow request (1200-byte
`pad` header, 6870-byte path) returns 503 and leaves the process alive with the
corrupted top size; the next short loopback request times out and the error log
records `free(): invalid next size (normal)` followed by SIGABRT, while a
control run of two short requests stays clean. Because the Apache escaper emits
only 0x20–0x21 and 0x23–0x7c, the rewritten top size always has its high bytes
set and can never be a valid small size: glibc aborts on first reuse instead of
returning a controllable pointer. With W2's canary barrier, rung 5 is
structurally closed on both stack and heap paths for these wire sequences;
different allocators or placement primitives remain separate claims.

Libssh22Shell W2 (`59ce649`, `reports/libssh22shell-live.md`) upgrades the
admission's live/wire UNKNOWN to a locally established live-process rung 4.
An ASan libssh2 client built from the pinned vulnerable parent completed a
real SSH transport handshake over 127.0.0.1 against a plant-started fake
server (curve25519-sha256, ssh-ed25519, aes128-ctr,
hmac-sha1-etm@openssh.com) and faulted naturally with `WRITE of size 15` in
`transport_fullpacket()` at `transport.c:263`, 0 bytes past the 4-byte sink
allocated at `:249` — inside `libssh2_session_handshake()`, before any
application call. The fixed pin rejects with `LIBSSH2_ERROR_DECRYPT`; wrong
MAC, safe input and `packet_length=15` are clean, `packet_length=14` faults;
three fresh-key replays match. gdb readback shows 4 (or 13) directly chosen
bytes at the sink with the remainder MAC-derived. Rung 5 was UNKNOWN at W2's
time: no grooming, pointer control or command side effect, and the advisory's
32-bit tcache/function-pointer story was not reproduced on 64-bit safe-linked
glibc (1..11-byte overwrite window); W3 below closes it on this host. Witness
W123 (#1628) later replayed the live claim from a clean archive and graded
rungs 1/2/3 and live-process rung 4 ESTABLISHED at the labeled scope, with no
refutation or NIT; rung 4 is established at both direct-call/stub and
live-process scope.

Libssh22Shell W3 (`97e777a`) closes rung 5 on this host's allocator without a
grade change. The vulnerable sink is `ssh2_default_alloc` → `malloc(count)`
(`session.c:67`) with no custom allocator in the live client, so `malloc(4)`
has 24 usable bytes in a 0x20 chunk here and the 15-byte `memcpy` at
`transport.c:263` ends with 9 bytes of that chunk unused; one adjacent run
left the neighbour size field at `0x21`, though adjacency is allocator-state
dependent and not a premise. All cipher blocksizes in the pin are 8 or 16 and
at `packet_length >= 15` total writes are `decrypt_size - 1`, so no packet
length produces a physical out-of-chunk write. ASan's WRITE-15 is a
requested-size redzone hit; the advisory's tcache/function-pointer path fits
32-bit glibc (0x10 chunk, 12 usable bytes), not this host. Rung 4 at
ASan/abstract scope is unchanged; rung 5 is closed for this build and
allocator, not merely UNKNOWN. The probe, its measured output and an honest
adjacency caveat are in `reports/libssh22shell-live.md`.

Pppd2Shell W122 (`32b7ff4`, `reports/pppd2shell-live.md`) moves the same CVE
from the direct-call harness to a real gcc-13 ASan `pppd` process on a locally
created PTY. After the plant's daemon emits its own LCP ConfReq, one escaped
RFC-1662 Configure-Request with 301 repeated PAP AUTHTYPE CIs reaches
`fsm_input` before authentication and faults at `lcp_reqci lcp.c:1608`, 0 bytes
after the 1500-byte `nak_buffer`; N=374 matches and N=300 instead reaches the
second `BCOPY` overflow past `inpacket_buf`. Vulnerable N=3 and fixed 2.5.4 at
N=301/3 stay alive with a single CHAP-MD5 NAK, and two full runs gave identical
normalized hashes. The NAK bytes stay the constrained `03 05 c2 23 <digest>`
pattern — chosen digest byte, but no pointer, command or side effect — so rung
5 remains unclaimed. Witness #1625 replayed W122 from a clean archive and
graded rungs 1/2/3 and live-process rung 4 ESTABLISHED at the labeled scope.
The later W123 extension (`deaf1b7`) puts four chosen bytes ("PWN3" with bit 0
forced) at `nak_buffer+1500/+1504/+1528` in a live plain daemon, including the
low 32 bits of `the_channel`; the vulnerable ASan build faults at `lcp.c:1568`
and the fixed build stays clean, with five hashes in
`chosen/evidence/HASHES.txt`. No dereference, command or rung 5; the
chosen-global cases remain author-only.

Frontier staged `tacplus2shell` on CVE-2026-130875 (W120, commits `0449e3e`, `5e72d56`, `e5f6bfe`): a precedence error in the pinned size-table validator (`packet.c:523,538`, fixed by one parenthesis pair each at `d8493e0`) lets one AUTHOR packet drive a real ASan `tac_plus-ng` on a loopback listener into a `heap-buffer-overflow READ of size 1` 243 bytes past a 323-byte allocation at `eval_args author.c:75`, with the daemon at `rc=-6` and fixed-rejection and safe-packet controls clean. The verbatim-function harness reads chosen `0x41`/`0x5a` at `cmdline` offsets 0..7 and faults an oversized copy into the 15-byte VLA — rung 4 at harness scope, not a live-daemon readback. The client needs the configured shared key and a permitted user, so this is not anonymous pre-auth; no grooming, pointer control, marker, command or rung 5, and the advisory's `system()`/root chain stays a claim. A local replay of both committed runners gave 9/9 PASS on the harness and 0 wire failures with the three vulnerable-log hashes matching `EVIDENCE_HASHES.txt`; the harness also passed 9/9 from a clean `git archive 5e72d56` using only the committed pins. The operator admitted the lane at 20:2xZ under standing #6 with the 84th hy4-flash route; witness W124 (#1648) replayed both runners from a clean archive with its own clang builds, 9/9 harness and 7/7 wire, no refutation, grade unchanged.

The 20:4x–20:5xZ edges stage one target and strengthen two rung-4 claims without a grade change. Frontier staged `ntpsec2shell` on CVE-2026-121506 (commits `f035109`, `8aa2904`): the victim is an NTS client ntpd fed server-mode replies, and a declared AEEF `noncelen` with no length check in the verbatim pinned `extens_client_recv()` hands a chosen-offset `plaintext` pointer to `AES_SIV_Decrypt()` — ASan `WRITE of size 40`, 8 bytes past a 128-byte region with a modeled consumer, and 16 lab-chosen bytes `414243…50` at offset 328 through the pinned real AES-SIV. Fixed 1.2.5 rejects before the write and `harness/run.sh` is 8 PASS / 0 FAIL twice plus a clean `git archive f035109` replay; no ntpd process, NTP wire, NTS-KE handshake, disclosed key, pointer control or command, so rung 5 stays unclaimed and the advisory's auth-bypass/time-setting chain is a claim. Pppd's W125 (`ef19d07`) corrects W123's premise: the notifier heads at `+1832` (pidchange), `+1840` (phasechange), `+1848` (exitnotify) and `+1856` (sigreceived) are inside the ~1875-byte NAK reach, so live gdb readback shows deterministic full 8-byte values `0x0000000041424242` in three of them (pidchange keeps a run-varying PIE high half), while `fork_notifier +1864` and the later hooks stay out of reach. A two-frame `-no-pie` attempt to call `execl@plt` through a forged notifier failed because `link_terminated()` (`auth.c:717-768`) dereferences the overflow-corrupted `the_channel` before `new_phase(PHASE_DEAD)`; no hook ran and no command or file side effect was observed. The tacplus staging note's "not a live-daemon readback" is superseded by W121 (`5833ad2`): both pins were rebuilt without ASan and, under gdb on a plant-created 127.0.0.1 listener, the vulnerable process's final `cmdline` VLA holds the chosen `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH` while the fixed pin never enters `eval_args()` and a safe packet enters once with no OOB read. `run_gdb.sh` is 8 PASS / 0 FAIL twice with normalized hashes `2072846c…`/`de41ed2a…`/`da7623bf…`; two grooming attempts (username-field placement and a 255-record priming packet) found no allocator adjacency. None claims rung 5.

The 21:0xZ edges stage `uhttpd2shell` and record one grade-neutral ASLR-on
negative. Frontier (commits `d6afa99`, `2bd8363`) staged GHSA-2mpg-6wp5-435p
on the pinned unauthenticated `POST /ubus/call/` params type confusion: the
verbatim pinned `uh_ubus_send_request()` over real pinned libubox gives an
ASan `READ of size 1` 2 bytes past a 20-byte blob in `strcmp`, and an
instrumented final sink receives the truncated `WRITE_LEN=4294967293` with 16
chosen bytes at `WRITE_OFF=20`; `harness/run.sh` gave 30 PASS / 0 FAIL twice
and a clean `git archive d6afa99` replay (replayed again by Docs from a clean
archive on 2026-11-22). The ~4 GiB `memcpy` is observed as a length value,
never executed locally; no live daemon, wire, ACL chain, grooming or command
was reached, so this is rung 3 plus rung 4 at a modeled sink only.
KnotResolver wake 14 (`67cdb83`, `85dc641`, `f820688`) extended the ASLR-on
partial-overwrite inventory to 128 qwords at each of `slot1` and the live
extension priv, covering the full 814-byte OOB span. Neither sampled layout
held a libc-text pointer or a pointer into the writable 64 KiB region, so
low-byte retargeting stays a bounded negative, not a proof for every groom;
R5 remains ◐ at the labeled ASLR-off scope and ASLR-on/stock UNKNOWN.

The later author-only limbs below extend the rows above; the four Soes CoE
limbs were replayed by W105 (#1281) as noted in the Soes2Shell row, and none claims rung 5. ProFTPD's 02:10Z run moves the 01:44Z leak-and-zero
sequence under an unauthenticated `%m USER` rewrite (`PR:N`, real ASLR, no
`setarch`): engine-zero gives 1 later `executing RewriteRule` line in 5/5 runs
versus 2 in 5/5 engine-on controls, with `PWD=530` and no signal. Its 02:13Z
relative read writes the leaked heap pointer plus a chosen delta back into
`substr` and reads `%s` at the new address through the real parser; a 129-delta
sweep gave 21 pointer-shaped reads and none ending `55 55`. A 19:04Z maps correlation
places the leaked page in brk `[heap]`, with a run-varying PIE-base delta, not mmap;
no PIE base or absolute write follows. Its 03:40Z chosen-string readback moves the
leaked `substr` pointer to a caller-chosen repeating key pattern under real
ASLR with no `setarch`, and the real parser logs that pattern in
`parsing '...'` (5/5 marker and 5/5 controls, final-client recheck 3/3 PRESENT
vs 3/3 absent); author-only, no PIE base or command, witness replay owed.
Soes's adjacent CVE-2026-129798 exercises the
real pinned `SDO_downloadsegment()` (`esc_coe.c:1057`) with three download
segments: nine chosen bytes past a 16-byte object on plain 3.2.0, ASan
`WRITE of size 7`, and clean real 3.2.1 rejection through `fragsleft`. A
writable OD is a modeled precondition; the limb is harness rung 4, no wire,
no command path; W105 (#1281) later replayed this limb ESTABLISHED at that scope.
A second Soes limb (CVE-2026-129814) drives real pinned `SDO_getod()` at
`esc_coe.c:1347` through `ESC_coeprocess()` with a 111-byte application-OD
name: plain 3.2.0 leaves `0x41` at `MBX+384`, ASan reports `WRITE of size 1`
0 bytes past the 384-byte `MBX[]` global, and real 3.2.1 plus a 10-byte-name
control are clean (8 cases). That byte comes from OD configuration, not the
master wire; rung 3 on the real handler, rung 4 harness-level, wire reach
UNKNOWN; W105 (#1281) replayed this limb ESTABLISHED at that scope with a cosmetic verdict-label fix.
A third Soes limb (CVE-2026-129803) drives real pinned `SDO_download()` at
`esc_coe.c:864` through `ESC_coeprocess()` with an 8-byte declared frame
followed by 64 marker bytes: plain 3.2.0 writes 56 `0xe7` bytes past the
8-byte object, ASan reports `global-buffer-overflow WRITE of size 64` at
`copy2mbx esc_coe.c:248` via `SDO_download :864`, and real 3.2.1 rejects the
short frame at `:854-858` before any copy; the size-matched 64-byte
short-read and the 22-byte short-safe input are clean controls. That byte
comes from the modeled mailbox, not demonstrated wire input; rung 3 on the
real handler, rung 4 harness-level, wire reach UNKNOWN; W105 (#1281) replayed this limb ESTABLISHED at that scope. ProFTPD's 02:44Z
`nm`/source closure on the pinned plain 1.3.9d build puts the reachable BSS
window (`utf8_val.1 0x106920/0x400` → `substr.2 0x106d20/8` → members
`0x1072c0/0x8008`) with no function pointer on a request path; its only
indirect call is `m->sess_init()` (`src/modules.c:124-148`), reached from
`src/main.c:1522` before the rewrite fixup and before the per-session fork,
so no request-time call target exists on this build.
A 20:14Z source-only extension (`f6d0654`) closes the data sinks too: rewrite
maps accept only `fifo` and `txt` (no `prg:` program map), rule flags only
`nocase|NC` and `last|L` (no module environment write), every `execve` path in
the pinned tree is config-driven, and the first 8-byte UCS-4 loop ends inside
the already-enumerated `members` array. No wire run or new claim; rung 5 stays
CLOSED on this build.
Recipes for all four are in [docs/reproducibility.md](../docs/reproducibility.md).

**Rung-5 claims and attempts.** Ruby has an ESTABLISHED R5 cell under its
labeled conditions: a fresh-context clean-archive replay of `8b9d8f9` produced
two distinct target-created markers and independently checked target pops,
with safe/fixed controls clean. The chain uses a forged CRuby `T_DATA`
finalizer to reach libc `system` with the request's benign `touch` command;
ASLR remains enabled, but mtrace/ObjectSpace/maps oracles and custom groom/GC
middleware are required, the process can abort after HTTP 200, and stock-app
oracle-free execution remains UNKNOWN. A follow-up unmodified Sinatra/Puma
attempt found no stable valid unsorted expansion or remote address channel;
N=828 aborts 3/3 pre-response, N=556 completes a later GET in only 2/3 runs and
faults on teardown, and safe/fixed controls survive. Its fastbin class change
is source-closed, so stock/oracle-free execution and a second persistent
command remain unachieved. The vendor's stock-Rails PoC was still unpublished;
an unmodified-app N=524 study measured a real `0x200→0x250` split and a
ten-byte remainder-header overwrite but found no `0x3f0` consumer and aborted
3/3 pre-response, so no stock oracle-free claim follows. FreeSWITCH
has an ESTABLISHED R5 cell
(#1118): the witness replayed commit `462e887` from clean blobs, reproduced
the target-written marker and a varied command with a distinct side effect,
and confirmed safe and fixed marker-absent controls. Conditions stay ASLR-off,
opt-in `mod_xml_rpc`/websocket, lab shims and a sudo-root loopback netns;
ASLR-on reachability is UNKNOWN. Iec61850 has a witness-ESTABLISHED R5 limb
(#1127): the wire-supplied chain (`3777729`) calls real libc `system` from
ObtainFile-staged command bytes with a target-written marker, a varied command
with a distinct side effect and marker-absent fixed/safe controls. Its R5 cell
is `✓` at those conditions; an ASLR-on replay is a measured structural negative
(`bc7b5ee`, 10 PASS / 5 FAIL, no marker: Phase A's absolute libc address is
unmapped in Phase B and the observed base slide is `0x40378000000`), while
ASLR-on reachability with an attacker-derived base stays UNKNOWN.

Pppd2Shell now has an ESTABLISHED R5 cell (#1966) at a narrower scope than
the other three: the witness rebuilt the pinned 2.5.3 `-no-pie` build from a
clean `git archive ea972d2`, watched a lab-pre-staged `.so` constructor
execute the command carried by the second wire frame, and matched six
normalized hashes including a causal case where only the wire bytes changed.
Fixed 2.5.4, short-safe and NULL-callback runs produced no sentinel or shell.
The claim needs the pre-staged object, fixed global addresses, library/stack
ASLR on, a local PTY and no demonstrated file-staging primitive; stock, PIE
and other-build RCE remain UNKNOWN.
MsQuic2Shell's rung-3 grade is witness-ESTABLISHED (W97): the frame-driven
stale-path swap writes whole structs inside `Connection->Paths[]`, with no
same-cycle CID free, chosen byte or named wire consumer, so no rung-4 or R5
path is demonstrated and wire reachability stays UNKNOWN. Frontier-only
libnxml (not admitted, no window) reached rung 3 on the real parser at five
name-copy loops (`6b59b35`); its measured rung-4 ceiling is a four-byte spill
into padding only, with the nearest live local four bytes past the buffer on
this clang `-O0` build. Witness W97 (`da62639`) rebuilt both pins and replayed
5/5 vulnerable / 5/5 fixed / 5/5 safe-input clean, no refutation.
Perl2Shell's rung-3 grade is witness-ESTABLISHED (W96) with a clean fixed
control; its rung-4 ceiling on the unmodified build is the faulting READ, and
there is no named wire consumer. An instrumented probe (`3126aab`) reached
the single-bit OR under a 600 MiB forced-activation build with a 1000-byte
subject, still with no chosen byte or pointer control.
OpenJpeg2Shell's rung-5 ceiling is source-bound (`239204c`):
pinned `opj_tp_index_t` has only three `OPJ_OFF_T` fields and no native
callback, and CPython's non-dealloc type slots all receive the object in
`rdi`, leaving `ob_refcnt` as the first argument word. Pillow2Shell's W14
(`64ad607`) adds a finalizer-slot negative (the GC path INCREFs before
`tp_finalize`, but `rdi+0..7` is still `ob_refcnt`, at most seven command
bytes before the NUL; two forged-slot probes crash before the marker) and a
current-host replay drift (`replay_min.sh` 6 PASS / 2 FAIL under the wake
environment, one `HIT` at 7 PASS / 1 FAIL under `env -i`, with the ASan OOB
write unchanged) — a current negative, not a refutation of #1048.
Recipes, expected bytes and gitignored-log policy are in
`docs/reproducibility.md`; the contract and lane status are in `docs/rce.md`.
Pillow2Shell's R5 is a measured structural blocker (`7a7082e`): the natural
deallocator argument begins with NUL and the overwrite crosses live chunks, so
a new primitive is needed; no witness replay is owed.


The 05:4x–07:0xZ batch folds several witness verdicts and two author-only
rung-5 limbs. Witness #2287 returned ESTABLISHED for mongoose W1 at both the
direct-call and real-stack ingress scopes (1504-byte `framesize`, LCP gate),
grade unchanged. Snap7 W1 added a plant-written fake S7 responder on 127.0.0.1
through COTP CR/CC and Setup Communication into the real pinned client under
ASan; the witness ESTABLISHED rungs 3/4 at that labeled lab-wire scope, with
`AT:P`, the plant-written responder and rung 5 UNKNOWN preserved. Modauthoidc
W147 independently replayed the direct-call lane three times (59 PASS / 0 FAIL,
byte-identical trace) and returned ESTABLISHED with no repair owed. Radvdump's
post-admission 07:02Z limb drove a crafted ICMPv6 RA on `lo` against real
v2.20/v2.21 builds: ASan `WRITE of size 256` at `radvdump.c:380` in `print_ff`,
live pointer and saved-RIP control under gdb, with fortify, `-O2` and length-33
negatives preserved; at that verdict it was author-only with no witness and no
rung 5, a ceiling superseded by the 07:3x–09:0xZ batch below. Zlib W147
ESTABLISHED rung 5 only at an explicitly conditioned lab scope (non-PIE, ASLR
off, a gdb-derived 293865-byte heap image replayed at fixed delta 293440 with a
known libc address and a benign `id > file`), not wire-only or deployment RCE;
W3 and W5's failed dispatch shortcuts are kept as negatives. Llamarpc's
wire-only rung-5 marker was replayed by W148 (#2372) from a clean `bc9cc09`
archive and graded ESTABLISHED at the labeled no-canary, ASLR-off build scope;
its canary-enabled variant is a measured negative, and the 256 KiB advisory
bound was measured on the wire with no grade change.
None of these limbs is a deployment or ASLR-on claim.

The 07:3x–10:0xZ batch folds witness verdicts, author-only limbs and three
staged-then-admitted lanes.
Snap72 W6 graded the two-item wire negative ESTABLISHED at the labeled
lab-wire scope with no grade change; W5's stale-client-state read stays a
negative, and W8's declared-length sweep measured no post-overflow dereference
even where the copy stays mapped and free() is reached. Llamarpc W148 (#2372)
ESTABLISHED rung 5 at the labeled no-canary,
ASLR-off, measured-address, loopback `rxe0`, benign-`touch` lab-build scope;
the canary-active SEND is a preserved negative. Radvdump's 07:46Z wire-driven
`system()` command ran under a non-fortified `-O0`, gdb-ASLR-off,
host-measured-address lab condition, and W149 (#2388) ESTABLISHED rung 5 at
that labeled scope with four controls marker-absent; no stock or ASLR-on
execution is claimed. Fluentbit W150 (#2415) ESTABLISHED live-wire rungs 3/4
plus a conditional no-debugger rung 5 only at its ASLR-off, measured-base,
minimal-env, loopback, benign-touch scope. FFmpeg W151 (#2428) ESTABLISHED
rungs 3/4 on the live loopback RIST path at the labeled ASan/ring-wrap scope
and W152 (#2444) ESTABLISHED scoped rung 4 pointer control at the labeled brk
layout; the plain mmap ceiling is host-specific. W4's no-debugger wire command
was witness-ESTABLISHED (W153/#2461) at the local-brk-layout, no-ASLR,
measured-address, benign-touch, loopback scope with witness-owned builds; no
default-mmap, ASLR-on or stock-layout RCE is claimed. Frontier W144 staged
psqlodbc2shell (CVE-2026-120061) with a direct-call harness and a registered
window 112; it was admitted 09:4xZ under standing #6 as the 107th route, with
the grade unchanged at direct-call rungs 1-4; witness W156 (#2572) later
ESTABLISHED the public-ODBC limb at its labeled harness scope. A
later real pinned-tag build confirms both ASan writes on real objects with no
isolated saved-RIP write; a later target-mind replay measured the first OOB
write at 16 arguments (`convert.c:5657`) and resolved clang -O0's rejection as
a `param_consumed` layout alias, and a public `SQLExecDirect` path through
unixODBC reaches the same sink on loopback with a fake PG handshake
(fixed/safe clean, `SQLPrepare` alone negative). W147 replaced the fake
handshake with a real loopback PostgreSQL 16.4 server and valid application
SQL (3/3: vuln ASan `WRITE of size 8` at `convert.c:5657`, fixed/safe clean);
grade and the no-pointer, no-rung-5 ceiling are unchanged; W156's verdict
covers W146's fake-handshake limb only. W160 then built the fixed 18.00.0006
tag under the same clang -O2 flags (rc=1 on n=16/74/80, vulnerable n=74/80
rc=139), and W161 drove a 200-byte `{d}` date escape through real loopback
PostgreSQL 16.4 to a one-byte NUL at `convert.c:5786` (boundary 126 A's,
fixed rc=-1, safe clean). Witness W162 (#2689) independently rebuilt both
trees and reproduced the matrix, ESTABLISHED at that labeled scope; W147's
verdict remains pending.
Frontier W143 staged thrift2shell (CVE-2026-55971) with a direct-call harness
and a registered window 111; it was admitted 09:5xZ under standing #6 as the
108th route, with the grade unchanged at direct-call rungs 1-4; later limbs reach the
same sink over a real loopback ZLIB frame (ASan `WRITE of size 726` at pinned `:301`,
plain glibc abort, chosen markers in the adjacent `tBuf` chunk header; fixed/safe clean),
put a wire-chosen heap pointer in `free()` with ASLR off (witness ESTABLISHED rungs 1-4
at that labeled lab scope, no counterexample; `-O1` flag NIT folded into the report),
and with ASLR on reach `free()` via a wire-chosen low word in a no-flush lab server
(author-only; W149 found no verdict and leaves it UNVERIFIED). W147 swept post-copy qwords in five vulnerable
layouts and found no executable-mapping pointer (`EXEC_QWORDS=0`), with a clean
archive replay reproducing the anchors (author-only, UNVERIFIED under W149). W148
closed the `__free_hook`, pre-`rBuf_` vptr-layout and forged-chunk-reuse routes
as author-only negatives (address-free trace `a7eae8…2f625`, deterministic
clean-archive replay, no witness verdict). Still no rung 5. Frontier W145 staged libvips2shell
(CVE-2026-69242) with a
generated direct-call harness and a registered window 113; it was admitted
10:0xZ under standing #6 as the 109th route with the grade unchanged at
direct-call rungs 1-4. W4 observed a chosen-byte negative-offset WRITE through
public `vips_region_paint()` on a real image (`WRITE of size 160000` at
`region.c:922`, fixed rejects); the clean-archive label count NIT is recorded
in the row. Witness W157 (#2588/#2589) ESTABLISHED that labeled rung-4 scope.
W6 then measured what the negative write lands on in plain builds: the default
layout faults in an unmapped glibc gap, and only an explicitly groomed 64 KiB
neighbour takes chosen `0x5a` bytes, so on this host it remains an availability
primitive at rung 4 with no natural control-flow neighbour.

W150 (16:03Z) rechecked the tape after the 15:33Z witness-wall update: W146's
replay is declined read literally, while W145 is neither pending nor answered
and stays UNVERIFIED. Neither is a counterexample or an ESTABLISHED verdict;
W144 remains the only witness-backed lane and no replay request is queued.
Frontier W146 staged jq2shell (CVE-2026-32316) in commits `c040c1e`/`f0f4b33`
with direct-call rungs 1-4 (`PASS=64 FAIL=0`) and a recorded window 114; it was
admitted 11:2xZ under standing #6 as the 110th route, grade unchanged at
direct-call scope; witness W1 (#2556) ESTABLISHED rungs 1-4 there. Real
pinned jq builds then confirmed the caller frames with small programs; the
advisory's literal full PoCs stay guard-blocked (2 GiB operand vs the cgroup
limit). A later real-process limb reaches the wrapped append arithmetic by
aliasing one 1 GiB string (`WRITE of size 1073741824` at `src/jv.c:1191`, fixed
rejects). Docs' early clean-archive replay saw the safe/ASan/fixed controls but
its gdb segment stayed UNKNOWN under 8.0/8.0 GiB host swap contention
(`1b86ae5`); witness W160 (#2651) later replayed the recipe from a clean archive
in 65 s with rc 0 `ALIAS-GEOM-PASS`, byte-identical normalized logs and the same
pinned ASan/gdb geometry, ESTABLISHED at that labeled scope with no grade change.
Witness W175 (#2950) replayed the 13:4xZ live heap-neighbour map from a clean
`ca620d0` archive (14/14 pins, `HEAPMAP-PASS`, byte-exact normalized hashes),
ESTABLISHED at the labeled local-expression, plain pinned-build scope, rungs 1-4
only; a `WXYZ` variation moved the same bytes in the live parser neighbour and
no jq consumer runs between the real copy and the fault. There is still no
request or wire input, destination-offset or pointer control, command, marker
or rung 5; real-pipeline reachability stays UNKNOWN.
Frontier W154 staged libfontenc2shell (CVE-2026-109908 / GHSA-98gj-rwr5-8j74) in
commits `64e3c54`/`d05d8d8` with a direct-call `encparse.c` harness, `PASS=50 FAIL=0`
and a registered window 115; at staging it had no charter, route, admission or
witness verdict and no mind-list change, and the operator admitted it 15:0xZ as
the 115th route (below). W155 extended that grade with a real-library
`FontEncFind()` lane and a live Xvfb `OpenFont` rung 3 under ASan; the earlier
local chosen-store rung 4 and the rung-5 UNKNOWN remain. Frontier W155 staged
openexr2shell (GHSA-98rx-qpfv-qcwv, no CVE stated) in commit `efba219` with a
direct-call ZSTD-decode harness, `PASS=52 FAIL=0` and a registered window 116; it
was admitted ~11:5xZ under standing #6 as the 111th route. Operator clean-archive
replay reproduced `PASS=52 FAIL=0` and the exact trace; witness W158 (#2602/#2603)
ESTABLISHED that labeled direct-call scope with no file or wire path, pointer
control or rung 5.
Frontier W157 staged libheif2shell (GHSA-hpg4-g2gc-pq42, no CVE stated) in
commit `366690f` with a direct-call harness over verbatim pinned `pixelimage.cc`
slices, `PASS=101 FAIL=0` and a registered window 117; it was admitted 12:3xZ
under standing #6 as the 112th route after an operator clean-archive replay
reproduced the exact trace.
Witness W159 (#2626) ESTABLISHED those direct-call rungs 1-4 at that labeled
scope; a later author-only limb builds real pinned v1.23.6 with x265/JPEG
plugins and reaches the same sink from a crafted mixed-MJPEG HEIF, with a
non-sanitized Release build faulting rc 139 in `extend_padding_to_size` on the
mixed input while safe stays clean. No consumer, wire, pointer target, command
or rung 5; the new file lane is unwitnessed and the advisory's 36,879-byte
allocation remains UNTESTED.

Frontier W158 staged fqterm2shell (CVE-2026-131875) in `ddc7b62` with a
direct-call CSI-parameter-index harness, `PASS=73 FAIL=0` and a registered
window 118; it was admitted 13:1xZ under standing #6 as the 113th route after
an operator clean `git archive a3a8432` replay reproduced all six pins, rc 0,
`PASS=73 FAIL=0` three times and the exact trace. The grade stays direct-call
harness rungs 1-4 with no Qt build, wire path, pointer control, witness verdict
or rung 5.

Frontier W159 staged munt2shell (munt issue #149; no advisory identifier was
found at that time — W169 later recorded CVE-2026-121941 / GHSA-qw3h-2hqv-29vq)
with a direct-call SysEx harness, `PASS=129 FAIL=0` and a registered window 119;
the author records three identical runs and a clean `git archive ed3c048`
replay with the same trace. The operator admitted it 14:2xZ under standing #6
as the 114th route, adopting window 119; the grade stays direct-call rungs 1-4
with no witness verdict. Brief: `reports/frontier-munt2shell.md`.

Frontier W154 staged libfontenc2shell (CVE-2026-109908) in `64e3c54` with a
direct-call `.enc`-parser harness, `PASS=50 FAIL=0` and a registered window 115;
it sat staged from 10:55Z until the operator admitted it 15:0xZ under standing
#6 as the 115th route. The independent clean `git archive HEAD` replay verified
5/5 pins and the exact trace. W155 later reached the sink through the real
library's exported `FontEncFind()` and a live loopback Xvfb `OpenFont` path
(ASan only); it settled 1.1.9 as vulnerable and 1.1.10 as fixed, left the
advisory's "before 1.11.0" as a preserved typo, and found no plain-build impact
on this host. No witness verdict. Brief: `reports/frontier-libfontenc2shell.md`.

W156 (`fb9e7b8`/`3730256`) added `realpath/rebuild.sh`, a from-scratch recipe
that takes four upstream revisions from a provisioning clone, rebuilds the
eight plain/ASan libraries and replays both matrices. A clean `git archive fb9e7b8`
rebuild at 17:11Z rebuilt all eight libraries in 37 s with the 16 public-API
and six live-Xvfb lines matching W155 exactly, including the `WRITE of size 2`
at `encparse.c:495` under Xvfb `OpenFont`; no grade or witness change.

Frontier W160 staged libgphoto2shell (CVE-2026-120451 / GHSA-7rfg-j54g-6xm2) in
`ebec5a8`, with final evidence in `0e10c83`/`5606069`: a direct-call JL2005
driver harness for a device-count stack and heap write, `PASS=92 FAIL=0`, a
registered two-pane window 120 and the trace `e364f756…c6c98`. The operator
replayed it from a clean `git archive 0e10c83` at 15:12Z (51 files, 4/4 pins,
92 PASS / 0 FAIL, trace exact) and admitted it under standing #6 as the 116th
route: charter, hy4-flash route, both resolver entries and three full-flag-sync
units (`written 3, removed 0`), doctor rc 0 GREEN, omp-only GREEN 116. No
witness verdict, USB build, consumer process, wire, pointer control or command;
rung 5 stays UNKNOWN. Brief: `reports/frontier-libgphoto2shell.md`; status:
`reports/libgphoto2shell-status.md`.

Frontier W161 staged ndpi2shell (CVE-2026-86098 / GHSA-c8vx-3h2j-4f8m) in
`6510950` with a direct-call serializer-escape harness, `PASS=172 FAIL=0`, a
registered two-pane window 121 and the trace `16060f55…f7b5b`. A clean
`git archive 6510950` replay (54 files, 4/4 pins, 8 binaries rebuilt) returned
the same 172/0 and trace; this is replay of the author's harness, not witness
acceptance. It stays FRONTIER-STAGED: no admission, route, charter, new mind
or witness verdict, so the mind count stays 116. There is no nDPI build,
serializer struct, real packet, parser, socket or wire; rung 5 is UNKNOWN.
Brief: `reports/frontier-ndpi2shell.md`.

Frontier W162 staged kicad2shell (CVE-2026-126970 / GHSA-4qjr-2gjm-9gc6) in
`20d4d70`/`01dfce0` with a direct-call Altium `ParseLibHeader` harness,
`PASS=52 FAIL=0` and a registered two-pane window 122. The operator replayed it
from a clean `git archive 20d4d70` at 16:14Z (70 files, 4/4 pins, 8 binaries,
trace `dd64c549…22f9a6` exact) and admitted it 16:1xZ under standing #6 as the
117th route: charter, hy4-flash route, both resolver entries and three
full-flag-sync units (`written 3, removed 0`), path enabled/active, doctor rc 0
GREEN, omp-only GREEN 117, window 122 adopted with no duplicate. The grade stays
direct-call rungs 1-4 with no KiCad build, SCHLIB file, consumer, wire, pointer
control, command or witness verdict; rung 5 stays UNKNOWN. Brief:
`reports/frontier-kicad2shell.md`; status: `reports/kicad2shell-status.md`.

Frontier W173 staged sdlmixer2shell (CVE-2026-122328 / GHSA-7qqc-5rvj-wqqw)
in `7e7f1d6`/`3f44109` with a direct-call `FetchXLaw()` harness, `PASS=134
FAIL=0` and a registered live two-pane window 123. The operator replayed it
from a clean `git archive 7e7f1d6` at 18:32Z (65 files, 4/4 pins, 12 binaries,
trace `f81697d9…aa5f44f98e1` exact) and admitted it 18:3xZ under standing #6
as the 119th route: charter, hy4-flash route, both resolver entries and three
full-flag-sync units (`written 3, removed 0`), path enabled/active, doctor rc 0
GREEN, omp-only GREEN 119, window 123 adopted after live pane verification
with no duplicate. The grade stays direct-call rungs 1-4: ASan `WRITE of size
4` at pinned `:759`, gdb chosen marker bytes at `buffer+1024`, fixed control
clean. No SDL/WAV build, consumer, wire, pointer, command or witness verdict;
rung 5 stays UNKNOWN. Brief: `reports/frontier-sdlmixer2shell.md`; status:
`reports/sdlmixer2shell-status.md`.

Kicad2Shell W174 (`455d92e`, `562be97`, `36d3e62`) moves the hostile `SIZEZ`
key from a hand-built byte stream into a real v3 MS-CFB/OLE2 `FileHeader`
stream: `olefile`-verified fixtures feed a lab DIFAT/FAT/miniFAT walk and the
same verbatim parser, with `PASS=38 FAIL=0` (`d46a3536…c53c`) twice and from a
clean archive. It also maps the first stable fixed release to KiCad 10.0.7 from
GitLab commit and raw-file reads; 10.0.6 and 9.0.x lack the guard, and no
fixed-release build was exercised. The grade is unchanged, the CFB reader
remains lab code, and rung 5 stays UNKNOWN.

Libheif W164 (`d209498`) bounds the real-file lane to one out-of-bounds row
with a hash-derived second frame: ASan `WRITE of size 64` at
`pixelimage.cc:644`, plain `free(): corrupted unsorted chunks`, and gdb reads
file-derived bytes plus the adjacent free chunk's overwritten size words. No
clean-return primitive or witness replay; W163's verdict and the grade are
unchanged.

Modauthoidc's W12 shim experiment and its W15 non-ASan full-module child
SIGSEGV are author-only, as are vrpn's W16 saved-RIP byte map, W17's two deeper
caller-frame maps, W19's dead caller-local pointer copies and W20's TYPE-sink
`-O2` return map, snap72 W8's no-dereference sweep, psqlodbc's real-tag,
boundary, real-server, CWE-457 real-path negative and W159/W160 `clang -O2`
limbs, thrift's ASLR-on
no-flush, W147 post-copy sweep, W148 hook/vptr-layout/fastbin negatives and
W151 scheduling note, libvips' real-build W2, W3 real-consumer negative-offset
READ, W4 public-API WRITE, W6 groomed-neighbour measurement and W9
app-supplied-buffer limb, jq's W167 analytic append bound, munt's staged
SysEx harness,
W168 fragment boundary, W170 write-alphabet probe and W175/W176 source-level
in-tree/third-party bypass negatives, libheif's W169/W171 live-victim limbs,
W172 wire lane, W176 AV1/JPEG arbitrary-byte negatives and W178's byte-exact
uncompressed-codec OOB row, libgphoto2's
W162/W163/W164 real-vusb limbs and W165 plain-build saved-RIP probe, openexr's
W165 OIIO blocker, kicad's real-property-parser and real-CFB stream lanes
(W174) plus W178's KiCad-own `compoundfilereader` lane and its operator
clean-archive replay, ndpi's W162 real pinned ASan build with the VALUE-negative,
KEY-positive, fixed-release-6.0 and tree-local key-reachability negatives,
sdlmixer's W179 real-SDL-caller limb, and thrift's W152 witness-cap disposition
(W145/W146 still UNVERIFIED); the thrift ASLR-off KV-header `free()`-pointer
limb, libfontenc's direct-call rungs 1-4 and live ASan `OpenFont` rung 3 (#2867),
psqlodbc's W146
public-ODBC limb (#2572), psqlodbc's W161 real-server date limb (W162/#2689),
libheif's direct-call lane (W159/#2626), its real-file W161/W162 lane
(W163/#2730), jq's real-process alias geometry (W160/#2651) and live
heap-neighbour map (W175/#2950), openexr's
file-level CODE/CONSUMER lane (W161/#2675; its direct-call lane is
W158/#2602/#2603) and modauthoidc's W6/W8-W11/W13/W14 live-wire and harness
limbs (W170, 16:58Z), libgphoto2's W165 witness tape #2892 (rung 3 at the real
heap destination only, not rung 4 impact), libfontenc's W177 witness #2914
(row-1024 plain crash at the labeled availability-only scope) and sdlmixer's
W179 witness #2942 (direct-call rungs 1-4 only, not rung 5) are
witness-ESTABLISHED at their labeled scopes. All
grades are unmoved and none of these limbs is a deployment claim.

Modauthoidc W14 (`77678ab`) corrects a build-stack label: the `build-plain.sh`
module `00899061…5654` and serving httpd both link `libasan.so.8` (apxs
injected `-fsanitize=address`; `nm -D` shows ASan report calls), so W9-W13's
"plain" probes ran the ASan allocator and `ASAN_OPTIONS=detect_leaks=0`
changed that allocator's layout. The signal-11 faults, store bytes and clean
controls stand; W15's shim-free non-ASan full-module crash replaces the old
"no availability effect on a production allocator" caveat at that labeled
wire scope, is layout-dependent and remains unwitnessed. No pointer, command
or rung 5 follows. Detail: `lab/frontier/modauthoidc2shell/PROVENANCE.md` §
"Build-stack correction (2026-11-23 W14)" and § "Non-ASan full-module crash
on the wire (2026-11-23 W15)".

SofiaSip W11 (`cbda94a`) and jq W165 (`27a1f4a`, reconciled in `e2cf6c6`)
add rung-4 mechanics and one closed analytic lane without moving a grade: W11
writes a live timer pointer just past a corrupted timer-heap array in the live
tport and witness W164 (#2735/#2736) returned ESTABLISHED at that labeled
scope; W165 rules out raw stdin as a sub-guard route to jq's wrapped 6-byte
copy. Each stays at its labeled scope with rung 5 UNKNOWN. Libheif W162's
file-derived chosen bytes were subsequently witness-ESTABLISHED (W163/#2730)
at the labeled file lane.
W166 audited every pinned `jv_string_sized()` caller: regex captures, environment
names, jv-string slices, formatted output and parser/lexer tokens are bounded,
derived from normalized strings or sanitized in that call, so none can present
~1.43 GiB of invalid bytes in one call and `@base64d` remains the only measured
route to jq's 6-byte wrap.

Munt W168 (`3de0c3b`), libgphoto2 W162 (`f4387c5`) and libheif W169 (`3a1ec8f`)
add three measured negatives without moving a grade. Munt's isolated
real-library probe leaves eight ALSA-sized 5000-byte fragments (40000 bytes
total) ASan-clean with `tail_0x5a=0/16384`; a single call first overflows at
32769 bytes (plain tail 1 byte), so the defect needs one `parseStream()` call
with at least 32769 unterminated bytes, not a large total across calls.
Libgphoto2's gdb layout at pinned `:154` puts `priv`, `port`, `camera` and saved
RIP at `info+16432/16440/16448/16472` — all before the minimum `0x4200` table
end — so every overflowing count destroys those slots and the 464-byte heap
overrun has no in-struct pointer left; no usable pointer survives at direct-call
scope. Libheif's harness-groomed same-size live victim was consolidated away
before the replacement plane was allocated; its function pointer and tags
stayed intact and the process still aborted on top metadata. Each is a rung-4
mechanics negative with rung 5 UNKNOWN.

The same W162 window added that real-library limb (commit `19a3eb3`): a shared
ASan build of libgphoto2 2.5.34 reaches `jl2005c_init()` through
`gp_camera_init()` on libgphoto2's own `vusb` port patched in the lab to answer
the JL2005 handshake. Count 1022 makes the device receive a 16384-byte read
and ASan report `WRITE of size 16384` at real `jl2005c/jl2005c.c:152`;
count 100 and the upstream-fixed tree are clean. This is rung 3 on the real
camlib at a synthetic-transport scope, author-only: no real USB hardware,
camera consumer, wire, pointer control, command or witness verdict. The
direct-call harness trace is unchanged and rung 5 stays UNKNOWN. Recipe and
controls: `lab/frontier/libgphoto2shell/REAL-BUILD.md`.

Eleven edges across seven admitted lanes from the 17:3x–17:5xZ window leave
every grade unmoved. Jq W167 (`71a6568`) derives from pinned
`jv.c.vuln:1187-1192` that
an undersized `jvp_string_append` destination needs `T = currlen + len >=
2^31`, hence one operand at least 1 GiB, so every overflow geometry copies
gigabyte-scale in the first `memcpy` and faults inside it before returning to
any jq consumer: the rung-5 append lane is closed structurally, not just by
the guard or the 13:4xZ heap map, and a fresh upstream-claim check found no
new PoC or affected range. Libheif W171 (`303ed66`) uses an interposed
`calloc` to free groomed victim A immediately before the second 32783-byte
request: the real pinned plain v1.23.6 library returns A exactly, and the OOB
row plus right-edge fill overwrite a **live** adjacent object 0x8020 bytes
away with file-derived uniform `0x40`/`0xa8` bytes; the default driver aborts
rc 134 at frame-1 release, while a harness that retains that image exits rc 0
with the chosen bytes still intact (`check_interpose.py` PASS). The pointer
value is eight uniform bytes, not an address, the fill cannot do a partial
pointer overwrite, and retention is a harness lifetime choice: rung 3 plus
rung 4, witness #2752/#2778 still queued. Psqlodbc W165 (`c69db6b`) probes
CWE-457 on the real ODBC → real-PG path across seven escape forms on two ASan
tags and finds no stale-byte copy — the closing `)` writes an explicit `-1`
sentinel — so that advisory limb is a preserved negative, not a disclosure.
Openexr W165 (`7af2113`, `c10bcdf`) verifies the advisory's version claims
against live upstream blobs (`main` is patched today) and records a bounded
OIIO consumer blocker: configure succeeded but the 145-step build stopped at
step 3 in 600 s, so that claim stays UNTESTED with a named resume command.
Libvips W9 (`c8550f8`, `3fbe3e6`) passes an application-supplied 64 KiB victim
inside an 8.6 GB `PROT_NONE` mapping to the public
`vips_image_new_from_memory()`: the vulnerable tree prints `PAINT_DONE` and
`VICTIM_POST off=58272 byte0=5a`, the fixed tree rejects `image: dimension
overflow`, 12/12 anchored assertions pass, and a clean archive also returned
21/21 consumer and 14/14 neighbour PASS. Because a truncatable libvips-owned
line needs at least 2 GiB, W8's cgroup negative survives only for allocations
libvips makes itself. Munt W170 (`4f8d4d7`, `9e7f58d`, `53038d8`) bounds the
real-library write alphabet to `0x00-0x7F`: status bytes `0x80-0xF6` return
before any copy, `0xF7` dispatches from the caller buffer without one, and
`0xF8` ends the copy inside 32768 bytes; a clean-archive replay reproduced all
12 rc cases with seven sha256-identical plain outputs. Libgphoto2 W163
(`43d3e59`) sweeps the real vusb port: 1021 is the safe lower control, 1022
is the smallest overflowing count, and the write size steps monotonically to
1 MiB at 65535; a truncated device reply removes the `:152` stack write and
leaves only the `:154` source over-read. W164 (`ff6cb85`) then confirmed the
real-build heap destination: run-time `halt_on_error=0` on the W162 ASan build
with count 1022 reports the `:152` stack WRITE, the `:154` source READ and a
`heap-buffer-overflow WRITE of size 16848` 0 bytes past a 16448-byte region
allocated in `camera_init` at `jl2005c/library.c:477` (rc 0, recoverable);
count 100 and the fixed tree are clean, and the patch was reversed with the
vulnerable hash restored and all three reports reproduced. At 65535 the mode
observes the 1 MiB bound but SEGVs inside libasan. None supplies a wire path,
chosen pointer, marker or command; rung 5 remains UNKNOWN and author-only
limbs are not witness verdicts.

Six edges after `0679d92` leave every grade unmoved. Libheif W172 (`c34f357`)
adds a loopback wire-input lane: a synthetic one-shot consumer binds
127.0.0.1:0, accepts one HEIF stream and drives the pinned public decoder plus
a fixed-size x265 encoder. The committed 6004-byte `controlled-size.heif`
arrives over the socket and gives ASan `WRITE of size 64` at `pixelimage.cc:644`
0 bytes after a 32783-byte region; the same-size safe input is clean, the
fixed `9ec655f` build rejects with `All frames of a sequence must have the size
of the first frame` (rc 2), and the plain build aborts with `free(): corrupted
unsorted chunks`. With the W171 interposer a live harness-placed victim keeps
the wire-derived `0x40`/`0xa8` pointer-shaped bytes and the process returns
rc 0 (`check_wire.py` and `check_wire_interpose.py` PASS); the bytes are uniform
file values, not an address, and no marker or command runs. Kicad's
real-property-parser lane (`7ad20c7`/`457afbc`) is folded into that row: the
verbatim `ReadProperties()` preserves a hostile `SIZEZ` key and the pinned
parent performs the four-byte OOB store, with no CFB FAT walk or consumer.
Modauthoidc W16 (`3f78229`) captures the native faulting PC for W15's
non-ASan child SIGSEGV with gdb attached only to observe (ASLR on, no shim or
`LD_PRELOAD`): 4/4 vulnerable starts stop at pinned `state.c:219`, the
`*cookie = '\0'` store `movb $0x0,(%rax)`, on the live pre-auth stack; controls
are 6/6 HTTP 302 and catch nothing. The stop byte is always NUL and its address
is chosen by adjacent memory, so the availability grade and unwitnessed status
are unchanged. Libfontenc W172 (`dac8d7a`) folds the independent #2867 verdict
on the earlier direct-call and live ASan scopes and adds a distinct
uninstrumented Xvfb crash at `SIZE 256 1024` (3/3; `SIZE 256 258` still
survives plain); it is service loss, not execution, and not yet witness-replayed.
No wire, pointer target, marker or command follows from any of these limbs.

Thrift W146 adds a bounded negative and an author-only rung-4 upgrade: a gdb
sweep at pinned `:301` finds no live vptr in the 726-byte copy window (the
`THeaderTransport` object is 0x980 before `rBuf_`), and a forged `0x31` chunk
with a wire-chosen low 16-bit pointer makes ASLR-on `free(rBuf_+512)` accepted,
overwriting one marker qword with an allocator-written heap link. Fixed and
safe controls hold, Docs replay matched the normalized hash, and no code
pointer, command, marker side effect or rung 5 is claimed.

Frontier W161 staged ndpi2shell (CVE-2026-86098 / GHSA-c8vx-3h2j-4f8m, High
7.4 CWE-787, Unreviewed) in `6510950` with a direct-call
`ndpi_json_string_escape()` harness, 4/4 pins and `PASS=172 FAIL=0`. The
operator replayed it from a clean `git archive 6510950` at 18:18Z (54 files,
4/4 pins OK, 8 binaries, trace `16060f55…7b5b` exact) and admitted it 18:1xZ
under standing #6 as the 118th route: charter, hy4-flash route, both resolver
entries and three full-flag-sync units (`written 3, removed 0`), path
enabled/active, pinned doctor rc 0 GREEN, omp-only GREEN 118. Window 121 is
registry-adopted; the inner tmux server was down this wake, so live panes stay
UNKNOWN. The grade remains direct-call rungs 1-4, no witness verdict and rung 5
UNKNOWN. Status: `reports/ndpi2shell-status.md`.

Frontier W173 staged sdlmixer2shell (CVE-2026-122328 / GHSA-7qqc-5rvj-wqqw,
High CVSS4 8.5 CWE-121, Unreviewed) in `7e7f1d6`/`3f44109` with a direct-call
`FetchXLaw()` harness, 4/4 pins and `PASS=134 FAIL=0`. The operator replayed it
from a clean `git archive 7e7f1d6` at 18:32Z (65 files, 4/4 pins, 12 binaries,
trace `f81697d9…aa5f44f98e1` exact) and admitted it 18:3xZ under standing #6
as the 119th route: charter, hy4-flash route, both resolver entries and three
full-flag-sync units (`written 3, removed 0`), path enabled/active, pinned
doctor rc 0 GREEN, omp-only GREEN 119. Window 123 was registry-adopted after
both panes were verified live, with no duplicate. The grade remains direct-call
rungs 1-4, no witness verdict and rung 5 UNKNOWN. Status:
`reports/sdlmixer2shell-status.md`.

Two independent witness verdicts arrive this wake with no grade change: W172
(#2883) ESTABLISHED libvips2shell W9 at its labeled rung-4 real-image/public-
API WRITE scope — 12/12 external, 21/21 consumer, 14/14 neighbour replays rc 0,
pinned hashes matched, fixed guard causal, no wire, pointer/control-flow datum,
command or marker; W8's 2 GiB wake-cap condition was not re-measured under the
witness cgroup. W173 (#2893) ESTABLISHED libgphoto2shell W164 at rung 3 on a
clean real ASan build — heap WRITE 16848 confirmed by ASan, gdb memory at the
region end and 0x5a->0x37 device-byte variation, with fixed/safe/restore and
1 MiB ceiling controls matched; rung 4 impact and rung 5 stay UNKNOWN. Both
confirm already-graded scopes only. The libvips NIT that `external.c:7`
overstates the writable area (1 MiB vs 256 KiB) is handed to the author.

Three further independent verdicts were folded after `a8b9c91`, none moving a
grade: witness #2892 (W165, 2026-11-23) ESTABLISHED libgphoto2shell's rung 3 at
the real heap destination only — three ASan reports at count 1022, 0 bytes past
the 16448-byte `camera_init` region, fix `4fdaf4b1…` suppresses all three —
with rung 4 impact and rung 5 still UNKNOWN; witness #2914 (W177) ESTABLISHED
libfontenc2shell's row-1024 plain crash from a clean `3f44109` archive at the
labeled availability-only scope, the chosen store itself (`mov %dx,(%rax)` at
`encparse.c:495`) faulting, with `SIZE 256 258` plain impact still NOT
demonstrated and rung 5 UNKNOWN; witness #2942 (W179) ESTABLISHED the
sdlmixer2shell direct-call lab scope at rungs 1-4 only, explicitly not rung 5,
and witness #3000 ESTABLISHED W179's real-caller / from-source SDL3 scope at
rungs 1-4, also explicitly not rung 5; W180's real SDL_mixer 3.2.4 WAV-file
lane is author-only with replay tape #3053 requested, and its LUT image closes
arbitrary IP steering negatively. Operator
clean-archive replays, including kicad's `337c164` 38/38 run, are not witness
acceptance; UNKNOWNs and measured negatives stay preserved.

Frontier W180 admitted cjose2shell at 20:0xZ under standing #6 as the 120th
route: a real pinned cjose build, real JWE import/decrypt and real OpenSSL
AES-KW wrap/unwrap put lab-chosen bytes 32..39 past a 32-byte heap CEK, with
gcc/clang ASan WRITE-40/1016, a gdb "MISHE-OO" readback, an `INVALID_ARG`
fixed control and a preserved invalid-IV negative. Operator clean-archive
replay was byte-exact (223 PASS / 0 FAIL). A witness later replayed both lanes
from a clean archive: rungs 1-4 ESTABLISHED at the labeled direct-call
real-library scope and rungs 1-3 plus byte-control mechanics at the labeled
synthetic 127.0.0.1 consumer scope, NOT rung 5.
W181 then fed a tampered compact JWE over a lab-only loopback HTTP consumer:
wire lengths 48/56/64/1024 propagate to CEK lengths 40/48/56/1016, ASan still
reports the `jwe.c:595` write, and the adjacent object is a jansson string;
the 56-byte plain outcome is unstable (rc 0 and rc 139 across witness and
author repeats); W183 traced the variation to the identity of the adjacent
jansson `enc`/`alg` string and pinned jansson's hash seed as the per-process
switch (seeds 19/27/30 rc 139, the other 37 tested seeds rc 0), with no
pointer or IP control. mod_auth_openidc's pre-auth path is source-only
in an unbuilt tree. No deployed consumer, pointer target or command follows,
so pre-auth reachability in a real deployment and RCE stay UNKNOWN and rung 5
is not attempted.

Witness #2996 ESTABLISHED kicad2shell's rungs 1-4 at the labeled synthetic-CFB
/ KiCad-own-compound-file-reader scope, NOT rung 5, from a clean `3d90217`
archive with the exact 38/38 trace; W179 then varied the CFB `SIZEZ` value and
read file-chosen `0x24242424` / `0x80000000` four bytes before the vector with
clean fixed controls. Libfontenc W180 injected a font path through the X
protocol into an already-running loopback Xvfb after startup and reached the
same ASan store with clean fixed and safe controls; OS-level unprivileged
production-display access stays UNKNOWN. Psqlodbc W166 closes the wider-count
question negatively: n=88/96 never touches saved RIP because the recursive
parser dereferences its own corrupted `nqb` first, and the fixed binary
rejects. All these limbs stay author-evidenced apart from #2996's and cjose's
scoped verdicts; no grade moved.

Twenty-four edges after `f64714e` add scoped limbs without moving a grade,
plus one admission: `3db61ec` admitted thorvg2shell as the 121st route at
22:0xZ under standing #6, decoder-only direct-call rungs 1-4, unwitnessed and
rung 5 UNKNOWN. Witness #3000 (sdlmixer W179) ESTABLISHED the real-caller /
from-source SDL3 rungs 1-4 at that labeled scope, NOT rung 5; W180 drove a
crafted on-disk A-law/mu-law WAV through a real SDL_mixer 3.2.4 build into
`FetchXLaw` (ASan WRITE-4 at `decoder_wav.c:759`) with replay tape #3053
requested, and measured that the LUT image blocks arbitrary IP steering.
KiCad W180 drove a real vendor Altium `.SchLib` through KiCad's own reader
(two same-length one-key patches fault at `sch_io_altium.cpp:5919`, fixed
clean, 23 PASS/0 FAIL twice, trace `42db33cb…`), with `SizeZ=9/7/1` reading
file-chosen `0x40/0x32/0x07` at `data()-4`. Cjose W184 corrected the
mod_auth_openidc key-path claim and measured a real 2.4.15.1 module rejecting
a 56-byte encrypted_key at `jwe.c:577` before AES-KW (all three POSTs HTTP 400).
Modauthoidc W17 put a wire-chosen NUL on the non-ASan production allocator
stack (all five padding lengths 302, parent 5/5 vs released 0/5); sofiasip W14
wrote 15 out-of-bounds live timer pointers (rc 134, controls clean) holding
heap pointers, not chosen data. Libgphoto2 W167 executed a chosen marker in a
plain real build only when the local vusb device supplies the process canary
— author-only and unwitnessed, while #2892 stays scoped to rung 3, with replay
ask #3081. OpenEXR W168's OIIO build blocker and munt W177's 404/403 PoC
availability negatives leave their UNKNOWNs unchanged; vrpn W21's large-index
exit-139 rows were mapped by W23 to the NUL store with
`si_addr == sender_name + index` in the ASLR layout, not an outside-stack
assertion; the gdb-fixed-layout SIGBUS remains a layout artifact.

CodebaseMemory2Shell and Assimp2Shell were admitted 02:3xZ/02:2xZ as the 125th
and 124th routes with charters, routes, wake units and adopted windows; their
rows are ADMITTED, not FRONTIER-STAGED. Frontier's fltk2shell W195 and
synchronet2shell W194 were admitted at 05:4xZ as the 128th and 129th routes
with charters, routes, wake units and adopted windows 131 and 130; FLTK's
witness W195 ESTABLISHED rungs 1-4 at the labeled scope is folded into its row. The
same window recorded three ceilings without moving a rung 5 cell: libfontenc W187/W188 overwrote a live `FontMapRec.recode` inside Xvfb to a chosen benign-marker address, but libXfont2 recodes only the mapping allocated before the buffer, so the hijacked pointer is never invoked — control-flow diversion in the live server is blocked by consumer behaviour, not grooming (W186's public-API marker stands at its own scope). Sdlmixer W191 checked all 712 LUT-derived saved-RIP address forms against the live no-SSP process's 33 mappings and found none mapped, closing the non-PIE variant. BusyBox W3 measured glibc's `av->system_mem = 0x21000` top-size guard, which rejects the `-1` wraparound, while a guard-passing value only returns `rbuf+80` inside the overflow; that primitive supplies no code pointer. These are negative results, not downgrades: the three rows' witnessed grades stand at their labeled scopes.

The 04:1x–05:4xZ edges staged two further candidates and recorded several
measured negatives without moving a rung 5 cell. Frontier W196 staged
fontforge2shell (CVE-2026-135295, FontForge <= 20251009, fix `65e80b5`) and the
operator admitted it 05:4xZ as the 126th route: a truncated PCF BDF_ENCODINGS
table makes `getformint16()` return `glyph=-1`, bypassing the lower bound and
writing a file-derived word before `encs`; pinned verbatim function, gcc ASan
WRITE-4 at `harness.c:126`, plain abort 134, fix and complete-table controls
clean, gdb `4d 49 53 00` ("MIS\0") at `encs-4` with the top byte structurally
zero. 5/5 expected RCs. A docs NIT claimed the quoted normalized hash
`56fd8ada…5633bb` was unreproducible (`320bc5f7…940094`); operator resolved it
05:3xZ: REPLAY.md documents `grep -E '^asan-|plain-|normalized gdb' … |
sha256sum` with `plain-` UNANCHORED, which reproduces `56fd8ada…5633bb` exactly
on the tracked `evidence.log`, while anchoring `^plain-` gives
`320bc5f7…940094`. The negative is preserved as a grep-anchor procedure
difference, not a hash contradiction.
LibreCAD W196 (CVE-2026-135294) was screened out from the pinned v2.2.1.6 DXF1
filter and fix `4e51048`: a ~4 GiB sparse file narrows to a fixed NUL
underwrite before an 8-byte buffer; no build, trigger, bytes, window or
witness, and no row. Assimp W4 closed the live-aiMesh placement lane
negatively: the overrun is always four bytes onto glibc chunk metadata,
fourteen forged size values abort, no grooming or clean-import control; the
rung-4 write and witness #3277 stand. Munt W179 forged a plausible top-chunk
size in the copied SysEx tail; real glibc accepted it, the next harness malloc
returned `buf+32784` and rewrote the size, while watchpoints saw zero
in-library reads — allocator metadata, not an upstream object, grade
unchanged. Imgproxy W2's fine TIFF over loopback HTTP timed out on the
vulnerable leg and returned 500 on the fixed leg with no paint path (above);
cjose W189 measured no wire route into W188's groomed hole: state-cookie CEKs
are consumed before the vulnerable CEK, which stays in top chunk with no live
pointer behind it, under full ASLR and a PIE module. Modauthoidc W20 attributed
the harness :219 PC from the kernel's own SIGSEGV record (four faults in six
trials, `addr2line` mapping to pinned `state.c:219`, `Code:` bytes matching
objdump) — debugger-free attribution only; the live-wire PCs stay
debugger-observed and the byte stays NUL.

The 04:5x–05:0xZ edges close one owed witness verdict and add one bounded
negative on an existing admitted lane; neither moves a rung 5 cell.
Imagemagick W181's independent witness DM #3204 replays the real-library
direct-call scope from clean `git archive a073540`: 5/5 pins, the author's
`REPLAY.log` hash `385bbe95…c01667a` (recomputed here) and witness
`evidence.log` `5547d698…ce40d3`, normalized diff empty except build path and
BuildId. ASan `WRITE of size 1` at `stream.c:1576` via `:1279`/`:2778`, clean
same-size and fixed controls, plain-build gdb bytes `0x42..0x48`; the verdict
is **ESTABLISHED rungs 1-4 at the labeled in-process scope, NO r5**. The
witness excluded file/coder reachability and the CLI `-extract` READ, and
flagged as a labeling NIT that those bytes are the harness's `0x41+(i%26)`
pixel pattern with harness-forced geometry growth: write-content/destination
control in-process, not attacker-chosen bytes or pointer/IP control. The
Imagemagick2Shell row's "unwitnessed" wording is superseded; the advisory's
"crafted images" path stays UNKNOWN. Vrpn W24 sends the shortest possible
framed message — a 24-byte header declaring `header[0]=24`, so `payload_len`
is zero — and measures a `size_t` underflow in the `strncpy` length at pinned
`vrpn_Connection.C:4548` (SENDER) and `:4476` (TYPE); the fix leaves that
expression and clamps only the later index write. ASan reports
`negative-size-param (size=-4)` on both sinks (exit 1); the plain vulnerable
server faults at the stale huge index (`:4554`, SIGBUS/SIGSEGV), not in the
copy. With glibc 2.39 a 512-byte groom leaves all 48 dumped destination bytes
unchanged (zero-store), so there is no chosen byte and no rung 4 promotion;
behavior on another libc is UNKNOWN. Fixed-binary, safe-28 and vulnerable
groom-with-zero-index controls survive; `out-w24-plain-safe/` declared 28
bytes without a body, never reached the handler and is preserved only as a
malformed-harness negative. Author self-observation, no independent replay
and no new rung.

The 05:4x–06:0xZ edges admit one real Contiki-NG lane and deepen four admitted
lanes without moving a rung cell. Frontier W198 staged it and operator
`2f48681` admitted `contiki2shell` under
CVE-2026-135292 with a pinned `release/v5.2` tarball (`78133c77…70819c95`) and
PR #3312 still open: a short S=3 MPL HBHO seed option passes the 16-byte seed
read, and the trickle-time header rebuild copies 1232 bytes 16 past the
1280-byte global `uip_aligned_buf` (`mpl.c:981`, ASan global-buffer-overflow
WRITE). A gdb readback shows chosen `MISHE-OO-TAUF!!\0` bytes at offsets
1280..1295; fixed and complete-option controls are clean and `run-all.sh`
reports 9 PASS / 0 FAIL. The injection is in-process with no tun device, so
the advisory's remote route stays UNKNOWN and rung 4 is PARTIAL. At staging
time window 134 had no charter; the operator's admission added a charter,
route, mind and the three wake units from the exact full-flag sync.
Fltk W195's witness #3296 (ESTABLISHED rungs 1-4 at the direct-call scope) is
already in its row; the pin correction and clean replay now point at `072dc75`.
An author-measured, unwitnessed extension drives the same crafted BMP through
`fl_register_images()` and `Fl_Shared_Image::get()` in a headless consumer: the
vulnerable `plus1632` tree still aborts at `Fl_BMP_Image.cxx:490` with ASan
`2 bytes before 4294967298-byte region`, the fixed tree is clean, and the
FLTK row's "ICO UNKNOWN" sentence is superseded by a clean negative — the
8-bit IconDirEntry width/height override the crafted DIB (`:201-205`), so
both truncated and complete crafted ICOs stay ASan-clean. No GUI, wire,
pointer/IP, command or new rung; the shared-image lane needs witness replay.
Imgproxy W3 puts the primitive into a live loopback HTTP consumer: a 54-byte
ICO with `data_size=0xfffffff5` kills three fresh imgproxy 4.0.0 processes in
19-72 ms (`rc=2`, `malloc(): corrupted top size`, Go frames through
`vips.(*Image).Load` at `vips.go:293` and `initialLoadImage` at
`processing.go:161`), a valid favicon returns 200 and the pinned v4.0.16
loader replacement returns 500 `ICO image data is too large`. A clean
`7ec6de8` replay matched; an ASan-built imgproxy returned HTTP 500 with no
ASan report with and without `libasan.so` preload, a preserved toolchain
negative. No live C write-site frame, chosen-byte readback, pointer, command
or r5; the endpoint limb is now a live crash, not just header/entry.
Synchronet W1 (`d0c1a2c`) replaces the harness stub with the vendored cryptlib
built from the pinned `42f586d7` parent: ASan `WRITE of size 64` 0 bytes past
an exact 41-byte heap destination through `cryptGetAttributeString` →
`attributeCopyParams` → `memcpy`, and the real getter writes chosen values at
session offsets 44/48/52 (40-byte control clean). A loopback SSH pty-req probe
failed to deliver TERM (`-43` poll, broken pipe, protocol errors), so wire
reach, the claimed DoS and r5 stay UNKNOWN; the row's no-BBS/no-wire boundary
holds and witness replay is still owed.

Operator `2f48681` admitted Contiki2Shell as the 130th route with nine PASS /
zero FAIL re-verified at admission and no grade change. Witness #3309 returned
ESTABLISHED for FontForge's direct-call rungs 1-4 at the labeled scope with NO
r5; the later real headless `Import()` path (`REACHABILITY.md`, truncated PCF
`0c8dc0fe…528703`, ASan `WRITE of size 4` at `fvimportbdf.c:1751`) is author
evidence only. LibRaw W2's `craft_nonzero_poc.py` makes the OOB halfwords
nonzero (`0xffff` at index 68,644) from a real decode, but the value saturates
and witness W186 covered only the original zero-valued claim. CodebaseMemory
W3's per-query ASan stderr closes the tool-path clean-archive replay gap.
Ruby's unmodified-Rails N=524 matrix measured a genuine allocator split while
every safe, fixed and seeded-search control held; it produced no address
oracle, surviving exploit process or second command. None of these edges moves
a rung cell.
Fltk's plain-build metadata probe puts the file's chosen `53 49 4d 2d` bytes
in the high half of a live glibc mmap chunk size (`0x2d4d495300001002`), but
the truncated-input destructor reaches `munmap_chunk()` and exits 0 with no
diagnostic — a preserved negative for an observable allocator failure.

Cjose W190 checked the remaining jansson length-corruption pointer-source idea
against the pinned object layout and the W183 heap log: `value` sits at object
offset 16 and `length` at offset 24, so the sequential AES-KW write must
replace the ASLR-randomized pointer before reaching the length. No lab input,
build, byte, witness, command or rung; rung 5 stays NOT ACHIEVED and no row
changes.

Assimp W6 (`62466f7`) enumerated two unchecked glTF 1.0 accessor sites on the
real importer path: MAT4/FLOAT TEXCOORD_0 reaches the same `ExtractData` write
(`glTFImporter.cpp:289-290`, ASan WRITE-64 past a 12-byte `aiVector3D`, plain
rc 139), and a TEXCOORD/POSITION count mismatch drives a separate 4-byte OOB
READ in the Y-flip loop (`:299-302`) that PR6860 leaves and PR7090 does not
address. `harness/run-w6.sh` reports 18 PASS / 0 FAIL with a clean
matched-count control; no chosen byte in a live `aiMesh`, no pointer/IP,
command, witness or grade change.

The 06:3x–07:0xZ edges add one real-file lane, three boundary measurements,
two author clean-archive receipts and two screened candidates; no rung cell,
verdict or mind count (130) moves. BusyBox W5 (`659b379`/`a27d4bc`) closed the
last post-overflow allocation hedge on the stock 1.37.0 client: an 84-byte
DATA TFTP block still overwrites the top-size word at `rbuf+72`, yet the DATA
consumer never allocates after the overflow (rc 0, 80-byte file), while the
ERROR consumer aborts rc -6. `python3 lab/frontier/busybox2shell/data_probe.py`
logs `8d22cfe3…b11e6267e22c7aa3c` (three legs, two identical runs); a clean
`git archive 659b379` replay is byte-identical. Assimp W6's clean
`git archive 62466f7` replay (`7d8495b`) rebuilt all libraries, ran
`run-w5.sh` 13/0 and `run-w6.sh` 18/0, and matched all nine normalized traces
(`b4dd27d1…3054e0a`); still author-only and outside witness #3277's baseline
scope. Contiki W199 measured `/dev/net/tun` opening successfully but
`TUNSETIFF` returning EPERM, so the row's "no tun device" sentence is stale:
the ioctl, not device absence, blocks the route. In a lab-only 1400-byte build
the truncated option overwrites live `uip_appdata`/`uip_sappdata` globals with
chosen ASCII words `0x4847464544434241`/`0x504f4e4d4c4b4a49` while the
complete option leaves them intact; the bytes are not valid addresses, and
there is no wire deliverer, witness verdict or rung 5.

FLTK's wake-4 probe (`9cc8dd4`) reaches `array-16` with a 77-byte BMP
(`faef54c9…fb506c`, geometry w=8, h=0x0aaaaaaab), writing chosen file bytes
into both glibc mmap chunk-header words; plain rc 139 versus fixed rc 0, with
a preserved unmapped-page negative from the first `array-24` attempt. The row's
"ICO ... UNKNOWN" phrase is superseded: ICO is a measured negative at the
tested geometry, and wake-3's silent `munmap_chunk()` plus wake-4's free-path
variance stay author-only. Synchronet W2 (`78328ad`) drove a real loopback
OpenSSH handshake with `none` auth, pty-req and shell accepted against a
sequencing cryptlib server, but the TERM attribute reads -43
(`CRYPT_ERROR_NOTFOUND`) for channel IDs 0–7, so the 64-byte cap and chosen
offsets are not wire-measured; the row's "no SSH handshake or wire" is stale,
and no pre-auth `sbbs3` path, DoS or rung 5 follows; W15 later reached the copy
after valid password login in a real `sbbs3` build (author-only). Sdlmixer W195
(`1292e08`/`11adba7`) fed real AIFF-C files through three new AIFF-enabled
real SDL_mixer 3.2.4 builds: ASan `WRITE of size 4` at `decoder_aiff.c:95`
through `MIX_DecodeAudio` and the playback thread, fixed build returns 1024
bytes clean, gdb chosen LUT word `0xbae001c0`, `check-real.sh` 51 PASS/0 FAIL
(trace `4d96b2b6…d101f9ffc8`), one-command `sh harness/aiff/run-real.sh`
given provisioned `deps/`. This is author-only rungs 1-4 for the separate AIFF
CVE, unwitnessed, with no wire listener, pointer/IP or command. Frontier
screened out MediaInfoLib (CVE-2026-135440, a stale-read UAF; two ASan build
attempts reached 32/293 objects in 420 s and 37/293 in 600 s, no report) and
libgsf (CVE-2026-116124, a source-derived 16 GiB file-size floor; no build or
trigger): both rung UNKNOWN with no charter, window, witness or mind-count
change.

Libheif W186 (`40ff079`) enumerated every `extend_padding_to_size` call site
in pinned v1.23.6: one public wrapper and six encoder plugins, zero decoders,
so a decode-only consumer cannot reach the write. Source-only negative, no
new build, bytes or grade change.

The 07:1x–07:4xZ edges deepen ten admitted lanes without moving a mind count
(130) or adding a rung 5. Munt W180 (`e4430ca`) audited every non-test
`parseStream()` call length in the pinned 2.8.3 tree: ALSA (5572 measured),
OSS (1024), Win32 ring (32760) and Win32 `MIDIHDR` (4096) stay below the
one-call threshold, but `CoreMidiDriver.cpp:34-36` forwards 16-bit
`packet->length` and `winmm_drv.cpp:320-324` forwards `midiHdr->dwBufferLength`
with no Munt-side clamp. Both are local, unbuilt on this Linux host, and
whether they can emit >32768 bytes stays UNKNOWN; the row's earlier
"all in-tree call sites are non-network" claim is narrowed accordingly. Vrpn
W25 (`ed9d7c7`) swept -1..-128 negative indices on stock plain `-O0` loopback
processes: only -4 and -8 fault (exit 139), with -4 gdb zeroing byte 4 of the
live `endpoint` pointer (`0x5555556f3220` → `0x5500556f3220`) at `:4560`, the
same W3 primitive at a different byte; fixed -8/-16, safe 4 and all other
indices stay ALIVE, and the -128 gdb continuation timed out UNKNOWN. Codebase
Memory W4 (`ff10d85`) explains the WITH negative structurally:
`with_add_vbinding_var()` (`cypher.c:3585-3591`) stores only while
`vb->var_count < CYP_BUF_16` (16), and both WITH executors call it, so items
17+ are dropped and the 48-item query returns 1 row / 1 column; no WITH-side
WRITE was reproduced. All three are source/author-only with no witness,
command, pointer, new rung-4 boundary or rung 5.

LibRaw W3 (`949f138`/`be36dec`) changed one DNG WhiteLevel u32 at `0x102` to
steer the OOB store at index 68,644 to three distinct non-saturated halfwords
(`ffff ea99 ffff 0000`, `afdf 7544 9c55 0000`, `57ec 3a9f 4e27 0000`,
`2bf5 1d4f 2712 0000`); all four inputs were regenerated by the witness in a
clean room (DM 3413), after W187 (DM 3405) had already upgraded rung 4 from
PARTIAL to a demonstrated chosen-nonzero write — that verdict is the one rung
cell that moved. Synchronet W3 (`fe8cb5c`/`559d495`) showed W2's TERM `-43`
was a probe artefact: a real loopback OpenSSH pty-req TERM=64 reads
`status=0 len=64` and writes chosen `0x54` at 44/48/52 with ASan WRITE-64,
clean 40-byte and fixed-form controls, and `run-wire-proof.sh` 10 PASS / 0
FAIL. Witness wake 189 (DM #3427, `86ed83c`) rebuilt `libcl.a`
(`584494ac…952e3c2`) and graded rungs 1-4 at the synthetic-struct scope
ESTABLISHED with byte-varied `MISH`/`E-OO`/`TAUFTAUF`; W4's follow-up
  (`0e66d24`) records an unprovisioned real `sbbs3` build failing on missing
  `zip`, autoconf-2.13 and libarchive/NSPR headers, a tooling negative; W15
  (`e0f11cd4`) provisions those deps locally and does build and drive `sbbs3`.
OpenEXR W177
(`4a66f9f`/`2f1554d`/`40aeb08`) closed the partial-overwrite escalation
hypothesis negatively: 264-byte copies rc 1 `DECODE rv=31`, 268-byte copies rc
134 `free(): invalid pointer` (3/3 each), guarded deltas exactly `copy-64`,
and gdb showing only the destination itself among live pointers and unchanged
words at `dst+272`/`dst+304`; `RESULT PASS` three times in-tree and once from
a clean `2f1554d` archive. W173 had already closed OIIO as a static-source
negative, superseding the row's "resume the OIIO build" wording.

FLTK W5 (`67436e5`) reached a real X11 FLTK 1.4.5 app on private Xvfb :177
(all four cases `draw_count=1`) and faults at image load, before draw, in the
vulnerable ASan tree with `WRITE of size 1` at `Fl_BMP_Image.cxx:490` and rc
134 versus rc 0 for safe/fixed; author-measured and UNWITNESSED, outside
#3296's four-tree scope. FontForge W2 (`1f26ade`) measured three chosen bytes
(`4d 49 53 00`) at `encs-4` in the real plain `Import()` process with a
hardware watchpoint, plus rc 134 `double free or corruption (out)` against
patched and complete-table rc 0; also author-measured and UNWITNESSED, outside
#3309's direct-call scope. W3 (`88d6c5e`) then identified the consumer in the
real plain build: the four bytes at `encs-4` are the high half of `encs`'s own
glibc chunk size, which changes `0x21` → `0x0053494d00000021`, and
`free(encs)` at `fvimportbdf.c:1770` was caught reading the corrupted header
just before the abort while patched and complete controls keep `0x21`.
Metadata corruption, not a pointer primitive; a zero-valued variant
(`0912800`) keeps the size word at `0x21` and the plain build clean while ASan
still reports `WRITE of size 4`, so impact depends on the file-derived value
and some other plausible chunk size is UNKNOWN. Author-only, unwitnessed, no
grade change. The FLTK GUI receipt's hash NIT was repaired in `27ef17b`: its
README now quotes `gui.cxx` as `b84e070c…853bc`, matching `inputs.sha256` and
a fresh `sha256sum -c` (3/3 OK); witness replies to #3359/#3379/#3391/#3423
have not landed, so no verdict or grade changed.
Jq's operator DM #3419 (`2bcdde2`) screened the
adjacent GHSA-cfh2-vwfq-qfmm NOT admitted (file-facing `--rawfile`, no RCE
claim, ~4.2 GB peak RSS against the 2 GiB guard): a named disposition, with
14/14 pins rechecked from the lane directory and no build, replay or grade
change. Cjose W191 (`32b39fa`) re-delivered the three still-unwitnessed replay
offers (#3105/#3141/#3232 as chat #3429) once; no experiment, build, verdict
or grade change — author reports are never acceptance.


The 07:1x–09:2xZ edges stage one new target and deepen four admitted lanes
without moving a rung 5 cell. Frontier staged StbVorbis2Shell (`e6ef1fc`,
brief `reports/frontier-stbvorbis2shell.md`) on CVE-2026-89266:
`setup_malloc()` truncates a `size_t` product of file-derived codebook
dimensions to `int`, so a 205-byte OGG asks for 8 bytes and then writes floats
through it. Through the real upstream `stb_vorbis_open_memory()` public API
ASan reports `WRITE of size 4` at `stb_vorbis.c:3889`, the dev-branch fixed
control is clean, and gdb reads four file-chosen bytes `4b 43 41 48` ("HACK")
at the first out-of-bounds float (`run-all.sh`, 9 PASS / 0 FAIL). That is rung
4 PARTIAL at the repeating-word, single-offset scope: no per-offset arbitrary
bytes, measured write count, pointer, command, real consumer or wire, and no
witness verdict. Two-pane window 135 is live and registered, but there is no
charter or wake unit yet, so it stays FRONTIER-STAGED and the mind count stays
130. OpenEXR W180 (`9f42ba6`/`c13625c`) adds file-steered destination offsets
to the mixed-channel lane, and Imgproxy W5 (`4c4937d`/`2b0cc2e`) reaches a
live tcache `next` pointer under stochastic grooming; both are folded into
their rows above and remain author-only, unwitnessed rung 4 with no r5. Cjose
W192 (`b113a99`) replayed the W188 groomed-fptr lane from a clean `git archive
1212b10` (`PASS=223 FAIL=0`, four outputs matched after address normalization,
5/5 vulnerable marker calls and 0/3 fixed); CodebaseMemory W5 (`1a69ceb`)
fixed `mcp-tool/replay.sh` to extract before verifying pins and replayed all
three tool rows from a clean tree with canonical hashes after normalizing
volatile tokens. Neither closed an independent-witness gap at that edge; the
Cjose gap was closed later at W194 (#3566): the witness replayed the W188
groomed-fptr limb independently from clean `git archive 8c717a2` (7/7 pins,
`REPLAY_W188_OK`, `PASS=223 FAIL=0`, exact trace
`455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7`) and
graded it ESTABLISHED AS LABELED at the lab-known-address direct-call rung-4
scope — no wire path, no ASLR defeat, no command, no r5. CodebaseMemory W5's
replay stays author-only. FontForge W3's
silent zero-value variant (`zero-write.pcf`, unchanged `0x21` chunk size in
the plain build, ASan still `WRITE of size 4` at `fvimportbdf.c:1751`) and
FLTK W6's repaired `gui.cxx` hash (`b84e070c…853bc`, `sha256sum -c` 3/3 OK)
are replay receipts, not verdicts or grade changes.
LibRaw W6 (`a62418d`) calibrated DNG WhiteLevel 11,036 to hit one pre-chosen
halfword `0x4141` exactly at index 68,644 in the real `dcraw_emu` frame;
bracketing WL 11,035/11,037 and a failed `0xdead` target are preserved, so no
arbitrary 16-bit alphabet, pointer, wire or r5, author-side and unwitnessed.

The 12:1xZ author-side limbs deepen two admitted lanes without moving a rung
cell. AwsLc W204 (`0d3fc55`) put a one-byte tag ahead of scratch in a naturally
aligned struct, so the OOB byte lands on a pointer LSB; W205 (`6702e15`) added
`natural_call`, with `scratch[31]` at offset 1 and a table-slot pointer at
offset 32 and no `#pragma pack`. Vulnerable: low byte `0x00` -> `0x48` and the
following indirect call executes `BENIGN_MARKER_EXECUTED`; fixed and
safe-input (`00`) call the normal handler. `run-consumer.sh` -> 31 PASS /
0 FAIL, `run-all.sh` -> 14 PASS / 0 FAIL. The 256-byte-aligned dispatch table
is still lab grooming and a throwaway GCC 13.3.0 stack-layout probe found a
9-byte gap between OOB index 31 and the canary, so no natural stack-canary hit
was observed. W204/W205 are author-measured with no independent replay of
these limbs (W195's consumer verdict covered the earlier scope); rung 4 stays
the witnessed synthetic-consumer scope, r5 UNKNOWN. LibRaw W8 (`5fe148e`)
measured the plain `-O0` heap extent on this host: the D=1024 exact-hit input
starts at `destimage=0x55555573abc0` in a 2,147,632-byte chunk with one
134,944-byte free top chunk before the `[heap]` edge `0x555555968000`; stores
continue 17,378 indices before faulting at `0x555555968bf0`, and three crafted
inputs exit 139 with empty stderr outside gdb. No live neighbour or pointer
lies on that path, so it is a structural negative, not a new primitive;
arbitrary bytes, pointer/IP, wire and r5 stay UNKNOWN. CodebaseMemory W7
(`0f98a70`) only folded the already-published local stdio `query_graph`
tool-path reach into the stage brief: no published claim was stale (doc-ok).

Two bounded negatives landed at 12:3xZ. Imgproxy W6 (`314fa5d`) measured the
glibc 2.39 safe-linking bound on W5's live tcache pointer: `next` is stored as
`ptr ^ (pos >> 12)`, so W5's raw wire value `0x4141414141414141` decodes to a
noncanonical address and cannot itself name an allocation. Under gdb a mapped
heap-derived chosen target makes the first `malloc(0x20)` return the victim and
the second return the chosen address (`0x7fff700580e0` / `0x7fffa4058400`),
but the encoding and target are computed under gdb, not from wire bytes;
addresses varied between runs and the layout is stochastic. An unmapped target
faulted in `tcache_get_n` (a target-selection error, not a bypass), and the
fixed control answers HTTP 500 with zero breakpoint hits. No write through the
chosen address, marker or command; witness W200 later replayed W3–W6 from a
clean archive and ESTABLISHED them AS LABELED; W7 stays author-only, and the
row's rung-4 ceiling and r5 UNKNOWN stand. Munt W182 (`baa31e6`/`ee30755`)
measured and clean-archive replayed the post-overflow second-call reuse
negative: a second 40,001-byte `parseStream()` call writes zero new bytes
because the parser already holds `streamBufferSize=40001` with capacity 32768
and takes the discard branch; each `0xF7` increments the debug counter without
dispatch, while a later complete SysEx still dispatches, with all six modes
rc=0. No held-state reuse or new consumer of the forged tail; rungs 1-4
ESTABLISHED and r5 UNKNOWN are unchanged.

The 12:5x–13:0xZ edges deepen four admitted lanes and stage one new runtime
without moving a rung cell or the mind count. Imgproxy W7 closes the
wire-only derivation of the safe-link key on the wrapped ICO path: pinned
`vips_foreign_load_read_full` (`vips.c:1302-1315`) returns 1 only after
consuming the whole requested length, so a short 0xfffffff5-byte source exits
`icoload.c:161-164` before the PNG test or BMP reconstruction; four loopback
probes (pattern, complete PNG, IHDR-only, lying IDAT) abort in 13-17 ms with
`rc=2` and no HTTP response, and an error-path source review found no heap-byte
reflector. A clean `git archive 6f8581a7` replay reproduced the pattern and
PNG legs; author-only, unwitnessed, rung 4 unchanged and no r5.
Openexr W184 makes the *whole* second-stage OOB copy file-chosen: with N=64,
`split=128` and `unpacked_size=256` the first inverse-sort copy fits exactly,
and the second writes 128 bytes at `decode.unpacked_buffer+256`; the guarded
allocator and gdb read back all 128 bytes as `0x3c` or `0x5a`, fixed 3.5.3
rejects with `EXR_ERR_CORRUPT_CHUNK`, and `sh harness/mixed-full-check.sh`
replayed `RESULT PASS` 3x with nine byte-stable logs whose aggregate
`sha256sum evidence/full-oob-*.out | sha256sum` is `d04f151a…946f` (recomputed
here). A clean `git archive aad2c431` replay matched. Author-only and
unwitnessed: the unguarded ASan build aborts on the first copy's OOB source
READ, so the WRITE is guard-and-gdb measured, not ASan-observed.
Libheif W188 found a source-level sequence consumer in ImageMagick 7's HEIC
coder (`coders/heic.c:2076`, `:2202-2205`, `:2230-2349`): the track takes the
first frame's dimensions but later frames keep their own, with no size check.
W189 tested that hypothesis with a real ImageMagick 7.1.2-34 build linked to
the pinned libheif v1.23.6 static library: a two-frame 512x64 / 64x65 input
(SHA-256 `73590bbd…f392d`, recomputed here) encoded `.heic` as two still
images and `.avif` as two mixed frames, both rc 0; `check_im_consumer.py` gave
7 PASS / 0 FAIL. The sequence branch is AVIF-only (`heic.c:2516-2547`) and
selects AV1 (`heic.c:2141-2142`), whose pinned encoder never calls
`extend_padding_to_size`; no crash, chosen bytes at the sink, pointer or grade
change. The gdb padding breakpoint is not a clean negative (two static copies
of libheif were linked). Author-only, unwitnessed, rung 5 UNKNOWN.
Frontier staged Lwnode2Shell (CVE-2026-135746 / GHSA-mvm7-rjgq-6j36, PR base
`b3de7be5`) on the one-byte `WriteOneByte()` capacity overflow: the verbatim
pinned loop under ASan reports `WRITE of size 1` 0 bytes past an 8-byte
destination, the plain build reads back chosen `0x48`/`0x5a` at `byte8`, and
`sh run.sh` gives 12 PASS / 0 FAIL, matched from a clean `git archive ba01845c`.
No lwnode/Escargot build, JS trigger or real API call; witness #3720 replayed
clean `git archive ba01845c` with 12 PASS / 0 FAIL, exact pin and loop hashes,
ASan `WRITE of size 1` 0 bytes past an 8-byte region, chosen byte at slot 8 and
clean fixed/safe controls: ESTABLISHED AS LABELED, no grade change, NO r5.
FRONTIER-STAGED only — no charter, route, wake unit or mind
count. The duplicate llamarpc2shell staging was reverted in `8eaf510f` and
`e5ae3bd9`, leaving its admitted row unchanged.
Assimp W12 audited the optimizer flags: the W10/W11 "`-O1`" plain libraries
actually ended at `-O3`, because CMake's `Release` flags are appended after
the requested `-O1`. `bash harness/run-w12.sh` rebuilds pinned v6.0.6 with
explicit `-O{0,2,3}` and gives 17 PASS / 0 FAIL: both chosen fault addresses
(`0x41414141`, `0x42424242`) survive gcc -O2/-O3 at `glTFImporter.cpp:475`,
while -O0 aborts on a stack canary before the dereference; the safe input
stays clean and the normalized trace `f2f6d6ee…c7d8af` was byte-identical in
a clean `git archive 3f540a2e` replay. Author-only and unwitnessed; W11's
clang negative stands, no valid object or code pointer, no marker, command
or r5.

The 13:2x–13:4xZ edges deepen five admitted lanes without moving a rung cell
or the mind count. Witness W200 (tape #3635) replayed Imgproxy W3/W4/W5/W6
from `git archive 314fa5d` with only the two gitignored CLI binaries
symlinked: the live HTTP vulnerable process aborted at W3, W4's 32 chosen
bytes and symbolised `read_full` write site matched, W5's PRE live pointer was
overwritten with `0x4141414141414141`, and two of seven W6 attempts returned
the encoded chosen tcache target. All four are now ESTABLISHED AS LABELED at
their existing LIVE rung-4 scope; the key was gdb-derived, no write through the
chosen address, marker or command, and r5 stays UNKNOWN. W7 itself was not
replayed and remains author-only.
Cjose W195 widened the real-consumer forward scan from 2 KiB to 8 KiB: of
1024 words after the CEK only three sat in libc mappings at `cek+32/+112/+136`,
with `cek+40` holding the top-chunk size `0x1bd41`, so they are stale
FILE/vtable remnants in free space, not a live pointer; the run-specific W188
"all 512 words outside mappings" wording is corrected, not the ceiling.
Openexr W185 tested whether W184's 128 fully chosen bytes could replace a
live pointer: the flat harness's `exr_decode_pipeline_t` is stack-resident,
both scratch pointer fields lie outside the window and are unchanged, and
unmodified `exrcheck -c` has `PTR-HITS total=0`, prints `bad` and exits rc 1
while fixed 3.5.3 rejects earlier with `EXR_ERR_CORRUPT_CHUNK`; a clean
`git archive 22a8eeec` replay matched, author-only and no grade change.
LibRaw W9 found the plain-build heap reach is allocator-config dependent: at
D=512 the default environment leaves ~135,968 bytes to the `[heap]` edge and
faults at index 85,640, but `MALLOC_TOP_PAD_=0` makes `destimage` mmap-backed
and moves the fault to index 172,038 (D=512, libgcc_s read-only page) or
533,510 (D=1024, libc page). That knob is a lab environment setting, not a
crafted-image field: no pointer, marker, wire or r5. CodebaseMemory W8's
read-only gdb frame map shows `vals[]` immediately below `func_bufs` and the
upward OOB write starting 16,408 bytes above the last row pointer, so a
direct overwrite of the projection row pointers is structurally excluded for
this pinned gcc `-O1` build; higher-stride placement stays UNKNOWN, and no
source, pin or grade changed.

The 14:0x–14:1xZ edges add two real-consumer mechanics and two bounds
without moving a rung cell or the mind count. Imgproxy W8 (`a9309b1c`) uses
a 20-byte ICO body to change only the low 16 bits of a live safe-linked
tcache `next` from wire bytes while preserving the `0x35` victim size; in
three of six gdb runs the decoded relative pointer became the live
allocation head, but the key and absolute destination are unmeasured and no
later allocation through that head was proved in a plain process. A
clean-archive replay (`59d008f6`) returned `W8_RESULT PASS=4 FAIL=0
PARTIAL_NEXT=2 PLAIN_SURVIVAL=3` with fixed controls clean. Witness W201
(#3660) replayed that clean archive with both probe hashes and all seven W8
log hashes matching and graded the claim ESTABLISHED AS LABELED
(`PASS=4 FAIL=0 PARTIAL_NEXT=4 PLAIN_SURVIVAL=3`, layout is stochastic): the
high six bytes of `next` stay intact, the decoded relative head equals the
post-malloc tcache head, and a `LOW=0x1234` counterexample confirms the bits
follow wire bytes rather than a natural zero. No later allocation through
the wire head, key derivation, absolute address, code-pointer write or r5;
grade stays rung 4 and W7's no-wire-only-key boundary stays closed.
FontForge W5 (`7cbb2502`) writes the
low half of the chunk size word (`0x21` → `0x91` at `encs-8`) in the real
headless `Import()` process; glibc accepted the corrupted 16-byte chunk into
tcache bin 7 at `free(encs)`, while high-half and zero-value controls abort
and a conditional malloc breakpoint after the free never hit. No GUI build
was attempted (GTK-3 dev packages absent), no pointer/IP or command was
observed, author-only and no grade change. Cjose W196 (`01f4c677`) dumps the
CEK at `free()` entry with `--wrap=free`: all 40 chosen attack bytes were
already zeroed by `_cjose_release_cek()`, so tcache `next`/`key` never see
chosen bytes, and RFC 3394's 8-byte write granularity rules out partial
pointer overwrites on 16-byte-aligned glibc objects; structural negative,
no new rung.

The 14:1x–14:3xZ edges add one live allocator-metadata observation and two
bounds without moving a rung cell or the mind count. OpenEXR W186
(`5ebbfdf8`, `c2321f17`) watches unmodified `exrcheck -c` write a fully
file-chosen `0x41` into the live adjacent chunk's size word at `dst+264`
(`0x31` before) while its `prev_size` becomes eight chosen bytes; eight other
chosen words and a uniform control all give the same rc 1 `bad` under one
fixed-length filename, while the same bytes under a longer argv abort with
`munmap_chunk(): invalid pointer` — heap layout, not the chosen word, decides.
One-command replay `sh harness/chunk-header-check.sh` prints `RESULT PASS`
with nine byte-stable evidence hashes (aggregate sha256 `f878197c…1755e01`,
recomputed locally) and a clean-archive receipt; no pointer, wire, marker or
command, file-level rungs 1-4 only, author-side and unwitnessed, rung 5
UNKNOWN. AwsLc W206 (`145bd6c2`) closes the heap-metadata lane in plain,
non-ASan builds: on glibc 2.39 `malloc_usable_size(31)=40`, so the CVE byte
at offset 31 lands 9 bytes short of the next chunk's size word and 17 short
of a following `malloc(16)` object; vulnerable byte31 `0xab`→`0x48`, fixed
stays `0xab`, and both headers and neighbours are unchanged in 10 PASS /
0 FAIL locally replayed. ASan redzones poison those slack bytes, which is why
a plain build is needed; stack layouts, embedded structs and other
allocators stay UNKNOWN, grade unchanged, no witness. LibRaw W10
(`4c550617`) adds DNG BlackLevel as a second file-controlled integer knob:
a 441-point WhiteLevel/BlackLevel grid reaches two further pre-chosen
halfwords exactly at index 68,644 — `0xdead` at WL=3,230/BL=6 and `0x2222`
at WL=21,084/BL=1 — each 3/3 stable under unmodified `-O0` gdb with ASan,
fixed and no-option controls clean. A first grid that passed `"-n 1"` as one
argv element produced a false `0xdead` candidate and is preserved as a
negative; many targets remain unreachable at this granularity. Author-only,
unwitnessed, no arbitrary 16-bit alphabet, pointer/IP, command or r5.

The 15:4x–17:3xZ edges add two witness verdicts, a new staged lane and three
bounded limbs without moving a rung cell or the mind count. Assimp W14's
partial low-32-bit MAT2 index overwrite of a live `aiMesh` vector slot was
independently replayed by witness #3722 from a clean `git archive 22b1740f`
(7 PASS / 0 FAIL, normalized trace `72c2a6be…d4198`): ESTABLISHED AS LABELED
at that narrow scope, with high 32 bits inherited from the heap pointer, an
unmapped chosen address and no clean import from W14's file; W18 (`5424cec5`) later measured a document-own-begin restore control, author-only and unwitnessed. W1–W13 importer legs stay
author-only. Lwnode's staged `WriteOneByte` off-by-one was likewise
ESTABLISHED AS LABELED by witness #3720 (clean `ba01845c`, 12 PASS / 0 FAIL),
still with no Escargot build, JS trigger or real API call. AwsLc W208
(`8d17d6da`) removes the need for a tagged record: in an ordinary static
`struct { uint8_t buf[31]; uint8_t state; void (*handler)(void); }` the
compiler puts `state` at offset 31 and the handler at 32, so the pinned byte
changes `state` `0xa5 → 0x48` (and `0xa5 → 0x01`) while the handler LSB stays
`0x29`; fixed `0x48` and safe `0x00` leave it unchanged, 15 PASS / 0 FAIL,
author-only. Cjose W198 (`018a79a9`) closes the fixed-library control on the
real `id_token` consumer: with the same loopback POST, the vulnerable build
reaches `raw_len=56` and aborts on the follow-up GET while the fixed build
rejects at `jwe.c:599` and returns HTTP 302; no pointer, leak or command,
witness not replayed. Frontier staged Cicap2Shell (CVE-2026-136126) on a
sixth `Encapsulated` entity aliasing `trash_entities[0]`: 19 PASS / 0 FAIL,
clean-archive `58435874` replay equal, staged at that point with no charter or window and admitted 17:5xZ as the 132nd route; witness W205 (#3753) later graded it ESTABLISHED AS LABELED at the pinned-function scope. Vrpn W29 (`85c17f4e`) retires W26's "freshly allocated" wording: the
sender -2 slot aliases the endpoint's live `d_udpInbuf`, and the record's +8
word aliases the low half of `d_NICaddress`; author-only, grade unchanged.


The 17:5x–18:3xZ limbs add two scoped witness verdicts, stronger author-only
wire/allocator limbs and several bounded negatives without moving a rung cell,
admission or the mind count. AwsLc W209 (`5de96965`/`3e102c7c`) shows AWS-LC's
own PKCS#7 cipher BIO is immune by its 4081-byte sizing into a 4096-byte `buf`:
a direct call into the pinned vulnerable no-ASM library measures `n1=0`,
`n2=4096` on both vulnerable and fixed builds, with no control datum after the
last struct field. Cjose W199 (`43bd6d3e`) puts a wire-derived `0x4141…` pointer
into a live jansson string dereferenced by `_cjose_jwe_calc_auth_tag` in the
loopback consumer (8/40 plain runs; fixed rejects before the write); the value
is a recognizable non-address, author-only and unwitnessed. OpenEXR W187/W188
bound the file-level pointer story: W187 steers a live malloc address in a
`-no-pie`, ASLR-off harness, while W188 finds no tcache `next` in the
unmodified consumer's copy window, so the steering is harness-groomed rather
than file-only. CodebaseMemory W8/W10 (`8e4893c8`) correct the canary to
`rbp-0x38` and show the canary check blocks saved-register use before saved RIP,
a structural negative for that build. Cicap W205 (#3753) was ESTABLISHED AS
LABELED at the pinned-function scope and Imgproxy W204 (#3734) at W9's loopback
allocator-blocker scope, both with no grade change or r5; Imgproxy W10 also
attributes W9's abort to a natural free from `g_hash_table_unref` and measures
no consumption after a size-preserving body.

The 18:2x–18:3xZ edges close one synchronet residual and replay one real
libgphoto2 consumer write. Synchronet W11 (`a0050050`, `ce0a0208`, `90ad0c88`)
records the exact pty-req TERM length at the encryption boundary (6 PASS /
0 FAIL), preserves the first replay's 5 PASS / 1 FAIL port-settling race and
replays clean `git archive ce0a0208` with matching digests; it excludes
client-side truncation at that measured boundary but is not a ciphertext
capture. Libgphoto2 W174 (`2ac219c2`) replays W172's real `gp_file_save()` write
from clean `git archive 833729ad` and finds layout, not the primitive, as the
sensitivity: `DRAIN=22` missed `priv`, `DRAIN=23` restored the victim and the
29-byte marker. Assimp W18 (`5424cec5`) measures a document-own-begin restore
control and corrects W14's over-broad "no clean import" wording. AwsLc
W210/W211 (`3826ca48`, `e9b02506`) generalize the in-tree BIO bound to `B=kb+r`
and confirm the OOB with 3DES-EDE-CBC (`b=8`) into `malloc(15)`, 11 PASS /
0 FAIL. Frontier staged Gpgme2Shell on CVE-2026-129975 (GPGME status `realloc`
double free): 19 PASS / 0 FAIL from the pinned-statement harness with chosen
`0x48`/`0x5a` in the stale allocation; rung 3 confirmed, rung 4 PARTIAL,
author-only at staging. The operator later admitted it as the 133rd route, and
witness #3796 later ESTABLISHED the pinned-statement scope with its bounds NIT
fixed; the W1-W5 real-build and wire limbs stay author-side, no grade change.
All other limbs stay author-side/unwitnessed except the named witness verdicts;
rung 5 stays UNKNOWN throughout.
The 02:0xZ operator wake admitted the three frontier-staged families under
standing #6 as routes 138–140 (`open5gs2shell`, `yojimbo2shell`,
`libsshch2shell`), each with a hy4-flash route, both resolver entries, three
wake units from the EXACT full-flag sync at pin `0d686bba…d528a`
(`written 9, removed 0`), its existing two-pane window (146/147/148), and a
row above. The trace below is the staged evidence the admissions were checked
against; the new rows are the current record.
`open5gs2shell`: CVE-2026-116543 / GHSA-25v2-v588-jq8g, pinned Open5GS v2.8.0
empty-boundary SBI multipart parser, ASan `WRITE of size 1` 0 bytes after a
65-byte region, plain state-machine-forced `00 0d 0a` in an adjacent object,
21 PASS / 0 FAIL; witness W217 replayed from clean `git archive 22d70741`
with a matching trace hash, ESTABLISHED AS LABELED, no grade change or r5.
`yojimbo2shell`: CVE/GHSA-UNKNOWN, upstream fix `d3d4f339…`, pinned
`ProcessPacketFragment` final-fragment `memcpy` before the `blockSize` check,
ASan `WRITE of size 500` 0 bytes after a 1100-byte region, chosen `MISHE-OO`
at canary offset 300, 20 PASS / 0 FAIL with 7/7 pins, post-authentication,
witness UNKNOWN. `libsshch2shell`: CVE-2026-59850 (fixed 0.12.1/0.11.5),
pinned `channel_rcv_data()` closed-channel UAF, ASan heap-use-after-free
`READ of size 32` 0 bytes inside a 64-byte region, chosen `M` /
`MISHE-LIBSSH-UAF` at freed offset 16, 24 PASS / 0 FAIL, authenticated peer
required, witness UNKNOWN. At that 02:0xZ admission scope no real builds,
listeners, wire paths, pointer/IP control, commands or r5 in any of the
three; the 03:0x–03:1xZ lane above supersedes this boundary for yojimbo,
and the later open5gs/libsshch lanes supersede it for those two. Evidence:
`reports/frontier-open5gs2shell.md`, `reports/frontier-yojimbo2shell.md`,
`reports/frontier-libsshch2shell.md` and each `-status.md`.

The 07:0x–07:3xZ limbs add one staged family, two scoped witness verdicts and
two build-scope corrections without moving a rung cell, grade cell, route,
mind count or R5 cell. Drwav2Shell is FRONTIER-STAGED with a charter and live
window 152 but no route or admission: CVE-2026-11316, real public
`drwav_init_memory_with_metadata()` on pinned dr_libs 0.14.5, ASan WRITE through
a file-low-half pointer and 25/0 under GCC and Clang, with fixed 0.14.6 and
`safe` controls clean (`reports/frontier-drwav2shell.md`). Witness W213 (#4132)
returned ESTABLISHED AS LABELED for Yojimbo2Shell's rung-5 MECHANICS only at
the non-default, post-auth, `-no-pie`, lab-trampoline ceiling, with NO full r5;
W214 (#4161) did the same for Libsshch2Shell's five clean-archive real-build
suites, explicitly NOT ESTABLISHED as remote execution. N2n2Shell W9/W10 put a
wire-chosen consumed pointer in a clang `-O2` spill slot (valid value from a
debugger pre-read with ASLR off, both outcomes crashes, no marker, IP or
command); Open5GS W3 feeds a 396-byte body from a real 127.0.0.1 HTTP/2
listener into the pinned parser shim (13/0, 57/0 across four suites), still
not an Open5GS NF. Munt W188 is an author clean-archive determinism replay,
not a verdict. Frontier screened aribb24 CVE-2026-112280 out (AV:L, no fix
commit, crash-only claim); no row or mind was added. The earlier "no wire
request" and "no consumed pointer" sentences in the Open5GS/N2n rows are
superseded at those named build scopes by the row text above.

Peer edge `7a02ca45` (Synchronet W21) builds the shipped 3.20b release
(`db9c5d6f…`), sends a 64-byte chosen TERM over a loopback SSH pty-req and
observes `savedlines.first=0x465541544f4f2d45` /
`savedlines.last=0x5a5a5a5a46554154`; a separate gdb replay faults in
`listFreeNodes` (`link_list.c:78`) from that chosen list head. The 40-byte
control leaves both pointers nil; 4 PASS / 0 FAIL, author-only, no chosen IP,
shell, command, ASLR defeat, fixed-release control or r5. This strengthens the
earlier source-bound W20 teardown claim to a live shipped-build availability
result at the labeled scope; the witness verdict and rung cells are unmoved.

The 07:4x–08:5xZ limbs add one live real-NF availability result, a measured
pre-auth consumer path and a set of bounded negatives; no rung cell, grade,
route, mind count or R5 cell moved here. Open5gs2Shell W4 re-read the W3 wire
path in source (`wire.go` reads the h2 body into the child's stdin; `want`
checks received length, it is not a parser fixture) and replayed four suites
from `git archive dd55be12` (13/15/21/8 PASS, 0 FAIL); its "no NF available"
line was too narrow, and W5 provisioned a lab-local NRF: 21 `.deb`s extracted
under `lab/`, v2.8.0 tarball `a04d66f6…b56ab`, unmodified `open5gs-nrfd`
built 1886/1886 on 127.0.0.1:18777. A 396-byte h2c POST (fixture sha256
`0c46e003…e0ba`, one leading CRLF before the staged 394 bytes) kills the
vulnerable NF (curl rc 56, nrf rc 134, SIGABRT in `ogs_talloc_free` via
`parse_multipart` `message.c:3498` → `nrf_state_operational` `nrf-sm.c:78`);
the patched build, safe and staged bodies and a 396-byte `ABC` counterexample
all answer HTTP 400 with the NF alive. The author calls this rung 4
DEMONSTRATED process termination and asks for witness replay (pending); a
`git archive 56363d35` rebuild reproduced the four CASE lines with hashes
`71b4b7e2…7c8e` / `2b31633e…41a7`. The cell stays `◐`: the effect is
count-controlled, with no chosen pointer, IP or command and r5 UNKNOWN.

Cjose2Shell W212 measures the advisory's pre-auth claim inside the lab Apache
consumer: an unauthenticated `GET /private` with `Authorization: Bearer`
compact JWE (56-byte `encrypted_key`) reaches real `cjose_jwe_import()` and
`AES_unwrap_key` through pinned mod_auth_openidc 2.4.15.1 and logs
`W2B_AES_UNWRAP_KEY_REACHED`; with the lab 16-byte KEK, gdb at `jwe.c:602`
reads 48 chosen bytes in `cek[0..47]` while the patched module rejects with
`CJOSE_ERR_INVALID_ARG`. `sh lab/frontier/cjose2shell/w2/run-oauth-bearer.sh`
scores 9 PASS / 0 FAIL live and from a clean `git archive 35e02887` with the
four provisioned build trees copied in; deployed reachability, ASLR defeat
and witness replay stay out of scope. W213's private gdb probe finds only the
next `0x41` chunk's size word changed (`0x41` → `0x4853494d2d323132`) with no
live pointer adjacent; its two logs hash to `dc77299a…4ec49` and
`74fcd254…e387cb4` (recomputed here). N2n2Shell W11 removes W9/W10's debugger
pre-read: a non-PIE clang `-O2` supernode dereferences wire-chosen `0x42f3e8`
at token+1682 as `comm` and stays alive on a zeroed `.bss` target, while
garbage bytes fault at `sn_utils.c:2324`; `sh live/w11_fixed_pointer.sh`
scores 13 PASS / 0 FAIL. The address is binary-known only, not an ASLR-defeating
leak, with no marker, control-flow hijack, command or witness verdict (#3909
still owed). Ccextractor2Shell W5 closes the truncated-MEDIA hypothesis with
4160/64-byte GXF inputs (`669ad202…0745`, `e2b32bf3…4ee2`) that produce only
an ASan `READ of size 3` at `boundary+3973` through `memmove` → `process_data`,
no `read()` WRITE, no write primitive and no rung change.

Pgactive2Shell W12 checks the shipped non-instrumented 2.1.9 `.so`
(`3177a37c…162998`) without starting a cluster: the parser inlines at
`0x16290`, the consumed saved RA sits at `rbp+8`, and the cold `elog(ERROR)`
path longjmps; a glibc probe returns 4 for the only accepted conversion set
with the `%s` destination untouched and 5 for any non-empty tail, so the
pinned `!=4` test cannot be passed by an overflowing store. Libraw2Shell W24
forces the top-size field to `0x21001` under gdb and watches it and the OOB
halfword through `border_interpolate()` — neither changes and the inferior
exits normally; the setup is debugger-forced, no report grade moved.
Libgphoto2Shell W189 rechecks the GitHub and advisory APIs at 08:17Z: newest
tag still v2.5.34 (`a4ec9cc8…`), GHSA patched versions still Unknown, no
numeric fixed version.

Ruby2Shell's 08:1x–08:2xZ limbs close the consumer-provenance question:
shaping wire headers (L=0/60/120/240) and routes (+100/+300) leaves the
post-attack `request=0x21c/0x1f8` pops unchanged in ten survivors, so those
consumers are fixed-size framework allocations, not a request-shaped Stage-B
analog. A surviving `consH-20` geometry does carve a fake 0x20 chunk that the
request thread recycles with an on-thread free (Q), and a dev error page
reflects about 169 KB of params, but the first 60-run carve-landing sweep
(N=508/524/556 × drain 1024/1152/1280) found 11 survivors and zero reflected
corruption — an unproven oracle preserved as a negative. Stock, oracle-free
and persistent r5 stays NOT ACHIEVED; the harness-condition witness label is
unchanged.

Synchronet2Shell W22 applies the pinned `cb6d77dbca` fixed-form hunk to the
same shipped 3.20b build and replays the 64-byte TERM: 5 PASS / 0 FAIL twice,
`off41=00`, nil `first`/`last` and completed teardown, with an author
`git archive 7d3a0088` receipt (`evidence/CLEAN-ARCHIVE.md`); no measured DoS
rate, pointer/IP, command or witness verdict. Drwav2Shell's witness DM #4189,
folded at `f5dce89c`, replayed 25/0 with 3/3 pins and graded the chosen
target-bytes / same-size-class scope ESTABLISHED AS LABELED; the
different-size-class `CHOSEN_WORD_PRESENT=0` counterexample and the no-grade,
no-r5 boundary stay. Xschem2Shell's window 154 is registered 155/155 unique
and the clean archive of `6081c45b` replays 25/0 with both pin hashes. All
limbs above are author-side unless a witness marker is named; none moved a
rung cell, grade, route, mind count or R5 cell.


The 2026-11-25 10:5xZ fold admits StbVorbis2Shell as the 147th route and
supersedes its earlier FRONTIER-STAGED note above: the charter, hy4-flash
route, both resolver keys and three wake units now exist, and window 135 was
adopted without duplication. The exact full-flag sync reported `written 3,
removed 0` and the pinned full-flag doctor returned PASS / GREEN rc 0. The
staged real-library grade is unchanged: rung 3 ASan and rung 4 PARTIAL at a
repeating file-chosen word written past an 8-byte allocation, with NO r5 and
no witness verdict. No grade, rung, witness or R5 cell moved by admission.

The 2026-11-25 11:2xZ fold admits Ctranslate22Shell as the 148th route and
supersedes its earlier FRONTIER-STAGED note above: the charter already
existed, the hy4-flash route and both resolver keys were added, and the exact
full-flag sync reported `written 3, removed 0`; path enabled/active and the
pinned full-flag doctor returned PASS / GREEN rc 0. Window 155 was already
live and registered and was adopted without duplication. The staged grade is
unchanged: rung 3 pinned functions with ASan `WRITE`, rung 4 PARTIAL
file-chosen bytes at one offset of a stand-in 16-byte region, NO r5 and
witness UNKNOWN. No grade, rung, witness or R5 cell moved by admission.

The 2026-11-25 08:5x–13:0xZ fold covers 98 author edges and corrects the
Open5gs2Shell, Mcuboot2Shell, Xschem2Shell, StbVorbis2Shell and
Ctranslate22Shell rows above; rung cells, the route/mind count and the R5
cells stay put. Xschem2Shell W2 is the one new independent verdict in this
window: witness W216 replayed a clean `git archive 42e0f33f` (25/0 harness,
3/0 real unrenamed `main`, same ASan `WRITE of size 8` at pinned `:130`,
allocator-derived readback, fixed rejecting) and graded ESTABLISHED AS
LABELED with no grade change; the row's earlier "witness UNKNOWN" is
superseded. Cjose2Shell W216 and Gpgme2Shell W15 only verified queued replay
offers and corrected a stale verdict line; neither returned a new verdict.
Gpgme2Shell's #4333 W11 offer is UNKNOWN (wake started 12:33:50Z, no settled
output at 12:49Z), not GREEN and not declined.

Drwav2Shell W4 (`0a16d1ef`) adds a file-chosen control-flow diversion in a
non-PIE `libsndfile` consumer: six consecutive cue-desync u32 writes take
`libsndfile__sf_close`/`sf_readf_short`/`sf_readf_int` at `0x41e118..0x41e130`
and call an `LD_PRELOAD` benign marker at `0x50000000`, observed in a gdb
backtrace; fixed 0.14.6 and a safe loop count produce no marker, 14 PASS /
0 FAIL, author-only, no wire or r5. Libsshch2Shell W12 (`d9ef7b38`) derives
the callee address from the compiled ELF symbol table and drives a separate
client process (7/0) while a source-level survey closes the
library-internal close-free shortcut; Synchronet2Shell W24 (`3e681d41`,
clean-archive receipt `3c85349e`) shows the W21 faulting load reads
`0x20(%rax)` with `rax` equal to the wire-chosen `savedlines.first`, 7/0,
with the direct `si_addr` cross-check preserved as a negative because gdb
returned `(nil)`. Open5GS W6 and Mcuboot W1/W2/W3 moved their evidence into
real NF / real pinned decryptor lanes as recorded in their rows, still
without a witness verdict on those new scopes.

Stbvorbis2Shell W203 supersedes the staged "~1.07e9 writes" loop-bound
description with a measured bounded extent (corrected by W204 to 30 words /
120 bytes below); Ctranslate22Shell W1/W2 add a
real-source ASan consumer and a bounded real-heap pointer-control negative.
Vtkdicom2Shell W3/W4 localize the plain-build SIGSEGV to a stale OOB
`Value.V` decref that a nine-size OB sweep leaves unchanged, not file bytes
or a file-influenced pointer. OpenEXR W200 scans the modules loaded by the
pinned `exrcheck` and finds no `rsi`→`rdi` one-gadget route to an `exec*`
call from the W197 shape (bounded negative, receipt `d5aef12d`). Hping3 W11
surveys six more rebuild layouts and extends the chosen `i`/`j` replay to
clang `-O2` without finding a pointer or GOT entry in the 251-byte span.
Ruby2Shell closes the named stock leads — keep-alive same-thread pairing at
Puma `min=3/max=3`, T-header repair, consH-20 tcache retarget, main-arena
libc oracle, 48-part/filler-first, and a Sinatra 500-page GC-address oracle —
and pins wire-only chosen-header coverage to `N ∈ [540,588]`; stock,
oracle-free and persistent r5 stays NOT ACHIEVED and the labelled
harness-condition R5 cell is unchanged. Libraw W26, Munt W189, OpenEXR W200,
Libsshch W10–W12, Open5GS W6, Mcuboot W1–W3 and Synchronet W24 add
clean-archive receipts. Solanum2Shell was staged by frontier W230 with a
clean-archive 18/0 receipt and was subsequently admitted as the 149th route;
see `docs/task.md` and `docs/reproducibility.md`. No grade, rung, route, mind
count, witness cell (except Xschem's verdict text) or R5 cell moved by this
fold.

The 2026-11-25 13:1x–15:3xZ fold covers the 39 author edges after the solanum
admission and corrects the StbVorbis and Hping3 rows above. No commit in this
window carries an independent witness verdict: every replay offer asked for
one (Ctranslate2 W3/W4, Solanum W1/W2, Cjose W217/W218, Gpgme #4333, Codebase
W19/W20, Synchronet #4421, Drwav #4238, Mcuboot #4236, Stbvorbis #4336,
Vtkdicom #4276) stayed UNKNOWN, and the witness wake at 14:02Z failed to
start for the known person-owned engine-cap reason. No rung cell, grade,
route, mind count or R5 cell moved.

The row corrections are the real-consumer and real-build boundaries.
Stbvorbis2Shell W204 sets the guarded extent to 30 words / 120 bytes and
shows all 30 file-chosen words in an
adjacent live object's canary and pointer-typed field (`run-object.sh` 9/0,
pointer read back but never dereferenced); W206 drives the crafted OGG through
real SDL_mixer's public `MIX_LoadAudio_IO()` into its vendored v1.22 header
with ASan `WRITE of size 4` at `stb_vorbis.c:4040`, clean fixed and safe
controls, 12/0 live and from a clean archive. Hping3Shell W12 provisions the
Ubuntu 24.04 `3.a2.ds2-10build2` package: its source `display_ipopt.c` is
byte-identical to the pin, but the shipped binary imports `__memcpy_chk` and
aborts before the store under the crafted long RR (rc 134, valid-RR control
clean, `wire/replay-distro.sh` 5 checks from a clean archive) — a
build-dependent DoS on that package only, not a fix and not a grade change.

Other author limbs deepen admitted lanes without a new capability. Mcuboot W4
drives a real loopback SMP image-upload packet through the real
`boot_serial_input()`/`bs_upload()`/TinyCrypt path into the pinned OOB sink
and reads 16 wire-chosen bytes at the OOB destination (6144/7168) while 4104
SIGSEGVs and 2048 is in-bounds. Solanum W1/W2 move the ASan
`WRITE of size 564` and the plain chosen-byte readback into a real ASan IRCd
over authenticated loopback S2S KILL. Pgactive W-W crashes both apply workers
with an ASan `WRITE of size 8` in a two-node 2.1.9 conflict race; the 2.1.10
library is clean and the earlier crash proved to be a harness bug. Cjose
W217/W218 measure 144 chosen bytes in a real bearer lane and identify the far
object as OpenSSL's 56-byte RNG `CRYPTO_RWLOCK`, written at +0x18 with no
dereference. Ctranslate2 W4 sees a file-derived value in a live
`StorageView._size` but the `size != _size` guard blocks the copy, and its
`sysmalloc`-prev_size redirect hypothesis is disproved. PHP wake 61 repeats
the tinyfilemanager exec chain with two changed attacker constants (8.4.27
marker/id, 8.4.28 clean), still conditioned on the shim SIGKILL. The rest are
bounded negatives and receipts: FontForge W23's tcache-disabled sweep finds
no code pointer, Drwav W5/W6 finds a network-facing metadata caller only on
patched 0.14.6, Libraw W27/W28, Vtkdicom W5, Libsshch W13, Libgphoto2 W192,
Synchronet W25 (19/0 one-command replay of W21–W24), CodebaseMemory W19/W20
and the roughly 300-process Ruby result chain (order arms answered,
deterministic splitter measured, 0x650-band and giant-pop claims closed,
honeypot parity negative) leave stock/oracle-free/persistent R5 NOT ACHIEVED.
Recipes and pins are in `docs/reproducibility.md` and `docs/task.md`.

The 2026-11-25 16:1x–16:2xZ fold covers the 19 commits after `913d0415`
(signal head `a3321f38`, live head `624df6c1`). None touched README or
`docs/*`; none carries an independent witness verdict. No rung cell, grade,
route, mind count or R5 cell moved. The Solanum row above is corrected in
place: its "no real ircd build, S2S wire path" boundary was stale after W1/W2.

Openexr W202 reaches a command in the unmodified pinned 3.5.2 `exrcheck -c`
(`reports/openexr2shell-file-level.md` §W202). The file chooses `memcpy` as
the indirect-call target and a 104-byte source whose bytes 96..103 hold libc
`__libc_system`, so `memcpy(ctxt, …)` overwrites `ctxt->free_fn` and the
trailing `attr_destroy()` call runs `system("touch /tmp/w202m")`; the PoC
sha256 is `7f3eda1b00f54b56ec75108f9012be6b035c8b6393ec1d7c2241f94be91e412e`.
Under gdb the arguments, the overwritten pointer and the command string were
read at the call, with the debugger forcing neither pointer nor call. Plain
`setarch -R` runs give vulnerable rc 139 plus marker, fixed 3.5.3 rc 1 `bad`
with no marker, and a valid baseline rc 0 with no marker; the ASan build
reports `heap-buffer-overflow READ of size 3072` at `internal_zstd.c:472`.
`sh harness/w202-benign-command.sh` printed `RESULT PASS` twice with five
byte-identical evidence hashes, and a clean `git archive 043a0d41` repeated
them. This is rung-4 mechanics at the rung-5 boundary, not R5: every run has
ASLR off for file-carried absolute addresses, the input is a local path, the
command is a benign `touch`, and the process then faults. The row's W188
"no command" sentence is scoped to that earlier steering limb.

Stbvorbis W207 observes the full OOB run in a real SDL_mixer consumer built
without ASan: `evidence/chosen.ogg` aborts rc 134 with
`malloc(): invalid size (unsorted)` and the safe input exits 0. gdb snapshots
all 30 file-chosen `0x4b434148` words at `c->multiplicands+8..+124`; the word
at `+24` rewrites the next free chunk's size from `0x91` to `0x4b434148`, and
no live allocation occupies the range. Padding the file to 4096, 65536 or
1048576 bytes leaves the address, neighbour and clobber unchanged.
`sh lab/frontier/stbvorbis2shell/run-consumer-heap.sh` passes 11 shell and
14 heap-word checks with the 12/0 ASan and fixed controls replayed. This is
chosen bytes in allocator metadata, still not a chosen word in a live
consumer-owned field; no pointer, command, wire or witness verdict.
A clean archive of `624df6c1` (SDL/SDL_mixer dependencies symlinked read-only
from the live lab) replayed every committed script at 16:27Z: 11/0 plus 14/0
heap-word, 12/0 consumer controls, 9/0 `run-all.sh`, 4/0 `run-seq.sh`, 12/0
`run-guard.sh`, 9/0 `run-object.sh` and 9/0 `run-neighbor.sh`, all rc 0. An
earlier archive of `0c8b7c75` failed because the gitignored safe input was
absent; `624df6c1` regenerates it inside the replay. Author receipt only.

Hping3 W13 writes a linear permutation to 187 reachable sbox bytes through
the crafted RR reply. The first RNG output byte is reply-chosen only when the
hidden `j` lands the index inside that reach: `j=222` gave index 5, `S[5]=4`
and observed low byte 4 (counterfactual 22), a clean run with `j=92` gave
index 131, `S[131]=130` and byte 130 (counterfactual 237), and `j=156` sent it
to index 195 outside the reach. A `127.0.x.x` template moved the destination
off `127.0.0.1` and was rejected by `waitpacket.c:94`; a full chosen IP is
not available. `sh wire/replay-perm.sh` runs baseline 3, attack 5 and fixed 3
checks (`REPLAY_PERM_OK: 3 stages`) from a clean archive of `feb3f33f`.

The remaining limbs are bounded negatives and receipts. Open5GS W8 proves
the OOB values are forced `00 0d 0a` repeats: arbitrary 36-byte suffixes
write nothing, substitutions break the chain, and CRLF injection only
re-arms it (`harness/bytechoice/run.sh` 11/0; clean-archive receipt at
`0a6c868d` gives 11/0 plus 21/0). Cjose W219/W219b sweep the real pre-auth
bearer lane over `enc`-selected CEK sizes: two plain builds fault in
`OPENSSL_sk_dup` and `_cjose_release_cek`, a 168-byte write replaces
pointer-shaped fields at `cek+0x80..0xa8` with `0x4141…`, but no vulnerable
case faults on the written value and all return HTTP 401 (18/0 and 11/0
receipts). Awslc W223 synthesizes W213–W216: no checked real caller has both
the withheld-block carry and the documented-minimum destination, W216's Node
22.11.0 has one slack byte, and unprovisioned applications stay UNKNOWN.
N2n W16 adds `sh live/replay-all.sh` with seven passing lanes from a clean
archive of `a2284de2`; its first 4/3 run was a missing gitignored
`community.list`, fixed by reading the pinned tarball. Solanum W3 reads the
post-buffer window in a plain real ircd: `buf` sits at vaddr `0x5220`, size
`0x200`, in `.bss` ending at `0x5420`, with no writable object following it
(18/0 harness, 6/0 ASan controls). All replay offers stayed UNKNOWN.

The 2026-11-25 16:3x–17:1xZ fold covers the author/config edges after
`827436b5` (signal and live head `4e5ec955`). No independent witness verdict
arrived; no rung cell, grade, route, mind count or R5 cell moved. The signal's
vrpn correction is already present: W23 maps the large-index exit-139 rows to
the NUL store at `sender_name + index`, not an outside-stack assertion.

Ruby2Shell's stock-app allocator model was corrected again: glibc tcache ends
at chunk size `0x420`; each embed-legal multipart part makes two
content+9 slices and one next-power-of-two value buffer. Order arms falsified
the earlier "never swept" closure, but the upcase's own result allocation
deterministically splits the forged grown victim. Sacrificial-shield runs
completed the full sequence 6/12; honeypot-parity arms survived 8/12 and 7/12,
yet every `0x648` claim pop landed on a merged value chunk, never the grown
victim. The exact-fit giant-pop claim has no physical overshoot, so the poison
chain is structurally closed for stock/oracle-free/persistent R5 after roughly
300 fresh processes. Two arms produced the first stock Ruby-VM SIGSEGVs when
prettyprint consumed the split-cascade corruption: a wire-driven crash, not a
steered allocation, command or grade change.

Cjose W220 identifies W219b's far object as the live Jansson header hashtable
`jwe->hdr`, not an unknown allocation. The overflow replaces its type and
buckets, but pinned `value.c:106-113` checks `json_is_object()` before
`hashtable_get`; the first post-unwrap lookup fails closed and returns HTTP 401.
The identity/use replays scored 7/0 and 11/0. Libsshch W14 removes the harness
trampoline from the callee path: an authenticated loopback client selects real
libc `system()` and its `channel->session` argument from recycled wire bytes,
creating the benign marker in 6 PASS / 0 FAIL. The command string remains an
app-chosen static global and the addresses are fork-peer ASLR-local; this is
unwitnessed rung-5 mechanics, not established remote execution.

Synchronet W26 measured shipped 3.20b under four concurrent loopback SSH
pty-req probes. The imported node-exhaustion prediction failed (7/3, preserved):
the process instead SIGSEGVs at first teardown and the fifth client is refused.
After correcting only the fixed-control assertion, the replay and a clean
archive both scored 13/0; the fixed form served all five sessions. Openexr W203
closes W202's fixed-address staging route: all ten ASLR-on PIE/non-PIE runs
faulted without a marker, and no file-filled fixed-address staging buffer was
found. W202 remains an ASLR-off, local-file, benign-command rung-4 limb.

The remaining edges are replay/provenance work: Solanum W4 adds one-command
18/0 harness plus 6/0 real-ircd controls; CodebaseMemory W21 repairs witness
wrapper assertions and TERM/INT/HUP evidence restoration, with 44/0 assertions
checked lane-by-lane but no uninterrupted final-wrapper run; Munt W191 resolves
the second CISA exploit-tagged link as the same inaccessible note, whose mirror
contains only an unexecuted, truncated illustrative trigger. Route policy now
keeps exactly one `opencode-go/hy4-flash-free` candidate per role at
`max_parallel: 5`; the same-day hungerg-free fallback was retired after rate
limiting, and `docs/runtime-pin.md` carries the exact allowlist and limits.


The 2026-11-25 17:1x–17:4xZ fold covers the ten author edges after
`869e8435`. Only one carries an independent verdict: witness W219 (#4481)
returned **ESTABLISHED AS LABELED** for Solanum2Shell W5, replaying
`bash lab/frontier/solanum2shell/replay-all.sh` from a clean `b8885fcc`
archive (18 PASS / 0 FAIL, then 6 PASS / 0 FAIL), hash-checking both pins and
rebuilding them into its own prefixes. Its unauthenticated-peer counterexample
got `Incompatible TS version`, no KILL and zero ASan, confirming the PR:H
prerequisite. The published grade is rung 3 confirmed in a real ircd process
and rung 4 PARTIAL with chosen length and bytes at a known global offset; no
pointer, command or r5. This verdict text supersedes the row's earlier
"witness UNKNOWN"; no rung cell, grade, route, mind count or R5 cell moved.

Ruby2Shell's corrected-model tcache consumer was confirmed, but the stock
chain stays closed. On the class that genuinely has glibc tcache (`<=0x420`),
`bash lab/repro/ruby2shell-stageC.sh` got 5/5 `verdict=poisoned` with an mtrace
pop at the forged target and 3/3 clean controls. The HTTP replay
`lab/repro/ruby2shell-stageC-http.sh 3 2` got 3/3 request-thread attacks with
16 chosen bytes at the nominated address (`7a` repeated) and a pop line there,
2/2 clean controls, and all three attack processes aborting at teardown. The
wire-only class probe then failed in 12 fresh unmodified processes
(lab/repro/ruby2shell-stock-leakclass.sh with
`RUBY2SHELL_LEAKCLASS_COUNT=12`): 0 `q38=0x251` tcache-`next`
landings, 0 window `P` allocations, 0 window `Q` frees, and no arena base on
the wire in the one surviving response pair. Stock/oracle-free/persistent r5
remains NOT ACHIEVED; the harness-condition r5 cell is unchanged.

Hping3Shell W14 extends chosen-byte control from W9's zero fill to two measured
nonzero values: with `S[0]=0x7e` or `0xc3` and `i=0x20`, `j=0x10` in the clang
`-O0` build, 8/8 attack checks passed with 16/16 chosen low bytes and
counterfactual bytes `e7`/`e3`, against 4/4 clean no-inject and locally patched
controls. `bash lab/frontier/hping3shell/wire/replay-target-byte.sh` scores 4
baseline, 8 attack, 4 fixed checks, rc 0; the same frames also passed 8/0 under
clang `-O2` (author-side rebuild). This is one IP octet, no full IP, pointer,
command or grade change.

The remaining limbs are bounded negatives and replay receipts. PHP W62's
deployment-style `RLIMIT_FSIZE` at the calibrated cut K=1019 makes the kernel
write exactly 1019 of 1892 bytes with no SIGXFSZ, but the live FPM worker stays
alive and the splice is gone at consume time: no promotion, takeover or marker
on 8.4.27-app, 8.4.28-app clean, full r5 still UNCLAIMED. Libraw W31 withdraws
W29's causal claim that a file-chosen, glibc-plausible top-chunk size caused the
clean exit: watchpoints show the file-written `0x00c0` halfword, but the field
reads `0x11` at `__libc_free` entry, and a standalone control exits cleanly with
`0x11` whether PREV_INUSE is set or clear. Grade stays rung 4 on W13/W14/W15
(chosen halfwords at chosen offsets) and W17 (loopback); no overlapping
allocation, pointer, command or r5. Gpgme W19 records witness W222's
ESTABLISHED AS LABELED verdict on #4333 (W11 EOF replay) and #4487 (the clean
archive wrapper: `BUILD OK`, 25 PASS / 0 FAIL, rc 0, exact pins, fixed/2.3.1/
short-line controls clean). Its newline-terminated counterexample is consistent
with EOF as the differentiator, and the chosen-byte print is debugger-only; no
grade or r5 move. KiCad's redundant 302243840-byte AppImage tar was removed after both
tar and extracted hashes were verified; the extracted binary hash and replay
recipe are unchanged.

The 2026-11-25 18:1xZ operator wake admits Aspell2Shell and FreeImage2Shell
as declared target minds under standing #6 after replaying both staged
harnesses: Aspell 14 PASS / 0 FAIL and FreeImage 9 PASS / 0 FAIL, with the
primary advisories, pins, fixes, charters, walls and live two-pane windows
157/158 checked. Both lanes keep their staged grade and witness UNKNOWN.
Both resolver-key pairs are registered. Engine-route registration and the
generated path, debounce and per-role slice units remain missing because
engine-config changes and full-flag sync are person-reserved. The route
registry therefore remains at 149 roles while 151 target minds are declared;
the repository OMP-only checker is RED for exactly those two missing routes,
and doctor is RED for the six missing unit files. No route or operational
unit delivery is claimed. The pinned single-model OMP checker also remains
stale against the owner-directed two-model routes; it is not hand-greened.

The 2026-11-25 18:0x–18:5xZ fold covers the 30 author edges after
`77a552ce`; only the operator admission `fde6f94e` touched docs paths and
self-folded its two rows. No edge outside that admission carries an
independent witness verdict. The new verdict is Openexr2Shell W204, already
folded into its report: witness wake W218 (#4457) returned ESTABLISHED AS
LABELED for the benign `touch` through an unmodified `exrcheck -c`, matching
all five committed hashes from a clean `34832cb6` archive; ASLR was off, the
EXR was local, no wire target existed, full r5 stays UNKNOWN and the verdict
does not cover W203's ASLR-on negative. PHP2Shell W63 extends the preserved
W62 short-write negative: a native `RLIMIT_CPU=1s`/`RLIMIT_FSIZE=1024` chain
(`DEATH_MODE=rlimit PREBURN=1`, ASLR on, no phase-2 LD_PRELOAD) reaches the
author-side rung-5 gates 1–5 in a live 8.4.27 FPM worker, with marker
`php2shell-r5-w63-final-1837` and output hash `7df36e9a…`; the fixed 8.4.28
build leaves exactly 1024 bytes and no marker. Gate 6 stays OPEN: without a
clean-checkout replay that varies the command, full r5 is NOT ESTABLISHED.
Libsshch2Shell W16 puts a wire-resident `touch` string at a probe-derived
slot and calls the real libc `system()` (6 PASS / 0 FAIL, marker side effect,
fixed and bad-callee controls clean); a stale hard-coded slot scored 2 PASS /
4 FAIL, and the callee address remains forked-peer ASLR-local, so this is
author-only rung-5 mechanics, not r5.

The remaining limbs are chosen-byte reaches, replay receipts and negatives,
all with unchanged grades. Stbvorbis2Shell W208 drives file-chosen bytes
into a live glibc `_IO_save_base` in a real consumer (17/0; `_IO_save_base`
`0x4b4341484b434148` at k=27, plain rc 139, fixed and safe rc 0) but only
rung 4 PARTIAL. Vtkdicom2Shell W6 pins the exact VTK 9.5.2 bundled source,
ASan `WRITE of size 4` 32 bytes past a 136-byte region, and W7's
predecessor-item grooming yields only stale `Value` headers, no pointer.
Openexr2Shell W205 finds no libc-resident alternate `ctxt` victim under
ASLR on (`COMMAND_PLT_CALLS=0`), W206 finds no same-mapping command call
among the eight function-pointer slots; Fontforge2Shell W24's third PIE
build and W25's late Save state both score `CAND_COUNT 0` for a code pointer.
Libgphoto2Shell W193 overwrites 16 bits of `priv` with one ASLR-on fork-sweep
hit (16/0) but no absolute target or command. Pgactive2Shell's
`local==NULL` delete/delete conflict aborts with signal 6 live (fixed clean,
clean-archive replay exact) with a fixed boolean, not an attacker byte.
Synchronet2Shell W27 finds a 52-byte wire TERM threshold (13/0) on shipped
3.20b; the 48-byte arm corrupts only `line_delay`. Hping3 W15, N2n W17,
Openexr W205/W206, Fontforge W24/W25, Libsshch W16 and Pgactive receipts
were replayed from clean archives, and Ruby's free-order map, tcache
saturation, escaped disposition and stock small-class overlap arms remain
bounded negatives: no claim/pop, command or persistence, and stock RCE
stays NOT ACHIEVED. No rung cell, grade, route, mind count or R5 cell moved
by any of these limbs.

The 2026-11-25 18:56–19:2xZ fold covers the eleven author edges after
`f777c40d` (through `08e18012`); none touched docs paths and none carried an
independent witness verdict. Vtkdicom2Shell W8 only re-points both reports at
the exact-source replay material in DM #4503 (unanswered; #4276 is the earlier
W3 offer), leaving its witness UNKNOWN. PHP2Shell W64 extends W63's native
`RLIMIT` chain with a two-pool `RLIMIT_FSIZE=1024` unlock gap: a size-limited
FPM producer stays alive while a second, unlimited pool consumes the session,
so no CPU freeze, SIGKILL or phase-2 `LD_PRELOAD` is needed. The armed wire
request creates `php2shell-r5-w64-gap-chain` under `uid=1000(mesh-home)`
(hash `91a18f97…`); a varied SID creates `php2shell-r5-w64-gap-varying`
(`6bd15181…`); fixed 8.4.28 leaves a 78-byte session and no marker
(`2a38515d…`). Author-side rung-5 gates 1–5 are reached, gate 6 stays OPEN
and full r5 is NOT ESTABLISHED.

Libsshch2Shell's pinned-tree survey finds five callback registrations and no
in-callback channel free in any of them; `ssh_channel_close()` itself does not
free, so the in-callback free remains harness/app-owned. Ruby2Shell adds opt-in
`MTRACE_TID=1` tracing: in seven surviving N=972 processes all 22 planted
`0x3f1` allocations and frees, the last `0x400` free and the `0x3f8` upcase
allocation carry one worker tid, closing same-thread attribution; the tcache
arm's upcase took a newer planted slice, wrote `0x53` and aborted in
`munmap_chunk(): invalid pointer`, with no claim pop or command. Hping3Shell
W16 makes `--rand-dest 127.T.T.T` emit three chosen octets (the first fixed by
the template): T=1 predicted 20/20 destinations and got 15/16 `127.1.1.1`,
T=`0x2a` got 10/16 `127.42.42.42`, and a clean-archive replay scored
`REPLAY_MULTIOCTET_OK: 12 checks`; no pointer, command or witness.

Openexr2Shell W207 tests the file-to-argv address-leak lead and returns
NEGATIVE: all 12 ASLR-on `exrcheck -c` cases have `CASES_WITH_HEX_OUTPUT=0`,
`sh lab/openexr2shell-real/harness/w207-leak-negative.sh` gives `RESULT PASS`
with hash `d5d7b448…`, and a clean `git archive 2f12c2e5` replay with the
gitignored cases symlinked is byte-identical; `-s` on a FIFO timed out at 40 s
and stays UNKNOWN. Drwav2Shell W8 replays three exact consumer headers:
Moondust, Sphaira and Yup each keep `CHOSEN_WORD_PRESENT=1` and rc 0 for the
chosen metadata, fault the bad arm at `drwav__read_cue_to_metadata_obj:2281`
and leave the safe arm clean. Sphaira's mount-to-browser-to-audio path is
user-driven remote-file playback, not a listener, and its build is
switch-only; no exactly-0.14.5 consumer was found (absence unproved), so no
r5. This supersedes the Drwav2Shell row's earlier no-application boundary at
the exact-source-header level only; no running Linux application or listener
was exercised. Aspell2Shell's full release ASan build dumps 255–511-byte
words at rc 0, with complete NUL-terminated bytes and no ASan report or
crash; the `aspell -a` suggestion probe is UNKNOWN.
No rung cell, grade, route, mind count or R5 cell moved by any of these
limbs; all offers remain unanswered.

Three further author edges landed while this fold was in progress and are
recorded here rather than left as new stale boundaries. Hping3Shell W17
replaces W16's repeated-octet fill with a 187-byte reply-chosen pattern that
puts three **distinct** octets into one loopback packet: `127.11.22.33` and
`127.44.55.66` were each seen with all 20 full destinations predicted from
read-only GDB state and 1/16 post-attack hits, and a 500,000-trial search
found no swap-stable pattern for repeated packets. A clean `git archive
266144f0` replay scored `REPLAY_PATTERN_OK: 3 stages` (baseline 4, attack 5,
fixed 4 PASS) with the pinned source hashes rechecked; still no full IP,
pointer, command or witness verdict. FCEUX2Shell W233 is **staged, NOT
admitted**: CVE-2026-136918's UNIF `MAPR` chunk wraps a malloc argument at
`0xffffffff`, and the pinned `SetBoardName()` harness scores 14 PASS /
0 FAIL with ASan `WRITE of size 19` just past a 1-byte region and file-chosen
bytes through rc 42; no row, route, live emulator, command or verdict follows
from staging. No rung cell, grade or R5 cell moved by these limbs either.


The 2026-11-25 21:4xZ operator wake admits Nfdump2Shell as the 152nd declared
target mind under standing #6 after replaying the staged claim
(GHSA-gpgq-hv9x-7mqj, public endpoint HTTP 404, no CVE/CVSS), both hash-pinned
`nfdump` revisions (`8a00543a` / `32b9cbe7`), the 10 PASS / 0 FAIL GCC+Clang
ASan harness and the live two-pane window 160 (frontier W234, 21:26Z, adopted
without duplication). The grade is unchanged: rung 3 pinned verbatim, rung 4
PARTIAL packet-chosen offset with harness-chosen value, no wire/pointer/command,
no r5, witness UNKNOWN. No route, resolver key or unit was added: the owner's
standing approvals reserve engine-config changes, systemd units and the
full-flag sync to the person
(`.mishe-tauftauf/operator/standing-approvals.md:47-51`). The route registry
therefore stays at 152 roles while 153 roles are declared in the OMP checker
(which also counts staged Fceux2Shell); `check-omp-only.py` is RED for
`nfdump2shell: no route` and the 21:34Z doctor run lists twelve missing unit
files (nine for aspell/fceux/freeimage, three for nfdump2shell). The
`failed-m2shell-doctor-service` RED was re-observed GREEN on a refreshed
person-owned disposition, not because the units exist. No operational delivery
is claimed here; the person's exact full-flag sync and witness replay remain
owed.
