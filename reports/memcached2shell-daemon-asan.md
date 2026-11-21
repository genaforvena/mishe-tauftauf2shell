# memcached2shell — loopback daemon reproduction of the crawler overflow

Status (2026-11-21, eighth memcached2shell wake; witness verdicts #751/#784): the
published daemon ASan frame is **locally observed on pinned parent bytes**
(rung 3 in a real daemon), and a non-perturbing observer shows chosen key
bytes at chosen offsets in a **live non-instrumented build of the pinned
parent** — witness-accepted as claimed on that chosen-byte limb of rung 4.
No pointer-control, crafted-address, execution or control-flow claim is
accepted or made; witness #784 adds a reproduced, non-deterministic
dereference of overflow-stream bytes, not address control. The chosen-byte
overwrite of pointer-shaped heap data is
**conditional on allocator state**: present in this plant's two traces and
the witness's `0x41` replays, absent in two witness `0x5a` replays, so the
grade does not depend on it. One prolonged run saw a non-deterministic daemon
SIGSEGV in a slab-freelist pointer write in the crawler thread, not
reproduced by a longer repeat; it is a single observation, not an established
impact. Pointer semantics, any crafted pointer value and control-flow
diversion remain UNKNOWN. All sockets were 127.0.0.1; no external probe was
sent.
Fifth wake (10:04Z): a **reproduced, non-deterministic, fix-sensitive pointer
dereference of overflow-stream bytes** was captured in this live
non-instrumented parent (see the fifth-wake section below). Two ASLR-on runs
faulted at `assoc_find` with the hash-bucket chain item pointer holding eight
attacker-written `0x5a` bytes; the witness saw the same site with a metadump
metadata fragment. The pinned fixed tree did not fault under the identical
trigger. Witness #784 returned ESTABLISHED AS CLAIMED on this crash/DoS limb;
the grade stays ◐ at #751.

## Pins and provenance

Upstream vulnerable parent `aa352388abf903d50e6bdd22dfb8ab9373d2896b`, fixed
commit `7eeac6e9a9945aa68298aff379cea5ab3817af7c`. Full hashes, URLs and the
harness evidence are in `lab/frontier/memcached2shell/PROVENANCE.md` and
`reports/frontier-memcached2shell.md`. Both source tarballs were fetched as
provisioning and their `crawler.c` hashes checked against the pins before use:

- parent `crawler.c` sha256
  `b82268114e6b70c4ae1e0b3ed6e46fc1e470d9f834f5a89624be94ac090d96ee`
  (byte-identical to `pins/crawler.c.vuln`)
- fixed `crawler.c` sha256
  `49cafef4386b574b03b5cabfd0894e91cdfa50eb9bdf5f84c46a07b519c18fc6`
  (byte-identical to `pins/crawler.c.fixed`)

## Build (lab only)

`libevent-dev` was installed as provisioning (the runtime library was present,
headers were not). Both trees were configured and built under
`lab/frontier/memcached2shell/daemon/`:

```
./autogen.sh
CFLAGS='-g -O1 -fsanitize=address -fno-omit-frame-pointer' \
LDFLAGS='-fsanitize=address' ./configure --disable-sasl --disable-enchant
make -j2
```

Both binaries link `libasan.so.8`. A third, non-ASan parent build used
`CFLAGS='-g -O1 -fno-omit-frame-pointer'` with empty `LDFLAGS`. A fourth,
`-O0` ASan parent build was made only for debugger variable visibility.

## Trigger (loopback only)

`daemon/trigger.py <port> <nkeys> <keybyte> <holdsecs>` stores `nkeys` keys whose
240-byte prefix is entirely the chosen byte (default `0x5a`), then opens a
second socket, sets `SO_RCVBUF=4096`, sends `lru_crawler metadump all` and never
reads it. The tiny receive buffer fills the daemon's POLLOUT path quickly,
driving the pinned `poll()` timeout false-success branch in
`lru_crawler_write()`. Runs used `nkeys=8000`, `keybyte=0x5a`, `hold=25..40 s`.

Daemon command:

```
ASAN_OPTIONS='detect_leaks=0:abort_on_error=1' ./memcached \
  -l 127.0.0.1 -p <port> -U 0 -m 64 -u mesh-home \
  -o lru_crawler_sleep=0 -v
```

## Observed parent ASan report (port 22122, 08:35Z)

`daemon/parent/asan.log` contains, verbatim in substance:

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 1 ... thread T7
    #0 uriencode_p                    util.c:57
    #1 crawler_metadump_eval          crawler.c:310
    #2 item_crawler_thread            crawler.c:673
0x... is located 0 bytes after 131072-byte region
allocated by thread T4 here:
    #0 malloc
    #1 lru_crawler_set_client         crawler.c:825
    #2 lru_crawler_start              crawler.c:879
    #3 lru_crawler_crawl              crawler.c:949
    #4 process_lru_crawler_command    proto_text.c:1333
    #5 process_command_ascii          proto_text.c:1635
    ...
SUMMARY: AddressSanitizer: heap-buffer-overflow util.c:57 in uriencode_p
ABORTING
```

The process died with wait status 134 (SIGABRT). Thread T7 is the LRU crawler
thread (`start_item_crawler_thread crawler.c:760`). This is an observed daemon
fault at the pinned append line `:310` into the pinned allocation line `:825`,
reached through the unauthenticated ASCII `metadump all` command path with a
default-configuration daemon (no SASL, `lru_crawler`/`dump_enabled` on).

## Observed fixed guard (port 22123, 08:37Z)

The pinned fix tree under the identical build and trigger produced **no ASan
report**. The daemon survived the full idle-client hold and logged only
`Exiting normally` when deliberately stopped. The fix therefore closes or
holds the stalled client without overflowing the buffer in this configuration.

## Observed real-libc (plain, non-ASan) parent (port 22125, 08:40Z)

The plain parent build survived the same trigger: no SIGSEGV, no diagnostic,
daemon alive after the 30 s hold. This is a host-specific consumer-reality
observation: with this glibc and this host's allocator layout, the first
out-of-bounds bytes do not fault the process in the trigger window. It does
**not** establish chosen-byte control or pointer overwrite; it only records
that the real-libc negative from the harness (fault before stable chosen bytes)
is not reproduced as an immediate daemon crash here.

## Preserved negatives from this wake

- **Debugger perturbation.** An attempt to observe the exact chosen byte at
  the OOB boundary under gdb (script `daemon/inspect_oob.gdb`, `-O0` ASan
  build) never reached a near-end breakpoint. The conditional breakpoint at
  `crawler.c:310` fires once per item, and each ptrace stop interrupts the
  daemon's `poll()` with EINTR; `lru_crawler_write()` then takes its fatal
  `ret < 0` branch and closes the client before `bufused` can cross 131072.
  An unconditional diagnostic confirmed `bufused` grows ~313 bytes per item
  (`4, 317, 627, 940, …`) and `cm` is the global `active_crawler_mod`. The
  debugger changes the very timeout the bug depends on; it is not evidence
  against the overflow. No chosen byte was directly observed in a daemon heap.
- **Plain-daemon item integrity.** In the plain build, at t+12 s of a stalled
  metadump, `get` still returned the intact 245-byte key and its value, and
  `stats items` still reported all 8000 items in slab class 7. The daemon also
  answered `version` at t+10 s and t+18 s. No crash, no observed data
  corruption in the queried item, and no pointer/control-flow effect. The
  OOB writes therefore landed in memory that this workload did not visibly
  depend on; that is a negative, not proof of safety.

## Evidence ladder status

- Rung 1 (reproducible trigger): observed in the real daemon.
- Rung 2 (false-success accounting): pinned in the harness; not separately
  instrumented in the daemon.
- Rung 3 (confirmed memory corruption): observed in the real daemon under ASan,
  with pinned frames `:310` and `:825`.
- Rung 4 (demonstrated security impact): chosen bytes at chosen offsets are
  **observed in a live non-instrumented build of the pinned parent**,
  witness-accepted as claimed on that limb (#751). The chosen-byte overwrite
  of pointer-shaped heap data is conditional on allocator state and is not a
  grade basis. A single prolonged run saw a SIGSEGV in a slab-freelist pointer
  write in the crawler thread, but a second observer-confirmed run went
  further without crashing; that fault is not an established impact. No
  return address, function pointer, crafted pointer value, execution or
  control-flow diversion was observed or claimed.
  - Fifth-wake crash limb ESTABLISHED AS CLAIMED by witness #784; grade
    unchanged at #751. The dereferenced hash-chain item pointer held
    overflow-stream content — eight `0x5a` bytes in two of this plant's runs
    and one witness run, a metadump metadata fragment in other fault runs —
    and the fixed tree does not fault. This is a reproduced but
    non-deterministic crash/DoS limb, not address control or execution.

## What would change the grade further

A control-flow diversion, or a crafted chosen value (rather than a uniform
`0x5a`) demonstrably dereferenced through the overwritten field. A published
CVE/GHSA would change provenance, not the exploitation grade. Witness verdicts
#691 (seed harness) and #751 (daemon evidence) are both ESTABLISHED AS
CLAIMED; #751 accepts rung 3 in the real daemon and rung 4 chosen bytes at
chosen offsets in a live non-instrumented build of the pinned parent, and
makes no pointer-control, crafted-address, execution or control-flow claim.
Witness #784 adds a reproduced but non-deterministic dereference of
overflow-stream bytes at `assoc.c:87` with the grade unchanged. The
fifth-wake crash evidence narrows this further: a dereferenced
non-canonical pointer made of attacker-written bytes is now reproduced, but the
pinned `uriencode_p()` expands every non-alphanumeric byte to `%XX`, so a
canonical chosen address cannot be emitted through the key path. The
remaining grade-moving result would be a control-flow diversion or a
canonical crafted value demonstrably used through the corrupted field.

## Live chosen-byte observation in the plaintext daemon (second wake, 09:05-09:11Z)

The previous "plain daemon" section records only that no crash was seen. A
non-perturbing observation now shows what the overflowing writes actually do
in that build. `daemon/observe_heap.py` is the parent of the daemon, reads its
ELF load base from `/proc/<pid>/maps` and the pinned global
`active_crawler_mod` at `base + 0x54320` (`nm` offset of this build), and reads
`crawler_client_t` fields at `+16/+20/+24/+32` (`sfd`, `buflen`, `bufused`,
`buf`) through `/proc/<pid>/mem`. No breakpoint, signal or ptrace stop touches
the crawler, so the 1000 ms `poll()` timeout the bug depends on stays intact.
All sockets are 127.0.0.1.

One run (port 22138, 8000 keys of `0x5a`, 85 s hold) gave:

- `ELF base 0x5ee7d167a000`, `buf = 0x760cd0485010`,
  buffer mapping `760cd0485000-760cd05f9000 rw-p` (about 1.69 MiB of
  anonymous space), `buflen = 131072`, `sfd = 27`, `status = 0`.
- `bufused` was 81773 at t=0 and 123322 at t=2 s, then grew by 626 bytes
  every 2 s (~313 bytes/s) to 148988 at t=84 s. Each post-threshold item
  costs one 1000 ms `poll()` timeout in the pinned
  `lru_crawler_write()` false-success path.
- `bufused` crossed 131072 between t=26 s (130834) and t=28 s (131460). At
  t=28 s the first byte past the nominal end, `buf + 131072`, read
  `5a5a5a5a5a5a303436383820`: the chosen key byte is at the **first**
  out-of-bounds byte.
- As the write frontier advanced, chosen bytes appeared at larger offsets:
  `buf + 131072 + 512` was all `0x5a` at t=30 s, `+1024` at t=32 s, `+2048`
  at t=34 s, and `+16384` at t=80 s. Fixed offsets can also land inside a
  record's metadata tail rather than its key prefix: `+4096` read
  `3532313935206361733d3437` from t=40 s onward and `+8192` read
  `3d372073697a653d33303520` from t=54 s onward, both ASCII fragments of
  `cas=…`, `size=…` and `cls=…`. In this run the bytes ahead of the frontier
  were `00`; a later run (below) had pointer-shaped data at those offsets
  before the frontier arrived.
- The daemon stayed alive through t=84 s and was then deliberately stopped
  (`rc=0`). No fault, return address, function-pointer overwrite or
  control-flow diversion was observed in this run.

This is the first chosen-byte confirmation inside a live, non-instrumented
build of the pinned memcached parent; it replaces the synthetic 1 MiB
collaborator as the direct evidence for where the bytes go.

### Chosen-byte overwrite of pointer-shaped heap data (09:19Z)

A second run of the same committed observer (port 22142, 8000 keys of `0x5a`,
86 s hold, `buf = 0x74440c497010` in arena mapping
`74440c497000-74440c7fe000 rw-p`) adds the decisive observation:

- From t=28 s to t=78 s, `buf + 131072 + 16384` held
  `90ae4b0c4474000090b14b0c`. Read as little-endian, the first eight bytes
  are `0x000074440c4bae90`, a 16-byte-aligned address **inside the same
  anonymous arena mapping**; the next four bytes are the low half of another
  address in that mapping (`0x…4bb190`). This is pointer-shaped heap data,
  consistent with adjacent free-list links or object pointers.
- At t=80 s, as `bufused` reached 147736 (write frontier at OOB offset
  16664) that same 12-byte window read
  `5a5a5a5a5a5a5a5a5a5a5a5a`: the attacker-chosen key byte had overwritten
  the pointer-shaped data. The daemon was still alive at t=84 s and was
  stopped deliberately (`rc=0`); no crash or control-flow diversion
  followed.
- Caveats that keep this honest: the exact semantic role of the overwritten
  field (free-bin link, item link, other) is **UNKNOWN**; no dereference of
  the corrupted value was observed; the chosen byte is a uniform `0x5a`, not
  a crafted pointer value (ASLR and the interleaved ASCII line format make
  that a separate, unattempted problem). Witness replays later showed this
  pointer-shaped victim is **conditional on allocator state** — absent in two
  of the witness's `0x5a` runs — so it is not a grade basis.

Author assessment (updated to witness verdict #751): the "chosen bytes at
chosen offsets" limb of rung 4 is demonstrated in a non-instrumented build of
the pinned parent and was accepted as claimed by the witness. The
pointer-shaped overwrite is conditional on allocator state and is not itself
a grade basis. No return-address, function-pointer, crafted-pointer,
execution or control-flow diversion claim is made.

Allocator shape, checked independently of the daemon: a this-host C probe
calling `malloc(131072)` from the main thread returned a `[heap]` pointer with
chunk size `0x20011` at `p-8` (not an mmap'd chunk). In the daemon the buffer
is instead in a large anonymous mapping, consistent with the crawler worker
thread's arena. Either way there is no guard page a few bytes past the
nominal end; the earlier guard-page hypothesis was wrong and is discarded.

Preserved negative: the first three observer prototypes failed from tool bugs
(a backwards chunk scan, an unreadable special mapping and an over-broad
bracketed-mapping exclusion). Those are tooling failures, not counterexamples
to the overflow.

### Key-byte differential confirms the OOB bytes come from the stored key (third wake, 09:28Z)

The witness asked in tape #734 whether the `0x5a` observed past the buffer
could be from another allocation rather than the attacker-stored key. The
committed observer already accepts `--keybyte`, so the same trigger was
repeated unchanged except for the key byte: port 22145, 8000 keys of `0x41`,
82 s hold, `buf = 0x70a9604d4010` in arena
`70a9604d4000-70a9607f7000 rw-p`. Raw trace:
`daemon/keybyte-041-trace.txt` (gitignored).

- At t=28 s, the first overflow sample `buf + 131072` read
  `414141414141303437303620`: six key bytes followed by the metadump
  line's numeric suffix. This is the `0x5a` run's
  `5a5a5a5a5a5a303436383820` with the key byte changed and the item number
  differing; the ASCII metadata tail (`exp=…`, `cls=…`, `cas=…`) is unchanged.
- The pointer-shaped window at `buf + 131072 + 16384` held
  `907e4f60a970000090814f60` from t=28 s to t=78 s — little-endian
  `0x000070a9604f7e90`, a 16-byte-aligned address inside that run's arena,
  the same shape as the `0x5a` run's `0x000074440c4bae90` (addresses differ
  under ASLR). At t=80 s, with `bufused = 147736` exactly as in the `0x5a`
  run, that window read `414141414141414141414141`: twelve attacker-chosen
  key bytes.
- The daemon stayed alive and was deliberately stopped (`rc=0`). No
  dereference, crafted pointer value or control-flow diversion was observed
  in either run.

Two key bytes (`0x5a`, `0x41`) at identical offsets and timing, with the
differing byte appearing in both the record prefix and the formerly
pointer-shaped window, confirm that those overwritten bytes originate in the
stored key record — not in an unrelated allocation. The witness's semantic
role and dereference questions remain open; this differential does not answer
them and does not by itself change the grade.

### Prolonged overflow: one observed non-deterministic fault in the live parent, not reproduced (third wake, 09:33-09:40Z)

Earlier holds stopped at 80-86 s. A longer run asked whether the corruption
eventually faults the live non-instrumented build of the pinned parent. Port
22146, 8000 keys of `0x5a`, 300 s
requested, observer confirming the overflow at t=28 s; raw trace
`daemon/long-crash-trace.txt`. At t=116 s, with `bufused = 158378` (frontier
about 27 KB past the buffer), the daemon died with `rc=-11` (SIGSEGV).

The host kernel journal recorded, at 09:32:42Z:

```
traps: mc-worker[889478] general protection fault ip:5bfa40032b1d sp:7f9656f319d0 error:0 in memcached[5bfa40024000+2e000]
```

`mc-worker` is the crawler thread. With ELF base `0x5bfa40020000` the
instruction pointer is ELF offset `0x12b1d`; `addr2line` and `nm` on this
pinned plain binary resolve it to `do_slabs_alloc`, `slabs.c:434` (inlined
into `slabs_alloc`). The disassembly at that address is
`movq $0x0,0x8(%rcx)`, i.e. the freelist pop at `slabs.c:432-434`:

```
it = (item *)p->slots;
p->slots = it->next;
if (it->next) it->next->prev = 0;
```

So the fault is a write through an invalid `it->next` taken from a slab
freelist, in the crawler worker thread, downstream of the overflow into
adjacent heap data. A core dump was not retained: `ulimit -c` was raised
process-locally but apport wrote nothing. The faulting pointer value is
therefore UNKNOWN; this does **not** establish that a `0x5a`-filled pointer
was dereferenced, nor that the value was attacker-chosen.

Caveats that keep this from being a demonstrated reliable impact:

- A second observer-confirmed run (port 22149, same 8000 keys, 150 s hold,
  `daemon/long-repro-no-crash-trace.txt`) crossed 131072 at t=28 s and kept
  going to `bufused = 169020` at t=148 s — further than the crashing run —
  then was deliberately stopped, `rc=0`. No crash. The t=116 s fault is a
  **single, non-deterministic observation**, not a stable trigger.
- A witness replay was running concurrently on port 22342 when the crash
  happened, in a separate process and on a separate port. It is noted as an
  environmental difference, not established as a cause.
- A 150 s `trigger.py` repeat without the observer also survived, but did not
  confirm the overflow, so it does not bound the crash.

Source-backed interpretation of the pointer-shaped window (inference, not
proven object identity): `item`'s first two fields are adjacent `next` and
`prev` pointers (`memcached.h:615-616`). Default slab classes step
96 → 120 → 152 → 192 → 240 → 304 → 384 bytes, and a 245-byte key with CAS
needs about 305 bytes, so these items occupy 384-byte chunks. Across both
ASLR-randomized key-byte runs the two window pointers sat at window−384 and
window+384 (768 bytes apart) — exactly one chunk either side — consistent
with item LRU or freelist links. The corrupted freelist write above is
consistent with that interpretation, but no object identity was observed.

Fix-sensitivity control (09:38-09:41Z): a plain (non-ASan) build of the pinned
fixed tree was produced by rebuilding the already-configured parent-plain
tree with `fixed/crawler.c` (that file is the only source difference from the
parent). Running the identical observer and trigger for 150 s on port 22150
kept `bufused = 123009` from t=0 to t=148 — it never crossed 131072 — and the
daemon was alive at the deliberate stop (`rc=0`). Trace:
`daemon/fixed-plain-150s-trace.txt`. The earlier `fixed/` ASan build was not
used as a control: it exits on an unrelated 40-byte leak report and so is not
comparable to the plain parent.

## Reproduced, non-deterministic pointer dereference of overflow-stream bytes in the live parent (fifth wake, 09:53-10:04Z)

Witness #784 returned **ESTABLISHED AS CLAIMED** on this crash/DoS limb;
the accepted grade is unchanged at #751. It converts the earlier single,
non-deterministic fault into a reproduced, fix-sensitive crash whose
faulting pointer value was captured and shown to be **overflow-stream
content** — attacker-written key bytes in some runs and a metadump
metadata fragment in others, not a crafted address. The fault is not
deterministic in every run (see the preserved negative below).

- Method: the pinned plain parent binary
  `daemon/parent-plain/memcached` was run under gdb with **no breakpoints** —
  only `SIGSEGV`/`SIGBUS` stops — so the previous tooling negative (a per-item
  breakpoint injecting EINTR into the 1000 ms `poll()`) does not apply. ASLR was
  left enabled (`set disable-randomization off`). A loopback client stored
  8000 keys of the chosen byte, issued `lru_crawler metadump all` on a stalled
  `SO_RCVBUF=4096` socket, then drove continuous `set` commands on a second
  loopback socket so the corrupted heap links were actually traversed.
  Driver and gdb scripts are gitignored under `daemon/`
  (`gdb-fault.sh`, `gdb-capture-aslr.gdb`, `trigger_stress.py`).
- Fault: `Thread 5 "mc-worker"`, `assoc_find` at `assoc.c:87`; faulting
  instruction `assoc_find+126` is `movzbl 0x29(%rbx),%eax` reading
  `it->nkey` from a hash-bucket chain item. Disassembly shows `rbx` loaded
  from `primary_hashtable[hv & mask]`, so the corrupted field is the **hash
  chain item pointer** (`item` at offset 0 of the bucket link).
- Overflow-stream identity: two independent ASLR-on runs with key byte `0x5a`
  (ports 22162 and 22167) both faulted with
  `RBX=0x5a5a5a5a5a5a5a5a` — eight attacker-written key bytes, non-canonical,
  unmapped. Raw captures: `daemon/gdb-fault-p22162-095849.txt` and
  `daemon/gdb-fault-p22167-100319.txt`. A `0x41` run (port 22165) faulted at
  the same instruction with `RBX=0x6163203439313535`, an ASCII metadump-text
  fragment (`daemon/gdb-fault-p22165-095953.txt`): the site is stable, the
  exact eight-byte window varies with the written byte stream. In the
  witness's independent replays, p22185 faulted with `0x5a`×8 and p22180
  with `RBX=0x206f6e3d68637465` (`b'etch=no '`, a `fetch=%s` metadump field
  fragment from `crawler.c:304/:325`). Every captured value is
  overflow-stream content, not a reconstructed heap pointer.
- Fix sensitivity: the pinned **fixed** tree (its `crawler.c` is the only
  source difference) under the identical trigger and gdb script ran 90 s,
  completed 42,770 `set` commands and never faulted
  (`daemon/fixed-gdb-fixed-p22166-100112.txt`). The parent faults after
  about 20,462 sets (~42 s). The fixed build's `bufused` is known to plateau
  at 123009, below 131072.
- Preserved negative: a supplementary ASLR-on `0x5a` run on port 22168, with
  the same trigger and a gdb script extended to print `active_crawler_mod.c`
  at the stop, completed 70,642 `set` commands over 150 s **without** faulting
  (`daemon/gdb-fault-p22168-100757.txt`, `daemon/gdb-trigger-p22168-100757.log`).
  Of four gdb stress runs, three faulted (one with ASLR disabled, two ASLR-on
  with the chosen pointer captured) and one did not; the fifth-wake non-stress
  gdb run on port 22160 also did not fault. The crash is therefore itself
  allocator-state dependent, consistent with the accepted pointer-window
  counterexample. The frontier-reading gdb script
  (`daemon/gdb-capture-frontier.gdb`) remains available but produced no stop
  in its one use, so no direct in-run frontier value was obtained.

Caveats, preserved: the debugger was present to capture registers, though it
used no breakpoints and the binary is unmodified; ASLR was on; the overflow
frontier was **not** directly observed in the faulting gdb runs because the
`/proc` observer must be the daemon's parent and gdb is the parent here — that
the sequence crosses 131072 at t≈28 s is inferred from earlier observer runs
with the identical store and metadump, plus the fix-sensitivity and the
overflow-stream identity of the faulting value. The `0x5a` value is a uniform
filler, not a crafted canonical address; the earlier two natural GPFs remain
single observations with UNKNOWN faulting values. No control-flow diversion,
function-pointer overwrite or execution was observed. All sockets were
127.0.0.1.

Structural barrier to the remaining chain (source-backed): `uriencode_init()`
in the pinned `util.c:15-27` leaves literal only `isalnum` and `-._~`;
every other byte — NUL, `0x7f`, all high bytes — is expanded to three ASCII
characters `%XX` by `uriencode_p()` (`util.c:49-62`). A canonical x86-64
user-space address therefore cannot be emitted through the key path: any
pointer assembled from literal overflow bytes is non-canonical and faults on
dereference. This explains why the reachable impact is a crash and why
chosen-address control or execution is not demonstrable with this primitive.

## No-debugger register capture of the same fault (seventh wake, 10:25-10:39Z)

The fifth-wake capture used gdb with no breakpoints, but a debugger was still
the daemon's parent. This wake removes that caveat from the capture itself:
`daemon/sigctx.c` is a minimal `LD_PRELOAD` shim whose SIGSEGV/SIGBUS handler
prints the kernel-supplied `ucontext` registers at the fault and exits. It
uses no ptrace, breakpoint, live signal or in-run heap allocation. The pinned
plain parent binary is unmodified, ASLR is on, and every socket is 127.0.0.1.
`daemon/sigctx-fault.sh` starts the committed stress trigger and the daemon.

Two independent `0x5a` runs (ports 22390 and 22392) exited 139 after exactly
20,462 stress sets (~42 s). Both printed `RBX=0x5a5a5a5a5a5a5a5a` and
`RAX=0x000000000000005a`. The first printed
`RIP=0x00005ce0ca3235d7`: its low 12 bits `0x5d7` match `assoc_find+126`,
whose file offset is `0x17559 + 126 = 0x175d7` (`nm` and `objdump -d` on the
unmodified binary show `movzbl 0x29(%rbx),%eax` there); subtracting that
offset gives the page-aligned PIE base `0x00005ce0ca30c000`. RBX is the
hash-bucket chain item pointer that instruction dereferences, so the faulting
value is eight attacker-written key bytes — overflow-stream content — with no
debugger attached. Raw logs: `daemon/sigctx-p22390-102558-daemon.log` and
`daemon/sigctx-p22392-103024-daemon.log` (gitignored lab artifacts).

Preserved negatives and a tooling confound: a `0x41` run on port 22391 and a
`0x5a` run on port 22393 used a shim variant whose constructor read
`/proc/self/maps` to print the load base; both completed the full 120 s hold
(56,895 and 56,999 sets) without faulting. That variant allocates a `FILE`
buffer at process startup, so it is itself a heap-layout perturbation; its
printed `RIP_REL=0x135d7` came from matching the shim mapping, not the daemon
executable, and was discarded. With the final minimal shim, a `0x41` run on
port 22394 completed 42,764 sets in 90 s and a `0x5a` run on port 22395
completed 42,758 sets in 90 s, both without faulting. Crash timing is
therefore non-deterministic across runs (as already accepted for the pointer
window); the two early faults are real, the four no-fault runs are preserved,
and `si_addr=0` on the faulting runs is reported as observed rather than
interpreted. No crafted address, function-pointer overwrite, execution or
control-flow diversion was observed. This improves the capture method, not the
grade: rung 4 stays ◐ at witness verdict #751. Witness #784 accepted the
fifth-wake gdb crash limb; this no-debugger capture went to the witness as
addendum #795 and, per #784, no further replay is owed.

## Witness verdict #751 (fourth wake) — accepted with wording condition

The witness replayed the daemon evidence independently and returned
**ESTABLISHED AS CLAIMED on the chosen-byte limb**. Accepted: rung 3 in the
real daemon, and rung 4 chosen bytes at chosen offsets in a live
non-instrumented build of the pinned parent. Explicitly not accepted or made:
any pointer-control, dereference, execution or control-flow claim.

Reproduction conditions the witness checked: pinned vulnerable build with
`-g -O1 -fno-omit-frame-pointer` (not a distro binary); 8000 keys of 245
bytes; stalled `lru_crawler metadump all` client with `SO_RCVBUF=4096`; ~80 s
hold; 64 MB daemon; uniform key byte; no crafted pointer value. These match
the build and trigger sections above.

Method the witness verified: the observer is byte-identical to `HEAD`;
`parent-plain/crawler.c` sha256 `b8226811…` matches the pin; `nm` and DWARF
put `active_crawler_mod` at `0x54320` and pinned `crawler.c:28-34,53-59` give
module offsets `+16/+20/+24/+32`, so the `/proc/pid/mem` read is source-bound.

Independent replays (all 127.0.0.1): the unmodified `0x5a` run on port 22142
crossed 131072 at t=28 s (130834 → 131460), grew +626 per 2 s, first OOB
sample `5a5a5a5a5a5a303436393620`, with `0x5a` at +512/+1024/+2048 and
+16384 by t=80 s when `bufused=147736`, rc=0. Four `0x41` replays (ports
22342/22344/22356/22358): same t=28 crossing and t=80 frontier, OOB prefix
`414141414141…` and `0x41` at the same offsets. Rung 3: ASan parent port 22322
rc=134, `WRITE of size 1`, thread T7, `uriencode_p util.c:57` →
`crawler_metadump_eval crawler.c:310` → `item_crawler_thread :673`, 0 bytes
after a 131072-byte region allocated at `lru_crawler_set_client :825`; the
fixed tree on port 22324 returned rc=0 with no ASan report and `Exiting
normally`.

Counterexamples the witness hunted, preserved here: (1) the pointer-shaped
victim is **allocator-state dependent**, not stable — both witness `0x5a`
runs held `000000000000000000000000` at `buf+131072+16384` from t=28 to t=78,
while both `0x41` runs and this plant's two traces held 16-byte-aligned
addresses inside the arena; it is real pointer-shaped heap data when present
but semantically unidentified, and the grade does not depend on it. (2)
Far-field offsets +32768/+65536/+131072 stayed zero through t=84 — writes are
frontier-local. (3) No-metadump control: `buf=0/bufused=0`, rc=0. (4) Fixed
non-ASan build plateaus at `bufused=123009`, no OOB samples, rc=0. (5) One of
four `0x41` runs ended rc=-11 during SIGTERM shutdown after overwrite; three
`0x41` and two `0x5a` runs ended rc=0 — preserved as an unexplained
observation, not a grade basis; no dereference was observed while the daemon
ran.

Wording condition (grade unaffected), applied in this report and the status
surfaces: say "live non-instrumented build of the pinned parent" instead of
"live stock daemon", and label the pointer-victim overwrite conditional on
allocator state. No replay owed.

## Witness disposition #762 (sixth wake) — t=116 s fault stays non-deterministic

The witness dispositioned its own #750 query about the prolonged-daemon
SIGSEGV at t=116 s in `do_slabs_alloc`. Verdict: it does **not** change the
#710/#734 grade. The ESTABLISHED limb stays chosen bytes at chosen offsets in
a live non-instrumented build of the pinned parent; the pointer-victim
overwrite remains conditional on allocator state and is not a grade basis;
no pointer-control, dereference, execution or control-flow claim. No replay
owed. This matches the preservation already in the "Prolonged overflow"
section above: one non-deterministic fault, no core, faulting value UNKNOWN,
disassembly a zero-store through an invalid freelist pointer rather than a
chosen value, and a second observer-confirmed 150 s run reaching
`bufused=169020` without crashing. The witness also notes the fault lies
beyond its W53 observation window (86 s holds), so it does not contradict
that run's scoped statement that no dereference was observed while the daemon
was alive. The heading and body wording above are aligned with the #751
condition.

## Witness verdict #784 (eighth wake) — crash limb ESTABLISHED AS CLAIMED

Witness independent verdict on #773/#776 (commits `885d44f`/`0ff4a38`):
**ESTABLISHED AS CLAIMED** on the fifth-wake crash/DoS limb, **grade
unchanged at #751**. The witness hash-matched all four pinned files against
`PROVENANCE.md` in its own copy, rebuilt both plain binaries from scratch in
`/tmp` with `-g -O1 -fno-omit-frame-pointer`, and used HEAD-committed
`trigger_stress.py` + `gdb-capture-aslr.gdb` from a git archive on its own
loopback ports. It source-bound the fault site in byte-identical `assoc.c`
(`assoc_find+99` loads `primary_hashtable`, `+106 mov (%rax,%rdx,8),%rbx`,
`+126 movzbl 0x29(%rbx),%eax` = `it->nkey`).

Independent observations: p22185 (`0x5a`, rebuilt vulnerable binary) SIGSEGV
at `assoc_find+126` / `assoc.c:87` after 20,462 sets (~42 s) with
`RBX=0x5a5a5a5a5a5a5a5a5a` and the search key printing as eight `Z`s;
backtrace `complete_nread_ascii (proto_text.c:163) -> store_item
(thread.c:968) -> do_store_item (memcached.c:1549) -> do_item_get
(items.c:975) -> assoc_find (assoc.c:87)`, a normal ASCII `set` traversing
the corrupted chain. p22180 faulted at the same site after 18,983 sets with
`RBX=0x206f6e3d68637465` = `b'etch=no '`, a `fetch=%s` metadump field
fragment — other overflow-stream content, not a heap pointer. Rebuilt fixed
binary p22182 ran 90 s / 42,686 sets without fault; the same vulnerable
binary under set stress with **no** stalled metadump (p22186) ran 90 s /
42,706 sets without fault, so the crash needs the overflow path.

Conditions preserved: non-deterministic — three of five vulnerable +
metadump + stress runs did not fault (57,074 / >55k / 56,961 sets), matching
this plant's #776 correction; gdb present only to capture registers, no
breakpoints; no in-run frontier observed (crossing at t≈28 s stays inferred
from observer runs, fix sensitivity and byte identity). `uriencode_init()`
passing literal only alnum and `-._~` is source-bound, so a canonical chosen
address cannot be emitted through the key path. The witness's wording nit,
applied throughout these surfaces: call the faulting value **overflow-stream
content** (`0x5a`×8 in two of this plant's runs and one witness run; a
metadata fragment in the witness's other fault and this plant's `0x41`
run), and keep "not deterministic" adjacent to "reproduced" in the
fifth-wake headline. No further replay owed; next owner memcached2shell for
report wording only.

The #751 statement "no dereference claim" was scoped to its own replay and
is not contradicted by #784: #784 adds a reproduced, fix-sensitive,
overflow-dependent daemon SIGSEGV at a source-bound site without moving the
grade, and makes no address-control, control-flow diversion or execution
claim.

## Ninth wake (11:0xZ): provenance and source-bound checks, grade unchanged

No new probe was run. Three open claims were checked against pinned source and
public records; all three are preserved as negative or narrowing findings.

- **CVE/GHSA remains UNKNOWN, not a proven negative.** The original
  researcher's public disclosure
  (`https://github.com/dinosn/memcached-security-2026/blob/master/DISCLOSURE.md`,
  read 2026-11-21) records private reporting on 2026-07-06, maintainer
  confirmation and fixes on 2026-07-07, and release in 1.6.44, with **no CVE
  or GHSA identifier** for either finding. Ubuntu LP#2161693 (read same time)
  also names no CVE and records a reviewer asking why a CVE fix was going
  through the SRU process; openSUSE-SU-2026:21872-1 cites only bsc#1270716.
  A search did surface CVE-2026-90698, but it is a **different** memcached
  defect (mcmc Tokenizer, `proto_text.c try_read_command_asciiauth`
  out-of-bounds, published 2026-09-14), not this crawler path. No identifier
  for this bug was found; that stays UNKNOWN as before.
- **The second defect at pinned `:499` is an accounting bug, not an OOB read.**
  Re-reading `lru_crawler_write()` in `pins/crawler.c.vuln` (`:452-505`):
  `sent` is `unsigned int`; an EAGAIN `total == -1` added unconditionally
  decrements `sent` (or wraps it to `UINT_MAX` when `sent == 0`), so the
  `while (sent < data_size)` loop exits and `c->bufused = 0` runs. The huge
  `data_size - sent` value is never passed to `write()` because the loop
  condition fails first. No information-disclosure limb follows from this
  defect in the pinned code; rung 2 stays the false-success accounting
  observation already recorded in `reports/frontier-memcached2shell.md`.
- **Chosen-address barrier re-confirmed from pinned `:282-371`.** Every byte
  emitted by `crawler_metadump_eval()` is either `uriencode_p()` output on
  the key, decimal `itoa_*` output, or an ASCII literal (`key=`,
  `fetch=no `, spaces, `\n`). No NUL or other non-ASCII byte can appear, so
  a canonical x86-64 pointer (upper bytes zero) cannot be assembled in the
  overflow stream. This is why the accepted impact is a non-canonical
  pointer dereference (DoS), not address control.

Grade unchanged at #751/#784; no witness replay owed.



