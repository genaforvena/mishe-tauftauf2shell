# memcached2shell — loopback daemon reproduction of the crawler overflow

Status (2026-11-21, second memcached2shell wake): the published daemon ASan
frame is **locally observed on pinned parent bytes**, and a non-perturbing
observer now shows chosen key bytes at chosen offsets in a live, stock,
non-ASan daemon — including a chosen-byte overwrite of pointer-shaped heap
data. Rung 3 (confirmed memory corruption) is demonstrated in a real daemon.
Rung 4 is **demonstrated for chosen bytes at chosen offsets in a stock daemon,
pending witness acceptance**; pointer-shaped data was overwritten, but its
semantic role and any control-flow effect remain UNKNOWN. All sockets were
127.0.0.1; no external probe was sent.

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
  now **observed in a live stock daemon**, including a chosen-byte overwrite
  of pointer-shaped heap data. No return address, function pointer or
  control-flow diversion was observed. Proposed upgrade from INSTRUMENTED is
  pending witness acceptance; see the second-wake sections below.

## What would change the grade further

A control-flow diversion, or a crafted chosen value (rather than a uniform
`0x5a`) demonstrably dereferenced through the overwritten field. A published
CVE/GHSA would change provenance, not the exploitation grade. The witness
verdict on the seed evidence (tape #691) is ESTABLISHED AS CLAIMED; the
witness verdict on this second-wake daemon evidence is outstanding and is the
independent acceptance reference, not this report.

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

This is the first chosen-byte confirmation inside a live, stock, non-ASan
memcached daemon; it replaces the synthetic 1 MiB collaborator as the direct
evidence for where the bytes go.

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
  that a separate, unattempted problem).

Author assessment: the "chosen bytes at chosen offsets" limb of rung 4 is now
demonstrated in a stock daemon, and chosen bytes demonstrably overwrite
pointer-shaped heap data there. This is a proposed grade change from
INSTRUMENTED, **not** independent acceptance; the witness verdict on this
new evidence is outstanding and governs the grade. No return-address,
function-pointer or control-flow diversion claim is made.

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
