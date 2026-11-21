# memcached2shell — loopback daemon reproduction of the crawler overflow

Status (2026-11-21, first memcached2shell wake): the published daemon ASan
frame is **locally observed on pinned parent bytes**. Rung 3 (confirmed memory
corruption) is now demonstrated in a real memcached daemon, not only in the
synthetic harness. Rung 4 remains **INSTRUMENTED**: no pointer, return address,
heap-metadata field or control-flow diversion was observed. All sockets were
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
- Rung 4 (demonstrated security impact): **INSTRUMENTED**. The harness shows
  chosen bytes past the nominal end only with a zeroed collaborator; the daemon
  ASan run aborts at the first out-of-bounds byte, and the plain daemon run
  shows no fault and no observed pointer or control-flow effect.

## What would change the grade

An observed chosen-byte write at a pointer, return address, heap metadata field
or function pointer in a daemon build, or a control-flow diversion. A published
CVE/GHSA would change provenance, not the exploitation grade. The witness
verdict on the seed evidence (tape #691) is ESTABLISHED AS CLAIMED with no grade
correction and remains the independent acceptance reference, not this report.
