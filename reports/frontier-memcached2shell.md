# Frontier brief — memcached2Shell (memcached, no upstream CVE found)

Status: **frontier find, not admitted**. Brief written 2026-11-21T08:23Z.
Harness: `lab/frontier/memcached2shell/`; its `PROVENANCE.md` records every
pin, stub and repair. The operator owns admission; this brief never activates
a target mind by itself.

## Verified ground truth (primary sources, fetched 2026-11-21)

- Fix: commit `7eeac6e9a9945aa68298aff379cea5ab3817af7c`, dormando
  `<dormando@rydia.net>`, author date **2026-07-07T01:28:57Z** (the widely
  quoted 2026-07-06 is the release-wiki date, not the commit date). Parent
  `aa352388abf903d50e6bdd22dfb8ab9373d2896b`. Message:
  `crawler: fix buffer overflow on idle client` — "if a client starts a
  metadump/mgdump then doesn't read data the poll() timeout is handled as a
  success and we keep (sometimes) writing past the end of the buffer";
  "Reported by Nicolas Krassas <krasn@swissns.ch>".
  Sources: `https://api.github.com/repos/memcached/memcached/commits/7eeac6e9a9945aa68298aff379cea5ab3817af7c`
  and its `.patch`; pins `pins/commit.json` (`sha256=ece160a1…`) and
  `pins/fix.patch` (`sha256=8bd3348e…`).
- Release: tag `1.6.44` is an **annotated tag object**
  `7d2f9295f5685f47bf6c5fe26614e4fa382f5453` whose target is commit
  `e44dd0b01234bc0faf970e9225e3423e98022129`. Pin `pins/tag.json`
  (`sha256=ef377cf2…`). Release notes `pins/release-1.6.44.html`
  (`sha256=ff1114a8…`) call it "another security release" and list the fix;
  no CVE is assigned there. NVD keyword search for memcached lru_crawler
  returned 0 results at 08:13Z; Ubuntu LP#2161693 and openSUSE-SU-2026:21872-1
  are distro advisories. **CVE/GHSA: UNKNOWN / NO-CVE-FOUND**, not a proven
  negative.
- Claimed primitive: unauthenticated, default-configuration heap overflow via
  `lru_crawler metadump all` followed by a client that never reads. Not an
  external probe: all evidence below is from fetched source and loopback-free
  local harness runs.

## Source-bound mechanism (vulnerable parent, pinned bytes)

- `crawler.c:28-34` defines `crawler_client_t { … int buflen; int bufused;
  char *buf; }`; `:128` defines `LRU_CRAWLER_MINBUFSPACE 8192`;
  `:824-825` allocates `malloc(8192 * 16)` = **131072-byte heap buffer**.
- ASCII handler `proto_text.c:1314-1345` accepts `metadump <slab>` with only
  `settings.lru_crawler` and `settings.dump_enabled` checks; no auth gate.
  `memcached.c:266` sets `dump_enabled = true`, `:4728` sets
  `start_lru_crawler = true`, `:6055` starts the item crawler thread. `-X`
  (disable dumps) and `-o no_lru_crawler` are non-default mitigations.
  `metadump all` takes the per-LRU path; the hash path is `metadump hash`.
- `lru_crawler_write()` at `crawler.c:452-507` snapshots `data_size = bufused`,
  polls with a 1000 ms timeout, and at **`:471` returns 0 when `poll()`
  times out** while `bufused` is still nonzero. `:504` resets `bufused` only
  after the whole buffer was written. The per-LRU caller at `:628-640` treats
  `ret == 0` as success and never expands the buffer (contrast the hash path
  at `:582-587`, which calls `lru_crawler_expand_buf()`). `crawler_metadump_eval()`
  at `:282-372` therefore keeps appending at `buf + bufused` (`:307-310`,
  `:371`) with only per-item asserts (`:302`, `:370`), eventually writing
  beyond the 131072-byte allocation with attacker-stored, percent-encoded key
  bytes. `:499` also adds `total` unconditionally, so an EAGAIN `-1` makes
  `sent` wrap and the function falsely reports success — a second, separately
  preserved accounting bug.
- The fix changes only `crawler.c`: 1800 timeout retries with a 30-minute
  backstop and client close, and `sent += total` moved into the successful
  `else` branch. Local `diff -u` of the two pinned files shows exactly the
  three hunks from the upstream patch and nothing else.

## Local harness and observed rungs

`run.sh` extracts the pinned ranges verbatim under `#line` (struct, module
types, buffer constant, `KADD`/`KSP` macros, `crawler_metadump_eval`,
`lru_crawler_write`, `lru_crawler_set_client`) and drives them with synthetic
`conn`, item and `poll` stubs. It builds plain and ASan variants of both the
parent and fixed source, then writes a deterministic trace. No daemon, socket,
thread or network is involved. Full command: `cd lab/frontier/memcached2shell
&& ./run.sh`.

Latest run: **8 PASS / 0 FAIL**, trace
`sha256=5d4a05be6cebb89e7fd99e0f6d08731e47537c49d0b8396d6be73e554b51672b`.
Signed scenario outputs and trace are under `out/`.

- **Rung 1 — deterministic trigger.** Parent, stalled client (`poll()` always
  times out): `plain_fault=1`, exit 77, after ~1000 appended metadata lines.
  Fixed: 1800 polls, one close, `write_ret=-1`, no fault. This is a
  reproducible trigger in the pinned code, not a daemon reproduction.
- **Rung 2 — observed accounting failure.** Parent EAGAIN: one write call,
  zero bytes written, yet `write_ret=0` and no client close — the false-success
  contract. Fixed: 5000 bounded EAGAIN writes then timeout backstop,
  `write_ret=-1`, one close. (The harness caps poll calls at 5000 so the
  perpetual-EAGAIN loop cannot hang a replay; that cap is instrumentation.)
- **Rung 3 — ASan-confirmed corruption.** Parent ASan:
  `heap-buffer-overflow`, `WRITE of size 64`, `0 bytes after 131072-byte
  region`, append frame `crawler.c.vuln:310`, allocation frame
  `crawler.c.vuln:825`. Both fixed runs and a benign-length parent run are
  clean. The 64 bytes are the harness's verbatim copy of the stored key;
  real `uriencode_p()` percent-encodes, so the real write size is
  key-length dependent.
- **Rung 4 — INSTRUMENTED, honestly split.** With a 1 MiB zeroed collaborator
  replacing the nominal 131072-byte allocation, chosen key byte `0x5a` is
  observed past the nominal end at offsets 0, 4 and 65536 (`bounded_chosen=
  35231` of 65536 scanned bytes); an otherwise identical run with `0x41`
  keys puts `0x41` at exactly those offsets. This is chosen-byte control in a
  collaborator, not an upstream allocator property. Under a guard-mapped
  allocation the parent faults at the first byte past 131072 (exit 77), and
  the unmodified plain parent faults in host libc before any stable chosen
  bytes can be inspected: that real-libc negative is preserved. No pointer,
  return address, heap metadata field, function pointer or control-flow
  diversion was observed or attempted. The guard mapping and larger
  collaborator are instrumentation.

## Feasibility assessment

High tractability, stronger than most recent leads: default-config, pre-auth
surface; a 14/2-line upstream fix with explicit vulnerable/fixed pins; a
deterministic stalled-reader trigger; ASan corruption at pinned source lines;
independent distro advisories with a published ASAN recipe. Weaker points:
no upstream CVE/GHSA, rung 4 demonstrated only under a collaborator (the
guard-mapped and real-libc paths fault first), and no public pointer-control
claim for this bug. Overall rung 4 status: **INSTRUMENTED**, not
request-reachable, pointer-controlled or execution-proven.

Cheapest experiment to move it up a rung: build the pinned parent with ASan,
stored many loopback-only keys, issue `lru_crawler metadump all` from a client
that stops reading, and capture the daemon ASan frame plus the exact heap
layout around the 131072-byte buffer; repeat on the fixed tag for the guard.
Only an observed pointer/control-flow result would drop the INSTRUMENTED label.
If the daemon's allocator faults before chosen bytes persist, preserve that as
the same real-libc negative and cap this path at rung 3 in practice.

All advisory and reachability claims remain reproduced from public sources;
this brief proves the pinned code paths and their local memory effects, not
live-daemon exploitability, a CVE identifier, or RCE.
