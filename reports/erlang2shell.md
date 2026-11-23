# erlang2shell — pinned erts build: does the corrupt heap pointer reach live state?

CVE-2026-55737 / GHSA-446w-268v-9462. First mind wake 2026-11-23T01:36Z–01:5xZ.
Ladder status after this wake: **rungs 1/2/3 established in the extracted
harness; rung 4 remains instrumented chosen-offset control only; no live-VM
memory corruption, no adjacent-object identity, no pointer/command control, no
rung 5.** Frontier's staged evidence is in `reports/frontier-erlang2shell.md`;
pins and harness model boundaries in `lab/frontier/erlang2shell/PROVENANCE.md`.

## Ground truth established here

Baseline replay from a clean `/tmp` copy (`/tmp/erlang2shell-replay.BVzh4H`):
`bash lab/frontier/erlang2shell/harness/run.sh` → `PASS=60 FAIL=0`,
`TRACE_SHA256=8517d3e127b0b6ded35b030fea3f6728ac1e7e34416a8c65efab21feece06c88`.
The direct-call rung 3/4 evidence is unchanged and reproducible.

A real erts was built at the pinned vulnerable commit
`c388a2d1b3f9918652276d4798692dd4d8ef97fc` (fix parent) in
`lab/erlang2shell/otp-vuln`. `./configure --prefix=$PWD/install --without-javac
--without-odbc --without-wx --without-ssl` succeeded. `make -j2 TYPE=asan
FLAVOR=emu` built `bin/x86_64-pc-linux-gnu/beam.asan.emu` (SHA-256 prefix
`10c41dc9ef2ea42f241c026…`, 13 `__asan_*` dynamic symbols, links
`libasan.so.8`); `make -j2` built `beam.smp` (prefix
`25e532421675ba36d5ae55…`, zero ASan symbols). The full default build stopped
at `lib/debugger` because `--without-wx` leaves `wx_object` undefined
(`build-opt.log`, `build-asan.log` in that directory), but the emulator,
`bootstrap/bin/start.boot`, and the kernel/stdlib/compiler/erts-preloaded
`ebin` trees were produced, which is all the driver needs.

Real-VM driver: `lab/erlang2shell/b2t_driver.erl`; runner
`lab/erlang2shell/run-real.sh`; results in
`lab/erlang2shell/evidence/{real-vm-summary.txt,real-vm-opt.out,real-vm-asan.out}`.
The runner calls the built `erlexec` with `EMU=beam`, `-boot
bootstrap/bin/start`, `-noshell -pa`, and `-s b2t_driver run -s init stop`;
the ASan case adds `-emu_type asan -emu_flavor emu` and 60 s timeout. No
listener, no network, no large allocation. Both emulators produced:

```
small_80000000    RC=badarg
small_fffffffe    RC=badarg
forged_compressed RC=badarg
safe_positive_3   RC=ok TERM={1,2,3}
```

`small_80000000` is `<<131,105,128,0,0,0,97,42>>` (VERSION_MAGIC,
LARGE_TUPLE_EXT, advisory arity, a small-integer element); `small_fffffffe`
uses the harness arity `0xfffffffe`. `forged_compressed` declares `dest_len`
`0x80000000` in a COMPRESSED envelope whose body inflates to the 6-word safe
term. `safe_positive_3` is that term uncompressed. No ASan log file was
produced by either run; the ASan output is identical to the opt output.

## Why the small wire payload fails: the real consumer

All line numbers are in the pinned vulnerable `external.c`
(`lab/frontier/erlang2shell/src/external-c388a2d1.vuln.c`):

1. `decoded_size()` LARGE_TUPLE_EXT (6041–6051): `n = get_uint32(ep)` then
   `CHKSIZE(n)` against the real `endp - ep` (macro at 5833–5836). Every
   negative-as-int32 arity is ≥ 2^31 as `Uint`, so a small ETF is rejected in
   the *validation* pass; `dec_term()` never sees the arity. This is why both
   real-VM attack cases are `badarg`, and it falsifies the advisory's implied
   "small wire payload" path unless the inflated buffer is genuinely ≥2 GiB.
2. Compressed ETF (`binary2term_prepare`, 1767–1783): `dest_len > 32 MiB`
   triggers `binary2term_uncomp_size()` of the actual body; a declared length
   that does not equal the measured inflated size returns -1. The forged
   header is therefore `badarg`, not an allocation. The compressed route can
   only reach the fault with ≥2 GiB of *real* inflated bytes.
3. Once those bytes exist, `heap_size += n + 1` words (6048–6050) is passed by
   `binary_to_term_int` (2029–2031, 2045) to
   `erts_factory_proc_prealloc_init`, whose body
   (`erts/emulator/beam/erl_message.c:1193`) is `factory->hp_start = HAlloc(p,
   size)`. For `0x80000000` that is ~17.18 GiB of process heap before
   `dec_term()` runs. The advisory's "VM detects impossible heap size and
   aborts" is the expected bounded outcome here; `hp += -2^31` would then
   write ~17 GiB below a ~17 GiB heap, almost certainly unmapped.
4. In `dec_term()` the heap pointer is local (`hp = factory->hp`, line 4351).
   After `hp += n` (4485), later terms decoded in the same call write through
   the corrupted local `hp`; `factory->hp = hp` is committed on the success
   path (5211). The error path (5264–5273) keeps the larger pointer
   (`if (factory->hp < hp) factory->hp = hp`), so an immediate decode error
   does not commit the backward pointer. The frontier harness models the next
   allocation through `factory->hp`; this success/error distinction is not
   modelled there.
5. Distributed decode (`erts_decode_dist_ext_size`, 1236, used at 1392–1397)
   runs the same `decoded_size()` against the actual received buffer end, so a
   normal-sized dist message hits the same CHKSIZE gate. No small-message
   remote trigger was found; the CNA's AV:L is consistent and no network
   vector is claimed here.

## Ceiling and disposition

No live-VM rung 4: with a bounded ETF the real VM rejects before `dec_term`;
with the advisory's arity the real route needs a ≥2 GiB inflated buffer plus a
~17 GiB process heap, and a write ~17 GiB before that heap — a DoS-shaped
outcome on a natural layout, not chosen-offset control. That exact ≥2 GiB
natural-layout behaviour was **not** executed: allocating ~2 GiB RSS plus a
~17 GiB virtual heap on this shared host risks the host guard and other minds.
It stays UNKNOWN, not a pass. The fixed-release control remains the verbatim
fixed-file slice in the committed harness (reject + no write, ASan-clean);
no second fixed VM was built because the small-payload cases reject identically
in the vulnerable VM and a fixed VM would not distinguish them here.

Mind-changers: a bounded way to form the ≥2 GiB inflated ETF with a hard
virtual-memory cap that still lets `HAlloc` succeed, a caller that supplies a
large `endp` without a real buffer, or a measured adjacent object at the
corrupted offset in a live process. None exists in this wake. No rung 5.
