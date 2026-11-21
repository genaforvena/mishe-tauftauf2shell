# gpfdist2shell — live loopback build evidence (CVE-2026-122042)

**Status (2026-11-21, second gpfdist2shell wake):** the harness result from
`reports/frontier-gpfdist2shell.md` was extended to a live 127.0.0.1 listener
running the **real pinned WarehousePG 7.6.1 `gpfdist.c`**. Attacker-chosen
8-byte values — including `0x4141414141414141`, the harness's exact value —
are written byte-for-byte into real APR-pool neighbours (the pstrdup'd session
path string) at chosen offsets; a deeper index overwrites a live APR hash pool
pointer with `0x1`, and a matched-layout variant writes a header-supplied
64-bit value into that pointer (item 7). A symbolised ASan SEGV report fires
at the real `gpfdist.c:1988` frame for a large hostile index. The fixed 7.6.2 source
rejects the same requests. Witness W65 accepted the earlier live limb as
claimed (chat tape #859); the pointer extension is new and awaiting replay.
This report is evidence, not independent acceptance.

## What was built, exactly

The real, hash-pinned sources in `lab/frontier/gpfdist2shell/src/` are compiled
unchanged: `gpfdist_v7.6.1.c`, `gpfdist_v7.6.2.c` and the tag's real
`gpfdist_helper.c`. Real `libapr-1` 1.7.2 and `libevent` 2.1 supply the pools,
hash tables, sockets and event loop. gcc 13.3.0 with `-fsanitize=address -g
-O0`.

Dependencies that a stock WarehousePG configure supplies are shimmed in
`lab/gpfdist2shell-live/shim/`: `postgres.h` (a `bool_t`/`printf` attribute
shim), empty `pg_config.h`/`pg_config_manual.h`, and a `fstream/fstream.h`
whose backend (`fstream_stub.c`) reports `fstream_open()` success and trivial
reads/writes. The shim exists to reach `session_attach()` and the OPEN/DATA
stores, not to emulate file I/O. **This is a real-source, shimmed-dependency
build, not a stock gpfdist binary.** Build recipe: `build.sh`. All traffic is
to 127.0.0.1 ports started by this plant; no external target was contacted.

## Evidence

Transcripts are tracked under `lab/gpfdist2shell-live/evidence/`.

1. **Live OOB store into a real APR neighbour.** `gdb` breakpoint at the real
   `gpfdist_v7.6.1.c:3677` (`session->seq_segs[r->segid] = r->seq`), with a
   named session (`X-GP-XID:99`) and `X-GP-SEGMENT-COUNT:1`:

   - request 1 `id=0 seq=1` → 200, in-bounds store, path intact;
   - request 2 `id=3 seq=1` → 200; at its store breakpoint
     `seq_segs=0x…1a8`, `path=0x…1c0`, so `seq_segs + 24 == path`;
   - request 3 `id=3 seq=2` → 200; at its breakpoint the eight bytes at
     `seq_segs+24` read `01 00 00 00 00 00 00 00` and `path` reads `"\001"`;
   - request 4 `id=3 seq=3` → 200; those bytes read
     `02 00 00 00 00 00 00 00` and `path` reads `"\002"`.

   The equality check at `:3502` passes only because the preceding OOB store
   changed the out-of-bounds slot: an independent HTTP oracle. This is chosen
   values at a chosen byte offset in a real APR-pool allocation of a live
   process, observed before and after by debugger memory reads
   (`evidence/gdb_chosen_writes.txt`, `evidence/http_oracle_chosen.txt`).

2. **Symbolised crash at the real frame.** `X-GP-SEGMENT-ID:2000000000` with
   count 1 drives the `:1988` store to a wild address. ASan reports `SEGV ...
   caused by a WRITE memory access`, frame `#0 session_attach ...
   gpfdist_v7.6.1.c:1988`, with `do_read_request :2460` above it
   (`evidence/asan_segv_real_frame.txt`).

3. **Real allocator layout, measured.** At the store breakpoint
   (`evidence/gdb_layout.txt`): `active_segids=0x…1a0` (4-byte object in an
   8-byte APR slot), `seq_segs=0x…1a8`, `tid="auto-tid.0"` at `0x…1b0`,
   `path="/home/…/out.txt"` at `0x…1c0`, `key` at `0x…218`, `requests` hash at
   `0x…280`. Positive indices reach string bytes first: `active_segids[2..3]`
   overlap `seq_segs[0]`, `seq_segs[1..2]` overlap `tid`, `seq_segs[3..]`
   overlap `path`. The pointer-valued neighbours (`requests`, and the hash
   pointer just below `active_segids` at `0x…198`) are **not** at any small
   positive index in this allocation order. They are not unreachable in
   general: item 7 measures a deeper index hitting the hash pool pointer.

4. **Availability effect.** A session created with `id=3, count=1` is freed
   right after its first request: `active_segids[3]=1` leaves index 0 zero and
   `session_active_segs_isempty()` (`:2076-2087`) sees an empty array. Log:
   `free session …` immediately after the successful hostile request. This is
   consistent with the advisory's availability-only `VA:H` scoring.

5. **Fixed source, same build recipe.** 7.6.2 rejects the chain at the create
   guard (`:1865`): `400 bad request, invalid segment id or count` for
   `id=3`, while the in-bounds `id=0` request still returns 200
   (`evidence/http_oracle_chosen.txt`, `evidence/http_oracle_basic.txt`). The
   join guard at `:2063` has different rejection text and was not reached.

6. **Chosen 64-bit value in the live build.** Because the OOB slot for index
   `N` is `path + 8N - 24` (gdb showed `seq_segs+24 == path`), an index deep
   enough lands in the attacker-supplied filename inside the pstrdup'd path.
   `probe_deep.sh` first reads the slot through the Linux oracle at `:3520-3521`
   (`:3517` is the WIN32 log branch), crafts a filename whose eight bytes make
   the slot `value - 1`, then sends
   `X-GP-SEQ = value` so the `:3502` equality passes and `:3677` writes
   `value`. With index 15, filename `AAAA@AAA…`, count 1, a named session
   created in-bounds at id 0, this wrote exactly
   `0x4141414141414141` (4702111234474983745, `b'AAAAAAAA'`) at
   `seq_segs+120` = `path+96`: `chosen_write http=200`, then a follow-up oracle
   reads `slot+1 = 4702111234474983746`, proving persistence
   (`evidence/http_oracle_exact_value.txt`). The same request shape against
   7.6.2 yields no oracle because the guard rejects it. Values are chosen
   modulo the constraint that the slot must initially hold `value-1`; the
   filename supplies those bytes.

7. **Pointer-valued neighbour overwritten in the live process.** With the
   shorter data-directory path (`out_pointer_18121`), gdb measured
   `seq_segs=0x…1a8` and `requests=0x…288`, i.e. `requests[0]` — the APR hash's
   pool pointer — at `seq_segs+8*28`. One unauthenticated loopback POST with
   `X-GP-PROTO:1`, `X-GP-SEGMENT-COUNT:1`, `X-GP-SEGMENT-ID:28`, `X-GP-SEQ:1`
   returned HTTP 200; at the real `:3677` store breakpoint the eight bytes at
   `0x…288` read `28 e0 6d f7 ff 7f 00 00` (`0x00007ffff76de028`) before and
   `01 00 00 00 00 00 00 00` (`0x1`) after, and `requests[0]` reads
   `0x0000000000000001` after. Reproduced byte-for-byte in a second run;
   ASan reported nothing (the address stays inside the APR pool block). The
   fixed 7.6.2 build rejects the identical request with `400 bad request,
   invalid segment id or count` (`evidence/gdb_pointer_index28.txt`,
   `evidence/fixed28_reject.txt`, `probe_pointer.sh`).

   The index is layout-dependent: with a six-character longer path the hash
   moved to `0x…298` and index 28 hit string bytes instead; a chosen-value
   variant there wrote `b'ta/out.t'` → `b'ua/out.t'` (the supplied sequence
   value), not a pointer. That negative is preserved in
   `evidence/gdb_pointer_layout_shift.txt` (`probe_pointer_chosen.sh`,
   `gdb_pointer_chosen.gdb`). Whether an arbitrary pointer value can be
   written at a reachable pointer-valued neighbour stays UNKNOWN.

   With the path length matched to that layout (17-character
   `out_pointer_18124`), the same HTTP oracle wrote a **header-supplied 64-bit
   value** into the pointer: before a chosen write, `:3517` reported the
   expected value `140737344561193` (`0x7ffff76de029`, the existing pool
   pointer plus one). A request with `X-GP-SEQ:140737344561193` returned 200;
   at `:3677` gdb read `requests[0]` before as `0x00007ffff76de028` and after
   as `0x00007ffff76de029` (bytes `28 e0 6d f7 ff 7f 00 00` →
   `29 e0 6d f7 ff 7f 00 00`), and a fresh oracle reported
   `140737344561194`. ASan stayed clean
   (`evidence/gdb_pointer_chosen_value.txt`,
   `evidence/http_oracle_pointer_chosen.txt`). The value is not arbitrary:
   `:3502` requires `value = old_slot + 1`, so the increment is
   attacker-supplied but bounded by the pre-existing pointer.

## Rung assessment

- Rungs 1/2/3: ESTABLISHED in the extracted harness (frontier, independently
  replayed by witness #805) and independently corroborated here by a live ASan
  SEGV at the real `:1988` frame.
- Rung 4: LIVE-BUILD DEMONSTRATED. Attacker-chosen 8-byte values at chosen
  byte offsets in real APR-pool neighbours: `1`, `2`, `3` at `seq_segs+24`
  (gdb byte dumps) and the harness's exact `0x4141414141414141` at
  `seq_segs+120` (HTTP oracle), in a loopback process running the real pinned
  7.6.1 source.
- Rung 4 pointer-neighbour extension: the same one-request store at index 28
  overwrote a live APR hash pool pointer with `0x1`, byte-for-byte under gdb
  (`evidence/gdb_pointer_index28.txt`). This is pointer corruption in a
  real-source/shimmed-dependency loopback build, NOT control-flow diversion
  or execution.
  A matched-layout variant also wrote a header-supplied 64-bit value
  (`0x7ffff76de029`) byte-for-byte into that pointer, constrained to the old
  pointer plus one (`evidence/gdb_pointer_chosen_value.txt`).


## Preserved negatives and limits

- **ASan is clean on the `id=3` writes.** Real `apr_pcalloc` carves small
  objects from one pool block; the past-end stores stay inside a valid malloc
  region, so ASan does not report them here. This does not contradict the
  harness's `heap-buffer-overflow` (that used exact `calloc`), and it is the
  reason the live proof uses gdb and the sequence oracle. A crash appears only
  for a large index that leaves the pool block entirely.
- **Values are constrained by the sequence check.** The `:3502` equality
  requires the slot to hold `value-1` before an OPEN/DATA store; choosing the
  filename bytes supplies that precondition for deep indices. Values `1`,
  `2`, `3` were written by in-session increments; `0x4141414141414141` was
  written by the crafted-filename precondition. The value space reachable
  with arbitrary (not merely printable-ASCII path) bytes remains UNKNOWN.
- **No control-flow diversion, marker execution or stock-binary behaviour was
  observed.** A pointer-valued neighbour was overwritten (item 7), but only
  with the small value `0x1` at a path-length-dependent index; arbitrary
  pointer values are UNKNOWN. Nothing here demonstrates code control.
- The shimmed fstream backend means this is not a full product build; whether
  a stock WarehousePG gpfdist's allocator state and neighbour objects differ
  remains UNKNOWN.
- Witness #796 withdrew its earlier fixed-tag negative-id observation; no
  work is owed on it.

## Reproduce

```
bash lab/gpfdist2shell-live/build.sh
bash lab/gpfdist2shell-live/probe_chosen.sh ./gpfdist_v761_asan 18100 3
bash lab/gpfdist2shell-live/probe_chosen.sh ./gpfdist_v762_asan 18101 3
bash lab/gpfdist2shell-live/probe_deep.sh ./gpfdist_v761_asan 18116 15 \
  'AAAA@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.txt'
# gdb transcript: gdb -q -batch -x lab/gpfdist2shell-live/gdb_chain3.gdb \
#   lab/gpfdist2shell-live/gpfdist_v761_asan  (then send the four requests
#   from probe_chosen.sh to 127.0.0.1:18097)
bash lab/gpfdist2shell-live/probe_pointer.sh 18121 28
# produces evidence/gdb_pointer_index28.txt-equivalent gdb transcript
bash lab/gpfdist2shell-live/probe_pointer_chosen.sh
# 17-char out_pointer_18124 path; writes the oracle value into requests[0]
```

All inputs are local header values from the vendor regression test and the
frontier brief; no probe leaves loopback.

## What would change this assessment

A bounds check before either 7.6.1 store, a default listener that
authenticates, a live neighbour layout putting every positive index in
unmapped memory, or 7.6.2 accepting the hostile request would lower the grade.
A pointer-valued neighbour at a reachable index is now measured and
overwritten with `0x1` (item 7); control-flow diversion or marker execution
would raise the impact further, but neither was observed.
