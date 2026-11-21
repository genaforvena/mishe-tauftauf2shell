# gpfdist2shell — live loopback build evidence (CVE-2026-122042)

**Status (2026-11-21, first gpfdist2shell wake):** the harness result from
`reports/frontier-gpfdist2shell.md` has been extended to a live 127.0.0.1
listener running the **real pinned WarehousePG 7.6.1 `gpfdist.c`**. A chosen
value (`1`, then `2`, then `3`) is written byte-for-byte into a real APR-pool
neighbour — the session path string — at `seq_segs + 24`. A symbolised ASan
SEGV report fires at the real `gpfdist.c:1988` frame for a large hostile index.
The fixed 7.6.2 source rejects the same requests. This report is evidence, not
independent acceptance; the witness still replays it.

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
   positive index in this allocation order — a measured structural limit, not
   an exploitation result.

4. **Availability effect.** A session created with `id=3, count=1` is freed
   right after its first request: `active_segids[3]=1` leaves index 0 zero and
   `session_active_segs_isempty()` (`:2075-2087`) sees an empty array. Log:
   `free session …` immediately after the successful hostile request. This is
   consistent with the advisory's availability-only `VA:H` scoring.

5. **Fixed source, same build recipe.** 7.6.2 rejects the chain at the create
   and join guards: `400 bad request, invalid segment id or count` for
   `id=3`, while the in-bounds `id=0` request still returns 200
   (`evidence/http_oracle_chosen.txt`, `evidence/http_oracle_basic.txt`).

## Rung assessment

- Rungs 1/2/3: ESTABLISHED in the extracted harness (frontier, independently
  replayed by witness #805) and independently corroborated here by a live ASan
  SEGV at the real `:1988` frame.
- Rung 4: LIVE-BUILD DEMONSTRATED for chosen small values at
  `seq_segs+24` in a real APR neighbour, with byte-for-byte debugger evidence
  and an HTTP oracle in a loopback process running the real pinned source.

## Preserved negatives and limits

- **ASan is clean on the `id=3` writes.** Real `apr_pcalloc` carves small
  objects from one pool block; the past-end stores stay inside a valid malloc
  region, so ASan does not report them here. This does not contradict the
  harness's `heap-buffer-overflow` (that used exact `calloc`), and it is the
  reason the live proof uses gdb and the sequence oracle. A crash appears only
  for a large index that leaves the pool block entirely.
- **No arbitrary 64-bit value in the live build.** The `:3502` equality check
  only advances the slot by one per DATA request; reaching
  `0x4141414141414141` would need ~4.7e18 requests. The harness's chosen
  8-byte value remains INSTRUMENTED-only. Values written live here are `1`,
  `2`, `3`.
- **No pointer overwrite, control-flow diversion, marker execution or stock
  binary behaviour was observed.** The reachable neighbours at small positive
  indices are strings, not pointers; nothing here demonstrates code control.
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
# gdb transcript: gdb -q -batch -x lab/gpfdist2shell-live/gdb_chain3.gdb \
#   lab/gpfdist2shell-live/gpfdist_v761_asan  (then send the four requests
#   from probe_chosen.sh to 127.0.0.1:18097)
```

All inputs are local header values from the vendor regression test and the
frontier brief; no probe leaves loopback.

## What would change this assessment

A bounds check before either 7.6.1 store, a default listener that
authenticates, a live neighbour layout putting every positive index in
unmapped memory, or 7.6.2 accepting the hostile request would lower the grade.
A measured pointer-valued neighbour at a reachable index would raise the
security-impact question, but none was observed here.
