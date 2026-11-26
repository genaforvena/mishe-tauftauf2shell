# PROVENANCE — ctranslate22shell staged harness

Witness gate closed 2026-11-25 21:35Z: W223 replayed the one-command wrapper
from a clean `git archive` tree and returned ESTABLISHED AS LABELED at the
recorded scope (rung 3 CONFIRMED in a real consumer, rung 4 PARTIAL, NO r5).
The "witness replay UNKNOWN/owed/no verdict" lines in W1-W5 below were true
when written and are superseded by the dated verdict section at the end;
the W2/W3/W4 negative results are not affected by the replay.

## Source pins (read-only provisioning, 2026-11-25)

- `pins/model-v4.8.0.cc` — https://raw.githubusercontent.com/OpenNMT/CTranslate2/v4.8.0/src/models/model.cc
  sha256 `05ab59bb4413df14d36fbbb0d82ff6ce6fe0bee72245245f8ecec773d4cc2c65`
  (898 lines).
- `pins/model-fixed.cc` — https://raw.githubusercontent.com/OpenNMT/CTranslate2/d9b991e0700933a0c05373df8b52ed89cdcab96d/src/models/model.cc
  sha256 `5dcc3f1daa0de260c068b4645728a28305b27393f9461e650f45c8db89c707b7`
  (902 lines).
- Advisory: GHSA-7xqx-34h9-2w97 / CVE-2026-102566, 2026-09-29.
- Fix: PR #2068, merge `d9b991e0700933a0c05373df8b52ed89cdcab96d`,
  patch read from https://github.com/OpenNMT/CTranslate2/commit/d9b991e.patch .

## Verbatim ranges

- `harness/pinned_consume.h` lines 10-54 are byte-identical to vulnerable
  pin lines 43-87 (`report_stream_error` and both `consume` overloads).
  The fixed pin's `consume<std::string>` hardening at fixed `:82-85` is
  deliberately not merged into this header; the exercised buffer overload
  is byte-identical in both pins.
- `harness/probe_vuln.cpp` lines 67-85 are byte-identical to vulnerable
  pin lines 639-657 (the variable-loading caller through the OOB store).
- `harness/probe_fixed.cpp` lines 66-86 are byte-identical to fixed pin
  lines 641-661 (the same caller, including the two fix lines). Fixed
  pin line 640's `auto name = consume<std::string>(...)` is replaced by a
  stand-in string; it is upstream of the exercised store.
- `run-all.sh` re-checks every range with `diff` and both pin hashes with
  `sha256sum -c` before compiling. Rendered-source line numbers are
  claims; these local pins and fix hunks are authoritative.

## Stand-ins and negative results

- Stand-in `StorageView` allocates 16 bytes for shape `{2,2}` and float
  dtype. Under `-DMISHE_ASAN` it is a real `new char[16]` region; in the
  plain build it is a 16-byte member followed by a 32-byte marker so
  chosen bytes can be read back deterministically.
- Earlier harness iterations failed: `/bin/sh` process substitution,
  Clang not defining `__SANITIZE_ADDRESS__`, LeakSanitizer flagging the
  un-freed stand-in buffer, and a 64-byte plain payload overrunning the
  whole 48-byte fixture (`malloc(): corrupted top size`). All were repaired
  in the committed `run-all.sh`; the 64-byte case is retained as an ASan
  case only, with a 48-byte bounded case for plain readback.
- The stand-in harness alone had no real build; see the real-source consumer
  section below for the current boundary. Still no wire, pointer-IP or
  command, and witness replay UNKNOWN.

## Real-source consumer (W1, 2026-11-25 12:05-12:08Z) — NEW

Provisioned (network = provisioning only, no probe off loopback):
`realbuild/src/v4.8.0.tar.gz` sha256
`cd142054c14aa7f7a4b20674d6b5e4bb7ff9c63b919e6491d3df261b214fcfa5`.
Its `src/models/model.cc` hashes to `05ab59bb…` (identical to the vulnerable
pin); the separately fetched `realbuild/src/model-fixed.cc` hashes to
`5dcc3f1d…` (identical to the fixed pin). `build.sh` reproduces every binary
and output below offline.

Build: `realbuild/build.sh` compiles the **verbatim upstream `model.cc`**
plus real `storage_view.cc`, `allocator.cc`, `cpu/allocator.cc`,
`cpu/primitives.cc`, `cpu/backend.cc`, `cpu/cpu_isa.cc`, `cpu/kernels.cc`,
`env.cc`, `types.cc`, `devices.cc`, `ops`-free throwing stubs for unused
quantization/tensor-parallel branches, and a no-op spdlog shim. The exercised
path is real: `Model::load(ModelReader&,...)` → `StorageView(shape, dtype)` →
`cpu::AlignedAllocator::allocate` (`posix_memalign(ptr,64,size)`) →
`consume<char>(model_file, num_bytes, variable.buffer())`.

Input (`realbuild/evidence/crafted-n17.bin`, 109 bytes) is binary_version 6,
spec `"Transformer\0"`, spec_revision 1, 2 variables: `origin` shape {2,2}
FLOAT32 with file `num_bytes=17` and payload `A..Q`, then `victim` shape {2,2}
FLOAT32 with `num_bytes=16` and payload `V`*16, then 0 aliases. Hex:
`06 00 00 00 0c 00 54 72 61 6e 73 66 6f 72 6d 65 72 00 01 00 00 00
02 00 00 00 07 00 6f 72 69 67 69 6e 00 02 02 00 00 00 02 00 00 00 00
11 00 00 00 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 …`.

Raw results (verbatim output in `realbuild/evidence/`):

- `real-asan-17.out`: `ERROR: AddressSanitizer: heap-buffer-overflow`,
  `WRITE of size 17`, `0 bytes after 16-byte region`, allocation stack
  `posix_memalign` → `cpu::AlignedAllocator::allocate` →
  `StorageView::reserve` → `StorageView::resize`; write stack `memcpy` ←
  `istream::read` ← `consume<char>` ← `Model::load model.cc:657`.
- `real-asan-48.out`: same stack, `WRITE of size 48`, 0 bytes after the same
  16-byte region. `real-asan-16.out`: clean, `load returned; variables=2`.
- `fixed-asan-17.out`: fixed pin rejects the same 17-byte file —
  `what(): Variable 'origin' has an invalid payload size` (no ASan report).
- Plain build: `plain-16.out` reads `victim[0:16]=VVVVVVVVVVVVVVVV`;
  `plain-48.out`, `plain-64.out`, `plain-80.out` all abort with
  `malloc(): corrupted top size` — the overlong store damages real heap
  metadata. No chosen pointer value, no downstream dereference measured.

This moves the evidence from a stand-in buffer to the real library's
allocation and `Model::load` call. Grade: rung 3 confirmed corrupted state in
a real consumer; rung 4 PARTIAL (file-chosen length and bytes past a real
16-byte `StorageView` allocation, no pointer control); AV:L/UI:P ceiling
unchanged; no wire, no command, rung 5 NOT CLAIMED. Witness replay still owed.

## Pointer-control probe (W2, 2026-11-25 12:5xZ) — negative result

`realbuild/pointer-probe.sh` compiles `harness/driver-ptr.cpp` (hex-controlled
file payload) against the same verbatim vulnerable `model.cc` (sha256
`05ab59bb…`, rechecked in `evidence/pointer-probe.sha256`) with the real
allocator. Raw gdb output: `realbuild/evidence/pointer-layout-n17.txt` and
`pointer-chosen-80.txt`.

At the instant of the vulnerable store (`model.cc:657`) the 16-byte
`posix_memalign` buffer is followed by zeros and the top-chunk size field at
buffer+0x18 (`0xd8b1` in the 17-byte case): **no already-constructed object
with a pointer field follows the buffer**. After `register_variable`, the
`shared_ptr` control block is constructed at buffer+0x20 (vptr
`0x5555556001f8`) and the `StorageView` at buffer+0x30, with `_data` at
buffer+0x48 pointing back to the buffer — both allocated and constructed
after the store, so chosen bytes written there are overwritten by their
constructors. File-chosen bytes first touch allocator metadata: offset 16
overwrites the top chunk's `prev_size` (tolerated); offsets 24+ overwrite a
top-chunk size field (plain `malloc(): corrupted top size`).

An 80-byte chosen payload that preserved the initial top size and supplied
candidate sizes at later top positions kept `Model::load` alive through the
second variable, but the constructed control-block vptr and `StorageView`
fields replaced the chosen `0x4141…/0x4242…` values at +0x40/+0x48; the run
then aborted in `sysmalloc` (`old_end` misalignment) from the crafted top
sizes. No chosen pointer value was observed in a dereference. Therefore:
direct pointer control is not available in this consumer layout at the
vulnerable store; rung 4 remains PARTIAL (file-chosen length and bytes, real
heap corruption, no pointer target or control flow). Any future rung-4 upgrade
needs either a layout where a pointer-bearing object already sits after the
buffer at store time or a measured allocator-metadata technique; neither is in
evidence. Witness replay of `build.sh` remains owed and UNKNOWN.

## Groomed-layout probe (W3, 2026-11-25 13:3xZ) — negative result

W2's pointer probe answered the direct case but left open whether earlier
variables could put a live pointer-bearing object immediately after the
16-byte buffer at the instant of the store. `realbuild/harness/driver-groom.cpp`
builds a model file with 1-4 filler variables before `origin`; filler name
lengths (6 or 16 bytes) and dimensions-array ranks (2, 4, 8, all with a
shape product of 16) vary the small-allocation size classes so earlier
name/dimension allocations may be recycled for later buffers. It was compiled
with the same flags and the same verbatim vulnerable `model.cc`
(sha256 rechecked: `05ab59bb4413df14d36fbbb0d82ff6ce6fe0bee72245245f8ecec773d4cc2c65`).

Four gdb probes at `model.cc:657` (`realbuild/evidence/groom-*.txt`, cases
`f1-n6-r2`, `f2-n16-r2`, `f2-n6-r8`, `f4-n16-r4`) each dump eight qwords at
`variable.buffer()` **before** the store. In every case the 16 bytes of the
overflow target are followed by zeros and top-chunk size fields only
(e.g. `f2-n16-r2`: buffer `0x555555615b40`, words at +0x10..+0x38 are
`0`, `0xd4b1`, `0`, `0`, `0`, `0xd491`). No `0x5555…`/`0x7f…` pointer-shaped
word appears after the buffer at store time, for fillers or for `origin`.
Buffers still come from the top chunk (`0x5980`, `0x5a00`, `0x5b40`, `0x5c00`
in that case); the control blocks and objects are still constructed after
the store. All four runs completed with `load returned` (3/4/4/6 variables).

Grooming earlier file-controlled variables therefore did not change the
structural finding of W2: at the vulnerable store, forward writes from a
fresh `StorageView` buffer reach only free top-chunk space and allocator
metadata, never a live pointer-bearing object. Rung 4 stays PARTIAL.
Witness replay remains UNKNOWN: at 13:34Z the witness role's wake FAILED
("no working engine candidate"), so the 12:52Z replay request has no verdict.

## W4 allocator and downstream-field probes (2026-11-25 15:0xZ)

Two bounded probes, both offline against the verbatim vulnerable pin
(sha256 `05ab59bb4413df14d36fbbb0d82ff6ce6fe0bee72245245f8ecec773d4cc2c65`,
rechecked by each script).

NEGATIVE — glibc 2.39 `sysmalloc` reads only the top chunk's own size at
entry (`old_top = av->top; old_size = chunksize(old_top)`), never the top
chunk's `prev_size`. A plain gdb dump at `model.cc:657` with a 17-byte
payload shows the 16-byte `posix_memalign` buffer at `0x555555615740`
followed by zeros and the top-chunk size word `0xd8b1` at buffer+0x18; the
file-chosen bytes 16..23 overwrite that chunk's unused `prev_size` field.
No chosen address can redirect a `sysmalloc` read via this field. Hypothesis
discarded; not retried.

NEW downstream-consumer evidence — `realbuild/downstream-probe.sh` builds
`harness/driver-ptr.cpp` against the same verbatim pin and runs the
file-chosen 40-byte payload with the default `'A'` padding (no hex argv, so
the heap layout is deterministic). Result, 8/8 identical runs:
`downstream-plain-40.out` reports
`storage_view.cc:411: buffer to copy is of size 4 but current storage size
is -9042521604759584126` (`0x8282828282828282`, the doubled 0x41 byte).
`downstream-fields-40.txt` is a gdb `catch throw` capture: backtrace
`StorageView::copy_from<float>` ← `copy_from` ← copy-constructor ←
`unordered_map::emplace` in `get_variables()`; destination
`this=0x555555615b08`, `other._size=4`, `this->_size=0x8282828282828282`,
`this->_data=0x0`. The corrupted `_size` is a file-derived value in a live
constructed `StorageView` consumed after `Model::load` returned — unlike W2,
where chosen bytes landed only in free top-chunk space. It still fails the
`size != _size` guard at `storage_view.cc:409`, so `primitives::copy` is not
reached: no chosen pointer, no control flow, no command. Safe control
`downstream-safe-16.out` (16-byte payload) is clean: `load returned;
variables=2`, `victim[0:16]=VVVVVVVVVVVVVVVV`. Fixed pin still rejects the
same malicious file (W1 evidence, unchanged).

A uniform-byte sweep (40 bytes of 0x41/0x42/0x00/0x01/0x11/0x61/0xff,
hex-argv invocation) aborts earlier in `malloc`/`free`: the heap address of
the overflow buffer shifts when argv holds the payload, so the downstream
copy path is invocation-specific. Recorded as a layout dependency, not a
second exploit primitive. Grade remains rung 4 PARTIAL; no wire, no rung 5.

## Witness replay verdict (W6, 2026-11-25 21:31-21:35Z) — ESTABLISHED AS LABELED

Witness W223 replayed `bash lab/frontier/ctranslate22shell/run-witness.sh`
from a clean `git archive HEAD lab/frontier/ctranslate22shell` tree (HEAD
`305d4a68`), with upstream v4.8.0 source from the hash-pinned tarball and
the separately provisioned fixed pin. Verdict: ESTABLISHED AS LABELED, no
counterexample, no grade change, NO r5. Full evidence:
`.mishe-tauftauf/artifacts/witness-w223-ctranslate22shell/detail.md`.

- Wrapper blob check: `git show
  70baf7e6:lab/frontier/ctranslate22shell/run-witness.sh | sha256sum` =
  `b05fc1d721f41d87ea41c0245fc5b9d5b87e78c93da8d52319282572378fef7f`,
  identical to the HEAD blob and the working tree file (unmodified).
- Replay rc 0, `WITNESS REPLAY PASS`: staged harness 16 PASS / 0 FAIL, both
  model.cc sha256 values exact (vulnerable `05ab59bb…`, fixed `5dcc3f1d…`),
  all ten real-consumer assertions green. Vulnerable ASan reports
  `WRITE of size 17` and `WRITE of size 48`, 0 bytes after the real
  16-byte `posix_memalign` StorageView, write frame `Model::load
  model.cc:657`; n=16 clean in both the vulnerable and fixed ASan builds;
  fixed pin rejects n=17 with `Variable 'origin' has an invalid payload
  size`; plain n=16 reads back the chosen `V` bytes and plain n=48 aborts
  with `malloc(): corrupted top size`. Three extra vulnerable n=17 runs
  reproduced the same single ASan error and frame.
- Six regenerated real-consumer output files were byte-identical to the
  committed evidence after normalizing PID, hex addresses, binary build
  path and BuildId; the two ASan reports differed only in those volatile
  tokens before normalization, with no frame, line number or byte count
  changed.
- Source-bound check: the vulnerable store is at pin `:657`; the fixed pin
  adds the size check at `:659-660`; `realbuild/harness/stubs.cpp` contains
  only throwing stubs for off-path quantization/tensor-parallel branches.
  The model bytes are generated in-process by a `ModelReader` stand-in and
  consumed by the real `Model::load`: no wire path, live service, chosen
  pointer/IP, downstream control flow or command side effect. W2 (no
  pointer-bearing object after the buffer at store time), W3 (grooming
  negative) and W4 (`sysmalloc`-prev_size negative; `_size` guard blocks
  `primitives::copy`) still hold. Grade stays rung 3 CONFIRMED / rung 4
  PARTIAL with the AV:L/UI:P ceiling; rung 5 NOT CLAIMED.

## W6 shape-field mechanism (2026-11-25 22:1xZ) — negative result

One bounded gdb inspection answered the W4 open question in this layout.
Raw capture: `realbuild/evidence/downstream-shape-40.txt` (deterministic
`./consumer-downstream 40` from `downstream-probe.sh`, verbatim pin sha256
`05ab59bb…`). At the `storage_view.cc:411` throw, the source
`StorageView` (`&other=0x5555556157d0`, `_data=0x555555615780`, `_size=4`)
has `_shape = {0x4141414141414141, 2}`; the destination has `_size =
0x8282828282828282` and `_data=0x0`. `ptype /o` puts `_data` at offset 24,
`_size` at 40 and `_shape` at 48 in a 72-byte `StorageView`.

The source shape vector's storage is at buffer+0x20, so payload bytes
32..39 of the 40-byte store overwrite `shape[0]` (a live `dim_t`, allocated
before the store). `shape[1]=2` sits just past the store. `resize_as(other)`
then sets the destination `_size` to `compute_size(shape) = 0x4141… * 2 =
0x8282…`, which fails the guard against `other._size=4`; `primitives::copy`
is still not reached. The pointer fields a dereference would need are in
objects constructed after the store (`other._data` at buffer+0x68,
destination `_data`), and their constructors overwrite chosen bytes there.
A second run with a fixed-length hex argv using different bytes aborted
before the copy, confirming W4's layout dependency rather than providing a
second value. No chosen pointer, control flow or command: rung 4 stays
PARTIAL, rung 5 NOT CLAIMED. This closes the W4 question for this layout;
do not retry the same probe.

## W7 top-chunk size preservation (2026-11-26 00:0xZ) — negative result

W2 preserved the original top size at store offsets 24..31 but also crafted
candidate sizes at *later* top positions and aborted in `sysmalloc`. This
probe tests the untried case: exact original size preserved, chosen bytes
only in free top space. `realbuild/top-size-probe.sh` (offline; verbatim
vulnerable pin sha256 `05ab59bb4413df14d36fbbb0d82ff6ce6fe0bee72245245f8ecec773d4cc2c65`
rechecked) writes 48 bytes: 0..15 `0x41`, 16..23 zero (top `prev_size`),
24..31 the measured original top size `0xd6f1` little-endian, 32..47 `0x41`.

Result: plain `./consumer-payload 48 <hex>` prints `load returned;
variables=2` and an intact `victim[0:16]=VVVV…` — the first n=48 chosen
store in this lane that completes the real `Model::load`. gdb at the second
variable's store (`realbuild/evidence/topsize-48-gdb.txt`) shows the chosen
`0x4141…` words at buffer+0x20..+0x2f replaced by the `shared_ptr`
control-block vptr `0x5555556001f8` and its counts; buffer+0x30 holds shape
and storage pointers/sizes, all constructed after the store. No chosen byte
survives in a live pointer field. Raw plain output:
`realbuild/evidence/topsize-48-plain.out`.

Why no larger allocator primitive: in the glibc 2.39 source fetched for this
probe (`malloc.c`, tag `glibc-2.39`), `_int_malloc`'s top path checks only
`chunksize(top) > av->system_mem` (the W1 `malloc(): corrupted top size`
abort) and otherwise splits from the same top base with `av->top =
chunk_at_offset(top, nb)` — forward only, so it cannot overlap an already
live object. A size too small for the next request enters `sysmalloc`, whose
main-arena path reanchors `av->top` at the real brk with fenceposts (or
aborts `break adjusted to free malloc space` if the crafted end lies past
brk). Neither outcome gives a file-chosen address in a dereference.
Together with W2/W3/W4/W6 this closes the allocator-metadata route. Grade
unchanged: rung 3 CONFIRMED / rung 4 PARTIAL, AV:L/UI:P, rung 5 NOT CLAIMED.
