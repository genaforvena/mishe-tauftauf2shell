# PROVENANCE — ctranslate22shell staged harness

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
