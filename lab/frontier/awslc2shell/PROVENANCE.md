# PROVENANCE — awslc2shell lab (CVE-2026-134056)

All artifacts under `lab/frontier/awslc2shell/`. Provisioning only: upstream
source and advisory pages were fetched read-only; no external probes.

## Pins

- Vulnerable release: AWS-LC v5.6.0 tarball from
  `https://github.com/aws/aws-lc/archive/refs/tags/v5.6.0.tar.gz`,
  sha256 `2348c404dcb1166c09034aceb840bef21af440ae469cbc994f11ab57dd043d26`.
  `src/crypto/fipsmodule/cipher/cipher.c` sha256
  `72797ecccdd9fc8572962f00a7aba609a183eb1cf3dfd5e7b9a199d51f6250cb`.
- Fix: upstream commit `ed3d805d35b3cde60b5a407ea761e5c28b98fcd2`
  ("Fix EVP_DecryptUpdate output handling (#3460)"), patch saved as
  `fix-cipher.patch`, sha256
  `bf6afd852a6da2a88f920fd9efdee718302213f27b69d5b2f6a5a8ba485893a9`.
  Applied to a byte-for-byte copy (`src-fixed/`); patched cipher.c sha256
  `b40e79909b53a7e0eb6533e73ac328d099699fa4ea26fc18a859c6000b2754e7`.
- Advisory: CVE-2026-134056, Amazon CNA, published 2026-11-23;
  `GHSA-h63c-583w-4qfw`. AWS-LC < 5.7.0, plus FIPS branches; fixed in 5.7.0.

## Builds

All builds: `-DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=OFF -DDISABLE_GO=ON
-DDISABLE_PERL=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_FLAGS='-fsanitize=address
-fno-omit-frame-pointer -g -O0'`, target `crypto`.

- `build-asan/` — vulnerable v5.6.0, default assembly AES.
- `build-asan-c/` — vulnerable v5.6.0 with `-DOPENSSL_NO_ASM`, so the AES
  batch store is ASan-instrumented and the actual OOB write is reported.
- `build-fixed/` — v5.6.0 plus the upstream fix patch.

Harnesses: `harness.c` compiled against each as `harness-vuln`, `harness-c`,
`harness-fixed`. Ciphertext is generated with the same fixed key/IV; plaintext
is 32 bytes with byte 31 set to `0x48` ('H'), padded by AES-128-CBC to 48 bytes.
Decryption uses three 16-byte `EVP_DecryptUpdate` calls with a heap buffer sized
to the pre-fix documented minimum `in_len + block_len - 1 = 31`.

### Exact harness rebuild commands (witness NIT 1, 2026-11-24T11:20Z)

The three gitignored harness binaries are rebuilt from the pinned sources with
these exact commands (run from this directory). No generated include directory
is needed; `src/include` and `src-fixed/include` hold the public headers.

```
cc -fsanitize=address -fno-omit-frame-pointer -g -O0 -I src/include harness.c build-asan/crypto/libcrypto.a -lpthread -o harness-vuln
cc -fsanitize=address -fno-omit-frame-pointer -g -O0 -I src/include harness.c build-asan-c/crypto/libcrypto.a -lpthread -o harness-c
cc -fsanitize=address -fno-omit-frame-pointer -g -O0 -I src-fixed/include harness.c build-fixed/crypto/libcrypto.a -lpthread -o harness-fixed
```

Verified 2026-11-24T11:19Z by rebuilding to `/tmp/probe-harness-*` and running
`probe-harness-fixed byte2` (CHOSEN_BYTE_ABSENT) and `probe-harness-c asan`
(rc 1, one `WRITE of size 16`). `run-all.sh` itself tests the existing
binaries; it does not rebuild them.

## Observed bytes (2026-11-24T09:55Z)

- `harness-c asan`: ASan `heap-buffer-overflow`, `WRITE of size 16` at
  `aes_nohw.c:377` via `aes_nohw_cbc_encrypt` ->
  `EVP_EncryptUpdate (cipher.c:259)` -> `EVP_DecryptUpdate (cipher.c:411)`;
  address is 0 bytes after the 31-byte region allocated in `harness.c:56`.
  One byte of that batch store (offset 31) lies outside the caller's buffer.
- `harness-vuln asan`: ASan reports `READ of size 16` at `cipher.c:420`,
  0 bytes after the same 31-byte region. The assembly AES store itself is not
  instrumented; the subsequent `OPENSSL_memcpy(ctx->final, &out[*out_len], b)`
  reads the already-written OOB byte.
- Chosen byte: `harness-vuln byte2` allocates 32 bytes (one extra), stops after
  two updates and reports `byte31=0x48 chosen=0x48 CHOSEN_BYTE_PRESENT`; the
  canary `0xab` at offset 31 was overwritten by the file-derived plaintext byte.
  `harness-fixed byte2` reports `byte31=0xab ... CHOSEN_BYTE_ABSENT`.
- Controls: fixed library with the same 31-byte buffer exits 0 with no ASan
  report; vulnerable single-call decryption (63-byte documented minimum) and
  padding-disabled two-call decryption produce no ASan report.
- `sh run-all.sh` -> 14 PASS / 0 FAIL, rc 0, log `replay.log`.

## Known limits / negatives

- The v5.6.0 release tarball is the pinned source. Other vendor-listed
  branches were tested in W224 below; the Rust wrapper remains untested.
- The one-byte write is exercised in a minimal harness, not a network-facing
  application; no pointer, instruction pointer or command control; no wire
  replay; no rung 5.
- ASan's default assembly build reports the OOB read, not the write; the
  no-asm build is the write-detection control, not a different bug.

## Loopback consumer extension (2026-11-24T10:48Z, wake W1)

`consumer.c` is a synthetic loopback-only TCP consumer: a forked client sends
48 bytes of AES-128-CBC ciphertext to a server bound to `127.0.0.1:0`; the
server decrypts the first two 16-byte blocks in two `EVP_DecryptUpdate` calls
into a `#pragma pack(1)` record with `scratch[31]` immediately followed by a
dispatch pointer. `g_table` is a 256-byte-aligned array of 16 function
pointers: `table[0]` = normal handler (low byte `0x00`), `table[9]` = benign
marker (low byte `0x48`). The pointer starts at `&table[0]`; pre-fix byte 31
overwrites its low byte, redirecting the subsequent indirect call to
`&table[9]`.

Compiled against `build-asan-c/crypto/libcrypto.a` (`consumer-vuln`) and
`build-fixed/crypto/libcrypto.a` (`consumer-fixed`) with the same ASan/debug
flags as the harnesses. `sh run-consumer.sh` -> 11 PASS / 0 FAIL, log
`consumer-replay.log`; original `sh run-all.sh` still 14 PASS / 0 FAIL.
Built by `sh build-consumer.sh`: `cc -fsanitize=address
-fno-omit-frame-pointer -g -O0 -I src/include consumer.c
build-asan-c/crypto/libcrypto.a -lpthread -ldl -o consumer-vuln`, then the same
command with `build-fixed/crypto/libcrypto.a -o consumer-fixed`. The binaries
are gitignored like the harness binaries; `run-consumer.sh` rebuilds them if
missing.

- `consumer-vuln vuln`: `handler_before=...00`, `handler_after=...48`,
  `BENIGN_MARKER_EXECUTED`; no ASan report because the written byte is inside
  the enclosing 39-byte allocation (adjacent-object corruption, not a
  redzone hit).
- `consumer-fixed vuln`: pointer stays `...00`, `NORMAL_HANDLER`.
- `consumer-vuln safe` (32-byte scratch, padding byte before the pointer),
  `nopad` (padding disabled) and `single` (one 48-byte call) all leave the
  pointer intact / do not touch it; `vuln 00` (chosen byte `0x00`) calls the
  normal handler.

Limits: synthetic consumer and 256-byte-aligned dispatch table are lab
grooming, not a real allocator or a real application; the indirect call runs a
lab-chosen benign marker in-process. This is rung-4 pointer control, not
remote command execution. Witness W195 (#3550/#3551) independently replayed
this lane from clean source: ESTABLISHED AS LABELED, NO r5.

### Natural-alignment extension (2026-11-24T11:23Z, wake W204)

`consumer.c` gained two modes that remove both the `#pragma pack(1)` record and
the aligned dispatch table: `natural_tag` uses
`struct { uint8_t tag; uint8_t scratch[31]; void (*handler)(void); }`, and
`natural_pad` uses the same struct without the tag. No indirect call is made in
these modes; they report `offsetof`, the byte at `out[31]` and the handler
pointer before/after decryption. Compiled and run with the same ASan/debug
flags as the earlier consumer modes.

- vuln `natural_tag`: `scratch_off=1 handler_off=32 oob_byte=0x48`; handler LSB
  changed to `0x48` (the chosen byte). No ASan report; the byte is inside the
  40-byte enclosing allocation.
- vuln `natural_pad`: `scratch_off=0 handler_off=32 oob_byte=0x48`; handler LSB
  unchanged — the OOB byte lands in compiler padding at struct offset 31.
- fixed `natural_tag`: handler LSB unchanged. Here `out[31]` *is* the pointer
  LSB (initialized to the handler address, `0x69` in this build), not the
  `0xab` canary; the fixed build leaves it untouched.
- fixed `natural_pad`: handler LSB unchanged, `oob_byte=0xab` (padding canary).

`sh run-consumer.sh` -> 23 PASS / 0 FAIL (`consumer-replay.log`);
`sh run-all.sh` still 14 PASS / 0 FAIL (`replay.log`). This confirms the
source-bound alignment inference for compiler layouts only: a one-byte leading
field puts the OOB byte on a naturally aligned pointer's LSB; without it the
byte hits padding. The redirect still needs a groomed jump target and stays
rung 4, NO r5.

### Natural-alignment dispatch and stack-frame bound (2026-11-24T12:11Z, W205)

`consumer.c` gained `natural_call`: `struct { uint8_t tag; uint8_t scratch[31];
void (**handler)(void); }` with NO `#pragma pack`. Compiler-chosen alignment
puts scratch at offset 1 and handler at offset 32, so the OOB byte is the low
byte of the 256-byte-aligned table-slot address stored in handler. Unlike
W204's report-only modes, this one dispatches through the pointer after the
update.

- vuln `natural_call`: `handler_before low=0x00`, `handler_after low=0x48`,
  `BENIGN_MARKER_EXECUTED`, layout `scratch_off=1 handler_off=32
  oob_byte=0x48`; no ASan report (byte lands inside the enclosing allocation).
- fixed `natural_call`: pointer low stays `0x00`, `NORMAL_HANDLER`, no marker.
- vuln `natural_call 00`: pointer low stays `0x00`, `NORMAL_HANDLER`.

`sh build-consumer.sh`, then `sh run-consumer.sh` -> 31 PASS / 0 FAIL
(`consumer-replay.log`); `sh run-all.sh` -> 14 PASS / 0 FAIL (`replay.log`).
Packing is not needed for the layout or the indirect call; the 256-byte-aligned
dispatch table is still lab grooming.

Stack-frame bound (throwaway layout probes on host GCC 13.3.0 with
`-fstack-protector-strong -fno-omit-frame-pointer -O0`, not a committed
harness): a 31-byte local array is at rbp-0x30, its OOB index 31 at rbp-0x11,
and the compiler canary at rbp-8 — 9 bytes short. Preceding arrays of sizes
1..31 and `aligned(1..8)` attributes did not change that delta; scalar locals
and a trailing 8-byte array were placed below the scratch array. No natural
stack-canary hit was observed. Positioning the stack pointer deliberately at
the canary would be synthetic grooming, not a naturally occurring layout.

## Plain-process allocator bound (2026-11-24T14:25Z, W206)

ASan poisons heap redzones immediately after a 31-byte request, so the earlier
ASan builds cannot answer whether the CVE byte reaches real glibc allocator
metadata. This wake configured non-ASan builds of both pinned source trees
into gitignored `build-plain/` and `build-fixed-plain/` with the same CMake
flags minus `-fsanitize=address` (`sh build-plain.sh`), then compiled
`metadata.c` against each as `metadata-vuln` / `metadata-fixed`. The probe
drives two boundary-crossing `EVP_DecryptUpdate` calls into `malloc(31)` with a
separate `malloc(16)` object allocated after it; only the library writes the
OOB byte — there is no synthetic store in the probe.

Observed on glibc `2.39-0ubuntu8.12` (`metadata-replay.log`, two runs each):

```
vuln:  usable=40 gap_to_obj=48 byte31=0x48 chosen=0x48 next_header_before=0x21 next_header_after=0x21 header_unchanged=1 neighbor_unchanged=1 decrypt_ok=1
fixed: usable=40 gap_to_obj=48 byte31=0xab chosen=0x48 next_header_before=0x21 next_header_after=0x21 header_unchanged=1 neighbor_unchanged=1 decrypt_ok=1
```

`malloc_usable_size(31)=40`; the next chunk's size word sits at `buf+40`, so
the OOB byte at `buf+31` is 9 bytes short of it and 17 bytes short of the next
object. `sh run-metadata.sh` -> 10 PASS / 0 FAIL; `sh run-all.sh` -> 14 PASS /
0 FAIL, `sh run-consumer.sh` -> 31 PASS / 0 FAIL. Bounded negative: on this
host's glibc, a lone documented-minimum heap buffer cannot corrupt chunk
metadata or a neighboring allocation with this one-byte write. This does not
bound embedded structs or non-glibc allocators; W207 below bounds natural
stack layouts on this host. No rung change.

## Natural stack layout bound (2026-11-24T15:42Z, W207)

`stack-layout.c` + `run-stack-layout.sh` extend the plain-build lane from heap
metadata to ordinary stack locals. The probe declares `void (*cb_after)(void)`,
`uint8_t out[31]`, `void (*cb_before)(void)` and `uint8_t tail[16]` in that
order with no `#pragma pack` or alignment attribute, seeds `out[31] = 0xab`,
captures `__builtin_frame_address(0)` before decryption, then drives the two
boundary-crossing updates into `out` exactly as the vulnerable library does in
the harness. `run-stack-layout.sh` compiles against `build-plain` and
`build-fixed-plain` with GCC 13.3.0 and Clang 18.1.3 at `-O0..-O3`,
`-fno-omit-frame-pointer -fno-stack-protector`, and checks the one-past byte:
`0x48` for the vulnerable library, `0xab` for the fixed one, and no zero delta
from `out+31` to either adjacent pointer, the tail array or the saved frame.

Observed (`stack-layout-replay.log`, 16 runs):

```
vuln/gcc/O0  cb_after_delta=1 cb_before_delta=-39 tail_delta=-63 frame_delta=145 oob_byte=0x48
vuln/gcc/O2  cb_after_delta=-71 cb_before_delta=-63 tail_delta=-47 frame_delta=145 oob_byte=0x48
vuln/clang/O1 cb_after_delta=1 cb_before_delta=9 tail_delta=-47 frame_delta=81 oob_byte=0x48
fixed/gcc/O0 cb_after_delta=1 cb_before_delta=-39 tail_delta=-63 frame_delta=145 oob_byte=0xab
fixed/clang/O2 cb_after_delta=1 cb_before_delta=9 tail_delta=-47 frame_delta=81 oob_byte=0xab
```

`sh run-stack-layout.sh` -> 16 PASS / 0 FAIL; `sh run-all.sh` -> 14 PASS /
0 FAIL, `sh run-consumer.sh` -> 31 PASS / 0 FAIL, `sh run-metadata.sh` ->
10 PASS / 0 FAIL. The one-past address never coincides with a natural control
datum on these compilers/flags, so the previously throwaway canary-gap
observation is now a reproducible negative. Rung grade unchanged; no witness
replay of W207.

## Natural global-struct control datum (2026-11-24T17:11Z, W208)

The output contract is pinned in `src/include/openssl/cipher.h:155-158`:
"The number of output bytes may be up to |in_len| plus the block length minus
one and |out| must have sufficient space." A 16-byte update with a 16-byte
block therefore documents a 31-byte minimum; vulnerable `cipher.c:405-427`
writes 32. The overflow is exactly one byte on every boundary-crossing update,
never more.

`global-datum.c` + `build-global-datum.sh` cover the storage class W204-W207
did not: a static-duration, normally aligned record
`struct { uint8_t buf[31]; uint8_t state; void (*handler)(void); }`. With no
`#pragma pack`, no leading tag and no dispatch table, C layout puts `state` at
offset 31 and the 8-aligned handler at 32, so the byte written at `buf[31]`
is exactly `&g.state`. The probe is compiled against the W206 plain (non-ASan)
pinned libraries; only the library writes the byte.

Observed (`global-datum-replay.log`, four modes):

```
vuln:  buf_off=0 state_off=31 handler_off=32 struct_size=40 chosen=0x48 state_before=0xa5 state_after=0x48 handler_lsb_before=0x29 handler_lsb_after=0x29 decrypt_ok=1
fixed: buf_off=0 state_off=31 handler_off=32 struct_size=40 chosen=0x48 state_before=0xa5 state_after=0xa5 handler_lsb_before=0x29 handler_lsb_after=0x29 decrypt_ok=1
safe:  buf_off=0 state_off=31 handler_off=32 struct_size=40 chosen=0x00 state_before=0x00 state_after=0x00 handler_lsb_before=0x29 handler_lsb_after=0x29 decrypt_ok=1
steer: buf_off=0 state_off=31 handler_off=32 struct_size=40 chosen=0x01 state_before=0xa5 state_after=0x01 handler_lsb_before=0x29 handler_lsb_after=0x29 decrypt_ok=1
```

`sh run-global-datum.sh` -> 15 PASS / 0 FAIL; the four existing suites remain
14 / 31 / 10 / 16 PASS, 0 FAIL. In every mode the handler LSB stays `0x29`:
the OOB byte reaches the adjacent `uint8_t` state at offset 31, not the
pointer at 32. This is rung-4 control-datum overwrite with an ungroomed,
compiler-chosen layout: unlike W1's aligned table and W204/W205's leading
tag, no packing or tag is needed for the byte to land on a control datum.
Still no pointer/IP/command, no real application, no wire-to-command path.
Grade unchanged, author-only, no witness replay of W208.

## Vendor-listed 4.x and FIPS branches (W224, 2026-11-26T01:0xZ)

Advisory `GHSA-h63c-583w-4qfw` lists AWS-LC < 5.7.0, 4.0.0–4.1.x,
AWS-LC-FIPS 2.0.0–2.0.17 and FIPS 3.0.0–3.5.x as affected; patched at
5.7.0, 4.2.0, 2.0.18 and 3.6.0. This wake provisioned one release from each
range plus its patched peer. Fetch URLs (no external probe):
`https://github.com/aws/aws-lc/archive/refs/tags/<tag>.tar.gz` and
`https://raw.githubusercontent.com/aws/aws-lc/<tag>/crypto/fipsmodule/cipher/cipher.c`.
The v5.6.0 raw file hashed to the pinned `72797ecc…51f6250cb`, validating the
route. Fetched into gitignored `out-of-tree/versions/`.

| tag | tarball sha256 | `cipher.c` sha256 | class |
| --- | --- | --- | --- |
| v4.0.0 | `dec49e5c38dd8d3b4c2700c692bbb457a149cd6d23ad99463ce3612720c23bb0` | `adb5f9ccbadaddc22a62e6c25e5dcbe713e0573d2bff32cd6b41ecd561428d96` | vulnerable |
| v4.2.0 | `45e1735cb55571eb69782dff6a196e8b63d330056f25d6636c815cea2b8fc58b` | `6f8e5b8b2b5a49a82cf5f03f7aeb25453de7dfd1ce9594b9be360ef7cd165264` | patched |
| AWS-LC-FIPS-2.0.17 | `14ce24f28906305b11c284b68cb748dc51f75bdf54d4b3323bdec687659c7a62` | `fa2050b41c1f38db6389ca7d8ac26a9c2e652d83ab10c3965582355ee9a3fe79` | vulnerable |
| AWS-LC-FIPS-2.0.18 | `404ab9f4d7bbfab52c21bbfa5b6fac5c31cab9a1c8dfe18646ae154194379a42` | `8d42edac1577afacc5d5aee7e8b0358e1a41dd56765484d94fe054d18e651950` | patched |
| AWS-LC-FIPS-3.3.0 | `c137191845248c31251972f37a18381db10e579ebc205ebabb464d6f8abb759f` | `0689f3dcfa4624178ef0637cce3654a69295921e7b8a6c8b60e19d0bd301aa4e` | vulnerable |
| AWS-LC-FIPS-3.6.0 | `e3444e64c5e0adeaf23be8234f96e8e0834a68892df7dbd0ce511c81db3e557e` | `b3bafb43554b819954b5c9c2bfec6ddbe24ac488ea0e067834d1f02901526a3b` | patched |

Vulnerable tags keep `OPENSSL_memcpy(out, ctx->final, b); out += b;` before
the bulk `EVP_EncryptUpdate`, then `*out_len -= b` and copy the block to
`ctx->final` (v4.0.0 `cipher.c:453-475`, FIPS 3.3.0 `:453-474`, FIPS 2.0.17
`:437-458`). Patched tags compute `hold`, decrypt the withheld block into
`ctx->final` before the bulk store and leave bytes past `*out_len` untouched
(v4.2.0 `cipher.c:453-492`, FIPS 3.6.0 `:453-492`, FIPS 2.0.18 `:437-476`).

Builds used the pinned flags with `OPENSSL_NO_ASM` as a C flag:

```
cmake -S <tag>-src -B build-<tag> -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=OFF -DDISABLE_GO=ON -DDISABLE_PERL=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O0 -DOPENSSL_NO_ASM'
cmake --build build-<tag> --target crypto -j4
cc -fsanitize=address -fno-omit-frame-pointer -g -O0 -I <tag>-src/include \
  ../../harness.c build-<tag>/crypto/libcrypto.a -lpthread -o harness-<tag>
```

Observed (logs `out-of-tree/versions/run-<tag>-*.log`, addresses omitted):
v4.0.0 and FIPS 3.3.0 `asan` rc 1 with `WRITE of size 16`, `0 bytes after
31-byte region`, through `aes_nohw_uncompact_block (aes_nohw.c:388)` →
`aes_nohw_from_batch (:511)` → `aes_nohw_cbc_encrypt (:1273)` →
`EVP_EncryptUpdate (cipher.c:308)` → `EVP_DecryptUpdate (cipher.c:460)`;
`asan-ecb` faults through `aes_nohw_decrypt (:1172)`. FIPS 2.0.17 reports the
same shape at `aes_nohw.c:376` / `cipher.c:298` / `cipher.c:444`. All three
vulnerable `byte2` runs print `byte31=0x48 chosen=0x48 CHOSEN_BYTE_PRESENT`.
All three patched builds return rc 0 in `asan` with no ASan report and print
`byte31=0xab chosen=0x48 CHOSEN_BYTE_ABSENT` in `byte2`.

`replay-versions.sh` is the offline one-command check: it rehashes the six
tarballs and `cipher.c` files, extracts missing sources, builds missing
libraries, recompiles `harness.c` from the tracked source and asserts the
vulnerable/patched outcomes. Observed `51 PASS / 0 FAIL`, rc 0. It reuses
provisioned tarballs and existing libraries; `FORCE_BUILD=1` rebuilds. This
is an author-side receipt, not a witness verdict.

Limits: one tag per range, each built in the default (non-FIPS-mode)
configuration of a FIPS-labeled source snapshot, so no CMVP module-boundary
claim. Other tags in the ranges are source-bound by the shared code pattern.
No new caller, wire path or rung change.
