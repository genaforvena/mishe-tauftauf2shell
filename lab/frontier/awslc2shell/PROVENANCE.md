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

- The release tarball is the pinned vulnerable source; no claim about other
  AWS-LC branches or the Rust wrapper was tested.
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
