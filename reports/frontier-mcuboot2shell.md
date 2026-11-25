# Frontier brief — mcuboot2shell (CVE-2026-16663)

Status 2026-11-25 10:59Z: **rung 4 DEMONSTRATED**, extended to a live
loopback process where client-supplied bytes select the OOB destination and
client-supplied plaintext is read back there (W1/W2/W3 sections below).
Rung 3 real-source ASan OOB access confirmed. Rung 5 remains UNKNOWN: no
MCUboot SMP/UART parser, no real encrypted image or key TLV, no pointer, IP
or command control, no witness verdict. Fix merged on `main`; patched 2.5.1
release projected by the advisory, not observed.

## Verified ground truth (read-only provisioning)

- GitHub maintainer advisory
  https://github.com/mcu-tools/mcuboot/security/advisories/GHSA-7c8v-m3pm-wh74
  (`CVE-2026-16663`, published 2026-11-24, High 8.4,
  `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-787). Global record
  https://github.com/advisories/GHSA-r62q-q5vc-23h5 . Affected `>=1.9.0,
  <=2.5.0`; patched `2.5.1` is a **projection** in the advisory, not an
  observed release.
- Upstream fix `6e1465c38e3dba4849caed650ad83d0ba5c277b6` (PR #3006, 2026-11-20),
  parent `099379647ada83b31cc094e4c0c94a7d0e895639`. Provisioned by a shallow
  `git fetch` into `lab/frontier/mcuboot2shell/src/`; both versions of
  `boot/boot_serial/src/boot_serial_encryption.c` are stored verbatim there.
  Introduced by `953a761` (v1.9.0), moved by `c9fa608` (v2.0.0). The advisory
  reports a 2048-byte OOB write reproduced under ASan with `sz=4096`,
  `off=4096`, `ih_hdr_size=6144`.
- Duplicate screen FIRST: no `mcuboot` / `16663` / `7c8v-m3pm` match in
  `reports/frontier-*.md`, charters or operator files. Zephyr is an admitted
  target but MCUboot is a separate bootloader project; the admitted SRS RTCP
  bug (11/25) and Valkey UAF (11/24) were screened out as owned/excluded.
  Fetching/cloning is provisioning only; no external target was probed.

## Source-bound mechanism (verbatim pinned function, no hand-edited source)

`harness/decrypt_region_inplace_vuln.inc` is the unmodified parent function
(lines 118-204, sha256 `f7ba8c254a41312b3a7e3473ac228981d5010a7aaf9f6ec48e062f3b41ed2e87`):

```
uint16_t idx;
uint8_t buf[sz] __attribute__((aligned));
...
if (off + bytes_copied < hdr->ih_hdr_size) {
    ...
    blk_sz = off + bytes_copied + chunk_sz - hdr->ih_hdr_size;
    blk_off = 0;
    idx = hdr->ih_hdr_size;        /* absolute image offset, not sector-relative */
}
...
rc = boot_enc_decrypt(enc_data,
        (off + bytes_copied + idx) - hdr->ih_hdr_size, blk_sz,
        blk_off, &buf[idx]);       /* sector-sized VLA, no window check */
```

`decrypt_image_inplace()` calls it once per erase sector
(`boot_serial_encryption.c:286-287`), so `off=4096` is the second sector.
The sibling loader path `boot/bootutil/src/loader.c:876` uses the correct
`idx = hdr->ih_hdr_size - abs_off`. Validation before decryption is
`#if 0` at `boot_serial_encryption.c:245-252`; `bs_upload()` reaches
`boot_handle_enc_fw()` after upload (`boot_serial.c:1208`). The advisory also
describes a second window error at `:166-173` (TLV clamp measured from the
sector start, not from `idx`) — the harness reproduces that too.

The fixed function (`harness/decrypt_region_inplace_fixed.inc`, lines 118-210
of the fix commit, sha256
`e9f8366f8c69eeb6835e000bc51a0804c08c34fde241e3b9e8359780e2d53fda`) computes
`abs_off`, `idx = ih_hdr_size - abs_off`, `blk_sz = tlv_off - abs_off - idx`
and rejects the sector with
`if (idx > (uint32_t)chunk_sz || blk_sz > (uint32_t)chunk_sz - idx)`.
Both functions are compiled unchanged; only structs, flash stubs, the
`boot_enc_decrypt` store stub and the caller are local stand-ins.

## Lab evidence (`lab/frontier/mcuboot2shell/`)

`cd lab/frontier/mcuboot2shell/harness && sh run.sh > evidence/run-all.log`:
**22 PASS / 0 FAIL** (2026-11-25 05:52Z). Builds and inputs are listed in
`PROVENANCE.md`; evidence files are under `harness/evidence/`.

- `vuln-asan edge`: `dynamic-stack-buffer-overflow`, `WRITE of size 1`,
  stack `boot_enc_decrypt harness.c:78` → pinned
  `decrypt_region_inplace.inc:61` (the `&buf[idx]` call). `ih_hdr_size=4104`,
  `off=4096`, `sz=4096`: absolute `idx=4104`, 8 bytes past the VLA. clang
  ASan reports `stack-buffer-overflow` on the same input.
- `fixed-asan edge`, `fixed-asan attack`, `fixed-asan attack2` and all safe
  controls: rc 0, no ASan error. The fixed destination for the advisory case
  is `buf+2048` with `decrypt_len=2048`, ending exactly at the 4096-byte
  boundary; for the TLV case `buf+1024` with `decrypt_len=1976`.
- Deep advisory case (`ih_hdr_size=6144`): plain readback with
  `-fno-stack-protector` shows `dst=buf+6144`, `decrypt_len=2048`, chosen
  bytes at that OOB destination; Valgrind reports `Invalid write of size 1`
  and 1 error context. GCC/Clang ASan do **not** flag this deep jump (the
  first written byte is beyond the VLA redzone); that negative is preserved,
  and the ASan rung-3 claim rests on the `edge` input.
- Plain `edge` build aborts before printing (4088-byte overwrite destroys
  the stack frame); preserved as a negative, not used as an oracle.
- Safe control (`ih_hdr_size=0`): `dst=buf+0`, no sanitizer error.

## Rung assessment and cheapest next experiment

Ceiling is **rung 3 pinned function / rung 4 PARTIAL chosen bytes**, same
shape as the other staged frontier targets. Pre-authentication is real per
the advisory, but the attack vector is local serial/USB recovery with a
`MCUBOOT_ENC_IMAGES` build and a crafted *encrypted* image; no network wire,
no real bootloader process and no witness replay were observed. Fixed and
safe controls are the upstream patch and a zero header size.

Cheapest experiment for the target mind: rebuild the pinned parent and fix
under a real MCUboot unit-test configuration with `MCUBOOT_ENC_IMAGES`, drive
`decrypt_region_inplace()` through a real `flash_area` shim with a 4096-byte
sector and the three recorded inputs, and check whether the real
`boot_enc_decrypt()` writes chosen plaintext at the OOB offsets. Only after
that, investigate whether a host serial-recovery instance can expose the
upload path on 127.0.0.1. Do not claim a wire path, pointer control or rung 5
without measured evidence.

## Handoff receipt (2026-11-25 05:59Z)

Scoped commit `bf2a32ff` (47 files: pinned source, harness, evidence, brief,
status). A clean `git archive HEAD lab/frontier/mcuboot2shell` replay in a
throwaway directory ran `sh run.sh` again: **22 PASS / 0 FAIL**, same fixed
ASan output hash; raw vulnerable output hashes differ from the working tree
because ASan reports embed PID/address/path, not because checks changed.
Inner tmux window 151 (`%304`/`%305`, both alive) and registry 152/152 unique
names were verified after creation; operator DM #4142 states the window
already exists, witness replay DM #4143. No rung, charter or admission claim
is made by frontier beyond the staged grade above.

## W1 real-source result (2026-11-25 09:03Z, target mind)

The cheapest experiment is done. A scoped upstream provisioning fetched the
parent (`099379647ada`) and fixed (`6e1465c38e3d`) MCUboot trees into
`lab/frontier/mcuboot2shell/upstream-parent/` and `upstream/`. The pinned
whole-file hashes match the upstream files byte-for-byte
(`a77260e4…` parent, `3825b917…` fixed). A host build compiled the *real*
pinned source and the *real* `boot/bootutil/src/encrypted.c` with
TinyCrypt AES-CTR under `MCUBOOT_ENC_IMAGES`; only flash/state/key stubs and
the caller are local. Full recipe, hashes, evidence and negatives:
`lab/frontier/mcuboot2shell/real/PROVENANCE.md`; outputs under `real/evidence/`.

- Real ASan `edge` (`ih_hdr_size=4104`, `off=4096`, `len=4088`):
  `dynamic-stack-buffer-overflow`, `READ of size 1` at `tc_ctr_mode.c:81` →
  `encrypted.c:722` → pinned `boot_serial_encryption.c:175`, destination
  `buf+4104`. The report is an OOB **read** (AES-CTR reads OOB ciphertext
  before writing plaintext), not a WRITE; the earlier stub WRITE claim stays
  with the stub.
- Real plain `attack` (`ih_hdr_size=6144`): real `boot_enc_decrypt()` was
  called with `len=2048`, `blk_off=0`, destination `buf+6144`; readback was
  `MISHE-REAL-AES!!` (`4d495348452d5245414c2d4145532121`). `attack2` gave
  the same chosen bytes at `buf+1024` with `len=3000`. Chosen plaintext
  required deliberate adjacent-stack grooming with the real AES-CTR
  keystream; that condition is part of the result, not an omitted detail.
- Real fixed-source control: destinations `buf+8`, `buf+2048`, `buf+1024`,
  `buf+0`; rc 0 and no ASan error in all four modes.

Grade revision: **rung 4 DEMONSTRATED in a lab host build** (chosen bytes at
the chosen OOB offsets through the real pinned function and real decryptor),
with the stack-grooming condition stated; rung 3 real-source ASan OOB access
confirmed. Still no live bootloader process, serial/USB wire, real encrypted
image/key TLV, pointer/IP/command control or rung 5. Witness verdict remains
UNKNOWN; this is an author report, not independent acceptance.

## W2 live loopback wire-to-sink result (2026-11-25 09:49Z, target mind)

The W1 "no loopback path" negative covers the *in-tree* MCUboot serial
transport; it does not prevent a lab-built process from carrying client
bytes to the same real sink. `real/wire-harness.c` binds an ephemeral port
on `127.0.0.1`, accepts one 32-byte MCUboot image header per connection,
and calls the verbatim pinned `decrypt_region_inplace()` and real
`boot_enc_decrypt()` with the **wire-supplied** `ih_hdr_size`. Full recipe,
hashes, table and negatives: `real/WIRE-PROVENANCE.md`.

| wire `ih_hdr_size` | real decrypt `len` | real destination | process |
| --- | --- | --- | --- |
| 4104 | 4088 | `buf+4104` | SIGSEGV (139) |
| 6144 | 2048 | `buf+6144` | rc 0 |
| 7168 | 1024 | `buf+7168` | rc 0 |
| 2048 (control) | 2048 | `buf+0` | rc 0 |

This extends rung 4 to a live loopback wire-to-sink path: client-controlled
header bytes select the OOB destination in the real decryptor. It is not
rung 5: the transport is a lab shim, not MCUboot's SMP/UART parser; no real
encrypted image, key TLV, chosen plaintext (grooming disabled here), pointer,
IP or command control was observed. W1's chosen-byte readback and ASan report
remain the rung-4 memory-corruption evidence. Witness verdict UNKNOWN.

## W3 wire-to-chosen-bytes result (2026-11-25 10:59Z, target mind)

The W2 listener now has a `WIRE_GROOM` variant
(`real/wire-groom-harness.c`, `real/wire-groom-run.sh`) that keeps its
per-connection locals in static storage and accepts a 16-byte chosen
plaintext after the header. The same real pinned function and real
TinyCrypt AES-CTR decryptor run; the wire string is groomed as adjacent
stack ciphertext and read back from the real destination. Full hashes,
table and negatives: `real/WIRE-GROOM-PROVENANCE.md`.

| wire `ih_hdr_size` | real destination | readback | process |
| --- | --- | --- | --- |
| 6144 | `buf+6144` | `WIRE-CHOICE-1234` | rc 0 |
| 7168 | `buf+7168` | `WIRE-CHOICE-1234` | rc 0 |
| 4104 | `buf+4104` | none | SIGSEGV (139), negative preserved |
| 2048 (control) | `buf+0` | `WIRE-CHOICE-1234` | rc 0 |

Rung 4 is extended from wire-to-sink to **wire-to-chosen-bytes** in a live
loopback process, under the stated adjacent-stack grooming condition. The
default W2 path was re-run after the change and still reproduces its four
rows. This is not rung 5: the transport is a lab shim, not MCUboot SMP/UART;
the chosen bytes are groomed stack ciphertext, not an SMP upload field; no
pointer, IP or command control and no witness replay. Witness UNKNOWN.

## W4 native SMP upload path (2026-11-25 14:44Z, target mind)

The real MCUboot `boot_serial.c` (parent `099379647ada`), real zcbor decoder
and encoder, pinned `boot_serial_encryption.c` and real TinyCrypt AES-CTR
decryptor now build as a native host process. A loopback listener accepts one
mcumgr image-upload packet whose CBOR `data` field carries the crafted MCUboot
header, a valid TLV block and 16 wire-chosen plaintext bytes. The real
`boot_serial_input()` → `bs_upload()` → `boot_handle_enc_fw()` →
`decrypt_image_inplace()` → `decrypt_region_inplace()` path drives the sink.
Only flash, UART, OS, CRC/base64 and the wrapped-key load are host shims;
the two local source copies differ from upstream by tracing only.

| wire `ih_hdr_size` | real decrypt `len`/`off` | `dst_delta` | readback at OOB destination | process |
| --- | --- | --- | --- | --- |
| 6144 | 2048, off 4096 | 6144 | `574952452d43484f4943452d31323334` | rc 0 |
| 7168 | 1024, off 4096 | 7168 | same 16 bytes | rc 0 |
| 2048 (in-bounds control) | 2048, off 0 | 2048 | not the chosen string | rc 0 |
| 4104 | 4088, off 4096 | 4104 | none | SIGSEGV 139, negative preserved |

The chosen string is the client's 16 bytes after the SMP packet; it is
groomed as adjacent-stack ciphertext by the lab shim, decrypted by the real
AES-CTR body and read back by the interposing decryptor wrapper immediately
after the real call. `READBACK delta=` lines in
`real/smp/evidence/smp-6144.log` and `smp-7168.log` are the evidence; later
in-bounds decrypts overwrite the final `SMP_DONE` buffer. Full recipe,
hashes, corrections and negatives: `real/smp/SMP-PROVENANCE.md`; replay with
`sh real/smp/run.sh` (loopback only).

This closes W3's largest gap: the attacker-controlled header now travels
through MCUboot's real SMP command dispatch and CBOR decoder into the pinned
sink. It is still not rung 5: native host build, not Zephyr or a real MCU;
no serial-port framing parser (the packet goes straight to
`boot_serial_input()`), no real encrypted image/key TLV (key load is
shimmed), no ASan in W4, no pointer/IP/command control, no benign command
execution and no witness replay. Rung 5 remains UNKNOWN. Witness verdict on
W4 is UNKNOWN (author evidence only).

## W5 rung-5 ceiling: no controlled write reaches a saved return address (2026-11-25 17:17Z, target mind)

A gdb dump of the real native SMP process (breakpoint in the interposing
`boot_enc_decrypt()` wrapper) measured the stack geometry at the
wire-reachable OOB offsets. With the 4096-byte VLA base as origin, saved
return-address slots sit at `+5048` (`decrypt_image_inplace`), `+5096`
(`boot_handle_enc_fw`) and `+5688` (`bs_upload`); the wrapper's own saved rip
is at `-8`, below the buffer. Their values are code addresses
(`0x5555…`), confirmed in `info frame` output.

The two controlled OOB writes start above every one of those slots:
`ih_hdr_size=6144` writes `[+6144,+8192)` (2048 bytes) and `7168` writes
`[+7168,+8192)` (1024 bytes). The words in that region are groomed
ciphertext and image data (`0x4696a06174877e44` includes the TLV magic
`7e44`); no code address (`0x5555…`) and no saved frame pointer (`0x7fff…`)
appears there. The `4104` row is not a controlled write either: on a fresh
`sh real/smp/run.sh` the wrapper logged `len=1929027880 dst_delta=40415`
and the process SIGSEGVed (139). No chosen byte was observed in any saved
return-address slot.

Decision: the return-address-overwrite route to rung 5 is **structurally
closed at this native host build and frame geometry**. Grade unchanged:
rung 4 DEMONSTRATED through real SMP dispatch/CBOR; rung 5 UNKNOWN. This is
not a universal closure — a Zephyr/native_sim or real-MCU build has a
different frame layout and was not tested. Witness verdict on W4/W3 still
UNKNOWN. Reproduce with `sh real/smp/stack-layout.sh` →
`real/smp/evidence/stack-layout.txt`; raw words and frame map are in that
file. Negative preserved; do not re-claim W4 as rung 5.
