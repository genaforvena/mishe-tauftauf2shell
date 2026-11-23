# libgphoto2shell — pin provenance, harness scope and negatives (W160, 2026-11-23)

## Claims (not facts)

- GHSA-7rfg-j54g-6xm2 / CVE-2026-120451, "libgphoto2 through 2.5.34 contains
  stack-based and heap-based buffer overflow vulnerabilities in jl2005c_init()",
  High 7.0, CWE-787, Unreviewed, published 2026-11-02. Affected/patched version
  fields on the advisory are **Unknown**. The newest upstream tag observed is
  `v2.5.34`; the fix is a commit, not yet a release: **fixed numeric version
  UNKNOWN**.
- Upstream issue https://github.com/gphoto/libgphoto2/issues/1326 (opened
  2026-10-22, closed 2026-11-09) reports findings 1-3 from static review. Its
  comment thread claims a third-party ASan reproduction of the stack write at
  `jl2005c.c:152` with a mock USB device. That claim is independent of the
  evidence below; this harness reproduces it locally.
- The companion advisory GHSA-4cvw-qwj9-xjc2 / CVE-2026-120452 (finding 3,
  `jl2005bcd_decompress()` thumbnail) is **not** covered by this harness.

## Pinned bytes

Fetched with `curl` from raw.githubusercontent.com (provisioning, no probes of
external targets). Hashes in `PINS.sha256`:

| file | source | sha256 (first 16) |
| --- | --- | --- |
| `pins/jl2005c.c.vuln` | tag `v2.5.34`, `camlibs/jl2005c/jl2005c.c` | `0ccb1dac24a837b` |
| `pins/jl2005c.c.fixed` | commit `6a3393dd996502457ab965432cf0b2035278825e`, same path | `4fdaf4b1bd7a3691` |
| `pins/jl2005c.h.vuln` | tag `v2.5.34`, `camlibs/jl2005c/jl2005c.h` | `d2966f74665b4c99` |
| `pins/fix-6a3393d.patch` | commit `.patch` endpoint | `3f8dac0fed557f2b` |

`diff -u` of the two source pins is exactly the eight-line guard from
`6a3393d`; no other differences. `harness/jl2005c.h` is generated as
`#line 1 "jl2005c.h.vuln"` followed by the verbatim pinned header, because the
pinned `.c` includes it by quoted path.

## Source-bound mechanism (rendered lines are claims)

- `:138` `priv->nb_entries = (info[12] & 0xff) * 0x100 | (info[13] & 0xff);`
- `:144-146` `alloc_table_size = nb_entries * 0x10 + 0x30`, rounded up to a
  multiple of `0x200`, with no upper bound.
- `:151-153` `gp_port_read(port, info + 0x200, alloc_table_size - 0x200);`
  `info` is `unsigned char info[0x4020]` at `:50`. For `nb_entries = 1022` the
  round-up yields `0x4200` and the read length is `0x4000`, overflowing the
  15904 bytes of space past `info+0x200` by **480 bytes**. For `0xffff` the
  read length is `0x100000` (1 MiB). Content comes from the device.
- `:154` `memmove(priv->table, info + 0x30, alloc_table_size - 0x30);`
  `priv->table` is `Info table[0x4000]` (16384 bytes, last struct member).
  The same count yields a **16848-byte** copy: 464 bytes past the heap array,
  plus a 480-byte source over-read past `info`.
- Fix `6a3393d` inserts after the round-up: reject if `alloc_table_size >
  sizeof(info)` or `alloc_table_size - 0x30 > sizeof(priv->table)`, returning
  `GP_ERROR_CORRUPTED_DATA`.

## Harness scope — declared stubs

`harness/run.sh` generates `driver-{vuln,fixed}.c` and builds twelve binaries
(gcc/clang x vuln/fixed x plain/ASan/recover). Recover mode adds
`-fsanitize-recover=address` and is run with
`ASAN_OPTIONS=detect_leaks=0:halt_on_error=0`; it changes only instrumentation,
not the emulated device or pinned source.
Pinned source is included verbatim under `#line`; everything else is declared stub code:

- `config.h`, `gphoto2/gphoto2.h`, `gphoto2/gphoto2-port.h`,
  `libgphoto2/gphoto2-endian.h` under `harness/stubs/` — types and constants
  only. The stub's `GP_ERROR_CORRUPTED_DATA` numeric value is a harness value,
  not compared against upstream.
- `gp_port_write/get_settings/set_settings/close/open` are no-ops; `usleep`
  is a local no-op definition.
- `gp_port_read` emulates a device: 16 single-byte responses; a 0x200-byte
  first table block with `JL2005` magic, model byte `0x43`, and the chosen
  count at bytes 12/13; then a follow-up read of the attacker-derived length
  filled with chosen `0x5a`, with an optional eight-byte marker at a chosen
  device offset.
- `Camera` and `GPPort` are local structs; `CameraPrivateLibrary` is the
  pinned header's struct. Plain builds append a 16384-byte `0xa5` canary after
  the allocation so bytes past `table` can be read; ASan builds allocate the
  real size. No real allocator interposition beyond that canary.

Scenarios: `baseline` (count 100, in-bounds), `attack` (1022, full device
reply), `heap` (1022, device reply capped at `0x3E20` so only the `memmove`
destination stays out of bounds), `max` (65535, used only for layout probes).

## Observed evidence

`harness/check.sh`: 36 invocations plus gdb probes; this wake's run is
`146 PASS / 0 FAIL`, trace
`e364f756f482157bf25e852f98673131a94c4977d688bf691475024f286c6c98` (unchanged
because the trace covers plain/ASan only). Raw outputs in
`harness/evidence/`, including `recover-*.out`. The pre-recover check ran
`92 PASS / 0 FAIL` on three consecutive runs with the same trace. Clean
git-archive replay at `0e10c83`: 51 files, 4/4 pins OK, 92 PASS/0 FAIL and
that trace (older harness bytes; see `REPLAY.md`).


- Rung 1: vulnerable baseline returns `rc=0`, `big_n=1536`, one table block
  and 16 single-byte device replies; attack requests `big_n=16384`.
- Rung 2: fixed build rejects both attack and heap with `rc=-3`, never issues
  the oversized read (`big_seen=0`), no ASan report.
- Rung 3: gcc and clang ASan on `attack` report
  `ERROR: AddressSanitizer: stack-buffer-overflow`, `WRITE of size 16384`,
  at pinned `jl2005c.c.vuln:152`. Default-mode ASan on `heap` aborts on the
  source over-read (`READ of size 16848` at pinned `:154`) before the
  destination check. Recover-mode ASan on `heap` reports both checks inside
  the real libc `memmove` interceptor: the source over-read at pinned `:154`
  and `ERROR: AddressSanitizer: heap-buffer-overflow`, `WRITE of size 16848`,
  with the address `0 bytes after 16448-byte region`, frame at pinned
  `jl2005c.c.vuln:154`, and `scenario=heap ... rc=0` (recoverable errors do
  not abort). This is the heap destination ASan confirmation that default
  abort mode masked; it uses the pinned source and real memmove, not a
  custom destination-first copy or synthetic write. Fixed recover builds
  return `rc=-3` with no ASan report. Recover-mode `attack` also reports the
  stack write at `:152`, the source over-read and the heap write.
- Rung 4 (plain, gdb): at pinned `:155`, `x/8xb info+0x4020` and
  `x/8xb g_priv->table+0x4000` both show eight chosen `0x5a` bytes — exact
  offsets 24 bytes past the stack buffer and 0 bytes past the heap array.
  In `clang-vuln-plain`, the saved return-address slot is at `info+16472`;
  a device marker at device offset `0x3e58` places the chosen bytes
  `41 42 43 44 45 46 47 48` exactly in that slot. **Limit:** the process
  faults inside `memmove` (frame locals are already corrupted) before
  executing the function's `ret`, so instruction-pointer *control* is NOT
  demonstrated — only chosen bytes at the saved-RIP slot. gcc's plain
  `attack` aborts on its stack protector (`stack smashing detected`,
  EXIT=134); clang's plain `attack` faults (EXIT=139).

## Ceiling

Direct calls only. No libgphoto2 build, USB/gp_port driver, libusb, camera
enumeration, gvfs/digiKam consumer, socket, network wire, pointer-control
chain, benign marker execution, command execution or witness replay. The
issue's "malicious USB camera on connect" attacker model is a claim. Rung 5
is UNKNOWN. Finding 3 (thumbnail decompressor) is screened out here, not
disproved.
