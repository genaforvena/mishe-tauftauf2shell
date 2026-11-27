# PROVENANCE — wladxnamespace2shell

All work is local provisioning and loopback-free. No external system was
probed; source fetches were read-only provisioning from GitHub.

## Sources and pins

- Advisory: CVE-2026-131871 (NVD, published 2026-11-18T03:17Z, modified
  2026-11-27T02:16Z, CWE-121), upstream commit
  `63755ffcd12f78d3bbadf3b24796383c734c4d77`, release v10.8.
- Vulnerable pin: `git clone --depth 1 --branch v10.7
  https://github.com/vhelin/wla-dx.git src/wla-dx-10.7`, HEAD
  `91c52b1f4ef3cc8ba3c0638f7536539579af6a9f`.
- Fixed pin: `git clone --depth 1 --branch v10.8
  https://github.com/vhelin/wla-dx.git src/wla-dx-10.8`, HEAD
  `887e74809d26d4f58130e62ae525f1c29790b490`.
- Upstream fix patch fetched from
  `https://github.com/vhelin/wla-dx/commit/63755ffcd12f78d3bbadf3b24796383c734c4d77.patch`
  to `src/fix.patch`, SHA-256
  `5c330d0201e00d0bbcd5ce1a922a6429dfb49adf214f2cce5ad41cc04a5b041a`.
- Key source file SHA-256: v10.7 `wlalink/analyze.c`
  `bcb5df744410078e9bda8036d2219e955c8ff47cecd23db2266fd9e7fd78959f`;
  v10.8 `wlalink/analyze.c`
  `e0ec040a94ddf1bd7868aecd4a801b5e30a8d4d84c67f8b0cb5c6ba333a0d5d1`.

`build.sh` re-clones either pin if its directory is absent and refuses to
build if HEAD differs from the recorded commit. Build uses CMake targets
`wla-6502` and `wlalink` only; full-tree builds were tried first and timed
out, so the harness deliberately avoids the other assembler variants.

## Reproduction

From the repository root:

```
cd lab/frontier/wladxnamespace2shell/harness
sh build.sh
sh run-all.sh
```

Expected: `BUILD_OK`, then `RUN_ALL_OK 16 PASS / 0 FAIL`. Observed twice on
2026-11-27 (23:00Z), including after refreshing pins. Inputs and evidence
are regenerated on each run; `INPUT_SHA256SUMS` (SHA-256
`8fd65fb024938452d8b8a990c95586572f42236a396b68d94eb92182b7da0556`) and
`evidence/SHA256SUMS` (SHA-256
`df780231191578647cbf9b8581d3d450e3d39d61e42fa9e848ad46ddaf148ed9`) are
checked before and after the run. The hashes above are of pin files and will
change if the scripts change; the current values are committed with the
scripts.

`generate-inputs.py` writes `.s` sources containing section namespaces of
270 `C` bytes, 2044 `C` bytes, `A`×256 + `D`×14, and `ok`, plus the matching
linker configuration files. The real pinned assembler produces the objects;
no hand-built object bytes are used.

## Volatile vs pinned evidence

ASan PIDs, addresses and GDB inferior PIDs/stack addresses vary per run, so
the committed evidence logs keep only stable observations:

- `evidence/vuln-asan.log`: `ERROR: AddressSanitizer:
  stack-buffer-overflow`, `WRITE of size 1`, `analyze.c:2155`.
- `evidence/controls.log`: exit codes (vulnerable ASan attack 1, fixed ASan
  attack 0, both safe inputs 0, plain 2044-byte overrun 139) and fixed output
  size (1 byte).
- `evidence/gdb-pattern.log`: `BP_HIT=1` (GDB stopped at `analyze.c:2156`),
  `V256=44 V260=44 V269=44 V270=00`, and `exited normally`.

Raw logs (`*.raw`) and binaries/build directories are working-tree artifacts
and are not part of the commit. `evidence/gdb-pattern.raw` also contains a
stable-address memory dump (GDB `set disable-randomization on`) showing the
14 chosen `0x44` bytes past `buf` followed by an intact pointer-looking word;
only the indexed byte values are pinned.

## Preserved negatives

- 280-byte namespace: plain vulnerable build exits 135; 2044-byte namespace:
  exits 139. No chosen-byte readback is claimed for those lengths.
- 2045+ byte namespaces are rejected by the assembler's string limit; the
  fixed v10.8 buffer is 2048 bytes, so a 2044-byte namespace is valid input
  for the fixed binary and links cleanly. The fixed clean run is therefore a
  bounds-safety control, not a rejection control.
- The first full CMake build of all assembler targets exceeded the 180 s
  command limit; targeted builds of `wla-6502` and `wlalink` complete in
  about 20 s per arm from scratch.

## Claims boundary

R3 is confirmed on the real pinned `wlalink` binary. R4 is limited to chosen
bytes observed in adjacent stack memory of the plain lab build; no pointer,
return address or control-flow consumer was measured. R5 is not claimed: the
input is a local object file, with no loopback service, wire request or
command side effect.
