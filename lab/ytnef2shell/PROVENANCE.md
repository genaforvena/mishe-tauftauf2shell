# Provenance — real libytnef parse (ytnef2shell W1)

All actions local. Source fetches are provisioning; no probe was sent to any
external system. No mail was sent or received; no process outside this lab was
contacted.

## Pins

- `v2.1.2` = `d9f089144414d3b0912c29ab96f8f1c591d00319`; codeload tarball
  sha256 `340f03f495884611209e9c0bc943fad06ce920e8c79655aa228d5ca7418dc360`.
- `v2.1.3` = `f0ccad7dc2ad0d1c8c3f8676eff4d084eb97d6a3`; codeload tarball
  sha256 `5311e8c5dc49a191cc30aae3cebe477a5335c2b9dc052d680f192e9975c894e3`.

Fetch and extract (once, under `lab/ytnef2shell/src/`):

```
curl -fsSL -o /tmp/ytnef-v212.tar.gz https://codeload.github.com/Yeraze/ytnef/tar.gz/refs/tags/v2.1.2
curl -fsSL -o /tmp/ytnef-v213.tar.gz https://codeload.github.com/Yeraze/ytnef/tar.gz/refs/tags/v2.1.3
tar xzf /tmp/ytnef-v212.tar.gz -C lab/ytnef2shell/src
tar xzf /tmp/ytnef-v213.tar.gz -C lab/ytnef2shell/src
```

The full `lib/ytnef.c` from each tag is also committed under
`lab/frontier/ytnef2shell/src/` (hashes in that harness's `PROVENANCE.md`).

## Builds

For each pin, in `lab/ytnef2shell/src/ytnef-<pin>/`: `bash autogen.sh`.
Out-of-tree, in `lab/ytnef2shell/build/v<212|213>-<asan|plain>/`:

```
../../src/ytnef-2.1.2/configure \
  CFLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address' && make -j4        # ASan
../../src/ytnef-2.1.2/configure \
  CFLAGS='-g -O0 -fno-omit-frame-pointer' && make -j4   # plain
```

Configure and make logs are in each build directory. The wrapper
`ytnefprint/ytnefprint` is a libtool shell script; gdb must be pointed at
`ytnefprint/.libs/ytnefprint` and run with
`LD_LIBRARY_PATH="$PWD/lib/.libs"`.

## Inputs

`python3 lab/ytnef2shell/make_inputs.py` writes `lab/ytnef2shell/inputs/` and
`MANIFEST.txt`. Upstream source files are `test-data/rtf.tnef` (sha256
`4b9a7deed17028f0ccb853441824a9f444f24c59f31402e00bb529f719ee66e6`) and
`test-data/winmail.dat`, both shipped in the vulnerable tarball. The patch is
four bytes at the LZFu header's `uncompressedSize` field plus a repaired
2-byte TNEF attribute checksum; nothing else in the file changes.

## Reproduction

```
bash lab/ytnef2shell/run_real.sh
```

Captured logs: `evidence/v212-asan-*.log`, `evidence/v213-asan-*.log`,
`evidence/v212-plain-wrap16.*`, `evidence/v212-plain-gdb-before-after.log`.

## Instrumentation boundary

No source patch was applied to either pin. gdb breakpoints are at the pinned
lines 1573/1574 of `lib/ytnef.c`; ASan is compiler instrumentation only. The
crafted inputs are real TNEF files parsed by the unmodified library. The
plain-build gdb inspection reads raw heap bytes around the real `calloc`
result; it does not substitute an arena.
