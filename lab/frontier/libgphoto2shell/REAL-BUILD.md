# libgphoto2shell — real-library replay with a virtual USB device (W162, 2026-11-23)

## What is real and what is synthetic

Real: libgphoto2 2.5.34 release source, ASan build, the `jl2005c` camlib
compiled from that release, `gp_camera_init()` camlib dispatch, `camera_init()`
in `camlibs/jl2005c/library.c`, `jl2005c_init()` and `jl2005c_read_data()` in
`camlibs/jl2005c/jl2005c.c`, real `gp_port_read()` in `libgphoto2_port`, and the
real glibc `memset`/allocator under ASan. The vulnerable source is the release
source, not the pinned `#line` slices used by the direct-call harness.

Synthetic: the USB *device*. libgphoto2's own `vusb` virtual USB port driver is
patched (`live/vusb-jl2005.patch`, 53 lines) to answer the JL2005 handshake with
lab-chosen bytes and to accept USB id 0x0979:0x0227 when
`M2SHELL_JL2005_VUSB=1`. The driver `live/real_init.c` selects the model and
port explicitly; no hardware, USB/IP, socket, network or outside process is
involved. This advances the "no real build" gap; it is **not** a wire-level or
remote trigger and is not rung 5.

## Provisioning and build (all inside `lab/frontier/libgphoto2shell/`)

- `sudo apt-get install -y libusb-1.0-0-dev` (lab toolchain provisioning,
  standing approval #5); `pkg-config --modversion libusb-1.0` -> 1.0.27.
- Release tarball:
  `https://github.com/gphoto/libgphoto2/releases/download/v2.5.34/libgphoto2-2.5.34.tar.bz2`,
  sha256 `5df9e774eb4ab6087a193afff84dcafe9f666e3443fe29e73e6779f659ff7f28`,
  saved as `src/libgphoto2-2.5.34.tar.bz2`.
- Apply `live/vusb-jl2005.patch` with `patch -p1` from the source root, then:

```
make clean
CFLAGS='-O0 -g -fPIC -fsanitize=address -fno-omit-frame-pointer' \
LDFLAGS='-fsanitize=address' ./configure \
  --prefix="$PWD/installdir" --with-camlibs=jl2005c \
  --enable-shared --disable-static \
  --without-libxml-2.0 --without-libcurl --without-gdlib \
  --without-libtiff-4 --without-libexif --disable-nls --enable-vusb
make -j4 && make install
```

`-fPIC` and `make clean` are required: a previous static build leaves
non-PIC `.a` objects that break the shared camlib link. A shared build is
required because ltdl cannot load the static `jl2005c.a` camlib.

- Compile the driver against `installdir` with `-fsanitize=address`, adding
  `-lltdl`, using `pkg-config --cflags/--libs libgphoto2` from
  `installdir/lib/pkgconfig`.

## Run

From the repo root, with `P=$PWD/lab/frontier/libgphoto2shell/src/libgphoto2-2.5.34/installdir`:

```
env CAMLIBS="$P/lib/libgphoto2/2.5.34" \
    IOLIBS="$P/lib/libgphoto2_port/0.12.2" IOLIBS_PREFIX=vusb \
    LD_LIBRARY_PATH="$P/lib" \
    M2SHELL_JL2005_VUSB=1 M2SHELL_JL2005_COUNT=<count> \
    [M2SHELL_DEBUG=1] ASAN_OPTIONS=detect_leaks=0 \
    lab/frontier/libgphoto2shell/live/real_init "usb:001,001"
```

`IOLIBS_PREFIX=vusb` is required because `gphoto2-port-info-list.c` loads only
one iolib per port type and `usb1` otherwise wins over `vusb`. Use the exact
generic path `usb:001,001`: the regex-generated `vusb:<file>` entry carries a
bare `library_filename` that `gp_port_set_info()` cannot dlopen, failing with
`GP_ERROR_LIBRARY`. The id file `live/vusb-id.bin` is therefore not needed by
the current path (the patched `find_device` supplies the JL2005 id); it is kept
as the device-identity fixture.

Fixed control: apply `pins/fix-6a3393d.patch` (`patch -p1`) to the release tree,
`make -j4 && make install`, rerun, then reverse the patch and rebuild to
restore the vulnerable tree.

## Observed results

| run | device count | observed |
| --- | --- | --- |
| vulnerable, ASan | 100 | 16 one-byte replies, 512-byte table block, `gp_camera_init rc=0`, no ASan |
| vulnerable, ASan | 1022 | 16 one-byte replies, 512-byte block, **16384-byte** device read, ASan `stack-buffer-overflow WRITE of size 16384` at real `jl2005c/jl2005c.c:152`, frame reached via `camera_init` -> `jl2005c_init`; process exits 1 |
| fixed, ASan | 1022 | only 16 one-byte replies and the 512-byte block; no oversized read, no ASan, `gp_camera_init rc=0` |

`gp_camera_init` returning 0 in the fixed run is not the discriminator: the
discriminator is the absence of the 16384-byte device read. The guard returns
`GP_ERROR_CORRUPTED_DATA` inside the camlib and libgphoto2's init path falls
through without propagating that code to the driver in this configuration.

Raw outputs: `evidence/real-lib-asan-{attack,baseline}.out`,
`evidence/real-lib-{vuln,fixed}-reads.out` (`M2SHELL_DEBUG=1` read sizes),
`evidence/real-lib-fixed-{100,1022}.out`. All paths relative to
`lab/frontier/libgphoto2shell/`.

Rung-3 boundary sweep (W163): a count sweep (`evidence/real-lib-count-sweep.txt`)
found the smallest overflowing count at 1022 and a monotone write size
(16384 at 1022..1053, 16896 at 1054, 1048576 at 65535), with 1021 the safe
lower control. `M2SHELL_JL2005_VUSB=s1` truncates the device reply to `0x3E20`,
which removes the `:152` stack write and leaves the `:154` source over-read as
the first ASan report. Details and raw outputs in `PROVENANCE.md`, section
"Counterexample hunt on the virtual-port claim (W163)".

## Heap destination on the real build (W164, 2026-11-23)

No rebuild is needed for the heap-destination report: the W162 ASan build
reports it at run time with `halt_on_error=0`. With the run env above,
`M2SHELL_JL2005_COUNT=1022` and
`ASAN_OPTIONS=detect_leaks=0:halt_on_error=0`, one run reports three
faults: the `:152` stack `WRITE of size 16384` (via `memset` in
`gp_port_vusb_read`), the `:154` stack `READ of size 16848` (via
`memmove`), and the `:154` heap `WRITE of size 16848` at 0 bytes past a
16448-byte region allocated in `camera_init` at `jl2005c/library.c:477`.
`rc=0`: these errors are recoverable in this mode. Raw output:
`evidence/real-lib-recover-1022.out`.

Why this differs from the pinned harness: there the fault is an
instrumented store and needs `-fsanitize-recover=address` at compile
time; here all three are libasan interceptor reports, so the runtime
option alone suffices.

Controls: count 100 with the same options is clean
(`evidence/real-lib-recover-100.out`). Applying
`pins/fix-6a3393d.patch`, rebuilding only `camlibs/jl2005c.la` and
rerunning count 1022 gives only the 16 one-byte replies and the
512-byte block, no oversized read and no ASan
(`evidence/real-lib-recover-fixed-1022.out`, `...-reads.out`). The patch
was reversed, the vulnerable source hash `0ccb1dac24a837bc…` restored,
the camlib rebuilt, and a fresh run reproduced all three reports
(`evidence/real-lib-recover-restore-1022.out`). At count 65535 the same
mode reports the 1048576- and 1049040-byte faults and then SEGVs inside
`__sanitizer_internal_memmove` (`evidence/real-lib-recover-65535.out`):
the advisory's 1 MiB bound is observed but not recoverable.

Grade unchanged: rung 3 at the real heap destination. Device replies
remain lab-chosen vusb responses; no bus, wire, consumer, pointer chain,
marker or command, no rung 5.

## Scope limit

No real USB bus, camera hardware, wire protocol, consumer application, pointer
control, command or witness replay. Device-side replies are chosen by a lab
patch. The attack is request-local through a synthetic transport; rung 5 stays
UNKNOWN. The direct-call harness under `harness/` remains the deterministic,
pin-based evidence set; its trace is unchanged by this lane.
