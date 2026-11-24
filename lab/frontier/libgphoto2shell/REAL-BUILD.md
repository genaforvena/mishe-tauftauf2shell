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
control or command. Device-side replies are chosen by a lab patch. The attack
is request-local through a synthetic transport; rung 5 stays UNKNOWN. The
direct-call harness under `harness/` remains the deterministic, pin-based
evidence set; its trace is unchanged by this lane.

Independent witness replay (tape #2892, 2026-11-23) closed ESTABLISHED at this
labeled scope: rung 3 at the real heap destination, NOT rung 4 impact, rung 5
UNKNOWN. A clean git archive to `/tmp/w173-lgp` matched all 4 pins and the
tarball/patch hashes; a from-scratch ASan build with the witness's own driver
reproduced the three count-1022 reports with `halt_on_error=0` (`rc=0`), the
100/1021 and fix/reversal controls, and the 65535 faults then SEGV. Their gdb
and byte-substitution probes found no live neighbour or pointer chain:
`table` ends at the allocation boundary and the chosen bytes land in the ASan
redzone. The witness also closed the harness verdict (#2763) at 146 PASS/0
FAIL with trace `e364f756…c6c98`.

## Plain-build saved-RIP probe (W165, 2026-11-23)

One bounded lane was closed with a negative. A separate plain
(no-ASan) real-library build with the distro's default stack protector was
made from the same lab-patched source (`src/libgphoto2-2.5.34-plain`,
`CFLAGS='-O0 -g -fPIC -fno-omit-frame-pointer'`, installdir-plain, driver
`live/real_init_plain`). Count 100 gives `gp_camera_init rc=0`; count 1022
aborts with `*** stack smashing detected ***` (`rc=134`). Breaking at
`__stack_chk_fail` and inspecting frame 1 shows the real `jl2005c_init`
frame at `rbp=0x7fffffffc9b0` with both the canary at `rbp-8` and the saved
RIP at `rbp+8` equal to `0x5a5a5a5a5a5a5a` — device-chosen bytes fill both
slots. The stack protector calls `__stack_chk_fail` before `ret`, so no
chosen control-flow target executes. Grade unchanged: rung 4 chosen bytes
at a real control-flow slot, not IP control; no rung 5. Raw output and build
recipe: `evidence/real-plain-gdb-rip.out`. The build tree and driver are
local lab artifacts, not committed.

## Partial-reply / canary-leak lane (W166, 2026-11-23)

The remaining idea was to separate the stack write from the heap source
over-read with a short device reply, preserving the canary while still
reaching a control-flow slot or heap metadata. Measured on the plain build,
it fails structurally, not by chance. At the `:154` breakpoint `info` starts
at `rbp-16440`: buffer end `info+0x4020`, canary `info+0x4028`, the source
byte that lands on the next chunk's size field `info+0x4030`, saved RIP
`info+0x4038`. Any write that reaches the metadata or RIP source must pass
the canary; any write that stops before it leaves those bytes uncontrolled.
With a full reply the top size becomes `0x5a5a…` but the process aborts at
`__stack_chk_fail` (`rc=134`). With a reply capped at `0x3E28` bytes the
process survives (`gp_camera_init rc=0`) and the source over-read copies the
live canary into `priv->table+0x3FF8` — verified equal to `rbp-8` in gdb,
randomized between runs — while the top size becomes a leftover stack
pointer. The next real consumer allocation aborts:
`gp_camera_file_get()` for the table entry holding the canary ends in
`malloc(): corrupted top size` (`rc=134`), so the copy is not
consumer-visible. `table` is followed by the top chunk (original size
`0x129d1`), not a live pointer. Grade unchanged; pins, committed vusb patch,
harness and witness verdict untouched. Commands, local-only patch recipe and
raw output: `evidence/real-plain-partial-write.out`.

## Chosen control-flow target executes (W167, 2026-11-23)

W165 stopped at "the protector aborts". That is true when the reply fills
both slots with `0x5a`, but the canary is a per-process value and the same
oversized `:152` read writes both `rbp-8` and `rbp+8`. With a LOCAL-ONLY vusb
mode `c` that places the driver's own canary at bulk-reply offset `0x3E28`
(`info+0x4028` = `rbp-8`) and a chosen marker address at `0x3E38`
(`info+0x4038` = `rbp+8`), the real plain build executes the chosen target:
`M2SHELL_IP_CONTROL_MARKER`, `RC=0`. gdb at pinned `:154` shows
`canary=0x84d0d965013e3700 savedrip=0x5555555553c4` (the reported `&marker`)
in the real `jl2005c_init` frame, and breaks in `marker()` with a `0x5a...`
caller chain; `marker` writes its byte and `_exit(0)`s before any unwind.

Controls: count 100 — no marker; wrong canary — stack smashing, `RC=134`;
correct canary with `0x5a...` RIP — `RC=139`; all-`0x5a` reply — stack
smashing, `RC=134`. With `pins/fix-6a3393d.patch` applied and the camlib
rebuilt, no marker and `jl2005c_init` returns `-102`
(`GP_ERROR_CORRUPTED_DATA`); reversing the patch and rebuilding restores the
marker. `gp_camera_init rc=0` is not the discriminator: `camera_init` at
`library.c:489` still falls through to `GP_OK` in the fixed build.

Honest limit: the driver reads the canary from its own `%fs:0x28` and gives it
to the virtual device. This proves the protector is not a structural barrier
once the canary is known and W166 observed the canary copied into the heap,
but it does not show a device-only path that recovers the canary from that
heap copy — its consumer aborts on the corrupted top chunk. No bus or wire,
no remote request, no witness replay, no command side effect. Rung 4 now
includes a local chosen-target execution; rung 5 stays UNKNOWN. Raw output,
commands, local patch recipe and limits:
`evidence/real-plain-ip-control.out`. The local-only reply modes and probe
driver are preserved for replay as
`evidence/replay-vusb-local-modes.patch` (applies on top of the committed
`live/vusb-jl2005.patch`) and `evidence/replay-two_stage_probe.c`. Pins,
committed vusb patch and harness are unchanged.

## Groomed-heap canary-safe reply (W168, 2026-11-24) — negative

W166 left one variable untested: heap layout. Its canary-safe short reply
(`M2SHELL_JL2005_VUSB=p`, `M2SHELL_JL2005_LEN=0x3E28`) copies the live
canary into `priv->table+0x3FF8`, but `table` was followed by the top chunk
and the same over-read destroyed its size, so `gp_camera_file_get()` aborted
in malloc. W168 tried to place a live allocated chunk immediately after the
camera-private allocation, keeping all setup allocations and rejected probe
chunks live, then called the same real consumer APIs.

Five layout shapes were measured (naive hole; adjacent pair with rejected
holes freed; adjacent pair with rejected holes kept; oversized hole 32552;
hole 17848 sized to leave an exact 0x4050 remainder). In every case
`camera_init`'s `calloc(1,16448)` did not reuse the prepared hole: an
intermediate allocation inside `gp_camera_init()` splits any free hole
before `camera_init` runs (gdb: hole chunk 0x4051/0x7F31 before, 0x571 at
`camera_init` entry). `priv` was always the chunk after the live victim,
so the 464-byte overflow again reached the top chunk, and the first consumer
allocation aborted (`malloc(): corrupted top size` or `invalid size
(unsorted)`) before any file bytes were returned. No `gp_camera_init rc=`
line and no file data in any run.

Disposition: the W166 leak remains non-consumer-visible under grooming too.
Grade unchanged — rung 3 at the real heap destination, W167's local
chosen-target execution still conditional on canary knowledge, rung 5
UNKNOWN. No pin, committed patch, harness or library source changed; the
local-only probe is preserved as `evidence/replay-groom_leak_probe.c`, raw
output and commands in `evidence/real-plain-groom-negative.out`.

## Clean-archive W167 replay and loopback socket reply (W169, 2026-11-24)

W167 was rebuilt from `git archive 12056b0` into `/tmp/w169-lgp` with 4/4
pins OK and the 2.5.34 tarball sha256 `5df9e774…7f28`. The clean plain
build reproduced `M2SHELL_IP_CONTROL_MARKER`, `RC=0`, and every control
(count 100, wrong canary, `0x5a` RIP, all-`0x5a`, fixed camlib and fix
reversal). This rules out an untracked-local-tree artifact; it is not an
independent witness verdict on #3081.

The same clean tree then received a local-only vusb mode `k`
(`evidence/replay-vusb-socket.patch`): the 1-byte and 0x200-byte handshake
replies stay local, but the 16384-byte allocation-table read is fetched with
`connect()`/`recv()` from `127.0.0.1:M2SHELL_JL2005_PORT`. The lab sender
(`evidence/replay-socket_sender.py`) reads the target's own printed canary
and marker address from its stderr log and sends a 0x4000-byte payload with
those values at reply offsets `0x3E28` and `0x3E38`. Observed: sender logs
`addr=127.0.0.1:37862 bytes=16384`, the camlib logs
`VUSB_SOCKET got=16384 size=16384`, the target prints
`M2SHELL_IP_CONTROL_MARKER` and `RC=0`. Controls: count 100 reads only 1536
wire bytes with no marker; wrong canary over the wire gives `rc=134`; a
correct canary with `0x5a` RIP gives `rc=139`; the fixed camlib makes no
bulk read and gives no marker; reversing the fix restores the marker.

Scope: this is a loopback TCP connection into a lab-patched virtual port,
not USB/IP, a physical bus, a camera consumer or a remote host. The canary
comes from the target's own TLS via its diagnostic output, so no
device-only canary recovery is shown; the marker is an in-process function,
not a command. It closes the "no socket" observation gap but does not move
the grade: rung 3 at the real heap destination, local rung-4 chosen-target
execution conditional on canary knowledge, rung 5 UNKNOWN. Commands and raw
output: `evidence/real-plain-socket-loopback.out`.

## Device-chosen heap pointer at a real gphoto2 API (W170, 2026-11-24)

W168's outside grooming never put a live object after `camera->pl`; W170
allocates the victim from inside the lab vusb bulk-read hook, after
`camera->pl` exists. Draining 24 same-size tcache entries makes the victim
a real `CameraFile` at `priv+0x4050`, the first chunk after the private
struct. The `:154` overflow starts at `priv+0x4040`, so device bulk offsets
`0x3F90/0x3F98/0x3FA0` reach the object's `accesstype/size/data` fields.

With the reply also carrying the probe's own canary and a chosen saved RIP
(the local `finish()` function), `gp_file_get_data_and_size()` on that live
object returned `data=0x1122334455667788` and `size=0x1a2b3c4d`, both chosen
by the device. Controls: count 100 and the fixed camlib make no bulk read
and produce no diversion; a wrong canary aborts at `__stack_chk_fail`; a
zero-filled reply with no field overrides returns `data=(nil) size=0x0`;
reversing the fix restores the chosen values.

This is a controlled pointer and length at a real library API, not a
command or control-flow chain: the pointer is never dereferenced, the
canary/RIP and victim placement are lab-assisted, and there is no wire,
physical USB, consumer network path or witness replay. Rung 4 at the real
heap/API scope; rung 5 remains UNKNOWN. Local-only vusb diff
`evidence/replay-vusb-victim.patch`, probe `evidence/replay-victim_probe.c`,
commands and raw output `evidence/real-plain-heap-pointer-control.out`.


## Normal return and pointer dereference (W171, 2026-11-24)

W170 reached a real API only after diverting `jl2005c_init` to `finish()`.
W171 restores the caller's stack state in the device reply so the function
returns into the real `camera_init`: the reply carries the probe's own
canary at `jl2005c_init` `rbp-8`, the real saved `rbp`/RIP at `rbp`/`rbp+8`,
and (measured from the live stack by gdb) `camera_init`'s canary at `rbp-0x18`
plus its saved `rbx`/`rbp`/RIP. The reply's fill would otherwise replace all
of these with `0x41`: without the caller canary, `camera_init` aborts with
`stack smashing detected`; without its saved frame, it faults at `ret`.

The five gdb-injected env values shift the heap, so `M2SHELL_VUSB_DRAIN=22`
(not W170's 24) is required to put the victim at `priv+0x4050`; drain 24 puts
it at `priv+0x4370`, outside the 0x4000-byte reply, and the pointer is lost.
With drain 22, `gp_camera_init` returns 0, the real
`gp_file_get_data_and_size()` returns the device-chosen pointer and length,
and dereferencing them reads back the device-chosen 29-byte marker
`M2SHELL_DEREF_MARKER_20261124`. Controls: safe fill, count 100, wrong
canary, fixed camlib (no bulk read, no victim), fix reversal, and the two
omitted-restore failures all behave as reported.

This is still rung 4, not a command or rung 5: the canary and all saved
registers come from gdb reading the live process, the victim placement is a
lab hook, there is no device-only canary recovery, physical USB, wire or
consumer network path, and gphoto2's own `gp_file_save()` aborts at
`malloc(): corrupted top size` before writing anything. Replay bundle:
`evidence/replay-vusb-normal-return.patch` (on top of
`replay-vusb-victim.patch`), `evidence/replay-normal_return_probe.c`,
`evidence/replay-normal-return.gdb`, and
`evidence/real-plain-normal-return-deref.out`.

## Real consumer writes device-directed bytes (W172, 2026-11-24)

W171 stopped at `gp_file_save()` aborting in `malloc(): corrupted top size`:
the 464-byte `:154` overflow reached the top chunk immediately after the
live `CameraFile` victim at `priv+0x4050`. W172 keeps live guard chunks
**after** the victim from inside the same lab vusb bulk-read hook, so the
overflow ends inside the guards and the top size word survives. With the W171
normal-return setup (drain 22, caller canary and saved registers restored by
gdb), the real `gp_file_save()` then returns `rc=0` and writes a 29-byte file
whose content is the device-chosen marker `M2SHELL_DEREF_MARKER_20261124`
(hex `4d 32 53 48 ... 32 36 31 31 32 34`). This is a real gphoto2 consumer
dereferencing the device-directed `file->data` and producing a host-side side
effect, not the probe's own `memcpy`.

The matched control with `M2SHELL_VUSB_GUARDS=0` and otherwise identical env
returns the same pointer from `gp_file_get_data_and_size()` but aborts in
`gp_file_save()` with `malloc(): corrupted top size`, leaving a 0-byte file:
guards are causal. Other controls: count 100 has no victim and no file;
zeroed `DATA`/`SIZE` gives `data=(nil) size=0x0` and no dereference; the fixed
camlib makes no bulk read, produces no victim and no file; reversing the fix
restores the write. Vulnerable camlib hash `0ccb1dac24a837bc…` before and
after the fixed-control cycle.

Grade: rung 4 extended to a real gphoto2 consumer write with an observed file
side effect. Still lab-assisted — the pointer value is supplied by the probe
(a lab-known address), the canary and saved registers come from gdb, the
victim and guards are placed by the lab hook, and the replies are synthetic.
No physical USB, wire, remote request, device-only canary recovery, command
or witness replay. Rung 5 stays UNKNOWN. Local-only diff
`evidence/replay-vusb-guards.patch` (applies after the W170 and W171 patches),
commands and all six raw runs in `evidence/real-plain-consumer-write.out`.

## Clean-archive replay and DRAIN sensitivity (W174, 2026-11-24)

W172 was replayed from `git archive 833729ad` (115 files, 4/4 pins OK,
tarball `5df9e774…7f28`, vulnerable camlib `0ccb1dac…`) with the committed
patches and probe source, rebuilt from scratch. The verbatim `DRAIN=22`
failed to reproduce: `priv=0x555555563ff0`, victim `0x555555563cb0` (before
`priv`), `CONSUMER_GET data=(nil) size=0x0` and a 0-byte save file. The
author tree had `priv=0x555555564070` and victim `priv+0x4050`; a shifted
startup heap leaves one more pre-existing 0x180 tcache chunk in the clean
tree. A drain sweep found `DRAIN=23` puts the victim at `priv+0x4050` there;
24 overshoots by one 0x190 chunk. `DRAIN` is a layout-tuning knob, not an
exploit primitive: the observable requirement is victim at `priv+0x4050`.

With `DRAIN=23` all six cases reproduced from clean bytes: attack
`gp_file_save rc=0` with the 29-byte marker file, matched `GUARDS=0` abort at
`malloc(): corrupted top size` with a 0-byte file, count 100 no victim,
zeroed `DATA`/`SIZE` no dereference, fixed camlib no bulk read, and fix
reversal restoring the write. Author replay, not independent acceptance;
grade unchanged at rung 4, rung 5 UNKNOWN. Exact commands, hashes, layout
sweep and raw observations in `evidence/real-plain-clean-replay.out`.
