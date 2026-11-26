# Live dissector evidence — ettercap2shell

Companion to `reports/ettercap2shell-livedissector.md`. Files here are the
small durable artifacts; the source trees, object files and ASan binaries stay
in the gitignored `../live/` working directory.

## Provenance

- Sources: `git clone --depth 1 --branch v0.8.4.1` /
  `--branch v0.8.5.1` from `https://github.com/Ettercap/ettercap.git` on
  2026-11-23. Heads `0dc8409779f3a09cbfff4434b9a4d7b33480d88d` and
  `832524f3c4c215f1007fe9f190dbf052ee965b55`.
- `ec_gg.c` SHA-256: `a97a0984f9c9b62910f3259715287b42cff8dff87115913001f687f0a05189d8`
  (vuln), `a516ce050828f2c2abec17be35b1b87cea4d2b5c60484c073161d6e8a1fcce8d`
  (fixed) — identical to the pinned blobs in `../src/`.
- ASan binary SHA-256: `82bd9971fbf104928a56c2a418b5a75c4a066d15de593cb8d904cf6cfac60bb7`
  (vuln), `a6a85b52f7cc20e182cc2274a8c9566fc807e8532cda26d1df78fd5f9c1bbc67`
  (fixed).

## Dependencies provisioned

`sudo apt-get install -y libpcap-dev libpcre2-dev bison flex` (libssl, zlib,
ncurses and curl headers were already present). libnet 1.3 came from the
vulnerable tree's own `bundled_deps/libnet/libnet-1.3.tar.gz`, extracted to a
working dir and built with clean flags because exporting ASan flags to its
libtool configure breaks the build:

```
CFLAGS="-O2 -fPIC" ./configure --disable-shared --disable-samples \
  --enable-static --prefix=$PWD/inst
make -j4 && make install
```

## Exact cmake invocation (vulnerable; fixed identical apart from source dir)

```
LNP=<path-to>/libnet-1.3/inst
CC=clang CXX=clang++ cmake \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
  -DENABLE_GTK=OFF -DENABLE_CURSES=ON -DENABLE_PLUGINS=OFF \
  -DENABLE_GEOIP=OFF -DENABLE_IPV6=OFF -DENABLE_TESTS=OFF \
  -DSYSTEM_LIBNET=ON -DBUNDLED_LIBNET=OFF \
  -DLIBNET_INCLUDE_DIR=$LNP/include -DLIBNET_LIBRARY=$LNP/lib/libnet.a ..
make -j4
```

## Running

Offline replay: from `build-asan/` (so `./share/etter.conf` resolves):

```
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
  ./src/ettercap -T -q -r <pcap> -i lo
```

Live loopback: from `../live/`, `python3 liveinject.py gg-vuln.pcap` (optional
second/third args select the build directory and output tag). The script uses
`sudo -n env EC_UID=<owner> EC_GID=<owner> ...` so ettercap opens the capture
socket as root and then drops to the lab owner; a second privileged helper
sends the frame with `AF_PACKET` bound to `lo`. It terminates ettercap in its
`finally` block. Only `lo` is used.

## Plain (non-ASan) build — 2026-11-26

Same CMake switches as above, with `-DCMAKE_C_FLAGS="-g -O1 -fno-omit-frame-pointer"`
and the matching CXX flags and no linker sanitizer flag. Configure/build in
`../ettercap-0.8.4.1/build-plain` (and `../ettercap-0.8.5.1/build-plain` for the
fixed control), reusing the same libnet prefix. From `build-plain/`:


```
./src/ettercap -T -r ../../gg-vuln.pcap -i lo
```

Plain vulnerable: exit 134 `malloc(): corrupted top size`, 3/3; fixed plain,
safe, extent18, extent40, wrongtype and serverdir all exit 0. The abort
backtrace was captured with
`gdb -q -batch -ex 'set pagination off' -ex run -ex 'bt 12' --args ...`.

## File map

- `gg-vuln.pcap` — `version=0x44000042`, 24-byte TCP payload, client -> :8074.
- `gg-extent18.pcap`, `gg-extent40.pcap` — extent controls.
- `gg-safe.pcap`, `gg-wrongtype.pcap`, `gg-long.pcap`, `gg-serverdir.pcap` —
  safe version, type filter, full-length login, direction filter.
- `live-vuln.out`, `live-gg-extent18.out`, `live-gg-extent40.out`,
  `live-safe.out`, `live-wrongtype.out`, `live-fixed.out` — live runs.
- `replay-vuln.out`, `replay-fixed.out` — offline runs.
- `plain-vuln.out`, `plain-gdb.out`, `plain-safe.out`, `plain-fixed.out` —
  plain-build abort, backtrace and controls (2026-11-26).

`AddressSanitizer: attempting double-free` in `capture_getifs`/`pcap_freealldevs`
on SIGTERM and `Joining already joined thread` at shutdown are incidental
cleanup races in this build; they are not part of the GG finding. The control
criterion is `heap-buffer-overflow` inside `gg_get_version`.
