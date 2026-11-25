# open5gs2shell real-NF replay provenance (2026-11-25)

All paths are relative to `lab/frontier/open5gs2shell/`. Nothing was
installed system-wide: `.deb`s were downloaded and extracted under `lab/`.

## Provisioning (already present in this lab, gitignored)

1. `apt-get download` into `provision/debs/`: `libmongoc-dev
   libmongoc-1.0-0t64 libbson-dev libbson-1.0-0t64 libmongocrypt-dev
   libmongocrypt0 libsnappy-dev libsasl2-dev libutf8proc-dev
   libnghttp2-dev libnghttp2-14 libtalloc-dev libtalloc2 libc-ares-dev
   libcares2 libmicrohttpd-dev libmicrohttpd12t64 libgcrypt20-dev
   libgpg-error-dev libidn-dev libidn12`, then `dpkg-deb -x` each into
   `local-prefix/`.
2. Copy each `local-prefix/usr/lib/x86_64-linux-gnu/pkgconfig/*.pc` into
   `local-prefix/pkgconfig-fixed/`, replacing only its `prefix=` line with
   the absolute path to `local-prefix/usr`. The original `.pc` files say
   `prefix=/usr`, which would point at system headers that are not installed.
3. Fetch `provision/open5gs-v2.8.0.tar.gz` from
   `https://codeload.github.com/open5gs/open5gs/tar.gz/refs/tags/v2.8.0`;
   SHA-256 must be
   `a04d66f66f6df62a376a2434a05a7268e08e4fc0cc1b9c56221467689a8b56ab`.
   Extract into `build/open5gs-2.8.0`.
4. With `P` the absolute path to `local-prefix`, set
   `PKG_CONFIG_PATH=$P/pkgconfig-fixed`,
   `C_INCLUDE_PATH=$P/usr/include:$P/usr/include/x86_64-linux-gnu`,
   `LIBRARY_PATH=$P/usr/lib/x86_64-linux-gnu`,
   `LD_LIBRARY_PATH=$P/usr/lib/x86_64-linux-gnu`. Then:
   `meson setup build/bld build/open5gs-2.8.0 --prefix=<lab>/local-install --buildtype=debug`
   and `ninja -j4 -C build/bld src/nrf/open5gs-nrfd`.
   Meson fetches its freeDiameter, libtins and prometheus-client-c
   subprojects into the gitignored source tree.
5. Fixed build: `cp -a build/open5gs-2.8.0 build/open5gs-2.8.0-fixed`,
   `cd` there and `patch -p1 < ../../provision/fix-6820c274.patch`
   (hunk offset -135), then repeat step 4 with `bld-fixed` and the fixed
   source directory.

## Replay

`cd nfloop && TAG=vuln sh run.sh` and
`TAG=fixed NRF_BIN=../build/bld-fixed/src/nrf/open5gs-nrfd sh run.sh`.
`run.sh` recreates fixtures from `mkfixtures.sh`, binds NRF only to
`127.0.0.1:18777`, sends h2c POSTs with curl, and records per-case stdout,
curl status and response bodies under `evidence/`. `nrf.yaml` is the
loopback-only config. `sh gdbattack.sh` captures a backtrace of the
vulnerable crash. Summary traces: `evidence/vuln-run.out`,
`evidence/fixed-run.out`, `evidence/gdbattack.out`.

Expected: vulnerable attack -> curl rc 56, NRF rc 134 (SIGABRT in talloc
free during `parse_multipart` cleanup); staged/safe/abc -> HTTP 400, NRF
alive; fixed attack -> HTTP 400 with `Empty multipart boundary`, NRF alive.

## AddressSanitizer variant (2026-11-25 10:1xZ)

With the same environment as step 4, build each source copy again with
`meson setup build/bld-asan build/open5gs-2.8.0 --prefix=<lab>/local-install
--buildtype=debug -Db_sanitize=address` (and `bld-fixed-asan` with the fixed
source), then `ninja -j4 -C <bld> src/nrf/open5gs-nrfd`. Both targets build
1886/1886 RC 0; logs are `build/nrfd-asan-build.log` and
`build/nrfd-fixed-asan-build.log`.

Replay with
`TAG=asan ASAN_OPTIONS=detect_leaks=0 NRF_BIN=../build/bld-asan/src/nrf/open5gs-nrfd sh run.sh`
and the matching `asanfixed` / `bld-fixed-asan` pair. Traces:
`evidence/asan-noleak-run.out` and `evidence/asanfixed-noleak-run.out`.
Without `detect_leaks=0`, LeakSanitizer reports unrelated leaks when the
controls are terminated and makes their wait rc 1 even though the HTTP
responses are correct (`evidence/asan-run.out`). The vulnerable attack
produces a real `heap-buffer-overflow WRITE of size 1` at
`multipart_parser.c:260`, 0 bytes past the 65-byte region from
`multipart_parser_init:82`, on the live NRF call stack; the patched build
rejects it with `Empty multipart boundary` and no ASan report.
