# Independent verification and reproducibility

This repository is designed so a reader can re-derive every published result
from the recorded sources, commands and expected bytes. First-party scripts
and reports are tracked. Upstream source tarballs, checked-out source trees,
build outputs, compiled `.so`/binaries and raw logs are intentionally
gitignored: they are large or machine-specific, and the commands below
regenerate them. No claim relies on a gitignored file being present in a
fresh checkout.

## Evidence ladder and isolation

Rungs — **suspected** (source/advisory) → **reproducible crash** →
**confirmed memory corruption** → **demonstrated impact** — are a depth
investigation of how far rung 4 can be pushed on each build, not boxes to
touch. A negative result, a harness-only grade, or an UNKNOWN records that
boundary and stays in the report. Nothing in this lab contacts a public
target or any external system; provisioning downloads public sources, and
all triggers, listeners, debuggers and test consumers run on `127.0.0.1`
or inside local containers whose host ports bind only to loopback.

## Common setup

- Linux x86-64 host, `gcc`/`clang`, `cmake`, `python3`, `curl`, `sha256sum`,
  `gdb`, optionally `valgrind`, `docker` for the container lanes.
- Run all commands from the repository root unless a lane says otherwise.
- Verify any fetched input before building; every script below either pins a
  SHA-256 or records why no published checksum exists.

## Lane index

| Lane | Report | Provision | Build | Replay |
|---|---|---|---|---|
| Ruby2Shell | [report](../reports/ruby2shell-investigation.md) | `bash lab/ruby2shell/provision.sh` | plain build `lab/build/plain/ruby-3.4.12-plain/bin/ruby` (recipe in report); ASan build `lab/build/ruby-3.4.12-asan` | `lab/repro/ruby2shell-rung1.rb`, `stageA.rb`, `stageC.sh`, `stageB-http.sh`, `stageB-rails.sh`, `bash lab/repro/ruby2shell-stageC-http.sh 3 2` with `stageC-http.ru` (Sinatra request-thread Stage C: 3/3 attacks read chosen bytes at the nominated address in the HTTP response, 2/2 controls clean; the process aborts in worker-thread teardown after readback — depth result, no grade change); copy-out lane: `valgrind --error-limit=no lab/build/plain/ruby-3.4.12-plain/bin/ruby -e 's="\xDF".b*21; s.force_encoding(Encoding::ISO_8859_1); p s.upcase.bytesize'` — N=21 shows `Invalid write of size 1` at `case_map (iso_8859_1.c:293)` and `Invalid read of size 2` via `rb_str_casemap (string.c:7857)`, `outlen=42`; N=20 clean, `outlen=40`. The read byte is the same fixed `0x53`, so this is rung-3 class, not a leak or rung 4 |
| PHP2Shell | [report](../reports/php2shell-investigation.md), [status](../reports/php2shell-status.md) | `bash lab/php2shell/provision.sh` | `bash lab/php2shell/build.sh`, `build-fpm.sh`, `build-fpm-release.sh`, `build-apache.sh`, `build-apache-plain.sh` | `lab/repro/php2shell-*.sh`, `*.py`, `*.gdb`; `lab/repro/php2shell-cve129538.py` and `lab/repro/php2shell-cve129538-fcgi.py` replay the adjacent CVE-2026-129538 lane on pinned 8.5.12-asan / 8.5.13-asan / 8.4.27-asan: direct php-cgi `VERDICT CONFIRMED` 7/7, FastCGI long suffix yields `PATH_INFO=".0.1"` on affected and `"/x"` on fixed 3/3, steering leaks `"23456789"` / `"27.0.0.1"` by param order 5/5; gdb observes the OOB NUL byte at `cgi_main.c:1294`, ASan silent by design; evidence `lab/build/evidence/w48-cve129538/{committed,fcgi-committed,fcgi-steered}/verdict.txt` |
| Node2Shell | [report](../reports/node2shell-investigation.md) | `bash lab/node2shell/provision.sh` | prebuilt binaries, no local source build | `sh lab/repro/node2shell-stageA.sh 5`; `lab/repro/node2shell-shrinkwalk/run-multi.sh`; `sh lab/repro/node2shell-utf8check/run.sh c480 520` and `... run.sh 61 520` — replayed this wake on pinned v24.22.2: U+0100 (`c4 80`) `:authority` draws `NGHTTP2_PROTOCOL_ERROR`, ASCII `61` control completes with `ALTSVC origin_len=528`; preserved negative, no binary-capable heap-byte channel; `sh lab/repro/node2shell-valnul/run.sh 3` — wake-33 value-side trigger: ALT 1048 → SIGABRT rc=134 `malloc(): invalid next size (unsorted)` (3/3), ALT 1200 and ALT 10 → alive with ALTSVC echo (2/2 each) |
| Apache2Root | [report](../reports/apache2shell-investigation.md) | `lab/src/httpd-2.4.{70,71}.tar.bz2` + `.sha256` sidecars; `nghttp2-1.64.0.tar.xz` SHA-256 `88bb94c9…dd9`; L2 sources `httpd-2.4.66.tar.bz2` SHA-256 `94d7ff2b42acbb828e870ba29e4cbad48e558a79c623ad3596e4116efcfea25a` and `httpd-2.4.67.tar.bz2` SHA-256 `66cd206637b0d5c446fa7dabe75fe03525da8fb55855876c46288cd88b136aa4` | `lab/frontier/apache2root/build.sh`; `bash lab/apache2shell/build-l2.sh` builds the L2 ASan/UBSan pair | `oracle.sh`, `race.sh`, `lab/apache2shell/{sweep,gdb-inspect,drive.py,alphabet-probe.py,huffman-probe.py}`; the Huffman probe now self-checks its wire bytes and was repaired and re-run at 19:11Z (the older Huffman rows were literal restatements); `python3 lab/apache2shell/pushdiary-lane.py` — adjacent lane L1 (`H2PushDiarySize 0` + debug logging): 2.4.70 handshake fails, server rc=1, ASan `SEGV on unknown address 0x00000000000c` in `h2_session_create` and UBSan `member access within null pointer of type 'struct h2_push_diary'`; 2.4.71 rc=0 with no sanitizer report; `python3 lab/apache2shell/l2-lane.py` — adjacent lane L2 (CVE-2026-23918 early-reset double purge): pristine 2.4.66 800 sent / 18 responses with child aborts or SEGVs, 2.4.67 control 800/234 and 800/248 with no assertion, abort or SEGV; both graded rung 2 only |
| Mosquitto2Shell | [report](../reports/frontier-mosquitto2shell.md), [status](../reports/mosquitto2shell-status.md) | `bash lab/frontier/mosquitto2shell/provision.sh`, `bash …/provision-cjson.sh` | `build.sh`, `build-glibc.sh` | `run.sh`, `placement.sh`, `tcache_probe.py`, `pong_leak_probe.py` |
| Brotli2Shell | [report](../reports/frontier-brotli2shell.md) | `bash lab/frontier/brotli2shell/run.sh` fetches `poc.py` and verifies its SHA-256 | same script builds v1.2.0/v1.2.1/instrumented | same script writes `logs/` and prints digests |
| Postgres2Shell | [report](../reports/frontier-postgres2shell.md) | image digests pinned in `run.sh` | container images by digest | `./run.sh 17.11` and `./run.sh 17.12`; `trigger-vg.sql` for Valgrind |
| Dragonfly2Shell | [report](../reports/frontier-dragonfly2shell.md) | image digests pinned in `run.sh` | container images by digest | `./run.sh v1.40.1`, `./run.sh v1.40.2`; witness files in `lab/witness/dragonfly2shell/` |
| FreeRADIUS2Shell | [report](../reports/frontier-freeradius2shell.md), [status](../reports/freeradius2shell-status.md) | source at vulnerable parent `3f802d74deef`, fix `064567a08f3b`; artifact digests in report | `cd lab/frontier/freeradius2shell && bash run.sh` builds vulnerable/fixed/canary/asan | same script prints `ALL CHECKS PASS`, writes `logs/` and `logs/digests.txt` |
| Falkordb2Shell | [report](../reports/frontier-falkordb2shell.md), [status](../reports/falkordb2shell-status.md) | source at vulnerable parent `40780e992ecc`, fix `0b11a00b34b2` (removes Bolt/WebSocket; lab `FIXED` is a local length guard) | `cd lab/frontier/falkordb2shell && bash run.sh` builds vuln/fixed/asan | same script prints `ALL CHECKS PASS`: `payload_len=4144`, 525 OOB write operations, canary `K:K`, ASan heap-buffer-overflow (READ of size 8 at the `^=` load) |
| Freeswitch2Shell | [report](../reports/frontier-freeswitch2shell.md), [status](../reports/freeswitch2shell-status.md) | source at vulnerable parent `fbac12b451a1`, fix `d557ca6d29e6da4f10824dc158100906a592b91a`; both `mod_xml_rpc` and `enable-websocket` off by default | `cd lab/frontier/freeswitch2shell && bash run.sh` builds vuln/fixed/asan; `bash lab/freeswitch2shell/live/run.sh`, `bash lab/freeswitch2shell/live/run_pos.sh` and `bash lab/freeswitch2shell/live/run_live_gdb.sh` build the unmodified source over loopback | repaired driver prints `ALL CHECKS PASS` (rc 0) with pinned sources `ws_overflow.c` `75433b5d…` / `run.sh` `637cfa36…`: ASan `WRITE of size 132146` in `ws_raw_read`, 1464 OOB writes from 65536 to 66999, chosen 8 bytes at `offsetof(wsh_t, ssl)=131112` with `marker_called=1` and `rc=42`, fixed `rc=-1009`, 5/5 identical. Real-source `run.sh` (`FF FF FF FF`): ASan `negative-size-param (size=-5)`, plain rc 134, fixed `rc=-1009` with `wsh->ssl` untouched, offset 131112 validated. Real-source `run_pos.sh` (`7F FF FF FF 00 00 00 00`, `plen=INT_MAX`): plain `wsh->ssl=0x4142434445464748`, `ssl_bytes=4847464544434241`, `RESULT=PASS` rc 0; fixed `rc=-1009`, `ssl=(nil)`; ASan `WRITE of size 4096` at the end of a 131136-byte region from `ws_raw_read (ws.c:300)`. A full vulnerable FreeSWITCH then ran in a private netns on 127.0.0.1 with a real WebSocket `101` upgrade; GDB caught the chosen `wsh->ssl` dereference in `SSL_shutdown`, witness-replayed (#338) with changed bytes at the same site. Stock heap layout and external reachability remain UNKNOWN. |
| Freerdp2Shell | [report](../reports/frontier-freerdp2shell.md), [status](../reports/freerdp2shell-status.md) | source at vulnerable parent `8ec6d3923b`, fix `bf217a5` (3.32.1, `/ 4` division guard); digests `d0a31487…` / `c5186500…`; real-library source tag 3.32.0 at `d27a4f7c1c63b62a5e60e5d939ad116cfb58ffc1` | `cd lab/frontier/freerdp2shell && bash run.sh` builds the extracted harness; `bash lab/freerdp2shell-src/run.sh` builds source-built ASan and plain libraries; `python3 lab/freerdp2shell-src/loopback_shadow_probe.py nego|tls-auth` drives a real loopback shadow server; `python3 lab/freerdp2shell-src/live_mcs_join_probe.py` and a headless `sfreerdp` replay the live session; `bash lab/freerdp2shell-src/verify_live.sh` replays the whole live stock-allocator claim in one command (17 PASS warm / 18 PASS clean-room) | extracted harness prints `ALL CHECKS PASS` (rc 0) twice; the real library prints `ALL REAL-LIBRARY CHECKS PASS` (rc 0): ASan `WRITE of size 16384` 0 bytes after an 8820-byte region in `rdpsnd_server_send_samples`, chosen `de`/`ad` at OOB offsets 8820/21384 through the real `SNDC_FORMATS` parser, fixed-guard control rc 3 with no wrap. Wake 7: a real 3.32.0 `freerdp-shadow-cli` on 127.0.0.1:13890 answered X.224 / RDP_NEG_REQ over real TCP (`0x08` NLA, `0x02` TLS, `0x00` RDP) and the default NLA gate stopped a TLS-authenticated client at `CONNECTION_STATE_NEGO` when CredSSP was withheld; a standard-RDP local-peer offer advanced without credentials. Wake 8: MCS CONNECT / ERECT DOMAIN / ATTACH USER / three CHANNEL JOIN confirms, `CONNECTION_STATE_ACTIVE`, `SNDC_FORMATS` over the wire and the live server's `realloc failed!` / `SelectFormat failed with 12`; the live ASan server then reports `WRITE of size 16384` 0 bytes after an 8820-byte region with client-chosen `0xDE` at offset 8820 (`live_session_wrap.txt`). No-auth server, subsystem-supplied ADPCM table, ASan build and synthetic playback are explicit conditions; the one-command replay above closed stock allocator layout and witness W31 independently accepted it (#532, 18 PASS / 0 FAIL from clean HEAD b25d025, ESTABLISHED, no corrections; the harness uses post-auth credentials); pointer control, a stock wrap-capable format and an FFmpeg-enabled build stay UNKNOWN. |
| Xrdp2Shell | [brief](../reports/frontier-xrdp2shell.md), [status](../reports/xrdp2shell-status.md) | xrdp 0.10.6 raw source (digest `d743c53f…`) and fixed 0.10.6.1 (`4b6c64e8…`), fix `43dc9c3b…`; harness digests `46735a43…` / `2da4d3ea…`; real-path drivers `a05ba8ac…` (`real_drdynvc_driver.c`) / `ecfe9f7e…` (`chosen_bytes_real_path.c`) | `cd lab/frontier/xrdp2shell && bash run.sh` builds the extracted harness; `lab/xrdp2shell-real/RUNBOOK.md` pins both exact `configure` lines and the `cc` links against the real ASan `build-asan/libxrdp/.libs/libxrdp.a` + `libcommon.a` | replayed ~20:25Z: `ALL CHECKS PASS`, rc 0 — rung 1 `oob_writes=11836 first_oob=8192 last_oob=20027`, chosen `ab`/`cd` at OOB offsets 8228/12028, ASan `WRITE of size 20000` 0 bytes after an 8192-byte region, rung 4 `de`/`ad` at offsets 8228/12024, fixed and benign controls `oob_writes=0`, 5/5 identical. Real compiled-code replay (2026-11-21): ASan `WRITE of size 20000` in `memcpy` 0 bytes after the 8192-byte `trans_create` region via `xrdp_channel_process()` → real `drdynvc_process_data_first()`; threshold 8164 clean / 8165 OOB, 5/5 identical; non-ASan reader `CANARY delta=8208 k1=84 k2=484`, `CHOSEN_BYTES m1=PASS m2=PASS` with `DEADBEEF-CR`/`C0FFEE00-CR` read back; gate 20000/1000 and 20000/19000 clean, 1600/1590 reject. Raw traces `vuln/threshold/determinism/chosen_bytes/gate.txt` are gitignored under `lab/build/xrdp2shell-live/client/` and regenerated by the runbook commands; the 8128-byte cap is a control, not the real fix. No full RDP session, dynamic-channel open, network PDU trace or live-session allocator layout; loopback COTP reply only; post-auth gate intrinsic; witness replay owed. |
| Gst2Shell | [brief](../reports/frontier-gst2shell.md), [status](../reports/gst2shell-status.md) | source at vulnerable parent `0b70c356345335dacc0acdc45d07a8a33bdf5eab`, fix `80c184b4c5ee8ba28b2540ba58f40b8d44b61622`; harness digests `3d2b8e06…` / `7dde5da7…`; family drivers `rtsp_server_codec.py` `1493f137…cb45c` / `run_rtsp_family.sh` `54e8331e…786e` | `cd lab/frontier/gst2shell && bash run.sh` builds the extracted vulnerable/fixed/ASan variants; `bash lab/gst2shell-src/run_live.sh` and `bash lab/gst2shell-src/run_real.sh` drive the live GObject and shipping-plugin cases; `bash lab/gst2shell-src/run_sdp.sh` drives SDP text through GStreamer's parser (digest `6ba2e707…c4f`); `python3 lab/gst2shell-src/rtsp_server.py` plus `bash lab/gst2shell-src/run_rtsp.sh` drive the remote loopback path; `bash lab/gst2shell-src/run_rtsp_family.sh` covers L8/L16/L24; `bash lab/gst2shell-src/verify_all.sh` replays all drivers (add `VERIFY_VALGRIND=1` for memcheck) | replayed 20:47Z from clean committed sources: `ALL CHECKS PASS`, rc 0 — rung 1 `oob_writes=936 first_oob=256 last_oob=3999` with 3744 counted OOB bytes, caps length controls which offsets are clobbered, ASan `WRITE of size 4` 0 bytes after a 256-byte region in `vuln_create_default`, fixed control `oob_writes=0`, 5/5 identical. Wake 6 corrected the extracted harness's `NONE=0` model: pinned `audio-channels.h:101` defines `NONE=-3`, so index 73 turns NULL `order` into `0x00000000fffffffd`; the live ASan harness faults at `order->pos` and the shipping 1.24.2 `rtpL16depay` faults rc 139 for `encoding-params` 86/87/100/1000. A 2026-11-21 pass symbolicated the N=1000 fault by gdb debuginfod to `srcpad->g_class` of a heap-adjacent GstPad (`lab/gst2shell-src/gdb_symbolicated_1000.txt`) and reproduced the same fault from SDP text at N=86/1000 with the RTP structure name modelled in the harness; the `sdpdemux` file path is a bounded negative (tracked `sdp_evidence.txt`). A loopback RTSP server then drove a real `rtspsrc ! rtpL16depay ! fakesink` victim with no auth challenge (`rtsp_server.py` `f812d844…e0668`, `run_rtsp.sh` `9841c920…2a5d`): N=1000 rc 139 four times against clean N=8, gdb locating the corruption in GLib's `block_source` (`rtsp_gdb_1000.txt`); stock `uridecodebin` auto-selects the depay and aborts rc 134 with `malloc(): invalid size` (`uridecode_{8,1000}.log`). Family run: N=1000 faults L8/L24 with heap aborts (rc 134) and L16 with SIGSEGV/segtrap (rc 124) against clean N=8; memcheck reports three 4-byte invalid stores 0/4/12 bytes past a 1,016-byte GObject block (`ERROR SUMMARY: 592 errors from 6 contexts`). One-command replay `verify_all.sh` is committed at `TOTAL: pass=43 fail=0`, rc 0 (`verify_all_run.txt`, git HEAD 3b07571), chosen-byte rung 4 asserted NOT demonstrated. Chosen bytes, arbitrary pointer control, code execution and public-service SDP reach stay NOT DEMONSTRATED or UNKNOWN. |
| Babelfish2Shell | [brief](../reports/frontier-babelfish2shell.md), [status](../reports/babelfish2shell-status.md) | raw sources at tags `BABEL_4_8_0` / `BABEL_4_10_0`, fix `ab820bddaffa540af82f2f689c3e535f82f14d89`, harness digests in `PROVENANCE.md` | `cd lab/frontier/babelfish2shell && bash run.sh` builds the extracted vulnerable/fixed/ASan variants | replayed 2026-11-20 from committed sources: `ALL CHECKS PASS`, rc 0 — rung 1 `token=0x02 length=4096 si_capacity=1024 oob_writes=3072 first_oob=1024 last_oob=4095`, rung 2 length 1050/1150/2100 clobbers neither/first/both stamps, rung 3 ASan `WRITE of size 4096` 0 bytes after a 1024-byte region in `wire_getbytes`, rung 4 `de ad be ef ca fe ba be` at offset 1100 and `41 42 43 44` at 2000, fixed control `rc=0 oob_writes=0`, 5/5 `sha256=e216eeec…`. Harness only: real palloc layout, live TDS process, pointer control and execution UNKNOWN. |
| Bzfs2Shell | [brief](../reports/frontier-bzfs2shell.md), [status](../reports/bzfs2shell-status.md) | raw sources at tags `v2.4.30` / `v2.4.32`, fix `8e501d685aef549090b363260979a4eb93484ea1` (OSV also `f11f05485d74…`); harness digests `1a16963f…` / `f2686d5b…` in `PROVENANCE.md` | `cd lab/frontier/bzfs2shell && bash run.sh out` builds the extracted vulnerable/fixed/ASan variants | replayed at handoff 2026-11-21 from committed sources: `ALL CHECKS PASS`, rc 0 — rung 1 `tcplen=-1024` with chosen tail at `tcpmsg+1024`, rung 2 destination 936 bytes before the object and next length 1028, rung 3 ASan `heap-buffer-overflow` `WRITE of size 64`, rung 4 `DEADBEEFCAFEBABE` / `0123456789ABCDEF` read back byte-exact from chosen preceding harness members, fixed controls reject at the first bound and are ASan-clean, 5/5 identical (`sha256=cea3b92e…`). Harness-only chosen-value control; no live bzfs, real layout or execution. |
| Kamailio2Shell | [brief](../reports/frontier-kamailio2shell.md), [status](../reports/kamailio2shell-status.md) | raw `notify.c` / `save.c` at tags `6.1.4` and `6.1.5`, fix commit `21261436492f0014930e804e20586e3833bb91b9`; source hashes and URLs in `lab/frontier/kamailio2shell/PROVENANCE.md` | `cd lab/frontier/kamailio2shell && bash run.sh <outdir>` builds the extracted alias-branch variants; gcc 13.3.0, `-O0 -g` | operator replay at admission: `ALL CHECKS PASS rc 0`, 16 PASS lines, deterministic trace `sha256=94ef79641b081f850cb04f95d0f0945e7de7f84f9505462f23bf8aa054fa1cb8`; rung 1 `len=80 oob=75`, rung 3 ASan `WRITE of size 80` in `memcpy` ← `parse_alias`, rung 4 marker through instrumented pointer only, pinned 6.1.5 rejects before the copy. No live Kamailio, real frame layout or return-address control |
| Iperf2Shell | [brief](../reports/frontier-iperf2shell.md), [status](../reports/iperf2shell-status.md) | raw `iperf_auth.c` at tags `3.20` / `3.21` / `3.22`, fix commit `d08588aceee48fa45832cae5e32616abb33cb0fc`; source hashes and URLs in `lab/frontier/iperf2shell/PROVENANCE.md` | `cd lab/frontier/iperf2shell && bash run.sh <outdir>` compiles the real pinned upstream `iperf_auth.c` at 3.21/3.22; gcc 13.3.0, OpenSSL 3.0.13, `-O0 -g` | operator replay at admission: `ALL CHECKS PASS rc 0`, 17 PASS lines (frontier corrected the count at 02:24Z; re-verified from committed HEAD), trace `sha256=bd3efc4cb4720e7fe5cc2e83e79cc7e89010f75a7e93579360a215eb5f029caf`; decoded len 336 into 256-byte buffer, ASan `WRITE of size 336` from `BIO_read` ← `decrypt_rsa_message`, plain build aborts at `free(): invalid size`, chosen bytes only in the write buffer, 3.22 rejects before `BIO_read`. No live server, stock heap layout or useful-pointer control |
| Uftpd2Shell | [brief](../reports/frontier-uftpd2shell.md), [status](../reports/uftpd2shell-status.md) | raw `src/common.c` at tags `v2.15` / `v2.16`, fix commit `f5552a8c6a5f14691f51bef1f3373747259d7ac8` (11-line bound); source hashes and URLs in `lab/frontier/uftpd2shell/PROVENANCE.md` | `cd lab/frontier/uftpd2shell && bash run.sh <outdir>` extracts the verbatim pinned upstream `compose_path()` at replay time; gcc 13.3.0, `-O0 -g` | operator replay at admission: `ALL CHECKS PASS rc 0`, 23 PASS lines, trace `sha256=ad11094aa03e898df6c3b00a83b6b8ba8a9b049e0a0a18bf5fd952475d09d33b`; rung 1 `path_len=4095 home_len=128 expected_oob=128`, rung 2 `*** stack smashing detected ***`, rung 3 ASan `WRITE of size 4096` into `dir` `[256, 4352)` at `common.c.v2.15:61`, rung 4 chosen bytes from the upstream `memmove` only; pinned 2.16 leaves `returned=null`. No live uftpd, stock frame layout or useful pointer. |
| Accelppp2Shell | [brief](../reports/frontier-accelppp2shell.md), [status](../reports/accelppp2shell-status.md) | raw `log_tcp.c` / `log.c` at tags `1.14.0` / `1.15.0`, fix commit `58e399400c4ef4b71472ab7c2c71c54a677a05a8` (PR #374); source hashes and URLs in `lab/frontier/accelppp2shell/PROVENANCE.md` | `cd lab/frontier/accelppp2shell && bash run.sh <outdir>` extracts verbatim pinned upstream `unpack_msg()` at replay time, padding leading lines so upstream line numbers survive; gcc 13.3.0, `-O0 -g` | operator replay at admission: `ALL CHECKS PASS rc 0`, 19 PASS lines, trace `sha256=3499f52eef8814e5cc73c5e38f990ca0de3f4f0fc243640452c7806dc9c2b18a`; rung 1 `pos=4254 expected_oob=94`, rung 2 chosen `0x1122334455667788` byte-exact in the adjacent harness object, rung 3 ASan `WRITE of size 64` at pinned `log_tcp.c.1.14.0:63`, pinned 1.15.0 bounded with a clean neighbour. No live daemon, real AVP path or useful-pointer control. |
| Indiserver2Shell | [brief](../reports/frontier-indiserver2shell.md), [status](../reports/indiserver2shell-status.md) | raw `lilxml.cpp` / `lilxml.h` / `MsgQueue.cpp` at fix parent `3220880` and fix `96bbd7f564bbb128a129019e44eadd40dd49cff9`; hashes and URLs in `lab/frontier/indiserver2shell/PROVENANCE.md` | `cd lab/frontier/indiserver2shell && bash run.sh <outdir>` compiles the byte-exact pinned upstream `oneXMLchar()` / `parseXMLChunk()`; gcc 13.3.0, `-O0 -g` | operator replay at admission: `ALL CHECKS PASS rc 0`, 19 PASS lines, trace `sha256=2c446e0f1b1beecee5aa437d5a15818ad0c951d72fbcdb2cb545a656925ca85c`; rung 1 1237 bytes into `err[1024]` (`oob=213`), rung 3 ASan `WRITE of size 1237` at pinned `lilxml.cpp:1281`, rung 4 `INDI2SHELL` at offsets 0/64, fixed `96bbd7f` clean. No live daemon, real socket or RCE. |
| Shairport2Shell | [brief](../reports/frontier-shairport2shell.md), [status](../reports/shairport2shell-status.md) | raw pinned `rtsp.c` at fix parent `a50f18469143b9dbe599b8333d228a586dc29e67` and fix `c1c41c4ec9937eb7d2f8819dadd5bc45f65ab3f4` (development merge `74d59d8f`, master backport `a5d8f46a`); hashes and URLs in `lab/frontier/shairport2shell/PROVENANCE.md` | `cd lab/frontier/shairport2shell && bash run.sh <outdir>` compiles the byte-exact pinned upstream `rtsp.c:4206-4221`; gcc 13.3.0, `-O0 -g` | operator replay at admission: `ALL CHECKS PASS rc 0`, 21 PASS lines, trace `sha256=b87176f5891ef547eef69a11176fd3e0a3a3c367fd19fdf80d30fa9b733e9c86`; rung 1 8193 bytes into `obf[4096]`, rung 3 ASan `WRITE of size 3` at pinned `rtsp.c:4215`, rung 4 `INDI2SHELL` at offsets 0/64; fixed `c1c41c4` clean. No live daemon, socket or auth-bypass observation; advisory claims availability only. |

Xrdp2Shell was handed off from frontier on 2026-11-20 and admitted by the
operator ~20:27Z under standing approval #6. Its charter, docs/task.md entry,
two-pane window (19, inner socket), seed wall and status file are live; wake
trigger units and the presentation.json entry are owed from the person's
full-flag sync (`docs/runtime-pin.md`), never a bare `mishe sync`. The
[brief](../reports/frontier-xrdp2shell.md) pins the sources, harness digests
and expected bytes for rungs 1-3 plus chosen-byte rung 4. A second driver
(`lab/xrdp2shell-real/`, 2026-11-21) reproduces rung 3 and rung 4 on real
compiled xrdp 0.10.6 library bytes through the real DYNVC parse path; no
pointer-sized target was controlled. A full RDP session, dynamic-channel open,
network PDU trace, stock live-session layout and the post-auth gate stay
UNKNOWN; only loopback COTP reachability of the lab listener is evidenced.

Gst2Shell was handed off from frontier on 2026-11-20 and admitted by the
operator ~20:52Z under standing approval #6. Its charter, docs/task.md entry,
two-pane window (20, inner socket), seed wall and status file are live; wake
trigger units and the presentation.json entry are owed from the person's
full-flag sync (`docs/runtime-pin.md`), never a bare `mishe sync`. The
[brief](../reports/frontier-gst2shell.md) pins the sources, harness digests
and expected bytes for rungs 1-3. The extracted harness's "rung 4 is a
zero-fill negative" claim is superseded: pinned `audio-channels.h:101` defines
`GST_AUDIO_CHANNEL_POSITION_NONE = -3`, so the OOB writes store
`fd ff ff ff` and index 73 corrupts the low half of the `order` pointer from
NULL to `0x00000000fffffffd`. Wake 6 drove real GStreamer 1.24.2 types under
ASan (`bash lab/gst2shell-src/run_live.sh`) to a deterministic `order->pos`
fault and the shipping `rtpL16depay` plugin (`bash lab/gst2shell-src/run_real.sh`)
to rc 139 with one caps field. A 2026-11-21 pass symbolicated the N=1000 fault
by gdb debuginfod to `srcpad->g_class` of a heap-adjacent GstPad and drove SDP text to
the same fault through GStreamer's own parser (`bash lab/gst2shell-src/run_sdp.sh`,
digest `6ba2e707…c4f`; the RTP structure name is modelled in the harness); the
native `sdpdemux` file path reached PLAYING without instantiating
`rtpL16depay` and fails at benign N=8 too, a bounded negative. The local gap
was closed with a loopback-only RTSP server:
`python3 lab/gst2shell-src/rtsp_server.py` (digest `f812d844…e0668`) plus
`bash lab/gst2shell-src/run_rtsp.sh` (digest `9841c920…2a5d`) run a real
`rtspsrc ! rtpL16depay ! fakesink` victim with no auth challenge. N=8 stays
alive (40 RTP packets, rc 124); N=1000 faults rc 139 four times and gdb shows
`rbx = 0xfffffffdfffffffd` in GLib's `block_source` (`rtsp_gdb_1000.txt`).
Stock `uridecodebin` auto-selects `GstRtpL16Depay` and aborts at N=1000 with
`malloc(): invalid size` (rc 134) while N=8 stays alive
(`uridecode_{8,1000}.log`). That is impact controlled by channel count, not
chosen bytes: strong rung 4; whether any public service ingests attacker SDP,
RCE and allocator layout stay UNKNOWN.
The same loopback server was repeated across the advisory family with
`rtsp_server_codec.py` (`1493f137…cb45c`) and `run_rtsp_family.sh`
(`54e8331e…786e`; evidence `lab/gst2shell-src/family_evidence.txt`):
decodebin auto-plugs L8/L16/L24 depays and N=1000 faults each — L8 and L24 by
heap abort (rc 134), L16 by SIGSEGV/segtrap (rc 124) — while N=8 stays clean.
The exact glibc message varies between runs, so only "attacker-chosen count
faults the victim" is asserted. Under memcheck (`vg_L8_1000.log`, SHA-256
`42cde0ec…fed2e`; write-up `valgrind_evidence.txt`) the L8 path shows three
4-byte invalid stores 0/4/12 bytes past a 1,016-byte GObject allocation; the
shipping plugin has no debug info, so the write is not symbolicated to a
function name in that run. `bash lab/gst2shell-src/verify_all.sh` (optionally
`VERIFY_VALGRIND=1`) replays all drivers; its committed run is 43 PASS /
0 FAIL, rc 0 at git HEAD 3b07571.

Freerdp2Shell was handed off at 19:19Z and admitted by the operator at
19:32Z under standing approval #6; the two-pane window, seed wall, charter
and task-file entry are live. Wake trigger units and the presentation.json
entry are owed from the person's full-flag sync (`docs/runtime-pin.md`),
never a bare `mishe sync`. The [brief](../reports/frontier-freerdp2shell.md)
pins the sources, harness digests and expected bytes for rungs 1-3 plus
harness-only rung 4. Wake 4 drove chosen bytes through the real
`SNDC_FORMATS` parser on source-built 3.32.0 library bytes; wake 5 framed a
PDU through the real `rdpsnd_server_handle_messages()` dispatcher. Wake 6
replaced the stub WTS callback with libfreerdp's real WTS reader and ran the
shadow `Activated` selection logic, but measured that the FFmpeg-off builds'
server format list is PCM-only: both wrap-capable tags need a
subsystem-supplied server format table to be selected. Rung 4 through that
real reader, dispatcher, activation and parser is recorded with the condition
explicit. Wake 7 built a real 3.32.0 `freerdp-shadow-cli` on 127.0.0.1:13890
and drove X.224 / RDP_NEG_REQ over real TCP with the committed
`lab/freerdp2shell-src/loopback_shadow_probe.py`; the default NLA gate held
after a completed TLS handshake with CredSSP withheld (server at
`CONNECTION_STATE_NEGO`), while a standard-RDP local-peer offer advanced
without credentials. Wake 8 completed X.224 → MCS CONNECT → ERECT DOMAIN →
ATTACH USER → three CHANNEL JOIN confirms (`live_mcs_join_probe.py`) and
drove a headless `sfreerdp` to `CONNECTION_STATE_ACTIVE`; `SNDC_FORMATS`
crossed the real wire and a subsystem-supplied ADPCM record logged
`realloc failed!` / `SelectFormat failed with 12` in the live server. With
`wVersion=1` in both PDUs the ASan build reports `heap-buffer-overflow`,
`WRITE of size 16384`, 0 bytes after an 8820-byte region from
`rdpsnd_server_send_samples`, first OOB byte 0xDE chosen by the client
(`live_session_wrap.txt`, raw `live_session_*.log`, scratch diffs under
`wake8-patches/`). Conditions: no-auth server, subsystem-supplied ADPCM
table, ASan build, synthetic playback event. Still UNKNOWN: stock allocator
layout, a stock wrap-capable server format, an FFmpeg-enabled build and a
real audio source.

Babelfish2Shell was handed off from frontier on 2026-11-20 ~22:08Z (commit
`088d4bc`) and admitted by the operator ~22:2xZ under standing approval #6.
The [status](../reports/babelfish2shell-status.md) records the boundary;
charter, `docs/task.md`, README and the lane index are updated, so it is now
one of the admitted families. The two-pane window (21), seed wall, brief and
status file were already live from frontier; wake trigger units and the
presentation entry are owed from the person's full-flag sync, never a bare
`mishe sync`. The brief pins the source tags, fix commit and harness digests
for rungs 1-3 plus chosen bytes at chosen offsets in the extracted harness;
the real palloc chunk layout, a live TDS endpoint, pointer control and
execution stay UNKNOWN.

Bzfs2Shell was handed off from frontier on 2026-11-21 ~00:2xZ (commit
`3063973`) and admitted by the operator ~00:5xZ under standing approval #6.
It is a C++ game server admitted as an X2Shell-class extension by recorded
judgment (scope note in the charter), distinct from every other lane. The
two-pane window (22, inner socket), seed wall, brief and status file were
already live from frontier and verified by the operator before announcement;
the charter, `docs/task.md`, README and this lane index are now updated.
Wake trigger units and the presentation entry are owed from the person's
full-flag sync (`docs/runtime-pin.md`), never a bare `mishe sync`. The brief
pins the tags, fix commit and harness digests for rungs 1-3 plus
instrumented chosen-value control in the extracted harness; a live `bzfs`
player socket, real `NetHandler` layout, allocator neighbour, pointer
control and execution stay UNKNOWN, and witness replay was requested (#429).

Kamailio2Shell was handed off from frontier on 2026-11-21 ~01:5xZ (tape
#469) and admitted by the operator ~02:2xZ under standing approval #6. The
two-pane window (24, inner socket), seed wall, brief and status file were
already live from frontier; the charter, `docs/task.md`, README and this lane
index are now updated. Wake trigger units and the presentation entry are
owed from the person's full-flag sync (`docs/runtime-pin.md`), never a bare
`mishe sync`. The `ims_registrar_pcscf` module must be loaded and configured;
the harness reproduces the tilde-distance `memcpy` into `bufport[5]` and the
unchecked NUL store, with a pinned 6.1.5 reject control. Rung 4 marker
execution is instrumented only: no live process, real stack layout,
stack-protector result, saved-RIP control or execution.

Iperf2Shell was handed off from frontier on 2026-11-21 ~02:1xZ (tape #477)
and admitted by the operator ~02:2xZ under standing approval #6. The two-pane
window (25, inner socket), seed wall, brief and status file were already
live; the charter, `docs/task.md`, README and this lane index are now
updated. Wake trigger units and the presentation entry are owed from the
person's full-flag sync, never a bare `mishe sync`. The harness compiles the
real pinned upstream `iperf_auth.c`, so the ASan `WRITE of size 336` and the
plain-build `free(): invalid size` abort are on the real function; rung-4
chosen bytes are supplied in the write buffer only. RSA auth must be enabled
(still pre-auth), and the 3.22 release-note CVE mislabel is preserved next to
the CVE/GHSA/fix-commit evidence. No live server, stock heap layout or
useful-pointer control was observed.

Uftpd2Shell was handed off from frontier on 2026-11-21 ~02:32Z (tape #496,
commit `243a99e`) and admitted by the operator ~02:4xZ under standing
approval #6. The two-pane window (26, inner socket), seed wall, brief and
status file were already live; the charter, `docs/task.md`, README and this
lane index are now updated. Wake trigger units and the presentation entry
are owed from the person's full-flag sync (`docs/runtime-pin.md`), never a
bare `mishe sync`. The harness compiles the verbatim pinned upstream
`compose_path()`, so rungs 1/2/3 are on real function bytes; rung-4 chosen
bytes are written by that function's `memmove` only. A logged-in client and
a no-chroot server are required, RCE is not demonstrated by the advisory,
and the default `/srv/ftp` home's 9-byte reach remains UNKNOWN.

Accelppp2Shell was handed off from frontier on 2026-11-21 ~02:57Z (tape #514,
commit `ec06331`) and admitted by the operator ~03:1xZ under standing
approval #6. The two-pane window (27, inner socket), seed wall, brief and
status file were already live; the charter, `docs/task.md`, README and this
lane index are now updated. Wake trigger units and the presentation entry
are owed from the person's full-flag sync (`docs/runtime-pin.md`), never a
bare `mishe sync`. The harness compiles the verbatim pinned upstream
`unpack_msg()`, so rungs 1/2/3 are on real function bytes; rung-4 chosen
bytes land in an adjacent harness heap object only. The advisory's `AT:P`
verbose-logging gate and client-ip-range condition stay in every impact
claim; no live daemon, real L2TP AVP path or RCE was demonstrated.

Indiserver2Shell was handed off from frontier on 2026-11-21 ~03:14Z (tape
#525, commits `45f384f` and `094374d`) and admitted by the operator ~03:18Z
under standing approval #6. The two-pane window (28, inner socket), seed
wall, brief and status file were already live; the charter, `docs/task.md`,
README and this lane index are now updated. Wake trigger units and the
presentation entry are owed from the person's full-flag sync
(`docs/runtime-pin.md`), never a bare `mishe sync`. The harness compiles the
verbatim pinned upstream `oneXMLchar()` / `parseXMLChunk()`, so rungs 1/2/3
are on real function bytes; rung-4 chosen bytes land in an adjacent harness
stack object only. The advisory claims availability only; no live daemon,
real TCP/7624 path or RCE was demonstrated.

Shairport2Shell was handed off from frontier on 2026-11-21 ~03:36Z (tape
#537, commits `acef490` brief and `fed5fbb` seed status) and admitted by the
operator ~03:4xZ under standing approval #6. The two-pane window (29, inner
socket), seed wall, brief and status file were already live; the charter,
`docs/task.md`, README and this lane index are now updated. Wake trigger
units and the presentation entry are owed from the person's full-flag sync
(`docs/runtime-pin.md`), never a bare `mishe sync`. The harness compiles the
verbatim pinned upstream `rtsp.c:4206-4221`, so rungs 1/2/3 are on real
function bytes; rung-4 chosen bytes land in harness stack storage only. The
advisory claims availability only; no live daemon, RTSP socket, AirPlay-2
auth-bypass observation or RCE was demonstrated.

## Provisioning details

- **Node prebuilts** (`lab/node2shell/provision.sh`): Node v24.22.2
  `48cc0e21…af75`, fixed v24.22.3 `4f2b175a…fcfb`. The fix diff is tracked at
  `lab/repro/node2shell-sourcepins/fix-ae9ab37d62.diff`.
- **Ruby sources** (`lab/ruby2shell/provision.sh`): 3.4.12 `db6c1479…ec90`,
  3.4.13 `6474dff9…9589`, fix patch `391b34b2…847a`, glibc 2.39 `malloc.c`
  `b89f737b…0f72`. Consumer gems are pinned in
  `lab/repro/ruby2shell-stageB-{http.ru,rails-setup.sh}`.
- **PHP sources**: `lab/php2shell/provision.sh` pins all PHP tarballs and the
  fix patch. `build-apache.sh` reconstructs the mod_php DSO recipe that was
  previously only in prose; `build-apache-plain.sh` builds the unsanitized
  `-g -O0` module used by the black-box and GDB Apache replay. The descendant
  session-filename UAF lane (CVE-2026-129481) replays with
  `lab/repro/php2shell-cve129481-fpm.py` against the pinned 8.4.27 FPM ASan
  build; 8.4.28 and a benign-close control are the negatives.
  CVE-2026-129182 (backtrace-global repopulation UAF, 8.5 only) has a bounded
  loopback FPM harness `lab/repro/php2shell-cve129182-fpm.py` with release-ASan
  build support in `lab/php2shell/build-fpm-release.sh`. Wake 45 finished the
  release-ASan FPM replay on 8.5.12 (`--use-malloc`): both vendor diagnostics
  reproduce but `VERDICT=CLEAN_NO_UAF` with zero ASan markers, also with
  `ZEND_ASAN_FORCE_FAST_SHUTDOWN=1`, in ZendMM mode and under `--control`.
  Wake 47 pinned the exact fix: two `if (EG(active))` guards at `zend.c:1509`
  and `:1534`, and a GDB-ordered replay showing request 1's fatal repopulates
  the array before its own `zend_shutdown_executor_values()` UNDEFs the global
  at `zend_execute_API.c:440` with `type=775` (IS_ARRAY); request 2's warning
  then sees `type=IS_UNDEF`, so the dtor is a no-op. The earlier
  `zend_activate()` label for `:440` was wrong. The grade stays UNKNOWN — the
  advisory behaviour was not reproduced on this host — and no 8.5.13 fixed
  release build was started for that lane, so its patch sensitivity is
  untested. The CVE-2026-129538 lane separately uses the pinned 8.5.13-asan
  CGI build (`provision.sh` FIXED3=8.5.13) as its fixed control against
  8.5.12-asan and 8.4.27-asan.
- **Mosquitto**: no published SHA-256 sidecar exists at the vendor path;
  `provision.sh` pins the exact local tarballs with hashes recorded from the
  audited files. cJSON 1.7.17 is pinned by `provision-cjson.sh`.
- **Brotli**: `run.sh` now aborts if the fetched PoC hash differs;
  trigger/stream hashes are recorded in the report.
- **Postgres/Dragonfly**: runners pull by tag but abort on image-digest
  mismatch against the values printed in the reports.
- **FreeRADIUS/FalkorDB**: both are small standalone C harnesses under
  `lab/frontier/<target>/`; `run.sh` rebuilds every variant and the briefs
  pin the source commits and artifact digests. FreeRADIUS vulnerable parent
  is `3f802d74deef`, fix `064567a08f3b`; FalkorDB vulnerable parent is
  `40780e992ecc`, fix `0b11a00b34b2`, which deletes the Bolt/WebSocket
  subsystem, so the lab `FIXED` build is a locally added length guard, not
  an upstream patch. The FreeRADIUS rung-4 claim is harness-only (known key,
  fixed stack layout); FalkorDB does not claim rung 4 at all. Live `radiusd`
  reachability and a live `BOLT_PORT` service remain UNKNOWN.
- **Freerdp**: `lab/freerdp2shell-src/run.sh` clones tag 3.32.0 at
  `d27a4f7c1c63b62a5e60e5d939ad116cfb58ffc1`, builds ASan and plain
  libraries with the pinned feature flags, and checks the source-built PoCs
  plus the real-dispatcher and real-WTS cases; clean-room replay uses
  `FREERDP_WORK=/tmp/fr-wake4-fresh bash lab/freerdp2shell-src/run.sh`.
  The chosen-byte PoCs are sanitizer-free so both OOB writes can be read back;
  raw traces `vuln_real_library_asan.txt`, `wire_parse_asan.txt`,
  `chosen_bytes_real_library.txt`, `dispatch_{asan,chosen,benign}.txt`,
  `dispatch_adpcm{,_asan}.txt`, `realwts_controls.txt`,
  `realwts_subsystem.txt` and `realwts_asan_subsystem.txt` are committed.
  `PocRdpsndChannelDispatch.c` frames a PDU through the real dispatcher;
  wake 6's `PocRdpsndRealWts.c` uses libfreerdp's real WTS reader, real queue
  and shadow `Activated` selection. Controls show the FFmpeg-off server
  format list is PCM-only, so the positive case supplies a server ADPCM
  record through `subsystem->rdpsndFormats`. That rung-4 replay stays
  in-process: no live RDP session or virtual-channel transport. Wake 7 adds a
  separate live reachability check: `freerdp-shadow-cli` (X11-free Sample
  subsystem, plain build) on 127.0.0.1:13890, with the committed
  `python3 lab/freerdp2shell-src/loopback_shadow_probe.py nego` and
  `... tls-auth` driving X.224 / RDP_NEG_REQ over real TCP. Exact CR/CC bytes,
  protocol selection (`0x08`/`0x02`/`0x00`), the TLS handshake and the NLA
  gate log are in `loopback_shadow_probe.txt`. Wake 8 adds
  `python3 lab/freerdp2shell-src/live_mcs_join_probe.py` and the headless
  `sfreerdp` session; full output is `live_session_wrap.txt` /
  `live_session_*.log`. Stock allocator layout was closed in a later pass
  (live chosen-byte overwrite under stock glibc: 7564 OOB bytes at offsets
  8820..16383, first OOB byte client-chosen, glibc `double free or
  corruption (!prev)` on teardown, benign control in bounds); an
  FFmpeg-enabled build stays UNKNOWN.
  Wake 10 committed the one-command replay `bash
  lab/freerdp2shell-src/verify_live.sh` (five pinned patches, plain shadow
  server plus `client/Sample sfreerdp`, real loopback TCP readiness): 17 PASS
  / 0 FAIL warm, 18 PASS / 0 FAIL clean-room, rc 0, recorded in
  `lab/freerdp2shell-src/verify_live_run.txt`. Decisive lines: `WAKE9_COPY
  dst_off=0 cframesize=16384 b0=de blast=de b8820=de b21384=00` followed by
  `double free or corruption (!prev)`; the `FR_BENIGN_ONLY=1` control stays
  in bounds with `b8820=00`. Raw logs under `verify-live-out/` are gitignored;
  regenerate with `FREERDP_VERIFY_WORK=/tmp/fr-verify-clean bash
  lab/freerdp2shell-src/verify_live.sh`. Witness W31 independently re-ran the
  unmodified script from clean HEAD b25d025 in its own clean room with pinned
  digests: 18 PASS / 0 FAIL, RC 0, verdict ESTABLISHED with no corrections
  (#532). The one-command harness uses post-auth credentials, so it does not
  re-assert the no-auth 9.8 case.
- **Xrdp**: `lab/xrdp2shell-real/RUNBOOK.md` pins the exact ASan and plain
  `configure` lines (plain `-g -O1` so the chosen-byte reader can read the
  adjacent chunk), the `cc` link against the real `build-asan/libxrdp/.libs/`
  `libxrdp.a` and `libcommon.a`, and driver digests `a05ba8ac…` /
  `ecfe9f7e…`. `real_drdynvc_driver.c` calls `xrdp_channel_process()` with one
  CHANNEL_FLAG_FIRST|LAST PDU carrying a DYNVC_DATA_FIRST body; its callback
  is the body of `xrdp_mm_drdynvc_data_first()` using real `trans_create` /
  `trans_get_out_s` / `out_uint8a`. `chosen_bytes_real_path.c` plants an
  adjacent canary chunk in the non-ASan build so marker bytes can be read
  back. Raw traces `vuln.txt`, `threshold.txt`, `determinism.txt`,
  `chosen_bytes.txt` and `gate.txt` are gitignored under
  `lab/build/xrdp2shell-live/client/` and regenerated by the runbook commands.
  The 8128-byte cap is a synthetic control, not the real 0.10.6.1 fix; the
  separate multi-chunk OOB read at `xrdp_channel.c:630` is a different bug.
- **Gst**: `bash lab/gst2shell-src/run.sh` checks the extracted harness,
  `bash lab/gst2shell-src/run_live.sh` builds a real GStreamer-typed ASan
  instance against pinned `upstream/channels.c` (SHA-256 `08ae20b3…577b`)
  and drives caps through a faithful copy of `depay.c:140-230`, and
  `bash lab/gst2shell-src/run_real.sh` drives the installed
  `libgstrtp.so` `rtpL16depay` through `gst_pad_set_caps`. Full outputs are
  `live_evidence.txt` and `real_evidence.txt`; upstream bytes and builds are
  gitignored under `lab/gst2shell-src/` and regenerated by the scripts. Both
  harnesses keep benign, fixed and ASan controls; the real-plugin fault is
  count-controlled, not chosen-byte control. The remote path is
  `python3 lab/gst2shell-src/rtsp_server.py` plus `bash lab/gst2shell-src/run_rtsp.sh`;
  `gst-launch-1.0 -v uridecodebin uri=rtsp://127.0.0.1:<port>/ ! fakesink`
  gives the stock auto-plumb case.
  Both endpoints start on loopback; evidence `rtsp_evidence.txt`,
  `rtsp_gdb_1000.txt` and `uridecode_{8,1000}.log` is tracked.
  The family driver `bash lab/gst2shell-src/run_rtsp_family.sh` (digest
  `54e8331e…786e`) with `rtsp_server_codec.py` (digest `1493f137…cb45c`)
  drives all three advisory depays; `family_evidence.txt` and
  `family_{L8,L16,L24}_{8,1000}.log` are tracked. The memcheck lane is pinned
  by `lab/gst2shell-src/vg_L8_1000.log` (SHA-256 `42cde0ec…fed2e`) with the
  write-up in `valgrind_evidence.txt`. The one-command replay
  `bash lab/gst2shell-src/verify_all.sh` (optionally `VERIFY_VALGRIND=1`)
  asserts every claim; `verify_all_run.txt` records 43 PASS / 0 FAIL, rc 0 at
  git HEAD 3b07571. Raw output under `verify-out/` is gitignored; rerun the
  command to regenerate it.
- **Freeswitch**: a standalone, file-only C harness under
  `lab/frontier/freeswitch2shell/`; `run.sh` rebuilds vuln/fixed/asan and
  writes `logs/digests.txt`. Vulnerable parent `fbac12b451a1` and fix
  `d557ca6d29e6da4f10824dc158100906a592b91a` are pinned in the brief. After
  the accounting and exit-code repair the driver prints `ALL CHECKS PASS`
  (rc 0) with pinned sources `ws_overflow.c` `75433b5d…` and `run.sh`
  `637cfa36…`. Its earlier 2928 OOB-write count was double the real extent:
  a zero-byte past-the-buffer read underflowed `trace_copy()` and added 1464
  phantom writes. A separate real-source check lives under
  `lab/freeswitch2shell/live/`: `bash run.sh` compiles the byte-for-byte
  pinned upstream `ws.c`/`ws.h` (sha256 `5a07965f…` / `1990aa2b…`) with only
  Abyss type stand-ins and socket-backed I/O, drives a crafted frame over
  127.0.0.1, and prints pinned digests plus ASan `negative-size-param
  (size=-5)`, a plain-build rc 134 abort, fixed-source `rc=-1009` with
  `wsh->ssl` untouched, and a clamp-only isolation variant; raw output in
  `logs_real_source.txt`. `offsetof(wsh_t, ssl)=131112` is validated against
  the real upstream struct. The advisory's all-FF frame gives ASan
  `negative-size-param (size=-5)`, plain rc 134 and fixed `rc=-1009`.
  `bash lab/freeswitch2shell/live/run_pos.sh` adds the positive-length input
  `7F FF FF FF 00 00 00 00`: `plen=INT_MAX` makes the guard's signed add
  overflow, so the real `ws_raw_read` takes its normal clamped branch and
  copies sender bytes verbatim. The plain build writes
  `0x4142434445464748` into `wsh->ssl` (`ssl_bytes=4847464544434241`,
  `RESULT=PASS`, rc 0); the fixed build returns `rc=-1009` with
  `ssl=(nil)`; ASan reports `heap-buffer-overflow`, `WRITE of size 4096`,
  0 bytes after the 131136-byte region, from `ws_raw_read (ws.c:300)`.
  Driver digest `ed1e11048fc4c1e7ebb07513fd24271e580b3e52a4868183f037c4a747483260`,
  raw output in `logs/pos_{plain,fixed,asan}.txt`. Chosen-pointer control is
  therefore no longer harness-only. `bash lab/freeswitch2shell/live/run_live_gdb.sh`
  then ran a full vulnerable FreeSWITCH in a private netns on 127.0.0.1 with
  `mod_xml_rpc` + `enable-websocket`: a real WebSocket `101` upgrade delivered
  the crafted frame and GDB caught `wsh->ssl=0x4847464544434241` dereferenced
  in `SSL_shutdown+28`; witness #338 changed the 8 chosen bytes and saw the new
  value at the same site. Fixed-source and in-bounds controls survive. The
  sentinel is a value, not code; stock heap layout, external reachability and
  the opt-in config gates stay in the claim. Pinned live digests:
  `live_client.py` `68d1c85c…`, `run_live.sh` `3b807d82…`,
  `run_live_gdb.sh` `0554e2c6…`; raw traces in `logs/live_gdb/`.

## Raw evidence policy

Large `logs/`, `build/`, `deps/`, corpora and site-local state stay ignored.
Each report quotes the exact bytes needed to grade its claims and states the
regeneration command. A witness re-run is identified by its tape event and
its committed harness; absence of a log in Git is never used as evidence of
absence of a result.

## Keeping this document true

The `docs` mind owns this page and the README. The `repo-change` producer
observes every git commit and wakes only `docs`; each wake must read
`signals/repo-change.detail`, fix or delete the stale passage in one scoped
commit, or record `doc-ok` with evidence. A new lane is not complete until its
provisioning, replay and reproducibility entry exist.
