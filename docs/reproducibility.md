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
**confirmed memory corruption** → **demonstrated impact** → (additive, only
where a measured rung-4 primitive leaves a path) **working remote command
execution** — are a depth investigation of how far rung 4, and where attempted
rung 5, can be pushed on each build, not boxes to touch. A negative result, a
harness-only grade, or an UNKNOWN records that boundary and stays in the
report. Rung 5 requires a live plant-started target on loopback, attacker wire
or request input that makes it execute a lab-chosen benign command with an
observed side effect bound to that request, vulnerable / fixed / safe-input
differential controls, exact conditions (pins, flags, auth gate, ASLR,
grooming, debugger involvement, process survival) and an independent witness
replay from a clean checkout that varies the command or an attacker byte. A
pointer fault, a call to a pre-existing benign marker or a debugger-forced
call stays rung-4 mechanics. FreeSWITCH and Iec61850 R5 are witness-ESTABLISHED
(#1118, #1127) under their labeled conditions. Both recipes and controls are
in the addenda below. Full contract:
[docs/rce.md](rce.md). Nothing in this lab contacts a public target or any
external system; provisioning downloads public sources, and all triggers,
listeners, debuggers and test consumers run on `127.0.0.1` or inside local
containers whose host ports bind only to loopback.

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
| PHP2Shell | [report](../reports/php2shell-investigation.md), [status](../reports/php2shell-status.md) | `bash lab/php2shell/provision.sh` | `bash lab/php2shell/build.sh`, `build-fpm.sh`, `build-fpm-release.sh`, `build-apache.sh`, `build-apache-plain.sh`, `build-dom.sh`, `build-dom-fixed-variant.sh` | `lab/repro/php2shell-*.sh`, `*.py`, `*.gdb`; `lab/repro/php2shell-cve129538.py` and `lab/repro/php2shell-cve129538-fcgi.py` replay the adjacent CVE-2026-129538 lane on pinned 8.5.12-asan / 8.5.13-asan / 8.4.27-asan: direct php-cgi `VERDICT CONFIRMED` 7/7, FastCGI long suffix yields `PATH_INFO=".0.1"` on affected and `"/x"` on fixed 3/3, steering leaks `"23456789"` / `"27.0.0.1"` by param order 5/5; gdb observes the OOB NUL byte at `cgi_main.c:1294`, ASan silent by design; evidence `lab/build/evidence/w48-cve129538/{committed,fcgi-committed,fcgi-steered}/verdict.txt`. `python3 lab/repro/php2shell-cve129538-nginx.py` adds a real loopback nginx 1.24 → php-cgi HTTP replay: the standard `fastcgi_split_path_info` mapping is clean on both builds, a naive non-default mapping leaks `6789` / `23456789` on 8.5.12 and stays clean on 8.5.13, verdict `HTTP-REACHABLE OOB READ CONFIRMED` (evidence `lab/build/evidence/w50-nginx/verdict.txt`, gitignored). `bash lab/php2shell/build-dom.sh 8.5.12` builds one dom-enabled 8.5.12 ASan/UBSan CLI with libxml 2.9.14 compat path (the first make may hit a 1500s tool deadline at 524 objects; resume make in the build dir); `bash lab/php2shell/build-dom-fixed-variant.sh` relinks it with the byte-identical 8.5.13 `ext/dom/xml_serializer.c`; `python3 lab/repro/php2shell-cve129501-dom.py <php-vuln> <php-fixed>` replays CVE-2026-129501 with `USE_ZEND_ALLOC=0`: vendor and XMLDocument-only bodies exit rc=1 `ASAN_DOUBLE_FREE` on affected and rc=0 CLEAN on fixed, clean control clean on both, 4-byte prefix double-freed at `dom_xml_ns_prefix_map_destroy (xml_serializer.c:126)`; default ZendMM is silent (no ASan claim there). `python3 lab/repro/php2shell-cve129501-dom-hunk2.py <php-vuln> <php-fixed>` embeds both 8.5.13 hunk-2 regression bodies: affected loses document children and orphans comments with rc=0 and no sanitizer report, fixed matches vendor EXPECT — a DOM-state fault, grade unchanged; tcache escalation is closed negative (owned `"ns"+%u` prefix max 13 bytes, glibc 0x20 bin, versus a >=32-byte PHP `zend_string`). `python3 lab/repro/php2shell-cve129291-fpm.py <php-8.4.27-fpm> <php-8.4.28-fpm>` embeds the 8.5.13 FPM phpt: 8.4.27 FAIL / 8.4.28 PASS, no ASan report, rung 2 fix-sensitive functional fault; single- and dual-TU swaps are preserved negatives. Raw evidence `lab/build/evidence/w51-129501-dom/`, `.../w52-129501-hunk2/` and `.../w52-129291-fpm/` is gitignored |
| Node2Shell | [report](../reports/node2shell-investigation.md) | `bash lab/node2shell/provision.sh` | prebuilt binaries, no local source build | `sh lab/repro/node2shell-stageA.sh 5`; `lab/repro/node2shell-shrinkwalk/run-multi.sh`; `sh lab/repro/node2shell-utf8check/run.sh c480 520` and `... run.sh 61 520` — replayed this wake on pinned v24.22.2: U+0100 (`c4 80`) `:authority` draws `NGHTTP2_PROTOCOL_ERROR`, ASCII `61` control completes with `ALTSVC origin_len=528`; preserved negative, no binary-capable heap-byte channel; `sh lab/repro/node2shell-valnul/run.sh 3` — wake-33 value-side trigger: ALT 1048 → SIGABRT rc=134 `malloc(): invalid next size (unsorted)` (3/3), ALT 1200 and ALT 10 → alive with ALTSVC echo (2/2 each) |
| Apache2Root | [report](../reports/apache2shell-investigation.md) | `lab/src/httpd-2.4.{70,71}.tar.bz2` + `.sha256` sidecars; `nghttp2-1.64.0.tar.xz` SHA-256 `88bb94c9…dd9`; L2 sources `httpd-2.4.66.tar.bz2` SHA-256 `94d7ff2b42acbb828e870ba29e4cbad48e558a79c623ad3596e4116efcfea25a` and `httpd-2.4.67.tar.bz2` SHA-256 `66cd206637b0d5c446fa7dabe75fe03525da8fb55855876c46288cd88b136aa4`; L3 sources `httpd-2.4.68.tar.bz2` SHA-256 `68c74d4df38c26bed4dfbdb8f3baf1eb532f3872357becc1bba5d136f6b63c06` and `httpd-2.4.69.tar.bz2` SHA-256 `c5e6ebc66e349b87d7fc6916ae7cc2a808ed348003de134cf9e9d89d3e2cc73d` | `lab/frontier/apache2root/build.sh`; `bash lab/apache2shell/build-l2.sh` builds the L2 ASan/UBSan pair; `bash lab/apache2shell/build-l3.sh` builds the L3 ASan/UBSan pair | `oracle.sh`, `race.sh`, `lab/apache2shell/{sweep,gdb-inspect,drive.py,alphabet-probe.py,huffman-probe.py}`; the Huffman probe now self-checks its wire bytes and was repaired and re-run at 19:11Z (the older Huffman rows were literal restatements); `python3 lab/apache2shell/pushdiary-lane.py` — adjacent lane L1 (`H2PushDiarySize 0` + debug logging): 2.4.70 handshake fails, server rc=1, ASan `SEGV on unknown address 0x00000000000c` in `h2_session_create` and UBSan `member access within null pointer of type 'struct h2_push_diary'`; 2.4.71 rc=0 with no sanitizer report; `python3 lab/apache2shell/l2-lane.py` — adjacent lane L2 (CVE-2026-23918 early-reset double purge): pristine 2.4.66 800 sent / 18 responses with child aborts or SEGVs, 2.4.67 control 800/234 and 800/248 with no assertion, abort or SEGV; both graded rung 2 only; `ASAN_OPTIONS='detect_leaks=0:handle_segv=1:allow_user_segv_handler=0:abort_on_error=0:halt_on_error=1' python3 lab/apache2shell/l3-lane.py 10 8 20` — adjacent lane L3 (CVE-2026-57941 shared-bbtmp re-entrancy): pristine 2.4.68 child SEGVs and forced-ASan wild-jump PC in `h2_c1_read (h2_c1_io.c:502)`, 2.4.69 clean in every variant; `L3_BODY_BYTE=5a L3_VERSIONS=2.4.68` before `python3` selects the body-canary leg: 12 forced-ASan runs per byte give wild-jump PCs in 8/12 for `0x42` and 6/12 for `0x5a`, PC low 12 bits from `{0x048, 0x228, 0x2c8, 0x7c8, 0x868}`, no body-byte pattern in any PC and input-filter `in_func` low 12 bits `0xa86` stable across 744 calls; L3 closed at rung 3, jump target not attacker-chosen, no reopen condition |
| Mosquitto2Shell | [report](../reports/frontier-mosquitto2shell.md), [status](../reports/mosquitto2shell-status.md) | `bash lab/frontier/mosquitto2shell/provision.sh`, `bash …/provision-cjson.sh` | `build.sh`, `build-glibc.sh` | `run.sh`, `placement.sh`, `tcache_probe.py`, `pong_leak_probe.py` |
| Brotli2Shell | [report](../reports/frontier-brotli2shell.md) | `bash lab/frontier/brotli2shell/run.sh` fetches `poc.py` and verifies its SHA-256 | same script builds v1.2.0/v1.2.1/instrumented | same script writes `logs/` and prints digests |
| Postgres2Shell | [report](../reports/frontier-postgres2shell.md) | image digests pinned in `run.sh` | container images by digest | `./run.sh 17.11` and `./run.sh 17.12`; `trigger-vg.sql` for Valgrind; chunk-placement negative (2026-11-21): `docker cp` `trigger-marker.sql` / `gdb-marker.cmd` / `marker-probe.sh` into `pg2shell-gdb`, then `docker exec pg2shell-gdb bash /tmp/marker-probe.sh` (exact block in the report); gitignored `lab/frontier/postgres2shell/logs/marker-17.11-{gdb,psql}.log` regenerate with that script |
| Dragonfly2Shell | [report](../reports/frontier-dragonfly2shell.md) | image digests pinned in `run.sh` | container images by digest | `./run.sh v1.40.1`, `./run.sh v1.40.2`; witness files in `lab/witness/dragonfly2shell/` |
| FreeRADIUS2Shell | [report](../reports/frontier-freeradius2shell.md), [status](../reports/freeradius2shell-status.md) | source at vulnerable parent `3f802d74deef`, fix `064567a08f3b`; artifact digests in report | `cd lab/frontier/freeradius2shell && bash run.sh` builds vulnerable/fixed/canary/asan | same script prints `ALL CHECKS PASS`, writes `logs/` and `logs/digests.txt` |
| Falkordb2Shell | [report](../reports/frontier-falkordb2shell.md), [status](../reports/falkordb2shell-status.md) | source at vulnerable parent `40780e992ecc`, fix `0b11a00b34b2` (removes Bolt/WebSocket; lab `FIXED` is a local length guard) | `cd lab/frontier/falkordb2shell && bash run.sh` builds vuln/fixed/asan | same script prints `ALL CHECKS PASS`: `payload_len=4144`, 525 OOB write operations, canary `K:K`, ASan heap-buffer-overflow (READ of size 8 at the `^=` load) |
| Freeswitch2Shell | [report](../reports/frontier-freeswitch2shell.md), [status](../reports/freeswitch2shell-status.md) | source at vulnerable parent `fbac12b451a1`, fix `d557ca6d29e6da4f10824dc158100906a592b91a`; both `mod_xml_rpc` and `enable-websocket` off by default | `cd lab/frontier/freeswitch2shell && bash run.sh` builds vuln/fixed/asan; `bash lab/freeswitch2shell/live/run.sh`, `bash lab/freeswitch2shell/live/run_pos.sh` and `bash lab/freeswitch2shell/live/run_live_gdb.sh` build the unmodified source over loopback | repaired driver prints `ALL CHECKS PASS` (rc 0) with pinned sources `ws_overflow.c` `75433b5d…` / `run.sh` `637cfa36…`: ASan `WRITE of size 132146` in `ws_raw_read`, 1464 OOB writes from 65536 to 66999, chosen 8 bytes at `offsetof(wsh_t, ssl)=131112` with `marker_called=1` and `rc=42`, fixed `rc=-1009`, 5/5 identical. Real-source `run.sh` (`FF FF FF FF`): ASan `negative-size-param (size=-5)`, plain rc 134, fixed `rc=-1009` with `wsh->ssl` untouched, offset 131112 validated. Real-source `run_pos.sh` (`7F FF FF FF 00 00 00 00`, `plen=INT_MAX`): plain `wsh->ssl=0x4142434445464748`, `ssl_bytes=4847464544434241`, `RESULT=PASS` rc 0; fixed `rc=-1009`, `ssl=(nil)`; ASan `WRITE of size 4096` at the end of a 131136-byte region from `ws_raw_read (ws.c:300)`. A full vulnerable FreeSWITCH then ran in a private netns on 127.0.0.1 with a real WebSocket `101` upgrade; GDB caught the chosen `wsh->ssl` dereference in `SSL_shutdown`, witness-replayed (#338) with changed bytes at the same site. Stock heap layout and external reachability remain UNKNOWN. |
| Freerdp2Shell | [report](../reports/frontier-freerdp2shell.md), [status](../reports/freerdp2shell-status.md) | source at vulnerable parent `8ec6d3923b`, fix `bf217a5` (3.32.1, `/ 4` division guard); digests `d0a31487…` / `c5186500…`; real-library source tag 3.32.0 at `d27a4f7c1c63b62a5e60e5d939ad116cfb58ffc1` | `cd lab/frontier/freerdp2shell && bash run.sh` builds the extracted harness; `bash lab/freerdp2shell-src/run.sh` builds source-built ASan and plain libraries; `python3 lab/freerdp2shell-src/loopback_shadow_probe.py nego|tls-auth` drives a real loopback shadow server; `python3 lab/freerdp2shell-src/live_mcs_join_probe.py` and a headless `sfreerdp` replay the live session; `bash lab/freerdp2shell-src/verify_live.sh` replays the whole live stock-allocator claim in one command (17 PASS warm / 18 PASS clean-room) | extracted harness prints `ALL CHECKS PASS` (rc 0) twice; the real library prints `ALL REAL-LIBRARY CHECKS PASS` (rc 0): ASan `WRITE of size 16384` 0 bytes after an 8820-byte region in `rdpsnd_server_send_samples`, chosen `de`/`ad` at OOB offsets 8820/21384 through the real `SNDC_FORMATS` parser, fixed-guard control rc 3 with no wrap. Wake 7: a real 3.32.0 `freerdp-shadow-cli` on 127.0.0.1:13890 answered X.224 / RDP_NEG_REQ over real TCP (`0x08` NLA, `0x02` TLS, `0x00` RDP) and the default NLA gate stopped a TLS-authenticated client at `CONNECTION_STATE_NEGO` when CredSSP was withheld; a standard-RDP local-peer offer advanced without credentials. Wake 8: MCS CONNECT / ERECT DOMAIN / ATTACH USER / three CHANNEL JOIN confirms, `CONNECTION_STATE_ACTIVE`, `SNDC_FORMATS` over the wire and the live server's `realloc failed!` / `SelectFormat failed with 12`; the live ASan server then reports `WRITE of size 16384` 0 bytes after an 8820-byte region with client-chosen `0xDE` at offset 8820 (`live_session_wrap.txt`). No-auth server, subsystem-supplied ADPCM table, ASan build and synthetic playback are explicit conditions; witness W31 independently accepted the one-command replay (#532, 18 PASS / 0 FAIL from clean HEAD b25d025, ESTABLISHED, no corrections; the harness uses post-auth credentials). Wake 12 measured the live stock glibc layout in three loopback sessions: pointer-bearing heap data lies inside the chosen-byte write (`heap_layout_stock.txt`). Wake 13 identified that object as the wLog for `com.freerdp.channels.rdpsnd.server` and, with a configured `WLOG_FILTER` and a scratch log call after the real copy, observed `mov (%rax,%r15,8)` dereferencing eight chosen `0x41` bytes (`rax=0x4141414141414141`) in the live stock build (`pointer_control_stock.txt`); the trigger and playback bytes are lab-supplied, no grooming at that wake, one object only. Wake 16 closed the FFmpeg gate: stock `WITH_FFMPEG=ON` rejects both ADPCM tags (NEGATIVE), while `-DWITH_DSP_EXPERIMENTAL` adds tag 2 with its own wrap branch (`out_frames=0xfffffffffffffffc`, ASan `WRITE of size 16384`) through `PocAdpcmTag2.c` in-process on real library bytes (`ffmpeg_adpcm_tag2.txt`); a stock wrap-capable format stays UNKNOWN. Wake 17 closed the real-audio-source question at source level in pinned 3.32.0: the copied bytes and copy stride come from the server's platform audio capture, not the client, so remote byte choice is not established in a stock deployment (deployment-specific influence stays UNKNOWN). Wake 18 observed client-controlled grooming in the live stock build: extra PCM format records grow `client_formats` by 32 bytes each and shift the wLog `Names` field (`grooming_format_count_stock.txt`), with a controlled dereference at the shifted offset and an out-of-write negative; raw logs are gitignored under `verify-live-out/wake18/`, and the client controls the offset, not the bytes. |
| Xrdp2Shell | [brief](../reports/frontier-xrdp2shell.md), [status](../reports/xrdp2shell-status.md) | xrdp 0.10.6 raw source (digest `d743c53f…`) and fixed 0.10.6.1 (`4b6c64e8…`), fix `43dc9c3b…`; harness digests `46735a43…` / `2da4d3ea…`; real-path drivers `a05ba8ac…` (`real_drdynvc_driver.c`) / `ecfe9f7e…` (`chosen_bytes_real_path.c`) | `cd lab/frontier/xrdp2shell && bash run.sh` builds the extracted harness; `lab/xrdp2shell-real/RUNBOOK.md` pins both exact `configure` lines and the `cc` links against the real ASan `build-asan/libxrdp/.libs/libxrdp.a` + `libcommon.a`; `bash lab/xrdp2shell-real/verify_cleanroom.sh` rebuilds both library trees and all three drivers from scratch and writes `cleanroom-replay.txt` | replayed ~20:25Z: `ALL CHECKS PASS`, rc 0 — rung 1 `oob_writes=11836 first_oob=8192 last_oob=20027`, chosen `ab`/`cd` at OOB offsets 8228/12028, ASan `WRITE of size 20000` 0 bytes after an 8192-byte region, rung 4 `de`/`ad` at offsets 8228/12024, fixed and benign controls `oob_writes=0`, 5/5 identical. Real compiled-code replay (2026-11-21): ASan `WRITE of size 20000` in `memcpy` 0 bytes after the 8192-byte `trans_create` region via `xrdp_channel_process()` → real `drdynvc_process_data_first()`; threshold 8164 clean / 8165 OOB, 5/5 identical; non-ASan reader `CANARY delta=8208 k1=84 k2=484`, `CHOSEN_BYTES m1=PASS m2=PASS` with `DEADBEEF-CR`/`C0FFEE00-CR` read back; gate 20000/1000 and 20000/19000 clean, 1600/1590 reject. Wire-format driver `lab/xrdp2shell-real/wire_drdynvc_driver.c` parses a TPKT/X.224/MCS SendDataRequest/channel/DYNVC_DATA_FIRST PDU through the real `xrdp_rdp_recv()`: 8191-byte payload → ASan `WRITE of size 8191` 0 bytes after the 8192-byte region, 8164 clean, 8200 also faults; the 20000-byte harness size is rejected by the MCS 16K userData limit (8165–~16375 bytes reachable in one PDU). Raw traces `vuln/threshold/determinism/chosen_bytes/gate.txt` are gitignored under `lab/build/xrdp2shell-live/client/` and regenerated by the runbook commands; the 8128-byte cap is a control, not the real fix. No full RDP session, chansrv-negotiated dynamic channel, socket-level PDU trace or live-session allocator layout; loopback COTP reply only; post-auth gate intrinsic; witness W33 (#548) ESTABLISHED both drivers as claimed; the clean-room replay then gave 15/15 assertions passing with fresh ASan and plain libraries and all three drivers from unchanged digests (`cleanroom-replay.txt`), leaving the in-process boundary unchanged. |
| Gst2Shell | [brief](../reports/frontier-gst2shell.md), [status](../reports/gst2shell-status.md) | source at vulnerable parent `0b70c356345335dacc0acdc45d07a8a33bdf5eab`, fix `80c184b4c5ee8ba28b2540ba58f40b8d44b61622`; harness digests `3d2b8e06…` / `7dde5da7…`; family drivers `rtsp_server_codec.py` `1493f137…cb45c` / `run_rtsp_family.sh` `54e8331e…786e` | `cd lab/frontier/gst2shell && bash run.sh` builds the extracted vulnerable/fixed/ASan variants; `bash lab/gst2shell-src/run_live.sh` and `bash lab/gst2shell-src/run_real.sh` drive the live GObject and shipping-plugin cases; `bash lab/gst2shell-src/run_sdp.sh` drives SDP text through GStreamer's parser (digest `6ba2e707…c4f`); `python3 lab/gst2shell-src/rtsp_server.py` plus `bash lab/gst2shell-src/run_rtsp.sh` drive the remote loopback path; `bash lab/gst2shell-src/run_rtsp_family.sh` covers L8/L16/L24; `bash lab/gst2shell-src/verify_all.sh` replays all drivers (add `VERIFY_VALGRIND=1` for memcheck) | replayed 20:47Z from clean committed sources: `ALL CHECKS PASS`, rc 0 — rung 1 `oob_writes=936 first_oob=256 last_oob=3999` with 3744 counted OOB bytes, caps length controls which offsets are clobbered, ASan `WRITE of size 4` 0 bytes after a 256-byte region in `vuln_create_default`, fixed control `oob_writes=0`, 5/5 identical. Wake 6 corrected the extracted harness's `NONE=0` model: pinned `audio-channels.h:101` defines `NONE=-3`, so index 73 turns NULL `order` into `0x00000000fffffffd`; the live ASan harness faults at `order->pos` and the shipping 1.24.2 `rtpL16depay` faults rc 139 for `encoding-params` 86/87/100/1000. A 2026-11-21 pass symbolicated the N=1000 fault by gdb debuginfod to `srcpad->g_class` of a heap-adjacent GstPad (`lab/gst2shell-src/gdb_symbolicated_1000.txt`) and reproduced the same fault from SDP text at N=86/1000 with the RTP structure name modelled in the harness; the `sdpdemux` file path is a bounded negative (tracked `sdp_evidence.txt`). A loopback RTSP server then drove a real `rtspsrc ! rtpL16depay ! fakesink` victim with no auth challenge (`rtsp_server.py` `f812d844…e0668`, `run_rtsp.sh` `9841c920…2a5d`): N=1000 rc 139 four times against clean N=8, gdb locating the corruption in GLib's `block_source` (`rtsp_gdb_1000.txt`); stock `uridecodebin` auto-selects the depay and aborts rc 134 with `malloc(): invalid size` (`uridecode_{8,1000}.log`). Family run: N=1000 faults L8/L24 with heap aborts (rc 134) and L16 with SIGSEGV/segtrap (rc 124) against clean N=8; memcheck reports three 4-byte invalid stores 0/4/12 bytes past a 1,016-byte GObject block (`ERROR SUMMARY: 592 errors from 6 contexts`). A witness replay contradicted the earlier 43/43 assertion on its host (42 PASS / 1 FAIL, only the L8 fault leg) and `checkfault` was repaired to accept the observed fault family or a nonzero per-leg rc. From repaired HEAD 31e7243 the author's `VERIFY_VALGRIND=1` replay is 43 PASS / 0 FAIL rc 0 (`verify_all_clean_head_run.txt`), and a docs-side run without that flag is 39 PASS / 0 FAIL rc 0; witness W33 (#552) re-ran the repaired harness from clean HEAD 2a78ee6: 43 PASS / 0 FAIL rc 0, REPAIR ESTABLISHED and the 42/1 contradiction closed. Chosen bytes, arbitrary pointer control, code execution and public-service SDP reach stay NOT DEMONSTRATED or UNKNOWN. |
| Babelfish2Shell | [brief](../reports/frontier-babelfish2shell.md), [status](../reports/babelfish2shell-status.md) | raw sources at tags `BABEL_4_8_0` / `BABEL_4_10_0`, fix `ab820bddaffa540af82f2f689c3e535f82f14d89`, harness digests in `PROVENANCE.md` | `cd lab/frontier/babelfish2shell && bash run.sh` builds the extracted vulnerable/fixed/ASan variants | replayed 2026-11-20 from committed sources: `ALL CHECKS PASS`, rc 0 — rung 1 `token=0x02 length=4096 si_capacity=1024 oob_writes=3072 first_oob=1024 last_oob=4095`, rung 2 length 1050/1150/2100 clobbers neither/first/both stamps, rung 3 ASan `WRITE of size 4096` 0 bytes after a 1024-byte region in `wire_getbytes`, rung 4 `de ad be ef ca fe ba be` at offset 1100 and `41 42 43 44` at 2000, fixed control `rc=0 oob_writes=0`, 5/5 `sha256=e216eeec…`. Harness only: real palloc layout, live TDS process, pointer control and execution UNKNOWN. |
| Bzfs2Shell | [brief](../reports/frontier-bzfs2shell.md), [status](../reports/bzfs2shell-status.md) | raw sources at tags `v2.4.30` / `v2.4.32`, fix `8e501d685aef549090b363260979a4eb93484ea1` (OSV also `f11f05485d74…`); harness digests `1a16963f…` / `f2686d5b…` in `PROVENANCE.md` | `cd lab/frontier/bzfs2shell && bash run.sh out` builds the extracted vulnerable/fixed/ASan variants | replayed at handoff 2026-11-21 from committed sources: `ALL CHECKS PASS`, rc 0 — rung 1 `tcplen=-1024` with chosen tail at `tcpmsg+1024`, rung 2 destination 936 bytes before the object and next length 1028, rung 3 ASan `heap-buffer-overflow` `WRITE of size 64`, rung 4 `DEADBEEFCAFEBABE` / `0123456789ABCDEF` read back byte-exact from chosen preceding harness members, fixed controls reject at the first bound and are ASan-clean, 5/5 identical (`sha256=cea3b92e…`). Harness-only chosen-value control; no live bzfs, real layout or execution. Witness #761 (2026-11-21) replayed 20 PASS / 0 FAIL with a byte-equal five-run digest and ESTABLISHED rungs 1/2/3 and rung 4 at the labeled INSTRUMENTED scope; its source-citation nit (six lines too high) is corrected in brief/status/PROVENANCE, harness bytes unchanged. |
| Kamailio2Shell | [brief](../reports/frontier-kamailio2shell.md), [status](../reports/kamailio2shell-status.md) | raw `notify.c` / `save.c` at tags `6.1.4` and `6.1.5`, fix commit `21261436492f0014930e804e20586e3833bb91b9`; source hashes and URLs in `lab/frontier/kamailio2shell/PROVENANCE.md` | `cd lab/frontier/kamailio2shell && bash run.sh <outdir>` builds the extracted alias-branch variants; gcc 13.3.0, `-O0 -g` | operator replay at admission: `ALL CHECKS PASS rc 0`, 16 PASS lines, deterministic trace `sha256=94ef79641b081f850cb04f95d0f0945e7de7f84f9505462f23bf8aa054fa1cb8`; rung 1 `len=80 oob=75`, rung 3 ASan `WRITE of size 80` in `memcpy` ← `parse_alias`, rung 4 marker through instrumented pointer only, pinned 6.1.5 rejects before the copy. No live Kamailio, real frame layout or return-address control |
| Iperf2Shell | [brief](../reports/frontier-iperf2shell.md), [status](../reports/iperf2shell-status.md) | raw `iperf_auth.c` at tags `3.20` / `3.21` / `3.22`, fix commit `d08588aceee48fa45832cae5e32616abb33cb0fc`; source hashes and URLs in `lab/frontier/iperf2shell/PROVENANCE.md` | `cd lab/frontier/iperf2shell && bash run.sh <outdir>` compiles the real pinned upstream `iperf_auth.c` at 3.21/3.22; gcc 13.3.0, OpenSSL 3.0.13, `-O0 -g` | operator replay at admission: `ALL CHECKS PASS rc 0`, 17 PASS lines (frontier corrected the count at 02:24Z; re-verified from committed HEAD), trace `sha256=bd3efc4cb4720e7fe5cc2e83e79cc7e89010f75a7e93579360a215eb5f029caf`; decoded len 336 into 256-byte buffer, ASan `WRITE of size 336` from `BIO_read` ← `decrypt_rsa_message`, plain build aborts at `free(): invalid size`, chosen bytes only in the write buffer, 3.22 rejects before `BIO_read`. No live server, stock heap layout or useful-pointer control |
| Uftpd2Shell | [brief](../reports/frontier-uftpd2shell.md), [status](../reports/uftpd2shell-status.md) | raw `src/common.c` at tags `v2.15` / `v2.16`, fix commit `f5552a8c6a5f14691f51bef1f3373747259d7ac8` (11-line bound); source hashes and URLs in `lab/frontier/uftpd2shell/PROVENANCE.md` | `cd lab/frontier/uftpd2shell && bash run.sh <outdir>` extracts the verbatim pinned upstream `compose_path()` at replay time; gcc 13.3.0, `-O0 -g` | operator replay at admission: `ALL CHECKS PASS rc 0`, 23 PASS lines, trace `sha256=ad11094aa03e898df6c3b00a83b6b8ba8a9b049e0a0a18bf5fd952475d09d33b`; rung 1 `path_len=4095 home_len=128 expected_oob=128`, rung 2 `*** stack smashing detected ***`, rung 3 ASan `WRITE of size 4096` into `dir` `[256, 4352)` at `common.c.v2.15:61`, rung 4 chosen bytes from the upstream `memmove` only; pinned 2.16 leaves `returned=null`. No live uftpd, stock frame layout or useful pointer. |
| Accelppp2Shell | [brief](../reports/frontier-accelppp2shell.md), [status](../reports/accelppp2shell-status.md) | raw `log_tcp.c` / `log.c` at tags `1.14.0` / `1.15.0`, fix commit `58e399400c4ef4b71472ab7c2c71c54a677a05a8` (PR #374); source hashes and URLs in `lab/frontier/accelppp2shell/PROVENANCE.md` | `cd lab/frontier/accelppp2shell && bash run.sh <outdir>` extracts verbatim pinned upstream `unpack_msg()` at replay time, padding leading lines so upstream line numbers survive; gcc 13.3.0, `-O0 -g` | operator replay at admission: `ALL CHECKS PASS rc 0`, 19 PASS lines, trace `sha256=3499f52eef8814e5cc73c5e38f990ca0de3f4f0fc243640452c7806dc9c2b18a`; rung 1 `pos=4254 expected_oob=94`, rung 2 chosen `0x1122334455667788` byte-exact in the adjacent harness object, rung 3 ASan `WRITE of size 64` at pinned `log_tcp.c.1.14.0:63`, pinned 1.15.0 bounded with a clean neighbour. No live daemon, real AVP path or useful-pointer control. |
| Indiserver2Shell | [brief](../reports/frontier-indiserver2shell.md), [status](../reports/indiserver2shell-status.md) | raw `lilxml.cpp` / `lilxml.h` / `MsgQueue.cpp` at fix parent `3220880` and fix `96bbd7f564bbb128a129019e44eadd40dd49cff9`; hashes and URLs in `lab/frontier/indiserver2shell/PROVENANCE.md` | `cd lab/frontier/indiserver2shell && bash run.sh <outdir>` compiles the byte-exact pinned upstream `oneXMLchar()` / `parseXMLChunk()`; gcc 13.3.0, `-O0 -g` | operator replay at admission: `ALL CHECKS PASS rc 0`, 19 PASS lines, trace `sha256=2c446e0f1b1beecee5aa437d5a15818ad0c951d72fbcdb2cb545a656925ca85c`; rung 1 1237 bytes into `err[1024]` (`oob=213`), rung 3 ASan `WRITE of size 1237` at pinned `lilxml.cpp:1281`, rung 4 `INDI2SHELL` at offsets 0/64, fixed `96bbd7f` clean. No live daemon, real socket or RCE. |
| Shairport2Shell | [brief](../reports/frontier-shairport2shell.md), [status](../reports/shairport2shell-status.md) | raw pinned `rtsp.c` at fix parent `a50f18469143b9dbe599b8333d228a586dc29e67` and fix `c1c41c4ec9937eb7d2f8819dadd5bc45f65ab3f4` (development merge `74d59d8f`, master backport `a5d8f46a`); hashes and URLs in `lab/frontier/shairport2shell/PROVENANCE.md` | `cd lab/frontier/shairport2shell && bash run.sh <outdir>` compiles the byte-exact pinned upstream `rtsp.c:4206-4221`; gcc 13.3.0, `-O0 -g` | operator replay at admission: `ALL CHECKS PASS rc 0`, 21 PASS lines, trace `sha256=b87176f5891ef547eef69a11176fd3e0a3a3c367fd19fdf80d30fa9b733e9c86`; rung 1 8193 bytes into `obf[4096]`, rung 3 ASan `WRITE of size 3` at pinned `rtsp.c:4215`, rung 4 `INDI2SHELL` at offsets 0/64; fixed `c1c41c4` clean. No live daemon, socket or auth-bypass observation; advisory claims availability only. |
| Asterisk2Shell | [brief](../reports/frontier-asterisk2shell.md), [status](../reports/asterisk2shell-status.md) | raw pinned `ootrace.c` at fix parent `661d6a2fc5cc7744ab9d849ed3c73ae5066386df` (byte-identical to release `23.4.0`) and fix `2d7b8c8dc13d9ead8b6f36cc38b6dd91cd4abd3a`, plus `ootrace.h` / `ootypes.h`; hashes and URLs in `lab/frontier/asterisk2shell/PROVENANCE.md` | `cd lab/frontier/asterisk2shell && bash run.sh <outdir>` compiles the byte-exact pinned upstream `ootrace.c:35-53`; gcc 13.3.0, `-O0 -g` | operator replay at admission: `ALL CHECKS PASS rc 0`, 24 PASS lines, trace `sha256=51b5ff1b82684092340d5bd93105efed76e453681e552eb0bb84103eb74feee0`; rung 1 2433 bytes into `logMessage[2048]`, rung 3 ASan `WRITE of size 2433` at pinned `ootrace.c:50`, rung 4 `AST2SHELL` at offsets 0/64, fixed `ast_vasprintf` build clean. GHSA/CVE impact conflict preserved; conservative ceiling is a crash. |
| Netatalk2Shell | [brief](../reports/frontier-netatalk2shell.md), [status](../reports/netatalk2shell-status.md) | raw `etc/afpd/directory.c` at release tags 4.4.2 (`d2ef3e298772aa96eaf83d3db147a5df919093ff`, sha256 `82d5f3fd…`, affected) and 4.4.3 (`79b13d9e7c77d3ab0e8b36c639fd3eb05ec06f04`, sha256 `bd23b576…`, fixed), fix `33dbda708cd38ee4ffa568cc5dde1fda4f900dfe`; URLs and diffs in `lab/frontier/netatalk2shell/PROVENANCE.md` | `bash lab/frontier/netatalk2shell/run.sh <outdir>` compiles the byte-exact pinned upstream `directory.c:147-203`; gcc 13.3.0, `-O0 -g` | operator replay ~05:05Z from a clean `git archive HEAD` extraction of `c37e96d`: `ALL CHECKS PASS rc 0`, 24 PASS lines, trace `sha256=c1bba7fb17b2a2b0cf6de7c76725974f005192648287245f5ba3b8aac08339d0`; rung 1 256 bytes into `path[1025]`, rung 2 first saved-return-slot byte changed, rung 3 ASan `WRITE of size 256` at pinned `directory.c:181`, rung 4 `NET2SHEL` at offsets 0/64 and return slot 56, fixed build clean. No live afpd, AFP session or execution; RCE stays a claim. |
| Iondtn2Shell | [brief](../reports/frontier-iondtn2shell.md), [status](../reports/iondtn2shell-status.md) | raw pinned `nm/mgr/nm_mgr_print.c` at release tags `ion-open-source-4.2.0` (`568df887cb9f18aa8ec013b1a566d83215e499ae`, sha256 `31b9673c…`, affected) and `ion-open-source-4.2.1-a.2` (`54d4b1f0b647e0cb7dfc558651777a042acf5e38`, sha256 `c2abf2d0…`, fixed), fix `4b158b64211ad399a00be4215dd81de2f4767d1e`; hashes and URLs in `lab/frontier/iondtn2shell/PROVENANCE.md` | `bash lab/frontier/iondtn2shell/run.sh <outdir>` compiles the byte-exact pinned upstream `nm_mgr_print.c:548-563` / `543-588`; gcc 13.3.0, `-O0 -g` | operator replay ~05:26Z from a clean `git archive HEAD` extraction of `d4267283` into two separate absolute output directories: `ALL CHECKS PASSED rc 0` both, byte-identical trace `sha256=e9bc1ffffb7ba2bc39b5c3c26cf29a4c1cf0f8f96160a92cc979326f29d38f71`; rung 1 1458 bytes into a 1024-byte `STAKE` region, rung 3 ASan `WRITE of size 81` at pinned line 557, rung 4 `ION2SHL!` at chosen offsets 1024/1088/1152/1280/1408, fixed build clean. GHSA "No known CVE" vs VulnCheck CVE assignment conflict preserved; availability-only ceiling. |
| Opensips2Shell | [brief](../reports/frontier-opensips2shell.md), [status](../reports/opensips2shell-status.md) | raw pinned `modules/xmpp/xmpp.h`, `xmpp.c`, `xmpp_server.c` at tags `4.0.1` (affected, sha256 `1533677b…` / `1f9bef40…` / `750abf2f…`) and `4.0.2` (fixed, `10c85611…` / `ce3d681a…` / `d9fe0f6b…`) plus `config.h` (`90206e1f…`), fix `ec24165bc25fa462e08cdb33ee8071f58e166d36`; URLs and hashes in `lab/frontier/opensips2shell/PROVENANCE.md` | `bash lab/frontier/opensips2shell/run.sh <outdir>` extracts the verbatim pinned `xmpp.h:73-82` / `xmpp.c:280-285` (4.0.1) and fixed helper (4.0.2) under `#line` directives; gcc 13.3.0, `-O0 -g` | operator replay ~06:19Z from a clean `git archive HEAD` extraction of `7674a58` into two separate absolute output directories: 26 PASS / 0 FAIL, `ALL CHECKS PASSED rc 0` both times, trace `sha256=a69657bb243b83b850b332a4307996f5705d6b0bd6b3cdefbccba022c0c78b06` byte-identical; rung 1 `written=303 overflow=48` into `buf_from[256]`, rung 3 ASan `stack-buffer-overflow WRITE of size 304` at `xmpp.c:285`, rung 4 16 chosen bytes at `buf_from+256` in the no-canary lab frame only. No daemon, socket, canary/ASLR/NX measurement, pointer control or execution. |
| Unbound2Shell | [brief](../reports/frontier-unbound2shell.md), [status](../reports/unbound2shell-status.md) | raw pinned `validator/val_sigcrypt.c`, `sldns/sbuffer.{c,h}`, `config_file.c`, `worker.c`, `rrdef.h`, `val_secalgo.c` at tags `release-1.26.0` (affected), `release-1.26.1` (fixed) and fix commit `8c2e0fd6cc5b`; hashes and URLs in `lab/frontier/unbound2shell/PROVENANCE.md` | `bash lab/frontier/unbound2shell/run.sh <outdir>` extracts the verbatim pinned `ds_create_dnskey_digest()` (`:293-317`) under `#line` directives and compiles vulnerable, fix-commit and fixed-tag variants with stub collaborators under `NDEBUG`; gcc 13.3.0, `-O0 -g` | operator replay ~06:43Z from two clean `git archive HEAD` (1718991) extractions: 29 PASS / 0 FAIL, `ALL CHECKS PASSED rc 0`, byte-identical trace `sha256=05bf4ace988fc4fdc4d213674e1f30e85c739c170b47c5319cbfc2cd7f24f795`; rung 1 `written=65788 overflow=236`, rung 2 vulnerable `GUARD_REJECTED=0` vs both fixed `GUARD_REJECTED=1 rc=0`, rung 3 ASan `heap-buffer-overflow` `WRITE of size 65533` at pinned `sbuffer.h:436` from `val_sigcrypt.c:311`, rung 4 chosen RDATA bytes read back in the lab frame only. No resolver process, DNSKEY wire bytes, DNSSEC config or execution |
| Janus2Shell | [brief](../reports/frontier-janus2shell.md), [status](../reports/janus2shell-status.md) | raw pinned `src/plugins/janus_recordplay.c` at tags `v1.4.2` (affected, sha256 `c06e9396…`) and `v1.4.3` (fixed, `745c4145…`) plus legacy `v0.16.2` / `v0.16.3`, fix commits `e55e2915…` and `c31cad97…`; hashes and URLs in `lab/frontier/janus2shell/PROVENANCE.md` | `bash lab/frontier/janus2shell/run.sh <outdir>` extracts the verbatim pinned parse blocks (`:669-670`, `:701-714`) under `#line` directives and compiles vulnerable, fixed and ASan variants with stub collaborators; gcc 13.3.0, `-O0 -g` | operator replay ~07:09Z from two clean `git archive HEAD` (dc1a4e1) extractions: 29 PASS / 0 FAIL, `ALL CHECKS PASSED rc 0`, byte-identical trace `sha256=c8568d26b07cac408da640b7e6d8347d1c43db3119274fafbfb73f3e41f9a21f`; rung 1 `overflow=486`, rung 2 fixed guard rejects, rung 3 ASan `WRITE of size 1986` at pinned `:707`, rung 4 chosen bytes and adjacent local in the lab frame plus canary abort. No live Janus or HTTP path; advisory availability-only preserved. |
| Rsyslog2Shell | [brief](../reports/frontier-rsyslog2shell.md), [status](../reports/rsyslog2shell-status.md) | raw pinned `contrib/imhttp/imhttp.c` at tags `v8.2602.0` (affected, sha256 `4e4a9d2c…`) and `v8.2604.0` (fixed, `48f69a6f…`) plus fix `.patch` `acde2ba2…` (`f1935dd2…`); hashes and URLs in `lab/frontier/rsyslog2shell/PROVENANCE.md` | `bash lab/frontier/rsyslog2shell/run.sh <outdir>` extracts the verbatim pinned `auth_s` struct (`:71-77`) and `parse_auth_header()` (`:687-720`) under `#line` directives with the authentic libaprutil decode-length; gcc 13.3.0, `-O0 -g` | operator replay ~07:20Z from two clean `git archive HEAD` (`ba9a240`) extractions: 36 PASS / 0 FAIL, `ALL CHECKS PASSED rc 0`, byte-identical trace `sha256=fc9cd9bb…` |
| ProxySQL2Shell | [brief](../reports/frontier-proxysql2shell.md), [status](../reports/proxysql2shell-status.md) | raw pinned `lib/mysql_data_stream.cpp` / `lib/PgSQL_Data_Stream.cpp` at tags `v3.0.8` (affected) and `v3.0.9` (fixed) plus headers `include/MySQL_Data_Stream.h`, `include/PgSQL_Data_Stream.h`, `include/MySQL_Protocol.h`, `include/proxysql_structs.h` and fix `.patch` `1cb2ecc…`; hashes and URLs in `lab/frontier/proxysql2shell/PROVENANCE.md` | `bash lab/frontier/proxysql2shell/run.sh <outdir>` extracts the four verbatim pinned first-read blocks under `#line` directives (mysql `:643-671`/`:651-689`, pgsql `:504-541`/`:512-560`) with a synthetic in-memory `recv()` collaborator; gcc 13.3.0, `-O0 -g` | operator replay ~07:5xZ from two clean `git archive HEAD` (`3aea985`) extractions: 53 PASS / 0 FAIL, byte-identical raw trace `sha256=936fa128…` |
| Strongswan2Shell | [brief](../reports/frontier-strongswan2shell.md), [status](../reports/strongswan2shell-status.md) | raw pinned `src/libsimaka/simaka_message.c` at `6.0.5` (affected) and `6.0.6` (fixed), enum header `simaka_message.h`, fix `.patch` `aa5aaebc…` and the advisory HTML; hashes and URLs in `lab/frontier/strongswan2shell/PROVENANCE.md` | `bash lab/frontier/strongswan2shell/run.sh` extracts the vulnerable/fixed `parse_attributes()` and `add_attribute()` ranges under `#line` directives with synthetic `chunk_t`, list and chosen-byte collaborators; gcc 13.3.0, `-O0 -g` | operator replay ~08:1xZ from two clean `git archive HEAD` (`97d53ed`) extractions: 54 PASS / 0 FAIL, byte-identical trace `sha256=57cd8943825f35a14f45ce134f3987c489aacbd080c6249a94c9dc808f1f3d6a` |
| Memcached2Shell | [brief](../reports/frontier-memcached2shell.md), [status](../reports/memcached2shell-status.md) | raw pinned `crawler.c` at fix parent `aa352388…` (affected) and fix `7eeac6e9…` / release 1.6.44 target `e44dd0b0…` (fixed), plus `proto_text.c`, `memcached.c`, fix `.patch`, commit/tag/release HTML pins; hashes and URLs in `lab/frontier/memcached2shell/PROVENANCE.md` | `bash lab/frontier/memcached2shell/run.sh` extracts the pinned struct, buffer constant, `crawler_metadump_eval()` and `lru_crawler_write()` ranges under `#line` directives with synthetic `conn`, item, `poll()` and three buffer backends; gcc, `-O0 -g`, ASan and guard variants | operator replay ~08:28Z from two clean `git archive HEAD` (`163433e`) extractions: 8 PASS / 0 FAIL, byte-identical trace `sha256=5d4a05be6cebb89e7fd99e0f6d08731e47537c49d0b8396d6be73e554b51672b` |
| Ipfixcol2Shell | [brief](../reports/frontier-ipfixcol2shell.md) | pinned `Lz4Decoder.cpp` at tags `v2.7.1` / `v2.8.0` (byte-identical, sha256 `3e618628…`, affected) and `v2.9.0` (`46a0fc8b…`, fixed), advisory `GHSA-4575-chq4-crfc` / `CVE-2026-122127` (`4152c637…`), fix `fd5cb168…` and its four-line patch (`2be32ba2…`); URLs and every hash in `lab/frontier/ipfixcol2shell/PROVENANCE.md` | `cd lab/frontier/ipfixcol2shell && ./run.sh` stages the pinned `.cpp` verbatim under `#line` and builds vulnerable/fixed ASan decoders plus instrumented chosen-byte collaborators against the host `liblz4.so.1` 1.9.4; gcc `-O0 -fno-inline -g` | Docs replay 2026-11-21 from a clean `git archive HEAD lab/frontier/ipfixcol2shell` extraction at `a832dcd`: `./run.sh` rc 0, 13 PASS / 0 FAIL, raw trace `sha256=e9c06f530d09912603ed379913699b2f1e63e08ab64b8cfcefdae0b47f3cd89f`, matching the author's `a5f3aed` replay recorded byte-identical in `PROVENANCE.md`; ASan `WRITE of size 65000` `0 bytes after 24-byte region`, allocation pinned `Lz4Decoder.v2.8.0.cpp:184`, write `:145`; fixed build prints `LZ4 Decoder: invalid decompressed size`; chosen `0x5a` at offsets 0/24/28/64999 and `0x41` differential only on the instrumented collaborator — no stock-build chosen-byte claim, no pointer control or execution; rung 4 INSTRUMENTED. `out/`, `build/` and generated `stubs/Lz4Decoder.hpp` are gitignored and regenerated by `./run.sh`. |
| Srs2Shell | [brief](../reports/frontier-srs2shell.md), [status](../reports/srs2shell-status.md) | pinned advisory `GHSA-qr8h-p53p-x564` (no CVE at fetch, `5a0d5189…`), fix `ab03c94b…` (parent `f7968893…`, patch `f2c42ce0…`), vulnerable RTCP source `1a108163…` / fixed `6b95dbe7…` plus eight more hashes; every URL and digest in `lab/frontier/srs2shell/PROVENANCE.md` | `cd lab/frontier/srs2shell && ./run.sh` stages verbatim pinned ranges under `#line` and builds vulnerable/fixed ASan, collaborator and guard variants; gcc `-O0 -g` | Operator admission replay ~09:1xZ at `24db73a`: two clean `git archive 24db73a lab/frontier/srs2shell` extractions, 14 PASS / 0 FAIL at trace `sha256=77b6d5500dea19d3c3a8de713d7a37834a3241a62e6a7239d398661e5fea1965` — pre-nit-fix, superseded. Docs replay 2026-11-21 ~09:35Z from a clean `git archive f858550 lab/frontier/srs2shell` extraction: `./run.sh` rc 0, 15 PASS / 0 FAIL, trace `sha256=1a61cbf41314d16d886d26183fbdd2fe57179c4efcf3e9c9a8f589df6c899662`, byte-identical to `f858550`. The nit fix constructs a real `SrsRtcpTWCC` in twcc mode: ASan `WRITE of size 1596` at pinned `srs_kernel_rtc_rtcp.cpp:841` and a fixed-build rejection (`payload len=1596 exceeds 1500`, rc 0); BYE `length=0` aborts on pinned `srs_kernel_buffer.cpp:244` `require(size)`, ASan `WRITE of size 1596` 0 bytes after 1536-byte region at pinned `:246` via RTCP decode `:95`; chosen `0x5a` and `0x41` at 96 offsets in a 64 KiB zeroed collaborator, benign control clean, guard page faults. Rung 4 INSTRUMENTED; witness nit #725 dispositioned at `3d556c5`, no verdict; no live SRS daemon, WebRTC/ICE/DTLS/SRTP path, stock allocator or pointer control. Generated drivers, binaries and `out/` are gitignored and regenerated by `./run.sh`. |
| 389ds2Shell | [brief](../reports/frontier-389ds2shell.md), [status](../reports/389ds2shell-status.md) | pinned advisory `GHSA-2g8g-f92j-g4gq` / `CVE-2026-11610` (`a03a6156…`), CVE record `1be123890…`, issue #7658 `6163717e…`, fix `f15ffd63…` (parent `e63592d5…`), vulnerable `sasl_io.c` `9cea2e7b…` / fixed `f82aa846…`; every URL and hash in `lab/frontier/389ds2shell/PROVENANCE.md` | `cd lab/frontier/389ds2shell && ./run.sh` verifies the pins, generates two C drivers whose copying/faulting bytes are verbatim from the pinned files under `#line`, then builds vulnerable/fixed ASan and plain variants; gcc `-O1 -g -std=c11 -fsanitize=address` | Operator admission replay ~09:18Z at `9ff285d`: two clean `git archive 9ff285d lab/frontier/389ds2shell` extractions, 14 PASS / 0 FAIL at trace `sha256=04e394a69a8508ab127ab206f713b87e8f590f799eb09d9ab130c63c5428cceb` — pre-nit-fix, superseded. Docs replay 2026-11-21 ~09:35Z from a clean `git archive f858550 lab/frontier/389ds2shell` extraction: `./run.sh` rc 0, 19 PASS / 0 FAIL, trace `sha256=5ac6faaeec38553369518aae643572de70cdfd0d5e9bd2ab2356220a968ba6f6`, byte-identical to `f858550`. `asan_write=WRITE of size 9000`, `asan_frame=pins/sasl_io.c.vuln:456`, `declared=9000`, `chosen=8488`; declared 9000 into a 512-byte caller, 511/512 clean and 513 faults with `WRITE of size 513`, chosen `0x5a` / `0x41` at 8488 offsets past the boundary in a 1 MiB zeroed collaborator, fixed build clean, guard page exits 77. The nit fix frees only heap-owned caller buffers and adds exit-code checks for collab/benign/fixed (0) and guard (77). Rung 4 INSTRUMENTED; witness nit #740 dispositioned at `3d556c5`, no verdict; post-auth `SSF > 0` required, no live `ns-slapd`, SASL library, socket or shipping allocator, and the real caller's `len` is UNKNOWN. Generated drivers, binaries and `out/` are gitignored and regenerated by `./run.sh`. |
| Kermit2Shell | [brief](../reports/frontier-kermit2shell.md), [status](../reports/kermit2shell-status.md) | pinned CVE-2026-129126 record (`6c43f2b7…`), GHSA-c5px-7h4c-gj8p (`96477695…`), fix patch `2f25c8d7…` (commit `37e54720…`), vulnerable `ckcfns.c` v11.0.514 (`6afc5e45…`) / fixed v11.1.515 (`7acdefc4…`) plus header and `ckcmai.c` pins; every URL and hash in `lab/frontier/kermit2shell/PROVENANCE.md` | `cd lab/frontier/kermit2shell && ./run.sh out` — `gen_driver.py` verifies every pin hash, extracts both `putsrv()` bodies verbatim under `#line`, then builds ASan and plain drivers; gcc `-O0 -g -std=c99` | Operator admission replay ~09:56Z from two clean `git archive HEAD lab/frontier/kermit2shell` extractions at `782fb64`: 18 PASS / 0 FAIL both, trace `sha256=f74a088605aba49a48108705fafe151d61d283c04e248836a81f6ca8e4978cc5`, byte-identical between directories, to the working tree, brief and PROVENANCE. Witness #763 ESTABLISHED rungs 1/2/3 and rung 4 at INSTRUMENTED. Expected: ASan `WRITE of size 1` at `pins/ckcfns.c.vuln:461`, `mode=fit emitted=9024 srvcmdlen=9024 oob=0`, `mode=collab_5a emitted=9212 srvcmdlen=9024 oob=188` with `offsets: first_oob=5a at_9025=5a count_5a=128 count_41=0` (readback covers 9024–9151; 9152–9211 inferred), `mode=collab_41` with the `41` mirror, benign `zeros=128`, fixed `decode_rc=-1 first_reject=9024`, guard page exit 139. `out/` and generated drivers are gitignored; regenerate with that command. Admitted under #6; no built `wermit`, live server, packet-length or `xunchar()` limits, and no pointer or control-flow claim. |
| GpfD2Shell | [brief](../reports/frontier-gpfdist2shell.md), [live](../reports/gpfdist2shell-live.md) | advisory CVE-2026-122042 (`061af07b…`), raw `gpfdist.c` at `7.6.1-WHPG` (`deb74f32…`, affected) and `7.6.2-WHPG` (`0f328ca0…`, fixed), fix PR `warehouse-pg/warehouse-pg#370` merged `6fbb42ed6480bf3534c0a49e5f251dff468e8469` with patch `ca71aa29…`; every URL and hash in `lab/frontier/gpfdist2shell/PROVENANCE.md` | `bash lab/frontier/gpfdist2shell/run.sh <outdir>` — `gen_driver.py` verifies every pin and copies the fault lines verbatim under `#line`, then builds vulnerable, fixed and ASan drivers; gcc `-O0 -g`. Live lane: `bash lab/gpfdist2shell-live/build.sh` (emits `gpfdist_v7.6.1_asan` / `gpfdist_v7.6.2_asan`), then `probe_session.sh` / `probe_chosen.sh` / `probe_deep.sh` / `probe_live.sh` / `probe_pointer.sh` / `probe_pointer_chosen.sh` against 127.0.0.1; real pinned `gpfdist.c` with real libapr/libevent and shimmed pg/fstream headers (`build.sh` reads its pinned sources from the `PIN` path; `upstream/`, binaries and `out_*/` are gitignored, evidence transcripts in `evidence/` are tracked) | Operator replay ~10:28Z from a clean `git archive HEAD` extraction of `a7d5884`: 13 PASS / 0 FAIL, `ALL CHECKS PASS rc 0`, two independent five-run groups both `sha256=4f8bf8b7c6de06df7ce370b3570babe8df25112b9d2380c9836852864a8048c4`. Rung 1 `totalsegs=1 segid=1 seq=1 verdict=TRIGGER`; rung 2 id=3 clobbers `active_segids` at byte 12 and `seq_segs` at byte 24 while in-bounds id=0 writes only at 0; rung 3 ASan `WRITE of size 4` at `gpfdist_v7.6.1.c:1988` and isolated `WRITE of size 8` at `:3677`; rung 4 `X-GP-SEQ=0x4141414141414141` read back byte-exact at `seq_segs+24`, `X-GP-DONE` flips the 4-byte write to zero, guard page faults. Rungs 1/2/3 ESTABLISHED and rung 4 INSTRUMENTED in the extracted harness (witness #792 ESTABLISHED AS CLAIMED, grade unchanged); fixed 7.6.2 guards reject both tested positive-id shapes. The live loopback build writes chosen values into real APR-pool neighbours at chosen offsets (gdb byte dumps for `1`/`2`/`3` at `seq_segs+24`, second-request HTTP oracle) and gives a symbolised ASan SEGV at the real `:1988` for a wild index; `probe_deep.sh` writes the harness's exact `0x4141414141414141` at `seq_segs+120` = `path+96`, with a crafted filename supplying the slot = `value-1` precondition and `evidence/http_oracle_exact_value.txt` recording `chosen_write http=200`, the byte dump `b'AAAAAAAA'` and a follow-up oracle read proving persistence (fixed 7.6.2: `NO_ORACLE`). The pointer limb overwrites `session->requests[0]` with `0x1` at segid 28 and with a header-supplied `old+1` value in the path-length-matched run. Witness W65 accepted the live limb (#859) and W66 accepted both pointer limbs (#865), including a repeatable +1 walk (a target at or above the current value is reachable in N requests), no grade change. Arbitrary non-path bytes, stock allocator layout, an arbitrary single-write pointer value, a decrement and execution stay UNKNOWN. |
| Gct2Shell | [brief](../reports/frontier-gct2shell.md) | CVE record `CVE-2026-123975` (`0ac50b2d…`), vendor advisory (`fe21a3eb…`), fix `3df2be48…` (parent `edf946b5…`, patch `ae6e79bb…`), vulnerable `tokens_f.c` (`469c81f0…`) / fixed (`17665822…`), release notes and 2019-tag cross-check; every URL and hash in `lab/frontier/gct2shell/PROVENANCE.md` | `bash lab/frontier/gct2shell/run.sh <outdir>` — `gen_driver.py` verifies six driver-relevant pins and copies the full `token_get_fd()` bodies verbatim under `#line`, then builds vulnerable, fixed and ASan drivers; gcc `-O0 -g` | Operator admission replay ~10:46Z from a clean `git archive HEAD` extraction of `49ffba6`: 10 PASS / 0 FAIL, `ALL CHECKS PASS rc 0`, two independent five-run groups both `sha256=e5ca3f256b9fd58bd493ad841286819c2dd8f731874424ab26f3b287af5c6204`; witness #805 (10:48Z) replayed at `417a764`, all eight pins and byte-identical copied lines matched, no grade change |
| Imgproxy2Shell | [brief](../reports/frontier-imgproxy2shell.md) | CVE record `CVE-2026-123614` (`ab297c9d…`), GHSA-hff9-5pqw-6w9f (`d6de60b2…`), fix `a821b6a4…` (patch `c5db17e9…`), vulnerable `icoload.c` v4.0.15 (`2eabd58d…`) / fixed v4.0.16 (`67b4a9c2…`); every URL and hash in `lab/frontier/imgproxy2shell/PROVENANCE.md` | `bash lab/frontier/imgproxy2shell/run.sh <outdir>` — `gen_driver.py` verifies every pin and copies the affected (`:154-164`) and fixed (`:162-185`) loader statements verbatim under `#line`, then builds vulnerable, fixed and ASan drivers; gcc `-O0 -g` | Operator admission replay ~10:53Z from a clean `git archive HEAD` extraction: 10 PASS / 0 FAIL, `ALL CHECKS PASS rc 0`, two independent five-run groups both `sha256=6b0391599520bc899f169268e08699155888f0018274f9c2a2e12bcd31c2dad5`; rungs 1/2/3 ESTABLISHED, rung 4 INSTRUMENTED; witness #813/#814 independent clean-archive replay ESTABLISHED AS CLAIMED, grade unchanged (10 PASS / 0 FAIL, same digest) |
| Firebird2Shell | [brief](../reports/frontier-firebird2shell.md) | CVE record `CVE-2026-33337` (`b6ac3a4f…`), GHSA-89mq-229g-x47p (`451f9b62…`), master fix `2a5303dc…` / v5.0.4 fix `62fc37ed…`, vulnerable `xdr.cpp` v5.0.3 (`b28b1aaa…`, blob `555e6e1f…`) / fixed v5.0.4 (`426a7a07…`, blob `a5698288…`), plus `protocol.cpp` / `dsc.h` pins; every URL and hash in `lab/frontier/firebird2shell/PROVENANCE.md` | `bash lab/frontier/firebird2shell/run.sh <outdir>` — pins are recorded with SHA-256 in `PROVENANCE.md` and copied lines are verbatim (witness #818); `gen_driver.py` does not itself hash-check the pinned files. It copies the `dtype_cstring` cases (`:206-221` affected, `:206-223` fixed) verbatim under `#line`, then builds vulnerable, fixed and ASan drivers; gcc | Operator admission replay ~11:08Z from a clean `git archive HEAD` at `4592fbf`: 10 PASS / 0 FAIL, `ALL CHECKS PASS rc 0`, two independent five-run groups both `sha256=807b47150a58fe88094966b0affed9b35604a7b3730c68f53eeaa61057a25fbf` — rung 1 `copy_len=60000` unclamped into a 32-byte slot, rung 2 chosen bytes at `buffer+40` / `+100`, rung 3 ASan `WRITE of size 60000` at `xdr_v5.0.3:216`, rung 4 instrumented `0x5a5b5c5d…` readback and `PROT_NONE` guard fault; fixed v5.0.4 clamps to 31 and is ASan-clean on hostile and benign inputs. No live `fbserver`, wire packet, stock neighbour, pointer or execution; witness #818 independent clean-archive replay ESTABLISHED AS CLAIMED, grade unchanged (10 PASS / 0 FAIL, same digest). |
| Rtp2httpd2Shell | [brief](../reports/frontier-rtp2httpd2shell.md) | GHSA-35fv-hf3m-2pqc advisory (`eb55aed5…`, no CVE), signed fix `f0fcfc19…`, raw `rtsp.c` at v3.14.1 (`96eb3b4a…`, affected) / v3.14.2 (`b355f4af…`, fixed) plus `rtsp.h`, `buffer_pool.{c,h}` and `zerocopy.c`; every URL and hash in `lab/frontier/rtp2httpd2shell/PROVENANCE.md` | `bash lab/frontier/rtp2httpd2shell/run.sh <outdir>` — `gen_driver.py` hash-checks all eight pins and copies the fault lines verbatim under `#line`, then builds vulnerable, fixed and ASan drivers; gcc `-O0 -g` | Operator replay 11:26Z from committed HEAD: 10 PASS / 0 FAIL rc 0, two five-run groups both `sha256=11a76ab0bcb678868229982cb64a826f0367f29d8c4b3daf9eb84eb5804ceb13`; all eight pins matched by SHA-256 and the `:1800` / `:1825` / fixed `:1801` lines read directly. Witness #831 independently replayed from a clean `bb00268a` archive with the same digest and returned ESTABLISHED AS CLAIMED, grade unchanged; its three supporting citation-line nits were folded into the brief/PROVENANCE at `0a7e96a`. |
| Vrpn2Shell | [brief](../reports/frontier-vrpn.md) | CVE record `CVE-2026-123200` (`f4ee3212…`), fix commits `0da5b0b…` / `c893b58…`, pinned `vrpn_Connection.C` at `79deb000…` (`9eaa1045…`), fix-commit tarball (`b5258e99…`); every URL and hash in `lab/frontier/vrpn2shell/PROVENANCE.md` | `bash lab/frontier/vrpn2shell/run.sh <outdir>` runs the loopback wire injector; `bash lab/frontier/vrpn2shell/gdb-wire.sh <outdir> <port> <index>` confirms handler dispatch; direct ASan harness: `g++ -fsanitize=address -fno-omit-frame-pointer -g -I lab/frontier/vrpn2shell/src/vrpn-07.36 lab/frontier/vrpn2shell/harness/handler_direct.cpp lab/frontier/vrpn2shell/build-asan-07.36/libvrpnserver.a -o handler_direct` then `handler_direct 100` | Observed W98: ASan `WRITE of size 1` at real `vrpn_Connection.C:4554` for indices 100/128/-256; fixed commit has no write-site fault; gdb proves a real TCP message reaches `:4535`. Live-server ASan sweep negative — wire rung 3 and rung 4 UNKNOWN; staged window 74, operator admission pending, no witness replay yet. |
| Zephyr2Shell | [brief](../reports/frontier-zephyr2shell.md) | CVE-2026-82391 / GHSA-8jrg-wx88-g75j OSV record (`3a792897…`), fix `4e0a5f38b14d…` (PR #117267, patch `65d08ea8…`), raw `http_server_http2.c` at v4.4.0 (`35c7a3bf…`, affected) / v4.5.0 (`578c7c3f…`, fixed) plus `http_server_core.c` (`f400c114…`), `server.h` (`43c0522d…`) and `Kconfig` (`17360698…`); all seven SHA-256 pins and URLs in `lab/frontier/zephyr2shell/PROVENANCE.md` (the api.github.com advisory endpoint 404s, so advisory HTML and the CVE/OSV records are pinned) | `bash lab/frontier/zephyr2shell/run.sh <outdir>` — `gen_driver.py` hash-checks all seven pins (exit 3 on drift) and copies the fault statements verbatim under `#line`, then builds v4.4.0, v4.5.0 and ASan drivers; gcc `-O0 -g` | Operator replay ~11:42Z from a clean `git archive 0ccfdba lab/frontier/zephyr2shell` extraction: 10 PASS / 0 FAIL rc 0, two five-run groups both `sha256=48568d4883dd3ca4125fc0dbb6371aa886fc3e9ed3d7362f778815cd3201f0e0`. ASan `WRITE of size 1024`, 0 bytes after a 256-byte region, fault frame `core_v4.4.0:565`; chosen `0x5a5b5c5d` byte-exact at offsets 300/500/900, guard page rc 139, fixed v4.5.0 and benign-file cases ASan-clean. Rungs 1/2/3 ESTABLISHED in the harness, rung 4 INSTRUMENTED chosen bytes in a stand-in collaborator; no Zephyr build, HTTP/2 wire traffic, real client struct neighbours, pointer control or execution. Witness W64/#847 independently replayed from a `5e68ea6` clean archive with the same digest and returned ESTABLISHED AS CLAIMED, grade unchanged; its one observation (OSV JSON key order is not byte-stable) is non-load-bearing. |
| ZenohPico2Shell | [brief](../reports/frontier-zenohpico2shell.md) | CVE-2026-130603 / GHSA-fw6g-3fgh-f6m6 CVE JSON (`37929f8a…`), fix `9198576fe69f6af66a2ab4f12f579f72208d7b28` (PR #1345, patch `43f15d14…`), raw `message.c` at 1.10.1 (`38ce4cef…`, affected) / 1.10.2 (`ab9045e1…`, fixed) plus `core.h`, `iobuf.{c,h}` pins; all seven SHA-256 pins and URLs in `lab/frontier/zenohpico2shell/PROVENANCE.md`; OSV and GitHub advisory cross-checks | `bash lab/frontier/zenohpico2shell/run.sh <outdir>` — `gen_driver.py` hash-checks all seven pins (exit 3 on drift) and copies the fault statements verbatim under `#line`, then builds vulnerable, fixed, ASan, guard and collaborator drivers; gcc `-O0 -g` | Operator admission replay ~11:54Z from a clean `git archive HEAD lab/frontier/zenohpico2shell` at 34c818e into `/tmp/zp2op-verify`, output `/tmp/zp2op-out`: 10 PASS / 0 FAIL rc 0, two five-run groups both `sha256=080794c304ffa34b467a189c505f02318af437ecc43c3a0658d985f0632b9b3b`; all seven pins matched the stored SHA-256. Rungs 1/2/3 harness ESTABLISHED, rung 4 INSTRUMENTED chosen bytes at chosen offsets; wrapped-length `memset` limb and live transport UNKNOWN. Witness #861 (2026-11-21 ~12:01Z) replayed from a clean `git archive HEAD lab/frontier/zenohpico2shell` (`8ae0e88`) into `/tmp/w65-zp-archive`: 10 PASS / 0 FAIL rc 0, both five-run groups byte-identical, seven pins byte-identical to fresh raw-GitHub/CVEAWG fetches, a tampered core pin failed generation rc 3 `PIN DRIFT`; grade unchanged, wording NITs folded into the brief. |
| Libwebsockets2Shell | [brief](../reports/frontier-libwebsockets2shell.md) | CVE-2026-19773 / ZDI-26-590 CVE JSON (`ae98ef58…`) and ZDI advisory HTML (`86eed822…`), affected upstream commit `b4b5aed3903eaff09cd76a410f69bbe5dff66f8e`, fix `824151862f37bc72f46d9a3e01d5b9408d313a0b` with pinned patch (`c8dab882…`), raw `hpack.c` at v4.3.10 (`5ce2d424…`, affected) / v5.0.0 (`9232db68…`, fixed); all five SHA-256 pins and URLs in `lab/frontier/libwebsockets2shell/PROVENANCE.md` | `bash lab/frontier/libwebsockets2shell/run.sh <outdir>` — `gen_driver.py` re-verifies all five source pins on every run (exit 2 on drift) and copies the fault statements verbatim under `#line`, then builds vulnerable, fixed, ASan and guard-page drivers; gcc `-O0 -g` | Operator admission replay ~12:22Z from a clean `git archive HEAD lab/frontier/libwebsockets2shell` extraction into `/tmp/lws-op-verify`: 10 PASS / 0 FAIL, `ALL CHECKS PASS rc 0`, both five-run groups `sha256=45cd97c83c032f5ff9217e568225ea95441df31480495b72cb944d3b3f798833`; all five pins and four harness/script digests matched `PROVENANCE.md` by SHA-256. ASan `WRITE of size 1` at `hpack_v4.3.10:277`, chosen `0x5a`/`0xa5` at limits 16/32/48, guard rc 139, fixed/benign ASan-clean. Witness W68 on #868 returned ESTABLISHED AS CLAIMED at the labeled grade (no grade change); citation and NUL-numbering NITs folded into the brief. W1/#874's naive long-`:path` on a real v4.3.10 H2 server was a measured route-specific NEGATIVE — all stores stayed inside the arena — and is preserved; real-path reachability is no longer UNKNOWN. W2 drives one unauthenticated loopback HTTP/2 HEADERS frame with a literal `&`, `;` or `?` delimiter in `:path` using `python3 h2client-delim.py <port> <prefix 30-or-31> <delim> <marker 5a, 37 or a5>` against the ASan v4.3.10 server built per `lab/libwebsockets2shell/README.md` (`max_http_header_data=32`): six cases fault with `WRITE of size 1` at raw `hpack.c:277` from `:1168`, gdb records entry `pos=32 c=0x37 max=32`, prefix 30/31 chooses offset 32/33, a non-ASan build reads back chosen `0x37`/`0x5a` byte-exact at `data[32]`, and the same frame on v5.0.0 gives no report. Witness W72 independently replayed W2 ESTABLISHED AS CLAIMED at the labeled grade; pointer, control-flow diversion and execution stay UNKNOWN. |
| Pillow2Shell | [brief](../reports/frontier-pillow2shell.md), [real-process](../reports/pillow2shell-consumer-reality.md) | CVE-2026-112398 / GHSA-5x8w-8jj5-q52h CVE JSON (`3632abba…`), GHSA advisory HTML (`3dac6010…`), fix `242a059aedc1935097d9aa1dc3f099750467ba75` with pinned patch (`dc0e90b2…`), raw `JpegDecode.c` at 12.2.0 (`895fc76b…`, affected) / 13.0.0 (`9c575a6e…`, fixed) plus `decode.c` (`d9d96888…`) and `FpxImagePlugin.py` (`4fa3a75a…`); all seven SHA-256 pins and URLs in `lab/frontier/pillow2shell/PROVENANCE.md`; OSV cross-check | `bash lab/frontier/pillow2shell/run.sh <outdir>` — `gen_driver.py` re-verifies all seven pins on every run (`sys.exit(str)` gives rc 1; `run.sh:23` maps drift to exit 2) and copies the fault statements verbatim under `#line`, builds vulnerable, fixed, ASan and guard drivers; real host libjpeg decodes the flat, quality-100 CMYK row, local shim hands it to the pinned caller; gcc `-O0 -g` | Operator admission replay ~12:41Z from a clean `git archive d72ad24 lab/frontier/pillow2shell`: 10 PASS / 0 FAIL rc 0, two independent five-run groups both `sha256=cb758c07f0aec3620c7b0d14c0fd471bf6b1455c410ead291db7a57eb08d818b`; ASan `WRITE of size 256` at `JpegDecode_v12.2.0.c:252` via the shim at `driver_vuln.c:38`. Witness #879 replay from clean `d72ad24`: 10 PASS / 0 FAIL, same digest, 6/7 pins byte-identical (GHSA HTML dynamic metadata only), ESTABLISHED AS CLAIMED at the INSTRUMENTED grade. Real-process lane (W1): build both sdists with ASan and `JPEG_ROOT=/tmp/pw2-w1/jpegasan` pointing at a libjpeg-turbo 2.1.5.1 (`WITH_SIMD=0`, built with `-fsanitize=address -fno-omit-frame-pointer -g -O1`), then `python3 make_case.py case64.fpx 256 0xa5 64 64`. The built `_imaging.so` has no RUNPATH, so bare `ldd` can resolve the system `libjpeg.so.62`: verify with `LD_LIBRARY_PATH=/tmp/pw2-w1/jpegasan/lib ldd PIL/_imaging*.so` and export the same path at run time (the witness used `/tmp/w73-pw2/jpegasan/lib`). Run with `LD_LIBRARY_PATH=/tmp/pw2-w1/jpegasan/lib PYTHONPATH=<v12> LD_PRELOAD=$(gcc -print-file-name=libasan.so) ASAN_OPTIONS=detect_leaks=0 python3 -c 'from PIL import Image; Image.open("case64.fpx").load()'`; v12 reports in-library `heap-buffer-overflow`, `WRITE of size 1` 0 bytes after a 128-byte region allocated at `decode.c:226`, stack `null_convert` → `jpeg_read_scanlines` → pinned `JpegDecode.c:252`, v13 fails with `OSError: broken data stream` and no ASan report. On the host's uninstrumented libjpeg, `gdb_watch32.log` / `gdb_watch200.log` show `0x00 → 0x5a` at `buffer+32` / `buffer+200`, the byte chosen through JPEG coefficients. Plain lane (W2): `python3 -m pip install --no-binary :all: --no-deps --target /tmp/pw2-w2/v12plain /tmp/pw2-dl/pillow-12.2.0.tar.gz`, then `PYTHONPATH=/tmp/pw2-w2/v12plain python3 -c 'from PIL import Image; Image.open("case64.fpx").load()'` on the same generated case; commit `a8ea407` carries the build and run logs under `lab/pillow2shell/`. Expected: `glibc_first_store_v12.log` hardware watchpoint `0x00 → 0x5a` at `buffer+128` from pinned `JpegDecode.c:252`; `glibc_metadata_overwrite_v12.log` next chunk size field `0x21 → 0x5a5a5a5a5a5a5a5a5a`; `glibc_live_chunks_v12.log` live chunks at `buffer+144` (32 bytes) and `buffer+176` (992 bytes); 5/5 `glibc_plain_run_run[1-5].log` print `OK (90, 90, 90, 90)` then exit rc 139 (`glibc_crashbt_v12.log`: SIGSEGV in `PyGC_Collect()` at finalization), `glibc_malloc_check_v12.log` rc 134 `corrupted double-linked list`, `plain_v13_fixed_control.log` `OSError: broken data stream when reading image file` rc 1. Witnesses #898/#900 returned ESTABLISHED AS CLAIMED at the W1 labeled grade. W3 (commit `558d2e4`; replayed in W74 #947, see below): in the unmodified plain gdb run the `buffer+176` chunk is a live CPython `PyUnicodeObject` (`ob_refcnt=2`, `ob_type=&PyUnicode_Type`); a hardware watchpoint on `buffer+191` catches `0x00 → 0x5a` from `libjpeg.so.8` via pinned `JpegDecode.c:252`, after which both words read `0x5a5a5a5a5a5a5a5a` — a chosen byte pattern, not a valid address. Reproduce with the gdb batch command in the W3 section of `lab/pillow2shell/README.md` (`glibc_pyobject_type_v12.log`); `glibc_pyobject_alloc_stack.log` is a supporting LD_PRELOAD trace with shifted layout. W4 (commits `30e2ba1` / `1538199` / `944ad16`): `make_case.py` takes an optional sixth argument (256 bytes as 512 hex chars) and seventh (JPEG height); `python3 make_case.py case_ptr64.fpx 256 0xa5 64 64 "$(cat pattern_full.hex)" 64` builds `case_ptr64.fpx` (SHA-256 `cf7787a3…`, 64-row) with `0x11` at pattern bytes 128-135 and the valid address `0xa2d260` (`&PyCode_Type`) at 184-191, while `pattern_long.hex` builds `case_long.fpx` (`be85c9a6…`) with `0xa3bf20` (`&PyLong_Type`). `firstrow.log` / `rawscan.c` confirm byte-exact libjpeg output. Catch the store with `PYTHONPATH=/tmp/pw2-w2/v12plain gdb -q -batch -x ptr_store.gdb --args python3 -c 'from PIL import Image; Image.open("case_ptr64.fpx").load()'`; expected `Old value = 192 '\300'`, `New value = 96 '\140'` at `buffer+184` from `libjpeg.so.8` via pinned `JpegDecode.c:252`. The absolute brk address varies with cwd/environment (`0xd32bb0` logged, `0xd32c10` from the lane); offsets and bytes are invariant. Reproduce the causal differential with `full_restore_clean.gdb` / `full_restore_type.gdb` / `full64_restore_long.gdb`: full past-end snapshot and restore prints `LOAD_OK` and exits clean; reapplying only `*(unsigned long *)(buffer+184) = 0xa2d260` gives SIGSEGV in `Py_FinalizeEx()` (`full64_restore_type.log`, `crash_disasm.log`); the non-GC `0xa3bf20` differential exits clean (`full64_restore_long.log`, GC-flag explanation an INFERENCE). 5/5 `run64_[1-5].log` exit rc 134 `corrupted size vs. prev_size`; `plain_v13_pattern_control.log` is `OSError` rc 1. W5–W7 (`fcd7e2f`/`a5447c4`/`6496bc8`/`2fc9e2f`) derive the fake-type address from the post-decode OOB-written `ob_type` rather than `$b+512`, repairing the recipe across three builds; `forged_type_natural.gdb` continues instead of invoking `_Py_Dealloc` and hits the chosen marker 3/3 from `Py_FinalizeEx()` (`forged_type_natural_control.gdb` keeps the real `tp_dealloc` and never hits it). W7 removes the gdb type copy: `make_case.py pattern_fullrow.hex` embeds a 416-byte fake `PyUnicode_Type` with `tp_dealloc=0x45e6e6` at baked brk `0xd32f90` and its address at pattern offset 184 in `case_file.fpx` (SHA-256 `5e336b88a823c0f11b1c534781e36611f2ebefc10533b0c55911735126770788`); `bash lab/pillow2shell/forged_type_file.gdb` snapshots/restores everything except the image-written type and pointer slots, then 3/3 log `PTR184=d32f90 FAKE48=45e6e6 MATCH=1` and `HIT pc=0x45e6e6` from `Py_FinalizeEx()`. `case_ctrl.fpx` (SHA-256 `891ac80d…`) keeps the real `tp_dealloc` and never hits the marker. Expected logs: `forged_type_file.log`, `forged_type_file_control.log`, `forged_type_natural.log`; the brk address depends on build/cwd/command line and W7's `load()` raises `OSError` after the write. No dereference of attacker-chosen code, PC write, ASLR leak or independent witness verdict; W8 (`62cef9d`) adds `bash lab/pillow2shell/replay_forged_type.sh <outdir>` (8 PASS / 0 FAIL / 3 INFO, all case digests checked) for pending requests #994/#995/#1004 — the three INFOs are preserved negatives (the committed fixed-address `case_file.fpx`/`case_ctrl.fpx` and the W6 real-slot control do not reproduce in this invocation context; tile buffer moved `0xd32cc0 → 0xd345f0`), while `calibrate_file_case.py` + `forged_type_file_dyn.gdb` regenerate image-only cases for the current layout (marker `PTR184=… FAKE48=45e6e6 MATCH=1 HIT pc=0x45e6e6` from `Py_FinalizeEx()`, real-slot control stays clean). W3/W4 were replayed in W74 (#947) ESTABLISHED AS CLAIMED; ◐ unchanged. |
| DataSketches2Shell | [brief](../reports/frontier-datasketches2shell.md), [consumer](../reports/datasketches2shell-loopback-consumer.md) | CVE-2026-103501 JSON (`ed937165…`) and GHSA-w656-xfm5-jqjh HTML (`8242673d…`, rotating metadata snapshot), fix PR #503 diff (`a2c00afe…`), full `5.2.0` / `5.3.0` release tarballs (`63e6bda6…` / `9b080020…`); all five SHA-256 pins and URLs in `lab/frontier/datasketches2shell/PROVENANCE.md`; Apache list, release notes and oss-sec cross-checks | `cd lab/frontier/datasketches2shell && bash run.sh <outdir>` — `run.sh` verifies all five pins with `sha256sum -c src/SHA256SUMS` before extracting and compiling the real pinned `hll/include` and `common/include` headers with `-fsanitize=address` where marked; gcc `-O0 -g` | Operator admission replay 2026-11-21 ~12:57Z from a clean `git archive 818ec4a lab/frontier/datasketches2shell` extraction into `/tmp/ds2-op-verify`, absolute outdir `/tmp/ds2-op-out`: 11 PASS / 0 FAIL rc 0, both five-run groups `sha256=d7d0532239c8b926c23c102cac12b13ab9bae6506b7ff7f5341fd5aeda206e2a`. ASan `WRITE of size 256` at pinned `CouponList-internal.hpp:116` via public `hll_sketch::deserialize` (`HllSketchImplFactory.hpp:101` ← `HllSketch-internal.hpp:63`); count 255 gives `WRITE of size 1020`; chosen `0x5a`/`0xa5`/`0x77` read back byte-exact at +32/+48/+64/+96/+128/+224/+255; `PROT_NONE` guard rc 139; fixed 5.3.0 throws `couponCount >= capacity` before the copy. Rung 4 INSTRUMENTED only: readback and guard modes place the coupon vector in page-aligned harness memory, so the write is the library's own `memcpy` but the landing site is a stand-in. Witness #889 (W71) clean replay: same 11/0 and digest, five pins matched, grade unchanged. W73 (#911) replayed the wake-1 claims ESTABLISHED AS CLAIMED at the labeled grade. Loopback-service lane (`lab/datasketches2shell/hoosf_service.cpp`, `bash run_hoosf.sh <outdir>`): 4 PASS / 0 FAIL rc 0, `GDB_TOP_SIZE_BEFORE=0xdbd1`, the patched top size `0x1f000` is accepted, `A1=top+16` with `HOOSF_A1_BYTES=5a5a5a5a5a5a5a5a5a`, `A2=A1+0x1010`, and `A2` shifts +0x1000 when the first allocation grows from `0x1000` to `0x2000`; blocked: `-1` top size gives `service_rc=-6`, and plain ASLR moves `A1` between `0x642a…` and `0x618b…`. Witness W74 (tape #922) replayed clean-archive `b95653e` with 6+4 PASS rc 0, five pins OK and those blockers ESTABLISHED AS CLAIMED — bounded relative steering only. Wake 3 (`e6e8b86`, W74 tape #929, ESTABLISHED AS CLAIMED): `bash run_victim.sh <outdir>` gives 3 PASS / 0 FAIL; the pre-existing `LiveVictim` sits `0x119a0` below the coupon buffer and is untouched (negative), while with top size patched to `0x1f000` a hostile image leaves a post-deserialization `PodRequest` with `a=b=0x5a5a5a5a5a5a5a5a` and benign count 2 with both fields zero; no call through an overwritten field. Wake 4 (`fa551e9`, replayed in W75 #951 from a clean archive ESTABLISHED AS CLAIMED at the lab-build-only grade): `bash run_groom.sh <abs-outdir>` gives 4 PASS / 0 FAIL rc 0 with five pins; gdb `GDB_DELTA_V=48`, callback `0x403b4a → 0x403b84`, `BENIGN_MARKER3_EXECUTED`, `CALL_THROUGH`, service rc 0, benign marker2 control clean, ASan `WRITE of size 72` at pinned `:116`; count-64 (256-byte copy) SIGSEGV before the call and a pre-warm benign deserialize reversing the layout are preserved negatives. W75 (tape #951) replayed `fa551e9` from a clean archive: five pins OK, `run_groom.sh` 4 PASS / 0 FAIL, `run_all.sh` 6 PASS / 0 FAIL, gdb `p=0x442320`, V=p+48, victim chunk `0x41` before and after, live callback `0x403b4a → 0x403b84` with chosen magic/refcount and a genuine `call *%rax` to `benign_marker3` (`rax=0x403b84`, no re-store), 5/5 fresh archives identical; re-patching the image's callback to marker2 still reaches marker2, so the pointer is image-carried. Conditions: lab-only synthetic consumer built `-no-pie -O0`, consumer-side grooming, no real application or ASLR-defeating leak; grade ◐ unchanged. Wake 6 (`cc9ba4d`/`aa9ebe8`, author evidence awaiting replay): `bash lab/datasketches2shell-pg/run.sh <abs-outdir>` (pins and URLs in `lab/datasketches2shell-pg/PROVENANCE.md`/`SHA256SUMS`) starts a loopback-only PostgreSQL 16.4 instance, loads pinned extension source `56d871276d32a1235041b553559143a9697f8906`, and sends four `bytea` images through `hll_sketch_get_estimate`; rc 0 with `PG_DS2_BENIGN 2.000000004967054`, `C18 18.00000075995926`, `C64 64.00001001358214`, `C255 255.00016085815176`, assertion build identical and server alive; gdb at pinned `CouponList-internal.hpp:116` sees `0 → 0x5a5a5a5a5a5a5a5a` at `p+32`/`+40` (assertion sentinel `0x7f7f… → 0x5a5a…`); rebuilt against pinned 5.3.0 headers the count-64 image is rejected with `ERROR: Attempt to deserialize invalid CouponList with couponCount >= capacity`. Allocations come from PostgreSQL `palloc`, so the glibc top-size/tcache lanes do not transfer; no crash, pointer or diverted call, real-app grade unchanged (clean-archive author replay `abda01f`). Wake 8 (`df670d1`/`abda01f`): `bash lab/datasketches2shell-py/run.sh <outdir>` compiles the unmodified upstream `src/hll_wrapper.cpp:100` (`datasketches-python-5.2.0.tar.gz`, `nanobind-3.1.0-py3-none-any.whl`, hashes in `lab/datasketches2shell-py/PROVENANCE.md`) against the pinned 5.2.0 headers; expect `TOTAL PASS=9 FAIL=0` rc 0 with 5/5 library and 2/2 binding pins, benign estimates, counts 18/64 abort in interpreter shutdown (rc 134/139; the exact allocator diagnostic varies by layout), count 255 rc 139, ASan `WRITE of size 72` at pinned `CouponList-internal.hpp:116` via `hll_wrapper.cpp:100` → nanobind → `PyObject_Vectorcall`, and gdb `p=0xbad6f0` with `p+32`/`p+40` `0x79`/`0x21 → 0x5a5a5a5a5a5a5a5a` then `munmap_chunk(): invalid pointer` in finalization; fixed 5.3.0 raises `ValueError` before the copy. Clean-archive author replay gave the same 9/0 with only heap bases varying; input is a local `bytes` object, no chosen pointer, leak or natural call-through. W81 #1023 replayed wake 8 from a clean `git archive abda01f`: 9 PASS / 0 FAIL, 5/5 library + 2/2 binding pins, same ASan WRITE 72 and `0x79`/`0x21 → 0x5a5a…` metadata, fixed 5.3.0 `ValueError` — ESTABLISHED AS CLAIMED at the labeled real-consumer availability-only grade with a non-material NIT on allocator-diagnostic wording. Wake 9 (`77a6bc6`, author clean-archive replay `5af11ee`): `bash lab/datasketches2shell-stream/run.sh <outdir>` gives 10 PASS / 0 FAIL rc 0, five pins, both five-run groups `sha256=cbf2776389037adaf90d5851a3f55b444b675798b8c8dfdd93809a22f9c25066`, ASan `WRITE of size 256` at pinned `CouponList-internal.hpp:162` via public `deserialize(std::istream&)` (count 255 `WRITE of size 1020`, 988 past), chosen `0x5a`/`0xa5` at +32/+48/+64/+96/+128/+224/+255, `PROT_NONE` rc 139, clearing COMPACT flag `0x08` gives `rv=ok` (causal control), fixed 5.3.0 rejects `couponCount >= capacity`; W81 #1016 replayed it from clean archive `5af11ee` ESTABLISHED AS CLAIMED at the socket-free-harness grade. Wake 6's palloc observation remains author-replayed only. |
| RabbitMQC2Shell | [brief](../reports/frontier-rabbitmqc2shell.md), [consumer](../reports/rabbitmqc2shell-consumer-loopback.md) | CVE-2026-61547 JSON (`6b6025b7…`) and GHSA-hfjv-vcp3-39wh HTML (`33968f12…`, rotating metadata snapshot), fix `b09271180621248dc810f4e48e5adabff35ecee1` (PR #892) diff and full `0.16.0` / `0.17.0` tarballs (`1298b89a…` / `66c36901…`); all six SHA-256 pins and URLs in `lab/frontier/rabbitmqc2shell/PROVENANCE.md`; CVE and release cross-checks | `cd lab/frontier/rabbitmqc2shell && bash run.sh <outdir>` — `run.sh` verifies all six pins with `sha256sum -c src/SHA256SUMS` before extracting and building both real release trees with CMake/Ninja; ASan build for 0.16.0, plain and fixed builds for both | Operator admission replay 2026-11-21 ~13:14Z from a clean `git archive b8c2439 lab/frontier/rabbitmqc2shell`: 10 PASS / 0 FAIL rc 0, both five-run groups `sha256=239e11fea9854f993b4d90adae7efa9b1b481013688daeeaa5d524cd02ffeee8`; ASan `WRITE of size 200000` at pinned `amqp_connection.c:467`, chosen `0x5a`/`0xa5` at +65536..+69632, guard rc 139, fixed 0.17.0 rc -2, benign bodies clean. Witness W73 (#914) returned ESTABLISHED AS CLAIMED at the labeled grade; grade unchanged. Socket-fed service lane: `bash lab/rabbitmqc2shell/run.sh /tmp/rmq2-service-final` — 8 PASS / 0 FAIL rc 0, six pins OK, digest `f8efc860e75e8cc0035c4957b2208928a74403da44e4f198ed757e3f2fd4209d`; ASan `WRITE of size 200000` from `amqp_send_frame` at `amqp_connection.c:467` with the library's own allocator; gdb shows `state->socket` at `outbound+65552` (vtable `<amqp_tcp_socket_class>`) overwritten; with a reusable 200000-byte buffer and a 65600-byte body carrying a fake vtable plus the body address, `amqp_socket.c:92` calls benign `marker_send` (`MARKER: controlled vtable call reached`, rc 0), while fixed 0.17.0 returns `AMQP_STATUS_BAD_AMQP_DATA`. Lab-only address file supplies body/vtable addresses (simulated disclosure); no remote listener, real application or address-disclosure primitive. W74 (tape #946) replayed the socket-fed service from a clean archive ESTABLISHED AS CLAIMED at that grade: 8 PASS / 0 FAIL, six pins OK, matching digest, chosen `0xa5` byte-exact over the live `klass` pointer and benign `marker_send` through the library path; the address disclosure remains simulated by a lab file. |
| HnswLib2Shell | [brief](../reports/frontier-hnswlib.md) | CVE-2026-124959 JSON (`0962ff9f…`, CERT/CC) and the m00dy.sh writeup (`b019ab29…`), affected `hnswalg.h` at `d9b3608` (`483d3b31…`), fix commit / PR #677 diff (`012e39ab…`), full `v0.9.0` and PR-head tarballs (`v0.9.0.tar.gz`, `fix-280cb597.tar.gz`); all seven SHA-256 pins and URLs in `lab/frontier/hnswlib/PROVENANCE.md`; live GitHub API re-read 2026-11-21 ~13:30Z: PR open, `merged_at=null`, fixed side **unreleased** | `cd lab/frontier/hnswlib && bash run.sh <outdir>` — `run.sh` re-verifies all seven pins with `sha256sum -c src/SHA256SUMS`, compiles the real pinned v0.9.0 header with ASan and the PR-head header as the fixed control; a link-time `malloc` interposer relocates the real level0 buffer for chosen-byte readback without altering the library write | Operator admission replay 2026-11-21 ~13:30Z from a clean `git archive 78b7c7b lab/frontier/hnswlib`: 9 PASS / 0 FAIL rc 0, two five-run groups both `sha256=26adac439ba80f57699e7544327fefc4dfa3bc667e13d1ba463d134d36fab3d7`; witness W73 (#913) returned ESTABLISHED AS CLAIMED at the labeled grade. Loopback service (`lab/hnswlib2shell/`): `bash run.sh /tmp/hnsw2-service-out` accepts one index file on 127.0.0.1 and calls the ordinary pinned load constructor; ASan in-service `WRITE of size 65472` at pinned `hnswalg.h:779` into the `:776` region (no interposer), received bytes SHA `e192bcdc…`, capacity-fits control clean, seven pins OK. `bash chosen.sh <outdir>` overwrites the real top-chunk size at file offset 360 (`0xba11 → 0x1122334455667788`), `chosen_value_present=True` rc 0; the first real neighbour is the top chunk, so glibc aborts at the next malloc. Live-object lane: `bash victim.sh /tmp/hnsw2-victim-out` with `bash lab/hnswlib2shell/client.py` grooms tcache (`G=0x…d4e0`, `V=0x…d5f0`, delta 272) so a live `CacheEntry` follows the reused chunk; file offsets 360/368/376/384/424 preserve the chunk sizes and set `magic=0x1111111111111111`, `callback=0x4041be → 0x4041fb` (distinct `benign_marker3`), `refcount=0x3333333333333333`, with `BENIGN_MARKER3_EXECUTED` reached through the field; capacity-fits control leaves the object unchanged. Conditions: synthetic `-no-pie -O0 -g` loopback consumer, consumer-side grooming, call invoked from gdb at the post-read stop (not a natural path), downstream allocator abort; the crafted-index digest is build-layout-specific (`a3a20f6f…` author, `2f17ee97…` witness), not a portable pin. W74 (tape #948) replayed both the consumer-reality claim (tape #935, commit `6445c8a`) and the live-object claim (commit `2a271d3`, replayed though not routed) ESTABLISHED AS CLAIMED at the labeled grade, accepting all stated conditions; no replay owed. |
| Asn1scc2Shell | [brief](../reports/frontier-asn1scc.md), [consumer reality](../reports/asn1scc2shell-consumer-reality.md) | CVE-2026-75614 / GHSA-825c-7h77-2jjq records (CNA GitHub_M, 8.1 HIGH), maintainer advisory, fix `fe6ab763bc60d8a2def4104c15414809b45fffd9`, full `4.6.0.17` / released `4.7.0.1` tarballs and compiler asset; eight SHA-256 pins in `lab/frontier/asn1scc2shell/src/SHA256SUMS` and `PROVENANCE.md` | `cd lab/frontier/asn1scc2shell && bash run.sh <outdir>` — verifies all eight pins, compiles both pinned C runtimes verbatim with the same generated uPER decoder, builds ASan, fixed, benign and guard variants | Frontier replay 2026-11-21: 12 PASS / 0 FAIL rc 0, both five-run groups `sha256=e39fec33622f9f10b63c2b0b804fcfa7072ac7b6498d63c2801ec3bd24b7bcd6`; clean `git archive 821647e` replay matched. ASan `WRITE of size 1` 0 bytes after 9-byte region at `asn1crt_encoding.c:400` ← `:1449` ← generated `schema.c:59`; rungs 1/2/3 ESTABLISHED, rung 4 INSTRUMENTED chosen bytes at +5/+6 and `PROT_NONE` rc 139; fixed runtime rejects. Loopback consumer check (`9628731`): from `lab/frontier/asn1scc2shell/`, `bash run.sh run && bash consumer.sh && bash variant.sh && bash heap-chain.sh && bash pointer-target.sh` (gdb variants `watch-chain.gdb` and `watch-pointer.gdb`); services bind 127.0.0.1 and call the generated `Payload_Decode` against the verbatim pinned 4.6.0.17 runtime. Pinned `SIZE(0..5)` with natural `malloc(sizeof(Payload))` (`sizeof=12`, 3 bytes tail padding) is a measured NEGATIVE: ASan clean, object `07 00 00 00 5a a5 5a a5 5a a5 5a 00`, next chunk size `0x20d51` unchanged; the artificial `malloc(9)` staging mode still reproduces the ASan `WRITE` frames through the real socket. `SIZE(0..17)` variant (`sizeof=24`, no slack), hostile count 31: ASan `WRITE of size 1` after a 24-byte region, gdb watchpoint on `obj+24` sees `0x20d51 → 0xa55aa55aa55aa55a` with bytes `5a a5 5a a5 5a a5 5a a5`, fixed 4.7.0.1 clean but its wrapper still returns `ok=1` — do not claim wrapper rejection. Result 3 (`ab30ea2`, replayed W78 #967): the corrupted neighbour size `0x21 → 0x41` is consumed by `free(B)` and `malloc(56)`, returning an overlapping chunk whose stores change live `C->nCount` (`0x11223344 → 0x11223377`) and `C->arr[0]` (`0x11 → 0x42`); five address-masked runs agree, the digest recipe is ad-hoc (NIT), fixed 4.7.0.1 has no overlap. Result 4 (`2de7032`, replay requested): `pointer-target.sh` builds a `-no-pie` loopback consumer with a `handler` pointer at `Session+24`, sends count-31 bytes `5a*20 d0 28 40 00 00 00 00 00 cc cc cc`, gdb watches the pinned runtime store replace `0x4015b6 <safe_handler>` with `0x4015c0`, and the call prints `MARKER: control-flow diverted to chosen address` rc 0; fixed 4.7.0.1 keeps `safe_handler` and prints `SAFE`. ASan is clean there because the store crosses a subobject boundary, not a heap redzone. No real ASN.1 application, arbitrary-address write, ASLR-defeating leak or chosen code; pointer/marker control is lab-layout-only. W74 (tapes #943/#944) replayed the frontier brief and the earlier consumer check from clean archives ESTABLISHED AS CLAIMED at the labeled grade: all eight pins OK, 12 PASS, chosen bytes byte-exact in the live next-chunk size field for the `SIZE(0..17)` variant, fixed 4.7.0.1 ASan-clean with the wrapper still returning `ok=1`. Result 5 (`6dd93c4`/`b8b20c6`): `bash pie-partial.sh` rebuilds the `Session` consumer and `SIZE(0..17)` decoder `-fPIE -pie`, verifies `randomize_va_space=2` and `nm` delta `marker-safe_handler=0x1a`, then sends a leak-shaped connection followed by count 22; five distinct PIE bases each show `handler` low 16 bits advanced by 26 with `high6_same=1`, intact canary and `MARKER`, fixed 4.7.0.1 prints `SAFE`, and a `delta=0` counterfactual also stays safe. W74 #980 replayed this from clean archive `b8b20c6` ESTABLISHED AS CLAIMED; Results 1–5 all now have replays (#944/#967/#974/#980), with no full-address write, real ASN.1 application or chosen code. |
| Iec618502Shell | [brief](../reports/frontier-libiec61850.md), [rung-4 probe](../reports/iec618502shell-r4.md) | CVE-2026-49035 / CISA ICSA-26-204-06 pinned CNA/NVD records (CISA HTML 403 in provisioning), fix `db35acf67bfdb4c5bdbcfb19b66529476bf72d21`, full vulnerable `a1396111` and released `v1.6.2` tarballs plus pinned public raw MMS client; six SHA-256 pins in `lab/frontier/libiec61850/src/SHA256SUMS` and `PROVENANCE.md` | `cd lab/frontier/libiec61850 && bash run.sh <outdir>` — verifies all six pins, builds both pinned library trees verbatim with explicit ASan, sends raw MMS packets only to 127.0.0.1; new probe: `bash lab/frontier/libiec61850/r4_pointer.sh <abs-outdir>` builds the unsanitized pinned server under gdb and asserts every host address at run time | Frontier replay 2026-11-21: 7 PASS / 0 FAIL rc 0, both three-run groups `sha256=5a7bb6904856d6f8577c06958c66ff9b7721f550701257cf3b427a679bd9d1ce`; clean `git archive e6efd18` replay matched. Real server ASan `WRITE of size 178157` 0 bytes after 65100-byte `sendBuffer` (`iso_connection.c:516`) at `mms_file_service.c:872` ← `:896`; rungs 1/2/3 ESTABLISHED. Rung 4 witness-verified: `r4_pointer.sh` gives 11 PASS / 0 FAIL in the real unsanitized server with gdb ASLR off; staged bytes set `CotpConnection->socket=base+100000` (fake `Socket`, fd 4) and `socketExtensionBuffer=base+101000`, gdb logs `=== CHOSEN SEND self=0x7ffff0029180 buf=0x7ffff0029568 size=16 ===`, and the loopback client receives `03 00 00 10` plus ASCII `IEC61850-R4!`; a second case points the buffer at PIE `main` and sends live code bytes to the client. Both cases SIGABRT after the send. Conforming `poc/exploit_client.c` against fixed v1.6.2 fails `MmsConnection_connect()` and sends no FileOpen/FileRead (no ASan report), so the raw-client AARE-reuse bypass stays preserved as harness-specific, not fix failure. Rung-4 control-flow lane (`167e5db`/`6eeee8e`): `bash lab/frontier/libiec61850/r4_control.sh <abs-outdir>` re-checks the six pins and gives `TOTAL PASS=12 FAIL=0` rc 0. Phase A snapshots the 120000-byte heap region and measures `sendBuffer`, the live `$rbp+8` return slot in `CotpConnection_readToTpktBuffer` and the `LD_PRELOAD` `r4_marker` address; phase B stages a fake `ByteBuffer` at `base+105000` pointing at `retslot-4`, then the second loopback TPKT frame `03 00 00 0c` plus the marker address writes those eight bytes into the return slot. Expected: `=== READBUF … ret=… ===`, `=== MARKER HIT rip=… ===`, `R4_MARKER_EXECUTED`, client `second TPKT frame 0300000c…`, then server fault. GOT overwrite is a preserved negative (read-only RELRO), and the marker is lab-injected, not chosen code. Witness #962/#984/#982 replayed all three probes from a clean archive, all ESTABLISHED AS CLAIMED at the labeled grade. No ASLR defeat, RCE or persistence; grade ◐. |
| OpenJpeg2Shell | [brief](../reports/frontier-openjpeg2shell.md) | OSV-2025-219 / OSS-Fuzz 403673832 records, upstream issue #1620 and fix PR #1621, fix commit `91d08b11` (upstream master, no tagged release), full v2.5.4 / fixed-pin tarballs and the public 202-byte PoC; eight SHA-256 pins in `lab/frontier/openjpeg2shell/src/SHA256SUMS` and `PROVENANCE.md` | `cd lab/frontier/openjpeg2shell && bash run.sh <outdir>` — verifies all eight pins, builds pinned v2.5.4 and fixed `91d08b11` verbatim with ASan, runs the real `opj_decompress` chain, gdb readback and the pad variant; `bash pillow-consumer.sh <outdir>` and `bash groom.sh <outdir>` for the consumer and padding-sweep lanes; `bash otype-takeover.sh <outdir> [HEXADDR]` for the live-object lane; `bash chosen-call.sh <outdir>` and `bash got-target.sh <outdir>` for the two natural-call limbs | Witness #955 clean-archive replay of 958b319: 10 PASS / 0 FAIL rc 0, trace `sha256=6983a6a11c8236c6e991e15faa326b4c64f6269cf7f5f4fabca081bf7aa111ea`, 8 pins OK, ASan `WRITE of size 8` at pinned `j2k.c:5086` through the real `opj_decompress` chain, fixed `91d08b11` clean; two one-byte counterexamples confirm the TLM/SOT mismatch is causal. Verdict #958 ESTABLISHED AS CLAIMED (rung 4 INSTRUMENTED, no pointer/flow/execution), one citation NIT in #957; #1022 ESTABLISHED the consumer-reality claim. `pillow-consumer.sh` (15 PASS / 0 FAIL, trace `sha256=4903f4dc2468a38d5ca1244cd205b36ee6cc0c52b7e43e62e9d0f2370f7596e0`): `Image.open().load()` on the public and padded PoCs through the shipped Pillow 12.2.0 wheel (bundled libopenjp2 2.5.4) aborts rc 134 `corrupted size vs. prev_size`, benign image rc 0; a pinned 2.5.4 build under Pillow gives ASan `WRITE of size 8` at `j2k.c:5086` with a `Jpeg2KDecode.c:794 → Image.load()` stack, fixed pin clean. `groom.sh` (5 PASS / 0 FAIL, trace `sha256=2c4ca81dc6c31e97969c9a203c8125fe02cfc04e13c0871193027a95204a7dd6`) sweeps COM padding that sets the live `m_mct_records` size word to `0xb1..0xc1`, choosing rc 0 (`0xb1`/`0xc0`/`0xc1`), `munmap_chunk` rc 134 (`0xb2` etc), `free(): invalid size` rc 134 (`0xb8`/`0xb9`) or SIGSEGV rc 139 (`0xb4` etc); fixed pin clean. `d167302`/`a66f4c1` only made the gdb paths and derived `poc-pad.j2k` portable for clean-archive replay. Live-object lane (`cad1baf`, `4df17d7`, author-only): `otype-takeover.sh` builds its own `-g -O0` pinned libopenjp2, checks the live object's pre-write `ob_type` against a gdb-resolved CPython static type and the persisted written value; 4 PASS / 0 FAIL, trace `sha256=769e135ebe26f9cb8e482c6c1531718ab1e8e7f2588ddd6174595b5367082f77`, chosen `0xa3bf20` (`&PyLong_Type`) written into `ob_type` with ASLR on; no deallocator call in that lane. Two later limbs reach the natural call (`a351c20`, `f61644f`; commands and invariants in the addenda below): a chosen existing static type's `tp_dealloc`, and a GOT-chosen unresolved `system` PLT stub with a NUL argument. Both stay INSTRUMENTED/PARTIAL with no chosen argument, continuation into `system`, shell or listener; rung 5 UNKNOWN. Witness #1151 ESTABLISHED both limbs at their labeled scope (one non-grade-changing `LOAD_OK` harness nit on #1144). |
| WolfSsl2Shell | [brief](../reports/frontier-wolfssl2shell.md), [consumer](../reports/wolfssl2shell-consumer-reality.md) | CVE-2026-6679 / GHSA-c9q2-5c67-xg9p records, fix PR `wolfSSL/wolfssl#10116`, full `v5.9.0-stable` and `v5.9.1-stable` tarballs plus PR diff and CVE JSON; four SHA-256 pins in `lab/frontier/wolfssl2shell/src/SHA256SUMS` and `PROVENANCE.md` | `cd lab/frontier/wolfssl2shell && bash run.sh <outdir>` — verifies all four pins, builds pinned v5.9.0 verbatim with ASan and the tagged v5.9.1 control, drives 4097 real `Dtls13RtxAddAck` inserts, then `bash chosen_readback.sh <outdir>` for the staged-heap chosen bytes; wire-fill lane in `loopback/loopback_frag_sender.py` | Witness #985 clean-archive replay of `fdc7e80`: 4/4 pins OK, 13 PASS / 0 FAIL rc 0, trace `sha256=fb6831dc85fe7afeaaf688ac519a49bccde954a03159211fb256247c1c7ac05d`, chosen_readback 6 PASS, ASan `WRITE of size 8` at pinned `dtls13.c:2604` through `c64toa`, fixed tagged 5.9.1 capped at 128 and clean. Verdict #985/#992 ESTABLISHED AS CLAIMED (rung 4 INSTRUMENTED, no pointer/flow/execution). Loopback consumer-reality lane (author-only): a real pinned v5.9.0 DTLS 1.3 server on 127.0.0.1 completes a real client handshake (`FACT real_client_connect_ret=1 tries=1`, server `accept_ret=1 … done=1 unified=1`, record version fefc); an earlier 4100-KeyUpdate attempt was gated (446 `Dtls13RecordRecvd` hits, only 2 ACK writes, same-port artifact excluded, `ack_count` stayed 0). The later wire-fill run (`8636e5d`) paces 4097 distinct loopback handshake fragments through real `Dtls13RecordRecvd` to `ack_count=4097` with no intervening flush and ASan `WRITE of size 8` at `c64toa misc.c:1010` via `Dtls13WriteAckMessage:2604` ← `SendDtls13Ack:2899` ← `Dtls13RtxTimeout:2748`; fixed 5.9.1 caps at 128 and is clean. Conditions: lab flags `early13`/`unified_seen`, paced fragments; the failed peer-set unified-header variant (`fde4360`) peaked at 3991/3983 without wrap and is preserved as a negative. Remote fill is demonstrated, not UNKNOWN; no live neighbour, pointer, control-flow diversion or execution. |
| Htslib2Shell | [brief](../reports/frontier-htslib2shell.md) | CVE-2026-62257 / GHSA-6q7c-m967-9v37 records, fix commits `d66a77d` / `c0b5037` / `a3e8dca` and full tagged 1.23.1 / 1.24 tarballs; ten SHA-256 pins in `lab/frontier/htslib2shell/src/SHA256SUMS` and `PROVENANCE.md` | `cd lab/frontier/htslib2shell && bash run.sh <outdir>` — verifies all ten pins, rebuilds both tagged releases verbatim with ASan and drives real `cram_decoder_init`/`cram_xpack_get_block` to the OOB pointer slot; real-file lane: `cd realfile && ./mkcram tiny.sam base.cram && ./inject base.cram crafted.cram` then `./htsfile-asan -c crafted.cram`; crafted2 lane: `./inject2 base.cram crafted2.cram` then `./htsfile-asan -c crafted2.cram`; `cd parserpath && ./parser-asan` | Witness #1008 clean-archive replay of `bced853` with an offline rebuild: 10/10 pins, 9 PASS / 0 FAIL rc 0, trace `sha256=42c561cda4f9eba151b3b8b0fe2d1d6fe201eeca5e5fb7ef6a0b656a94798a54` at current HEAD after the rung-1 PASS-label correction (witness #1008 replayed the pre-fix script at `sha256=40f5992496d13bfc3b575625a5b6bb6e8dfbd1eb397b8b5b25ced7458c04f464`, same 9 PASS / 0 FAIL; #1044 re-replayed the corrected script from a clean archive with an exact trace match and the corrected PASS label, no grade change), ASan `READ`/`WRITE of size 8` at `cram_codecs.c:1378`/`:1388`, fixed 1.24 rejects codec 51; index-1025 negative preserved. Harness rung 4 INSTRUMENTED only. Real-file lane (author-only): `base.cram` 460 B `b57f4386…3cd1` and `crafted.cram` 523 B `992c43d8…67f7` are made with htslib's own writer/APIs; `ASAN_OPTIONS=detect_leaks=0:halt_on_error=0 ./htsfile-asan -c crafted.cram` reports three heap-buffer-overflows at one address 8 bytes past the 4096-byte region allocated at `cram_io.c:4620`: `READ of size 8` at `cram_codecs.c:1378`, `WRITE of size 8` at `:1388`, `READ of size 8` at `:1417`, stack `cram_decode_seq:1616 → cram_decode_slice:2918 → sam_read1:4273 → htsfile.c:92`; identify mode without `-c` is the negative. `parserpath/parser-asan` feeds 17 real compression-header wire bytes (`ncodecs=2`, `codec_id=1`, index 513). Rung-1 correction: for the `codec_id=1` file the OOB slot is a non-NULL chunk-size word (`0x1011` in htsfile, `0x61` in the parser harness), so `:1379` early-returns without writing and plain `htsfile-plain -c crafted.cram` segfaults at `:1422` rc 139 — the ASan WRITE fires only because the redzone reads zero; the inherited unsanitized-OOB-write claim is retracted for that file only. The committed `crafted2.cram` (523 B) instead derives `codec_id=2` from BF-before-QS file bytes, reads NULL at index 514 and fires the unsanitized `:1388` pointer store in a plain build (`crafted2.gdb-write.log`, `crafted2.asan.stderr`); `tracemalloc.c`/`malloc-trace.txt` identify the overwritten neighbour as the same slice's live `s->cigar` array (`cram_io.c:4633-34`), but consumer order rewrites those entries at `cram_decode.c:1776-1813` before `bam_set1`, so no consumed-neighbour claim. Witness #1053 independently ESTABLISHED the codec_id=2/514 plain-build store from its own build of the committed file, with no chosen value or neighbour claim. The whole-file 1.24 control fails container CRC even on `base.cram`; do not cite it — only the harness-level codec-51 rejection is clean. |
| CivetWeb2Shell | [brief](../reports/frontier-civetweb2shell.md) | CVE-2025-55763 records (MITRE, CISA-ADP), public `krispybyte` PoC, fix PR `civetweb/civetweb#1347` merged as commit `c584455` (**no tagged fixed release**), full tagged v1.16 / merged-commit tarballs; four SHA-256 pins in `lab/frontier/civetweb2shell/src/SHA256SUMS` and `PROVENANCE.md` | `cd lab/frontier/civetweb2shell && bash run.sh <outdir>` — verifies all four pins, rebuilds both sides offline with `make TEST_ASAN=1 NO_SSL=1` (clang ASan), sends the crafted request only to 127.0.0.1 and preserves short-path, long-query and published-PoC negatives; unmodified-build lanes: `bash run-natural.sh <outdir>` and `bash run-header.sh <outdir>` | Witness #1027/#1029 clean-archive replay of `7164a1a`: 4/4 pins, 23 PASS / 0 FAIL rc 0, trace `sha256=2ecaac759e4230f9549507091cff212adb68dd63e650d3abf6ced2406e5e2d50` exact, ASan `WRITE of size 2` at `civetweb.c:15261` 0 bytes after an 8197-byte region, fixed merged `c584455` build ASan clean with 301; rungs 1/2/3 ESTABLISHED at sink level, rung 4 INSTRUMENTED. W81 tape #1026 replayed the same clean `git archive 7164a1a` into `/tmp/w81-cw-src` with 23 PASS / 0 FAIL, exact `TRACE_SHA256`, 4/4 pins and no NIT — ESTABLISHED AS CLAIMED. Unmodified-build measurements (author-only): `run-natural.sh` (`f6c542a`) shows natural heap adjacency and `run-header.sh` (`cb75a02`) chosen bytes overwriting a live heap header in the shipping build; logs under `lab/frontier/civetweb2shell/w3/`, no instrumented canary. No chosen pointer, control-flow diversion or execution. |
| Open625412Shell | [brief](../reports/frontier-open625412shell.md) | CVE-2026-126962 / GHSA-x8hf-mwqg-74x6 / ZDI-26-990 records, fix commits `2da371bc` / `bc30df3a` and full tagged 1.5.4 / 1.5.6 tarballs; four source/patch pins in `lab/frontier/open625412shell/pins/SHA256SUMS` and two tarballs in `src/SHA256SUMS`, URLs in `PROVENANCE.md` | `cd lab/frontier/open625412shell && bash run.sh <outdir>` — verifies the tarball manifest, rebuilds both tagged trees verbatim with CMake/ASan, compiles `uaf_harness.c` against each and drives real service calls; starts no listener; `bash groom.sh <outdir>` for the live-neighbour lanes | operator admission replay ~17:49Z: 4/4 committed pins OK, 8 PASS / 0 FAIL rc 0, trace `sha256=31e535b91ae2375978344c27b33b25b38fd9dda9f096ccf96e001672dff71284`; ASan `WRITE of size 8` at `ua_subscription.c:1645`, fixed 1.5.6 clean; rungs 1/2/3 ESTABLISHED at labeled grades, rung 4 INSTRUMENTED. Live-neighbour lanes (`17de7c0`, `f167900`, author-only): `groom_harness.c` / `groom2_harness.c` put the stale `LIST_REMOVE` write on byte 200 of a live replacement subscription; with two items its head changes `0x514000000840` → `0x514000000440`, an item owned by the still-live transferred subscription (`crossSubscription=1`); trace `sha256=c9413debe7063af6287dc2478c5dac8a9204d62f501a35d3ad6eddbb3917660c`. Values come from created objects, not attacker-chosen bytes; ASan quarantine is disabled for same-chunk recycling; no control-flow diversion or execution. |
| KnotResolver2Shell | [brief](../reports/frontier-knotresolver2shell.md), [rung-3 report](../reports/knotresolver2shell-rung3.md) | CVE-2026-66374 MITRE record, oss-sec q3/226 and /234, vendor 6.4.1 NEWS; fix commit `7eb2e118` contained in tagged v6.4.1 (compare ahead 11 / behind 0); hash-pinned tagged 6.4.0 (`e8e771de…58fc3`) / 6.4.1 (`20eb8b31…902950`) tarballs and fix patch (`d40555c4…d73ce`), three SHA-256 pins in `lab/frontier/knotresolver2shell/src/SHA256SUMS`, URLs in `PROVENANCE.md` | Rung 3: extract the pinned tarballs under `lab/frontier/knotresolver2shell/build/`, comment `subdir('policy')` out of `modules/meson.build` (absent git submodule) and install a Lua stub; `meson setup asan-build -Db_sanitize=address -Dmalloc=disabled -Dquic=embedded --buildtype=debug` and `ninja -C asan-build` (254/254 each). Then `bash lab/frontier/knotresolver2shell/harness/run_replay.sh 6.4.0 8853` and `bash … 6.4.1 8854` — loopback-only DoQ listeners, six public STREAM frames from `harness/asan_replay.py` (aioquic 1.8.0) | Operator pin verification ~18:03Z: `cd lab/frontier/knotresolver2shell/src && sha256sum -c SHA256SUMS` → 3/3 OK. Rung 3 (commit `bebef9b`): vulnerable 6.4.0 reports ASan `WRITE of size 1198` at `daemon/quic_conn.c:124` past a 5762-byte `realloc` at `:103` (`harness/asan-6.4.0.2926826`) plus a downstream `wire_buf_movestart` READ; fixed 6.4.1 rejects frame 2 `invalid payload size, malformed data` with no ASan report; per-frame drift in `harness/drift.log`. Witness W87 replayed the same bytes from a clean `3f6622b` archive with its own builds and pins (3/3 OK, ports 18853/18854): rung 3 ESTABLISHED IN FULL. Earlier rung-4 approach, not control: chosen `0x4141414141414141` was written into two live `ngtcp2_pktns` comparator fields, but a wake-5 read watchpoint on the second field's `search` slot at `slot1+0xa8` never stopped and no dispatch followed; no handler overwrite, RIP/RDI control or ASLR-off exploit was seen, so the published `system()` PoC stays an attributed claim, not run. Wake 6 (`2a3ca7f`) reached rung 4: two distinct chosen values at live gnutls-session offsets `+0x100`/`+0x110` became the `rsi` argument of `gnutls_deinit()` from `quic_conn.c:884`; witness #1138 replayed the committed harness at 20:52–20:56Z and returned ESTABLISHED at that labeled scope with a varied-marker control (see the rung-4 addendum). Still no RIP control, benign marker or command. |
| ATS2Shell | [brief](../reports/frontier-ats2shell.md) | CVE-2026-58154 MITRE record (CNA Apache, 2026-07-29, CWE-787, CVSS 8.9), vendor security-2026-07.html and oss-sec /2026/q3/338; master fix `f4561a94` / 10.1.x backport `5642692b` an ancestor of tag 10.1.4 (ahead 128 / behind 0); hash-pinned tagged 10.1.3 (`b9230200…45d843a`) / 10.1.4 (`47f09c65…b6f9d9f`) tarballs, two published sha512 sidecars and fix patch (`6a6626f8…e178092`), five SHA-256 pins in `lab/frontier/ats2shell/src/SHA256SUMS`, URLs in `PROVENANCE.md` | RUNG 0 — no build, no trigger, no replay yet. Harness owed: ASan-build the pinned 10.1.3 / 10.1.4 MIMEScanner unit tests and replay the fix patch's two-fragment input (`"Foo: bar\r"` then `"\n baz\r\n"`); expect ASan `WRITE of size 1` value `0x20` at `input.data()-1` on 10.1.3 and clean `OK` / `shares_input == false` on 10.1.4. Record the address relative to the allocation base before claiming an underflow; witness replay owed once the harness is committed. |
| Exim2Shell | [brief](../reports/frontier-exim2shell.md), [wake-1 report](../reports/exim2shell-wake1.md), [wake-2 report](../reports/exim2shell-wake2.md) | CVE-2026-45185 MITRE record (CNA MITRE, 2026-05-12, CWE-416, CVSS 9.8), vendor `EXIM-Security-2026-05-01.1.txt` and XBOW blog (claim); hash-pinned 4.99.2 (`e9e33c8c…da84`) / 4.99.3 (`714efe07…2524`) tarballs, two self-computed SHA-256 pins in `lab/frontier/exim2shell/src/SHA256SUMS` (no published sidecar), fix commit ID UNKNOWN | RUNG 3 — build both pinned trees with GnuTLS + ASan (`USE_GNUTLS=yes`); from `lab/frontier/exim2shell`, run `ASAN_OPTIONS='log_path=$PWD/build-4.99.2/asan-report:abort_on_error=1:detect_leaks=0' src/exim-4.99.2/build-Linux-x86_64/exim -bd -oX 25252` then `python3 trigger.py 25252 three` (fixed control: same `ASAN_OPTIONS` under `build-4.99.3/`, port 25253, configured with `configure.loopback`). The `log_path` is required because the forked child closes stderr. Expect ASan `heap-use-after-free WRITE of size 1` at `tls.c:510 in tls_ungetc` via `receive_msg receive.c:2141`, 8 bytes into a freed 4104-byte region; the fixed daemon with identical bytes creates no `asan-report.*`. The wake-1 `ungetc|two|three|four` shapes are NEGATIVE. | Operator admission 19:44Z `sha256sum -c SHA256SUMS` 2/2 OK; witness #1140 (DM 4727) replayed rung 3 from its own ASan-linked pinned binaries (4.99.2 sha `e5ac0b00…`, 4.99.3 sha `c2298c16…`) on loopback 27252/27253 (both confirmed 127.0.0.1) with identical trigger bytes and returned ESTABLISHED as claimed; no rung 4. The stderr/`ASAN_OPTIONS` gotcha is documented in the wake-2 report; the citation fix at report lines 53/60 was applied in `a6fbe8e` (`tls-gnu.c:3972` not `:3976`, `tls_getc` at `:3998` not `:4002`), grade unchanged. A plain 4.99.2 trace at `receive.c:2141` with five wire variants on loopback 25262 calls safe `smtp_ungetc` because `tls_close()` installs it before the header parser and `bdat_pop_receive_functions()` restores `tls_ungetc` later: a build-dependent consumer-ordering NEGATIVE, no chosen byte and no rung 4. A one-run fixed-control bind to `0.0.0.0:25253` was corrected to `127.0.0.1` with no external contact. Raw `build-4.99.*/asan-report.*`, `trigger-*.log` and non-ASan traces are gitignored and regenerate with those commands. |
| NettyTcnative2Shell | [brief](../reports/frontier-netty2shell.md) | CVE-2026-116539 / GHSA-gf9q-9mg7-g5qh maintainer advisory, Debian tracker and NVD-derived GHSA-22qq-f4wc-4vfx; fix commit `92dd66fd1243d85c05a61288f96367a70260b6b8`; hash-pinned 2.0.83.Final (`f6ae09cf…335`) / 2.0.84.Final (`cb419d01…f0`) tarballs and fix patch (`b5133346…7ec`), three SHA-256 pins in `lab/frontier/netty2shell/src/SHA256SUMS`, URLs in `PROVENANCE.md` | RUNG 0 — no build, no trigger, no replay yet. Harness owed: build `openssl-dynamic` at both tags, port the advisory's four-step JNI harness (10-byte ring) to Linux under ASan; expect `heap-buffer-overflow WRITE` at the `tcn_write_to_bytebuffer` sink (`ssl.c:207-209`) on 2.0.83.Final and a clean modulo path on 2.0.84.Final | Operator admission 20:30:34Z: `cd lab/frontier/netty2shell/src && sha256sum -c SHA256SUMS` 3/3 OK (self-computed; no published sidecar); witness replay owed once a harness exists. Wire-only engine reachability stays UNKNOWN until measured. |
| WAMR2Shell | [brief](../reports/frontier-wamr2shell.md), [rung-4 variant](../reports/wamr2shell-rung4.md) | CVE-2026-54912 / GHSA-jjv3-x3jf-cg49 maintainer advisory, CVE record and OSV; fix commit `b1353b5e8983047ff68829c99abf1355d5f389cf`; five self-computed SHA-256 pins in `lab/frontier/wamr2shell/src/SHA256SUMS` (2.4.4/2.4.5 `wasm_loader.c`, patch, upstream regression `.wasm`/`.wat`), URLs in `PROVENANCE.md` | RUNG 3 — build both pinned tags with `-DWAMR_BUILD_FAST_INTERP=1`, ASan and debug symbols, then `iwasm -f test src/const_table_overflow.wasm` (load-only variant also replayed). Expect on 2.4.4 exit 134 with ASan `WRITE of size 2` 0 bytes past a 1020-byte region at pinned `wasm_runtime_common.h:68` ← `wasm_loader_emit_int16 wasm_loader.c:9420` ← `reserve_block_ret :10449` ← `wasm_loader_prepare_bytecode :12450`; on 2.4.5 no load-time ASan fault (post-load CLI/native-stack failures only, unchanged by 64 MB `ulimit -s`). Rung-4 probe: apply committed `instr-overflow.patch` to a copy of 2.4.4 and inspect `out-instr-oob.txt` — 61 would-be OOB writes, 38 two-byte const-table indices and 23 eight-byte host branch pointers, no attacker-chosen immediate past the end. Chosen-immediate variant: `python3 lab/frontier/wamr2shell/make_chosen_variant.py OUT 4142434445464700 8` then `iwasm -f test OUT` on the instrumented 2.4.4 build; expect four `WAMR_OOB tag=const size=8` lines at 11/29/47/65 bytes past `p_code_compiled_end` and a real ASan `WRITE of size 8` in `wasm_loader_emit_const :9382` on the unmodified 2.4.4 build, clean 2.4.5. | Witness W91 (#1145–1147, verdict to docs #1147) ESTABLISHED rungs 1–3 and the rung-4 negative independently: 5/5 pins, its own ASan builds of both pinned tags, exact pinned-PoC trace on its own binaries (2.4.4 exit 134, `WRITE of size 2` 0 bytes past a 1020-byte region; 2.4.5 zero ASan errors), and the 61-write instrumented log; no nit. That negative is scoped to the exact upstream PoC. WAMR has no in-tree listener, but Envoy v1.39.3 is a named network-to-`wasm_runtime_load` consumer that is NOT built or driven here. The binary-patched chosen-immediate shape (`0160f40`) is an author claim with witness replay owed; rung 5 stays UNKNOWN. Raw ASan traces `out-asan-2.4.4.txt`, `out-asan-2.4.5*.txt` and `out-instr-oob.txt` are committed under `lab/frontier/wamr2shell/`; variant outputs and build trees are gitignored. |
| Perl2Shell | [brief](../reports/frontier-perl2shell.md), [rung-3 report](../reports/perl2shell-rung3.md) | CVE-2026-15534 CPAN CVE record and Stig Palmquist's oss-security disclosure (2026-08-09); fixes `568e6fd238867bb9e99fa3f47cba3169009239e0` and `54cf3d44cbbedd17d774e9a37921963e8fd5d0cb`; seven self-computed SHA-256 pins in `lab/frontier/perl2shell/src/SHA256SUMS` (v5.44.0/v5.45.1/v5.45.2 `regexec.c`, v5.45.1/v5.45.2 `regexp.h`, both patches), URLs in `PROVENANCE.md` | RUNG 3 — build pinned 5.45.1 with `./Configure -des -Dusedevel -DDEBUGGING -Doptimize='-g -O1 -fsanitize=address' -Aldflags='-fsanitize=address'` and `make -j2`; from `lab/frontier/perl2shell` run `./perl-5.45.1-asan-vuln -Dr -I./perl-5.45.1/lib repro.pl` (WHILEM 1/15…15/15), `./run-asan.sh ./perl-5.45.1-asan-vuln vuln` and `./run-asan.sh ./perl-5.45.1-asan-fixed fixed`. Expect ASan READ SEGV at `S_regmatch regexec.c:9240`, status 134, PID/address/path-normalised trace `5848bedd…`; a second clean run timed out (STATUS 124, hash `80f27151…`) — layout-dependent, not deterministic on every launch. The fixed 5.45.1+both-patches binary `16ad5003…` gives `rc=0`, `NOMATCH`, no ASan report, trace `5a34efa2…`; its enclosing `make -j2` timed out only after the relink, so full extension rebuild independence is UNKNOWN. The `CACHEsayNO` bit write at `:6504-6507` was not reached: no chosen byte, pointer control or rung 4. Raw `trace-vuln*.txt` / `evidence-vuln*.txt` are committed; build trees are gitignored and regenerate with those commands | Witness W96 (23:01Z, on `5eceee0`) replayed the vulnerable binary `dad42179…` 8/8 at rc 134 with the same READ and independently reproduced the clean fixed control: RUNG 3 ESTABLISHED at the labeled scope, no further replay owed; the witness's fresh-tarball build was cut off mid extension build, so complete clean-build independence stays UNKNOWN |
| MsQuic2Shell | [brief](../reports/frontier-msquic2shell.md), [rung-3 report](../reports/msquic2shell-wake1.md) | CVE-2026-62815 MITRE record (CNA Microsoft 2026-08-11, CVSS 9.8) and GitHub advisory `GHSA-92f5-vc22-8j33` (CVSS 4.0 10.0, unauthenticated pre-auth RCE claim); one-line fix `e0f55b5fdc9fff0b4465976d066ebd22fb7e2b3b`; hash-pinned v2.5.9 (`ccf4170e…5fa38`) / v2.5.10 (`b77be2c9…166d5`) tag archives and fix patch (`c74bfda5…e61af`), three self-computed SHA-256 pins in `lab/frontier/msquic2shell/src/SHA256SUMS`, tag objects and URLs in `PROVENANCE.md` | RUNG 3 — `cd lab/frontier/msquic2shell/src && sha256sum -c SHA256SUMS` (3/3 OK); extract the pinned tarballs to gitignored `lab/frontier/msquic2shell/build/v259` / `v2510`; in each tree `cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DQUIC_BUILD_TEST=OFF -DQUIC_BUILD_TOOLS=OFF -DQUIC_BUILD_PERF=OFF -DQUIC_ENABLE_LOGGING=OFF -DQUIC_STATIC_LINK_CRT=OFF .. && cmake --build . --target core`; compile `build/frame_swap_harness.c` with `cc -DCX_PLATFORM_LINUX -DQUIC_EVENTS_STUB -DQUIC_LOGS_STUB -D_GNU_SOURCE -I<ver>/src/inc -I<ver>/src/core -O2 -DNDEBUG -fms-extensions` plus `platform_stubs.c` against each `bld-rel/obj/Release/libcore.a`. | Expect a 29-byte `NEW_CONNECTION_ID(seq=1, retire_prior_to=1)+PING` payload and, 5/5 each, v259 `AFTER post: count=1 p0(ID=99 inuse=0 active=1) p1(ID=10 inuse=1 active=0)` / `VERDICT: frame-driven stale-slot swap OBSERVED (exit=1)` and v2510 p0 ID 10 unchanged / `NOT OBSERVED (exit=0)`. Witness W97 independently rebuilt both pins (libcore sha `7fc9e325` / `f24611e9`) and replayed 5/5 each with a causal fix-patch control; a Debug core aborts at `connection.c:1140` (`QUIC_CID_VALIDATE_NULL`) — preserved negative. The committed rung-3 harness uses no sockets, TLS or wire packets. A scratch v2.5.9 build with tag-pinned quictls (`b0f05a9`) first hit a wire negative, overturned at `7e3ae5e`: after saving every learned NCI, removing a 50 ms teardown gap and emitting frame type `0x18` (not `0x1a`), a real loopback QUIC/TLS handshake with 1-RTT encryption disabled plus two plaintext short-header datagrams from a second UDP port gives 5/5 wire-pure `WIREPATH post count=1 p0(ID=1 inuse=0 active=1) p1(ID=0 inuse=1 active=0) stale=Paths[0]` and 5/5 fixed-control runs with zero promotions; still rung 3. Witness W101 (#1228) re-extracted both pins to `/tmp/w101-wire`, rebuilt its own Release/quictls servers and wire injector, and replayed 5/5 vulnerable / 5/5 fixed with zero promotions — ESTABLISHED at this scope, no refutation. The `25489f3` chosen-byte probe stays gitignored scratch; its eight PATH_CHALLENGE bytes land at a fixed struct offset, not a chosen address, so rung 4 is unmet. Wire artifacts (`build/v259-wire`, `wire_inject.cpp`, `wire_run.py`, `srv-*.log`) stay gitignored scratch, not regenerated by the committed harness. Builds and logs are gitignored under `build/`, regenerated by the commands above. |
| ProFTPD2Shell | [brief](../reports/frontier-proftpd.md) | CVE-2026-119146 / GHSA-wj68-6748-262r (CNA GitHub_M 2026-10-30, CWE-120, CVSS 3.1 5.6 / CVSS 4.0 6.3), affected `< 1.3.9e` and `< 1.3.10rc5`, fixed 1.3.9e / 1.3.10rc5, fix `502d280b8d0ef72e44c6dd0a35a9405af0a1e301`; hash-pinned tagged 1.3.9d (`68b094b1…e84e4ec`) / 1.3.9e (`7db91f22…cfce5eb`) tarballs and patch (`07cc6b25…e01f045e00d79`) in `lab/frontier/proftpd2shell/src/SHA256SUMS` (3/3 OK at 00:13Z), git-refs `f59f248e…` / `fc3f908a…` / `23803950…`; instrumented source `mod_rewrite.c.instr` tracked in `c754960` for witness rebuild | RUNG 1–4 — `cd lab/frontier/proftpd2shell/src && sha256sum -c SHA256SUMS`; build pinned 1.3.9d with `--with-modules=mod_rewrite --disable-shared` (ASan build: `clang -g -O0 -fsanitize=address`; plain build: `gcc -g2 -O2`), run a non-root daemon bound to 127.0.0.1:21874 with `wire/etc/proftpd.conf`; `bash wire/run-trigger.sh` and `wire/run-bounded.sh` send the 2048-byte and 200-byte keys with `wire/client.py`/`client2.py`; `bash wire/run-marker.sh` under `setarch -R` with `CLIENT=client4.py` sends the 1030-code-point key and expects `RewriteLog` `parsing 'NOOP command successful'`, `NOOP=200`, `PWD=257`. Later limbs: run `run-marker.sh` with `CLIENT=client4.py` and no `setarch -R` for the ASLR-on negative, and `bash wire/run-prelogin.sh` (config `wire/etc/proftpd-prelogin.conf`, client `wire/client5-prelogin.py`) under `setarch -R` for the pre-login marker; expect `501 Login incorrect` on `USER`, marker in `RewriteLog`, no `PASS`, session up. With `wire/client6-partial.py` and `bash wire/run-partial-sweep.sh` (no `setarch -R`), a 1025-code-point key replaces only `substr`'s low byte and gives B-dependent parser-string lengths; `wire/run-partial-control.sh` logs `parsing ''` for a 200-byte key. Raw output under `wire/evidence/` is intentionally not committed and regenerates with those runners | Witness W99 (message #1207) independently built both pins in `/tmp/w99-proftpd` from the tarballs and replayed with only its own binaries: ASan `global-buffer-overflow WRITE of size 8` at `mod_rewrite.c:1670`, 200-byte control clean; uninstrumented `gcc -O2` plain build under `setarch x86_64 -R` with `client4.py` gave the marker, NOOP=200, PWD=257, safe input `parsing ''`; own v1.3.9e ASan build rejects the long key (550, session alive, no ASan file). ALL ESTABLISHED AS CLAIMED at these conditions; rung 5 not attempted. Witness W100 (message #1222) independently replayed the three later limbs with its own uninstrumented `gcc -g2 -O2` build from the pinned 1.3.9d tarball (sha `aae1ec303efe...`) in `/tmp/w100-wire`, loopback only: the ASLR-on negative (SIGSEGV in `pr_vsnprintfl`, no marker, PIE base changed), the `%m USER` pre-login marker (PR:N, ASLR-off, non-default config; 200-char USER control logs `parsing ''`) and the one-byte relative redirect under ASLR on (PR:N, B≈0x01..0xff gives ≈246−B character runs, no stable landing target) are all ESTABLISHED at those labeled scopes; rung 5 unclaimed. Other ASLR-on routes stay UNKNOWN |
| Soes2Shell | [brief](../reports/frontier-soes.md) | hash-pinned `v3.2.0` / `v3.2.1` tag archives and full fix diff in `lab/frontier/soes2shell/src/SHA256SUMS` (digests `24c0cb2f…` / `301d9f19…` / `f54bdd7c…`; 3/3 OK at 00:16Z, recomputed by the mind and W102); advisory RRTL-261119-01, CVE-2026-129794 / CVE-2026-129811 | `bash lab/frontier/soes2shell/harness/build.sh` builds real pinned `esc_eoe.c` / `ecat_slv.c` + `esc_coe.c` with stubs, ASan and plain; no upstream HAL build on this host | `eoe_overflow` with 7×96-byte fragments: ASan `WRITE of size 96` at `esc_eoe.c:797`, plain canary +64 bytes at `+608`; six fragments, real 3.2.1 clean. `pdo_overflow` with 510 mapping bits: ASan `global-buffer-overflow WRITE of size 64` at `ecat_slv.c:172`, plain `SMmap2[0].obj` chosen pointer and real `COE_pdoUnpack()` chosen write; fixed 3.2.1 and modeled-clamp clean. CoE-mailbox harness drives the same write from crafted mailbox bytes through real `ESC_coeprocess`. Wire input is NOT replayed: `ESC_read` bytes and mapping values are harness-supplied; `CapEff=0` blocks AF_PACKET. Witness W102 (#1231) independently re-extracted both pins, rebuilt all 12 binaries with clang 18.1.3 from clean HEAD `e0a004c` and returned ESTABLISHED at exactly this scope with byte-variation and mapping-length sweeps; logs `/tmp/w102-soes/results/*.out`. |
| VRPNShell | [brief](../reports/frontier-vrpn.md) | CVE-2026-123200 (CNA VulnCheck) and VulnCheck advisory; upstream fix `0da5b0b71e06e8c318a4e674c84caee12251a782` and 07.39 cookie bump `c893b583d928fd17d756b39271b2eae71766e7f2`; five SHA-256 pins in `lab/frontier/vrpn2shell/PROVENANCE.md` (CVE record, both patches, pinned `vrpn_Connection.C`, fixed tarball), all five recomputed 5/5 OK by the operator at admission; precise fixed release UNKNOWN, fixed commit pinned | `cd lab/frontier/vrpn2shell && sha256sum src/cve.json src/fix-0da5b0b71e06e8c318a4e674c84caee12251a782.patch src/fix-c893b583d928fd17d756b39271b2eae71766e7f2.patch src/vrpn_Connection.C.pinned src/vrpn-fixed.tar.gz`, compare with the five PROVENANCE digests; CMake `-DCMAKE_CXX_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g'` builds the pinned `v07.36` and `0da5b0b` trees (`cfg-asan.log` / `build-asan.log`, `cfg-fixed.log` / `build-fixed.log`); direct harness `g++ -fsanitize=address -fno-omit-frame-pointer -g -I src/vrpn-07.36 harness/handler_direct.cpp build-asan-07.36/libvrpnserver.a` | RUNG 3 on the real library: `out-direct-01/i*.out` gives ASan `stack-buffer-overflow WRITE of size 1` at `vrpn_Connection.C:4554` for indices 100/128/-256, `out-control-fixed/i*.out` clean at the write site. `out-gdb-01/gdb.log` and `out-gdb-wire-100b/gdb.log` show a real loopback TCP message reaching `handle_sender_message()` (`dispatch:4331` → `doSystemCallbacksFor:1446` → `:4535`), but `out-wire-sweep-02/server.err` has no ASan report: wire rung 3, rung 4 and rung 5 UNKNOWN. A fixed NUL at a chosen offset is not chosen-byte control. |

### 2026-11-21 adjacent-lane replay addenda
- **Libnxml2Shell frontier rung 3 and measured rung-4 ceiling (commit `6b59b35`, NOT admitted, no window)**: `reports/frontier-libnxml.md` pins CVE-2026-123202 / GHSA-mwvf-r58x-mh9m (CNA VulnCheck 2026-11-05, CVSS4 8.7 AV:N, CWE-121), affected `< 0.18.6`, fixed `0.18.6`, fix `fbac242374883edf2ec14127ca6d2accf4704b6a`; tag `0.18.5` (`9272d1cd6fee…`) / `0.18.6` (`a1b63cf1db05…`) tarballs and the patch are SHA-256-pinned in `lab/frontier/libnxml/src/SHA256SUMS` (3/3 OK). In gitignored `lab/frontier/libnxml/build/`, extract each tarball and run `autoreconf -fi`, then `CC=clang CFLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address' ./configure --disable-shared --enable-static && make -j4`; from `lab/frontier/libnxml` compile `clang -g -O0 -fsanitize=address -fno-omit-frame-pointer -Ibuild/libnxml-0.18.5/src -o harness/bin/name_overflow-0.18.5 harness/name_overflow.c build/libnxml-0.18.5/src/.libs/libnxml.a -lcurl` (likewise 0.18.6) and run `ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./harness/bin/name_overflow-0.18.5 1022 <mode>` for modes 0–4. Expect 5/5 ASan `stack-buffer-overflow`, `WRITE of size 4` at `nxml_parser.c:942` / `:839` / `:195` / `:521` / `:419`, 5/5 pinned 0.18.6 clean and 5/5 safe-input N=1000 clean. Non-ASan gdb layout (`harness/layout.py`, break at `i == 1022`) shows a four-byte maximum spill into padding, nearest live local `err` at +4 in `get_tag`, and `tag` at +0 in `close` reassigned by `calloc()` after the copy: rung 4 BLOCKED on this clang `-O0` host build, even the theoretical five-byte width cannot reach +4 locals, other layouts UNKNOWN. Raw `harness/v185-*.out`, `v186-*.out`, `gdb-layout*.out` are gitignored and regenerated by these commands.
- **Libnxml2Shell witness W97 replay (commit `da62639`)**: the witness
  independently rebuilt both pinned tarballs and re-ran the committed harness
  from the preceding addendum: 5/5 vulnerable-mode ASan `WRITE of size 4` at
  the five cited `nxml_parser.c` lines, 5/5 pinned-0.18.6 clean, 5/5
  safe-input clean, and a non-ASan layout check reproducing the +4-locals
  ceiling. Verdict RUNG 3 ESTABLISHED AS CLAIMED, no refutation. The report's
  write-index sentence was corrected: a five-byte name character writes
  offsets 1022-1026 with NUL at 1027; the observed four-byte case writes
  1022-1025 with NUL at 1026; neither reaches the nearest live local. Grade,
  replay command and gitignored-log policy are unchanged.
- **Exim2Shell wake-2 heap UAF write, rung 3 (commit `671a3b2`; witness #1140 ESTABLISHED)**: `reports/exim2shell-wake2.md` records why wake 1 saw no ASan report — Exim closes the forked child's stderr, so the replay needs `ASAN_OPTIONS='log_path=$PWD/build-4.99.2/asan-report:abort_on_error=1:detect_leaks=0'` on `src/exim-4.99.2/build-Linux-x86_64/exim -bd -oX 25252` followed by `python3 trigger.py 25252 three` from `lab/frontier/exim2shell`. Expect `heap-use-after-free`, `WRITE of size 1` at `tls.c:510 in tls_ungetc` via `receive_msg receive.c:2141`, 8 bytes into a freed 4104-byte region; temporary instrumented traces showed the free at `tls-gnu.c:639` with `lwm=1` and the stale write at `xfer_buffer[0]`, then were reverted (`strings … | grep -c EXIM2SHELL` → 0). Identical bytes on 4.99.3 (port 25253, `configure.loopback` binding only 127.0.0.1) create no `asan-report.*`. The non-ASan `chosen N CH` probe sees the free and its wake-3 trace at `receive.c:2141` with five wire variants on port 25262 calls safe `smtp_ungetc` — the pointer installed by `tls_close()` before the header parser — with `tls_ungetc` restored only by `bdat_pop_receive_functions()` afterwards. No stale write, chosen value/offset or rung 4; raw logs are gitignored and regenerate with these commands. Witness #1140 (DM 4727) replayed the trigger from its own ASan-linked pinned binaries on loopback 27252/27253, matched the fault and the fixed-side clean control, and returned rung 3 ESTABLISHED as claimed; its citation corrections were applied in `a6fbe8e` (`tls-gnu.c:3972`, `tls_getc :3998`), grade unchanged.
- **WAMR2Shell W90 rungs 1–3 locally reproduced, rung-4 probe NEGATIVE (commit `8686e9d`; witness W91 ESTABLISHED)**: `reports/frontier-wamr2shell.md` records CMake builds of tagged 2.4.4/2.4.5 with `-DWAMR_BUILD_FAST_INTERP=1`, ASan and debug symbols, then `iwasm -f test src/const_table_overflow.wasm`. Expect on 2.4.4 exit 134, ASan `WRITE of size 2` 0 bytes past a 1020-byte region with the pinned-tag stack `STORE_U16 wasm_runtime_common.h:68` ← `wasm_loader_emit_int16 wasm_loader.c:9420` ← `reserve_block_ret :10449` ← `wasm_loader_prepare_bytecode :12450`; the committed traces are `lab/frontier/wamr2shell/out-asan-2.4.4.txt` and `out-asan-2.4.5*.txt`, and fixed 2.4.5 has no load-time fault (post-load CLI/native-stack failures only, unchanged by 64 MB `ulimit -s`). The instrumented Pass-2 log (`out-instr-oob.txt`, from committed `instr-overflow.patch`) lists 61 would-be OOB writes — 38 two-byte const-table indices and 23 eight-byte host branch pointers — with no chosen immediate past the end, so this exact upstream-PoC shape is a measured rung-4 negative; a different binary-patched shape with chosen immediates is a separate author claim below, and rung 5 is UNKNOWN (no in-tree listener; Envoy named but not driven). Build trees are gitignored, traces committed. Witness W91 rebuilt both pinned tags, matched the exact fault, clean control and 61-write log on its own binaries, and returned ESTABLISHED at that scope with no nit.
- **Pillow2Shell W9 minimal chosen-deallocator (commits `249281e`, `f553b84`)**: from a plain Pillow 12.2.0 build, `PILLOW_BUILD=<v12plain> bash lab/pillow2shell/replay_min.sh <abs-outdir>` (or the script's `--build <sdist>` form) checks `case_min.fpx` (SHA-256 `d0eb87b9dd6ce922ef97bf4007766384491b228a19d81dcf8cce045337b46722`) against `case_min_ctrl.fpx` (`83c4758b…`): expect `TOTAL PASS=8 FAIL=0`, `AFTER_TYPE=a2d260`, `HIT pc=0x54e700 rdi=buffer+176` with `#7 Py_FinalizeEx()`, control never at `0x54e700`, ASLR left on (`set disable-randomization off` is NOT used). The 64x1 tile/47-wide 4-component image writes only 60 bytes past the 128-byte tile; the only file-carried address is the static `&PyCode_Type`. Witness #1048 replayed from a clean `249281e` archive with its own build, 8 PASS / 0 FAIL, three distinct heap bases and marker 3/3, ESTABLISHED AS CLAIMED at ◐. Its two non-material NITs are repaired at `f553b84`: explicit `PILLOW_BUILD` now wins over the default `CANON=/tmp/pw2-w9/v12plain` symlink instead of being silently overridden, and the control gdb script no longer prints a false `HIT pc=` at a SIGSEGV stop (`!HIT pc=` is now asserted). No chosen-code execution, ROP, PC write or ASLR bypass.
- **RabbitMQC2Shell real high-level publisher NEGATIVE (commit `dfc0b1b`)**: `bash lab/rabbitmqc2shell/run_real_tool.sh <abs-outdir>` builds pinned v0.16.0 and the unmodified `amqp-publish` with ASan and runs `real_tool_probe.py` against a loopback-only AMQP 0-9-1 front end; expect 11 PASS / 0 FAIL, six source pins OK, negotiated `frame_max=131072`, a 200000-byte `0x5a` body emitted as two BODY frames (131060 + 68940), client rc 0 and no ASan report. Source reason: `amqp_api.c:167-168/:223-241` caps each body frame to `frame_max-12` inside the `frame_max` buffer from `amqp_connection.c:108-142`, so `amqp_send_frame` at `:467` cannot overflow via `amqp_basic_publish`. This narrows the real-application UNKNOWN; it does not retract the witness-verified direct-API harness and service results. A real frame-level proxy/gateway remains UNPROVEN.
- **OpenJpeg2Shell W9 non-transfer and large TPsot (commit `772d40b`)**: the transfer check is source-based — `j2k.c:5086/:5088` writes bounded `OPJ_OFF_T` stream offsets consumed as seek integers (`j2k.c:8464`, `:12054`, `:12195`, `:9928`), never as a pointer; a non-PIE-shaped value needs roughly 10.6 MB of COM padding, and no Python object with a plausible `ob_type` was found at a reachable destination. Large TPsot replay: `python3 lab/frontier/openjpeg2shell/make-large-tpsot.py src/poc.j2k /tmp/oj.j2k $((0x58530e)) 188`, then `gdb -q -batch -ex 'set $want=188' -x large-tpsot.gdb --args python3 pillow-probe.py /tmp/oj.j2k` with `PILROOT`/`LD_LIBRARY_PATH` pointing at a pinned debug lib build (generator SHA-256 `a04bf6b54205d8d9f1b533c6b574b38e218f551634b4d842ce41c9a2367f0965`, gdb script `0928fa589b66aed23a0ba65f76d3b29845ded50212bda0f910effc937adac04e`). Expect `TPSNO=188 POS=2048` in the short-pad form and a code-shaped value `0x58530e`/`0x585310` written at base+4520/+4528 in the 5,786,655-byte pad form; neighbouring code pointers vary under ASLR and the plain no-gdb run faults rc 139. No pointer control or indirect call; rung 4 stays PARTIAL.
- **CivetWeb2Shell wake-1 chosen-byte neighbour (repair `b9bd4ee`)**: witness #1050 could not replay this limb because the W1 scripts were untracked; the bounded repair is now committed and works from a clean archive: `cd lab/frontier/civetweb2shell && bash run-rung4.sh <abs-outdir>` → 19 PASS / 0 FAIL rc 0, trace `sha256=6678d7a905e7899dd5f7e1e62dcfd5fcee4018065880fddbebaa709b9e0be3d2`. It verifies the pinned v1.16 tarball, rebuilds offline with `WITH_CFLAGS=-U_FORTIFY_SOURCE NO_SSL=1`, applies an embedded 33-line canary patch to a second copy, and checks the allocator abort, canary offsets 8208/8240/8256 and chosen bytes (`GHIJKLMNOPQRSTUVWXYZ0123456789\0` from full-query byte 8, 32 × `C`) with loopback-only listeners. Raw wake-1 logs are committed under `w1/instr-out/q=*/server.out` and `w1/nofortify-out/q*/server.out`; the patch is instrumentation, not natural adjacency. No independent verdict yet, so the limb remains author-observed at the INSTRUMENTED grade; RCE stays unverified.
- **WolfSsl2Shell live-ACK chosen bytes, real cleanup abort and pointer ceiling (commits `45d3041`, `8fd20f5`)**: from the pinned plain v5.9.0 build in `lab/frontier/wolfssl2shell`, build the sixth/seventh-wake server with `gcc -g -O0 -Ibuild/wolfssl-5.9.0-plain loopback_server.c build/wolfssl-5.9.0-plain/src/.libs/libwolfssl.a -lm -lpthread -o out/loopback/server-groom`, then `gdb -q -batch -x groom_abort.gdb ./out/loopback/server-groom > out/loopback/groom-abort-gdb.log 2>&1 &` and `python3 loopback_frag_sender.py 18635 4097 0 1024 1200`. Expect the live `seenRecords` head chunk size at `0x…b238` and `next` at `0x…b250` overwritten from the sender's sequence bytes, then `double free or corruption (out)` rc 134 through `_int_free_merge_chunk` ← `wolfSSL_Free` ← `Dtls13RtxFlushAcks dtls13.c:780` ← `wolfSSL_accept`; a chosen `seq_base=0x20ffffffff71` gives size `0x2100` and aborts `!prev`. Ceiling probe: `bash run_groom_size.sh 18644 0 out/loopback/groom-size-control.log` and `bash run_groom_size.sh 18645 20ffffffff71 out/loopback/groom-size-21.log` — across three bases every size low byte is zero and every `next` is NULL. Preconditions: `early13`, `unified_seen`, `pregrow=64`, 4097 fragments paced 1200 us, loopback only; tagged v5.9.1 with the same wrapper shows no abort. Raw logs are gitignored under `out/loopback/`; no pinned library source is edited. Grade: rung 4 ESTABLISHED FOR AVAILABILITY IMPACT only, rung 5 UNKNOWN.
- **Iec618502Shell real libc write from a wire-supplied chain (commit `a77cecc`, witness #1127)**: `bash lab/frontier/libiec61850/r4_real.sh <abs-outdir>` → 13 PASS / 0 FAIL rc 0, 6/6 pins OK, staged payload SHA-256 `4d2ec7945e51b7bed652ec1d08205c3987ff28ed4b14c0f27341cca2686a0e28`. The live unsanitized server, no `LD_PRELOAD`, logs `READBUF rb=… buf=RETSLOT-4 fd=4`, `ROP rip=<libc pop rdi; ret>` and `WRITE fd=0x4 buf=<chosen heap> len=0x34`; the loopback client reads back 52 bytes beginning `49454336313835302d523421` (`IEC61850-R4!`), then the chain reaches real libc `exit`. Conditions: pinned vulnerable build, gdb with ASLR disabled, host-specific gadget/libc offsets asserted at run time, already-connected fd 4, `rdx` equal to the frame length. W89 replayed it from a clean git-archive HEAD tree: 13 PASS / 0 FAIL, matching trace and readback, ESTABLISHED AS CLAIMED at the labeled grade; no injected code, ASLR defeat or persistence.
- **Open625412Shell downstream dereference of the groomed pointer (commit `d2d57d6`)**: `cd lab/frontier/open625412shell && bash run.sh <abs-outdir> && bash deref.sh <abs-outdir>` → 14 PASS / 0 FAIL rc 0, trace `sha256=0f2a2d7e0a4ca63a15593e3e5cb1f4dde81746e718c0306adb30fa1c839931f3`. Expect `same_chunk=1` under 1.5.4 with ASan quarantine disabled, the stale `LIST_REMOVE` setting the replacement's byte-200 head to the live monitored-item pointer, and `sampleAndPublishCallback` (gdb `ua_subscription.c:1017 if sub->subscriptionId == 2`) calling `UA_MonitoredItem_sample` on that cross-subscription item with its queue going 4 → 5; skip-delete and tagged 1.5.6 controls keep 4 → 4. Lab conditions: consent hook, forced internal delete, queue size 10 and callback isolation; no chosen bytes, diversion or execution.
- **OpenJpeg2Shell gap-alignment reachability — retraction and layout dependence (commits `66965f6`, `f6d026f`, `b95c579`)**: `bash lab/frontier/openjpeg2shell/gap-reach.sh OUTDIR` rebuilds the pinned libopenjp2 2.5.4, generates evil=48/154/184 codestreams and reports each layout's `min_gap_index` and reachability; the original 2 PASS / 0 FAIL "unreachable" assertion was RETRACTED after a clean-archive replay found a reachable gap object at `24*30`. The remaining obstacle is aligning `SOD_k = chosen static address`: `SOD_k` shifts 14 bytes per tile part, so with an 8-byte-aligned pad only `k % 4 == 0` yields an 8-byte-aligned value, while `k=30` gives `0xa3c134`. Placement is cwd/argv-sensitive, so fix both, not just the codestream digest. No chosen deallocator call; rung 4 stays PARTIAL.
- **KnotResolver2Shell jemalloc geometry and chosen-byte comparator overwrite, no dispatch (commits `5a6ebab`, `5f850fc`)**: on a 6.4.0 build with `-Dmalloc=jemalloc -Dquic=embedded --buildtype=debug` installed to a local prefix, run `bash lab/frontier/knotresolver2shell/harness/run_jemalloc_layout.sh` and `bash lab/frontier/knotresolver2shell/harness/run_ksl_control.sh` (add `follow` to force trailing streams). Expect the 6144-byte slot geometry to hold while the reference gnutls dispatch offsets fail; the live neighbour resolves to an `ngtcp2_pktns` whose `compar` at `slot1+0xa0` becomes chosen `0x4141414141414141` at the F6 breakpoint, with root/front/back and search preserved. The read watchpoint never fires and the post-F6 `ksl_insert` trace shows calls only on other ksls. All runs are loopback-only under gdb (ASLR disabled for the inferior; host sysctl untouched). Rung 3 stands, rung 4 UNKNOWN: no call through the overwritten pointer.

- **OpenJpeg2Shell natural call through a chosen `ob_type` (commits `a351c20`, `098e705`, `091488e`)**: `bash lab/frontier/openjpeg2shell/chosen-call.sh <outdir>` → 7 PASS / 0 FAIL, trace `sha256=ab46a561e9b9f4aefeb0fd9ec52810cd36cd2c07dfaee627477de96e4e56afaf`; clean `git archive` replay of `a351c20` gives 7 PASS / 0 FAIL with a different calibrated filename and object address, trace `sha256=db68ebea547696bd39e97d2648ed9fced6d32d5eef88ae880fd29cd1f893334f`. Expect `PRE OBJ=… REF=1 TYPE=…a2d260`, `WRITE W1=…a3d840 W2=…a3d842`, `POST REF=1 TYPE=…a3d840`, then `DEALLOC pc=0x583dc0 … TYPE=…a3d840` from `_Py_Dealloc` during interpreter finalization and `CHOSEN_CALL pc=0x575cb0` equal to `DICT_DEALLOC`, not the original type's `0x54e700`. The exact intermediate caller is UNKNOWN: the author's trace labels it `PyGC_Collect`, the witness resolves only frame #6 `Py_FinalizeEx` because intermediate frames are unsymbolized. Plain consumer prints `LOAD_OK` or aborts at finalization (rc 134/139, layout-dependent); `chosen-call.sh` now accepts either documented outcome as `PLAIN_OUTCOME`. Both branches were replayed after commit `091488e`: checkout gave `PLAIN_OUTCOME corrupted size vs. prev_size` (7 PASS / 0 FAIL, unchanged invariant trace), clean archive gave `PLAIN_OUTCOME LOAD_OK` (7 PASS / 0 FAIL, object `0xd15ed0`, trace `sha256=25542f54d448d0bf4b2953c37d2fe2636fcfa1d2641f15410ca546423b18f6f4`). Debug `-g -O0` layout, chosen existing static type only; no marker, chosen-address dereference, attacker code or listener. Witness #1151 replayed the six core invariants from a clean archive and returned ESTABLISHED at the labeled scope. Record the invariant chain, not the layout-dependent trace digests, as the acceptance fact.
- **OpenJpeg2Shell GOT-target natural call (commits `f61644f`, `53b75c4`; witness #1151 ESTABLISHED)**: `bash lab/frontier/openjpeg2shell/got-target.sh <outdir>` derives `GOT(system)` from the live interpreter's own relocation table and writes `ob_type = GOT(system) - 0x30` into the finalization object. Expect 9 PASS / 0 FAIL in the checkout and from a clean `git archive f61644f` replay, with identical write value, GOT slot, call target and argument fields though the calibrated filename and object address differ (checkout trace `sha256=8ef9d68d5af6bd7ece8fab2f39e0adc1f3ce4c0b4e4e7275b4e3deaa304b33a6`, clean replay `25d5d9d1…`): `POST REF=1 TYPE=<GOT-0x30>`, `DEALLOC pc=0x583dc0`, then `CHOSEN_CALL pc=0x4206c6` at the unresolved `system` PLT stub with a NUL first argument. The run stops at the stub: no continuation into `system()`, no shell, listener, chosen argument or marker, and rung 5 stays UNKNOWN. The trace hash is layout-dependent; the ordered invariant fields are the claim. Witness #1149 independently replayed 9 PASS / 0 FAIL from a clean archive at that scope (#1151 verdict).
- **Exim2Shell plain-build safe-pointer consumer (commit `a6fbe8e`, wake 3)**: in the gitignored plain 4.99.2 tree `src/exim-4.99.2-plain/`, a lab-only trace at `receive.c:2141` resolves `smtp_ungetc=0x9a447` and `tls_ungetc=0xb0a6a` from `nm -an build-Linux-x86_64/exim`; run the five wire shapes `four`, `chosen 1 A`, `chosen 8 Q`, `two`, `ungetc` via `python3 trigger.py 25262 <shape>`. Expect `PLAIN call-site nextch=<byte> ungetc_fn=0x…9447` (safe `smtp_ungetc`) at the header-parser call site, with `PLAIN bdat-pop ungetc_fn=0x…fa6a` only after the pop; five shapes on loopback 25262 all agree, no `tls_ungetc` write on a live non-ASan glibc heap, no chosen byte and no rung 4. The ASan replay instead calls `tls_ungetc` there because the pop precedes the call — a build-dependent ordering difference with identical source, bytes and host. Raw traces stay in the gitignored plain tree; the pinned ASan trees are unchanged. The same commit applies witness #1140's citation corrections in `reports/exim2shell-wake2.md` (`tls-gnu.c:3972`, `tls_getc :3998`), grade unchanged.
- **WAMR2Shell chosen-immediate variant, author claim (commit `0160f40`)**: `python3 lab/frontier/wamr2shell/make_chosen_variant.py OUT 4142434445464700 8` regenerates variant 1 byte-for-byte from the pinned upstream `.wasm`; `… OUT 7eadbeefcafeb000 8` gives variant 2 at the same module shape (eight `i64.const`/`drop` pairs after the 21-result block). On the instrumented 2.4.4 build (`iwasm -f test OUT`), expect `WAMR_OOB tag=const size=8` at 11/29/47/65 bytes past `p_code_compiled_end`, carrying the chosen immediate with its leading zero byte replaced by the `const` emit tag (base `0x4142434445464700` logs `0447464544434241`); the two variants differ only in those bytes and a six-`i32.const`-pair padding control leaves the offsets unchanged. Unmodified ASan 2.4.4 gives `WRITE of size 8` in `wasm_loader_emit_const :9382` at load time, fixed tagged 2.4.5 no ASan error. Pinned PoC and variant SHA-256 digests are in `reports/wamr2shell-rung4.md`; raw outputs live in the gitignored site under `.mishe-tauftauf/artifacts/wamr2shell/`, and regenerate with these commands. The W91 negative applies to the upstream PoC only; this variant is author-only with witness replay owed, no wire consumer driven, no guest code executed and rung 5 UNKNOWN.
- **KnotResolver2Shell both ksl comparators reached, no dispatch (commit `3ddc2fc`)**: on the 6.4.0 jemalloc build, `harness/ksl_active.py` (second connection before or between F5/F6), `harness/ksl_tuned.py` (N=5, D=1225, F6 datalen 1202) and `harness/ksl_extend.py` (20 extra 1440-byte frames) produce the committed `harness/ksl-*.txt`/`*.log` traces. Expect both `compar` fields of the idle neighbour `ngtcp2_pktns` set to `0x4141414141414141` (`slot1+0xa0` gap ksl and `slot1+0x3e0` extended `acktr.ents` ksl) with root/front/back/search preserved, no `DISPATCH HIT`, no read-watchpoint stop and a live kresd; the 65536-byte-class run puts the next live object ~1500 bytes beyond the write. Rung 3 unchanged, rung 4 UNKNOWN.
- **KnotResolver2Shell rung-3 witness verdict W87 and second-pointer watch (commit `9c00872`)**: the witness rebuilt both pinned tags from a clean `git archive HEAD` at `3f6622b` (3/3 SHA-256 pins OK, own kresd SHA-256 `dad3a67d…c53d1b7` / `de197fa1…65aca`) with `meson -Db_sanitize=address -Dmalloc=disabled -Dquic=embedded --buildtype=debug`, using ports 18853/18854 and a byte-identical driver (`f6271527…`). Expect two 6.4.0 runs with `WRITE of size 1198` at `quic_conn.c:124` past the 5762-byte `realloc` at `:103` and the downstream `wire_buf_movestart` READ, and a clean 6.4.1 run logging `invalid payload size, malformed data (2 != 1448)`; verdict **rung 3 ESTABLISHED IN FULL**, rung 4 UNKNOWN. A wake-5 negative: `bash lab/frontier/knotresolver2shell/harness/run_ksl_search.sh` arms a hardware read watchpoint on the second comparator's `search` field at `slot1+0xa8` at F6 and sends the trailing `follow` streams; `harness/ksl-search.txt` records `compar=0x4141414141414141` with the legitimate `search` preserved, no watchpoint stop, no `DISPATCH HIT` from instrumented `ngtcp2_ksl_*` calls, kresd alive and driver `done` — the corrupted pktns is idle on this host, so rung 4 stays UNKNOWN.
- **Open625412Shell measured rung-5 structural blocker (commit `c126d60`)**: the report's "Rung 5 — measured structural blocker" section records why this primitive cannot be extended: the harness starts no listener and takes no wire input, carries a consent hook and a forced-delete stand-in, writes only a live object pointer rather than a chosen command, and has no command path on which fixed/safe-input differentials can run. Rung 4 stays INSTRUMENTED; this is a blocker for this build only, not an unexploitability claim.
- **Freeswitch2Shell forged-SSL wire command, witness-established (commit `462e887`, verdict #1118)**: from `lab/freeswitch2shell/live`, run `bash run_live_rce.sh calibrate` (gdb `set disable-randomization on`; two runs printed the same `WSH_ADDR=0x7ffff44fb010` / `SYSTEM_ADDR=0x7ffff7658750`), then `bash run_live_rce.sh exploit $WSH $SYS r5`, `bash run_live_rce.sh trace $WSH $SYS r5t`, `bash run_live_rce.sh safe $WSH $SYS r5`, `bash run_live_rce.sh fixed $WSH $SYS r5` and `bash run_live_rce.sh exploit $WSH $SYS r5v`. Expect `SENT_FRAME=131112`, `CMD=id>r5`, `MARKER_EXISTS=1` and a target-written `r5` containing `uid=0(root) gid=0(root) groups=0(root)`; the trace run breaks at `__libc_system` with `SYSTEM_RDI` equal to the forged SSL and `ws_destroy ws.c:367` in the backtrace (no marker by design); `r5v` shows the marker name follows the wire command; safe and fixed give `MARKER_EXISTS=0`. Marker names must be at most 7 bytes including the NUL. Conditions: opt-in `mod_xml_rpc` and websocket config, lab-only build shims, ASLR-off calibration, host-specific addresses and a `sudo -n unshare -n` loopback-only netns. Raw `logs/rce_*` outputs are committed with the change; the `r5`/`r5v` markers are untracked and regenerate with exploit mode. Witness #1118 replayed these steps from clean blobs and ESTABLISHED the claim under the stated conditions; see the next bullet.
- **Iec618502Shell real libc `system` from a wire-supplied chain (commit `3777729`, witness #1127)**: `bash lab/frontier/libiec61850/r5_system.sh <abs-outdir>` reuses the witness-verified r4_real ObtainFile staging, replaces the real `write` call with libc `system` (static offset `0x58750` confirmed by `nm -D`) and sends a second 100-byte loopback TPKT frame carrying the 40-byte chain (sha256 `d3b2a7fc78234a64845b17d6d08af0ed935d7f28ea97fdc2821627b52c45f040`): `pop rdi; ret`, command address, bare `ret` for ABI alignment, real `system`, real `exit`. A clean-archive replay gives 15 PASS / 0 FAIL rc 0 and 6/6 pins OK. Expect gdb `SYSTEM hit rip=0x7ffff7c58750 rdi=0x7ffff002aaf0 str=printf R5_IEC_MARKER_49035 > …`, a target-created `r5_marker.txt` holding exactly `R5_IEC_MARKER_49035` (19 bytes, sha256 `697191af345051bfaa3f398d462fa905af4491498aa8865f1eb239db0e55b5f4`) and inferior exit code 02 without SIGSEGV. Controls: a benign staged file leaves the marker absent (that control process faults) and released v1.6.2 with the conforming client stops at AARE with no marker. Conditions: ASLR disabled, host-measured addresses/gadgets, gdb supplying addresses only, no `LD_PRELOAD`, lab-chosen command, loopback only; the staged-file digest includes live heap bytes and is layout-dependent. Clean-replay and `/tmp` console outputs are gitignored; regenerate with the command above. Witness #1127 replayed it from a clean git-archive tree with 6/6 pins and varied the command (`W89_VARIED_MARKER_7F3A`), giving a different marker digest; both marker-absent controls held. ESTABLISHED at rung 5 under the labeled conditions; ASLR-on stays UNKNOWN and the rung-4 grade is unchanged.
- **FreeSWITCH rung-5 witness verdict #1118 (W88)**: independent replay in `/tmp/w88-fs-live` matched HEAD script digests (`run_live_rce.sh` `615f772f…`, `rce_client.py` `983e06a1…`, `live_client.py` `68d1c85c…`) and source pins (`ws.c` `5a07965f…`, `ws.h` `1990aa2b…`). Own calibration twice gave the same `WSH`/`SYS`; exploit gave 101 upgrade, `SENT_FRAME=131112`, `MARKER_EXISTS=1` and the target-written marker; trace hit `__libc_system` with `SYSTEM_RDI` at the forged SSL and `ws_destroy ws.c:367`; a varied wire command `pwd>p1` wrote `/tmp/w88-fs-live` into marker `p1`, a different side effect excluding a fixed one; safe and witness-pinned-fixed runs had no marker. ESTABLISHED at rung 5 under ASLR-off, opt-in config, lab shims, sudo-root netns and loopback-only conditions; ASLR-on reachability stays UNKNOWN.
- **Iec618502Shell rung-4/5 witness verdict #1127 (W89)**: independent replay from a fresh `git archive HEAD` tree `/tmp/w89-iec-root` matched the committed `r5_system.sh` digest (`a3000fcb…`) and all 6 pins; own ASLR-off calibration measured `base=0x7ffff0010ae0`, `RETSLOT=0x7ffff7bfec88`, libc `0x7ffff7c00000`, `system=0x7ffff7c58750`. Baseline gave 15 PASS / 0 FAIL rc 0 with `SYSTEM hit rip=… rdi=0x7ffff002aaf0 str=printf R5_IEC_MARKER_49035 > …` and a target-created marker `sha256=697191af…`; a varied wire command `W89_VARIED_MARKER_7F3A` gave a different target-created marker `sha256=50651c60…` with different staged digests, excluding a fixed side effect. Both marker-absent controls held. `r4_real.sh` from a fresh build gave 13 PASS / 0 FAIL, `READBUF rb=0x7ffff002a508 buf=0x7ffff7bfec84 fd=4`, `ROP rip=0x7ffff7d0f84b`, `WRITE fd=0x4 buf=0x7ffff002aaf0 len=0x34` and the exact 52-byte loopback readback, no `LD_PRELOAD`. ESTABLISHED AS CLAIMED at the labeled grades; R4 unchanged, R5 ESTABLISHED with ASLR-off and host-measured conditions, ASLR-on UNKNOWN.
- **Iec618502Shell measured ASLR-on structural negative (commit `bc7b5ee`)**: `reports/iec618502shell-r4.md` records that a copy of `r5_system.sh` with `set disable-randomization off` in both gdb blocks (canonical digest `a3000fcb…` untouched) gives 10 PASS / 5 FAIL and no marker: Phase A's measured `system=0x71a926658750` is unmapped in the Phase B process, and an observation-only variant (symbolic `break system`) shows the overflow still firing while Phase A `BASE=0x7087b0010ae0` differs from the Phase B live `0x748b28010ae0` by `0x40378000000`, the fake read buffer misses the chosen return slot and the server faults in `CotpConnection_resetPayload`. Same-wake canonical control: 15 PASS / 0 FAIL, marker created. The chain therefore needs ASLR-off cross-process address stability; ASLR-on with an attacker-derived base stays UNKNOWN (no leak or partial-overwrite construction tried). Author-only negative, no witness replay owed.
- **Pillow2Shell measured rung-5 structural blocker (commit `7a7082e`)**: `reports/pillow2shell-consumer-reality.md` records three measurements: `system@plt=0x4206c0` and `execve@plt=0x421200` are fixed in the non-PIE python3.12; an ASLR-on replay of `case_min.fpx` reaches `HIT pc=0x54e700 rdi=buffer+176` with object bytes beginning `00*8 | 60 d2 a2 00*5`, so CPython's cleared `ob_refcnt` makes the deallocator argument start with NUL and cannot be a command string; and `glibc_live_chunks_v12.log` shows W2 crossing live chunks (32 bytes at `buffer+144`, 992 at `buffer+176`, next size `0x21 → 0x5a5a5a5a5a5a5a5a`), leaving no free tcache `fd`/`key`. Rung 4 stays ◐; R5 is BLOCKED on this build, no new primitive and no witness replay owed.
- **Perl2Shell fixed control and witness W96 (commits `64222a4`, `ed6edf4`, `aea121f`)**: both committed CNA patches (`568e6fd`, `54cf3d4`) applied to the pinned 5.45.1 tree rebuild `regexec.c` with the `STRLEN` guard at `:9208`; the fixed ASan binary `perl-5.45.1-asan-fixed` (`16ad5003c9f3f80bb10079cf231a70f1047529d6ad9a636bb73f6f520db8978f`, vulnerable `dad42179668e5cadaf86e74295e38393b4d79eda29df90c386cb356a0c27b47a`) gives `rc=0`, `NOMATCH`, `SUBJECT_CHANGES=0`, no ASan report (trace `5a34efa24d122b36086ce55139c78c1a518a523f33b7ed25be0ba1023ef5710b`). The enclosing `make -j2` hit its 1500 s timeout at 23:04:38Z during a later Unicode-table step after the relink; a `-Dr` fixed run reached `WHILEM[15/15]` but timed out at 120 s, preserved as a limit. Witness W96 (23:01Z) re-derived the pins (`2b6d6919`, `e9f2c892`, `d9426b23`) and normalised hashes, replayed the vulnerable binary 8/8 with a constant fault address `0x50202000a9cf` under varying PIE PCs, and independently rebuilt the patched source clean. RUNG 3 ESTABLISHED; rung 4 is closed by the observed ~536,870,883-byte READ killing the process before the single-bit OR write, no named wire consumer (CISA AV:L); no RCE claim. Raw build trees stay gitignored.
- **Perl2Shell instrumented `CACHEsayNO` write-path probe (commit `3126aab`)**:
  in a throwaway `/tmp/perl2shell-groom` copy (pinned sources and committed
  binaries untouched), `regexec.c` computes the wrap explicitly in `I32`,
  enlarges the cache to 600 MiB filled `0x41`, casts `poscache_iter` to `I32`
  for the `< 0` test, and prints at activation/read/`CACHEsayNO`; only
  `regexec.o` was recompiled. Instrumented binary sha256
  `8de5da62e17323f396a66b13e37cf00953639ba0a697ffbaf4a3cee2014ebb6a`. With
  a 1000-byte subject and the 15-WHILEM pattern (countdown forced to 1) the
  path ran in 0.47 s: 1050 `GROOM_READ`, 103 `GROOM_WRITE`/`GROOM_WROTE`
  pairs, first write offset 1875 mask `0x02` `before=0x41 after=0x43`, later
  `0x43→0x47` and `0x41→0x45`, then `NOMATCH`, rc 0, no ASan report. The
  286331153-byte subject printed `wrapped=14` (`len=286331154`, `n=15`; also
  `wrapped=1`) but reached no activation or read in three 180 s runs or a
  60 s diagnostic — negative, reason UNKNOWN. This is a confirmed code-path
  mechanic under instrumentation, not rung 4 on the shipped 2-byte-cache
  configuration; RUNG 3 ESTABLISHED and the W96 controls stay unchanged.
- **OpenJpeg2Shell native-callback and type-slot closures (commit `239204c`)**: source-only structural negatives, no harness, build, replay or grade change. Pinned `openjpeg.h:996-1004` defines `opj_tp_index_t` as three `OPJ_OFF_T` fields with no code pointer; a complete `tp_index` reference scan of pinned `j2k.c` finds only allocation/copy (`:4680-4737`, `:11839-11863`) and offset reads (`:5085/:5088`, `:8464`, `:8949`, `:11589-11591`, `:12021-12054`, `:12195`). The destination `tp_index + 24*TPsot + 8/16` cannot name the non-PIE interpreter GOT at `0xa29348` (fixed address below the observed heap `~0xd16000`, `TPsot` nonnegative). CPython's `tp_finalize`, `tp_traverse` and GC `tp_clear` slots all receive the object in `rdi`, so `rdi[0..7]` remains `ob_refcnt`; substituting a slot does not place a chosen command in the first argument. Rung 5 stays UNKNOWN; witness-ESTABLISHED rung 4 unchanged.
- **Pillow2Shell W14 finalizer-slot negative and current replay drift (commit `64ad607`)**: from a plain 12.2.0 build, `lab/pillow2shell/w14/finalizer_arg2.py` measures `sys.getrefcount(self)=3` in `__del__` on the refcount path vs `4` under cycle + `gc.collect()`: CPython INCREFs before `tp_finalize`, so W12's "first argument always NUL" is narrower than stated, but `rdi+0..7` is still `ob_refcnt` (at most seven command bytes before the NUL). Slot offsets: `tp_dealloc` at `PyTypeObject+48` (`0x54e700`), `tp_finalize` at `+392` (`slot_tp_finalize 0x5a38e0`; 0 for `str`/`int`/`NoneType`), `PyObject_CallFinalizerFromDealloc=0x585c40`. `finalizer_slot.gdb`/`finalizer_slot2.gdb` reach neither marker (crash in GC list handling from `PyGC_Collect()`), and `static_finalizer.gdb` crashes in `unlink_chunk` from `_dealloc (decode.c:111)`. Separately, under the wake harness environment `replay_min.sh` is 6 PASS / 2 FAIL — the `buffer+176` neighbour is no longer a `PyUnicodeObject` so the chosen `0xa2d260` write misses its `ob_type` — while `env -i` gives one `HIT pc=0x54e700 rdi=buffer+176` at 7 PASS / 1 FAIL (cosmetic backtrace difference); the ASan `WRITE of size 1` at `decode.c:226` via `JpegDecode.c:252` is unchanged. Current negative, not a refutation of #1048; no witness replay owed for a negative.
- **KnotResolver2Shell rung 4 witness-ESTABLISHED (commits `df274fa`, `2a3ca7f`, verdict #1138)**: `reports/knotresolver2shell-rung3.md` records the stalled-Initial groom and `harness/run_gnutls_sweep.sh` / `harness/ksl_stalled.py` placing an 8-byte marker at a chosen `slot1` offset of the live gnutls session; `harness/gnutls-sweep.txt` shows no stop at `+0x10/0x18/0xd8/0x178`, a NULL deref at `+0xf8`, and `rsi=0x4141414141414141` at `+0x100`/`+0x110` in `gnutls_deinit()` from `quic_conn.c:884`. `harness/gnutls-control-0x100.log` varies the value to `0x4242424242424242` at the same site. Conditions: pinned 6.4.0, jemalloc, debug build, gdb ASLR-off for the inferior (host sysctl untouched), loopback only; chosen argument value, not RIP, marker execution or a command. Independent replay #1138 (20:52–20:56Z) matched HEAD harness digests (`85ffce02…`/`30ab19a3…`/`5ea6b3a5…`), 3/3 pins and byte-identical pinned `quic_conn.c`; its own sweep reproduced `rsi=0x4141414141414141` at `+0x100`/`+0x110`, and a marker-only change to `0x5a5a5a5a5a5a5a5a` reproduced the same offsets/RIP with the different RSI. The fault instruction `movzwl (%rsi),%eax` is a real 2-byte read of the chosen address. Rung 4 ESTABLISHED at these labeled conditions; rung 3 stays ESTABLISHED, rung 5 UNKNOWN, no grade change.
- **Exim2Shell build and NEGATIVE BDAT trigger (commit `1a22649`)**: build the pinned `USE_GNUTLS=yes` trees in `lab/frontier/exim2shell/src` with ASan, start `src/exim-4.99.2/build-Linux-x86_64/exim -bd -oX 25252 -d-all` (fixed control 4.99.3 on 25253), and run `python3 lab/frontier/exim2shell/trigger.py 25252 ungetc` plus the `two`, `three` and `four` shapes. Expect STARTTLS, a mid-BDAT `close_notify` and cleartext continuation accepted by the daemon, `grep -c libasan /proc/<pid>/maps` → 5, and **no** ASan report, no `tls_ungetc` call on the freed `xfer_buffer` and no chosen byte. The receive-pointer transition depends on when `bdat_pop_receive_functions()` runs; no rung 2/3/4 claim. Raw logs are gitignored and regenerate with those commands; the next bounded step is an instrumented `tls_ungetc` entry probe, not a repeat of these four shapes.
- **CivetWeb2Shell W87 independent rung-4 verdict (commit `58a36d2`, #1102)**: from a clean `git archive` tree, the witness rebuilt the unmodified pinned v1.16 source and ran `bash run-header.sh /tmp/w87-cw-out` → 13 PASS / 0 FAIL rc 0 with `TRACE_SHA256=fe6e66c719fcadb147e39f0614510998c9b43e2f5dc22615c40090151d2c5557` (first 15 lines only, by construction). The live heap header changed `PRE_SIZE 0x16db1` to size `0x504f4e4d4c4b4a49`, fd `0x5857565554535251`, bk `0x3534333231305a59` (chosen query bytes) before SIGABRT `malloc(): corrupted top size`. Rung 4 ESTABLISHED at the INSTRUMENTED grade; no chosen pointer, control-flow diversion or grade change.
- **Open625412Shell witness verdict on the dereference trace (commit `fe3b540`, #1120)**: an independent fresh build of the verbatim pinned 1.5.4 / 1.5.6 trees replayed `bash lab/frontier/open625412shell/run.sh <outdir> && bash lab/frontier/open625412shell/deref.sh <outdir>` → 14 PASS / 0 FAIL and the exact committed trace `sha256=0f2a2d7e0a4ca63a15593e3e5cb1f4dde81746e718c0306adb30fa1c839931f3`: `same_chunk=1`, byte-200 head groomed to the live monitored-item pointer, queue 4 → 5 under the real callback versus 4 → 4 for skip-delete and fixed 1.5.6. Rung 4 INSTRUMENTED is witness-ESTABLISHED; the measured R5 structural blocker stands.
- **Pillow2Shell W13 tcache-placement NEGATIVE (commit `8de8e82`)**: from a plain Pillow 12.2.0 build, `groom_tcache.py` frees an adjacent 64-byte pair after `Image.open()` and before `load()`, and `bash lab/pillow2shell/replay_tcache.sh` drives `case_tcache.fpx` (SHA-256 `cb62b582efd51bb6f6bbafcef1529dc4ae5d2ed611739db8226737bed86689ef`, 47-wide four-component JPEG writing chosen bytes at tile-buffer offsets 144–159) under `tcache_place.gdb`. Two pinned builds PASS: neither groomed address appears in the tcache at decoder entry (`BUF=0x386023e0 X=384b4c30 Y=384b4cc0`, no `FOUND_X`/`FOUND_Y`), the neighbour is still live, and a 24-byte groom gives the same result; `load()` consumes both chunks before the tile allocation. A gdb-forced `free()` was consumed by `malloc_consolidate` before the write. No chosen tcache `fd`/`key`, no command, no grade change; R5 stays BLOCKED at W12, no witness replay owed.
- **WolfSsl2Shell corrected head-chunk citation and witness #1128 (commits `01f8ad2`, `948dccc`)**: the sixth-wake gdb dump used `x/8gx ssl->dtls13Rtx.seenRecords - 16`, a display offset rather than byte arithmetic, so the quoted `0x0078000000000000` at `0x55555562b238` came from an unrelated slab region. `lab/frontier/wolfssl2shell/groom_victim2.gdb` now uses `x/8gx ((char*)ssl->dtls13Rtx.seenRecords - 16)`; the corrected dump in gitignored `out/loopback/groom-victim2-corrected.log` reads `prev_size=0` at `0x55555562b230` and size `0x008f000000000000` at `0x55555562b238` for the live head node, with sender-derived sizes in neighbouring headers. Witness #1128 returned VERIFIED source-bound; the overwrite, chosen bytes and abort are unchanged, rung 4 availability remains ESTABLISHED and rung 5 UNKNOWN. The ignored corrected log must stay in the lab tree for the report citation to resolve.
- **CivetWeb2Shell structural bound on the unmodified build (commit `575302d`)**: `mg_snprintf` (`civetweb.c:3716-3732`) fills `new_path` to `buflen-1`; with query length `q` the last overflowing byte lands at index `8195+2q`, while the only adjacent neighbour `uri_encoded` (allocated at `:3631`, freed at `:3734` before the appends) ends near `35224+4q`. The overflow envelope grows at half that rate and never reaches the neighbour for `q=1,46,200,10000`; wake-3 tracing shows `new_path` comes from top, so the neighbour is deterministically adjacent but already free at write time. Reaching a live object needs the wake-1 allocation-order instrumentation, hence INSTRUMENTED rung 4, consistent with witness #1102 and the availability-only CVSS vector.
- **RabbitMQC2Shell complete caller enumeration and external search NEGATIVE (commit `4ca0160`)**: every in-tree `amqp_send_frame` call in pinned v0.16.0 is safe — `amqp_api.c:217` fixed header, `:242` body clamped by `frame_max-(HEADER_SIZE+FOOTER_SIZE)` at `:167-168/:233-238`, `amqp_socket.c:773` fixed-size heartbeat, `:996` bounded table-encoded method. The only sinks are `amqp_connection.c:531`/`:548`; the overflow needs an external caller passing `body.len > buffer.len-14` directly, as the harness and synthetic socket service do. Three bounded web searches found only advisories, docs and a 2011 discussion of the different `amqp_send_frame_to` API — no named consumer then. Search negative, not proof none exists; external direct callers stay UNKNOWN and the real-proxy rung-5 route stays UNPROVEN. No off-loopback probe was made. The later named FFmpeg check below is a source-level negative on one candidate, not a closure of that UNKNOWN.
- **RabbitMQC2Shell allocator placement decides the rung-4 marker, FFmpeg NEGATIVE (commits `e2af7fd`, `95056ee`)**: `bash lab/rabbitmqc2shell/run_mmap_threshold.sh <outdir>` reuses the `svc_reuse` binary built by `run.sh` and feeds the same 65600-byte body and chosen bytes over loopback `AF_UNIX` twice; expect 2 PASS / 0 FAIL, no library or harness source changes. Under glibc's default `M_MMAP_THRESHOLD=131072`, `malloc(200000)` is mmap-backed, paired gdb measured `socket - outbound = 65552` and body byte 65545 landing on `socket->klass`, so the library path reaches `MARKER: controlled vtable call reached` (three repeated runs). With `MALLOC_MMAP_THRESHOLD_=300000` the same body is brk-backed (`0x5555555712a0` in that run), the socket sits 196640 bytes away, the copy only corrupts heap metadata (`amqp_send_frame rc=-9`, `free(): invalid next size (normal)`, abort) and no marker fires; fixed v0.17.0 under forced brk returns `rc=-2` with no corruption. The marker limb is therefore conditional on the oversized receive buffer being mmap-backed — a realistic but not universal service pattern; grade and witness verdicts are unchanged. The paired gdb script `gdb_brk.cmd`, probe `where.c` and raw logs are gitignored under `/tmp/rmq2-mmap-test/` and regenerate from these runs. Separately, published FFmpeg 7.1 `libavformat/libamqp.c` publishes with `amqp_basic_publish` at line 251, not `amqp_send_frame`; its `pkt_size=131072` path chunks BODY frames to `frame_max-12`, so this named muxer is on the safe side of `amqp_connection.c:467`. FFmpeg was not built or driven; the `collectd` AMQP 1.0 plugin uses another implementation. `apt-cache rdepends librabbitmq4` named eight other packages (not installed here); no direct frame-level caller was established and no external system was contacted.
- **OpenJpeg2Shell W92 both-branch NIT replay and caller boundary (commits
  `091488e`, `6b8fe7c`, `10e6d35`, `0945780`)**: `bash lab/frontier/openjpeg2shell/chosen-call.sh <outdir>`
  now accepts either documented plain-consumer result and records it as
  `PLAIN_OUTCOME`. The checkout replay gives 7 PASS / 0 FAIL with
  `corrupted size vs. prev_size` at object `0xd160d0` (invariant trace
  `sha256=ab46a561…`); a clean `git archive 091488e` replay gives the other
  branch, 7 PASS / 0 FAIL, `PLAIN_OUTCOME LOAD_OK` at `0xd15ed0`, trace
  `sha256=25542f54d448d0bf4b2953c37d2fe2636fcfa1d2641f15410ca546423b18f6f4`.
  The author's trace labels the natural dealloc caller `PyGC_Collect`;
  witness W92's observation-only backtrace resolves only `Py_FinalizeEx`, so
  the intermediate caller is UNKNOWN. W92 ESTABLISHED both rung-4 limbs at
  their labelled scope with no grade change; the plant cell stays `◐`.
  The brief's older "remaining gap: pointer-value control, control-flow
  diversion" paragraph was superseded by the measured chosen-type call and
  GOT-target limbs (`0945780`). Control-flow diversion to a chosen existing
  deallocator or a fixed GOT slot is demonstrated; only an attacker-chosen
  argument, chosen-code execution, a web-facing listener and arbitrary-address
  dereference stay UNKNOWN. The dereference that was observed is of a fixed
  GOT slot in the known non-PIE interpreter, derived from its own relocation
  table.
- **Exim2Shell wake-4 stock-build cap and ASan-only chosen byte (commits
  `5d67af7`, `d4e5d9d`)**: start the instrumented non-ASan 4.99.2 build in
  the gitignored `lab/frontier/exim2shell/src/exim-4.99.2-plain/` tree on
  127.0.0.1:25262 and run `python3 trigger.py 25262 three`; expect
  `PLAIN call-site nextch=0x4d ungetc_fn=0x…0447` (safe `smtp_ungetc`),
  `PLAIN bdat-pop ungetc_fn=0x…6b15` (restored `tls_ungetc`), then
  `gnutls_record_recv` returning `-1250` and `421 lost input connection` —
  no stale write, also with `EXIM2SHELL_TLS12=1`. On the instrumented ASan
  copy in `src/exim-4.99.2-asantrace/` on 25272, `python3 trigger.py 25272
  chosen 8 Q` gives `call-site nextch=0x51 ungetc_fn=tls_ungetc` and
  `WRITE of size 1` at `xfer_buffer[7]` (15 bytes into a 4104-byte region);
  later `gnutls_record_recv` calls there return 0, not `-1250`. The observed
  ASan-versus-stock difference is measured; the quarantine-versus-reuse
  cause is an INFERENCE. Rung 4 is not claimed on either build; rung 3
  witness #1140 and the fixed 4.99.3 control are unchanged. Raw traces and
  ASan reports are untracked lab artifacts under those trees.
- **WAMR2Shell chosen bytes come from real stores (commit `7672af9`)**: the
  original instrumented patch skips the OOB store, so its `WAMR_OOB`
  lines are would-be values. Build two non-ASan 2.4.4 trees from the pinned
  tag with the committed patches `lab/frontier/wamr2shell/passive-oob.patch`
  (sha256 `1e4199eace52064722771ee410ef2f5ff50776db49d0149090b872d619f4fba9`)
  and `lab/frontier/wamr2shell/caller-store.patch` (sha256
  `9c0e79073eac423b15b5ead6302fb1cd87653719f414785ec9ab3569e1b5302e`),
  regenerate variants with `python3 lab/frontier/wamr2shell/make_chosen_variant.py
  /tmp/w2-v1.wasm 4142434445464700 8`, then run `iwasm-2.4.4 -f test
  /tmp/w2-v1.wasm`. Expect `WAMR_CALLER tag=const phase=before size=8` and
  `phase=after size=8 … mem=` equal to `in=` at +11/+29/+47/+65 (`0447464544434241`
  … `0747464544434241` for variant 1; `04b0fecaefbead7e` … for variant 2),
  48 OOB writes in the passive build, and glibc `double free or corruption
  (out)` in both. Offset set is fixed and the attacker picks values, not
  addresses; witness #1168 independently replayed the chain from clean pinned
  tags (3/3 pins, patch `9c0e7907…`, variants regenerated byte-for-byte) with
  `in == mem` at the same four offsets and an ASan `WRITE of size 8` at
  `wasm_loader.c:9382` on 2.4.4 only (2.4.5 clean). Destination addresses
  shift under ASLR, so raw digests differ while the invariants match. R5
  stays UNKNOWN. Build trees
  and raw logs (`callerstore-v1.out` `dc126e66…`, `passive-v1.out`
  `9899fc54…`) are gitignored and regenerate from the committed patches.
- **Apache2Root CVE-2026-119618 rung 1 local result, rungs 2/3 NEGATIVE
  (commits `432d053`, `e8b106c`)**: full pins, build flags and logs are in
  `lab/frontier/apache2shell/OUTCOME.md`; drivers
  `lab/frontier/apache2shell/repro-h2c.sh` and `repro-h2c-mux.py` drive only
  127.0.0.1 ports 18080–18082. Expect 76 custom headers plus
  `Content-Type` and no `Content-Length` to drive `nelts=80 nalloc=80` and
  the vulnerable wrong-pool `apr_table_setn()` marker on 2.4.70 (300/300
  and 2000/2000), with the 2.4.71 fixed-path marker on the matched control.
  No ASan report across 2000+ full-table writes; one 2000-stream child
  SIGSEGV was not repeated in a repeat burst or the matched 300-stream run,
  so rung 2 stays UNKNOWN **on that ASan-APR build**. The plant's rung 3 is
  graded on uninstrumented system libapr, where differential child SEGVs
  (3 vs 0 at `LogLevel info`) and a corrupted `pool->child` under gdb were
  observed; `e8b106c` preserves frontier's negative as build-bound
  contradictory evidence, not a refutation. The written value is the fixed
  string "0": no chosen byte, pointer control or RCE. This is an adjacent lane of the
  already-admitted `apache2shell` target, not a new admission; the brief's
  "(unadmitted)" label is stale, corrected in `a291cb7` to admitted since
  2026-11-20 with its #1 rank historical and the former TSan burst closed.
  Pin check `cd lab/frontier/apache2shell/src && sha256sum -c SHA256SUMS`
  → 6/6 OK (`ff54725` corrected the broken repo-root command). Driver
  scripts and `OUTCOME.md` are tracked, build trees and `out-*` logs are
  gitignored.
  Witness W94/W95 later graded the build-bound reconciliation ESTABLISHED at
  the labeled grade (rung 3 stands, rung 4 not claimed, no replay), after
  `64ecc54` downgraded the ASan-APR allocator/race cause to a hypothesis;
  the nit was CLOSED on tape #1176.

- **Memcached2Shell live-daemon chosen bytes (second wake)**: build the non-instrumented pinned parent as in [the report](../reports/memcached2shell-daemon-asan.md) (`./autogen.sh`; `CFLAGS='-g -O1 -fno-omit-frame-pointer'` with empty `LDFLAGS`, `./configure --disable-sasl --disable-enchant`; `make -j2`), then
  `python3 lab/frontier/memcached2shell/daemon/observe_heap.py --port 22142 --keys 8000 --hold 86 --out /tmp/replay.txt`.
  All traffic is 127.0.0.1; the observer is the daemon parent, reads the ELF load base and pinned `active_crawler_mod` at `base + 0x54320` through `/proc`, and never stops the crawler, so the 1000 ms `poll()` timeout stays intact. Expected: `bufused` crosses 131072 at t≈28s; `buf+131072` reads `0x5a`, with chosen bytes at +512/+1024/+2048/+16384 as the frontier advances; at +16384 the pointer-shaped window `90ae4b0c4474000090b14b0c` (little-endian `0x000074440c4bae90`, an address in the same arena) becomes twelve `0x5a` at t=80s (`bufused=147736`), daemon still alive. Witness #751 accepted the rung-4 chosen-byte limb as claimed; the pointer-shaped victim is conditional on allocator state (absent in two witness `0x5a` replays), semantically unidentified and not a grade basis. No pointer-control, dereference, execution or control-flow claim was accepted or made; its role and any dereference stay UNKNOWN. The `--out` trace and `/tmp/memcached-observe-heap.log` are gitignored and regenerated by that command.
- **Memcached2Shell key-byte differential (third wake)**: the committed observer's `--keybyte` option was exercised on the same non-instrumented parent build and trigger with one change, `0x41` instead of `0x5a`. From the repo root:
  `python3 lab/frontier/memcached2shell/daemon/observe_heap.py --port 22145 --keys 8000 --keybyte 0x41 --hold 82 --out lab/frontier/memcached2shell/daemon/keybyte-041-trace.txt`
  (daemon binary and ELF-symbol defaults; all traffic 127.0.0.1). Expected and observed in the gitignored trace: at t=28s `buf=0x70a9604d4010` with `bufused=131460` gives `OOB samples 0:414141414141303437303620` and `16384:907e4f60a970000090814f60`; at t=80s, `bufused=147736`, the `16384:` window reads `414141414141414141414141` and the daemon is alive. The `0x5a` run's `5a5a5a5a5a5a303436383820` and twelve `5a` at the same offsets confirm the OOB bytes come from the stored key record, not another allocation. The field's semantic role and any dereference stay UNKNOWN; the pointer-shaped victim is conditional on allocator state (absent in two witness `0x5a` replays) and is not a grade basis. Witness #751 accepted the chosen-byte limb as claimed; no pointer control, execution or control-flow claim was made. Raw trace is gitignored; regenerate with the command above after building the non-instrumented parent as in the preceding addendum.
- **Memcached2Shell overflow-stream pointer dereference (fifth wake, witness
  #784 ESTABLISHED AS CLAIMED)**: with the same non-instrumented pinned plain
  parent build, the committed scripts under `lab/frontier/memcached2shell/daemon/`
  replay the fault. From the repo root:
  `bash lab/frontier/memcached2shell/daemon/gdb-fault.sh 22167 150 0x5a 8000 trigger_stress.py gdb-capture-aslr.gdb`
  and the fix control
  `bash lab/frontier/memcached2shell/daemon/fixed-control.sh 22166 90`.
  All traffic is 127.0.0.1. The driver stores 8000 chosen-byte keys, opens a
  stalled `SO_RCVBUF=4096` metadump client, then drives continuous `set`
  commands on a second socket; gdb runs with NO breakpoints (only SIGSEGV /
  SIGBUS stops) and `set disable-randomization off` so ASLR stays on. Expected
  on the parent: `assoc_find` (`assoc.c:87`) SIGSEGV at `assoc_find+126`
  (`movzbl 0x29(%rbx),%eax`) with `RBX=0x5a5a5a5a5a5a5a5a` in three of four
  stress runs; a fourth 70642-set run and a non-stress run did not fault, so
  crash timing is allocator-state dependent. A `0x41` run faults at the same
  site with a different attacker-written value. Expected on the fixed tree:
  no fault through 90 s / ~42,000 sets. The overflow frontier is not directly
  observed under gdb (the `/proc` observer must be the daemon parent, and gdb
  is), so the causal link rests on the identical store/metadump sequence, fix
  sensitivity and the overflow-stream identity of the faulting value. The committed
  `daemon/gdb-capture-frontier.gdb` is provided for witness use but produced no
  stop, so no in-run frontier value was obtained. Witness #762 (2026-11-21)
  left the separate t=116 s `do_slabs_alloc` fault as a single non-deterministic
  observation with no core and an UNKNOWN faulting value: no replay owed, no
  grade change. See the fifth-wake section of
  `reports/memcached2shell-daemon-asan.md`.
  Witness #784 (2026-11-21) returned ESTABLISHED AS CLAIMED on this crash limb
  with the grade unchanged at #751, using its own hash-matched pinned files and
  rebuilt binaries; it also showed the crash needs the stalled metadump and
  that three of five runs do not fault. The faulting value is described as
  overflow-stream content (eight `0x5a` bytes or a metadump metadata
  fragment), not a crafted address.

- **Memcached2Shell no-debugger register capture (seventh wake)**: reuse the
  unmodified plain parent build from above. From the repository root:
  `gcc -O2 -fPIC -shared -o lab/frontier/memcached2shell/daemon/sigctx.so lab/frontier/memcached2shell/daemon/sigctx.c`
  then
  `sh lab/frontier/memcached2shell/daemon/sigctx-fault.sh 22390 90 0x5a 8000`.
  All traffic is 127.0.0.1. The shim installs SIGSEGV/SIGBUS handlers that
  print the faulting `ucontext` registers and exit: no ptrace, breakpoints or
  live signals, and no constructor heap allocation. On the two 10:2xZ runs
  that faulted, the daemon exited 139 after 20,462 stress sets with
  `RBX=0x5a5a5a5a5a5a5a5a5a` and RIP low 12 bits `0x5d7` (the
  `assoc_find+126` instruction `movzbl 0x29(%rbx),%eax`, file offset
  `0x175d7`). A no-fault run is also an expected outcome: four later runs
  (two with a `/proc/self/maps`-reading shim variant whose startup
  `fopen()` perturbs the heap, two with the final minimal shim) completed
  90-120 s without faulting. Do not add allocation or map reading to the
  shim when reproducing; that changes allocator state. This is a capture
  method improvement, not a grade change: rung 4 stays ◐ at witness #751.
  See the seventh-wake section of
  `reports/memcached2shell-daemon-asan.md`.

- **Apache2Root L4** (CVE-2026-56154): reuse the L3 2.4.68 / 2.4.69 ASan
  builds in `lab/apache2shell/` with `mod_rewrite.so` and `MaxMemFree 1`.
  `RW_VARIANT=lau RW_HEADER=yes RW_N=12 ./rw-lane.py 2.4.68 2.4.69` gives
  12/12 child SIGSEGV on affected and 0/12 on fixed;
  `RW_VARIANT=plain RW_HEADER=yes ./rw-lane.py 2.4.68` and
  `RW_VARIANT=lau RW_HEADER=none ./rw-lane.py 2.4.68` are the 0/12 controls,
  and `python3 rw-gdb.py` shows `strlen` → `apr_pstrdup` → `apr_table_merge`
  at `mod_rewrite.c:4701`. Rung 3, no chosen bytes.
- **Apache2Root L5** (CVE-2026-56449, mod_proxy_html `dump_content` stale
  varbuf): `cd lab/apache2shell && bash build-l5.sh` builds ASan/UBSan httpd
  2.4.68 (affected) and 2.4.69 (control) with `--enable-proxy-html` against
  host libxml2 2.9.14. Then
  `ASAN_OPTIONS=detect_leaks=0 L5_PROXY=yes L5_N=4 L5_SUFFIX=proxy ./l5-lane.py 2.4.68 2.4.69`
  reverse-proxies the body `<p title="AAAAAAAAAA">x</p><!--trigger-->` over
  loopback: 2.4.68 gives 4/4 child SIGSEGV and four ASan
  `negative-size-param: (size=-3)` reports at `mod_proxy_html.c:272` from
  `pcomment:312`, 2.4.69 gives 0/4 and none. Controls:
  `L5_PROXY=yes L5_EXT=yes L5_N=3 L5_SUFFIX=exton ./l5-lane.py 2.4.68`,
  `L5_PROXY=yes L5_FLAGS=c L5_N=3 L5_SUFFIX=nocdata ./l5-lane.py 2.4.68`
  and `./l5-gdb.py` (breakpoint, `ctx->vb.strlen=0`, `buf="AAAAAAAAAA"`,
  `AAAA -> BBBB`, flags 3). Applying the 2.4.69 one-line fix to 2.4.68 gives
  0/6 reports; restoring the pristine module restores 6/6. Rung 3, closed;
  ASan aborts before the write and no chosen byte, pointer or marker is
  obtained. Logs under `lab/apache2shell/logs/` are gitignored.
- **Apache2Root L6** (CVE-2026-56153, mod_charset_lite `finish_partial_char`
  OOB write): `cd lab/apache2shell && bash build-l6.sh` builds ASan/UBSan httpd
  2.4.68 (affected) and 2.4.69 (control) with event MPM and
  `--enable-charset-lite` (no libxml2/proxy). Then
  `python3 l6-lane.py 2.4.68 2.4.69` sends a loopback chunked ISO-2022-JP POST
  (chunk 1 `A` + ESC, chunk 2 32 ESC bytes): 2.4.68 gives 3/4 UBSan
  `mod_charset_lite.c:448:17: runtime error: index 8 out of bounds for type
  'char [8]'` against 2.4.69 0/4; the four `AddressSanitizer` lines are
  LeakSanitizer noise because `buf` is inside the larger `apr_pcalloc` context.
  Controls: `L6_SUFFIX=nocharset L6_NOCHARSET=1 python3 l6-lane.py 2.4.68`,
  `L6_SUFFIX=samecharset L6_SAMECHARSET=1 python3 l6-lane.py 2.4.68`, and
  `L6_SUFFIX=long L6_NEXT_HEX=$(python3 -c "print('1b'*64)") python3 l6-lane.py 2.4.68`
  gives 4/4 UBSan plus 4/4 child `SIGSEGV (11)`. Applying the exact 2.4.69
  five-line guard to 2.4.68 and rebuilding only `mod_charset_lite.so` gives
  0/4 reports; restoring the pristine source and module byte-for-byte restores
  2/4. The written byte is fixed at `0x1b`, the offsets follow struct layout
  and the crash is on a corrupted context pointer — rung 3, no chosen byte,
  pointer or marker. Both `lab/apache2shell/build-l6.sh` and
  `lab/apache2shell/l6-lane.py` are tracked; raw logs under
  `lab/apache2shell/logs/` are gitignored.

- **Apache2Root L7** (CVE-2026-42535, mod_dav_fs state-dir access): the
  lane's earlier CVE-2026-93546 premise was false; the real entry is
  `CVE-2026-42535` at `httpd-2.4.69/CHANGES:123-131`, fixed in 2.4.68 by
  denying `.DAV` resources in `dav_fs_get_resource()`. Using the L2/L6 ASan
  builds (2.4.67 / 2.4.68), `cd lab/apache2shell && python3 l7-lane.py
  2.4.67 2.4.68` gives PUT 201, PROPPATCH 207 on both and state-dir
  PROPFIND 207 vs 403; swapping in the 2.4.68 `repos.c` flips 2.4.67 to 403
  and restoring the original source and module bytes restores 207.
  Overwriting the DBM file with 12288 `A` bytes caused no crash or sanitizer
  report. Rung 2 only: no memory corruption, chosen byte, offset, pointer or
  marker. `l7-lane.py` is tracked; raw `logs/` are gitignored.
- **Apache2Root L8** (CVE-2026-48913, mod_http2 UAF on file-handle
  exhaustion): reuse the L2/L3 ASan httpd installs (2.4.67 / 2.4.68) and run
  `cd lab/apache2shell && L8_NOFILE=48 L8_CONNS=10 L8_STREAMS=80 L8_DATA_ROUNDS=3 python3 l8-lane.py 20`.
  The trigger is deterministic — both builds log hundreds of
  `(24)Too many open files ... AH10309 ... error create input write pipe`
  entries — but no pristine run gives an ASan use-after-free, double free,
  chosen-byte write or deterministic child fault; only exit LeakSanitizer
  noise and Apache's SIGSEGV handler masking pool-internal faults. The
  2.4.67 → 2.4.68 fix moves the three `h2_beam_on_*` registrations after
  successful pipe creation in `c2_setup_io()`. Three instrumentation
  attempts (freed-address tracking, a poison field, and allocation-aware
  freed/live tracking) were negative and are explicitly not to be retried;
  source and module bytes were restored byte-for-byte. Grade rung 1/2:
  suspected UAF with a reachable trigger, no confirmed corruption.
  `l8-lane.py` is tracked; raw `logs/` are gitignored.
- **Apache2Root L9** (mod_auth_digest shared client-entry / auth-state
  corruption): reuse the L3 ASan httpd installs (2.4.68 / 2.4.69) with
  `modules/mod_auth_digest.so` loaded and run
  `cd lab/apache2shell && L9_CHURN=0 L9_VICTIMS=0 python3 l9-lane.py 1`.
  Both builds answer a clean Digest challenge→200 6/6; an unauthenticated
  request quoting the victim's opaque leaves the 2.4.68 victim at 0/6 (all
  401) against 6/6 on 2.4.69 — deterministic auth-state corruption. The churn
  leg (`L9_SHMEM=4096 L9_CHURN=4 L9_VICTIMS=4 python3 l9-lane.py 15`) gives
  1523/825 gc events and 4529/4529, 6616/6616 victim 200s with no ASan
  report, child fault or chosen byte: rung 2 only, no confirmed UAF.
  `l9-lane.py` is tracked; raw `logs/` are gitignored. The dossier CVE
  (CVE-2026-73637) is UNVERIFIED — 2.4.69 `CHANGES` records the fix without a
  CVE number.
- **Freerdp2Shell wake 14**: no committed replay changed. On the live stock
  build from `verify_live.sh`, a scratch client-side delay after the second
  `SNDC_FORMATS` PDU lets FreeRDP's own `SNDC_QUALITYMODE` receive path log
  after the overwrite and fault at `mov (%rax,%r15,8)` with
  `rax=0x4141414141414141`; capture
  `lab/freerdp2shell-src/natural_log_trigger_stock.txt`, raw logs under
  `verify-live-out/wake14/`. `WLOG_FILTER` is required; the no-filter leg is
  clean. No server-side log injection, no off-loopback probe.
- **Freerdp2Shell wake 15**: NEGATIVE control for wake 14. On the same live
  stock build a committed patched `sfreerdp` with only `Sleep(400)` between
  its two `SNDC_FORMATS` PDUs (no scratch delay) still logs
  `realloc failed!` / `SelectFormat failed with 12` /
  `WAKE9_COPY ... b8820=de`, but `SNDC_QUALITYMODE` arrives at the wrap
  instant before the copy; no audio PDU or `SNDC_WAVECONFIRM` follows, so
  there is no post-write log, filter frame or SIGSEGV — only the wake-9
  allocator abort at logoff (`rax=0`). Summary
  `lab/freerdp2shell-src/natural_trigger_no_timing.txt`, raw logs
  `verify-live-out/wake15/`. No committed replay changed; the wake-14 client
  delay remains necessary and `WLOG_FILTER` is still required.
- **Freerdp2Shell wake 16**: FFmpeg dev packages 6.1.1 were unpacked into
  `/tmp` only; pinned 3.32.0 was rebuilt stock `WITH_FFMPEG=ON` and with
  `-DCMAKE_C_FLAGS=-DWITH_DSP_EXPERIMENTAL` (`WITH_VIDEO_FFMPEG=OFF`).
  `lab/freerdp2shell-src/ffmpeg_adpcm_tag2.txt`: stock build is NEGATIVE —
  `PCM encode=1 decode=1`, `ADPCM(2) encode=0 decode=0`,
  `DVI_ADPCM(17) encode=0 decode=0`, server list only AAC_MS and PCM. With
  the experimental macro, tag 2 enters the list and
  `lab/freerdp2shell-src/PocAdpcmTag2.c` matches it with
  `nBlockAlign=8, nChannels=2`: `SelectFormat rc=12`,
  `out_frames=0xfffffffffffffffc`, ASan `WRITE of size 16384 ... 0 bytes
  after an 8820-byte region` in `rdpsnd_server_send_samples`; benign PCM
  gives `rc=0, out_frames=0x89d` and no report. In-process on real library
  bytes on a non-default build; no live session, chosen-byte dereference or
  remote audio. The scratch ASan log under `/tmp` is gitignored; the
  committed driver and trace regenerate the measurement. Tag 17 has no
  FFmpeg encoder in either build.
  Witness #602 independently ESTABLISHED this FFmpeg format-gate result with
  no corrections (`reports/frontier-freerdp2shell.md`).
- **Netatalk2Shell**: the clean `git archive HEAD` replay at `bd30e2d` ran
  twice into separate absolute output directories with 24 PASS / rc 0 and a
  byte-identical trace sha256 `c1bba7fb…`
  (`reports/frontier-netatalk2shell.md`).
- **Iondtn2Shell**: the clean `git archive HEAD` replay at `d4267283` ran
  twice into separate absolute output directories with `ALL CHECKS PASSED
  rc 0` and a byte-identical trace sha256 `e9bc1fff…`
  (`reports/frontier-iondtn2shell.md`).
- **Opensips2Shell**: the clean `git archive HEAD` replay at `7674a58` ran
  twice into separate absolute output directories with 26 PASS / 0 FAIL,
  `ALL CHECKS PASSED rc 0` and a byte-identical trace sha256 `a69657bb…`
  (`reports/frontier-opensips2shell.md`).
- **Unbound2Shell**: the clean `git archive HEAD` replay at `1718991` ran
  twice into separate absolute output directories with 29 PASS / 0 FAIL,
  `ALL CHECKS PASSED rc 0` and a byte-identical trace sha256 `05bf4ace…`
  (`reports/frontier-unbound2shell.md`).
- **Janus2Shell**: the clean `git archive HEAD` replay at `dc1a4e1` ran twice
  into separate absolute output directories with 29 PASS / 0 FAIL,
  `ALL CHECKS PASSED rc 0` and a byte-identical trace sha256 `c8568d26…`
  (`reports/frontier-janus2shell.md`).
- **Rsyslog2Shell**: the clean `git archive HEAD` replay at `ba9a240` ran twice
  into separate absolute output directories with 36 PASS / 0 FAIL,
  `ALL CHECKS PASSED rc 0` and a byte-identical trace sha256 `fc9cd9bb…`
  (`reports/frontier-rsyslog2shell.md`).
- **ProxySQL2Shell**: the clean `git archive HEAD` replay at `3aea985` ran twice
  into separate absolute output directories with 53 PASS / 0 FAIL and a
  byte-identical raw trace sha256 `936fa128…`
  (`reports/frontier-proxysql2shell.md`).
- **PHP2Shell wake 52 (CVE-2026-129291 / GHSA-jm4m-qfqx-967m)**: adjacent
  FPM epoll use-after-free lane, graded rung 2 (fix-sensitive functional
  fault, NOT memory corruption). Affected PHP 8.4.27, fixed 8.4.28; 8.5.12
  also fails. The fix is the 8.4.27 → 8.4.28 `sapi/fpm/fpm/fpm_children.c`
  change that calls `fpm_event_del()` and sets dead workers' stdout/stderr
  fds to `-1` before closing them. The vendor regression test
  `sapi/fpm/tests/ghsa-g3vh-838c-65v7.phpt` (added in 8.5.13, no separate
  published checksum) is embedded verbatim in the committed harness
  `lab/repro/php2shell-cve129291-fpm.py` (sha256
  `f6c4b001ad02b2149a849b0d5d4f8df782316b290ec734e8666915b62bf5e9f4`).
  Provision tarballs with `bash lab/php2shell/provision.sh`, then build the
  same-branch ASan pair with `bash lab/php2shell/build-fpm.sh 8.4.27` and
  `bash lab/php2shell/build-fpm.sh 8.4.28`, producing
  `lab/build/php-<version>-fpm-asan/`. Replay with
  `python3 lab/repro/php2shell-cve129291-fpm.py lab/build/php-8.4.27-fpm-asan lab/build/php-8.4.28-fpm-asan [outdir]`.
  The harness writes the phpt into each build tree and runs `make test`
  against a loopback Unix-socket FPM master; expected affected `FAIL`
  (`bool(false)`, no child-exit warning or replacement), fixed `PASS`
  (`bool(true)`), stdout `affected=FAIL  fixed=PASS` then
  `verdict: CONFIRMED`, rc 0. Docs replay ~09:26Z on the already-provisioned
  build pair observed exactly that stdout and rc 0, with `verdict.txt`
  matching, into a throwaway `/tmp/docs129291-replay/` output directory.
  Raw logs and `verdict.txt` land under the gitignored
  `lab/build/evidence/w52-129291-fpm/` (all of `lab/build/` is
  gitignored) and regenerate with that command. No ASan/UBSan report on the
  failing runs: no confirmed corruption, pointer/chosen-byte control,
  marker, LPE demo or web path. Negative, do-not-repeat limit: swapping
  only the 8.5.13 `fpm_children.c` into 8.5.12, or that plus
  `zend_builtin_functions.c`, left the test FAILing — the flip is not
  isolated to the epoll hunk. Detail in
  [the status report](../reports/php2shell-status.md) and
  [the investigation](../reports/php2shell-investigation.md).
- **PHP2Shell wake 53 (CVE-2026-129496 / GHSA-gr4f-wgx5-jpfv)**: standalone
  stale-tzcache read, rung 3 CONFIRMED (no chosen bytes, rung 4 closed).
  Provision/build: patch-sensitive release-ASan 8.5.12 php-cgi pair in
  `lab/build/php-8.5.12-fpm-release-asan/sapi/cgi/` — `php-cgi-vuln` and
  `php-cgi-fixed` (the latter rebuilt with only the upstream one-line
  `main/main.c` guard `PG(modules_activated) && EG(active)`; the full fix also
  moves `php_date_global_timezone_db` init before `REGISTER_INI_ENTRIES()` in
  `ext/date/php_date.c`). Replay with
  `python3 lab/repro/php2shell-cve129496-tzcache.py <php-cgi-vuln> <php-cgi-fixed>`
  (direct CGI environment, no listener). Expected: affected rc=1, ASan SEGV
  READ in `__strlen_avx2` via `php_error_docref` → `php_format_date` →
  `timelib_get_time_zone_info` → `_estrdup` → `strlen`, with the startup
  invalid-timezone warning in the error log; fixed rc=0, `Hello world`, zero
  ASan; no-invalid-timezone control clean on both; plain 8.4.27 rc=139 vs
  8.4.28 rc=0 cross-branch. Requires default ZendMM and release-ASan —
  `USE_ZEND_ALLOC=0` and debug ASan CLI builds are recorded clean negatives
  (do not repeat). Raw logs and `verdict.txt` are gitignored in
  `lab/build/evidence/w53-129496/`, regenerated by that command; the harness
  is committed.
- **PHP2Shell wake 55 (un-CVE'd DOM reflected-attribute setter UAF)**: rung 3
  CONFIRMED, local CLI only. A side is wake 51's `php-fixed` (8.5.12 ASan DOM
  tree with only the byte-identical 8.5.13 `xml_serializer.c`); B side is
  `php-fixed-domattr`, the same tree after the committed four-file upstream
  patch `lab/php2shell/dom-reflected-attribute-fix.patch`
  (`dom_set_attribute_value()` calls `node_list_unlink(existing->children)`
  before `xmlSetNsProp()`). Replay with
  `python3 lab/repro/php2shell-dom-reflected-attr.py <php-vuln> <php-fixed> [outdir]`.
  Expected: five vendor cases ASAN_UAF on A / CLEAN on B, control
  CLEAN/CLEAN, fixed output byte-exact to vendor EXPECT, `verdict.txt`
  CONFIRMED under gitignored `lab/build/evidence/w55-domattr/` (regenerated by
  the command). ASan: heap-use-after-free READ of 8 at
  `dom_node_parent_get (node.c:247)`, freed by `xmlFreeNodeList <- xmlSetNsProp
  <- dom_element_reflected_attribute_write (element.c:160)`. No SAPI, HTTP
  path, chosen bytes, pointer control or marker; rung 4 closed, and the same
  A/B is not to be repeated.

Xrdp2Shell was handed off from frontier on 2026-11-20 and admitted by the
operator ~20:27Z under standing approval #6. Its charter, docs/task.md entry,
two-pane window (19, inner socket), seed wall and status file are live; wake
trigger units and the presentation.json entry are owed from the person's
full-flag sync (`docs/runtime-pin.md`), never a bare `mishe sync`. The
[brief](../reports/frontier-xrdp2shell.md) pins the sources, harness digests
and expected bytes for rungs 1-3 plus chosen-byte rung 4. A second driver
(`lab/xrdp2shell-real/`, 2026-11-21) reproduces rung 3 and rung 4 on real
compiled xrdp 0.10.6 library bytes through the real DYNVC parse path; no
pointer-sized target was controlled. A third driver
(`lab/xrdp2shell-real/wire_drdynvc_driver.c`) feeds a wire-formatted
TPKT/X.224/MCS/channel/DYNVC_DATA_FIRST PDU to the real `xrdp_rdp_recv()`:
payload 8191 overflows the sink (`WRITE of size 8191`, 0 bytes after the
8192-byte `trans_create` region) through `drdynvc_process_data_first` →
`out_uint8a`, while the 20000-byte harness size is rejected by the MCS 16K
userData limit (8165–~16375 bytes are wire-reachable in one PDU). A full RDP
session, chansrv-negotiated channel open, socket-level PDU trace, stock
live-session layout and the post-auth gate stay UNKNOWN; only loopback COTP
reachability of the lab listener is evidenced.

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
`VERIFY_VALGRIND=1`) replays all drivers. A witness replay contradicted the
earlier "43 PASS / 0 FAIL at HEAD 3b07571" assertion on its host with
42 PASS / 1 FAIL (rc 1), only the L8 N=1000 fault leg failing on allocator
abort text. The repaired `checkfault` accepts that fault family or a nonzero
per-leg rc. From repaired HEAD 31e7243 the author's `VERIFY_VALGRIND=1`
replay is 43 PASS / 0 FAIL, rc 0 (`verify_all_clean_head_run.txt`); a
docs-side run without that flag is 39 PASS / 0 FAIL, rc 0. Witness W33
(#552) re-ran the unmodified `VERIFY_VALGRIND=1` replay from clean HEAD
2a78ee6: 43 PASS / 0 FAIL, rc 0, REPAIR ESTABLISHED; the 42/1 contradiction
is closed. Chosen-byte rung 4 stays NOT DEMONSTRATED.
  A source data-flow pass (2026-11-21) records why: the OOB loop's only store
  is the constant -3 (`channels.c:308-309`); the `order->pos` copy at
  `depay.c:203-207` is guarded by `if (order)` and the static order table
  covers only 1..8; the reorder at `:264-269` is guarded by `order &&` and
  becomes live at high counts only through the fixed `-3` corruption of
  `order`; `gst_audio_info_to_caps` at `:218-219` reads positions the loop has
  already filled with NONE, so no adjacent content leaks. No
  content-controlled sink exists in the pinned source; chosen bytes or an
  arbitrary pointer need a different primitive. No harness or grade changed.

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
table, ASan build, synthetic playback event. Still UNKNOWN at wake 8: stock
allocator layout, a stock wrap-capable server format, an FFmpeg-enabled build
and a real audio source. Wake 9 closed the stock-allocator item and wake 16
the FFmpeg-build item; wake 17 closed the real-audio-source question at source
level: in pinned 3.32.0 the copied bytes and copy stride come from the
server's platform audio capture, not the client, so remote byte choice is not
established in a stock deployment (deployment-specific influence stays
UNKNOWN). Wake 16 also CLOSED the default-format question NEGATIVE on the
measured pinned 3.32.0 + stock FFmpeg 6.1.1 build: both ADPCM tags are
encode/decode 0/0 and the server list is AAC_MS + PCM only; other FFmpeg
versions and platform audio subsystems stay UNKNOWN.
Wake 18 closed grooming in the live stock allocator: extra PCM format records
shift the wLog target by 32 bytes each (`grooming_format_count_stock.txt`),
with a controlled dereference at the shifted offset and an out-of-write
negative; byte choice stays bounded by wake 17.

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
control and execution stay UNKNOWN. Witness replay #761 (2026-11-21)
ESTABLISHED rungs 1/2/3 and rung 4 at INSTRUMENTED chosen-value control with
those conditions preserved; its one nit was source-line citations six lines
too high, corrected in the brief, status and PROVENANCE while the
digest-pinned harness bytes were left unchanged.

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

Asterisk2Shell was handed off from frontier on 2026-11-21 ~04:09Z (tape #550,
brief commit `4c1d50d`) and admitted by the operator ~04:2xZ under standing
approval #6. The two-pane window (30, inner socket), seed wall, registry entry
and brief were already live; the charter, `docs/task.md`, README, seed status
and this lane index are now updated. Wake trigger units and the presentation
entry are owed from the person's full-flag sync (`docs/runtime-pin.md`), never a
bare `mishe sync`. The harness compiles the verbatim pinned upstream
`ootrace.c:35-53`, so rungs 1/2/3 are on real function bytes; rung-4 chosen
bytes land in harness stack storage only. GHSA and CVE disagree on impact and
the conservative availability-only ceiling applies; no live daemon, H.323
socket, packet-path reachability or RCE was demonstrated.

Netatalk2Shell was handed off from frontier on 2026-11-21 ~05:01Z (tape #574,
brief commits `bd30e2d` / `c37e96d`) and admitted by the operator ~05:0xZ
under standing approval #6. The two-pane window (31, inner socket), seed
wall, registry entry and brief were already live; the charter,
`docs/task.md`, README, seed status and this lane index are now updated. Wake
trigger units and the presentation entry are owed from the person's
full-flag sync (`docs/runtime-pin.md`), never a bare `mishe sync`. The harness
compiles the verbatim pinned upstream `directory.c:147-203`, so rungs 1/2/3
are on real function bytes; rung-4 chosen bytes land in harness stack storage
only. Reachability needs an authenticated AFP session and a cross-device
rename path inside a share; no live afpd, socket, mount, useful-pointer
control or execution was demonstrated.

Iondtn2Shell was handed off from frontier on 2026-11-21 ~05:25Z (handoff #585,
announcement #586, commits `fefc2b7` / `de67924`) and admitted by the operator
standing approval #6. The two-pane window (32, inner socket), registry entry,
seed wall and brief were already live; the charter, `docs/task.md`, README,
seed status and this lane index are now updated. Wake trigger units and the
presentation entry are owed from the person's full-flag sync
(`docs/runtime-pin.md`), never a bare `mishe sync`. The harness compiles the
verbatim pinned upstream `nm_mgr_print.c` lines, so rungs 1/2/3 are on real
function bytes; rung-4 chosen bytes land in the harness allocator's adjacent
region only. The remote path needs non-default `-l -r` logging; both primary
advisories claim availability only, and the GHSA/CVE identity conflict is
preserved. No live `nm_mgr`, socket, AMP payload or execution was demonstrated.

Opensips2Shell was handed off from frontier on 2026-11-21 ~06:05Z (handoff #606,
commits `b4bc31a`, `92a9c15`, `41818af`) and admitted by the operator ~06:2xZ
under standing approval #6. The two-pane window (34, inner socket), registry
entry, seed wall and brief were already live and capture-verified; the charter,
`docs/task.md`, README, seed status and this lane index are now updated. Wake
trigger units and the presentation entry are owed from the person's full-flag
sync (`docs/runtime-pin.md`), never a bare `mishe sync`. The harness compiles
verbatim pinned `xmpp.h` / `xmpp.c` lines, so rungs 1/2/3 are on real upstream
bytes; rung-4 chosen bytes land in the no-canary lab frame only. Reaching the
sink pre-auth needs `backend=server`; RCE remains an advisory claim depending
on canary/ASLR/NX. No live receiver, socket, XMPP stanza, pointer control or
execution was demonstrated.

Unbound2Shell was handed off from frontier on 2026-11-21 ~06:32Z (handoff
#620, commits `f9295a0`, `34fd212`, `e76e23d`) and admitted by the operator
~06:5xZ under standing approval #6. The two-pane window (35, inner socket),
registry entry, seed wall and brief were already live and capture-verified;
the charter, `docs/task.md`, README, seed status and this lane index are now
updated. Wake trigger units and the presentation entry are owed from the
person's full-flag sync (`docs/runtime-pin.md`), never a bare `mishe sync`.
The harness compiles the verbatim pinned `ds_create_dnskey_digest()` lines,
so rungs 1/2/3 are on real upstream bytes; the 236-byte heap overflow is
measured with the harness's `NDEBUG` stub, while shipping compile flags are
UNKNOWN. Rung-4 chosen bytes land in the synthetic lab frame only. No live
resolver, DNSKEY wire bytes, compression-pointer path, DNSSEC configuration,
pointer control or execution was demonstrated; witness #619 reached
ESTABLISHED AS CLAIMED with no grade correction.

Janus2Shell was handed off from frontier on 2026-11-21 ~07:00Z (handoff #632,
commits `500db0e`, `8e754c0`) and admitted by the operator ~07:1xZ under
standing approval #6. The two-pane window (36, inner socket), registry entry,
seed wall and brief were already live and capture-verified; the charter,
`docs/task.md`, README, seed status and this lane index are now updated. Wake
trigger units and the presentation entry are owed from the person's full-flag
sync (`docs/runtime-pin.md`), never a bare `mishe sync`. The harness executes
the verbatim pinned `.mjr` parse blocks, so rungs 1/2/3 are on real upstream
bytes; rung-4 chosen bytes and the adjacent local overwrite land in the
synthetic lab frame, with a canary control abort on the host-default build.
No live Janus process, HTTP/SDP path, real `.mjr` bytes, shipping flags,
pointer control or execution was demonstrated; witness replay was requested
in parallel and no verdict was in hand at admission.

Rsyslog2Shell was handed off from frontier on 2026-11-21 ~07:19Z (commit
`759215f`) and admitted by the operator ~07:2xZ under standing approval #6.
The two-pane window (37, inner socket), registry entry, seed wall and brief
were already live and capture-verified; the charter, `docs/task.md`, README,
seed status and this lane index are now updated. Wake trigger units and the
presentation entry are owed from the person's full-flag sync
(`docs/runtime-pin.md`), never a bare `mishe sync`. The harness executes the
verbatim pinned `contrib/imhttp/imhttp.c` struct and function blocks, so
rungs 1/2/3 are on real upstream bytes; rung-4 chosen bytes land past a
zero-length heap allocation in a synthetic lab frame. No live rsyslog
process, imhttp module, CivetWeb listener, HTTP request, shipping compile
flags, caller-side pointer control or execution was demonstrated; witness
replay was requested in the handoff and no verdict was in hand at admission.

ProxySQL2Shell was handed off from frontier on 2026-11-21 ~07:46Z (handoff #658,
commit `3aea985`) and admitted by the operator ~07:5xZ under standing approval
#6. The two-pane window (38, inner socket), registry entry, seed wall and brief
were already live and capture-verified; the charter, `docs/task.md`, README,
seed status and this lane index are now updated. Wake trigger units and the
presentation entry are owed from the person's full-flag sync
(`docs/runtime-pin.md`), never a bare `mishe sync`. The harness executes the
verbatim pinned `v3.0.8`/`v3.0.9` first-read blocks, so rungs 1/2/3 are on real
upstream bytes; rung-4 chosen bytes land past the 32768-byte `queueIN` in a
synthetic guard-mapped lab frame. No live ProxySQL daemon, frontend listener,
stock allocator, PostgreSQL config gate, caller-side pointer control or
execution was demonstrated; the advisory's real-daemon ASan frames and stock
crash remain claims, and witness replay was requested (#657) with no verdict in
hand at admission.

Strongswan2Shell was handed off from frontier on 2026-11-21 ~08:06Z (handoff
#670, commits `37e0b1a` / `cda059a` / `6b9ac2d`) and admitted by the operator
~08:1xZ under standing approval #6. The two-pane window (39, inner socket),
registry entry, seed wall and brief were already live and capture-verified;
the charter, `docs/task.md`, README, seed status and this lane index are now
updated. Wake trigger units and the presentation entry are owed from the
person's full-flag sync (`docs/runtime-pin.md`), never a bare `mishe sync`.
The harness executes the verbatim pinned `6.0.5`/`6.0.6` `libsimaka` ranges,
so rungs 1/2/3 are on real upstream bytes; rung-4 chosen bytes land past the
wrapped 12/14-byte allocation in a synthetic bounded-copy frame, while the
real-libc negative is preserved separately. No live daemon, IKEv2/EAP path,
local-termination config, shipping allocator, caller-side pointer control or
execution was demonstrated; the advisory's potential RCE and the public
exploit-module claims remain claims. Witness replay #669 returned verdict #675
(08:11Z): ESTABLISHED AS CLAIMED, no grade correction, rung 4 INSTRUMENTED
only.

Memcached2Shell was handed off from frontier on 2026-11-21 ~08:25Z (handoff
#686, commits `b7fb237` / `163433e`) and admitted by the operator ~08:29Z
under standing approval #6. Ubuntu LP#2161693 and openSUSE-SU-2026:21872-1
are distro advisories; no upstream CVE/GHSA was found (UNKNOWN, not a proven
negative). The two-pane window (40, inner socket), registry entry, seed wall
and brief were already live and capture-verified; the charter, `docs/task.md`,
README, seed status and this lane index are now updated. Wake trigger units
and the presentation entry are owed from the person's full-flag sync
(`docs/runtime-pin.md`), never a bare `mishe sync`. The harness executes the
verbatim pinned `crawler.c` ranges, so rungs 1/2/3 are on real upstream
bytes; rung-4 chosen key bytes land past the 131072-byte buffer only in a
zeroed 1 MiB collaborator, while the guard-mapped and real-libc paths fault
before stable chosen bytes. No live daemon, socket-buffer timing, shipping
allocator, caller-side pointer control or execution was demonstrated; the
LP's daemon ASan frame is from a different build and stays a claim. Witness
replay #685 was requested with no verdict in hand at admission.

Ipfixcol2Shell was handed off from frontier on 2026-11-21 ~08:35Z (handoff
#698, commits `a5f3aed` / `a832dcd`) and admitted by the operator ~08:44Z
under standing approval #6. The advisory pins `CVE-2026-122127` /
`GHSA-4575-chq4-crfc`, vulnerable tags `v2.7.1`/`v2.8.0` and fixed `v2.9.0`,
with fix commit `fd5cb168efb4b864d33f655174711b2779cef502`. The two-pane
window (41, inner socket), registry entry, seed wall and brief were already
live and capture-verified; the charter, `docs/task.md`, seed status and this
lane index are now updated. Wake trigger units and the presentation entry are
owed from the person's full-flag sync (`docs/runtime-pin.md`), never a bare
`mishe sync`. The harness compiles the verbatim pinned `Lz4Decoder.cpp`
under `#line` against the host's real `liblz4.so.1`, so rungs 1/2/3 are on
real upstream bytes; rung-4 chosen bytes land past the 24-byte ring only in
a 1 MiB mmap collaborator, with an `0x41` differential, a benign zero
control and a stock-build fault as preserved negatives. No live collector,
loopback TCP input, shipping allocator, caller-side pointer control or
execution was demonstrated; the advisory's daemon frame and severity stay
claims. Operator clean-archive replay: two HEAD (`18cae3d`) extractions,
13 PASS / 0 FAIL each, raw trace
`sha256=e9c06f530d09912603ed379913699b2f1e63e08ab64b8cfcefdae0b47f3cd89f`
byte-identical between directories, to the working tree and to the brief.
Witness replay #697 was requested with no verdict in hand at admission.

**2026-11-21 ~09:00Z live loopback addendum.** Witness replay #712 returned
ESTABLISHED AS CLAIMED. `lab/ipfixcol2shell-live/` now compiles the plugin's
real v2.8.0/v2.9.0 `Lz4Decoder.cpp`, `DecodeBuffer.cpp`, `ByteVector.cpp` and
`read_until_n.hpp` verbatim (sha256-verified tarball staging by `stage.sh`),
accepts a 127.0.0.1:0 TCP connection and replays the same wire bytes. `sh
run.sh`: 9 PASS / 0 FAIL, trace
`sha256=b81b947cf21f4ab92c6f268534dfbe8fbd6c3eb7da35ee5e9caab000e5471600`
byte-identical in three runs. Rung 3 holds at real upstream frame numbers;
the stock-glibc build faults in `unlink_chunk` with `rax=0x5a…58` / `0x41…40`
(differential) and a crafted payload puts chosen `0x4141414141414141` bytes
in a pointer that `unlink_chunk+39` dereferences. Still INSTRUMENTED: no
valid target address or execution. Full daemon remains UNKNOWN (no libfds,
lz4-dev or rst2man on this host). Full evidence:
`lab/ipfixcol2shell-live/RESULTS.md`.

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
  `live_session_*.log`. Stock allocator behaviour was measured in a later pass
  (live chosen-byte overwrite under stock glibc: 7564 OOB bytes at offsets
  8820..16383, first OOB byte client-chosen, glibc `double free or
  corruption (!prev)` on teardown, benign control in bounds). Wake 16 later
  closed the FFmpeg-build UNKNOWN; see the addendum below.
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
  Wake 12 (scratch observation, not part of the one-command replay): a
  temporary `fprintf` inserted immediately before the real `CopyMemory` in
  `rdpsnd_server_send_samples` (`rdpsnd_main.c:771`) dumps
  `malloc_usable_size(out_buffer)` and the following glibc chunk headers once
  on the first 16384-byte OOB copy; the source was restored and the plain
  build rebuilt afterwards, leaving the five committed replay patches and
  their digests untouched. Three loopback `-auth` sessions (ports
  23143-23145, Sample client `/sec:rdp /u:test /p:test /sound`) produced
  byte-identical layouts apart from the ASLR arena base, captured in
  `lab/freerdp2shell-src/heap_layout_stock.txt`. Decisive lines:
  `HEAP12 base=... usable=8824 cframesize=16384` and
  `HEAP12_CHUNK off=9056 sz=64 ... data=`, whose two pointer values both
  equal `base+0x2340`; `WAKE9_COPY ... b8820=de` replaces them. This makes
  pointer-bearing heap data in the write path OBSERVED; no target object,
  chosen pointer value, controlled dereference or off-loopback probe was demonstrated.
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
  Witness W33 (#548) established both drivers as claimed on replay. The
  build-tree limit was later closed by `verify_cleanroom.sh`: 15/15 assertions
  pass after fresh ASan and plain library builds and all three drivers rebuilt
  from unchanged pinned digests (`lab/xrdp2shell-real/cleanroom-replay.txt`).
  Witness W41 (#617) independently ESTABLISHED that clean-room claim from two
  fresh builds with its own work dirs (`XRDP_CLEANROOM_WORK=/tmp/witness-xrdp-cr`
  and `-cr2`): fresh 0.10.6 source `440a5381…`, all three drivers rebuilt from
  unchanged sha256, 15/15 passes and rc 0 both times, gate traces byte-identical
  (`chosen.txt` `337cbfc9…`, `wire_20000.txt` `f312c4ad…`). Fresh `.a` digests
  differ between builds because static archives embed member timestamps and
  paths, so the gate results are the reproducing evidence. W41 covers only
  the xrdp claims; the in-process boundary and PR:L stay unchanged.
  On this host the committed `real_drdynvc_driver.c` needs
  `-include config_ac.h` and the `-I$B` include path first; the RUNBOOK
  correction is recorded there. The in-process boundary is unchanged.
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
  The rung-5 lane (`462e887`, witness-ESTABLISHED by #1118) uses
  `bash run_live_rce.sh calibrate|exploit|trace|safe|fixed` in this directory;
  its recipe, `system(rdi=forged SSL)` trace, committed `logs/rce_*` outputs and
  the witness's varied-command replay are in the 2026-11-21 addenda above.

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
