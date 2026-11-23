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
call stays rung-4 mechanics. FreeSWITCH, Iec61850 and Ruby R5 are
witness-ESTABLISHED under their labeled conditions (#1118/#1127; Ruby
clean-archive replay of `8b9d8f9`). Their recipes and controls are in the
addenda below. Full contract:
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
| Ruby2Shell | [report](../reports/ruby2shell-investigation.md) | `bash lab/ruby2shell/provision.sh` | plain build `lab/build/plain/ruby-3.4.12-plain/bin/ruby` (recipe in report); ASan build `lab/build/ruby-3.4.12-asan` | `lab/repro/ruby2shell-rung1.rb`, `stageA.rb`, `stageC.sh`, `stageB-http.sh`, `stageB-rails.sh`, `bash lab/repro/ruby2shell-stageC-http.sh 3 2` with `stageC-http.ru`; rung 5 `bash lab/repro/ruby2shell-rung5-http.sh attack <tag>` (repeat with distinct tags), then `control <tag>` and `fixed <tag>` (plain 3.4.13 build recipe in the report; expect distinct markers on attacks, none on controls) (Sinatra request-thread Stage C: 3/3 attacks read chosen bytes at the nominated address in the HTTP response, 2/2 controls clean; the process aborts in worker-thread teardown after readback — depth result, no grade change); copy-out lane: `valgrind --error-limit=no lab/build/plain/ruby-3.4.12-plain/bin/ruby -e 's="\xDF".b*21; s.force_encoding(Encoding::ISO_8859_1); p s.upcase.bytesize'` — N=21 shows `Invalid write of size 1` at `case_map (iso_8859_1.c:293)` and `Invalid read of size 2` via `rb_str_casemap (string.c:7857)`, `outlen=42`; N=20 clean, `outlen=40`. The read byte is the same fixed `0x53`, so this is rung-3 class, not a leak or rung 4 |
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
| Vrpn2Shell | [brief](../reports/frontier-vrpn.md), [wire rung-3 / rung-4 report](../reports/vrpn2shell.md) | CVE record `CVE-2026-123200` (`f4ee3212…`), fix commits `0da5b0b…` / `c893b58…`, pinned `vrpn_Connection.C` at `79deb000…` (`9eaa1045…`), fix-commit tarball (`b5258e99…`); every URL and hash in `lab/frontier/vrpn2shell/PROVENANCE.md`, including the superseded 28-byte header hash; W5 read-only upstream release lookup in `lab/frontier/vrpn2shell/UPSTREAM-RELEASE-LOOKUP.md` | `bash lab/frontier/vrpn2shell/run.sh <outdir>` and `gdb-wire.sh <outdir> <port> <index>` now send the required 24-byte header (the old 28-byte header pinned `i=0` for every index); live wire ASan: `bash lab/frontier/vrpn2shell/probe-gdb.sh <outdir> 13901 100`, expect `WRITE_SITE_HIT i=100` and ASan `stack-buffer-overflow WRITE of size 1` at real `vrpn_Connection.C:4554` in the plant-started loopback server; plain saved-rip: `bash lab/frontier/vrpn2shell/probe-plain-rip.sh <outdir> 13905 120`, expect `saved_rip` low byte `0x…88 → 0x…00` and SIGILL with canary and rbp intact; second sink TYPE_DESCRIPTION (message type -2): `VAR=type_name LINE=4482 MSGTYPE=-2 bash lab/frontier/vrpn2shell/probe-gdb.sh <outdir> 13911 100`, expect `WRITE_SITE_HIT i=100` at `handle_type_message:4482` and ASan `WRITE of size 1` with shadow frame `[112,212) 'type_name'` and access at offset 212 (short index 4 and fixed `:4486` at index 100 are clean controls); plain: `VAR=type_name MSGTYPE=-2 LINE_PRE=4482 LINE_POST=4484 bash lab/frontier/vrpn2shell/probe-plain-rip.sh <outdir> 13914 120`, expect `saved_rip 0x…d88 → 0x…d00` and SIGILL (fixed plain 120 clean). `--msgtype` defaults to -1, so W1 commands are unchanged; gitignored `out-type-*` gdb logs regenerate with those two commands. Direct ASan harness: `g++ -fsanitize=address -fno-omit-frame-pointer -g -I lab/frontier/vrpn2shell/src/vrpn-07.36 lab/frontier/vrpn2shell/harness/handler_direct.cpp lab/frontier/vrpn2shell/build-asan-07.36/libvrpnserver.a -o handler_direct` then `handler_direct 100` | Observed W98: ASan `WRITE of size 1` at real `vrpn_Connection.C:4554` for indices 100/128/-256; fixed commit has no write-site fault; gdb proves a real TCP message reaches `:4535`. W1 author-only correction: the earlier "live-server sweep negative, different frame layout" was the injector's 28-byte header; wire rung 3 and the plain-build saved-rip rung-4 boundary are now observed at the labeled g++ 13.3.0 Debug layout. W2 (author-only) repeats both limbs over real loopback TCP through type -2 into `type_name[i] = '\0'` at `:4482`: index 100 ASan fault in `handle_type_message`, index 120 plain saved-rip zeroing and SIGILL, with short-input, fixed-commit and fixed-plain controls clean. Byte is a fixed NUL at a chosen offset, no chosen byte or pointer control, no command side effect, no rung 5. Admitted under standing #6 (~01:1xZ in task.md); witness replay of both wire limbs (W1 and W2) pending. W5 resolves the released-fixed UNKNOWN to an authoritative negative by read-only metadata lookup: `git ls-remote --tags` has 35 refs with no 07.37/07.38/07.39 tag, the GitHub releases API lists v07.36 (2025-06-28) as newest, the v07.39 tarball URL is 404, and both fix commits are untagged 2026-10-22 master commits; the fixed control stays the pinned commit tarball and no build, grade or witness fact changes. |
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
| ProFTPD2Shell | [brief](../reports/frontier-proftpd.md) | CVE-2026-119146 / GHSA-wj68-6748-262r (CNA GitHub_M 2026-10-30, CWE-120, CVSS 3.1 5.6 / CVSS 4.0 6.3), affected `< 1.3.9e` and `< 1.3.10rc5`, fixed 1.3.9e / 1.3.10rc5, fix `502d280b8d0ef72e44c6dd0a35a9405af0a1e301`; hash-pinned tagged 1.3.9d (`68b094b1…e84e4ec`) / 1.3.9e (`7db91f22…cfce5eb`) tarballs and patch (`07cc6b25…e01f045e00d79`) in `lab/frontier/proftpd2shell/src/SHA256SUMS` (3/3 OK at 00:13Z), git-refs `f59f248e…` / `fc3f908a…` / `23803950…`; instrumented source `mod_rewrite.c.instr` tracked in `c754960` for witness rebuild | RUNG 1–4 — `cd lab/frontier/proftpd2shell/src && sha256sum -c SHA256SUMS`; build pinned 1.3.9d with `--with-modules=mod_rewrite --disable-shared` (ASan build: `clang -g -O0 -fsanitize=address`; plain build: `gcc -g2 -O2`), run a non-root daemon bound to 127.0.0.1:21874 with `wire/etc/proftpd.conf`; `bash wire/run-trigger.sh` and `wire/run-bounded.sh` send the 2048-byte and 200-byte keys with `wire/client.py`/`client2.py`; `bash wire/run-marker.sh` under `setarch -R` with `CLIENT=client4.py` sends the 1030-code-point key and expects `RewriteLog` `parsing 'NOOP command successful'`, `NOOP=200`, `PWD=257`. Later limbs: run `run-marker.sh` with `CLIENT=client4.py` and no `setarch -R` for the ASLR-on negative, and `bash wire/run-prelogin.sh` (config `wire/etc/proftpd-prelogin.conf`, client `wire/client5-prelogin.py`) under `setarch -R` for the pre-login marker; expect `501 Login incorrect` on `USER`, marker in `RewriteLog`, no `PASS`, session up. With `wire/client6-partial.py` and `bash wire/run-partial-sweep.sh` (no `setarch -R`), a 1025-code-point key replaces only `substr`'s low byte and gives B-dependent parser-string lengths; `wire/run-partial-control.sh` logs `parsing ''` for a 200-byte key. Raw output under `wire/evidence/` is intentionally not committed and regenerates with those runners. The 01:10Z control-flag limb: `bash wire/run-engine.sh` with `ENGINE_ZERO=1` and `wire/client7-engine.py` sends a 1281-code-point key that also zeroes `rewrite_engine`; expect one `executing RewriteRule` and no short-STOR map substitution on a later command, versus two and one with `ENGINE_ZERO=0`, on both instrumented and plain builds under `setarch -R`. The 01:44Z ASLR-on limb (author-only): plain build, config `wire/etc/proftpd-leak.conf`, authenticated `%m STOR`, no `setarch -R` — `wire/client-leak-warm.py` and `wire/sweep-substr-leak.py` leak the eight `substr` bytes through `pstrdup` into `maps subst'd pattern:`; expect a heap mmap pointer such as `0x000056e9a4efeae8`, and zero log strings ending `55 55 55` in the 256-byte redirect sweep (`wire/evidence/oneserver-aslron-clean.txt`). Then `wire/client9-engine-aslron.py` sends the 1281-code-point zeroing key without any address computation: expect 2 `executing RewriteRule` lines in 8 of 9 engine-zero runs vs 3 in 5/5 `ENGINE_ZERO=0` controls, no signals, `NOOP=200` / `PWD=257`; the `aslron-ab-3-1` negative is preserved, not averaged. Check the listening PID with `fuser -n tcp 21904` before every run — an earlier apparent ASLR-on absolute write came from a stale `setarch -R` child and was discarded; `wire/client-aslr-leak-write.py` is the negative attempt. Raw `wire/evidence/aslron-ab-*.txt` and `rewrite-aslron-ab-*.log` stay gitignored. 03:40Z ASLR-on chosen-string readback: from `lab/frontier/proftpd2shell/wire`, a free port 21914, config `etc/proftpd-leak.conf`, `proftpd-vuln-plain` and `randomize_va_space=2`, no `setarch -R`; marker `PAT='ZZZZZZZZZZZZZZZZNOOP-ASLR-OK!' TAG=m1 python3 client13-aslr-marker.py`, control `PAT='ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ' TAG=c1 python3 client13-aslr-marker.py`. Expect `NOOP-ASLR-OK!` at offsets 17–19 of the wild `parsing '...'` read in 5/5 marker trials and only Z filler in 5/5 controls, all `SIGNALS 0`, `NOOP 200`, `PWD 530`, run-varying `PTR_OLD` (e.g. `0x62a49b78a0e8`), final-client recheck 3/3 PRESENT vs 3/3 absent; raw `wire/evidence/{m,c,wm,wc}-[1-5].txt` and paired `rewrite-*.log` are untracked (no ignore rule matches). The rung-5 call-path negative is in the report | Witness W99 (message #1207) independently built both pins in `/tmp/w99-proftpd` from the tarballs and replayed with only its own binaries: ASan `global-buffer-overflow WRITE of size 8` at `mod_rewrite.c:1670`, 200-byte control clean; uninstrumented `gcc -O2` plain build under `setarch x86_64 -R` with `client4.py` gave the marker, NOOP=200, PWD=257, safe input `parsing ''`; own v1.3.9e ASan build rejects the long key (550, session alive, no ASan file). ALL ESTABLISHED AS CLAIMED at these conditions; rung 5 not attempted. Witness W100 (message #1222) independently replayed the three later limbs with its own uninstrumented `gcc -g2 -O2` build from the pinned 1.3.9d tarball (sha `aae1ec303efe...`) in `/tmp/w100-wire`, loopback only: the ASLR-on negative (SIGSEGV in `pr_vsnprintfl`, no marker, PIE base changed), the `%m USER` pre-login marker (PR:N, ASLR-off, non-default config; 200-char USER control logs `parsing ''`) and the one-byte relative redirect under ASLR on (PR:N, B≈0x01..0xff gives ≈246−B character runs, no stable landing target) are all ESTABLISHED at those labeled scopes; rung 5 unclaimed. Witness #1834 later replayed the 03:17Z extended over-read and 03:40Z chosen-string readback from its own clean-archive gcc 13.3.0 builds and graded them ESTABLISHED at the labeled ASLR-on rung-4 scope with fixed 1.3.9e rejection controls (PAT_HIT 17 vs 0, client12 200/1062/1158, fixed LEAK NONE and 550), no refutation or NIT. The 01:10Z, 01:44Z, 02:10Z and 02:13Z limbs are author-only, witness replay owed. Other ASLR-on routes stay UNKNOWN |
| Soes2Shell | [brief](../reports/frontier-soes.md) | hash-pinned `v3.2.0` / `v3.2.1` tag archives and full fix diff in `lab/frontier/soes2shell/src/SHA256SUMS` (digests `24c0cb2f…` / `301d9f19…` / `f54bdd7c…`; 3/3 OK at 00:16Z, recomputed by the mind and W102); advisory RRTL-261119-01, CVE-2026-129794 / CVE-2026-129811; adjacent CVE-2026-129796 uses the same pinned pair and fix diff | `bash lab/frontier/soes2shell/harness/build.sh` builds real pinned `esc_eoe.c` / `ecat_slv.c` + `esc_coe.c` with stubs, ASan and plain, and now also builds the CVE-2026-129796 `coe_download_{3.2.0,3.2.1}` / `coe_download_asan_{3.2.0,3.2.1}` binaries from `harness/coe_download_overflow.c` against both pinned trees; no upstream HAL build on this host | `eoe_overflow` with 7×96-byte fragments: ASan `WRITE of size 96` at `esc_eoe.c:797`, plain canary +64 bytes at `+608`; six fragments, real 3.2.1 clean. `pdo_overflow` with 510 mapping bits: ASan `global-buffer-overflow WRITE of size 64` at `ecat_slv.c:172`, plain `SMmap2[0].obj` chosen pointer and real `COE_pdoUnpack()` chosen write; fixed 3.2.1 and modeled-clamp clean. CoE-mailbox harness drives the same write from crafted mailbox bytes through real `ESC_coeprocess`. Adjacent CVE-2026-129796: `memset` mode gives ASan SEGV from `__asan_memset` ← `SDO_download esc_coe.c:827` ← `ESC_coeprocess :1501` (plain SIGSEGV, rc 139); `copy-global` gives `global-buffer-overflow WRITE of size 64` at `copy2mbx esc_coe.c:248` ← `SDO_download :864`, plain dump shows chosen `0x5a` with `oct_canary_bytes=56` past the 8-byte global; both malicious modes clean on real pinned 3.2.1, ASan and plain; writable OD entries are a modeled precondition (shipped demo entries are `ATYPE_RO`), and one transient `canary[0]=0x90` read is preserved as unexplained, with the claim resting on the final dump. Evidence `lab/frontier/soes2shell/evidence/replay-soes2shell-20261122/cve129796/INDEX.txt` lists 20 runs. Wire input is NOT replayed: `ESC_read` bytes and mapping values are harness-supplied; `CapEff=0` blocks AF_PACKET. Witness W102 (#1231) independently re-extracted both pins, rebuilt all 12 binaries with clang 18.1.3 from clean HEAD `e0a004c` and returned ESTABLISHED at exactly the original-12-case scope with byte-variation and mapping-length sweeps; logs `/tmp/w102-soes/results/*.out`. The CVE-2026-129796 limb is author-only — W102's replay does not cover it. |
| Netx2Shell | [brief](../reports/frontier-netx.md), [investigation](../reports/netx2shell-investigation.md) | GHSA-rcv5-vfff-25gh (published 2026-10-02) and CVE-2026-93475, CVSS 9.8 CWE-787/CWE-1284; affected `<= 6.5.1.202602` → fixed `6.5.2.202603`, fix commit `4adb237093c1f578c876e28c3752affaaf159ee0`; tag archives and the real upstream 8192-bit DER fixture SHA-256-pinned in `lab/frontier/netx2shell/src/SHA256SUMS` and `PROVENANCE.md`, all three digests recomputed 3/3 OK by the operator at admission | `cd lab/frontier/netx2shell/src && sha256sum -c SHA256SUMS` (3/3 OK); from `lab/frontier/netx2shell` run `bash harness/build.sh` (clang 18.1.3 ASan) and `bash harness/build-plain.sh` (unmodified pinned sources, `-g -O0 -fno-omit-frame-pointer -no-pie`); `bash harness/evidence-w1/run.sh` regenerates the chosen-byte gdb/ASan evidence in ~4 s; `bash harness/tls/run.sh` rebuilds and replays the TLS handshake in ~3 min; W3 crafted certificate: `bash harness/tls/run-crafted.sh` regenerates the DER header from `harness/tls/gen-crafted-cert.py`, rebuilds, and replays runs A, B and the fixed control | Vulnerable `netx_vuln` with the real fixture: `parse_status=0 modulus_bytes=1024`, ASan `global-buffer-overflow WRITE of size 1` 0 bytes after `decrypted_signature[512]` via `nx_crypto_huge_number.c:1783` ← `nx_crypto_rsa.c:147/:393` ← `nx_secure_x509_certificate_verify.c:230`. Plain build writes 1024 bytes at `decrypted_signature+0..+1023` (byte 1024 and beyond unchanged); with attacker-chosen `s` starting `0x40` then 511 `0xff` bytes, `e = 2`, `n = s² − T`, all 1024 output bytes equal `T`, run A carries `de ad be ef ca fe ba be` at +512..+519, run B changes only +512 to `5a`, the fixed build writes zero bytes with `verify_status=131074`, and an `e = 1` control writes only 512 bytes. TLS handshake: real oversized certificate reaches the same sink through `nx_secure_tls_session_start` → `nx_secure_x509_certificate_verify` → `_nx_crypto_huge_number_extract` under ASan; fixed tag and a 2048-bit safe-input certificate are clean (`REMOTE_CERT_CALLBACK len=702` on the vulnerable build). W3 crafted certificate: the DER modulus, exponent and signature themselves carry `n = s² − T`, `e = 2`, `s` (identical DER lengths), and the client reaches the same write through the full TLS handshake: ASan `global-buffer-overflow WRITE of size 1` 0 bytes after `decrypted_signature[512]` (`harness/tls/run-vuln_crafted_asan.txt`), plain gdb at `nx_secure_x509_certificate_verify.c:270` shows `modulus_length=1024`, `exponent_length=3`, `sig_length=1024`, zeros at 504..511 and `de ad be ef ca fe ba be` at 512..519, with the adjacent global `generated_hash` beginning at +512; run B changes only +512 to `5a`; the fixed build has no ASan report but rejects before verification and stalls 20 s — weaker than a clean pass, recorded as such. Host-socket loopback is structurally unavailable (pinned tree has no host driver); transport is the in-process RAM driver. No pointer control or rung 5; witness #1262 returned ESTABLISHED at the claimed scope. Admitted 2026-11-22 ~01:4xZ under #6; commits `d111bae`, `3f4ac83`, `3923066`, `8f888d2`, `31dba3c`. |
| Wazuh2Shell | [brief](../reports/frontier-wazuh.md), [wire reach](../reports/wazuh2shell-wire-reach.md), [live crash](../reports/wazuh2shell-live-crash.md), [1514 wire](reports/wazuh2shell-1514-wire.md), [heap adjacency](../reports/wazuh2shell-heap-adjacency.md) | GHSA-gc4j-j9fg-4cfr (saved HTML) and NVD CVE-2026-74045 (saved JSON), CVSS 4.0 7.1 / CWE-122; affected `wazuh-manager >= 3.12.0, < 4.14.8`, fixed 4.14.8; v4.14.7 and v4.14.8 raw sources, advisory records and harness SHA-256-pinned in `lab/frontier/wazuh2shell/src/SHA256SUMS` and `PROVENANCE.md`, all 13 digests recomputed 13/13 OK by the operator at admission; five more SHA-256 pins for the 1514 trace in `reports/wazuh2shell-wire-reach.md` | RUNG 3/4 — from the repo root run `sha256sum -c lab/frontier/wazuh2shell/src/SHA256SUMS` (13/13 OK; paths are repo-relative), then `cd lab/frontier/wazuh2shell && bash run.sh out-direct`, which extracts four verbatim top-level functions from each pinned `syscheck.c` and builds ASan and plain binaries for both tags. Source-level wire reach: `cd lab/frontier/wazuh2shell && bash trace-wire.sh` re-fetches the five tagged upstream files into gitignored `trace-src/`, checks each SHA-256 and prints the chain lines (`secure.c:57/:771/:956/:964`, `mq_op.h:21/:23`, `analysisd.c:1231/:1560/:1579/:2434`, pinned `syscheck.c:1265/:1288/:1436/:1551/:1680`, fixed v4.14.8 `:1548/:1694/:1720`); it contacts no target. W108 plain-daemon readback: rebuild the two ASan-instrumented objects without ASan (`CFLAGS="-g -O0"`, `DEBUG=1`), verify `nm -D wazuh-analysisd | grep -c __asan` = 0, run that binary under `gdb -batch` breaking at `syscheck.c:1680` (before) and `:1706` (after), print `lf->full_log` and its chunk words from +400 to +600, then drive the 228-byte advisory JSON through the same AF_UNIX datagram as the ASan live-crash leg; the 406-byte `poc-control.json` goes through the same breakpoints. Scripts `live-src-plain/{readback,before}.gdb` and `run-readback.sh` live in the gitignored lab tree; logs `readback-plain-{exploit,control}{,-before}.gdb.log`. | v4.14.7 advisory-derived 228-byte JSON: ASan `heap-buffer-overflow WRITE of size 528`, 0 bytes after the 459-byte `full_log` allocation, frame `fim_generate_alert` → `run_case` → `main` (`out-direct/trace.txt`); plain build puts chosen JSON byte `Q` in a neighbouring heap object; v4.14.8 and full-`old_attributes` controls clean. Wire reach is source-confirmed and now also exercised in a live ASan `wazuh-analysisd` from a lab AF_UNIX `8:syscheck:` datagram: `WRITE of size 506` 0 bytes after the 459-byte region at `syscheck.c:1680` ← `:1436` ← `:1288` ← `analysisd.c:1586`, allocation `cleanevent.c:62`; full-`old_attributes` and v4.14.8 controls clean. The separate enrolled-agent TCP/1514 leg is in `reports/wazuh2shell-1514-wire.md`. W108 plain-daemon readback: a 459-byte request (`full_log` chunk size `0x1e5`) receives a 506-byte alert, overwriting chunk A's size word at `F+472` with ASCII `"ibutes w"` (`0x7720736574756269`) and its `agent_id` user bytes at `F+480..495` with `"ere: ''\nNow they"`, chunk B's `prev_size` at `F+496..503` with `" are 'a'"` and its size low bytes at `F+504..505` with `0x0a 0x00`; chunk B's user string and chunk C past `F+506` are intact. The 406-byte control gives a 74-byte alert with no overrun. Source tracing finds no pointer consumer in `agent_id`/`location`/`hostname` and the cJSON nodes are not the immediate neighbours; whether a groomed heap can place one there is UNKNOWN. No pointer control, marker, command primitive, witness replay or grade change; rung 5 UNKNOWN. The live ASan driver is in gitignored `live-src/` with no tracked generator; see the 2026-11-22 addendum for its recipe. |
| MapServer2Shell | [brief](../reports/frontier-mapserver2shell.md), [live stock build](../reports/mapserver2shell-live.md) | CVE record `https://www.cve.org/CVERecord?id=CVE-2026-77326` (published / updated 2026-11-20, CNA GitHub maintainer advisories) and GHSA `https://github.com/MapServer/MapServer/security/advisories/GHSA-4mwc-qc95-5959` (published 2026-07-10), CWE-787, CVSS 3.1 8.6 High `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H`; affected `<=8.6.4` (<8.6.5), fixed 8.6.5 (tags rel-8-6-4 / rel-8-6-5), fix commits `ea1d87a6…` / `a7d5eb84…`; 12 digests inline in `lab/frontier/mapserver2shell/PROVENANCE.md` (10 files under `src/`: 2 patches + 8 raw sources, plus harness `legend_layer_overflow.c` `3aca5129…` and `run.sh` `96f1757b…`), all recomputed and matched by the operator from the repo root at admission — no `SHA256SUMS` manifest | RUNG 1–4 INSTRUMENTED HARNESS — from the repo root run `bash lab/frontier/mapserver2shell/run.sh` -> `ALL CHECKS PASS`, rc 0; the digests are inline in `PROVENANCE.md`, there is no `SHA256SUMS` manifest to check. LIVE stock lane: configure rel-8-6-4, rel-8-6-5 and a plain rel-8-6-4 with the exact CMake flags and compiler in the live report's Build provenance table (WMS/libxml2/OGCAPI/WFS/WCS/GEOS/FCGI/FRIBIDI/HARFBUZZ/CAIRO on; ASan `-fsanitize=address -fno-omit-frame-pointer -O1 -g`, plain `-O0 -g -fno-omit-frame-pointer`), producing `lab/mapserver2shell/build-asan2/mapserv`, `build-fixed/mapserv` and `build-plain/mapserv`; those build trees and logs are gitignored by `lab/mapserver2shell/.gitignore`. | Witness #770 (2026-11-21) replayed from a clean `git archive` of HEAD `57364e6`: rungs 1/2/3 ESTABLISHED and rung 4 ESTABLISHED AS CLAIMED at the INSTRUMENTED chosen-value label (`DEADBEEFCAFEBABE` at pointer slots 110/150/190), no nits, six checks reproduced, determinism digest `5df6fce0…082c2e`. Extracted, source-bound harness only: no live MapServer, stock build, CGI/HTTP path, real heap neighbour, pointer control, execution or rung 5; advisory explicitly does not demonstrate RCE. Admitted 2026-11-22 ~02:4xZ under standing #6 (68th mind, 72nd route). LIVE limb, witness W125 ESTABLISHED at the labeled rung-3/rung-4 scope: `cd lab/mapserver2shell && ./poc.sh 95` gives rc 1 with ASan `WRITE of size 8` at `mapwms.cpp:5991`, 0 bytes after an 800-byte region; `BIN=./build-fixed/mapserv ./poc.sh 95` and `./poc.sh 97` give rc 0. Start `python3 loopback_bridge.py` (127.0.0.1:8077 only) and GET `/mapserv?map=…&SERVICE=WMS&VERSION=1.3.0&REQUEST=GetLegendGraphic&BBOX=0,0,1,1` plus 95 `&LAYER=DEADBEEFCAFEBABE` for the wire fault. `./readback.sh 95` under gdb shows `req->NumParams=195` and `ParamValues[100]`/`[150]` = `DEADBEEFCAFEBABE`; without gdb the plain process passes the chosen 8 bytes as the `free()` argument (`0x4542414245464143`, `0x5a5a5a5a5a5a5a5a`, `0x4141414141414141`) and faults. Witness W125 replayed all of this from its own clean `-O0 -g` builds (see W125 addendum); no chosen command or control-flow redirection, rung 5 UNKNOWN; the CGI bridge is a lab adapter. |
| Nanomsg2Shell | [brief](../reports/frontier-nanomsg.md), [status](../reports/nanomsg2shell-status.md) | NVD CVE-2026-97152 (MITRE CNA, published 2026-09-24), fix PR `nanomsg/nanomsg#1130` and release 1.2.3; affected 0.5-beta..<1.2.3, fixed 1.2.3; release tarballs `nanomsg-1.2.2.tar.gz` `3ffeafa9335245a23a99827e8d389bfce5100610f44ebbe4bfaf47e8192d5939` and `nanomsg-1.2.3.tar.gz` `aa3f501a58435fde639755f9f26c87ba720b386235f32ea795dc9d4dd90bc155` SHA-256-pinned in `lab/frontier/nanomsg2shell/src/SHA256SUMS`, 2/2 OK at admission and recomputed by the witness | `cd lab/frontier/nanomsg2shell/src && sha256sum -c SHA256SUMS` (2/2 OK); from `lab/frontier/nanomsg2shell`, build the harness WS server from `harness/ws_server.c` against pinned v1.2.2 with GCC-ASan and clang-ASan and start it (binds 127.0.0.1:28765); `python3 harness/wire_inject.py 600` sends the raw Upgrade with 600 `Q` bytes (argument is byte count, not port); rebuild against v1.2.3 for the fixed control. W106 offset lane: build the `-g -O0` debug library (`cmake -S nanomsg-1.2.2 -B src/build-dbg -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-g -O0 -fno-omit-frame-pointer"`), link `harness/ws_server_dbg.c`, then `bash harness/run_gdb_case.sh marker:41` / `marker:ff` or `python3 harness/wire_pattern.py 489 marker:41 0` / `marker:ff 0`. W108 shipped process: `bash harness/nanocat_reach.sh` binds the pinned `nanocat` CLI to `ws://127.0.0.1:28765` and repeats the raw requests. | v1.2.2 600-byte request: 669-byte reply with a 67-byte prefix, so 155 chosen bytes land past `response[512]` into the pointer-bearing `done` FSM event; the server aborts `item->next == NN_QUEUE_NOTINQUEUE` (`queue.c:47`) in both ASan builds; 2-byte control 71 bytes and clean, fixed 1.2.3 71-byte version-13 reply with no assertion. W106 on the debug build: `&done - response == 516`, `done.item.next` at header 481..488, position-encoded `0x3231307a79787776`, `marker:41` → `0x4141414141414141` + `queue.c:47`, `marker:ff` → `0xffffffffffffffff` + `aws.c:316 "Unexpected source"` (chosen wire bytes select the live path). W107 is an independent witness verdict (#1292/#1293) from its own rebuilt libraries: all three readbacks, both FSM divergences, fixed clean control and all 14 hashes in `harness/EVIDENCE_HASHES.txt` reproduced — rung 4 ESTABLISHED at the standalone-listener scope, no refutation or NIT. W108 on the shipped `nanocat`: short 71 bytes clean, `marker:41` 558 + `queue.c:47`, `marker:ff` 558 + `aws.c:316`, fixed 1.2.3 71 bytes, gdb reads `DONE_OFFSET=516` and chosen `item.next`; raw `harness/nanocat/` traces hold ASLR/PID data and are outside the hash manifest. ASan does not flag the libc `sprintf` store (clang padding silent), so the consumer assertion is the detector. No chosen command, clean takeover, shipped-daemon generality or rung 5; the +516 offset is build-specific. Admitted 2026-11-22 ~03:0xZ under standing #6 (69th mind, 73rd route). |
| Pgpool2Shell | [brief](../reports/frontier-pgpool2shell.md), [status](../reports/pgpool2shell-status.md) | JVN#22475874 (JPCERT/CC CNA, 2026-09-29) and NVD CVE-2026-92867 / -92869 / -92870 (Awaiting Analysis); CWE-787, CNA CVSS 4.0 8.7 `PR:L`; affected 4.3.0–4.3.20 / 4.4.0–4.4.17 / 4.5.0–4.5.12 / 4.6.0–4.6.7 / 4.7.0–4.7.2, fixed 4.3.21 / 4.4.18 / 4.5.13 / 4.6.8 / 4.7.3; fix `0388652d` (backport `a58fe0c7`); tarballs `pgpool-II-4.7.2.tar.gz` `e72b9d0f…d1938` and `pgpool-II-4.7.3.tar.gz` `4bf9df3e…ce250` SHA-256-pinned in `lab/frontier/pgpool2shell/src/SHA256SUMS`, recomputed 2/2 OK by the operator at admission | `cd lab/frontier/pgpool2shell/src && sha256sum -c SHA256SUMS` (2/2 OK); from `lab/frontier/pgpool2shell` run `bash harness/run.sh` (rc 0). Expect case A (`NodeCount=1`, 4.7.2) `values=11111111,00000000`; B (`NodeCount=2`, 4.7.2) `values=41414141,00000000` (second value went through the bad index); C (4.7.3, `NodeCount=2`) `values=41414141,42424242`; D gdb breakpoint at `wd_json_data.c:858` reports `node_id_set[1]` = the JSON buffer pointer and chosen `0x42424242` written as `42 42 42 42` there. ASan case B is `stack-buffer-overflow READ of size 8` at `:858`. Direct-call harness on the real pinned parser object — no wire packet, daemon or rung 5. Normalized hashes in `harness/EVIDENCE_HASHES.txt`. |
| Bacnet2Shell | [brief](../reports/frontier-bacnet2shell.md) | GHSA-gr74-333w-7wg8 / CVE-2026-97692 (CNA GitHub, 2026-10-04, High 7.7), bug audit `1068250f…`, fix PR #1435 / merge `37b081d0…`; affected `bacnet-stack <= 1.5.0` plus audited `1.6.0-rc1`, patched `1.4.6/1.5.2/1.6.1/1.7.0`; pins and fix hunk in `lab/frontier/bacnet2shell/pins/PINS.txt` / `pins/fix-97692.patch` (kept outside the nested clone), hashes in `PROVENANCE.md` / `EVIDENCE_HASHES.txt` | From `lab/frontier/bacnet2shell`, `clang -fsanitize=address,undefined -fno-sanitize-recover=undefined -g -O1 -I src/src harness/poc.c src/src/bacnet/datalink/bsc/bvlc-sc.c $(ls src/src/bacnet/*.c) src/src/bacnet/basic/sys/days.c -o harness/poc-vuln`; replace `src/` with `src-fixed/` for the control; `poc_global.c` builds the same way with `-DDUMP` for the plain byte dump | `harness/poc-vuln 1` gives ASan `READ of size 1` at `bvlc-sc.c:557`, case `3` `WRITE of size 8` at `:601`, case `2` benign with zeroed slack; the server-shaped `poc_global` gives `global-buffer-overflow` 0 bytes past the 432-byte file-static `g_dm`, and its plain 11-option chain prints chosen `41 42 43` at struct offsets 304/344/384/424 and `bf` at 248/288/328/368/408; all fixed cases return `header options is truncated`. Raw `out-*/` and built binaries are gitignored; normalized `evidence/norm-*` and hashes are committed. Author-only, no wire or daemon. |
| Ud3tn2Shell | [brief](../reports/frontier-ud3tn2shell.md) | CVE-2026-121510 / GHSA-96mh-pq33-phch (CNA GitLab, 2026-11-03, CVSS 3.1 7.5 `AV:N/AC:L/PR:N/C:N/I:N/A:H`), affected µD3TN `<0.15.2`, fixed 0.15.2; tag commits `00b2fbef…` / `6b18b267…`, defect fix `09f18b9c…`; pins in `lab/frontier/ud3tn2shell/src/PINS.txt` and `PROVENANCE.md` (GitLab archive endpoints returned 429, so trees came from pinned tags via `git archive`) | In each pinned tree `make posix -j8 sanitize=yes sanitize-strict=yes DISABLE_JSON=0`; rebuild a plain v0.15.1 copy without sanitizers for the gdb readback (no `libjansson-dev` on this host) | From `lab/frontier/ud3tn2shell`, `python3 harness/wire_trigger.py --src "$PWD/src" --outdir "$PWD/replay" --vuln-port 19224 --fixed-port 19230` and `python3 harness/gdb_readback.py --binary "$PWD/src/ud3tn-v0.15.1-plain/build/posix/ud3tn" --outdir "$PWD/replay-gdb" --port 19234 --marker 90`; expect ASan `WRITE of size 1` at `components/bundle6/reports.c:439` for markers `41` and `5a`, rc=-6, the source-EID-length-8 and fixed-0.15.2 cases clean, and 20 consecutive `5a` (or `43`) bytes at offsets 0..19 with `index=20`, `bytes_remaining=65516`. Source trees, `replay*/` and `out-*` are gitignored; committed `harness/evidence/` and `EVIDENCE_HASHES.txt` are the normalized record. Author-only, no witness. |
| Fastnetmon2Shell | [brief](../reports/frontier-fastnetmon2shell.md) | CVE-2026-48689 claim sources (Debian tracker, Lorikeet blog, upstream PR #1051) with URLs in `lab/frontier/fastnetmon2shell/pins/PINS.txt`; vulnerable parent `97b04568b6f12977aedb9682fcd9ca7ca952e84a`, fix `fa80390ed446f887ca6fa39c9e5b6fff8846e822`; three self-computed SHA-256 pins for the two raw `dynamic_binary_buffer.hpp` versions and the fix patch in `pins/PINS.txt` | `cd lab/frontier/fastnetmon2shell && bash harness/run.sh` — g++ 17, `-g -O0 -fno-omit-frame-pointer -I../pins`, compiles `harness/poc.cpp` against the real pinned header into vuln/fixed × ASan/plain binaries. No network at replay time. | Expect vuln-ASan `AddressSanitizer: heap-buffer-overflow`, `WRITE of size 1`, `0 bytes after 24-byte region`, frame `dynamic_binary_buffer_t::append_data_as_pointer ... vuln.hpp:115` for markers `0x41` and `0x5a`; fixed-ASan `accepted=0 failed_flag=1 shift=24` with no report; vuln-plain `accepted=1 READBACK byte[24]=0x41`/`0x5a`; fixed-plain rejected. Normalized logs (`evidence/norm-*.log`) and `EVIDENCE_HASHES.txt` are tracked; raw `harness/poc-*` binaries and `out-*` logs are gitignored by `lab/frontier/fastnetmon2shell/`, regenerate with `run.sh`. No daemon, listener or wire packet; rung 4 is direct-call only. |
| Snac2Shell | [brief](../reports/frontier-snac2shell.md) | CVE-2026-112021 claim sources (MITRE CNA record, NVD, GHSA-6hv3-2r7g-774j, finder writeup, public PoC gist) with URLs in `lab/frontier/snac2shell/PROVENANCE.md`; vulnerable tag 2.92 `3d2af2ef…` / fixed 2.93 `795355ac…`, fix `ec2c5c20…`, both tarballs and the patch hashed in `PIN_HASHES.txt` / `PROVENANCE.md` | `cd lab/frontier/snac2shell && bash harness/run.sh` — compiles the real pinned single-header parser with `cc -g -O0` and `-fsanitize=address` for both tags, runs all four ASan/plain × vuln/fixed cells with markers `0x41`/`0x5a`, asserts the ASan and gdb readback conditions and writes `EVIDENCE_HASHES.txt` / `PIN_HASHES.txt`; starts no daemon or listener | Expect vulnerable ASan `heap-buffer-overflow WRITE of size 1`, 0 bytes after a 32-byte region, frames `xs_insert_m (xs.h:469)` ← `_xs_json_load_lexer (xs_json.h:302)` ← `xs_json_load_full`; fixed rc=0 clean; plain vulnerable gdb readback shows 46 writes per marker at offsets 40..85 with `usable=40` and byte `0x41`/`0x5a`, fixed grows to `usable=72` at offset 31 with zero writes past usable. Two back-to-back normalized replays matched. Rung 3 on the real parser, rung 4 direct-call harness only; wire-to-crash and RCE stay claims. |
| Pnet2Shell | [brief](../reports/frontier-pnet2shell.md), [status](../reports/pnet2shell-status.md) | CVE-2026-127122 / GHSA-9cfr-5cg8-55x5 / EUVD-2026-125302 (CNA RT-Labs AB 2026-11-13, vendor RRTL-261109-01 §3.6), CVSS 4.0 7.2 `AV:A/AC:L/PR:N`; affected p-net `<1.0.4` (vulnerable tag public/v1.0.3 `19782d52…`), fixed public/v1.0.4 `1c3b0b43…`; both tarballs and the one-hunk fix patch SHA-256-pinned in `lab/frontier/pnet2shell/pins/PIN_HASHES.txt`, provenance and claim URLs in `PROVENANCE.md` | `cd lab/frontier/pnet2shell && bash harness/run.sh` — self-extracts both hash-verified tarballs, generates `pnet_options.h` (`PNET_OPTION_MC_CR=1`, `PNET_MAX_MC_CR=1`) and OSAL/PNAL stubs, compiles the real pinned `pf_block_reader.c` and `pf_types.h` into vuln/fixed × ASan/plain binaries and runs 11 asserts; no daemon, socket or wire packet | Expect vuln-ASan `heap-buffer-overflow WRITE of size 2` at `pf_get_mcr_request (pf_block_reader.c:790)`, 0 bytes after a 49600-byte `calloc`, frames ← `main (harness.c:81)`; fixed-caller ASan rc=0 no report. Vuln-plain two-block readback at `slot1_offset=252`: `iocr=4142 protocol=43 resolution=44 timeout=4546 namelen=16 name=5a5a…`; fixed rejects block 1 with `WRONG_BLOCK_COUNT`. `evidence/norm-*.log` and `EVIDENCE_HASHES.txt` are tracked; extracted trees, generated headers and binaries are gitignored and regenerate with `run.sh` (two replays, one after deleting all generated files, gave 11/11 and four identical normalized hashes). Rung 3 on the real pinned writer, rung 4 chosen bytes at a chosen relative index at direct-call scope only; wire reach is an advisory claim. |
| Inetutils2Shell | [brief](../reports/frontier-inetutils2shell.md), [wire report](../reports/inetutils2shell.md) | CVE-2026-32746 claim URLs (CVE record, GNU bug report, finder writeup, upstream fix `1ffb28a2…`) in `lab/frontier/inetutils2shell/PROVENANCE.md`; 2.7 `a156be1c…` / 2.8 `57b3cf4f…` tarballs and fix `5729c658…` SHA-256-pinned in `pins/PIN_HASHES.txt`; harness scripts hashed in `PROVENANCE.md` | `cd lab/frontier/inetutils2shell && bash harness/run.sh` — verifies the three pins, extracts both tarballs into gitignored `src/`, uses `gen_slc.py` to copy `start_slc()`/`add_slc()` verbatim from each tag, builds vuln/fixed × ASan/plain at `-g -O0 -fno-omit-frame-pointer`, starts no listener and writes normalized logs plus `EVIDENCE_HASHES.txt`; W1 wire replay `bash wire/run_all.sh` starts a loopback-only listener, needs no external host | Expect rc 0, 8 PASS / 0 FAIL: vulnerable ASan `global-buffer-overflow WRITE of size 1` at `gen-vuln/slc_functions.inc:24` in `add_slc`, 0 bytes past the 108-byte `slcbuf`; fixed clean; vulnerable plain `slcbuf_size=108 slcptr_offset=154` and `readback+0=42415a42415a42415a`; two in-tree and one clean `git archive b1c02f3` replays byte-identical. `run.sh` pins `-O0`: at `-O2/-O3` gcc relocates the stub `slcptr` and corrupts readback past index 3; a `FRONTIER_ASAN` guard covers GCC and clang so ASan builds skip the intentional readback. Wire replay expect 17 PASS / 0 FAIL: 50-triplet LINEMODE suboption faults 2.7 ASan at `add_slc (slc.c:172)`, 2.8 and 5-triplet clean, plain 100-triplet SIGSEGV; hashes in `WIRE_HASHES.txt`, raw daemon logs in gitignored `wire/evidence/` regenerate with the same script. Staged witness ESTABLISHED (DM #1503); wire witness W119 (18:50Z) ESTABLISHED at labeled scope from a clean-archive tree with 9/10 normalized hashes identical (one ASan shadow-row difference), fixed 2.8 clean at 50/100/200, and boundaries preserved (34-triplet `end_slc:237 sprintf`, `func<=18` never faults, runtime `slcptr` canonical); #1538 NIT ledger closed for the portable `FRONTIER_ASAN` guard. No rung 5. |
| H2o2Shell | [brief](../reports/frontier-h2o2shell.md), [status](../reports/h2o2shell-status.md) | CVE-2026-55368 / GHSA-m998-r5ww-rqjf (advisory 2026-10-23, High 8.1); affected `4212ce11…` and earlier, fixed `48b7ae12…` (PR #3757); both `git archive` stream hashes, both `logconf.c` hashes and the fix-patch hash in `lab/frontier/h2o2shell/pins/PIN_HASHES.txt`, claim URLs in `PROVENANCE.md`; six staged harness digests in `harness/EVIDENCE_HASHES.txt` | `cd lab/frontier/h2o2shell && bash harness/run-harness.sh` builds six `libh2o.a` harness binaries against both pinned trees. Live W1: build each pin out-of-tree with ASan as `src/{vuln,fixed}/build-asan/h2o`, then `bash live/replay-live.sh` (loopback ports only, configs generated under gitignored `live/replay-out/`); gdb readback uses `live/inspect-run.gdb` and `live/gdb-transcript.txt`. W4: with the plain build at `src/vuln/build-plain/h2o` and port 17999 free, `python3 live/top-reuse.py overflow` then `python3 live/top-reuse.py control` (loopback only; each run starts and kills its own server) | Expect harness rc 0 and six normalized digests matching `EVIDENCE_HASHES.txt` (vuln-ASan rc 1, other five rc 0); a clean `git archive` replay gave `REPLAY_IDENTICAL=yes`. Live replay expect `vuln-short: ASAN=no`, `vuln-long: ASAN=YES` (stack-buffer-overflow at frame offset 4160, `append_unsafe_string_apache logconf.c:438` ← `h2o_log_request :843`), `fixed-long: ASAN=no`; a single 5000-A request with format `'%{error}x'` and a minimal redirect is enough. gdb shows chosen pattern at `buf+4064` and ASCII `FGHIJKLM` in the saved frame slot; threshold measured at path 3959 (`error_logs` 4096 + `\n`), 3958 clean. W4 expects the overflow run's req1 to return 503 with the process alive, req2 to time out and `live/top-reuse-overflow-errlog.txt` to end with `free(): invalid next size (normal)` and `received fatal signal 6`; the control run gives two normal 503s with no allocator diagnostic. Build trees, ASan reports and replay-out logs are gitignored and regenerate with those commands; the four `live/top-reuse-*` server-output/error-log files are committed, though the script overwrites the two `-errlog.txt` tails in place. Witness #1583 replayed W1 from a clean archive (3/3 outcomes, exact threshold, saved-frame bytes) at labeled rungs 1/2/3 and chosen-byte wire rung 4, and W2/W3/W4 measured the canary, heap-metadata and corrupted-top reuse barriers, so rung 5 stays UNKNOWN. |
| Pppd2Shell | [brief](../reports/frontier-pppd2shell.md), [status](../reports/pppd2shell-status.md), [live](../reports/pppd2shell-live.md) | GHSA-frhv-j822-2pvx / CVE-2026-85495 (CWE-787/120, advisory High 7.5, GitHub displays 4.2); affected ≤2.5.3, fixed 2.5.4 (`cc8b00c`, `1baf2ac`); 2.5.3 `96f962b9…` / 2.5.4 `379a630a…` tarballs and both fix patches SHA-256 in `lab/frontier/pppd2shell/pins/PIN_HASHES.txt`, rechecked at the top of `harness/run.sh`; URLs in `PROVENANCE.md` | `cd lab/frontier/pppd2shell && bash harness/run.sh` — verifies four pins, extracts both tarballs into gitignored `src/` / `src-fixed/`, generates `lcp_reqci()` verbatim with `gen_lcp.py`, builds vuln/fixed × gcc/clang ASan and plain at the pinned `pppdconf.h`, asserts fix markers present/absent and writes nine normalized logs; starts no daemon, pty or network device | Expect rc 0, 12 PASS / 0 FAIL: vulnerable gcc and clang ASan `global-buffer-overflow WRITE of size 1` 0 bytes after `nak_buffer` (1500) in verbatim `lcp_reqci`; vulnerable plain `readback+1500=0305c223800305c2238…` with chosen digest byte `0x80` (or `0x05` under `CHOSEN_MDTYPE=MDTYPE_MD5`) at offsets 1504/1509/1514…; fixed ASan clean and `out=5`; `CI_COUNT=2` safe control clean on both. Nine hashes in `EVIDENCE_HASHES.txt`; two in-tree and one clean `git archive b3ec18d` replay were byte-identical. Admitted 18:56Z with the 82nd hy4-flash route; direct-call only there. W122 adds a live replay: `cd lab/frontier/pppd2shell/live && bash run_matrix.sh` (local `sudo modprobe ppp_async`; `sudo -n` only for the locally built daemon, its 0600 secrets file and ASan log permissions) builds both pins as gcc-13 ASan `pppd`, starts the daemon as root on a local PTY and sends one escaped RFC-1662 LCP Configure-Request after the daemon's own ConfReq. Expect vulnerable N=301/374 `global-buffer-overflow WRITE of size 1` at `lcp_reqci lcp.c:1608`, 0 bytes after `nak_buffer`; N=300 `WRITE of size 1500` at `:1853` 0 bytes after `inpacket_buf`; vulnerable N=3 and fixed N=301/3 alive with one CHAP-MD5 NAK. Six normalized hashes in `evidence/LIVE_HASHES.txt` were identical over two full runs. Pre-auth, constrained `03 05 c2 23 <digest>` bytes, no pointer or command; W122 was independently replayed by witness #1625 at the labeled scope. W123 (`bash chosen/run_chosen_matrix.sh`) adds five author-only chosen-global cases; rung 5 unclaimed. Raw logs regenerate under gitignored `live/raw/`. |
| Libssh22Shell | [brief](../reports/frontier-libssh22shell.md), [status](../reports/libssh22shell-status.md), [live](../reports/libssh22shell-live.md) | GHSA-v6rf-8q4r-r495 / CVE-2026-66035 (CWE-122, CVSS v4 7.7 High `AV:N/AC:H/PR:N/UI:P`); libssh2 through 1.11.1, vulnerable parent `edec1cce…`, six-line guard fix `42e33d8`; advisory Patched field Unknown, so no fixed release asserted. Both raw `src/transport.c` blobs and the fix patch SHA-256-pinned in `lab/frontier/libssh22shell/pins/PIN_HASHES.txt`, claim URLs and the two claim-source discrepancies in `PROVENANCE.md` | `cd lab/frontier/libssh22shell && bash harness/run.sh` — verifies pins, uses `harness/gen_fn.py` to extract the verbatim 180-line pinned `transport_fullpacket()` under line directives, builds vuln/fixed × gcc/clang ASan and plain with stub collaborators, starts no listener or SSH handshake and writes nine normalized logs plus `EVIDENCE_HASHES.txt` | Expect rc 0, 17 PASS / 0 FAIL: vulnerable gcc and clang ASan `heap-buffer-overflow WRITE of size 15`, 0 bytes after a 4-byte region, top frame `transport_fullpacket`; plain readback of 15 chosen bytes at offsets 0..14 (bases `0x41`/`0x5a`); fixed pin `LIBSSH2_ERROR_DECRYPT` (`rc=-18`) clean and safe `TOTAL_NUM=64` clean on both. Nine hashes identical over two in-tree replays and a clean `git archive 9795ecf` replay; raw logs under gitignored `evidence/` regenerate with that script. W2 adds a live-process replay with no stubs: `cd lab/libssh22shell-live && bash run_live.sh vuln short 3 22320` expects CLIENT_RC=1 and a natural ASan `WRITE of size 15` at `transport.c:263`, 0 bytes past the 4-byte sink from `:249`; the fixed pin, wrong MAC, safe input and `packet_length=15` are clean, `packet_length=14` faults and three fresh-key replays match. Direct-call/stub scope at admission and live-process scope from W2; the victim is a connecting client fed by a malicious server, not a web-facing service. No grooming, pointer control, command side effect or witness replay at W2's time; witness W123 (#1628) later replayed the live claim from a clean archive and graded it ESTABLISHED at the labeled scope. W3 below closes rung 5 for this build and allocator. |
| Tacplus2Shell | [brief](../reports/frontier-tacplus2shell.md) | CVE-2026-130875 / GHSA-v384-f7x8-f7c7 (VulnCheck 2026-11-17, CVSS v4 7.7, CWE-783/121); affected `<= e20ac82`, fixed `d8493e0d6420b91737fa34c2cd7bbd365d023b5b`, advisory PoC base `929671c22ff9f390f22decd7eb97dffaece8aebe`; pinned `packet.c` / `author.c` blob SHA-256 in `lab/frontier/tacplus2shell/PIN_HASHES.txt`, claim URLs in `PROVENANCE.md` | In each pinned tree `./configure --asan --minimum --prefix=<lab inst dir> tac_plus-ng mavis && make -j4` (clang ASan `-g -O0`; binaries under `src/{,fixed/}build/<os>/tac_plus-ng/tac_plus-ng`, configure/build logs per `PROVENANCE.md`) | `cd lab/frontier/tacplus2shell && bash harness/run.sh && bash harness/run_wire.sh` — `harness/gen.py` reads the committed `pins/` blobs, so the harness is self-contained in a clean `git archive 5e72d56` with no source clone or `.git`; the wire runner starts the real pinned daemon inetd-style with a plant-created 127.0.0.1 listener passed as fd 0 on ports 4949–4951 only. Locally replayed at this fold: harness 9 PASS / 0 FAIL — vuln `validator_bogus=0`, `cmdline=AAAAAAAA` / `cmdline=ZZZZZZZZ` at offsets 0..7, fixed `validator_bogus=1 cmdline_len=0`, 40-byte copy into the 15-byte VLA gives ASan `dynamic-stack-buffer-overflow`; wire 0 failures — one crafted AUTHOR packet on the vulnerable pin gives `heap-buffer-overflow READ of size 1`, 243 bytes after a 323-byte region at `eval_args author.c:75`, daemon `rc=-6`, while the fixed 57-byte rejection and safe 18-byte reply are `rc=0` with empty ASan logs. Normalized hashes in `harness/wire-r{1,2}.txt` and `EVIDENCE_HASHES.txt` (vuln `599ab1f0…`, clean `e3b0c442…`); raw logs, binaries and source trees are untracked local artifacts under `lab/frontier/tacplus2shell/`, regenerated by the committed pins, scripts and commands above |
| Ntpsec2Shell | [brief](../reports/frontier-ntpsec2shell.md) | CVE-2026-121506 (GitLab CNA 2026-11-03, CWE-787, CVSS 3.1 7.4), affected 1.1.4 up to (excluding) 1.2.5, fixed 1.2.5; vulnerable tag `NTPsec_1_2_4` `a9e66af44c0be…`, fixed `NTPsec_1_2_5` `42b5703303c8…`, fix `0a36941e…`; seven pinned blobs and the fix patch SHA-256 in `lab/frontier/ntpsec2shell/PIN_HASHES.txt`, claim URLs in `PROVENANCE.md` | `harness/gen.py` copies `extens_client_recv()` byte-for-byte from the pinned `nts_extens-{vuln,fixed}.c` into `fn.inc` with two buffer helpers from pinned `nts-vuln.c`; `harness/run.sh` builds gcc `-O0 -g` ASan/plain variants of both pins and links pinned 1.2.4 `aes_siv.c` against OpenSSL 3.0.13, opening no sockets | `cd lab/frontier/ntpsec2shell && bash harness/run.sh` — expect 8 PASS / 0 FAIL: ASan `WRITE of size 40`, 8 bytes after a 128-byte region, frames `AES_SIV_Decrypt` (modeled) ← `extens_client_recv` (verbatim pinned) ← `stub_case` on the vulnerable pin with noncelen=64, fixed pin rejects before the consumer (`WRITE_OFF=-1`); plain build reads back 16 chosen `41…`/`5a…` bytes at offset 136, real pinned AES-SIV writes `414243…50` at offset 328; normalized PASS-line hash `1f04e12d…` identical over two in-tree replays and a clean `git archive f035109` replay. Raw per-case output in `evidence/`, regenerable from the pinned blobs and `run.sh`. FRONTIER-STAGED: rung 3 plus scoped rung 4, no ntpd process, NTP wire, NTS-KE handshake, disclosed key, pointer control or command. |
| Uhttpd2Shell | [brief](../reports/frontier-uhttpd2shell.md) | GHSA-2mpg-6wp5-435p (GitHub CNA 2026-08-03, CVSS 3.1 7.5 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`); affected through `f682ccabee9ed5f39dd3b0aaf96228975eeb478d` (shipped `7b1bec45` byte-identical), fixed `e76736e5676fb25536b27d45865eb4153c68aca3`, libubox `a396f38a8568a1d670c240465cd8d24fdfdf6463`; seven pinned blobs SHA-256 in `lab/frontier/uhttpd2shell/harness/pins/PIN_HASHES.txt`, claim URLs in `harness/PROVENANCE.md` | `harness/gen.py` extracts `uh_ubus_send_request()` verbatim from pinned `ubus.c` with only the function name changed; `harness/run.sh` builds gcc/clang, ASan/plain against pinned libubox `blob.c` / `blobmsg.c`, checks seven SHA-256 pins and opens no sockets | `cd lab/frontier/uhttpd2shell && bash harness/run.sh` — two full rounds, 30 PASS / 0 FAIL rc 0; expect REAL ASan `READ of size 1` 2 bytes after a 20-byte region in `strcmp`, fixed `ERROR=3 INVOKED=0`, MODEL `WRITE_LEN=4294967293` with 16 chosen `41…` / `5a…` bytes at `WRITE_OFF=20` (hash lines `dbe5197f…` / `56c26e93…`), and both determinism diffs empty. `round2-pass.txt` sha256 `c3b2b9d19d6950090c4efdbc2b5e483881f1d23b297beea41343c6dc5622fc66`, reproduced from a clean `git archive d6afa99` with no source clones or network. Raw per-case logs under gitignored `harness/build/` and `harness/evidence/raw-r1-*`; canonical normalized and raw-r2 files are tracked and regenerate with `run.sh`. No live daemon or wire; the ~4 GiB memcpy is not executed. |
| Gdbserver2Shell | [brief](../reports/frontier-gdbserver2shell.md), [status](../reports/gdbserver2shell-status.md) | CVE-2026-121997 / GHSA-jq36-9pw3-8r4v (Red Hat 2026-11-05, HIGH 8.1, CWE-122); upstream HEAD `633ae02c4ea8f87c670f7192804349860cfa291d` still vulnerable, fix is a posted-but-unmerged gdb-patches hunk; vulnerable `tracepoint-633ae02.cc` SHA-256 `942306a5…`, derived fixed `c3aa8ac2…`, fix patch `5b8bc3cb…` in `lab/frontier/gdbserver2shell/PROVENANCE.md` | `harness/run.sh` re-extracts verbatim pinned `cmd_qtdpsrc()` slices and helpers, asserts eight SHA-256 pins and builds gcc/clang ASan plus plain-canary variants; opens no socket | `T=$(mktemp -d /tmp/gdb-replay.XXXXXX); cp -a lab/frontier/gdbserver2shell/. "$T/"; bash "$T/harness/run.sh"` → rc 0, `SUMMARY=60 PASS / 0 FAIL`, `NORMALIZED_HASH=0c9b837e…1c1db73`; attack packet `QTDPsrc:1:0:cond:0:1:<hex>` with N=8/32/64/128 gives ASan `WRITE of size 1` 0 bytes after a 2-byte region; full recipe in the lane section below |
| Erlang2Shell | [brief](../reports/frontier-erlang2shell.md), [status](../reports/erlang2shell-status.md) | CVE-2026-55737 / GHSA-446w-268v-9462 (EEF CNA 2026-07-27, MEDIUM 5.1 CVSS4 AV:L, CWE-195+CWE-787); affected OTP 25.0+ before 27.3.4.15 / 28.5.0.4 / 29.0.4, fix `c5210b42`; pinned `external.c` / `erl_term.h` blobs and the five-line patch SHA-256 in `lab/frontier/erlang2shell/PROVENANCE.md` | `harness/run.sh` re-extracts four verbatim pinned slices, asserts source/patch/slice/driver SHA-256 pins, builds gcc and clang ASan plus plain-canary variants; opens no socket, VM or BEAM build | `T=$(mktemp -d /tmp/erlang-replay.XXXXXX); cp -a lab/frontier/erlang2shell/. "$T/"; bash "$T/harness/run.sh"` → rc 0, `PASS=60 FAIL=0`, `TRACE_SHA256=8517d3e1…c88` |
| MiniSnmpd2Shell | [brief](../reports/frontier-minisnmpd2shell.md), [status](../reports/minisnmpd2shell-status.md) | CVE-2026-59961 / GHSA-c9g2-5ghh-8g8c (CNA GitHub_M; CVE published 2026-11-18, GHSA displays 2026-07-10; HIGH 8.2 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H`, CWE-125 via `size_t` underflow), affected `< 1.7`, fixed `5419bc38` / release `6894e33e`; pinned vulnerable `protocol.c` `b5322437` (`4bd06467…`), fixed `5419bc38` (`eeb05d95…`), patch `fac30b06…`; five blob/driver hashes in `lab/frontier/mini-snmpd/PROVENANCE.md`, URLs there and in `src/SHA256SUMS` | `harness/run.sh` re-extracts verbatim `decode_oid` (190–256) and `decode_str` (175–187) from both pinned files, asserts five source/patch/driver and four slice SHA-256 pins, builds gcc/clang ASan plus plain variants; opens no socket | `cd lab/frontier/mini-snmpd && bash harness/run.sh` → `PASS=43 FAIL=0`, normalized trace SHA-256 `0146b9b59168bb92ad4d725d7b1f162aa6de47661674f0086a0bf02e838e9859`; ASan `READ of size 1` 0 bytes after a 2048-byte region in `decode_oid`, fixed/safe clean. `bash wire/run_wire.sh` starts a plant-owned ASan daemon on 127.0.0.1:16161 and sends one 2048-byte GET with declared OID length 0xffff; `run_fixed_wire.sh` uses 16162 and `run_safe_wire.sh` the 35-byte control. Full staging recipe below |
| Ettercap2Shell | [brief](../reports/frontier-ettercap.md), [status](../reports/ettercap2shell-status.md), [live dissector](../reports/ettercap2shell-livedissector.md) | CVE-2026-125401 / GHSA-vrjv-f8gv-2h35 (GitHub CNA 2026-11-06, HIGH 8.1 `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`, CWE-131+CWE-787; OSV CVSS4 also AV:A), affected `<=0.8.4.1`, patched `0.8.5.1`, fix `1d8badb7`; pinned vulnerable `3548c10c` and PR-head fix `a8c1a50` (byte-identical to merged/released 0.8.5.1), six blobs in `lab/frontier/ettercap2shell/src/SHA256SUMS`, URLs in `PROVENANCE.md` | `cd lab/frontier/ettercap2shell && bash harness/run.sh` re-extracts the verbatim pinned `gg_get_version()` slices, asserts source/patch/tag/slice/driver SHA-256 pins, builds plain plus gcc/clang ASan variants; opens no socket. Real dissector: build both pinned tags with clang ASan and drive a crafted TCP/8074 frame from a pcap and from `lo` (recipe below) | operator clean `/tmp` replay: rc 0, `PASS=58 FAIL=0`, normalized trace SHA-256 `d650b34e3bbc1ea336c60d2cb4b9c7743fdc4657b7d8e0d07c7e1bc1c1027b7a`; gcc/clang ASan `WRITE of size 13`, 0 bytes after a 30-byte region in `gg_get_version`; fixed and small-version controls clean. Real dissector gives the same `WRITE of size 13` at `gg_get_version:673` via `dissector_gg:360` offline and live; extent, safe, wrong-type, server-direction and fixed controls as recorded below. Full admission recipe below |

### 2026-11-22 post-admission follow-on evidence (author-only except netx witnesses #1262/#1296 and nanomsg witness W107; Soes limbs replayed by W105)

- **Eight 18:2x–18:4xZ edges** (commits `4cf9784`, `6bb732b`, `0b8cc5e`,
  `15abd26`, `322f5d5`, `b3ec18d`, `2ea38bf`, `a5f2cc9`): H2O was staged then
  admitted as the 77th mind / 81st route (`15abd26`, docs self-folded at
  admission) and W1 then upgraded it from a direct-call harness to a live
  wire-triggered stack overflow. `bash lab/frontier/h2o2shell/live/replay-live.sh`
  expects `vuln-short: ASAN=no`, `vuln-long: ASAN=YES` at frame offset 4160 and
  `fixed-long: ASAN=no`; the exact threshold is path 3958 clean and 3959
  faulting (`live/threshold-results.txt`, `live/asan-threshold-3959.1162820`).
  Inetutils W1: `bash lab/frontier/inetutils2shell/wire/run_all.sh`
  (17 PASS / 0 FAIL, hashes in `WIRE_HASHES.txt`) drives a loopback-only
  telnetd; the staged harness's `-O0` pin and portable `FRONTIER_ASAN` guard
  (`0b8cc5e`) are required for a valid plain readback on gcc/clang. Pgpool W9:
  `bash lab/pgpool2shell/wdnodes/run-harness.sh` (A–G, hashes in
  `lab/pgpool2shell/wdnodes/EVIDENCE_HASHES.txt`) shows chosen port/hostname
  bytes writing the adjacent `trusted_servers` field at N=129 on pinned 4.7.2,
  ASan-clean because the write stays inside the config allocation; N=128 and
  fixed 4.7.3 clean, no wire, no rung 3 on this branch, direct-call rung 4
  only (`reports/pgpool2shell-wdnodes-w9.md`). Pppd2Shell was FRONTIER-STAGED
  here at 18:4xZ but admitted at 18:56Z (82nd route); its `lcp_reqci()` recipe
  is in the row above. All harness and live trees, daemon logs and normalized
  ASan reports are gitignored and regenerate with these scripts; h2o witness
  #1583 and pppd's W122 witness #1625 returned ESTABLISHED at their labeled
  scopes (the W123 chosen-global cases remain author-only), and none
  claims rung 5.
  Witness W119 (18:50Z) independently rebuilt both pins from a clean `git
  archive` tree and returned ESTABLISHED at the labeled wire scope: pin
  tarballs 3/3 and pinned `slc.c` 2/2, `run_all.sh` 17 PASS / 0 FAIL, 9/10
  normalized hashes identical (sole difference: ASan shadow-byte rows from
  allocator layout; fault frames and 0-bytes-past-`slcbuf` lines match),
  fixed 2.8 clean at 50/100/200 triplets. Its boundaries are preserved, not
  refutations: 34 triplets first fault in `end_slc:237 sprintf` (WRITE-3 at
  `slcbuf+108`), 35+ in `add_slc`; `func<=18` never faults at 50 or 200, so
  `func>18` is required; gdb shows the final plain-build `slcptr` canonical
  (`0x00005555555560ba`), making the report's static byte pattern a layout
  inference. #1538 NIT ledger closed: `0b8cc5e` verified on gcc (8/8 PASS,
  hashes unchanged) and clang 18 ASan (fixed clean, vulnerable natural
  WRITE-1).
- **Six 18:5x–19:1xZ folds** (commits `5595f4d`, `7cf50fd`, `38ba908`, `9795ecf`, `547a5c6`, `fec0e05`, `befa1c3`, `09ad67e`, `79717f2`, `309450b`; all author-only except the two witness replays): H2O W2/W3 — from the built pinned trees in `lab/frontier/h2o2shell/live`, `python3 forced-heap.py 1200 10000` with the committed `forced-heap.conf` format `'%{pad}i %{error}x'` grows the log line to an 8192-byte heap buffer and the unreserved append faults with ASan `heap-buffer-overflow WRITE of size 1` 0 bytes past it (`asan-forced-heap.1817275`); `python3 forced-heap-gdb.py 1200 6870` shows 16 chosen `A` bytes then the `\n` suffix in free space past `line_end`; `python3 heap-groom.py <base|prep|live|mix> [nprep] [path_len]` dumps four layouts in `heap-groom-{base,prep,live,mix}.out`, each with the log buffer carved from the top at log time and the next chunk ending at the `[heap]` mapping end `0x5555557e0000`, so the 17-byte append overwrites only `prev_size`/`size` with `0x4141414141414141` twice. On the plain build a 5000-byte request under `corrupt-layout.gdb` / `corrupt-probe.py` overwrites saved RBP `XYZABCDE` and saved RIP `FGHIJKLM` but reaches `__stack_chk_fail` before `ret` (`canary-gdb-transcript.txt`); the escaper passes only printable bytes, so no raw pointer can be emitted. Witness #1583 rebuilt both pins in a clean archive, matched all five hashes, 3/3 outcomes and the exact 3958-clean/3959-fault threshold, and graded rungs 1/2/3 live wire and rung 4 live wire-triggered ESTABLISHED; rung 5 stays UNKNOWN with no demonstrated grooming path. Inetutils W2 preserved the W119 verdict and added local negatives: 34 triplets first fault in `end_slc (slc.c:237)` `sprintf` `WRITE of size 3` at `slcbuf+108`, `func=0x12` survives 50/200 triplets while `0x13` faults, and a gdb probe finds final `slcptr = slcbuf+154` (`0x00005555555560ba`) canonical, so the static byte pattern stays a layout inference. ProFTPD's `python3 wire/probe-leak-maps.py` correlated five ASLR-on leaks (plus `setarch -R`) with the forked child's `/proc/<pid>/maps`: brk `[heap]`, PIE-base deltas `0x0e3af0e8` / `0x11f670e8` / `0x1831a0e8` / `0x1afaa0e8`, correcting the earlier "mmap address" wording while the no-PIE-recovery negative stands. MsQuic closed its last rung-4 hypothesis by a structural read only, no new run: the post-free copy at `path.c:255` uses the pointer already in `Paths[0]`, a nonzero CID length suppresses the copy, and `QuicConnRetireCid` writes fixed offsets, so even a successful groom would be a fixed-value UAF flag write at rung 3; grooming stays UNTESTED and the R4 gate unchanged. Pppd2Shell and Libssh22Shell were admitted at 18:56Z/19:14Z with self-folded rows, task limbs and the harness lanes above; both remain direct-call/stub scope with no witness. Raw ASan/gdb transcripts and heap dumps are gitignored lab scratch and regenerate with the scripts named here.

- **H2o2Shell W4 corrupted-top reuse (commit `c360f20`,
  `reports/h2o2shell-status.md` W4)**: the one hypothesis W3 left open was
  House-of-Force-like reuse of the top size rewritten to `0x4141414141414141`.
  From `lab/frontier/h2o2shell` with `src/vuln/build-plain/h2o` built and port
  17999 free, `python3 live/top-reuse.py overflow` sends a 1200-byte `pad`
  header and 6870-byte path (17-byte stop over the 8192-byte log line), waits
  0.5 s, then sends a short request; `python3 live/top-reuse.py control` sends
  two short requests. Expect overflow req1 `HTTP 503` with `alive after req1:
  True`, req2 failure, and an error-log tail with
  `free(): invalid next size (normal)` and `received fatal signal 6` (SIGABRT);
  the control stays alive with two 503s and no allocator diagnostic. Repeated
  twice with the same outcome; server-output and error-log artifacts are the
  committed `live/top-reuse-{overflow,control}.out` and
  `live/top-reuse-{overflow,control}-errlog.txt`. The Apache escaper emits only
  0x20-0x21 and 0x23-0x7c (`logconf.c:437`), so the rewritten size always has
  high bytes set and cannot be a valid small size; glibc aborts on first reuse.
  This closes rung 5 on the stack and heap paths for these wire sequences;
  a different allocator or an object-placement primitive would be a new claim.

- **Libssh22Shell W2 live-process rung 4 (commit `59ce649`,
  `reports/libssh22shell-live.md`)**: from `lab/libssh22shell-live`, build both
  pinned trees (`edec1cce…` vulnerable, `42e33d8…` fixed) with OpenSSL 3.0.13
  and `-fsanitize=address -fno-omit-frame-pointer -g -O1`, then
  `bash run_live.sh vuln short 3 22320` starts the plant's `fake_server.py` on
  127.0.0.1 and drives a real `libssh2_session_handshake()` client. Expect
  curve25519-sha256/ssh-ed25519/aes128-ctr/hmac-sha1-etm@openssh.com
  negotiation, `NEWKEYS both directions done`, then ASan
  `heap-buffer-overflow WRITE of size 15` in `memcpy` from
  `transport_fullpacket .../src/transport.c:263`, 0 bytes after the 4-byte
  region allocated at `:249`; the fault is inside the handshake before any
  application call. Controls: fixed pin `HANDSHAKE_RC=-12`
  (`LIBSSH2_ERROR_DECRYPT`), wrong MAC `-4` (`LIBSSH2_ERROR_INVALID_MAC`),
  safe 48-byte IGNORE and `packet_length=15` clean, `packet_length=14` faults;
  three fresh-key replays on other loopback ports match. Plain-build gdb
  readback shows sink bytes `41 42 43 a4 …` at `packet_length=4` (4 directly
  chosen) and `41 42 43 44 … 99 13 00` at 14 (13 directly chosen); the rest
  are MAC-derived, so fully chosen 15 bytes remain a direct-call-only result.
  Rung 4 is now established at live-process scope; witness W123 (#1628) later
  replayed it from a clean archive and graded it ESTABLISHED at the labeled
  scope. Rung 5 was UNKNOWN at W2's time — no grooming, pointer control, command
  side effect, and the advisory's 32-bit tcache/function-pointer path was not
  reproduced on this 64-bit safe-linked glibc with a 1..11-byte window. The W3
  bullet below closes it structurally on this host.
- **Libssh22Shell W3 rung-5 allocator negative (commit `97e777a`,
  `reports/libssh22shell-live.md`)**: compile the probe embedded in the report
  with `gcc -O0 -g` on this host and run it. Expect `malloc(1)` through
  `malloc(16)` all reporting `usable=24 chunk=32`, `sink malloc(4): usable=24
  chunk=32`, and `15-byte copy ends at a+14; bytes of usable slack left = 9`.
  The sink is `ssh2_default_alloc` → `malloc(count)` (`session.c:67`) with no
  custom allocator in `client.c`; all pin cipher blocksizes are 8 or 16, and
  at `packet_length >= 15` writes are `decrypt_size - 1`. So no reachable
  packet length produces a physical out-of-chunk write on this x86-64 glibc,
  and ASan's WRITE-15 is a requested-size redzone hit. The report also records
  an adjacent-run neighbour-header check (`0x21` unchanged, 10-byte gap) and
  its caveat that adjacency is allocator-state dependent, not a premise.
  Rung 4 at ASan/abstract scope is unchanged; rung 5 is closed for this build
  and allocator. The advisory's tcache path fits 32-bit glibc, not this host.

- **Pppd2Shell W122 live daemon over a local PTY (commit `32b7ff4`,
  `reports/pppd2shell-live.md`)**: after a local `sudo modprobe ppp_async`,
  `cd lab/frontier/pppd2shell/live && bash run_matrix.sh` verifies the four
  pins, builds both tagged trees with gcc 13 `-g -O0 -fsanitize=address`,
  starts the locally built `pppd` as root on a PTY slave with
  `nodetach passive local refuse-pap refuse-eap ... chap-secrets <0600 file>`,
  waits for the daemon's own LCP ConfReq, then sends one RFC-1662 HDLC frame
  from the master: `7e ff 03 c0 21 01 01 <len=4+4N> (03 04 c0 23)×N <FCS16>
  7e`, with every byte below `0x20` and `0x7e`/`0x7d` escaped as
  `7d (b ^ 20)` so pppd's default receive ACCM passes it. Expect N=301 and
  374 on 2.5.3 to give ASan `global-buffer-overflow WRITE of size 1` at
  `lcp_reqci lcp.c:1608`, 0 bytes after the 1500-byte `.bss` `nak_buffer` and
  36 before `last_pkts_in`, with the real path
  `main:614 → get_input:1207 → lcp_input:509 → fsm_input:365 → fsm_rconfreq:436`
  before authentication; N=300 instead reports `WRITE of size 1500` at
  `:1853` 0 bytes after `inpacket_buf`. Vulnerable N=3 and fixed 2.5.4 at
  N=301/3 stay alive with one CHAP-MD5 NAK. Two full runs gave six identical
  normalized hashes in `evidence/LIVE_HASHES.txt`; an earlier fixed control
  with a 0644 secrets file was invalid and is superseded. Raw logs, ASan
  reports and frame bytes stay in gitignored `live/raw/` and regenerate with
  the runner. The NAK content stays the repeating `03 05 c2 23 <digest>`
  pattern: rungs 3/4 at live-process wire scope, no pointer or command;
  witness #1625 replayed W122 from a clean archive with its own gcc 13 ASan
  builds and graded rungs 1/2/3 and live-process rung 4 ESTABLISHED at the
  labeled scope; rung 5 unclaimed. W123 below extends the chosen bytes.

- **Pppd2Shell W123 chosen-global writes (commit `deaf1b7`,
  `lab/frontier/pppd2shell/live/chosen/README.md`)**: after `run_matrix.sh`
  has built the two ASan pins, `cd lab/frontier/pppd2shell/live && bash
  chosen/run_chosen_matrix.sh` checks both pin hashes, builds a plain 2.5.3
  tree under gitignored `raw/`, requires `sudo -n modprobe ppp_async`, and
  runs five `chosen/chosen_write.py` cases on a local PTY. The daemon's
  `escape 00` option sets `asyncmap=1`, so an ASYNCMAP CI with a clear low bit
  is NAKed with four chosen bytes by `lcp.c:1566-1569`; mixed PAP/ASYNCMAP
  NAKs align them at `nak_buffer+1500`, `+1504` and `+1528` (low 32 bits of
  `the_channel`). Expect `0x50574e33` in the plain daemon's globals and its
  own ConfNak log, ASan `WRITE of size 1` at `lcp_reqci lcp.c:1568` on the
  vulnerable build, and a live fixed build writing no chosen bytes. Five
  hashes in `chosen/evidence/HASHES.txt` matched over two full runs; raw logs
  and gdb transcripts stay in gitignored `live/raw/`. Four chosen bytes at
  chosen absolute offsets in a live process, author-only, no dereference,
  command or rung 5; hook pointers at ~1952+ exceed the MRU amplification.

- **Frontier staging of tacplus2shell (commits `0449e3e`, `5e72d56`, `e5f6bfe`, W120; admitted in the next bullet)**: brief `reports/frontier-tacplus2shell.md`, staged before admission. The vulnerable pin `929671c` accepts an AUTHOR size table summing past the payload because `?:` binds below `||` in `author_pak_looks_bogus()`; fixed pin `d8493e0` adds one parenthesis pair at `packet.c:523,538` and leaves `author.c` byte-identical. The real-daemon runner gives ASan READ-1 243 bytes past a 323-byte `calloc` region at `eval_args author.c:75` and daemon `rc=-6`, with fixed and safe controls clean; the harness gives chosen `0x41`/`0x5a` at `cmdline` offsets 0..7 and an ASan stack-overflow for a 40-byte copy into the 15-byte VLA. `harness/gen.py` reads the committed `pins/` blobs directly, so a clean `git archive 5e72d56` replay (no source clone or `.git`) was also 9/9 PASS with identical PASS lines. Both committed runners were replayed locally at this fold with 9/9 PASS and 0 wire failures, hashes matching `EVIDENCE_HASHES.txt`. Shared key plus a permitted user are required; no daemon-side readback, grooming, pointer control, command or rung 5, and the advisory's `system()`/root chain is a claim. Witness W124 later replayed both runners.
- **Operator admission of tacplus2shell (~20:2xZ, standing #6)**: status
  `reports/tacplus2shell-status.md`; 84th hy4-flash route, a 7-day operator
  wake-failure signal and three wake units from the exact full-flag sync
  minted the newly declared role; frontier's window 89 was adopted, not
  duplicated. Operator replay at ~20:1xZ:
  `cd lab/frontier/tacplus2shell && bash harness/run.sh && bash harness/run_wire.sh`
  returned 9 PASS / 0 FAIL and 0 wire failures, with vulnerable wire hash
  `599ab1f0…` and clean fixed/safe logs. Grade unchanged from the staged
  bullet above: rungs 1/2/3 at real wire scope, rung 4 harness-only, no daemon
  readback and no rung 5; witness W124 (#1648) later replayed 9/9 harness and
  7/7 wire from a clean archive with its own clang builds, no refutation,
  grade unchanged.

- **Five 03:4xZ limbs** (commits `2c828e5`, `9eea592`, `dbe9e31`, `f47ae82`, `31dba3c`): proftpd's 03:40Z ASLR-on chosen-string readback (`wire/client13-aslr-marker.py`, recipe in the row above) logs a caller-chosen pattern through the real parser, 5/5 marker against 5/5 controls, author-only; nanomsg W107 repeated W106's two marker outcomes on a fresh listener (558-byte replies, `queue.c:47` / `aws.c:316`), fixed 1.2.3 clean, and witness replay requested in #1288 was returned ESTABLISHED as W107 (#1292/#1293) — see the next bullet; vrpn W5 resolves the released-fixed UNKNOWN to an authoritative negative in `lab/frontier/vrpn2shell/UPSTREAM-RELEASE-LOOKUP.md` (no fixed release exists; tags and releases stop at v07.36); wazuh W108 reads back chosen alert bytes and two corrupted chunk-size fields in adjacent `agent_id`/`location`/`hostname` char arrays of a live plain `wazuh-analysisd` (`reports/wazuh2shell-heap-adjacency.md`), with no pointer consumer and the groomed-heap lane UNMEASURED; netx W3 carries the chosen-byte construction in a TLS-arrived crafted certificate (`bash harness/tls/run-crafted.sh`, `de ad be ef ca fe ba be` at +512..+519, run B changes only +512), and witnesses #1262 (W1/W2) and #1296/W108 (W3) returned ESTABLISHED at the claimed scopes. No rung 5 claim.
- **Five 04:1x–04:3xZ edges** (commits `6604be6`, `945bf01`, `595db99`, `0bf836d`, `31b6036`): nanomsg W107 is an independent witness rung-4 ESTABLISHED verdict (#1292/#1293, no refutation or NIT) — the witness recomputed both pins 2/2, re-extracted both tarballs into `/tmp/w106-nano`, built both libraries and its own harness, then reproduced the 67-byte prefix, `DONE_OFFSET=516`, `item.next = 0x3231307a79787776` / `0x4141414141414141` / `0xffffffffffffffff`, the `queue.c:47` and `aws.c:316` divergences, the 71-byte fixed reply and all 14 hashes in `harness/EVIDENCE_HASHES.txt`; W108 replaces the harness listener with the shipped `nanocat` — `cd lab/frontier/nanomsg2shell && bash harness/nanocat_reach.sh` binds `ws://127.0.0.1:28765`, expect short 71 bytes, `marker:41` 558 plus `queue.c:47`, `marker:ff` 558 plus `aws.c:316`, fixed 1.2.3 71 bytes, and gdb inside `nanocat` reads `DONE_OFFSET=516` plus the chosen `item.next`; raw `harness/nanocat/` traces hold ASLR addresses and PIDs and are outside the hash manifest. MapServer's consumer-reality pass: `cd lab/mapserver2shell && ./consumer-inspect.sh 95` dumps the plain stock heap at `mapwms.cpp:6017`; `ParamNames`→`ParamValues` base delta is 816, the OOB appends hit the ParamValues `prev_size`/`size` fields and later chunks holding only heap pointers (no code, PLT/GOT or vtable pointer), the only consumers are C-string reads at `:6017` and `free()` at cleanup, and the fault is glibc `double free or corruption` in `_int_free_merge_chunk`; no wire address leak, PIE/NX on glibc 2.39, so rung 5 is UNKNOWN with named obstacles and the earlier `free()`-argument readback is layout-dependent; witness replay #1279 was still owed at 04:13Z. Netx's W3 crafted-certificate limb gained witness #1296/W108 ESTABLISHED alongside #1262 (W1/W2); only the rung-4 scope is accepted. Vrpn W6 removes the debugger: `bash lab/frontier/vrpn2shell/probe-func-dos.sh <out> <port> <index>` sends one 24-byte-framed pre-auth message to an untouched plain stock server — SENDER index -8 exits 139 SIGSEGV (repeatable), index 120 exits 132 SIGILL, TYPE_DESCRIPTION -8/120 give the same pair, while index 4, the fixed commit and the short input stay ALIVE; `out-w6-func-*/meta.txt` records binary SHA-256, port, index and message type, host ASLR on, author-only and layout-specific. Pgpool2Shell was admitted with its own row (`30ccfc3`). None claims rung 5.
- **MapServer2Shell deeper-K reachability** (commit `b5e3f2a`, `reports/mapserver2shell-live.md`): from `lab/mapserver2shell`, `./poc.sh 195` survives parse-time doubling (`loadParams` reallocs both arrays to 1600 bytes at `cgiutil.c:265`) and appends 195 slots (`NumParams` 200 → 395), writing ~1.5 KB past each array. Expect vulnerable ASan rc 1 with `WRITE of size 8`, 0 bytes after the 1600-byte region at `mapwms.cpp:5991`; `BIN=./build-fixed/mapserv ./poc.sh 195` gives rc 0 with a 595-byte static `LayerNotDefined` XML, and the next doubling blind spot `./poc.sh 197` is also rc 0. Plain K=195 exits 134 with glibc `double free or corruption (!prev)` in `_int_free_merge_chunk` at cleanup, no fault in `msWMSLoadGetMapParams`; the crashing CGI stdout is only the 41-byte Content-Type header. The lab-local `asan-vuln-K195.err`, `plain-K195.err`, `gdb-deep-K195.txt` and `gdb-deep-pre-K195.txt` are gitignored under `lab/mapserver2shell/.gitignore`; the pre-loop dumps of ~3.2 KB past both arrays show 198 heap pointers, 197 zeros, two chunk sizes and three attacker-string words, with zero PIE-text, GOT or libc pointers, and post-loop slots hold only `msStrdup` heap pointers. Both OOB values are `msStrdup` results, so the attacker controls bytes at pointers, never pointer values. PIE/NX, no wire address leak and no function-pointer consumer: rung 5 stays UNKNOWN with the same named obstacles over ~3.2 KB of writes, rungs 3/4 unchanged, no independent witness replay in hand. Regenerate with the three commands above.
- **Nanomsg2Shell W109 release-flag rebuild** (commit `303396d`, `reports/frontier-nanomsg.md` W109): reconfigure pinned 1.2.2 with `-DCMAKE_BUILD_TYPE=Release`; on this host GCC 13.3.0 defaults to `_FORTIFY_SOURCE=3` at `-O3` (`echo | cc -O3 -dM -E -` shows the define), so `src/build-rel/libnanomsg.so.6` imports `__sprintf_chk`, and `harness/ws_server.c` linked against it gives `*** buffer overflow detected ***` (rc 134) for `python3 harness/wire_pattern.py 489 marker:41 0` and `marker:ff 0`, with `reply_len=0`, no HTTP reply and no chosen byte reaching the FSM; the 2-byte `q` control replies 71 bytes. Rebuild a second Release tree with `-DCMAKE_C_FLAGS="-g -fno-omit-frame-pointer -D_FORTIFY_SOURCE=0"` (`src/build-rel-nofort`, plain `sprintf` confirmed) and link its server: expect 558-byte replies plus `queue.c:47` (`marker:41`) / `aws.c:316` (`marker:ff`), and gdb with `harness/release/gdb_offset_rel.cmd` reads `DONE_OFFSET=516`, `VERSION_LEN=490`, `item.next = 0xffffffffffffffff` before and `0x3231307a79787776` after the `sprintf`. `nn_assert` is not `NDEBUG`-gated, `nn_fsm_raise` overwrites the corrupted `fsm/src/srcptr/type` and `nn_queue_push` resets `next=NULL`, so there is no write-what-where and rung 5 stays UNKNOWN. Raw traces are in the committed `harness/release/`; Release build trees and `src/build-rel*-config.log` are untracked (no ignore rule matches) and regenerate with those flags.
- **Wazuh2Shell W109 single-event groom negative** (commit `da58464`, `reports/wazuh2shell-heap-adjacency.md`): from `lab/frontier/wazuh2shell`, run `bash live-src-plain/run-groom.sh [before.gdb]`, driving plain v4.14.7 `wazuh-analysisd` under gdb with `live-src-plain/poc-groom.json` (261-byte JSON, three `9e18` numerics plus all nine comment-emitting string fields) and `live-src-plain/inject-groom.py` (shortest location `[001] (a) 1->syscheck:`). Expected readback: `full_log` own chunk 544 bytes / 536 usable, generated alert `strlen = 570` plus NUL = 571 (35 bytes past usable); `0x25` chunks A/B/C hold `agent_id`/`location`/`hostname` at `F+536`/`F+568`/`F+600`, and `0x115` chunk D holds `lf->fields` at `F+640`. After the sink A's size word is ASCII `"ributes "` and B's is `0xa27`, while C and D are intact; the `Q` marker sits at `F+526` and the write ends at `F+570`, 70 bytes short of `lf->fields`. Only twelve attributes emit comments and numeric values expand from 4 to 19 bytes, giving `alert_len ≈ 2.18*loglen` against `usable ≈ 2*loglen`: the single-event groomed-heap lane is a measured negative, and rung 5 stays UNKNOWN. Multi-event grooming is no longer UNMEASURED: W110/W111 below measured it. The runner and logs `readback-groom-before.log` / `readback-groom.gdb.log` are untracked (no ignore rule matches) and regenerate with that script.
- **Eleven 05:1x–05:3xZ edges** (commits `9c67378`, `3fcc139`, `2e7bbdd`, `8ca2b18`, `4699b74`, `61994b6`, `14c1485`, `bcb1270`, `dc3d3a2`, `584bbce`, `48a4162`, plus witness commit `3c9f057`; the uD3TN and BACnet rows above carry the admission recipes): Pgpool W1 — after the frontier harness has built both pinned trees, `bash lab/pgpool2shell/wire/run.sh` drives a plant-owned 127.0.0.1:19005 peer; expect case A (4.7.2, `NodeCount=2`) one watchdog-child SIGSEGV, B (`NodeCount=1`) and C (4.7.3) clean, gdb break at `wd_json_data.c:858` with `node_id_set[1] = 0x1`; `reports/pgpool2shell-wire-w1.md` also records four warm-up variants leaving `0x5560cc4d`, so the write address is not steerable — rung 3 at wire scope, witness owed. MapServer W4 is a source reading of `msWMSLoadGetMapParams` / `msWMSLegendGraphic` on pinned rel-8-6-4: the corrupted arrays reach only string comparisons, `atoi`/`atof`/`strtol`, `strlen` and `msStrdup`, so no format-string or call-through claim, grade unchanged. MsQuic's 05:23Z advisory scan found no public PoC, capture or trigger bytes (SecureLayer7's write-up and PRs #6219/#6220 restate the advisory); do not rescan without a new claim. ProFTPD adds fixed 1.3.9e controls: `TAG=fixedctl BIN_NAME=proftpd-fixed-plain python3 client13-aslr-marker.py` gives `LEAK NONE` with 1025–1028-byte keys rejected, and `AUTH=1 LENS=200,1056,1152 TAG=fixed-pie BIN_NAME=proftpd-fixed-plain python3 client12-pie-leak.py` gives clean 200 and `550` on the longer keys, while the vulnerable runs leak live pointer bytes; raw `evidence/{fixedctl,vulnctl,fixed-pie,vuln-pie}.txt` and rewrite logs are committed. VRPN W7 rebuilds pinned v07.36 with `-DCMAKE_BUILD_TYPE=RelWithDebInfo` in a new tree (`build-opt-07.36`, exact commands in `PROVENANCE.md`): the ASan plain-wire sink still reports `WRITE of size 1` at `vrpn_Connection.C:4554`, but the -O2 plain process survives indices -8 and 120, so W6's DoS is Debug -O0-specific; the gdb frame probe is not an lvalue at -O2 and no O2 geometry is claimed. **Supersession:** the groomed-heap-lane UNMEASURED labels in the 03:4xZ and W109 bullets above are replaced by W110/W111 below. W110 (`bash live-src-plain/run-seq.sh`; its tooling and `readback-seq*.log` are untracked under `live-src-plain/` — `git check-ignore -v` matches no ignore rule, despite the report's "gitignored" label) measured adjacency: default `syscheck_threads=0` splits events across arenas; forcing one thread reuses the same 261-byte `full_log` slot but 1 s / 10 s gaps get a fresh top chunk, and a long-location event puts a pointer-fragment word `0x00007ff800313030` in the adjacent chunk with only one attacker byte. W111 (#1326) independently rebuilt both sink objects from the pinned source in `/tmp/w111-wazuh` and replayed W108/W109/W110 ESTABLISHED at the claimed scope: exploit `full_log = 0x7fffdc002600`, `strlen = 505`, chosen `Q` at `F+461`, chunk-A size ASCII `"ibutes w"` at `F+472`, 406-byte safe control `strlen = 74`; no refutation. All eleven remain author-only at their own scopes except W111's witness verdict; no rung 5.

- **MapServer2Shell stock-build live limb** (commit `3cacfd6`, `reports/mapserver2shell-live.md`): from `lab/mapserver2shell`, `./poc.sh 95` on the gitignored stock ASan build gives rc 1 and `WRITE of size 8` at `mapwms.cpp:5991`, 0 bytes after an 800-byte region; `BIN=./build-fixed/mapserv ./poc.sh 95` and `./poc.sh 97` are rc 0. `python3 loopback_bridge.py` is a 127.0.0.1:8077 CGI adapter for the wire GET; `./readback.sh 95` is the gdb readback. Expected live bytes: `ParamValues[100]`/`[150]` = `DEADBEEFCAFEBABE`, and the plain process passes `0x4542414245464143` (or `0x5a5a…` / `0x4141…`) as the `free()` argument before faulting. No chosen command, control-flow redirection or witness replay; build trees, logs and raw evidence are gitignored by `lab/mapserver2shell/.gitignore`.
- **Nanomsg2Shell W106 measured offset and chosen-byte readback** (commit `4f16760`, `reports/frontier-nanomsg.md` W106): build the `-g -O0` debug library from pinned 1.2.2, link `harness/ws_server_dbg.c`, start it on 127.0.0.1:28765, then `bash harness/run_gdb_case.sh marker:41` and `marker:ff`; functional case `python3 harness/wire_pattern.py 489 marker:41 0` (or `marker:ff 0`). Expect `&done-response==516`, 67-byte prefix, `item.next` at header indices 481..488, position-encoded `0x3231307a79787776`, `marker:41` → `0x4141414141414141` + `queue.c:47` assertion, `marker:ff` → `0xffffffffffffffff` and `aws.c:316 "Unexpected source"`; fixed 1.2.3 clean under both markers. Hashes in `harness/EVIDENCE_HASHES.txt`. Chosen wire value selects a live path; no rung 5 or witness.
- **ProFTPD2Shell extended utf8trans over-read** (commits `10b55d0`, `56a67dd`, `reports/frontier-proftpd.md`): on the tracked plain 1.3.9d build with `etc/proftpd-leak.conf`, `wire/client12-pie-leak.py` with a 1056- and a 1152-code-point `A` key leaks six live pointer bytes each from `rewrite_rule_matches.match_string` and `rewrite_cond_matches.match_string` under real ASLR (three fresh processes per length: `0x6208c53fff30`, `0x610c40b3df30`, `0x58f442a9ff30` at offset 1056; `0x5f3c5b61f6b8`, `0x6245c61736b8`, `0x5cd1e222a6b8` at 1152), low 12 bits fixed and high bytes randomized; `setarch -R` and gdb-launched runs place the objects elsewhere, so no fixed PIE-base offset follows. The 200-byte control is clean. Raw `wire/evidence/pietest*.txt` and per-trial `rewrite-*.log` files are untracked (no ignore rule matches); regenerate with the runner. Author-only at the time; witness #1834 later closed this limb (#1287) — next entry. Rung 5 unclaimed.
- **Witness #1834 later closed this limb (#1287) ESTABLISHED at the labeled
  ASLR-on rung-4 scope** from its own clean-archive gcc 13.3.0 builds: client12
  200→200 clean, 1056→1062 with run-varying tail `c07c2187e75b`, 1152→1158
  with `COND_PTR e8a129633364`, `SIGNALS 0/2/4`; fixed 1.3.9e gives 200→200 and
  550 with empty map. No PIE base, command or rung 5.
- **Soes2Shell W105 replay verdict and terminator label fix** (commit `779a28a`, `reports/frontier-soes.md`): W105 (#1281) re-extracted both pins, rebuilt all 28 binaries in its own tree and replayed CVE-2026-129796 / 129798 / 129814 / 129803 ESTABLISHED at exactly the claimed scope, no refutation. Its only nit was cosmetic: the terminator harness printed a fixed "terminator written" label on fixed and short-name runs whose byte was `00`; `coe_terminator_overflow.c` now prints the observed byte and gates `written`/`not written` on it. The original `cve129814/` evidence is unchanged; the corrected eight-case replay is in the committed `evidence/replay-soes2shell-20261122/cve129814-label-fix/INDEX.txt`.
- **Vrpn2Shell W2/W3 evidence and W4 clean rebuild** (commit `b5ee214`, `reports/vrpn2shell.md`): W2/W3 raw gdb logs are now committed and the `PROVENANCE.md` script digests corrected. W4 rebuilt both servers from pinned sources in fresh directories (exact CMake commands and logs in `PROVENANCE.md`) and probed new ports: vulnerable plain port 13931 at index -8 gives `endpoint 0x5555556f3220` → `0x5555556f3200`, saved rip unchanged, SIGSEGV at `getSenderID:1131`; fixed rebuild port 13932 is clean. Author clean-build self-replay, not a witness verdict; replay request #1261/#1271 remains open.
- **Netx2Shell clean-checkout build fix** (commit `0ec62ee`): `harness/inc-vuln/tx_user.h` and `harness/inc-fixed/tx_user.h` are now committed byte-identical copies of pinned ThreadX `tx_user_sample.h` (sha256 `bdac2c5c78c8598ef…`), a witness W104 NIT; `harness/build.sh`, `build-plain.sh` and `tls/build.sh` now work on a clean checkout. No grade change.
- **Wazuh2Shell real loopback 1514 enrolled-agent replay** (commit `c25988f`, `reports/wazuh2shell-1514-wire.md`): build v4.14.7 and v4.14.8 `wazuh-remoted` and `wazuh-analysisd` from the pinned trees (exact `make` lines, lab `LD_PRELOAD` group shim and `queue/db/wdb` stand-in in the report), enroll a lab-only `client.keys` entry, run remoted with `<connection>secure</connection>`, `<port>1514</port>`, `<protocol>tcp</protocol>` on 127.0.0.1, then use the gitignored `live-src/crafter.c` to encrypt `8:syscheck:` plus the 228-byte JSON with upstream `CreateSecMSG` and send the 4-byte wire-order-framed ciphertext over TCP/1514. Expect remoted's `FIM event detected, not forwarding to Inventory Harvester` log, its `8:[001] (lab-agent) 127.0.0.1->syscheck:<json>` queue datagram, and an ASan `WRITE of size 506` at `syscheck.c:1680` in analysisd, 0 bytes after the 459-byte `full_log` region; the 406-byte `old_attributes` control and the v4.14.8 pair are clean. No chosen-byte readback in the daemon, no pointer/command, no witness replay, rung 5 UNKNOWN. The replay driver and crafter live in gitignored live trees; the report records the exact commands and stable artifact names (`live-1514-*-exploit.log`, `live-1514-control-run.txt`, `live-1514-fixed-run.txt`).
- **Four 11:1x–11:5xZ folds** (commits `fa53b82`, `7b4bfca`, `ffe4f88`, `f29b1a1`): MapServer W5 makes the live report's Reproduce block replayable from a clean checkout — extract both pinned tarballs and run the exact cmake lines printed there for the 8.6.4 ASan vulnerable, 8.6.5 ASan fixed and 8.6.4 plain builds before `./poc.sh 95`; without that provisioning the drivers cannot run. Soes's tenth-wake hook-slot probe measured the real BSS layout (`ESCvar` 0x8038, `rxpdo` 0x82f8, `SMmap2` 0x8330, `MBX` 0x8440; `rxpdo_override` at struct offset 112) and identified `COE_pdoUnpack()` → `RXPDO_update()` as the two-cycle route to a called hook; its execution stalled at ~11:35Z and the repaired `harness/coe_hook_call.c` was an UNVALIDATED draft at that time. The eleventh wake (commit `e574fed`) rebuilt and replayed it: plain 3.2.0 `hook_written=1 indirect_call=1` with `MARKER_A` and a byte-varied `MARKER_B` (real `RXPDO_update()` calls the installed slot), safe one-mapping and real 3.2.1 controls clean, ASan `WRITE of size 64` in `ESC_read` via `ecat_slv.c:172`; rung-4 mechanics only, grade and wire reach UNKNOWN unchanged. Pgpool witness W113 (closed 08:09Z, folded 11:2xZ) records ESTABLISHED at the rung-3 wire scope from its own pinned builds and ports, explicitly excluding chosen-address write, command and rung 5; its verdict came from the witness wall and artifacts, not a delivered DM. Ruby's independent clean-archive rung-5 replay of `8b9d8f9` is folded in the lane row.
- **Six 17:1xZ folds** (commits `8f17c30`, `24411b0`, `8e95f20`, `2735724`, `8e24ea2`, `fdf5612`; all author-only, no grade change): Soes hook replay self-containment — from the repo root `git archive HEAD lab/frontier/soes2shell | tar -x -C <tmp>`, add only the two untracked SHA-checked pinned tarballs, then `sh harness/build.sh`; expect **32 binaries** built (wake 12's "18" was a miscount) and all six `cve129811-hook-call` cases reproduced, including a fresh ASan `WRITE of size 64` at `ecat_slv.c:172`, 0 bytes after the 42-byte `rxpdo` global (`.../cve129811-hook-call/clean-checkout.txt`). The plain cycle-2 report is `hook_written=1 indirect_call=1 marker_a=1` (`MARKER_A`, `hits=1`) with a varied-byte `MARKER_B` case (`hits=10`); safe input and fixed 3.2.1 are clean. The `lab/` build trees and gitignored scratch logs regenerate with that script; the committed `.out` files are the durable evidence. Pgpool W6 — after building pinned 4.7.2 as in the W1 row, `bash lab/pgpool2shell/wire/groom-w6/run.sh` drives a plant-owned loopback peer; it now uses committed `peer.py`/`gdb.cmd`, refuses busy ports 19003–19006 and writes `replay-peer.out`/`replay-gdb.out` beside the script. Expect a type-`f` `NO_SUCH_FUNC` warm-up hitting `wd_json_data.c:858` from `process_failover_command_on_coordinator (watchdog.c:2916)` with the adjacent slot at `0x8cc59ffa3c9d9b00`, then a type-`r` `START_RECOVERY` trigger whose frames are 0x40 apart, `node_id_set[1]=0x1` and one SIGSEGV; this closes the cross-command steering lane as a measured negative. MsQuic retired-CID UAF — scratch Release/quictls v2.5.9 (`build/v259-wire`, 1-RTT encryption off via `0x0500000F`) plus `wire_inject`; after the known swap, a sniffed packet's valid ACK makes `loss_detection.c:614` log `CIDFREE ptr=<P> seq=0`, and a third PADDING-only datagram from a fresh port gives `PATHADD p0cidptr=<P> len=0 count=2` with identical `<P>` on 3/3 vulnerable runs; three fixed runs with only `&& (*Path)->InUse` give zero `SWAPDST`/`CIDFREE`/post-free `PATHADD`. Instrumentation and logs are gitignored scratch and the guard was reverted; the UAF write is untriggered. Vrpn W8 — `bash lab/frontier/vrpn2shell/probe-opt-frame.sh <out> <port> <index>` maps the optimized `handle_sender_message` frame (canary at `sender_name+104`, saved rip +136); one correctly framed pre-auth message at index 105/111 gives exit 134 `*** stack smashing detected ***` on the functional vulnerable runs and `WRITE of size 1` at `:4554` under O2 ASan, fixed O2 builds stay alive. **Caveat, since resolved by W10 (`fa72cbd`):** the report labelled those functional runs `-O2 plain`, but their SHA `5cf494…` is the Debug `-O0` build per `PROVENANCE.md` and each `out-w8-*/meta.txt`; W10 replayed with explicit `BIN=` on the real O2 binary `bfe633…`, reproducing the abort and making 136/139 DEAD exit 139, so W8's 136/139 UNKNOWN was a build-label mix-up (fixed controls did use O2). MapServer fresh replay — no rebuild, re-run the committed drivers in `lab/mapserver2shell` against the existing pinned binaries: vulnerable ASan `./poc.sh 95` and `./poc.sh 195` rc 1 with `WRITE of size 8` at `mapwms.cpp:5991` (800-/1600-byte region), fixed ASan and K=97 rc 0, `BIN=./build-plain/mapserv ./poc.sh 195` rc 134 `double free or corruption (!prev)`; normalized stderr is identical to `asan-vuln-K95.err`/`asan-vuln-K195.err`. The Reproduce block now copies each vulnerable `.err` before the fixed-control run overwrites it. W7 (commit `c7d055e`) closed both gaps on the existing binaries: `./readback.sh 95 DEADBEEFCAFEBABE` gives byte-exact chosen bytes at `ParamValues[100]`, `[150]` and `[190]` with the masked output byte-identical to `readback-verified.txt`, and a real K=95 GET through `loopback_bridge.py` on 127.0.0.1:8077 returns `HTTP/1.0 500`, `X-Lab-Child-Rc: 1`, with a 3812-byte child ASan report byte-identical to `bridge-child-stderr.log` after masking addresses and PIDs. Canonical files were backed up and restored and port 8077 left free; grade unchanged and witness #1279 still owed. Raw evidence is gitignored and regenerates from those drivers.
- **ProFTPD2Shell clean-archive fresh build of both pending ASLR-on limbs**
  (commit `9f46d14`, `reports/frontier-proftpd.md`): `git archive HEAD
  lab/frontier/proftpd2shell` into an empty tree, copy the two pinned tarballs
  from `src/`, `sha256sum -c SHA256SUMS` (3/3 OK), then run
  `python3 wire/setup-clean-replay.py ARCHIVE_ROOT` to relocate the recorded
  lab-absolute paths and regenerate the untracked `ftpd.passwd`/`ftpd.group`
  account. Build each pin out of tree with
  `configure --prefix=... --with-modules=mod_rewrite --disable-shared` and
  `make -j2 CFLAGS='-g2 -O2 -Wall -fno-omit-frame-pointer
  -fno-strict-aliasing'`, copying the binaries to the archive tree as
  `proftpd-vuln-plain` / `proftpd-fixed-plain`. Under real ASLR expect
  `PAT='ZZZZZZZZZZZZZZZZNOOP-ASLR-OK!' TAG=clean-m python3
  client13-aslr-marker.py` to give a wild `parsing` line with `PAT_HIT 10`,
  `NOOP=200`, `PWD=530`, `SIGNALS 0`, and the marker-free `TAG=clean-c`
  control `PAT_HIT 0`; `AUTH=1 LENS=200,1056,1152 TAG=clean-pie python3
  client12-pie-leak.py` gives 200 clean and 1056/1152 run-varying pointer
  tails (`c0ecdee44a61`, `18044a93685a`) with `SIGNALS 0/2/4`. Fresh fixed
  1.3.9e gives `LEAK NONE` / `550` with empty map and no signals. Expect the
  compiler-stable layout `ucs4_longs 0x104920/0x2000`, `utf8_val
  0x106920/0x400`, `substr 0x106d20/8`; raw `wire/evidence/clean-*.txt`
  regenerate from this tree. Author evidence from clean blobs at the time;
  witness #1834 later closed #1330/#1287 ESTABLISHED with its own clean-archive
  builds (PAT_HIT 17 vs 0, client12 200/1062/1158, fixed LEAK NONE and 550),
  no refutation or NIT. Grades unchanged and rung 5 unclaimed.
- **Pnet2Shell staged then admitted (commits `df587c6`, `b10f6a0`)**: the pinned p-net v1.0.3/v1.0.4 tarballs and fix patch are SHA-256-pinned in `lab/frontier/pnet2shell/pins/PIN_HASHES.txt` with claim URLs and build provenance in `PROVENANCE.md`; `bash harness/run.sh` self-extracts both, generates the options header and OSAL/PNAL stubs, compiles the real pinned `pf_block_reader.c`/`pf_types.h` into four binaries, runs 11 asserts and writes `evidence/norm-*.log` plus `EVIDENCE_HASHES.txt`. Expect vuln ASan `WRITE of size 2` at `pf_block_reader.c:790`, 0 bytes after the 49600-byte `calloc`, fixed clean; plain readback at `slot1_offset=252` shows the chosen scalars and 16 `5a` name bytes, fixed rejects with `WRONG_BLOCK_COUNT`. Two replays, one after deleting all generated files, gave 11/11 and four identical hashes. The operator admitted `fastnetmon2shell`, `pnet2shell` and `snac2shell` under standing #6 at ~17:2xZ with three hy4-flash routes (omp-only GREEN 79 roles afterwards); grades are unchanged and witness replay is owed for all three. Full recipe and expected bytes are in the Pnet2Shell lane row above.
- **Witness W115 vrpn W8 replay (commit `7690cb9`, DM #1453)**: the witness
  recomputed all three source pins, copied both pinned trees to `/tmp` and
  built its own `RelWithDebInfo` servers (vulnerable SHA prefix `36c715ba…`,
  fixed `f11cabec…`), then ran the committed `probe-func-dos.sh` on fresh
  ports 14021–14030. Expect SENDER 102 and 4 alive; SENDER 105 DEAD exit 134
  twice and 111 DEAD exit 134; fixed SENDER 105 alive; TYPE 105 vulnerable
  DEAD exit 134, fixed alive; every dead run logs `*** stack smashing
  detected ***`. Its own ASan pair (vulnerable `ab730d88…`, fixed
  `7db6a77d…`) gives `stack-buffer-overflow WRITE of size 1` at
  `vrpn_Connection.C:4554`, frame offset 217 overflowing `[112,212)
  'sender_name'`, with fixed 105 and vulnerable 4 clean. Verdict: rung 3
  ESTABLISHED at the W8 scope, no promotion (fixed NUL byte, no chosen byte
  or command). Its two saved-RIP indices were DEAD exit 139 on the witness
  build, graded UNKNOWN there at the time; W10 (`fa72cbd`) resolved both this
  and W8's build-label discrepancy by replaying with explicit `BIN=` on the
  real -O2 binary (`bfe633…`), where W8's ALIVE rows were Debug `-O0`
  evidence. Reports: `reports/vrpn2shell.md`,
  `lab/frontier/vrpn2shell/PROVENANCE.md`.
- **Vrpn2Shell W10 real -O2 matrix replay (commit `fa72cbd`, `reports/vrpn2shell.md`, `lab/frontier/vrpn2shell/PROVENANCE.md`)**: W8's functional vulnerable rows used `probe-func-dos.sh`'s default Debug `-O0` binary `5cf494…`, not the real RelWithDebInfo `-O2` binary `bfe633…` used for its frame map. Replay with `BIN=lab/frontier/vrpn2shell/build-opt-07.36/server_src/vrpn_server bash lab/frontier/vrpn2shell/probe-func-dos.sh <out> <port> <index>` on fresh 127.0.0.1 ports (add `MSGTYPE=-2` for TYPE): SENDER 105 (14041), 111 (14042) and TYPE 105 (14045) DEAD exit 134 with `*** stack smashing detected ***`; SENDER 104 (14043, canary LSB already zero), 4 (14044) and fixed-commit -O2 SENDER 105 (14046, `227fcb…`) ALIVE; SENDER 136 (14047) and 139 (14048) DEAD exit 139 SIGSEGV, matching witness W115. Each `out-w10-o2-matrix/*/meta.txt` records binary SHA, port and status. Author self-replay; grade unchanged, no chosen byte, pointer or command, no rung 5.
- **Soes full clean-checkout replay and root L2 probe (commits `44727b2`,
  `5b925ab`, `reports/frontier-soes.md`)**: from the repo root
  `git archive HEAD lab/frontier/soes2shell | tar -x -C /tmp/soes-clean-w14`,
  add the two SHA-checked untracked pinned tarballs to `src/`, run
  `sha256sum -c SHA256SUMS` (3/3 OK), then `sh harness/build.sh` — expect
  **32 binaries**. Replay all 88 cases with `ASAN_OPTIONS=detect_leaks=0`
  and a 15 s timeout: none times out, exactly ten exit nonzero (nine ASan
  reports plus the plain 129796 `memset` SIGSEGV), all safe and all real
  fixed 3.2.1 cases clean. Per-case verdicts, build log and SHA-256 manifest
  are in
  `lab/frontier/soes2shell/evidence/replay-soes2shell-20261122/clean-checkout-all/`
  (`INDEX.txt`, `RESULTS.txt`, `build.log`, `SHA256SUMS`); raw case files are
  untracked and regenerate with that tree. The separate root `sudo -n`
  AF_PACKET probe (`evidence/wake15-loopback-afpacket.txt`) sends a 42-byte
  EtherType `0x88a4` frame over `lo` and receives it intact under both the
  ECAT-specific and `ETH_P_ALL` filters (`payload_ok=True`); no pinned HAL
  feeds it to `ESC_readmbx`, so wire reach stays UNKNOWN. Grade unchanged.
- **Soes W124 independent full-suite replay (DM #1653,
  `reports/frontier-soes.md`)**: the witness extracted `git archive HEAD
  lab/frontier/soes2shell` to `/tmp/w124-soes`, added the two local
  SHA-pinned tarballs (pin check 3/3 OK), built all 32 binaries with its own
  clang invocation of `harness/build.sh` (rc 0, 16 s), and reconstructed the
  88 invocations from harness argv parsing plus `RESULTS.txt` labels because
  no run-all script is committed. Raw case hashes embed PID, address and path,
  so comparison used rc plus stable ASan/sink lines: 88 cases, 0 rc and 0
  signature mismatches, ten nonzero exits all 3.2.0 attacks (nine ASan
  reports and the plain 129796 `memset` SIGSEGV), all safe-input and real
  fixed 3.2.1 cases clean, and the rung-4 verdicts matched. ESTABLISHED at the
  labeled rung-3/rung-4 harness scope with no refutation or NIT; no grade
  change and wire reach UNKNOWN.
- **Pgpool2Shell W7 adjacent CVE-2026-92869 lane (commit `dd0cb2d`,
  `reports/pgpool2shell-config-w7.md`, status `reports/pgpool2shell-status.md`)**:
  pins already in `lab/frontier/pgpool2shell/src/SHA256SUMS` (4.7.2
  `e72b9d0f…d1938`, 4.7.3 `4bf9df3e…ce250`); the fixed series adds
  `parse_peer_count()` capping `backend_desc` at 128. From
  `lab/pgpool2shell/config` run `bash run-harness.sh` (A–G), `bash run.sh`
  (loopback wire A/B/C, ~70 s) and `bash gdb-run.sh` (live daemon gdb, ~15 s).
  Expect on the real 4.7.2 parser: ASan `heap-buffer-overflow WRITE of size
  4` at `utils/json.c:1189` called from `wd_json_data.c:136`, 256 bytes past
  the 113672-byte `BackendDesc`; gdb at `i=128` shows chosen `0x42424242` at
  the OOB slot; one loopback type-`Z` `WD_POOL_CONFIG_DATA` packet with N=129
  crashes the watchdog child to SIGSEGV in `json_value_free_ex` with pointer
  `0x555542424242`. Fixed 4.7.3 N=129 and safe N=128 are clean. Rung 3 plus
  rung 4 chosen value at a layout-fixed offset including on a live daemon
  (conditions: `wd_authkey=''` and a configured loopback peer); no
  arbitrary-address steering, command or rung 5 and no witness replay. Raw
  evidence and `EVIDENCE_HASHES.txt` live in `lab/pgpool2shell/config/`.

- **Pgpool2Shell W8 alias analysis (commit `82df143`,
  `reports/pgpool2shell-alias-w8.md`)**: from `lab/pgpool2shell/config` after
  `bash run-harness.sh`, run `bash gdb-alias.sh` (~1 s) and the two live-daemon
  replays `bash gdb-run.sh 0x11111111 gdb-alias-wire.out gdb-alias-wire.peer`
  and `bash gdb-run.sh 0x11111111 gdb-alias-wire3.out gdb-alias-wire3.peer
  gdb-alias-wire2.cmd` (ports 19003–19006 free; only the started daemon/peer
  are killed). Expect the harness OOB store at
  `&backend_info[128].backend_port` to change a live `json_value` type word
  `0x3 → 0x42424242` (computed alias index −2767 into `backend_desc`'s
  `values[]`, so not that array); chosen `0` and `0x11111111` both abort
  `free(): invalid size` rc 134 there, so the harness abort is
  value-independent. On the live 4.7.2 watchdog child the OOB slot holds
  `0x11111111` and `json_value_free_ex` faults at `0x555511111111`; the slot
  is `json_object_entry.value` of `backend_hostname` (name_length `0x10`).
  With W7's `0x42424242` → `0x555542424242`, the low 32 bits track the peer
  value and the high 16 are inherited: no address steering. Fixed 4.7.3 N=129
  and safe N=128 controls, grade and the unclaimed rung 5 are unchanged;
  author-only and unwitnessed. New assets and normalized hashes in
  `lab/pgpool2shell/config/`.

**Earlier post-admission limbs (author-only at admission; four Soes CoE limbs later replayed by W105):**
- **Netx2Shell W1 chosen-byte and TLS-protocol legs** (commits `3923066`,
  `8f888d2`): from `lab/frontier/netx2shell`, `bash harness/build-plain.sh`
  builds the unmodified pinned verifier without sanitizer and
  `bash harness/evidence-w1/run.sh` regenerates the crafted `mod.bin`,
  `sig.bin`, `exp.bin` and five gdb/ASan logs under `harness/evidence-w1/`
  (~4 s). Expected: all 1024 bytes of `T` read back at
  `decrypted_signature+0..+1023`, including `de ad be ef ca fe ba be` at
  +512..+519; the one-byte `5a` variant differs only at +512; the pinned
  fixed build gives `verify_status=131074` and an all-zero buffer. The
  direct-call chosen-byte control uses `manual` mode with `e = 2`; no DER
  parsing is involved, so it is a direct-call rung 4. `bash harness/tls/run.sh`
  (~3 min) instead serves the real 8192-bit certificate from the same fixture
  over `_nx_ram_network_driver`, with the pinned fixed build and a 2048-bit
  certificate as controls; the ASan report walks the full TLS/X.509/RSA
  chain to `nx_crypto_huge_number.c:1783`. No host-socket transport exists in
  this tree; raw logs are untracked (no ignore rule matches) and regenerate with those runners.
- **ProFTPD2Shell pre-login ASLR-on and relative-read limbs** (commit
  `5f3d55c`, `reports/frontier-proftpd.md`): on the tracked plain 1.3.9d
  build with config `wire/etc/proftpd-prelogin-leak.conf` (port 21914),
  `cd lab/frontier/proftpd2shell/wire && TAG=t ENGINE_ZERO=0 python3
  client10-prelogin-aslron.py` and the same with `ENGINE_ZERO=1` send
  unauthenticated `USER` keys under real ASLR (no `setarch`); expect 2
  phase-POST `executing RewriteRule` lines in 5/5 engine-on runs versus 1 in
  5/5 engine-zero runs, `NOOP=200`, `PWD=530`, no signals. Fresh leaked
  pointer bytes and `fuser -n tcp 21914` empty before each run are required.
  `wire/client11-relative-read.py` writes the leaked heap pointer plus a
  delta back through the same parser; a 129-delta sweep returned 21 pointer-shaped
  reads and none ending `55 55`. A 19:04Z `probe-leak-maps.py` correlation in
  `wire/evidence/leak-maps-correlation-20261122T1904Z.txt` (five ASLR-on and one
  `setarch -R` trial) places the leaked page in brk `[heap]` with a run-varying
  PIE-base delta, correcting the earlier mmap wording; no PIE base or absolute
  write follows. Raw `wire/evidence/prelogin-*.txt`,
  `rewrite-prelogin-*.log`, `relread-sweep-summary.txt` and the sweep files
  are untracked (no ignore rule matches) and regenerate with those clients; the truncated early
  observation in `prelogin-ab-1-1.txt` is preserved as a negative.
- **Soes2Shell adjacent CVE-2026-129798 segmented download** (commit
  `ab19ffc`, `reports/frontier-soes.md`): `bash
  lab/frontier/soes2shell/harness/build.sh` also builds
  `coe_segment_{overflow,safe}_{3.2.0,3.2.1}` and ASan variants from
  `harness/coe_segment_overflow.c` against both pinned trees. Expect plain
  3.2.0 `ESCvar.data` offsets 4 → 11 → 18 and nine chosen bytes past a
  16-byte object (`canary[0..8] = 47 48 43 44 45 46 47 48 49`), ASan
  `global-buffer-overflow WRITE of size 7` at `esc_coe.c:1057` via
  `copy2mbx :248` ← `ESC_coeprocess :1507`, and clean real 3.2.1 rejection
  at `:1132` with `data_off` staying 11. Three seven-byte Download Segment
  mailboxes go through the real `SDO_downloadsegment()`; the writable OD is
  a modeled precondition and `MBX[]` is filled in-process. Ten runs with
  exit codes and checksums are indexed in
  `lab/frontier/soes2shell/evidence/replay-soes2shell-20261122/cve129798/INDEX.txt`;
  raw output is untracked (no ignore rule matches). No witness replay existed at admission; W105 later replayed this limb — see the W105 bullet above.
- **Soes2Shell adjacent CVE-2026-129814 one-byte mailbox terminator
  write** (commit `c637b38`, `reports/frontier-soes.md`): the same
  `bash lab/frontier/soes2shell/harness/build.sh` builds
  `coe_terminator_{3.2.0,3.2.1}` and `coe_terminator_asan_{3.2.0,3.2.1}`
  from `harness/coe_terminator_overflow.c`, driving real `ESC_coeprocess()` →
  `SDO_getod()` with one SDO Information Get Object Description mailbox and
  `ESC_claimbuffer()` returning the last of three slots. Expect plain 3.2.0
  `byte_at_MBX_end=41` (the OD name's `A`) and response length 122; ASan
  3.2.0 exits 1 with `global-buffer-overflow WRITE of size 1` at
  `esc_coe.c:1347` via `ESC_coeprocess :1524`, 0 bytes after the 384-byte
  `MBX[]` global; real pinned 3.2.1 and the 10-byte `safe` name are clean
  (`byte_at_MBX_end=00`, lengths 121 / 22, no ASan report). The byte is the
  next application-OD name byte, not master wire input; the long OD name and
  in-process mailbox are modeled, so rung 3 on the real handler, rung 4
  harness-level, wire reach UNKNOWN. Eight runs with exit codes, checksums
  and the repaired `__SANITIZE_ADDRESS__` harness negative are indexed in
  `lab/frontier/soes2shell/evidence/replay-soes2shell-20261122/cve129814/INDEX.txt`;
  raw output is untracked (no ignore rule matches). No witness replay existed at admission; W105 later replayed this limb — see the W105 bullet above.
- **Soes2Shell adjacent CVE-2026-129803 undersized SDO frame** (commit `e9a5220`,
  `reports/frontier-soes.md`): `bash lab/frontier/soes2shell/harness/build.sh`
  also builds `coe_shortframe_{3.2.0,3.2.1}` and ASan variants from
  `harness/coe_shortframe_overflow.c` against both pinned trees. Expect plain
  3.2.0 `short-write`: 56 `0xe7` bytes past a standalone 8-byte object, with
  `write_canary[0]` and `[55]` both `e7`; ASan `global-buffer-overflow WRITE of
  size 64` at `copy2mbx esc_coe.c:248` via `SDO_download :864` ←
  `ESC_coeprocess :1501`, 0 bytes after `g_oct_alone[8]`. `short-read` is an
  in-bounds read of that object (`[0]`/`[8]`/`[63]` all `e7`); `short-safe`
  (declared 8, body 22) leaves canaries clean; fixed 3.2.1 rejects
  `length < COE_HEADERSIZE` at `:854-858` before any copy, plain and ASan
  clean. Twelve runs, exit codes and checksums are in
  `lab/frontier/soes2shell/evidence/replay-soes2shell-20261122/cve129803/INDEX.txt`
  with `sha256sum -c SHA256SUMS` 3/3 OK; the INDEX and its 12 raw `.txt` files
  are committed in-tree here, not gitignored. Rung 3 on the real handler, rung
  4 harness-level, wire reach UNKNOWN, later replayed by W105 (#1281) ESTABLISHED at that scope.
- **Four 06:3x–06:5xZ grade-neutral edges** (commits `cc5e018`, `ee020ad`,
  `540b339`, `08b13df`): Pgpool W2 (`../reports/pgpool2shell-o2-w2.md`)
  rebuilds pinned 4.7.2 at `-g -O2 -fno-omit-frame-pointer` with
  `bash lab/pgpool2shell/wire/build-o2.sh` then `run-o2.sh`; expect SIGSEGV
  only at `NodeCount=2`, and `node_id_set[1] =
  0x55555562d742 <read_packet_of_type+402>` under `gdb-o2-run.sh`, unchanged
  by `gdb-o2-warm.sh`. Pgpool W3 (`../reports/pgpool2shell-n3-w3.md`) sends
  `NodeCount=3` and faults at `i=1` before `i=2` (`w3-n3-{peer.out,
  gdb-trace.out}`), refuting multi-slot steering. The regenerated
  `evidence-o2-*` files were overwritten by a witness port collision on
  19003–19005 and are deliberately uncommitted: use the hashes quoted in the
  W2 report from the clean 05:50Z run, not the on-disk bytes. Soes advisory
  write-set closure re-reads the primary CSAF (`../reports/frontier-soes.md`):
  six write-capable limbs (129794/129796/129798/129803/129811/129814) are
  exactly those already harnessed; 15 read/NULL/length CVEs remain, the
  `esc_eoe.c:812-817` timestamp underflow has no SOES-side write and its
  consumer is unbuildable here, so no new harness. uD3TN/BACnet admission
  completion (`../reports/ud3tn2shell-status.md`,
  `../reports/bacnet2shell-status.md`) only completes `docs/task.md`; their
  recipes are already in the rows above.
- **Vrpn2Shell W3 negative wire index** (commit `42101a4`,
  `reports/vrpn2shell.md`): `bash lab/frontier/vrpn2shell/probe-frame-write.sh
  <out> <port> -8` (ports 13914 plain / 13915 ASan) sends a 24-byte-header
  `SENDER_DESCRIPTION` with index -8. Expect ASan `stack-buffer-overflow WRITE
  of size 1` at `vrpn_Connection.C:4554` with the access in the left redzone
  (`shadow [f2] poisoned`), and plain `PRE endpoint=0x5555556f3220 byte 0x20`
  → `POST endpoint=0x5555556f3200 byte 0x00`, `saved_rip` unchanged, then
  SIGSEGV in `vrpn_TypeDispatcher::getSenderID:1131` through the corrupted
  endpoint. Fixed plain/ASan at index -8 clamp to `sender_name[99]` and are
  clean; index -48 hits an already-zero byte (no-op) and index -64 in ASan hits
  `p.msg_time` with no report. Raw `out-w3-*` gdb logs are in-tree; regenerate
  with the committed probe on fresh ports. The precise released fixed version
  is UNKNOWN from the fetched commits; witness replay of W1/W2 (#1261) is
  pending and W3 is author-only.
- **Wazuh2Shell live `wazuh-analysisd` crash** (commit `8705ecc`,
  `reports/wazuh2shell-live-crash.md`): build pinned v4.14.7 and v4.14.8
  `wazuh-analysisd` with `make -C src -j2 TARGET=server wazuh-analysisd` (ASan
  variant `CFLAGS=-fsanitize=address -fno-omit-frame-pointer -g -O0
  LDFLAGS=-fsanitize=address`), then run the gitignored
  `lab/frontier/wazuh2shell/live-src/live-replay.sh exploit|control`, which
  starts a lab daemon on the local queue and sends one AF_UNIX `8:syscheck:`
  datagram from `inject.py`. Expect the v4.14.7 ASan daemon to abort with
  `heap-buffer-overflow WRITE of size 506`, 0 bytes after a 459-byte region,
  frames `fim_generate_alert syscheck.c:1680` ← `fim_process_alert:1436` ←
  `decode_fim_event:1288` ← `w_decode_syscheck_thread analysisd.c:1586`,
  allocation `OS_CleanMSG cleanevent.c:62`; the 406-byte full-`old_attributes`
  control and v4.14.8 ASan daemon stay alive with zero reports, and v4.14.7
  plain is not reliably faulting. This is a lab-only runtime adaptation (no
  1514 session or enrolled agent), a deterministic availability fault and
  rung 3 in the live process; no heap-neighbour readback, pointer or command,
  no witness replay, rung 5 UNKNOWN. The live driver lives in gitignored
  `live-src/` with no tracked generator; the tracked recipes are `bash run.sh
  out-direct` (direct harness) and `bash trace-wire.sh` (source trace).
- **ProFTPD2Shell request-time call-path closure** (commits `67883ca`,
  `eee4811`, `reports/frontier-proftpd.md`): `nm -n -S proftpd-vuln-plain` plus
  source reads on the pinned plain 1.3.9d build show the reachable BSS window
  `utf8_val.1 0x106920/0x400 → substr.2 0x106d20/8 → … → members
  0x1072c0/0x8008` with no function pointer on a request path; the sole
  indirect call through it is `m->sess_init()` in `modules_session_init()`
  (`src/modules.c:124-148`, call site `src/main.c:1522`), before the rewrite
  fixup and before the per-session fork at `src/main.c:1198`. No code-pointer
  leak or request-time call target exists on this build; this is a boundary
  determination for pinned plain 1.3.9d only, not a general RCE refutation.
  Overall rungs 1–4 remain witness-ESTABLISHED (W99/W100); rung 5 unclaimed.
- **ProFTPD2Shell data-sink and first-loop closure** (commit `f6d0654`,
  `reports/frontier-proftpd.md`): source-only reading of the pinned plain
  1.3.9d tree, no new runner or wire traffic. `set_rewritemap()`
  (`contrib/mod_rewrite.c:2481-2569`) permits only `int`, `fifo` and `txt`
  maps; `rewrite_subst_maps_fifo():1441-1444` writes the key to an
  admin-configured FIFO with no reader in the tree, and
  `rewrite_parse_rule_flags():488-520` allows only `nocase|NC` and `last|L`,
  so no rule sets a module environment variable. The tree's `execve` sites
  (`mod_exec.c:626,629`, TLS/SFTP passphrase providers) take config-driven
  paths, not rewrite results. The first loop's 8-byte UCS-4 words
  (`mod_rewrite.c:1665-1703`) end at `0x108920` inside the already-enumerated
  `members` array; `grpfields` at `0x10f2e0` needs ~8700 code points and is
  not demonstrated. Boundary determination only: rung 5 CLOSED on this build,
  rungs 1–4 verdicts unchanged.

- **Frontier staging of ntpsec2shell (commits `f035109`, `8aa2904`, W121; FRONTIER-STAGED, not admitted)**: brief `reports/frontier-ntpsec2shell.md`. CVE-2026-121506 (GitLab CNA 2026-11-03, CWE-787, CVSS 3.1 7.4 `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H`), affected 1.1.4 up to (excluding) 1.2.5, fixed 1.2.5; vulnerable tag `NTPsec_1_2_4` = `a9e66af44c0be47e8e32a972b3f3fb7cea65f808`, fixed `NTPsec_1_2_5` = `42b5703303c8c7e6513f3a119cfab670924dd7be`, fix `0a36941e499d533dfbc3fb6b1fcd8c367679d719` (8 insertions / 4 deletions). Seven pinned blobs and the fix patch are SHA-256 in `lab/frontier/ntpsec2shell/PIN_HASHES.txt`; claim URLs in `PROVENANCE.md`. The victim is an **NTS client ntpd receiving server-mode replies**, not an NTP server. Duplicate check found no prior ntp target, window, charter or mind; adjacent PHP-CGI CVE-2026-129538 was rejected as `php2shell`-owned. `harness/gen.py` extracts `extens_client_recv()` byte-for-byte from the pinned `nts_extens-{vuln,fixed}.c` plus two buffer helpers from pinned `nts-vuln.c`; `harness/run.sh` builds gcc `-O0 -g` ASan/plain variants and links pinned 1.2.4 `libaes_siv/aes_siv.c` against OpenSSL 3.0.13, opening no sockets. `cd lab/frontier/ntpsec2shell && bash harness/run.sh` expects 8 PASS / 0 FAIL: ASan `WRITE of size 40`, 8 bytes past a 128-byte region, frames `AES_SIV_Decrypt` (modeled) ← `extens_client_recv` ← `stub_case` with declared `noncelen=64` (fixed rejects before the consumer, `WRITE_OFF=-1`); plain readback of 16 chosen `41…`/`5a…` at offset 136, and the real pinned decryptor writing `4142434445464748494a4b4c4d4e4f50` at offset 328 with a lab-chosen key. Normalized PASS hash `1f04e12d…` in `EVIDENCE_HASHES.txt` over two in-tree replays and a clean `git archive f035109`; raw per-case output in `evidence/` regenerates from the pins and `run.sh`. Rung 3 plus scoped rung 4 only: no ntpd process, NTP wire, NTS-KE handshake, disclosed key, pointer control, marker or command; the advisory's auth-bypass/time-setting chain stays a claim.
- **Pppd2Shell W125 reachable notifier pointers, failed rung-5 attempt (commit `ef19d07`, `lab/frontier/pppd2shell/live/chosen2/README.md`)**: extension of W123 at unchanged rung 4. `nm -n -S` on the plain 2.5.3 build locates the notifier heads at `pidchange +1832`, `phasechange +1840`, `exitnotify +1848`, `sigreceived +1856` inside the ~1875-byte NAK amplification of the fixed `inpacket_buf[PPP_MRU+PPP_HDRLEN]`; only `fork_notifier +1864` and the `+1952..` hooks are out of reach. `PUTLONG` writes big-endian, so a chosen little-endian pointer must be byte-swapped in the request CI with the `escape NN` forced bit cleared — `escape 00` produced a reversed pointer, `escape 09` works. Start the locally built plain 2.5.3 daemon on a PTY as in W122 and run `live/chosen_write.py` at the target offsets; under `sudo -n gdb -p`, readback shows `phasechange = exitnotify = sigreceived = 0x0000000041424242`, `pidchange` low half only (PIE heap pointer high half), `fork_notifier` zero; safe offset 1500 leaves all pointers at their normal values. The same frame gives ASan `global-buffer-overflow WRITE of size 1` 0 bytes past `nak_buffer[1500]` at `lcp_reqci lcp.c:1608` on 2.5.3 and is clean with duplicate-option rejection on 2.5.4. Seven normalized cases and SHA-256 in `live/chosen2/evidence/HASHES.txt`, byte-identical over two `normalize_chosen2.py` runs; raw logs stay in the gitignored `live/raw/`. The two-frame `live/rce_attempt.py` on a `-no-pie` build tried a forged `struct notifier` with `func=execl@plt`, `arg="/bin/sh"` reached via a rejected ConfReq body and SIGTERM → `new_phase(PHASE_DEAD)` → `notify(phasechange,0)`; in three replays pppd logged `Connection terminated.` then `Fatal signal 11` because `link_terminated()` (`auth.c:717-768`) dereferences the corrupted `the_channel` before the phase transition. No hook call, shell, command or file side effect; rung 5 remains unclaimed and the cases are author-only.
- **Tacplus2Shell W121 live-daemon chosen-byte readback (commit `5833ad2`, W121)**: closes the owed plain-build + gdb experiment from the admission bullet. Both pins were rebuilt without ASan from the same committed blobs into gitignored trees: `cd src-plain && ./configure --debug --minimum tac_plus-ng mavis && make -j4` (vulnerable `929671c22ff9…`) and the same in `src-fixed-plain` (fixed `d8493e0d6420…`), `clang -O0 -g -ggdb -DDEBUG`, no `-fsanitize` in `build-plain.log` / `build-fixed-plain.log`. `harness/run_gdb_case.py` launches each binary under gdb 15.1 with a plant-created 127.0.0.1 listener as fd 0 (`ptrace_scope=1` requires gdb to be the parent); `harness/gdb-author.cmd` breaks at `author.c:72`, `:75` (only for `a - base >= 64`), `:77`, `:78`. `cd lab/frontier/tacplus2shell && bash harness/run_gdb.sh` expects 8 PASS / 0 FAIL: vulnerable crafted AUTHOR (body 92, `arg_cnt=20`, table `8` + 19×`8`, eight `cmd=AAAA`…`cmd=HHHH` records) reaches `eval_args()` and the final `cmdline` string is the chosen `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH`, with 12 past-payload reads at `off=64..160`; fixed pin never enters `eval_args()` and replies 57 bytes; vulnerable safe packet (`arg_cnt=1`, `cmd=`) enters once with no OOB read and an 18-byte reply. Normalized hashes `2072846c…` / `de41ed2a…` / `da7623bf…` in `harness/gdb-r1.txt` and `gdb-r2.txt`, byte-identical over two runs. Two grooming attempts were negative: `cmd=ZZZZ` in the username field landed ~6 KB before the packet buffer, and a 255-record priming packet left the trigger buffer in a different heap region with no marker. Grade: rung 4 chosen bytes at chosen offsets now holds at **live-daemon scope** with fixed and safe controls, not only the verbatim harness; the bytes come from the crafted packet's own payload, with no out-of-payload heap byte, pointer, function pointer, marker or command. Rung 5 and the advisory's five-connection `system()`/root chain remain UNKNOWN / claim text. Raw `harness/gdb-*.log` and `gdb-*.stdout` are gitignored and regenerate with `run_gdb.sh`.
- **Frontier staging of uhttpd2shell (commits `d6afa99`, `2bd8363`, W122; FRONTIER-STAGED, not admitted)**: brief `reports/frontier-uhttpd2shell.md`. GHSA-2mpg-6wp5-435p (GitHub CNA 2026-08-03, High 7.5 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`), affected through `f682ccabee9ed5f39dd3b0aaf96228975eeb478d` (shipped `7b1bec45` byte-identical), fixed `e76736e5676fb25536b27d45865eb4153c68aca3`; libubox `a396f38a8568a1d670c240465cd8d24fdfdf6463`. Seven blobs SHA-256 in `lab/frontier/uhttpd2shell/harness/pins/PIN_HASHES.txt`; claim URLs in `harness/PROVENANCE.md`. Duplicate check found no prior uhttpd report, window, charter or mind and no entry in frontier's do-not-duplicate list; the four other published uhttpd advisories are in `client.c` framing. A scalar `"params":1` in an unauthenticated `POST /ubus/call/...` is copied by `blob_memdup()` and reinterpreted as a container by the verbatim pinned `uh_ubus_send_request()`: `blobmsg_name(cur)` reads 2 bytes past the 20-byte allocation (ASan `READ of size 1` in `strcmp`) and `blobmsg_data_len(cur)` underflows to `0xFFFFFFFD`, truncated to `4294967293` in `blobmsg_add_field()`'s `memcpy`. REAL mode stops at the read; the ~4 GiB write is never executed locally (no recover-mode run, to stay inside the lab memory guard). MODEL mode replaces only the final sink: `WRITE_OFF=20`, `WRITE_LEN=4294967293`, 16 chosen `41…`/`5a…` bytes, ASan `WRITE of size 16` into `malloc(8)`; fixed pin rejects with `ERROR=3 INVOKED=0`, well-formed TABLE `params` writes only 4 bytes. `cd lab/frontier/uhttpd2shell && bash harness/run.sh` gave 30 PASS / 0 FAIL twice; Docs replayed it from `git archive HEAD` and observed rc 0, the same 30 PASS and byte-identical `round2-pass.txt` (`c3b2b9d1…`). Raw per-case logs are gitignored and regenerate with `run.sh`; tracked `round2-*` and `raw-r2-*` files are the canonical normalized/raw copies. Rung 3 plus rung 4 at modeled-sink scope only: no live uhttpd, HTTP wire, rpcd, ACL-chain replay, heap grooming, pointer control, marker, command or rung 5; the advisory itself scores DoS only.
- **KnotResolver2Shell ASLR-on partial-overwrite negative (commits `67cdb83`, `85dc641`, `f820688`, evidence committed in `9b5c988`)**: `reports/knotresolver2shell-rung3.md` adds a wake-14 inventory on the pinned 6.4.0 jemalloc/debug build with `set disable-randomization off` on the gdb inferior (host sysctl untouched, loopback only). Final sample: `buf=0x7c25a48a8800`, `slot1=0x7c25a48aa000`, extension priv `0x7c25a488cf00`; libc text `0x7c25a5428000`–`0x7c25a55b1000`, libgnutls text `0x7c25a5b1f000`–`0x7c25a5c59000`. Scanning 128 qwords at `slot1` (the full 814-byte OOB span) and 128 at `priv` found no libc-text pointer, no pointer into `slot1`'s 64 KiB region and only three `slot1+0x100/0x108/0x110` pointers into `priv`'s region, all before the writable span. An earlier sample has a libgnutls call target at `priv+0x110` and a heap RDI source at `priv+0xb8`, again outside the landing region. Both layouts refute low-byte retargeting to `system` or the command string; a three-byte patch crosses independently randomized bases. Bounded negative for these object sets, not a universal claim; R5 stays ◐ at the labeled ASLR-off scope and ASLR-on/stock UNKNOWN. The cited `harness/aslr-pointer-inventory.gdb`, `harness/run_aslr_inventory.sh`, `harness/aslr-inventory.gdb.log` and the alongside `harness/aslr-inventory.driver.log` are tracked in `9b5c988` under `lab/frontier/knotresolver2shell/harness/`; a fresh checkout can regenerate the inventory as cited.

- **KnotResolver2Shell libgnutls PLT-retarget negative (commit `91a5bd6`,
  `reports/knotresolver2shell-rung3.md`)**: on the exact mapped
  `/usr/lib/x86_64-linux-gnu/libgnutls.so.30.37.1` (SHA-256
  `ddbae2995750875c07bc218d12a062d73f8250678f54dedda7e9be5068781c98`,
  dpkg `libgnutls30t64 3.8.3-1.1ubuntu3.6`, confirmed in
  `harness/aslr-inventory.gdb.log`), `readelf --dyn-syms -W LIB | grep ' UND ' |
  grep -E '(system|popen|exec[lvpe]*|posix_spawn|dlopen)'` returns no matches,
  and `objdump -d LIB | grep p11_kit_module_load@plt` finds `0x34da0`, but wake
  14 found no live libgnutls pointer in the 128 qwords at `slot1` or `priv` to
  patch to it, so the staged-`.so` route has no reachable pointer on this
  geometry. Static, deterministic negative for this library and sampled
  layout; no grade change, ASLR-on/stock chosen control stays UNKNOWN.
- **Frontier staging of minisnmpd2shell (commit `02bb46a`, W132; FRONTIER-STAGED, no route at 02:2xZ)**: brief `reports/frontier-minisnmpd2shell.md`. CVE-2026-59961 / GHSA-c9g2-5ghh-8g8c (CNA GitHub_M; CVE published 2026-11-18, GHSA displays 2026-07-10; HIGH 8.2 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H`, CWE-125 via `size_t` underflow), affected `< 1.7`, fixed commit `5419bc38` and release `6894e33e`; five blob/patch hashes in `lab/frontier/mini-snmpd/PROVENANCE.md` and `src/SHA256SUMS`. In the pinned vulnerable `protocol.c` the decode helpers guard with `*pos >= (size - len + 1)` without `len > size`, so a declared BER length above the 2048-byte datagram wraps the bound; the fix adds `len > size ||` and widens `decode_ptr`'s `int len`. `cd lab/frontier/mini-snmpd && bash harness/run.sh` re-extracts the verbatim `decode_oid`/`decode_str` slices on every run and asserts the pins; expect `PASS=43 FAIL=0` with normalized trace SHA-256 `0146b9b5…9859` from three working-tree runs plus a clean `/tmp` replay. gcc and clang ASan report `heap-buffer-overflow READ of size 1` 0 bytes after a 2048-byte region in `decode_oid`; fixed and in-bounds safe inputs are clean. Rung 4 is scoped: the declared length chooses the read extent and 0x5a/0x3c canary bytes at offset 2048 read back byte-exact in the direct-call plain workspace (`POS_AFTER=4007`, fixed `RC=-1`). `bash wire/run_wire.sh` starts a plant-owned ASan daemon on 127.0.0.1:16161 and sends one 2048-byte SNMP GET declaring OID length 0xffff: vulnerable logs `overflow for OID byte`, fixed rejects with `underflow for oid` via `run_fixed_wire.sh` on 16162, and a 35-byte in-bounds GET is clean on both. No wire-level ASan report — `client->packet` sits inside a larger global struct and a 20-subid cap stops the walk — so the daemon observation is rung-2 reachability only, and pre-auth parsing order is advisory text. No pointer, marker, command or rung 5; charter and two-pane window are prepared but no route or admission record exists at 02:2xZ, so the target stays staged and is not in the mind list.


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
- **Ruby2Shell forged-`T_DATA` HTTP command, witness-ESTABLISHED (candidate `8b9d8f97f0ec1237fe1fb2bc30339d1a32db1341`)**: provision both pinned tarballs with `bash lab/ruby2shell/provision.sh`; build plain 3.4.12 and 3.4.13 using `./configure --disable-install-doc --prefix=<repo>/lab/build/plain/ruby-3.4.{12,13}-plain`, `make -j2 && make install` (the fixed tree is extracted from `ruby-3.4.13.tar.xz`; gcc 13.3.0/default flags, no ASLR disablement). Build the tracer with `gcc -shared -fPIC -O2 lab/preload/mtrace.c -o lab/preload/mtrace.so`. Run `bash lab/repro/ruby2shell-rung5-http.sh attack <tag>` with at least two distinct tags, then `control <tag>` and `fixed <tag>`. Each attack must return HTTP 200 + `rce=OBSERVED`, create its distinct `lab/build/evidence/rung5-http-<tag>.marker`, and show an mtrace `3e9` allocation at the logged VWA target; controls return HTTP 200 + `rce=ABSENT`, no marker and zero target pops, and the driver returns nonzero on any missing condition. The command is the request's `/usr/bin/touch <unique marker>`; the forged untyped `RData` routes GC `dfree(data)` to host libc `system` (offset `0x58750` on glibc 2.39-0ubuntu8.12). Custom groom/GC middleware, `ObjectSpace.dump`, `/proc/self/maps` and mtrace are required; ASLR stays enabled, post-response abort is possible, stock-app oracle-free RCE is UNKNOWN. Independent clean-archive replay ran `witness-alpha`, `witness-beta`, `witness-control`, `witness-fixed`: 2/2 distinct markers + exactly one independently scanned target pop each, controls 2/2 marker/pop absent, ESTABLISHED with no code repair. Evidence index `lab/build/evidence/w-ruby-r5/tree/lab/build/evidence/witness-verification.json`; optional syscall attribution uses `strace -f -e trace=execve -o <log> bash lab/repro/ruby2shell-rung5-http.sh attack <tag>` and records `/bin/sh -c -- /usr/bin/touch …` plus `/usr/bin/touch` exit 0.
- **Ruby2Shell stock/oracle-free/persistence follow-up — bounded NEGATIVE (2026-11-22)**: run `RUBY2SHELL_STOCK_N=556 bash lab/repro/ruby2shell-stock-baseline.sh attack stock-n556-attack` against plain 3.4.12, then the same with `control` and with `fixed` (default fixed binary `lab/build/plain/ruby-3.4.13-plain/bin/ruby`). The app has no routes or custom middleware and the driver uses no preload/ObjectSpace/maps/debugger. Attack POST + later GET completed in only 2/3 fresh runs, with `corrupted size vs. prev_size` on SIGTERM teardown; 1/3 aborted pre-response with `malloc(): mismatching next->prev_size (unsorted)`. N=828 aborts 3/3 pre-response with `malloc(): invalid next size (unsorted)`. Safe/fixed N=556 controls return both 404s and terminate normally. `RUBY2SHELL_STOCK_TRACE=1` enables analysis-only mtrace; `stock-size.gdb`, `stock-first.gdb`, `stock-second.gdb`, `stock-after.gdb` reproduce the untouched/corrupted header inspections with ASLR enabled. N=556 is fastbin (second qword != tcache_key), not an overlap; unsorted/filler/primer sweeps found no stable valid expansion or address disclosure. No stock RCE/persistence grade change; Rails remains UNKNOWN. Full matrix and caveats in `reports/ruby2shell-investigation.md`.
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
- **KnotResolver2Shell rung 4 witness-ESTABLISHED (commits `df274fa`, `2a3ca7f`, verdict #1138)**: `reports/knotresolver2shell-rung3.md` records the stalled-Initial groom and `harness/run_gnutls_sweep.sh` / `harness/ksl_stalled.py` placing an 8-byte marker at a chosen `slot1` offset of the live gnutls session; `harness/gnutls-sweep.txt` shows no stop at `+0x10/0x18/0xd8/0x178`, a NULL deref at `+0xf8`, and `rsi=0x4141414141414141` at `+0x100`/`+0x110` in `gnutls_deinit()` from `quic_conn.c:884`. `harness/gnutls-control-0x100.log` varies the value to `0x4242424242424242` at the same site. Conditions: pinned 6.4.0, jemalloc, debug build, gdb ASLR-off for the inferior (host sysctl untouched), loopback only; chosen argument value, not RIP, marker execution or a command. Independent replay #1138 (20:52–20:56Z) matched HEAD harness digests (`85ffce02…`/`30ab19a3…`/`5ea6b3a5…`), 3/3 pins and byte-identical pinned `quic_conn.c`; its own sweep reproduced `rsi=0x4141414141414141` at `+0x100`/`+0x110`, and a marker-only change to `0x5a5a5a5a5a5a5a5a` reproduced the same offsets/RIP with the different RSI. The fault instruction `movzwl (%rsi),%eax` is a real 2-byte read of the chosen address. Rung 4 ESTABLISHED at these labeled conditions; rung 3 stays ESTABLISHED and #1138 made no R5 claim — rung 5 was UNKNOWN at wake 6, and the next bullet records a later author-observed R5 limb with witness W114's MIXED verdict. |
- **KnotResolver2Shell chosen-RIP benign-command replay, author-only, witness W114 MIXED (commits `f4f63d0`, `c3c4c62`)**: on the pinned 6.4.0 jemalloc/debug build on 127.0.0.1:8855, `harness/r5_dispatch.py` writes the fake gnutls cleanup struct into the OOB span (`+0x100 = slot1+0x20`, `+0xb8 = command address`, `+0x110 = call target`, `+0x174=1`, `+0x2d8=0`) and requires `cfg.max_datagram_size = 1500` so F6 stays one frame. `harness/r5-trace.gdb` verifies `extptrs[0]=0x7ffff68aa020`, chosen `+0xb8` and `0x4242424242424242` at `+0x110`; `harness/r5-syms.gdb` measures `system=0x7ffff7458750` from this host's libc layout. Expect SIGSEGV at the `call *0x110` in libgnutls `0x7350c` for a non-canonical target and `rip=0x12345678` for a canonical unmapped one; with `system` at `+0x110`, the author reports two distinct benign `touch` commands creating two distinct marker files with separate vfork detaches and marker-absent safe-input/fixed-6.4.1 controls. Replay logs `r5-{system-vuln,rip-canon,f6-bytes,syms,safe,second,fixed}*.{gdb,driver,kresd}.log` are tracked under `lab/frontier/knotresolver2shell/harness/`; gdb disabled ASLR for the inferior only (host sysctl stayed 2), no breakpoints or forced calls in the execution runs, no wire-derived address leak. Independent replay W114 (10:14Z chat tape) rebuilt both pinned trees (3/3 pins, byte-identical `quic_conn.c`): chosen RIP/chosen argument is ESTABLISHED, and two distinct commands execute with vfork detach and clean controls **only at `argoff 0x300`**; at the committed/default `argoff 0x2f0` the command limb failed twice because `gnutls_deinit` zeroed the string before dispatch (`system` got an empty string). Author clarification was requested in #1376; do not record command execution as witness-ESTABLISHED verbatim until reconciled. R5 cell stays ◐; ASLR-on/stock UNKNOWN. |
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

## Admitted frontier lanes — 2026-11-22 21:2xZ

Three targets admitted under standing #6 from frontier staging. Each harness
copies the vulnerable function verbatim from a pinned blob, builds vulnerable
and fixed pins with ASan and plain, and reserves clean-archive replay evidence.
All three are code/harness scope: no live process, wire or command side effect
is claimed, and the grade is unchanged by admission.

- **Ntpsec2Shell** (CVE-2026-121506): `bash
  lab/frontier/ntpsec2shell/harness/run.sh` — 8 PASS / 0 FAIL twice, normalized
  SHA-256 `1f04e12d2a9332d2cf9f0161c1a9155f40d8d6936b13b295934113ad7e164106`,
  with a clean `git archive f035109` replay. `harness/gen.py` extracts
  `extens_client_recv()` byte-for-byte from the pinned blob; the fixed pin
  rejects before the modeled AES-SIV consumer. Pins and claim URLs in
  `lab/frontier/ntpsec2shell/PIN_HASHES.txt` and `PROVENANCE.md`.
- **Uhttpd2Shell** (GHSA-2mpg-6wp5-435p): `cd lab/frontier/uhttpd2shell &&
  bash harness/run.sh` — 30 PASS / 0 FAIL twice (gcc 13.3.0 and clang 18.1.3),
  `round2-pass.txt` SHA-256 `c3b2b9d19d6950090c4efdbc2b5e483881f1d23b297beea41343c6dc5622fc66`,
  with a clean `git archive d6afa99` replay. The verbatim pinned
  `uh_ubus_send_request()` runs over pinned libubox blobs; REAL mode stops at
  the OOB read and MODEL mode observes the truncated length at an instrumented
  sink. Pins in `harness/pins/PIN_HASHES.txt`, provenance in
  `harness/PROVENANCE.md`.
- **Libvnc2Shell** (GHSA-v9pm-47h4-jcq8 / CVE-2026-50538): `bash
  lab/frontier/libvnc2shell/harness/run.sh` — 20 PASS / 0 FAIL twice with
  byte-identical normalized hashes, plus a clean `git archive 0d4103f` replay.
  `harness/gen_fn.py` extracts 275 verbatim lines from the vulnerable pinned
  `tight.c` and 285 from the fixed one (the extra 10 are the clamp);
  real zlib is used with no socket, client or server. Hashes in
  `src/PIN_HASHES.txt`, `harness/PROVENANCE.md` and
  `lab/frontier/libvnc2shell/EVIDENCE_HASHES.txt`.

- **Witness W126 verdicts and tacplus W122 grooming negative (21:2xZ, tape
  #1706/#1708)**: from a clean `git archive HEAD` at `0d4103f`, W126 replayed
  libvnc twice (20 PASS / 0 FAIL, all nine normalized logs and
  `lab/frontier/libvnc2shell/EVIDENCE_HASHES.txt` byte-identical), uhttpd
  (30 PASS / 0 FAIL,
  `round2-pass.txt` `c3b2b9d1…`, chosen hashes `8966ae93…`) and ntpsec
  (8 PASS / 0 FAIL, run-final `1f04e12d…`), grading each ESTABLISHED at its
  labeled code/harness scope: no wire, live process, pointer, marker or
  command. The chosen-byte sweep on libvnc's own plain build varied the base
  (`0x41` → `4142…4f50`, `0x5a` → `5a5b…6869`), so the adjacent bytes track
  input rather than incidental state.
- **Tacplus2Shell W122 heap-grooming NEGATIVE (commits `568bf7a`/`b404533`,
  reconciled in `8d5af1b`)**: `reports/tacplus2shell-status.md` W122 checks
  the pinned consumer in source — `mem_destroy()` (`misc/memops.c:239-253`)
  really calls `m->arr[i].f(m->arr[i].p)` and `cleanup_session()`
  (`packet.c:1326`) reaches it — then records four plain vulnerable
  live-daemon configurations under gdb that never place chosen `cmd=ZZZZ`
  bytes behind the trigger buffer (tcache off on separate connections, `find`
  showing the prime intact but unreused, two AUTHOR packets on one connection
  where the prime's reply deletes the session, and an AUTHEN START prime with
  the AUTHOR trigger on seq 3). The GHSA's own large-then-small packet premise
  is negative result 1 on this glibc/build; no public PoC link or exact
  five-connection shape exists, so `uid=0(root)` stays claim text. New tracked
  tooling: `harness/{gdb-groom.cmd,wire2.py,wire3.py,run_gdb2.py}`; raw logs
  stay local. Smoke replay `bash
  lab/frontier/tacplus2shell/harness/run_gdb.sh` gives 8 PASS / 0 FAIL with
  normalized hashes `2072846c…`/`de41ed2a…`/`da7623bf…` unchanged from W121.
  Grade unchanged: rung 4 at live-daemon chosen-offset scope, rung 5 UNKNOWN.
  Witness W126 (#1708) rebuilt both plain binaries itself and ESTABLISHED the
  W121 readback at that scope; it did not replay the W122 grooming negatives.

## Admitted frontier lane — 2026-11-22 21:3xZ libyang2shell

- **Libyang2Shell** (GHSA-vw2p-pq79-92xh / CVE-2026-44673): `bash
  lab/frontier/libyang2shell/harness/run.sh` — operator replay 42 PASS / 0
  FAIL, `rc=0`; two rounds with byte-identical normalized hash
  `edf0399fb7c5e5aef309e460d60286394a324d149cf600305c9f6bfffdda51f2`.
  `harness/gen_fn.py` extracts `lyb_read`, `lyb_read_size`,
  `lyb_read_string` and `ly_in_read` verbatim from three pinned blobs;
  `harness/verify_verbatim.py` checks the slices, and `harness/harness.c`
  supplies only types, log macros, scripted input and a bounded memcpy sink
  so the 536 MB copy is never executed. The vulnerable pin (`979f6925`) under
  gcc and clang ASan reports `WRITE of size 1` 0 bytes after a 1-byte region;
  the plain build reads back 16 chosen `0x41`/`0x5a` bytes at offset 0 of the
  0-byte allocation and the terminator at offset 4294967295. Partial pin
  `73da1db8` widens the arithmetic but still requests 4 GiB; hardened pin
  `48672b28` rejects `UINT32_MAX` before allocation; the 8-byte safe string
  is clean on both compilers. Pins, digests and claim URLs in
  `lab/frontier/libyang2shell/harness/PROVENANCE.md`; raw logs in
  `harness/evidence/`. Grade is rung 3 plus scoped rung 4 at direct-call/stub
  scope: no libyang build, real `lyd_parse_data()` call, crafted LYB framing,
  consumer, wire, pointer control, marker or command.
  A clean `git archive 53af313` replay (frontier commit `255abfd`) also gave
  42 PASS / 0 FAIL with byte-identical `r1-normalized.txt` and
  `r1-pin-hashes.txt`, needing no clone or network. Witness #1829 returned
  ESTABLISHED AS CLAIMED at the labeled rung-3 / real-parser rung-4 scope,
  with no nit and no further replay owed.
  That direct-call/stub ceiling was lifted at 22:0xZ: W1 built both pins and
  reached `lyb_read_string` through real `lyd_parse_data_mem(..., LYD_LYB, ...)`
  on a valid LYB blob with one four-byte length patched; see the admitted-lane
  limb below.

## Admitted frontier lane — 2026-11-22 22:0xZ msgpack2shell (staged 21:5xZ)

- **Msgpack2Shell** (GHSA-8pq6-mw7r-9f5g / CVE-2026-130065; admitted 22:0xZ as the 89th route):
  `bash lab/frontier/msgpack2shell/harness/run.sh` extracts the verbatim
  `msgpack_vrefbuffer_migrate()` from three pinned `vrefbuffer.c` blobs with
  `gen_fn.py` (checked by `verify_verbatim.py`), builds each with gcc 13.3 and
  clang 18.1 under ASan, plain and safe modes, and writes normalized evidence
  plus `evidence/{r1,r2}-normalized.sha`. Expect **177 PASS / 0 FAIL**, rc 0,
  with two rounds byte-identical at normalized hash
  `cbc13d219f85df289efd33aaab66b945cf29ba0d45576bd5ce96e750c9567538`.
  Vulnerable pins (shipped C 7.0.2 `c-7.0.2` and fix parent `8a34070b`, whose
  `migrate()` bodies are byte-identical) give ASan `heap-buffer-overflow WRITE
  of size 320`, 0 bytes after a 128-byte destination, with 12 chosen iovecs
  past capacity: `OOB_FIRST_BASE=4141414141414141`,
  `OOB_FIRST_LEN=5a5a5a5a5a5a5a5a`, and an intact tail sentinel. Fixed pin
  `1c47ce0` (one-line free-slot count) grows the array to 32 slots with
  `OOB_PAST_CAP=-12`; a 4-iovec safe input is clean on all pins and compilers.
  Pins, digests and claim URLs are in `harness/PROVENANCE.md` and
  `harness/evidence/pin-hashes.txt`; generated `.inc` files, binaries, raw logs
  and `run*.txt` are gitignored and regenerate with the script. The advisory
  is local (`AV:L/AC:H`), affected/patched versions are UNKNOWN and no fixed
  release tag exists; no msgpack build, public API sequence, serialized input,
  consumer, wire, natural heap layout, pointer dereference or command. Docs
  replayed the harness from a clean `git archive 36b8676` tree: rc 0, 177 PASS
  / 0 FAIL, `r1-normalized.txt` byte-identical to the committed hash above.
  The old `7edebe0e…` hash was superseded when `36b8676` normalized ASan
  BuildId/PIE bytes; frontier's `c628e1a` corrected the brief and PROVENANCE
  to the verified `cbc13d219…` value and recorded its own clean-archive replay.
  The operator also replayed `run.sh` from a copy of
  `lab/frontier/msgpack2shell` outside the checkout: rc 0, 177 PASS / 0 FAIL,
  `NORMALIZED_HASH=cbc13d219f85df289efd33aaab66b945cf29ba0d45576bd5ce96e750c9567538`,
  byte-identical to the committed `evidence/r1-normalized.sha`. Admission added
  the 89th route and the three wake units; no grade or scope change.

## 21:4x–21:5xZ witness and cross-packet addenda

- **MapServer2Shell W125 independent witness replay** (commit `a2d657b`,
  `reports/mapserver2shell-live.md`): from `git archive HEAD lab/mapserver2shell/`
  at `62b3e76`, re-hash both SHA-pinned tarballs (8.6.4 `41d3ee09…`, 8.6.5
  `5d7cf167…`) and extracted `mapwms.cpp` (`74e0d502…` vulnerable,
  `cd330d585…` fixed), then build three full-config trees with the same
  `WITH_*` flags, `OGCAPI=ON` and `-O0 -g` (vulnerable ASan `955501d6…`, fixed
  ASan `73898391…`, plain `6b477823…`). Expect vulnerable K=95 ASan `WRITE of
  size 8` at `mapwms.cpp:5991`, 0 bytes after an 800-byte region, K=195 the
  same after 1600 bytes, K=97/K=197 and fixed builds clean, and plain K=195 rc
  134 `double free or corruption (!prev)`; masked stderr is byte-identical to
  the canonical `asan-vuln-K95.err` / `asan-vuln-K195.err`. Under gdb,
  `./readback.sh 95` gives `NumParams=195` and byte-exact `DEADBEEFCAFEBABE`
  at `ParamValues[100]/[150]/[190]` and `libc_free` receives all three chosen
  8-byte values; a real 127.0.0.1:8077 GET gives HTTP 500 with the child ASan
  report byte-identical after masking. An earlier `-O1` build stalled on
  `mapogcapi.cpp.o` under load 12 and `OGCAPI=OFF` did not compile — preserved
  intermediate, closed by the `-O0` rebuild. Verdict: ESTABLISHED at labeled
  rung-3/rung-4 scope, rung 5 UNKNOWN. Canonical evidence files are gitignored
  and regenerate from the report's Reproduce block; the port was left free.
- **Pppd2Shell W126 chosen2 witness replay and normalizer fix** (commit
  `68dbc06`, `lab/frontier/pppd2shell/live/chosen2/README.md`,
  `reports/pppd2shell-live.md`): the witness rebuilt both pins from a clean
  `git archive HEAD` with its own gcc 13.3 and replayed all seven cases driven
  by `lab/frontier/pppd2shell/live/chosen_write.py` on a live PTY under sudo
  gdb (build procedure and the seven tags are in `live/README.md` and the
  chosen2 table). Expect `0x0000000041424242` in `phasechange` (+1840),
  `exitnotify` (+1848) and `sigreceived` (+1856), `fork_notifier` zero,
  2.5.4 duplicate-CI rejection, and 2.5.3 ASan `WRITE of size 1` at
  `lcp_reqci lcp.c:1608`, 0 bytes past `nak_buffer[1500]`. Four normalized
  hashes matched; three differed only in PIE pointer values, so
  `python3 lab/frontier/pppd2shell/live/chosen2/normalize_chosen2.py` now
  masks paths, PIDs, gdb addresses and pointer-shaped values while keeping
  zero-extended markers like `0x0000000041424242` and deterministic NAK bytes
  verbatim — `evidence/HASHES.txt` is stable across fresh captures. Raw logs
  stay in gitignored `live/raw/`. Verdict: rung 4 ESTABLISHED at live-process
  wire scope; the two-frame command attempt remains a negative and rung 5 is
  UNKNOWN.
- **Tacplus2Shell W127 cross-packet chosen-byte readback** (commits `186ac46`,
  `e3b614a`, `reports/tacplus2shell-status.md` W127): with the two plain pins
  already built as in the lane row, `bash
  lab/frontier/tacplus2shell/harness/run_reuse.sh` sends a seq-3 AUTHEN/CONT
  prime (body 2000, `cmd=ZZZZ`×40 at offset 1112) then a seq-1 AUTHOR trigger
  with a new session id on the same 127.0.0.1 connection; the runner drives
  `run_gdb2.py --client wire4.py` and records normalized hashes. Expect 10
  PASS / 0 FAIL twice, `063cc018…`/`6499bb53…`/`306a4569…`/`d951bc9d…` in
  `harness/reuse-r1.txt` and `-r2.txt`, prime and trigger `in=` the same
  address, a final `cmdline` of `AAAABBBB…HHHH` followed by 32 prime `Z`
  bytes (64 chosen bytes at chosen offsets), fixed pin's 57-byte rejection,
  a no-prime control with only the in-payload copies, and byte-exact `Y` for
  the alternate pattern. `e3b614a` tightened the `emit` patterns to require
  the `0xADDR` address prefix before `'Z' <repeats`. Raw `reuse-*.log`/stdout
  stay local; `run_gdb.sh` stays 8 PASS / 0 FAIL with W121 hashes unchanged.
  Grade: rung 4 extended to cross-packet live-daemon scope; no pointer,
  marker, command or rung 5, and the advisory's five-connection root chain
  stays claim text.

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

## Admitted lane limb — 2026-11-22 22:0xZ libyang2shell real parse

[Report](../reports/libyang2shell.md) ·
`lab/libyang2shell/harness/PROVENANCE.md`.

Provision: `git clone https://github.com/CESNET/libyang.git
lab/libyang2shell/src/libyang` then checkout `979f6925cf1f0918915613022e9e9dfc751bf647`;
from that tree `git worktree add ../libyang-hardened
48672b289e2e4c6773712c3ee0abae6b7fffe1f3`. Both trees are gitignored under
`lab/libyang2shell/.gitignore`. Consumer-source snapshots for the negative
result (`src/consumer-libnetconf2`, `src/consumer-sysrepo`) are shallow clones
and are read only, never built or started.

Replay: `cd lab/libyang2shell/harness && bash run.sh`. It builds both pins with
`-fsanitize=address -fno-omit-frame-pointer -g -O1`, compiles `lyb_driver.c`,
regenerates the 29-byte `valid.lyb` (sha256
`9c005b6982641a752998432eb51a58d53958fce835a11455cfd9fcb470074ad4` with the
module-name length at offset 3 and the leaf-value length at offset 16), and
runs six cases into `evidence/`. Expect: vulnerable `none` RC=0; vulnerable
`patchmod` ASan `heap-buffer-overflow` `READ of size 536870911` via
`lyb_read_string` → `lyb_parse_module` → `lyd_parse_data_mem` (exit 1);
vulnerable `patch` ASan `READ of size 4294967295` in `lyb_read_value` (exit 1);
hardened `none` RC=0, `patch` RC=3, `patchmod` logs `LYB string length
overflow.` with RC=3 and no ASan. The hardened driver sets
`LY_TEST_SEARCHDIR` to its `modules/` directory because that pin loads
internal YANG modules from files rather than embedding them. No listener or
external contact at replay time.

## Admitted lane limbs — 2026-11-22 22:0x–22:1xZ tacplus W128 and vrpn W11

- **Tacplus2Shell W128** (commit `3f7a3b1`,
  [report](../reports/tacplus2shell-status.md) W128). The runner needs the
  plain trees from the admission recipe: vulnerable `929671c` in `src-plain/`
  and fixed `d8493e0` in `src-fixed-plain/`, each built with
  `./configure --debug --minimum tac_plus-ng mavis && make -j4` (exact logs and
  pins in `lab/frontier/tacplus2shell/PROVENANCE.md`). Then from the repo root
  run `bash lab/frontier/tacplus2shell/harness/run_overflow.sh`; it starts
  plant-owned 127.0.0.1 listeners under gdb via `run_gdb2.py` and
  `harness/gdb-overflow.cmd`, with `wire4.py --skips 8,9,10,11,12` on the
  seq-1 trigger of the reused seq-3 prime. Expect 9 PASS / 0 FAIL twice;
  normalized hashes `f76aeb15…` (vulnerable), `6499bb53…` (fixed, 57-byte
  rejection) and `664aa0ce…` (no prime, 18-byte reply) in
  `harness/overflow-r1.txt` / `-r2.txt`. Live readback: `cmdline` at
  `0x7fffffffdca0`, the prime's `5a 5a 5a 5a 63 6d 64 3d` bytes at
  `cmdline+28` onward, and both saved RBP and saved RIP equal
  `0x3d646d635a5a5a5a` before the fault at `author.c:92`. The 104-byte VLA is
  followed by live locals, so the epilogue is never reached with intact loop
  state: no pointer, marker, command or rung 5. Raw `harness/overflow-*.log`
  and `-*.stdout` are gitignored; runner, gdb command and expected logs are
  committed.
- **Vrpn2Shell W11** (commit `ed4094f`, [report](../reports/vrpn2shell.md)
  W11). Build both pinned trees from `lab/frontier/vrpn2shell/src/vrpn-07.36`
  with `cmake -S <src> -B <out> -DCMAKE_BUILD_TYPE=Debug
  -DCMAKE_CXX_FLAGS='-fno-stack-protector -fno-pie -falign-functions=256'
  -DCMAKE_EXE_LINKER_FLAGS='-no-pie'`; vulnerable binary SHA-256
  `1cd5404e1b45358091e37aaa53cbf95891c370644173a5ecb6f4e6137b917fcd`, fixed
  `20d2da0907bcd01c69447bad0999cbea6ffa1799bcdbed23a79fc287a0e92359`. Patch
  a copy with `python3 lab/frontier/vrpn2shell/install_marker_patch.py
  <out>/server_src/vrpn_server <out>/server_src/vrpn_server-marked --target
  0x413d00 --ret 0x413dda --cave 0x40be40` (patched SHA-256 `45b33f20…`,
  patched fixed `a8f2ebf4…`); the source is unmodified. Run
  `BIN=<out>/server_src/vrpn_server-marked bash
  lab/frontier/vrpn2shell/probe-func-dos.sh <outdir> <port> 136` on fresh
  loopback ports: SENDER and TYPE vulnerable rows stay ALIVE with
  `VRPN2SHELL_MARKER` on server stderr; index 4, the patched fixed binary and
  the unpatched vulnerable binary (exit 139) are the controls.
  `lab/frontier/vrpn2shell/out-w11-final-gdb/gdb.log` shows the stub entered
  by the corrupted return; `out-w11-marked-*` and `out-w11-marked2-*` are
  preserved wrong-stub negatives. Target/return/cave addresses are
  build-specific — `probe-marker-frame.sh` and `probe-marker-stub.sh`
  remeasure them.
  Source pins and configure logs are in `lab/frontier/vrpn2shell/PROVENANCE.md`;
  raw logs for every reported W1–W12 row are committed, while two superseded
  W11 stub iterations and the W11/W12 CMake configure logs remain uncommitted.
  The marker bytes come from the binary patch, not wire input, and stock
  builds stay at witness W115's rung 3. W12 (`ceb6bd5`) rebuilt both pins in
  new directories with the W11 flags (vulnerable SHA `52eefbfb…`, fixed
  `f8d50ba7…`) and replayed the marker; a control without
  `-falign-functions=256` (SHA `d82632d5…`) zeroes saved RIP to `0x410800`,
  mid-function, so alignment is the precondition. Witness W135 (#1985)
  rebuilt both pins from a clean `8e9fd0a` archive with the same flags,
  replayed the six-case matrix on fresh loopback ports and graded the marker
  ESTABLISHED at the labeled lab-patched rung-4 scope; build-specific
  addresses and `-falign-functions=256` stay preconditions, and no command or
  rung 5 is claimed.

## Admitted frontier lane — 2026-11-22 22:2xZ sofiasip2shell

- Claim and pins: `reports/frontier-sofiasip2shell.md`,
  `lab/frontier/sofiasip2shell/harness/PROVENANCE.md`. GHSA-whfw-c3jj-99rp /
  CVE-2026-116791, affected `<= 1.13.17` (`6198851a`), patched `>= 1.13.18`
  (`ad36ac8f`); both `ws.c`/`ws.h` pins and the fix patch are committed with
  digests in `harness/evidence/pin-hashes.txt`.
- Operator replay: `rm -rf /tmp/sofia-replay && cp -a
  lab/frontier/sofiasip2shell /tmp/sofia-replay && bash
  /tmp/sofia-replay/harness/run.sh` — rc 0, 128 PASS / 0 FAIL across two
  rounds, gcc 13.3 and clang 18.1, both pins and safe/vulnerable cases.
  `gen_fn.py` extracts the function verbatim from each pin and
  `verify_verbatim.py` checks the slice; `evidence/*.log` was byte-identical
  to the committed worktree evidence.
- Path-independent hash: `cat $(printf '%s\n' evidence/*.log | sort) | sha256sum`
  gives `f6d088b793c8450b20bd26a49f309851502e6812e32f8e2891a4f04d25a3b3d3`,
  the value recorded in the staged brief from a clean `git archive 189441f`
  replay. The path-dependent form from `harness/` is
  `2ee5618bf4ff4df33b72c9dc1b0f027cbfca23a28b7b59cff5f1455a16ac7595`.
- Observed rows: vulnerable pin ASan `heap-buffer-overflow READ of size 1`,
  0 bytes after a 64-byte region, frame `ws_read_frame` at
  `fns-1.13.17.inc:185`; fixed pin rc 0 with `DATALEN=78 RPLEN=64`. Plain mode
  reads back NUL at offset 64 and `0xEE ^ mask[i%4]` at 65..77 for mask
  `415a4243`, offset 78 untouched; the fixed pin writes nothing.
- Staged baseline boundary (W1 below reaches the real layout): direct-call
  harness with deterministic stubs, not a sofia-sip build, real 64 KiB allocator
  layout, WebSocket upgrade, loopback listener or wire frame; no adjacent object
  corruption, pointer control or rung 5 at that scope. [Status](../reports/sofiasip2shell-status.md).

## Admitted frontier lane — 2026-11-22 22:4xZ ytnef2shell

- Claim and pins: `reports/frontier-ytnef2shell.md`,
  `lab/frontier/ytnef2shell/harness/PROVENANCE.md`. GHSA-jhg4-xcxm-cfg6
  (maintainer Yeraze, published 2026-11-20, HIGH, CWE-190/122/125, no CVE at
  publication), affected `<= 2.1.2` (`d9f08914`), patched `2.1.3` (`f0ccad7d`);
  the vulnerable/fixed `lib/ytnef.c` pins and the fix patch are committed with
  digests in `harness/evidence/pin-hashes.txt`.
- Operator replay: copied `lab/frontier/ytnef2shell` to a fresh `/tmp` directory
  and ran `bash <copy>/harness/run.sh` from that copy: rc 0, 240 PASS / 0 FAIL
  across two rounds, gcc and clang, both pins, ASan and plain-arena cases.
  `gen_fn.py` re-extracts `RTF_PREBUF`, `SwapDWord()` and `DecompressRTF()` from
  each pin on every run and `verify_verbatim.py` aborts on any drift.
- Path-independent hash: `cat $(printf '%s\n' evidence/*.log | sort) | sha256sum`
  over 72 normalized logs gives
  `a2819d82cc5fdf23c88ee65fc4d8eb08a48fe01be80afa092fdf37ac43bce639`, exactly
  the value frontier recorded from a clean `git archive 3f72935` replay.
- Observed rows: vulnerable pin ASan `heap-buffer-overflow`, `WRITE of size 207`,
  0 bytes after a 16-byte region, frame `DecompressRTF`; 1-byte and 206-byte
  region variants for the other chosen sizes; MELA `READ of size 64` past a
  20-byte input. Plain arena: `ALLOC=16 OVERRUN=191 B0=64 BMID=6f BEND=78
  TAIL=ee` plus the 0/206-byte variants; fixed pin `ALLOC=none OVERRUN=0 TAIL=ee`
  and `Corrupted file` on all four attack inputs; well-formed 8-literal stream
  clean on both pins.
- Staged baseline boundary (W1 below builds both pins and parses real TNEF
  files): direct-call harness with a synthesized stream header and a static
  plain-mode arena, not a ytnef build, TNEF blob, mail client, procmail hook,
  natural allocator layout or adjacent object corruption at that scope. The
  written bytes are fixed by the pinned prebuffer; only the allocation size and
  therefore the overrun length and offsets are chosen. [Status](../reports/ytnef2shell-status.md).

## Admitted lane limbs — 2026-11-22 22:1x–23:0xZ real-layout reach

- **Pgpool2Shell W10 `wd_nodes` wire reach** (commit `00c84f2`,
  [report](../reports/pgpool2shell-wdnodes-w9.md)). The pinned 4.7.2/4.7.3
  trees come from the `SHA256SUMS` in the Pgpool row above. From
  `lab/pgpool2shell/wdnodes/wire` run `bash run.sh` on loopback ports checked
  free beforehand (19003–19006); expect three cases: 4.7.2 with N=128 and N=129
  both receive `CONFIG DATA` and emit `WD_VERIFY_*` warnings plus a `DETAIL`
  line naming the peer's node count, while 4.7.3 rejects with `ERROR: invalid
  watchdog configuration JSON` and no verify warnings. Neither 4.7.2 case
  faults on this branch. For the readback run `bash gdb-run.sh CHOSEN HOST ...`
  and break at `watchdog.c:4476`; with peer port `0x42424242` and hostname
  `wxyzUUUUUUUU`, `wd_node_info[128].wd_port` / `.pgpool_port` read
  `1111638594` and `.hostname` plus adjacent `trusted_servers` read the chosen
  bytes; `0x11111111` / `wxyzAAAAAAAA` gives the corresponding `0x4141…`
  neighbour. The slot address is build-dependent; its offset from `wd_nodes`
  is not. `EVIDENCE_HASHES.txt` was stable across two `run.sh` replays; raw
  `evidence-*` and `gdb-w9*.out` are committed there, and the daemon logs are
  too timing-dependent to hash whole. No dereference, crash, command or rung 5.
- **Pgpool2Shell W11 `wd_authkey` is not a type-Z gate** (commit `f5df311`,
  [status](../reports/pgpool2shell-status.md) W11): from the same wire lane run
  `bash lab/pgpool2shell/wdnodes/wire/auth-probe.sh` with
  `wd_authkey = 'labsecret'` and no key from the peer. The N=129
  `WD_POOL_CONFIG_DATA` packet is still received and parsed with no JSON or
  auth error and no crash; normalized decisive hashes match W10's vulnerable
  N=129 case. `watchdog.c:4467-4472` has no `verify_authhash` on that branch.
  W11 is author-only and grade-neutral: rung 3 wire scope unchanged, chosen
  address and command still unestablished.
- **Tacplus2Shell W129 live write-what-where** (commit `7603775`,
  [status](../reports/tacplus2shell-status.md) W129). Build the plain 2.1.2
  pins as in the admission recipe (`src-plain/`, `src-fixed-plain/`), then
  `bash lab/frontier/tacplus2shell/harness/run_ptr.sh`. It sends the wire5.py
  seq-3 prime / seq-1 AUTHOR pair to a plant-owned 127.0.0.1 daemon under gdb
  (ASLR disabled by the debugger); expect 14 PASS / 0 FAIL twice, with hashes
  `e93c5bbc…`, `97a5907c…` and `a1c849b2…` in `harness/ptr-r1.txt` /
  `-r2.txt`. gdb observes `t` at `cmdline+168`, the i=13 copy replacing it with
  the chosen address, and the i=14 copy writing `50 57 4e 33` four times
  (`PWN3PWN3PWN3PWN3`) plus a NUL there with `i`, `p` and `argsizep` still live.
  Fixed pin, no-prime and the wire6.py destructor probe are the controls: the
  latter ends in `free(): invalid next size (fast)` before any fake destructor
  call, with no marker file. Raw `ptr-*.log` / `-*.stdout` are local-only;
  `run_ptr.sh`, `wire5.py`, `wire6.py`, `gdb-ptr.cmd` and expected logs are
  committed. Rung 4 at live-daemon scope; rung 5 UNKNOWN, no leak claimed.
- **Pppd2Shell W131 sigreceived-notifier negative** (commit `f95ddc9`,
  [live](../reports/pppd2shell-live.md) W131). After the W122/W125 plain
  `-no-pie` build from the row above, run
  `python3 lab/frontier/pppd2shell/live/rce_sigrecv.py` against the locally
  started daemon under gdb. Expect the callback to be reached and pppd to log
  a forked `Child process <command>`; the child then dies with SIGSEGV before
  `execve` and no sentinel appears, in five replays. The cause is the
  +1532..+1535 high half of `the_channel` holding PAP-NAK pattern bytes
  `0x23c20503`, so the pointer reads `0x23c20503004688a8`. Normalized evidence
  and hashes are in `live/sigrecv/evidence/`; raw pppd logs, strace and frames
  stay under the gitignored `live/raw/` and regenerate with the driver. Grade
  stays rung 4; this is a preserved negative, not a rung-5 route.
- **SofiaSip2Shell W1 real layout and pinned library** (commit `c0fcf70`,
  [report](../reports/sofiasip2shell-real-layout.md)). The verbatim pinned
  `ws_read_frame()` slices come from the staged harness, re-hash-checked by
  `run.sh`. Run `bash lab/sofiasip2shell/layout/run.sh` (eight cases; output in
  `lab/sofiasip2shell/layout/layout-run.txt`). Expect plain v1.13.17 with a
  65536-byte masked frame to print `USABLE=65544`,
  `NEXT_SIZE_BEFORE=710c020000000000`,
  `NEXT_SIZE_AFTER=30564043415a0000`, `XOR_DELTA_BAD=0` and `NUL=00`; a
  post-frame `malloc(64)` exits 134 with `malloc(): corrupted top size`. The
  `plain-v17-victim` case keeps neighbour data `c3c3c3c3c3c3c3c3` while its
  size becomes `d05a4243415a0000`. ASan v1.13.17 reports `READ of size 1` 0
  bytes after the 64 KiB region at `fns-1.13.17.inc:185`; short frames and
  fixed v1.13.18 are clean. For the real API path build both tags from
  `git archive` with `./autogen.sh` and the ASan `configure` / `make -C
  libsofia-sip-ua -j4` lines in the report, then run
  `bash lab/sofiasip2shell/libbuild/driver/build_and_run.sh v17 v1.13.17 full
  short` (and `v18 ... full short`; recover mode with
  `ASAN_OPTIONS_OVERRIDE='detect_leaks=0:abort_on_error=0:halt_on_error=0'`).
  The driver does a real HTTP 101 upgrade on a loopback socket; v1.13.17 first
  faults at `ws.c:427` (`ws_raw_read` terminator) with the unmask at `:1090`
  and NUL at `:1100` under recover mode; `lab/sofiasip2shell/libbuild/RESULT.md`
  records the clean controls. Raw `.out/.err/.rc` stay in the gitignored
  `layout/evidence/` and `libbuild/` trees; the scripts regenerate them.
- **Ytnef2Shell W1 real parse** (commits `8d1c59d`, `e3630a2`, `a377784`,
  [report](../reports/ytnef2shell-w1.md)). Tarball SHA-256 pins and build
  commands are in `lab/ytnef2shell/PROVENANCE.md`; from the repo root run
  `python3 lab/ytnef2shell/make_inputs.py` and `bash
  lab/ytnef2shell/run_real.sh` (20 parses: both pins x ten inputs). Expect
  pinned 2.1.2 ASan `WRITE of size 207` 0 bytes after a 16-byte region with
  frames `DecompressRTF ytnef.c:1573` → `MAPIPrint :1454` → `PrintTNEF
  main.c:172` → `main :87`, allocation at `:1571`; 0/206-byte variants and
  every winmail.dat-derived input behave likewise. 2.1.3 prints `Corrupted
  file` with rc 0, and unmodified upstream files are clean on both pins.
  In the plain 2.1.2 build, gdb breakpoints at `:1573`/`:1574` show the next
  chunk size `0x7d1` → `0x7b30323762617466` and the following `calloc` exits
  134 with `malloc(): invalid size (unsorted)`. `wrap16`/`wrap0` give rc 134;
  `wrap206` is a preserved negative — rc 139 at the later copy `:1611` with
  its 216 usable bytes and intact header. Per-file offsets, checksums and
  digests are in `lab/ytnef2shell/inputs/MANIFEST.txt`; raw ASan/gdb logs and
  built trees are local-only and regenerate with the two commands above.
- **Ytnef2Shell W2 second/third callers and witness** (commit `fb180df`,
  [report](../reports/ytnef2shell-w2.md)): the fixed-shape TNEF input also
  reaches `DecompressRTF` via `SaveVCalendar` (`ytnef/vcal.c:408` ←
  `ProcessTNEF main.c:179`) and a third named caller. Witness #1876 replayed a
  clean archive with hash-exact pins over 20 parses x 2 runs and ESTABLISHED
  rungs 1–4 at the natural-layout scope, refuting a pre-existing-header
  counterexample with no nit. The synthetic hybrid input does not cleanly
  reject on fixed 2.1.3, so only the first two callers have paired fixed
  controls — a preserved confounder. No natural-layout grooming produced
  pointer control, marker or command; rung 4 is the structural ceiling here.

## Admitted frontier lane — 2026-11-22 23:2xZ baresip2shell

Frontier staged GHSA-hvxv-v2gp-v93h / CVE-2026-50161 in `6cd23ec` / `6459f07`
with brief `reports/frontier-baresip2shell.md`; hash-pinned v4.8.0
(`7ace643f`) and v4.8.1 (`89aed31f`) sources, fix `718b926` and the toolchain
are in `lab/frontier/baresip2shell/PROVENANCE.md`. All inputs are local; the
harness opens no socket.

From the repository root, replay from an isolated copy so the staged evidence
directory is untouched:

```sh
T=$(mktemp -d /tmp/baresip-replay.XXXXXX)
cp -a lab/frontier/baresip2shell "$T/lane"
bash "$T/lane/harness/run.sh"
```

`run.sh` re-extracts the 54-line vulnerable and 55-line fixed
`websock_decode()` from the saved pinned `websock.c` with
`sed -n '/^static int websock_decode/,/^}/p'`, asserts five SHA-256 pins
(two source files, the fix patch, and both function slices), then builds
gcc 13.3.0 and clang 18.1.3 ASan variants plus a plain guard-page variant.
Expect rc 0, `SUMMARY=43 PASS / 0 FAIL` and
`NORMALIZED_HASH=d6a3d40dd5fba54383ccece9e7010a85819737577710854493d90954cb9349fc`
over `harness/evidence/*.out` after address/path normalization. The operator
observed exactly those values on 2026-11-22 at admission, matching frontier's
clean-archive replay. Witness #1933 (`c5587a7`) rebuilt all four `libre.a`
and four `ws_server` binaries from clean archive `c06152a` and found nine
evidence files byte-identical; the narrow rung-4 grade is ESTABLISHED.

Expected bytes: crafted frame `CRAFT_B0=82 CRAFT_B1=ff MASKBIT=1
LENBYTES=fffffffffffffffc KEY=b4b4b4b4`; vulnerable pins report
`ERROR: AddressSanitizer: heap-buffer-overflow`, `READ of size 1`, `0 bytes
after 30-byte region`, top frame `websock_decode` (the load half of
`p[i] = p[i] ^ mkey[i%4]`). The plain run prints
`REGION_BYTES=30 PAYLOAD_BYTES=16 SENTINEL_BYTES=32 KEY=0xb4`,
`PLAIN_FIRST_OOB_OFFSET=12`, `PLAIN_FAULT_OFFSET=44` and 32 adjacent sentinel
bytes changed from `0xEE` to `0x5A`, proving the store. Fixed pin: `RC=61`
(`ENODATA`), `HDR_LEN=0xfffffffffffffffc`, `PAYLOAD_FIRST=00`, `MKEY=00000000`,
`CONSUMED=10`, no ASan report; safe 8-byte masked frame `RC=0` with
`PAYLOAD_FIRST=b4` on both pins.

Boundary after W1: both pinned tags are really built, a plant-started
`websock_accept()` listener on 127.0.0.1:19015 completes a real HTTP 101,
and the 14-byte frame `82fffffffffffffffffcb4b4b4b4` is sent over that socket
(`bash lab/frontier/baresip2shell/live/run.sh`; probes in `run-probes.sh`).
Expect `UPGRADE_STATUS=HTTP/1.1 101 Switching Protocols`, rungs 1/2/3 at the
real caller/wire scope and rung 4 as attacker-keyed corruption of adjacent
allocator metadata that kills the lab server. The structural ceiling is
measured: `hdr->len` stays ~2^64, so there is no small attacker-selected
write length, and `websock_decode()` never returns on this frame, leaving no
post-corruption object read or call. Other allocators and concurrent
consumers are UNKNOWN; no marker, command or rung 5. Admission minted the
92nd hy4-flash route and adopted frontier's window; that changes no grade.

## Admitted lane limbs — 2026-11-22 23:0x–23:3xZ public API, live tport, chosen call

- **Msgpack2Shell W1 real public-API two-migrate reproducer** (commit `7145879`,
  [report](../reports/msgpack2shell-realapi.md)): `bash lab/msgpack2shell/run.sh`
  builds vulnerable `c-7.0.2` and fixed `1c47ce0` pinned C libraries with gcc
  13.3.0 and clang 18.1.3, then drives only `msgpack_vrefbuffer_init`,
  `append_ref` and `migrate` through upstream #1197's two-migrate sequence (5
  refs → migrate → 4 refs → migrate) with no forced `src->end`. Expect rc 0,
  74 PASS / 0 FAIL, summary hash
  `b8c96187de5cbf66bc53cc1b350d977eab95e5cda5351875c992136880bca022`: on the
  vulnerable pin both compilers report ASan `heap-buffer-overflow WRITE of
  size 64`, 0 bytes after a 128-byte region at `vrefbuffer.c:222` (allocation
  from the prior migrate's `realloc` at `:210`), the plain build aborts
  `free(): invalid size`, and the upstream single-migrate canary PoC is
  `CORRUPTED`; fixed and equal-capacity safe controls stay clean and grow B to
  16 slots. Instrumentation prints `cmp=0` on every variant. Rung 4 through the
  real public API of a built library. Consumer reach is UNKNOWN with three
  preserved negatives: the only in-tree caller in `c-7.0.2` is
  `test/msgpack_c.cpp:1570`; GitHub search (658 indexed files, 113 filtered
  paths) leaves only the unit test or advisory/OSV/NVD databases among source
  paths; Sourcegraph (53 exhaustive matches in 29 repos, 44 with archived and
  forked included) likewise shows only bindings and request-serving vendors
  (`msgpack-node`, `msgpack-objectivec`, fluent-bit, griddb, OpenNJet,
  ytsaurus, gecko-dev), not a production `migrate()` caller. grep.app returned
  429, Debian Code Search showed none, and private callers stay UNKNOWN.
  Disposition: stop at rung 4 and reopen only on a real caller. No serialized
  input, socket, live process, dereference of a copied `iov_base`, marker,
  command or rung 5. Evidence files under `lab/msgpack2shell/evidence/` are
  tracked; build trees stay gitignored.
- **SofiaSip2Shell W2 chosen-delta neighbour data and live WS SIP tport**
  (commits `df6fb42`, `32b6757`, `620ce97`;
  [layout](../reports/sofiasip2shell-real-layout.md),
  [live](../reports/sofiasip2shell-live-ws-tport.md)): after the W1 recipe in
  the lane limbs above, `bash lab/sofiasip2shell/layout/run.sh` adds two
  natural glibc geometries — `plain-v17-geom` (65527-byte bbuffer, 5 chosen
  XOR bytes in a live neighbour's user data) and `plain-v17-realloc` (65544-byte
  frame on the default bbuffer, the library's real `ws.c:1057` realloc, 6 bytes
  in neighbour data) — with `plain-f18-*` fixed-pin controls leaving that data
  untouched. A clean `git archive HEAD` replay regenerated the two gitignored
  `.inc` files from tracked `ws-*.c` (hashes `b96477e0` / `42dce55f`) and
  reproduced all 12 per-case rcs and the four new evidence files byte-for-byte.
  The live tport lane links against the same full pinned-library static builds:
  `bash lab/sofiasip2shell/libbuild/live/build_and_run.sh v17 'v1.13.17' 18857`
  (and `v18 ... 18858`; `SAN=plain` variants on 18859/18860) starts a raw `ws`
  tport on 127.0.0.1 and forks a client that waits for the library's real HTTP
  `101 Switching Protocols` before sending a masked 65544-byte BINARY frame.
  Expect the ASan vulnerable pin to fault at `ws_read_frame ws.c:1073` ←
  `tport_recv_stream_ws tport_type_ws.c:217`, the plain vulnerable pin to abort
  `corrupted size vs. prev_size` with `NEXT_SIZE_BEFORE=1101000000000000` →
  `NEXT_SIZE_AFTER=005b4243415a4243`, and the fixed pin and short frames clean.
  Rung 4 only at the in-process harness scope. W3 (`21a4be1`) narrows the old
  ceiling: with even `mask[0]` the `PREV_INUSE` bit survives but glibc still
  aborts, and no tested mask/geometry produced a fake chunk; witness #1942
  returned CLOSED ESTABLISHED at that negative-result scope. W4 (`08e86c0`)
  chooses a 4-byte mask that sets a freed tcache chunk's `next` to
  `P_A ^ T`, then two `malloc(128)` calls return the victim and the chosen
  address, with an observed 8-byte key-slot zero write there — still
  in-process mechanics; witness #1968 replayed it three times from a clean
  archive and returned ESTABLISHED at that labeled rung-4 scope, no nit or
  grade change. No marker, command or rung 5;
  gitignored pin trees and raw logs regenerate with the committed scripts.
- **Pppd2Shell W132 chosen function call with chosen argument** (commit
  `740b6fd`, [live](../reports/pppd2shell-live.md) W132): after the W131
  `-no-pie` plain build from the Pppd lane row, run the driver against that
  binary with a fresh marker and normalization:
  `python3 lab/frontier/pppd2shell/live/rce_call.py --binary "$PWD/lab/frontier/pppd2shell/live/raw/build-vuln-nopie/pppd/pppd" --marker <unique> --mode attack [--strace]`
  then `python3 lab/frontier/pppd2shell/live/call/normalize_call.py`.
  `notify()` calls `(*np->func)(np->arg, val)`, so a one-argument
  `unlink@plt` stub receives the attacker-chosen sentinel path in `rdi` while
  the signal number is ignored; the same 1498-byte ConfReq writes the fake
  notifier at `sigreceived`. Expect a live strace line
  `unlink("/tmp/pppd2shell-r5-…-victim") = 0` and the sentinel file gone, with
  two normalized replays byte-identical in `live/call/evidence/HASHES.txt`.
  Short safe frames, `func=NULL` and the fixed 2.5.4 pin leave the sentinel
  intact; the process later faults in shutdown on the corrupted `the_channel`,
  `unlink` is a libc call, not a command, so W132 alone is rung 4. W133
  (`cb1da9e`, `ea972d2`) supersedes that for the pinned non-PIE 2.5.3 lab
  build: `dlopen@plt` loads a pre-staged lab `.so` whose constructor reads the
  command from the second wire frame and calls `system()`. Witness #1966
  replayed from clean `git archive ea972d2`, matched six normalized hashes
  and observed the sentinel with a wire-only causal change. Fixed 2.5.4,
  short-safe and NULL-callback controls are clean. Preconditions: pre-staged
  `.so`, fixed `-no-pie` globals, library/stack ASLR on and a local PTY; no
  file-staging primitive or stock/PIE RCE is claimed. Raw logs stay in
  gitignored `live/raw/`.
- **Tacplus2Shell W130 environment-scoped hash normalization** (commit
  `f2aac1c`, [status](../reports/tacplus2shell-status.md) W130): witness #1814
  found that `POST12 cmdoff` is a decimal pointer delta that varies with stack
  and environment layout. `harness/run_ptr.sh` now masks `cmdoff=[0-9]+` to
  `cmdoff=N`; two canonical replays at 2026-11-22 23:07Z give 14 PASS / 0 FAIL
  and byte-identical logs, and a 4096-byte environment filler leaves the three
  hashes unchanged, while the fixed/no-prime hashes and the write-what-where
  verdict are unaffected. Two byte-prefill checks remain environment-sensitive
  and report FAIL under the filler; they are byte-prefill assertions, not the
  write proof. Replay: `bash lab/frontier/tacplus2shell/harness/run_ptr.sh`.
- **Tacplus2Shell W132/W134 hash portability and fake-mem ceiling** (commits
  `177955a`, `ec4aebc`, `cd620de`, `f0d712f`, `44d2978`;
  [status](../reports/tacplus2shell-status.md) W132/W134): witness #1884's
  second hash NIT is closed by `vuln_target_changed` /
  `vuln_written_nul` assertions in `run_ptr.sh`; three replays give 14 PASS /
  0 FAIL with stable hashes. W133 measured `session->mem arr_count=0
  arr=(nil)` with no destructor registered. W134 uses W129's `t`-slot
  write-what-where to replace the `session->mem` pointer with a fully fake
  `mem_t`: at `cleanup_session()` (`packet.c:1326`) the pointer lands and
  `mem_destroy()` is entered, but faults in libmavis at `memops.c:247`
  before the indirect call completes, and `send_author_reply_final()`
  rebuilds the reply into the reused prime chunk, overwriting the staged
  object. No command, marker or rung 5; the staging barrier is structural on
  this build/config, not an offset guess.
- **Tacplus2Shell W135 live-daemon chosen command (commit `32b53e9`,
  [status](../reports/tacplus2shell-status.md) W135)**: from the repo root run
  `bash lab/frontier/tacplus2shell/harness/run_rce.sh` (needs the committed
  vulnerable/fixed plain builds under `src-plain/build/` and
  `src-fixed-plain/build/`, plus gdb). Expect a measured `in=`/`mem=` pair,
  `DESTROY … type=0 count=1 arr=…`, `ARR0 f=… p=…`, the quoted
  `touch /tmp/tacplus-rce-marker` command string, a vfork-detach line and
  `FAILURES=0` over 13 PASS / 0 FAIL (both committed replay files contain 13
  PASS lines; the status report's "14" is a count NIT). The vulnerable case creates
  `/tmp/tacplus-rce-marker` (cleared by the script per case); fixed `d8493e0`
  with the same wire input replies 57 bytes with no marker, and vulnerable
  with no prime replies 18 bytes with no marker. Two committed replays
  `harness/rce-r1.txt` / `rce-r2.txt` are byte-identical; normalized hashes
  `d316b431…` (vulnerable), `88754a15…` (fixed), `ee3c069a…` (no prime). The
  generated `rce-*.log` / `rce-*.stdout` files are untracked, not gitignored,
  and regenerate with the script. gdb-disabled ASLR plus addresses measured by
  a benign prime in the same shell are preconditions; this is rung 5 OBSERVED
  at that build scope with no independent witness verdict.
- **Tacplus2Shell W136 independent witness verdict (commit `1e23aec`,
  [status](../reports/tacplus2shell-status.md) W136, verdict #2049)**: from a
  clean `git archive 32b53e9` into a throwaway `/tmp` tree with no shared
  checkout writes, the witness hash-verified both pinned `packet.c`/`author.c`
  blobs (working-tree digests differ only by `$Id$` expansion), built plain
  vulnerable `929671c` and fixed `d8493e0` binaries itself and replayed
  `bash lab/frontier/tacplus2shell/harness/run_rce.sh` twice: rc 0 and
  `FAILURES=0` both times, with 13 PASS lines emitted and exactly three
  normalized hashes —
  `d316b431f00ce51c488fc79391b687afdea16fbfa596e3ccbb612e12fb539436`
  (vulnerable), `88754a15124254c2b88eb6851cb762d2f64232edb6b9bcc1cc72cb9550d4de6f`
  (fixed) and `ee3c069a0b4d5de24ebf810d5bb6dd2d6e0249cae7564a4e296520e5201b96ee`
  (no prime). Its gdb trace showed `EVAL`, `POST14`, `DESTROY type=0 count=1`,
  `ARR0 f=0x7ffff7c58750`, `x/s "touch /tmp/tacplus-rce-marker"`, the
  vfork-detach line and the expected `free()` abort; the fixed pin rejected
  with 57 bytes and the no-prime control replied 18 bytes, both without a
  marker. The witness changed only `--marker` in the throwaway tree's wire
  arguments: a different marker appeared while the default stayed absent, so
  the command bytes are wire-controlled, not a fixed harness string. No
  counterexample or leftover daemon/port was found. Grade: rung 5
  **ESTABLISHED** at the labeled build scope (plain `-O0`, gdb parent, ASLR
  off, configured shared key, permitted user, cross-packet prime, one AUTHOR
  trigger). No privilege change was measured; the advisory's five-connection
  `system()`/root chain stays claim text. Rungs 1-4 and all preserved
  negatives stand unchanged. A docs replay of the repo-root harness observed
  the same three hashes, 13 PASS lines and the same marker/control behavior.

## Admitted frontier lane — 2026-11-23 00:1xZ connman2shell

Frontier staged CVE-2026-115863 / GHSA-725f-6r9j-c4hf at 23:53–23:55Z with
brief `reports/frontier-connman2shell.md`; tag-2.0 `gdhcp/client.c`, the derived
fixed snapshot and Andrei Miu's mailing-list fix patch are SHA-256-pinned in
`lab/frontier/connman2shell/PROVENANCE.md`. There is no tagged upstream fix:
the fixed snapshot is tag 2.0 plus the posted hunk from Debian bug #1153442.
All inputs are local; the harness opens no socket and starts no daemon.

From the repository root, replay from an isolated copy so the staged evidence
directory is untouched:

```sh
T=$(mktemp -d /tmp/connman-replay.XXXXXX)
cp -a lab/frontier/connman2shell "$T/lane"
bash "$T/lane/harness/run.sh"
```

`run.sh` re-extracts `get_domains()` from both pinned sources with
`sed -n '/^static GList \*get_domains/,/^}/p'`, asserts six SHA-256 pins (three
full files and both verbatim function slices plus the driver), then builds gcc
13.3.0 and clang 18.1.3 ASan variants and a plain stack-canary variant. Expect
rc 0, `SUMMARY=61 PASS / 0 FAIL` and
`NORMALIZED_HASH=bf6810e7c0d3db2fa2bae36e7233974e6fd593084c209952e742df1e3a48211f`
over `harness/evidence/*.out` after address/path normalization. The operator
observed exactly those values at admission on 2026-11-23 from a fresh `/tmp`
copy, matching frontier's clean-archive replay; no witness verdict exists yet.

Expected bytes: crafted DOMAIN_LIST is 2048 bytes of `0xff` except
`value[1024] = K`; the vulnerable ASan runs report
`ERROR: AddressSanitizer: stack-buffer-overflow`, `READ of size 1`, top frame
`get_domains`, `dns_name` at gcc frame `[48,1074)`, with access offsets
1089/1105/1137/1201 for K=0x10/0x20/0x40/0x80 (delta `K-1`) and clang K=0x80
delta 127. The plain build reports `CANARY DOTS=69 FIRST=49 LAST=16301`,
observing the store half. The fixed snapshot returns `RC=0 LIST_LEN=256` on
the same attack input and the safe DOMAIN_LIST returns `RC=0 LIST_LEN=1` on
both pins with no ASan report. The write byte is fixed `.`; no pointer,
marker, command or rung 5 is claimed. Status:
`reports/connman2shell-status.md`.

## Admitted lane limbs — 2026-11-23 00:3xZ connman2shell caller chain and REPLY

These W1/W2 lanes remove the admission row's "no natural layout / no DHCPv6
REPLY" caveats without adding a daemon, socket or full build; W4 below adds
loopback socket delivery only. W1
(`reports/connman2shell-callpath.md`) calls three verbatim tag-2.0 functions —
`get_domains`, `get_dhcpv6_option_value_list`, `get_dhcpv6_request` — from a
forged option-24 value; only `dhcpv6_get_option()` is stubbed. W2
(`reports/connman2shell-wirereply.md`) adds the verbatim
`dhcpv6_get_option()` from tagged `gdhcp/common.c`
(SHA-256 `2ff01d8b8d8347fad8876092035a3acfc38fb9048b2ea0da8be90c43af73eada`)
and parses a raw REPLY-shaped packet in-process. Every run re-extracts and
SHA-256 asserts the included function slices. From the repository root:

```sh
bash lab/connman2shell/callpath/run.sh
bash lab/connman2shell/callpath/retarget.sh
bash lab/connman2shell/wirereply/run.sh
```

Expect W1 rc 0, `SUMMARY=37 PASS / 0 FAIL`, with the ASan stack
`get_domains` ← `get_dhcpv6_option_value_list` ← `get_dhcpv6_request` ←
`main`, `dns_name` at `[48, 1074)` and access at 1201 (delta 127 for K=0x80).
W2 expects rc 0, `SUMMARY=29 PASS / 0 FAIL` (observed three times), with
`WIREPARSE OLEN=2048 COUNT=1 OFFSET=8` on the 2056-byte REPLY (message type 7,
option code 24, length 2048, 2048-byte value `0xff` except `value[1024]=K`)
and the same ASan stack through `run_chain` ← `main`; the safe option gives
`WIREPARSE OLEN=8 COUNT=1 OFFSET=8`. Both lanes report `CHAIN DONE STATUS=0`
with no ASan on the derived fixed snapshot and on the well-formed short
DOMAIN_LIST. Plain store counts and crash/no-store categories are printed as
`OBS` and are informational only: commit `89fad72` removed them as pass
criteria because the continuation after the first chosen step reads ambient
stack bytes and is ASLR-dependent.

The gdb limb expects `RETARGET_K=0x67 HITS=5/5` with `BEFORE=33 AFTER=2e`:
K=103 puts the first fixed `.` store on the saved return-address byte of
`get_dhcpv6_option_value_list` in this harness layout, re-entering
`get_domains` once. This is a layout-specific observation, not a hijack; a
real connmand build would need a different K. Each lane's `.gitignore` keeps
generated function slices, binaries and build logs out of Git; the evidence
`.out` files are tracked. A full build is a preserved negative: `configure.ac`
needs `dbus-1 >= 1.4` and (except with firewall `none` and wireguard off)
`libmnl >= 1.0.0`; neither is installed here, and `client.c` includes
`<connman/dbus.h>`, so no live build, daemon, remote input or witness
replay is claimed; W4 below adds loopback socket delivery, not a daemon.

### W4 — loopback UDP REPLY delivery (2026-11-23 01:4xZ)

`lab/connman2shell/wireloop/` moves the 2056-byte REPLY out of the receiver
process: `driver.c` forks, the child binds an ephemeral UDP port on
`INADDR_LOOPBACK` and blocks in `recvfrom()`, and the parent `sendto()`s the
same message-7 / option-24 / `len=2048` packet with `value[1024]=K`. The
receiver casts the bytes it actually received to `struct dhcpv6_packet` and
runs the four verbatim tag-2.0 functions. Report:
`reports/connman2shell-wireloop.md`.

From the repository root, replay from an isolated copy so tracked evidence is
untouched:

```sh
T=$(mktemp -d /tmp/connman-loop.XXXXXX)
mkdir -p "$T/frontier/connman2shell"
cp -a lab/connman2shell/wireloop "$T/"
cp -a lab/frontier/connman2shell/src "$T/frontier/connman2shell/"
bash "$T/wireloop/run.sh"
bash "$T/wireloop/retarget.sh"
```

Expect rc 0 and `SUMMARY=30 PASS / 0 FAIL` (observed three consecutive runs
by the author, and once from the isolated copy above on 2026-11-23): four
source SHA-256 pins plus four extracted-function pins are asserted on every
run. The attack output carries `CLI SENT=2056 PKTLEN=2056 DST=127.0.0.1:`,
`SRV BOUND=127.0.0.1: RECV=2056` and `WIREPARSE OLEN=2048 COUNT=1 OFFSET=8`;
ASan reports `stack-buffer-overflow`, `READ of size 1` through `get_domains`
← `get_dhcpv6_option_value_list` ← `get_dhcpv6_request` ← `run_chain` ←
`server_body`, with the same 127-byte delta as W1/W2. Fixed snapshot and the
8-byte safe DOMAIN_LIST both give `CHAIN DONE STATUS=0`, exit 0 and no ASan.
Plain canary outcomes are informational (`OBS`, ASLR-dependent); the observed
mix from the isolated copy was `store=7 none=5 crash=0 total=12`.

`retarget.sh` solves K from the live receiver's frame chain at the
`get_domains()` breakpoint; expect `RETARGET_K=0x67 HITS=5/5` and a hardware
watchpoint on the saved return-address byte of
`get_dhcpv6_option_value_list` reading `BEFORE=ae AFTER=2e` in each run.
That byte is the fixed `.`, K is layout-specific (the socket receiver adds a
frame), and there is no connmand daemon, hostile remote input, pointer,
marker or command; grade stays rung 3 plus scoped rung 4. The lane's
`.gitignore` keeps generated slices, binaries and build logs out of Git; the
`.out` files are tracked.

## Admitted lane limb — 2026-11-23 02:0xZ connman2shell W5 real object

`reports/connman2shell-realobject.md` removes the earlier "full build is
blocked by missing dbus-1/libmnl dev packages" caveat: that was true of the
unprovisioned host, not of a lab-local dependency prefix. From the repo root,
`bash lab/connman2shell/realobj/build.sh` asserts the three frontier pin
hashes, `apt-get download`s eight `.deb` files (no install, no sudo),
extracts them under `lab/connman2shell/realobj/deps/`, copies the pinned tree
into that ignored prefix, runs `autoreconf -fi` on the copy and configures
three out-of-tree builds (plain, ASan, fixed ASan). Configure found dbus-1
1.14.10, libmnl 1.0.5, xtables 1.8.10 and libnftnl 1.2.6; `make -j2` linked
`src/connmand` plain 1,319,488 B (`5aee902c…fec1c`), ASan 7,309,184 B
(`d5aeb7ee…2ec`) and fixed ASan 7,309,848 B (`96521172…779e`). The pinned
tree is never modified; the Miu-patched file used for the fixed build is
SHA-asserted (`d252cf01…5c0e`).

`bash lab/connman2shell/realobj/probe.sh` → rc 0, `PROBE TOTAL 12 PASS /
0 FAIL`. It prints `BIN asan sha256=d5aeb7ee9d6d4819b176256208030165eeb7ddd210a5a48485d873536005b2ec`
and `BIN fixed sha256=96521172de5e15e11d2c21e3810d635ededd6bcf703d9096a7eee4555058779e`,
then the four probes `asan attack rc=1` (expected ASan abort), `asan safe
rc=0`, `fixed attack rc=0`, `fixed safe rc=0`. The attack allocates a
2048-byte value of `0xff` with `value[1024]=0x80` in the inferior and calls
the static `get_domains()` under gdb; expect `AddressSanitizer:
stack-buffer-overflow`, `READ of size 1`, top frame `get_domains …
gdhcp/client.c:2223`, object `'dns_name' (line 2214)` at `[48, 1074)` and
`Memory access at offset 1201` — the same 127-byte delta as every earlier
harness, now in the linked object. Fixed ASan and both well-formed 8-byte
DOMAIN_LIST cases have no ASan report. The plain `-O2` disassembly summary
in `evidence/geometry-summary.txt` shows `strncpy@plt` and `fs:0x28`
(stack canary). W6 (`bash lab/connman2shell/realobj/canary-boundary.sh`, 9 PASS
/ 0 FAIL) measured the boundary in the real object: the canary is at
`dns_name+1032` (`rsp+0x418`), K=7 reads its zero low byte at frame offset
1080 and the walk stops, K=0x80 steps over to offset 1201. This is a
structural negative for W1's synthetic-canary byte-run claim; a larger K can
step into a caller-frame byte but the store there is still unobserved. The
private-netns daemon was not run (CAP_SYS_ADMIN and loopback-only scope).

This is a debugger-forced call: no running daemon, natural DHCPv6 REPLY call
chain, observed store in the production object, pointer, marker, command or
rung 5. Root-service impact stays an advisory claim. Scripts, geometry
summary and `evidence/probe-*.out` are tracked; `deps/`, `build-*/` and the
copied source tree are gitignored and regenerate with `build.sh`. A docs
replay observed the 12 PASS result and both binary hashes above.

## Admitted frontier lane — 2026-11-23 01:0xZ gdbserver2shell

Frontier re-opened the previously held gdbserver lane at 01:01Z with brief
`reports/frontier-gdbserver2shell.md`, site charter and seed wall, and pinned
upstream bytes plus a derived fixed snapshot in
`lab/frontier/gdbserver2shell/PROVENANCE.md`. The vulnerable pin is
`binutils-gdb` HEAD `633ae02c4ea8f87c670f7192804349860cfa291d`; the "fixed"
snapshot is that file with Andrew Burgess's 2026-11-16 gdb-patches hunk
applied, because the fix is posted but not merged and no tagged fixed release
exists. The admission harness below is local and direct-call: it starts no
gdbserver and opens no socket. The W1/W1b limbs below do both; W2 adds a
plain-build readback and forged call.

From the repository root, replay from an isolated copy so staged evidence is
untouched:

```sh
T=$(mktemp -d /tmp/gdb-replay.XXXXXX)
cp -a lab/frontier/gdbserver2shell/. "$T/"
bash "$T/harness/run.sh"
```

`run.sh` re-extracts the verbatim 61-line vulnerable and 71-line fixed
`cmd_qtdpsrc()` slices plus `ishex`/`unpack_varlen_hex` from the saved pinned
files and asserts eight SHA-256 pins on every run before compiling gcc 13.3.0
and clang 18.1.3 ASan variants and a plain canary variant. Expect rc 0,
`SUMMARY=60 PASS / 0 FAIL` and
`NORMALIZED_HASH=0c9b837e5300ac744b133e6668179cda410520177d87b859c99cac9af1c1db73`.
The operator observed exactly those values at admission on 2026-11-23 from a
fresh `/tmp` copy, matching frontier's clean-archive replay. No witness
verdict exists for this second harness yet.

Expected bytes: the crafted packet is `QTDPsrc:1:0:cond:0:1:<hex>` (RSP
numbers are hex, so `SLEN=1` allocates 2 bytes) with N=8/32/64/128 decoded
pattern bytes. Both compilers report `AddressSanitizer: heap-buffer-overflow`,
`WRITE of size 1`, `0 bytes after 2-byte region`, frames `hex2bin` →
`cmd_qtdpsrc` → `main`. The plain 64 KiB `0xEE` arena reports
`WRITTEN=N-2 FIRST=2 LAST=N-1 PATTERN_OK=1` at N=32/64, so every chosen byte
lands past the allocation. The fixed snapshot returns `RC=0 REPLY=E01
LIST_LEN=0` on the attack and the well-formed packet returns `RC=0 REPLY=OK
LIST_LEN=1` on both pins, with no ASan report. The `hex2bin` decoder is a
faithful reimplementation, not verbatim GDB source; all allocation and length
decisions come from the verbatim slices. No pointer, marker, command or rung
5 is claimed. Status: `reports/gdbserver2shell-status.md`.

### Admitted lane limbs — 2026-11-23 01:1x–01:4xZ gdbserver2shell RSP and real build

`rsp/wire_driver.c` extends the harness to a checksummed `$QTDPsrc:...#xx`
frame sent over a 127.0.0.1 socket to a server that acks `+`, calls the
verbatim pinned `handle_tracepoint_general_set()` and then `cmd_qtdpsrc()`.
From the isolated copy above, replay with `bash "$T/rsp/run.sh"`. Expect rc 0,
`SUMMARY=70 PASS / 0 FAIL` and
`NORMALIZED_HASH=f25a563e0b06136e1dec12d2dbe70c593dfae5aca9aaa851f3e337d1c29331f2`.
ASan on g++ and clang++ gives `heap-buffer-overflow`, `WRITE of size 1`,
`0 bytes after 2-byte region`, frames `hex2bin` → `cmd_qtdpsrc` →
`handle_tracepoint_general_set`; the fixed snapshot replies `E01` and the
safe packet `OK`, both without ASan. On stock glibc a two-hole tcache groom
lets the decoded length select the adjacent bytes reached (N=8 intact, N=32
victim size and `type` low byte, N=48 `next`, N=64 all three `source_string`
pointers); with a verbatim `process_info_private` slice as victim, N=64 writes
chosen `0x504f4e4d4c4b4a49` into `thread_db` at offset 8. Safe and fixed
controls stay intact; the simpler one-hole groom aborted with `malloc():
corrupted top size` and is preserved as a negative. This is placement
feasibility, not a call through the pointer.

`rsp/build-gdbserver.sh` provisions the exact 633ae02 HEAD source, builds a
gdbserver-only ASan binary and a fixed control, then restores the vulnerable
binary and a clean source tree. It needs network provisioning (sourceware
clone) and a local build; both are outside the replay itself. With those
binaries in `lab/build/gdbserver-633ae02-asan/gdbserver/`:

```sh
bash lab/frontier/gdbserver2shell/rsp/live_verify.sh \
  lab/build/gdbserver-633ae02-asan/gdbserver/gdbserver \
  lab/build/gdbserver-633ae02-asan/gdbserver/gdbserver-fixed
```

Expect `LIVE_SUMMARY=16 PASS / 0 FAIL` and
`LIVE_NORMALIZED_HASH=5701a8746f6b5ed7dc43eadef6b4b938f85af6410a44e5d2105537929687de42`.
W3 normalized the compile-time source path in `live_verify.sh`; the earlier
`b646cc08…` value differed across build directories and is superseded.
The loopback client acks every reply; `QTDP:1:0:E:0:0` creates a tracepoint,
then `QTDPsrc:1:0:cond:0:1:` with 64 chosen bytes produces ASan `WRITE of
size 1` in `hex2bin (gdbsupport/common-utils.cc:465)` ← `cmd_qtdpsrc
(gdbserver/tracepoint.cc:2547)`, server exit 134; safe `SLEN=16` replies `OK`
with exit 0 and the fixed binary rejects with `E01`, both ASan-clean. A client
that did not ack the replies desynced the session and reached no handler; that
negative is preserved in `PROVENANCE.md`. The same pin built with default
CFLAGS (`lab/build/gdbserver-633ae02-plain/gdbserver/gdbserver`) and run
through `rsp/live_run.sh` with `attack 64` answers `OK` to `QTDPsrc`, `E01` to
`qGetTLSAddr` and dies with `SERVER_RC=139` at teardown; the safe `16` case is
`CLIENT_RC=0 SERVER_RC=0`. The `E01` means no thread_db was loaded, not an
executed indirect call. At W1b's time neither live build yielded a readback,
forged pointer call, marker or command, so rung 3 on a live wire and rung 4 at
the groomed scope only; W2 below supersedes that boundary on the plain build,
and witness replay is still outstanding.

### Admitted lane limb — 2026-11-23 02:1xZ gdbserver2shell W2 plain-build rung 4

With the plain 633ae02 binary at
`lab/build/gdbserver-633ae02-plain/gdbserver/gdbserver`,
`bash lab/frontier/gdbserver2shell/rsp/plain_verify.sh` replays three loopback
cases (attack N=64, well-formed N=16, short N=8). Expect rc 0, `6 PASS /
0 FAIL` twice, normalized hash
`f8bb0fd0692a906dcde774bbc1f9de86a117ac8f7991c6aa6347eb9dcf451de9`: attack
answers `QTDPsrc_REPLY=OK` then dies `SERVER_RC=139` at teardown, while both
controls exit 0 with no debugger attached.
`bash lab/frontier/gdbserver2shell/rsp/gdb_heap_probe.sh <binary> attack 64`
reads the natural layout under gdb 15.1 without forcing the call: the 64 bytes
overwrite the adjacent live `tdesc_feature` vptr at `...61c480`
(`vtable for tdesc_feature + 16`) to `0x4847464544434241` and the next chunk
size to `0x605f5e5d5c5b5a59`; N=8 leaves it intact, N=32 faults. Dumps are in
`rsp/evidence/gdb-heap-*.log`.
`bash lab/frontier/gdbserver2shell/rsp/gdb_marker_probe.sh <binary> <port> <tag> <payload>`
sends a second 64-byte packet that preserves the chunk size, points the vptr
inside the object and installs `abort@plt` at fake-vtable `+0x10`; the
destructor's `call *%rax` gives SIGABRT twice, while the same-length control
carrying the original four words exits 0 (`rsp/evidence/marker-marker-{1,2}.log`,
`marker-control-3.log`). All wire clients hit 127.0.0.1 only; raw logs and
per-run `.out` files under `rsp/evidence/` are committed. Witness W137 (#2085)
reproduced the W2 mechanism in its own plain pinned build (6 PASS / 0 FAIL
twice, byte-identical hash), changing only the vptr field to that build's
object+8; the wire bytes must be re-derived per build for both the gdb-fixed
load base and the heap object offset. W4's `rsp/aslr_off_verify.sh` removes the
debugger: under `setarch -R` with the recorded invocation a loopback-client
forged `abort@plt` call fires with no gdb (3 PASS / 0 FAIL twice,
`SERVER_RC=134`); short N=8 and well-formed N=16 exit 0. No lab-chosen command,
no wire-only command side effect, no `thread_db` call (`qGetTLSAddr` stays
`E01`) and no rung 5 — `abort()` is a marker, not a command. Author-only;
details in `reports/gdbserver2shell-status.md`.

## Admitted frontier lane — 2026-11-23 01:3xZ erlang2shell

Frontier handed over W131 at 01:30:22Z (DM #2033) with brief
`reports/frontier-erlang2shell.md`, site charter and seed wall, and pinned
vulnerable/fixed `external.c` plus fix patch in
`lab/frontier/erlang2shell/PROVENANCE.md`. Its two-pane inner tmux window
already existed at index 23, reusing the gap left by gdbserver2shell's
retired duplicate; admission created no second window.

From the repository root, replay from an isolated copy so staged evidence is
untouched:

```sh
T=$(mktemp -d /tmp/erlang-replay.XXXXXX)
cp -a lab/frontier/erlang2shell/. "$T/"
bash "$T/harness/run.sh"
```

`run.sh` re-extracts four verbatim pinned slices and asserts all source,
patch, slice and driver SHA-256 pins before compiling gcc 13.3.0 and clang
ASan variants plus plain-canary variants. Expect rc 0, `PASS=60 FAIL=0` and
`TRACE_SHA256=8517d3e127b0b6ded35b030fea3f6728ac1e7e34416a8c65efab21feece06c88`.
The operator observed exactly those values at admission on 2026-11-23 from a
fresh `/tmp` copy, matching frontier's clean-archive replay. No witness
verdict exists yet.

Expected bytes: wire arity `0x80000000` validates as 2147483648 and decodes
as −2147483648, so the modelled `hp += n` moves the heap pointer backwards by
17,179,869,184 bytes; vulnerable validation returns 2147483649 words while
the fixed variant rejects with −1. Both compilers report
`AddressSanitizer: heap-buffer-overflow`, `WRITE of size 8`, `8 bytes before
64-byte region` in the modelled consumer. High-bit arities −2/−3/−4/−8 words
place chosen `0x4141414141414141` byte-exact at negative offsets
32760/32752/32744/32712. Fixed rejects and skips the write; safe arity 3
stays in bounds. At admission no BEAM build or VM call was claimed; the
real-VM limb below adds built emulators but no live-VM corruption or rung 5.
Status: `reports/erlang2shell-status.md`.

## Admitted lane limb — 2026-11-23 02:0xZ erlang2shell real VM

`reports/erlang2shell.md` adds a real pinned erts build to the harness lane.
From `lab/erlang2shell/otp-vuln`, checked out at the vulnerable fix parent
`c388a2d1b3f9918652276d4798692dd4d8ef97fc`, configure with
`./configure --prefix=$PWD/install --without-javac --without-odbc
--without-wx --without-ssl`, then `make -j2 TYPE=asan FLAVOR=emu` for
`bin/x86_64-pc-linux-gnu/beam.asan.emu` (SHA-256 prefix `10c41dc9…`, 13
`__asan_*` symbols, links `libasan.so.8`) and `make -j2` for `beam.smp`
(prefix `25e53242…`, no ASan symbols). The default build stops at
`lib/debugger` because `--without-wx` leaves `wx_object` undefined; the
emulator, `bootstrap/bin/start.boot` and the preloaded `ebin` trees are all
the driver needs. From the repo root, `bash lab/erlang2shell/run-real.sh`
compiles `lab/erlang2shell/b2t_driver.erl` and runs both emulators through
`erlexec` with no listener, network or large allocation; expect:

```
MODE=opt ARGS= RC=0
small_80000000 RC=badarg
small_fffffffe RC=badarg
forged_compressed RC=badarg
safe_positive_3 RC=ok TERM={1,2,3}
MODE=asan ARGS=-emu_type asan -emu_flavor emu RC=0
(same four case lines)
--- asan reports ---
(clean: no ASan report)
```

The attack ETFs are `<<131,105,128,0,0,0,97,42>>` (advisory arity), the same
term with harness arity `0xfffffffe`, and a COMPRESSED envelope declaring
`dest_len=0x80000000` around the six-word safe term. In the pinned
`external.c` `decoded_size()` applies `CHKSIZE(n)` against the real buffer
end (lines 6041–6051), so every negative-as-int32 arity is rejected before
`dec_term`; `binary2term_prepare()` (1767–1783) requires a declared
compressed length equal to the measured inflated size, so the forged header
is badarg too. The advisory route would need ≥2 GiB of *real* inflated bytes
and, via `HAlloc(p, size)` at `erl_message.c:1193`, ~17 GiB of process heap
before `dec_term`; that allocation was deliberately not attempted on this
shared host and the outcome stays UNKNOWN, not a pass. The harness rungs 1–4
and its 60 PASS / 0 FAIL replay stand unchanged; no adjacent-object identity,
pointer control, marker, command or rung 5. The `otp-vuln/` tree and `*.beam`
are gitignored and rebuild with the configure/make commands above; the driver
and runner are tracked and the four result lines are regenerated by
`run-real.sh`. A docs replay observed both emulator modes, all four case
lines and no ASan report.

## Admitted frontier lane — 2026-11-23 02:4xZ minisnmpd2shell

Frontier handed over W132 (DM #2079) with brief
`reports/frontier-minisnmpd2shell.md`, site charter and seed wall, hash-pinned
vulnerable/fixed `protocol.c` plus fix patch and loopback wire scripts in
`lab/frontier/mini-snmpd/PROVENANCE.md`. Its two-pane inner tmux window
already existed at index 100 (0..99 occupied), so admission created no second
window and the registry stayed at 101 entries / 101 unique names.

From the repository root, replay from an isolated copy so staged evidence is
untouched:

```sh
T=$(mktemp -d /tmp/minisnmpd-replay.XXXXXX)
cp -a lab/frontier/mini-snmpd/. "$T/"
bash "$T/harness/run.sh"
```

`run.sh` re-extracts the verbatim pinned `decode_oid` and `decode_str`
slices, asserts all source/patch/slice/driver SHA-256 pins before compiling
gcc 13.3.0 and clang ASan plus plain-canary variants, and opens no socket.
Expect rc 0, `PASS=43 FAIL=0` and
`TRACE_SHA256=0146b9b59168bb92ad4d725d7b1f162aa6de47661674f0086a0bf02e838e9859`.
The operator observed exactly those values at admission on 2026-11-23 from a
fresh `/tmp` copy, matching frontier's clean-archive replay. No witness
verdict exists yet.

Expected bytes: a declared OID BER length of 4000 against a 2048-byte packet
wraps `*pos >= (size - len + 1)` to 18446744073709549665, so the walk reaches
offset 4007 and fills 18 subids; the fixed pin returns `RC=-1` at
`POS_AFTER=8`. Both compilers report `AddressSanitizer:
heap-buffer-overflow`, `READ of size 1`, `0 bytes after 2048-byte region` in
the verbatim `decode_oid`. Canary bytes at offset 2048 land byte-exact in
`SUBID2_HEX` (0x5a and 0x3c across runs); fixed and in-bounds safe inputs are
clean. The plant-started loopback ASan daemon on 127.0.0.1:16161 logs
`overflow for OID byte` on the vulnerable pin, fixed 16162 rejects with
`underflow for oid`, and a 35-byte GET is clean on both. Preserved negative:
no wire-level ASan report because `client->packet` sits inside a larger
global struct and the 20-subid cap stops the walk. Under gdb the daemon reads
18 bytes past the logical 2048-byte packet and recovers the adjacent
`g_udp_client.size` byte `0x08` into `subid_list[5]`; declared lengths
2047–2049 reject at the guard while 2050/65535 saturate at 18 reads. Grade
stays harness rungs 1–4 plus scoped rung 4 in the real daemon; witness W138
replayed the harness (43 PASS / 0 FAIL, byte-identical hash) and the full
18-read gdb dump from `git archive 4096b47`, ESTABLISHED at that labeled scope
with no grade change. No pointer, marker, command or rung 5.
Status: `reports/minisnmpd2shell-status.md`.

## Admitted frontier lane — 2026-11-23 02:4xZ ettercap2shell

Frontier handed over W133 (DM at 02:44:47Z, staging commit `55afa77`) with
brief `reports/frontier-ettercap.md`, site charter and seed wall, pinned
vulnerable/fixed `ec_gg.c` plus fix patch and raw evidence in
`lab/frontier/ettercap2shell/PROVENANCE.md`. Its two-pane inner tmux window
already existed at index 101 (0..100 occupied), so admission created no second
window and no registry change was needed.

From the repository root, replay from an isolated copy:

```sh
T=$(mktemp -d /tmp/ettercap-replay.XXXXXX)
cp -a lab/frontier/ettercap2shell/. "$T/"
bash "$T/harness/run.sh"
```

Expect rc 0, `PASS=58 FAIL=0` and
`TRACE_SHA256=d650b34e3bbc1ea336c60d2cb4b9c7743fdc4657b7d8e0d07c7e1bc1c1027b7a`.
The operator observed exactly those values at admission from a fresh `/tmp`
copy, matching frontier's clean-archive replay. No witness verdict exists yet.

Expected bytes: a 30-byte `tbuf3` passed to an unsized `gg_get_version()`
receives `sprintf` of a chosen `u_int32` plus two flag-selected literal
`strcat`s. `version=0x44000042` gives `STR_LEN=43`, `OOB_COUNT=14`; gcc and
clang ASan report `heap-buffer-overflow WRITE of size 13`, `0 bytes after
30-byte region`, frame `gg_get_version`. The fixed helper composes into a
128-byte stack buffer and ends with `snprintf(str, size, "%s", buf)` with
size 64, writing 29 chars in 30 and 43 in 64 bytes, ASan-clean; `0x2a` writes
3 chars cleanly on the vulnerable helper. Both flag bits select the exact OOB
tail `69 6f 20 2b 20 65 72 61 6f 6d 6e 69 78 00`, and chosen hex digits land
byte-exact at offsets 11..18 **inside** the object — so the crossing bytes are
fixed suffix literals, not arbitrary attacker bytes. No pointer control, marker,
command or rung 5; the advisory's AV:A vector is preserved.

The real-dissector lane (`reports/ettercap2shell-livedissector.md`, commit
`fcec372`) moves the same fault onto unmodified ettercap v0.8.4.1 built with
clang 18 ASan (`CMAKE_BUILD_TYPE=Debug`, `-fsanitize=address -g -O1
-fno-omit-frame-pointer`; the cmake switches and both `ec_gg.c` SHA-256 pins
are in `live-evidence/README.md`). From `lab/frontier/ettercap2shell/live`,
run `python3 mkggpcap.py gg-vuln.pcap` (or `mkcontrols.py`), then from
`ettercap-0.8.4.1/build-asan` run
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./src/ettercap -T -q -r ../../gg-vuln.pcap -i lo`
and finally `python3 liveinject.py gg-vuln.pcap` back in `live/`, which sends
the frame verbatim with `AF_PACKET` on `lo` and stops the process.
Expect `WRITE of size 13` at `gg_get_version:673`, reached via
`dissector_gg:360` before the length guard, 0 bytes after the 30-byte `tbuf3`
allocated at `:356`, both offline and live through `pcap_loop` ← `capture:90`.
The two extent packets (`0x44000018`, `0x04000042`) give `WRITE of size 12` at
`:676`, while safe version `0x0000002a`, wrong type, server direction and the
fixed v0.8.5.1 build are clean. Injection is same-host on `lo`; an
adjacent-network sender is untested and AV:A stays. Several control runs log
an unrelated ASan double-free during shutdown and offline "Joining already
joined thread"; neither is in the GG path. Status:
`reports/ettercap2shell-status.md`.
