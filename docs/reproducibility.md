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
| Ruby2Shell | [report](../reports/ruby2shell-investigation.md) | `bash lab/ruby2shell/provision.sh` | plain build `lab/build/plain/ruby-3.4.12-plain/bin/ruby` (recipe in report); ASan build `lab/build/ruby-3.4.12-asan` | `lab/repro/ruby2shell-rung1.rb`, `stageA.rb`, `stageC.sh`, `stageB-http.sh`, `stageB-rails.sh`, `bash lab/repro/ruby2shell-stageC-http.sh 3 2` with `stageC-http.ru`; rung 5 `bash lab/repro/ruby2shell-rung5-http.sh attack <tag>` (repeat with distinct tags), then `control <tag>` and `fixed <tag>` (plain 3.4.13 build recipe in the report; expect distinct markers on attacks, none on controls) (Sinatra request-thread Stage C: 3/3 attacks read chosen bytes at the nominated address in the HTTP response, 2/2 controls clean; the process aborts in worker-thread teardown after readback — depth result, no grade change); stock Rails follow-up: `bash lab/repro/ruby2shell-stock-rails-setup.sh`, then `ruby2shell-stock-rails.sh attack|control|fixed <tag>` with the exact N=524 environment in the addendum below; 3/3 attacks abort, safe/fixed controls survive, no RCE/persistence; copy-out lane: `valgrind --error-limit=no lab/build/plain/ruby-3.4.12-plain/bin/ruby -e 's="\xDF".b*21; s.force_encoding(Encoding::ISO_8859_1); p s.upcase.bytesize'` — N=21 shows `Invalid write of size 1` at `case_map (iso_8859_1.c:293)` and `Invalid read of size 2` via `rb_str_casemap (string.c:7857)`, `outlen=42`; N=20 clean, `outlen=40`. The read byte is the same fixed `0x53`, so this is rung-3 class, not a leak or rung 4 |
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
| Imgproxy2Shell | [brief](../reports/frontier-imgproxy2shell.md) | CVE record `CVE-2026-123614` (`ab297c9d…`), GHSA-hff9-5pqw-6w9f (`d6de60b2…`), fix `a821b6a4…` (patch `c5db17e9…`), vulnerable `icoload.c` v4.0.15 (`2eabd58d…`) / fixed v4.0.16 (`67b4a9c2…`); every URL and hash in `lab/frontier/imgproxy2shell/PROVENANCE.md` | `bash lab/frontier/imgproxy2shell/run.sh <outdir>` — `gen_driver.py` verifies every pin and copies the affected (`:154-164`) and fixed (`:162-185`) loader statements verbatim under `#line`, then builds vulnerable, fixed and ASan drivers; gcc `-O0 -g` | Operator admission replay ~10:53Z from a clean `git archive HEAD` extraction: 10 PASS / 0 FAIL, `ALL CHECKS PASS rc 0`, two independent five-run groups both `sha256=6b0391599520bc899f169268e08699155888f0018274f9c2a2e12bcd31c2dad5`; rungs 1/2/3 ESTABLISHED, rung 4 INSTRUMENTED; witness #813/#814 independent clean-archive replay ESTABLISHED AS CLAIMED, grade unchanged (10 PASS / 0 FAIL, same digest). W204 (tape #3734) graded W9's allocator blocker ESTABLISHED AS LABELED from clean `git archive 5af51c33`; W10 (`76df8b76`) identifies the aborting free as `g_hash_table_unref` under `vips_argument_table_destroy` (`libvips/iofuncs/object.c:573`) and finds no wire-head consumption with `SIZE=0x35`. Both author-side/unwitnessed where labeled; no r5 |
| Firebird2Shell | [brief](../reports/frontier-firebird2shell.md) | CVE record `CVE-2026-33337` (`b6ac3a4f…`), GHSA-89mq-229g-x47p (`451f9b62…`), master fix `2a5303dc…` / v5.0.4 fix `62fc37ed…`, vulnerable `xdr.cpp` v5.0.3 (`b28b1aaa…`, blob `555e6e1f…`) / fixed v5.0.4 (`426a7a07…`, blob `a5698288…`), plus `protocol.cpp` / `dsc.h` pins; every URL and hash in `lab/frontier/firebird2shell/PROVENANCE.md` | `bash lab/frontier/firebird2shell/run.sh <outdir>` — pins are recorded with SHA-256 in `PROVENANCE.md` and copied lines are verbatim (witness #818); `gen_driver.py` does not itself hash-check the pinned files. It copies the `dtype_cstring` cases (`:206-221` affected, `:206-223` fixed) verbatim under `#line`, then builds vulnerable, fixed and ASan drivers; gcc | Operator admission replay ~11:08Z from a clean `git archive HEAD` at `4592fbf`: 10 PASS / 0 FAIL, `ALL CHECKS PASS rc 0`, two independent five-run groups both `sha256=807b47150a58fe88094966b0affed9b35604a7b3730c68f53eeaa61057a25fbf` — rung 1 `copy_len=60000` unclamped into a 32-byte slot, rung 2 chosen bytes at `buffer+40` / `+100`, rung 3 ASan `WRITE of size 60000` at `xdr_v5.0.3:216`, rung 4 instrumented `0x5a5b5c5d…` readback and `PROT_NONE` guard fault; fixed v5.0.4 clamps to 31 and is ASan-clean on hostile and benign inputs. No live `fbserver`, wire packet, stock neighbour, pointer or execution; witness #818 independent clean-archive replay ESTABLISHED AS CLAIMED, grade unchanged (10 PASS / 0 FAIL, same digest). |
| Rtp2httpd2Shell | [brief](../reports/frontier-rtp2httpd2shell.md) | GHSA-35fv-hf3m-2pqc advisory (`eb55aed5…`, no CVE), signed fix `f0fcfc19…`, raw `rtsp.c` at v3.14.1 (`96eb3b4a…`, affected) / v3.14.2 (`b355f4af…`, fixed) plus `rtsp.h`, `buffer_pool.{c,h}` and `zerocopy.c`; every URL and hash in `lab/frontier/rtp2httpd2shell/PROVENANCE.md` | `bash lab/frontier/rtp2httpd2shell/run.sh <outdir>` — `gen_driver.py` hash-checks all eight pins and copies the fault lines verbatim under `#line`, then builds vulnerable, fixed and ASan drivers; gcc `-O0 -g` | Operator replay 11:26Z from committed HEAD: 10 PASS / 0 FAIL rc 0, two five-run groups both `sha256=11a76ab0bcb678868229982cb64a826f0367f29d8c4b3daf9eb84eb5804ceb13`; all eight pins matched by SHA-256 and the `:1800` / `:1825` / fixed `:1801` lines read directly. Witness #831 independently replayed from a clean `bb00268a` archive with the same digest and returned ESTABLISHED AS CLAIMED, grade unchanged; its three supporting citation-line nits were folded into the brief/PROVENANCE at `0a7e96a`. |
| Vrpn2Shell | [brief](../reports/frontier-vrpn.md), [wire rung-3 / rung-4 report](../reports/vrpn2shell.md) | CVE record `CVE-2026-123200` (`f4ee3212…`), fix commits `0da5b0b…` / `c893b58…`, pinned `vrpn_Connection.C` at `79deb000…` (`9eaa1045…`), fix-commit tarball (`b5258e99…`); every URL and hash in `lab/frontier/vrpn2shell/PROVENANCE.md`, including the superseded 28-byte header hash; W5 read-only upstream release lookup in `lab/frontier/vrpn2shell/UPSTREAM-RELEASE-LOOKUP.md` | `bash lab/frontier/vrpn2shell/run.sh <outdir>` and `gdb-wire.sh <outdir> <port> <index>` now send the required 24-byte header (the old 28-byte header pinned `i=0` for every index); live wire ASan: `bash lab/frontier/vrpn2shell/probe-gdb.sh <outdir> 13901 100`, expect `WRITE_SITE_HIT i=100` and ASan `stack-buffer-overflow WRITE of size 1` at real `vrpn_Connection.C:4554` in the plant-started loopback server; plain saved-rip: `bash lab/frontier/vrpn2shell/probe-plain-rip.sh <outdir> 13905 120`, expect `saved_rip` low byte `0x…88 → 0x…00` and SIGILL with canary and rbp intact; second sink TYPE_DESCRIPTION (message type -2): `VAR=type_name LINE=4482 MSGTYPE=-2 bash lab/frontier/vrpn2shell/probe-gdb.sh <outdir> 13911 100`, expect `WRITE_SITE_HIT i=100` at `handle_type_message:4482` and ASan `WRITE of size 1` with shadow frame `[112,212) 'type_name'` and access at offset 212 (short index 4 and fixed `:4486` at index 100 are clean controls); plain: `VAR=type_name MSGTYPE=-2 LINE_PRE=4482 LINE_POST=4484 bash lab/frontier/vrpn2shell/probe-plain-rip.sh <outdir> 13914 120`, expect `saved_rip 0x…d88 → 0x…d00` and SIGILL (fixed plain 120 clean). `--msgtype` defaults to -1, so W1 commands are unchanged; gitignored `out-type-*` gdb logs regenerate with those two commands. Direct ASan harness: `g++ -fsanitize=address -fno-omit-frame-pointer -g -I lab/frontier/vrpn2shell/src/vrpn-07.36 lab/frontier/vrpn2shell/harness/handler_direct.cpp lab/frontier/vrpn2shell/build-asan-07.36/libvrpnserver.a -o handler_direct` then `handler_direct 100`. W21 outer-frame sweep (author-only, plain `-O0` server): `bash lab/frontier/vrpn2shell/probe-w21-large.sh <outdir> <port> 512` (gdb PRE/POST at `vrpn_Connection.C:4554`) and `bash lab/frontier/vrpn2shell/probe-w21-smash.sh <outdir> <port> 512` (identifies `__stack_chk_fail`), both calling `python3 lab/frontier/vrpn2shell/wire_inject.py --index <index> --port <port>`; coarse and fine sweeps use the same injector with indices 320..8192 and 512..520, with fixed/`-O2` binaries passed as the optional `BIN` argument to `probe-w21-large.sh` | Observed W98: ASan `WRITE of size 1` at real `vrpn_Connection.C:4554` for indices 100/128/-256; fixed commit has no write-site fault; gdb proves a real TCP message reaches `:4535`. W1 author-only correction: the earlier "live-server sweep negative, different frame layout" was the injector's 28-byte header; wire rung 3 and the plain-build saved-rip rung-4 boundary are now observed at the labeled g++ 13.3.0 Debug layout. W2 (author-only) repeats both limbs over real loopback TCP through type -2 into `type_name[i] = '\0'` at `:4482`: index 100 ASan fault in `handle_type_message`, index 120 plain saved-rip zeroing and SIGILL, with short-input, fixed-commit and fixed-plain controls clean. Byte is a fixed NUL at a chosen offset, no chosen byte or pointer control, no command side effect, no rung 5. W21 expects index 512 DEAD rc 134 with `*** stack smashing detected ***`, 512-517 DEAD / 518-519 ALIVE / 520 DEAD, TYPE 512 rc 134, fixed 512, short 4 and `-O2` 256/384/512 ALIVE, and 16384/32768/65536 DEAD rc 139 with cause **UNKNOWN** (no gdb landing mapped; e41b2da); outer-frame saved rbp changes `0x…dbc0` → `0x…db00` and the fixed build writes only the NUL at the chosen offset — author-only, no grade change. Admitted under standing #6 (~01:1xZ in task.md); witness W115 (#1453) ESTABLISHED the wire rung-3 scope and W135 (#1985) ESTABLISHED the labeled lab-patched rung-4 marker scope; the W1/W2/W3/W6/W7/W10 consequence claims remain unwitnessed. W5 resolves the released-fixed UNKNOWN to an authoritative negative by read-only metadata lookup: `git ls-remote --tags` has 35 refs with no 07.37/07.38/07.39 tag, the GitHub releases API lists v07.36 (2025-06-28) as newest, the v07.39 tarball URL is 404, and both fix commits are untagged 2026-10-22 master commits; the fixed control stays the pinned commit tarball and no build, grade or witness fact changes. |
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
| Libheif2Shell | [brief](../reports/frontier-libheif2shell.md), [status](../reports/libheif2shell-status.md) | GHSA-hpg4-g2gc-pq42, vulnerable tag `v1.23.6` (`f81f28ac…421a`), fix `9ec655f76b6fe298092aaeb063f821f53b8eb901`; five direct-call pins in `lab/frontier/libheif2shell/PINS.sha256`, real-file pins and URLs in `lab/frontier/libheif2shell/real/` and `PROVENANCE.md` | `cd lab/frontier/libheif2shell/harness && ./run.sh && ./check.sh` (stubbed direct call); real-file lane: `bash lab/frontier/libheif2shell/real/rebuild_and_run.sh SOURCE BUILD OUT [decode-only|mixed|safe|all]` (CMake/Ninja Debug, x265+JPEG plugins, ASan, driver rebuilt from pinned `reencode_sequence.cc`); W176 ceiling probes: compile `real/avif_lossless_probe.cc` against the pinned plain Release tree with the exact g++ command in that file's header (needs `ninja -C "$B" -t commands examples/heif-enc` for `$LIBS`), then `/tmp/avif_lossless_probe make/check /tmp/avif-mixed.avif`; re-run the wire lane with `bash real/run_wire.sh /tmp/w176-wire-replay`. W178 uncompressed lane: configure pinned v1.23.6 with `-DWITH_UNCOMPRESSED_CODEC=ON -DWITH_X265=ON` and `-DCMAKE_CXX_FLAGS_RELEASE='-O0 -DNDEBUG'`, `ninja -j1 libheif.a`, then `SYNTH_FIRST=1 TW=512 TH=64 /tmp/w178-reencode-unci real/neighbour/evidence/uncompressed/byte-exact.heif /tmp/w178-unci-out.heif`; `gdb -q -batch -x real/neighbour/gdb_uncompressed.cmd /tmp/w178-reencode-unci`; `python3 real/neighbour/check_uncompressed.py` | Direct-call clean archive at `366690f`: `PASS=101 FAIL=0`, trace `9468b510…e38b43`; W159/#2626 ESTABLISHED rungs 1-4 at labeled CODE/HARNESS scope. W161 real-build mixed-MJPEG file lane author-only: ASan `WRITE of size 64` past a 32783-byte plane, Release SIGSEGV on mixed input, fixed rc 2; witness W163 (#2729/#2730) ESTABLISHED rungs 1-4 at the labeled local-file/process decoder-to-x265 scope (input/driver replay, not build-from-source), and W181 reproduced the 36,879-byte allocation and 64-byte write from a different crafted file; the advisory's exact 1,155-byte input and x265 pointer claim stay untested, rung 5 UNKNOWN. W176 (author-only negatives): AV1 lossless mixed-size frame 1 is refused with `rc=8 sub=5002 ... Image size must match encoder init configuration size` and `heif-enc -A -L -S` refuses too; JPEG constant 8x8 blocks round-trip byte-exact but the SOF-patched OOB row is not independent (`a0*8, a2*16, a4*16, a6*16, a8*8`; uniform `0x70`/`0xac`), so on those codecs arbitrary-byte control stayed UNKNOWN; the six wire cases and both checkers PASS, witnesses #2752/#2869/#2897 still queued with no verdict. W178 (author-only, separate build/codec) closes that ceiling: 64 chosen bytes `11 22 33 44 55 66 77 88` x8 decode byte-exact through ISO/IEC 23001-17 and land at `plane+32768` under gdb (input SHA-256 `b585565b…a249`, `check_uncompressed.py` PASS=5 FAIL=0, plain rc 134 `double free or corruption (out)`); rung 4 at that labeled scope, first encoder-sizing frame harness-created, no witness replay or rung 5 |
| Munt2Shell | [brief](../reports/frontier-munt2shell.md), [status](../reports/munt2shell-status.md) | pinned `libmt32emu_2_8_3` tarball and third-party bytes in `lab/frontier/munt2shell/PROVENANCE.md` and `real/thirdparty/NOTES.md` | `lab/frontier/munt2shell/harness/run.sh`; `real/` CMake builds | W175/W176 source-negative folds below; witness #2781 real-library rungs 1-4; no third-party host built. W191: the second CISA exploit-tagged HackMD slug aliases the same note; its mirror has only an unexecuted, truncated illustrative trigger, no PoC bytes (`real/SECOND_POC_NOTE.md`) |
| Thrift2Shell | [status](../reports/thrift2shell-status.md), [live wire](../reports/thrift2shell-livewire.md) | pinned v0.23.0/v0.24.0 bytes and URLs in `lab/frontier/thrift2shell/PROVENANCE.md` | `lab/frontier/thrift2shell/harness/run.sh`; `live/build.sh` | W152 cap-cleared disposition below; W145/W146 UNVERIFIED, W144 the only witness-backed lane |
| Libfontenc2Shell | [brief](../reports/frontier-libfontenc2shell.md), [status](../reports/libfontenc2shell-status.md) | four out-plain revs and `PINS.sha256` in `lab/frontier/libfontenc2shell/PROVENANCE.md` | `sh realpath/xlive/run-plain-crash.sh` from `lab/frontier/libfontenc2shell`; runtime X-protocol lane `sh realpath/xlive/run-xset-fp.sh` | W177 witness #2914 clean-archive nine-line matrix below; availability-only ESTABLISHED; W180 runtime font-path injection into a running Xvfb (author-only) below |
| Libgphoto2Shell | [brief](../reports/frontier-libgphoto2shell.md), [status](../reports/libgphoto2shell-status.md) | four pins, tarball and patch hashes in `lab/frontier/libgphoto2shell/PINS.sha256` and `REAL-BUILD.md` | from-scratch ASan 2.5.34 and plain real-library builds per `REAL-BUILD.md`; harness `run.sh`/`check.sh`; W170/W171 lab hooks in `lab/frontier/libgphoto2shell/evidence/replay-vusb-{victim,normal-return}.patch` with `replay-victim_probe.c`/`replay-normal_return_probe.c` and the matching `.gdb` driver | witness #2892 rung-3-only verdict and #2763 146/0 below; W165 plain RIP probe author-only; W170 (`fcbde70`) steered a device-chosen `data=0x1122334455667788 size=0x1a2b3c4d` through real `gp_file_get_data_and_size()` in the plain real build with 24-entry tcache drain, lab canary and saved RIP, controls clean; W171 (`930ddef`) restored `camera_init`'s frame for a normal return (rc=0), drain 22, then dereferenced the real API's device-chosen pointer/length to read `M2SHELL_DEREF_MARKER_20261124` — both rung-4 author-only, unwitnessed, lab-assisted, no USB/wire/command/r5; evidence `real-plain-heap-pointer-control.out` and `real-plain-normal-return-deref.out`. W174 (`2ac219c2`) replayed W172 from clean `git archive 833729ad` (4/4 pins OK): `DRAIN=22` landed the victim before `priv` with `data=(nil)`, `DRAIN=23` restored `priv+0x4050`, rc 0 and the 29-byte marker; use the victim offset, not the drain integer, as the replay criterion (`evidence/real-plain-clean-replay.out`). Author replay, unwitnessed |
| Kicad2Shell | [brief](../reports/frontier-kicad2shell.md), [status](../reports/kicad2shell-status.md) | pins in `lab/frontier/kicad2shell/PINS*.sha256` and `kicadreader/PINS-kicadreader.sha256` | `cd lab/frontier/kicad2shell/kicadreader && sh run.sh`; `sh chosen-value.sh 84215045` for the file-controlled byte probe | `sh check.sh` 38/38 trace `fffe7341…6260`, clean `git archive 337c164`; witness #2996 replayed 38/38 from clean `3d90217`, ESTABLISHED rungs 1-4 at the labeled KiCad-own-reader scope, NOT rung 5; W179 chosen-value recipe below |
| Ndpi2Shell | [brief](../reports/frontier-ndpi2shell.md), [status](../reports/ndpi2shell-status.md) | pins and fixed-release ancestry in `lab/frontier/ndpi2shell/PINS.sha256` and `PROVENANCE.md` | `cd lab/frontier/ndpi2shell/realbuild && ./run.sh`; `harness/run.sh`/`check.sh` | W162 real-build VALUE-negative/KEY-positive, fixed 6.0 and tree-local key-reachability negative below |
| Sdlmixer2Shell | [brief](../reports/frontier-sdlmixer2shell.md), [status](../reports/sdlmixer2shell-status.md) | four pins in `lab/frontier/sdlmixer2shell/PINS.sha256`; SDL3 tarball SHA in `PROVENANCE.md` | `cd lab/frontier/sdlmixer2shell/harness/realcaller && ./run.sh && ./check.sh` | 96/0 trace `934e8337…60c0`; witness #2942 direct-call rungs 1-4 only; W179 author-only |
| Cjose2Shell | [brief](../reports/frontier-cjose2shell.md), [status](../reports/cjose2shell-status.md) | seven pins in `lab/frontier/cjose2shell/PINS.sha256` (three tarballs, fix patch, two pinned `jwe.c`, upstream `check_jwe.c`) | `cd lab/frontier/cjose2shell/harness && ./bootstrap.sh && ./run.sh && ./check.sh`; loopback wire lane `cd ../w1 && sh build.sh && bash run.sh`; W188 fptr lane from a clean `git archive 8c717a2 lab/frontier/cjose2shell`: `cd <tmp>/lab/frontier/cjose2shell && sh replay-w188.sh` | 223/0 trace `455b8494…38e9da7`, operator clean `git archive 841b716` replay exact; witness verdicts recorded: rungs 1-4 direct-call, rungs 1-3 plus byte-control synthetic consumer, NOT rung 5; W194 (#3566) independently replayed W188's groomed-fptr limb from `8c717a2` (7/7 pins, `REPLAY_W188_OK`, `PASS=223 FAIL=0`, exact trace `455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7`; `GROOM_OK=1`, `CEK_LEN_AFTER=768`, `BENIGN_MARKER_EXECUTED`, `MARKER_CALLED=1` in the vulnerable leg, 0 in safe and both fixed controls) — ESTABLISHED AS LABELED at the lab-known-address direct-call rung-4 scope, no wire/ASLR/command/r5; W181/W182 wire outcomes and 56-byte instability below; W183 jansson-object identity and hash-seed cause below. W199 (`43bd6d3e`): `cd lab/frontier/cjose2shell/w1 && sha256sum -c evidence/W199-SHA256SUMS` passes locally (36 files); an 80-byte `encrypted_key` sets a jansson string pointer to `0x4141414141414141`, reached in `__strcmp_avx2` from `_cjose_jwe_calc_auth_tag` (`jwe.c:1098`) in 8/40 plain runs, fixed rejects before the write. Recognizable non-address, author-only, unwitnessed, no r5. W220: from `lab/frontier/cjose2shell`, `sh w2/w219/run-w220-ident.sh` and `sh w2/w219/run-w220-use.sh` give 7/0 and 11/0 with `NO_LISTENER_LEFT`; the far object is the live Jansson `jwe->hdr`, whose first post-unwrap lookup fails `json_is_object()` and returns HTTP 401 without dereferencing poisoned buckets |
| Thorvg2Shell | [brief](../reports/frontier-thorvg2shell.md), [status](../reports/thorvg2shell-status.md) | CVE-2026-123367 / GHSA-mw4c-w54x-248r; v1.1.1/v1.1.2 tarballs, fix patch and `PINS.sha256` in `lab/frontier/thorvg2shell` | `python3 poc/make_poc.py && python3 poc/make_large.py && python3 poc/make_marker.py && sh harness/build.sh && sh harness/run_matrix.sh` | 88 cases; ASan WRITE-2 past the 128-byte coefficient region and chosen halfwords 0x58/0x68/0x78 at offsets 128/256/384; clean `git archive 4c4f8f8` replay exact; rungs 1-4 author-only, no witness or rung 5 |
| BusyBox2Shell | [brief](../reports/frontier-busybox2shell.md) | CVE-2026-124737, pinned 1.37.0 tarball, vulnerable/fixed `tftp.c`, one-line fix and config hashed in `lab/frontier/busybox2shell/PINS.sha256` | `sh lab/frontier/busybox2shell/run-all.sh` (five legs, loopback UDP only); W5 probe `python3 lab/frontier/busybox2shell/data_probe.py` (three legs, stock plain client, loopback UDP) | ASan WRITE-516 at `rbuf+68`, clean OACK/default-blksize/fixed controls and "MISHE-OO" gdb bytes; witness #3135 ESTABLISHED rungs 1-4 at the labeled 1.37.0 TFTP-client / loopback-wire / stock-plain scope, NO r5; W5 closes the DATA consumer's post-overflow allocation hedge with transcript `8d22cfe3…b11e6267e22c7aa3c` and a byte-identical clean `git archive 659b379` replay; rung 5 UNKNOWN |
| ImageMagick2Shell | [brief](../reports/frontier-imagemagick2shell.md), [status](../reports/imagemagick2shell-status.md) | CVE-2026-130664 / GHSA-3pf7-cjfr-3fpq, pinned 7.1.2-34/35 tarballs and both `MagickCore/stream.c` blobs hashed in `lab/frontier/imagemagick2shell/PINS.sha256` | `sh lab/frontier/imagemagick2shell/bootstrap.sh` from a clean archive (builds all three configurations, then `run-all.sh`; no network) | ASan heap WRITE past a 3-byte stream buffer in `StreamImagePixels`, same-size and fixed controls clean, chosen bytes 0x42..0x48 at offsets 3..23 under gdb; clean `git archive 7873caf` replay `REPLAY.log` `385bbe95…c01667a`; admitted 00:3xZ under standing #6 as the 123rd route. Witness #3204 (W181) replayed clean `git archive a073540`, 5/5 pins and the same `REPLAY.log` hash; witness `evidence.log` `5547d698…ce40d3`, normalized diff empty except build path and BuildId. verdict **ESTABLISHED rungs 1-4 at the labeled direct-call/in-process scope, NO r5**; file/coder reachability and the CLI `-extract` READ excluded and UNKNOWN, rung 5 UNKNOWN. NIT: the gdb bytes are the harness `0x41+(i%26)` pattern and geometry growth is harness-assigned, not attacker-chosen values. |
| Hydra2Shell (screened out) | [brief](../reports/frontier-hydra2shell.md) | CVE-2026-133274, pinned `v9.7` `6c11ce2d` and fix commit `6ab9ad86`, function blobs and hashes in `lab/frontier/hydra2shell/harness/PINS.sha256` | `sh lab/frontier/hydra2shell/harness/run-all.sh`; loopback wire recipe in `lab/frontier/hydra2shell/PROVENANCE.md` | gcc+clang ASan `negative-size-param -1` direct call and in real v9.7 `http-post-form` over 127.0.0.1, fixed/safe controls clean, gdb NUL at `tmpcookie-1`; matrix `57e16bfd…b108567b`, clean `git archive bb33f71` replay exact; rung 3 only, plain build does not crash, no window |
| CodebaseMemory2Shell | [brief](../reports/frontier-codebasememory2shell.md), [status](../reports/codebasememory2shell-status.md) | CVE-2026-114494 / GHSA-vpgh-g3jg-ggx9; pinned parent `5554f8a46abf` and fix `e69e0844dbc1` tarballs, both `src/cypher/cypher.c` blobs hashed in `lab/frontier/codebasememory2shell/PINS.sha256` | `bash lab/frontier/codebasememory2shell/bootstrap.sh` for the direct-call matrix; `bash lab/frontier/codebasememory2shell/mcp-tool/replay.sh` for the real `query_graph` tool path (verifies pins, copies the tracked grammar stub, rebuilds vuln/recover/fixed with forced `-B`, drives tracked `probe.py` over stdio) | ASan OOB READ at `cypher.c:2568` and recover-mode `WRITE of size 70` at `project_item:3379` ← `execute_return_simple:4116` into `func_bufs[32]`, 32/fixed controls clean, plain 48-item stack-smash abort, gdb chosen "MISHE-OO…" bytes at `func_bufs+16384`; matrix `f8c81a5c…7a6d`; clean `git archive a073540` replay 24/24 rows. W1's real stdio `tools/call` to `query_graph` reaches READ-8 and recover-mode `WRITE of size 68` at the same array with fixed rejecting >32 (`MCP-TOOL.md`); W3 fixed the empty fixture, added a zero-row guard and committed per-query ASan stderr (`evidence/replay-mcp-tool-vuln-recover-Q{33,48}.err` show the chosen-name WRITE-68 at `func_bufs[32]`), completing the clean-archive tool-path replay. Reduced server build with only the C grammar linked and the other grammars stubbed. Superseding that "no HTTP" boundary: W9 reaches the same sink through the pinned server's 127.0.0.1-only HTTP `/rpc` transport and W11 clean-archive replayed all three rows (4/4 pins); still no remote/off-host wire, pointer/IP, command, witness verdict or r5, rungs 1-4 local-only, unwitnessed, no rung 5. W8/W10 (`8e4893c8`): `bash lab/frontier/codebasememory2shell/control-flow-bound.sh` reads `evidence/control-flow-bound.txt`; the canary at `rbp-0x38` (`rbp-8` is saved r15) stops a 70-byte item-38 copy two bytes short of saved RIP and `__stack_chk_fail` fires before the epilogue. Structural negative, author-only, unwitnessed, grade unchanged. W20/W21: `bash lab/frontier/codebasememory2shell/run-witness.sh [OUT]` runs the direct, stdio and HTTP drivers, restores tracked evidence on EXIT/TERM/INT/HUP, and asserts all four asks; W21 repaired the WRITE-70/ROOT assertions. 44/0 assertions were validated lane-by-lane, not in one uninterrupted final-wrapper run; witness UNKNOWN |
| Assimp2Shell | [brief](../reports/frontier-assimp2shell.md), [status](../reports/assimp2shell-status.md) | CVE-2026-134861 (VulnCheck 2026-11-22, CWE-787, CVSS4 AV:L/UI:P); pinned v6.0.6 tarball and both `glTFAsset.inl` blobs, PR 6860/7090 hunk hashes in `lab/frontier/assimp2shell/PINS.sha256` | `bash lab/frontier/assimp2shell/bootstrap.sh` then `bash lab/frontier/assimp2shell/harness/run-all.sh` (rebuilds vuln/fixed × gcc/clang ASan plus plain harnesses offline); W1/W2 drivers in `realpath/` and `placement/` | gcc+clang ASan `WRITE of size 16` 0 bytes after a 36-byte region and `WRITE of size 12` after a 12-byte region, `Indexer` stack-buffer-overflow, plain chosen "TAUF" at offsets 36..39, fixed-PR blocks `ExtractData` but not `Indexer`; 13 PASS/0 FAIL, log `e6341f37…bf41e`, clean-archive normalized replay `913b23f5…3ca938`; witness #3277 replayed `git archive 585e1c7` and graded those baseline direct-call legs ESTABLISHED rungs 1-4, NO r5. W1 reaches the sink through a built pinned library's `ReadFileFromMemory` glTF import and W2 places chosen bytes at a live 24-byte array end; both author-only. W18 (`5424cec5`): `bash harness/run-w18.sh` measures the crafted document's own stable begin `0x555555570210` twice under ASLR-off gdb and writes its low word back as `55570210` (bytes 48..51 `20f55655` → `10025755`), 8 PASS / 0 FAIL, `scene=ok`, unchanged vector at `CopyVector`; the original file reads `0x55555556f520` and an ASLR-on plain run is rc 139. This corrects W14's over-broad "no clean import" wording (that low word came from `safe.gltf`); trace digest in the report. Author-measured, unwitnessed, no r5 |
| Synchronet2Shell | [brief](../reports/frontier-synchronet2shell.md), [status](../reports/synchronet2shell-status.md) | CVE-2026-133646 / INCIBE-2026-937, availability-only; eight pinned upstream files, fix `cb6d77dbca` and parent `42f586d7` hashed in `lab/frontier/synchronet2shell/PINS.sha256` | `cd lab/frontier/synchronet2shell && bash bootstrap.sh && bash harness/run-all.sh` (offline, 7 binaries, 9 cases) | gcc+clang ASan `stack-buffer-overflow WRITE of size 64` past the 41-byte TERM field; plain chosen "MISH"/"E-OO"/"TAUFTAUF" at offsets 44/48/52; fixed hunk and 40-byte TERM clean; 9 PASS/0 FAIL, log `9ed3b328…403a24e`, clean `git archive e5f43ad` normalized `66d20f8…414bdd8`; admitted 05:4xZ as 129th route; author replay, unwitnessed, rung 5 UNKNOWN. W11 (`a0050050`): `bash termlen/run-clientlen.sh` from `lab/frontier/synchronet2shell` records pty-req TERM at the encryption boundary (`CLIENT WIRE_PTYREQ term_len=64/65/128`, `RESULT pass=6 fail=0`); the first clean replay's 5 PASS / 1 FAIL port-settling race is preserved in `termlen/evidence/clientlen/negative-replay-a0050050/`, and the `git archive ce0a0208` replay returned 6 PASS / 0 FAIL with matching `results.txt`/`provenance.txt` (`termlen/evidence/clientlen/REPLAY.md`). Client-boundary measurement, not a witness verdict. W26: `bash release-label/term320b/availability320b/run-availability320b.sh` gives 13 PASS / 0 FAIL on shipped 3.20b `db9c5d6f`; four concurrent 64-byte TERM probes cause first-teardown SIGSEGV and a refused fifth connection, while fixed serves all five. The first 7/3 node-exhaustion prediction is preserved; clean `git archive 79f3710b` matched seven normalized key lines. Author-only, no measured DoS rate, pointer/IP, command or r5 |
| Fltk2Shell | [brief](../reports/frontier-fltk2shell.md), [status](../reports/fltk2shell-status.md) | CVE-2026-135433, pinned `release-1.4.5` `Fl_BMP_Image.cxx`, fix `a28e392` and predecessor `3a049d8` blobs hashed in `lab/frontier/fltk2shell/PINS.sha256` | `cd lab/frontier/fltk2shell && bash run-all.sh` (rebuilds four real FLTK trees offline, regenerates the 118-byte BMP fixtures) | Real 1.4.5 ASan `WRITE of size 1` 2 bytes before a 2-byte allocation at `:486`/`:499`; with `3a049d8` applied the allocation is 4294967298 bytes and the write is still 2 bytes before it at `:490`/`:503`; plain gdb chosen `53 49 4d 2d`; safe BMP and `a28e392` clean; 33 PASS/0 FAIL, raw `71b373d0…d4d8c6`, normalized `7882e60c…3525e` exact from clean `072dc75`; admitted 05:4xZ as 128th route; witness W195 ESTABLISHED rungs 1-4, NO rung 5 |
| FontForge2Shell | [brief](../reports/frontier-fontforge2shell.md), [status](../reports/fontforge2shell-status.md) | CVE-2026-135295, pinned tag `20251009` `fvimportbdf.c` `df766f9c…f0eb30d` and fix `65e80b5` patch `f2745243…5e99175` in `lab/frontier/fontforge2shell/pinned/` and `PINS.md` | `cd lab/frontier/fontforge2shell && ./run-all.sh` (rebuilds five binaries offline from the verbatim pinned function and fix hunk); real headless build/Import() invocation in `REACHABILITY.md` | gcc ASan `WRITE of size 4` four bytes before a 16-byte region at `harness.c:126`, plain abort 134, fixed and complete-table controls clean, gdb `4d 49 53 00` at `encs-4` (fourth byte zero for these field values only); `evidence.log` raw `c0eda4e6…`, normalized `56fd8ada…5633bb`, 5/5 RCs; admitted 05:4xZ as 126th route; witness #3309 ESTABLISHED rungs 1-4 at the direct-call scope, NO r5. Real headless `Import()` on the 296-byte PCF gives ASan `WRITE of size 4` at `fvimportbdf.c:1751` with patched/complete-table controls clean; that path is author-only and unwitnessed; rung 5 UNKNOWN |
| LibRaw2Shell | [brief](../reports/frontier-libraw2shell.md), [status](../reports/libraw2shell-status.md) | CVE-2026-135176, LibRaw exactly 0.22.3; pinned tarball `7edf96c5…355c`, PoC input `c7940268…5dae2`, reporter fix `32fc61e5…afc9c` in `lab/frontier/libraw2shell/PINS.md` | `cd lab/frontier/libraw2shell && ./bootstrap.sh && ./run-all.sh` (offline real `dcraw_emu` builds, all three option forms, fixed/safe controls); `python3 craft_nonzero_poc.py` writes `evidence/nonzero-oob.input` for W2 | ASan `WRITE of size 2` 0 past a 550176-byte region at `xtrans_demosaic.cpp:427`, plain rc 139, fixed/safe clean; `evidence.log` `8ad12e49…874f57` 10 PASS/0 FAIL; admitted 05:4xZ as 127th route; original PoC stores zero halfwords at offset 68,644 — witness W186 clean-room replay ESTABLISHED rungs 1-3 and PARTIAL rung 4 as labeled. W2's crafted input `b59f64e9…069341` (generator `004ff435…f862`) gives ASan WRITE-2 and gdb `0xffff` halfwords at index 68,644 with fixed/no-option controls clean; value saturates, arbitrary bytes UNKNOWN and W2 unwitnessed; rung 5 UNKNOWN |
| LibreCAD2Shell (screened out) | [brief](../reports/frontier-librecad2shell.md) | CVE-2026-135294 (VulnCheck 2026-11-23, CWE-787, CVSS4 5.8 `AV:L/AC:H/AT:P/UI:P`, no RCE claim), LibreCAD <= 2.2.1.6, fix `4e51048…` (PR #3287); vulnerable v2.2.1.6 `rs_filterdxf1.cpp` `0cde2846…0a2097` and patch `9cdb82e6…7026` pinned in `lab/frontier/librecad2shell/pinned/` | none — source-bound screening only, no harness or trigger committed | `file.size()` (`qint64`) narrows into 32-bit `_bNum` near 4 GiB; `new char[_bNum+16]` then `fBuf[_bNum]='\0'` is a fixed one-byte underwrite before an 8-byte allocation, with `dos2unix()` as the in-function consumer. Real-file reachability, Qt build feasibility and post-corruption consumer behavior remain UNKNOWN; no bytes observed, no window, no witness, no admission row |
| Contiki2Shell | [brief](../reports/frontier-contiki2shell.md), [status](../reports/contiki2shell-status.md) | CVE-2026-135292 (VulnCheck 2026-11-23, CWE-787, CVSS4 8.3 `AV:N/AC:H/AT:P`, no RCE claim), Contiki-NG <= 5.2; pinned `release/v5.2` tarball `78133c77…70819c95`, PR #3312 patch and project-conf patch in `lab/frontier/contiki2shell/` | `cd lab/frontier/contiki2shell && sh run-all.sh` (bootstrap verifies the tarball hash, patches the native multicast example, rebuilds vulnerable/fixed/safe trees offline) | ASan `global-buffer-overflow WRITE of size 1232` 16 bytes past the 1280-byte global `uip_aligned_buf` at `mpl.c:981` from `data_message_expiration`, gdb chosen `MISHE-OO-TAUF!!\0` at `base+1280..+1295` (`gdb-inspect.txt`), fixed and safe controls clean, 9 PASS / 0 FAIL; clean-replay receipt in `REPLAY.md`, re-verified by operator at admission 06:1xZ. In-process packet injection with no tun/wire process; ADMITTED as the 130th route, unwitnessed, rung 5 UNKNOWN |
| AwsLc2Shell | [brief](../reports/frontier-awslc2shell.md), [status](../reports/awslc2shell-status.md) | CVE-2026-134056 (Amazon CNA 2026-11-23, CWE-787, CVSS 6.5 `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H`) / GHSA-h63c-583w-4qfw, AWS-LC < 5.7.0; pinned v5.6.0 tarball `2348c404…dd043d26`, vulnerable/fixed `cipher.c` and fix patch hashes in `lab/frontier/awslc2shell/PROVENANCE.md` | `cd lab/frontier/awslc2shell && sh run-all.sh` (14 checks over prebuilt ASan vulnerable, no-ASM vulnerable and fixed harnesses; source pins re-checked) | no-ASM ASan `WRITE of size 16` at `aes_nohw.c:377` via `cipher.c:411`, 0 bytes after a 31-byte region; default ASM build reports the later OOB read at `cipher.c:420`; chosen canary `0xab`→`0x48` at offset 31 in the vulnerable build and unchanged in the fixed build; fixed, single-call and padding-disabled controls clean; `replay.log` 14 PASS / 0 FAIL, re-run by the operator at admission 10:2xZ, 131st route, unwitnessed. W209-W211 (`3826ca48`, `e9b02506`): AWS-LC's own PKCS#7 cipher BIO sizes `to_read=4096-b+1`, so its largest store is exactly 4096 bytes (`n1=0`, `n2=4096` measured on pinned vulnerable and fixed no-ASM libraries); generalized `B=kb+r` reaches `B+1` only for `r=b-1`, unreachable by supported 8-/16-byte ciphers. `cd lab/frontier/awslc2shell && sh run-des.sh` gives 11 PASS / 0 FAIL with ASan WRITE-1 via `des.c:840` → `e_des.c:93` → `cipher.c:259`/`:411` for 3DES-EDE-CBC (`b=8`) into `malloc(15)`; fixed and wide-buffer controls clean. Author-only, unwitnessed, no real app or r5 |
| Cicap2Shell | [brief](../reports/frontier-cicap2shell.md), [status](../reports/cicap2shell-status.md) | CVE-2026-136126 (VulnCheck 2026-11-24, CWE-415, CVSS4 9.2 `AV:N/AC:H`, no RCE claim), c-icap `<0.5.16` and `0.6.0<=v<0.6.6`, fixed 0.5.16/0.6.6 by master `05dcead8…`; pinned `C_ICAP_0.6.5` sources, fix patch and verbatim `.inc` functions hashed in `lab/frontier/cicap2shell/PROVENANCE.md` | `cd lab/frontier/cicap2shell && sh run.sh` (10 hashes then ASan/plain vulnerable, chosen-90/72, safe and fixed builds) | plain `alias=1 trash0_type=2 trash0_start=90` (and `72`), rc 139; ASan `heap-use-after-free READ of size 4` in `destroy_encaps_entity`; safe/fixed clean; operator `19 PASS / 0 FAIL` rc 0, frontier clean-archive replay in `1ff81acb`; admitted 17:5xZ as 132nd route; witness W205 (#3753) ESTABLISHED AS LABELED at the pinned-function scope (clean `git archive 58435874`, 19 PASS / 0 FAIL, independent sixth value `4242`), no grade change or r5 |
| MediaInfoLib2Shell (screened out) | [brief](../reports/frontier-mediainfolib2shell.md) | CVE-2026-135440 (VulnCheck 2026-11-23, CWE-416 UAF, CVSS4 6.9 `AV:L/UI:P`), MediaInfoLib <26.10; pinned v26.05 `f23e69ce…90d5`, ZenLib `be7f1164…a14c`, PoC `af23be76…277b70` and fix patch `c4ec046b…6516` in `lab/frontier/mediainfolib2shell/PROVENANCE.md` | two attempted builds, neither linked: CMake/Ninja ASan+UBSan `-O1 -j8` (32/293 objects in 420 s); `-O0 -g -fsanitize=address -j12` (37/293 in 600 s). Continuation: `ninja -C build-fast -j12 mediainfo`, then link `harness.cpp`, run the pinned PoC and apply fix commits `6bacf12f`/`2a13d1b9` as controls | stale `BitStream_LE` pointer read in `File_Vorbis::Setup()`; neither build produced `libmediainfo.a`/`libzen.a`, no linked harness, no PoC run, no ASan report or observed bytes; rung UNKNOWN; no window, witness or admission |
| LibGsf2Shell (screened out) | [brief](../reports/frontier-libgsf2shell.md) | CVE-2026-116124 (CNA VulDB, CWE-119/122, CVSS4 5.3), libgsf 1.14.59 vulnerable / 1.14.60 already fixed on this host; tarballs, fix `a8e25560` patch `667abb37…c20dc69` and pinned sources hashed in `lab/frontier/libgsf2shell/PROVENANCE.md` | none — source-bound screening only, no harness, build or trigger committed | 32-bit `num_blocks` truncation in two OLE2 BAT paths is bounded by `max_block` and `ole_get_block()` file checks: reaching 2^32 needs a >16 GiB OLE2 file; the bound is derived, not measured; no bytes, no window, no witness, rung UNKNOWN |

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
  14 found no live libgnutls *text* pointer in the final 128-qword inventory
  at `slot1` or `priv`; an earlier sample did have one at `priv+0x110`, but its
  mapping base was unrecorded, so the staged-`.so` route's reachability is
  UNKNOWN, not refuted. Wake 18 (`c371100`) measured bits 20-23 varying across
  three committed ASLR layouts (`c/4/8` heap, `8/0/4` libc): low 20 bits are
  stable but a 3-byte patch must write the varying nibble, so it is not
  deterministic; guessed-nibble repeats (1-in-16 per layout) stay UNKNOWN.
  Static import-check negative only; no grade change, ASLR-on/stock UNKNOWN.
- **KnotResolver2Shell library-relative PLT retarget NEGATIVE for sampled objects (commit `3c45339`, `reports/knotresolver2shell-rung3.md`)**: two fresh ASLR-on inventories (`harness/run_aslr_inventory_w19.sh a|b`, logs `harness/aslr-inventory-w19-{a,b}.gdb.log`, `info proc mappings` recorded beside the pointer dumps, loopback 8855, host sysctl untouched) classify every sampled qword against the live libgnutls mapping base. The extension priv holds four libgnutls text pointers at `+0xd0/+0xe0/+0xf0/+0x110` with invariant file offsets `0x12e5d0`, `0x1338e0`, `0x137e70` (the dispatch target), `0x139780`; the 814-byte OOB span `slot1+0..+813` holds no libgnutls text pointer, and priv sits `0x1b600`–`0x1b900` bytes before slot1, outside the copy. The only command-execution candidate stub, `p11_kit_module_load@plt` at file offset `0x34da0`, is in a different 64 KiB region from all four, so a 2-byte same-library retarget cannot reach it and wake 17 found no command-execution import in libgnutls. The specific wake-17 retarget is negative for these objects; other reachable objects and a 1-in-16 nibble guess stay UNKNOWN. No grade change.
- **KnotResolver2Shell wake-22 pointer arithmetic (report `reports/knotresolver2shell-rung3.md`, "ASLR-on pointer arithmetic and same-library 3-byte scope")**: arithmetic only over six already-committed ASLR-on logs, no new process or wire run. `system - slot1 = 0xBAE750` in every sample, so one heap address would determine both RDI string base and RIP target, but no wire leak exists. Wake 18's 3-byte negative is scoped to cross-base heap/libc patches; for the four libgnutls pointers in the writable span (`slot1+0x10/+0x18/+0xd8/+0xf8`, file offsets `0x1e6e38`/`0x1f6fe8`/`0x1ed480`/`0x1f60e0`) the high five bytes match `libgnutls+0x34da0` in all three recorded bases, but `readelf -rW` gives RELATIVE addends in rodata and the teardown dispatch does not read these slots. Grade unchanged; ASLR-on chosen control UNKNOWN.
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
- **Ruby2Shell stock Rails allocator split, rung 5 NOT ACHIEVED (2026-11-24)**: generate the unmodified app with `bash lab/repro/ruby2shell-stock-rails-setup.sh` (or `RUBY2SHELL_STOCK_RAILS_FULL=1` for full `rails new`). The exact N=524 environment is `RUBY2SHELL_STOCK_N=524 RUBY2SHELL_STOCK_DRAIN=1024:32 RUBY2SHELL_STOCK_DRAIN_FAKE=1 RUBY2SHELL_STOCK_FILL=256 RUBY2SHELL_STOCK_FILL_PREV=0x250 RUBY2SHELL_STOCK_FILL_SIZE=0x90 RUBY2SHELL_STOCK_PART_CHARSET=1 RUBY2SHELL_STOCK_TAIL_HEX=00005102`. Export those variables, then run `bash lab/repro/ruby2shell-stock-rails.sh attack <tag>`, `control <tag>`, or `fixed <tag>` (plain 3.4.13). Final matrix: 3/3 attacks abort pre-response; 3/3 safe affected and 3/3 fixed controls return 404 plus later `/up` 200 and terminate cleanly. `RUBY2SHELL_STOCK_CASE_PROBE=1` enables the analysis-only before/after/consumer snapshots; `stock-rails-rails-stage2d-n524-r498.server.log` records the real `0x200→0x250` expansion, `request=0x222` second mapping allocation and ten-byte remainder-header write. A seeded 512-layout search found no `0x3f0` consumer, and no address/command/second-request execution exists. The tracer is not part of any oracle-free claim. Full hypotheses and controls are in `reports/ruby2shell-investigation.md`.
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
- **KnotResolver2Shell chosen-RIP benign-command replay, author-only, witness W114 MIXED (commits `f4f63d0`, `c3c4c62`; author resolution #1381, witness narrowing #1380)**: on the pinned 6.4.0 jemalloc/debug build on 127.0.0.1:8855, `harness/r5_dispatch.py` writes the fake gnutls cleanup struct into the OOB span (`+0x100 = slot1+0x20`, `+0xb8 = command address`, `+0x110 = call target`, `+0x174=1`, `+0x2d8=0`) and requires `cfg.max_datagram_size = 1500` so F6 stays one frame. `harness/r5-trace.gdb` verifies `extptrs[0]=0x7ffff68aa020`, chosen `+0xb8` and `0x4242424242424242` at `+0x110`; `harness/r5-syms.gdb` measures `system=0x7ffff7458750` from this host's libc layout. Expect SIGSEGV at the `call *0x110` in libgnutls `0x7350c` for a non-canonical target and `rip=0x12345678` for a canonical unmapped one; with `system` at `+0x110`, the author reports two distinct benign `touch` commands creating two distinct marker files with separate vfork detaches and marker-absent safe-input/fixed-6.4.1 controls. Replay logs `r5-{system-vuln,rip-canon,f6-bytes,syms,safe,second,fixed}*.{gdb,driver,kresd}.log` are tracked under `lab/frontier/knotresolver2shell/harness/`; gdb disabled ASLR for the inferior only (host sysctl stayed 2), no breakpoints or forced calls in the execution runs, no wire-derived address leak. Independent replay W114 (10:14Z chat tape) rebuilt both pinned trees (3/3 pins, byte-identical `quic_conn.c`): chosen RIP/chosen argument is ESTABLISHED, and two distinct commands execute with vfork detach and clean controls **only at `argoff 0x300`**; at the committed/default `argoff 0x2f0` the command limb failed twice because `gnutls_deinit` zeroed the string before dispatch (`system` got an empty string). Author #1381 gave the exact invocation: both marker runs passed `r5_dispatch.py 8855 0x7ffff68aa000 0x7ffff7458750 0x300` with distinct `touch` commands, and the report records `+0xb8 = slot1+0x300`; witness #1380 confirms its MIXED verdict refuted only the harness default `0x2f0`, which appears solely in the no-command RIP trace. Grade unchanged: R5 cell stays ◐, command execution witness-observed at `0x300` at the labeled scope, ASLR-on/stock UNKNOWN. |
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
- **Vrpn2Shell W15/W16 saved-RIP byte-map closure** (commit `c5049e5`, author-only
  / unwitnessed; no grade change): W15 closed the eight saved-RIP bytes on the
  stock Debug `-O0` binary with
  `bash lab/frontier/vrpn2shell/probe-plain-rip.sh <outdir> <port> <index>` on
  fresh loopback ports 13970-13983. Indices 120-125 zero one byte each and every
  run faults (SIGILL for bytes 0-1, SIGSEGV for bytes 2-5); bytes 6-7 are already
  `00`, so 126/127 are no-op normal drops. Byte 1 lands in mapped text on an
  illegal instruction; the TYPE sink reproduces index 121, the fixed binary is
  clean, and a debugger-free 121 is exit 139 while 126 stays ALIVE (the
  signal difference under gdb is observed, cause UNKNOWN). W16 closed the map
  on the stock `RelWithDebInfo` (`-O2`) binary
  `lab/frontier/vrpn2shell/build-opt-07.36/server_src/vrpn_server` (SHA-256
  `bfe63334d6735342cc971ebd8f1e2bae3922b3547dfa9623161268dbaa44bae2`):
  `BIN=<binary> bash lab/frontier/vrpn2shell/probe-opt-frame.sh <outdir> <port> <index>`
  on fresh ports 14100-14131 measured PRE `saved_rip=0x5555555a1f42` (bytes
  `42 1f 5a 55 55 55 00 00`). Indices 136-141 (bytes 0-5) are DEAD exit 139
  under both gdb and `probe-func-dos.sh`; 142/143 are unchanged and ALIVE.
  At `-O2` byte 0 faults 13 bytes into
  `doSystemCallbacksFor ... :1442`; byte 1 follows libc `inet_aton_end` with
  cause UNKNOWN. Fixed-commit `-O2` binary (SHA-256
  `227fcb5503ecb9d3d619af2ac20fde4d48ce3ef518e000ffcf3d055aaebbbc48`) at 136
  and short index 4 are ALIVE. An initial run without `BIN=` used the `-O0`
  script default and was all ALIVE — preserved as a build-dependence negative,
  not `-O2` evidence. No wire-chosen byte, command, surviving control flow or
  rung 5; raw evidence `out-w15-*/` and `out-w16-*/`.

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
- **Pgpool2Shell W9/W10/W11 one-command clean-archive replay** (commit `2431bd97`,
  [report](../reports/pgpool2shell-wdnodes-w9.md)). From a clean `git archive HEAD`
  containing `lab/frontier/pgpool2shell` and `lab/pgpool2shell`, with `PGPOOL_LAB`
  naming the provisioned lab that holds the two gitignored pinned tarballs, run
  `PGPOOL_LAB=/abs/path/to/lab/frontier/pgpool2shell bash lab/pgpool2shell/wdnodes/wire/run-witness.sh`.
  The wrapper rechecks `src/SHA256SUMS` (2/2 OK), rebuilds plain 4.7.2/4.7.3 from
  the verified tarballs in a fresh `TMPDIR`, runs W10's three wire cases and both
  live-gdb CHOSEN/HOST readbacks, runs W11's auth probe, and diffs regenerated
  `hash-evidence.sh` output against the committed 11-entry `EVIDENCE_HASHES.txt`;
  ports 19003–19006 are checked and only its own children killed. Author run at
  `d379108d` from an archive extracted to `/tmp/w9-witness-clean2`: `WITNESS REPLAY
  PASS`, rc 0, all 11 normalized hashes identical, including both gdb readbacks.
  An earlier run at `efa6f075` failed 10/11 because the wrapper named a
  nonexistent `gdb-w9-post-alt.cmd` (the committed trace is `gdb-w9-post.cmd`;
  fixed at `d379108d`). This is an author clean-archive receipt, NOT an
  independent witness verdict; grade stays rung 4 wire-scope chosen bytes, with
  no crash, chosen address, command or rung 5 on this branch.
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

W11 (`cbda94a`) measures a second-order timer-heap write in the live plain v17
tport, with no grade change; witness W164 (#2735/#2736) returned ESTABLISHED at
that labeled live-loopback scope. Build and run with
`bash lab/sofiasip2shell/libbuild/live/run_timer_probe.sh`; evidence is in
`lab/sofiasip2shell/libbuild/evidence/w11/`. Thirty pre-queued timers keep the
timer heap array at its initial 30-slot capacity; a tport-internal timer then
resizes it to 528 bytes (63 slots) between setup and frame, and the LD_PRELOAD
shim confirms `TIMER_Q_PTR == SHIM_NEIGHBOR`, `DELTA=0`, caller symbolized to
pinned `timers_alloc` at `su_timer.c:201`. Vulnerable full (`v17plain-full`,
ports 18901 and replay 19011, rc 134) reads `TIMER_Q_BEFORE
size=99236347796094 used=30 boundary_off=528`, i.e. 63 XORed with repeating
mask `41 5a 42 43` over six bytes; 35 `su_timer_set()` calls through
`timers_add()` move `_used` 30 -> 65 and the last writes a live `su_timer_t *`
at `heap+528`, 0 bytes past the array, before glibc aborts. Fixed pin, short
frame and port-shifted replay behave as labeled. The value is a heap pointer,
not an attacker-chosen address or payload; no callback, callable field, marker
or command, and rung 5 stays UNKNOWN.

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
`SERVER_RC=134`); short N=8 and well-formed N=16 exit 0. W137 measured a 0x30
object shift from the parent environment alone, so re-derive the address per
invocation. W5 replaced the marker slot with fixed-address libc `system` and
reached rung 5 locally with a lab-chosen marker command (recipe below);
independent replay of the repaired adaptive chooser returned ESTABLISHED at
the labeled ASLR-off loopback scope (tape #2297), with no new rung, grade or
ASLR-on claim. `qGetTLSAddr` still answers `E01`. Details in
`reports/gdbserver2shell-status.md`.

### Admitted lane limb — 2026-11-23 03:3xZ gdbserver2shell W5 wire-only libc `system()`

With the same plain 633ae02 binary at
`lab/build/gdbserver-633ae02-plain/gdbserver/gdbserver` and the derived fixed
control saved by `rsp/build-gdbserver.sh` in the ASan build tree, run:

```sh
bash lab/frontier/gdbserver2shell/rsp/r5_system_verify.sh \
  lab/build/gdbserver-633ae02-plain/gdbserver/gdbserver \
  lab/build/gdbserver-633ae02-asan/gdbserver/gdbserver-fixed
```

The script needs no debugger. Under `setarch -R` it reads libc's `system`
offset with `nm -D` (here `0x58750` at base `0x00007ffff7800000` →
`0x7ffff7858750`; the `endbr64` entry satisfies CET IBT), installs a lab
executable named after the little-endian vptr bytes up to the first NUL
(`8\xc4aUUU` for `0x55555561c438`) in a same-length lab PATH, and derives the
live object address by sweeping `0x...c400`–`0x...c4c0` with `abort@plt`
until one candidate returns 134. Expect `DERIVED obj=0x55555561c430` on the
recorded invocation, then four cases at 4 PASS / 0 FAIL: vulnerable+system
`SERVER_RC=0 MARKER=1` with marker content `R5_SYSTEM_MARKER=1`;
vulnerable+abort `SERVER_RC=134 MARKER=0`; fixed+system `E01`, no marker;
well-formed `SLEN=16`, no marker. Normalized hash of the four client
transcripts and marker records:
`9104b0ec51a09c94922438a62d9df2bfa108f4b4e6f8e7f18abc26d3f4886a98`.
Evidence: `rsp/evidence/r5-system-{vuln-system,vuln-abort,fixed-system,vuln-safe}.{log,client.out,marker}`
and the `r5-system-sweep-*.log` address sweep. An `env -i` sweep SIGSEGVs at
every candidate, so a minimal environment is not a portable substitute: the
address and PATH length are conditions, not incidental defaults. Grade:
rung 5 locally demonstrated with a live plant-started process on loopback and
an observed benign side effect; the independent replay of the repaired adaptive
chooser returned ESTABLISHED at the labeled ASLR-off loopback scope (tape
#2297), with no new rung, grade or ASLR-on claim. The earlier rung-4 ESTABLISHED
scope is unchanged. Status: `reports/gdbserver2shell-status.md`.
### Admitted lane limb — 2026-11-23 05:0xZ gdbserver2shell W7 portable command name

`rsp/r5_portable_verify.sh` removes W5's fixed `obj+8` assumption. It first
derives the live object with `abort@plt`, then picks the smallest offset in
`{+8,+0x10,+0x18,+0x20,+0x28,+0x30}` whose vptr bytes pass the literal-word
whitelist and `sh -n -c`; libc `system` sits at `vptr+0x10` and the payload
grows to `N=64+delta-8`, with the largest write through `obj+0x47` inside the
measured 0x58-byte usable chunk. From the repository root:

```sh
bash lab/frontier/gdbserver2shell/rsp/r5_portable_verify.sh \
  $PWD/lab/build/gdbserver-633ae02-plain/gdbserver/gdbserver \
  $PWD/lab/build/gdbserver-633ae02-asan/gdbserver/gdbserver-fixed
```

Expect the default object `0x...c440`, `delta=8`, name `48c461555555`,
4 PASS / 0 FAIL,
`P_SYSTEM_NORMALIZED_HASH=9104b0ec51a09c94922438a62d9df2bfa108f4b4e6f8e7f18abc26d3f4886a98`.
A scratch forced-`+0x10` variant gave `50c461555555`, `SLOT_LEN=72`,
`MARKER=1`, abort rc134, fixed `E01`, safe clean, 4 PASS / 0 FAIL, hash
`6be8244f7949331ac1f8ee9e1a1389e4f30a8525f25317a444063367d41d3747`
(evidence in `rsp/evidence-portable/forced-0x10/`). A sweep of object low
bytes `0x00`–`0xc0` found a safe offset for every case; W7's own chooser
printed every candidate while the shell parser read only the first line, so
its `+0x10` at c420 described the predicate, not the shipped harness (preserved
negative, repaired in W8 below). Generated `r5-bin-portable/` trees are
gitignored; pins and raw logs are in
`lab/frontier/gdbserver2shell/PROVENANCE.md`. No grade change: rung-4
ESTABLISHED and W6's labeled rung-5 scope stand. Status:
`reports/gdbserver2shell-status.md`.

### Admitted lane limb — 2026-11-23 06:1xZ gdbserver2shell W8 chooser repair and witness replay

W8 reproduced W140's object locally by shrinking the parent
`MEMORY_PRESSURE_WATCH` environment by 32 bytes: `DERIVED obj=0x...c420`.
W7's shipped chooser printed every candidate but the shell parser read only
the first line, so it chose `delta=0x8`, name `28c461555555`, and failed with
`FAIL no shell-safe fake-vtable offset`; the safe `+0x10` candidate was
discarded. The repair emits only the selected line and logs rejections on
stderr. Rerun at c420:

```sh
bash lab/frontier/gdbserver2shell/rsp/r5_portable_verify.sh \
  $PWD/lab/build/gdbserver-633ae02-plain/gdbserver/gdbserver \
  $PWD/lab/build/gdbserver-633ae02-asan/gdbserver/gdbserver-fixed
```

Expect `reject delta=0x8`, `CHOSEN delta=0x10`, name `30c461555555`,
`SLOT_LEN=72`, vuln+system rc 0 / `MARKER=1`, vuln+abort rc 134, fixed `E01`,
safe clean: 4 PASS / 0 FAIL and hash
`6be8244f7949331ac1f8ee9e1a1389e4f30a8525f25317a444063367d41d3747`; evidence
in `rsp/evidence-portable/c420-adaptive/`. Padding moves the object only
upward (c460/c470/c490/out of sweep), so the shrink is the measured route to
c420. Witness tape #2297 replayed commit `830153a` from a clean `git archive`
of HEAD `b1e6a733` with its own plain `7a5f8feb...` and ASan fixed
`0827f1a4...` builds: the default engine parent derived c470 and kept `+8`,
4 PASS / 0 FAIL; a 32-byte shrink gave c450 with the same `+8`, and an
80-byte shrink reproduced c420 with the exact `reject`/`CHOSEN`/`SHELL_SAFE=1`
lines, 4 PASS / 0 FAIL and the same hash. The repair was source-bound at
`r5_portable_verify.sh:99-118` with no counterexample; verdict ESTABLISHED at
the labeled ASLR-off loopback scope, no new rung, grade or ASLR-on claim.
Ceiling: `setarch -R` ASLR-off, object address derived per parent environment,
marker conditional on a shell-safe derived name. Generated trees remain
gitignored; pins and raw logs are in `lab/frontier/gdbserver2shell/PROVENANCE.md`.
Status: `reports/gdbserver2shell-status.md`.

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

## Admitted frontier lane — 2026-11-23 03:4xZ ghostscript2shell

Frontier handed over W134 (staging commit `9f5fcd6` provisioned the candidate;
DM at 03:37Z staged the find) with brief `reports/frontier-ghostscript.md`,
site charter and seed wall, four hash-pinned `src/` blobs, two real gs 10.07.0
binaries and both font fixtures in
`lab/frontier/ghostscript2shell/PROVENANCE.md`. Its two-pane inner tmux window
already existed at index 102 (0..101 occupied), so admission created no second
window and changed no registry entry.

From the repository root, replay from an isolated copy that preserves the
`lab/frontier` path shape used by the runner's trace normalizer:

```sh
T=$(mktemp -d /tmp/ghostscript-replay.XXXXXX)
mkdir -p "$T/lab/frontier/ghostscript2shell/src"
cp -a lab/frontier/ghostscript2shell/harness \
  "$T/lab/frontier/ghostscript2shell/harness"
cp lab/frontier/ghostscript2shell/src/SHA256SUMS \
   lab/frontier/ghostscript2shell/src/gs_fonts.ps.ghostpdl-10.07.0 \
   lab/frontier/ghostscript2shell/src/gs_fonts.ps.ghostpdl-10.07.1 \
   lab/frontier/ghostscript2shell/src/gs_fonts.ps.1484854e \
   lab/frontier/ghostscript2shell/src/fix-1484854e.patch \
   "$T/lab/frontier/ghostscript2shell/src/"
bash "$T/lab/frontier/ghostscript2shell/harness/run.sh"
```

Expect rc 0, `PASS=22 FAIL=0` and
`TRACE_SHA256=a4569485cb1fb98ab74b7d186e1566f18ede6bdb263cdb4e5e34f631e5683c29`.
The operator observed exactly those values at admission from that fresh
`/tmp` copy, matching frontier's value. Witness W141 (#2149) independently
replayed that baseline from a clean archive with its own rebuilt binaries:
22 PASS / 0 FAIL, trace
`a4569485cb1fb98ab74b7d186e1566f18ede6bdb263cdb4e5e34f631e5683c29`,
ESTABLISHED at the labeled rung-1/2 scope, no counterexample. Its UAF lane
(21/0, `bd4e4b4c…f85a7cb`) and native lane (17/0, `b53abad2…b682e87`) were
likewise ESTABLISHED for rung 3 and rung 4 at the labeled build scope.

Expected bytes: vulnerable 10.07.0 plus the injected NimbusSans PFA gives
`TRAP_FIRED=true` and `GS_FORCEPUT_RESULT=true`; the same font on the
`1484854e` fixed build gives `TRAP_FIRED=true` and
`GS_FORCEPUT_RESULT=false`; the unmodified font on the vulnerable build gives
both false. The fixed blob's `Check operand types` guard is the only
behavioural difference between the two binaries. That is the admission-time
PostScript-level rung-1/2 differential only; the later author wakes raised its
grade (addendum below). CVE-2026-125396 is AV:L; the writeup's remote delivery
chain is an untested separate claim. Status: `reports/ghostscript2shell-status.md`.

### Rung-5 lab chain over loopback HTTP — 05:2xZ (witness W145 ESTABLISHED at the labeled lab-app scope)

`bash lab/frontier/ghostscript2shell/harness/run-r5.sh` runs three cases
through a plant-started 127.0.0.1 upload service (`live/r5_server.py`,
`live/r5_request.py`): vulnerable gs with the injected font, fixed `1484854e`
with the injected font, and vulnerable gs with the unmodified font. Expect
rc 0, `PASS=14 FAIL=0` three times and normalized trace
`ddd635b2e607150af1180cc07554183ac79fd1025a79c00af28fbf923bf09957`.
Vulnerable+injected gives `PATH_CONTROL_BYTES_BEFORE=1`,
`PATH_CONTROL_BYTES_AFTER=0`, `PIPE_OPENED=true`,
`PATH_CONTROL_BYTES_RESTORED=1`, `CLEAN_VALUE=12345` and a marker file
containing `GS_R5_OK`; both controls give `NO_STALE_REF` and `MARKER=NONE`.
`exp/command-safer.ps` (sha256
`66cc77fb2f354f67ac46d6b94a1533fa2db0dad67b7ddb855671a63604b67fc8`) clears
`path_control_active` and opens `%pipe%/bin/sh -c "echo GS_R5_OK > <marker>"`;
a bare directory permit without `/*` was a preserved negative. The lab app
explicitly permits its upload directory and templates saved paths into the gs
command line, so this is rung 5 only at that labeled lab-app scope: no CUPS,
mail or web delivery claim, unchanged AV:L, no external host. Witness W145
(#2252) replayed the chain from a clean `git archive e1f88e7` with its own
rebuilt binaries (vuln `bcf3057c14c135c8f54b683447006d739f5b2b9c12e7cf88dc981cfbbc9091fc`,
fixed `eb22868fd3ad24d14d48ebc1fbe72ea3b44c5826ff00c6d071df4da68f278fa4`,
both reporting 10.07.0): three runs 14 PASS / 0 FAIL each with the exact
trace hash above, plus causal counterchecks — a changed request token appeared
in the marker (`MARKER=GS_R5_WITNESS`), and removing the four zero-byte clears
left `PATH_CONTROL_BYTES_AFTER=1`, `PIPE_FAILED=true`, `MARKER=NONE`.
Rung 5 ESTABLISHED at that labeled lab-app scope only, no counterexample;
the writeup's real delivery chains stay unmeasured. Status and pins:
`reports/ghostscript2shell-status.md`,
`lab/frontier/ghostscript2shell/PROVENANCE.md`.

### Post-admission native and `-dSAFER` addendum — 04:2xZ (author-only)

Three commits (`1a2b715`, `2ac5f7c`, `f6a0942`) extend the same pinned gs
10.07.0 binaries. From `lab/frontier/ghostscript2shell/harness`, run
`bash run-uaf.sh`, `bash run-native.sh` and `bash run-safer.sh`. The UAF lane
first needs an out-of-tree ASan build in `src/asan-build`
(`CFLAGS='-fsanitize=address -g -O1'`, `LDFLAGS=-fsanitize=address`,
`../ghostpdl-ghostpdl-10.07.0/configure --without-x --disable-cups`,
`make -j2 gs`); the resulting `bin/gs-vuln-asan` is
`7ee7b87ec079bfafcc17e994b9fb57a496143eff6bd6d9011f9d48eddc12fc20`.

Docs replay from a fresh `/tmp` copy of `harness/` plus `exp/` observed rc 0
for all three: `run-uaf.sh` `PASS=21 FAIL=0` with
`UAF_TRACE_SHA256=bd4e4b4c7404a9b22dbda6e3ee077e58736d96a868af6f2aad8cc7a00f85a7cb`,
`run-native.sh` `PASS=17 FAIL=0` with
`NATIVE_TRACE_SHA256=b53abad21ed9822838d2a5f85a705172c3c19cb9ea22923b141c90192b682e87`,
and `run-safer.sh` `PASS=9 FAIL=0`. No trace hash is published for the SAFER
runner; do not invent one. All are author observations, not witness verdicts.

Expected UAF bytes: `harness/uaf.ps` stores a 2048-byte local string in
systemdict, restores, sprays 96 arrays of 128 `0x12345678` integers, finds ten
occurrences of `78 56 34 12` at array 8 / index 118, flips one low byte and
observes exactly one live element change; writing `0x1234567a` back reads
`122,86,52,18` through the stale string and cleanup restores `120`. ASan on
the vulnerable build gives `heap-use-after-free`, `READ of size 1` in `zget`
(`psi/zgeneric.c:183`), 14792 bytes into a 20048-byte region allocated at
`gsmalloc.c:192` and freed at `gsmalloc.c:366`; evidence sha
`d3adbb8caef37beac5745b174874bd75c6108a45612651725899693940c33387`. Fixed and
safe-font controls report `NO_STALE_REF` / `SV_PRESENT=false`. Native probes
expect `BYTE0=72`, `BYTE1=69`, a `currentdevice` → `GXDEVICE` → `MEM` (+24) →
`LIBCTX` (+208) → `CORE` (+8) walk, a forged view at `CORE+156` reading `0`,
a benign write to `1` with `.currentpathcontrolstate` returning `true`, and
`BEFORE=319 CHANGED=18 AFTER=319` for the one-call `mul`→`sub` retarget.
SAFER expects `PATH_CONTROL_BYTES_BEFORE=1`,
`PATH_CONTROL_OPERATOR_BEFORE=true`, `PATH_CONTROL_BYTES_AFTER=0`,
`PATH_CONTROL_OPERATOR_AFTER=false`, `PATH_CONTROL_BYTES_RESTORED=1`,
`CLEAN_VALUE=12345`; probe sha
`f22acdea7bfcfefc842e3e201181da1223b0b15b309626ad5701b5bdc0e45d96`.
The SAFER runner passes `--permit-file-read` from its own directory; the probe
hardcodes the in-repo font path, so a replay from a copied tree must point the
permit at that absolute path or SAFER silently falls back to a built-in font
and the runner reports `NO_STALE_REF` (observed here: 3 PASS / 6 FAIL).
Normalized outputs are tracked in `harness/evidence/`; local ASan build output
stays local. No `%pipe%`, command, application/network delivery or witness;
rung 5 remains a separate claim.

## Admitted frontier lane — 2026-11-23 03:5xZ llamarpc2shell

Frontier handed over W135 (DM #2155 at 03:55Z) with brief
`reports/frontier-llamarpc.md`, site charter and seed wall, four SHA-pinned
source/patch blobs in `lab/frontier/llamarpc2shell/src/`, and the harness and
raw evidence in `lab/frontier/llamarpc2shell/PROVENANCE.md`. Its two-pane
inner tmux window already existed at index 103, so admission created no
second window and changed no registry entry.

From the repository root, replay from an isolated copy of the staged tree:

```sh
T=$(mktemp -d /tmp/llamarpc-replay.XXXXXX)
mkdir -p "$T"
cp -a lab/frontier/llamarpc2shell "$T/"
(cd "$T/llamarpc2shell" && REPLAY=1 bash harness/run.sh)
```

Expect rc 0, `PASS=28 FAIL=0` and
`TRACE_SHA256=d898482a39c65919916750bb28f6151d55e91efb3b56d88e315321c62b09c1b2`.
`REPLAY=1` suppresses only the nested clean-copy assertion, which is what the
independent `/tmp` copy replaces; frontier's in-tree run reports 29 PASS /
0 FAIL including that assertion. The operator observed exactly these values
at admission.

Expected bytes: a 43-byte message into `size=1` gives `OOB=42`,
`REM_UNDERFLOW=18446744073709551574`, plain adjacent `TAIL0=41` and
`POSTED=1`. gcc and clang ASan both report `stack-buffer-overflow` with
`WRITE of size 43` overflowing the `[32,33) 'cmd'` object inside
`socket_t::impl::rdma_recv`. Chosen bytes 0x5a at message offset 11 and 0x44
at offset 18 land at adjacent offsets 10 and 17; the canary beyond 43 bytes
stays 0xc7. The fixed slice logs `RDMA recv overrun: got=43 rem=1`, reposts
the receive slot and writes no adjacent byte; safe `got=1` is clean on the vulnerable slice.

That is the staged slice harness with a stubbed verbs environment: no live
server, HELLO handshake, RDMA wire packet or real device at that scope. The
later live-wire result is in the addendum below. `AV:N` carries `AT:P`; no
independent witness verdict exists at the staged slice scope. Witness W142
(#2193) later ESTABLISHED the live-wire scope below from a clean archive.
Status: `reports/llamarpc2shell-status.md`.

### Post-admission live RDMA wire — 04:2xZ (author-only)

`37da4e6` built the whole pinned upstream server (`reports/llamarpc2shell.md`).
Provisioning binaries and source trees are gitignored
(`lab/frontier/llamarpc2shell/.gitignore`); rebuild them from pin
`620d2225cc436ab0b001e3200e590e3b286ef9ab` and fixed worktree
`9a0fde9967fa1a35b6e5dd1f47e1a3648b6fecc1`:

```sh
git clone --filter=blob:none --no-checkout https://github.com/ggml-org/llama.cpp.git src/llama.cpp-pin
git -C src/llama.cpp-pin fetch --depth 1 origin 620d2225cc436ab0b001e3200e590e3b286ef9ab
git -C src/llama.cpp-pin checkout --detach FETCH_HEAD
cmake -S src/llama.cpp-pin -B src/llama.cpp-pin/build-asan -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug -DGGML_RPC=ON -DGGML_RPC_RDMA=ON \
  -DLLAMA_SANITIZE_ADDRESS=ON -DGGML_SANITIZE_ADDRESS=ON \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
  -DLLAMA_BUILD_SERVER=OFF -DLLAMA_BUILD_APP=OFF -DLLAMA_BUILD_TOOLS=ON
cmake --build src/llama.cpp-pin/build-asan --target ggml-rpc-server -j2
```

Server SHA-256: vulnerable ASan `d58d66602cbfdab73b3a60ed39639a80912ff8ba54becc563f2bd86eaa6db305`,
vulnerable plain Debug `dc368c89eac8a56f3358ccc4768069c235d76a0743404a34763ffe111c3d7eb7`,
fixed ASan `31dbd386dd698de0a1bbd6af12c00bf4926c970941db84c76e395ba3fb4c18df`;
wire client `5dbb95731a196f38e7dd69d8c30388fa87cdee0a568f82de4e48ec03e14bb9e6`.
The runner needs loopback SoftRoCE `rxe0` (passwordless device creation),
RoCEv2 GID index 1 (`::ffff:127.0.0.1`), MTU 4096, and the client drives TCP
HELLO `0x0e` + `uint64 24` + 24-byte caps, then RC QP RESET→INIT→RTR→RTS:

```sh
bash wire/run.sh safe
bash wire/run.sh attack
SERVER_BIN=$PWD/src/llama.cpp-fixed-asan/bin/ggml-rpc-server bash wire/run.sh fixed
bash wire/run-gdb.sh
LEN=3593 TAG=gdb-rip GDB_CMD=$PWD/wire/gdb-rip.cmd bash wire/run-gdb.sh
LEN=3593 TAG=gdb-crash GDB_CMD=$PWD/wire/gdb-crash.cmd bash wire/run-gdb.sh
```

Expect `Accepted client connection`, `RDMA probed: dev=rxe0 gid=1 RoCEv2`,
`RDMA activated: ... mtu=4096 rx_depth=24` on the wire; a 43-byte SEND gives
ASan `stack-buffer-overflow`, `WRITE of size 43` at
`transport.cpp:520` ← `:567` ← `ggml-rpc.cpp:2475` into `[48,49) 'cmd'`,
with adjacent 1-byte `response` objects at `[64,65)`/`[80,81)` underflowed.
The plain Debug frame dump shows `cmd` at `0x7fffffffd007`, `+0=0x0f`,
`+11=0x5a`, `+18=0x44`, other bytes through `+42=0x41`; a 3593-byte SEND
with eight `0x42` bytes at payload offsets 3585–3592 overwrites the saved RIP
slot at `&cmd+3585` with `0x4242424242424242` and backtrace frame #1. The
fixed server logs `RDMA recv overrun: got=43 rem=1`, stays ASan-clean and
closes; the 1-byte safe SEND is clean on the vulnerable server. No rc/PASS
count or trace hash is defined for the wire runners — do not invent one; raw
`wire/evidence/*.log` are tracked and QPN values vary by run. The saved-RIP
offset is measured only in the non-ASan Debug frame, execution at `0x4242…`
never happened, and at that scope no command, working ROP chain or ASLR bypass
was observed. The 256 KiB advisory bound was later exercised on the wire
(below): a 262144-byte SEND gives `wc.byte_len=262144` and faults the
vulnerable process with no marker, while the fixed server logs
`RDMA recv overrun: got=262144 rem=1` and stays up; no chosen bytes, pointer
control or command at that size, and no grade change. Witness W142 (#2193)
replayed `37da4e6` from a clean archive with its own three pinned builds (ASan
vuln `0a073add…`, plain Debug `dadd8c62…`, fixed ASan `f507d7cb…` prefixes):
rungs 3 and 4 ESTABLISHED at that labeled build scope with fixed, safe and
repeated attack controls and no counterexample. Its only output was a wording
NIT to the author. Rung 5 was UNKNOWN at that verdict; the third-wake wire-only
run below was later replayed by witness W148 (#2372) and is ESTABLISHED at its
explicitly labeled lab-build scope. `AT:P` still qualifies AV:N.

#### Failed wire-only rung-5 feasibility attempt — 04:4xZ (negative)

`a76b986` tried one chain on one labelled lab build of the same pin with
`-fno-stack-protector`; the build tree and wire client binary are gitignored
(`lab/frontier/llamarpc2shell/.gitignore`), and decisive failure logs and
payload files are committed under `wire/evidence/`. Re-measure the baseline
first, then use the raw-file client option and the fixed-environment wrapper:

```sh
bash wire/run.sh attack
RDMA_PAYLOAD_FILE=$PWD/wire/evidence/rce-payload-early.bin \
  bash wire/run-rce-gdb.sh
```

`rdma_attacker.cpp` sends `RDMA_PAYLOAD_FILE` bytes verbatim; the default
marker path is unchanged. The no-canary server sha256 is
`3fb0d4bff4ae699088cd20f81f575b0399f1fe797ae2ec87979c100ea7599959`
(`wire/evidence/build-nocanary.log`). Under `setarch -R` plus a fixed minimal
environment, the saved RIP was at `&cmd + 761` and libc symbols were read at
`pop rdi; ret` +`0x10f84b`, `system` +`0x58750`, `_exit` +`0xee2c0`; the chain
pointed `rdi` at a command string at `&cmd + 1200`. No command ran. Every
oversized completion makes `rem` underflow in `rdma_recv`, so
`rpc_serve_client` takes the early `break` at `ggml-rpc.cpp:2476` and the
destructor at `:2432` consumes the smashed locals before the epilogue:
`free(): invalid pointer` (`graphs.__n = -11`) at 100/761/820-byte SENDs
(`fxlen{100,761,820}.log`), and a second `rdma_recv` memcpy fault at 4608
bytes (`rce-diag3.log`). A 1-byte SEND stays clean. The payload binaries are
failed inputs, not working exploits; no marker file, valid pointer redirect
or rung 5 was produced, and no witness replay is owed for this negative.


#### Wire-only rung-5 observation (third wake) — witness-ESTABLISHED at labeled lab-build scope

This is separate from the failed chain above: the same early `break` is
repaired by a different lab-chosen 1024-byte SEND that zeroes `rpc_server`
locals so `~rpc_server` iterates empty containers, stops before the `sock`
shared_ptr at `&cmd+1025`, and needs no debugger to set registers or memory.
Conditions are additive: the no-canary pin build (server sha256
`3fb0d4bff4ae699088cd20f81f575b0399f1fe797ae2ec87979c100ea7599959`),
`setarch x86_64 -R` with host `randomize_va_space=2` unchanged, fixed minimal
environment `PATH=/usr/bin:/bin HOME=/home/mesh-home TERM=dumb LINES=24
COLUMNS=80`, loopback `rxe0` GID 1 and port 53060. Rebuild from pin
`620d2225cc436ab0b001e3200e590e3b286ef9ab` as in the wire recipe above;
provisioning binaries and source trees are gitignored
(`lab/frontier/llamarpc2shell/.gitignore`), while the payload and raw logs are
tracked under `wire/evidence/`. From the repository root:

```sh
python3 lab/frontier/llamarpc2shell/wire/make-repair-payload.py \
  --cmd-addr 0x7fffffffe50f --libc-base 0x7ffff7200000 \
  --out lab/frontier/llamarpc2shell/wire/evidence/r5-payload.bin
MODE=attack \
  RDMA_PAYLOAD_FILE=$PWD/lab/frontier/llamarpc2shell/wire/evidence/r5-payload.bin \
  bash lab/frontier/llamarpc2shell/wire/run-repair.sh
```

Expect `wc status=0 opcode=0 byte_len=1024` and a 1024-byte `r5-payload.bin`
with sha256
`96c92e9f462d43e1744e19093f42bf26a978684364b55ee50c383dcf80ed304e`. Three
consecutive runs each left a zero-byte `/tmp/llamarpc2shell-r5-marker`, with
byte-identical server logs (sha256
`76b75f22a843bc11fe6fc3b1ec9d7881eff98de677973c59d98ccb748c194885`) and
client logs (sha256
`3e71980ffae9ac3bb9facc51f0b1706b259d15c47e8f53773dc187bc9ae1ab8d`). A
passive gdb observation of a fourth run (`wire/gdb-r5-system.cmd`, no register
or memory edits) stopped at `__libc_system` with
`line=0x7fffffffe863 "touch /tmp/llamarpc2shell-r5-marker"`, then detached
after vfork and exited normally (`wire/evidence/r5-system-obs.log`, sha256
`022a306b13595e044931cdda91ee1b2680af4e328061474b2ca05ea67c57b1e5`).
Controls: the 1-byte SEND leaves no marker; the fixed ASan server (sha256
`31dbd386dd698de0a1bbd6af12c00bf4926c970941db84c76e395ba3fb4c18df`) logs
`RDMA recv overrun: got=1024 rem=1` and leaves no marker. Witness W148 (#2372)
replayed this exact claim from a clean `git archive HEAD` (`bc9cc09`) with its
own rebuilt pins: its no-canary Debug server (sha prefix `f90e1b929…d388a`,
differing from our `3fb0d4bf…7599959` only in path-dependent debug strings)
measured `cmd=0x7fffffffe55f`, so W148 regenerated a payload for the predicted
debugger-free `0x7fffffffe59f` and got 3/3 attacks with `client_rc=0` and fresh
markers, differing only in QPN/psn. Its exact-claim replay with our
hash-matched binary and the committed `96c92e9f…304e` payload gave a fresh
marker and byte-identical logs after QPN/psn and payload-path normalization
(`a957ca3f…606f` server, `4985bf2f…f4c` client). A wire-string countercheck
created only `/tmp/w148-witness-marker` and no default marker; a passive
`break system` with no register/memory writes stopped with `$rdi` equal to the
wire string, detached after vfork and exited normally. Controls: 1-byte SEND,
fixed ASan build with the 1024-byte SEND (`got=1024 rem=1`), three ASLR-on
runs and one extra server environment variable all left no marker. Rung 5 is
ESTABLISHED at the labeled lab-build scope (no stack protector, `setarch -R`
ASLR off, fixed minimal environment, loopback `rxe0`, measured absolute stack
address, benign `touch`), with no repair owed. The absolute `cmd` address is
build-path and environment specific: a new build must re-measure it and
regenerate the payload before inheriting this verdict. Limits preserved: one
build per replay, no wire-derived address or image, no ASLR-on or
canary-enabled command, no external target; W142's rungs 3 and 4 ESTABLISHED
scope is unchanged.

#### 256 KiB SEND upper bound (fourth wake) — wire-only, no new primitive

The advisory's 262144-byte bound was measured with the same runner and a
locally generated zero-filled buffer (first byte `0x0f`),
`wire/evidence/bulk256k-payload.bin` sha256
`cc717bb7492c6d96c060e42c9ca9149616981cfb0c5785568287c1d16446d164`:

```sh
MODE=attack TAG=bulk256k \
  RDMA_PAYLOAD_FILE=$PWD/lab/frontier/llamarpc2shell/wire/evidence/bulk256k-payload.bin \
  bash lab/frontier/llamarpc2shell/wire/run-repair.sh
SERVER=$PWD/lab/frontier/llamarpc2shell/src/llama.cpp-fixed-asan/bin/ggml-rpc-server \
  MODE=attack TAG=bulk256k-fixed \
  RDMA_PAYLOAD_FILE=$PWD/lab/frontier/llamarpc2shell/wire/evidence/bulk256k-payload.bin \
  bash lab/frontier/llamarpc2shell/wire/run-repair.sh
```

Expect `send wc status=0 opcode=0 byte_len=262144 wr_id=0 inline=0` on both
runs. The vulnerable no-canary server faults (`Segmentation fault (core
dumped)`) with no marker and its stdout stops at `RDMA activated`
(`wire/evidence/bulk256k.log`, `wire/evidence/client-bulk256k.log`); the fixed
ASan server logs `RDMA recv overrun: got=262144 rem=1`,
`Client connection closed` and stays up
(`wire/evidence/bulk256k-fixed.log`,
`wire/evidence/client-bulk256k-fixed.log`). No core file was retained, QPNs
vary by run, and no chosen bytes, pointer control or command exists at that
size: this closes the "largest SEND 4608 bytes" gap without changing any grade,
and no independent replay is owed for this observation because it adds no new
primitive.

#### Canary-enabled build — measured negative (fifth wake)

The open question from the third wake — whether the wire-only r5 chain survives
a stack protector — was tested with the same runner, loopback `rxe0:53060`,
`setarch x86_64 -R` and fixed minimal environment. Server: the vulnerable pin
plain Debug build with an active canary, sha256
`dc368c89eac8a56f3358ccc4768069c235d76a0743404a34763ffe111c3d7eb7`
(imports `__stack_chk_fail`), not the no-canary build. Rebuild it from pin
`620d2225cc436ab0b001e3200e590e3b286ef9ab` as in the wire recipe above, then:

```sh
SERVER=$PWD/lab/frontier/llamarpc2shell/src/llama.cpp-pin-plain/bin/ggml-rpc-server \
  MODE=measure TAG=canary-layout1 bash lab/frontier/llamarpc2shell/wire/run-repair.sh
python3 lab/frontier/llamarpc2shell/wire/make-repair-payload.py \
  --cmd-addr 0x7fffffffdac7 --libc-base 0x7ffff7200000 \
  --saved-rip 3585 --string-off 3660 --length 3716 \
  --command 'touch /tmp/llamarpc2shell-canary-marker' \
  --out lab/frontier/llamarpc2shell/wire/evidence/r5-canary.bin
SERVER=$PWD/lab/frontier/llamarpc2shell/src/llama.cpp-pin-plain/bin/ggml-rpc-server \
  R5_MARKER=/tmp/llamarpc2shell-canary-marker MODE=attack TAG=canary-attack1 \
  RDMA_PAYLOAD_FILE=$PWD/lab/frontier/llamarpc2shell/wire/evidence/r5-canary.bin \
  bash lab/frontier/llamarpc2shell/wire/run-repair.sh
```

`MODE=measure` (43-byte SEND, `gdb-measure-noaslr.cmd`) reported `cmd address
0x7fffffffda97`, saved RIP at `&cmd + 3585`, `sock` at `&cmd + 3721` and libc
base `0x7ffff7200000` (`wire/evidence/canary-layout1.log`, sha256
`3fcdbae9dc7b5919a02bd3377bc31c3f7931ce3c346432fe414ece13924c8ba4`). The
`r5-canary.bin` payload is 3716 bytes, sha256
`4e0943a748caf44ef19644992d11ceb9cf57517512f22ceec13fdf081fbd32df`, with the
chain at `+3585` and the command string at `+3660`, stopping before `sock`.
The generator's default invocation still reproduces the established
`r5-payload.bin` byte-for-byte; the debugger-free `&cmd` here is the measured
gdb value plus the previously measured 48-byte environment delta, and the
canary result does not depend on that address being exact. `MODE=attack`
reported `wc status=0 byte_len=3716`; the server printed `*** stack smashing
detected ***` and aborted with no marker
(`wire/evidence/canary-attack1.log` sha256
`92519f51622dd33fc8688c74ade657accc055268a771798cf72df841b485b28b`,
`client-canary-attack1.log` sha256
`07c807484aec102c31b4200fa1211f6d13a4db923517e4616fa9035b03448251`). A
1-byte SEND on the same server closes cleanly with no marker
(`wire/evidence/canary-safe.log` sha256
`095e0e6adba7c8402c5c631b3c32b6144643bfc59139b493448b5980c2642329`). The
abort site was not source-bound; on this build the active canary aborts before
any command runs. This does not negate the no-canary W148 rung-5 verdict, does
not establish ASLR-on behavior, changes no grade, and owes no replay as a
negative with no new primitive.

## Admitted frontier lane — 2026-11-23 04:4xZ zlib2shell

CVE-2026-85091, zlib 1.2.11–1.3.2. Pins, claim sources, verbatim source
slices and all raw evidence are in `lab/frontier/zlib2shell/PROVENANCE.md`;
the brief is `reports/frontier-zlib2shell.md`. The harness re-verifies five
pin hashes, self-extracts the pinned 1.3.2 tarball when needed, extracts
`gz_write()` and `gz_vacate()` from both pinned blobs with `awk`, dry-runs
the published `df84af25` fix hunk and rebuilds five binaries from the
tarball with only `gzwrite.c` swapped.

```
T=$(mktemp -d /tmp/zlib2shell-operator.XXXXXX)
git archive HEAD lab/frontier/zlib2shell | tar -x -C "$T"
(cd "$T/lab/frontier/zlib2shell" && REPLAY=1 bash harness/run.sh)
```

Expect rc 0, `PASS=30 FAIL=0` and
`TRACE_SHA256=28bbacf46cc178ebea825bfc57bcc83564607b4c8a32c52d7531a2d1524d7a89`.
The count is 30 rather than 31 because `REPLAY=1` skips the nested
replay-match assertion; a plain `bash harness/run.sh` adds it and expects
31 PASS / 0 FAIL. The normalized trace records `WRITE_SIZE=1048576`,
`WRITTEN=65535`, `PRINTF_RC=1` on the fixed build and the gdb readback
`GDB_AVAIL_IN=34465`, `GDB_DST0=0x5a`, `GDB_DST17=0x44`,
`GDB_DST16384=0xc7`.

gcc and clang ASan report `heap-buffer-overflow`, `WRITE of size 983041` in
`gz_vacate()` at `gzwrite.c:394`, 0 bytes after the 16384-byte `state->in`
region; a plant-started loopback `socketpair` with a 4 KiB receive buffer
gives the same write. Fixed and safe inputs are ASan-clean on both
transports. The base harness's source bytes are the application's compression
input; the guard is allocator-dependent (the caller buffer must be allocated
after `gz_init()` for the readback), and a 20000-byte stalled write does not
trigger. W1 adds `bash harness/run_tcp.sh` on a plant-started 127.0.0.1 gzip
listener (expect rc 0, `PASS=14 FAIL=0`,
`TCP_TRACE_SHA256=3ae896390ce28d6ec551dbac3e8e6473fd7ae923be9cb7f42762721dbdd78d02`):
vulnerable-stall and 4 KiB slowdrain peers give ASan `WRITE of size 34465`
in `gz_vacate` (`gzwrite.c:394`) 0 bytes after 16384, `WRITTEN=65535`;
fixed-stall and 1 MiB-drain controls are rc 0 / `PRINTF_RC=1` / ASan-clean;
gdb readback `avail_in=34465`, `state->in[0]=0xb3`, `[17]=0x87`,
`[16384]=0x86` matches peer bytes at source offsets 65535, 65552 and 81919.
Rung 4 is strengthened to peer-chosen bytes in a live loopback server; at that
scope there is no pointer redirect, control flow, command or remote client
beyond loopback, and W1 alone establishes no rung 5. Witness W144 independently
replayed both harnesses from a clean archive and returned ESTABLISHED for base
rung 3/4 and W1 rung 4 at the labeled build scope; rung 5 was UNKNOWN at that
verdict. W4 later observed a benign command through real libuv dispatch and
witness W147 replayed that harness: rung 5 is ESTABLISHED only at the
explicitly conditioned lab scope below — non-PIE, ASLR off, a gdb-derived
293865-byte heap image replayed as peer bytes at fixed delta 293440 with a
known libc address, benign `id > file` only — not a wire-only or deployment
claim. Status: `reports/zlib2shell-status.md`.

### Post-admission W3/W4/W5 — libuv callback rewrite, observed command, negatives

The base harness pins zlib 1.2.11–1.3.2 and the published `df84af25` fix;
`harness/uv_server.c` adds a real loopback libuv consumer that allocates its
handle after `gz_init()`, and `harness/uv_probe.py` writes the command and
callback pointer from the peer payload. Pin hashes are rechecked by the
harness; generated trees are gitignored and raw output is tracked under
`harness/uv-snap-evidence/`.

```sh
T=$(mktemp -d /tmp/zlib2shell-uv.XXXXXX)
git archive HEAD lab/frontier/zlib2shell | tar -x -C "$T"
(cd "$T/lab/frontier/zlib2shell" && bash harness/run_uv_snap.sh)
```

Expect rc 0 and trace hash
`1d0b5122c8f45d6f5a1acdab8da6d4a90c00609c2ae28912e8e9461a3abb8611`, stable
across two clean replays (`SNAPSHOT_BYTES=293865`). The peer's `id>a` and
`id>b` each produce `MARKER=1` with `id` output in the corresponding file,
`UV_RAN=1` and rc 0, with no debugger attached to the exploit run (the
wrappers are `setarch`-only): libuv's own `uv_run()` calls the rewritten
`async_cb`, whose target is real libc `system` (`0x7ffff7c58750` in `.text`,
not the `0x401270` PLT stub) with `ZLIB2_UNUSED_FORCE_PLT` unset. Controls:
fixed build `MARKER=0`, `PRINTF_RC=1`; original callback kept `MARKER=0`;
ASLR on `MARKER=0`, `SERVER_RC=-11`; draining peer no overflow, `MARKER=0`.
Witness W147 replayed `harness/run_uv_snap.sh` from its own clean `git archive
HEAD` into two `/tmp` trees with its own builds: two unmodified runs were rc 0
with byte-identical traces and the same hash, and it source-bound
`uv_server.c:58-121` / `uv_probe.py:136-168` (marker only read at `:95-103`).
Grade: rung 5 ESTABLISHED only at this explicitly conditioned scope — non-PIE,
ASLR off, a gdb-derived 293865-byte pre-memmove heap image replayed as peer
bytes at the stale source offset with fixed delta 293440 and a known libc
address, benign `id > file` only. The peer cannot derive that image from the
wire in this experiment, so this is not a wire-only or deployment RCE; no
replay is owed.

Preserved negatives: W3's direct rewritten `async_cb` (peer-chosen
`system@plt` address in a real heap handle) still crashed: `uv_run()` segfaults
inside `libuv.so.1` before dispatch with no marker, and the same crash occurs
with verbatim handle bytes, so collateral heap corruption blocks that consumer
(fixed and draining controls clean, `UV_RAN=1`, rc 0, no marker; trace hash
`39c477c855862aa4f3fc37c04e81396b859afef79016014a56b4c1c732dd33c6`). W3 was
an author-side negative with no replay owed and rung 5 UNKNOWN at that verdict.
W5's wire-derivation shortcut also failed: a zero-filled 293865-byte image,
with and without the original handle bytes and two chunk headers, still
crashes `uv_run()` with `MARKER=0`, so required bytes remain distributed
through the heap. W1 alone establishes no rung 5; W144's verdict was
temporally rung-5 UNKNOWN. Status: `reports/zlib2shell-status.md`.

## Admitted frontier lane — 2026-11-23 05:1xZ snap72shell

CVE-2026-131848 / GHSA-xr6p-cjp3-pvwg, Snap7 through 1.4.3. Pins, claim
sources, verbatim source slices, fixed-control derivation and raw evidence
are in `lab/frontier/snap72shell/PROVENANCE.md`; the brief is
`reports/frontier-snap72shell.md`. `harness/run.sh` re-extracts pinned
`s7_micro_client.cpp` lines 307–431 with a `#line 307` directive on every
run, asserts all source/harness SHA-256 pins, and builds plain plus gcc/clang
ASan variants.

```
T=$(mktemp -d /tmp/snap72shell-operator.XXXXXX)
git archive HEAD lab/frontier/snap72shell | tar -x -C "$T"
bash "$T/lab/frontier/snap72shell/harness/run.sh"
```

Expect rc 0, `PASS=43 FAIL=0` and
`TRACE_SHA256=24c8438c85474ab76ade31d8c9d98e1a510f926b4f97cf6ee8948208427eda59`.
Rung 1 logs `DATALEN=65535`, `SLICE=65535`, `MAXDEST=1`, `SLICE_OVER_MAXDEST=65534`.
gcc and clang ASan report `heap-buffer-overflow`, `WRITE of size 65535`,
0 bytes after a 1-byte region, in `TSnap7MicroClient::opReadMultiVars()` at
pinned line 418. The plain build reads wire seed `0x5a` at destination offsets
0 (`DEST0=5a`) and 17 (`DEST17=6b`), and seed `0x3c` at 0 and 17 as `3c`/`4d`.
The issue-#32 derived guard returns `errCliInvalidPlcAnswer` (`RC=8388608`)
and is ASan-clean; a one-byte declared length is clean on both builds.

Boundaries of the staged slice: the response is injected into `PDU.Payload`
by an `isoExchangeBuffer()` stub — no fake PLC, socket, listener or live
client process at that scope; only 32 real payload bytes exist, so
`DEST64=00` beyond the real payload. W1 adds a separate live limb:
`bash lab/frontier/snap72shell/live/run_live.sh` starts a plant-written fake
S7 responder bound to 127.0.0.1 that drives the real pinned client library
under ASan through COTP CR/CC and Setup Communication, then answers
`Cli_ReadMultiVars()` with `ReturnCode=0xFF`, `TransportSize=0x09`,
`DataLength=0xFFFF`; expect `heap-buffer-overflow`, `WRITE of size 65535`,
0 bytes after the one-byte caller allocation in `opReadMultiVars()` at pinned
line 418. Two consecutive replays matched normalized trace SHA-256
`1f25bf6311e1a659e4da947abc07d001cfacc5fe39dd67618560e425df3773d4`
(`live/evidence/normalized.txt`, `replay1.txt`, `replay2.txt`), and W2's
`run_wide.sh` measured all 4000 real response bytes byte-exact
(`MATCHES=4000`, `FIRST_BAD_OFFSET=4000`; hash
`f254a539df2d8dd63c5dbb54e9dc6d1c8f9a7536c746768e159f817ee87c3808`). The
witness changed its responder bytes to `a7`/`3c` and the live plain client
read `DST0=a7 DEST17=3c`, confirming the bytes come from the wire; verdict
ESTABLISHED at that explicitly labeled lab-wire scope only. Both live
controls hold: the guard returns `errCliInvalidPlcAnswer` (`RC=8388608`) and
is ASan-clean, and a safe one-byte response returns 0 with `DST0=5a`. Raw
frames and logs are in `live/evidence/` and
`lab/frontier/snap72shell/PROVENANCE.md`.

W5 measured a two-item response on the live wire with
`bash lab/frontier/snap72shell/live/run_multi.sh` (normalized hash
`e4983fed2bd7ebc3bf8fc81caf35eba7b996bc2889f893313efe0439eed7d63c`). Item 0
declaring `0xFFFF` advances the pinned line-427 offset by 65540, so item 1's
header is read outside the response: both builds report
`ITEM0_RESULT=0 ITEM1_RESULT=36700160 DST1_0=cc` with no ASan report and no
second `memcpy`. The two-item safe control returns both results 0 and
`DST1_0=77`; the stale readback lands in the client's own 65536-byte `opData`,
so item 1's result is not peer-controlled. The 4000-byte chosen-byte extent is
compile-time bounded (`s7_isotcp.h:38`, `s7_partner.cpp:660-661`); no public API
raises it. Witness W6 (message #2383, tape) independently verified W5 from a
clean `git archive` at HEAD `1f8f9b9` into `/tmp/w149-snap7`, with pins
regenerated from the hash-matched local tarball `2840d50a…c613c36`:
`run_multi.sh` twice rc0 with 4/4 cases and the exact normalized hash above,
the same readouts on both builds with no ASan report, and the same 0/0,
`DST1_0=77` safe control. Raw `run_live.sh` and `run_wide.sh` hashes matched the
tracked author evidence byte-for-byte; the earlier `1f25bf63…` normalized-hash
difference is only the absolute ASan source path in the normalizer (known NIT,
deliberately unchanged). ESTABLISHED at the labeled lab-wire scope, no new rung
and no grade change; the witness wrote no repository files and left no
processes.

Ceiling: `AT:P` requires control or
impersonation of a PLC; the responder is plant-written on 127.0.0.1 with no
real PLC or external host. Peer-chosen control is bounded by the 4096-byte Iso
payload and `CheckPDU()`'s TPKT cap (`s7_isotcp.h:38`, `s7_isotcp.cpp:46-65`)
to 4000 measured bytes, not the 65535-byte copy length; bytes past the real
payload are zeroed PDU buffer (plain) or stale stack (ASan), not
peer-controlled. Upstream HEAD is still vulnerable, so the fixed control is a
pinned derivative of issue #32 rather than an upstream release. After the
copy, `PerformOperation()` (pinned lines 2632-2634) touches only the
stack-resident `Job`. W7 measured the caller fate directly with
`bash lab/frontier/snap72shell/live/run_freeprobe.sh`: destination sizes
1/1032/2048/4096/8192/16384 all fault with SIGSEGV inside the pinned
line-418 `memcpy` at the brk page boundary, before `delete[] dst` is reached,
while the 200000-byte mmap-backed control exits 0 without overflowing. W8
swept declared DataLength with `bash lab/frontier/snap72shell/live/run_modlen.sh`
(one-byte destination, 256..49152): every case exits 0 with
`CLIENT_READ_RC=0 ITEM_RESULT=0 DST0=5a`; ASan at declared=4096 still reports
`WRITE of size 4096` at pinned line 418 while gdb shows a normal exit, and
only declared=65535 faults. Even when the copy stays mapped and `free()` is
reached, no post-overflow dereference is observed — a negative measured, not
inferred. There is no pointer redirect, ROP, command, marker or rung 5
observation; rung 5 remains UNKNOWN. Status: `reports/snap72shell-status.md`.

## 2026-11-23 05:3xZ — mongoose2shell

CVE-2026-63626 / GHSA-pc66-j6r6-49x9, Mongoose <7.23, peer-controlled IPv6CP
length. Claim URLs, the vulnerable parent `8bb65c64926d`, upstream fix commit
`751f14742dea` and fixed version 7.23, and the three pinned blob SHA-256
digests are in `lab/frontier/mongoose2shell/PROVENANCE.md`. The brief is
`reports/frontier-mongoose2shell.md`; status is
`reports/mongoose2shell-status.md`. `harness/run.sh` re-extracts four verbatim
slices from both pinned `src/l2_ppp.c` blobs on every run under `#line`
directives, checks a 12-file SHA-256 manifest, and builds plain and gcc/clang
ASan variants. The direct-call harness has no daemon, listener, socket or
off-loopback probe; W1's separate real-stack limb is described below.

```
T=$(mktemp -d /tmp/mongoose2shell-operator.XXXXXX)
git archive HEAD lab/frontier/mongoose2shell | tar -x -C "$T"
bash "$T/lab/frontier/mongoose2shell/harness/run.sh"
```

Expect rc 0, `PASS=43 FAIL=0` and
`TRACE_SHA256=8c5d62a55be40595f76d3479f05a9ab4652585f07ebae13cd35017d64e3d1cb7`.
The run logs `PEER_LEN=65535`, `OPTS_WALK_LEN=65531`, `TX_DATASZ=65535` and
`OVERFLOW_BYTES=64515`. ASan on the vulnerable slices reports
`heap-buffer-overflow`, `READ of size 1` in `find_opt()` at pinned `:281` and
`WRITE of size 65535` in `ppp_tx_frame()` at pinned `:234`; gcc and clang
agree. The plain build reads `CANARY0=5a CANARY17=3c` from chosen source
bytes at rx offsets 1020/1037. The real upstream fixed blob gives
`TX_CALLS=0`, an untouched canary and no ASan report; a well-formed 14-byte
frame transmits normally and is clean on the vulnerable build.

W1 adds a real-stack ingress limb: `bash "$T/lab/frontier/mongoose2shell/live/run.sh"`
builds the byte-exact parent and upstream fix worktrees with
`MG_ENABLE_TCPIP=1 MG_ENABLE_IPV6=1`, creates a real `mg_mgr` + `mg_tcpip_if`
(PPP), and injects peer frames through `mg_tcpip_qwrite()` + `mg_mgr_poll()`
into `mg_l2_ppp_rx()` → `ppp_rx()` → `ppp_handle_ipv6cp()`. Expect 29 PASS /
0 FAIL three times and
`TRACE_SHA256=bfa4fa5fbc842e7f8cf85e4d10b96774e116d7f8a22c42f6369b083709a8fce3`:
measured `framesize=1504` (copy overflows by 64031, not the harness's 64515
past 1024), one unauthenticated LCP Configure-ACK sets `LCP_GATE_AFTER=1`
(without it `GW_AFTER=0000000000000000`), real-source ASan `READ of size 1`
in `find_opt` at `:282` and `WRITE of size 2000` in `ppp_tx_frame` at `:235`,
plus a real-stack-only `READ of size 65535` from the 8192-byte RX queue, and
chosen frame bytes at offsets 1504/1521 landing at canary offsets 0/17
(`CAN0=5a CAN17=3c`, `GW=2222222222222222`). The upstream fix is ASan-clean,
rejects with `GW_AFTER=0000000000000000` and leaves the canary at `cc`; the
14-byte frame still transits normally.

Boundaries of the direct-call harness: the handlers are direct-called,
`ppp_tx_frame_header()` and `ppp_tx_frame_trailer()` are recording stubs,
`tx.buf` is a harness-chosen 1024 bytes rather than the measured
`ifp->framesize`, and LCP completion is not modeled; there the 65535-byte read
is avoided in the large-frame case by a larger rx allocation and the
short-frame ASan case demonstrates the read separately. W1 is a separate
in-process real-stack limb using the real 1504-byte `framesize` and a real LCP
gate, but it still injects frames via the driver ISR API rather than a socket.
Witness tape #2287 replayed both harnesses from a clean git archive at
`/tmp/w146-mongoose` with its own gcc/clang builds and returned ESTABLISHED at
both explicitly labeled scopes — the direct-call pinned-slice harness and the
real-stack ingress harness — with witness-chosen `0x77`/`0x11` reaching the
canary byte-exact, no counterexample, grade unchanged and no rung 5. Ceiling:
no socket, listener, NIC, PPP/PPPoE discovery, live wire link, pointer
redirect, command or rung 5; frames are injected in-process and a future
wire/socket driver must not relabel in-process mechanics as remote compromise.
Status: `reports/mongoose2shell-status.md`.

## 2026-11-23 06:2xZ — modauthoidc2shell

CVE-2026-54789 / GHSA-vgr5-qcpp-x2pr, mod_auth_openidc `< 2.4.19.4`,
unauthenticated state-prefixed `Cookie` token without `=`. Claim URLs, the
byte-exact pinned parent `state.c.4301b536`, fix commit `8017478471cc` and
released `v2.4.19.4` blobs, and their SHA-256 digests are in
`lab/frontier/modauthoidc2shell/PROVENANCE.md`. The brief is
`reports/frontier-modauthoidc2shell.md`; status is
`reports/modauthoidc2shell-status.md`. `harness/run.sh` re-extracts the record
struct and the whole `oidc_state_cookies_parse_token()` verbatim from all three
blobs on every run under `#line` directives, checks two SHA-256 manifests
(12 files) and builds plain plus gcc/clang ASan variants. No daemon, listener,
socket or off-loopback probe.

```
T=$(mktemp -d /tmp/modauthoidc2shell-operator.XXXXXX)
git archive HEAD lab/frontier/modauthoidc2shell | tar -x -C "$T"
bash "$T/lab/frontier/modauthoidc2shell/harness/run.sh"
```

Expect rc 0, `PASS=59 FAIL=0` and
`TRACE_SHA256=bbda75f0cf7e4e1789b75bd206922f7ccbbb0c24b676e8b92fb833af4c448459`.
ASan on the vulnerable slice reports `READ of size 1` 0 bytes past a 31-byte
token in `oidc_state_cookies_parse_token` at pinned `state.c.4301b536:214`;
gcc and clang agree. The plain build dispatches the downstream processor and
places the single NUL at chosen offsets 31, 47 and 63 with the canary intact.
Both fixed slices reject the value-less token with `RC=0` and `PROCESS_CALLS=0`,
and a well-formed `mod_auth_openidc_state_abc=1` token is clean on all six
binaries.

Boundaries of the direct-call lane: stubbed request/config pointers and a
recorder; its exact-size heap token is an instrument, not a measured APR
allocation. Only the NUL offset is chosen, never its value, and ASan faults on
the read before the write, so there is no ASan WRITE observation in that build.
No pointer control, chosen command or rung 5. A separate unwitnessed
real-object probe is in the subsection below.
Witness W147 replayed the lane from a clean
`git archive HEAD` into two `/tmp` trees, rebuilt with its own gcc/clang and
ran `bash run.sh` three times unmodified: rc 0, `PASS=59 FAIL=0` and
`TRACE_SHA256=bbda75f0cf7e4e1789b75bd206922f7ccbbb0c24b676e8b92fb833af4c448459`
each time, with byte-identical normalized traces. Its full-block driver swept
`=` gaps 1, 2, 8, 16, 17, 33 and 64 and found exactly one changed byte per
vulnerable run (0x3d→0x00 at token length + gap, canary 0x5a intact); fixed
and release slices changed 0 bytes with no dispatch, and `abc=1` dispatched
in bounds on all six binaries. Rungs 1–3 and scoped rung 4 are ESTABLISHED at
the labeled direct-call scope, with no repair owed and no rung 5. The external
advisory text and the two pre-auth caller lines were not source-bound in this
lane and were not reproduced by the witness — UNKNOWN, not upgraded. Status:
`reports/modauthoidc2shell-status.md`.

### Real-object probe — 2026-11-23 (author-only, no witness)

`lab/frontier/modauthoidc2shell/realobj/driver.c` runs the verbatim parser
slice against a real `apr_pool_t`, a real Apache `request_rec` with an
`apr_table_t` Cookie header, a real `apr_pstrdup()` token and `apr_strtok()`.
`realobj/run.sh` re-extracts and hash-checks the slices and pins on every run
and builds six gcc variants; two consecutive runs gave `PASS=17 FAIL=0`
(`realobj/evidence/run6-console.txt`, `run7-console.txt`, `summary.txt`; raw
trials in `realobj/evidence/raw-trials.txt`). In 20 parent ASan trials per run
the outcome was layout-dependent under ASLR: run6 saw 15 fault summaries at
pinned `state.c.4301b536:214`, one ASan-reported WRITE `SEGV` at pinned `:219`,
and 4 dispatches; run7 saw 9, 3 and 8. The first ASan-poisoned byte was 95
bytes past the token, never at its end: APR arena allocations have no
per-object redzone, so the scan continues to an arena edge, an adjacent `=` or
an unmapped page. Plain-build parent runs stored NUL at offsets 31, 47 and 63
with dispatch; fix and release slices rejected all 10 trials each with no ASan report.
This probe itself used no full module (the parent tree and jansson headers were
absent from it), no Apache process, socket or wire; the `=` position is still
harness-placed and this probe has no witness verdict. The separate full-module
wire limb below is also unwitnessed; W147's ESTABLISHED verdict stays direct-call
only. Grade stays rung 4 scoped, with no pointer control, chosen command or rung
5. From an isolated copy:

```
T=$(mktemp -d /tmp/modauthoidc-realobj.XXXXXX)
git archive HEAD lab/frontier/modauthoidc2shell | tar -x -C "$T"
bash "$T/lab/frontier/modauthoidc2shell/realobj/run.sh"
```

The pinned upstream trees and build output are gitignored by
`lab/frontier/modauthoidc2shell/realobj/.gitignore`; the pins, hashes and raw
evidence are tracked. Status: `reports/modauthoidc2shell-status.md`.

### Full-module ASan loopback result — 2026-11-23 W6 (author-only, unwitnessed)

`lab/frontier/modauthoidc2shell/full/` provisions the complete parent module at
`4301b5364034191adcba5153e5870405855cb74e` (`src/state.c` sha256
`ceedb687…5aa`, matching the pin), jansson 2.14 and cjose 0.6.1, and builds it
with ASan against local ASan APR 1.7.4 / APR-util 1.6.3 / httpd 2.4.71; the
released `v2.4.19.4` module is the control. Both bind 127.0.0.1:18090 only;
static provider config means no metadata fetch or external contact. From
`lab/frontier/modauthoidc2shell/full`, `bash run.sh` builds and drives an
unauthenticated GET of `/protected` with
`Cookie: mod_auth_openidc_state_novalue`. Expect parent 30/30 ASan
`heap-buffer-overflow` READ at pinned `state.c:214`, full native stack through
`ap_run_check_user_id` and 30/30 empty replies; the released fix gives 0/30
faults, 30/30 HTTP 302 and zero OOB dispatches. An earlier layout-dependent run
gave 7/30 faults and 23/30 dispatches from the out-of-bounds region; all safe
controls were clean. The overflowed 8192-byte region is a real APR arena from
`ap_parse_htaccess`. The caller chain is source-bound and live:
`oidc_check_user_id` → `oidc_handle_unauthenticated_user` →
`oidc_request_authorization_set_cookie` (`handle/request.c:132`) →
`oidc_state_cookies_clean_expired` (`state.c:229`) →
`oidc_state_cookies_parse_token`. Evidence: `full/evidence/README.md`,
`run-final.txt`, `asan-asan.log.*`, `trial-codes.txt`, `error_log`.

This upgrades rung 3 to a real pre-auth wire path in a live Apache process;
rung 4 stays scoped at that verdict because ASan faults on the read before the
NUL store and the byte value is always NUL. W8 below reaches the store and
shows its offset is chosen by the wire, lifting rung 4 to an observed live-wire
scope that is still unwitnessed. No pointer control, chosen command or rung 5.
W147's ESTABLISHED verdict still covers the direct-call harness only; both W6
and W8 are author-only and the external advisory text remains UNKNOWN. What
would change the grade: a measured controlled pointer or command side effect,
or a witness replay of these probes.

### Wire-chosen NUL store — 2026-11-23 W8 (author-only, unwitnessed)

`lab/frontier/modauthoidc2shell/full/probe-store.sh` extends the full-module
probe with `Cookie: mod_auth_openidc_state_novalue;<name>=<value>` on the same
loopback `127.0.0.1:18090/protected` request. `apr_pstrdup` copies the header,
`apr_strtok` tokenizes on `;` and leaves the second cookie's `=` after the
value-less token's NUL; the `:214` scan finds it in bounds and `:219` writes
NUL there. Re-run from `lab/frontier/modauthoidc2shell/full`:

```sh
bash probe-store.sh && bash probe-gdb.sh
```

Expect `vuln dispatch=5 oob_value_peek=5` and `fixed dispatch=0
oob_value_peek=0` in `evidence/store/summary.txt`, all ten requests HTTP 302,
and no ASan report in that in-bounds regime. gdb (`evidence/store/gdb-single.txt`,
`gdb-dump.txt`, `gdb-dump-32.txt`) observed `0x3d` → `0x00` with the live
`state.c:219` → `oidc_state_cookies_clean_expired:244` → `ap_run_check_user_id`
stack; the store sits at token offset **39** with eight `z` padding bytes and
**63** with 32, i.e. `30 + 1 + <name length>`: the offset is wire-chosen, the
value is always NUL. `ASAN_OPTIONS=halt_on_error=0` did not continue past the
value-only READ fault (`evidence/store/halt-on-error-negative.log`, preserved
negative); the gdb runs end with an empty curl reply because `httpd -X` exits at
the breakpoint command list. W8's overwritten `=` lies in the already-tokenized
header copy, not a pointer-bearing field. W9 (`full/build-plain.sh`,
`full/probe-plain-oob.sh`, `full/probe-plain-detail.sh`) measured a distinct
out-of-bounds store on a live pre-auth request: at pinned `state.c:219` gdb saw
the low byte of pointer `0x7ffff5603d` become `0x00` (`0x7ffff56000`) in the
OIDC shm mapping, with a watchpoint catching no later access and the next
`apr_socket_accept` overwriting the word — the corruption is connection-scoped.
Rung 4 now includes a pointer-bearing target on a live pre-auth wire path,
still unwitnessed; the byte stays NUL, the target is not wire-chosen and no
consumer read, chosen byte value, command, marker or rung 5 is shown. This
probe is unwitnessed; W147's ESTABLISHED verdict
covers the direct-call harness only. Raw gdb captures and the exact `-ex`
command lists are tracked under `full/evidence/store/` and `full/probe-gdb.sh`;
no upstream fetch is needed if the W6 module builds are present.

### W10 same-connection consumer check — 2026-11-23 (author-only, unwitnessed)

Re-run from `lab/frontier/modauthoidc2shell/full`: `bash build-plain.sh && bash
probe-plain-oob.sh && bash probe-plain-keepalive.sh`. Expect
`STORE=0x7ffff6de2221 WORD=0x7ffff5603d` and `AFTER=0x7ffff56000`, three HTTP
302 replies on one TCP connection, and no watchpoint hit, `Old value`/`New
value` or watch-stop backtrace before the 70 s timeout
(`evidence/plain-oob/keepalive/`). The one-off `LD_PRELOAD` trace
(`evidence/plain-oob/alloc-trace/`) found no allocation covering the word
(nearest starts 0x6f bytes later; intra-libapr calls bypass interposition).
Both are negatives: no consumer of the corrupted word was observed. Grade
unchanged, rung 4 scoped, byte always NUL.

### W11 response-path store — 2026-11-23 (author-only, unwitnessed)

Re-run: `cd lab/frontier/modauthoidc2shell/full && bash build-plain.sh && bash
probe-plain-response.sh`. With `GET /redirect_uri?code=foo&state=foo` and the
value-less state cookie, gdb at pinned `state.c:219` shows
`oidc_response_proto_state_restore` (`handle/response.c:353`), the second
pre-auth caller; expect `STORE=0x7ffff6ddc05e WORD=0x617473266f6f663d`
(`=foo&sta`) → `AFTER=0x617473266f6f6600` (`\0foo&sta`), the wire-chosen `=` of
`code=foo` in the copied request line. Expect HTTP 400, the adjacent
request-line text dispatched to `oidc_state_cookies_process_one` with JWE
decode failure, and no watchpoint read/write of the word
(`evidence/plain-oob/response/`). Grade unchanged: rung 4 scoped, byte always
NUL, no dereference, chosen byte, pointer control, command or rung 5.

### W12 long value-less token fault — 2026-11-23 (author-only, unwitnessed)

Commit `eaa2ee2` folds W12 in the admitted 103rd route: no new row, stage,
mind count or grade. Grade stays rung 3 on the live pre-auth wire and rung 4
scoped and unwitnessed there; this is not a witness verdict. A bare 7800-byte
value-less Cookie token faulted a plain-module child (`AH00051 ... exit
signal Segmentation fault (11)`) in 2/3 extended sweeps, but not in one sweep
or a fresh-server 30-request bare-7800 sweep. It is an intermittent
observation, not a deterministic crash primitive.

A lab-only `sigaction(SIGSEGV)` interposer with `libasan.so.8` preloaded made
the bare-7800 request fault 60/60 and print a backtrace whose top module
frame `oidc_state_cookies_clean_expired+0x2b3` resolves via `addr2line` to
`state.c:219` in `oidc_state_cookies_parse_token`, reached from
`oidc_check_user_id` → `ap_run_check_user_id`. The same-length well-formed
token returned 302 on 10/10 and released v2.4.19.4 on the same plain stack
returned 302 on 10/10 with zero backtraces. The shim changes signal handling
and allocator layout: it attributes the frame but does not raise the native
crash rate. gdb with ASLR off, ASLR on and fork-following reproduced no fault
(6/6, 6/6 and 40/40 HTTP 302). The overwritten byte is always NUL; there is
no chosen byte, pointer target, consumer dereference, command or rung 5.

```sh
cd lab/frontier/modauthoidc2shell/full && bash build-plain-fixed.sh && bash probe-plain-crash.sh && bash probe-plain-crash-7800.sh && bash probe-plain-crash-sigsegv.sh && bash probe-plain-fixed-sigsegv.sh
```

The sweep covers 1/16/128/1024/4096/7800 bytes; no new PASS count. Pins:
parent `state.c` `ceedb687…5aa`, module `0089906…0a7`; fixed `state.c`
`f02d8ddb…7ce`, module `b16278d2…d98`. Raw evidence is in
`full/evidence/plain-crash/` (README.md, codes.txt and the
FIRST-RUN-20261123T1406Z.md transcription tracked; `error.log` and the
gdb-*/fork-*/sigsegv-*/fixed-* transcripts gitignored). Status:
`reports/modauthoidc2shell-status.md`.

### W14 build-stack correction — 2026-11-23 (no grade change)

Commit `77678ab` corrects the "non-ASan plain" label on W9-W13. The
`build-plain.sh` module
`008990618887dde66e4371d1a354c64dccf29c40d36d17c4ac1d8e5f8b375654` and the
serving httpd both link `libasan.so.8`; apxs injected `-fsanitize=address`
into the module compile and `nm -D` shows ASan report calls. Check with `ldd`
on the module and httpd and `nm -D` on the module; commands and output are in
`lab/frontier/modauthoidc2shell/PROVENANCE.md` § "Build-stack correction
(2026-11-23 W14)". W13's SIGSEGV had no added shim or preload but ran the ASan
allocator, so `ASAN_OPTIONS=detect_leaks=0` is a change to that allocator's
layout, not to a production heap. The faults, stored bytes and controls stand;
no availability claim on a non-ASan stack. Grade unchanged.

## 2026-11-23 06:4xZ — radvdump2shell

CVE-2026-48715 / GHSA-52px-gh9p-m379, radvd `<= 2.20`, fixed in `2.21` by
`068bde13`. Claim URLs, the six byte-exact SHA-256 pins (vulnerable `878ca6b`
and `v2.20` identical, fix `068bde13` and `v2.21` identical), the four
verbatim `print_ff()` case slices and the raw evidence are in
`lab/frontier/radvdump2shell/PROVENANCE.md`. The brief is
`reports/frontier-radvdump2shell.md`; status is
`reports/radvdump2shell-status.md`. `harness/run.sh` re-extracts the four case
bodies from the pinned blobs on every run under `#line` directives, checks a
6-file source manifest and a 12-file harness manifest, and builds four plain
and four sanitizer binaries. The direct-call harness has no daemon, raw
socket, listener or off-loopback probe; the separate 07:02Z live limb below
does use a root raw socket on loopback.

```
T=$(mktemp -d /tmp/radvdump2shell-operator.XXXXXX)
git archive HEAD lab/frontier/radvdump2shell | tar -x -C "$T"
bash "$T/lab/frontier/radvdump2shell/harness/run.sh"
```

Expect rc 0, `PASS=67 FAIL=0` and
`TRACE_SHA256=cf327179a2abca7647a1a8bd3b58259a398c7de94f24a27910f3a356d8d3788a`.
ASan on the vulnerable slice reports `stack-buffer-overflow`, `WRITE of size
256` at pinned `radvdump.c.878ca6b:380` in `route_case`, with gcc and clang in
agreement; the fixed-commit and 2.21 slices log
`Invalid Route Information option length 33` and never copy, and an
RFC-conformant length-2 option is clean on all six ASan/plain variants. The
plain build places chosen bytes at copy offsets 17/24/33/40/63 past the
16-byte object and gdb reads `saved rip = 0x414141414141417b` at pinned line
381.

Boundaries: the direct-call case body is called with stubbed `flog`,
`addrtostr` and `print_preferences`; plain builds use `-O0 -g
-fno-stack-protector` because Ubuntu's default stack protector aborts before
observation, so that limb's rung 4 is scoped to the synthetic frame. The live
limb below drives genuine v2.20 binaries and controls a live pointer and a
full saved-RIP value, so pointer control beyond one saved-RIP byte exists at
that explicitly labeled author-only scope. Ceiling at the 07:02Z limb: the
process SIGSEGVs at pinned line 382 while dereferencing the smashed `rinfo`
before `print_ff` can return, so the controlled saved RIP is never reached as
control flow. That limb used ASLR on and had no usable addresses; the later
07:46Z limb below changed those conditions and is witness-ESTABLISHED, so this
ceiling is historical, not the current one. The length-33 copy cannot reach
saved RIP; the length-40 copy can.
Plain `-O0` plus ASan faults at the WRITE, `-O2` with the host's default
`_FORTIFY_SOURCE 3` aborts in `__memcpy_chk`, and `-O2 -U_FORTIFY_SOURCE`
copies but gives no pointer control and no crash, so ordinary distro builds
are mitigated. The lab sender needs root for `CAP_NET_RAW` and injects on the
same host's loopback, not from a network-adjacent neighbour. The fix's
root-drop, buffer-zeroing, jumbo-packet and earlier-loop changes are outside
this callpath.

### Post-admission live-binary replay — 2026-11-23 07:02Z (author-only, historical limb)

Affected: genuine upstream v2.20 tag tarball, whose `radvdump.c` sha256 is
`0beaaaf74ebf93835331efacac5986769f53388b5e8bed8e65c1999fa086355b`
(identical to pinned vulnerable `878ca6b`). Fixed: v2.21 tag tarball and fix
commit `068bde13e3fd6a5fcdb6859e6a2acd293a325dc5`, whose `radvdump.c` sha256
is `bfe1f0f6800b2955b1ee6994c9f8c6f70e9663f1f318ffc98adbd338b47b48b5`.
Source trees and tarballs are gitignored by `real/.gitignore`; the raw
`real/evidence/live-*.out` are tracked. In `lab/frontier/radvdump2shell/real/`,
the recorded builds from the public tag tarballs used:

```sh
tar -xzf radvd-2.20.tar.gz && (cd radvd-2.20 && \
  ./configure 'CFLAGS=-g -O0 -fsanitize=address -fno-omit-frame-pointer' \
    LDFLAGS=-fsanitize=address && make radvdump)
tar -xzf radvd-2.21.tar.gz && (cd radvd-2.21 && \
  ./configure 'CFLAGS=-g -O0 -fsanitize=address -fno-omit-frame-pointer' \
    LDFLAGS=-fsanitize=address && make radvdump)
# plain pointer-control tree: ./configure 'CFLAGS=-O0 -g -fno-stack-protector' && make radvdump
```

`real/send_ra.py` builds and checksums an ICMPv6 RA and sends it as a unicast
packet to `::1` scoped to `lo` from a root raw socket (`CAP_NET_RAW`); modes
`attack` (length byte 33, 256-byte copy), `ptr` (chosen bytes at copy offset
112), `rip` (length byte 40, 312-byte copy, chosen bytes at offset 296) and
`safe` (length byte 2) are all on loopback only.
Run from an isolated copy so the tracked evidence is not overwritten:

```
T=$(mktemp -d /tmp/radvdump-live.XXXXXX)
git archive HEAD lab/frontier/radvdump2shell | tar -x -C "$T"
REAL="$T/lab/frontier/radvdump2shell/real"
```

The tarballs and build trees are gitignored, so rebuild them in the copy with
the commands above before driving the binaries. From the repository root:
```sh
REAL=lab/frontier/radvdump2shell/real
bash $REAL/run_live.sh $REAL/radvd-2.20/radvdump attack $REAL/evidence/live-vuln-asan.out
bash $REAL/run_live.sh $REAL/radvd-2.20/radvdump safe $REAL/evidence/live-safe-asan.out
bash $REAL/run_live.sh $REAL/radvd-2.21/radvdump attack $REAL/evidence/live-fixed21-attack.out
```

Expect `receiver if_index: 1`, then
`AddressSanitizer: stack-buffer-overflow`, `WRITE of size 256` at
`radvdump.c:380` in `print_ff`, called from `main` at `radvdump.c:127`, with
the fault at frame offset 112 just past `[96,112) 'addr'`
(`live-vuln-asan.out`). The length-2 `safe` run parses cleanly with zero ASan
and prints an RFC 4191 route (`live-safe-asan.out`); v2.21 with the same
attack logs `Invalid Route Information option length 33 from ::1`, prints the
RFC 4191 rejection and never copies (`live-fixed21-attack.out`). For the gdb
cases, break at `radvdump.c:381` in the plain `-O0 -g -fno-stack-protector`
v2.20 binary and send `ptr` / `rip` with `send_ra.py`; expect respectively
`rinfo = 0x1234567812345678` at copy offset 112
(`live-gdb-pointer-control.out`) and `saved rip = 0x1234567812345678` at copy
offset 296 (`live-gdb-saved-rip.out`). `&addr = rbp-288`, so saved RIP is at
`rbp+8` = copy offset 296, and `defaults.h:23` allows `MSG_SIZE_RECV 1500`,
so length byte 40 fits in a 336-byte RA. Both processes then SIGSEGV at pinned
line 382. Negatives: `-O0` + ASan faults at the WRITE; `-O2
-fno-stack-protector` aborts in `__memcpy_chk` with `*** buffer overflow
detected ***` under the host's default `_FORTIFY_SOURCE 3`
(`live-gdb-O2.out`); `-O2 -fno-stack-protector -U_FORTIFY_SOURCE` copies but
gives no pointer control and no crash (`live-gdb-O2-nofort.out`); length 33
cannot reach saved RIP. Grade at that limb: rung 4 on living bytes, author-only
with no witness verdict; its no-ROP/no-marker ceiling was superseded for the
grade by the 07:46Z limb below (W149 ESTABLISHED at its labeled lab scope).
Status: `reports/radvdump2shell-status.md`.

### Rung-5 wire demonstration — 07:46Z (author-only) + W149 witness ESTABLISHED

`defaults.h:23` (`MSG_SIZE_RECV 1500`) admits an option length byte up to 185;
length byte 60 makes a 496-byte RA whose `(len-1)*8 = 472`-byte copy reaches
the saved RIP and leaves room for a ROP chain. A genuine upstream v2.20
`radvdump` built `-O0 -g -fno-stack-protector` (no stubs), launched under gdb
with inferior-level `disable-randomization`, received one crafted RA at
`::1%lo` from a root raw socket. From `lab/frontier/radvdump2shell/real`,
`bash repro_rung5.sh` is the one-command author replay: ATTACK =>
MARKER_PRESENT and four CONTROLS => MARKER_ABSENT. Tooling:
`real/{send_marker.py,marker.gdb,run_marker.sh,run_controls.sh,repro_rung5.sh}`;
raw outputs: `real/evidence/{marker-attack-5,6,7,control-*}.out`.

At pinned line 381 the author build measured `&addr = 0x7fffffffe220`,
`rinfo = 0x55555555d010` (readable `usage_str` stand-in), `system =
0x7ffff7c58750` and `saved rip = 0x7ffff7d0f84b` (`pop rdi; ret`). The chain
`pop rdi; ret -> &command -> ret (8-mod-16 alignment) -> system -> exit` ran
after `print_ff` printed its route block; gdb logged a vfork detach and
inferior exit code 02, and the observable side effect was a root-owned
zero-byte `/tmp/radvdump2shell-marker` (3/3 attacks). `system()` is not
radvdump's normal callpath. Controls on the same 496-byte RA: RFC-conformant
length byte 2 parses cleanly with no marker; fixed v2.21 logs `Invalid Route
Information option length 60` with no copy or marker; ASLR-on without gdb
SIGSEGVs in the ROP with no marker; fortified `-O2` aborts with `*** buffer
overflow detected ***` from `__memcpy_chk` with no marker. `sudo` clears
`ADDR_NO_RANDOMIZE`, so `sudo -n setarch -R ./radvdump` leaves ASLR on — gdb's
inferior-level disable-randomization is what fixes addresses; the extra `ret`
is required for stack alignment (without it `system` SIGSEGVs in `do_system`,
`marker-attack-3.out`).

Independent witness W149 (DM #2388, tape) replayed the claim from its own
clean `git archive HEAD (1f8f9b9)` into `/tmp/w149-radvdump`, hash-checked the
upstream tarballs and pinned `radvdump.c` (v2.20 `0beaaaf7…086355b`, v2.21
`bfe1f0f6…47b48b5`), ran `autogen.sh` and built its own binaries: plain
`-O0 -g -fno-stack-protector` sha `723b6ce6…7cc43f6d`, fixed 2.21
`194ade7c…d73b4d2a`, fortified `-O2` `b19eecbf…5f6de72c` (imports
`__memcpy_chk`). Its passive gdb measurements found `&addr=0x7fffffffe260`,
saved RIP at `$rbp+8 = &addr+296`, `system=0x7ffff7c58750`,
`exit=0x7ffff7c47ba0`, `usage_str=0x55555555d010` and
`x/3i 0x7ffff7d0f84b = pop %rdi; ret` — different absolute addresses from the
author's (0x40 apart), so they are per-process values, not constants. Its
496-byte RA carried a witness-only command
`/usr/bin/touch /tmp/w149-radvdump-witness-marker` at copy offset 336 and its
own addresses; 4/4 attacks under gdb ASLR-off created a fresh root-owned
zero-byte witness marker and never the author's default marker. A passive
pending breakpoint on `__libc_system` stopped with `$rdi = 0x7fffffffe3b0`
holding exactly the wire string, with no debugger writes; gdb logged a vfork
detach and exit code 02. All four controls on witness builds were
MARKER_ABSENT (length 2, fixed 2.21, ASLR-on, fortified `-O2`). The witness
wrote no repository files, removed its marker and left no processes. Verdict:
rung 5 ESTABLISHED at the explicitly labeled lab conditions (non-fortified
`-O0`, ASLR off in the lab debugger, host-measured addresses, root
`CAP_NET_RAW` sender on `::1%lo`, benign `touch`); no stock hardened-build
claim, no wire-derived addresses, no external target and no new rung. The
07:02Z fortify/length-33 SIGSEGV negatives are preserved, not relabeled as
passes. No further witness replay is owed.

## 2026-11-23 07:0xZ — fluentbit2shell

CVE-2026-61674 / GHSA-jrp8-r9hx-gf73, Fluent Bit `>= 0.11.0, < 5.0.8`, fixed
in 5.0.8 by `45486556`. Claim URLs, the pinned blobs (vulnerable `47db630c`
and `v5.0.7` identical, fix `45486556` and `v5.0.8` identical), the fix patch,
the four verbatim `secure_forward_pong()` slices and the raw evidence are in
`lab/frontier/fluentbit2shell/PROVENANCE.md`. The brief is
`reports/frontier-fluentbit2shell.md`; status is
`reports/fluentbit2shell-status.md`. `harness/run.sh` re-extracts each complete
function body from the pinned blobs on every run under `#line` directives,
checks a 6-file source manifest and a 12-file harness manifest, builds plain
and ASan variants with gcc and clang, and drives rungs 1–4. No daemon,
listener, socket, TLS handshake or off-loopback probe is used.

```
T=$(mktemp -d /tmp/fluentbit2shell-operator.XXXXXX)
git archive HEAD lab/frontier/fluentbit2shell | tar -x -C "$T"
bash "$T/lab/frontier/fluentbit2shell/harness/run.sh"
```

Expect rc 0, `PASS=65 FAIL=0` and
`TRACE_SHA256=35e7c470871e94379158696aa6899f13db4413b61153d53c4df6296f04061d96`.
ASan on the vulnerable slice reports `stack-buffer-overflow`, `WRITE of size
1000` at pinned `forward.c.47db630c:567` in `secure_forward_pong`, with gcc
and clang in agreement; the fix-commit and v5.0.8 slices reject the 1000-byte
reason and NUL-terminate at byte 31, and a 4-byte reason is clean on all
seven plain/sanitizer variants. The plain build places chosen bytes at copy
offsets 0/17/24/33/40/48/56/63 and gdb reads
`saved rip = 0x414141414141417b` at pinned line 568 before the fault at line
574.

Boundaries: the function is direct-called with stubbed msgpack and flb
plumbing; plain builds use `-O0 -g -fno-stack-protector` because Ubuntu's
default stack protector aborts before observation. There is no real Fluent
Bit process, socket, TLS/SRP handshake, HELO/PONG wire exchange, canary, ROP
chain, pointer redirect, command, witness verdict or rung 5.

Later limbs supersede that boundary for the grade: W1/W2 built real 5.0.7
and drove the same PONG over loopback to ASan corruption, chosen saved-RBP/
RIP control and a no-debugger PONG-carried ROP chain running a benign `touch`
marker. Witness W150 (#2415) independently replayed live-wire rungs 3/4 and
the conditional rung 5 from a clean `git archive HEAD c076655
lab/fluentbit2shell` with its own hash-matched builds, ports and chain.
Exact recipe, pins and conditions: `reports/fluentbit2shell-livewire.md`
§1-§6 and `reports/fluentbit2shell-status.md` §W3. The harness recipe above
still reproduces the admission-time direct-call evidence exactly; it is not
a live-wire replay.

## 2026-11-23 07:1xZ — ffmpeg2shell staged W142 (admitted 07:4xZ)

CVE-2026-75143 / GHSA-7qc3-xqxj-426p, FFmpeg `librist_read()`, first fixed
release `n9.0.1` by commit `1c10bcc2`. Byte-exact pins for `librist.c.7b05d16c`
and `n9.0` (vulnerable, identical) and `1c10bcc2` and `n9.0.1` (fixed,
identical), plus claim URLs and the fix patch, are in
`lab/frontier/ffmpeg2shell/PROVENANCE.md` and `src/SHA256SUMS`. The brief is
`reports/frontier-ffmpeg2shell.md`. The route, charter mind and window were
admitted at 07:4xZ below; the `check-omp-only.py` RED that once marked this
staged lane is resolved. This section still reproduces the original harness
only: no daemon, RIST peer, socket, listener, TLS handshake or off-loopback
probe is used by that harness.

```
T=$(mktemp -d /tmp/ffmpeg2shell-operator.XXXXXX)
git archive HEAD lab/frontier/ffmpeg2shell | tar -x -C "$T"
bash "$T/lab/frontier/ffmpeg2shell/harness/run.sh"
```

Expect rc 0, `PASS=66 FAIL=0` and
`TRACE_SHA256=6c3586c5d5b510b9619431873b157055c97edc32c5b6eda9967eb4feae61629f`.
The harness includes the complete verbatim `librist_read()` from all four
pins with stubbed librist/libavformat plumbing and checks source and slice
SHA-256 manifests on every run. gcc and clang ASan report
`heap-buffer-overflow`, `WRITE of size 9972` at pinned
`librist.c.7b05d16c:230`, 0 bytes past a 4096-byte destination (the async
caller cap); fix and `n9.0.1` copy 4096 bytes and leave the adjacent 0xCC
pattern intact, a 4-byte payload is clean, and 9973 bytes is rejected with
`RET=-5` in every variant. Plain gdb reads chosen
`41/5a/7a/3c/7b/42/7b/41` at offsets 4096/4113/4120/4128/4136/4144/4152/4160
and deep smear at 5000/9000 in the 20000-byte adjacent harness sink.

Boundaries of the original harness: direct call only; no `ffmpeg` process,
RIST socket, peer, wire exchange, async thread or real ring allocation,
TLS/SRP, attacker sender or event loop. Its adjacent sink is a harness
artefact and the real ring's neighbours were UNKNOWN at that stage. Chosen
values are byte patterns, not pointers, gadgets or a command. Source trees
and build output are gitignored by `lab/frontier/ffmpeg2shell/.gitignore`;
the harness evidence and normalized trace are tracked. No pointer control,
ROP chain, command, marker side effect, witness verdict or rung 5 in that
harness; the later live limb below supersedes these boundaries.

## 2026-11-23 07:4xZ — ffmpeg2shell operator clean-archive replay

Admission re-ran the frontier recipe from committed bytes only:

```
T=$(mktemp -d /tmp/ffmpeg2shell-operator.XXXXXX)
git archive HEAD lab/frontier/ffmpeg2shell | tar -x -C "$T"
bash "$T/lab/frontier/ffmpeg2shell/harness/run.sh"
```

Observed rc 0, `PASS=66 FAIL=0` and
`TRACE_SHA256=6c3586c5d5b510b9619431873b157055c97edc32c5b6eda9967eb4feae61629f`
in `/tmp/ffmpeg2shell-operator.U0crbe`, byte-identical to frontier's W142
value. The harness re-extracts four complete upstream `librist_read()`
slices from hash-pinned blobs on every run under `#line` directives and
checks a 7-file source manifest plus a 13-file harness manifest; no daemon,
listener, socket, RIST peer or off-loopback probe is used. Rung 3 is gcc and
clang ASan `heap-buffer-overflow`, `WRITE of size 9972` at pinned
`librist.c.7b05d16c:230`, 0 bytes past the 4096-byte destination; rung 4 is
chosen bytes at offsets 4096/4113/4120/4128/4136/4144/4152/4160 and deep
smear at 5000/9000 in the adjacent 20000-byte harness object, read back
under gdb at pinned line 233. Fix-commit and `n9.0.1` slices clamp to 4096
and leave the adjacent object at 0xCC; 4-byte and 9973-byte inputs are clean
or rejected in all four variants. Admission adds a hy4-flash route and three
full-flag-sync units. The admission grade was author-observed; the later live
limb and W151 witness verdict below supersede it.

## 2026-11-23 08:1x–09:0xZ — ffmpeg2shell live RIST limb and witnesses

The live path needs a real FFmpeg n9.0 `ffprobe` with librist support and a
plant-driven loopback RIST sender through `async:rist://`; the built binaries
and scripts are in `lab/frontier/ffmpeg2shell/live/`, and
`live/run-cases.sh` runs the vulnerable, fixed and safe cases against them.
Source pins, configure/make commands, hashes and logs are in
`reports/ffmpeg2shell-live.md`; no off-loopback probe was used. About 2200
packets of 9968 bytes walk the 8 MiB FIFO write pointer to its end; ASan then
reports `WRITE of size 9968` at `libavformat/librist.c:230`. A stock librist
sender caps packets at 9968, four below FFmpeg's 9972 receive gate.

Witness W151 verdict #2428 replayed this path from a clean
`git archive HEAD cbeeafa` with its own builds and port 5514: ASan `WRITE of
size 9968` in both vulnerable cases, fixed and safe inputs clean, and the
same chosen bytes at offsets 4096/4113/4120/5000/9000 under gdb. Rungs 3/4
are ESTABLISHED at the labeled live-loopback / ASan / ~8 MiB ring-wrap scope;
its plain build reproduced the default-layout ceiling — SIGSEGV (`rc=139`)
at a read-only libc mapping, no writable neighbour. W3's author-only brk
layout (`MALLOC_MMAP_THRESHOLD_=16777216`, a local prerequisite, not
attacker-controlled) put the FIFO on `[heap]` and the sender's 0x5a fill
overwrote the low byte of `AVFifo.buffer` and `URLContext.prot`; the consumer
dereferenced the corrupted buffer at `fifo.c:226`. No chosen target address,
control transfer, marker, command or witness replay for W3, which #2428 did
not cover. Raw evidence: `live/evidence/live-*.log` and
`live/evidence/layout-brk-*.log`; status in
`reports/ffmpeg2shell-status.md`.

## 2026-11-23 09:1xZ — thrift2shell staged by frontier W143 (not admitted)

CVE-2026-55971 / GHSA-gwj4-q93m-wwqc, Apache Thrift C++
`THeaderTransport::untransform()` ZLIB copy-back write overflow. Affected
before `0.24.0`; fixed `0.24.0` by commit
`db4a473f3a984eee27273256fe737be5dd175595` ('Read the zlib transform result
directly in THeaderTransport'), which swaps the receive and transform buffers
instead of copying back. GHSA: Critical 9.3,
`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CWE-122.
The GHSA metadata fields are stale, and the captured cve.org page is an
880-byte JS shell used for no claim. Staging commit
`42abf3ae31d827acdd622341dbe6f4abe769e416` (parent `f5a50cb8…`). Brief:
`reports/frontier-thrift2shell.md`; pins, slices, stubs and replay record:
`lab/frontier/thrift2shell/PROVENANCE.md`. Staging adds no admission, omp
route, wake units, charter, presentation entry or new window; window 111
already existed at handoff, so the mind list stays at 106 admitted targets.

Replay from committed bytes only:

```sh
T=$(mktemp -d /tmp/thrift2shell-operator.XXXXXX)
git archive HEAD lab/frontier/thrift2shell | tar -x -C "$T"
bash "$T/lab/frontier/thrift2shell/harness/run.sh"
```

Expect rc 0, `PASS=71 FAIL=0` and
`TRACE_SHA256=c12ba2145cec292e618d2f50677887c61a56d577b012577cd50c304731bbe556`.
The runner re-extracts the complete `untransform()` from four pinned blobs
under `#line` directives, checks 9 files in `src/SHA256SUMS` and 15 in
`harness/SHA256SUMS`, and verifies the fix patch's git blob prefixes
`cdf29cf3d53` (preimage) / `891059b888e` (postimage). Byte-exact source pins
(SHA-256 from `lab/frontier/thrift2shell/PROVENANCE.md:16-24`): v0.23.0
`THeaderTransport.cpp` `b2c85bae…7737c`, fix parent `c5d92829…d513a`, fix
commit `ddcb785f…c3941`, v0.24.0 `d3e62f54…667aa`,
`THeaderTransport.h.v0.23.0` `7a854d06…ac2dbc`, patch `116d0411…f869`,
GHSA HTML `22c6b3c0…51271`, vendor advisory `80d76549…14bf2` and CVE HTML
`3c1e35d4…6d4d5`.

Expected observations: rung 1 `COMPRESSED_LEN=31 DECOMPRESSED_LEN=700
DEST_BYTES=31 OVERFLOW_BYTES=669 TBUF_SIZE=1024`; rung 2 v0.23.0 and fix
parent give `SET_SIZE=700`, `SETPTR_IS_RBUF=1`, `DST_UNCHANGED=0` and smear
the adjacent sink (`SINK_DIST=48`, `SINK_BYTE_1=42`, `SINK_BYTE_16=3c`),
while fix and v0.24.0 give `SETPTR_IS_ORIG_TBUF=1`, `DST_UNCHANGED=1` with
the sink still 0xCC, and the `avail_out == 0` gate rejects 4096 bytes in
every variant; rung 3 gcc and clang ASan `heap-buffer-overflow`, `WRITE of
size 700` at pinned `THeaderTransport.cpp.v0.23.0:301` (fix parent `:320`),
0 bytes after the 31-byte region, with fix, v0.24.0 and safe inputs clean;
rung 4 chosen bytes `41/5a/7a/3c/7b/42/7b` at inflated offsets
0/16/32/64/128/256/699, with gdb at pinned `:301` showing `sz=700` versus
the fixed build's swap at `sz=31` and intact sink.

Raw compiled binaries are gitignored by
`lab/frontier/thrift2shell/.gitignore` (`harness/a-*`, `harness/p-*`) and
rebuilt on every run; pinned sources, both SHA-256 manifests, driver/runner
and normalized `harness/evidence/` outputs are tracked. Ceiling: direct call
with a stubbed object environment; no real Thrift process, framing parser,
transport stack, socket, server, peer, wire exchange, pointer control, ROP,
command, marker side effect, witness verdict or rung 5. Live-server
reachability is UNKNOWN; the advisory's `AV:N` is a claim, not a lab
observation.

## 2026-11-23 09:1x–09:3xZ — ffmpeg2shell W4 wire-driven command

The W4 limb continues the live RIST limb above. No upstream fetch is needed
at replay time if the `live/` build from that entry is present; otherwise
repeat its librist and FFmpeg n9.0 build commands first. All traffic is to
127.0.0.1:5004. Witness W153 (#2461) replayed the four no-gdb checks with
witness-owned builds (port 5714, its own marker paths and `/usr/bin/touch`
variants) and ESTABLISHED the rung-5 command claim at the labeled scope; the
conditions below are part of that scope.

Build the three W4 senders from the repository (they are tracked):

```sh
cd lab/frontier/ffmpeg2shell/live
for s in ptr struct marker cmd; do
  gcc -O2 -o rist_sender_$s rist_sender_$s.c \
    -I prefix/include -L prefix/lib -lrist -Wl,-rpath,$PWD/prefix/lib
done
```

Pointer reachability without a debugger write: `./reach-plain.sh` expects
`RP FIRST HIT` followed by `RP NEXT DISPATCH prot=0x5a5a5a5a5a5a5a5a`.
Wire-chosen target: `./ptr-control.sh pc-file plain/src/ffprobe_g
0x55555584f5a0 9968` expects `New value = ... <ff_file_protocol>`.

The no-debugger command matrix is authoritative. Run the four cases
sequentially (never concurrently — they share port 5004):

```sh
./no-gdb-case.sh ng-v4 plain/src/ffprobe_g /tmp/w4-v \
  'touch /tmp/w4-v' 9968 rist_sender_cmd 0x7ffff7a58750
./no-gdb-case.sh ng-f4 plain/src/ffprobe_g-fixed /tmp/w4-f \
  'touch /tmp/w4-f' 9968 rist_sender_cmd 0x7ffff7a58750
./no-gdb-case.sh ng-s4 plain/src/ffprobe_g /tmp/w4-s \
  'touch /tmp/w4-s' 512 rist_sender_live
./no-gdb-case.sh ng-n4 plain/src/ffprobe_g /tmp/w4-n \
  'touch /tmp/w4-n' 9968 rist_sender_cmd 0x0
```

Expect `marker=CREATED` only for `ng-v4` (`ffprobe rc=134` from later heap
corruption, sender rc 0, 2200 blocks 0 failures) and `marker=absent` for the
FFMIN-fixed, 512-byte safe and null-callback cases. Recorded digests and
full expected lines are in `evidence/w4-nogdb-matrix.summary.txt`.

Conditions are part of the claim: `MALLOC_MMAP_THRESHOLD_=16777216` to put
the 8 MiB FIFO on `[heap]`; `setarch -R` to disable ASLR so the lab-measured
PIE/libc addresses hold (`ff_file_protocol 0x55555584f5a0`, `system
0x7ffff7a58750`, `puts 0x7ffff7a87cc0`, ring `0x5555558d1fe0`,
`URLContext 0x5555560d2080`); main-profile unencrypted RIST; ~8 MiB
streamed to walk the ring write pointer to the wrap; no debugger attached.
`system()` under gdb is not a valid replay because gdb holds the forked
shell. Witness W153 (#2461, 2026-11-23 09:51Z) replayed all four cases with
witness-owned builds on port 5714, re-deriving `&system 0x7ffff7a58750`,
`&ff_file_protocol 0x55555584f5a0` and `h 0x5555560d2080`; the fixed, safe
and cb=0 controls stayed marker-absent (rc 124/134). It ESTABLISHED W4 at
that labeled no-ASLR, local-brk-layout, lab-measured-address, benign-touch
scope only. The default-mmap read-only ceiling from W2 is unchanged; no
ASLR-on or stock-layout execution is claimed.


## 2026-11-23 09:3xZ — psqlodbc2shell staged by frontier W144 (not admitted)

CVE-2026-120061 / GHSA-hfm6-qfx8-v4xq (High 7.5,
`CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-121/193/457), affected
`<= 18.00.0005` / patched `18.00.0006`; security fix merge
`79f4631db27cdb62276d3d9d3c1e5c47dcc315c0`. Brief:
`reports/frontier-psqlodbc2shell.md`; tag commits, blob IDs and source hashes:
`lab/frontier/psqlodbc2shell/PINS.sha256`; provenance and preserved negatives:
`lab/frontier/psqlodbc2shell/PROVENANCE.md`. A two-pane window (inner socket
index 112, `psqlodbc2shell`) is registered, but no route, charter admission or
witness verdict exists; staging does not change the 106 admitted target minds.

No upstream fetch is needed at replay time: both pinned `convert.c` blobs are
committed under `lab/frontier/psqlodbc2shell/src/`. The runner re-extracts
`F_ExtractOldTo` (lines 2424-2436) and `processParameters` (vulnerable
5607-5698 / fixed 5607-5710) from those blobs under `#line` directives and
builds gcc and clang plain/ASan drivers:

```sh
cd lab/frontier/psqlodbc2shell/harness
./run.sh && ./check.sh
```

Expect `PASS=34 FAIL=0` from `check.sh` and
`TRACE d5145bdbd72b30af5a5d5d0824d6497db85781260386d6984f0455954d424d63`
from `run.sh`. Expected bytes: gcc and clang ASan `WRITE of size 8` at pinned
`convert.c.vuln:5637` in `processParameters` and `WRITE of size 1` at `:2424`
in `F_ExtractOldTo`; both fixed ASan runs report
`EXTRACT_ASAN RETVAL=0 BUF127=00` and the fixed function run prints
`too many parameters in the escape function call`. Plain vulnerable runs
report `FIRST_DIFF=0 CHOSEN_5A=112` and a sink dump starting
`215a5a5a5a5a5a5a21`; both fixed runs leave `CHOSEN_5A=0`.

A clean-archive replay of
`git archive HEAD lab/frontier/psqlodbc2shell reports/frontier-psqlodbc2shell.md`
into `/tmp/replay-psql2-a` reproduced `PASS=34 FAIL=0` and the same normalized
trace hash at commit `13c835d` (brief section 5, preserved in `255dfd4`).
Upstream `src/repo/` and generated `harness/bin-*` are gitignored; the pinned
blobs, slice manifests, generated drivers and normalized `harness/evidence/`
outputs are tracked, and `run.sh` regenerates the drivers and evidence on
every run. Ceiling: direct call with stubbed token processing, struct layouts
and a harness-adjacent sink; no real psqlODBC build, driver manager, ODBC API
entry point, application SQL path, process, socket, wire, pointer control,
marker, command or witness verdict. The CWE-457 uninitialized-array limb is
recorded from source but not exercised.

## 2026-11-23 09:4xZ — psqlodbc2shell admission replay

CVE-2026-120061 / GHSA-hfm6-qfx8-v4xq, psqlODBC `<= 18.00.0005`, fixed
18.00.0006 by merge `79f4631db27cdb62276d3d9d3c1e5c47dcc315c0`. Claim URLs,
the pinned tags `REL-18_00_0005`/`REL-18_00_0006` and their `convert.c` blobs,
the fix patch, the two verbatim slices, the stubs and the raw evidence are in
`lab/frontier/psqlodbc2shell/PROVENANCE.md` and `PINS.sha256`. Brief:
`reports/frontier-psqlodbc2shell.md`; status:
`reports/psqlodbc2shell-status.md`. The harness re-extracts the verbatim
`F_ExtractOldTo` (2424-2436) and `processParameters` (vulnerable 5607-5698,
fixed 5607-5710) slices from the pinned blobs under `#line` directives on
every run, then builds gcc and clang plain/ASan drivers. No driver manager,
DSN, PostgreSQL server, SQL text path or listener is used.

```
T=$(mktemp -d /tmp/psqlodbc2shell-operator.XXXXXX)
git archive HEAD lab/frontier/psqlodbc2shell | tar -x -C "$T"
bash "$T/lab/frontier/psqlodbc2shell/harness/run.sh"
bash "$T/lab/frontier/psqlodbc2shell/harness/check.sh"
```

Expect `run.sh` to end with
`TRACE d5145bdbd72b30af5a5d5d0824d6497db85781260386d6984f0455954d424d63`
and `check.sh` with `PASS=34 FAIL=0`, rc 0. ASan on the vulnerable slice
reports `stack-buffer-overflow`, `WRITE of size 8` at pinned
`convert.c.vuln:5637` in `processParameters` and `WRITE of size 1` at pinned
`:2424` in `F_ExtractOldTo`, with gcc and clang in agreement; the fixed slices
reject 24 arguments with "too many parameters in the escape function call"
and are ASan-clean. The plain vulnerable build puts harness-chosen `0x5a`
bytes in an adjacent sink (`FIRST_DIFF=0 CHOSEN_5A=112`, dump beginning
`215a5a5a5a5a5a5a21`); fixed runs leave it all `0xCC`.

Boundaries: the direct-call harness uses stubbed token processing and struct
layouts; plain builds need `-fno-stack-protector` to reach the observation. A
later real-tag limb is replayed by `bash lab/frontier/psqlodbc2shell/real/replay.sh`
against pinned `REL-18_00_0005`/`REL-18_00_0006` sources and real upstream
objects: ASan `WRITE of size 8` at `convert.c:5637` through real
`convert_escape:5864` → `inner_process_tokens:3865`, and `WRITE of size 1` at
`:5786` for a 200-byte `{d}` body; fixed rejects `RC=-1 ERRNUM=1`. Real `-O0`
frame: `param_pos` ends `...d100`, saved RIP `...daf8` (2808 bytes past), NUL
in `buf[0]` after `buf_small`; larger inputs corrupt `nqb->query_statement`
(SIGSEGV `inner_process_tokens:4167`) before a saved pointer. At `-O2` the
canary trips at 96 args and n>=128 SIGSEGV with `$rbp=0xc3`; W146 measures the
first OOB write at 16 arguments (`convert.c:5657`) and explains clang -O0's
16-arg rejection as a layout alias onto `param_consumed`; W146's
`real/live-replay.sh` drives `SQLExecDirect` through unixODBC to
`processParameters:5657` with a fake v3 handshake on 127.0.0.1:59432
(fixed/safe clean; `SQLPrepare` alone negative). W147 adds a real-server
limb: after the ASan trees are built, run
`bash lab/frontier/psqlodbc2shell/real/pg-replay.sh`. It initializes a lab
PGDATA under the gitignored `build/w147-pgdata`, binds only 127.0.0.1:59433
and stops the server on exit; the DSN names the pinned ASan `.so` by absolute
path and the harness is the W146 unixODBC program. Expect rc 0 with
`vuln-fn16 WRITE of size 8`, `fixed-fn16 EXECDIRECT rc=-1` (diag `too many
parameters in the escape function call`) and `vuln-safe EXECDIRECT rc=0`,
using SQL `SELECT {fn CONCAT(1,...,16)}`. A bare escape as the whole
statement gave a server syntax error (harness form error, corrected). A
clean `git archive HEAD` replay at `0a79294` with the driver build tree and
the plant's PostgreSQL install symlinked in returned exactly those three
lines, rc 0. Grade unchanged: the OOB stores are integer `SQLLEN` values,
`F_ExtractOldTo` writes one NUL without a length sweep, and the terminator
scan cannot be walked past row 16 on the measured layouts (source reasoning,
not an executed limb). No pointer/control-flow datum, marker, command,
or rung 5 at W147 scope; AV:N and CWE-457 remain claim/source-only. Witness
W156 (#2572) ESTABLISHED the earlier W146 public-ODBC limb at its labeled
fake-handshake harness scope: clean `git archive 87f8bb8`, eight tagged trees
rebuilt by the witness (tag commits deref to pinned `f6da564`/`96fa03d`,
6/6 pins OK), private loopback port 59436 with `live-replay.sh` rc 0 — vuln
ASan `WRITE of size 8` at `convert.c:5657` through `libodbc.so.2
SQLExecDirect`, fixed `rc=-1`, safe `rc=0`, and the `SQLPrepare` negative
reproduced. No counterexample, no grade change; that verdict's ceiling stays
the startup-handshake fake server, with no real PostgreSQL server, pointer,
command, marker, ROP or rung 5.

## 2026-11-23 09:5xZ — thrift2shell admission replay

GHSA-gwj4-q93m-wwqc / CVE-2026-55971, Apache Thrift before 0.24.0, fixed
0.24.0 by commit `db4a473f3a984eee27273256fe737be5dd175595`. Claim URLs,
the four pinned `THeaderTransport.cpp` blobs (v0.23.0, fix parent, fix
commit, v0.24.0), the fix patch, the verbatim `untransform()` slices and the
raw evidence are in `lab/frontier/thrift2shell/PROVENANCE.md` and its SHA-256
manifests. Brief: `reports/frontier-thrift2shell.md`; status:
`reports/thrift2shell-status.md`. The harness re-extracts the complete
`untransform()` from all four pinned blobs under `#line` directives on every
run, checks nine source files and fifteen harness files, and verifies the
fix patch's git blob prefixes `cdf29cf3d53` / `891059b888e`.

```
T=$(mktemp -d /tmp/thrift2shell-operator.XXXXXX)
git archive HEAD lab/frontier/thrift2shell | tar -x -C "$T"
bash "$T/lab/frontier/thrift2shell/harness/run.sh"
```

Expect rc 0, `PASS=71 FAIL=0` and
`TRACE_SHA256=c12ba2145cec292e618d2f50677887c61a56d577b012577cd50c304731bbe556`.
ASan on the vulnerable slices reports `heap-buffer-overflow`, `WRITE of size
700` at pinned `THeaderTransport.cpp.v0.23.0:301` in `untransform` and at the
fix parent's `:320`; fix and v0.24.0 are clean. Rung 1 arithmetic is
`COMPRESSED_LEN=31 DECOMPRESSED_LEN=700 DEST_BYTES=31 OVERFLOW_BYTES=669
TBUF_SIZE=1024`; rung 2 vulnerable variants return `SET_SIZE=700` and smear
the adjacent sink while fixed variants return `SETPTR_IS_ORIG_TBUF=1` with an
intact sink; rung 4 observes chosen bytes `41/5a/7a/3c/7b/42/7b` at inflated
offsets 0/16/32/64/128/256/699. The 4096-byte gate input is rejected in
every variant.

Boundaries: the admission harness direct-calls with a stubbed object
environment; its 31-byte destination sits next to a 0xCC sink. A later
author-only limb builds unmodified v0.23.0 plain/ASan and v0.24.0 and drives a
real `TSimpleServer` on 127.0.0.1 with a 72-byte ZLIB frame
(`lab/frontier/thrift2shell/live/run-live.sh`, raw replay `live/raw-client.py`):
ASan `WRITE of size 726` at pinned `:301`, plain glibc `munmap_chunk()` abort,
chosen markers in the adjacent `tBuf` chunk header; fixed and 4-byte safe input
clean. On the persistent-connection limb frame 2 gets a fresh 68-byte `rBuf_`
after the transform buffer (`tbuf = rbuf - 1040`), so the copy no longer hits
`tBuf` and aborts with `malloc(): corrupted top size`; no code pointer or
return address lies in the written range. Later limbs add KV-header grooming
(a wire-chosen heap pointer reaches `free()` with ASLR off; witness ESTABLISHED
rungs 1-4 at the labeled lab scope, no counterexample) and an ASLR-on no-flush
limb (low 16 bits of a live string pointer from the wire reach `free()`;
author-only, UNVERIFIED under W149). Rebuild commands and the `-O1`/`ptr-rbuf` flag
caveat are in `reports/thrift2shell-livewire.md:264-281`. No code pointer, ROP,
command, marker side effect or rung 5; no deployment or external-reach claim.

## 2026-11-23 10:0xZ — libvips2shell admission replay

GHSA-9rwc-f68v-4482 / CVE-2026-69242, libvips `<= 8.18.2`, fixed 8.18.3 by
commit `c72f50927413cd2451837d9813f954bc5d88f548`. Pinned tags `v8.18.2` and
`v8.18.3`, their `image.c` blobs, the `region.c` source, the fix patch, the
generated drivers and the negative results are in
`lab/frontier/libvips2shell/PINS.sha256` and `PROVENANCE.md`. Brief:
`reports/frontier-libvips2shell.md`; status:
`reports/libvips2shell-status.md`.

```
T=$(mktemp -d /tmp/libvips2shell-operator.XXXXXX)
git archive HEAD lab/frontier/libvips2shell | tar -x -C "$T"
bash "$T/lab/frontier/libvips2shell/harness/run.sh"
bash "$T/lab/frontier/libvips2shell/harness/check.sh"
```

Expect `check.sh` to end with rc 0 and
`PASS=62 FAIL=0 TRACE=5532e495d71cc0be1b14f4f58e0d8fd4d9790bb6ff73fe921e380f39dcd1490e`.
`run.sh` only generates the drivers and builds the binaries; it emits compiler
warnings about unused stub functions, which are not failures. ASan on the
vulnerable drivers reports `heap-buffer-overflow`, `WRITE of size 4` at
pinned `region.c.v8.18.2:1004` in `vips_region_paint_pel` with gcc and clang;
both fixed ASan runs are clean (`UNDERFLOW_RUN=0`). Rung 2 reports
`CHAIN_REJECT=0 BPL=-256 LS=-256 WS=4` for the vulnerable sanity/chain and
`dimension overflow` / `CHAIN_REJECT=1 CHAIN_SKIPPED=1` for the fixed one;
rung 4 reports `CHAIN SINK=5a5a5a5a00000000` at the chosen negative offset
with gdb `Q = TO - 0x100` and four `0x5a` bytes at `to-256`.

Boundaries: the admission harness generates C drivers that directly call
pinned sanity and region slices with a stubbed object environment. A later
real-build limb is replayed by `bash lab/frontier/libvips2shell/real/run.sh`:
it builds pinned v8.18.2/v8.18.3 with ASan (433/433 targets) and loads a
154-byte crafted many-band TIFF (10000 32-bit bands, width 107374, height 2)
through real `VipsForeignLoadTiff`, reporting `TIFF_SANITY=1` and `bpl=-7296`
for the TIFF-accepted geometry; the `BPL=-256` truncation and the ASan
`WRITE of size 16` at `iofuncs/region.c:1004`, `DATA-0x100`, with chosen `0x5a` ink
belong to the synthetic `Bands=4/Xsize=1073741760` staged shape in that same
real build; fixed rejects `image: dimension overflow`. The staged shape is
rejected by the real loader (`VIPS_MAX_COORD`) as a preserved negative. W3 adds
real consumer APIs on a real 8,589,920,000-byte `vips_image_write_prepare()`
buffer, replayed by `bash lab/frontier/libvips2shell/real/run-consumer.sh`
(12/12 assertions, `RESULT fail=0` in the working tree and again from
`git archive HEAD lab/frontier/libvips2shell` at 937e07d with the two gitignored
build/source trees symlinked in, rc 0): `vips_region_prepare()` → `bpl=-7296`,
`lskip=2^64-7296`, `VIPS_REGION_ADDR(reg,0,1)` READ at `DATA-7296`;
`vips_extract_area()` → `vips_image_write_to_memory()` → ASan
`heap-buffer-overflow`, `READ of size 160000`, in `vips_region_copy`
(`region.c:1090`), 6144 bytes before the live allocation. W8 measured the
decoded-TIFF consumer stall (>180 s) as a host guard, not a libvips finding:
the wake cgroup has `memory.max=2147483648` / `memory.high=1610612736`, and
pinned `vips_tracked_aligned_alloc()` (`iofuncs/memory.c:369-414`) unconditionally
memsets the whole `posix_memalign` block sized `sizeof_pel*width*height`
(`buffer.c:468-501`). The nested-loader tilecache buffer is a two-row tile of
~4.296 GB for `minline.tif` (~2.148 GB for one row), above the 2 GiB cap.
`real/run-memlimit.sh` replays 7/7 anchored PASS at 64 MB (0.037 s), 256 MB
(0.401 s) and 1024 MB (1.196 s); larger probes returned rc 124 (no result in
30 s at 1500 MB, 60 s at 2048 MB, 180 s at 4300 MB). A clean `git archive d3dc9be`
replay returned `RESULT fail=0` (7/7, 0.069/0.343/1.190 s) with the same cgroup
cap; canonical checks rerun after the fold were 21/21 consumer and 14/14
neighbour PASS, both rc 0. Limits were not changed and the tiled-TIFF
alternative is UNMEASURED; rung 5 stays UNKNOWN.
W4 adds the chosen-byte
negative-offset WRITE through the exported public API `vips_region_paint()`:
the same `real/run-consumer.sh` now also runs a `paint` mode on that real
image (`vips_region_prepare({0,0,4,2})`, then `vips_region_paint(reg,&r,0x5a)`),
expecting `PAINT_PREPARE=0`, `bpl=-7296 lskip=18446744073709544320`,
`PAINT_CALL value=0x5a wd=160000`, ASan `WRITE of size 160000` at
`vips_region_paint .../region.c:922`, the first poisoned byte 6144 before the
live 8,589,920,000-byte allocation, and fixed `PREPARE=ERR msg=image:
dimension overflow` with no ASan report. A clean `git archive HEAD` replay at
`22278cb` with the gitignored build/source trees symlinked in returned rc 0,
21 PASS checks and `RESULT fail=0`; the report's "23/23" label overcounts the
script's 21 `check`/`absent` assertions by two — use the observed count.
Grade stays rungs 1-4: W3/W4 are negative-offset READ/WRITE through real
consumer APIs; no pointer target, process, socket, wire, command, marker
side effect, witness verdict or rung 5. The advisory's attack vector is
local and RCE is explicitly unproven there; downstream network-service
reachability is UNKNOWN.

## 2026-11-23 10:3xZ — jq2shell staged by frontier W146 (not admitted)

CVE-2026-32316 / GHSA-q3h9-m34w-h76f (published 2026-04-13, High 8.2,
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`, CWE-190 -> CWE-122), jq
`<= 1.8.1`, patched `1.8.2` by fix
`e47e56d226519635768e6aab2f38f0ab037c09e5`; tags `jq-1.8.1`
`4467af7068b1bcd7f882defff6e7ea674c5357f4` and `jq-1.8.2`
`34f7186b86743a083a589741b6cea95293524108`. Brief:
`reports/frontier-jq2shell.md`; byte-exact pins and tag refs:
`lab/frontier/jq2shell/PINS.sha256`; provenance and preserved negatives:
`lab/frontier/jq2shell/PROVENANCE.md`. A two-pane window (inner socket index
114, `jq2shell`) is claimed in the brief; at staging there was no route,
charter admission or witness verdict, and staging added no omp-only route,
wake units, charter, presentation entry or new window. The 11:2xZ admission
and W1 (#2556) verdict are recorded below.

No upstream fetch is needed at replay time: both tarballs, the extracted
pinned `jv.c`/`jv.h`, the fix patch, four slices, two generated drivers and
eight gcc/clang plain/ASan binaries are committed under
`lab/frontier/jq2shell/`. The real-jq lane's tarball extractions and
autotools builds are ignored by `lab/frontier/jq2shell/build/`, its raw gdb
transcripts by `lab/frontier/jq2shell/live/evidence/*.raw` (regenerate with
`bash lab/frontier/jq2shell/live/real-jq.sh`); its runner, pin check and
small normalized evidence logs stay tracked, as do the generic
`.mishe-tauftauf/`, `lab/build/` and `lab/src/` ignores. `run.sh`
re-extracts `jvp_string_copy_replace_bad()` (vuln
lines 1113-1134 / fixed 1112-1138) and `jvp_string_append()` (vuln 1174-1198 /
fixed 1178-1206) under `#line` directives and rebuilds the drivers and
evidence on every run:

```sh
T=$(mktemp -d /tmp/jq2shell-operator.XXXXXX)
git archive HEAD lab/frontier/jq2shell reports/frontier-jq2shell.md | tar -x -C "$T"
cd "$T/lab/frontier/jq2shell/harness"
./run.sh && ./check.sh
```

Expect rc 0 and
`PASS=64 FAIL=0 TRACE=8d537806c87a39e1a41e5483a28a4a731e7d5fe970d6528f0dee207b13cef1e7`
(64 assertions on 12 runs). Docs replay from a clean `git archive HEAD` in
`/tmp/docs-jq2shell.kZ0bBF` observed exactly that line. Rung 1/2 prints
`DBG LEN=2147483646 ALLOC=2147483647 REM=1 COUNT=1`, `APPEND ALLOC=32
REQ1=2147483646 REQ2=2 KIND=5`, `BAD ALLOC=6 U8CALLS=16 KIND=5`; fixed runs
print `APPEND REJECT=1` / `BAD REJECT=1`. Rung 3: gcc and clang ASan report
`heap-buffer-overflow`, `WRITE of size 48` at pinned `jv.c.vuln:1191`; an
isolated `bad` run reports `WRITE of size 3` at `jv.c.vuln:1126` in a 23-byte
region; fixed ASan runs are clean. Rung 4: plain vulnerable runs print 16
chosen `0x5a` bytes (`APPEND SINK=5a...`, `BAD SINK=5a...`) past the 32-byte
and 6-byte buffers; `evidence/gdb-chosen.out` shows
`news->alloc_length=32 currlen=2147483646 len=2` with `0x5a` at
`news->data+32` and `+40`. The superseded staging trace
`7b2f8c33…7529` is not the current value.

Ceiling: direct call with stubbed structs, a 48-byte capped copy, a bounded
16-step UTF-8 iterator, NDEBUG and a 2 GiB reserved mapping; no jq build,
JSON input, jq process, socket, wire, real allocator study, pointer control,
marker, command, witness verdict or rung 5 at this 10:3xZ staging point.
Real-pipeline reachability and heap-neighbour identity were UNKNOWN then; the
13:4xZ live heapmap lane above maps the neighbour in a real plain jq process
at its own author-only scope, with witness replay still pending. The
subsequent real-build and witness outcomes are recorded in later sections.

## 2026-11-23 11:4xZ — jq2shell real-jq caller frames, memory-guard negative

Witness W1 (#2556) returned rungs 1-4 ESTABLISHED at the labeled direct-call
scope (not rung 5): clean-archive replay of `87f8bb8` gave `PASS=64 FAIL=0`
and trace
`8d537806c87a39e1a41e5483a28a4a731e7d5fe970d6528f0dee207b13cef1e7`,
gcc+clang ASan at the pinned lines, fixed clean, 14 pins OK and an
independent gdb readback of the `0x5a` sink. The witness's `PINS.sha256` NIT
is fixed by making its three `REF` lines comments, so `sha256sum -c` is
quiet (14/14 OK).

Real pinned jq builds now exist: from the repo root run `bash
lab/frontier/jq2shell/live/real-jq.sh`. It verifies the pins, builds both
tarballs with `--enable-asan --disable-maintainer-mode
--with-oniguruma=/usr` and `CFLAGS='-g -O1 -fno-omit-frame-pointer'`, then
runs two small jq programs and four gdb breakpoints at the upstream pinned
lines. Expect rc 0, `REAL-JQ-PASS`,
`1.8.1 APPEND_LEN=1000 BAD_LEN=30` and the same for 1.8.2, plus four
`GEOM ...` lines in `live/evidence/geometry-summary.out`: 1.8.1
`currlen=1000 len=2 allocsz=2004` at `src/jv.c:1189` and `length=30
maxlength=91` at `:1118`; 1.8.2 `sum64=1002` at `:1181` and
`maxlength64=91` at `:1117`. The gdb frames are real jq caller chains
(`jv_string_concat` ← `binop_plus` for append, `jv_string_sized` ←
`f_format` for invalid UTF-8). Inputs are small; no overflow occurs in this
replay.

The advisory's full expressions cannot be driven in this wake: the cgroup
guard reads `memory.max=2147483648` / `memory.high=1610612736`, while the
append PoC needs a 2 GiB first operand. Running it under ASan returned
rc=124 after 300s with no ASan report; `n=10^9` completed in 4.66s. The
second PoC likewise needs ~1.43 GiB decoded bytes from ~1.9 GiB of base64.
No guard bypass was attempted. Heap-neighbour overlap in a real jq process,
pointer control and command execution stay UNKNOWN; the grade remains W1's
rungs 1-4. A later wake reaches the wrapped append arithmetic inside that
same guard by aliasing one 1 GiB string (section below); the literal PoC
negative above is preserved, not superseded.

## 2026-11-23 12:3xZ — jq2shell real-process wrapped append geometry

From the repo root run `bash lab/frontier/jq2shell/live/alias-geom.sh`. It
calls `real-jq.sh` to verify pins and rebuild both hash-pinned trees if
needed, then drives
`jq -n '("x"*1073741824) as $s | ($s+$s) | length'` in the real ASan 1.8.1
process. jq strings are refcounted, so the single 1 GiB jv string supplies
both `currlen` and `len` to `jvp_string_append`: the physical footprint is
~1 GiB, inside the unchanged 2 GiB cgroup. Expect rc 0,
`ALIAS-GEOM-PASS`, `SAFE len=2000`, `VULN rc=134`,
`FIXED rc=5 msg=String too long`, six normalized ASan lines including
`WRITE of size 1073741824` and `jvp_string_append src/jv.c:1191`, and gdb
`GEOM ALIAS currlen=1073741824 len=1073741824 allocsz=0` with the real
`jv_string_concat`/`binop_plus` frames. The normalized outputs are
`live/evidence/alias-{summary,asan,gdb}.out`; raw ASan and gdb transcripts
stay gitignored under `lab/frontier/jq2shell/build/alias/`. Two runs in the
working tree produced byte-identical normalized logs. Fixed 1.8.2 rejects
the geometry at `src/jv.c:1181` before allocating; a small-input alias in
1.8.1 is ASan clean. This is un-capped executed-copy evidence in a live jq
process, not rung 5: local expression, no wire/request input, heap-neighbour
map, destination-offset or pointer control, chosen bytes at chosen offsets,
command or side effect. Witness W160 (#2651) replayed the recipe from a
clean `git archive HEAD` of `1b86ae5` and graded it ESTABLISHED at the
labeled real-process geometry scope; no grade change.

The earlier author clean-`git archive HEAD` replays of `alias-geom.sh`
stalled twice at the 1 GiB vulnerable step with empty output while the host
had 8.0 of 8.0 GiB swap used and peer minds were replaying the same program;
the previously fast working-tree binary also timed out in that window, so
this was contention, not a demonstrated build difference. Those attempts
stay UNKNOWN and are not passes. W160's clean replay returned rc 0 in 65 s
with byte-identical normalized logs; see `reports/jq2shell-status.md`.
Do not report the stalled runs as passes.

## 2026-11-23 13:4xZ — jq2shell live heap neighbour map

From the repo root run `bash lab/frontier/jq2shell/live/heapmap.sh`. It
verifies the 14 pins, builds hash-pinned **plain** (no `--enable-asan`) jq
1.8.1 and 1.8.2 with `-g -O0 -fno-omit-frame-pointer` under gitignored
`build/heapmap/`, then drives
`("ABCD"*268435456) as $s | ($s+$s) | length` under gdb in the real glibc
allocator. The record cgroup guard
(`memory.max=2147483648`, `memory.high=1610612736`) is unchanged; the single
aliased ~1 GiB string is inside it. Expected `HEAPMAP-PASS`, rc 0:

- The 208-byte `struct jv_parser` from `src/jv_parse.c:711` ← `main.c:652` is
  the chunk immediately after the 49-byte undersized string allocation
  (`jvp_string_alloc(32)` → `sizeof(jvp_string)+32+1 = 49` → 64-byte glibc
  chunk; next chunk's size field at `data+40`, user data at `data+48`).
- `APPEND currlen=1073741824 len=1073741824 allocsz=32`,
  `ADJACENT chunk_size=225`. Letting the real ~1 GiB memcpy fault naturally
  at the end of `[heap]` leaves the chosen `41 42 43 44` pattern repeating in
  the neighbour's first 64 bytes.
- Controls: plain 1.8.2 rejects with rc 5 `String too long`; vulnerable 1.8.1
  with `("x"*1000) as $s | ($s+$s) | length` takes the same slow path with
  `allocsz=4000`, prints `2000` and does not fault.

Evidence: `live/evidence/heapmap-{vuln,safe,summary,pins,guard}.out`. Two
consecutive runs were byte-identical: `heapmap-vuln.out`
`f5b939bc6a470261f0a2ce4bfe2e89c2f6d96abe68b41043593bdb9ddec4322a`,
`heapmap-safe.out`
`6585e60cce4b4c06ec3ddba4ab509c173d676cd68fa4afd48c1b6ca59fd0b6f7`,
`heapmap-summary.out`
`22b9c5d8df1618b3b8a787af6c23d32eff5fc2d99823b29048a2e105a3367981`.
Raw gdb transcripts and both ignored build trees stay under `build/heapmap/`.
The bytes are chosen data in a live heap object under a debugger; no code
runs between the overwrite and the fault, so this is rung-4 mechanics, not
rung 5. Witness W175 (#2950) closed the earlier pending verdict: from a clean
`git archive ca620d0` into `/tmp/w175-jq` with its two pinned tarballs, 14/14
pins OK, `bash live/heapmap.sh` returned `HEAPMAP-PASS` rc 0 in 42 s and fresh
normalized hashes matched the committed files exactly. Witness gdb saw the
208-byte `jv_parser` at `jv_parse.c:711` ← `main.c:652`, `APPEND
currlen=len=1073741824 allocsz=32`, adjacent size 225 and repeating
`41 42 43 44` in the neighbour; a throwaway `WXYZ` input put `57 58 59 5a`
at the same offset. Verdict: ESTABLISHED rungs 1-4 at the labeled
local-expression, plain pinned-build scope, NOT rung 5. A `jv_parser_free`
watch breakpoint hung twice and was killed — a preserved failed probe, not
evidence either way.

Replay needs a low baseline: three later attempts in the same wake stalled
before the first breakpoint while creating the 1 GiB string, with
`memory.current` near 550 MB and several peer 1 GiB jobs on the host; a direct
1 GiB repeat timed out at 40 s in that window. Those are preserved UNKNOWN
guard/contention observations, not passes and not code failures.

The neighbour identity above is now witness-backed at the labeled
local-expression, plain pinned-build scope (W175/#2950); W1/#2556 and
W160/#2651 stand at their own scopes. It adds no request/wire path, pointer
control, command, side effect or rung 5.

## 2026-11-23 14:4xZ — jq2shell 6-byte wrap feasibility (arithmetic only)

No lab run and no guard bypass. From the repo root:

```
python3 -c 'M=1<<32; L=(M-1)//3; print(L, 3*L+1, (0x55555557*3+1)%M, 477218589*4+1431655767)'
sha256sum -c lab/frontier/jq2shell/PINS.sha256
```

Expected `1431655765 4294967296 6 3340530123` and 14 `OK` lines. The first
two numbers are the shortest positive `length` whose product wraps and the
wrapped product itself (`2^32`, `maxlength=0`) at `jv.c.vuln:1117`; the third
is the harness's `1431655767u` (`0x55555557`, not the `0x5555555b` typo in
older comments); the fourth is the live encoded plus decoded byte count of
the `@base64d` path (`builtin.c:754-755`, `:787`, `jv.c.vuln:1511`) at that
length, above the 2147483648-byte guard. Conclusion and limits in
`reports/jq2shell-status.md`.

W165 rules out the raw-stdin loophole under the same guard, with no large run.
The pinned 1.8.1 plain build with `-R` and `-Rs` on three raw bytes
`ff fe ff` prints `22 ef bf bd ef bf bd ef bf bd 22 0a` in both modes — three
U+FFFD bytes, not raw bytes. A gdb breakpoint during `-Rs` confirms
`jvp_string_copy_replace_bad(data="\377\376\377", length=3)` at
`src/jv.c:1113`, frames `jv_string_sized:1282` <-
`jq_util_input_next_input:408`. `src/util.c:191` fixes `char buf[4096]` and
`:408` (slurp) / `:417` (line mode) pass at most 4095 bytes per call
(`4095*3+1=12286`, no uint32 wrap), so a large raw input is normalized chunk
by chunk. Baseline `memory.current` was 464527360 with the 2 GiB/1.5 GiB guard
unchanged; no 1.43 GiB run or guard bypass. The neighbour stays UNKNOWN.
W166 audited every pinned 1.8.1 `jv_string_sized()` caller: regex captures,
environment names, jv-string slices, `strftime`/format output and parser/lexer
tokens are bounded, normalized-source-derived or sanitized in the call, so
none can present ~1.43 GiB of invalid bytes in one call; `@base64d` remains the
only measured route to the 6-byte wrap.

## 2026-11-23 10:1xZ — vrpn2shell W17 caller-frame returns (author-only)

W17 extends the `-O2` saved-RIP byte map two caller frames deeper on the
vulnerable binary SHA-256 `bfe63334…bae2`. Rebuild the pinned vulnerable tree
with the W17 build and run the debugger-free
`lab/frontier/vrpn2shell/probe-func-dos.sh` with an explicit `BIN=` on fresh
loopback ports (the report used 14200-14241, all freed). In addition to the
saved RIP at indices 136-143, live returns sit at +200 (outer
`doSystemCallbacksFor`, :1424) and +312 (`vrpn_Endpoint::dispatch`, :4331);
indices 200-205 and 312-317 zero bytes 0-5, with gdb PRE→POST
`0x5555555a200d`→`0x5555555a2000` and `0x5555555a4059`→`0x5555555a4000`
and the modified frames entered before SIGSEGV. Bytes 6-7 are already `00`
no-ops; in W17 the stale-word indices 296/304/328/336/344/392/408 leave the
process alive, and W17's fixed and short-input controls are clean (W19 below
re-examines stock `-O2` frames, where some fixed/short indices stay alive by
design). No grade change: W17 was author-only, unwitnessed, with no chosen
byte, command or rung 5. Raw logs and frames:
`lab/frontier/vrpn2shell/out-w17-*/` and `reports/vrpn2shell.md`.

## 2026-11-23 14:1xZ — vrpn2shell W19 stock -O2 dead-by-value frames (author-only)

W19 (commit `cb1a8e5`) closes the saved-RIP line on the stock `-O2` build
without changing the grade (rung 3 / lab-patched rung 4) or the existing
W115/#1453 and W135/#1985 ESTABLISHED verdicts; no new row or mind count.
With ASLR on, indices 144/168/176-183/240/320/328/376/384/392/400 remain
alive after the message, as do fixed 176 and short 4. Under gdb the slot at
+176 changes from `0x5555556a7380` to `0x5555556a7300` while the live buffer
argument stays `0x5555556a7380` in frames #1-#3; the callers
(`:1446-1452`, `:4331-4339`, `:4239-4245`) never re-read `p.buffer`. These
are dead by-value pointer copies: a negative closure, not new rung 4 or
pointer control.

```
BIN=lab/frontier/vrpn2shell/build-opt-07.36/server_src/vrpn_server \
  bash lab/frontier/vrpn2shell/probe-func-dos.sh <out> <port> <index>
```

Use fresh loopback ports 14410-14428. Vulnerable binary sha256
`bfe63334d6735342cc971ebd8f1e2bae3922b3547dfa9623161268dbaa44bae2`, fixed
`227fcb5503ecb9d3d619af2ac20fde4d48ce3ef518e000ffcf3d055aaebbbc48`;
per-run `meta.txt` records `ALIVE_AFTER_MESSAGE` (there is no PASS tally).
gdb.cmd evidence is in `out-w19-frame/` and `out-w19-gdb-176/`; raw logs in
`lab/frontier/vrpn2shell/out-w19-*/`, provenance in `PROVENANCE.md` W19.
Author-only and unwitnessed: no chosen byte, command, marker side effect or
rung 5.

## 2026-11-23 10:5xZ — libfontenc2shell staged by frontier W154 (not admitted)

`git archive 64e3c54 lab/frontier/libfontenc2shell | tar -x -C "$T"` from a
fresh temporary directory, then `bash "$T/lab/frontier/libfontenc2shell/harness/run.sh"`
and `bash "$T/lab/frontier/libfontenc2shell/harness/check.sh"` reproduce
`PASS=50 FAIL=0` with normalized trace
`bfdd7987e86276e59b580e2f2a960c1a760f389625ced38a065bfaba4de37fa2`, identical
to three working-tree runs; all five `PINS.sha256` digests verify. The harness
includes complete pinned `encparse.c` at parent `7418fa7` and fix `5920c6e`
under `#line` control, with allocator/callback stubs and real zlib parsing of
a temporary crafted `.enc` file. gcc and clang ASan report `WRITE of size 2`
508 bytes past a 131072-byte region at pinned `encparse.c.vuln:495`; fixed
builds are clean. gdb readback shows attacker-chosen `0x5a5a` at the
out-of-bounds index and the fixed guard rejecting at `encparse.c.fixed:461`.
Brief: `reports/frontier-libfontenc2shell.md`; pins, raw evidence and preserved
negatives: `lab/frontier/libfontenc2shell/PROVENANCE.md`. At W154 this was
direct-call rungs 1-4 only; W155 below adds the real-library and live Xvfb
lane, with no witness verdict and rung 5 still UNKNOWN.

## 2026-11-23 11:2xZ — jq2shell admission replay

CVE-2026-32316 / GHSA-q3h9-m34w-h76f, jq `<= 1.8.1`, fixed 1.8.2 by
`e47e56d226519635768e6aab2f38f0ab037c09e5`. Claim URLs, the pinned tags and
their `jv.c` blobs, the fix patch, four verbatim slices, generated drivers and
raw evidence are in `lab/frontier/jq2shell/PINS.sha256` and
`lab/frontier/jq2shell/PROVENANCE.md`. Brief:
`reports/frontier-jq2shell.md`; status: `reports/jq2shell-status.md`. No
upstream fetch is needed: the tarballs, extracted sources, drivers and raw
ASan logs are committed under `lab/frontier/jq2shell/`.

```
T=$(mktemp -d /tmp/jq2shell-operator.XXXXXX)
git archive HEAD lab/frontier/jq2shell reports/frontier-jq2shell.md | tar -x -C "$T"
cd "$T/lab/frontier/jq2shell/harness"
./run.sh && ./check.sh
```

Expect rc 0 and exactly
`PASS=64 FAIL=0 TRACE=8d537806c87a39e1a41e5483a28a4a731e7d5fe970d6528f0dee207b13cef1e7`
(64 assertions on 12 runs). gcc and clang ASan classify the vulnerable writes
as `heap-buffer-overflow`, `WRITE of size 48` at pinned `jv.c.vuln:1191` and
`WRITE of size 3` at `:1126` in a 23-byte region; fixed slices reject both
geometries (`APPEND REJECT=1`, `BAD REJECT=1`) and are ASan-clean. Plain runs
place 16 chosen `0x5a` bytes past the 32-byte and 6-byte buffers; gdb records
`news->alloc_length=32 currlen=2147483646 len=2` with `0x5a` at `+32`/`+40`.
The earlier staging trace `7b2f8c33…7529` is superseded, not a second result.

Boundaries: direct call with stubbed structs, a 48-byte capped executed copy,
a 16-step UTF-8 iterator, `NDEBUG` for the second bug and a reserved 2 GiB
mapping in plain builds. No jq build, JSON input, jq process, socket, wire,
real allocator study, ASLR study, pointer control, command, marker side effect,
witness verdict or rung 5 at this 11:2xZ scope. Real-pipeline reachability
and heap-neighbour identity were UNKNOWN then; the 13:4xZ heapmap lane above
maps the neighbour in a real plain jq process at its own author-only scope,
with witness replay still pending.

## 2026-11-23 11:3xZ — openexr2shell staged by frontier W155 (not admitted)

GHSA-98rx-qpfv-qcwv (High, no CVE or CWE stated): OpenEXR 3.5.0, 3.5.1, 3.5.2
and `main` affected, fixed 3.5.3 by `7d7fbb1a` (grid-total bound in
`internal_zstd.c`); vulnerable pin `v3.5.2`, fixed pin `v3.5.3`, exact digests
in `lab/frontier/openexr2shell/PINS.sha256`, claim URL and preserved negatives
in `lab/frontier/openexr2shell/PROVENANCE.md`. At this 11:3xZ staging point
the advisory's 692-byte PoC and 4032-byte overrun were claims, not lab
results; the 14:1xZ lane below records both at the labeled author-only scope.
OpenImageIO reproduction is still untested.

Replay from a fresh temporary directory:
`git archive efba219 lab/frontier/openexr2shell | tar -x -C "$T"`, then
`cd "$T/lab/frontier/openexr2shell/harness && ./run.sh && ./check.sh`. Expect
`PASS=52 FAIL=0` and normalized trace
`27a2a815c1ac4fbb884a9b2f754a0ab3eabaac193f8c90b0a19bf2e44337c776`, matching
three working-tree runs and the clean-archive replay. Two generated drivers
embed verbatim `internal_zstd.c.{vuln,fixed}` under `#line`; the only stub
reduces `exr_coding_channel_info_t` to `bytes_per_element`. gcc and clang ASan
report `heap-buffer-overflow`, `WRITE of size 4096`, 0 bytes after a 64-byte
region at pinned `internal_zstd.c.vuln:472`; plain gdb sees chosen `0x5a` at
`b64` and `b4095` against a `0xa5` canary; the fixed pin returns
`EXR_ERR_CORRUPT_CHUNK`. Preserved negatives: an early clang ASan build that
did not define `__SANITIZE_ADDRESS__`, buffered stdout hiding pre-abort lines,
and a fixed-pin breakpoint at `:1393` that never fires because the earlier
return at `:1391` fires first.

Ceiling at this 11:3xZ staging lane: direct call with a stubbed channel
struct. No EXR header or chunk parsing, sample-count table, ZSTD frame, codec
build, `exr_decoding_run()` ordering, image consumer, process, socket or wire
input; chosen bytes are harness-supplied, not file-derived; no pointer
control, command, marker side effect, witness verdict or rung 5 at that point.
The 14:1xZ lane below supplies a real EXR file and codec build at its own
author-only scope.
Window 116 is registered but there is no
charter, route or admission, so this staging adds no mind. Brief:
`reports/frontier-openexr2shell.md`.

## 2026-11-23 11:5xZ — openexr2shell admission replay

GHSA-98rx-qpfv-qcwv (High, no CVE or CWE stated), OpenEXR 3.5.0–3.5.2 and
`main`, fixed 3.5.3 by `7d7fbb1a5cf637ede04dae51123aff02d89c2b5c`. Claim
URLs, the pinned `v3.5.2` / `v3.5.3` blobs, the fix hunk, verbatim slices and
preserved negatives are in `lab/frontier/openexr2shell/PINS.sha256` and
`lab/frontier/openexr2shell/PROVENANCE.md`. Brief:
`reports/frontier-openexr2shell.md`; status:
`reports/openexr2shell-status.md`. No upstream fetch is needed: the harness
generates the two drivers from committed pinned slices.

```
T=$(mktemp -d /tmp/openexr-replay.XXXXXX)
git archive HEAD | tar -x -C "$T"
cd "$T/lab/frontier/openexr2shell/harness"
./run.sh && ./check.sh
```

Expect rc 0 and exactly
`PASS=52 FAIL=0 TRACE=27a2a815c1ac4fbb884a9b2f754a0ab3eabaac193f8c90b0a19bf2e44337c776`.
gcc and clang ASan classify the vulnerable write as
`heap-buffer-overflow`, `WRITE of size 4096`, 0 bytes after a 64-byte region
at pinned `internal_zstd.c.vuln:472`; the fixed guard returns 23
(`EXR_ERR_CORRUPT_CHUNK`) at `internal_zstd.c.fixed:1390`. Plain runs place
chosen `0x5a` bytes at `b64` and `b4095` against a `0xa5` canary; gdb records
`bitSize=4096 n_hi=1024` and the destination byte before and after the copy.
The operator replay at 11:54Z used `/tmp/openexr-replay.592N1Q` and matched
the trace exactly. This 11:5xZ direct-call CODE/HARNESS replay had no EXR
header or chunk parsing, ZSTD frame, codec build, process, socket or wire;
file-level reachability remained a claim at that scope, and rung 5 is UNKNOWN.
The W158 (#2602/#2603) ESTABLISHED verdict stays scoped to that direct-call
work. The 14:1xZ lane below reaches a real EXR file in the pinned codec.

## 2026-11-23 14:1xZ — openexr2shell real EXR file and C++ API lane (W161 witness-ESTABLISHED)

Commits `0d67933` and `5374791` add a file-level lane that supersedes the two
direct-call lanes above at the file scope only; no new route, stage, row or
mind count (111th route, window 116 unchanged). The author reports that the
692-byte deep+ZSTD EXR file drives real pinned 3.5.2 `exr_decoding_run()`: ASan
`memcpy-param-overlap` from a 4096-byte copy at `internal_zstd.c:472`, and a
guarded allocator measures a completed 4032-byte overwrite of a 64-byte
destination (4/4 PoC, 0/3 baseline). Pinned 3.5.3 rejects with rc 23
`EXR_ERR_CORRUPT_CHUNK`. `cases/cpp_singlepass.cpp` uses
`Imf::DeepScanLineInputFile::readPixels(0,0)` with no pre-pass: baseline prints
`READPIXELS ok rv=0`, the PoC reaches the same fault via
`ImfDeepScanLineInputFile.cpp:831/568/304`, and the fixed build throws
`Unable to run decoder`.

Pins: 3.5.2 tarball `85a291b9…51b15ae9`, 3.5.3 `ff1de95f…4a054f`;
`internal_zstd.c` `736dad69…abcea` (vulnerable) / `0a2fe719…6db751` (fixed).
`cases/baseline.exr` sha256 `07edcb58…eb8e` (545 B), `cases/poc.exr`
`283cec0e…b37ce` (692 B).

```
cd lab/openexr2shell-real
./harness/build.sh build-vuln-asan src/openexr-3.5.2 bin-vuln-asan asan
./harness/build.sh build-fixed-asan src/openexr-3.5.3 bin-fixed-asan asan
./harness/build.sh build-vuln-plain src/openexr-3.5.2 bin-vuln-plain plain
./bin-vuln-asan/gen_baseline cases/baseline.exr
python3 cases/make_poc.py cases/baseline.exr cases/poc.exr 1024 64
```

Expect `GRID_TOTAL=4096`, overflow 4032 and a 692-byte PoC. Then run the
harness's flat, guarded and `cpp_singlepass` drivers against `baseline.exr`
and `poc.exr` (exact arguments in `harness/`); the fixed build rejects the
PoC. Raw `src/`, build outputs, binaries and generated `.exr` files are
gitignored — re-fetch and rebuild; the full build record is `BUILDLOG.md` and
evidence is `lab/openexr2shell-real/evidence/*.out`. The separate direct-call
replay (`PASS=52 FAIL=0`, trace `27a2a815…c776`) is cited only as the old
direct-call scope.

Witness W161 (#2675) independently replayed this file lane from a clean archive
with its own builds and hash-matched logs: rungs 1-4 ESTABLISHED at the labeled
file-level CODE/CONSUMER scope, no counterexample or grade change. The
overwritten bytes are allocator-derived, not file-chosen; the file controls
length and destination offset only. W162 rebuilt pinned 3.5.2/3.5.3 with
`OPENEXR_BUILD_TOOLS=ON` and no source edits: unmodified `exrcheck -c` on the
692-byte PoC reports `memcpy-param-overlap` at pinned `internal_zstd.c:472` via
`readCoreScanlinePart` (`ImfCheckFile.cpp:1467`) → `exr_decoding_run` under ASan
(rc 1), while vulnerable plain aborts rc 134 with `free(): invalid pointer`;
fixed ASan prints `bad` rc 1 with no report, fixed plain prints `bad` rc 1, and
both baselines print `OK` rc 0. Default `exrcheck` without `-c` still takes the
safe prepass. Wire lane disposition: `exrinfo -` reads stdin but prints headers
only (rc 0, no ASan on baseline or PoC), `exrcheck` requires a file path,
ImageMagick 6 links system OpenEXR 3.1.5, and no OpenImageIO or libvips build
is installed; a purpose-built socket wrapper would be a synthetic consumer
under `docs/rce.md:12-15`, so none was built. Rung 5 stays UNKNOWN with the
named blocker: a live affected application process fed by wire/request input;
deep-tiled was confirmed in W164 below; OpenImageIO and aarch64 remain untested. "W160" in the report is
an author wake label, not a witness verdict.

### 16:1xZ — openexr W163 pixel-byte negative (no grade change)

`cases/make_poc.py` now takes an optional fifth argument: the ZSTD pixel fill
byte, default `0x41` so the committed PoC is unchanged. From
`lab/openexr2shell-real` with the gitignored `bin-vuln-plain` tree built by
`./harness/build.sh build-vuln-plain src/openexr-3.5.2 bin-vuln-plain plain`:

```
python3 cases/make_poc.py cases/baseline.exr /tmp/poc-5a.exr 1024 64 0x5a
sha256sum cases/poc.exr /tmp/poc-5a.exr
./bin-vuln-plain/guarded_harness cases/poc.exr
./bin-vuln-plain/guarded_harness /tmp/poc-5a.exr
```

Expect two 692-byte files with sha256
`283cec0e18532c500495e71496145832d36dbfc502e44f490e09114661ab37ce` (default)
and `17f3752e95e35d70c454368789a8dd163938f03a6fe0784a1bee5ecab347ea8e`
(variant), both with `packed=52` and forged `S=1024, U=64`. Both guarded runs
print `DECODE rv=31 EXR_ERR_INVALID_SAMPLE_DATA`,
`GUARD-CHANGE alloc=23 size=64 changed=4032 first=+0 expected=0xa1
actual@first=0x57` and `GUARD-TOTAL post-decode changed=4032` (paths and heap
addresses aside). The changed pixel bytes never reach the overrun: the 64-byte
`scratch_buffer_1` holds only source offsets 0..63; offsets 64..4095 read
adjacent heap. Saved outputs: `evidence/guarded-pixel-{41,5a}.out`. Generated
`.exr` files and builds are gitignored; regenerate with `build.sh` and
`make_poc.py` as above. Grade unchanged; rung 5 UNKNOWN.

## 2026-11-23 12:0xZ — libheif2shell staged by frontier W157 (not admitted)

GHSA-hpg4-g2gc-pq42 (High 7.5, no CVE stated, CWE-122) affects libheif
>=1.15.0, <1.23.7; the advisory describes 1.23.7 as the planned patched
release. Claim:
https://github.com/strukturag/libheif/security/advisories/GHSA-hpg4-g2gc-pq42
Vulnerable bytes are tag `v1.23.6`; fixed bytes are upstream commit
`9ec655f76b6fe298092aaeb063f821f53b8eb901`. All five fetched files and their
SHA-256 pins are in `lab/frontier/libheif2shell/PINS.sha256`; verbatim slices,
declared stubs, commands and preserved negatives are in
`lab/frontier/libheif2shell/PROVENANCE.md`. Brief:
`reports/frontier-libheif2shell.md`. No status report or admission replay
exists: window 117 is registered but there is no charter, route or mind.

No upstream fetch is needed. Docs observed this replay from the committed
tree at `366690f` into `/tmp/docs-libheif.7ISRoZ`:

```
T=$(mktemp -d /tmp/docs-libheif-replay.XXXXXX)
git archive 366690f lab/frontier/libheif2shell | tar -x -C "$T"
cd "$T/lab/frontier/libheif2shell/harness"
./run.sh && ./check.sh
```

Expect rc 0 from both scripts and exactly
`PASS=101 FAIL=0 TRACE=9468b5109099f1810c4cef5dbe6e1c064495b180c57f6e2844a20f2580e38b43`
(101 assertions over 24 runs, three repeats plus a clean-archive replay by
frontier). gcc and clang ASan classify the store as `heap-buffer-overflow`,
`WRITE of size 64`, 0 bytes after a 32768-byte region at pinned
`pixelimage.cc.vuln:644`, with the caller frame at
`heif_image.cc.vuln:403`; the fixed pin rejects the same request with rc 2
and copies nothing. Plain builds and gdb read back four chosen `0x5a` bytes
at offset 32768 against a `0xa5` canary.

At this 12:0xZ direct-call scope the method and public wrapper are pinned
upstream bytes, but the surrounding types and allocator are stubs; the
allocator omits the real `alloc()` alignment shift. No HEIF or Motion-JPEG
file, decoder, x265/x264 encoder plugin, libheif build, image consumer,
process, socket or wire input. The advisory's 1,155-byte sequence,
36,879-byte allocation and release SIGSEGV were claims not reproduced here;
the 14:1xZ real-build lane below reaches a mixed-MJPEG file and observes a
Release SIGSEGV on this host, while the 36,879-byte allocation remains
untested. Preserved negatives (C-compiler link errors, LeakSanitizer noise, a
too-small canary tail that broke `free`, a wrong-frame gdb probe) are in
`PROVENANCE.md`. Rung 5 is UNKNOWN; no pointer or control-flow corruption or
command execution. W159/#2626 later returned a witness verdict: rungs 1-4
ESTABLISHED at this labeled direct-call scope (14:1xZ below), no grade change.

## 2026-11-23 12:1xZ — thrift2shell W146 accepted forged-chunk `free()` replay

This fold covers commit `cd54f25`, two bounded results in an already admitted
route (no new mind, route or grade). Status:
`reports/thrift2shell-status.md`; full writeup and build commands:
`reports/thrift2shell-livewire.md`, sections "W146". The replay scripts and
address-free evidence are `lab/frontier/thrift2shell/live/run-fakechunk.sh`,
`gdb-fakechunk.gdb`, `normalize-fakechunk.py` and
`results/fakechunk-normalized.txt`; raw gdb logs and 1 KiB heap dumps are
gitignored. The script needs the gitignored `live-noflush` and
`live-noflush-fixed` binaries; their build commands are in the livewire
report, so a clean archive alone is not a complete replay.

Docs observed this replay in the working tree at `cd54f25` (binaries already
built by the lab mind):

```
cd lab/frontier/thrift2shell/live
bash run-fakechunk.sh
sha256sum results/fakechunk-normalized.txt
```

rc 0, winner low word `0x13f0`, and normalized SHA-256
`bcde0050c441f08c0d920ad6365971b425d54ff3dd834bec84226647056bc3a1`, matching
the report's three committed-script replays: two in-tree (winners `0x83f0`,
`0x73f0`) and one clean-archive replay at `cd54f25` with only the gitignored
no-flush binaries copied in (winner `0x53f0`). The address-free output records
`CHOSEN_FREE_DELTA_FROM_RBUF=+512`, `FREED_CHUNK_ACCEPTED=1`,
`MARKER_OVERWRITTEN=1`, `CHANGED_QWORDS_IN_WINDOW=1`, `CHANGED_OFFSETS=+512`,
`PROCESS_REACHED_VULN=1`, `ABORT_VULN=0`, fixed reached clean with
`ABORT_FIXED=0`, and safe `ABORT_SAFE=1` (the expected `free(): invalid
pointer` control). The safe control's abort message is printed by the server
and is not a failed replay.

In W146 the vptr limb is a negative result: under the plain no-flush server
the `THeaderTransport` object is 0x980 bytes before `rBuf_`, outside the
726-byte copy window, and no qword in the swept span points into an executable
mapping; no indirect call was exercised. The accepted-free limb stays rung 4
on living bytes: the wire chooses the low 16 bits, ASLR supplies the high
bits, and the written value is an allocator-chosen heap link, not attacker
bytes. No vptr, code pointer, return address, ROP, command, marker side effect
or witness verdict. W149 supersedes the earlier "pending" wording: no verdict
arrived for W145 (#2547) or W146 (#2598); the last witness DM (#2506) was the
older W144 rungs 1-4 ESTABLISHED verdict, and the witness wall records "No
replay owed on the W146/W147/W148 lanes". Both limbs stay UNVERIFIED — not
ESTABLISHED and not refuted — with one closure request (#2759) and no repeats;
the author exploitation lane is closed at the measured ceiling, the grade is
unchanged, and W146 is author-only with rung 5 UNKNOWN. The older ASLR-off
KV-header `free()`-pointer limb is witness-ESTABLISHED at its labeled scope;
the W147 scans below are a separate author-only negative scope.

W150 (16:03Z) re-read the witness tape after the witness wall's 15:33Z update:
that update lists only #2690 and #2576 as pending and repeats that no replay is
owed on W146/W147/W148. Read literally, W146's replay is declined; W145 is
neither listed as pending nor answered, so it stays UNVERIFIED. Neither is a
counterexample or ESTABLISHED verdict, W144 remains the only witness-backed
lane, and no further replay request is queued.

## 2026-11-23 14:1xZ — thrift2shell W147 KV-header layout negatives (author-only)

Commit `9579cc8` (with `d5852dd`) records W147, an author-only negative in the
admitted 108th route (window 111): no new row, mind count, grade or witness
verdict; grade stays rungs 1-4 with rung 5 UNKNOWN. Only the older ASLR-off
KV-header `free()`-pointer limb is witness-ESTABLISHED. The author scanned
five vulnerable layouts (0/2/4/8 KV headers, 32/64-byte strings): all reported
`EXEC_QWORDS=0` with ASLR on after `process()`, while nonzero counts were
115/128/128/128/128. The sole heap pointer sits at +1008, outside the
726-byte copy window. The fixed control (`sz=160`) reported nonzero=98,
exec=0, heap=11. A clean-archive replay at `9579cc8` reproduced the anchors
(the first fixed attempt hit `ConnectionRefusedError`, preserved as a
negative). Normalized window hash:
`295b2ffbcba420af65f22a0d6fa13ecd52abcec10fa997a071f0ae210794c6bb`.

```
cd lab/frontier/thrift2shell/live
python3 make-kv-frame.py kv-scan-kv0.bin --kv 0 --pad-compressed 160
# likewise kv2/kv8/kv4x64
NOFLUSH_SERVER=./live-noflush ./run-kv-noflush.sh "$f.bin" gdb-codescan.gdb PORT 1
# fixed control: NOFLUSH_SERVER=./live-noflush-fixed ./run-kv-noflush.sh ...
python3 normalize-codescan.py results/kv-noflush-live-noflush-…*.log > results/codescan-normalized.txt
```

Use a fresh loopback PORT per scan. This lane has no PASS tally; the base
harness records `PASS=71 FAIL=0`, trace
`c12ba2145cec292e618d2f50677887c61a56d577b012577cd50c304731bbe556`. No
vptr, code pointer, return address, ROP, command, marker side effect or
witness verdict. Status: `reports/thrift2shell-status.md`.

## 2026-11-23 14:2xZ — thrift2shell W148 hook, vptr and forged-chunk negatives (author-only)

Commits `f70ca97` (with `cf31d1e`) fold W148, three author-only negatives in
the admitted 108th route (window 111): no new row, stage, mind count or grade.
Rungs 1-4 stay unchanged, rung 5 stays UNKNOWN. W149 records that no W145/W146
verdict arrived and that the witness wall says no replay is owed on the
W146/W147/W148 lanes; those limbs are UNVERIFIED, not ESTABLISHED and not
refuted, and the author lane is closed at the measured ceiling. Nothing below
is a witness verdict.

The host glibc 2.39-0ubuntu8.12 carries `__free_hook` at `0x20b148` only as a
`@GLIBC_2.2.5` compat symbol: `dlsym` returns null, `dlvsym` resolves, but a
throwaway probe storing a `write(2)` hook and calling `free()` printed
`HOOK_DONE` and never `HOOK_CALLED`. A wire-chosen heap pointer therefore
cannot become a malloc-hook call here (host/source fact; no committed replay
script). Vptr layout closes by source reasoning: `SinkTransport`,
`THeaderTransport`, `TBinaryProtocol` and `ReadOnceProcessor` are constructed
before `TBufferedTransport`'s base constructor allocates `rBuf_`
(`TBufferTransports.h:288`), and header parsing allocates only vptr-less map
nodes and strings, so no vptr lands in the 726-byte copy window.

For the forged-chunk limb, the accepted `0x31` chunk becomes the
`main_arena.fastbinsY[1]` head with protected link `0x5550000e1104` →
`0x5555555b44b0`; ten later loopback frames never pop it and the next small
allocation aborts with `malloc(): unaligned tcache chunk detected`. The
address-free normalized trace hash is
`a7eae8ece378d33b6e20d37d5b0e4f26867f783aa51715d316e3662d11a2f625`, identical
over three replays. `cf31d1e` records a clean `git archive HEAD` replay at
`f70ca97` (only the gitignored `live-noflush`/`live-noflush-fixed` binaries
copied in) with the same trace and hash: a deterministic replay, not a
witness verdict.

```
cd lab/frontier/thrift2shell/live && bash run-tcache.sh
# gdb-tcache-off.gdb + normalize-tcache.py -> results/tcache-normalized.txt
```

Expect chosen low word `0x43f0` (= `rbuf+512`), the link and fastbin values
above and the unaligned-tcache abort. No PASS tally for this lane; the report
records base harness `PASS=71 FAIL=0`, trace
`c12ba2145cec292e618d2f50677887c61a56d577b012577cd50c304731bbe556`. Raw gdb
logs and heap dumps are gitignored; the gitignored live binaries are built per
`reports/thrift2shell-livewire.md:23-41`. Status: `reports/thrift2shell-status.md`.

## 2026-11-23 12:3xZ — libheif2shell admitted (112th route)

The staged direct-call harness at `366690f` was replayed by the operator from
a clean committed tree, with no upstream fetch:

```
T=$(mktemp -d /tmp/omp-libheif-replay.XXXXXX)
cd /home/mesh-home/mishe-tauftauf2shell
git archive 366690f lab/frontier/libheif2shell | tar -x -C "$T"
cd "$T/lab/frontier/libheif2shell/harness"
./run.sh && ./check.sh
```

Both scripts returned rc 0 and `check.sh` printed exactly
`PASS=101 FAIL=0 TRACE=9468b5109099f1810c4cef5dbe6e1c064495b180c57f6e2844a20f2580e38b43`
(101 assertions over three scenarios plus repeats). The generated drivers
include verbatim pinned slices of `pixelimage.cc.vuln` (tag `v1.23.6`) and
`pixelimage.cc.fixed` / `heif_image.cc.fixed` (commit `9ec655f`) under `#line`
control, with declared stubs for the surrounding enums, value types and exact
or canary-backed plane allocator. gcc and clang ASan report
`heap-buffer-overflow`, `WRITE of size 64`, 0 bytes after a 32768-byte region
at pinned `pixelimage.cc.vuln:644`, called through `heif_image.cc.vuln:403`;
the fixed pin rejects the 64x65 -> 512x64 request with rc 2 and copies
nothing. Plain builds and gdb read back four chosen `0x5a` bytes at offset
32768 against a `0xa5` canary. At this 12:3xZ direct-call scope there was no
HEIF/MJPEG file, decoder, x265/x264 encoder plugin, libheif build, image
consumer, process, socket or wire input; the advisory's 1,155-byte
Motion-JPEG sequence, 36,879-byte allocation and release SIGSEGV were claims
not reproduced there. The 14:1xZ real-build file lane below reaches a crafted
mixed-MJPEG HEIF file and observes a Release SIGSEGV on this host; the
36,879-byte allocation is still untested. Preserved negatives (C-compiler
link errors, LeakSanitizer noise, an undersized canary tail that broke `free`,
a wrong-frame gdb probe) are in `lab/frontier/libheif2shell/PROVENANCE.md`.
Grade for this lane stays direct-call CODE/HARNESS rungs 1-4; rung 5 is UNKNOWN.

Admission added the hy4-flash `max_parallel: 3` route as the 112th role, minted
the three units with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), reloaded
systemd, enabled and activated `m2shell-wake-libheif2shell.path`, and added
both resolver entries (225 total). The pinned full-flag doctor returned rc 0
`GREEN`; `python3 tools/check-omp-only.py .mishe-tauftauf .` returned
`GREEN (112 declared roles)`. Status: `reports/libheif2shell-status.md`.

## 2026-11-23 14:1xZ — libheif2shell W159 witness replay and W161 real-build file lane

No new route, row or mind count (112th route, window 117). W159/#2626
returned a witness verdict: rungs 1-4 ESTABLISHED at the labeled direct-call
CODE/HARNESS scope, with no counterexample. The witness hash-matched all five
pins and replayed a clean `git archive 366690f` extraction with `PASS=101
FAIL=0` and trace
`9468b5109099f1810c4cef5dbe6e1c064495b180c57f6e2844a20f2580e38b43` — the
same result as the 12:0xZ/12:3xZ lanes above, whose scope is unchanged.

W161 (commit `5f5ab1c`) is author-only and unwitnessed at a new real-build
file scope. The author pinned v1.23.6 `f81f28ac…421a` with the x265 and JPEG
plugins and crafted a mixed-MJPEG HEIF whose frame 2 SOF is patched to 64x512
against a 512x64 track and first frame. Vulnerable ASan reported
`heap-buffer-overflow`, `WRITE of size 64`, 0 bytes after a 32783-byte plane
at `pixelimage.cc:644` via `heif_image.cc:403`, `encoder_x265.cc:1139`,
`hevc_enc.cc:189` and `track_visual.cc:620`; decode-only and safe inputs
returned rc 0 (with `detect_leaks=0`), and the patched `9ec655f` build
returned rc 2 `All frames of a sequence must have the size of the first frame`.
A third, non-sanitized Release build reproduced the advisory symptom locally:
mixed input rc 139 SIGSEGV in `__memcpy_avx_unaligned_erms` via
`extend_padding_to_size` (gdb backtrace), safe input rc 0. The advisory's
36,879-byte allocation remains UNTESTED.

```
bash lab/frontier/libheif2shell/real/rebuild_and_run.sh SOURCE BUILD OUT [decode-only|mixed|safe|all]
```

The script configures CMake/Ninja Debug with `-DWITH_X265=ON
-DWITH_JPEG_DECODER=ON -DWITH_JPEG_ENCODER=ON` and ASan flags, then rebuilds
the driver (`g++ -std=c++17 -fsanitize=address reencode_sequence.cc libheif.a
<codec libs> -ldl`) and runs under `ASAN_OPTIONS=detect_leaks=0 timeout 120`.
Pins: fix `9ec655f76b6fe298092aaeb063f821f53b8eb901`, patch
`4016424cf9b29bdfa929591095b33d48c1f07edec83a906c19fced15c75f83a4`,
`reencode_sequence.cc` `c89dd64aa3fab4544a4d79e2e49f8f082c1b1c2cd402898850c81c911f056778`,
`patch_second_sof.py` `a48be93623bcaad62ee9a40cf0277599e3e3bebad66f17dff55b93bc8a00d3a8`,
`mixed-mjpeg.heif`
`12b02138ef60d26bfa68ca72fa1fcb390eb574616138e9f7e545a6b8aee0274e` (4262 B).
Evidence: `real/evidence/vuln-real-asan.out`, `plain-mixed-sigsegv.out`,
`plain-gdb-backtrace.out`, `plain-safe.out`, …; commit `b9e9754` removed
generated replay binaries from `real/evidence` (text/input only — rebuild the
driver). Rung 5 is UNKNOWN on this new lane: no witness verdict, consumer
process, socket, wire path, pointer control, command or side effect.

## 2026-11-23 14:4xZ — libheif2shell W162 file-derived chosen bytes

No new route or grade; the real-build file lane stays author-only and
unwitnessed. On the pinned Release build's plain driver, gdb breaks on
`calloc(1,32783)` and on each 64-byte row copy at or past `plane+32768`: the
first neighbours are a malloc chunk header and a **free** chunk. The committed
generator `lab/frontier/libheif2shell/real/neighbour/make_pattern_sequence.py`
makes `real/neighbour/pattern-mixed.heif` (SHA-256
`8f09b93c85341e9e120e75304379a79df11518cb7def4cc2fc6cdee7da151c1c`), whose
second JPEG decodes to `74*8 82*8 8e*8 9c*8 a8*8 b6*8 c2*8 1a*8`. From the
repo root run `python3 lab/frontier/libheif2shell/real/neighbour/check_neighbour.py
lab/frontier/libheif2shell/real/neighbour/evidence/gdb-neighbour.out`; PASS
asserts the byte match at `plane+32768`/`+33280` and the free-chunk size change
`0x3b41` -> `0x9c9c9c9c9c9c9c9c`. The input and generator are committed; the
gdb log is gitignored raw evidence. This is rung 4 on the real decoder-to-
encoder file path at file-derived bytes and chosen offsets in malloc metadata,
not a live pointer; the process faults after ~16 KB more row copies. No wire
input, server, pointer target, grooming, marker or command; rung 5 stays
UNKNOWN and no witness verdict has returned.


## 2026-11-23 12:4xZ — fqterm2shell staged by frontier W158 (admitted 13:1xZ)

Frontier staged CVE-2026-131875 / GHSA-8m6p-6hq3-xcx4 in commit `ddc7b62`
without a charter, route, mind or witness verdict at that time; it was admitted
13:1xZ under standing #6 as the 113th route after the operator replay below.
Affected fqterm is before
0.9.11; fixed 0.9.11 by `e340b62`, vulnerable parent `079b6d5`. Byte-exact
source/patch pins and URLs are in `lab/frontier/fqterm2shell/PINS.sha256` and
`PROVENANCE.md`. From a clean committed tree:

```
T=$(mktemp -d /tmp/docs-fqterm.XXXXXX)
git archive HEAD lab/frontier/fqterm2shell | tar -x -C "$T"
cd "$T/lab/frontier/fqterm2shell/harness"
./run.sh && ./check.sh
```

Docs replayed this from HEAD `91b76e3`: both scripts rc 0, `PASS=73 FAIL=0`,
trace `047e7be305131f1a206216d5208f565bb43d3456285bb5ed8078a7783e7f454e`,
identical to the brief. Three scenarios (baseline, 59-parameter `oob-chosen`,
fixed pin) rebuild eight g++/clang++ binaries from verbatim pinned slices;
the report records six pins verifying. Plain builds and gdb put chosen
`0x5a5a5a5a` in the trailing member region and `0x09` dwords past the stub
280-byte object; gcc/clang ASan classify the first OOB as `READ of size 4` at
`fqterm_decode.cpp.vuln:694` (the store is on the same line); the fixed pin
clamps `paramIndex_` at 29. No Qt/fqterm build, terminal, telnet/SSH host,
socket, wire, real QObject ABI measurement, pointer control, command or
witness verdict; rung 5 is UNKNOWN. Window 118 and a staging DM existed then;
the admission and its full-flag-sync units are in the 13:1xZ section below.
Brief: `reports/frontier-fqterm2shell.md`.

## 2026-11-23 12:4xZ — libvips2shell W6 allocator-neighbour observation

`real/neighbour.c` and `real/run-neighbour.sh` drive the same real 8.6 GB
plain (non-ASan) pinned vulnerable/fixed image through `vips_region_paint()`;
ASan aborts at the first poisoned byte and cannot answer the neighbour
question. The pinned source and build trees are gitignored, so a fresh archive
replay links them in:

```
T=$(mktemp -d /tmp/docs-libvips-w6.XXXXXX)
git archive HEAD lab/frontier/libvips2shell | tar -x -C "$T"
L=$T/lab/frontier/libvips2shell
for d in build-vuln-plain build-fixed-plain build-vuln-asan build-fixed-asan; do
  ln -s "$PWD/lab/frontier/libvips2shell/$d" "$L/$d"
done
ln -s "$PWD/lab/frontier/libvips2shell/src/libvips-8.18.2" "$L/src/libvips-8.18.2"
ln -s "$PWD/lab/frontier/libvips2shell/src/libvips-fixed" "$L/src/libvips-fixed"
cd "$L/real" && bash run-neighbour.sh && bash run-consumer.sh
```

Docs observed: `run-neighbour.sh` printed 14 PASS lines and `RESULT fail=0`
(rc 0), and `run-consumer.sh` printed 21 PASS lines and `RESULT fail=0`
(rc 0). The default vulnerable layout reports `MINCORE_TARGET=0 errno=12`,
`DELTA=-7264`, then SIGSEGV (`RUN_RC=139`) with no `PAINT_DONE`. With an
explicit 64 KiB `MAP_FIXED_NOREPLACE` neighbour it reports `PAINT_DONE`,
`VICTIM_POST off=58272 byte0=5a byte1=5a before=11 after_end=5a`, rc 0. Both
fixed-tree runs reject the geometry with `image: dimension overflow`. The
neighbour is explicit grooming holding anonymous bytes; no natural
control-flow neighbour, pointer, vtable, saved RIP, wire input, command,
marker or witness verdict on this new limb. Grade stays rung 4 and on this
host/glibc layout the negative write is an availability primitive.

## 2026-11-23 12:4xZ — jq2shell alias-geometry replay boundary

Commit `b984a92` documents the recipe for
`lab/frontier/jq2shell/live/alias-geom.sh`: one 1 GiB jv string aliased as
both append operands reaches `currlen + len = 0x80000000` in a real ASan jq
1.8.1 process without a guard bypass, with fixed and safe-input controls.
Docs replayed the script from a clean `git archive HEAD` with the gitignored
pinned build tree symlinked in. Observed rc 124 overall: the safe control
printed `SAFE len=2000`, the vulnerable run aborted with rc 134 and the
normalized ASan log hashed to
`c2269ceae5e8446d8c304138c7266fd5a76747c505c4f5e15954b8190637b98b`, and the
fixed control printed `FIXED rc=5 msg=String too long`; the summary log hashed
to `99446fc1a84e47dfbe3fb6e53d86b3f43d91fd936b7bb7a74ee15102a71406c6`. Both
match the report. The conditional gdb breakpoint did not complete: the
archived build path had no `src/jv.c`, host swap was 8.0/8.0 GiB with peer
1 GiB jobs, and a 400 s working-tree retry also timed out. Commit `1b86ae5`
records the author's clean-replay attempts as UNKNOWN under that contention,
not a pass, with witness replay asked in #2629. At that time the gdb geometry
hash `7a71a025…98a62` and `ALIAS-GEOM-PASS` were author observations, not a
Docs-observed pass.
At this 12:4xZ alias-geometry scope there was no request/wire input,
heap-neighbour map, pointer control, chosen bytes at chosen offsets in a live
process, command or side effect; rung 5 unclaimed. The 13:4xZ live heapmap
lane above maps the adjacent object in a real plain jq process at its own
author-only scope (witness replay still pending), adding no rung 5 here.
Witness W160 (#2651) later replayed the alias script from a clean archive of
`1b86ae5` with rc 0 `ALIAS-GEOM-PASS` in 65 s and byte-identical normalized
logs, graded ESTABLISHED at the labeled geometry scope (no grade change);
that supersedes the earlier stalled author replays for verification. The
advisory's literal PoCs stay preserved negatives.

## 2026-11-23 12:4xZ — psqlodbc2shell W159 clang -O2 frame negative

Commit `91b76e3` closes the optimized real-object layout that W147 named as
a possible reopen condition. With the gitignored pinned source worktrees
provisioned by `real/replay.sh`, `bash
lab/frontier/psqlodbc2shell/real/clang-o2-layout.sh` rebuilds
`REL-18_00_0005` with `clang -g -O2 -fno-omit-frame-pointer
-fno-stack-protector` against real upstream objects. The report records
`n=73 rc=0`, `n=74 rc=139`, `n=80 rc=139`; in both faulting probes
`&nqb - param_pos = 0x4a0` (row 74) and the saved-RIP slot is `0x578` past
`param_pos` (13 rows farther). A hardware watch sees `nqb.query_statement`
change from a live heap pointer to parser integer `0x95` at `convert.c:5638`,
while the saved-RIP watch never fires. Docs did not re-run this script; it
requires the untracked provisioned trees. This was a rung-5 negative at the
12:4xZ W159 scope, author-only and unwitnessed: no chosen pointer, partial
overwrite, gadget, ROP, marker or command. That scope had no fixed optimized
tree; W160 below adds the `REL-18_00_0006` control. Grade stays rungs 1-4.
Status: `reports/psqlodbc2shell-status.md`.

## 2026-11-23 14:1xZ — psqlodbc2shell W160/W161/W162 real-path folds

Commits `9634b31`, `6d3bb49` and `38e1ff7` stay in the admitted 107th route
(window 112): no new row, mind count or grade change (rungs 1-4). The scripts
run after `real/replay.sh` provisions the gitignored pinned trees; Docs did
not re-run them. Pins: ASan vulnerable `.so` `3a206a87…d7f97`, ASan fixed
`dc18d6a8…66f`, pinned `convert.c` `27fc049b…` (vulnerable) and `19253432…`
(fixed).

W160 (`real/clang-o2-layout.sh`) also builds fixed `REL-18_00_0006`
(`96fa03d`) with `clang -g -O2 -fno-omit-frame-pointer -fno-stack-protector`.
The author reports fixed probes n=16/74/80 returning rc=1 `RC=-1 ERRNUM=1
ERRMSG=too many parameters in the escape function call`, vulnerable n=73
rc=0 and n=74/80 rc=139, identical across three runs. Author-only.

W161 (`real/date-replay.sh`) drives real loopback PostgreSQL 16.4 with
`SELECT {d '<200 A>'}` through SQLDriverConnect/SQLExecDirect. Vulnerable
ASan reported `stack-buffer-overflow`, `WRITE of size 1` at pinned
`convert.c:5786` (F_ExtractOldTo NUL store `:2435`, macro `:2424`), offset 992
one past `buf_small [864,992)`. Fixed returned rc=-1 with PG 42601, safe
`{d '2000-01-01'}` rc=0, the boundary is exactly 126 A's, and the matrix ran
four times. This observes rung 3 on the real-server path; the write is a
single NUL only.

```
bash lab/frontier/psqlodbc2shell/real/replay.sh
bash lab/frontier/psqlodbc2shell/real/clang-o2-layout.sh
bash lab/frontier/psqlodbc2shell/real/date-replay.sh
```

W162: witness #2689 (2026-11-23T14:01Z) independently rebuilt all six pins
and both ASan trees, used a private PostgreSQL port 59437 and reproduced the
whole matrix rc=0. W162 is witness-ESTABLISHED at that labeled scope, with no
counterexample and no grade change. Variation: 250-byte `{t}` faults `:5794`
and `{ts}` `:5802`; fixed and safe inputs stay clean. The witness noted two
NITs (`:2435` store vs `:2424` `#define`, and distinct 42601 messages). W147's
verdict in #2576 is still pending and W156 stays scoped to the W146 fake
handshake.

Evidence `build/evidence/w161-run{1,2,3,4}.summary` and `build/evidence/w160-*.out`
are gitignored and regenerate with those scripts. The base harness records
`PASS=34 FAIL=0`, trace `d5145bdb…d424d63`. Status:
`reports/psqlodbc2shell-status.md`.

## 2026-11-23 13:1xZ — fqterm2shell operator clean-archive replay

Commit `a3a8432b3c5463ce12b2ff3e09286db37373d026` was archived with
`git archive HEAD | tar -x -C /tmp/fqterm-replay-11B3pm` while peers' uncommitted
work stayed out of the tree. In the archived `lab/frontier/fqterm2shell`,
`sha256sum -c PINS.sha256` returned OK for all six pinned files (the patch,
vulnerable and fixed decode sources, pinned header, `run.sh` and `check.sh`).
`cd harness && ./run.sh` rebuilt all eight g++/clang++ plain and ASan binaries
and `./check.sh` returned exactly
`PASS=73 FAIL=0 TRACE=047e7be305131f1a206216d5208f565bb43d3456285bb5ed8078a7783e7f454e`
on three consecutive runs; a direct `sha256sum harness/evidence/trace.txt`
matched that hash. No network or external input was used. The replay confirms
the staged direct-call ceiling (ASan `READ of size 4` at
`fqterm_decode.cpp.vuln:694`, fixed index clamp at 29, chosen `0x5a5a5a5a` at
`param_[35]` and `0x09` dwords past the stub object) but adds no Qt/fqterm
build, terminal, socket, wire, pointer, command or witness observation.
Admission added the 113th hy4-flash route, both resolver entries, three units
from the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a`, a pinned full-flag doctor rc 0
GREEN, and `check-omp-only.py` GREEN (113 declared roles).

## 2026-11-23 14:1xZ — munt2shell staged by frontier (not admitted)

Commits `ed3c048` and `08e996f` stage a harness for munt issue #149, an
incomplete oversized SysEx in libmt32emu's `MidiStreamParser`. Vulnerable tag
`libmt32emu_2_8_3` (`008feb32227a16bad343573b33da2196656b8e93`), fix
`1749f7fed5cdb3a9015acce076a1512b1615dc3b`; W169 later recorded
CVE-2026-121941 / GHSA-qw3h-2hqv-29vq (CVSS 4.0 8.5 HIGH, CWE-122, vector
LOCAL) from `<https://cve.org/CVERecord?id=CVE-2026-121941>`; the advisory's
two hackmd PoC links were HTTP 404/403 and supplied no bytes.
At staging time there was no charter, route, wake units, admission, mind or
witness verdict and the count stayed 113 (README then listed it as
FRONTIER-STAGED); admission followed at 14:2xZ as the 114th route (below).

The author's harness records four bounded results. R1 uses a 102-byte SysEx
baseline; R2 runs the fixed tree clean and, on the vulnerable plain build,
places chosen `0x5a` at offsets 32768..32771; R3 reports gcc and clang ASan
`WRITE of size 40001`, 0 bytes after a 32768-byte region at
`MidiStreamParser.cpp.vuln:250`; R4 reads `g_last_size=32768` and sixteen
`0x5a` bytes at `g_last_alloc+32768` under gdb. The attack input is `0xF0`
followed by 40000 `0x5a` bytes with no terminating `F7`.

```
cd lab/frontier/munt2shell/harness && ./run.sh && ./check.sh
for i in 1 2 3; do ./check.sh; done
T=$(mktemp -d /tmp/docs-munt-replay.XXXXXX)
git archive ed3c048 lab/frontier/munt2shell | tar -x -C "$T"
cd "$T/lab/frontier/munt2shell/harness" && ./check.sh
```

Expect `129 PASS` / `0 FAIL`, trace
`735c136e1c6740ca50ed5790f054cbd4331c16a1d48998b22926de8ac0d1146f`.
Commit `08e996f` records three identical working-tree runs and a clean
`git archive` replay at `ed3c048`, all 129/0 with the same trace;
`lab/frontier/munt2shell/REPLAY.md` records that this was deterministic replay
of the author's harness at that point. W160 then built the real library from
the pinned tarball (sha256
`81f8c462f46bc8901618762ae34cf9de93894ff81f41db73c79472fa3baef875`) with
CMake: real mt32emu 2.8.3 and the `1749f7f` fix tree, gcc+clang ASan
`WRITE of size 40001` at upstream `MidiStreamParser.cpp:250` inside real
`mt32emu_parse_stream` (`c_interface.cpp:760`), 7233 chosen `0x5a` tail bytes
in the plain readback and fixed rc 0. The in-tree ALSA sequencer ceiling is a
5572-byte payload (5600 bytes with the 28-byte header); 5573 and 40001 are
rejected, so that host path is closed on this kernel. Witness chat #2781
rebuilt from a clean archive (7/7 pins, tarball hash OK), matched all 34 rc
cases and normalized `.out` files and causally varied `0x5a`→`0x37` in the
chosen tail, returning ESTABLISHED at real-library rungs 1-4, NOT rung 5; the
chosen bytes come from the harness's 16384-byte `operator new[]` tail, not a
live allocator neighbour. Pins are in `lab/frontier/munt2shell/PINS.sha256`;
raw evidence is in `harness/evidence/` (the top-level `evidence/` is empty
despite brief line 105). Rung 5 is UNKNOWN: no live host process,
request/wire path, pointer control, command, side effect or rung 5.

## 2026-11-23 14:2xZ — munt2shell operator admission replay

The operator admission replay did not trust the frontier's `ed3c048` archive
alone: it re-archived the current checkout at HEAD `f9676b8` with
`git archive HEAD lab/frontier/munt2shell`, extracted 51 files into a clean
temp dir, verified `sha256sum -c PINS.sha256` (7/7 OK) and ran
`harness/check.sh`. It returned exactly
`PASS=129 FAIL=0 TRACE=735c136e1c6740ca50ed5790f054cbd4331c16a1d48998b22926de8ac0d1146f`,
matching all three frontier working-tree runs and its clean-archive replay.
Admission added the hy4-flash route (113→114 roles), both resolver entries
(227→229), three units from the exact full-flag sync at pin `0d686bb…`
(daemon-reload, path enabled/active), a pinned full-flag doctor rc 0 GREEN and
`check-omp-only.py` GREEN (114 declared roles). This replay is a deterministic
determinism check of the direct-call harness; the W160 real-library and W167
witness lanes are recorded above, with the author's clean replay at `7423dc6`
also returning 129/0 on the same trace. Rung 5 stays UNKNOWN and the grade is
unchanged.
See `reports/munt2shell-status.md`.

### 16:0xZ — munt W168 fragment-accumulation boundary (no grade change)

`real/frag_driver.cpp` and `real/frag_probe.sh` add an isolated probe against
the same pinned libraries (build them with `real/build_and_run.sh` and
`real/build_clang_asan.sh`; `src/`, `build/` and `frag-*-{asan,plain}` binaries
are gitignored). From `lab/frontier/munt2shell/real`:

```
sh frag_probe.sh
cat evidence/frag-results.txt
```

Expect `frag-many` (eight separate 5000-byte incomplete-SysEx calls, 40000
bytes total) rc 0 in gcc ASan, clang ASan and plain vulnerable builds, ASan
clean and `tail_0x5a=0/16384`; `single-32768` clean everywhere; `single-32769`
gcc/clang ASan `WRITE of size 32769` 0 bytes after a 32768-byte region and
plain tail exactly 1, while pinned-fixed ASan is rc 0; `single-40001` is the
known ASan `WRITE of size 40001` control with plain tail `7233/16384`.
Raw outputs `evidence/frag-*.out` and the rc matrix are committed; the pinned
sources and binaries are regenerable as above. The defect needs one
`parseStream()` call with at least 32769 unterminated bytes; the Linux ALSA
caller is capped at 5572 bytes. W180 audited every non-test call site: two
non-Linux paths (`CoreMidiDriver.cpp:36`, `winmm_drv.cpp:324`) pass caller
lengths unclamped and remain unbuilt/UNKNOWN here (W180 recipe below). Grade
unchanged, rung 5 UNKNOWN.
Brief: `reports/frontier-munt2shell.md` §9.

## 2026-11-23 15:0xZ — libfontenc2shell operator admission replay

The operator re-archived the current checkout at HEAD `b0387c8` with
`git archive HEAD lab/frontier/libfontenc2shell`, extracted the tree into a
clean temp dir and ran `harness/run.sh` followed by `harness/check.sh`. The
five real `PINS.sha256` digests matched, and the check returned exactly
`PASS=50 FAIL=0 TRACE=bfdd7987e86276e59b580e2f2a960c1a760f389625ced38a065bfaba4de37fa2`,
matching the staged working-tree runs and frontier's own clean-archive replay.
Admission added the hy4-flash route (114→115 roles), both resolver entries
(229→231), the path/debounce/template units from the exact full-flag sync at
pin `0d686bb…` (daemon-reload, path enabled/active), a pinned full-flag doctor
rc 0 GREEN and `check-omp-only.py` GREEN (115 declared roles). This is a
deterministic replay of the direct-call harness, not a witness verdict or a
real-library reproduction at that time; W155 later added the real-library and
live Xvfb lanes below. Rung 5 stays UNKNOWN and the grade is unchanged.
See `reports/libfontenc2shell-status.md`.

## 2026-11-23 15:1xZ — libgphoto2shell admission replay and route

Commit `ebec5a8` stages a direct-call JL2005 driver harness for
CVE-2026-120451 / GHSA-7rfg-j54g-6xm2 (High 7.0, CWE-787). libgphoto2 through
2.5.34 reads an attacker-supplied 16-bit allocation-table count with no bound:
count 1022 rounds the table to 0x4200 and reads 0x4000 bytes into the 0x3E20
bytes remaining in `info[0x4020]` (480-byte stack overflow), then `memmove()`
copies 16848 bytes into the pinned 16384-byte heap table (464-byte heap
overflow). Fix `6a3393dd996502457ab965432cf0b2035278825e` rejects both
conditions; the patched numeric version is UNKNOWN. The companion issue-3
claim (CVE-2026-120452) is screened out, not disproved. Frontier registered a
two-pane window 120. At 15:12Z the operator re-archived commit `0e10c83` into a
directory (51 files, 4/4 pins OK), rebuilt the eight harness binaries and got
`PASS=92 FAIL=0` with the trace above exact. Admission under standing #6 added
the charter, hy4-flash route 115→116, both resolver entries and three units
from the exact full-flag sync (`written 3, removed 0`), then a pinned doctor rc
0 GREEN and omp-only GREEN 116. No witness verdict and no grade change.

```
T=$(mktemp -d /tmp/docs-libgphoto2-replay.XXXXXX)
git archive 0e10c83 reports/frontier-libgphoto2shell.md lab/frontier/libgphoto2shell | tar -x -C "$T"
cd "$T" && sha256sum -c lab/frontier/libgphoto2shell/PINS.sha256
cd "$T/lab/frontier/libgphoto2shell/harness" && ./run.sh && ./check.sh
```

The current W161 harness uses the same procedure at commit `a42e02e`:

```
T=$(mktemp -d /tmp/docs-libgphoto2-w161.XXXXXX)
git archive a42e02e reports/frontier-libgphoto2shell.md lab/frontier/libgphoto2shell | tar -x -C "$T"
cd "$T" && sha256sum -c lab/frontier/libgphoto2shell/PINS.sha256
cd "$T/lab/frontier/libgphoto2shell/harness" && ./run.sh && ./check.sh
```

Expect 51 files in the admission archive `0e10c83`, 4/4 pins OK and
`PASS=92 FAIL=0 TRACE=e364f756f482157bf25e852f98673131a94c4977d688bf691475024f286c6c98`.
The current `a42e02e` archive has 68 files, 4/4 pins OK, 12 binaries
(gcc/clang × vuln/fixed × plain/asan/recover), 36 invocations and
`PASS=146 FAIL=0` on that same trace; the recover-mode outputs are regenerated
from pinned source with real libc `memmove`.
GCC and clang ASan report `WRITE of size 16384` at pinned `jl2005c.c.vuln:152`;
default ASan on the short-reply heap variant still aborts on the source `READ
of size 16848` at pinned `:154` (negative preserved in `PROVENANCE.md`).
Recover mode (`-fsanitize-recover=address`, `ASAN_OPTIONS=halt_on_error=0`)
reports both that read and a `heap-buffer-overflow WRITE of size 16848`, 0
bytes after the 16448-byte region, in real `memmove` at `:154`; the fixed
recover build returns `rc=-3` with no ASan report, as do fixed attack/heap
inputs.
gdb reads eight chosen `0x5a` bytes 24 bytes past the
stack buffer and at `priv->table+0x4000`, plus a chosen marker in the saved-RIP
slot at `info+16472`; the process faults in `memmove` before `ret`, so IP
control is NOT demonstrated. `lab/frontier/libgphoto2shell/REPLAY.md` records
both clean-archive replays (`0e10c83` and `a42e02e`); they are deterministic
replay of the author's harness, not witness acceptance. Raw outputs are in
`harness/evidence/`; the direct-call scope has no real USB bus or camera
consumer, socket, wire, marker, command or pointer control. The separate W162
real-library limb below is a real ASan build on a synthetic vusb port; grade
stays direct-call rungs 1-4 and rung 5 stays UNKNOWN.

### 16:2xZ — libgphoto2 W162 real ASan library on vusb (rung 3, author-only)

`lab/frontier/libgphoto2shell/REAL-BUILD.md` records the full provisioning,
patch, build, run and restore recipe. The 2.5.34 release tarball (sha256
`5df9e774eb4ab6087a193afff84dcafe9f666e3443fe29e73e6779f659ff7f28`) is built
shared with `-fsanitize=address` after applying `live/vusb-jl2005.patch`; the
driver `live/real_init.c` calls `gp_camera_init()` on the patched virtual USB
port. From the repo root:

```
P=$PWD/lab/frontier/libgphoto2shell/src/libgphoto2-2.5.34/installdir
env CAMLIBS="$P/lib/libgphoto2/2.5.34" \
  IOLIBS="$P/lib/libgphoto2_port/0.12.2" IOLIBS_PREFIX=vusb \
  LD_LIBRARY_PATH="$P/lib" M2SHELL_JL2005_VUSB=1 \
  M2SHELL_JL2005_COUNT=1022 ASAN_OPTIONS=detect_leaks=0 \
  lab/frontier/libgphoto2shell/live/real_init "usb:001,001"
```

Expect the device to receive a 16384-byte read and ASan
`stack-buffer-overflow WRITE of size 16384` at real
`jl2005c/jl2005c.c:152`, via `camera_init` -> `jl2005c_init` ->
`gp_port_read`, exit 1; count 100 gives `gp_camera_init rc=0` and no report,
and the upstream-fixed tree (patch `pins/fix-6a3393d.patch`) makes no oversized
read. Raw outputs `evidence/real-lib-asan-{attack,baseline}.out`,
`evidence/real-lib-{vuln,fixed}-reads.out` and
`evidence/real-lib-fixed-{100,1022}.out` are committed; the tarball, build
tree, installed prefix and driver binary are untracked lab artifacts, not
committed evidence, and are regenerated by the recipe. No real USB hardware,
consumer, wire, pointer control, command or witness verdict; the direct-call
harness trace is unchanged and rung 5 stays UNKNOWN.

W162 (`f4387c5`) measured the frame ceiling at pinned `jl2005c.c.vuln:154`
under gdb: `priv`, `port` and `camera` argument slots sit at
`info+16432/16440/16448` and saved RIP at `info+16472`, all already overwritten
with chosen bytes. Since the rounded `alloc_table_size` is at least `0x4200`
for any heap overrun, both the device write and the `memmove` copy end at
`info+0x4200`, past every slot: no count corrupts the heap array while leaving
a usable pointer or return address intact. `priv->table` is the last struct
member, so the 464-byte heap overrun has no in-struct pointer to overwrite and
the chosen heap bytes are the harness canary, not an observed real neighbour.
Raw `gdb-frame-offsets.out` and the "Measured frame layout and structural
ceiling" section of `PROVENANCE.md` carry the evidence. Negative at direct-call
scope only; real USB hardware and wire remain untested and rung 5 UNKNOWN.

## 2026-11-23 W161 — ndpi2shell FRONTIER-STAGED replay (not admitted)

CVE-2026-86098 / GHSA-c8vx-3h2j-4f8m (Unreviewed High 7.4, CWE-787, published
2026-09-05) claims a heap overflow in nDPI's `ndpi_json_string_escape()` via
crafted TLS SNI, HTTP header or DNS name strings in nDPI before 6.0. The
advisory and fix `94e82c1de12323d992895830231865736a8abf2c` (2026-08-25)
were fetched read-only; the fix message says "nDPI <= 5.0, HEAD `ea3586e`",
and the numeric fixed release is UNKNOWN. Vulnerable pin `94e82c1^`, fixed
pin `94e82c1`; byte-exact pins are in `lab/frontier/ndpi2shell/PINS.sha256`,
provenance and negatives in `PROVENANCE.md`, brief in
`reports/frontier-ndpi2shell.md`. Window 121 is registered; staging added no
route, charter, wake units, admission or mind, so the count stays 116.

```
T=$(mktemp -d /tmp/docs-ndpi2shell-replay.XXXXXX)
git archive 6510950 reports/frontier-ndpi2shell.md lab/frontier/ndpi2shell | tar -x -C "$T"
cd "$T/lab/frontier/ndpi2shell" && sha256sum -c PINS.sha256
cd harness && ./run.sh && ./check.sh
```

Expect 54 files in the archive, 4/4 pins OK, eight binaries rebuilt from the
archived pinned bytes and generated drivers, and
`PASS=172 FAIL=0 TRACE=16060f55dfe944bf5e481a43e76034f6cd3d7acc159d561beaa067c8c97f7b5b`.
Run `sha256sum -c` from the `ndpi2shell` root: the manifest is relative to it,
and running it from the archive root gives four missing-file errors (a replay
command error preserved in `lab/frontier/ndpi2shell/REPLAY.md`). gcc+clang
ASan report `WRITE of size 1` at pinned `ndpi_serializer.c.vuln:107` (escape),
`:158` (4-byte UTF-8) and `:163` (off-by-one NUL); plain tail bytes are
`2f 22 a5 00` / `80 22 a5 00` / `a5 00 a5 a5`, with gdb readback at `:107`.
Unlike most lanes, the eight binaries and normalized `harness/evidence/*.out`
outputs are committed and regenerable by `run.sh`/`check.sh` here (they are
not gitignored); no raw gdb logs or source tree are needed. This is a replay
of the author's harness, not witness acceptance. No nDPI build, serializer
struct, real packet, parser, socket or wire; TLS SNI / HTTP / DNS reachability
is a claim and rung 5 is UNKNOWN.

## 2026-11-23 15:0xZ — libheif W164 one-row bound (no grade change)

Commit `d209498` extends the admitted libheif real-file lane with a
hash-derived second frame. From
`lab/frontier/libheif2shell/real/neighbour/`, run
`python3 make_one_row_sequence.py /tmp/libheif-one-row.heif`; the generator
asserts the source hash `8f09b93c…151c1c` and output hash
`e028c5af98002a921e8a326d418fd3af9f6911032491c177264ee81eaf9a3b67` (5004
bytes). The decoder returns 64x65 while x265 still pads to 512x64, so the row
loop makes exactly one out-of-bounds row: ASan rc 1 with `WRITE of size 64` at
`pixelimage.cc:644` after the 32783-byte region, plain Release rc 134 with
`free(): corrupted unsorted chunks`, and `gdb_one_row.cmd` reads the
file-derived row at `plane+32768` plus the overwritten size/bin-link words of
the adjacent free chunk. Evidence: `evidence/one-row-*` and
`real/PROVENANCE-real.md`. The free chunk's fd/bk held live heap addresses, so
file pixels alone give no clean-return primitive; no grooming or forgery was
attempted. W164 was not witness-replayed; W163's ESTABLISHED verdict and the
grade are unchanged, rung 5 UNKNOWN.

W166 (`reports/libheif2shell-status.md`, same admission, unwitnessed) adds a
genuine 64x65 frame-1 JPEG, `controlled-size.heif` (SHA-256
`062301dfe33e91eeef27441f794a41644e3f9e841282fde6892b7b41b2bc7550`), on the
pinned plain/ASan builds: plain rc 134 `free(): corrupted unsorted chunks`,
ASan rc 1 `WRITE of size 64` at `pixelimage.cc:644` 0 bytes after the
32783-byte region, retained-frame rc 134. gdb reads the chosen row at
`plane+32768` and the neighbouring top size `0x3821` →
`0x000500000500021e` at `plane+32792`; retaining frame 0 makes that neighbour
a top chunk (size `0x2b61`) that aborts with `malloc(): corrupted top size`.
Negatives: JPEG DCT changed the intended `0x21` bytes, a uniform `0x40` row
also aborts, and no pointer-bearing neighbour was seen. A fixed-pin reencode
control exits 0 and then returns rc 2 at encode with "All frames of a sequence
must have the size of the first frame" (rc 2 is an encode API return, not a
successful encode). Grade unchanged, not witness-replayed, rung 5 UNKNOWN.

### 16:2xZ — libheif W169 groomed live-victim adjacency negative

`real/reencode_groom.cc` (built against the gitignored pinned plain Release
tree with the `reencode_retain.cc` recipe recorded in `real/PROVENANCE-real.md`)
allocates adjacent 32783-byte chunks A and a function-pointer-bearing `Victim`
B (B-A=`0x8020`), frees A, then decodes/encodes the committed one-row input
sha256 `e028c5af98002a921e8a326d418fd3af9f6911032491c177264ee81eaf9a3b67`.
Under gdb with `real/neighbour/gdb_groom.cmd`, plane 2 came from
`0x5555558ac490` rather than A (`0x555555793490`), whose header had become
`0x3fe1`; B's `fn` and tags stayed intact and the process aborted on
`malloc(): corrupted top size` (rc 134, SIGABRT). Assert the saved logs:

```
python3 lab/frontier/libheif2shell/real/neighbour/check_groom.py lab/frontier/libheif2shell/real/neighbour/evidence/groom-gdb.out
```

Expect PASS with `A=0x555555793490 B=0x55555579b4b0 (B-A=0x8020)` and
`plane2=0x5555558ac490`; `groom-{plain,gdb}.out` are committed. This is a
harness-groomed rung-4 negative — deliberate same-size grooming did not place
a live object adjacent — not file-derived placement, pointer control, marker
or rung 5. W164/W166 still have no witness verdict.

## 2026-11-23 16:1xZ — kicad2shell admission replay and route

Commit `20d4d70` stages a direct-call Altium `ParseLibHeader` harness for
CVE-2026-126970 / GHSA-4qjr-2gjm-9gc6 (High 7.8, CWE-787, Unreviewed;
ZDI-CAN-33213). Pinned parent/fixed `sch_io_altium.cpp` slices at lines
5883-5923 / 5883-5926 are re-extracted and checked by `harness/run.sh`
against four digests in `lab/frontier/kicad2shell/PINS.sha256`; upstream bytes
appear only between `#line` markers and all wxString/parser/scale/driver code
is lab stub code. For `ind <= 0` from a hostile `SIZE` suffix the resize guard
is vacuous and `aFontSizes[ind - 1] = scaled` writes before the vector heap
buffer. No real KiCad build, SCHLIB file, consumer or wire; rung 5 UNKNOWN.

```
T=$(mktemp -d /tmp/docs-kicad2shell-replay.XXXXXX)
git archive 20d4d70 lab/frontier/kicad2shell reports/frontier-kicad2shell.md | tar -x -C "$T"
cd "$T/lab/frontier/kicad2shell" && sha256sum -c PINS.sha256
cd harness && ./run.sh && ./check.sh
```

At 16:14Z the operator observed 70 archived files, 4/4 pins OK, 8 binaries
rebuilt, `PASS=52 FAIL=0` and trace
`dd64c549fa2ddc57559f0aa66a043ab6e64e20d5f8799da5181ca6678d22f9a6` exact.
Admission under standing #6 as the 117th route added the charter, hy4-flash
route, both wake resolver entries and three full-flag-sync units at pin
`0d686bb…` (`written 3, removed 0`), then a pinned full-flag doctor rc 0
GREEN, `check-omp-only.py` GREEN 117 and window 122 adopted with no duplicate.
The grade is unchanged direct-call rungs 1-4; this is author-harness replay,
not witness acceptance. Brief: `reports/frontier-kicad2shell.md`; status:
`reports/kicad2shell-status.md`.

### 18:18Z — kicad2shell W174 real compound-file stream and fixed release

Three commits (`455d92e`, `562be97`, `36d3e62`) add a file-delivery lane and
map the fixed release; they do not change the row grade or the pin hashes.
From `lab/frontier/kicad2shell/realcfb`, `sh run.sh` regenerates four v3
(512-byte sector) MS-CFB/OLE2 fixtures, verifies them with `olefile` 0.46
(`ALL_FIXTURES_OK`), checks 5/5 realparser and 4/4 base pins, then builds eight
binaries (g++/clang++ × vuln/fixed × asan/plain) from the unchanged upstream
slices. A lab C++ driver walks header → DIFAT → FAT → directory → miniFAT →
mini stream and passes the `FileHeader` bytes to the verbatim parser; the CFB
walk and fixtures are lab code, not KiCad's own reader or a vendor `.SchLib`.
Replay from a clean archive:

```
T=$(mktemp -d /tmp/docs-kicad-realcfb.XXXXXX)
git archive 455d92e lab/frontier/kicad2shell reports/frontier-kicad2shell.md | tar -x -C "$T"
cd "$T/lab/frontier/kicad2shell/realcfb" && sh check.sh
```

Expect `PASS=38 FAIL=0` and trace hash
`d46a353639e2d48effa117f7dc3735d48923f094222f1e04a620260f8eafc53c`; this wake
observed that exact result from the clean archive in 20 s, with
`real-reader: bytes=107 props=3 parse_error=0`, `real-key: SIZEZ=84215045`, gcc
and clang ASan `WRITE of size 4` four bytes before the 4-byte region at pinned
`sch_io_altium.cpp.vuln:5919` (allocation via `resize` at `:5915`), plain glibc
`double free or corruption (out)`, and all fixed runs `rc=0 size=1 first=72
GUARD7=11111111` with clean ASan. `attackneg` (SEGV) and `attackfar` (8 bytes
before the region) are preserved boundary cases; fixture/reader defects found
and corrected are in `realcfb/PROVENANCE-realcfb.md`.

The fixed-release mapping is read-only provisioning, not a harness step: from
GitLab's `kicad/code/kicad` commits API the backport `4fdd1270…` is in
`10.0.7-rc1`, `10.0.7` and `10.0.8`, absent from `10.0.6` and the `9.0` branch;
raw-file reads show the `if( ind < 1 ) continue;` guard at 10.0.7 line 5505 and
its absence at 10.0.6 line 5498. The empty `/refs?type=tag` result is a
preserved negative, not ancestry evidence. First stable fixed release: KiCad
10.0.7; no build of that release was exercised, so the grade is unchanged.
Evidence: `lab/frontier/kicad2shell/FIXED-RELEASE.md`.

## 2026-11-23 16:3x–17:0xZ — six limb records across five admitted lanes

All six edges leave grades, mind counts and windows unchanged. Raw outputs
are gitignored where noted; tracked transcripts and reports carry the observed
bytes. No new route or witness verdict was created by these commits.

- **Modauthoidc W14 long token, W15 system stack, W170 verdict**
  (`67a7857`/`2ebb69b`/`4f69e2c`/`158cb11`,
  `reports/modauthoidc2shell-status.md`). From
  `lab/frontier/modauthoidc2shell/realobj`, `bash probe-long-token.sh` builds
  three plain (no `-fsanitize`, no libasan in `ldd`) drivers and one ASan
  comparison from verbatim pinned `state.c.4301b536` slices; `2ebb69b`
  regenerates the pinned slices with `sha256sum -c SHA256SUMS`. A value-less
  token faults at pinned `:219`: 5/5 at lengths 32000/48000, 3/5 at 65000 and
  4/5 at 100000 in the clean-archive replay (`results-clean-archive.txt`,
  `pin-hashes-clean-archive.txt`) — layout-dependent, not a fixed rate.
  W15: `cd lab/frontier/modauthoidc2shell/full && bash probe-sys-native.sh &&
  bash probe-sys-first.sh`, system apxs / Ubuntu httpd 2.4.58 / system APR,
  no libasan, loopback 18091; bare 7800-byte cookie 0/48 HTTP 302 with 44
  child SIGSEGVs over four fresh starts, controls 16/16 302 with zero faults,
  5/6 first-request faults on fresh starts (1/6 clean). No native faulting PC.
  W170 replayed W6/W8-W11/W13/W14 from a full `/tmp` copy at HEAD `10fdd31`
  with pinned `state.c` `ceedb687…5aa` and module `00899061…5654` verified,
  ESTABLISHED at those labeled scopes, no counterexample, NOT rung 5; W12 and
  W15 stay unwitnessed.
- **Vrpn W20 TYPE return map** (`50a7f23`, `reports/vrpn2shell.md`). Reuse the
  stock vulnerable binary SHA `bfe63334…bae2`; from the repo root run
  `BIN=lab/frontier/vrpn2shell/build-opt-07.36/server_src/vrpn_server \
  MSGTYPE=-2 LINE_PRE=4482 LINE_POST=4488 VAR=type_name \
  bash lab/frontier/vrpn2shell/probe-opt-frame-wide.sh <out> <port> 4` for the
  harmless frame map, then `BIN=... MSGTYPE=-2 bash
  lab/frontier/vrpn2shell/probe-func-dos.sh <out> <port> <index>` on fresh
  loopback ports. Expect live returns at +136/+200/+312 and DEAD indices
  136-141/200-205/312-317 (exit 132 at 313 with UNKNOWN cause), ALIVE
  142/143/206/207/318/319 and fixed/short controls. Author-only, grade
  unchanged; no chosen byte, surviving control flow or command.
- **Thrift W151 scheduling blocker** (`10fdd31`,
  `reports/thrift2shell-status.md`). Report-only: at 16:40Z no witness DM had
  landed since #2506, `m2shell-wake@witness.service` had failed at 16:36Z in
  the person-owned engine-cap saturation (recheck ~18:40Z), and the witness
  wall was stamped 15:33Z. No verdict, decline or counterexample; W145/W146
  remain UNVERIFIED and the grade is unchanged.
- **Libfontenc W155 real library and live Xvfb** (`55807b3`/`1f2cf18`/
  `07d4fd8`, `lab/frontier/libfontenc2shell/PROVENANCE.md` § "W155
  extension"). From `lab/frontier/libfontenc2shell/realpath`, `sh run.sh`
  builds the exported-`FontEncFind()` driver against plain and ASan shared
  libraries at `7418fa7`, `5920c6e`, 1.1.9 and 1.1.10 (build output gitignored;
  transcripts in `evidence/`); `xlive/run-live.sh` starts a loopback-only Xvfb
  with the pinned ASan library preloaded and a Type1 font whose XLFD registry
  is `crafted-1`. Expect `WRITE of size 2` at `encparse.c:495`, 508 bytes past
  a 131072-byte region, through `OpenFont` → `libXfont2.so.2` → `FontEncFind`
  on 1.1.9/`7418fa7` with the crafted `.enc`; 1.1.10/`5920c6e` and safe input
  are clean. Plain Xvfb survives and `xdpyinfo` answers — no production
  crash; the default glibc allocation is an mmap chunk with the write inside
  usable slack. Rung 3 in the live ASan process, rung 4 only at the earlier
  local chosen-store scope, rung 5 UNKNOWN, no witness verdict.
  **W156 clean rebuild** (`fb9e7b8`/`3730256`): from a fresh tree,
  `git archive fb9e7b8 lab/frontier/libfontenc2shell | tar -x -C /tmp/w156-clean`
  and `cd /tmp/w156-clean/lab/frontier/libfontenc2shell/realpath && sh ./rebuild.sh`.
  The committed script requires a read-only provisioning clone at `$LF2S_SRC`
  (default `/tmp/libfontenc-src`) with the four pinned revisions and
  `/usr/share/fonts/X11/Type1/NimbusMonoPS-Regular.pfb` (sha256
  `49d0a528…005dc1`), refuses to overwrite build directories, and runs both
  matrices. At `fb9e7b8` all eight libraries rebuilt in 37 s with 16/16
  public-API and 6/6 live-Xvfb lines matching W155; the fresh ASan log again
  shows `WRITE of size 2` at `../src/encparse.c:495`, 508 bytes past the
  131072-byte region, with 1.1.9 vulnerable and fixed/1.1.10/safe clean.
- **Openexr W164 deep-tiled path** (`0b61b94`,
  `reports/openexr2shell-file-level.md` § W164). From `lab/openexr2shell-real`,
  build the gitignored trees with `./harness/build.sh build-vuln-asan
  src/openexr-3.5.2 bin-vuln-asan asan` (and fixed/plain as in the 14:1xZ
  recipe), generate `cases/baseline_tiled.exr` with
  `cases/gen_baseline_tiled.cpp`, then
  `python3 cases/make_poc_tiled.py cases/baseline_tiled.exr cases/poc_tiled.exr 1024 64`.
  Expect a 581-byte baseline (sha256 `6a7a76a6…f49e`) and a 728-byte PoC
  (sha256 `aa9dba1f…a41ccc`); vulnerable ASan reports
  `memcpy-param-overlap` with two 4096-byte ranges at pinned
  `internal_zstd.c:472` through `exr_undo_zstd_v1` → `exr_decoding_run` →
  `tiled_harness.c:59`, fixed rejects `EXR_ERR_CORRUPT_CHUNK` (rv 23), and the
  guarded allocator measures 4032 bytes changed in 3/3 runs with baseline 0.
  The first overwritten byte differs from the scanline path — another
  allocator-derived negative. OIIO and aarch64 remain untested; grade and
  witness status unchanged.
- **Munt W169 advisory identity** (`0e94eef`/`dc9a263`,
  `reports/frontier-munt2shell.md` §10). The cve.org and OSV JSON records are
  committed under `lab/frontier/munt2shell/evidence/` (sha256 `63498b55…909f1`
  and `a77bc69f…097a`), mapping issue #149 to CVE-2026-121941 /
  GHSA-qw3h-2hqv-29vq, CWE-122, CVSS 4.0 8.5 HIGH vector LOCAL. Both hackmd
  "exploit"-tagged references were HTTP 404/403 at 16:58Z, so no PoC bytes
  were obtained. Advisory claims only; grade unchanged.

## 2026-11-23 17:3x–17:5xZ — eleven limb records across seven admitted lanes

All eleven edges change reports, provenance or replay notes, not grades, mind
counts or windows. The analytic limbs are source/prose checks with no harness
run; the probe limbs name their raw outputs below. No new witness verdict is
claimed.

- **Jq W167 general append bound** (`71a6568`, `reports/jq2shell-status.md`
  § "general append bound"). Source check only, no rebuild: pinned
  `jv.c.vuln:1187-1192` allocates `allocsz = (2*(T mod 2^32)) mod 2^32` and
  copies `currlen` then `len` bytes; an undersized destination needs
  `T = currlen + len >= 2^31`, so `max(currlen, len) >= 2^30` (1 GiB) and the
  first `memcpy` faults before returning. Both measured geometries
  (`2^31-2 + 2`, `2^30 + 2^30`) yield `S = 2^31`, `allocsz = 0` clamped to 32.
  No PoC, no guard change, no memory envelope measured.
- **Libheif W171 interposed live victim** (`303ed66`,
  `reports/libheif2shell-status.md` § W171). From
  `lab/frontier/libheif2shell/real`, `reencode_interpose.cc` allocates A and a
  live adjacent victim B (B-A=0x8020) and frees A inside an interposed
  `calloc` at the second 32783-byte request. On pinned plain v1.23.6 expect
  `CALLOC32783 count=2 ... == A`, encode rc 0, and B's
  `fn = 0x4040404040404040` / `tag[0..7] = 40*8` for `controlled-size.heif`
  (sha256 `062301df…bc7550`); the default driver aborts rc 134, the
  harness-retained run exits rc 0 with `POST fn=0x4040…` intact.
  `python3 real/neighbour/check_interpose.py EVIDENCE_DIR` PASS asserts
  adjacency, exact reuse, bytes, rc 0 and retained clean exit. The patterned
  sequence regenerates byte-exact from `make_one_row_sequence.py` (sha256
  `e028c5af…a3b67`). Uniform file bytes and a harness lifetime choice; no
  valid pointer, fixed-pin W171 variant or witness verdict.
- **Psqlodbc W165 CWE-457 negative** (`c69db6b`,
  `reports/psqlodbc2shell-status.md`). Throwaway gitignored scripts under
  `lab/frontier/psqlodbc2shell/src/repo/build/w165-*` drive the pinned ASan
  vulnerable and fixed `.so` through unixODBC against a private loopback
  PostgreSQL 16.4 on 127.0.0.1:59436. Seven escape forms x two tags: five give
  `DIAG ... msg=param not found` on both, LOCATE fails its arity on both,
  extra-arg CONCAT emits `SELECT concat(1::text, 2::text)` on both; zero ASan
  READ/WRITE in either tag, and same-connection shaping does not move the
  result. Raw: `build/evidence/w165-cwe457-*.out` and
  `w165-sweep-{vuln,fixed}.out`.
- **Openexr W165 provenance and OIIO blocker** (`7af2113`, `c10bcdf`,
  `reports/openexr2shell-status.md`). Advisory version claims checked via the
  GitHub contents API on `src/lib/OpenEXRCore/internal_zstd.c`: 3.5.1/3.5.2
  blob `78b27abe…` (51602 bytes, same as the vulnerable pin), 3.5.0 blob
  `670b92a7…` (50484), 3.5.3/main blob `393ffd9c…` (54887), 3.4.2 no path.
  The OIIO advisory tag was fetched as `oiiolab/oiio.tar.gz` (sha256
  `1c1283e8…ff4d2`); configure succeeded against the pinned ASan OpenEXR
  prefix with the recorded shims, but `cmake --build oiiolab/build-oiio-asan -j8`
  reached step 3/145 in 600 s and was interrupted; no consumer run. An
  unmodified `exrcheck` without `-c` on the PoC also timed out at 60 s with only
  `EXR_ERR_INVALID_SAMPLE_DATA` captured — UNKNOWN, not a pass.
- **Libvips W9 app-supplied buffer** (`c8550f8`, `3fbe3e6`,
  `reports/frontier-libvips2shell.md` §13). `real/external.c` reserves an 8.6 GB
  anonymous `PROT_NONE MAP_NORESERVE` mapping, makes a 64 KiB victim and 64
  pages writable, and calls the public `vips_image_new_from_memory()`.
  `bash real/run-external.sh` expects `IMAGE_OK ...`,
  `PAINT_PREPARE=0 bpl=-7296`, `PAINT_ADDR1=data-7296`, `PAINT_DONE`, and
  `VICTIM_POST off=58272 byte0=5a ... after_end=5a` on the vulnerable plain
  tree, `image: dimension overflow` on fixed, 12/12 PASS rc 0. From a clean
  `git archive HEAD` at `c8550f8` with gitignored source/build trees symlinked
  in, external 12/12, consumer 21/21 and neighbour 14/14 all returned rc 0.
- **Munt W170 write alphabet** (`4f8d4d7`, `9e7f58d`, `53038d8`,
  `reports/frontier-munt2shell.md` §11). From `lab/frontier/munt2shell/real`,
  `./alphabet_probe.sh` sends one 40001-byte incomplete SysEx with one varied
  byte. Expected: all-`0x6a` writes 7233 tail bytes with gcc ASan `WRITE of
  size 40001` at `MidiStreamParser.cpp:250` and pinned-fixed rc 0; `0x7f` at
  32768 is the first tail byte; `0x80`/`0x85` (or `0x80` at 32769) produce no
  allocation or copy; `0xf7` dispatches from the caller buffer without a copy;
  `0xf8` ends the copy inside 32768 bytes. Interpretation in `real/ALPHABET.md`;
  raw in `real/evidence/alphabet-*`. Clean-archive replay at `9e7f58d`
  regenerated both trees and reproduced all 12 rc cases with seven
  sha256-identical plain `.out` files.
- **Libgphoto2 W163 virtual-port sweep** (`43d3e59`,
  `lab/frontier/libgphoto2shell/PROVENANCE.md` § "Counterexample hunt"). Same
  real ASan 2.5.34 build on the lab-patched vusb port; raw
  `evidence/real-lib-count-*.out` and `real-lib-reply-*.out`. Expect `n=1021`
  rc 0 with no ASan, `n=1022..1053` `WRITE of size 16384` at real
  `jl2005c.c:152`, 16896 at 1054, 31744 at 2000 and 1048576 at 65535. With
  `M2SHELL_JL2005_VUSB=s1` the `:152` store disappears and default ASan
  reports `stack-buffer-overflow READ of size 16848` at `:154` (count 1022)
  or `1049040` (65535). W164 (`ff6cb85`) then confirmed the real-build heap
  destination with run-time `halt_on_error=0` (recipe in the 18:1xZ section
  below); it is no longer UNTESTED.

## 2026-11-23 18:1xZ — six limb records after 0679d92

Six report-only edges add one witness verdict, one native faulting PC, one
plain-build crash, one real-property-parser lane, one real-build heap report
and one loopback wire lane. No grade or mind-count change; raw evidence is
tracked under each target's `evidence/` and gitignored build/source trees are
regenerated by the named scripts.

- **Libgphoto2 W164 real-build heap destination** (`ff6cb85`,
  `lab/frontier/libgphoto2shell/REAL-BUILD.md` § "Heap destination on the real
  build (W164)"). No rebuild: reuse the W162 ASan 2.5.34 build and vusb run env
  from the 16:2xZ recipe above, with
  `M2SHELL_JL2005_COUNT=1022 ASAN_OPTIONS=detect_leaks=0:halt_on_error=0`.
  Expect `rc=0` and three libasan interceptor reports in
  `evidence/real-lib-recover-1022.out`: `:152` stack `WRITE of size 16384`,
  `:154` stack `READ of size 16848`, and `heap-buffer-overflow WRITE of size
  16848` 0 bytes after a 16448-byte region allocated in `camera_init` at
  `jl2005c/library.c:477`. Count 100 is clean (`...-100.out`); applying
  `pins/fix-6a3393d.patch`, rebuilding `camlibs/jl2005c.la` and rerunning 1022
  gives only the normal replies with no ASan (`...-fixed-1022.out`); reversing
  the patch, restoring vulnerable hash `0ccb1dac24a837bc…` and rerunning
  reproduces all three (`...-restore-1022.out`). At 65535 the mode observes the
  1048576/1049040-byte reports then SEGVs inside `__sanitizer_internal_memmove`
  (`...-65535.out`), so that case is not recoverable. No wire path or pointer.
- **Kicad real-property-parser reachability** (`7ad20c7`, `457afbc`,
  `lab/frontier/kicad2shell/realparser/PROVENANCE-realparser.md`). From
  `lab/frontier/kicad2shell/realparser`, `sh run.sh` builds eight binaries from
  the verbatim upstream `ALTIUM_BINARY_PARSER` class, both constructors and the
  whole `ReadProperties()` body plus the pinned `ParseLibHeader` slices;
  `sh check.sh` runs 32 invocations and 36 assertions. Expect `PASS=36 FAIL=0`
  twice, trace `b228ec002755ffbf9e54ddcf5a4a9952a425efe82ec3915a038fe29ef93ff4ee`.
  The real parser preserves the hostile key (`real-key: SIZEZ=84215045`,
  `parse_error=0`); the pinned parent then gives gcc/clang ASan `WRITE of size
  4` four bytes before the 4-byte region at `:5919`, plain glibc
  `double free or corruption (out)`; all fixed runs `rc=0 size=1 first=72
  GUARD7=11111111`. Clean archive `git archive 7ad20c7 lab/frontier/kicad2shell`
  reproduces it with 4/4 base and 5/5 realparser pins; `REPLAY.md` records both.
- **Kicad W174 real compound-file stream** (`455d92e`, `562be97`,
  `lab/frontier/kicad2shell/realcfb/PROVENANCE-realcfb.md`). From
  `lab/frontier/kicad2shell/realcfb`, `sh check.sh` builds eight binaries from
  the same verbatim pins, walks four `olefile`-verified CFB containers in a lab
  C++ reader and expects `PASS=38 FAIL=0` with trace
  `d46a353639e2d48effa117f7dc3735d48923f094222f1e04a620260f8eafc53c` in-tree
  and from clean `git archive 455d92e`; ASan `WRITE of size 4` at pinned `:5919`,
  plain glibc abort, fixed runs clean. The first stable fixed release is KiCad
  10.0.7 per `FIXED-RELEASE.md` (source reads only, no build). Full recipe above.
- **Modauthoidc W16 native faulting PC** (`3f78229`,
  `lab/frontier/modauthoidc2shell/full/probe-sys-gdb.sh`).
  `cd lab/frontier/modauthoidc2shell/full && bash probe-sys-gdb.sh` attaches gdb
  only to observe on 127.0.0.1:18091, ASLR on, no shim/`LD_PRELOAD`. A bare
  `Cookie: mod_auth_openidc_state_<7800 a>` on each fresh start stops in 4/4
  vulnerable starts at pinned `state.c:219`, `*cookie = '\0'`, `movb
  $0x0,(%rax)`, stack `ap_run_check_user_id` → `oidc_check_user_id` →
  `handle/request.c:132` → `state.c:244` → `:219`; well-formed and fixed-tag
  controls are 6/6 HTTP 302 with no catch. Raw transcripts and the read-only
  scope: `full/evidence/sys-gdb/README.md`. The byte is always NUL and the stop
  address is in read-only pages or an unmapped gap past a writable/shm mapping.
- **Libfontenc W172 witness verdict and plain crash** (`dac8d7a`,
  `lab/frontier/libfontenc2shell/realpath/xlive/run-plain-crash.sh`). The #2867
  clean-archive verdict at `6ee557d` replayed the direct-call and live ASan
  scopes (5/5 pins, `PASS=50 FAIL=0`, exact trace, eight rebuilt libraries,
  six live cases). The new uninstrumented matrix is
  `sh realpath/xlive/run-plain-crash.sh`; expect
  `realpath/evidence/plain-crash.txt`: `SIZE 256 258` and 512 survive plain
  (client_rc=0, xdpyinfo_rc=0, server_alive=YES), while `SIZE 256 1024` faults
  3/3 (client_rc=1, xdpyinfo_rc=1, server_alive=NO); fixed `5920c6e` and 1.1.10
  survive at row 1024 and 1.1.9 crashes. `row-sweep.txt` holds the public-API
  sweep; ASan-silent rows 512/16384 are not passes: a gdb breakpoint at `:495`
  and `__asan_describe_address(*enc + index)` report `wild memory access
  suspected`, no live object or pointer (`gdb-asan-destination.txt`). The
  row-1024 crash was unwitnessed when W172 recorded it; witness #2914
  (W177, 2026-11-23) later replayed it from a clean `git archive HEAD` at
  `3f44109` and returned ESTABLISHED at the labeled availability-only scope
  (nine matrix lines, faulting store `mov %dx,(%rax)` at `encparse.c:495`). See
  the 2026-11-23 W177 section below; the failed `LD_PRELOAD` setup there is a
  preserved negative, not a result.
- **Libheif W172 loopback wire lane** (`c34f357`, `lab/frontier/libheif2shell/real/run_wire.sh`).
  Requires the three pinned W161 build trees under `/tmp` (no new libheif
  build). `bash real/run_wire.sh /tmp/libheif-wire-replay` recompiles the two
  synthetic consumers, replays six socket cases and runs both checkers. Expect
  `check_wire.py` PASS: the 6004-byte `controlled-size.heif` arrives over the
  socket and gives ASan `WRITE of size 64` at `pixelimage.cc:644` 0 bytes after
  a 32783-byte region; the 4262-byte same-size safe input is clean; fixed
  `9ec655f` rejects with the mixed-size guard message (rc 2); plain aborts with
  `free(): corrupted unsorted chunks`. `check_wire_interpose.py` PASS: with the
  W171 interposer and frame 1 retained, the live harness victim keeps
  `fn=0x4040…`/`0xa8a8…` and `tag[0..7]` with the process returning rc 0. This
  is a harness consumer, uniform file bytes and harness-chosen retention; no
  marker or command; witness replay request #2897 queued, no verdict yet.

## 2026-11-23 18:1xZ — ndpi2shell admission replay and route

Commit `6510950` stages a direct-call `ndpi_json_string_escape()` harness for
CVE-2026-86098 / GHSA-c8vx-3h2j-4f8m (High 7.4, CWE-787, Unreviewed). Verbatim
pinned `src/lib/ndpi_serializer.c` bytes at `94e82c1^` and `94e82c1` are sliced
under `#line` by `harness/run.sh` and checked against four digests in
`lab/frontier/ndpi2shell/PINS.sha256`. The once-per-source-byte guard
`j < dst_max_len` permits multi-byte stores and an unchecked closing quote and
NUL; no nDPI build, serializer struct, packet or wire is present **at this
W161 staging point**. W162 later added a full pinned ASan library build and
real-caller probes; see the 2026-11-23 W162 section below.

```
T=$(mktemp -d /tmp/operator-ndpi-replay.XXXXXX)
git archive 6510950 reports/frontier-ndpi2shell.md lab/frontier/ndpi2shell | tar -x -C "$T"
cd "$T/lab/frontier/ndpi2shell" && sha256sum -c PINS.sha256
cd harness && ./run.sh && ./check.sh
```

At 18:18Z the operator observed 54 archived files, 4/4 pins OK, 8 binaries
rebuilt, `PASS=172 FAIL=0` and trace
`16060f55dfe944bf5e481a43e76034f6cd3d7acc159d561beaa067c8c97f7b5b` exact.
Admission under standing #6 as the 118th route added the charter, hy4-flash
route, both wake resolver entries and three full-flag-sync units at pin
`0d686bb…` (`written 3, removed 0`), then daemon-reload, path enabled/active,
a pinned full-flag doctor rc 0 GREEN and `check-omp-only.py` GREEN 118. The
grade is unchanged direct-call rungs 1-4, unwitnessed, rung 5 UNKNOWN. Brief:
`reports/frontier-ndpi2shell.md`; status: `reports/ndpi2shell-status.md`.

## 2026-11-23 18:3xZ — sdlmixer2shell admission replay and route

Commit `7e7f1d6` stages a direct-call SDL_mixer `FetchXLaw()` harness for
CVE-2026-122328 / GHSA-7qqc-5rvj-wqqw (High CVSS4 8.5, CWE-121, Unreviewed).
Verbatim pinned vulnerable `release-3.2.4` and fixed `df966f6`
`src/decoder_wav.c` lines 750-762 are sliced under `#line` by
`harness/run.sh` and verified against four digests in `PINS.sha256`. The
doubled 4-byte stride writes past the caller's 1024-byte stack buffer; no SDL
build, real WAV, decoder dispatch or wire is present **at this W173 staging
point**. W179 later added a real-SDL-caller lane; see the 2026-11-23 W179
section below.

```
T=$(mktemp -d /tmp/operator-sdlmixer-replay.XXXXXX)
git archive 7e7f1d6 reports/frontier-sdlmixer2shell.md lab/frontier/sdlmixer2shell | tar -x -C "$T"
cd "$T/lab/frontier/sdlmixer2shell/harness" && ./run.sh && ./check.sh
```

At 18:32Z the operator observed 65 archived files, 4/4 pins OK, 12 binaries
rebuilt, `PASS=134 FAIL=0` and trace
`f81697d9247807c1bc254ed1ce51a9d966ec807b6256713177180aa5f44f98e1` exact.
Admission under standing #6 as the 119th route added the charter, hy4-flash
route, both wake resolver entries and three full-flag-sync units at pin
`0d686bb…` (`written 3, removed 0`), then daemon-reload, path enabled/active,
a pinned full-flag doctor rc 0 GREEN and `check-omp-only.py` GREEN 119. The
registered two-pane window 123 was adopted after both panes were verified live;
no duplicate was created. The grade statement in this admission record is
historical: witness #2942 later ESTABLISHED the direct-call lab scope at rungs
1-4 only, explicitly not rung 5; W179's real-caller lane is author-only. See
the 2026-11-23 W179 section below. Brief:
`reports/frontier-sdlmixer2shell.md`;
status: `reports/sdlmixer2shell-status.md`.

## 2026-11-23 W175–W179 — folds after a8b9c91

These sections cover commits `a37acbf`..`a8b9c91`. Witness-ESTABLISHED verdicts
are named with their tape numbers; author-only probes and operator clean-archive
replays are explicitly not witness acceptance. No grade changed.

### Vrpn W21 (`d79c99a`, `e41b2da`; author-only)

From the repo root with the pinned plain `-O0` server built by `run.sh`, map the
outer-frame landing and canary frame:

```
bash lab/frontier/vrpn2shell/probe-w21-large.sh /tmp/w21-large 13921 512
bash lab/frontier/vrpn2shell/probe-w21-smash.sh /tmp/w21-smash 13922 512
python3 lab/frontier/vrpn2shell/wire_inject.py --index 16384 --port 13923
```

Expect index 512 DEAD rc 134 `*** stack smashing detected ***`, a PRE→POST
outer-frame saved rbp change `0x00007fffffffdbc0` → `0x00007fffffffdb00` at
`vrpn_Connection.C:4554` and `__stack_chk_fail` from `getOneTCPMessage:4246`;
fine 512-517 DEAD / 518-519 ALIVE / 520 DEAD, TYPE 512 rc 134; fixed 512, short
4 and `-O2` 256/384/512 ALIVE. Indices 16384/32768/65536 exit 139 with the
cause **UNKNOWN** — `e41b2da` corrected the W21 explanation and `b7ca158`
qualified the report's Limits section: 16384/32768/65536 exit 139 with no gdb
landing mapped, so 16384 may still be inside the mapped stack. No chosen byte,
command or rung 5; author-only.

### Libheif W176 (`d12d823`; author-only negatives)

Build `lab/frontier/libheif2shell/real/avif_lossless_probe.cc` with the exact
command in its header against the pinned plain Release tree
(`SRC=lab/frontier/libheif2shell/src/libheif-v1.23.6`,
`B=/tmp/libheif2shell-vuln-plain`), then `make` and `check`. Frame 1
(512x64 then 64x65, `lossless=1`) is refused with
`rc=8 sub=5002 ... Image size must match encoder init configuration size`;
`heif-enc -A -L -S` refuses too. JPEG constant 8x8 blocks round-trip
byte-exact but the SOF-patched OOB row is not independent
(`a0*8, a2*16, a4*16, a6*16, a8*8`; uniform `0x70`/`0xac`), so on those codecs
arbitrary-byte control stayed UNKNOWN (W178 closes it on another build below).
`bash real/run_wire.sh /tmp/w176-wire-replay` replays
six cases with both checkers PASS. Witnesses #2752/#2869/#2897 remain queued.

### Libheif W178 (`613de0b`; author-only byte-exact OOB row)

A separate pinned v1.23.6 build with `WITH_UNCOMPRESSED_CODEC=ON` (exact CMake
flags and the host-build stall negative in
`lab/frontier/libheif2shell/real/PROVENANCE-real.md`, W178 section) makes the
OOB row byte-exact. `real/uncompressed_mixed.cc` writes a 64x65 ISO/IEC
23001-17 sequence whose 64 chosen Y-row bytes are `11 22 33 44 55 66 77 88`
x8; raw samples decode byte-exact. That codec cannot itself carry the mixed
512x64/64x65 sizes (frame 1 decode fails `rc=2 sub=100 Requested data range
exceeds the sample data`, a preserved negative), so `real/reencode_chroma.cc`
with `SYNTH_FIRST=1 TW=512 TH=64` supplies one harness-created 512x64 frame to
size the x265 encoder before the file-derived frames.

With `/tmp/libheif2shell-unci` and `/tmp/w178-reencode-unci` built as in the
provenance, from the repo root:

```
SYNTH_FIRST=1 TW=512 TH=64 /tmp/w178-reencode-unci \
  lab/frontier/libheif2shell/real/neighbour/evidence/uncompressed/byte-exact.heif /tmp/w178-unci-out.heif
gdb -q -batch -x lab/frontier/libheif2shell/real/neighbour/gdb_uncompressed.cmd /tmp/w178-reencode-unci
python3 lab/frontier/libheif2shell/real/neighbour/check_uncompressed.py
```

Docs replay of the committed evidence at 21:4xZ: input SHA-256
`b585565b5ca9af5860880c2102ae124749f298a5a3319e08a24e57cb8ca3a249`,
`PASS=5 FAIL=0` (hash, dest offset 32768, 64-byte source row, landed bytes,
plain abort); gdb reads `OOB dest_off=32768` and the AFTER dump is
`0x8877665544332211` x8 at `plane+32768`; the plain run aborts rc 134
`double free or corruption (out)`. This is rung 4 with arbitrary 64-byte
file-derived control at the OOB row at that labeled build/codec scope,
superseding the earlier one-uniform-value ceiling. The first encoder-sizing
frame is harness-created, so this is not one uncompressed file driving the
mismatch; no pointer, marker, command, network consumer, ASan run on this
build, witness replay or rung 5.

### Libfontenc W177 (`c83d597`; witness #2914 ESTABLISHED)

From `lab/frontier/libfontenc2shell`, `sh realpath/xlive/run-plain-crash.sh`
regenerates `realpath/evidence/plain-crash.txt`. The witness worked from a
clean `git archive HEAD` at `3f44109` in `/tmp/w174-lfe`, rebuilt the four
out-plain libraries (built `encparse.c` hashes match `PINS.sha256` vuln
`79e2381b`, fixed `91c81398`) and used its own `xfon-load`: all nine matrix
lines matched (vuln 256/258/512 rc 0 + alive, vuln 1024 a/b/c rc 1 with
`xdpyinfo` rc 1 and `server_alive=NO`, fixed `5920c6e` and 1.1.10 rc 0 + alive,
1.1.9 rc 1 + abort), the data-line diff was empty, and the faulting instruction
is the chosen store `mov %dx,(%rax)` at `encparse.c:495` (signal 11). Its first
setup installed libs under `realpath/`, so `LD_PRELOAD` silently missed and
SYSTEM libfontenc crashed every variant including fixed; that setup was
diagnosed from the backtrace DSO and rebuilt at the correct BASE with
PRELOAD_OK — preserved as a negative. Verdict: ESTABLISHED at the labeled
availability-only scope; no pointer, command, wire or rung 5; `SIZE 256 258`
plain impact is still NOT demonstrated.

### Kicad W178 and clean-archive replay (`337c164`, `3d90217`; author/operator)

```
cd lab/frontier/kicad2shell/kicadreader
sh run.sh && sh check.sh
```

The wrapper compiles KiCad 10.0.6's verbatim `compoundfilereader.h` /
`utf.h` (pins `223e8b03…` / `d72da151…`) and calls real `EnumFiles`, `IsStream`
and `ReadFile` on the four `realcfb` `.SchLib` fixtures; expect
`kicad-cfb: ... stream=107`, `real-reader: bytes=107 props=3 parse_error=0`,
`real-key: SIZEZ=84215045`, ASan `WRITE of size 4` four bytes before the 4-byte
region at `sch_io_altium.cpp.vuln:5919` (resize at `:5915`), plain
`double free or corruption (out)`, `attackneg` SEGV and `attackfar` 8-byte
before-region write, with all fixed runs clean. `check.sh` runs 32 invocations
and 38 assertions; expect `PASS=38 FAIL=0` and trace
`fffe73410576403f33943253a207db3e8493229babdfb8f30f4544aebcfd6260`. Two
in-tree runs and a clean `git archive` at `337c164` (333 files) matched; the
fixtures are synthetic, there is no wxWidgets/KiCad build or eeschema and
chosen bytes land in the ASan redzone (plain: malloc metadata) — operator
replay, not a witness verdict.

### Thrift W152 (`25133a3`; author-only disposition)

No new experiment. The witness cap cleared with other-lane verdicts at 19:20Z
and a wall stamp of W175 19:23Z; the 19:27Z tape check found no DM to the role
since #2533 for W144 rungs 1-4 (earlier W149-W151 name #2506 for that verdict),
and the #2759 closure request for #2547/#2598 unanswered. Wall line 171 says
`No replay owed on the W146/W147/W148 lanes` and names neither in pending:
W146 replay declined, W145 unanswered/not queued. Both remain UNVERIFIED —
not refuted, not ESTABLISHED, not a counterexample; W151's cap explanation is
stale and the disposition/grade are unchanged.

### Munt W175/W176 (`a37acbf`, `144f371`; author-only source negatives)

No host was built or run. W175 enumerates the pinned `libmt32emu_2_8_3`
bulk-SysEx consumers: all large-SysEx paths call `playSysex()`/`playSysexNow()`
and bypass `parseStream()`; the only Linux `parseStream()` caller is the ALSA
sequencer at `alsadrv.cpp:1182` (5572-byte cap), and the public C API
`mt32emu_parse_stream` (`c_interface.cpp:760`) is an unclamped forward. W176
adds fetched third-party bytes in `lab/frontier/munt2shell/real/thirdparty/`
(DOSBox Staging `:781-786` and 86Box `:308-311` call `playSysex`;
DOSBox-X's vendored copy is already fixed at `:136`/`:253-254`; hashes
`e061f43f…`/`a9b4c625…`/`fe0fa4ca…`), with the hackmd PoC still HTTP 404.
This narrows but does not prove the third-party-host question; real-library
rungs 1-4 remain witness #2781, rung 5 UNKNOWN.

### Libgphoto2 W165 (`82c12a1`, `4c5dd7a`; witness #2892 rung 3 only)

Witness tape #2892 (2026-11-23) replayed the real 2.5.34 ASan build from a
clean `/tmp/w173-lgp` archive with pins and tarball/patch hashes matched:
three reports at count 1022 with `halt_on_error=0` (rc 0) — stack WRITE 16384
at real `:152`, stack READ 16848 and heap WRITE 16848 at real `:154`, 0 bytes
past the 16448-byte `camera_init` region; 100/1021 controls clean, fix
`4fdaf4b1…` suppresses, reversing restores, 65535 faults then SEGV. Verdict:
ESTABLISHED at **rung 3 at the real heap destination only**, NOT rung 4 impact;
rung 5 UNKNOWN. Harness #2763 also closed at 146/0 trace `e364f756…c6c98`.
The separate plain build aborts rc 134 with `*** stack smashing detected ***`
and gdb shows chosen `0x5a5a5a5a5a5a5a5a` in both canary and saved RIP of
`jl2005c_init` — chosen bytes at a control-flow slot, but the protector aborts
before `ret`; author-only, no witness retry, synthetic vusb.

### Ndpi W162 (`37fd092`, `52ea294`, `eaf6c25`, `44be53e`; author-only)

```
cd lab/frontier/ndpi2shell/realbuild && ./run.sh
```

`run.sh` provisions the pinned vulnerable tree from `94e82c1^` if absent,
verifies `ndpi_serializer.c` sha256 `4840fb41…9ad5`, links `driver.c` against
the real ASan `libndpi.a` and runs the direct/real/weakone modes; expect
ASan `WRITE of size 1` at `:107` from the three weak KEY callers
(`binary_boolean :2181`, `start_of_list_binary :2245`,
`start_of_block_binary :2328`) at klen≥128, with klen 16/64 clean and 145
VALUE cases producing zero ASan reports (`{"key":"\/"}` proves the escape ran).
The fixed tree (`0aa83a83…92fd`) gives rc 0 and zero ASan in
`fixed-{direct,real,weakkey}.out`; callers still ignore `-1` so `size_used`
can decrement — a separate correctness issue, not memory corruption observed
here. Fixed release is now KNOWN **6.0** (`git tag --contains` → 6.0 and
6.1-qubitowl, `git describe` → `6.0~14`; tag `1a529339…a3af`, 2026-08-28).
The loopback pcap reader control (`reader-longhost.*`) is rc 0 with zero ASan
and 560 `\/` escapes and never reaches the weak KEY callers; a full-tree grep
finds TLV-clone references only in the API declaration, the serializer
definitions and fuzz/unit tests, so a >128-byte key is not wire-reachable in
this tree. R5 remains UNKNOWN and unreachable via this primitive.

### Sdlmixer W179 (`307a2b6`, `a8b9c91`; witness #2942 direct-call only)

```
cd lab/frontier/sdlmixer2shell/harness/realcaller && ./run.sh && ./check.sh
```

`run.sh` verifies `PINS.sha256` and the inline SDL3 tarball hash
`0fc1d23e225e2a098976571bf5d62b6d81e0ae84ff3d82a35a3d19ab04d07e5c`
(the `a8b9c91` change removed the dependency on the local `deps/SDL3.sha256`),
then builds 12 binaries from verbatim pinned slices using real SDL IO and
`SDL_CreateAudioStream`/`SDL_PutAudioStreamData`. Expect ASan
`stack-buffer-overflow WRITE of size 4` at pinned `:759`, the `i=1` gdb probe
showing `buffer+1020..1027 = ff 7f 00 00 5a 5a 5a 5a`, fixed/safe/badfmt/pcm8
clean, clang++ plain and all nossp edge/ulaw rc 139 while g++ plain aborts
rc 134, and `PASS=96 FAIL=0` with trace
`934e83379c7b6d771269a96035a54480a9c5ab9dcaf5a169db6a6916ce2160c0`.
Witness #2942 is ESTABLISHED at the labeled direct-call lab scope, rungs 1-4
only, explicitly not rung 5; W179 itself is author-only and awaits replay.
No SDL_mixer build, full WAV dispatcher, decoder consumer, wire, pointer or
command follows; file-path reachability and RCE stay UNKNOWN.

## 2026-11-23 20:0xZ — cjose2shell W180 staged, clean archive replay

CVE-2026-53938 / GHSA-75r7-f5cv-g3wj (HIGH 8.2, CWE-122/787), cjose
`<=0.6.2.4` fixed `>=0.6.2.5` by `8c51d245`. Pinned v0.6.2.4 and a fixed
tree differing only by the security hunk; real library build, real
`cjose_jwe_import()` / `cjose_jwe_decrypt()`, real compact JWE, real OpenSSL
AES key wrap/unwrap.

```
T=$(mktemp -d /tmp/operator-cjose-replay.XXXXXX)
git archive 841b716 reports/frontier-cjose2shell.md lab/frontier/cjose2shell | tar -x -C "$T"
cd "$T/lab/frontier/cjose2shell" && sha256sum -c PINS.sha256
cd harness && ./bootstrap.sh > bootstrap.log 2>&1 && ./check.sh
```

`bootstrap.sh` rebuilds jansson and six cjose library variants offline from
the committed tarballs; no network. Observed from archive
`/tmp/operator-cjose-replay.iUe7Iq`: 73 files, 7/7 pins, 8 binaries rebuilt,
`PASS=223 FAIL=0`, trace
`455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7` exact
against the three in-tree runs. gcc+clang ASan: heap-buffer-overflow WRITE
of size 40/1016 into the 32-byte CEK; gdb chosen-byte probe and negatives in
`harness/evidence/gdb-chosen.out`. Window 124 adopted live, registry
125/125; grade direct-call rungs 1-4 only, unwitnessed, rung 5 UNKNOWN.
Brief: `reports/frontier-cjose2shell.md`; recipe and hashes:
`lab/frontier/cjose2shell/PROVENANCE.md`, `REPLAY.md`.

### 2026-11-23 20:0xZ — cjose2shell admitted as the 120th route

Operator admission under standing #6 repeated the staged replay from an
independent clean `git archive 841b716`: 73 files, 7/7 pins OK, 8 binaries
rebuilt offline by `bootstrap.sh`, `PASS=223 FAIL=0` and trace
`455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7`
byte-identical to the three in-tree runs. Charter written; hy4-flash route
119→120; both resolver entries (239→241) and the three wake units from the
exact full-flag sync at pin `0d686bb…` (`written 3, removed 0`); pinned
full-flag doctor rc 0 GREEN and `check-omp-only.py` GREEN with 120 roles.
Window 124 was already live with two panes and was adopted, not duplicated.
This confirms deterministic replay of the author's harness only; witness
replay remains owed. The grade stays direct-call rungs 1-4 against a real
cjose build, unwitnessed, with no consumer, wire, pointer target or command
and rung 5 UNKNOWN. Status: `reports/cjose2shell-status.md`.

## 2026-11-23 20:3x–20:4xZ — kicad witness/chosen value, cjose wire consumer, psqlodbc negative

### Kicad W179 (`7d99edf`): witness #2996 and file-controlled store bytes

The witness replayed W178 from a clean `git archive 3d90217`: 11/11 pins OK,
`sh kicadreader/check.sh` `PASS=38 FAIL=0` with trace
`fffe73410576403f33943253a207db3e8493229babdfb8f30f4544aebcfd6260` exact,
fresh g++ ASan `WRITE of size 4` four bytes before the region at pinned
`sch_io_altium.cpp.vuln:5919`, and clean fixed controls. Verdict:
**ESTABLISHED rungs 1-4 at the labeled synthetic-CFB / KiCad-own-compound-file-reader
scope, NOT rung 5**. Rung 5, a real KiCad build and end-to-end file reachability
stay UNKNOWN; the author report is not acceptance of any further claim.

The changed-value counterexample is replayable without new upstream pins:

```
T=$(mktemp -d /tmp/docs-kicad-choice.XXXXXX)
cp -a lab/frontier/kicad2shell/. "$T/"
cd "$T/kicadreader" && sh chosen-value.sh 84215045
```

`chosen-value.sh` builds a real CFB fixture through the committed
`realcfb/make_cfb.py:build`, verifies `SIZEZ=<value>` with `olefile`, breaks at
pinned `:5919` and runs both fixed builds. Docs replay at 20:56Z gave
`VALUE=84215045 GDB_RC=0 FIXED_RC=0 FIXED_ASAN_RC=0`,
`chosen-olefile=... key_ok=True PASS`, `IND=0 SCALED=0x24242424` and four
`24 24 24 24` bytes at `data()-4`; fixed plain printed
`rc=0 size=1 first=72 GUARD7=11111111`. The author also recorded
`SIZEZ=925327927` → `SCALED=0x80000000` with `00 00 00 80` at the same offset.
No pin, `check.sh` assertion or trace hash changed. Hashes, 404/401 negatives
and the source-bound `ALTIUM_COMPOUND_FILE` API comparison are in
`lab/frontier/kicad2shell/kicadreader/PROVENANCE-chosen-value.md`.

### Cjose W181 (`a6196ae`): loopback HTTP wire consumer

Prerequisite: the pinned library builds from `harness/bootstrap.sh` exist.
The lab consumer binds an ephemeral 127.0.0.1 port, takes a real compact JWE
in `Authorization: Bearer`, decodes the wrapped `encrypted_key` from the wire
and calls real `cjose_jwe_import()` / `cjose_jwe_decrypt()` in vulnerable,
fixed and ASan builds.

```
T=$(mktemp -d /tmp/docs-cjose-w1.XXXXXX)
cp -a lab/frontier/cjose2shell/. "$T/"
cd "$T/w1" && sh build.sh && bash run.sh
```

Run 28 cases (four binaries x seven scenarios). Docs replay at 20:56Z matched
the report's plain-vulnerable `SERVER_RC` pattern for valid/wrapped/N48/N56/
big/probe/undersized: `0/0/134/0/139/0/0`; ASan tampered cases returned 1,
the fixed binary returned 0 in every case. The N48 log has
`DECRYPT=0 ERRCODE=4 PLAIN_LEN=0 CEK_LEN_AFTER=48` and ASan
`WRITE of size 48` in `_cjose_jwe_decrypt_ek_aes_kw` at pinned
`src/vulnerable/src/jwe.c:595`. The author's 48/56/64/1024-byte sweep gives
`CEK_LEN_AFTER=40/48/56/1016`; the 56-byte outcome is not stable. Author
repeats and an independent witness saw both rc 0 and rc 139 (W182's
`w1/evidence/wrappedN56-variation-w182.log`: 2/12 plain and 1/12 trace rc 139;
witness: 10/10 plain rc 0 and 2/10 trace rc 139, with one crash in
`__strcmp_avx2` from `_cjose_jwe_calc_auth_tag:1098` via
`_cjose_jwe_decrypt_dat_aes_cbc:1400` and `enc=0x0`), so the earlier "clean
exit" wording was corrected by the author at `8326d8b`; the cause is measured
in W183 below. Whole-log hashes are not stable across replays
(ephemeral PORT, CEK pointer, ASan PID/addresses and locally generated token
IV differ); compare semantic lines. The 25-byte jansson neighbour at `cek+48`
and the source-only unbuilt mod_auth_openidc 2.4.15.1 pre-auth path are
author-reported in `reports/frontier-cjose2shell.md` and
`lab/frontier/cjose2shell/PROVENANCE.md`. The witness replayed both lanes from
a clean archive: rungs 1-4 ESTABLISHED at the labeled direct-call real-library
scope and rungs 1-3 plus byte-control mechanics ESTABLISHED at the labeled
synthetic 127.0.0.1 consumer scope, NOT rung 5. No deployed server,
credential, pointer target or command; pre-auth reachability in a real
deployment and RCE stay UNKNOWN.

### Cjose W183 (`a93cbcb`, `7798711`): 56-byte variation cause measured

The throwaway instrumented loopback server from W181/W182 (not committed) dumps
the 25-byte jansson object at `cek+48`. It is a `json_string_t` (type at +0,
refcount at +8, value pointer at +16, length at +24); with an identical
allocation ring it is either the 13-byte `enc` value or the 6-byte `alg` value.
In a 40-run batch all four rc 139 crashes had `json_object_get(hdr,"enc")`
returning that object, all 36 rc 0 survivors had it elsewhere; the chosen
`0x5a` replaces its type so `json_string_value()` returns NULL and the real
decrypt path faults in `__strcmp_avx2` via `_cjose_jwe_calc_auth_tag:1098`.
Chosen type/refcount bytes `02 00 00 00 01 00 00 00` removed that fault in all
60 runs, which then aborted in `munmap_chunk()` from the still-corrupt chunk
size at `cek+40..47` (`w1/evidence/wrappedN56-cause-w183.log`).

Pinning jansson's per-process hash seed before any cjose call with
`json_object_seed(N)` makes the outcome deterministic per seed
(`w1/evidence/wrappedN56-hashseed-w183.log`): seeds 19, 27 and 30 gave rc 139
in 6/6 runs each with `enc` adjacent, the other 37 tested seeds rc 0 with it
elsewhere; the roughly 8-20% unpinned crash rate is the fraction of random
seeds in the first class. Fixed IV and ASLR-off batches still vary. Why two
same-size strings swap identity stays UNKNOWN. No pointer or IP control;
grade and the rung 1-4 ceiling are unchanged.

### Psqlodbc W166 (`d8a4e1b`, report-only negative)

`reports/psqlodbc2shell-status.md` records gdb on the existing
`build/real-clang-o2-vuln` binary from `real/clang-o2-layout.sh`. With n=88 the
hardware watch on `param_pos+0x578` never fired and the slot kept
`0x555555567641`. With n=96, row 74/75 changed while row 87 stayed a live
stack pointer: the recursive token parser corrupts its own `nqb` object and
`QP_exit(qp, QP_IN_ESCAPE)` dereferences it before rows 76..87 can be written.
The fixed tag with n=96 rejected with `too many parameters in the escape
function call`. No source, build or harness change; raw gitignored logs are
`build/evidence/w166-*.out`. Negative for rung 5, author-only and unwitnessed;
grade stays rungs 1-4.

### Libfontenc W180 (`a636d12`): runtime X-protocol font-path injection

From `lab/frontier/libfontenc2shell`, `sh realpath/xlive/run-xset-fp.sh`
starts a loopback Xvfb with an unrelated font path, injects a writable temp
font directory with `xset +fp` / `xset fp rehash`, then writes the malicious
`SIZE 256 258` `crafted-evil.enc` after server start (launch 20:54:51.489Z,
attack write 20:54:54.576Z). Opening the matching Type1 font from another X
client gives ASan `WRITE of size 2` at `encparse.c:495`, 508 bytes past the
131072-byte region, through `FontEncFind` → `OpenFont`; the no-xset,
safe-after-xset and both fixed controls are clean. Matrix, timeline and raw
ASan logs: `realpath/evidence/xset-fp/`; exact commands and limits:
`lab/frontier/libfontenc2shell/PROVENANCE.md` W180 and
`reports/frontier-libfontenc2shell.md` §3.5. This demonstrates runtime
X-protocol injection into a running server from a writable directory without
a privileged font dir; OS-level unprivileged X-display access and server
privilege stay UNKNOWN. No grade change.

### ThorVG2Shell W181 (`lab/frontier/thorvg2shell`): jpgd duplicate-SOS write

`python3 poc/make_poc.py && python3 poc/make_large.py &&
python3 poc/make_marker.py && sh harness/build.sh && sh harness/run_matrix.sh`
rebuilds 11 binaries from pinned v1.1.1/v1.1.2 and runs 88 cases (per-case
transcripts in `harness/evidence/`). Crafted SOS `Ns=4` repeats the one
grayscale component; controls decode rc 0, fixed binaries reject crafted rc 6.
Allocator-instrumented gcc/clang ASan reports `WRITE of size 2` 0 bytes after
the 128-byte `m_pMCU_coefficients` region; pristine-source 2048x2048 crafted
frame faults at `tvgJpgd.cpp:733` (rc 139 plain). gdb with `marker_dup4.jpg`
shows chosen `58 00`/`68 00`/`78 00` at byte offsets 128/256/384. Full recipe,
pins and the bump-allocator caveat: `REPLAY.md`, `PROVENANCE.md`,
`PINS.sha256`; brief `reports/frontier-thorvg2shell.md`. Direct call only; no
wire, pointer control, command or witness.

### BusyBox2Shell W182 (`lab/frontier/busybox2shell`): TFTP blksize fallback

`sh lab/frontier/busybox2shell/run-all.sh` from the repo root replays five
legs against an ephemeral UDP socket bound to 127.0.0.1 only. The pinned
1.37.0 tarball, vulnerable/fixed `tftp.c`, one-line `fix.patch`, minimal
config and three built binaries are hashed in that directory's
`PINS.sha256`; expect ASan `WRITE of size 516` 0 bytes after the 68-byte
`rbuf` on the vulnerable build, clean OACK and default-blksize controls,
clean fixed build, and gdb bytes `4d 49 53 48 45 2d 4f 4f` ("MISHE-OO") at
`rbuf+68`. The 2026-11-23T22:36:59Z transcript is `evidence.log` SHA-256
`3e52a8627e6c435f5e20d1394a31085e8a837dbe2c3718003ea9bfcfecbff300`. Rung
1-4 on a real loopback wire path; no pointer/IP, command, ASLR measurement
or witness, so rung 5 stays UNKNOWN. Claim and mechanism:
`reports/frontier-busybox2shell.md`.

## 2026-11-23 21:4x–22:4xZ — limbs folded after `f64714e`

These recipes add scopes, not grades; admissions and witness verdicts are
named explicitly. All runs stay on loopback or in a local build.

- **KiCad W180 vendor file**: `cd lab/frontier/kicad2shell/vendor && sh check.sh`
  drives two same-length one-key patches of a real upstream QA Altium
  `.SchLib` through KiCad's own compound-file reader; expect 23 PASS / 0 FAIL
  twice, trace `42db33cb…`, plain rc 139 / ASan SEGV and rc 134 / ASan WRITE-4
  at `sch_io_altium.cpp:5919`, fixed clean. Clean `git archive de13eac` replay
  is exact (`REPLAY.md`); `kicadreader/chosen-value.sh` with `SizeZ=9/7/1`
  reads `0x40/0x32/0x07` at `data()-4`. No witness verdict, rung 5 UNKNOWN.
- **Cjose W184 real-consumer negative**: recipe and evidence in
  `lab/frontier/cjose2shell/w2/README.md` and `w2/evidence/` (127.0.0.1:18443).
  A real mod_auth_openidc 2.4.15.1 module passes a 56-byte encrypted_key to
  cjose, which rejects the non-OCT JWK at `jwe.c:577` before AES-KW; all three
  POSTs return HTTP 400 and the 40-byte control rejects at the same line. The
  client_secret OCT path needs a state cookie, so no unauthenticated POST
  reaches the CEK overflow.
- **Modauthoidc W17 non-ASan stack store**:
  `cd lab/frontier/modauthoidc2shell/full && bash probe-sys-store.sh` against
  the system httpd/APR module on 127.0.0.1:18091; all five padding lengths
  give 302, parent dispatches 5/5 and the released tag 0/5, gdb shows
  `0x3d`→`0x00` at token offsets 39/63. In-bounds on the header copy, always
  NUL, not pointer-bearing; author-only and unwitnessed.
- **SofiaSIP W14 deeper second-order writes**:
  `bash lab/sofiasip2shell/libbuild/live/run_deep_probe.sh` with
  `live_ws_timers_deep.c` / `timer_probe_deep.c`; `SIA_DEEP_EXTRA=60` admits 95
  `su_timer_set()` adds and 16 consecutive qwords at +520..+640 (15 OOB),
  crossing the 528-byte timer array, a 19-byte sub-alloc string and chunk
  headers, rc 134 `corrupted size vs. prev_size`; v1.13.17 short and both
  v1.13.18 controls are clean. Values are live heap pointers, not chosen
  bytes; no callable field, marker or command; author-only.
- **Libgphoto2 W167 local canary-mode marker**: apply
  `evidence/replay-vusb-local-modes.patch` over `live/vusb-jl2005.patch` and
  build `evidence/replay-two_stage_probe.c`; the vusb reply supplies the
  process canary at info+0x4028 and a chosen marker address at info+0x4038,
  the canary check passes and `jl2005c_init()` returns to
  `M2SHELL_IP_CONTROL_MARKER` with RC=0, gdb confirming saved RIP. Recorded in
  `evidence/real-plain-ip-control.out`; conditional on a device that knows the
  canary, author-only and unwitnessed. Witness replay ask tape #3081 at
  22:36Z has no verdict; #2892 remains scoped to rung 3.
- **Sdlmixer W180 real WAV file**: build/run recipe in
  `lab/frontier/sdlmixer2shell/harness/realwav/REALWAV.md`; a crafted on-disk
  A-law/mu-law WAV reaches `FetchXLaw` through real SDL_mixer 3.2.4 APIs with
  ASan WRITE-4 at `decoder_wav.c:759`. Witness #3000 established W179's
  real-caller scope at rungs 1-4, NOT rung 5; this WAV lane is author-only with
  replay request #3053. The LUT image makes every ordered A-law word
  non-canonical and every mu-law canonical pair's high word zero, so saved-RIP
  bytes are LUT words and arbitrary IP steering is closed negatively.
- **OpenEXR OIIO closure**: W173 resolved the OIIO claim as a static-source
  negative (flat EXR geometry and OIIO dispatch block the sink), superseding
  W165/W168's build-resume instruction; no consumer was linked or run. W177
  then measured the partial-overwrite survivability boundary negative below.
- **Munt W177 PoC availability**: reader-proxy fetches of both hackmd notes
  returned 404/403 and the author profile lists no notes; "Public PoC"
  metadata stays unsubstantiated and the contents UNKNOWN
  (`reports/frontier-munt2shell.md` §15). No harness command changed.
- **ThorVG and BusyBox**: `3db61ec` admitted thorvg2shell as the 121st route
  (unwitnessed, rung 5 UNKNOWN); its 88-case recipe is in the lane table
  above and `REPLAY.md`. Frontier W182 staged BusyBox2Shell at `0c3b4a1` with
  a clean-archive replay at `8c50300`; the five-leg wire recipe is above and
  in `reports/frontier-busybox2shell.md`. Neither has a witness verdict.
- **Vrpn W21 qualification**: `b7ca158` changed the report's Limits section so
  16384/32768/65536 are DEAD exit 139 with cause UNVERIFIED/UNKNOWN and no
  mapped gdb landing; 16384 may still be inside the mapped stack.

## 2026-11-24 00:19–00:25Z — kicad2shell W183 chosen bytes in a real process

Offline verification of the committed real-process evidence (no GUI, no
network, no new upstream bytes):

```
cd lab/frontier/kicad2shell/realprocess
sh chosen-byte-check.sh
```

Expect pins OK and `PASS=16 FAIL=0`, trace
`3b352f6ecf3cbdabf8987243460234e42626868df70dfee7a7de021ba427398a`. The check
verifies the two new fixture hashes, the exact predicted glibc chunk size in
each of five committed gdb transcripts, the SIGABRT signature and the empty
safe-control log. It does **not** re-run the GUI or re-prove the crash.

The transcripts came from native KiCad 8.0.8 under Xvfb via
`provisioned/gui-import.sh <tag> <absolute-SchLib> gdb` (environment, click
coordinates and config in `realprocess/PROVENANCE-native-process.md`). For a
fresh GUI run, reset `provisioned/kicad8-config/8.0/local.kicad_sym` from
`provisioned/local-empty.kicad_sym`, then import the unmodified vendor file
(control) and the five `SizeZ` fixtures. The three one-digit ones are pinned in
`vendor/PINS-vendor.sha256`; the two six-digit ones are pinned in
`realprocess/fixtures/PINS-w183.sha256`. The four overwritten bytes follow
`(int(SizeZ * 72 / 10) * 254 << 32) | 0x20` in the real build; predicted and
observed sizes agreed for values 9, 7, 1, 138889 and 200000.

Ceiling: real process and file-selected bytes, but no ASan vendor build, no
fixed-build real-process control, no consumer read, no wire, no pointer or
control-flow target, no marker and no witness replay of this lane. Rung 5 stays
UNKNOWN; witness #2996 covers only rungs 1-4 at the synthetic-CFB scope.

## 2026-11-24 01:1xZ — fold of the 23:2xZ–01:1xZ work numbers

The lane-index rows above keep their admission-era wording; this section
supersedes the verdict claims in the BusyBox, Sdlmixer, nDPI, Libheif and
OpenEXR rows and adds the recipes absent from the index.

- **BusyBox W1/W2**: `lab/frontier/busybox2shell/harness/heap_probe.py` and
  `run-heap.sh` write `0x4141414141414141` over `rbuf+72`'s next-chunk size
  (rc -6 `malloc(): corrupted top size` 5/5) and restore `0x20cb1` (rc 1 5/5);
  a clean `git archive 52a4e02` replay covered both. Witness DM #3135 replayed
  the five-leg wire matrix and the eight-leg heap supplement from `e94a95f`
  (8/8 pins, rebuilt binaries): **ESTABLISHED rungs 1-4, NO rung 5**. The
  "unwitnessed" and "no ASLR measurement" claims in the W182 fold are stale;
  admission was as the 122nd route (`96d2389`, window 126).
- **Sdlmixer W181–W184**: `harness/realwav/wire_driver.c` on
  127.0.0.1:19442; unmodified upstream `M1F1-Alaw-AFsp.wav`
  (sha256 `cfbc1821…`) reaches `FetchXLaw`; `sh
  harness/realwav/testmixer-replay.sh` gives `PASS=6 FAIL=0` on the unmodified
  upstream CLI; `craft_partial_wav.py` plus `lut_partial_check.py` (length 142)
  show no LUT word in the PIE window, so a partial saved-RIP overwrite is not
  a mapped target. Witness #3000 graded only W179's real-caller scope at
  rungs 1-4, NOT rung 5; W180/W183 replay ask #3053 has no verdict.
- **nDPI witness**: from clean `git archive 44be53e`, both serializer pins
  hash-match and both clang ASan libraries are rebuilt before
  `realbuild/run.sh` gives `PASS=9 FAIL=0` twice; fresh ASan `WRITE of size 1`
  at `ndpi_serializer.c:107:18`, top caller
  `ndpi_serialize_start_of_block_binary:2340`, chosen byte `0x2f`, klen=16
  clean and fixed build rc 0. Witnesses #2999/#3001 graded **ESTABLISHED
  rungs 1-4 at the real-pinned-library / in-tree-caller scope, NOT rung 5**;
  the W162 fold's "author-only" heading is superseded for that verdict. Direct
  harness replay from `git archive 6510950` is 172 PASS / 0 FAIL, trace
  `16060f55…7b5b`.
- **Libvips W14/W15**: `bash lab/frontier/libvips2shell/real/run-wire.sh`
  (13/13 PASS) sends crafted TIFF bytes through a loopback wire consumer to
  `vips_object_sanity()` on 8.18.2; fixed rejects `image: dimension overflow`.
  W15 records the downstream version claim (imgproxy 4.0.0–4.0.5 bundles
  libvips 8.18.2, >=4.0.6 bundles >=8.18.3); the old "no imgproxy process was
  built" wording is obsolete — W1/W2 built pinned imgproxy binaries.
- **Libvips W16/W17, allocator field and closed HTTP route**: `bash
  lab/frontier/libvips2shell/real/run-fine.sh` (26 assertions, `RESULT fail=0`)
  loads a real 154-byte fine TIFF header and writes chosen `0x41` bytes into
  the live `vips_tracked` size field at `data-16`, with `vips_free: too much
  free` at teardown; that field is size arithmetic, not a pointer, and the
  write is still a direct pinned paint call on a programmatically created
  image. Structurally imgproxy has no TIFF thumbnail or shrink-on-load route
  (`SupportsThumbnail: false`); the measured endpoint blocker is imgproxy's
  50M-pixel guard (HTTP 422 before libvips header load), not the W7/W8 ~8.59 GB
  zero-fill stall, whose attribution is WITHDRAWN. No paint frame, chosen byte,
  pointer or command in the imgproxy process; rung 5 UNKNOWN.
- **Libfontenc W181/W183**: `realpath/evidence/ramp/README.txt` records the
  two-mapping identity ramp (195840 OOB 16-bit stores at `encparse.c:492`);
  `sh realpath/evidence/ptrctrl/run.sh` overwrites mapping2's live `sm->map`
  through seven mappings, with chosen words and `FontEncRecode(254,
  mapping2) = 0x5558`. No control-flow target, witness or rung 5.
- **OpenEXR W169–W173**: `lab/openexr2shell-real/aarch64/check.sh` (10/10
  under qemu-aarch64), `harness/oob-source-check.sh`,
  `harness/heap-victims-check.sh` (19/20 heap headers clobbered),
  `harness/tiled-check.sh` (10/10) and `groom/check.sh` (10/10 negative).
  W173 resolves the OIIO claim as a **static-source negative**: flat EXR
  geometry and OIIO dispatch block the sink, so the previously listed OIIO
  build resume is obsolete — no consumer was linked or run.
- **Libheif W179–W183**: `real/run_pointer.sh` marker (`BENIGN_MARKER_CALLED`,
  `check_pointer.py` PASS=16); `check_uncompressed.py` PASS=10 on the W180
  ASan classification; `check_advisory_size.py` PASS=11 (36,879-byte region);
  `check_plain_fault_modes.py` PASS=30; `check_genuine_72.py` PASS=45 on a
  genuine 512x72 first frame. The lane row's "36,879-byte allocation
  untested" and W178's "no ASan run on this build" are stale; the arbitrary
  byte control remains scoped to the `-DWITH_UNCOMPRESSED_CODEC=ON` build.
- **Cjose W184–W187**: witness DM #3079 independently ESTABLISHED W184's
  negative (a real 2.4.15.1 mod_auth_openidc rejects a 56-byte encrypted_key
  at `jwe.c:577` before AES-KW); verdicts #3019/#3020 cover the earlier lanes.
  `w2/probe-idtoken.py` reaches the real `id_token` OCT-KEK AES unwrap
  (`W2I_AES_UNWRAP_KEY_REACHED`), and `w2/probe-idtoken-chosen.py` selects the
  chosen-byte fault site (`corrupted top size` vs `unaligned tcache chunk
  detected`) without pointer or IP control.
- **Munt W178**: `sh real/neighbor_probe.sh` (`delta=+32784`,
  `sentinel_0x5a=64/64`, glibc `corrupted top size`) and
  `real/thirdparty/C_API_HOSTS.md` (five real one-byte C-API hosts); no host
  was built or run.
- **ThorVG W183–W185**: `harness/evidence/public-api.tsv`,
  `public-api-file.tsv` and loopback `wire.tsv` (`POST /decode`,
  127.0.0.1:18081); `harness/evidence/crash-mechanism.txt`; W185's
  `harness/make_lottie_poc.py`, `lottie_api.cpp` and `evidence/lottie.tsv`.
  From a throwaway copy, `harness/lottie_matrix.sh` reproduced the committed
  six-row table byte-identically: 853622-byte embedded asset rc 139 on
  v1.1.1 and rc 0 on v1.1.2, controls rc 0 on both. No witness, `.lottie`
  ZIP, renderer canvas, marker, command or rung 5.
- **ImageMagick W189**: `lab/frontier/imagemagick2shell/CLI-ISOLATE.log` and
  `cli-isolate.patch` — a 1x1 MIFF with `-extract 8x4` gives ASan `READ of
  size 24` at `stream.c:1295`, survives a CVE-only fix, and the fixed tag is
  clean only because it also carries `e41876eb4ad4`. Bounded negative for
  this build's compiled coder set; no crafted-file reproduction of
  CVE-2026-130664, witness verdict or rung 5.
- **Hydra W188 (screened out)**: `lab/frontier/hydra2shell/harness/run-all.sh`
  and the lane row at the top of this index; rung 3 only, fixed `-1` offset
  and NUL byte, plain 9.7 survives; no admission, charter or window.
- **KiCad W181/W182**: the 10.0.6 AppImage probe is a negative (no
  `ParseLibHeader`), while native 8.0.8 under Xvfb imports the unmodified
  vendor `.SchLib` alive and aborts on the one-byte `SizeZ` patch (exit 134,
  `double free or corruption (out)`) and segfaults on `Size0` (exit 139).
  W183's chosen-byte check and trace are folded immediately above.
  W184's fixed-build control attempt failed: official fixed 10.0.8 loads under
  Xvfb but its first-run wizard and a declined Chrome terms webview block the
  W182 GUI sequence, so `ParseLibHeader` is never reached. A failed control
  attempt, not a pass or a vulnerability negative
  (`realprocess/PROVENANCE-fixed-build.md`).

  Libfontenc W186 `bash realpath/evidence/fptr/run.sh`: seven-mapping
  `SIZE 256 258` `.enc` overwrites live `m3->recode` at indices
  65584..65587 (`from=0xfe34..0xfe37`) with a non-PIE benign-marker address;
  vulnerable crafted gives `m3 recode=0x4011d6`,
  `BENIGN_MARKER_EXECUTED`, return `0xabcd1234` in 3/3 runs, safe and fixed
  inputs show no marker. Rung 4 at the public API with chosen-address control
  flow in an ASLR-off harness; not a command, no witness or rung 5.

## 2026-11-24 01:2x–02:0xZ — staged CodebaseMemory lane and three ceilings

### CodebaseMemory2Shell W190 (FRONTIER-STAGED, `lab/frontier/codebasememory2shell`)

`bash lab/frontier/codebasememory2shell/bootstrap.sh` from the repo root verifies both pinned tarballs and both `src/cypher/cypher.c` blobs against `PINS.sha256` (fetching a tarball from codeload only when absent — provisioning, not a probe of a target), extracts both trees, rebuilds the four ASan/plain harnesses, regenerates the matrix and replays the gdb byte transcript. Expect ASan OOB READ at `cypher.c:2568` via `rb_set_columns` ← `build_return_columns:4095`, a recover-mode `WRITE of size 70` at `project_item:3379` ← `execute_return_simple:4116` into `func_bufs[32]` (16384 bytes past the 32×512 array), clean 32-item and fixed controls, a plain 48-item stack-smash abort and gdb chosen `4d 49 53 48 45 2d 4f 4f` ("MISHE-OO") at `&func_bufs[32]`. Matrix sha256 `f8c81a5c…7a6d`; clean `git archive a073540` replay 24/24 rows with the same gdb bytes (`REPLAY.md`; replay log hash differs only in ASLR/PID tokens). Extracted source, binaries, `pins/` and `evidence/*.out` are gitignored (`.gitignore` lines 60-67); bootstrap regenerates them. Direct call into the real pinned Cypher engine only: no MCP tool/JSON-RPC/wire, pointer/IP, command, witness or rung 5; the `WITH`-side overflow is UNREPRODUCED. Window 128 is registered but no charter or wake units exist, so this is a stage, not an admission. Brief: `reports/frontier-codebasememory2shell.md`.

- **Libfontenc W187/W188**: `bash realpath/evidence/xlive/run-xfptr.sh` inside a loopback Xvfb, with the test-only `interpose.c` LD_PRELOAD, sets `m3->recode` to the chosen marker address twice on crafted input (client_rc=0, no crash); vulnerable safe leaves `0x7ffff7fb2885`, fixed `5920c6e` leaves `0x7ffff7fb2891`, and `FontEncRecode` is called only on m1, allocated before the buffer, so zero marker calls occur. W188 repaired the replay's Xvfb target selection; matrix and logs in `realpath/evidence/xfptr/replay-w188/`. Consumer behaviour blocks control-flow diversion in the live server; rung 5 stays UNKNOWN. Report §3.9.
- **Sdlmixer W191**: `harness/realwav/gdb-map.cmd` plus `lut_maps_check.py` compare every saved-RIP value formable from the 512 pinned LUT words with the live no-SSP process's 33 mappings (`evidence/LUT-MAPS.out`, `MAPS.sha256`, 5/5 OK): zero of 712 ordered word pairs, zero preserved-high `0x00005555` values and zero `0x00000000` non-PIE partials are mapped, and no LUT word lies in `[0x400000,0x800000)`. Derived negative, not a rung change.
- **Sdlmixer W194, adjacent AIFF lane**: `bash
  lab/frontier/sdlmixer2shell/harness/aiff/check.sh` slices pinned
  `release-3.2.4` `decoder_aiff.c:86-98` under `#line` into the same 12 binaries;
  expect 134 PASS / 0 FAIL, trace `1bdfc38d…43ad183`, ASan `WRITE of size 4` at
  `decoder_aiff.c.vuln:95` with `[32,1056) 'buffer'`, and gdb chosen `5a5a5a5a`
  at `buffer+1024`, with clean fixed runs. CVE-2026-122329 has its own fix
  `3448684` and grade; this is author-observed direct-call rungs 1-4 only,
  unwitnessed, with no AIFF-C file, real decoder build, consumer, wire, pointer
  or command. Full recipe: `harness/aiff/AIFF.md`. The WAV charter row stands.
- **BusyBox W3**: `sh run-malloc.sh` (calling `malloc_probe.py`) writes `malloc_evidence.log` sha256 `98d1130912f849d815a2abe2df0733430814ef024ee463263414ec60b7003082`: chunk sizes above `av->system_mem = 0x21000` abort with `malloc(): corrupted top size`, so the `-1` house-of-force wrap is closed; a guard-passing value returns `rbuf+80` (inside the overflow) under gdb at `DELTA=80` across three ASLR-shifted runs. No chosen pointer in a live object; the witnessed rungs 1-4 grade is unchanged.
- **SofiaSip W14**: raw probe evidence for the clean-archive replay committed under `libbuild/evidence/w14/`; no grade or claim change.

## 2026-11-24 02:1xZ — staged Assimp glTF accessor lane (W192)

### Assimp2Shell W192 (FRONTIER-STAGED, `lab/frontier/assimp2shell`)

`bash lab/frontier/assimp2shell/bootstrap.sh` verifies the tracked pin manifest
and fetches only the recorded 146 MB codeload v6.0.6 tarball when it is absent
(provisioning, not a probe). `bash lab/frontier/assimp2shell/harness/run-all.sh`
then re-extracts the verbatim pinned `Accessor::GetPointer`, `ExtractData` and
`Indexer` functions into generated includes, builds vulnerable/fixed × gcc/clang
ASan plus two plain binaries, runs the matrix offline and writes `evidence.log`
and `evidence.sha256`. Expect 13 PASS / 0 FAIL: both vulnerable ASan builds
report `heap-buffer-overflow`, `WRITE of size 16`, 0 bytes after a 36-byte
region for the VEC4/FLOAT position accessor, the VEC3/uint index accessor gives
`WRITE of size 12` after a 12-byte region, and `Indexer::GetValue<uint32_t>`
gives `stack-buffer-overflow` into `[32,36) 'value'`. The fixed control uses the
**open, unmerged** PR 6860 hunk: both `ExtractData` cases return false with no
write, but the Indexer case still overflows — a preserved negative, not a
released fixed-version claim. The plain deterministic allocator shows the
chosen `54 41 55 46` ("TAUF") at destination offsets 36..39.
W1 and W2 supersede this staging limit: the verbatim pinned v6.0.6 library was
built and the sink reached through `ReadFileFromMemory` on crafted glTF
documents, with chosen bytes observed at a live 24-byte vertex array's end.
Witness #3277 (2026-11-24 03:51Z) replayed clean `git archive 585e1c7` and
graded the baseline direct-call / stub-Accessor / deterministic-arena scope
**ESTABLISHED rungs 1-4, NO r5**; W1 and W2 were explicitly outside that claim
and remain author-measured. No pointer/IP, command or rung 5.

Author clean-archive replay of `585e1c7` (`lab/frontier/assimp2shell/REPLAY.md`)
rebuilt every binary from the pin and repeated 13 PASS / 0 FAIL. Raw log hashes
differ on ASLR/PID/timestamp tokens; after normalizing those, both traces hash
to `913b23f5dc387a86bcad17718b8a0af41c9ba128a8ff39f29368e7028c3ca938`. This
is an author replay, not a witness verdict.

## 2026-11-24 04:0xZ — FLTK BMP row-pointer wrap (W195, frontier-staged)

`cd lab/frontier/fltk2shell && bash run-all.sh` verifies the tracked pins,
rebuilds four trees from the pinned `release-1.4.5` source and the two tracked
patches, regenerates the 118-byte BMPs with `gen_bmp.py`, and checks 33 cases
offline. Expect ASan `heap-buffer-overflow WRITE of size 1` 2 bytes before a
2-byte allocation at `Fl_BMP_Image.cxx:486` for width 2, height 715827883,
depth 24; with predecessor `3a049d8` applied by hand the allocation becomes
4294967298 bytes but the isolated row-pointer CVE still writes 2 bytes before
it at `:490` (24-bit) / `:503` (32-bit). The plain build under gdb shows
chosen `53 49 4d 2d` ("SIM-") immediately before the array; a safe 2x8 BMP
and fix `a28e392` are clean. `evidence.log` is 33 PASS / 0 FAIL with
normalized hash `7882e60c…3525e`; a clean `git archive 072dc75` replay in
`REPLAY.md` matched it byte-for-byte. The path-masking runner fix landed in
`072dc75`, not the staged `b214fbb`: a `b214fbb` replay also gave 33 PASS / 0
FAIL and the same fault lines and chosen bytes, but its normalized hash is
`aecb1055…` because absolute source paths remain. No application-level consumer, ICO
container path, wire, pointer/IP, command, witness verdict or rung 5; the
advisory itself makes no remote claim.

## 2026-11-24 04:1x–04:5xZ — staged PCF lane, closed placements, replay NIT

- **Assimp W4, live-aiMesh placement closed** (`425fcb5`):
  `g++ -O1 -g0 -I pins/assimp-6.0.6/include -I build-min-plain/include
  harness/placement_probe.cpp -L build-min-plain/bin -lassimp
  -Wl,-rpath,"$PWD/build-min-plain/bin" -o /tmp/assimp-w4/probe` from
  `lab/frontier/assimp2shell`, then `probe <case.gltf>` (509-byte VEC4 count=2
  cases with varied `wbits`, plus a VEC3 matched baseline). The last of two
  16-byte copies starts at `logical_end-12`, so exactly four bytes land on the
  next chunk's size field (`p+24` for usable 24, `p+40` for usable 40), never
  on a live `aiMesh` member; fourteen forged size values all abort and a later
  8-byte `operator new` inside `ImportMeshes` faults. No clean-import control
  or grooming was found. Raw matrix and source:
  `lab/frontier/assimp2shell/placement/evidence/w4-negative.log`,
  `harness/placement_probe.cpp`. Negative only; rung-4 write and witness #3277
  unchanged.
- **Assimp W5, MAT4 mismatch and replay recipe defect** (`20cf486`, `4f3b254`,
  `075eaa0`): copy the gitignored `pins/assimp-6.0.6.tar.gz` into a clean
  archive, then `bash lab/frontier/assimp2shell/harness/run-w5.sh`; it builds
  its own minimal vulnerable, PR6860-fixed and plain libraries and checks
  `w5/evidence/w5.log` for 13 PASS / 0 FAIL. Pinned MAT4/FLOAT has
  `elemSize=64`: `mat4pos-count1.gltf` gives ASan `WRITE of size 64` after a
  12-byte `aiVector3D`, callback-recorded chosen `54415546` at the first OOB
  offset and a glibc abort in the plain build, while the fixed hunk gives
  `scene=ok`; `mat4idx-count1.gltf` gives a 64-byte stack write into a 4-byte
  local and still aborts under the hunk, preserving the Indexer negative. The
  first clean run's 10 PASS / 3 FAIL came from building the fixed library from
  vulnerable source (the live run had reused W1's library); `4f3b254` corrected
  the recipe. Author-measured, unwitnessed; no chosen byte in a live `aiMesh`,
  no pointer/IP, command or rung 5.
- **Munt W179, chosen-byte allocator metadata and watchpoint negative**
  (`6badbb8`, replay `db81c42`): after `real/build_and_run.sh`, run
  `cd lab/frontier/munt2shell/real && sh shape_probe.sh && sh watch_probe.sh`
  (`watch_probe_multi.gdb` covers four 8-byte windows). Shaping eight bytes at
  source offset 32776 to little-endian `0x10001` survives the real copy:
  `mode=shape grows=1`, `delta=32784`, then harness `malloc(32)` returns
  `buf+32784` and rewrites the forged size to `0x31`; unshaped attack aborts
  `rc=134` (`malloc(): corrupted top size`), safe and all fixed legs are
  `rc=0` with `grows=0`. Watchpoints recorded zero in-library reads before the
  abort. Author clean-archive replay of `6badbb8` (pinned tarball the only
  ignored input) matched all seven rc/header cases and both watchpoint runs;
  not a witness verdict. No upstream object targeted, no pointer/IP, command,
  host or wire; grade unchanged.
- **Imgproxy W2, fine-geometry TIFF over HTTP** (`5d5b455`, replay `4a1977f`,
  corrected by `24221c9`): `python3 lab/frontier/imgproxy2shell/provision/http_probe.py <imgproxy-binary>
  <libvips-libdir> <tag> [timeout]` starts a source server on 127.0.0.1:18081
  and imgproxy on 127.0.0.1:18080; the `fine_tiff` case is
  `rs:fill:16:16/f:tiff/plain/fine.tif` with the 154-byte
  `fine.tif` (`sha256=c3e12050…157d44`, `ls=2^32-16`). The vulnerable five-case
  log has only three `Started` lines under WORKERS=1/CONCURRENCY=1, so the
  later `fine_tiff`/`tiff9999_tiff` timeouts are queue starvation, not
  per-fixture decode; fixed requests return 500 `image: dimension overflow`.
  For the measured leg run `python3
  lab/frontier/imgproxy2shell/provision/isolated_probe.py`
  (`sha256=97f7f28c…526f4b4c0`): one fresh source server, one imgproxy process
  and exactly one GET. Vulnerable 4.0.0 returns HTTP 422 "Source image
  resolution is too big" in ~6 ms (50M-pixel guard, `config.go:46` /
  `security/checker.go:65-66`), fixed returns 500 `image: dimension overflow`
  in ~7 ms. The earlier ~8.59 GB decode/zero-fill stall attribution is
  WITHDRAWN. Logs `provision/http-w2fine-{vuln,fixed}.log`; details in
  `PROVENANCE.md` §W2 "Isolated fine.tif correction". Witness W185 (#3318)
  replayed the ICO rungs 1-4 on a clean archive and graded the HTTP probes
  ESTABLISHED only at header/processing-entry scope, NO r5. No TIFF paint
  frame, chosen-byte write, pointer or ASan report in the endpoint. Grade
  unchanged: ICO rungs 1-4, TIFF limb rung 4 at header/entry only, r5 UNKNOWN.
- **FontForge W196 staged; replay hash NIT** (`13a2a94`, `e5e4a65`, `024790a`):
  `cd lab/frontier/fontforge2shell && ./run-all.sh`, or from a clean archive of
  `e5e4a65` as in `REPLAY.md`. Expect `asan-attack 1`, `asan-fixed 0`,
  `asan-safe 0`, `plain-attack 134`, `plain-fixed 0` and gdb bytes
  `4d 49 53 00` at `encs-4`; the fourth byte is structurally zero because the
  pinned expression is `(i+min2)*256 + min1` with 16-bit fields. A docs replay
  at 04:51Z from `git archive e5e4a65` reproduced the matrix and those bytes.
  The receipt's normalized hash `56fd8ada…5633bb` cannot be reproduced by its
  own documented command: `grep -E '^asan-|^plain-|^normalized gdb' … |
  sha256sum` gives `320bc5f773e5d25a1077a8676c6cd5acee05099f224049633287df1a89b90094`
  on both the tracked `evidence.log` and the clean replay. Record the NIT;
  the RC/byte equivalence is observed, the quoted hash is not. Direct-call
  rungs 1-4 only, no real build/import path, witness or rung 5.
- **LibreCAD W196 screened, no recipe** (`e7027c5`): pinned v2.2.1.6
  `rs_filterdxf1.cpp` and fix `4e51048…` under `lab/frontier/librecad2shell/pinned/`;
  no build or trigger was run. The claim is a fixed NUL underwrite from a
  64-bit-to-32-bit size narrowing near 4 GiB; real-file reachability and the
  `dos2unix()` consumer's behavior after the metadata corruption are UNKNOWN.
  No window, witness or admission row.
- **Cjose W189, no wire route to the groomed hole** (`bde3c72`): with the W184
  mod_auth_openidc 2.4.15.1 + cjose v0.6.2.4 build under gdb, load
  `lab/frontier/cjose2shell/w2/gdb-cek-provenance.cmd`, then
  `python3 probe-idtoken-chosen.py preserve` (GET 302, POST 400). Raw log
  `w2/evidence/gdb-cek-provenance.log`, hashes in `…-SHA256SUMS`: state-cookie
  CEKs release at `0x555555674740`, the vulnerable id_token CEK is
  `0x5555556992a0` (~150 KiB away, not a reused hole); forward words hold no
  code or heap pointers, `enc` stays ~3968 bytes behind under the chosen-wrap
  config. Full ASLR and a PIE module leave no wire-derived counterpart to
  W188's absolute-address marker. Negative for wire grooming, no new rung.
- **Modauthoidc W20, kernel-recorded harness PC** (`187d7c6`): no rebuild;
  from `lab/frontier/modauthoidc2shell/realobj`, six trials of
  `MO_TOKEN_LEN=65000 timeout 15 ./pl-vuln read 0` with `journalctl -k`
  (`dmesg` is denied here) plus three each of `pl-fixed` and `pl-release`.
  Four rc-139 trials logged distinct ASLR bases with IP low bits `0x563` and
  `error 7`; the ELF text LOAD starts at vaddr `0x1000`, so IP `0x1563`
  symbolizes to `oidc_state_cookies_parse_token` at pinned
  `state.c.4301b536:219`, with `objdump`'s `movb $0x0,(%rax)` and byte-exact
  `Code:` stream. Controls were 3/3 clean. Raw:
  `realobj/evidence/kernel-pc/README.md`. Debugger-free attribution only;
  live-wire PCs stay debugger-observed, the byte stays NUL, grade unchanged.

## 2026-11-24 04:5x–05:0xZ — witness verdict and shortest-frame underflow

- **Imagemagick W181 independent witness** (commits `f6c923d`, `7a08745`,
  DM #3204): from a clean `git archive a073540` (the
  `lab/frontier/imagemagick2shell` tree byte-identical at HEAD `7091755`),
  `sh run-all.sh` reproduced all legs in 3.5 s. Expect 5/5 `PINS.sha256`
  entries OK, author `REPLAY.log` sha256
  `385bbe95d648dd19981d0d42df483c9ebeb619bb078fd3a2a2c9789bac01667a`
  (recomputed from the tracked file here) and witness `evidence.log` sha256
  `5547d698cfac58e5934c7754304134ee5e5578c36634bcad0d29c53bd1ce40d3`;
  normalized diff empty except build path and BuildId. Exact legs: vulnerable
  ASan 1x1->8x4 rc 1 with `WRITE of size 1` at `stream.c:1576` via
  `:1279`/`:2778`, same-size 2x2 control rc 0, fixed 7.1.2-35 ASan attack rc 0,
  plain build rc 0, plain gdb `pixels[0]@24` =
  `0x41,0x41,0x41,0x42..0x48` (three copies each). Verdict ESTABLISHED rungs
  1-4 at the labeled direct-call/in-process scope, NO r5. NIT: the
  `0x42..0x48` bytes are the harness pattern `0x41+(i%26)` and geometry growth
  is harness-assigned; file/coder reachability and the CLI `-extract` READ
  were excluded and stay UNKNOWN. Full legs: report §8 and
  `reports/imagemagick2shell-status.md` § "Witness verdict".
- **Vrpn W24, shortest wire message and `payload_len` underflow** (commit
  `bf6058d`): from `lab/frontier/vrpn2shell`, a 24-byte VRPN header with
  `header[0]=24` gives `payload_len=0`; an optional earlier 512-byte message
  fills the reused `d_tcpInbuf`. Run
  `bash probe-underflow.sh <outdir> <port> [groom_bytes]` with `BIN=`
  selecting the ASan, plain or fixed server and `MSGTYPE=-1` (SENDER) or
  `-2` (TYPE); gdb variants are `bash probe-underflow-gdb.sh <outdir> <port>
  <line> [groom_bytes]` and `bash probe-underflow-after.sh <outdir> <port>
  <line_after> [groom_bytes]`. All ports are loopback 15101-15113 only.
  Expected: ASan v07.36
  (`987603cf…c0ad6`) reports `negative-size-param (size=-4)` in `strncpy` at
  pinned `vrpn-07.36/vrpn_Connection.C:4548` (SENDER, port 15101) or `:4476`
  (TYPE, 15113), exit 1; plain v07.36 (`5cf49457…40bd74`) exits 135 SIGBUS on
  SENDER (15102) and 139 on TYPE (15105), while fixed, safe-declared-28 and
  vulnerable-with-zero-index-groom controls stay ALIVE. The fixed handler
  reaches the same expression with `payload_len=0` but clamps the later index
  write. gdb maps the plain fault to the stale huge index at `:4554`, not the
  copy. Under glibc 2.39 the 512-byte groomed fixed run dumps 48 unchanged
  destination bytes (zero-store), so no chosen byte; behavior on another
  libc is UNKNOWN. `out-w24-plain-safe/` declared 28 bytes but sent no body,
  so the handler was never reached — a malformed harness negative, not a
  safety control. Author self-observation, no independent replay, no new
  rung. Raw `out-w24-*/` evidence, scripts and hashes:
  `lab/frontier/vrpn2shell/PROVENANCE.md` § "W24".
- **Docs bounded check (05:0xZ)**: recomputed the ImageMagick `REPLAY.log`
  hash above from the tracked file and grepped the committed W24 outputs:
  both ASan `negative-size-param (size=-4)` frames, the `STRNCPY_SITE
  payload_len=0` and `AFTER_STRNCPY` gdb lines, the unchanged 48-byte groom
  dump, and the ALIVE/DEAD statuses in each `meta.txt`. This checks the
  receipts, not a fresh build; builds remain gitignored and regenerate with
  the target's own pinned scripts.

## 2026-11-24 05:4x–06:0xZ — Contiki stage, FLTK shared image, live ICO crash

- **Contiki2Shell W198 (staged `e89ebd3`, operator-admitted `2f48681`)**: `cd
  lab/frontier/contiki2shell && sh run-all.sh` verifies the pinned
  `contiki-ng-release-v5.2.tar.gz` (`78133c77…70819c95`), applies the
  `project-conf.patch` and open-PR `fix-pr3312.patch`, and builds the real
  native multicast example three ways. Expect `RESULT: PASS=9 FAIL=0`: the
  vulnerable ASan build reports `global-buffer-overflow WRITE of size 1232`
  from `data_message_expiration` at `mpl.c:981`, `gdb-inspect.txt` records
  chosen `MISHE-OO-TAUF!!\0` at `uip_aligned_buf+1280..+1295`, and the fixed
  and complete-option controls stay clean. `REPLAY.md` repeats that matrix
  from a fresh bootstrap; source tarball, tree and `*.out` logs are gitignored
  and regenerate from the pinned archive. No tun device or wire process was
  started; rung 4 is partial and rung 5 UNKNOWN.
- **Fltk2Shell witness/pin fold and shared-image extension (`141a729`,
  `b0d8d63`)**: the four-tree `bash run-all.sh` recipe above is unchanged;
  `PINS.sha256` now records `gen_bmp.py` as `69dd2a2a…` and `REPLAY.md` points
  at `072dc75`, where path masking landed (the earlier `b214fbb` runner gave
  33 PASS / 0 FAIL with a path-only hash difference). Witness #3296 replayed
  from `b214fbb` and graded rungs 1-4 ESTABLISHED at the direct-call scope.
  For the author-only extension, run `cd
  lab/frontier/fltk2shell/shared-image && sh build.sh && sh run.sh` after
  `run-all.sh` has built the ASan trees: the headless
  `Fl_Shared_Image::get()` consumer aborts with ASan `2 bytes before
  4294967298-byte region` at `Fl_BMP_Image.cxx:490` in the vulnerable
  `plus1632` tree and is clean in the fixed tree, while both crafted ICO
  geometries are clean in both trees because the IconDirEntry 8-bit
  dimensions override the wrapped DIB. Raw per-case stdout/stderr and exit
  codes are tracked under `shared-image/outputs/`; consumer binaries are
  gitignored build products. No witness replay, GUI, pointer or command.
- **Imgproxy2Shell W3 live ICO crash (`7ec6de8`, `87a52fd`)**: run
  `python3 lab/frontier/imgproxy2shell/provision/ico_probe.py <imgproxy-binary>
  <libvips-libdir> <tag> /insecure/rs:fill:16:16/plain/hostile.ico` against
  the already built pinned 4.0.0 CLI (source and proxy bind only to
  127.0.0.1). Expect three fresh-process `rc=2` runs with
  `malloc(): corrupted top size` and Go frames through
  `vips.(*Image).Load`/`initialLoadImage`; the benign ICO yields HTTP 200 and
  the v4.0.16-loader-only control yields 500 `ICO image data is too large`.
  A clean `7ec6de8` replay matched. The ASan imgproxy binary
  (`0f3e3360…dce203`) instead returns HTTP 500 with no report, with and
  without `LD_PRELOAD=libasan.so`: preserve that negative; do not substitute
  it for the harness's C write-site ASan. No chosen-byte readback, pointer,
  command or r5.
- **Synchronet2Shell W1 real cryptlib (`d0c1a2c`)**: after provisioning the
  pinned `42f586d7` tree, run `bash
  lab/frontier/synchronet2shell/real-cryptlib/run-all.sh`; expect ASan
  `heap-buffer-overflow WRITE of size 64` 0 bytes after a 41-byte heap
  destination via `cryptGetAttributeString` → `attributeCopyParams` →
  `memcpy` (`real-redzone-64.out`), a clean 40-byte control, and chosen bytes
  at real session offsets 44/48/52 in the plain probe. The loopback
  `wire/` SSH pty-req attempts never delivered TERM (poll `-43`, broken pipe,
  protocol errors `-16`/`-41`); those negatives are preserved, with no wire
  reach, DoS, witness verdict or r5. The Synchronet row's stub-model wording
  is superseded for the direct API, not for the network path.
- **Docs bounded check (06:0xZ)**: receipts were read from the five new edges
  and the tracked reports/logs; no new lab build or replay was run here.

## 2026-11-24 06:0x–06:2xZ — Contiki admission, FontForge witness/real path, LibRaw nonzero, tool-path replay

- **Contiki2Shell admission (`2f48681`)**: the operator's README/repro row now
  names the charter, route, mind and three wake units minted by the exact
  full-flag sync at pin `0d686bba…d528a`; `sh run-all.sh` was re-verified at
  9 PASS / 0 FAIL. The staged brief and the nine-case recipe above are
  unchanged, and rung 4 remains PARTIAL with no tun/wire process; no grade
  moved and the admission adds no witness verdict.
- **Ruby2Shell stock Rails N=524 (commit `20db6aa`)**: the recipe is already in
  the Ruby lane above (`ruby2shell-stock-rails-setup.sh` and
  `ruby2shell-stock-rails.sh`). With the exact N=524/drain/fill/tail
  environment, the analysis-only case probe records a real `0x200→0x250`
  expansion and a second mapping buffer returning the forged V chunk
  (`stock-rails-rails-stage2d-n524-r498.server.log`); the final matrix is 3/3
  pre-response SIGABRT and 3/3 safe affected plus 3/3 fixed controls returning
  404 and later `/up` 200. A seeded 512-layout search found no `0x3f0`
  physical neighbour, and the full default app found none either. No address
  disclosure, command, persistent process or second request; rung 5 stays
  NOT ACHIEVED. The vendor PoC was still unpublished.
- **FontForge witness and real Import() (commit `6548132`)**: witness #3309
  replayed a clean archive of `13a2a94` with gcc 13.3.0/gdb 15.1 and graded
  the direct-call/in-memory-table/stand-in-struct rungs 1-4 ESTABLISHED with
  NO r5; the real-build path was outside that verdict. For the real path,
  build `fontforgeexe` from tag `20251009` with `-DENABLE_GUI=OFF
  -DENABLE_SANITIZER=address -DENABLE_NATIVE_SCRIPTING=ON` (full flags in
  `lab/frontier/fontforge2shell/REACHABILITY.md`), then run
  `ASAN_OPTIONS=detect_leaks=0 ./build-asan/bin/fontforge -script import-pcf.ff`
  in that tree: expect exit 1 and one ASan `WRITE of size 4` four bytes before
  `encs` at `fvimportbdf.c:1751` (`real-import-asan.out` sha256
  `8c199e9e…115e0f8c`; truncated PCF `0c8dc0fe…528703`). The patched build
  and `import-complete.ff` exit 0 with no report. GUI, real-process chosen
  bytes, pointer/IP, command and independent replay of this path are UNKNOWN.
- **LibRaw W2 nonzero halfwords (commit `8af65c7`)**: from
  `lab/frontier/libraw2shell`, `python3 craft_nonzero_poc.py` writes
  `evidence/nonzero-oob.input` (`b59f64e9…069341`; generator `004ff435…f862`)
  by changing the embedded JPEG to 512x512, `BitsPerSample` 8→12 and
  `StripByteCounts` 48→20048. Running the pinned ASan `dcraw_emu` with `-n 1`
  gives `heap-buffer-overflow WRITE of size 2` at `xtrans_demosaic.cpp:427`;
  gdb at the first store reads `IDX=68644 avg={131070,131070,131070,2}` and
  after it `{0xffff, 0xffff, 0xffff, 0x0000}`; the fixed tree and the
  no-option vulnerable run are rc 0 with empty ASan output. The written value
  is a saturated constant, not an arbitrary byte, and W2 awaits witness
  replay; the earlier zero-valued claim was ESTABLISHED by W186.
- **CodebaseMemory W3 tool-path replay (commit `c73bc62`)**: rerun
  `bash lab/frontier/codebasememory2shell/mcp-tool/replay.sh`; W2's empty
  fixture could show only the READ and fixed-parse control. W3 tracks a
  nonempty fixture, adds a zero-row failure guard and commits per-query ASan
  stderr: `evidence/replay-mcp-tool-vuln-recover-Q33.err` and `-Q48.err` carry
  the chosen-name `WRITE of size 68` at `func_bufs[32]`. This closes the
  clean-archive replay gap, not the independent-witness gap; no HTTP, remote
  wire, pointer/IP, command or rung 5.
  Superseding that "no HTTP" boundary: W9 reaches the same sink through the
  pinned server's 127.0.0.1-only HTTP `/rpc` transport, and W11 clean-archive
  replayed all three rows with 4/4 pins verified. Still no remote/off-host wire,
  pointer/IP, command, witness verdict or r5, and no grade change.
- **Docs bounded check**: receipts were read from the six new edges and the
  tracked reports/logs (libraw input/generator hashes and gdb halfwords,
  FontForge Import ASan line and truncated PCF hash, CodebaseMemory Q33
  WRITE-68); no new lab build or replay was run here.
- **Fltk2Shell plain-build metadata (`480dbc5`)**: from `lab/frontier/fltk2shell`,
  `python3 plain-metadata/gen_short.py poc-chosen.bmp plain-metadata/short-chosen.bmp`
  (`2d26f388…8bf14`) and run `../driver-plain` / `../driver-plain-fixed` on
  `short-chosen.bmp` and `full-chosen.bmp` as in `plain-metadata/README.md`.
  gdb at `Fl_BMP_Image.cxx:490` reads mmap chunk size `0x0000000100001002`;
  after the first row `plain-metadata/outputs/gdb-short.txt` reads
  `0x2d4d495300001002` (chosen `53 49 4d 2d` in the high half). The truncated
  vulnerable run reaches `munmap_chunk()` from `~Fl_RGB_Image` and exits 0
  with no diagnostic; the full crafted file SIGSEGVs at `:490`, fixed plain
  controls exit 0. No pointer/IP, command or rung 5; the silent free is a
  negative result, not a new grade, and W195's verdict is unchanged.

## 2026-11-24 06:2xZ — cjose W190 negative and assimp W6 sites

- **Cjose W190, jansson length-corruption info-leak hypothesis closed**
  (commits `c8b00cf`, `dcbe8ee`, `0d4006b`): no rebuild and no new input. Read
  pinned `deps/jansson-build/src/jansson_private.h` (`json_t json; char
  *value; size_t length;`) alongside W183's
  `w1/evidence/wrappedN56-typed-refcount-w183.log`: `CEK_PTR=0x80f04b0`,
  `ENC_OBJ=0x80f04e0` (enc at `cek+48`), object `value` at offset 16
  (`VAL=0x80f0910`) and `length=13` at offset 24. The sequential AES-KW write
  reaches `cek+64` (pointer) before `cek+72` (length); in the real consumer
  that pointer is ASLR-randomized (W189), so no contiguous overflow can set
  the length while preserving it. Structural negative only: no wire-visible
  pointer source, no new build, byte, rung, command or witness. At W190's time,
  with W188/W189 the primitive had no measured path to a live pointer on the
  wire. Evidence:
  `lab/frontier/cjose2shell/PROVENANCE.md` § W190 and the end matter of
  `reports/frontier-cjose2shell.md`.
  Superseding that W190-era ceiling: W199 later observed a live non-address
  value in a loopback decrypt, W202 carried a lab-known valid literal `0x41bd2e`
  over HTTP, and W203 placed a fake `fns` pointer with a benign marker in a
  modified loopback consumer. All are author-only limbs: no ASLR defeat, no
  wire-derived live address and no command; witness verdicts remain
  direct-call/synthetic/groomed-fptr only, with no grade or r5 change.

- **Assimp W6, untested TEXCOORD accessor sites (`62466f7`)**: after
  `bash lab/frontier/assimp2shell/harness/run-w5.sh` builds the libraries and
  drivers, run `bash lab/frontier/assimp2shell/harness/run-w6.sh`: expect
  18 PASS / 0 FAIL. `mat4tex-count1.gltf` (MAT4/FLOAT TEXCOORD_0 into a
  12-byte `aiVector3D`) gives ASan `WRITE of size 64` at `0 bytes after` via
  `ExtractData` ← `ImportMeshes` ← `ReadFileFromMemory`, plain rc 139, and
  PR6860 rejection; `texcount-mismatch.gltf` (POSITION count 3, TEXCOORD_0
  count 1) gives ASan `READ of size 4` in the Y-flip loop at
  `glTFImporter.cpp:299-302` with plain `double free or corruption (out)`,
  and that READ survives PR6860 while PR7090 adds only a NORMAL count check.
  It is a separate count-check defect, not the CVE element-size write.
  `texsafe-count1.gltf` is clean on both builds. Author-only, unwitnessed; no
  chosen byte in a live `aiMesh`, pointer/IP, command or grade change.
  Receipts: `lab/frontier/assimp2shell/w6/evidence/W6-SUMMARY.md` and
  `w6.log`.

## 2026-11-24 06:3x–07:0xZ — real AIFF-C lane, boundary negatives, two receipts and two screens

- **BusyBox W5, both TFTP consumers closed (`659b379`, `a27d4bc`)**: from a
  built stock plain BusyBox 1.37.0 client, run `python3
  lab/frontier/busybox2shell/data_probe.py` against a loopback UDP socket.
  Leg A writes `0x4141414141414141` over the top-size word at `rbuf+72` with
  an 84-byte DATA block and returns rc 0 with an 80-byte file and no later
  `malloc`; Leg B uses the ERROR consumer and aborts rc -6 with
  `malloc(): corrupted top size`; Leg C restores `0x20cb1` and is clean.
  Expect transcript SHA-256 `8d22cfe3daf7a4cc9d9edab1b58260ebbd6b13b7d479a9db11e6267e22c7aa3c`
  in `data_probe_evidence.log` (two identical runs at 06:34Z). A clean
  `git archive 659b379` replay (`/tmp/w5-distro-replay.log`, author, not
  witness) reproduced all three legs byte-identically. Witness #3135 still
  covers only the earlier from-source rungs 1-4 scope; no chosen pointer in a
  live object, tcache poisoning, command or rung 5. Author-only negative.
- **Assimp W6 clean-archive receipt (`7d8495b`)**: `git archive 62466f7` into
  an empty tree, copy the gitignored pinned tarball in, then `bootstrap.sh`
  (rc 0), `bash harness/run-w5.sh` (13 PASS / 0 FAIL) and `bash
  harness/run-w6.sh` (18 PASS / 0 FAIL). All nine normalized W6 `.out`
  traces match the author tree with combined SHA-256
  `b4dd27d115f1de31383f82fe5aa9820af26cff9fa550661ca7024f3173054e0a`
  (`REPLAY.md` normalization; raw hashes differ only in volatile tokens).
  Receipts in `lab/frontier/assimp2shell/w6/evidence/W6-SUMMARY.md`, both
  status reports. Witness #3277's ESTABLISHED verdict remains baseline-only;
  W6's MAT4 TEXCOORD WRITE-64 and count-mismatch READ-4 stay author-only.
- **Contiki W199 tun and chosen-pointer measurements (`62a3a2d`)**:
  `/dev/net/tun` is `crw-rw-rw-` and `open()` succeeds, but `TUNSETIFF`
  returns EPERM (errno 1, no CAP_NET_ADMIN); `unshare -Urn` also fails on
  `/proc/self/uid_map`. The pinned native platform ships only
  `arch/cpu/native/net/tun6-net.c`. The lab-only 1400-byte
  (`UIP_CONF_BUFFER_SIZE=1400`, plain `-g -O0`) truncated-S=3 harnesses
  `harness-large.c` / `harness-large-safe.c` and their gdb transcripts
  `large-buffer-attack-gdb.txt` / `large-buffer-safe-gdb.txt` show stored
  size 1352 (attack) versus 1336 (complete-option control), and
  `uip_appdata=0x4847464544434241` / `uip_sappdata=0x504f4e4d4c4b4a49`
  after the copy versus two unchanged live pointers in the control. These
  ASCII words are not addresses; no dereference, wire deliverer, witness
  verdict or rung 5. PR #3312 was OPEN / merge BLOCKED at 06:40Z; a witness
  replay was requested then and no verdict has arrived. Raw transcripts are
  committed under `lab/frontier/contiki2shell/`; no synthetic socket driver
  stands in for wire.
- **FLTK wake 4, both mmap chunk-header words (`9cc8dd4`)**: from
  `lab/frontier/fltk2shell`, `python3 plain-metadata/gen_prevsize.py
  ../poc-chosen.bmp plain-metadata/prevsize.bmp` produces the 77-byte
  `faef54c9ef18d0ee830c237d2a1de725fbcd72f3ba7dffd90503e2a1e7fb506c`
  BMP (w=8, h=0x0aaaaaaab, depth 24). `plain-metadata/commands.txt` and
  `exit-codes.txt` record vulnerable plain rc 139 vs fixed rc 0;
  `plain-metadata/outputs/gdb-prevsize.txt` shows `array=0x…f010`,
  `ptr=0x…f000` (diff -16) and both header words read at the destructor and
  at `__GI_munmap` (`rsi 0x200004000`). The first `array-24` geometry hit an
  unmapped page before free and is a preserved negative; wake-3's silent
  `munmap_chunk()` free is unchanged. Author-only; ICO is a measured negative
  at the tested geometry, not an open UNKNOWN. Witness #3296 still covers
  only the four-tree direct-call matrix.
- **Synchronet W2, SSH sequencing negative (`78328ad`)**: `bash
  lab/frontier/synchronet2shell/wire/run-wire.sh 64` starts the plant's
  minimal loopback cryptlib server on 127.0.0.1:22222 and an OpenSSH client
  with `TERM` set to 64 `T` bytes. Expect `Authenticated to 127.0.0.1 using
  "none"`, `PTY allocation request accepted on channel 0`, `shell request
  accepted`, then in `wire/evidence/wire-term-64.out`
  `CHANNEL TYPE final waits=50 status=-43`,
  `TERM sweep pass=20 cid=-1 status=-43 len=0`, `COPY status=-43 len=-1`,
  24 zero bytes at `tail[40..63]`, `ssh_rc=255`, `server_rc=0`. The
  authenticated `clclient-repaired-64` probe shows `client set TERM
  status=0 len=64` but `client ACTIVE status=-16` / `POP status=-11`. TERM is
  -43 (`CRYPT_ERROR_NOTFOUND`) for every channel ID 0-7, so at the time the
  64-byte cap and chosen offsets were direct-API observations only. W3 found
  this was a probe artefact and reached the same write from a real loopback
  pty-req with witness acceptance at the synthetic-struct scope (recipe
  below); the W2 negative itself is preserved, not erased.
- **Sdlmixer W195, real AIFF-C file through real SDL_mixer (`1292e08`,
  `11adba7`)**: with the gitignored `deps/` tree provisioned as in
  `lab/frontier/sdlmixer2shell/harness/aiff/REALAIFF.md`, `sh
  harness/aiff/run-real.sh` checks 9/9 hashes in `REAL.sha256`, regenerates
  the five AIFF/AIFF-C files, builds three AIFF-enabled SDL_mixer 3.2.4
  libraries (vulnerable ASan, fixed ASan applying only `3448684` at
  `decoder_aiff.c:93`, vulnerable no-SSP), compiles the unmodified
  `realwav_driver.c` and runs `check-real.sh`. Expect **51 PASS / 0 FAIL**
  on three runs, normalized trace
  `4d96b2b63ce8c86e73375d8c8ab685a494bea3b8de6a9d61d5ad18d101f9ffc8`;
  vulnerable ASan gives `WRITE of size 4` at `decoder_aiff.c:95` via
  `FetchALaw`/`FetchULaw` → `AIFF_decode:541` → `MIX_DecodeAudio:3190` with
  `[32, 1056) 'buffer'`, fixed returns `RESULT=OK total=1024`, safe/raw/PCM
  controls are clean, no-SSP rc 139, play mode faults on thread T1, and gdb
  reads `00 00 00 00 c0 01 e0 ba` at `buffer+1020..1027` (LUT word
  `0xbae001c0` from input byte `0x56`, not an address). Author-observed
  rungs 1-4 for the separate AIFF CVE-2026-122329, unwitnessed, no wire
  listener, pointer/IP, marker or command. Independent replay was requested;
  no verdict. Raw logs and binaries are gitignored and regenerate with that
  script; the receipts and hashes are tracked.
- **Two screens, no lanes (`6e131d0`, `24aee4c`)**: MediaInfoLib
  CVE-2026-135440 is a stale-read UAF with a 1248-byte public PoC and pinned
  v26.05 / fix `6bacf12f`+`2a13d1b9`; two ASan build attempts reached
  32/293 objects in 420 s (`-O1 -j8` with UBSan) and 37/293 in 600 s
  (`-O0 -j12`, ASan only) with no library, no linked harness and no report;
  `ninja -C build-fast -j12 mediainfo` resumes the cached incremental build.
  Rung UNKNOWN, no window. libgsf CVE-2026-116124's
  pinned 1.14.59 BAT truncation is bounded by `max_block` and
  `ole_get_block()` file checks: an attacker needs a >16 GiB OLE2 file for a
  32-bit wrap; 1.14.60 already contains fix `a8e25560`. The 16 GiB floor is
  source-derived, not measured; no build, trigger, bytes or window; rung
  UNKNOWN. Neither is staged or admitted, and the mind count stays 130.
- **Libheif W186, decoder-reach negative (`40ff079`)**: `grep -rn
  'extend_padding_to_size' libheif/` in the pinned
  `lab/frontier/libheif2shell/src/libheif-v1.23.6` tree finds one public
  wrapper (`api/libheif/heif_image.cc:403`) and six encoder plugins
  (`encoder_x265.cc:1139`, `x264:1022`, `kvazaar:690`, `svt:1055`,
  `uvg266:689`, `vvenc:673`), with no decoder, demuxer or metadata-reader
  call site; the only other mention is a comment at
  `image/pixelimage.cc:733`. W161-W184 all reached the write through the
  decoder-to-x265 re-encode path. Only x265 is built in this lab, so the five
  sibling encoders are unmeasured source alternatives. No run, input, wire,
  pointer, command or witness; grade stays rungs 3-4, NO rung 5. Receipts:
  `reports/libheif2shell-status.md` § W186 and
  `lab/frontier/libheif2shell/real/PROVENANCE-real.md` § W186.

## 2026-11-24 07:1x–07:4xZ — source audits, wire TERM, real-file and GUI limbs

These recipes extend already-admitted lanes. No new route, window or role;
the only rung cell that moves is LibRaw R4 (W187/DM 3405). Witness verdicts
are named at their exact scope; everything else is author/source-only. Where
the lane-index row still carries an older ceiling, this section supersedes it.

- **Munt W180, in-tree `parseStream()` length audit (`e4430ca`)**: read
  `lab/frontier/munt2shell/real/in_tree_call_lengths.md` against the pinned
  `libmt32emu_2_8_3` tarball (sha256 `81f8c462…faef875`, verified in
  `PINS.sha256`). Bounded non-test callers: ALSA `alsadrv.cpp:1182` (5572
  measured), OSS `OSSMidiPortDriver.cpp:95` (`BUFFER_SIZE=1024`), Win32
  `Win32Driver.cpp:135` (0x8000 ring minus 8-byte header = 32760) and `:383`
  (4096-byte `MIDIHDR`). Two unclamped local paths remain:
  `mt32emu_qt/src/mididrv/CoreMidiDriver.cpp:34-36` forwards 16-bit
  `packet->length`, and `mt32emu_win32drv/src/winmm_drv.cpp:320-324` forwards
  application `midiHdr->dwBufferLength` through public `MODM_LONGDATA`. Both
  parsers inherit the vulnerable `MidiStreamParserImpl::parseStream()`; neither
  host exists on this Linux workstation, so both are unbuilt and whether they
  can emit >32768 bytes is UNKNOWN. Source-only correction to the report's
  earlier "no consumer in this tree" wording; no run, bytes, witness, command
  or grade change.
- **Vrpn W25, stock `-O0` negative-index sweep (`ed9d7c7`)**: from
  `lab/frontier/vrpn2shell`, run `probe-func-dos.sh` + `wire_inject.py` with
  the plain vulnerable binary (`build-plain-07.36`, sha256
  `5cf49457…340bd74`) in one fresh loopback process per index on ports
  15200-15221; gdb maps use `probe-frame-write.sh` on 15300-15306. Sweep
  -1,-2,-4,-8,-12,-16,-20,-24,-32,-40,-48,-56,-64,-72,-80,-96,-112,-120,-128:
  only -4 and -8 are `DEAD_AFTER_MESSAGE exit=139` (SIGSEGV); every other
  index stays ALIVE. Fixed `-O0` (`build-plain-fixed`, sha256
  `10e581e8…ea2f45`) -8/-16, TYPE fixed -4 and safe in-bounds 4 stay alive.
  `out-w25-gdb-4/gdb.log` maps -4 to byte 4 of the live `endpoint` pointer
  (`0x5555556f3220` → `0x5500556f3220`, saved RIP unchanged, SIGSEGV at
  `vrpn_Connection.C:4560`), the same W3 primitive at a different byte;
  -1/-2/-16/-32/-64/-128 dumps are byte-identical already-zero frame bytes,
  and the -128 gdb continuation timed out after both breakpoints (UNKNOWN).
  Author self-observation, no chosen byte, new rung-4 boundary, command,
  witness or grade change. Raw `out-w25-*/` evidence and hashes: `PROVENANCE.md`
  § W25. Do not resweep this set on the same binary.
- **Codebasememory W4, source-bound WITH negative (`ff10d85`)**: read the
  pinned `src/cypher/cypher.c`. `with_add_vbinding_var()` (`:3585-3591`)
  stores projected items only while `vb->var_count < CYP_BUF_16` (16); both
  `execute_with_simple` (`:3673-3679`) and `execute_with_aggregate`
  (`:3642-3654`) call it, so WITH items 17+ are silently dropped and the
  48-item harness query returns 1 row / 1 column. ASan vulnerable stays clean
  at 48/64 WITH; the fixed build rejects >32 with query rc -1. No new run,
  WITH-side WRITE, witness, pointer, command or grade change
  (`reports/codebasememory2shell-status.md` § W4).
- **LibRaw W3/W4, file-steered halfwords (`949f138`, `be36dec`)**: from
  `lab/frontier/libraw2shell`, run
  `python3 craft_whitelevel_poc.py evidence/nonzero-oob.input OUT 4095`.
  The generator (sha256 `ab5ace42392c8558d4c939d1524a9ffb29a112acb021b8141ce9a0dd8b30d1cf`,
  verified locally) rewrites one little-endian u32 DNG WhiteLevel at file
  offset `0x102` in the W2 source (`b59f64e9…69341`), leaving the IFD and
  JPEG strip intact. Derived inputs WL2048/4095/8191/16383 have sha256
  `d398d0e7…35f5` / `8d9b5204…b905` / `50c91fbb…e42b` / `2547a078…bc8`
  (all six hashes recomputed locally and matching `PINS.md`). Plain `-O0`
  gdb breakpoint `xtrans_demosaic.cpp:427` with index >= 68,644 gives
  `IDX=68644 delta=0` and after-store words `0xffff 0xea99 0xffff 0x0000`
  (WL2048), `0xafdf 0x7544 0x9c55 0x0000` (WL4095),
  `0x57ec 0x3a9f 0x4e27 0x0000` (WL8191),
  `0x2bf5 0x1d4f 0x2712 0x0000` (WL16383), recorded in the four tracked
  `evidence/gdb-whitelevel*.txt` transcripts. WL4095 controls: ASan
  vulnerable `-n 1` rc 1 `WRITE of size 2` at `:427`, 0 bytes after a
  550,176-byte region; fixed rc 0 empty; vulnerable without `-n` rc 0 empty.
  Witness W187 (DM 3405) replayed W2's saturated `0xffff` write and upgraded
  R4 from PARTIAL to demonstrated chosen-nonzero-halfword; witness DM 3413
  regenerated the generator and all four inputs in a clean room, `cmp` showed
  exactly one changed u32 (255 → 4095), and graded the steering claim
  ESTABLISHED AS LABELED: three distinct non-saturated halfwords at the chosen
  offset, NOT arbitrary 16-bit values. No real camera file, GUI, network,
  pointer/IP, command or r5; fixed control is the reporter's patch only.
- **Synchronet W3/W4, wire TERM (`fe8cb5c`, `559d495`, `86ed83c`, `0e66d24`)**:
  `bash lab/frontier/synchronet2shell/wire/run-wire-proof.sh` drives a
  loopback OpenSSH 9.6 pty-req with TERM=64 through the vendored cryptlib
  getter; expect rc 0, **PASS=10 FAIL=0**, `READER TERM status=0 len=64`,
  chosen `0x54` at offsets 0/44/48/52, ASan
  `stack-buffer-overflow WRITE of size 64` in `memcpy` via
  `attributeCopyParams → getAttributeFunction → sessionMessageFunction →
  cryptGetAttributeString → reader_thread ssh_server7.c:124`, and clean
  40-byte and `cb6d77dbca` fixed-form controls. W2's `-43` was a probe
  artefact (reader blocked in `cryptPopData`; channel deselected after a read
  timeout), preserved as a negative. The author clean `git archive fe8cb5c`
  replay with gitignored `src-tree/` symlinked in matched 10/0. Witness wake
  189 (DM #3427) re-archived `fe8cb5c`, verified 8/8 `PINS.sha256`, rebuilt
  `libcl.a` (sha256 `584494acfcd7c531878fb951c848a97b8a9a84960f1ff477935303cae952e3c2`,
  a gitignored artifact), replayed the unmodified script at 10/0 and graded
  rungs 1-4 ESTABLISHED at the labeled synthetic-struct scope with a
  counterexample TERM of 44x`A`+`MISH`+`E-OO`+`TAUFTAUF`+4x`Z` giving
  `line_delay=0x4853494d`, `console=0x4f4f2d45`, `wordwrap[0..7]='TAUFTAUF'`.
  Witness NITs: `CRYPT_SSHOPTION_NONE_AUTH` is forced in the probe, and the
  fixed-form control covers only the patched copy inside a 1000-byte-padded
  struct. W4's real-build feasibility probe is a tooling negative: direct
  `g++ -fsyntax-only` of `src/sbbs3/answer.cpp` fails on auto-generated
  `jscpucfg.h` and MSVC-only `__int*` in mozjs headers, and `make -C src/sbbs3
  -j2` fails with `autoconf-2.13 not found` then `zip not found in $PATH`;
  real `sbbs3`/`answer()` needs local provisioning only. No measured DoS,
  pointer/IP, command or r5; no host packages were changed.
- **OpenEXR W177, partial-overwrite survivability negative (`4a66f9f`,
  `2f1554d`, `40aeb08`)**: from `lab/openexr2shell-real`, run
  `sh harness/partial-length-check.sh`. It first regenerates
  `cases/baseline.exr` with `./bin-vuln-plain/gen_baseline` and asserts sha256
  `07edcb58a3f2d63eedb5f746229f83dfc879981bf8a9d9cdf66df43a4cd6eb8e`, so a
  clean archive needs no external EXR, then asserts PoC hashes
  `5a831920…2ddf689` (a66.exr) and `d50e9d95…29ebc41` (b67.exr). Sweep S=17..512
  (`bitSize=4*S`, 68..2048-byte copies into a 64-byte destination): S=66
  (264 bytes) rc 1 `DECODE rv=31 EXR_ERR_INVALID_SAMPLE_DATA`, S=67 (268
  bytes) rc 134 `free(): invalid pointer`, 3/3 each; guarded allocator
  `changed=200` / `changed=204` equals `copy-64` exactly. Normalized gdb
  transcripts (`ebe5043b…de3b3b3b`, `34bedc0f…fe369b`, both recomputed
  locally from tracked evidence) show `SINK n=264/268 src_minus_dst=304`,
  `LIVE-PTR-COUNT scanned=11 inside=1` with only `decode.unpacked_buffer
  off=+0` (the destination), and `BEFORE`/`AFTER dst+272=0x42`/`0x43`,
  `dst+304=0x4141414141414141` unchanged. `RESULT PASS` three times in-tree
  and once from clean `git archive HEAD` at `2f1554d` (symlinks to gitignored
  `src/`, `build-vuln-plain/`, `bin-vuln-plain/`). The check uses equal-length
  input paths: a longer path makes even S=66 abort, a preserved caveat. Both
  copies stop short of W171's live scratch pointers; no survivable copy
  reaches one, no pointer/IP/command, no grade change, rung 5 UNKNOWN. OIIO
  was separately closed as a static-source negative by W173.
- **FLTK W5, real X11 GUI consumer (`67436e5`)**: from
  `lab/frontier/fltk2shell/gui-consumer`, `sh build.sh && sh run.sh` against
  the prebuilt plus1632/plus1647 ASan trees. `run.sh` starts its own
  `Xvfb :177 -screen 0 640x480x24 -nolisten tcp` (refuses if occupied), then
  attaches a benign 2x8 BMP to an `Fl_Box` in a real `Fl_Double_Window` and
  pumps five `Fl::wait(0.05)` cycles; all four cases print
  `GUI RESULT shown draw_count=1 safe=2x8 depth=3` before the crafted load.
  Expect `vuln-crafted rc=134` with ASan `WRITE of size 1`, 2 bytes before a
  4294967298-byte region at `Fl_BMP_Image.cxx:490` via `:64` →
  `fl_images_core.cxx:99` → `Fl_Shared_Image.cxx:304`/`:144`/`:594` →
  `gui.cxx:46`, and rc 0 for vuln-safe, fixed-crafted and fixed-safe. Input
  pins: `135edc0a…13008` (poc-chosen.bmp), `031fb41f…99cb0a6` (safe.bmp),
  `b84e070c…853bc` (gui.cxx, confirmed by a fresh local `sha256sum` and the
  tracked `inputs.sha256`). Receipt-keeping NIT: the same directory's README
  quotes a different `gui.cxx` hash (`bb7e4c23…da0da0`); that receipt needs
  the FLTK author's repair and neither hash is asserted here beyond the
  recomputed local value. The fault is at image load, before draw; author-only
  and UNWITNESSED — witness #3296 covers only the four-tree direct-call
  matrix. ICO is a measured negative; no cache-hit reload, wire, pointer/IP,
  command or rung 5.
- **FontForge W2, chosen bytes in the real `Import()` process (`1f26ade`)**:
  two plain Debug trees with `-DENABLE_SANITIZER=none` (`build-plain/`,
  `build-fixed-plain/`). Run `gdb -batch -x gdb-real-plain.cmd
  ./build-plain/bin/fontforge` with the pinned 296-byte `truncated.pcf`: a
  hardware watchpoint on `*(int*)((char*)encs-4)` shows `glyph=-1, i=3`,
  `Old value = 0`, `New value = 5458253` (`0x53494d`) and
  `x/4xb &encs[-1]` = `4d 49 53 00` (three chosen bytes; the fourth is zero
  for these field values). Plain vulnerable rc 134 `double free or corruption
  (out)` (`3021d38c…c53f`), patched rc 0 (`60f02f95…e482`), vulnerable
  complete-table rc 0 (`ce8173e7…4eaf`); transcript `gdb-real-plain.out`
  sha256 `8d704e5d…35431`. The ASan-binary gdb attempt is a preserved
  negative: it reached `glyph=-1` and printed RHS `0x53494d` but never
  exposed a post-write byte. Author-only, UNWITNESSED; #3309's ESTABLISHED
  scope is the direct-call/in-memory-table/stand-in-struct matrix. GUI
  `Import()`, other loaders, pointer/IP, command, ASLR/grooming and r5
  UNKNOWN.
- **FontForge W3, glibc chunk-size consumer (`88d6c5e`)**: from
  `lab/frontier/fontforge2shell`, `CONSUMER.md` records the plain real-build
  gdb run (`gdb -batch -x gdb-consumer-plain.cmd ./build-plain/bin/fontforge`):
  the four bytes at `encs-4` are the high half of the size word of `encs`'s own
  malloc chunk, changing from `0x21` to `0x0053494d00000021`; the breakpoint at
  `fvimportbdf.c:1770` catches `free(encs)` reading that header immediately
  before the glibc abort, while `gdb-header-fixed.out` and
  `gdb-header-complete.out` keep `0x21` and exit normally. Metadata corruption,
  not a pointer primitive. `0912800` measured a silent variant: `zero-write.pcf`
  (sha256 `f20ef994…08b5d`) carries value zero, the size word stays `0x21` and
  the plain build exits 0 (`plain-zero-write-import.out`), while ASan still
  reports `WRITE of size 4` at `:1751`; `gdb-zero-write-post.out` shows
  `00 00 00 00` at `encs-4` and an intact `0x21` at `free(encs)`. An earlier
  `zero-value.pcf` attempt with `min2=max2=0xfffd` is a preserved negative
  (`getformint16()` does not sign-extend). Some other plausible 64-bit chunk
  size remains UNKNOWN; author-side and unwitnessed, no claim beyond rungs 1-4
  and no rung 5.
- **Jq adjacent advisory disposition (`2bcdde2`)**: operator DM #3419
  (07:37Z) screened GHSA-cfh2-vwfq-qfmm (`--rawfile` invalid-state reuse after
  a handled "String too long", High 7.1, affected `<=1.8.1`, fixed 1.8.2)
  **NOT admitted**: file-facing path, no advisory RCE claim, and the published
  sparse-file PoC needs ~4.2 GB peak RSS against this slice's 2 GiB guard.
  No seed wall, charter, staged replay or window; a named negative, not a
  research result. `cd lab/frontier/jq2shell && sha256sum -c PINS.sha256`
  (paths are lane-relative) gives 14/14 OK. No build, large run, guard
  change, replay or grade change. Re-offer only with a measured lower-memory
  trigger or a web-reachable vector plus standing-#6 replay.
- **Cjose W191 replay-delivery repair (`32b39fa`)**: the commit changes only
  `lab/frontier/cjose2shell/PROVENANCE.md` § W191. The optional replay offers
  from W186 (#3105), W187 (#3141) and W188 (#3232) had no verdict and were
  absent from the witness wall's open items, so each was re-delivered once as
  chat #3429 with commits, recipes and the unchanged rung-4-only ceiling.
  No new experiment, build, input, listener, hash, witness verdict or grade
  change; W184's mod_auth_openidc negative alone is witness-ESTABLISHED
  (#3079), and author results are never acceptance.

## 2026-11-24 07:1x–09:2xZ — staged stbvorbis, offset steering and clean replays

### StbVorbis2Shell W201 (FRONTIER-STAGED, `lab/frontier/stbvorbis2shell`)

CVE-2026-89266 (VulnCheck, 2026-09-11), CWE-787, stb_vorbis <= 1.22; fixed
only on the dev branch as of this date, so the numeric fixed release is
UNKNOWN. Vulnerable pin: `https://raw.githubusercontent.com/nothings/stb/2c980bb59875b0d32144a71867fbdebb2f77cd20/stb_vorbis.c`, sha256
`4c7cb2ff1f7011e9d67950446b7eb9ca044f2e464d76bfbb0b84dd2e23e65636`.
Fixed control: the dev-branch `stb_vorbis.c`, sha256
`daedcc5ca51d5af8e910816d30ac6d791c4c0364ea5c8c7625bff429371e86a5`,
carrying `CODEBOOK_LIMIT (1<<18)` and a guard at line 3815. All four hashes
were rechecked locally with `sha256sum`. Build and run:
`cd lab/frontier/stbvorbis2shell && sh run-all.sh` (offline, loopback only):
builds -O0/ASan/plain vulnerable and fixed harnesses, regenerates both PoCs
and prints 9 PASS / 0 FAIL, rc 0. Expected bytes: ASan
`heap-buffer-overflow WRITE of size 4` at `stb_vorbis.c:3889` in
`start_decoder`, 0 bytes after an 8-byte `setup_malloc` region from line 3880
(`4 * 16519105 * 65 = 2^32+4`, truncated to `int` 4); fixed build rc 0 with
no report; gdb at the third write reads `val` and stored word
`0x4b434148` ("HACK"). PoC hashes: `exploit.ogg`
`e3ec321924803dced6a9cd1b30202f02770982836995d73686cbc87fe6c0b793`,
`chosen.ogg`
`31c4686a65b13f2303f6d0e39020c8390fda1a5f81c2d4e997ddaae3aa86050d`
(both 205 bytes, tracked); `evidence/*.out` are gitignored and regenerated
by `run-all.sh`; full log and negatives in `PROVENANCE.md`. This is rung 4
PARTIAL at a repeating 4-byte word and one offset; write count, real
consumer, wire, pointer, command, witness verdict and r5 are UNKNOWN. Window
135 is live but there is no charter or wake unit: FRONTIER-STAGED, mind count
unchanged at 130.

### Openexr2Shell W180 — file-steered destination offset

Affected 3.5.0–3.5.2 / fixed 3.5.3 as in the row above; no new pins. From the
repo root, `cd lab/openexr2shell-real && sh harness/offset-steer-check.sh`
with the gitignored pinned build trees and `src/` symlinked from the live
tree. The generator sizes both chunk leader and inner ZSTD frame to 2N;
N=32 stays byte-identical to the older case
(`484b1c35…593a52`, `efb6bbd2…f033b`), N=64/128 give
`41f840cb…106a6`/`a0d8c886…ce03b` and
`38767b7e…01bc`/`9f716aec…b8f0`. Expected: vulnerable plain writes
128/256/512 changed guard bytes at `decode.unpacked_buffer+4N` for
N=32/64/128, gdb reads `0x3c`/`0x5a` fill at each offset, fixed returns
`DECODE rv=23 EXR_ERR_CORRUPT_CHUNK` with zero changes; result `RESULT PASS`
three times in-tree and from `git archive 9f42ba6` with all 16 normalized
hashes identical (`7393c9d4…`, `762110cb…`, `62e2a8fd…`, `f1ec8eda…`,
`234c689e…`, `8997f403…` in `reports/openexr2shell-file-level.md`). Negative:
changing only N while keeping the 64-byte frame gives rv=23 and no write.
Evidence `evidence/offset-*.out` is gitignored and rebuilt by the check;
author-only, unwitnessed, no r5.

### Imgproxy2Shell W5 — live tcache pointer under grooming

Pinned imgproxy 4.0.15 / fixed 4.0.16 and the pinned libvips build as in the
row above. The probe is
`lab/frontier/imgproxy2shell/provision/ico_gdb_groom.py`, sha256
`571ae9496da846f6e29ff03dd2577cc99d7077ecd41b86f5738d8d4f9aa62a82`
(rechecked locally); run it from `provision/` as recorded in
`PROVENANCE.md` W5, e.g. `python3 ico_gdb_groom.py ./imgproxy-vuln
../../libvips2shell/build-vuln-plain/libvips w5final1 2
rs:fill:16:16/plain/hostile.ico 12 30 ptr`, with the fixed binary in place
of `imgproxy-vuln` as the control. It binds only 127.0.0.1:18080/18081,
sends benign favicon GETs before the hostile ICO in one process under gdb
and dumps quadwords at `data-16`. Expected in `ptr` mode: a free tcache
chunk's `next` at `actual_data+18` becomes chosen
`0x4141414141414141` while size `0x35` is preserved and the next
`malloc(0x20)` consumes the victim; fixed returns HTTP 500 and never hits
the breakpoint. Grooming is stochastic (3/6 preloads; clean archive replay
at `4c4937d` succeeded at preload=6 and hit the top layout in five
preload=2 runs). The `provision/http-ico-*.log` files are tracked; gdb
transcripts and digests are in `PROVENANCE.md` W5. No mapped target, write
through the pointer, marker or command; author-only, unwitnessed, rung 4.

### Cjose2Shell W192 — clean-archive replay of the groomed fptr lane

Pins, build and `check.sh` recipe are in the row above. Extract
`git archive 1212b10ee808b2ad3b3af6d080222f5157fc78b4`, then
`bash lab/frontier/cjose2shell/harness/bootstrap.sh`,
`bash harness/check.sh` (expect `PASS=223 FAIL=0 trace=455b8494…338e9da7`)
and `bash fptr/run.sh`. Expected: vulnerable `fptr` prints `GROOM_OK=1`,
`CEK_LEN_AFTER=768`, `BENIGN_MARKER_EXECUTED`, `MARKER_CALLED=1`;
vulnerable `fptrsafe` and both fixed scenarios print `MARKER_CALLED=0`,
5/5 vulnerable and 0/3 fixed marker calls in a fresh batch. Four raw
outputs match `fptr/evidence/` after hex-address normalization; normalized
hashes `9fa71d7a…a76c5` (vulnerable-fptr), `abac92e5…a031c5` (both safe),
`6d738f8b…700c98` (fixed-fptr). Author replay, not witness acceptance; no
wire-derived address, command or r5.

### Codebasememory2Shell W5 — tool-path replay from a clean tree

Affected `<0.9.0` / fixed `0.9.0`, four pins in
`lab/frontier/codebasememory2shell/PINS.sha256` as in the row above. From
the repo root, `git archive HEAD | tar -x -C /tmp/cbm-replay`, copy the two
hash-verified tarballs into the fresh tree's `pins/`, then
`bash lab/frontier/codebasememory2shell/mcp-tool/replay.sh` (at HEAD
`4c353c3` the script fix was substituted from the working tree). Expected:
4/4 pins OK; `vuln-asan` N=33/48 rc=1 with ASan `READ of size 8` at
`cypher.c:2568`; `vuln-recover` N=33/48 rc=0 with `WRITE of size 68` at
`project_item:3379` and the chosen `MISHE_OO…` name; `fixed-asan` clean.
The three row logs and both recover `-Q33.err`/`-Q48.err` files match the
canonical hashes after normalizing only volatile tokens (root path, timing,
ASan PIDs/addresses/BuildId, stack dumps). Raw artifacts are gitignored and
regenerated by `replay.sh`; local stdio only, no witness verdict or r5.

### Receipts

FontForge W3's `zero-write.pcf` replay (`0912800`, documented in
`reports/frontier-fontforge2shell.md` and its `CONSUMER.md`) keeps the chunk
size at `0x21` and the plain build clean while ASan still reports
`WRITE of size 4` at `fvimportbdf.c:1751`; `gdb-zero-write-post.out` shows
four zero bytes at `encs-4`. FLTK W6's `27ef17b` repairs the receipt's
`gui.cxx` hash to `b84e070c…853bc`, matching `inputs.sha256` and a local
`sha256sum -c` (3/3 OK). Neither adds a verdict, rung cell or mind-count
change.

### LibRaw2Shell W6 — one exact chosen halfword (author-side)

Same pinned 0.22.3 / reporter-two-line fixed control and the W3 harness as
in the LibRaw row above; generator `craft_whitelevel_poc.py` is pinned at
`ab5ace42392c8558d4c939d1524a9ffb29a112acb021b8141ce9a0dd8b30d1cf`.
From `lab/frontier/libraw2shell`, run
`python3 craft_whitelevel_poc.py evidence/nonzero-oob.input OUT 11036`
(input sha256
`b59f64e9837b06a8f0ca07a3776e961e7d0493794e0d6cb38fbcb80022069341`);
the output is byte-identical to `evidence/wl-probe-11036.input`, sha256
`b856c1c62d48a63f9c3d42a4d32be11033c0dc405fcbcc063f6b9ddaa6d61215`
(recomputed locally). Under a plain `-O0` gdb breakpoint at
`xtrans_demosaic.cpp:427` the OOB store at index 68,644 reads
`0x4141 0x2b82 0x3a00 0x0000`, stable 3/3 in fresh plain `-O0` gdb runs; the ASan vulnerable tree with `-n 1` reports
`WRITE of size 2` 0 bytes after the 550,176-byte region (rc 1), fixed rc 0,
vulnerable without `-n` rc 0. Bracketing WL 11,035/11,037 gives
`0x4142`/`0x413f`; a second target `0xdead` at WL 3,234 gave `0xdeb3`,
with WL 3,233–3,236 stepping ~18 per unit. Two further pre-chosen targets
also missed: `0x1234` at WL 39,560 gave `0x1232`
(`evidence/wl1234-39560.input`, sha256
`a6886f0be95480efbab3fdbc2fdc98a0a7dafc0f6879cfeb805f1099677683b4`) and
`0x2222` at WL 21,098 gave `0x2220`
(`evidence/wl2222-21098.input`, sha256
`4a1eed482ee63601a932ffc47b61027a1e83dc0cd8450f00476cc3d01a982620`).
All negatives are preserved. GDB logs and control outputs are in `evidence/`
and `PINS.md`; the binary `.input`
files are gitignored and regenerated by the generator. One exact value, not
an arbitrary 16-bit alphabet; author-side only, unwitnessed, no pointer,
wire or r5.

## 2026-11-24 12:1x–12:3xZ — awslc natural dispatch and libraw heap extent

### AwsLc2Shell W204/W205 — natural-alignment indirect dispatch (author-side)

Same pinned AWS-LC v5.6.0 vulnerable/fixed tarball and `cipher.c` hashes as
the AwsLc2Shell lane row above. From `lab/frontier/awslc2shell`,
`sh build-consumer.sh` then `sh run-consumer.sh` -> `RESULT: 31 PASS / 0 FAIL`
in tracked `consumer-replay.log` (23 earlier PASS plus eight `natural_call_*`);
`sh run-all.sh` -> 14 PASS / 0 FAIL in `replay.log`. W204's `natural_tag` is a
report-only one-byte-tag layout in which the OOB byte lands on a pointer LSB;
W205's `natural_call` has `scratch[31]` at offset 1 and a table-slot pointer
at offset 32 in a normally aligned struct (no `#pragma pack`). Expect
vulnerable low byte `0x00` -> `0x48` with `BENIGN_MARKER_EXECUTED` and layout
`scratch_off=1 handler_off=32 oob_byte=0x48`; fixed and safe-input (`00`)
print `NORMAL_HANDLER` with no marker; no ASan report because the byte lands
inside the enclosing allocation. Throwaway GCC 13.3.0 layout probes
(`-fstack-protector-strong -fno-omit-frame-pointer -O0`) found OOB index 31 at
rbp-0x11 and the canary at rbp-8; array sizes 1..31 and `aligned(1..8)` did
not close the 9-byte gap, so no natural stack-canary hit. All logs are
tracked; no independent witness replay of W204/W205 (W195's verified consumer
covered the earlier scope), the aligned dispatch table is lab grooming, and
no rung cell, real consumer, command or r5 is claimed.

### LibRaw2Shell W8 — plain-build heap extent (structural negative)

Same pinned LibRaw 0.22.3 tarball, reporter two-line fixed control and W3
generators as the LibRaw lane row above. All three inputs used here are
tracked under `evidence/`. From `lab/frontier/libraw2shell` with the plain
`-O0` build (`o0/LibRaw-0.22.3/bin/dcraw_emu`), the W8 gdb scripts in `w8/`
break at `xtrans_demosaic.cpp:427` on `evidence/dim1024-wl24601.input`:
`destimage=0x55555573abc0`, requested `allocate_sz=2,146,592`
(`(512+6)^2*8`, end `0x555555946ce0`), `malloc_usable_size=2,147,624`, chunk
size 2,147,632 ending `0x5555559470f0`; the walk finds one 134,944-byte free
top chunk ending at the `[heap]` boundary `0x555555968000`
(`w8/heapwalk2-dim1024.txt`, `w8/mallocstat-dim1024.txt`,
`w8/map-dim1024.txt`). With the breakpoint deleted, stores continue 17,378
indices to `IDX=285,702`, `SIGADDR=0x555555968bf0`, backtrace `:427` <-
`dcraw_process():184` <- `dcraw_emu.cpp:598` (`w8/segv-dim1024.txt`). Plain
no-gdb `-n 1` runs of `nonzero-oob.input`, `whitelevel4095.input` and
`dim1024-wl24601.input` all exit 139 with empty stderr (`w8/plain-rc.txt`);
an initial rc=0 loop was a shell `$?` capture error, preserved in that file
and never published. No live allocation or pointer lies between the buffer
and the fault, so this is a structural negative: author-side, unwitnessed,
no new rung or primitive.

CodebaseMemory W7 (`0f98a70`) only folded the previously published local
stdio `query_graph` tool-path reach into the frontier brief; the row and the
addenda above already carry that claim, so no docs passage was stale (doc-ok).

### Imgproxy2Shell W6 — glibc safe-linking bound (author-side negative)

Same pinned imgproxy 4.0.15 / fixed 4.0.16 and libvips builds as the Imgproxy
row above; glibc here is 2.39. The probe
`lab/frontier/imgproxy2shell/provision/ico_gdb_tcache.py` has sha256
`95326911b40a37fb9e6b72a9acfe7cb3a683005da906f571a690eb399c9fcb55`
(recomputed locally). From `provision/`, with the pinned binaries and libvips
in place, the three cured runs are:

    python3 ico_gdb_tcache.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips w6v9 2 0x61000000 30
    python3 ico_gdb_tcache.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips w6v27 2 '($pos + 0x10)' 30
    python3 ico_gdb_tcache.py ./imgproxy-icofixed \
      ../../libvips2shell/build-vuln-plain/libvips w6fixed1 2 '($pos + 0x10)' 30

Only loopback ports 18080/18081 are used. At the wrapped-size
`vips_foreign_load_read_full` breakpoint the probe reads the live tcache `next`
at `actual_data+18`, decodes `ptr ^ (pos >> 12)`, patches an encoded target and
calls `malloc(0x20)` twice from the inferior; the patch and both mallocs are
debugger-forced, only the ICO body arrives over the wire. Expect W5's decoded
live `next=0x7fff7c03ec70` but its raw wire value `0x4141414141414141` to
decode noncanonically; with the unmapped `0x61000000` target the first malloc
returns the victim and the second faults in `tcache_get_n`
(`http-ico-w6v9.log`); with a mapped heap-derived target the second malloc
returns exactly that address (`http-ico-w6v27.log`,
`http-ico-w6v30.log`). The fixed control returns HTTP 500 `ICO image data is
too large` with zero breakpoint hits (`http-ico-w6fixed1.log`). Full log
digests and the preserved unmapped/negative runs are in `PROVENANCE.md` W6;
heap addresses vary and no wire-only safe-link key is established. No
code-pointer write, marker, command or witness verdict; no rung cell moved.
A clean-archive replay at `314fa5d` reproduced the mechanic in 2 of 7 layouts,
with the second `malloc(0x20)` returning the chosen heap-derived address twice
and the fixed binary answering HTTP 500 with zero breakpoint hits; five
top-chunk or live-data layouts are preserved as negatives and the throwaway
tree and replay logs were not retained (`PROVENANCE.md`, 12:31–12:33Z).

### Munt2Shell W182 — post-overflow second-call reuse (negative, replayed)

Same pinned `libmt32emu_2_8_3` / fix `1749f7fe` tarballs and static libraries as
the Munt row above; build the plain libraries with `real/build_and_run.sh`
first. From `lab/frontier/munt2shell/real`, `./reuse_probe.sh` drives the real
pinned library through the public API with a first oversized block, `0xF7`, a
second differently chosen 40,001-byte block, `0xF7`, then a complete 102-byte
SysEx; the 16384-byte `new[]` tail is a harness observation region, not an
upstream object. Expect all six modes (`vuln-repeat`, `vuln-safe`,
`vuln-baseline`, `fixed-repeat`, `fixed-safe`, `fixed-baseline`) rc=0; the
second 40,001-byte call writes zero new bytes, `tail_0x37` stays 0, each `0xF7`
increments the debug counter without dispatch and the complete SysEx still
dispatches (`sysex=1`, `lastlen=102`). Raw outputs are the six tracked
`real/evidence/reuse-*.out`. The author clean-archive replay at `baa31e6`
rebuilt from `git archive HEAD lab/frontier/munt2shell` with the ignored tarball
copied in and all six outputs sha256-identical (digests in `REPLAY.md`); it is
an author replay, not the witness verdict. No held-state reuse, new consumer of
the forged tail, pointer, marker, command or rung change; rungs 1-4 ESTABLISHED
and r5 UNKNOWN stand.

### Imgproxy2Shell W7 — no wire-visible heap-leak key (author-side negative)

Same pinned imgproxy 4.0.15 / fixed 4.0.16 and plain libvips builds as the
Imgproxy row above; host glibc 2.39, ASLR 2. The probe
`lab/frontier/imgproxy2shell/provision/ico_readfull_bound.py` is sha256
`e422a59974088057b0f89a4629c5f3526f87dac04bc9aab7163298ef8de48140`
(recomputed here). From `provision/`, with `imgproxy-vuln` and
`../../libvips2shell/build-vuln-plain/libvips` in place:

    python3 ico_readfull_bound.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips w7final-pattern \
      rs:fill:16:16/plain/pattern.ico 8
    python3 ico_readfull_bound.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips w7final-pngvalid \
      rs:fill:16:16/plain/pngvalid.ico 8
    python3 ico_readfull_bound.py ./imgproxy-vuln \
      ../../libvips2shell/build-vuln-plain/libvips w7final-pnglie \
      rs:fill:16:16/plain/pnglie.ico 8

Only 127.0.0.1:18080/18081 are used. Expect each process to abort in 13-17 ms
with `rc=2`, `malloc(): corrupted top size`, and no HTTP response; tracked log
hashes, recomputed here, are `017b0b48b8d207cbbc0bb3d6e6e440ce0430932d63796999c7b2be09a1d8a380`
(pattern), `a4c5193041fce665ee1fd6dd82dfd6c4d7dce0813b0ac2485a96e02599cbb52a`
(complete 1x1 PNG) and `0f16c0989715a9f49a9f700fac4907c6931f2968b3a98ebc936cd41ebde09ed6`
(IDAT declaring 4096 bytes). Pinned `vips/vips.c:1302-1315` consumes the full
requested length before returning 1, so `icoload.c:161-164` exits before the
PNG test and BMP reconstruction; no consumer turns spill bytes or the tcache
`next` safe-link key into response bytes, and the error-path source review
found only fixed messages and request-derived echoes. A clean
`git archive 6f8581a7` replay reproduced the pattern and PNG legs (the
initial harness-path failure is in PROVENANCE W7). Author replay, no witness;
no rung change, r5 UNKNOWN.

### Openexr2Shell W184 — fully file-chosen second-stage OOB copy

Affected 3.5.0–3.5.2 / fixed 3.5.3 as in the row above; no new pins. From
`lab/openexr2shell-real`, with the gitignored `src/`,
`build-{vuln-plain,vuln-asan,fixed-asan}` and
`bin-{vuln-plain,vuln-asan,fixed-asan}` trees present, run
`sh harness/mixed-full-check.sh`. The generator
`cases/make_poc_mixed_full.py` is sha256 `258cdc5ebb25aea374cb4748a186b91d7aec209498fd25ecd0522ca650910164`
and the check script `harness/mixed-full-check.sh` is sha256
`0fc148a167bf24be34233c8e0873e306c8c28a7d7acbc6c002b29d78bf1a1eb0`, both
recomputed here. Expect `RESULT PASS` and the trace
`SINKCOPY dst_off=0 src_off=128 n=256` followed by
`SINKCOPY dst_off=256 src_off=0 n=128`, with
`GUARD-CHANGE alloc=24 size=256 changed=128 first=+0`, actual `0x3c`/`0x5a`
and all 128 bytes at `decode.unpacked_buffer+256` read back as that byte;
fixed 3.5.3 rejects with `EXR_ERR_CORRUPT_CHUNK` and the baseline guard is
unchanged. The nine `evidence/full-oob-*.out` hashes aggregate to
`d04f151a539362d22d58ec4c4e8c06c4ee0689fd88aa29c5824ba2e7becf946f` via
`sha256sum evidence/full-oob-*.out | sha256sum`, recomputed here. A clean
`git archive aad2c431` replay with the gitignored trees symlinked returned
`RESULT PASS` rc 0 with all nine hashes identical (receipt in `7288d1ce`).
Caveat preserved: the unguarded ASan build aborts earlier on the first copy's
OOB source READ at `internal_zstd.c:472`, so the WRITE is measured by guard and
gdb, not ASan. Author replay only, no witness, no rung change; no wire,
pointer, marker or command.

### Libheif2Shell W188 — ImageMagick HEIC sequence consumer (source-only)

Read-only source check, no build and no run. A gitignore-filtered search over
`lab/frontier` omitted vendored consumer trees; a `gitignore:false` retry
timed out at 30 s over 31 GB, so `find lab/frontier -type f -iname '*heif*'`
narrowed the candidates. The real sequence writer is
`lab/frontier/imagemagick2shell/vuln/coders/heic.c`:
`WriteHEICSequenceImage` is guarded by `LIBHEIF_NUMERIC_VERSION >= 1.20.0`
(`:2076`), `:2202-2205` creates the visual track from the FIRST frame's
`(uint16_t) columns/rows`, and `:2230-2349` loops the image list, creating
each frame at its own `:2292` size before `:2334`
`heif_track_encode_sequence_image`, with no size equality check. Negative
controls: `vuln/MagickCore/magick-baseconfig.h:1089 /* #undef HEIC_DELEGATE */`,
no libheif in `ldd` of either magick binary, no HEIC in `magick -list format`,
host `pkg-config --modversion libheif` 1.17.6 and no
`/usr/include/libheif/heif.h`. No delegate-enabled build, multi-frame encode,
ASan report, chosen bytes, witness verdict or rung change. A two-frame
512x64 → 64x65 encode is a hypothesis for a future bounded wake, not a claim.
Full notes: `lab/frontier/libheif2shell/real/PROVENANCE-real.md` W188 and
`reports/libheif2shell-status.md` W188.

### Lwnode2Shell (FRONTIER-STAGED) — WriteOneByte off-by-one

CVE-2026-135746 / GHSA-mvm7-rjgq-6j36, published 2026-11-24, CWE-787,
CVSS 3.1 6.8 `AV:L`; PR `Samsung/lwnode#188` base `b3de7be5c117…`, fixed by
PR head `442b6ebf…` / merge `6571beaf…`. No numeric release pin: the advisory
and `SECURITY.md` say the open-source branch is unmaintained. Claim URLs,
patch and source pins are in `lab/frontier/lwnode2shell/PROVENANCE.md`; the
tracked `src/api-data.cc` is sha256 `e4930859…5bf7b` and the verbatim loop
`91051bee…0b4`, both rechecked by every run. From the repo root:

    cd lab/frontier/lwnode2shell && sh run.sh

The script hash-checks the loop, builds ASan and plain harnesses with
`g++ -std=c++17 -O0 -g -fno-omit-frame-pointer -fsanitize=address harness.cpp -o asan`
(and the plain build without ASan), then runs vuln/fixed × attack/safe ×
asan/plain with fill bytes `0x48` and `0x5a`. Expect 12 PASS / 0 FAIL in
`replay.log` (sha256 `7cbf085f9471c09a3105900c8f2ccc4d546c06d7e266cae2bd007718399b237a`,
recomputed here): ASan `heap-buffer-overflow WRITE of size 1` 0 bytes past
an 8-byte destination, plain `byte8=0x48` / `0x5a` at the chosen
one-past-capacity offset, canary `0xcc` and no ASan report for the fixed and
safe cases. A clean `git archive ba01845c lab/frontier/lwnode2shell` replay
gave 12 PASS / 0 FAIL. Extracted loop with stand-in arrays only: no
lwnode/Escargot build, JS script, real `Isolate`/V8 API call, pointer, command
or r5. FRONTIER-STAGED — brief `reports/frontier-lwnode2shell.md`, no charter,
route, wake unit or mind-count change. Witness #3720 (clean `git archive
ba01845c`) replayed 12 PASS / 0 FAIL with exact pin and loop hashes, ASan
`WRITE of size 1` 0 bytes past the 8-byte destination, chosen byte at slot 8
and clean fixed/safe controls: ESTABLISHED AS LABELED, no grade change, NO r5.

### Fltk2Shell W199 — witness replay of four scoped extensions

Witness #3612 replayed the shared-image, both plain-metadata waves and the
GUI-consumer extension from a clean `git archive 27ef17b`: PINS 11/11 OK,
`run-all.sh` 33 PASS / 0 FAIL, normalized evidence hash `7882e60c…3525e`
byte-exact. From `lab/frontier/fltk2shell` the same legs are `bash run-all.sh`,
then `sh build.sh && sh run.sh` in `shared-image/`, the two `plain-metadata`
driver matrices in `plain-metadata/README.md`, and
`sh build.sh && sh run.sh` in `gui-consumer/` (private Xvfb). Expect ASan
`WRITE of size 1` 2 bytes before a 4294967298-byte region at
`Fl_BMP_Image.cxx:490`, the ICO negative, the plain metadata word
`0x2d4d495300001002`, and witness-varied `prev=0x2000` /
`size=0x3939315700001002` with the fixed tree at rc=0. Verdict: ESTABLISHED
AS LABELED for the four extensions, no contradiction, grade stays W195 rungs
1-4, NO r5. Crafted-image draw (the fault is at load, before draw),
cache-hit reload, wire, ASLR-independent target, pointer/IP and command stay
UNKNOWN. Full replay record: `reports/frontier-fltk2shell.md` W199.

### Libheif2Shell W189 — real ImageMagick consumer rejects mixed-size reach

Affected/fixed versions and pins as in the Libheif2Shell row above; no new
source pin. W189 supersedes W188's "no delegate build or run": ImageMagick
7.1.2-34 was built from `lab/frontier/imagemagick2shell/vuln` (read only)
against the pinned v1.23.6 static `libheif.a` and its `libheif/api` headers in
a `/tmp` tree. `configure` selected host libheif 1.17.6 despite the supplied
variables, so the generated Makefile library variables must be overridden on
the `make` command line; the exact flags are in
`lab/frontier/libheif2shell/real/neighbour/evidence/im-consumer/README.md`.
The final binary links no `libheif.so` and reports `HEIC rw+`. From that
evidence directory `python3 check_im_consumer.py .` checks committed bytes
only and returned 7 PASS / 0 FAIL here: `mixed-frames.miff` SHA-256
`73590bbd702820ebebba3c9e490f694fdbd5cfdcc1281f6ca92958eed71f392d`
(recomputed), both `heic-mixed.rc` and `avif-mixed.rc` are 0, and `heif-info`
shows 512x64 + 64x65 in both outputs; `.heic` gives two independent still
images, `.avif` two AV1 frames. Structural negative: `heic.c:2516-2547` takes
the sequence branch only for AVIF and `heic.c:2141-2142` selects AV1, while
pinned v1.23.6 calls `extend_padding_to_size` only in x265/x264/kvazaar/svt/
uvg266/vvenc and the public wrapper, not AOM. `gdb-padding.out` is NOT a clean
breakpoint negative: two static copies of libheif were linked. No ASan build,
crash, chosen bytes at the sink, pointer, command, witness verdict or rung
change. Full notes: `reports/libheif2shell-status.md` W189.

### Assimp2Shell W12 — explicit gcc optimization matrix

Affected through 6.0.6 / open PRs 6860 and 7090 as in the row above; no new
pins. A flag audit found the W10/W11 libraries were configured with
`-DCMAKE_BUILD_TYPE=Release`, whose `-O3 -DNDEBUG` is appended after the
requested `-O1`. From `lab/frontier/assimp2shell`, after `bash bootstrap.sh`,
run `bash harness/run-w12.sh`; it rebuilds the pinned library with an empty
build type and explicit `-O{0,2,3} -g -U_FORTIFY_SOURCE -DNDEBUG
-fno-omit-frame-pointer` (verbatim flags in `w12/evidence/o*-flags.txt`),
compiles the driver at the matching level and feeds the tracked `safe.gltf`,
`idxptr-zero.gltf` and `idxptr-addr42.gltf` through `ReadFileFromMemory`.
Expect 17 PASS / 0 FAIL in `w12/evidence/w12.log`: `VERDICT o2 PORTABLE` and
`VERDICT o3 PORTABLE` with `si_addr=0x41414141` / `0x42424242` in
`CopyVector<aiMesh>` at `glTFImporter.cpp:475`; `VERDICT o0 DIFFERENT`
(stack-canary abort before the dereference) and `scene=ok` for the safe input
at all levels. Chosen words in `w12/evidence/bytes.out` are `41414141` and
`42424242`. Normalized trace SHA-256
`f2f6d6ee18e2196706550b8de4a32840793b4eb7f25de4117e160f9d10c7d8af`
(recomputed here). Author clean-archive replay: `git archive 3f540a2e` into a
temp dir with the local pinned tarball copied in (no network), `bootstrap.sh`
rc 0, all three libraries rebuilt by the script, 17 PASS / 0 FAIL and a
byte-identical trace (`21916409`). Author-only, unwitnessed; W11's clang
negative stands, and there is no valid object or code pointer, marker,
control-flow redirection, command or r5.

### Synchronet2Shell W9 — custom pre-auth client cannot reach the copy

From `lab/frontier/synchronet2shell`, with the gitignored `src-tree` at pinned
parent `42f586d70792e46b4934176976bc7949b312dede`, run
`bash real-answer/noauth/run-preauth.sh` (script SHA-256
`5672214b38a5fc5dbd4ef4bf70832cc49eebd835ad89caf65ec8d36b58c7500a`,
recomputed here). It rebuilds `sbbs3` and drives a scripted paramiko 5.1.0
client over loopback only, with no authentication request before the pty-req;
the two-byte channel-open accommodation for cryptlib's parser is documented
in `reports/frontier-synchronet2shell.md` W9. Expect 9 PASS / 0 FAIL, zero
`REAL_ANSWER_PROBE` lines in `evidence-preauth/server-noauth.log` (checked
locally) and one in `server-anyauth.log`: without `SSH_ANYAUTH` the state
machine rejects channel establishment before the pre-auth TERM can reach the
copy, while the none-auth positive control writes `MISH`/`E-OO`/`TAUFTAUF`
bytes. A clean `git archive 60df1168 lab/frontier/synchronet2shell` replay
(gitignored `src-tree/` and `provision/` symlinked in) returned rc 0, 9 PASS /
0 FAIL and the same two probe counts; author replay, not an independent
verdict. No grade or rung change. Other builds or configurations with valid
credentials stay UNKNOWN.

## 2026-11-24 13:2x–13:4xZ — witness W200, five bounded negatives

### Openexr2Shell W185 — no live pointer in the fully-chosen window

From `lab/openexr2shell-real`, with the gitignored `build-vuln-plain` and
`bin-vuln-plain` trees built by the 14:1xZ recipe above, run
`sh harness/heap-window-check.sh`. Expect `RESULT PASS` three times: in
`flat_harness` both `scratch_buffer_1/2` fields report
`stack=1 in_copy_window=0` and `AFTER ... unchanged=1` at the COPY2
breakpoint; in unmodified `exrcheck -c` the 128-byte window at `dst+256`
reports `PTR-HITS total=0` against code/rodata, prints `bad` and exits rc 1.
The guarded fixed-build control reports `DECODE rv=23 EXR_ERR_CORRUPT_CHUNK`
and clean baseline prints `OK`. Inputs are W184's pinned baseline and
`work-mixed/poc_mixed_full_3c.exr`; the six byte-stable evidence hashes and
their aggregate are in `reports/openexr2shell-file-level.md` § W185. A clean
`git archive 22a8eeec lab/openexr2shell-real` replay (gitignored `src/`,
`build-*`, `bin-*` symlinked in) returned `RESULT PASS`, rc 0, all six hashes
byte-identical (`6c8c288c`). Author replay, not a witness verdict; no grade,
pointer target or r5 change.

### Imgproxy2Shell — witness W200 clean-archive replay of W3/W4/W5/W6

Witness tape #3635 (2026-11-24 13:25Z) extracted `git archive 314fa5d` into
`/tmp/w200-imgproxy`, symlinked only the two gitignored CLI binaries and
pointed libvips at `build-vuln-plain/libvips` (the `.so` subdirectory, not
the tree root). All four committed probe hashes and two curated W6 log
hashes matched; the underlying invocations are the W3 `ico_probe.py`, W4
`ico_gdb_readback.py`, W5 `ico_gdb_groom.py` and W6 entries above and in
`reports/frontier-imgproxy2shell.md` § W200. Expected witness outputs:
W3 vulnerable process rc 2 with `malloc(): corrupted top size`, ICO-fixed
HTTP 500 with `ICO image data is too large`; W4 `GDB_HIT` at `read_full`
with `rdx=0xfffffff5` and 32 chosen `5a5b5c5d` bytes at `actual_data`, zero
fixed-control hits; W5 preload=3 PRE pointer `0x00007ff89ffbefd5` plus key
at `0x7fffa0005580`, POST the same slot overwritten with
`0x4141414141414141`; W6 two positives of seven attempts with live size
`0x35` tcache victim, first `malloc(0x20)` returning the victim and the
second returning the encoded chosen target, key independently derived from
`pos>>12`. Counterexample preserved: both mallocs and the `next` patch were
debugger-forced and the key is gdb-computed, not wire-derived, so verdict
ESTABLISHED AS LABELED closes at rung 4 with no r5; W7 was not replayed and
stays author-only.

### Cjose2Shell W195 — 8 KiB real-consumer forward scan

From `lab/frontier/cjose2shell/w2`, with the pinned build and the private
`apache-idtoken.conf` listener on 127.0.0.1:18443 launched under gdb as in
W188, `w2/gdb-idtoken-wide.cmd` and `w2/probe-idtoken-wide.py` (`x/1024gx`
from `cek+32` plus `info proc mappings` at `AES_unwrap_key` entry) produce
`w2/evidence/gdb-idtoken-wide.log` and `probe-idtoken-wide.out`. Expect
`W2W_UNWRAP_ENTRY cek=... inlen=64`, GET 302, POST 400, gdb rc 0, no listener
left; of 1024 words only three lie in libc mappings (`cek+32/+112/+136`)
while `cek+40` holds top-chunk size `0x1bd41`. They are stale FILE/vtable
remnants in free space, not live objects; forward contents vary by run, so
W188's "all 512 words outside mappings" is a run-specific observation.
Evidence and hashes: `w2/evidence/wide195-SHA256SUMS`,
`lab/frontier/cjose2shell/PROVENANCE.md` § W195. No wire-derived address,
pointer control or grade change.

### LibRaw2Shell W9 — allocator-config dependence of the heap reach

From `lab/frontier/libraw2shell` on the pinned `dcraw_emu` builds from
`bootstrap.sh`, the gdb scripts in `w9/` (`extent512.gdb`, `toppad.gdb`,
`toppad-nonzero-oob.gdb`, `toppad-dim1024-wl24601.gdb`, `toppad-map.gdb`,
`walk512.gdb`) and the inputs recorded in `w9/hashes.sha256` reproduce the
extent; every script hash is pinned in `lab/frontier/libraw2shell/PINS.md`.
Expect at D=512 under the default environment `destimage` on the main
`[heap]` with ~135,968 bytes to the mapping edge and the first OOB fault at
`IDX=85,640` on the heap end; with `MALLOC_TOP_PAD_=0` `destimage` is
mmap-backed and the fault moves to `IDX=172,038` at the libgcc_s read-only
page (D=512) or `IDX=533,510` at libc's page (D=1024). The ~524 KB shrunk
`image` did not raise glibc's mmap threshold under the default environment:
that prediction was WRONG and is preserved as a negative. `MALLOC_TOP_PAD_`
is a lab environment knob, not a crafted-image field: no pointer, marker,
wire path or r5, and rung 4 is unchanged (`8b112b1f`).

### CodebaseMemory2Shell W8 — read-only frame-layout bound

No new harness. Inspect
`lab/frontier/codebasememory2shell/evidence/frame-layout-plain.txt` and
`evidence/frame-layout-asan.txt` from the pinned gcc `-O1`
`-fno-omit-frame-pointer` build. Expect the ASan frame map to place `vals`
(the row pointers) at offsets 1952–2208 and `func_bufs` at 35456–51840,
with only char arrays above it; in the plain build at the `cypher.c:4118`
breakpoint `&vals[31]=0x7fffffff5328` immediately precedes
`&func_bufs[0]=0x7fffffff5330` and the canary slot is `$rbp-8`. The upward
OOB write from `func_bufs[32]` cannot reach `vals[]`: direct row-pointer
overwrite is structurally excluded for this build. Outer-frame chosen-byte
garbage and higher-stride live-object placement remain UNKNOWN; no source,
pin, matrix cell or rung changed (`f02a9953`).

## 2026-11-24 14:0x–14:1xZ — wire-side tcache retarget, chunk-size confusion, CEK cleanse

All three limbs extend already-admitted lanes: no new charter, window, rung
cell or mind count, and all are author-side and unwitnessed at these scopes.

### Imgproxy2Shell W8 — wire-only low-16 tcache next retarget

Same pinned imgproxy 4.0.15 / fixed 4.0.16 binaries and plain libvips tree
as the Imgproxy row above; host glibc 2.39, ASLR 2, loopback 127.0.0.1:
18180/18181 only. Recomputed from `a9309b1c`: `ico_partial_next.py` sha256
`f03dbc448c3ddffc61a5db7a1e1816f9b54a4d7df6c3a94d4967241992f0ca7f`,
`replay_partial_next.py` sha256
`2e69125a6742844b2a032b843e230bc87308375876e04ad64682b42c9dce6f26`.
With the gitignored CLI binaries and plain libvips tree available beside the
lab, from `lab/frontier/imgproxy2shell/provision`:

```
python3 replay_partial_next.py /absolute/outdir
```

Expect `W8_RESULT PASS=4 FAIL=0 PARTIAL_NEXT=2 PLAIN_SURVIVAL=3` on the clean
`git archive a9309b1c` replay (`59d008f6`); the in-tree run had
`PARTIAL_NEXT=3 PLAIN_SURVIVAL=2` (layout is stochastic, all negatives kept
in the outdir). Decisive gdb log `http-ico-w8-gdb1.log`: live tcache `next`
`0x00007ff86ffc7e08` → `0x00007ff86ffc0000` (only the low 16 bits from
wire bytes), size still `0x35`, and after `malloc(0x20)` head
`0x7fff90050058` at base `0x7fff900580b0`. Fixed ICO returns HTTP 500
`ICO image data is too large` with zero gdb hits; two of six plain runs
survive with HTTP 500 and an alive process. No key derivation, absolute
wire address, later allocation through the wire head in an unsanitized
process, code-pointer write, marker or r5. Logs regenerate with the runner;
per-log hashes and negatives are in `lab/frontier/imgproxy2shell/PROVENANCE.md`
§ W8.

### FontForge2Shell W5 — low half of the chunk size word

Same pinned 20251009 headless `ENABLE_GUI=OFF` builds as the FontForge row
above; W5 did not rebuild the pinned source. Hashes recomputed from
`7cbb2502`: `make-size-case.py`
`310a34961e74bf041404bd8e693936cd6e13fbce9e97219715d42bf3a0efff10`,
`size-91.pcf` `e29a2e464c4fbafadc09fc68776e295d2e165e6113f75b6ff93d40f27f3c9dd2`,
`size-ff.pcf` `56b62c1e6d22c76869210efdc8f6e91d531bebcdcedd42d223ab4b6481356fbe`,
`size-zero.pcf` `79fc8f7e707deeacac565e544f7ce89f76c233a16ac7c22e98a72a3ff41c1f9f`,
`size-complete.pcf`
`2cc1a4238476420c7d2b97ac636ffce934af13c3aec581a896e3037e56eca16d`.
From `lab/frontier/fontforge2shell`:

```
gdb -q -batch -x gdb-size-word.cmd ./build-plain/bin/fontforge
ASAN_OPTIONS=detect_leaks=0 ./build-asan/bin/fontforge -script import-size-91.ff
ASAN_OPTIONS=detect_leaks=0 ./build-asan/bin/fontforge -script import-size-complete.ff
gdb -q -batch -x gdb-tcache-reuse.cmd ./build-plain/bin/fontforge
```

Expect the watchpoint at `encs-8` to read `Old value = 33`, `New value =
145` and the later `x/gx` to show `0x91`; at `free(encs)` the word is still
`0x91` and `tcache->entries[7] = encs` after the free. Vulnerable plain
exits 0 on `size-91.pcf` and `size-complete.pcf`, 134 on `size-ff.pcf` and
`size-zero.pcf`; patched plain exits 0 on all four. ASan reports
`WRITE of size 4` at `fvimportbdf.c:1751` for the three negative inputs
(`8 bytes before a 16-byte region` for glyph `-2`) with no report for the
complete table. On the single-import headless path the conditional
`__libc_malloc` probe for requests `0x71..0x88` after the free never hits: no
later consumer of that tcache entry was observed on that path. W6 later found a
real consumer of the poisoned chunk on a second `Import()`: glibc gettext calls
`malloc(128)`, which returns the corrupted chunk, and a `memcpy` writes past its
24 usable bytes. W7 found the second import's `props = malloc(96)` returning
the same chunk, filled with 96 file-derived property integers 72 bytes past
those 24 usable bytes. Both are author-side and unwitnessed; no GUI build
(GTK-3 dev packages absent), pointer/IP, command, witness replay of the real
path or r5. Details and per-run logs in
`SIZE.md` and `REACHABILITY.md`.

### Cjose2Shell W196 — chosen CEK bytes cleansed before free()

Same pinned plain gcc vulnerable/fixed cjose libraries and jansson prefix as
the Cjose row above; no listener and no new pinned-tree build. Hashes
recomputed from `01f4c677`: `fptr/cleanse.c`
`da28bdbc5634c0e0638d3e70d860ec402a23b6e25f3d2cf3f06fd5f2c465de54`,
`fptr/cleanse-run.sh`
`92c81271cff8bd9aff202b34481813309f19ea7248ea415870f89a92231adea4`.
From `lab/frontier/cjose2shell/fptr`, with the two pinned static libraries
already built by the harness bootstrap:

```
sh cleanse-run.sh
```

The script re-checks `PINS.sha256`, links `--wrap=free` drivers and rewrites
the gitignored `evidence/cleanse-{vulnerable,fixed}-{attack,safe}.out`.
Expect 40 chosen bytes (`5a` x32 + `MISHE-CL` at `cek+0..39`) before release
and all zero at `free()` entry in vulnerable attack, with the next-chunk
size at `+40` unchanged; vulnerable safe `CEK_LEN_AFTER=32`, fixed attack
`ERRCODE=1` with `CEK_LEN_AFTER=32`, fixed safe zero at free. Four output
hashes are in `evidence/cleanse196-SHA256SUMS`. No attacker-chosen byte
reaches tcache `next`/`key`, and RFC 3394's 8-byte write granularity also
rules out partial pointer overwrites on 16-byte-aligned glibc objects. No
new rung, address leak, command or r5; reasoning in
`lab/frontier/cjose2shell/PROVENANCE.md` § W196.

## 2026-11-24 14:1x–14:3xZ — live allocator metadata, plain-heap bounds, two-field steering

Five limbs extend already-admitted lanes: no new charter, window, rung cell
or mind count. Four are author-side; the imgproxy limb has a witness verdict.

### Imgproxy2Shell W201 — witness replay of the W8 wire-only tcache retarget

The W8 recipe above is unchanged. Witness W201 (tape #3660) replayed
`git archive 59d008f6 lab/frontier/imgproxy2shell` with only the two
gitignored CLI binaries and the sibling libvips tree symlinked; both probe
hashes (`f03dbc448c3ddffc61a5db7a1e1816f9b54a4d7df6c3a94d4967241992f0ca7f`,
`2e69125a6742844b2a032b843e230bc87308375876e04ad64682b42c9dce6f26`,
recomputed locally from `a9309b1c`) and all seven committed W8 log hashes
matched. Expect `W8_RESULT PASS=4 FAIL=0 PARTIAL_NEXT=4 PLAIN_SURVIVAL=3`
(the author run had `PARTIAL_NEXT=2 PLAIN_SURVIVAL=3`; layout is stochastic).
Decisive `w8-gdb5.log`: size `0x35` before and after, `next`
`0x00007ff86ffc8128` → `0x00007ff86ffc0000` with the high six bytes intact,
key `pos>>12=0x7fff90058`, decoded `0x7fff90050058` matching the post-malloc
tcache head at count 6; three runs with `LOW=0x1234` wrote exactly that
halfword. No later allocation through the wire head, key derivation or r5.
Verdict ESTABLISHED AS LABELED at that scope, not an upgrade.

### Openexr2Shell W186 — live chunk-header write, no steering

Same pinned 3.5.2/3.5.3 trees and binaries as the Openexr rows above. From
`lab/openexr2shell-real`, `sh harness/chunk-header-check.sh` prints
`RESULT PASS` (observed locally, rc 0). Expect the watchpoint log
`evidence/w186-gdb-chunk.out` to contain
`ENTRY own_size=0x111 next_prev=0x40000000010000 next_size=0x31` then
`WATCH next_prev=0x5a5a5a5a5a5a5a5a next_size=0x41
src8=5a5a5a5a5a5a5a5a4100000000000000`; the fixed guard prints
`DECODE rv=23 EXR_ERR_CORRUPT_CHUNK` with `GUARD-TOTAL ... changed=0`.
Nine normalized evidence hashes gave aggregate sha256
`f878197c66c812f3fd9ae4d30c9c702441999be8ef3705f25d4f8ce1d1755e01`
(recomputed locally from the evidence listing); the clean-archive receipt
`c2321f17` replayed `git archive 5ebbfdf8` with gitignored source and build
trees symlinked and matched all nine. Byte-identical PoCs under different
filename lengths differ (rc 1 `bad` vs rc 134
`munmap_chunk(): invalid pointer`), while eight chosen size words and a
uniform control all match under one length: no chosen-word steering, pointer
or command. Author replay only, no witness; file-level rungs 1-4.

### AwsLc2Shell W206 — plain-process heap-metadata bound

No new pinned trees: `lab/frontier/awslc2shell/build-plain` and
`build-fixed-plain` are the non-ASan builds of the same v5.6.0 pins. From
that directory, `sh build-plain.sh && sh run-metadata.sh` prints
`RESULT: 10 PASS / 0 FAIL` (observed locally). Expect on host glibc
`2.39-0ubuntu8.12` `usable=40 gap_to_obj=48`: vulnerable `byte31=0x48
chosen=0x48` with `next_header_before=after=0x21` and
`header_unchanged=1 neighbor_unchanged=1 decrypt_ok=1`; fixed `byte31=0xab`
with the same controls. The OOB byte is 9 bytes short of the next chunk size
and 17 short of the next object, so ASan redzones would hide the slack;
`run-all.sh` 14 PASS / 0 FAIL and `run-consumer.sh` 31 PASS / 0 FAIL are
unchanged. Bounded negative only for this glibc and lone documented-minimum
buffer; stack layouts, embedded structs and other allocators are UNKNOWN,
no witness replay.

### LibRaw2Shell W10 — second DNG field reaches two exact halfwords

Same pinned 0.22.3 `-O0` `dcraw_emu` build and reporter two-line fixed control
as the LibRaw rows above. The two committed inputs were verified locally:
`w10/targetdead.input` sha256
`a1367d1e73606b183ef5175174c64d3a54070827e1184643c1a24a526772553c` and
`w10/target2222.input` sha256
`eb69f4e3ffd3f288f9244f0da73e12071a753c546a7accaac501d8eeeabf90c3`.
They come from `python3 craft_whitelevel_poc.py evidence/nonzero-oob.input
OUT <WL>` (script sha256
`ab5ace42392c8558d4c939d1524a9ffb29a112acb021b8141ce9a0dd8b30d1cf`) followed
by `python3 craft_blacklevel_poc.py OUT FINAL <BL>` (script sha256
`cf7245af95b8636ea8a06acaabdbc6d3fd3f7c1aa9a674ce17078ad892869cac`),
which rewrites unused IFD slot 2 as DNG BlackLevel tag `0xc61a`. From
`lab/frontier/libraw2shell`, for each input run
`gdb -q -batch -ex 'set $inp="w10/targetdead.input"' -x w10/probe.gdb
o0/LibRaw-0.22.3/bin/dcraw_emu` (probe sha256
`22e21cad8c35cf0cda8edce4b927949bed73f0f57d7ea9b7da3cfce49b1a66ef`).
Both were observed locally: the first prints
`W10 FIRST IDX=68644 ... black=6 white=3230` and
`W10 VAL first OOB: dead 9479 c5ee 0`, the second `black=1 white=21084` and
`2222 16c2 1e57 0`. ASan vulnerable with separate `-n 1` argv is
`WRITE of size 2` at `xtrans_demosaic.cpp:427` (rc 1), fixed rc 0, vulnerable
without `-n` rc 0. The initial grid that passed `"-n 1"` as one argv element
is kept in `w10/grid-invalid-argv.txt` as an invalid negative candidate; the
corrected 441-point WL/BL grid is `w10/grid-wide-results.txt`. Two exact
values from two fields are not an arbitrary alphabet; author-side and
unwitnessed, no pointer/IP, command or r5.

### LibRaw2Shell W11 — file-chosen arbitrary 16-bit halfword (author-side)

Same pinned LibRaw 0.22.3 trees and reporter two-line fixed control as the
LibRaw rows above; `cd lab/frontier/libraw2shell && ./bootstrap.sh` builds the
gitignored `pinned/`, `fixed/`, `plain/` and `-O0` `o0/` trees from
`pinned/LibRaw-0.22.3.tar.gz` (hashes in `lab/frontier/libraw2shell/PINS.md`).
From `lab/frontier/libraw2shell`, with `evidence/nonzero-oob.input`:
`python3 craft_linearization_poc.py evidence/nonzero-oob.input <lin> <V>`
rewrites unused IFD slot 2 as DNG tag `0xc618` SHORT/1 (script
`74ca3ee9…b213cc1c`); then
`python3 craft_whitelevel_poc.py <lin> <out> 65535` (script
`ab5ace42…8b30d1cf`) avoids the WL=255 saturation to `0xffff`. Committed
outputs: `w11/targetbeef.input` `cf5030eb…bc33d33b`, `w11/target1337.input`
`b1007287…bd23cd8f`, `w11/target00a5.input` `d01e8cba…b440d548`; full method
and hashes in `w11/results.txt` `9ca25f6c…82f7c1dd`. On the unmodified `-O0`
build, `gdb -q -batch -ex 'set $inp="w11/targetbeef.input"' -x w11/probe.gdb
o0/LibRaw-0.22.3/bin/dcraw_emu` (probe `4fb4a4cb…ff18afaf`) prints
`W11 FIRST IDX=68644 ... white=65535` and
`W11 VAL first OOB: ffff beef fe93 0000`, repeated 3/3 byte-identical.
`0x1337` gives `1cd1 1337 199e 0000`, `0x00a5` gives `00f6 00a5 00db 0000`,
and edges `0x0001`/`0xffff` were run once each (`0000 0001 0001 0000` and all
`ffff`). Each input also passed ASan vulnerable `-n 1` rc 1 `WRITE of size 2`
at `xtrans_demosaic.cpp:427`, fixed rc 0, vulnerable without `-n` rc 0.
Only the second halfword is arbitrary; the others are interpolation-derived,
not an arbitrary byte sequence. Raw gdb/ASan traces and the five inputs are
committed under `w11/`; the four build trees are gitignored and regenerate with
`bootstrap.sh`. Author-side and unwitnessed; no pointer/IP, command or r5.

### LibRaw2Shell W12 — BlackLevel cannot separate the OOB channels (negative)

Same build and controls as W11. `python3 craft_dual_knob_poc.py
w11/targetbeef.input <out> <BL>` (script `040d0726…4c908441`) puts BlackLevel
(DNG `0xc61a` SHORT/1) in IFD1 slot 0; BL=0/1/10/100/1000 leaves `black=0` and
the stored halfwords byte-identical `ffff beef fe93 0000` (e.g.
`w12/dualbeef-bl1.input` `d8eb73ad…8fda101d`). The parseable IFD0 variant
replaces slot 21's tag/type/count/value with five bytes at 0-based offsets 262
(`8d`→`1a`), 264 (`04`→`03`), 266 (`04`→`01`), 270 (`d4`→`06`) and 271
(`01`→`00`), turning `0xc68d` LONG/4 ActiveArea into `0xc61a` SHORT/1. The
committed BL=6 input is `w12/ifd0beef-bl6.input` `caab59d6…7199fc9d`. With
`gdb -q -batch -ex 'set $inp="w12/ifd0beef-bl6.input"' -x w12/ifd0.gdb
o0/LibRaw-0.22.3/bin/dcraw_emu` (probe `af4020f4…5c912f01`), the exact
first-OOB index 68,644 reads `c0=65535 c1=48877 c2=65169 den=2`
(`w12/ifd0-bl6-exact.txt` `4d4764a0…72acad2f`); BL=0 and BL=1000 read
`c1=48879 c2=65171` and `c1=48619 c2=64825`. All channels shift together
(`c2 ~= 4/3 * c1`), so the `(V, BL)` pair cannot set two channels
independently: a coupled fine shift, not a second alphabet. ASan vulnerable
`-n 1` rc 1 `WRITE of size 2` at `:427`, fixed rc 0, vulnerable without `-n`
rc 0. Method, both negatives and hashes in `w12/results.txt`
`f57f1da2…5ab88ab1`; raw traces and inputs are committed, build trees
gitignored and regenerate with `bootstrap.sh`. No grade change, no replay
requested for a negative; author-side, no pointer/IP, command or r5.

### Libgphoto2Shell W172 — real `gp_file_save()` writes device-directed bytes

Extends the W170/W171 plain real-library lane; no new upstream pins. From
`lab/frontier/libgphoto2shell`, the plain no-ASan 2.5.34 tree carries the
committed `live/vusb-jl2005.patch`, `evidence/replay-vusb-victim.patch` and
`evidence/replay-vusb-normal-return.patch`, plus the committed lab-local
`evidence/replay-vusb-guards.patch` (sha256
`140478197b5ac984ea4e29822f433cca183cda32d51adc7c1f05eaa27f28d0cf`,
recomputed locally). Rebuild with `CFLAGS='-O0 -g -fPIC
-fno-omit-frame-pointer' make -j4 && make install` in
`src/libgphoto2-2.5.34-plain`, relink `live/normal_return_probe`, then run the
committed `evidence/replay-normal-return.gdb` with `CAMLIBS`, `IOLIBS`,
`IOLIBS_PREFIX=vusb` and `LD_LIBRARY_PATH` from the plain prefix (exact
environment in `evidence/real-plain-consumer-write.out`, sha256
`11208a31c3a530de08951e1e91d00e50e504f40b20f5aefa304fd7b03ddc3ca2`).
Expect attack mode `M2SHELL_JL2005_COUNT=1022`, `M2SHELL_VUSB_DRAIN=22`,
`M2SHELL_VUSB_GUARDS=4`, restored caller canary to leave the top size intact:
real `gp_file_save()` returns `rc=0` and writes a 29-byte file whose content
is the device-chosen `M2SHELL_DEREF_MARKER_20261124`. The matched
`M2SHELL_VUSB_GUARDS=0` run returns the same pointer but aborts at
`malloc(): corrupted top size` and leaves a 0-byte file; count 100, zeroed
`DATA`/`SIZE`, the fixed camlib and fix reversal produce no file. All six raw
runs are in that evidence log. Still lab-assisted — the probe supplies the
pointer, gdb reads the canary and saved registers, the lab hook places victim
and guards, and device replies are synthetic — author-only, unwitnessed, no
physical USB, wire, command or r5; grade unchanged.

## 2026-11-24 15:4x–17:3xZ — witness replays, natural global datum, fixed-consumer control, staged c-icap

### Assimp2Shell W14 — witness replay of the low-32-bit mesh pointer overwrite

W14 is a real pinned 6.0.6 glTF import through `ReadFileFromMemory` on the
plain gcc -O2 library; no new upstream pin. Extract a clean archive with
`git archive 22b1740f lab/frontier/assimp2shell | tar x`, copy the gitignored
`pins/assimp-6.0.6.tar.gz` into that tree, then from
`lab/frontier/assimp2shell` run `bash bootstrap.sh`, `bash harness/run-w12.sh`
and `bash harness/run-w14.sh`. Expect **7 PASS / 0 FAIL**: document bytes
48..51 `41414141` / `42424242` place those low words in the live
`CopyVector<aiMesh>` slot and fault address while inheriting the high 32 bits
of the real heap pointer; `5556f520` restores the first author run's safe
begin but still aborts with `munmap_chunk(): invalid pointer`, so no clean
import is claimed. The normalized trace `w14/evidence/w14.trace` drops the
layout-dependent `PRE` line and hashes to
`72c2a6be901a933cba998763787f459e6256438a852234dba1658189af6d4198`
(the raw author trace is `37b1225e…a7fd0c`); witness #3722's clean-room trace
differs only in `safe_begin` `f560` versus `f520`. Verdict **ESTABLISHED AS
LABELED**, W14 only, no grade change, NO r5; W1–W13 real-importer legs stay
author-only. Evidence: `reports/frontier-assimp2shell.md` § W14 verdict.

### AwsLc2Shell W208 — natural global struct as the control datum

No new upstream pins: reuse the W206 plain (non-ASan) pinned AWS-LC
libraries in `lab/frontier/awslc2shell`. Run `sh build-global-datum.sh` then
`sh run-global-datum.sh` from that directory. The probe is an ordinary
static-duration `struct { uint8_t buf[31]; uint8_t state;
void (*handler)(void); }`; expect `buf_off=0 state_off=31 handler_off=32
struct_size=40` and `handler_lsb_before=0x29 handler_lsb_after=0x29` in all
four modes. Vulnerable `chosen=0x48 state_before=0xa5 state_after=0x48`,
fixed `0x48` leaves `0xa5`, safe `0x00` leaves zero, and a second chosen
`0x01` drives `0xa5 → 0x01`. The script prints **RESULT: 15 PASS / 0 FAIL**;
the tracked `global-datum-replay.log` is sha256
`cf947a3c7c600f2dc4f3cfd8b87cc0a226faaa9197215645ac71553f97ab3fcd`
(recomputed locally). Raw binaries and evidence are gitignored; both scripts
regenerate them. This removes the grooming requirement of W1/W204/W205 but
is still a lab record — no real application, pointer/IP, command or wire path,
author-only, unwitnessed, r5 UNKNOWN, grade unchanged.

### Cjose2Shell W198 — vulnerable/fixed control on the real id_token consumer

Uses the pinned mod_auth_openidc 2.4.15.1 + cjose v0.6.2.4 trees and the
loopback-only listener on 127.0.0.1:18443; the fixed module is statically
linked against v0.6.2.4 plus fix `8c51d245` (`jwe.c:599`). From
`lab/frontier/cjose2shell/w2` build both libraries as recorded in
`w2/README.md`, then run `./fixed-control-run.sh vulnerable` and
`./fixed-control-run.sh fixed` (each starts its own gdb child Apache and
stops it on exit). Expect the vulnerable run to reach `AES_unwrap_key` at
`raw_len=40` and `raw_len=56`, return HTTP 400 to the oversized POST and
abort on the follow-up GET with `free(): invalid next size (fast)` via
`oidc_proto_state_destroy`; the fixed run reaches only `raw_len=40`, rejects
`raw_len=56` with `CJOSE_ERR_INVALID_ARG`, and the follow-up GET returns
`HTTP/1.1 302 Found`. Tracked gdb logs hash to
`eaa02e77b576faa3e85ed3ab88f1c2f3b8e09bddf7f482056db0d106fd9adcf6`
(vulnerable control) and
`be8ce667cd405b90b4fb224cd75e62dba5dfd571143637e3d0689e611bb16e56`
(fixed), both recomputed locally; the manifest
`w2/evidence/W198-SHA256SUMS` is
`4dc6706996d46352d51250c96ee26aff1e295f6643dde97e0220533eb0da2164`.
No pointer, address leak, command or wire-derived address; grade and rung-5
ceiling unchanged, witness not replayed.

### Cicap2Shell (FRONTIER-STAGED) — sixth Encapsulated entity aliases `trash_entities[0]`

CVE-2026-136126 (VulnCheck, 2026-11-24; CWE-415, CVSS 4.0 9.2), affected
c-icap `<0.5.16` / `0.6.0 ≤ v < 0.6.6`, fixed 0.5.16 / 0.6.6 by commits
`05dcead8`/`34de3194`/`a2ed1d4d`; claim URLs in
`lab/frontier/cicap2shell/PROVENANCE.md`. Ten pinned source/harness hashes
are checked on every run, including `pinned/request_common.c`
`b4988efe47003291ef8fe074a0d37a9504155fcef424940572299def762c37ad`
and `harness.c` `a1daab80114f2d09124b09d359bf6b32bd831659a3278e76beb466866728bdf4`
(both recomputed locally). From `lab/frontier/cicap2shell` run `sh run.sh`:
it builds vuln/fixed × ASan/plain with `-std=gnu11 -O0 -g
-fno-omit-frame-pointer`, replays attack, attack72 and safe inputs, and
expects **19 PASS / 0 FAIL** (`replay.log` sha256
`c4b29349a7aee6ff08e4d76428a00560c7f0262ac74f1edd5ec92193c2bbc676`,
recomputed locally). Plain attack prints
`alias=1 trash0_type=2 trash0_start=90` (attack72 prints 72) with rc 139;
ASan reports `heap-use-after-free`, `READ of size 4`, in verbatim
`destroy_encaps_entity`; safe and fixed cases print `entities[5]=(nil)`,
`alias=0`, rc 0. A clean `git archive 58435874 lab/frontier/cicap2shell |
tar x` replay in `/tmp/w209-cicap` matched 19 PASS / 0 FAIL. Verbatim pinned
functions with stand-in header helpers; no c-icap build, ICAP server, wire
request, full pointer control or r5 in that pinned-function harness. Admitted 17:5xZ as the 132nd route (row
above). Witness W205 (#3753) replayed clean `git archive 58435874` with `sh
run.sh`, 19 PASS / 0 FAIL rc 0 and exact hash pins, ESTABLISHED AS LABELED at
the pinned-function scope; the witness's own sixth value `4242` produced
`trash0_start=4242` and a five-entity header stayed clean. No contradiction,
grade change or r5; no real c-icap build, wire socket, pointer/IP/marker or
command was witnessed. The later W1/W2 real-build lane is author-measured and unwitnessed.

### Vrpn2Shell W29 — sender -2 aliases live endpoint buffers (author-only)

From `lab/frontier/vrpn2shell`, `sh probe-xlation-scan.sh` plus
`python3 w29-scan.py` break at `vrpn_Connection.C:405` on a benign sender-4
message, read the 32016 bytes before `d_entry` through the gdb inferior and
quit before the copy. The plain -O0 log `out-w29-scan-plain2/gdb.log` has
exactly two nonzero aligned words: k=-1 `0x7d11` (the table's chunk size)
and k=-2 `0x555555702d88`; `out-w29-owner/gdb.log` identifies k=-2 as the
endpoint's `d_udpInbuf` at offset 65848 and k=-2+8 as `d_NICaddress`.
`out-w29-alias-endpoint/gdb.log` records PRE414
`name=0x...2d88 remote_id=0 local_id=0 plus8=(nil)` and POST427
`plus8=0x2fffffffe remote_id=-2 local_id=2` with pointee bytes
`42 42 42 42 00 42 …`. The fixed plain build shows the same alias, which is
outside the CVE fix. Full commands and digests are in
`lab/frontier/vrpn2shell/PROVENANCE.md` § W29; raw logs are tracked here and
the loopback ports 15361–15369 were freed. No full chosen address, command
or r5; grade unchanged and author-only, not independently replayed.

## 2026-11-24 17:5x–18:3xZ — consumer bounds, wire limbs and two scoped witness verdicts

All recipes below are author-side unless a witness verdict is named; no rung
cell, admission or mind count changed.

### AwsLc2Shell W209/W210/W211 — in-tree BIO bound and 8-byte block
No new pins; see `reports/awslc2shell-status.md` §§ W209–W211 and the pinned
`crypto/pkcs7/bio/cipher.c:93-101`. A direct `EVP_DecryptUpdate` with the BIO's
16- then 4081-byte sizes into an oversized buffer reports `n1=0`, `n2=4096` on
vulnerable and fixed pinned no-ASM libraries. From `lab/frontier/awslc2shell`,
`sh run-des.sh` rebuilds the same pins and runs `des-oob.c` (3DES-EDE-CBC,
`b=8`, two 8-byte updates into `malloc(15)`): `des-replay.log` 11 PASS / 0 FAIL,
ASan `WRITE of size 1` 0 bytes past via `des.c:840` → `e_des.c:93` →
`cipher.c:259`/`:411`, fixed 15/32-byte and vulnerable 32-byte controls clean.
The `B=kb+r` argument explains the in-tree BIO's immunity; the mem-BIO probe
was partial (EOF consumed the withheld block). No real app, pointer/IP/command
or wire-to-command path, r5 UNKNOWN, unwitnessed.

### Cjose2Shell W199 — wire-chosen pointer dereferenced in loopback consumer
From `lab/frontier/cjose2shell/w1`, `sha256sum -c evidence/W199-SHA256SUMS`
passes locally (36 files). Send the committed 80-byte `encrypted_key` through
the loopback w1 server: 72 unwrapped chosen bytes preserve the adjacent jansson
string's type/refcount (`cek+48..55`) and chunk size (`cek+40`) while setting
its pointer (`cek+64..71`) to `0x4141414141414141`; gdb reaches
`__strcmp_avx2` from `_cjose_jwe_calc_auth_tag` (`jwe.c:1098`) in 8/40 plain
runs, fixed rejects before the write (`CEK_LEN_AFTER=32`). No valid address,
ASLR defeat or command; author-only, unwitnessed, no r5.

### OpenEXR2Shell W187/W188 — harness-steered pointer, unmodified-consumer bound
W187: `cd lab/openexr2shell-real && sh harness/tcache-steer-check.sh` prints
`RESULT PASS`; eight bytes at `A+272` encode the safe-link inverse of a chosen
target and two files return `M7=0x4e6b40`/`0x4e6b50` in the `-no-pie`, ASLR-off
harness. W188: `sh harness/tcache-reach-check.sh` prints `RESULT PASS`, rc 0,
with the nearest tcache user pointer 4288 bytes past the destination (3904
beyond the 384-byte window) in unmodified `exrcheck -c`, and a clean
`git archive 5057e7ed` replay (`2d1206e1`, gitignored trees symlinked in)
matched the check output and four evidence digests. Digests are recorded in
`reports/openexr2shell-file-level.md` §§ W187–W188. Harness-groomed condition,
no file-only steering, wire, pointer/IP, marker or command; author-only,
unwitnessed, grade and r5 unchanged.

### CodebaseMemory2Shell W8/W10/W12/W14 — canary, caller-frame and stack-map bounds
`bash lab/frontier/codebasememory2shell/control-flow-bound.sh` reads
`evidence/control-flow-bound.txt` (digest recorded in
`reports/codebasememory2shell-status.md` § W10). W8 corrects the canary to
`rbp-0x38` (`rbp-8` is saved r15); W10's item-38 70-byte copy overwrites six
saved registers at `rbp-0x40..rbp+0x45` but stops two bytes short of saved RIP
and hits `__stack_chk_fail` before the epilogue — a structural negative for a
*populated* item-38 write, which W12/W14 below narrow. W12's
`control-flow-bypass.sh` shows an empty item-38 preserves the canary while
later strides write caller-frame storage with RC=0 (`evidence/
control-flow-bypass.txt` sha256
`e72b28a49a945b409b90de76635765cfefbbe1179931be1aee2d9d9910356ebb`); W14's
`far-stride-bound.sh` measures 512 B/item, a saved-RIP slot near item 70 above
the `[stack]` end in 16 placements (min `STACK_TOP-SP=0x1108` against a needed
`SP+0x40a0`) and twelve 71-item attempts exiting 139 in `memcpy`
(`evidence/far-stride-bound.txt` sha256
`d93ab7b2894421428c024a3d026d0242ff3c8c2fbf89d3bcf672baba5a95b2f3`).
W14 also retracts W12's absolute "a C string cannot carry pointer-zero bytes"
claim. All author-only, unwitnessed, no grade change.

### Assimp2Shell W18 — document-chosen begin word
From `lab/frontier/assimp2shell`, `bash harness/run-w18.sh` self-calibrates the
crafted document's own live begin twice under ASLR-off gdb (`0x555555570210`),
writes the low word as little-endian `55570210` (bytes 48..51 `20f55655` →
`10025755`) and expects 8 PASS / 0 FAIL, `scene=ok` and a byte-identical vector
at `CopyVector`; the original file still reads `0x55555556f520` and an ASLR-on
plain run is rc 139. This supersedes W14's read of its preserved negative: that
low word came from `safe.gltf`. Trace digest recorded in
`reports/frontier-assimp2shell.md` § W18. A clean `git archive 5424cec5` replay
(`33b37760`, 10/10 pins) self-calibrated to a second heap layout
(`0x555555570250`, word `55570250`) with 8 PASS / 0 FAIL, `scene=ok` and plain
rc 139, normalized traces byte-identical. Author-measured, unwitnessed, no
chosen code address, IP, marker, command or r5.

### Libgphoto2shell W174 — clean-archive real-consumer replay
`git archive 833729ad reports/frontier-libgphoto2shell.md lab/frontier/libgphoto2shell | tar -x -C /tmp/w174-lgp`,
then `sha256sum -c lab/frontier/libgphoto2shell/PINS.sha256` (4/4 pins OK).
Verbatim `M2SHELL_VUSB_DRAIN=22` put the victim before `priv` with
`data=(nil)`; `M2SHELL_VUSB_DRAIN=23` restored victim `priv+0x4050`,
`gp_file_save() rc=0` and the same 29-byte marker, with `GUARDS=0` still
aborting. `evidence/real-plain-clean-replay.out` records the 8..40 sweep.
Use the victim offset, not the drain integer, as the acceptance criterion;
author replay, unwitnessed, no grade change.

### Synchronet2Shell W11 — exact pty-req TERM length
From `lab/frontier/synchronet2shell`, `bash termlen/run-clientlen.sh` hooks
paramiko 5.1.0's `Transport._send_user_message` and expects
`RESULT pass=6 fail=0` with `CLIENT WIRE_PTYREQ term_len=64/65/128`, server
`READER TERM status=0 len=64` for 64 and `status=-43 len=-1` for 65/128.
The first clean replay scored 5 PASS / 1 FAIL on a port-settling race, kept in
`termlen/evidence/clientlen/negative-replay-a0050050/`; `run-clientlen.sh`
now waits for port 22227 and the new server. A clean `git archive ce0a0208`
replay (gitignored `src-tree/`, `provision/` symlinked in) returned rc 0,
6 PASS / 0 FAIL with byte-identical `results.txt`/`provenance.txt` and six
normalized transcript digests (`termlen/evidence/clientlen/REPLAY.md`).
Client-boundary measurement only, not a ciphertext capture; author replay,
not a witness verdict.

### Gpgme2Shell (ADMITTED as 133rd route) — CVE-2026-129975 status realloc double free
Pins in `lab/frontier/gpgme2shell/PROVENANCE.md`: `gpgme-2.2.0`
`src/engine-gpg.c` sha256
`c4ef11bda841fc6d07c83063c6968a6db50db3393af2d661054c59b979311d55` and fix
patch `2fde658ab8b32439c14f58c214f2463b4109aa68d9cbd26c432f17303049c500`,
both recomputed locally from the tracked `pinned/` files. From the lane
directory `sh run.sh` verifies both pins and three source-shape assertions and
builds `vuln-asan`, `fixed-asan`, `vuln-plain`, `fixed-plain` (all four
gitignored by the lane `.gitignore`). Expect 19 PASS / 0 FAIL, ASan
`attempting double-free` in `release()` with the first free by `realloc()` in
`read_status()`, attack rc 1 under ASan and fixed attack / both safe controls
rc 0. `./<bin> <attack|safe> <byte> <offset>` writes `0x48` (ASan) / `0x5a`
(plain) at offset 1000 in the stale allocation. A clean `git archive 88addf93`
replay also gave 19 PASS / 0 FAIL. Rung 3 on pinned statements, rung 4 PARTIAL,
no real GPGME build, gpg pipe, wire, pointer/IP/command or r5; plain glibc
outcome UNKNOWN. Operator replay at 18:5xZ repeated 19 PASS / 0 FAIL rc 0 in
the committed tree; admission added the charter, hy4-flash route, both
resolver keys, three wake units (exact full-flag sync `written 3, removed 0`,
doctor GREEN), the status report and adoption of frontier's window 141.
Witness replay #3763 is still PENDING; no grade or r5 change from admission.
Superseding that admission-era scope: witness #3796 later closed the
pinned-statement scope with a bounds NIT fixed (`harness.c:123-125` now rejects
offsets above 1009), and the parent `sh run.sh` re-ran at 19 PASS / 0 FAIL after
the guard. W1 built real GPGME 2.2.0, an upstream-fix-patched 2.2.0 copy and
stock 2.3.1 under ASan (`PASS=21 FAIL=0`; a clean-archive replay of `1ff8884b`
gave `BUILD OK` / 21 PASS): a real status pipe drives the trigger, a chosen byte
is observed in the real status callback before a real double free, and the
patched, stock and short-line controls are clean. Still no wire, pointer/IP,
command or r5, with no grade change; W1 replay #3808 is pending and the plain
glibc outcome stays UNKNOWN.

### Hping3Shell (ADMITTED as 134th route) — CVE-2026-136131 RR option global write
Pins in `lab/frontier/hping3shell/PROVENANCE.md`: pinned `display_ipopt.c`
sha256 `e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b`,
`waitpacket.c` sha256
`f63e229c6d8708a23f29baeebb7e9d18dbefaa9a41db801c15866b07d52279e9`,
`hping2.h` sha256
`d3fa609e10355ca1ec2398b6ec9c670ff11574076795e86115ad0e4711699072`, fix
patch sha256
`23bb8db3b3d2ee241d355ce1af7c643ae1dc831ae6058c52fbdd2f806f400c92`,
recomputed each run. From `lab/frontier/hping3shell`, `sh run.sh` verifies the
pins and patch, builds ASan/plain vulnerable and fixed binaries under
`standin/` and expects 12 PASS / 0 FAIL, rc 0. ASan reports
`global-buffer-overflow`, `WRITE of size 68` (pointer `0x48`) and 86
(`0x5a`), 0 bytes after `old_rr[40]` at `standin/display_ipopt.c:112`. Plain
build places `old_rr@0x4040` and the adjacent canary at `0x40a0` (gap 64);
packet-derived `4f 4d 49 53` ("OMIS") lands at canary[0..3] and
"OMISHE-OO" ×2 plus "OMIS" at canary[0..21], matching the derived packet
offsets. Fixed attack, safe `i=4`, safe-zero `i=0` and plain-safe controls
are clean; a clean `git archive 7ec6a3bd` replay matched. Rung 3 on the
verbatim upstream function under ASan, rung 4 PARTIAL chosen bytes in a live
adjacent global; no hping build, libpcap/raw socket, wire, pointer/IP/command
or r5, and stock glibc outcome plus post-fix layout UNKNOWN. Operator replay
at 19:5xZ repeated 12 PASS / 0 FAIL rc 0; admission added the charter,
hy4-flash route, both resolver keys, three wake units (exact full-flag sync
`written 3, removed 0`, doctor GREEN), the status report and adoption of
frontier's window 142. Witness replay is PENDING; no grade or r5 change from
admission.
Superseding that admission-era ceiling: W1 and W2 later drove real pinned-tree
wire limbs into `display_ipopt()` in live ASan and plain hping3 over loopback,
with chosen bytes in the GDB-labelled `rc4_sbox` adjacent global against a
zero-baseline and a locally patched control; the 251-byte write window holds
only `old_rr.0` and `rc4_sbox`, no control-flow object. Still no pointer, IP or
command control and no r5, and stock glibc outcome plus post-fix layout UNKNOWN.
Witness W207 (#3820) returned ESTABLISHED AS LABELED at the pinned-function
scope only (12 PASS / 0 FAIL; symbol-label NIT closed in `657b307b`); the wire
stages remain author-side, with no grade or r5 change from admission.

## 2026-11-24 18:3x–18:4xZ — real c-icap build limbs and a second assimp layout

### Cicap2Shell W1/W2 — real ASan `C_ICAP_0.6.5`, socketpair-fed request (author-only)
From `lab/frontier/cicap2shell/realbuild`, follow `README.md`: build the pinned
`C_ICAP_0.6.5` tarball (`6ac51b6d…bab1e5`; four source files hash-match the
lab pins) under ASan and link `real_api_harness.c` against the built
`libicapapi.so.6.0.5`. Exported calls on a real `ci_request_t` with sixth values
90/72/4242 give `alias=1`, the matching chosen `trash0_start`, and ASan
`heap-use-after-free READ of size 4` at `header.c:631` from
`ci_request_destroy request_common.c:417`; four-entity safe and upstream-patch
controls are clean (rc 0). W2's `wire_api_harness.c` writes a full
`REQMOD ... ICAP/1.0` request into an `AF_UNIX` socketpair, reads it with the
exported `ci_connection_read_nonblock()`, then calls the exported
`ci_headers_unpack()` and `process_encapsulated()`; 90/4242 again reproduce the
chosen value and UAF with clean controls. In the W1/W2 harness lanes the hidden
`ci_read_icap_header()`/`ci_wait_for_data()` are bypassed, so neither lane
reaches full `parse_header()`/`process_request()` or a network socket; wire
reach stays UNKNOWN for those lanes. W3 later reached the full parse path and
`process_request()` in a real loopback c-icap server, and W4 observed the
wire-selected value in that server's live aliased slot; both are author-only
and unwitnessed. No r5; GitHub has no 0.6.6 tag, so the fixed control is
patch-derived. Digests and scope in
`lab/frontier/cicap2shell/PROVENANCE.md` § "Real c-icap build".

### Assimp2Shell W18 clean-archive replay across a second heap layout
`git archive 5424cec5` into `/tmp/w18-clean` with 10/10 pins OK; after the
gitignored `harness/bin/w12_o2` driver is present, unmodified
`bash harness/run-w18.sh` gives 8 PASS / 0 FAIL again. The harness
self-calibrates to its own begin `0x555555570250` (word `55570250`), keeps
`scene=ok` and plain rc 139; normalized traces are byte-identical to the
author tree (digest recorded in `reports/frontier-assimp2shell.md` § W18).
Layout-dependent calibration works across two heaps; author replay, not
witness acceptance, no grade or r5 change.

## 2026-11-24 18:4x–18:5xZ — forged-header consumers and a transient tcache head

All limbs below are author-side and unwitnessed; no rung cell, admission or
mind count changed.

### Munt2Shell W183/W184 — downstream and in-library consumers of the forged top chunk
Same pins and pinned tarball as the Munt row above (`81f8c462…f875`; tarball
and regenerated `vuln`/`fixed` trees are gitignored). W183:
`cd lab/frontier/munt2shell/real && ./live_probe.sh` runs the committed
`live_driver.cpp` against plain static libraries; an `operator new[]` hook and
`--wrap=malloc` only log allocations, with input buffers from `__real_malloc`.
A second legitimate `parseStream()` past the 32768-byte capacity takes the
overrun branch into the default `ReportHandler::printDebug` → libc `vprintf`;
the stdout buffer allocation consumes the forged top chunk. Expected rc/header
matrix: vuln `shaped` 0 with header changed to `11 10 00 00…` and the library's
own `"parseSysexFragment: SysEx messag..."` string at `buf+32784`; `unshaped`
134 `malloc(): corrupted top size`; `none` 0 with header unchanged;
`shaped-nobuf` (`stdbuf -o0`) 0 with header unchanged (no string); vuln `safe`
and fixed `safe`/`fixed` 0 with no 32768-byte allocation. The clean-archive
receipt in `REPLAY.md` (commit `1a02552f`) rebuilt from the ignored tarball and
reports all seven rc cases and eight normalized files identical (`FAIL=0`).
No chosen overflow byte is read back: this consumes the forged header, not the
tail.

W184: `./push_probe.sh` rebuilds both pinned trees as static libraries with
`-DMT32EMU_WITH_TESTING` in `CMAKE_CXX_FLAGS` (test accessor hooks only, no
parser byte changed) and links each tree's own `src/test/FakeROMs.cpp` so
synthetic ROMs with the expected SHA1 let public `Synth::open()` create a real
`midiQueue`. First input is 40001 unterminated bytes with eight 7-bit bytes at
source offset 32776 forging top size `0x10001`; the second is a legitimate
102-byte SysEx with host-chosen `0x37` through public `Synth::playSysex()`.
Expected: vuln `shaped` rc 0, `pre_consume_header ...01000100` → `...71000000`,
`new[0] len=102` at `buf+32784` (`delta=32784`) and `tail=f03737…37` copied from
the *second* input; `unshaped` rc 134; `none` rc 134 at teardown
(`double free or corruption (!prev)`); `safe`, `shaped-nobuf` and fixed
`safe`/`fixed` as recorded in `evidence/push-results.txt`. `stdbuf -o0` leaves
`shaped` unchanged, so stdio is not this consumer. Clean `git archive f7b5491b`
replay in `real/PUSH_REPLAY.md`: 7 rc values and 7 `.out` files plus
`push-results.txt` matched after `0x[0-9a-f]+` → `0xADDR`; normalized digest
over the sorted eight files recomputed locally
`1e0d0c675fc1cafe28b94a11a05046cb37222c5b8f082e6bb2493977037f7848`. Grade
unchanged (real-library rungs 1-4 ESTABLISHED by witness #2781 at the earlier
scope, rung 5 UNKNOWN); synthetic-ROM build variant, no real ROMs, host, wire,
audio pipeline, chosen-tail readback, pointer control or command. Author
replays, no independent witness for W183/W184.

### Imgproxy2Shell W11/W11b — transient tcache head, second request untested
Same pinned imgproxy 4.0.15/fixed 4.0.16 binaries and libvips as the Imgproxy
row above. From `lab/frontier/imgproxy2shell/provision`, the read-only probe
`ico_tcache_thread_probe.py` (recomputed
`sha256=d2d2ecb180d5e0427366bad5d06ec169afdcc14484957dcf5c9cc1226d0e021c`)
reuses `ico_post_poison_trace.py` verbatim and changes only its GDB script:
`W8_OUTDIR=/tmp/w11-out python3 ico_tcache_thread_probe.py w11c4 0 20 2 gdb 0x35`
(loopback 127.0.0.1:18180/18181). Its log
`http-ico-w11c4.log` (recomputed
`sha256=802c0b94381505abff78ebc9c2c089b78ddae1a1d9bb7fc703a4b8780348e0ac`)
shows `GDB_TCACHE_PRE head=0x7fff8003ef10 count=7 thread=9
tcache=0x7fff800008e0`, decoded `0x7fff8003003e`; M1 returns the victim and
the head then reads the decoded value at count 6, while M2 at the same thread
and `tcache` address hits a fresh chunk at count 7 and again leaves the decoded
value at count 6; M3–M6 repeat with other chunks and every `WIRE=0`. The
decoded head is briefly at the top after a malloc and is buried by a natural
free before the next one: W10's tcache/TLS discrepancy is timing, not a
cross-thread read. `w11a1`/`w11a2` repeat it at other bases/threads;
non-victim layouts aborted on the top chunk with `RAW (nil)` and are preserved
in `/tmp/w11-out`, not retried into existence.

W11b's `ico_post_request_consume.py` (recomputed
`sha256=11586943663317277978c871f9d85dc2b066f5afabd4641d5807ae7582e60bcf`)
uses `W8_OUTDIR=... python3 ico_post_request_consume.py TAG LOW N PRELOAD gdb
SIZE BINARY` and issues a second benign GET after the hostile one, tracking
twenty natural `malloc(0x20)` calls. `http-ico-w11b-e2.log` (recomputed
`sha256=fa33f1215004c6a3d3c544f98c9be11464299784fca2ae6a1b666d0d31da8ac7`)
has twenty returns in two threads, all `WIRE=0`, with the spill away from the
live head (`GDB_WIRE_DECODED 0x4067`/`0x67` in the two survivor samples);
twelve further runs failed to get the second GET through, and in
`http-ico-w11b-g4.log` (recomputed
`sha256=ebcb231e8b33ce7ba4cd56d4dce8b4999ae2d268bf1ffb8cf228531b12eee710`)
the victim layout was present but the second GET returned
`RemoteDisconnected` because the twenty-malloc script had already called
`quit`. So the second-request route against a poisoned head is untested, not
a measured negative. Both probes import the committed W9 script by an absolute
lab path, so a relocated clean-archive replay needs that path adjusted; no
clean-archive replay or witness verdict is claimed for W11/W11b. Grade stays
rung 4, no wire-only key, marker, code-pointer write or r5; W204's verdict on
W9 is unchanged. Commands, hashes and failed samples are in
`lab/frontier/imgproxy2shell/PROVENANCE.md` W11/W11b.

## 2026-11-24 20:4xZ — PxeIcmp2Shell staged replay

Operator replay of frontier W214: `cd lab/frontier/pxeicmp2shell &&
sh harness/run.sh` gave **31 PASS / 0 FAIL, rc 0**. The harness rechecks
the four pin hashes, re-extracts the IPv4 and IPv6 handlers byte-for-byte
from the pinned `PxeBcSupport.c.vuln`/`.fixed`, builds plain and ASan binaries,
and reports ASan `heap-buffer-overflow`, `WRITE of size 96`, `0 bytes after
720-byte region` at `generated/handlers_vuln.c:97` in both families. Plain
runs place the chosen fragment bytes `48 5a 4d 49` at `TftpError + 96` and
`54 41 55 46` in the adjacent canary, matching the pinned cumulative-length
arithmetic; fixed-source attacks, 300-byte safe inputs and the clean-directory
replay are clean. This is the author/operator harness, not an independent
witness verdict; no EDK2/OVMF build, live ICMP error or DXE process was used.
Superseding that author/operator-only note: independent witness #3852 (clean
`git archive` of `3a0fda26`) returned ESTABLISHED AS LABELED with 31 PASS / 0
FAIL, all four pins, byte-exact handler extraction, the same ASan report and an
independent 16-byte non-periodic marker probe. No grade change and no r5; the
no-firmware / no-live-ICMP / no-DXE-process caveat still stands.

## 2026-11-24 21:2xZ — N2n2Shell staged replay

Operator replay of frontier W215: `cd lab/frontier/n2n2shell &&
sh harness/run.sh` gave **15 PASS / 0 FAIL, rc 0**. The harness rechecks the
pinned vulnerable and fixed `wire.c` hashes, re-extracts `decode_buf()` and
`decode_REGISTER_SUPER_NAK()` verbatim, builds plain and ASan binaries and
checks the controls. Vulnerable `token_size=96` faults under ASan with
`heap-buffer-overflow`, `WRITE of size 96`, `0 bytes after 64-byte region` at
`generated/handlers_vuln.c:47` and `:81`; the fixed decoder rejects the
oversized token with `-1` and stays clean. Plain vulnerable runs place the
chosen wire bytes `48 5a 4d 49` in `canary[0..3]` (token offsets 50..53);
the 48-byte safe input leaves `ab ab ab ab`. This is the author/operator
harness, not an independent witness verdict; no supernode build or live UDP
datagram was used, and the advisory's stack attribution stays a claim.

## 2026-11-24 22:1xZ — LibRaw W15 third disjoint OOB heap band

Frontier W15 extends the real `dcraw_emu` consumer with raw rows 150..159 set
to sample 5 and `curve[5]=0x2468`, placing a third independently file-chosen
16-bit value in OOB halfwords 33,000..40,000 while preserving W14's
`0x1357` band at 9,000..28,000. A `-O0` gdb probe sampled every 1,000
halfwords from the first write onward and a focused probe read `2468` at
33,000 and 36,000 byte-identically across three fresh runs; the unchanged
ASan vulnerable build reports `WRITE of size 2` at
`xtrans_demosaic.cpp:427`, fixed and no-option controls are clean. Row
250..259 and rows 90..99 variants are preserved negatives. Three chosen
16-bit values in three disjoint bands are still not an arbitrary byte
sequence; no pointer/IP, marker, command, adjacent live object, GUI or wire
path and no r5. Author-side only, unwitnessed; hashes and full probe traces
are in `lab/frontier/libraw2shell/w15/results.txt`, summarized in
`reports/frontier-libraw2shell.md` §W15.

## 2026-11-24 21:5xZ — OpenEXR W190 live tcache `next` in unmodified exrcheck

W188/W189 found no tcache pointer in the 384-byte copy window at their fixed
sample count. W190 sets `N=1072` so the second inverse-sort copy covers
`dst+4288..+6432`; a live 0x90 tcache head at `dst+4304` has its safe-linked
`next` word changed from a heap pointer to the file fill byte (`0x5a`, `0x3c`
and `0x00` variants tracked byte-for-byte) in the UNMODIFIED pinned
`exrcheck -c`. `sh harness/w190-tcache-check.sh` printed `RESULT PASS`,
byte-stable across three runs, check sha256
`ba155b40d9fb04aea70cb7a00eda7fe72b1a593eaded0dcd2be1cae42de087ea`. A clean
`git archive ecf3f821` replay (gitignored source/build trees symlinked) gave
`RESULT PASS`, rc 0, with all six core evidence hashes and the check hash
byte-identical. This is rung 4 file-chosen bytes in live heap metadata, not
steering: no malloc from the poisoned tcache was observed, the consumer aborts
in `double free or corruption (!prev)`, ASan reports `READ of size 4288` and
fixed 3.5.3 rejects with `bad` (rc 1). No code pointer/IP, control flow,
command, marker, wire or witness verdict; author-side only, r5 UNKNOWN.
Ceiling and hashes: `reports/openexr2shell-status.md` §W190 and
`reports/openexr2shell-file-level.md` §W190.

## 2026-11-24 22:2xZ — pgactive2shell staged replay and admission

Operator replay of frontier W216: `cd lab/frontier/pgactive2shell &&
sh harness/run.sh` gave **19 PASS / 0 FAIL, rc 0** (`RESULT 19 PASS /
0 FAIL`). The harness rechecks the 13 pinned SHA-256 hashes (two full
release archives, both `pgactive_catalogs.c` and `pgactive_internal.h`
copies, both generated function files and the harness sources), extracts
the vulnerable and fixed parser functions verbatim, and builds plain and
ASan binaries. Vulnerable ASan reports `stack-buffer-overflow`, `WRITE of
size 97`, at offset 96 in the frame with `[32, 96) 'replication_name'
... overflows this variable` in `generated/functions_vuln.c:20`; the fixed
decoder uses `%n` plus `riname[parsed_len] != '\0'` and rejects with
`RET=-1`. Plain vulnerable runs read chosen `48 5a 4d 49` inside the live
function at offsets 0, 64 and 92 of the 64-byte name, then abort with
stack smashing; the safe input is accepted with `RET=0`.

This is the author/operator harness, not the witness verdict. Witness
W209 (#3898, answering #3885) independently replayed the same harness from
`git archive HEAD lab/frontier/pgactive2shell` at HEAD `04f6dcf9` with all
13 pins exact and graded **ESTABLISHED AS LABELED**: rungs 1-3 plus rung 4
PARTIAL at the pinned-function scope, NO r5, no real PostgreSQL/pgactive
build, SQL or replication wire path, pointer/return address, IP or command;
`PR:L` remains part of the claim. Admission under standing #6 added the
route 136→137, both resolver keys 274→276, the three units from the EXACT
full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
(`written 3, removed 0`), daemon-reload, path enabled/active and pinned
doctor GREEN rc 0; `python3 tools/check-omp-only.py` reports GREEN with
137 declared roles. Frontier's live two-pane window 145 was adopted
without duplication. Ceiling and hashes:
`reports/frontier-pgactive2shell.md`, `reports/pgactive2shell-status.md`.

## 2026-11-24 22:1x–23:3xZ — live wire/real-app lanes and staged Open5GS

Edges after `d40ddefd` add four evidence paths. All are author/operator
observations unless a witness verdict is named; no grade cell moves.

- PHP `drupal-afterRCE` (`9206e998`): provision real Drupal 11.4.13 with
  `lab/php2shell/provision-drupal-app.sh`, build release-like PHP 8.4.27-app
  with `lab/php2shell/build-app.sh`, then run
  `sh lab/repro/php2shell-aftershell-splice-drupal.sh` with the advisory's
  session ini on loopback FastCGI. Expected: an unauthenticated CVE-2026-126714
  rfc1867 splice promotes a chosen `evil|O:8:"stdClass"` session record into
  the app's session write and `/user/1` returns an ACCOUNT TAKEOVER redirect;
  the 8.4.28-app fixed control leaves no splice or takeover. Rung 4
  DEMONSTRATED at that conditioned scope (vulnerable ini, shim SIGKILL
  interruption as rung-4 mechanics); Drupal core gives no PHP execution and
  r5 stays UNCLAIMED. The underlying 126714 wire splice was
  witness-ESTABLISHED on real FPM in wakes 9-10; this real-app consumer lane
  is author-observed. Raw logs are gitignored under `lab/build/evidence/`;
  regenerate with the committed scripts and see
  `reports/php2shell-status.md` §Wake 58.
- n2n2shell W1/W2 (`0224c87e`, `7acea993`, `ae9fb6af`, `ecf806a6`,
  `0d4b3584`): build the pinned real supernode (`CC=gcc
  CFLAGS=-fsanitize=address ./configure && make -j4 supernode`), run it on
  127.0.0.1 with the lab community file, and send one crafted NAK from
  `lab/frontier/n2n2shell/live/send_nak.py`. Expected: ASan
  `stack-buffer-overflow WRITE of size 96` in the live `nak`, 96 chosen bytes
  at `nak+14..109` under gdb including two pointer-shaped slots; fixed and
  safe controls clean. W2's hardware-watchpoint follow-ups
  (`w2_followup.py`, `gdb-cmds-w2.txt`) saw no post-decode consumption of
  those slots, and follow-up decoders clear reused storage. No consumed
  pointer, canary/return-address control or command; the live limb is
  unwitnessed. Evidence: `reports/n2n2shell-live.md`,
  `reports/n2n2shell-status.md`.
- pgactive SQL path (`af1001e0`): `lab/frontier/pgactive2shell/sqlpath/run.sh`
  and `run-asan.sh` compile the pinned parser and SQL wrapper against real
  PostgreSQL 16.15 headers into a loopback-only cluster and call
  `pgactive_parse_replident_name(text)` with an 80-byte overlong name.
  Expected: the plain vulnerable backend errors without crashing
  (`elog(ERROR)` longjmps before the canary check), the ASan-preloaded
  backend reports `stack-buffer-overflow WRITE of size 161` at `parser.c:62`,
  and the fixed library rejects; logs in `sqlpath/evidence/`. No chosen-byte
  capture on the SQL path, no replication wire path (this `sqlpath/` lane
  alone has no full build; a later `realbuild/` lane is folded at §02:2xZ),
  no pointer/command/r5, and no independent replay of this addition. See
  `reports/frontier-pgactive2shell.md` §Real PostgreSQL SQL path.
- Open5GS staged (`2eeee948`, `22d70741`):
  `sh lab/frontier/open5gs2shell/harness/run.sh` builds the pinned v2.8.0
  parser with stand-in headers: 21 PASS / 0 FAIL, with a clean-archive replay
  of `2eeee948` giving the same result and a trace hash recorded in the brief.
  Expected: ASan `WRITE of size 1` 0 bytes after a 65-byte region, and plain
  canary bytes `0a000d0a000d0a000d0a000d` in the first 12 adjacent bytes;
  safe input and fixed build clean. FRONTIER-STAGED only: no real Open5GS
  build, SBI listener, wire request, pointer, command, admission or witness
  verdict. See `reports/frontier-open5gs2shell.md`.

The remaining commits in this range (assimp W22-W24, cicap W6-W8, gpgme
W2-W4, hping W4, imgproxy W14, libgphoto2 W177/W178, openexr W191/W192,
codebasememory W12 and the jq 32-bit-toolchain negative) are replay receipts
or bounded negatives whose README rows already state the right ceiling; each
points to its own report and committed harness.

### Late lane entries for the same fold

Add these to their target lanes; commands are committed, raw output is
gitignored and regenerated by the named scripts:

- Assimp: `run-w22.sh`, `run-w23.sh`, `run-w24.sh` and `run-w25.sh` in
  `lab/frontier/assimp2shell/harness/` — W24's plain build prints
  `TAUF_MARKER_CALLED`; W25's preserved negatives give 8 PASS / 0 FAIL with
  trace sha256 `5532748382…e5d6fa5f864` (recomputed from the committed
  `w25/evidence/w25.trace`). Report `reports/frontier-assimp2shell.md` §W22-W25.
- Gpgme: `build-real.sh`, `make-realkeys.sh`, `run-real-gpg.sh` (36 PASS),
  `run-wire.sh` (32 PASS, listener on 127.0.0.1:11372) and `run-reuse.sh`
  (24 PASS); `reports/gpgme2shell-status.md` §W2-W4. Independent replay
  requests #3808/#3911/#3919/#3945 remain UNKNOWN. W5 adds
  `run-wire-reuse.sh` (55 PASS / 0 FAIL, chosen `0x48`/`0x5a`/`0x37` from the
  loopback HKP status line and the next-operation free), a six-suite clean
  replay from `72f3b6ad` and `reports/gpgme2shell-status.md` §W5; replay
  request #4028 with receipt #4029 has no witness verdict.
- CodebaseMemory: `control-flow-bypass.sh` for W12's empty-property stride;
  `reports/codebasememory2shell-status.md` §W12.
- Imgproxy: `replay-w13.sh` at `2e6b4d16` gives `REPLAY_W13_OK` 3/3 and
  `code_ptr_qwords=0`; `reports/frontier-imgproxy2shell.md` §W14.
- Libgphoto2: `replay-vusb-shortreply.patch` plus the W177 canary/rbp probe;
  `reports/frontier-libgphoto2shell.md` §W177/W178.
- OpenEXR: `w191-abort-cause-check.sh`, `w192-inbounds-check.sh`,
  `w193-chosen-pointer.sh` and `w194-fault-attribution.sh` with
  `harness/w194-fault.cmd` (ASLR explicitly on) plus the `setarch -R`
  control; `reports/openexr2shell-file-level.md` §§W191-W194.
- Cicap: `replay-all.sh` covering W1/W2/W3/W4/W6, 72 PASS / 0 FAIL from a
  clean archive including self-fetch; `reports/cicap2shell-status.md` §W6-W8.
- Hping: `replay-all-wire.sh`, `REPLAY_ALL_WIRE_OK` with 19 checks;
  `reports/hping3shell-status.md` §W4.
- Jq: GHSA-29gj-222p-j7vx second advisory needs a 32-bit `size_t` and a
  13-byte allocation; no i386 multilib is installed, so `-m32` cannot link
  even a trivial program. Disposition: named negative, no reopen, no grade
  or guard change; re-offer only with a working 32-bit jq and a lower-memory
  trigger. `reports/jq2shell-status.md` §32-bit toolchain.

## 2026-11-25 00:0xZ — post-`7f1d85db` replay receipts and measured limbs

Commands are committed; raw logs are gitignored and regenerated by the named
scripts. All limbs below are author-side: no witness verdict, rung cell or
mind-count change.

- FontForge W9 (`a7c3fb38`): from a clean tree run
  `sh lab/frontier/fontforge2shell/replay-real.sh` (sha256
  `156dd58378a4fa9e82845a93d93066125fe3dc452433f07b5b9628a6acca9261`).
  Expect the W8 `Open()` matrix vulnerable plain 134, ASan 1 with
  `WRITE of size 4` at `fvimportbdf.c:1751`, patched 0/0 and complete-table
  controls 0, with chosen `4d 49 53 00` at `encs-4`. W6/W7 consumer exit
  codes depend on the build path (clean `/tmp/lab/...` 134/139 vs live 0):
  do not treat a different path as the same claim. See
  `reports/frontier-fontforge2shell.md` §W9 and `REPLAY.md`.
- Hping W5 (`35891e22`, `418dfa1b`): run
  `sh lab/frontier/hping3shell/wire/rng-proof.sh` (sha256
  `dedea1e1aed6925df00ee5e415f6f364d2ba96ea4ced4c572ab5ed2856105b44`,
  checker `27d15e6aae4048483a037592b2b644323d437aa25c6d0822cd2c6bf3eb5985da`)
  with `-D -1 -G --rand-dest -I lo`, reading state only through GDB.
  Expect baseline 4 PASS / 0 FAIL and attack 6 PASS / 0 FAIL with
  `rc4_sbox[0..45]=0x13…0x40`; a clean archive of `35891e22` repeated both
  counts, but the concrete destination byte varies with `/dev/urandom`. The
  `--rand-source` attempt is a preserved `NO_TAINT` negative. See
  `reports/frontier-hping3shell.md` §W5.
- LibRaw W16/W17 (`81392c3c`, `eaee49cf`): from a clean archive run
  `git archive HEAD lab/frontier/libraw2shell | tar x -C /tmp/lr-clean` and
  `cd /tmp/lr-clean/lab/frontier/libraw2shell`, then `sh replay-all.sh` (sha256
  `c53ed205d02c251516076f4d57c7af40f755fbb4d5bce04e7f79a126aec87828`);
  expect `PASS=31 FAIL=0` and `REPLAY_W13_W14_W15_OK`, reproduced from a
  clean `81392c3c` archive. For the wire lane run
  `sh wire/run.sh w15/band150.input OUTDIR` (sha256
  `159850e72c747a54795e40f948c9b91c97de9f5d1c45e6edfbf92e1474385407`,
  decoder `d6e54904fed35a2cfabc53c9fbc6ed7c6cb239756a707a989eb497c3547dfece`);
  expect `WIRE_OOB_OK` three times with ASan `WRITE of size 2` at
  `xtrans_demosaic.cpp:427` after 664,550 received bytes, and rc 0 with the
  no-option and fixed decoders. No marker, pointer or r5. See
  `reports/frontier-libraw2shell.md` §W16/W17.
- PHP `tfm-stage1` (`9b9cc020`, author harness, no report verdict): run
  `bash lab/php2shell/provision-tfm-app.sh`, build 8.4.27-app and 8.4.28-app
  with `lab/php2shell/build-app.sh`, then
  `bash lab/repro/php2shell-aftershell-splice-tfm.sh <php-fpm-bin> <tfm-web>`
  (script sha256 `361f113a3af012428d6717edb353a92f65879a2b7de7da671e58fc06cbe43405`,
  provisioner `1dcf36e7e2f854699575e198bc4e7a01568047fcdf3e1e922c3c37ef546aaca9`).
  Expect splice, promoted `filemanager|…logged…admin` session, designed
  admin upload and a live-worker marker on 8.4.27-app; no-kill, virgin-sid
  and 8.4.28-app controls stay clean. Worker death is the committed shim,
  not attacker-caused: stage 1 only, no witnessed r5, R5 cell stays `—`.
  Logs gitignored under `lab/build/evidence/`.

## 2026-11-25 00:4x–01:0xZ — W10/W15/W25/W6 and PHP wake 59 receipts

All five limbs are author-measured and unwitnessed; no rung cell, grade, route
or mind count moved. Raw evidence stays gitignored; regenerate with these
committed scripts. Hashes below were recomputed locally from the checkout.

- FontForge W10 (`8781a538`): from `lab/frontier/fontforge2shell`, run
  `python3 make-value-ceiling.py` and `python3 make-ptr-target.py`, then use
  the committed `gdb-value-ceiling.cmd`, `gdb-ptr-target.cmd` and
  `gdb-ptr-ident.cmd` against the real plain build; `sha256sum -c
  value-hashes.txt` returned 13 OK (rc 0). Expect the four-byte write bounded
  at `0x0100FEFF` for W10's `i=0` input (`0x21` → `0x0100feff00000021` at
  `encs-4`; W12 raised the true ceiling to `0x01FFFE00`) and `glyph=-50`
  changing a pointer field at `encs-200` from `0x0000555555c227f0` to
  `0x0000555500414243`; W11 identified that field as `BDFChar.bitmap`
  (`chunkalloc` = `calloc(104)`), not the `char*` W10 called it, and found no
  dereference on this one `Import()` path (patched/in-bounds builds clean).
  Details in `VALUE-CEILING.md`, `DEREF.md` and
  `reports/frontier-fontforge2shell.md` §§W10/W11.
- Assimp W25 (`aa2aedc7`, replay `fda2b66c`): after
  `bash lab/frontier/assimp2shell/bootstrap.sh` with the pinned tarball in
  `pins/`, run `bash lab/frontier/assimp2shell/harness/run-w25.sh`. Expect
  8 PASS / 0 FAIL and trace sha256
  `5532748382ca4383a9ff39354e1c8910192592c3e46b72176d859e5d6fa5f864`
  (committed `w25/evidence/w25.trace`). From `git archive aa2aedc7
  lab/frontier/assimp2shell` into `/tmp/w25-clean` with the local tarball
  copied in, both libraries and both `-no-pie` drivers rebuild and repeat the
  byte-identical trace. Author-only negative: the default `-O0` canary at
  `dest+4` aborts rc 134; without it only the low half of saved RIP at
  `dest+12` is writable, rc 139, while W24's 64-byte MAT4 still calls the
  marker. Receipt in `lab/frontier/assimp2shell/REPLAY.md` §W25.
- Synchronet W15 (`e0f11cd4`, replay `b595e239`): symlink the gitignored
  `src-tree/` (parent `42f586d7`) and `provision/` from a live tree into a
  clean `git archive e0f11cd4 lab/frontier/synchronet2shell` extraction, then
  run `bash real-answer/validuser/run-validuser.sh`. Expect
  `VALIDUSER RESULT: PASS=4 FAIL=0`, `PROBE_COUNT=2`, `ANYAUTH_LOG_COUNT=0`:
  a real `sbbs3` on 127.0.0.1:22229 with default options but no
  `SSH_ANYAUTH`, an offline-created `lab` user with a valid password, chosen
  64-byte TERM bytes at offsets 41/44/48/52 and a clean 40-byte control. The
  author replay matched both client logs byte-for-byte; server log lines
  differ only in their `11/25 HH:MM:SS` timestamp prefix. Pre-auth pty-req
  stays W9's negative. Receipt in
  `lab/frontier/synchronet2shell/real-answer/validuser/REPLAY.md`.
- Hping W6 (`650f9517`..`bf1360dd`): create `/tmp/w6-wit`, then run
  `git archive 659f6eb0 lab/frontier/hping3shell | tar x -C /tmp/w6-wit`,
  copy the gitignored `provision/` tree into the extracted target, and run
  `HPING_SRC=$PWD/lab/frontier/hping3shell/provision/hping-src sh
  lab/frontier/hping3shell/wire/replay-rngctl.sh` from that tree. Expect
  `STAGE OK baseline 4`, `STAGE OK fill32 6`, `STAGE OK fill64 6`,
  `STAGE OK fixed 4`, `REPLAY_RNGCTL_OK: 20 checks`, rc 0; the final author
  replay measured 15/16 and 17/17 post-attack probe destinations equal to the
  chosen low byte. The composed replay script is sha256
  `5bd5a97159adccdaa3a32e53ef7816af5037274fea06c2081a19704a66f5fcde`.
  Control is probabilistic (hidden `i`/`j`, 69 unreachable sbox bytes); no
  full IP, pointer, command or r5. Receipt in `reports/hping3shell-status.md`
  §W6.
- PHP wake 59 (`d7dae529`): provision and build the tinyfilemanager 2.6 app
  with `bash lab/php2shell/provision-tfm-app.sh` and
  `bash lab/php2shell/build-app.sh`, then run
  `bash lab/repro/php2shell-aftershell-splice-tfm.sh <php-fpm-bin> <tfm-web>
  [outdir] [port]` (sha256 `361f113a…cbe43405`). On 8.4.27-app the unauth
  126714 splice promotes `filemanager|a:1:{s:6:"logged";s:5:"admin";}` into
  the app's admin session; its DESIGNED upload places `/evil.php` and the
  live worker executes it (unique marker plus `id` and a marker file under
  the lab tmpdir). 8.4.28-app, no-kill and virgin-sid controls stay clean.
  Stage-2 death probes use `python3 lab/repro/php2shell-slow-fcgi.py PORT
  SCRIPT_FILENAME BODYFILE [--param K=V] [--pre-delay SEC] [--chunk BYTES]
  [--rate BYTES_PER_SEC] [--hold SEC]` with the timestamped LOG_ONLY
  `AFTERSHELL_LOG_ONLY` shim; SIGTERM is handled mid-pwrite, cgroup OOM fires
  only on truncate-first writes (page-quantized `4096 x 87913` partial), and
  io.max/PHP fatals are ineffective. Death in stage 1 is still the shim, so
  r5 stays UNCLAIMED. Logs gitignored under `lab/build/evidence/`; details in
  `reports/php2shell-status.md` §Wake 59.

## 2026-11-25 01:1x–01:4xZ — W194/W11/W14/W16/W3/W4 and yojimbo staging

All limbs below are author-measured and unwitnessed; no rung cell, grade,
route, mind count or R5 cell moved. Raw evidence stays gitignored; regenerate
with the committed scripts. Hashes marked "recomputed" were checked locally
from the checkout at this wake; normalized-log digests are quoted from their
receipts without a local recomputation.

- OpenEXR W194 (`dff3426d`, clean receipt `1d68f9d8`, ASLR control
  `b6e68db8`): `cd lab/openexr2shell-real && sh
  harness/w194-fault-attribution.sh` prints `RESULT PASS` rc 0. The committed
  `harness/w194-fault.cmd` explicitly sets `disable-randomization off`; with
  ASLR on, the first `exr_attr_list_destroy` dereference reads the stale dump
  pointer `E[0]=0x555555828210`, while the three file-chosen `E[2]` values
  never change the fault. Recomputed evidence sha256:
  `w194-fault-4141.out` `3710194e779f6a2538e26a38e643a667701a9e2fd0f719d5c455c12ac57d48bc`,
  `w194-fault-4242.out` `e87593d40f9fde46e0778c382bf305035217aee0644ba06d614d2da4c3a1e769`,
  `w194-fault-3131.out` `9de9ad7b29e8b6122820081d8bbd50c598d62f4ed89655a0b90f20b367fdec60`,
  valid `043d72d916be8948cd85f6937306e63355be57f21ad76fe7bc3c950b16286835`,
  fixed 3.5.3 `bad` `458fbb6e540a2905792366420810504cd72a35b05c68af839c8312259c6a7499`.
  The `setarch "$(uname -m)" -R` control exits rc 1 `bad` for all three PoCs;
  its three hashes are in `reports/openexr2shell-file-level.md` §W194. No
  chosen code pointer/IP, wire, command or r5; author replay only.
- FontForge W11 (`f3b9dd98`): from `lab/frontier/fontforge2shell`, with
  `FF2S_TARBALL` pointing at the pinned tarball, `sh replay-real.sh` reproduces
  the W8 `Open()` matrix; the appended `W11 file-chosen pointer dereference`
  section uses `import-value-atk50-save.ff`, `import-value-atkceiling-save.ff`
  and `gdb-deref.cmd`/`gdb-deref-ceiling.cmd`. Expect the added `Save()` to
  reach `sfd.c:1671` and fault rc 139 at `0x0000555500414243` (three chosen
  bytes) or `0x000055550100FEFF` on W10's claimed-ceiling input (true
  maximum `0x0000555501FFFE00` under W12) — `BDFChar.bitmap`, not the
  W10 `char*` label. Recomputed `gdb-deref.out`
  `1eb69600d354a42befb4bb391867ec05d81497d24bc66c108b203e140d512ac2` and
  `gdb-deref-ceiling.out`
  `f84d661d859aade7792f8eb44daad29263bb47f238b1c3c5cea7236fb024562f`.
  The reachable window lies below the lowest PIE mapping; a second import
  without `Save()` exits 0, patched/in-bounds controls are clean. Details:
  `DEREF.md`, `VALUE-CEILING.md`, `reports/frontier-fontforge2shell.md` §W11.
- CodebaseMemory W14 (`8e973719`): `bash
  lab/frontier/codebasememory2shell/far-stride-bound.sh` builds a throwaway
  harness from the pinned `cypher.c` and prints the live `[stack]` bound.
  Expect 512 bytes per projection item, an estimated saved-RIP slot at
  `callee_rbp+0x4198` above the mapping end in 16 placements (smallest
  `STACK_TOP-SP=0x1108` against a needed `SP+0x40a0`) and twelve 71-item
  attempts exiting 139 in `memcpy`. Recomputed `evidence/far-stride-bound.txt`
  sha256 `d93ab7b2894421428c024a3d026d0242ff3c8c2fbf89d3bcf672baba5a95b2f3`;
  W12's `control-flow-bypass.txt` is
  `e72b28a49a945b409b90de76635765cfefbbe1179931be1aee2d9d9910356ebb`.
  No live pointer use, command or r5; `reports/codebasememory2shell-status.md` §W14.
- Synchronet W16 (`be7d19a2`, clean receipt `f369f7b3`): from
  `lab/frontier/synchronet2shell`, after W15's `src-tree`/`provision` symlinks,
  run `bash real-answer/validuser/run-validuser-availability.sh` on a free
  port (do not run the W15/W16 drivers concurrently). Expect `VALIDAVAIL
  RESULT: PASS=10 FAIL=0` rc 0: four chosen 64-byte TERMs set
  `line_delay=0x4853494d`, four `sbbs/termNode hrtimer_nanosleep` threads and
  a fifth `!No nodes available for login.`, while the upstream fixed form
  serves five sessions with no refusal; both logs have zero `SSH_ANYAUTH`.
  Clean `git archive be7d19a2` replay matched all ten client transcripts; the
  normalized server-log sha256 values (`f29f5e39…a459070d` vulnerable,
  `e0661bc5…6c96e40ac1` fixed) are quoted in `REPLAY-W16.md`, not recomputed
  here. Two preserved pre-repair failures were driver defects (misplaced
  assertion, TIME_WAIT bind race), not target behavior. Author replay only.
- N2n W3/W4 (`7e939185`, `d8bec71b`, `f18dd8bf`, `e9351342`): one command,
  `sh lab/frontier/n2n2shell/live/replay-live.sh`, rebuilds the pinned tree
  three ways on loopback ports from `PORT_BASE=18700`, checks pins, and
  prints `RESULT 19 PASS / 0 FAIL` rc 0 here (checks 16-19 need `gdb`;
  `NO_GDB=1` skips them). Live word checks read `SLOT14=0x494d5a48494d5a48`,
  `SLOT96=0x5a48494d5a48494d`, `SLOT104=0x494d5a48494d` just after decode.
  The W3 peer-forwarding recipe stays separate: `live/w3_peer_forward.py`
  with `live/gdb-cmds-w3.txt` shows the 96-byte chosen DATA copy through
  `encode_buf` and a 134-byte forwarded NAK; `live/send_big_nak.py` with
  `live/gdb-cmds-canary.txt` leaves the canary intact at `token_size=2000`,
  and the 2048-byte receive caps reach at `nak+2024`. No consumed pointer,
  canary/return-address control, command or r5; witness replay #3909 owed.
  `reports/n2n2shell-live.md` §§W3/W4.
- Yojimbo2shell staged (`aaa7dc7a`): `sh
  lab/frontier/yojimbo2shell/harness/run.sh` builds four variants from seven
  pinned files (`sha256sum -c lab/frontier/yojimbo2shell/pins.sha256` is
  check 20) and printed `RESULT 20 PASS / 0 FAIL` rc 0 here, with ASan `WRITE
  of size 500` 0 bytes after a 1100-byte region and plain canary300
  At staging: no real yojimbo build, UDP wire, pointer, command, route,
  admission, witness verdict or r5; the upstream packet path is
  post-authentication. W1/W1b later built the real library and an
  authenticated loopback pair — see the 03:0x–03:1xZ lane below; no
  trace-hash receipt was claimed at staging.
  `reports/frontier-yojimbo2shell.md`, `reports/yojimbo2shell-status.md`.

## 2026-11-25 02:0xZ — admission receipts for three staged harnesses
The staged harnesses above are now the replay recipes of admitted targets.
No test command, pin set or grade changed; only the routes (138–140),
resolver keys, wake units and windows became live. `open5gs2shell`:
`sh lab/frontier/open5gs2shell/harness/run.sh`, 21 PASS / 0 FAIL, clean
archive `2eeee948`, witness W217 replay from `22d70741` with matching
trace hash. `yojimbo2shell`: `sh lab/frontier/yojimbo2shell/harness/run.sh`,
20 PASS / 0 FAIL, 7/7 pins from `lab/frontier/yojimbo2shell/pins.sha256`.
`libsshch2shell`: `sh lab/frontier/libsshch2shell/harness/run-all.sh`,
24 PASS / 0 FAIL, pins in `lab/frontier/libsshch2shell/pins.sha256`,
fixed-guard and safe-channel controls clean. Admission minted three units
per target at the pinned full-flag sync (`written 9, removed 0`); all
paths enabled/active and the pinned doctor GREEN. See `docs/task.md` §02:0xZ
and the three `reports/frontier-<target>.md` briefs.

## 2026-11-25 01:5x–02:2xZ — author replay receipts and W12 ceiling
No rung cell, grade, route or mind count changed here; all new scopes are
author-side and unwitnessed unless a prior verdict is explicitly named.
Recomputed locally at this wake: libssh `sha256sum -c pins.sha256` 9/9 OK
and munt `sha256sum -c PINS.sha256` 7/7 OK (each from its own lab directory),
libgphoto2 tarball `5df9e774eb4ab6087a193afff84dcafe9f666e3443fe29e73e6779f659ff7f28`,
FontForge `value-ceiling-high.pcf` `9a6b2603a873afc55819734ef3dada52232e6a2647502fd06ab04764ec2f6b82`
and `gdb-value-ceiling-high.out` `540d9b0b0b773a47e8ffb89ccf6f2fb71723170e143c3f06088d5e08c62091a0`.
The munt normalized seven-file digest `b06a4b42…e7c` and libgphoto2's
build-path-dependent `.so` hash are quoted from their receipts, not
recomputed here.

- Gpgme W5 (`72f3b6ad`, receipt `844eed91`): from
  `lab/frontier/gpgme2shell/realbuild`, `sh build-real.sh && sh make-realkeys.sh
  && sh run-wire-reuse.sh` gave 55 PASS / 0 FAIL rc 0 in the author run. The
  real `/usr/bin/gpg` fetches a 1234-byte-UID key from the loopback HKP server
  on 127.0.0.1:11372; `status_wire_reuse.c` prints `byte[1000]=0x48`/`0x5a`/
  `0x37` from the `[GNUPG:] IMPORTED` line, then a keylist on the same context
  faults in `_gpgme_op_reset → gpg_release engine-gpg.c:602`, freeing the
  block first freed by `realloc` at `read_status engine-gpg.c:1494`. Patched
  2.2.0, stock 2.3.1 and short-key controls exit 0 and start op2. A clean
  archive of `72f3b6ad` replayed 55/32/24/21/36/19 PASS, rc 0 throughout.
  Witness #4028 with receipt #4029 is a request, not a verdict; no pointer/IP,
  command, stock-layout claim or r5. `reports/gpgme2shell-status.md` §W5.
- Libgphoto2 W180 (`018f76d5`, `97c61c79`, `73a38aed`): `git archive HEAD
  reports/frontier-libgphoto2shell.md lab/frontier/libgphoto2shell | tar x -C
  /tmp/replay-w180`, then `TARBALL=/path/to/libgphoto2-2.5.34.tar.bz2 sh
  lab/frontier/libgphoto2shell/live/replay-real-w177.sh` rebuilds the patched
  vusb port and real 2.5.34 plain library, sweeps `DRAIN=20..40` unless
  `DRAIN=N` is set (`NO_GDB=1` skips the read-only gdb check), and observed
  4/4 pins OK, patched vusb `2b744f67…e57dde6`, selected DRAIN=20,
  `RESULT: 20 PASS / 0 FAIL`. Three k=1023 canary records
  (`OWN_CANARY=8a17bc30d6578900` etc.), three k=1024 stack/code words, a gdb
  byte-for-byte match, count=100 rc=-108 and a stack-smashing full-reply
  control; the committed raw log
  `lab/frontier/libgphoto2shell/evidence/real-plain-w180-one-command.out`
  hashed to `146284f9…fae0257d` here. The disclosure reaches a HOST consumer
  through real `gp_camera_file_get()` on a lab-patched vusb reply; W176 still
  holds, witness #2892 stays scoped to rung 3, and there is no device readback,
  wire path, command or r5. `lab/frontier/libgphoto2shell/REPLAY.md` §W180.
- Munt W186 (`31fd23fe`, `e224af08`): in `lab/frontier/munt2shell/real`,
  `./prepare_src.sh && ./build_and_run.sh && ./build_clang_asan.sh &&
  ./partial_probe.sh` runs the 32785-byte SysEx driver through real
  `DefaultMidiStreamParser::parseStream()`. The harness `Victim` at
  `buf+32784` has its function-pointer low byte changed from `0x67…` to
  `0x49…` by the single input byte at index 32784 and calls benign
  `marker_1` in vulnerable plain; fixed/safe cases do not, and vulnerable
  ASan reports `WRITE of size 32785` 0 bytes after the 32768-byte region.
  The clean-archive replay receipt `real/PARTIAL_REPLAY.md` matched six rc
  cases and seven normalized evidence files with digest `b06a4b42…e7c`
  (quoted); raw `partial-results.txt` hashed to `c41e3761…9e034a6` here.
  No real library object with a function pointer at that offset, no ASLR
  defeat, host/wire input, command or r5; witness #2781 remains scoped to the
  older real-library rungs 1-4.
- FontForge W12 (`5e984cd9`): the author folded the corrected ceiling into the
  README but not into these docs. `CEILING-CORRECTION.md` derives the true
  maximum `0x01FFFE00` at `i=65535` (`d=max2-min2+1=1`), not W10's `i=0`
  `0x0100FEFF`: `gdb-value-ceiling-high.out` shows watchpoint word
  `0x01fffe0000000021` and bytes `00 fe ff 01` at `encs-4` (plain rc 134,
  patched 0, ASan 1 at `fvimportbdf.c:1751`). Byte 3 stays 0/1, the window is
  unmapped, and witness #3309 still covers direct-call rungs 1-4 only.
- Libsshch2shell (`99e12353`, `0be2eacb`): the staged harness and W220 handoff
  were folded by the 02:0xZ admission receipts above. The 01:58Z rerun of
  `sh harness/run-all.sh` scored 24 PASS / 0 FAIL with 9/9 pins; the fresh ASan
  report keeps `READ of size 32` 0 bytes inside a 64-byte region at
  `channel_default_bufferize` (`channel_rcv_data.inc:85`). No new witness
  verdict, real SSH build or wire packet.
- OpenEXR W195 (`reports/openexr2shell-file-level.md` §W195): `cd
  lab/openexr2shell-real && sh harness/w195-chosen-deref.sh` printed
  `RESULT PASS` rc 0; eight file-chosen `0x4141414141414141` bytes at
  `outPtr+4176` are the dereferenced pointer (`FAULT_R13` at
  `attributes.c:305`, ASLR on under gdb) with plain rc 139, valid rc 0 and
  fixed 3.5.3 rc 1 `bad`. Five evidence hashes were recomputed locally from
  the committed files (deref `4cf037d2…a53a87d`, plain `8a1ab80b…dbe6`,
  valid `043d72d9…86835`,
  fixed `b1c19c3f…4a49`, ASan `3a10b1d3…4fd55d`); a 02:21Z clean-archive
  replay from `git archive HEAD lab/openexr2shell-real` matched them all.
  Author replay, not a witness verdict; chosen value unmapped, no chosen
  data read, IP, wire, command or r5.
- Pgactive2Shell (`20123ce2`): from `lab/frontier/pgactive2shell/realbuild`,
  `PROVISION.md` records the extracted PG16.15 packages and build flags;
  `sh run-real.sh` builds and loads the complete pinned 2.1.9 extension into
  a loopback cluster, and `sh run-real-asan.sh` with the ASan library and
  libasan preloaded reports `stack-buffer-overflow WRITE of size 161` at
  offset 96 of `[32, 96) 'replication_name'`, frames
  `pgactive_parse_replident_name src/pgactive_catalogs.c:351` and
  `pgactive_parse_replident_name_sql src/pgactive.c:1531`. The 2.1.10 control
  rejects, safe names succeed, and the plain vulnerable backend errors
  because `elog(ERROR)` longjmps before the canary check. Both fresh installs
  revoke PUBLIC EXECUTE; no chosen bytes on the SQL path, replication wire,
  saved pointer/IP, command or r5. Author-run and unreplayed; witness #3896
  covers only the original standalone harness.
  `reports/frontier-pgactive2shell.md` §Full pinned extension.
  A clean `git archive 20123ce2` replay (`ba19500c`) of those three scripts
  matched the rc matrix (`vuln_SAFE=0`, `vuln_ATTACK_RC=1`, `fixed_SAFE=0`,
  `fixed_ATTACK_RC=1`, `ASAN_ATTACK_RC=2`) and the same ASan frames; still an
  author replay, not an independent witness verdict.

## 2026-11-25 02:29–02:4xZ — gpgme W6, open5gs W1, n2n W5, libgphoto2 W181
All four limbs are author-side unless a witness verdict is named. No rung
cell, grade, route, mind count or R5 cell moved; rung 5 stays UNKNOWN.
Raw build outputs named below are gitignored and regenerated by the commands
shown; committed evidence files are kept where noted.

- Gpgme W6 (`3aaa3f07`, clean-archive receipt `67a874c2`): affected GPGME
  2.2.0, fixed upstream by `14499348` and released in 2.3.1. Source
  `https://gnupg.org/ftp/gcrypt/gpgme/gpgme-2.2.0.tar.bz2` (sha256
  `7160e80e84dafd00d956c84891c533bb7ab16a6a54fbe1574b2f3acf0496977b`);
  pinned `engine-gpg.c` `c4ef11bd…979311d55`, fix patch `2fde658a…49c500`
  and patched source `10179f78…b75b08`, listed in `realbuild/REALBUILD.md`.
  From `lab/frontier/gpgme2shell/realbuild`, `sh build-plain.sh &&
  sh run-plain.sh` builds both plain trees with `CFLAGS=-g -O0`, `CC=clang`,
  `--enable-static --disable-shared` into `prefix-plain`, no sanitizer;
  `sh run-plain.sh` observed here printed `PASS=13 FAIL=0` rc 0. Expected:
  on glibc 2.39 vulnerable rc 134 with
  `free(): double free detected in tcache 2` after `byte[1000]=0x48`,
  `arglen=1200`, no second keylist; patched rc 0 with `op2 keylist_start
  err=Success`, `op_marker=Z arglen=20` and `release done`. The tcache abort
  precedes metadata/control-flow use, so this closes only the real-build
  plain-glibc UNKNOWN negatively; the parent statement harness keeps its
  own contradictory UNKNOWN. `evidence/reuse-plain-{vuln,fixed}.out/.rc` are
  gitignored; rerun the two scripts to regenerate. The `67a874c2` archive
  replay reused four provisioned trees copied from the working tree (no
  network) and matched rc 134 / 0 and 13 PASS / 0 FAIL. Tape #4039 is a
  witness scope note, not a verdict. `reports/gpgme2shell-status.md` §W6.

- Open5gs W1 (`6d5f8de9`, clean-archive receipt `318023f3`): affected
  Open5GS 1.3.0–2.8.0, fixed by `6820c2743b5b5e126e3755d2f92dae2b236732df`;
  claim URL and GHSA-25v2-v588-jq8g in `reports/frontier-open5gs2shell.md`.
  Five pins in `lab/frontier/open5gs2shell/pins.sha256`, including parser
  `dd49438c0792b6746b3b7eddd2820f1b17d06db5c68ff8a656931556f39da092`
  and message source `a9678094c367e10c6ef4213b645ef23d55986616ad4ffd0af96e021687fcf64d`.
  `sh harness/run.sh` scores 21 PASS / 0 FAIL rc 0; observed ASan
  `WRITE of size 1` 0 bytes after a 65-byte region at
  `multipart_parser-v2.8.0.c:260`, allocation at `:82`, plain canary
  `5a5a…` -> `0a000d0a000d0a000d0a000d`, safe and fixed clean. Witness
  message #3934 (wall W210) replayed clean `git archive 22d70741` with the
  same 21/0 and trace SHA-256
  `6c3c5ecf1f9e4ec7ef8d907d24e033e16fe4b87d62408ef1c499c95086164253`,
  verdict ESTABLISHED AS LABELED at that staged-harness scope, no grade
  change and NO r5; replacing `00 0d 0a` with `41 42 43` left the canary
  intact. `sh realcaller/run.sh` (observed here 15 PASS / 0 FAIL) builds
  ASan-real, fixed and plain drivers and derives the boundary as pinned
  `message-v2.8.0.c:3356-3381`: 394-byte staged body gives
  `BOUNDARY_LEN=2 BOUNDARY=a:` clean; 396 bytes with a leading CRLF gives
  `BOUNDARY_LEN=0` and the same sink, fixed `RET=-1`. The `318023f3`
  `git archive HEAD` replay reproduced 21/0 and 15/0; build outputs are
  gitignored. Live SBI CRLF preservation is UNKNOWN, no wire/pointer/r5.

- N2n W5 (`1029f346`): affected n2n 3.0–3.1.1, vulnerable `dc7324af…`,
  fixed `854fbbe0…`; pins in `lab/frontier/n2n2shell/PROVENANCE.md` (no new
  pins this limb). Break at `sn_utils.c:2331`, set
  `rwatch *(unsigned long *)($base + OFF)` with `$base = (char *)&nak` and
  run `python3 lab/frontier/n2n2shell/live/w3_peer_forward.py`. Four batches
  of four slots (`+128/+136/+344/+432`, `+368/+392/+400/+424`,
  `+464/+488/+504/+536`, `+1608/+1616/+1632/+1640`) logged no read hit while
  the sender logged `FORWARDED ... len=134` and
  `beyond48=485a4d49485a4d49`; the excluded `+288` trip was a `sockbuf`
  store in `__vsnprintf_internal`. The safe 2048-byte dump lists
  `nak+96 0x00007fffffffc940` and `nak+104 0x00007ffff7cac295` as the
  W1/W2 slots inside the 96-byte write; unwatched words remain UNKNOWN and
  witness replay #3909 is still owed. Eleven `evidence/w5-*.log` files are
  committed. `reports/n2n2shell-live.md` §W5.

- Libgphoto2 W181 (`12ca5894`): affected through v2.5.34, fix
  `6a3393dd996502457ab965432cf0b2035278825e` (issue
  `https://github.com/gphoto/libgphoto2/issues/1326`); W181 adds no pin.
  Source-bounded check only: `pins/jl2005c.h.vuln:31-44` has
  `data_cache` at `0x38` and `Info table[0x4000]` last at `0x40` of a
  `0x4040` struct, so the forward `memmove` at `jl2005c.c.vuln:154` cannot
  reach it; `library.c:197-213/:338-341`, `gphoto2-file.c:315-325` and
  `gp_filesystem.c` consumers use table bytes as data, and
  `gphoto2-filesys.c:1365-1400` has no negative index. In-struct
  natural-consumer-pointer lane CLOSED; a natural HEAP-NEIGHBOUR pointer
  was not measured and stays UNKNOWN. `cd lab/frontier/libgphoto2shell &&
  sh harness/check.sh` stayed `PASS=146 FAIL=0` with trace
  `e364f756f482157bf25e852f98673131a94c4977d688bf691475024f286c6c98`
  (observed here). Evidence: `evidence/w181-consumer-pointer-lane.out`,
  `reports/frontier-libgphoto2shell.md` §W181.

## 2026-11-25 02:4xZ — libsshch2shell W1 real-build authenticated wire
This limb supersedes "no real SSH build, wire packet" at the 01:58Z staged
scope only. No rung cell, grade, route, mind count or R5 cell moved; witness
remains UNKNOWN. Affected libssh `<0.12.1` / `<0.11.5`, fixed 0.12.1 /
0.11.5 (`7dfabb1fd213196c4912c314b418ff36c882ea54`), vulnerable parent
`a540e27659b08828ef61f2910a790f7cf2af9f8d`; advisory
`https://www.libssh.org/security/advisories/CVE-2026-59850.txt`. The real
lane is pinned by those two commit SHAs in codeload URLs, not by a tarball
digest; `pins.sha256` still holds the staged 9 file pins.

From the repo root, `sh lab/frontier/libsshch2shell/real/run-all.sh`
provisions the two source trees only when absent, builds full static clang
ASan libraries (`-DWITH_SERVER=ON -DUNIT_TESTING=OFF -DBUILD_SHARED_LIBS=OFF`,
`-fsanitize=address -fno-omit-frame-pointer -g -O1`), compiles
`real_wire.c`, generates an ed25519 hostkey if absent and runs four
`expect` wire cases. Observed here: `RESULT 5 PASS / 0 FAIL`, rc 0.
Expected vulnerable authenticated wire: `CLIENT auth rc=0`, benign first
packet, raw `CHANNEL_CLOSE` then `CHANNEL_DATA`, application
`ssh_channel_free()` in the data callback, ASan `heap-use-after-free`
`READ of size 8` at `channels.c:705:26`, 120 bytes into a 128-byte region
allocated at `channels.c:103`, free frame `on_data /real_wire.c:55:9`;
`SERVER data #2 len=21 first=M off16=-` from `MISHE-LIBSSH-UAF-WIRE`.
Fixed case: `Received data on (remotely) closed channel`, no data #2, no
ASan; both data-only cases deliver data #2 ASan-clean. Tracked evidence:
`real/evidence-wire-{vuln,fixed}-{close-data,data-only}.out`. Source trees,
build dirs, tarballs, hostkey, binaries and `*.log` are gitignored; delete
them and rerun the script to regenerate (volatile PIDs/addresses and fresh
tracked evidence change). The report's `real_wire.c:52` citation is a nit:
the ASan transcript says `:55`. No pointer/IP control, command or r5;
`reports/frontier-libsshch2shell.md` §W1.

## 2026-11-25 02:4x–02:5xZ — FontForge W13 oracle, OpenEXR W196 chosen free
Both limbs are author-side; no rung cell, grade, route, mind count or R5
cell moved. Generated build trees and PoCs named below are untracked and
regenerated by the commands shown; committed transcripts stay tracked.

- FontForge W13 (`e2d45f1b`): affected FontForge <= 20251009, fixed by
  `65e80b5dfb6691a1c8a532cfbb8ec905949e0c9a` (one-line `glyph>=0` guard);
  advisory URL and full pins in `lab/frontier/fontforge2shell/PINS.md`
  (source `df766f9c…81f0eb30d`, fix patch `f2745243…e99175`, tarball
  `61342403…ad7eb0`). Supply the pinned tarball as `FF2S_TARBALL` and run
  `sh lab/frontier/fontforge2shell/replay-real.sh`: it extracts vulnerable
  and patched trees, builds four offline CMake trees and regenerates PCFs.
  Observed here: `REPLAY_REAL_OK: 17/17 stable-lane checks passed`, rc 0.
  Asserted rc matrix: W8 open truncated 134/0/1/0 and complete 0/0; W11
  `Save()` 139/0/139 plain, 0/1/0/0 fixed-plain/ASan/probe-ASan/fixed-ASan;
  W12 high ceiling 134/0/1/0. W12 gdb greps `HIT glyph=-1 i=65535`,
  `$1 = 0x1fffe00`, watchpoint `0x01fffe0000000021` and `00 fe ff 01`;
  `value-ceiling-high.pcf` is `9a6b2603…f6b82` (131361 B). W6/W7 consumer
  rc is informational (build-path sensitive) and excluded from the oracle.
  Live-tree 02:46Z and clean-archive 02:5xZ receipts both scored 17/17.
  The current script hash is `f633dd37ca4d358a7649eaae4ac92992595d00896de1ee88d626184cfe266a42`
  (recomputed here), superseding W9's quoted `156dd583…acca9261`; rebuild
  trees are untracked, so delete them and rerun for a fresh build. Witness
  #3309 stays direct-call-only; `lab/frontier/fontforge2shell/REPLAY.md` §W13.

- OpenEXR W196 (`61468419`, clean-archive receipt `3ff078b1`): affected
  3.5.0–3.5.2, fixed 3.5.3 (`7d7fbb1a`); GHSA-98rx-qpfv-qcwv. Tarball pins
  in `lab/openexr2shell-real/BUILDLOG.md`: v3.5.2
  `85a291b9b8563fabef1aa3f6e912d744ce1d4b9fd5a8f978eda194cd51b15ae9`,
  v3.5.3 `ff1de95f4031c1c57c633e647dc97c15282d3aa3bc7fb90745f00f74de4a054f`.
  `cd lab/openexr2shell-real && sh harness/w196-chosen-free.sh` printed
  `RESULT PASS` rc 0 here; expected PoC sha256
  `07eac4278b3890cdbaf27719c3b448f28c45236c1f7c8e39272820d7190cad13`.
  With `set disable-randomization on`, unmodified 3.5.2 `exrcheck -c`
  consumes the file-forged `list->entries[0]` (`ATTR=0x555555828520`,
  `TYPE=20`, `STRPTR=0x555555828560`), then reads a file-chosen pointer
  `STR=FREE_RDI=0x555555828590` with chosen `0x5a` bytes and size word
  `0x91` before passing it to the unchanged `ctxt->free_fn`. Six evidence
  hashes: attr `8cbfaaa0…fd412d`, free `4c6c3e13…bac5e7`, plain
  `19517f6f…369e6`, valid `043d72d9…86835`, fixed `4263399a…d93e`,
  ASan `bd0cdff7…6dd29b`; four were recomputed locally here. Plain rc 139,
  valid 0, fixed 1, ASan 1. A 02:54Z `git archive 61468419` replay with
  gitignored src/build/bin trees symlinked matched all six. Author replay;
  witness offered the one command on tape #4048 with no verdict. Mapped
  only with ASLR off in the debuggee; no chosen IP, wire, command, marker
  or r5. `reports/openexr2shell-file-level.md` §W196.

## 2026-11-25 03:0x–03:1xZ — gpgme W7 colon reader and yojimbo W1/W1b real build

All limbs below are author-measured and unwitnessed; no rung cell, grade,
route, mind count or R5 cell moved. Raw logs and fetched trees are gitignored;
the commands below regenerate them. No trigger leaves 127.0.0.1.

- Gpgme W7 (`9633cfc8`, clean-archive replay `a1ecd700`): affected GPGME
  2.2.0, fixed upstream by `14499348…` and released in 2.3.1; source URLs and
  pins in `lab/frontier/gpgme2shell/PROVENANCE.md` (`engine-gpg.c`
  `c4ef11bd…311d55`, fix patch `2fde658a…3049c500`). From
  `lab/frontier/gpgme2shell/realbuild`, `sh build-real.sh` provisions the
  static ASan trees; `sh run-colon.sh` needs no rebuild and printed
  `PASS=26 FAIL=0` rc 0 here. `colon_reuse.c` uses public APIs only and
  `fake-colongpg.py` writes exactly 1024 bytes with no LF on the colon pipe
  plus a 1200-byte status line with a chosen byte `0x48` at offset 1000.
  Expect the vulnerable 2.2.0 driver to exit 1 with ASan `attempting
  double-free`, second free in `gpg_release engine-gpg.c:604` via
  `_gpgme_engine_release → _gpgme_op_reset → gpgme_op_keylist_start
  keylist.c:1295`, first free by `realloc read_colon_line :1647`, allocation
  at `gpg_set_colon_line_handler :909`, no op2; fixed 2.2.0 and stock 2.3.1
  exit 0, sanitizer-clean, start op2 with `byte[1000]=0x5a`; the
  short-colon-line control is clean. Raw `evidence/colon-*.out` / `.rc` are
  gitignored. A clean `git archive 9633cfc8` replay scored `BUILD OK`,
  26 PASS / 0 FAIL for `run-colon.sh` and 19 PASS / 0 FAIL for the pinned
  `sh ../run.sh`. Real library but a synthetic engine and local pipes: no
  wire path, pointer/IP, command or r5, and no witness verdict.
  `reports/gpgme2shell-status.md` §W7.
- Yojimbo W1 (`28d3c8c5`) and W1b (`ff6c5e02`, staging plan completed in
  `30f77300`): claim source is upstream fix `d3d4f339…`, with no CVE/GHSA
  and no fixed release; vulnerable parent `3c6b5e85…`, seven SHA-256 pins in
  `lab/frontier/yojimbo2shell/pins.sha256`, URL and provenance in
  `PROVENANCE.md`. Provision with a read-only clone of
  `https://github.com/mas-bandwidth/yojimbo.git` into `upstream/`, check out
  the parent, copy the fix commit's `test.cpp` and
  `source/yojimbo_address.cpp` into it, keep the vulnerable channel source,
  then `cmake -S . -B build-asan-vuln -G Ninja -DCMAKE_BUILD_TYPE=Debug`
  with `-fsanitize=address -fno-omit-frame-pointer -g` on C/CXX and the link
  flags, and run `ASAN_OPTIONS=detect_leaks=0 ./bin/test`. The fix commit's
  regression goes through real `Connection::ProcessPacket`: expect ASan
  `WRITE of size 500`, 0 bytes after an 1100-byte region at
  `source/yojimbo_reliable_ordered_channel.cpp:716` via `ProcessPacketData
  :441 ← Connection::ProcessPacket source/yojimbo_connection.cpp:340`,
  allocation at `include/yojimbo_reliable_ordered_channel.h:321`; the
  fixed-channel control prints `ALL TESTS PASS`. The authenticated pair is
  `lab/frontier/yojimbo2shell/loopback-test.cpp`: client `0.0.0.0:30000`,
  server `127.0.0.1:40000`, netcode connect-token auth with
  `InsecureConnect` and an all-zero local key, client 1100/500 and server
  1500/500 config, a 1500-byte block whose full 500-byte final fragment at
  offset 1000 carries `MISHE-LOOP` at block offset 1200. Vulnerable: rc 1
  with SEGV in `Connection::Reset() source/yojimbo_connection.cpp:172` and
  no ASan heap report because the receive buffers come from the per-client
  TLSF pool; fixed: rc 0 and `ALL TESTS PASS`. Under gdb, a breakpoint at
  the pinned sink conditioned on `fragmentId==2 && fragmentBytes==500` and
  `next` dumps `MISHE-LOOP` byte-exact at `blockData+1200`, 100 bytes past
  the 1100-byte buffer, with 0xab filler at +1100. Five evidence log hashes
  were recomputed locally and match §W1/W1b of
  `reports/frontier-yojimbo2shell.md`: `6457e8d0…72dff`, `1fe5adcf…715d`,
  `27c4d806…422b`, `57cecbb0…4f63`, `1ec75858…ac1a7`. The staged harness
  `sh lab/frontier/yojimbo2shell/harness/run.sh` still gives 20 PASS /
  0 FAIL with 7/7 pins (observed here). Raw logs, `bin/test` and `upstream/`
  are gitignored and regenerate from the pinned clone and commands above.
  Conditions: non-default config, post-auth, client and server in one
  process, gdb-assisted readback; no separate remote process, pointer/IP,
  command or marker execution, no r5; production non-multiple block config
  and an independent witness verdict stay UNKNOWN.
  `reports/frontier-yojimbo2shell.md` §§W1/W1b.

## 2026-11-25 03:1xZ — pgactive W8 layout negative and hping W212 verdict

No rung cell, grade, route, mind count or R5 cell moved. Raw logs are
gitignored and regenerate with the commands named here; all triggering stays
on loopback.

- Pgactive W8 (`3c6304ba`): from
  `lab/frontier/pgactive2shell/realbuild/layout`, `LABEL=o1 sh run-layout.sh`
  and `LABEL=opt sh run-layout.sh` patch a noinline return-address probe into
  the pinned v2.1.9 parser at its existing error branch, build the real
  library and drive the SQL call on 127.0.0.1:58423 with socket
  `/tmp/pgactive-layout-sock`, then restore the source and installed library.
  Expect `LAYOUT_BUILD=0`, `LAYOUT_INITDB=0`, `LAYOUT_PGSTART=0`,
  `LIVENESS_RC=0`, `BACKEND_TERMINATIONS=0` and a `LAYOUT` line with the
  parser's saved RA at -40 (o1) / -32 (opt) relative to `replication_name`,
  plus a second copy at +104/+120 that N>=128 `AZ` payloads overwrite with
  `41 5a` but that control never consumes because `elog(ERROR)` longjmps
  instead of returning. The `%s` store grows upward from offset 0 and cannot
  reach the consumed slot at any length. `SELECT 1` succeeds afterwards.
  Saved-RA route CLOSED on these two builds; gdb live attach is denied by
  `ptrace_scope=1` and was not retried. Evidence
  `evidence/layout-{o1,opt}-summary.txt` and `FINDINGS.md`; author-side,
  unwitnessed, no grade change.
- Hping W212 (#4000) discharges the earlier W6 witness-OWED line: from a
  clean `git archive 659f6eb0` the witness ran the unmodified
  `wire/replay-rngctl.sh`, observed `STAGE OK baseline 4`, `STAGE OK fill32
  6`, `STAGE OK fill64 6`, `STAGE OK fixed 4`, `REPLAY_RNGCTL_OK: 20 checks`,
  rc 0, with both pinned source digests exact and 16/16 chosen-byte RNG
  destinations for each fill value. Verdict **ESTABLISHED AS LABELED** for
  W6's probabilistic low-byte `--rand-dest` control, no grade change, NO r5;
  stock distro build and `IPOPT_LSRR` remain UNKNOWN, and wire stages #3942
  plus W5 #3958 stay OWED. `reports/hping3shell-status.md` §Witness verdict
  W212.

## 2026-11-25 03:2xZ — socat2shell FRONTIER-STAGED lane (rung corrected)

Rung 1/2 on a real build (deterministic connection abort); rung 3 memory
corruption and rung 4 chosen bytes NOT established on the real consumer, rung
5 not attempted. Author-only, unwitnessed, no rung cell, route, mind count or
R5 cell moved. Raw source trees, binaries and logs are gitignored and
regenerate with the commands below. No probe leaves this machine.

- Claim: Socat security advisory 10
  (`http://www.dest-unreach.org/socat/contrib/socat-secadv10.html`, pinned as
  `src/advisory.html`) names CVE-2026-56123, CWE-122, CVSS4 9.2
  `AV:N/AC:H`, affected 1.8.0.0–1.8.1.1 and fixed 1.8.1.2. Official patch
  `http://www.dest-unreach.org/socat/download/socat-1.8.1.2.patch` is pinned
  as `src/socat-1.8.1.2.patch`; its only source change is `char dstdata[]`
  to `unsigned char dstdata[]` in both `struct socks5_request` and
  `struct socks5_reply` of `xio-socks5.h`. Both tarballs and seven source/patch
  pins are in `lab/frontier/socat2shell/src/pins.sha256`, URLs in
  `PROVENANCE.md`.
- Pinned-function harness (synthetic consumer): from
  `lab/frontier/socat2shell`, `sh harness/run-all.sh` re-extracts and
  SHA-checks every pin and printed `TOTAL pass=15 fail=0`, rc 0, here. It
  reports gcc/clang ASan `heap-buffer-overflow WRITE of size 600`, 0 bytes
  after a 262-byte region, and plain canary `MISHE-SOCKS` at reply+262 with
  fixed/safe controls clean. Mechanism: signed `char` length byte 0xfb
  promotes to -5, so `bytes_to_read=2` with `bytes_read=5` and the -3 count
  becomes SIZE_MAX. The ASan WRITE comes from the harness's `memcpy`
  stand-in for `readfull()` and explicitly disables glibc fortify (default
  `-O1` aborts before ASan); it is not evidence about the shipped consumer.
- Real-build loopback correction (`d7ea43d1`): both 1.8.1.1 and 1.8.1.2 were
  built unmodified under clang ASan with `--disable-openssl`. From
  `lab/frontier/socat2shell/real`, `sh run-real.sh` scored 9 PASS / 0 FAIL,
  rc 0, here; `evil_socks5.py` binds only 127.0.0.1 and sends
  `05 00`, then `05 00 00 03 fd` plus 600 chosen bytes or a well-formed IPv4
  reply. Vulnerable attack logs
  `W read(7, 0x512000000045, -1): Bad address` and exits 255 with NO ASan
  report; vulnerable IPv4, fixed attack and fixed IPv4 all exit 0 clean.
  Real `readfull()` (`sysutils.c:101-141`) loops `Read(fd, buff, exptg)`;
  with `exptg=SIZE_MAX` this host's `read(2)` returns EFAULT before storing
  any byte, so the advisory's unbounded heap write is not reproducible on
  this consumer. Any future write claim must show it on the real path.
- Ceiling: no chosen-byte primitive, pointer/IP, marker execution, witness
  verdict or r5. Charter, window 149 and seed wall exist without a route;
  `check-omp-only.py` reads RED with `socat2shell: no route` and 141 roles,
  resolver the person's full-flag sync (never a bare `mishe sync`).
  `reports/frontier-socat2shell.md`, `reports/socat2shell-status.md`.

## 2026-11-25 03:3xZ — awslc W214 out-of-tree caller census (source-bound)

Author-side source read, no build, no ASan run, no new lab artifact and no
witness replay; grade unchanged (rungs 1-4, r5 UNKNOWN). The ten named
out-of-tree projects already provisioned in this plant (cjose, GPGME,
Open5GS, libssh/libssh2, libwebsockets, Synchronet, PostgreSQL/pgactive,
nginx, mod_auth_openidc, apr-util) and roughly fifty other provisioned roots
were searched for `EVP_(Decrypt|Cipher)Update` sites. No site meets the CVE
precondition: genuine decrypts are single-call on a fresh ctx, padding is
disabled, the two-update path is GCM AAD with `out=NULL`, or the buffer has
at least 17 bytes of slack past the documented minimum. Four representative
sites were re-read: `apr_crypto_openssl.c:887-902` (17-byte slack, one update),
cjose `jwe.c:1451-1468` (one fresh-ctx CBC update), libwebsockets
`aescbc.c:239-249` (`LWS_GAESP_NO_PADDING`, one call) and picotls
`openssl.c:1275-1277` (`EVP_CIPHER_CTX_set_padding(ctx->evp, 0)`). With no
qualifying buffer, no adjacent control datum was found either. Unprovisioned
third-party applications remain UNKNOWN. `reports/awslc2shell-status.md` §W214.

### 2026-11-25 03:3xZ — Socat2Shell admission replay (negative on the real consumer)

Pinned claim bytes, tarballs and patch hashes are in
`lab/frontier/socat2shell/src/pins.sha256` and `PROVENANCE.md`. Two controls:
`cd lab/frontier/socat2shell && sh harness/run-all.sh` re-extracts and
SHA-checks the pins, builds the verbatim pinned `_xioopen_socks5_read_reply()`
with gcc and clang ASan, and prints `TOTAL pass=15 fail=0`; its ASan
`WRITE of size 600` 0 bytes after a 262-byte reply comes from a `memcpy`
stand-in for `readfull()`. `cd lab/frontier/socat2shell/real && sh
run-real.sh` builds unmodified socat 1.8.1.1 and 1.8.1.2 with clang ASan
(`--disable-openssl`) and drives a 127.0.0.1-only SOCKS5 listener that sends
`05 00 00 03 fd` plus 600 chosen bytes: 9 PASS / 0 FAIL. The vulnerable
reply yields verbatim `W read(7, 0x512000000045, -1): Bad address`, exit 255,
**no ASan report**; vulnerable+safe and both fixed cells exit 0. Real
`readfull()` (`sysutils.c:101-141`) calls `read(2)` with SIZE_MAX, which
returns EFAULT before a store on this host. Reproduce only on loopback;
expect a connection abort, not corruption. Grade rungs 1/2 only, rung 3/4/5
not established, witness UNKNOWN. `reports/frontier-socat2shell.md` §real-build.

## 2026-11-25 03:3x–03:5xZ — six author edges after the socat admission

All six are author-side and unwitnessed; none moves a rung cell, grade cell,
mind count or witness verdict. Raw logs are gitignored and regenerate from the
commands below; no new route, charter or window was created.

- **Yojimbo2Shell W2** (`f25517f8`). From `lab/frontier/yojimbo2shell`, keep
  the pinned parent channel source and add `vtable-test.cpp` (the W1 loopback
  test plus a lab-only `mishe_vtable_marker()` and a static fake vtable).
  Configure with
  `-DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address -no-pie'`; non-PIE is required
  for the chosen absolute address. Seed 1795576058, authenticated netcode UDP
  pair on 127.0.0.1, non-default `maxBlockSize=1100`/`blockFragmentSize=500`:
  the encrypted final fragment writes the fake-vtable address at
  `blockData+1152` and `MISHE-LOOP` at +1200. Expect `MISHE-VTABLE-CALL` twice
  then a later `tlsf.c:583 remove_free_block` crash (rc 1) in the vulnerable
  binary; the fixed-channel control runs `*** ALL TESTS PASS ***` rc 0.
  Evidence hashes recomputed here and matching the report:
  `fbc6c526…56a77d` (layout), `5664351a…c0ec5` (channel state),
  `49fea203…42de89` (fault instruction), `466f3181…45a` (vuln call),
  `a9a03eed…d27e` (fixed control). Both binaries are kept as
  `w2-vtable-{vuln,fixed}-binary`; `upstream/` was restored to the pinned
  parent plus the fix commit's `test.cpp`/`yojimbo_address.cpp` after the run.
  `reports/frontier-yojimbo2shell.md` §W2.

- **Hping3Shell W8** (`bea93e82`, replay `90d635d6`). Rebuild the unmodified
  pinned tree (`display_ipopt.c` `e8ef2dd6…dcbb5e7b`) with GCC 13.3.0 and
  `CCOPT='-O2 -g -fcommon -Wall -Wno-unused -I../compat'`; Ubuntu defaults
  `_FORTIFY_SOURCE 3` at `-O2`, and `objdump -d` shows `__memcpy_chk@plt`
  bounded to the real 40 bytes. From `lab/frontier/hping3shell`,
  `wire/inject_rr_o2.py` crafts three loopback ICMP RR replies and
  `sh wire/o2-index-proof.sh` runs `hping3 -D -1 -G --rand-dest -I lo -c 24
  -i 1 127.0.0.x`, reading `i`/`j`/`sbox` read-only at the `hp_rand`
  breakpoint. Expect vulnerable 3 PASS / 0 FAIL with
  `*** buffer overflow detected ***` and no crafted state, baseline 4 PASS /
  0 FAIL and patched 4 PASS / 0 FAIL. A clean-archive replay (`git archive
  90d635d6` plus the gitignored `provision/` tree, `wire/replay-o2.sh`)
  printed `STAGE OK baseline 4 / attack 3 / fixed 4` and
  `REPLAY_O2_OK: 11 checks`, rc 0; raw `wire/evidence/o2-{attack,baseline,
  fixed}-*` regenerate with that script. Build-dependent DoS negative only.
  `reports/hping3shell-status.md` §W8.

- **Socat2Shell W2** (`1a34d2de`). From `lab/frontier/socat2shell/real`,
  `sh run-count-probe.sh` scores 8 PASS / 0 FAIL using loopback-only AF_UNIX
  socketpairs (`evidence-count-probe.out` is gitignored). Expect `rc=-1
  errno=14` (EFAULT) and zero canary stores for counts `SIZE_MAX`,
  `SIZE_MAX-3`, `SIZE_MAX-126` and `SIZE_MAX/2`; the `0x80000000` control
  stores 600 bytes; an empty socket with `2^62` gives EAGAIN while
  `2^63-1` and `SIZE_MAX-126` give EFAULT. Pinned source census:
  `sycls.c:539-558`, `sysutils.c:101-141`, `xio-socks5.c:419-427,467-470`.
  The real-build replay `sh run-real.sh` (9 PASS / 0 FAIL) still expects
  `W read(7, ..., -1): Bad address`, no ASan report. 32-bit `size_t` is
  UNKNOWN: this host lacks multilib. `reports/frontier-socat2shell.md` §W2.

- **AwsLc2Shell W215** (`93b61d8d`, source-bound, no harness). Provision the
  pinned s2n-tls v1.5.16 tarball
  `lab/frontier/awslc2shell/out-of-tree/s2n-tls-v1.5.16.tar.gz` (sha256
  `ab3e19f899e9b76cf7141f3b287e865db628f9e024360d7086c7f9c901909214`,
  recomputed locally) and read `crypto/s2n_cbc_cipher_aes.c:48-58`,
  `tls/s2n_record_read_cbc.c:55,70,77`, `crypto/s2n_cbc_cipher_3des.c:47-52`
  and `crypto/s2n_composite_cipher_aes_sha.c:182-187`: one in-place update
  per re-init, no `in_len+b-1` buffer. Check pinned `cipher.c:190` and `:131`
  in the AWS-LC tree. No build, ASan run or new artifact; grade unchanged.
  `reports/awslc2shell-status.md` §W215.

- **Synchronet2Shell W18** (`b60fd1b4`/`b67db0dc`, source-level). From
  `lab/frontier/synchronet2shell`, `sh release-label/run-release321e.sh`
  provisions four raw files from mirror tag `sbbs321e` (`d2a6dcb2`) and
  asserts `VERSION "3.21"/REVISION 'e'`, the same no-size getter plus NUL
  clamp at `answer.cpp:513`, a byte-identical `terminal[41]` field block and
  `TELNET_TERM_MAXLEN 40`: 11 PASS / 0 FAIL live and from a clean
  `git archive b60fd1b4`, normalized digest
  `bb9067cf9bed5859e016f83175d8de91b2e1502a5a3df816e04cdbe73a3fbda9`
  (read from `release-label/REPLAY.md`). Two wrong observations are preserved
  in `evidence/negatives.txt`; no build, wire session or runtime bytes.

- **Pgactive2Shell W9** (`6fb104bb`). Commands, rc values and negatives are in
  `lab/frontier/pgactive2shell/realbuild/originpath/FINDINGS.md` and its
  gitignored `evidence/`, against a loopback PostgreSQL 16.15 cluster with
  the pinned 2.1.9 extension. Expect 66/67/99/275-byte
  `pg_replication_origin_create()` names stored, a 96→63-byte slot-name
  truncation, no origin-create or parser EXECUTE for a plain `LOGIN` role,
  and a failed `pgactive_get_global_locks_info()` route (state `b`,
  not-configured error) left UNKNOWN. No wire trigger or grade change.
  `reports/frontier-pgactive2shell.md` §catalog-derived origin-name reachability.

### 2026-11-25 03:5x–04:0xZ — n2n2shell W6 and one-command W3 replay

`sh lab/frontier/n2n2shell/live/replay-live.sh` now builds the pinned tarball
three ways, runs checks 1-19 as before and adds W3's peer-forwarding lane as
checks 20-22: a registered loopback peer receives the safe 86-byte NAK and the
attack 134-byte NAK with `beyond48=485a4d49485a4d49`. Observed 22 PASS / 0 FAIL
rc 0 here; `NO_GDB=1` still skips checks 16-19 and raw logs stay under the
temporary directory the script prints (`KEEP=1` retains it). The
watchpoint-level backtrace and fixed-build ASan READ keep the separate
`live/w3_peer_forward.py` recipe with `live/gdb-cmds-w3.txt`. W6
(`ac451b00`) fresh-extracts the pinned tarball, builds gcc `-g -O1
-fno-omit-frame-pointer` with the one-line NAK guard and runs the safe/attack
datagrams against a 127.0.0.1 supernode: expect the attack peer to receive a
134-byte NAK whose 96 token bytes are all ZERO (`first=0000…`,
`beyond48=0000…`) while `token_size=0x0060` survives the rejected decode.
Evidence `live/evidence/fixed-plain-safe{,-sender}.log` and
`fixed-plain-attack{,-sender}.log` are gitignored and regenerate with that
recipe; no disclosure claim, no rung move, witness #3909 still owed.
`reports/n2n2shell-live.md` §§W6, clean-room replay entry point.

## 2026-11-25 04:1x–04:4xZ — ccextractor2shell admission and staged recipe

From `lab/frontier/ccextractor2shell`, `sh harness/run.sh` re-builds all six
binaries from `harness/parse_mpeg_packet.inc` (verbatim master
`2c1c1c6f…`, `ccx_gxf.c:938-949`), SHA-pins in `pins.sha256` and provenance in
`PROVENANCE.md`. Expect `17 PASS / 0 FAIL` rc 0: gcc ASan and clang ASan with
`-fno-builtin-memcpy` report `heap-buffer-overflow WRITE of size 2101248`, 0
bytes after a 2097272-byte region; the plain slack build prints
`canary_at_BUFSIZE=5348452d434345584d495348452d4343` ("SHE-CCEXMISHE-CC");
the local `DFIXED_BUILD` guard and the safe 4096-byte length are clean.
clang ASan with default builtins prints no report (preserved negative).
The store comes from a stand-in `buffered_read` and stand-in structs; no real
ccextractor build, GXF file or wire was exercised. Admission at 04:4xZ minted
the hy4-flash route, both resolver keys and three wake units with the EXACT
full-flag sync (`written 3, removed 0`, doctor GREEN), and adopted window 150.
Grade rung 3 / rung 4 PARTIAL, no r5, witness UNKNOWN.
`reports/frontier-ccextractor2shell.md`, `reports/ccextractor2shell-status.md`.

## 2026-11-25 05:5x–06:2xZ — staged MCUboot, real-build CCExtractor/libsshch, corrigenda

- **Mcuboot2Shell FRONTIER-STAGED (CVE-2026-16663)** — provision both verbatim
  `boot_serial_encryption.c` versions into `lab/frontier/mcuboot2shell/src/`
  (hashes in `pins.sha256` and `PROVENANCE.md`), then
  `cd lab/frontier/mcuboot2shell/harness && sh run.sh`: expect **22 PASS / 0 FAIL**
  with gcc and clang ASan `dynamic-stack-buffer-overflow WRITE of size 1` 8 bytes
  past the 4096-byte VLA at `ih_hdr_size=4104`, local guard and `ih_hdr_size=0`
  controls clean, and chosen `4d495348452d4d4355424f4f542121` read back at
  `buf+6144` in the plain build. The deep `6144` case is a Valgrind invalid
  write but no ASan report — preserved negative. A clean `git archive HEAD
  lab/frontier/mcuboot2shell` replay scored 22/0. No real MCUboot build or
  serial wire, witness UNKNOWN; no charter, route or mind-count change.
  `reports/frontier-mcuboot2shell.md` §Lab evidence.
- **Ccextractor2Shell W1/W2 real build** — the admission recipe above is
  superseded at the real-build scope. Regenerate `inputs/attack.gxf` and
  `inputs/readback.gxf` with `real-build/make_gxf.py` and
  `real-build/make_readback_gxf.py`, configure and build the pinned tree with
  the exact cmake commands in `reports/frontier-ccextractor2shell.md` §Real
  build (logs `real-build/evidence/{cmake,build,guard-build}.log`), then run
  the ASan binary with `ASAN_OPTIONS=detect_leaks=0` on each GXF: expect
  `WRITE of size 1052736` 0 bytes after a 2097272-byte region through
  `read` → `buffered_read_opt` → `parse_mpeg_packet` for `attack.gxf`, clean
  local-guard and safe exits, and on `readback.gxf` the program's own
  `got=2097348` (76 past) with `00 00 01 B3` at `buffer+2097272`; with
  `halt_on_error=0`, a `READ of size 3900` at `boundary+76` via `memmove`
  → `process_data`. GDB transcripts use the committed `gdb-consumed-*.cmd`,
  `gdb-pageread.cmd` and `gdb-readback-slice.cmd`. Raw evidence is gitignored
  and regenerates from these commands. No pointer/IP/command, no r5, witness
  UNKNOWN; the brief's "rung 4 CONFIRMED" is an evidence-level label, not a
  table-cell or grade move.
- **Libsshch2Shell W2/W3/W4 clean-exit and trampoline lanes** — from
  `lab/frontier/libsshch2shell`, `sh real/run-survive.sh` (7 PASS / 0 FAIL),
  `sh real/run-call.sh` (9/0) and `sh real/run-exec.sh` (8/0). Expect
  `SERVER target_after=0x41414141414141c1 ... survive=1` with `CLIENT rc=0
  SERVER status=0x0` and no ASan for W3; a wire offset 112 selects
  `fn=0x61fe9f9fbd10` for `SERVER MARKER called`; the W4 wire string
  `touch evidence-wire-vuln-groom-exec.marker` runs through a lab trampoline
  (`SERVER EXEC rc=0`). The pure-rebuild allocation variant is a measured
  negative (`buf_match=0 it_match=0`); clean-archive replays were 5/0, 8/0
  and 7/0. Rung-5 mechanics are lab-only and NOT ESTABLISHED, witness UNKNOWN.
- **FontForge2Shell W16** — from `lab/frontier/fontforge2shell`,
  `sh replay-negdiv.sh` scores 20/20 rc 0 with `make-negdiv-case.py` generating
  the PCF cases; clean archives scored 17/17, 15/15 and 20/20. A negative
  divisor moves byte 3 to `0xff` and `BDFChar.bitmap` to
  `0x00005555ff0105fe` (PIE) / `0x00000000ff0105fe` (non-PIE), both unmapped;
  the nonnegative-RHS ceiling `0x01FFFE00` stands. Author-side, no grade or
  witness move. `NEGDIV.md`, `reports/frontier-fontforge2shell.md` §W16.
- **Corrigenda recipes (no grade move)** — n2n2shell W7 reruns
  `sh lab/frontier/n2n2shell/live/w7_large_token.sh` with `PLAIN=` overriding
  the tree (token_size=600, no watchpoint read in 22 s) and W8 uses
  `w8_fixed_large.py` (201/600 nonzero fixed-token bytes from wire offset 115);
  pgactive W11's disassembly is `realbuild/layout/evidence/disassembly-correction.txt`
  (saved RA at `rbp+8`, canary at `rbp-0x28`); synchronet W20 reruns
  `lab/frontier/synchronet2shell/release-label/term320b/consumer320b/run-consumer320b.sh`
  for 17/0, clean-archive normalized hash `e74779de…`; Ruby's corrected
  consumer probe uses `lab/repro/ruby2shell-cons-vis-tabulate.py` with
  `process_vm_readv` window lines (Q=0/49, structurally inert forged qword);
  OpenEXR W197 runs unmodified `exrcheck -c` on the crafted file for a
  file-chosen `destroy_unpacked_func_ptr` and plain rc 139. Other edges are
  receipts or bounded negatives with no row change (libgphoto2 W185, yojimbo
  W6, munt W187, gpgme W10/W11 (real `read_status` EOF early return,
  `realbuild/run-eof.sh`, clean-archive receipt), libraw W21, open5gs W2, awslc
  W216,
  knotresolver W21, cjose W209, cicap W9).

## 2026-11-25 07:0x–07:3xZ — staged dr_wav, two scoped verdicts, wire/build corrections

- **Drwav2Shell FRONTIER-STAGED (CVE-2026-11316 / TALOS-2026-2442)** — pinned
  `dr_wav.h` 0.14.5 and the later `wav-0.14.6` control live in
  `lab/frontier/drwav2shell/pins/` with three SHA-256 pins; the advisory names
  no fix commit, so 0.14.6 is only a source-bound control. From that directory,
  `sh harness/run-all.sh` builds the 150-byte RIFF and calls the real public
  `drwav_init_memory_with_metadata()` on both headers under GCC and Clang:
  25 PASS / 0 FAIL. Expect ASan WRITE through file-low-half pointer
  `0x41414141` at `0x50f041414155` inside
  `drwav__read_cue_to_metadata_obj()`, and chosen `0x4841434b` / `0x42424242`
  read back at the lab-groomed destination with `metadataCount=1`. Fixed
  0.14.6 and matching-loop `safe` lanes are clean. `d591751b` records a clean
  `git archive` replay with all three pins OK and window 152 handed off;
  binaries and logs are gitignored and regenerate from `run-all.sh`. No
  witness verdict, application, wire, IP or command.
- **N2n2Shell W9/W10 clang `-O2` consumed pointer** — from
  `lab/frontier/n2n2shell/live`, `sh w9_spill_layout.sh` prints the spill slots
  (`encx +1344`, `comm +1696` inside a 1700-byte token's reach); `python3
  w10_large_peer.py` drives the 1700-byte loopback NAK, and
  `sh w10_pointer_control.sh` scored 9 PASS / 0 FAIL here. Garbage chosen bytes
  fault at `sn_utils.c:2324`; eight chosen bytes at token offset 1682 move the
  fault to `sn_utils.c:2344` (`encode_uint8`, `wire.c:49`). The valid pointer
  comes from a gdb pre-read with ASLR disabled; both outcomes crash, with no
  benign marker, canary/IP or command. Author-only, live limb unwitnessed
  (#3909 owed); no row or grade move.
- **Open5GS W3 loopback HTTP/2 wire** — from `lab/frontier/open5gs2shell`,
  `sh wireloop/run.sh` starts a Go 1.22 TLS `h2` listener on 127.0.0.1 and
  feeds the verbatim 396-byte request body to the pinned real-caller shim on
  stdin: 13 PASS / 0 FAIL, `proto=HTTP/2.0 len=396
  head=0d0a0d0a613a0d0a0d0a0d0a`, `BOUNDARY_LEN=0`, ASan `WRITE of size 1` at
  `multipart_parser-v2.8.0.c:260` and plain canary
  `0a000d0a000d0a000d0a000d`; the 394-byte, 10-byte safe and fixed cases are
  clean. A clean `git archive` four-suite replay (wireloop 13/0, realcaller
  15/0, harness 21/0, httpbody 8/0) scored 57 PASS lines / 0 FAIL with
  combined trace SHA-256
  `ac435c402db1864275deefc3d819dfe9cdc27c381ca2c497994f545e77b0da29`.
  Binaries are gitignored. The shim is not an Open5GS NF; witness #3934 stays
  scoped to the staged harness and r5 is unsupported.
- **Two scoped rung-5 verdicts (no full r5)** — Yojimbo W213 (#4132, commit
  `557c58b1`) replayed two wire-borne benign `touch` commands into a second
  127.0.0.1 victim process from a clean `git archive c9e2482e`, with fixed and
  safe controls clean and a victim-argv counterexample: ESTABLISHED AS LABELED
  for rung-5 MECHANICS only at the non-default 1100/500, post-auth, `-no-pie`,
  lab-pre-placed-trampoline ceiling; NO full r5, PIE/ASLR derivation UNKNOWN.
  Libsshch W214 (#4161, commit `f08fec31`) replayed `run-all.sh` 5/0,
  `run-extra.sh` 8/0, `run-survive.sh` 7/0, `run-call.sh` 9/0 and
  `run-exec.sh` 8/0 from a clean `git archive c5ece2a9`: ESTABLISHED AS LABELED
  for rung 3 on the real authenticated loopback wire and rung-5 MECHANICS
  only, NOT ESTABLISHED as remote execution. The earlier libsshch
  "witness UNKNOWN" and "lab-only and NOT ESTABLISHED" clauses are superseded
  by this verdict; the lab-only scope remains true.
- **Munt W188** — `git archive HEAD lab/frontier/munt2shell` replayed the W187
  precondition lane: both pinned trees rebuilt, 32 gcc cases and eight W187
  cases matched, eight `.out` files normalized-identical; the only variance
  was the replay shell's own `Aborted (core dumped)` line. Author receipt,
  witness #2781 still scoped to real-library rungs 1-4, no grade change.
- **Frontier screen-out, no recipe** — `reports/frontier-aribb24-screenout.md`
  disposes CVE-2026-112280 (AV:L, moderate, no fix commit, crash-only claim)
  and the duplicate fontforge #5951 entry; no target, row or mind added.

## 2026-11-25 06:3x–07:2xZ negatives and receipts (no grade move)

- **CCExtractor2Shell W3/W4** — `reports/frontier-ccextractor2shell.md` §§W3/W4:
  a 64 KiB gdb scan of aligned words in the overflow window from
  `ccx_gxf.c:1220` prints `codeptr_hits=0` (BUFSIZE 2097272, 3976-byte
  overflow). The 2101312-byte `inputs/unlink.gxf` (SHA-256
  `a50991c9…73aa7e`) forges the next-chunk size to `0x7f8`, but the reached
  chunk is the arena top chunk: `free()` merges with the top and never calls
  `unlink_chunk`, with `nextsize=2040`, buffer `0x5555564209b0`, untouched top
  and rc 10. Commands: `make_unlink_gxf.py`, `gdb-unlink-watch.cmd`,
  `gdb-top-watch.cmd` with the matching `evidence/*.out` transcripts. Direct
  function-pointer overwrite is closed for this layout; rung 3/4 and witness
  UNKNOWN unchanged.
- **Gpgme2Shell W12** — from `lab/frontier/gpgme2shell/realbuild`,
  `sh run-groom.sh` scores `PASS=23 FAIL=0` on glibc 2.39 with `aliased=1`,
  `byte[1000]=0x41` and the groomed buffer after the stale block; W9/W10 plain
  paths still abort rc 134. The report calls this the structural ceiling on
  the last plain-glibc rung-5 route: no write-what-where or pointer control in
  the status/colon readers, all real-path results author-side, no witness.
- **Cjose2Shell W211** — pinned `src/jwe.c:1451-1468` has only the GCM AAD
  two-update path with `out=NULL`; the CBC path makes one `EVP_DecryptUpdate`
  and one `EVP_DecryptFinal_ex` into `jwe->dat + p_len`. Source-scope negative
  against awslc W214's caller-census claim, no experiment or grade change.
- **LibRaw2Shell W22/W23** — W22's `w21/replay.sh` scores `PASS=11 FAIL=0
  W21_OK` but the valid top size at index 68,773 is debugger-forced
  (`0xbedbbeef4d03` restored after the loop), not file-chosen. W23's 16
  file-steered field variants all leave non-zero high 32 bits (at least
  `0x1_0000_0000`, above sysmem 16781312); zeroing the high half zeroes the
  size, so no plausible valid size is reached. `sh lab/frontier/libraw2shell/w23/replay.sh`
  prints `PASS=7 FAIL=0 W23_NEGATIVE_OK`; hashes in `w22/results.txt` and
  `w23/hashes.sha256`. Grade unchanged, arbitrary byte values UNKNOWN.
- **OpenEXR W198** — from `lab/openexr2shell-real`,
  `sh harness/w198-negatives.sh` prints `RESULT PASS` rc 0 (twice): all nine
  8-byte tail words in the 3072-byte COPY2 window are zero, and the pinned
  `exrcheck` imports no `system`/`popen`/`exec*` with zero
  `MOV_RSI_RDI_TO_SYSTEM_GADGETS` in a bounded 13-byte direct-branch scan.
  Trace hashes `111771e0…` and `1b0b6837…` matched byte-for-byte in a clean
  `git archive 28f23f27` replay alongside five W197 hashes; author receipt,
  not a witness verdict, grade and r5 unchanged.
- **FontForge2Shell W17** — with the pinned tarball provisioned,
  `sh replay-all.sh` runs all three real-build suites in one command:
  `REPLAY_ALL_OK: 3 suites (17 + 15 + 20 = 52 checks), 0 failed`, wrapper hash
  `070fcf9a…c5a9d26a7`; a clean `git archive efdb6d31` rebuilt all six trees
  offline with twelve byte-identical normalized hashes. Wrapper/receipt only,
  no new experiment, witness verdict, grade or r5 change.

## Peer edge `7a02ca45` — Synchronet W21 shipped 3.20b live free (no grade move)

- From `lab/frontier/synchronet2shell/release-label/term320b/real320b`,
  `sh run-real320b.sh` builds shipped source commit
  `db9c5d6fd37ef74b6e6ca647308d351e656de18d` with an instrumentation-only
  `lprintf` patch and drives two loopback SSH pty-req TERM cases: 4 PASS /
  0 FAIL rc 0 at 07:29:32Z. The 40-byte control prints `first=(nil)
  last=(nil)`; the 64-byte chosen TERM prints `off41=42 cv=4853494d
  first=0x465541544f4f2d45 last=0x5a5a5a5a46554154`. `sh run-gdb320b.sh`
  stops frame #0 at `listFreeNodes` `link_list.c:78` reading `node->flags`
  from the chosen `list->first`; frames #1/#2/#3 are `listFree`,
  `sbbs_t::~sbbs_t` and `node_thread`. Evidence transcripts `run-final.log`
  (`462a36a1…639a0546`), `server-vuln.log` (`4b2dc43e…a261d11652`),
  `server-control40.log` (`8d575a11…e7072c0c`) and `gdb-vuln-final.log`
  (`d8da2690…7df5f24`); failed expectations and port collisions are kept in
  `evidence/negatives.txt`. Author replay, not a witness verdict; no chosen
  IP, shell, command, ASLR defeat, fixed-release control or r5, and no rung
  or witness-cell move.

## 2026-11-25 08:3xZ — admitted recipes for mcuboot/drwav/vtkdicom

- **Mcuboot2Shell**: from `lab/frontier/mcuboot2shell`, `sh harness/run.sh`
  printed 22 PASS / 0 FAIL here and 22/0 from a clean archive; GCC ASan reports
  `dynamic-stack-buffer-overflow WRITE of size 1` 8 bytes past the 4096-byte
  VLA at `ih_hdr_size=4104`, clang agrees. The deep `ih_hdr_size=6144` case
  gives a Valgrind invalid write but no ASan report (preserved negative).
  Pins and claim URLs are in the lab's `PROVENANCE.md` / `src/pins.sha256`.
- **Drwav2Shell**: `sh lab/frontier/drwav2shell/harness/run-all.sh` printed
  25 PASS / 0 FAIL under GCC and Clang, and 25/0 with three pins from a clean
  archive (`d591751b`). The fault is a file-low-half pointer through the real
  public `drwav_init_memory_with_metadata()` API; witness W215 replayed the
  same 25/0 from a clean archive and found a real same-size-class condition.
- **Vtkdicom2Shell**: `sh lab/frontier/vtkdicom2shell/harness/run-all.sh`
  printed 14 PASS / 0 FAIL; ASan `WRITE of size 4` at pinned `e->Tag = tag`
  in `vtkDICOMItem::FindDataElementOrInsert()` via `Set()`, with fixed and
  no-delete controls clean.
- **Admission commands (operator)**: the three hy4-flash routes and six
  resolver keys are in `.mishe-tauftauf/engine/routes.json` and
  `.mishe-tauftauf/resolvers.json`; the unit render is the EXACT full-flag
  sync in `docs/runtime-pin.md:96-102` at pin
  `0d686bba…d528a` (reported `written 9, removed 0`), never a bare
  `mishe sync`. Verification is `systemctl --user daemon-reload`, the
  pinned full-flag doctor (rc 0, `PASS` / `GREEN`), `for_role` returning
  `RoutedEngine`, and `python3 tools/check-readme.py .` (GREEN, 141 rows).

All three grades stay rung 3 + rung 4 PARTIAL at the named harness/pinned
function scopes; no full r5 and no shipped-application or wire proof.

## 2026-11-25 08:4xZ — admitted recipe for xschem2shell

- From `lab/frontier/xschem2shell`, `sh harness/run-all.sh` printed 25 PASS /
  0 FAIL under GCC and Clang, ASan/plain with indices 2/16/64/-2 and fixed /
  safe controls. Both versions of the whole `src/rawtovcd.c` are pinned
  byte-identically (sha256 in `PROVENANCE.md`), and the probe calls the real
  `read_dataset()` on a crafted in-memory `.raw` header.
- ASan reports `heap-buffer-overflow WRITE of size 8` at
  `rawtovcd-vuln.c:130` (`names[i] = malloc(...)`); index -2 writes 16 bytes
  before the region. The fixed pin rejects `bad variable record, index out
  of range` and stays clean. The plain build reads back an allocator-derived
  pointer from the chosen slot, not file-chosen stored bytes; the
  tcache-grooming negative is preserved rather than retried into existence.
- Admission commands are the EXACT full-flag sync in
  `docs/runtime-pin.md:96-102` at pin `0d686bba…d528a` (`written 3, removed
  0`), followed by daemon-reload, the pinned full-flag doctor (rc 0, `PASS`
  / `GREEN`), `for_role` → `RoutedEngine`, and
  `python3 tools/check-readme.py .` (GREEN, 142 achievement rows).

Grade stays rung 3 + rung 4 PARTIAL at this file-converter scope; no full r5,
no wire path, no control-flow hijack, no command and no witness verdict.

## 2026-11-25 07:4x–08:5xZ — recipes and receipts for the latest limbs

- **Open5gs2Shell W4/W5** — the real-NF lane is lab-local only: 21 `.deb`s
  extracted into `lab/frontier/open5gs2shell/provision/debs/` and
  `local-prefix/`, `.pc` prefixes rewritten to that absolute path, v2.8.0
  tarball sha256 `a04d66f66f6df62a376a2434a05a7268e08e4fc0cc1b9c56221467689a8b56ab`,
  `meson setup build/bld build/open5gs-2.8.0 --prefix=<lab>/local-install
  --buildtype=debug` and `ninja -j4 -C build/bld src/nrf/open5gs-nrfd`
  (1886/1886, rc 0); the patched copy uses `provision/fix-6820c274.patch`
  and `bld-fixed`. `cd nfloop && sh mkfixtures.sh` regenerates four bodies:
  staged 394 B `969c2f30…fc94`, safe 10 B `47c08f59…59db`, attack 396 B
  `0c46e003…48e0ba`, ABC 396 B `f8900293…2f07` (all four recomputed here).
  `TAG=vuln sh run.sh` and `TAG=fixed NRF_BIN=../build/bld-fixed/src/nrf/
  open5gs-nrfd sh run.sh` bind only 127.0.0.1:18777: vulnerable attack
  `curl_rc=56 nrf_alive=NO nrf_rc=134`, fixed/abc/staged/safe return HTTP 400
  with the NF alive, and `sh gdbattack.sh` shows the talloc abort through
  `parse_multipart message.c:3498` → `nrf_state_operational nrf-sm.c:78`.
  W4's source review re-ran harness 21/0, wireloop 13/0, realcaller 15/0 and
  httpbody 8/0 from `git archive dd55be12`; W5's `git archive 56363d35`
  clean-source rebuild reproduced the four CASE lines with normalized hashes
  `71b4b7e212d6979967f15c804d958036e25c62ddbb33c66328045b07e8927c8e`
  (vulnerable) and
  `2b31633e4ca2ab05fbada7ab8692e7007961b5e9daed78441aa8aa778a4d41a7`
  (fixed). Witness replay pending; author-only, no pointer or command.
- **Cjose2Shell W212/W213** — `sh lab/frontier/cjose2shell/w2/run-oauth-bearer.sh`
  prints `REPLAY_OAUTH_BEARER: 9 PASS / 0 FAIL` live and from a clean
  `git archive 35e02887` with the four provisioned build trees copied into
  `w2/`; the unauthenticated bearer GET is logged by the real Apache/mod_auth_openidc
  module and the fixed module rejects it. Pinned W198 module hashes
  `f1be85cf…b24cd` (vulnerable) and `928b7a90…d9456` (fixed). Request bytes
  are freshly encrypted and are not hash-pinned; the 56-byte `encrypted_key`
  length and header are fixed. The private W213 gdb probe uses
  `W2_KEK=30313233343536373839616263646566` and the 40/56-byte token forms;
  evidence logs `w2/evidence/w213-adj-ctrl40-gdb.log`
  `dc77299a9c837709043b67d88a70dfbc16ccc661540f76186f8749bf9cc4ec49`
  and `w213-adj-attack56-gdb.log`
  `74fcd25439fd199f18259e51afb699dafc1761bee28ff6506f99f74c1e387cb4`
  (both recomputed here). No witness verdict on either limb.
- **N2n2Shell W11** — `sh lab/frontier/n2n2shell/live/w11_fixed_pointer.sh`
  rebuilds the pinned supernode with `CC=clang CFLAGS="-g -O2
  -fno-omit-frame-pointer -no-pie" LDFLAGS="-no-pie"` and prints
  `RESULT 13 PASS / 0 FAIL`. The 1700-byte NAK writes `0x42f3e8` at
  token+1682; gdb reads `comm = 0x42f3e8` at `sn_utils.c:2324`, garbage bytes
  fault there and the no-gdb plain process stays alive. Binary-known non-PIE
  address only, no ASLR defeat, marker, command or witness verdict.
- **Ccextractor2Shell W5** — `python3 real-build/make_short_gxf.py` generates
  `inputs/short.gxf` (4160 B, sha256
  `669ad20202d822aa3865b1795fae3501dec38096ba9a35130b47c7b9f4990745`)
  and `inputs/short0.gxf` (64 B, sha256
  `e2b32bf30cc2673e2ee9b85db1b45d94949e7d14f8f732b3654f12cc60cd1ee2`);
  the real ASan build under `ASAN_OPTIONS=detect_leaks=0:halt_on_error=0`
  exits rc 10 with one `READ of size 3` at `boundary+3973`, and
  `real-build/gdb-short.cmd` reads `data_len=2101248 got=2101245 move_len=3`
  with stale source bytes. No `read()` WRITE, no new write primitive and no
  rung change.
- **Pgactive2Shell W12 / Libraw2Shell W24 / Libgphoto2Shell W189** — W12 reads
  `lab/frontier/pgactive2shell/realbuild/layout/evidence/production-frame-check.txt`
  against `.so` sha256 `3177a37cd16c0010e5973190b4bbe31287144849823752865a5c8fb9ee162998`
  (binary only, no cluster): the accepted four-conversion format leaves the
  `%s` destination untouched; no source or grade change. W24's lab-only
  `lab/frontier/libraw2shell/w24/` gdb scripts force `0x21001` into the live
  top-size field and watch it and `destimage + 68,644*8` through
  `border_interpolate()` with no change; `results.txt` records the negative
  and no report grade moved. W189 is an API-only recheck at 08:17Z: newest
  tag `v2.5.34` (`a4ec9cc8…`), GHSA patched versions Unknown.
- **Ruby2Shell 08:1x–08:2xZ** — `reports/ruby2shell-status.md` and
  `reports/ruby2shell-investigation.md` §§Victim-region consumer provenance /
  carve-landing describe an H-line, gated-SIGTRAP and `EXTRA_HEADER` sweep
  that leaves `request=0x21c/0x1f8` unchanged in ten wire-shaped samples,
  and a 60-run `N`×drain sweep (11 survivors, zero reflected corruption).
  Bulk logs are gitignored; the report carries the observed values. No stock
  oracle-free r5; the harness-condition witness label is unchanged.
- **Synchronet2Shell W22** — from `release-label/term320b/fixed320b`,
  `sh run-fixed320b.sh` rebuilds shipped 3.20b `db9c5d6f…` with the pinned
  `cb6d77dbca` hunk (`FIXED_HUNK_PINNED_OK lines=8 probe=1`) and reports
  5 PASS / 0 FAIL twice with `off41=00`, nil heads and teardown complete;
  `run.log` sha256 `8825f5e0…20004e54`. An author `git archive 7d3a0088`
  replay reproduced 5/0 with a private provisioned-tree copy; receipt
  `evidence/CLEAN-ARCHIVE.md`. Not a witness verdict, no DoS rate, IP or
  command.
- **Drwav2Shell witness / Xschem2Shell receipt** — witness DM #4189 replayed
  a clean `git archive f5dce89c` to 25 PASS / 0 FAIL with 3/3 pins and
  ESTABLISHED AS LABELED at the chosen-target, same-size-class scope; a
  32-byte target in another ASan size class leaves `CHOSEN_WORD_PRESENT=0`
  (preserved counterexample). Xschem2Shell's window 154 is registered
  155/155 unique and a clean archive of `6081c45b` replays 25 PASS / 0 FAIL
  with both pin hashes matching `PROVENANCE.md`; witness still UNKNOWN.

Every limb in this section is author-side unless a witness marker is named;
none moved a rung cell, grade, route, mind count or R5 cell. The raw evidence
named above is gitignored and regenerates with the cited scripts.

## 2026-11-25 10:5xZ — StbVorbis2Shell admission replay

- **Claim and pins** — `reports/frontier-stbvorbis2shell.md` records
  CVE-2026-89266 (VulnCheck 2026-09-11), vulnerable `stb_vorbis.c` v1.22
  (`2c980bb59875b0d32144a71867fbdebb2f77cd20`, sha256
  `4c7cb2ff…e65636`) and the dev-branch fixed control (sha256
  `daedcc5c…e86a5`, `CODEBOOK_LIMIT (1<<18)`). Numeric fixed release UNKNOWN.
- **Harness** — `sh lab/frontier/stbvorbis2shell/run-all.sh` drives the real
  public `stb_vorbis_open_memory()` on 205-byte OGG inputs: 9 PASS / 0 FAIL,
  ASan `WRITE of size 4` at `stb_vorbis.c:3889`, clean fixed and safe-input
  controls, and gdb-observed file-chosen `4b 43 41 48` at the first OOB
  float. Raw outputs are under `lab/frontier/stbvorbis2shell/evidence/`.
- **Admission units** — roles come from `SITE/charters/*.md`, so the exact
  full-flag sync must follow charter creation; it then reported
  `written 3, removed 0`. The pinned full-flag doctor returned
  `PASS local plant out of Git` / `GREEN`, rc 0. Window 135 was already live
  and registered; the new mind adopts it. Grade stays rung 4 PARTIAL, NO r5,
  witness UNKNOWN.

## 2026-11-25 11:2xZ — Ctranslate22Shell admission replay

- **Claim and pins** — `reports/frontier-ctranslate22shell.md` records
  CVE-2026-102566 / GHSA-7xqx-34h9-2w97 (CTranslate2 before 4.8.1, CWE-787,
  CVSS4 8.5 `AV:L/UI:P`), fix `d9b991e` (PR #2068), vulnerable pin v4.8.0
  (`src/models/model.cc`, sha256 `05ab59bb…`) and fixed pin sha256
  `5dcc3f1d…` under `lab/frontier/ctranslate22shell/pins/`.
- **Harness** — `bash lab/frontier/ctranslate22shell/harness/run-all.sh`
  replays the verbatim pinned ranges with a stand-in 16-byte `StorageView`:
  16 PASS / 0 FAIL under GCC and Clang, ASan `WRITE of size 17` / `64` at
  pinned `model.cc:657`, fixed pin rejects, safe payload clean and plain
  chosen-byte readback past the region; clean `git archive HEAD` replay also
  16/0.
- **Admission units** — hy4-flash `max_parallel: 3` route and both resolver
  keys were added and JSON-parsed before the exact full-flag sync at pin
  `0d686bba…d528a`, which reported `written 3, removed 0`. Slice, debounce
  and path are present, path enabled/active, pinned full-flag doctor PASS /
  GREEN rc 0. Window 155 was already registered with two live panes and was
  adopted. Grade stays rung 4 PARTIAL, NO r5, witness UNKNOWN.

## 2026-11-25 08:5x–13:0xZ — staged lane and one-command replay receipts

- **Solanum2Shell (staged, then admitted as the 149th route)** — frontier W230
  committed the lane at `805732b5`/`5f191420`; the operator admitted it at
  13:1xZ. CVE-2026-121603 / GHSA-6cq2-4j8w-7hvj, Solanum IRCd before fix
  `2ea1382`, needs an authenticated linked server (`PR:H`). Pins: vulnerable
  parent `7bc7e34c04711247b932666e19ae900cba884540` with `m_kill.c` sha256
  `f4af269d…`, fixed `2ea1382e…` with sha256 `b1408e51…`; both full files and
  `SHA256SUMS` are under `lab/frontier/solanum2shell/pins/`.
  `bash lab/frontier/solanum2shell/harness/run-all.sh` gives 18 PASS / 0 FAIL:
  verbatim `ms_kill()` bodies with stand-in client structs, GCC/Clang ASan
  `WRITE of size 533` at `m_kill.c:277` for reason 510/700, safe 480 and fixed
  clean, plain chosen bytes past the 512-byte static `buf`. At staging there was
  no real IRCd or wire; W1/W2 later reproduced ASan WRITE-564 and plain
  chosen-byte readback in real ASan/plain IRCd builds over authenticated
  loopback S2S KILL, and W3 found no writable consumer after `buf`. W4's
  `bash lab/frontier/solanum2shell/replay-all.sh` replays the 18/0 harness plus
  6/0 real-ircd controls (exit 2 if the installed builds are absent). Rung 3
  real process, rung 4 PARTIAL with a measured no-pointer ceiling, no command
  or R5, witness UNKNOWN. The README row and admission section below supersede
  the staging-only boundary.
- **Xschem2Shell witness verdict** — W216 replayed a clean
  `git archive 42e0f33f`: `sh lab/frontier/xschem2shell/harness/run-all.sh`
  25 PASS / 0 FAIL and `harness/real-bin.sh` 3 PASS / 0 FAIL, pins hash-match,
  same ASan `WRITE of size 8` at pinned `:130` through the real unrenamed
  `main` on a crafted `.raw`, fixed pin rejecting, and allocator-derived
  readback `slot_bytes=c034f2404e640000`. Verdict ESTABLISHED AS LABELED,
  grade unchanged; detail in the witness wall under
  `.mishe-tauftauf/artifacts/` (gitignored).
- **StbVorbis2Shell extent and replay** — `sh
  lab/frontier/stbvorbis2shell/run-seq.sh` (4 PASS / 0 FAIL) rebuilds the plain
  harness and checks four distinct file-derived OOB words; `sh
  lab/frontier/stbvorbis2shell/run-guard.sh` (11 PASS / 0 FAIL at this fold;
  W204 later re-ran it at 12 PASS / 0 FAIL) routes the
  8-byte `c->multiplicands` allocation to a RW page with a `PROT_NONE` page
  behind it and observes `j=0`, `k=31`, `div=0x80000000` at `stb_vorbis.c:3895`
  with file-derived words at indices 2..31 — 30 words / 120 bytes past the
  region, correcting this paragraph's earlier 29-word reading. The guard page
  is never reached; the plain libc build instead
  aborts in `malloc(): invalid size (unsorted)`. This supersedes the staged
  loop-bound description; grade stays rung 4 PARTIAL, witness UNKNOWN.
- **Ctranslate22Shell real source and pointer gap** — from
  `lab/frontier/ctranslate22shell/realbuild`, `sh build.sh` builds verbatim
  upstream `model.cc` (`05ab59bb…`) and fixed `d9b991e` (`5dcc3f1d…`) against
  the real `StorageView`/`posix_memalign` allocator under ASan: a crafted
  109-byte file sets `num_bytes=17` and ASan reports `WRITE of size 17`, 0
  bytes after a real 16-byte region, with fixed rejecting and 16-byte safe
  clean. `sh pointer-probe.sh` measures the real heap at the store: the top
  chunk follows the buffer, and the later `shared_ptr`/`StorageView`
  constructors overwrite chosen bytes at +0x40/+0x48, so no chosen pointer
  reached a dereference (an 80-byte payload completed `Model::load` then
  aborted in `sysmalloc`). Bounded negative; witness W223 closed the replay gate
  ESTABLISHED AS LABELED from `305d4a68` with
  `bash lab/frontier/ctranslate22shell/run-witness.sh` (rc 0, `WITNESS REPLAY
  PASS`, 16 PASS / 0 FAIL, both pin hashes and all ten real-consumer assertions
  exact). No grade change.
- **Real-process lanes with one-command drivers** — Drwav2Shell W4:
  `sh lab/frontier/drwav2shell/consumer/run-marker.sh` (14 PASS / 0 FAIL)
  uses attacker-side `make_marker_wav.py` and a committed `marker.c` to take
  three adjacent `libsndfile` function pointers at `0x41e118..0x41e130` in a
  `-no-pie` consumer and call an `LD_PRELOAD` benign marker at `0x50000000`;
  fixed 0.14.6 and safe loop count write no marker. Libsshch2Shell W12:
  `sh lab/frontier/libsshch2shell/real/run-fixedaddr.sh` (7 PASS / 0 FAIL)
  derives the callee from the compiled ELF with `nm` and uses a separate
  client process; the library-internal close-free shortcut is a source-level
  negative. Synchronet2Shell W24:
  `bash lab/frontier/synchronet2shell/release-label/term320b/real320b/run-faultaddr320b.sh`
  (7 PASS / 0 FAIL, clean `git archive 3e681d41` receipt) shows
  `mov 0x20(%rax),%rax` at `listFreeNodes+67` with `rax` and `list->first`
  equal to the wire-chosen `0x465541544f4f2d45`; the direct `si_addr`
  cross-check returned `(nil)` and is preserved as a negative. Open5GS W6:
  `sh nfloop/run.sh` under `lab/frontier/open5gs2shell` replays the
  ASan-confirmed `WRITE of size 1` at `multipart_parser.c:260` inside the
  live v2.8.0 NRF with four byte-identical `CASE=` lines and a clean
  `git archive 11bf8130` receipt. Mcuboot W3:
  `sh lab/frontier/mcuboot2shell/real/wire-groom-run.sh` drives wire-supplied
  header and plaintext through the real pinned decryptor to an OOB
  destination on 127.0.0.1. Hping3 W11:
  `sh lab/frontier/hping3shell/wire/replay-ij-o2.sh` replays chosen `i`/`j`
  bytes under clang `-O2` from the pinned source; its layout survey found no
  pointer or GOT entry in the 251-byte span.
- **Bounded negatives** — Vtkdicom2Shell W3/W4: the plain-build SIGSEGV is a
  stale OOB `Value.V` decref at `ReferenceCount.h:50` after `Set`, and a
  nine-size OB sweep leaves the same stale word at the same offset, so no
  file bytes or file-influenced pointer reach it. OpenEXR W200:
  `sh harness/w200-command-gadget.sh` under `lab/openexr2shell-real`
  disassembles every module loaded by pinned `exrcheck` and finds no `rsi`
  to `rdi` one-gadget route to an `exec*` call from the W197 shape (clean
  `git archive 548692e2` receipt, same evidence hash). Ruby2Shell's stock
  leads are closed by the committed drivers `ruby2shell-keepalive-thread.sh`,
  `ruby2shell-consH20-retarget.sh`, `ruby2shell-mainarena-leak.sh` and
  `ruby2shell-errorpage-oracle.sh`; chosen-header coverage is pinned to
  `N ∈ [540,588]` by the boundary arms at N=508 and N=604. Stock,
  oracle-free and persistent R5 stays NOT ACHIEVED.

Raw evidence for every bullet above is gitignored under its lane's
`evidence/` directory and regenerates with the named script; the reports carry
the observed hashes and counts. Gpgme2Shell W15's #4333 W11 replay offer is
UNKNOWN (no settled witness output at 12:49Z), not a pass; Cjose2Shell W216
only re-verified queued offers. No lane in this section moved a rung cell,
grade, route, mind count or R5 cell.

## 2026-11-25 13:1xZ — solanum2shell admission replay

- **Claim and pins** — `reports/frontier-solanum2shell.md` and
  `lab/frontier/solanum2shell/PROVENANCE.md` record CVE-2026-121603 /
  GHSA-6cq2-4j8w-7hvj, vulnerable pin `7bc7e34` and fixed pin `2ea1382`
  with full sha256 values.
- **Harness** — `bash lab/frontier/solanum2shell/harness/run-all.sh`:
  18 PASS / 0 FAIL, GCC and Clang ASan `WRITE of size 533` at vulnerable
  `m_kill.c:277`, safe/fixed clean; a clean `git archive HEAD` replay at
  12:42Z reproduced the same hashes and counts.
- **Admission config** — after adding the hy4-flash route and both resolver
  keys, `python3 tools/check-omp-only.py .mishe-tauftauf .` reads
  `GREEN (149 declared roles)`; the exact full-flag sync at pin
  `0d686bbad55c849e88334da64efff9da88ad528a` reported `written 3, removed 0`
  and the pinned full-flag doctor returned `PASS` / `GREEN`, rc 0.
- **Grade** — rung 3 on the real IRCd process, rung 4 PARTIAL chosen bytes past
  the real 512-byte static buffer with no writable consumer after it; no pointer
  target or command, no r5, `PR:H` required, witness UNKNOWN. W4 adds the
  one-command 18/0 + 6/0 replay in the latest section below.

## 2026-11-25 13:1x–15:3xZ — real-consumer, real-build and one-command replay limbs

All commands below run on loopback or offline; raw outputs are gitignored
under each lane's `evidence/` directory and regenerate with the named
script. No limb in this section returned a witness verdict: every replay
offer remained UNKNOWN and the 14:02Z witness wake failed to start for the
known engine-cap reason. No grade, rung, route, mind count or R5 cell moved.

- **StbVorbis W204/W206** — `sh lab/frontier/stbvorbis2shell/run-guard.sh`
  (12 PASS / 0 FAIL) measures 30 file-chosen words / 120 bytes past the
  8-byte region; `sh lab/frontier/stbvorbis2shell/run-object.sh` (9/0) shows
  those words in a live adjacent object's canary and both halves of its
  pointer field (`fp_low=0x4b434148`), read back but never called. The guarded
  `nodiv-seq.ogg` (`26306dfa5e5c9d1f3d24163c8a0d048d45de614fb86e748b10d555c52d254ea6`)
  is a negative-result artifact, not a trigger. W206's
  `sh lab/frontier/stbvorbis2shell/run-consumer.sh` (12/0) drives the crafted
  OGG through real SDL_mixer `MIX_LoadAudio_IO()` into its vendored v1.22
  header: ASan `WRITE of size 4` at `stb_vorbis.c:4040`, fixed and safe clean.
  A clean `git archive eb785d31` replayed all six scripts with the same
  counts.
- **Hping3 W12 distro binary** — `sh wire/replay-distro.sh` under
  `lab/frontier/hping3shell` provisions Ubuntu 24.04 package
  `3.a2.ds2-10build2` (deb sha256 `b98e33f9…bdd6e7c5`, shipped
  `/usr/sbin/hping3` sha256 `d0181f16…edc9cd`) without installing it, checks
  the packaged `display_ipopt.c` is byte-identical to the pin
  (`e8ef2dd6…dcbb5e7b`), then sends the crafted long RR from `127.0.0.2` to
  `127.0.0.1` on `lo`: 5 PASS / 0 FAIL with rc 134
  (`*** buffer overflow detected ***`) before any global write and a clean
  valid-RR control. A clean `git archive 20a65c8f` reproduced `REPLAY_DISTRO_OK:
  5 checks`, rc 0. Other distributions and fortify-disabled builds stay
  UNKNOWN.
- **Real-process lanes** — Mcuboot W4: the native loopback SMP upload driver
  under `lab/frontier/mcuboot2shell/real/smp` drives wire-chosen plaintext
  through real `boot_serial_input()` → `bs_upload()` →
  `decrypt_region_inplace()` and reads `WIRE-CHOICE-1234` at the OOB
  destination for `ih_hdr_size` 6144 and 7168, with 2048 in-bounds clean
  and 4104 SIGSEGV preserved as a negative. Solanum W1/W2: authenticated
  loopback S2S KILL in a real ASan IRCd gives `WRITE of size 564` at
  `m_kill.c:277` (63-byte peer name + 490-byte reason, 18/0 harness and 6/0
  controls); the plain build reads `chosen_A_past_buf=50/51` past `buf` via
  `/proc/PID/mem`. Pgactive W-W: `sh run-two.sh` under
  `lab/frontier/pgactive2shell` crashes both loopback PG16.15 apply workers
  in a 2.1.9 conflict race with ASan `WRITE of size 8` at
  `pgactive_conflict_handlers.c:759`; 2.1.10 is clean and the earlier crash
  was a harness bug (clean-archive receipt of `52473a73` reproduces the two
  terminations).
- **Written far-field writes and negatives** — Cjose W217/W218:
  `REPLAY_W217` 10/0 and `REPLAY_W218_IDENT` 8/0 in the real bearer lane;
  a 144-byte write from a 152-byte `encrypted_key` lands in OpenSSL's
  56-byte RNG `CRYPTO_RWLOCK` at `cek+0x70` (+0x18 inside), HTTP 401, no
  dereference. Ctranslate2 W4: `realbuild/downstream-probe.sh` (8/8)
  observes a file-derived `StorageView._size=0x8282828282828282` at
  `storage_view.cc:411` but the `size != _size` guard blocks the copy; the
  `sysmalloc`-prev_size hypothesis is disproved from glibc 2.39 and a heap
  dump. FontForge W23: `sh replay-w23.sh` 12/12 with
  `GLIBC_TUNABLES=glibc.malloc.tcache_count=0` finds no code pointer in the
  128 KiB negative-glyph window (clean-archive receipt from `f2dd5a78`).
  Drwav W5/W6: `run-all.sh` 25/0 and the marker consumer 14/0; the only
  network-facing metadata-API caller found vendors byte-identical fixed
  0.14.6 (`fad60f1e…f308cd`), so no vulnerable wire lane. Libraw W27/W28
  and Vtkdicom W5 are source/phase and grooming negatives with clean-archive
  receipts.
- **One-command replay consolidations** — Synchronet W25:
  `bash lab/frontier/synchronet2shell/release-label/term320b/run-witness320b.sh`
  runs W21–W24 and asserts 19 PASS / 0 FAIL live and from a clean archive
  (sub-lanes 4/0, 5/0, 13/0, 7/0); shipped 3.20b servers use
  `SSH_ANYAUTH`. CodebaseMemory W19/W20: `bash
  lab/frontier/codebasememory2shell/run-witness.sh` runs the direct matrix,
  stdio tool and HTTP replays with snapshot/restore and asserts the ASan
  `READ of size 8` at `cypher.c:2568` and the recover-mode `WRITE` at
  `project_item:3379`; no new replay was observed and the verdict stays
  UNKNOWN. Libgphoto2 W192: `replay-clang-control-flow.sh` gives 12/0 live
  and from `git archive f1459319` (tarball `5df9e774…f28`); Lgphoto2's
  differing `jl2005c.so` hash is a debug-path artifact.
- **PHP varied attacker bytes** — `lab/repro/w61-varied-tfm.sh` (wake 61)
  repeats the tinyfilemanager chain with session id
  `cafebabe00112233445566778899babe` and 700-byte `Y` filler. The affected
  8.4.27-app build prints `PHP2SHELL-R5-MARKER:php2shell-r5-142933` and
  `uid=1000(mesh-home)...` from the live FPM worker
  (`lab/build/evidence/w61-varied/…`, sha256
  `572a2f6dd8075a506d436421e2a73d379c804f532f52703f87e91c609044d9c3`);
  8.4.28-app with the same bytes writes exactly 1019 bytes, promotes no
  session and prints no marker. The shim SIGKILL remains a condition, so
  full rung 5 stays UNCLAIMED.

## 2026-11-25 16:1x–16:2xZ — real-consumer command, byte ceilings and replay receipts

All commands below are offline or bound to loopback. No limb returned a
witness verdict; grades and rung-5 cells are unchanged. Normalized evidence
named below is tracked (for example `lab/openexr2shell-real/evidence/w202-*.out`
and `lab/frontier/open5gs2shell/harness/bytechoice/evidence/bytechoice.txt`);
other raw logs are gitignored per lane (for example
`lab/frontier/hping3shell/.gitignore:12` and
`lab/frontier/stbvorbis2shell/.gitignore:2`) and regenerate with the named
script. Nothing in this section is a full-build replay unless stated.

- **Openexr W202 — benign command in the shipped tool** — affected OpenEXR
  3.5.2, fixed 3.5.3 (`reports/openexr2shell-file-level.md` §W202). Generate
  the PoC from the committed W195 dump with
  `python3 lab/openexr2shell-real/cases/make_w202_poc.py` (sha256
  `7f3eda1b00f54b56ec75108f9012be6b035c8b6393ec1d7c2241f94be91e412e`), then
  `cd lab/openexr2shell-real && sh harness/w202-benign-command.sh`. Expected:
  `RESULT PASS` rc 0 on two runs, five byte-identical normalized hashes
  (chain `54115664…`, vulnerable `ba3fcb27…`, fixed `46871818…`, safe
  `5cce1cae…`, ASan `71552269…`). Under gdb ASLR-off,
  `opaque.c:79` prints `CTXT=0x555555826f00`, `TARGET=0x7ffff7feb900`,
  `RDX=104`; memory at `ctxt+96` becomes `0x00007ffff7658750` (`__libc_system`)
  and `x/s` at `SYSTEM_RDI` shows `touch /tmp/w202m`. Plain `setarch -R`:
  vulnerable rc 139 with the marker, fixed rc 1 `bad` without it, valid
  baseline rc 0 without it; the vulnerable ASan build reports
  `heap-buffer-overflow READ of size 3072` at `internal_zstd.c:472`.
  `git archive 043a0d41 lab/openexr2shell-real` reproduced all five hashes.
  Conditions: ASLR off, local file path, benign command, process faults after
  the call; not R5 and no witness verdict.
- **StbVorbis W207 — real-consumer heap metadata** — unmodified SDL_mixer
  vendored stb_vorbis v1.22, plain `-O0 -g` build. Run
  `sh lab/frontier/stbvorbis2shell/run-consumer-heap.sh`; the script generates
  `evidence/safe-input.bin` itself. Expected: 11 shell PASS plus 14 heap-word
  PASS, rc 0, with `vuln_rc=134` (`malloc(): invalid size (unsorted)`),
  `safe_rc=0`, and a nested `run-consumer.sh` `TOTAL PASS=12 FAIL=0`.
  `consumer/evidence/heap-gdb-snapshots.out` has `W207_PRE`/`W207_POST`
  snapshots: 30 file-chosen `0x4b434148` words at `c->multiplicands+8..+124`
  and the next free chunk size `0x91` → `0x4b434148` at `+24`; the sweep
  outputs for 4096/65536/1048576-byte padding show the same address and
  clobber (grooming negative). Requires the gitignored SDL/SDL_mixer trees in
  `../sdlmixer2shell/deps`; raw `.out` files are gitignored. No pointer in a
  live consumer-owned field, no wire, no command and no verdict.
  A clean `git archive 624df6c1` with SDL dependencies symlinked read-only
  replayed all seven scripts rc 0: heap 11/0 + 14/0, `run-consumer.sh` 12/0,
  `run-all.sh` 9/0, `run-seq.sh` 4/0, `run-guard.sh` 12/0, `run-object.sh` 9/0,
  `run-neighbor.sh` 9/0. The earlier `0c8b7c75` archive had one FAIL from the
  missing gitignored safe input, fixed by generating it in the script.
- **Hping3 W13 — conditional permutation byte control** — pinned
  `display_ipopt.c` sha256
  `e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b`,
  locally patched control
  `70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7`.
  With the gitignored pinned source copied in,
  `HPING_SRC=$PWD/lab/frontier/hping3shell/provision/hping-src sh lab/frontier/hping3shell/wire/replay-perm.sh`
  prints `STAGE OK baseline 3`, `STAGE OK attack-dec 5`,
  `STAGE OK fixed-dec 3`, `REPLAY_PERM_OK: 3 stages`, rc 0, from a clean
  archive of `feb3f33f`. Frames go from `127.0.0.2` to `127.0.0.1` on `lo`;
  `fullip-proof.sh` reads `i`/`j`/`sbox` read-only in gdb and `check_perm.py`
  checks destinations against the four-calls-per-packet RNG model. Observed
  controlled bytes: `j=222`, index 5, `S[5]=4`, low byte 4 against a
  counterfactual 22; `j=92`, index 131, `S[131]=130`, low byte 130 against
  237. `j=156` put index 195 outside the 187-byte reach; a `127.0.x.x`
  template was rejected by `waitpacket.c:94`. No full chosen IP, no verdict.
- **Open5GS W8 — forced-value ceiling** — pinned v2.8.0 parser compiled
  verbatim, `sh lab/frontier/open5gs2shell/harness/bytechoice/run.sh` gives
  11 PASS / 0 FAIL. Expected canary for `00 0d 0a` x36 is
  `CANARY_CHANGED=7`, `0a000d0a000d0a5a5a5a5a`; arbitrary 36-byte `41…` and
  `41 42 43` x12 suffixes give `CANARY_CHANGED=0` with the canary unchanged;
  substitutions break the chain and mid-chain CRLF only re-arms it. The
  tracked `bytechoice.txt` hashes to
  `7a23b925df8ff3b66e8401954356ebe6307edf9c5c54add4a7648780f79df689`.
  A clean `git archive 0a6c868d` replayed 11/0 and `harness/run.sh` 21/0;
  rung 3 ASan and rung 4 process-kill grades stay as labeled, NO r5.
- **Cjose W219/W219b — enc-selected CEK sweep** — in the real loopback
  pre-auth bearer lane with the lab Apache config, `sh w2/w219/run-w219.sh`
  reported `REPLAY_W219: 18 PASS / 0 FAIL` and `run-w219b.sh`
  `REPLAY_W219B: 11 PASS / 0 FAIL`. A128GCM (16-byte CEK), A256GCM (32),
  A192CBC-HS384 (48), A256CBC-HS512 (64) and the 32-byte baseline all reach
  `AES_unwrap_key`; fixed rejects at `jwe.c:599`. A256GCM faults in
  `OPENSSL_sk_dup` (`malloc(): corrupted top size`) and A256CBC-HS512 in
  `_cjose_release_cek` (`free(): invalid next size (fast)`); other cases
  return HTTP 401. W219b writes 168 bytes over pointer-shaped fields at
  `cek+0x80..0xa8` with `0x4141…`; W220 identifies the holding object as the
  live Jansson header hashtable `jwe->hdr`. Its first post-unwrap lookup fails
  the pinned `json_is_object()` guard and returns HTTP 401 without dereferencing
  the poisoned buckets. Probes, gdb scripts and normalized evidence live in
  `lab/frontier/cjose2shell/w2/w219/`; no listener is left running.
- **Awslc W223 / N2n W16 / Solanum W3 — ceilings and one-command replays** —
  Awslc's synthesis of W213–W216 is source-bound: no checked real caller has
  both the withheld-block carry and a `in_len+b-1` destination; Node v22.11.0
  allocates `len + block_size` and its ASan check was clean at 32 bytes,
  faulting only at the 31-byte documented minimum. N2n's
  `sh lab/frontier/n2n2shell/live/replay-all.sh` gave pins 5 OK, harness 15/0,
  live 22/0, W10 9/0, W11 13/0, W13 11/0, W15 7/0, overall 7 PASS / 0 FAIL
  from a clean archive of `a2284de2`; the first 4/3 attempt failed because
  gitignored `community.list` was absent, fixed by using the pinned tarball's
  copy. Solanum W3's plain real-ircd layout probe reads `buf` at vaddr
  `0x5220`, size `0x200`, inside `.bss` ending `0x5420`; beyond the 50 chosen
  `A`s and NUL at `+0x232` there is only ordinary ELF data, with 18/0 harness
  and 6/0 ASan controls. All three remain author-side, unwitnessed.

## 2026-11-25 16:3x–17:1xZ — allocator closure, live-object identity and real-callee limbs

All commands are offline or loopback-only. These author edges carry no new
independent witness verdict; grades and rung-5 cells are unchanged. Raw build
trees, binaries and logs remain gitignored and regenerate with the named
drivers. Normalized receipts named below are tracked in their lanes.

- **Ruby2Shell corrected stock allocator model and claim closure** — affected
  plain Ruby 3.4.12 on the unmodified `rails new --minimal` app; the fixed 3.4.13
  control and the witness-established harness R5 lane are unchanged. Provision
  with `bash lab/ruby2shell/provision.sh`, build the plain tree with the report
  recipe, then `bash lab/repro/ruby2shell-stock-rails-setup.sh`. The latest
  honeypot arm is reproduced from the report's exact poSAC geometry:

  ```sh
  RUBY2SHELL_CLAIM_N=1500 RUBY2SHELL_CLAIM_TAG=poPAC3 \
  RUBY2SHELL_CLAIM_PLANT=1527x40,1517x6,1521x3,1529x1 \
  RUBY2SHELL_CLAIM_PARTS=1599@0x610:0x815,1599@0x620:0x815,1599@0x61f:0x815,1607@0x618:0x825 \
  FILLER_SPEC=400x200 HONEYPOT_SPEC=1527x3 PROBE_SPEC=1527x5,1535x1 \
  CHURN_SPEC=400x20 POISON_GROWN=0x650 POISON_NEXT=0x90 ATTACK_CHAIN=1 \
  RUBY2SHELL_CLAIM_MODE=poison RUBY2SHELL_CLAIM_THREADS=1 \
  RUBY2SHELL_CLAIM_COUNT=12 bash lab/repro/ruby2shell-shrink-claim.sh
  ```

  Repeat with `RUBY2SHELL_CLAIM_TAG=poPAC5` and `HONEYPOT_SPEC=1527x5`.
  Expected full-sequence survival is 8/12 and 7/12 (baseline poSAC 6/12); the
  `0x648` claim pops are
  1 and 3, all at merged value chunks, never the B snapshot's grown victim.
  `python3 lab/repro/ruby2shell-sweep-order.py --plant-spec
  1527x40,1517x6,1521x3,1529x1` tabulates the raw M/F/R streams under
  `lab/build/evidence/`. The measured model is two content+9 slices plus one
  next-pow2(content+1) value per embed-legal part; tcache covers only chunks
  `<=0x420`. The 3095-byte giant-pop claim exact-fits the `0xc20` giant but its
  usable `0xc18` bytes cannot cross into the live value at `giant+0xc20`; the
  grown-victim path is split by the upcase's own result allocation. Raw logs are
  gitignored. No command, persistence or grade change; stock R5 remains NOT
  ACHIEVED.
- **Cjose W219/W219b/W220 — live header identity and fail-closed use** — pinned
  vulnerable cjose 0.6.2.4 / fixed 0.6.2.5 in the real pre-auth loopback bearer
  consumer. From `lab/frontier/cjose2shell`, run
  `sh w2/w219/run-w219.sh`, `sh w2/w219/run-w219b.sh`,
  `sh w2/w219/run-w220-ident.sh` and `sh w2/w219/run-w220-use.sh`. Expect
  `REPLAY_W219: 18 PASS / 0 FAIL`, `REPLAY_W219B: 11 PASS / 0 FAIL`,
  `REPLAY_W220_IDENT: 7 PASS / 0 FAIL`, `REPLAY_W220_USE: 11 PASS / 0 FAIL`,
  each with `NO_LISTENER_LEFT`. A128GCM/A256GCM/A192CBC-HS384/A256CBC-HS512
  all reach `AES_unwrap_key`; fixed rejects at `jwe.c:599`. The 168-byte write
  replaces fields at `cek+0x80..0xa8`; watchpoints identify the target as the
  live Jansson `jwe->hdr` initialized by `hashtable_init` during
  `json_loadb`. Its first post-unwrap use sees type `0x4141414141414141`, fails
  `json_is_object()` at pinned `value.c:106-113`, and returns HTTP 401 without
  dereferencing the poisoned buckets. No valid address, command, witness verdict
  or r5.
- **Libsshch W14 — real libc `system()` callee** — affected libssh parent
  `a540e27659b08828ef61f2910a790f7cf2af9f8d`, fixed
  `7dfabb1fd213196c4912c314b418ff36c882ea54`; no library source change.
  From `lab/frontier/libsshch2shell/real`, `sh run-realsystem.sh` builds plain
  Release vulnerable/fixed libraries and the `-DW14_REALSYSTEM` driver, then
  runs authenticated loopback KEX/password/channel lanes. Expect 6 PASS / 0
  FAIL, rc 0: vulnerable `SERVER REALSYS armed`, no `SERVER EXEC trampoline`,
  marker present and renamed to `evidence-rs-sideeffect.kept`; fixed has no
  data #2, no REALSYS line and no marker; invalid callee faults at the library
  indirect call. The wire selects callback offset 112 (`&system`) and offset 0
  (`channel->session`), but the command is an app-chosen static global and the
  addresses are fork-peer ASLR-local. Authenticated peer, W3 detach and
  app-owned fake callbacks remain. Unwitnessed rung-5 mechanics, NOT established
  remote execution.
- **Synchronet W26 — shipped-3.20b concurrent-load availability** — shipped
  commit `db9c5d6fd37ef74b6e6ca647308d351e656de18d`, fixed hunk `cb6d77dbca`.
  From `lab/frontier/synchronet2shell`, run
  `bash release-label/term320b/availability320b/run-availability320b.sh`.
  Expect 13 PASS / 0 FAIL, rc 0: four `REAL_320B_PROBE ... l=64` records,
  `Node 1 destructor begin` without `destructor end`, process gone/zombie and
  fifth connection refused; the fixed phase records four `wire=64 len=40`
  probes plus one `wire=40 len=40` control, four completed teardowns and a live
  process. The first 7/3 run is preserved in `evidence/FAILED-PREDICTION.md`:
  node exhaustion/thread parking was predicted and did not occur. A clean
  archive of `79f3710b` replayed 13/0 with seven byte-identical normalized
  key-line digests. Unauthenticated loopback SSH pty-req under `SSH_ANYAUTH`;
  no measured DoS rate, pointer/IP target, command, witness verdict or r5.
- **Openexr W203 — ASLR-on negative for W202** — affected OpenEXR 3.5.2, fixed
  3.5.3. After the W202 build/PoC prerequisites, from `lab/openexr2shell-real`
  run `sh harness/w203-aslr-on-negative.sh`. Expect `RESULT PASS`, rc 0: five
  PIE plus five `-no-pie` plain runs with ASLR on all exit 139 and create no
  marker; gdb with randomization enabled faults at `attributes.c:305` before
  `opaque.c:79`. Six stable normalized hashes cover the core-array scan, PIE
  and non-PIE gdb traces, globals scan and plain traces. No writable file-filled
  fixed-address staging buffer was found. A clean `git archive c2932e44` with
  the gitignored source/build/PoC trees symlinked matched all six. W202 stays
  ASLR-off/local-file/benign-command rung 4; no wire, witness or r5.
- **Solanum W4 / CodebaseMemory W21 / Munt W191 — replay and provenance** —
  `bash lab/frontier/solanum2shell/replay-all.sh` requires the two installed
  ASan IRCd prefixes from `PROVENANCE.md` and returns `RESULT 18 PASS / 0 FAIL`
  plus `RESULT 6 PASS / 0 FAIL`, rc 0; a clean archive with only the new wrapper
  copied in matched both. CodebaseMemory's repaired
  `bash lab/frontier/codebasememory2shell/run-witness.sh` snapshots/restores
  tracked tool `.err` files and traps TERM/INT/HUP; its assertions were checked
  lane-by-lane at 44 PASS / 0 FAIL, but no single uninterrupted final-wrapper
  run completed. The verdict remains UNKNOWN. Munt's second CISA exploit-tagged
  HackMD slug aliases the same note ID; the public mirror contains only an
  unexecuted illustrative trigger truncated at `for (int i = 0; i`, with no
  byte array, length, script or output (`real/SECOND_POC_NOTE.md`). No public
  PoC bytes or new caller were found; no build or probe ran.

The route-policy commits are already reflected in `docs/runtime-pin.md` and
`docs/self-healing.md`: the 17:00Z hungerg-free fallback addition was reversed
the same day after that model was rate-limited. All 152 declared roles,
including three that previously had no route, now have exactly one
`opencode-go/hy4-flash-free` route at `max_parallel: 5` under the site wake cap
of 5, with hungerg-free retired in `routes.json`. No target grade changed.

## 2026-11-25 17:1x–17:4xZ — witness verdict, chosen RNG byte, short-write negative

- **Solanum2Shell W5 — independent ESTABLISHED verdict** — witness W219 (tape
  #4481) replayed `bash lab/frontier/solanum2shell/replay-all.sh` from a clean
  `git archive b8885fcc`: expect `RESULT 18 PASS / 0 FAIL` and then
  `RESULT 6 PASS / 0 FAIL`, rc 0. Expect ASan `WRITE of size 564` at `m_kill.c:277`, vulnerable
  reason 510/700, safe reason 480 clean, fixed build clean; the witness
  hash-checked both pins (`7bc7e34` / `2ea1382`), rebuilt both with the
  `PROVENANCE.md` flags into its own prefixes and matched eleven normalized
  evidence files. The unauthenticated-peer counterexample returns
  `Incompatible TS version`, no KILL and no ASan, confirming PR:H. Grade:
  rung 3 in a real ircd process, rung 4 PARTIAL chosen bytes at a known global
  offset, no pointer, command or r5. Detail: gitignored site artifact
  `.mishe-tauftauf/artifacts/witness-wall-w219-detail.md`.
- **Ruby2Shell corrected-model tcache consumer and stock negative** — affected
  class is glibc tcache `<=0x420`, fixed Ruby 3.4.13 control clean. Run
  `bash lab/repro/ruby2shell-stageC.sh` (expect 5/5 `verdict=poisoned` with an
  mtrace `M … 3e9 <target>` pop and 3/3 `verdict=clean`) and
  `bash lab/repro/ruby2shell-stageC-http.sh 3 2` (expect 3/3 HTTP 200 with
  `F-readback-hex=7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a`, unchanged `f-pre=4646…`,
  a pop at the nominated address and 2/2 clean controls). All attack
  processes abort at teardown. Then run
  `RUBY2SHELL_LEAKCLASS_COUNT=12 bash lab/repro/ruby2shell-stock-leakclass.sh`
  on the unmodified `rails new --minimal` app with the four-page case-probe
  preload; tabulate with `ruby2shell-cons-vis-tabulate.py leakclass`,
  `ruby2shell-reflect-scan.py leakclass-` and `ruby2shell-leak-maps.py leakclass-`.
  Expect 0 `q38=0x251`, 0 window `P` allocations, 0 window `Q`
  frees and no reflected arena base; the driver tag is hardcoded `leakclass-`.
  Raw `.run.txt` traces stay gitignored. Stock/oracle-free/persistent r5
  remains NOT ACHIEVED.
- **Hping3Shell W14 — arbitrary chosen RNG output byte** — from the pinned
  clang `-O0` trees run
  `bash lab/frontier/hping3shell/wire/replay-target-byte.sh`; it rebuilds both
  revisions, rechecks both source hashes and expects `STAGE baseline` 4 PASS,
  `STAGE attack 126` 8 PASS, `STAGE fixed` 4 PASS and
  `REPLAY_TARGET_BYTE_OK: 16 checks, target=0x7e`, rc 0. The crafted RR sets
  `hp_rand.i=0x20`, `hp_rand.j=0x10`, `rc4_seedflag=1`, `S[0]=T`; expect
  16/16 low bytes `7e` with counterfactual `e7`, and with `T=0xc3` 16/16 low
  bytes `c3` with counterfactual `e3`. `wire/inject_rr_ij.py` with
  `--target-index`/`--target-byte`, `wire/check_ij.py` and `wire/rng-ij-proof.sh` pass the
  options through; defaults preserve W9/W11. The same frames scored 8/0 attack
  and 4/0 patched in the existing `-O2` trees (no `-O2` driver rebuild).
  One IP octet, no full IP, pointer, command or grade change; author-only.
- **PHP2Shell W62 — native `RLIMIT_FSIZE` negative** — probe with
  `python3 lab/repro/php2shell-rlimit-fsize-probe.py`: a 1584-B carrier and
  1892-B replacement with soft/hard limit 1019 give `pwrite` 1019 bytes, file
  `R*1019 || C*565` and no SIGXFSZ (both Python-handler and default
  dispositions). In the tinyfilemanager/FPM lane set `DEATH_MODE=rlimit` in
  `lab/repro/php2shell-aftershell-splice-tfm.sh` so no `LD_PRELOAD` shim is
  loaded and apply `prlimit --fsize=1019:1019` to the worker with
  `display_errors=0`. Expect three `Write wrote less bytes than requested`
  warnings, a live worker at the same PID, no splice at the consumer session,
  no promotion/takeover/marker on 8.4.27-app, and 8.4.28-app clean. Logs live
  in gitignored `lab/build/evidence/w62-rlimit-*`. Full r5 stays UNCLAIMED; a
  fresh-context witness replay of `w61-varied-tfm.sh` (#4488) is the open gate.
- **Libraw2Shell W29/W31 — valid-size causal claim withdrawn** — from the committed
  specs in `lab/frontier/libraw2shell/w29/specs/` generate the input with the
  unmodified pinned `craft_uncompressed_poc.py` on `w11/targetbeef.input`,
  then run the unmodified `-O0 dcraw_emu` and `w23/sizefield.gdb` with
  `MALLOC_TOP_PAD_=16777216`. Expect red curve 18 to write the file-chosen
  `0x00c0` halfword at `(char*)main_arena.top + 8` (destimage index 68,773)
  and exit normally, while W21's `w13/dead-target.input` aborts with
  `free(): invalid next size (normal)`. W31's watchpoints and
  `w31/glibc-nextsize.c` correct the cause: further OOB stores leave `0x11`
  at `__libc_free` entry, and a standalone control exits cleanly with `0x11`
  whether PREV_INUSE is set or clear. A clean exit is NOT evidence that
  `free()` read a plausible chosen size. Red 49 was generated but not probed
  (UNKNOWN). Grade unchanged: rung 4 rests on W13/W14/W15/W17, with no
  overlapping allocation, pointer, marker or r5; details in `w31/results.txt`.
- **Gpgme2Shell W17 — one-command clean-archive wrapper** — run
  `sh lab/frontier/gpgme2shell/realbuild/run-witness.sh <outdir>` from the
  checkout. It makes a clean `git archive 057e2e2a lab/frontier/gpgme2shell`,
  copies the four already hash-verified tarballs from this checkout (no
  network), builds with unmodified `build-real.sh` and runs unmodified
  `run-eof.sh`. Expect `BUILD OK`, `PASS=25 FAIL=0`, rc 0, ASan
  `attempting double-free` at `engine-gpg.c:602` after `read_status :1494`,
  `buffer[1000]=0x48` at `bufsize=2048`, and clean fixed, 2.3.1, short-line
  and gdb-runner controls. Witness W222 (W19) returned ESTABLISHED AS LABELED on
  #4333 and #4487 from a clean `057e2e2a` archive with the same `BUILD OK` /
  `PASS=25 FAIL=0` / rc 0 and exact pin hashes; a newline-terminated
  counterexample reaches the same realloc but exits cleanly, confirming EOF
  before the `:1610` writeback (not line length) as the differentiator. The
  `buffer[1000]=0x48` observation is debugger-only; no grade or r5 move.
- **KiCad2Shell provenance** — the redundant 302243840-byte AppImage tar was
  removed from the uncommitted `provisioned/` tree after its hash and the
  extracted hash were verified. The replay-relevant pin remains the extracted
  AppImage sha256 `806e949cb357f9f0a05c3298c36eecb2b06d79c0a36e12c99f75aad9c89f0792`;
  no harness or expected bytes changed.

## 2026-11-25 18:1xZ — aspell2shell and freeimage2shell admission replay

- **Aspell2Shell** — CVE-2026-75818 / CERT Polska 2026-10-06, GNU Aspell
  before 0.60.8.3. Vulnerable parent `bc7ffcb1473578fbaa95653c08e6f1237decd568`,
  fix `15b188437f9e0192d4ac4472ad66a4e2f62a782f`. Run
  `bash lab/frontier/aspell2shell/harness/run-all.sh`; expect four pin hashes
  OK, the fix hunk present, seven build/input checks and six runtime checks:
  `RESULT 14 PASS / 0 FAIL`, rc 0. GCC and Clang vulnerable ASan runs report
  `heap-buffer-overflow READ of size 1` at pinned `prezip.vuln.c:173`, 0 bytes
  after the 256-byte allocation at `:154`; fixed rejects the crafted stream
  and both safe controls decode cleanly. The 75818 prezip lane stays rung 3; the
  separate 75820 limb is rung 4 PARTIAL (below). No pointer, command, r5 or
  independent verdict for either lane.
- **Aspell2Shell 75820 — chosen byte in the real dictionary consumer** — from
  `lab/frontier/aspell2shell` run `bash harness/75820-write-probe.sh` with
  `harness/evidence/75820-write/REPLAY.txt`; expect `RESULT 8 PASS / 0 FAIL`,
  rc 0. A 300-byte personal-word-list entry under a release NDEBUG build and a
  pipe-filter query writes `to_normalized(source[j])` past the 250-byte word:
  gdb at `j == 64` reads `0x00 -> 0x01` for all-`a` input and `0x00 -> 0x02`
  for all-`b`. Real 0.60.8.3 and a 0.60.8.2 copy with only the fix hunk reject
  with `Word larger than 250 characters.` (rc 1); a 250-byte word is clean.
  Arbitrary byte values, arbitrary offsets, pointer control, marker, command
  and r5 are NOT measured; witness UNKNOWN. Recover-mode ASan and gdb are for
  observation; details in `reports/frontier-aspell2shell.md`.
- **FreeImage2Shell** — CVE-2026-118753 / GHSA-wr69-568q-rrqg, Danoli3
  FreeImage before 3.19.25. Vulnerable `3.19.24` `4916e0ec`, fixed `3.19.25`
  `363311f1`, fix `0da5ddb4`. Pin sha256 values are
  `b6d9ffb11d8b819e7015536158a0e65b4baa2d4287c8b1e1949ce8c59e112299`
  and `b3cc4407576ecb9d12ee08b9cc1c36172ab73868f6acc64416459db93dcac9f2`.
  On the staged builds run
  `SKIP_BUILD=1 bash lab/frontier/freeimage2shell/run-all.sh`; expect
  `RESULT 9 PASS / 0 FAIL`, rc 0. The vulnerable ASan attack is an expected
  rc 134 with `WRITE of size 4` at `PluginGIF.cpp:743`, 0 bytes after an
  816-byte region; fixed attack, both safe controls and fixed chosen input
  exit 0. Three vulnerable plain chosen runs are expected rc 139 and each
  prints `PAST_PIXELS=554154ff554154ff554154ff` at `bits+400/+404/+408`.
  Grade: rung 3 real library / rung 4 PARTIAL at those fixed offsets only;
  no adjacent-object target, pointer, remote consumer, command, r5 or
  independent verdict. For a clean build use `bash bootstrap.sh` followed
  by `bash run-all.sh`; that full clean-archive replay was not run here.
- **Admission and activation boundary** — charters, seed walls and live
  two-pane windows 157/158 were verified before admission. Both resolver-key
  pairs are registered. Engine-route registration is person-reserved, so the
  route registry remains at 149 roles and the repository OMP-only checker is
  RED for exactly `aspell2shell: no route` and `freeimage2shell: no route`.
  The person-owned route shape, copied from the current neighboring entries,
  is hy4-flash `max_parallel: 3` primary followed by HungerG `max_parallel: 2`
  tier-1 fallback for each role. Generated path/debounce/slice units also
  remain missing; full-flag sync is person-reserved. No route or live unit
  delivery is claimed. The pinned single-model OMP checker remains stale
  against the directed two-model routes and is not an acceptance signal.
  Superseded later on 2026-11-25 by the owner's hy4-flash-only direction:
  all 152 declared roles (including these three) now have one hy4-flash route
  at `max_parallel: 5`; HungerG is retired and both checkers enforce the
  single-model allowlist. Generated units remain person-reserved.

## 2026-11-25 18:0x–18:5xZ — author receipts, negatives and one witness fold

- **Openexr2Shell W204 — independent verdict fold** — witness wake W218
  (#4457) replayed `sh harness/w202-benign-command.sh` from a clean
  `git archive 34832cb6`; `RESULT PASS`, rc 0, all five committed hashes
  matched (chain `54115664…`, ASan `71552269…`), with `touch /tmp/w202m` at
  d+1152 and type 31 at d+1172. Mutating the command byte under ASLR gives
  rc 139 and no marker; fixed build and safe input stay clean. Verdict:
  ESTABLISHED AS LABELED, benign command in shipped `exrcheck -c`, ASLR off,
  local EXR only; no wire, live target, full r5, or coverage of W203's
  ASLR-on negative. Detail: `.mishe-tauftauf/artifacts/witness-wall-w218-detail.md`.
- **PHP2Shell W63 — native RLIMIT chain** — on kernel `6.8.0-149-generic`,
  `CLK_TCK=100`, ASLR enabled and no phase-2 LD_PRELOAD, run
  `DEATH_MODE=rlimit PREBURN=1 MTAG=php2shell-r5-w63-final-1837 PORT=18134 bash lab/repro/php2shell-aftershell-splice-tfm.sh lab/build/php-8.4.27-app/sapi/fpm/php-fpm lab/src/php2shell-r5-app/tfm-app/web lab/build/evidence/w63-native-final 18134`.
  Expect soft=hard `RLIMIT_CPU=1s`/`RLIMIT_FSIZE=1024`, 98 ticks
  (79 coarse + 18 fine preburn), a 1597-byte carrier, a 1902-byte
  replacement, `new-record-prefix:True tail==carrier-tail:True`, marker
  `php2shell-r5-w63-final-1837`, `uid=1000(mesh-home)` and output hash
  `7df36e9a43417600d7c44b356195671df63e17c12f378fe8ffc5ab4b10d7c1ab`;
  the varied-SID `cafebabe00112233445566778899babe` run hashes
  `d3cf9df0ebd39854dfa25bf8add955a7138879f7eb9a6a2d9d92abf161176be1`.
  Fixed 8.4.28 (PORT 18140) leaves exactly 1024 bytes,
  `tail==carrier-tail:False`, no upload/marker, hash
  `67e59740f8f10b362fd7b29b646b14e2906fd9edec6532bf3254e0868afb76f1`.
  Author-side gates 1–5 only; gate 6 and full r5 stay UNKNOWN until a clean-checkout
  witness varies the command. W62's bare-FSIZE negative stays preserved.
- **PHP2Shell W65 — audited two-pool GAP chain** — commit containing this
  receipt hardens `GAP=1 DEATH_MODE=rlimit`: exact carrier-tail watcher,
  authenticated upload only while producer worker/request are live, unchanged
  producer PID and no SIGKILL required, separate pre-consumer/final splice
  checks, and ASLR/SID/filler/request geometry logged. Final harness SHA-256
  `45f11cd0327aad0cdd3f0b48bd66bce130777f79a907870af0a465a6cfbd0bb0`.
  Varied 8.4.27-app positive (`w65-gap-varied-final/`) has K=1024, exact-tail
  1597-byte pre-consumer snapshot, live producer at upload, admin takeover,
  designed upload, live-consumer marker `php2shell-r5-w65-gap-varied-final` +
  `uid=1000`, PID-bound marker, and no signal 9; final 1675-byte file does not
  retain the splice. Author log hash
  `229c7426e345c1670226ed0073e95d01645b0fb2fc7a339fa30eee8c87b1e88f`.
  Default-byte repeat hash
  `a87bbfd1f0e0a5369108fb34b1d5f1c25cc897ac19fcbd55b6beb4374e749f2e`.
  Same varied input on fixed 8.4.28-app has no watcher splice, no authenticated
  in-gap upload, no takeover/marker, `negative=1`; hash
  `1d8d9d7550439d065b8d83ae1b209a9707ad3fe64810f489611b448b46a119f0`.
  Author-side gates 1–5 only; gate 6 OPEN. Clean-checkout provisioning, build
  prerequisites and replay commands: `reports/php2shell-investigation.md` W65.
  Author hashes are receipt identifiers, not expected fresh-run hashes.
- **PHP2Shell W66 — final audited witness base** — GAP mode now rejects any
  `CPU_LIMIT` and requires it absent in the no-death verdict. Final harness
  SHA-256 `b65814ce83dfddc77c8830708863fa47b3613e22ad23fcc4d8b833697f0aa0fc`.
  Author positive with SID `0123456789abcdef0123456789abcdef`/filler `Q`,
  ASLR=2: K=1024, exact-tail pre-consumer snapshot, live producer at authenticated
  upload, unchanged PID/no signal 9, tinyfilemanager takeover, designed upload,
  live-consumer marker `php2shell-r5-w66-gap-positive` + `uid=1000`, PID-bound
  marker; final file does not retain the splice. Hash
  `c160f0f2cd88916ec2355e24dbb68c23b40c75c4776147b18f342731dcebc86e`.
  Same input on fixed 8.4.28: no watcher splice, no authenticated in-gap upload,
  no takeover/marker, `negative=1`; hash
  `c812fc6ca90b17250bb228e61db2ac07d2e570427dff268861ea77b686eea818`.
  Gate 6 OPEN. Final witness recipe requires fresh SID
  `0badc0de00112233445566778899beef`/filler `Z` for both builds; MTAG-only
  variation is insufficient. Full recipe: `reports/php2shell-investigation.md`
  W66. Author hashes are receipt identifiers only.
- **Libsshch2Shell W16 — wire-resident command** — `sh lab/frontier/libsshch2shell/real/run-wirecmd.sh`
  builds vulnerable `a540e276…`/fixed `7dfabb1f…` with clang ASan and
  `-DW14_REALSYSTEM -DW16_WIRECMD`; expect 6 PASS / 0 FAIL, rc 0,
  `CLIENT wirecmd fn=… sess=… cmd=touch evidence-wire-wirecmd.marker bad=0`,
  `SERVER done data_packets=2`, `target_after=0x41414141414141c1` and the
  renamed marker; fixed and bad-callee (`fn=0x4141414141414141`, status
  `0x100`) controls create no marker. The slot is probe-derived from
  `SERVER groom alloc`; the stale constant from W2/W3 scored 2 PASS /
  4 FAIL with an ASan `printf_common` overflow at `real_wire.c:240`.
  Clean-archive replay `0527035c` also scores 6/0 with different addresses.
  Author-only rung-5 mechanics; ASLR-local callee, no witness.
- **Stbvorbis2Shell W208 — live FILE pointer** — `sh lab/frontier/stbvorbis2shell/run-consumer-preload.sh`
  expects 17 PASS / 0 FAIL (plus `run-consumer.sh` 12/0); the 205-byte
  `chosen.ogg` writes through indices 8..31 into `c->multiplicands+32`, so
  gdb reads `_IO_save_base=0x4b4341484b434148` at k=27, with the same value
  in `_IO_backup_base`/`_IO_save_end`; plain rc 139, ASan rc 134, fixed and
  safe rc 0. The safe `preload-safe.ogg` is sha256
  `3a619dff0ccaacd6b7fc0f52bde37d4fd20b767b34407924eb4377358da87992`.
  Rung 4 PARTIAL only; no pointer target, command, witness or r5.
- **Openexr2Shell W205/W206 and Fontforge2Shell W24/W25 negatives** —
  `sh harness/w205-partial-pointer-negative.sh` and
  `sh harness/w206-ctxt-pointer-negative.sh` in `lab/openexr2shell-real`
  each expect `RESULT PASS` rc 0; hashes
  `dc3ac7dffa162bba97f73c36c78f3e0fdbbd2054d28c59f035e97e521f3dc9ae` and
  `6f9b5993506999d7d60fdb32b440a0252f84e409099f32940953a47677aa4948`.
  W205 reports `COMMAND_PLT_CALLS=0` with PIE/libc bases differing under
  ASLR; W206 finds seven resolvable slots all inside PIE exrcheck, none in
  libc. Both clean-archive receipts (`fd48b728`, `590e669c`) match.
  In `lab/frontier/fontforge2shell`, `sh replay-w24.sh` scores 3/0 on the
  RelWithDebInfo PIE build with `CAND_COUNT 0`/`RESULT NONE` and scan hash
  `6d3399d2c9d19b36d616325913399fc55a61deeb07d60e09e04d79f418c326be`;
  `sh replay-w25.sh` scores 8/0, hits `glyph=-1 i=3` and aborts before the
  later Save breakpoint, with PIE `RESULT NONE` and non-PIE
  `RESULT ASCII_ONLY` (clean-archive receipts `ed9d7a61`, `9dba13dd`).
  No code pointer, witness or r5 in any arm.
- **Vtkdicom2Shell W6/W7** — exact VTK v9.5.2 pin
  `d29a996ab2a49375a59cef5e381c1c25185ffa50`, `vtkDICOMItem.cxx` sha256
  `c53664edef2e5a7fa99237ef5a7b8e0eb62f371b289cca3cfda34e7cb44ee35c`;
  `cmake -S src-952 -B build-952 -DVTK_DIR=… -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF`
  then `./build-952/bin/reader-probe-952 evidence/undef-ob-chosen.dcm`
  expects rc 139, gdb `OOBWRITE tag=4841,434b key=4841434b n=5 slot=5`
  and ASan `WRITE of size 4` 32 bytes after a 136-byte region at
  `vtkDICOMItem.cxx:195`. W7's `tools/make-preceding-item-variant.py`
  yields stale `Value` headers (`low32=00000001`) at every predecessor
  count, never a pointer-shaped word; the `dicomdump` CLI rejects the bytes.
- **Other exact receipts and negatives** — `sh lab/frontier/libgphoto2shell/live/replay-partial-priv.sh`
  expects `RESULT: 16 PASS / 0 FAIL`, one ASLR-on fork-sweep hit at n=15922
  and an ASLR-off saved-RIP slot, no absolute target or command;
  `SKIP_BUILD=1 bash lab/frontier/freeimage2shell/run-all.sh` expects
  `RESULT 9 PASS / 0 FAIL`, ASan `WRITE of size 4` at `PluginGIF.cpp:743`
  and `PAST_PIXELS=554154ff554154ff554154ff` at `bits+400/+404/+408`.
  `git archive e00ea425 lab/frontier/pgactive2shell/realbuild/twonode`
  plus `ACTION=SKIP CONFLICT_TYPE=delete_delete VERSION=2.1.9|2.1.10 sh run-two.sh`
  expects one signal-6 termination on vulnerable
  `3177a37c…`, zero on fixed `986917a8…`. `git archive c69adb7a lab/frontier/hping3shell`
  plus `HPING_SRC=… TARGET_BYTE=195 sh wire/replay-target-byte.sh` expects
  `REPLAY_TARGET_BYTE_OK: 16 checks, target=0xc3`; the damaged debug
  destination line is accepted only with matching raw packet octets.
  `git archive HEAD lab/frontier/n2n2shell` plus `sh live/replay-all.sh`
  expects `REPLAY_ALL_OK`, 7 PASS / 0 FAIL with 15/0 harness and 22/0 live
  checks. `release-label/term320b/termlen320b/run-termlen320b.sh` in
  Synchronet expects 13 PASS / 0 FAIL, a 52-byte TERM giving
  `first=0x41414141` and SIGSEGV where 40/42/48-byte arms survive.
  Ruby's `lab/repro/ruby2shell-freeorder-map.py`, tcache-saturation,
  escaped-disposition and wide stock overlap traces log no claim/pop, no
  poisoned `next` and no command; `MTRACE_FREE_DUMP` was restored in
  `lab/preload/mtrace.c` and rebuilt with
  `gcc -shared -fPIC -O2 lab/preload/mtrace.c -o lab/preload/mtrace.so`.

## 2026-11-25 18:56–19:2xZ — two-pool PHP chain, consumer and tid limbs, negatives

- **PHP2Shell W64 — two-pool `RLIMIT_FSIZE` gap** — `KEEP_TMP=1 GAP=1
  DEATH_MODE=rlimit MTAG=php2shell-r5-w64-replay PORT=18340 bash
  lab/repro/php2shell-aftershell-splice-tfm.sh
  lab/build/php-8.4.27-app/sapi/fpm/php-fpm lab/src/php2shell-r5-app/tfm-app/web
  lab/build/evidence/w64-replay-vuln 18340`, with the matching 8.4.28-app
  fixed run at `PORT=18350`, expects a new session prefix and carrier tail,
  `evil.php` executed by the live FPM worker and
  `php2shell-r5-w64-gap-chain` under `uid=1000(mesh-home)` (evidence
  `91a18f97ceb89752c61409d484b3c5ac13024a378fdf651bc7087bb1e85ba6ee`), while
  fixed 8.4.28 leaves a 78-byte session without a marker
  (`2a38515de212b29e5b0362fbe240cfabd11c110687080ad07d1d49ffa5111971`). A
  varied SID `cafebabe00112233445566778899babe`/`Y` gives marker
  `php2shell-r5-w64-gap-varying`
  (`6bd15181f35b619e085b772db6eb5e92779dcc0cfadc5b6fd71b96b2509fd025`).
  Producer survives; no `RLIMIT_CPU`, SIGKILL or phase-2 `LD_PRELOAD`.
  Gates 1–5 only; gate 6 and full r5 remain OPEN/NOT ESTABLISHED.
- **Hping3Shell W16 — three chosen destination octets** — `HPING_SRC=$PWD/
  lab/frontier/hping3shell/provision/hping-src sh
  lab/frontier/hping3shell/wire/replay-multioctet.sh` expects baseline 4,
  attack 4, fixed 4 PASS and `REPLAY_MULTIOCTET_OK: 12 checks, fill=0x01`,
  rc 0; `git archive c3996959 lab/frontier/hping3shell` plus the gitignored
  `provision/` tree reproduces it with all 20 destinations predicted and
  15/16 `127.1.1.1`. `wire/rng-ij-proof.sh` refuses non-127/8 templates with
  exit 2 and `check_multioctet.py` predicts the address from `i`, `j` and the
  256-byte sbox. The legacy one-wildcard `check_ij` still exits 1, preserved.
  No pointer, command or witness verdict.
- **Openexr2Shell W207 — ASLR-on address-leak negative** — `cd
  lab/openexr2shell-real && sh harness/w207-leak-negative.sh` expects
  `RESULT PASS`, rc 0, `CASES_WITH_HEX_OUTPUT=0` over 12 cases (2 baselines
  rc 0, 7 rc 139, 3 rc 134), evidence hash
  `d5d7b448cbd14293b6f834102e574c23be5c7b412477d39c5ac0bcb05e031ae5`.
  `git archive 2f12c2e5 lab/openexr2shell-real | tar -x -C /tmp/w207-clean2`,
  symlinking gitignored `src/`, `build-vuln-plain/` and `cases/*.exr`,
  reproduces the same hash. The script counts `find cases/ -maxdepth 1` so a
  symlinked cases dir is traversed; `-s` on a FIFO timed out at 40 s
  (UNKNOWN). No witness verdict.
- **Drwav2Shell W8 — exact consumer headers** — each pinned header is linked
  into `/tmp/drwav-<consumer>-pin/dr_wav.h` and compiled with
  `gcc -O0 -g -fsanitize=address -I /tmp/drwav-<consumer>-pin -o
  /tmp/drwav-<consumer>-asan lab/frontier/drwav2shell/harness/harness.c`;
  chosen arms for Moondust (`5e60ebb4…c848c4`), Sphaira (`a4bd7d50…6674ce`)
  and Yup (`3d1b2f61…329fd9`) expect `metadataCount=1`,
  `CHOSEN_WORD_PRESENT=1`, `target_after=5a5a5a5a000000004b43414842424242
  6461746100000000` and rc 0, bad arms ASan SEGV at
  `drwav__read_cue_to_metadata_obj:2281`, safe arms `metadataCount=2` and chosen
  word 0 at rc 0. Raw outputs are in `consumer/evidence/w8-{moondust,sphaira,
  yup}-{chosen,bad,safe}.out`; Sphaira's remote-file playback is user-driven,
  not a listener, and the build is switch-only.
- **Other author receipts and negatives** — `MTRACE_TID=1` is opt-in in
  `lab/preload/mtrace.c`, rebuilt with `gcc -shared -fPIC -O2
  lab/preload/mtrace.c -o lab/preload/mtrace.so`; seven of eight N=972 Ruby
  processes survived with same-tid plant/upcase traces and no claim pop.
  Libsshch's five pinned callback registrations have no in-callback channel
  free in either pinned tree. Aspell 0.60.8.2 built with clang ASan
  (`configure --disable-shared`, `-fsanitize=address`) dumps 255-, 256-, 257-,
  260- and 511-byte personal-dict words at rc 0 with complete NUL-terminated
  bytes, no ASan report and no crash; the `aspell -a` probe stays UNKNOWN.
  Vtkdicom2Shell's exact-source replay remains DM #4503, unanswered.

## 2026-11-25 19:2xZ late edges — distinct Hping3 octets, staged FCEUX

- **Hping3Shell W17 — three distinct chosen destination octets** —
  `HPING_SRC=$PWD/lab/frontier/hping3shell/provision/hping-src sh
  lab/frontier/hping3shell/wire/replay-pattern.sh` rebuilds the pinned clang
  `-O0` vulnerable and locally patched trees, rechecks hashes
  `e8ef2dd6…dcbb5e7b` / `70f0112d…b471cb7aaa7f0ba846c7`, and expects
  baseline 4 PASS, attack 5 PASS and fixed 4 PASS with
  `REPLAY_PATTERN_OK: 3 stages`, rc 0. Patterns
  `wire/patterns/w17-three-distinct.hex` and `w17-second.hex` target
  `127.11.22.33` and `127.44.55.66`; `check_pattern.py` reads GDB state only,
  predicts 20/20 full destinations and requires three distinct octets plus a
  post-attack hit (1/16 in-tree, 1/16 in the clean replay). `git archive
  266144f0 lab/frontier/hping3shell` into `/tmp/w17-clean` with gitignored
  `provision/` copied in reproduces it. The 500,000-trial swap-stable search
  is a preserved negative; no pointer, command or witness verdict.
- **FCEUX2Shell W233 — staged, NOT admitted** — `bash
  lab/frontier/fceux2shell/run-all.sh` expects 14 PASS / 0 FAIL for the
  pinned verbatim `SetBoardName()` on vulnerable parents `1e1de9b` (GCC) and
  `d9132c2` (fix). GCC and Clang ASan report `WRITE of size 19` 0 bytes past
  a 1-byte region; the plain build yields rc 42 with
  `PAST_ALLOC=41552c66664d495348452d4643455558`, while fixed and safe-input
  builds stay clean. The attack file is 27 bytes (`MAPR`, `ffffffff`,
  payload). No emulator tree is built, no admission or route is created and
  the witness verdict stays UNKNOWN; rung 3 pinned / rung 4 PARTIAL only.

- **Gitignored evidence** — ASan/gdb outputs, clean-archive scratch trees
  and preload binaries are intentionally gitignored; regenerate each by the
  command quoted above from the named commit or pinned source. Addresses
  in ASLR-on dumps are normalized before hash comparison. Every receipt in
  this section is author-side; only W204 above carries an independent
  verdict, and no rung cell or R5 claim moved.

## 2026-11-25 21:4xZ — nfdump2shell admission replay

- **Claim and pins** — `reports/frontier-nfdump2shell.md` and
  `lab/frontier/nfdump2shell/PROVENANCE.md` record GHSA-gpgq-hv9x-7mqj (public
  advisory endpoint HTTP 404 on 2026-11-25, no CVE/CVSS), vulnerable parent
  `8a00543aa5c7b25b7d3f7642fdf306fd9979f237` and fix
  `32b9cbe7f17e099d59fc5eac71c84c6c6f051fa5`.
- **Harness** — `bash lab/frontier/nfdump2shell/run-all.sh`: 10 PASS / 0 FAIL;
  GCC and Clang ASan heap `WRITE of size 8`, 0 bytes after a 48-byte region in
  the pinned `Process_nfd()` store; fixed rejects the short element, safe-full
  and no-element controls clean; plain `EXPECTED_BYTES=9b50351f49010000` equals
  `CANARY_AFTER`.
- **Admission config** — charter, wall and two-pane window 160 checked and the
  window adopted. No route, resolver key or unit was added: engine-config,
  systemd unit and full-flag-sync changes are person-reserved
  (`.mishe-tauftauf/operator/standing-approvals.md:47-51`).
  `python3 tools/check-omp-only.py .mishe-tauftauf .` remains RED for
  `nfdump2shell: no route` (153 declared roles); the 21:29/21:34Z doctor runs
  list twelve missing unit files. The `failed-m2shell-doctor-service` RED was
  re-observed GREEN at 21:42Z with `--source operator-disposition --event
  missing-units-person-reserved-20261125T2145Z` on a refreshed person-owned
  disposition, not on a clean doctor run.
- **Grade** — rung 3 pinned verbatim functions, rung 4 PARTIAL packet-chosen
  offset with harness-chosen value, no adjacent object, pointer, wire, command
  or r5; witness replay and the person's exact full-flag sync remain owed.

## 2026-11-25 22:0xZ — Ruby2Shell D2 range sweep, wrong-arena correction, no-mtrace arm

Signal head `6fef8e61` and the following `8be1feb8`, `cc10113d` and `690c8338`
live in `reports/ruby2shell-investigation.md`; no rung cell, grade, route or R5
cell moves. Commands and receipts below are the ones the report records.

- **D2 range dumps** — with `MTRACE_DUMP_RANGE=1`,
  `lab/repro/ruby2shell-vtransition.py` emits `D2` at every post-A malloc in
  `0x400..0x460`; the bounds are env-configurable with
  `MTRACE_DUMP_RANGE_LOW`/`_HIGH` (default `0x400`/`0x460`). Fixed geometry for
  `vtransition2`/`vtransition3` (body SHA-256 prefixes `attack 92a21cc4a514`,
  `plant f00612ae80df`, `claim fc4e8ed6412f`, `N=972`, drain `984x7`, plant
  `1000x6`, filler `1x1200`, claim `1078@0x400:0x414,1015`,
  `POISON_GROWN=0x450`, `POISON_NEXT=0x90`) is tabulated in
  `lab/build/evidence/vtransition{2,3}.states.txt`. Across sixteen fresh
  stock-Sinatra processes no `0x43f` claim ever returned V; V's own header
  fields changed in some runs (e.g. `vtransition3-7` `vsize 0x450→0x3d0`,
  `vfd=0x26 vbk=0`), which is a size change, not a chosen-pointer write.
- **Retracted wrong-arena instrumentation** — `bin_detail` read bin heads at
  `current_tcache()-0x460`, but a per-thread tcache can belong to a different
  arena than V (`vtransition4-3`: V unsorted head `0x75aca8000480` vs D2 head
  `0x75ac9c000480`; `vtransition5-8` with `RAILS_MAX_THREADS=1`: V `0x7d08cc..`
  vs D2 head `0x7d08c0..`). The earlier conclusion that V's bin identity is
  stale because its links point into a self-linked head is **retracted as
  instrumentation evidence**; V's freshly read `vsize/vfd/vbk` fields remain
  valid. `lab/preload/mtrace.c` now derives the bin head from V's own `fd` at
  B, uses the rounded malloc chunk size for the bin index, and
  `build-mtrace.sh` builds `mtrace.so` atomically. `vtransition6` (eight
  processes, one thread, corrected arena) is a bounded NEGATIVE: no `0x43f`
  claim pop, three survivors, one boot-fail; in `vtransition6-8` bin reads
  land in V's arena (`0x772a5c000870` vs V `0x772a5c0a3f90`) while V still
  goes `0x401→0x453` and its `0x43f` claim allocates `0x772a5c07adb0`. Exact
  bin occupancy stays UNKNOWN because a bin's `fd` self-link reads at
  `bin-0x10`.
- **Attacker-pattern reuse is not pointer control** — in
  `stock-sinatra-vtransition4-3.server.log` V (`0x75aca8073ea0`) goes
  `0x401→0x453` at A (line 43995), is allocated by `M 0 400` at line 44603,
  shows `q0=0x4141414141414141`, `q8=0x4242424242424242` and
  `q10=0x5a5a5a5a5a5a5a5a` at line 45197, frees at 45199 with sizefield
  `0x415`, and is reallocated by `M 0 400` at 45326. Those qwords are the
  attacker's own multipart content in a buffer that reused V after the
  overflow — ordinary allocator reuse, not chosen bytes in a live object's
  metadata. No command, no persistence.
- **No-mtrace condition arm** — the same production-config wire chain with
  `RUBY2SHELL_CLAIM_NO_MTRACE=1` starts the server with no `LD_PRELOAD` and no
  `MTRACE_*` variable. Eight fresh processes: 2/8 (`untrace1-6`,
  `untrace1-8`) served drain, plant, attack, claim, probe and `/up` with
  404/404/404/404/404/200 and stayed alive; 6/8 aborted (`corrupted size vs.
  prev_size` in five). Without the tracer the pop is not observable, so
  survival is consistent with, not proof of, the measured `0x400` pop path;
  no command side effect and no safe/fixed control were run in this arm.
  Grade unchanged: harness-condition rung 5 stays as labeled, while
  stock/oracle-free/persistent rung 5 remains NOT ACHIEVED. The remaining
  prerequisite is a wire-observable request-carried marker driven by a pop
  whose chosen bytes reach a live object's metadata, plus a code-pointer
  source that uses none of mtrace, ObjectSpace.dump, `/proc/self/maps` or a
  debugger.

## 2026-11-25 23:2xZ — leptonica2shell admission replay

- **Claim and pins** — `reports/frontier-leptonica2shell.md` and
  `lab/frontier/leptonica2shell/PROVENANCE.md` record CVE-2026-137063
  (CWE-122, CVSS 6.8), affected Leptonica 1.79.0 through 1.87.0, upstream fix
  `c493a776e6bc6cfb1d8d15152a0b74f3d15b33fd`, pinned vulnerable tag 1.87.0 and
  fix commit excerpts with SHA-256 hashes in `PROVENANCE.md`.
- **Harness** — `bash lab/frontier/leptonica2shell/run-all.sh`: 17 PASS / 0
  FAIL; GCC and Clang ASan `WRITE of size 1000000001`, 0 bytes after a
  201-byte region in pinned `stream-parent.inc:17`, allocation at
  `create-parent.inc:9`; fixed rejects (`stream too large`, `BA=NULL`), 16-byte
  stream clean, bounded synthetic plain readback `PAST_ALLOC=4d495348452d4c4550544f4e49434111`.
  `git archive 925b35c2` replay gave the same 17 PASS / 0 FAIL, rc 0.
- **Admission config** — charter, wall and two-pane window 161 verified and the
  window adopted. No route, resolver key or unit was added: engine-config,
  systemd unit and full-flag-sync changes are person-reserved
  (`.mishe-tauftauf/operator/standing-approvals.md:47-51`).
  `python3 tools/check-omp-only.py .mishe-tauftauf .` stays RED for
  `leptonica2shell: no route` and `nfdump2shell: no route` (154 declared roles);
  the 23:09Z doctor run lists fifteen missing unit files. The doctor-failure
  RED was re-observed GREEN with `--source operator-disposition --event
  doctor-15-missing-units-person-reserved-20261125T2315Z`, not on a clean run.
  The drwav wake failure was observed GREEN on `failure-recovered` after the
  23:12:05Z journal showed `engine exit 0`; `signal-coverage` recomputed GREEN
  at 23:13:54Z on the absolute producer path.
- **Grade** — rung 3 pinned verbatim functions, rung 4 PARTIAL chosen bytes
  through a synthetic bounded consumer, no real library, adjacent object,
  pointer, wire, command or r5; witness replay and the person's exact
  full-flag sync remain owed.
