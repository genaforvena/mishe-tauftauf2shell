# mishe-tauftauf2shell

A public research lab that tries to take "X2Shell" runtime vulnerabilities
all the way to **rung 4 — demonstrated security impact** — and publishes
every step, including the ones that fail.

It studies twenty-five admitted vulnerability families in local, isolated
copies of the affected software:

- **Ruby2Shell** — CVE-2026-132825, a one-byte heap overflow in Ruby's
  string case conversion (upcasing `ß` writes two bytes where the loop
  checks space for one).
- **PHP2Shell** — CVE-2026-109618 / -109619, core-PHP OOM-handling
  corruption and stale state across requests; plus the reopened lane
  CVE-2026-126714, a session-file splice that decodes as a third session.
  Both splice halves were reproduced on the pinned affected builds, and the
  8.4.28 fix was verified in the lab. Several descendant lanes are at rung 3:
  CVE-2026-129481, a session-filename use-after-free after an interrupted
  shutdown on FPM 8.4.27, and CVE-2026-129474, a stale-argument read in
  `debug_backtrace()` on 8.5.12 triggered by the vendor's own regression
  case; both have clean fixed controls, and neither claims rung 4. The
  129474 read is invisible to ASan because ZendMM pools the affected memory.
  CVE-2026-129182, a backtrace-global repopulation UAF on 8.5, has a bounded
  loopback FPM harness; wake 45 completed the release-ASan FPM replay on
  8.5.12 — both vendor diagnostics reproduce but `VERDICT=CLEAN_NO_UAF`
  with zero ASan markers, also with fast shutdown forced, in ZendMM mode and
  under the control. Wake 46 root-caused that negative under gdb; wake 47
  corrected its source label and ordered it exactly: the 8.5.12 → 8.5.13 fix
  is two `if (EG(active))` guards around the dtor at `zend.c:1509` and the
  repopulation at `:1534`. Request 1's fatal repopulates the array, then its
  own `zend_shutdown_executor_values()` clears `EG(active)` and UNDEFs the
  global at `zend_execute_API.c:440` while its type is still `IS_ARRAY`
  (775); request 2's timezone warning runs with `active=0, flags=7` but
  `type=IS_UNDEF`, so the dtor is a no-op and the repop branch is never
  reached. `zend_activate()` is not the UNDEF site — that was wake 46's
  source-label error. The grade stays UNKNOWN with a fully ordered measured
  cause; no fatal while `active==0` with the zval still `IS_ARRAY` was found,
  and no 8.5.13 fixed release build was started for that lane.
  A new adjacent lane, CVE-2026-129538 / GHSA-5j3f-64r7-f564 (PHP-CGI
  out-of-bounds read and write during PATH_INFO correction), is rung 3
  CONFIRMED: on 8.5.12 a PATH_INFO shorter than the stripped SCRIPT_FILENAME
  suffix makes `path_info[0] = 0` write 15 bytes before the PATH_INFO string,
  and gdb observes that byte change from `47` to `0` at `cgi_main.c:1294`.
  The suffix length chooses the out-of-bounds offset and the FastCGI parameter
  order chooses the neighbouring value leaked into `$_SERVER['PATH_INFO']`
  (`"23456789"` or `"27.0.0.1"`); fixed 8.5.13 returns `"/x"` in both orders.
  ASan is silent because the touched bytes live in the environment block, so
  the evidence is the gdb byte observation plus the affected/fixed output
  difference. Wake 50 drove an ordinary HTTP request through a real loopback
  nginx 1.24 FastCGI responder (`lab/repro/php2shell-cve129538-nginx.py`): the
  standard `fastcgi_split_path_info` mapping is clean on both builds, while a
  naive non-default mapping (full URI in SCRIPT_FILENAME, short PATH_INFO)
  leaks adjacent param bytes (`6789` / `23456789`) on 8.5.12 and stays clean
  on 8.5.13 — verdict `HTTP-REACHABLE OOB READ CONFIRMED`. No chosen-byte
  write, pointer control or marker execution; grade stays rung 3.
  Another adjacent lane, CVE-2026-129501 / GHSA-x8r7-mg3g-74hg (double free
  during DOM XML serialization), is rung 3 CONFIRMED on 8.5.12: the vendor
  regression body and an XMLDocument-only shape both exit rc=1
  `ASAN_DOUBLE_FREE` on a dom-enabled ASan CLI, while a binary relinked with
  the byte-identical 8.5.13 `ext/dom/xml_serializer.c` exits rc=0 CLEAN and a
  single-namespace control is clean on both. The double free is in
  `dom_xml_ns_prefix_map_destroy()` at `xml_serializer.c:126`, patch-sensitive
  to the real fix; it needs `USE_ZEND_ALLOC=0` because the default ZendMM
  pools the 4-byte prefix and hides the second free from ASan. Wake 52 tested
  hunk 2 with the two 8.5.13 DOM regression bodies: both show affected-only
  DOM-state faults (lost children, orphaned comments) with rc=0 and no ASan
  report, while fixed matches vendor EXPECT; grade stays rung 3 from hunk 1.
  Tcache escalation is CLOSED NEGATIVE: the only owned prefix is `ns` plus a
  number (max 13 bytes, glibc 0x20 bin), while a PHP `zend_string` is at least
  32 bytes. A new FPM lane, CVE-2026-129291 / GHSA-jm4m-qfqx-967m (epoll UAF,
  claimed local privilege escalation), is rung 2 only: the 8.4.27 vendor phpt
  FAILs and 8.4.28 PASSes with no sanitizer report; single- and dual-file
  swaps of the fix did not isolate it. No chosen byte, pointer, marker, LPE
  demo or web path. Reproduce with `bash lab/php2shell/build-dom.sh 8.5.12`,
  `bash lab/php2shell/build-dom-fixed-variant.sh`,
  `python3 lab/repro/php2shell-cve129501-dom.py <php-vuln> <php-fixed>`,
  `python3 lab/repro/php2shell-cve129501-dom-hunk2.py <php-vuln> <php-fixed>`
  and `python3 lab/repro/php2shell-cve129291-fpm.py <php-8.4.27-fpm> <php-8.4.28-fpm>`.
- **Node2Shell** — CVE-2026-123828, two one-byte heap overflows in Node's
  HTTP/2 `Alt-Svc` handling (`src/node_http2.cc`): fix `nodejs/node@ae9ab37d62`
  removes `kNullTerminate` from both `WriteOneByteV2` calls, so the origin
  buffer and the app-supplied ALT/value buffer each write a terminator one
  byte past their end. Wake 33 isolated the value-side write as an independent
  rung-3 trigger (ALT 1048 → 4/4 then 3/3 SIGABRT rc=134 `malloc(): invalid
  next size (unsorted)` on v24.22.2; ALT 1200 and ALT 10 controls 2/2 each
  alive with the ALTSVC echo). Wake 34 put both terminators on-class in one
  request: 8/8 aborts rc=134 across three glibc signatures, the origin write
  dominating and no combination primitive. Rung 4 is not demonstrated and no
  sibling overflow was found in the subsystem. Reproduce: `sh
  lab/repro/node2shell-valnul/run.sh 3`.
  Admitted by the operator under standing approval #6.
- **Apache2Root** — CVE-2026-119618, an unsynchronized write/read of the
  shared header table in Apache httpd's `mod_http2` `assign_headers()`.
  Rung 3 is confirmed under gdb with Stage A chosen-byte placement. The lane
  is closed at Stage A: Stage C pointer control is unreachable in this build
  on this host — the wire-byte alphabet rejects the bytes a canonical pointer
  needs, Huffman-coded HPACK does not bypass validation, and no reachable
  size/index/count field was found. Rung 4 is not demonstrated. The earlier
  bounded race sweep was negative. An adjacent same-subsystem lane L1 (not a
  reopen of CVE-2026-119618) covers httpd 2.4.71's `H2PushDiarySize 0` +
  debug-logging crash: on 2.4.70 the h2c handshake fails (server rc=1) with
  UBSan `member access within null pointer of type 'struct h2_push_diary'`
  and ASan `SEGV on unknown address 0x00000000000c` in `h2_session_create`,
  while 2.4.71 answers rc=0 clean. It is rung 2 only — a fixed-offset NULL
  read needing operator-set config, so no chosen-byte or scalar-steering
  primitive and no route to rung 4; the main lane's Stage A closure stands.
  Adjacent lane L2 (CVE-2026-23918, an early-reset double purge) is also
  rung 2 only: h2c HEADERS plus RST_STREAM on pristine ASan httpd 2.4.66
  gives 800 sent / 18 responses with three child aborts/SEGVs across two
  runs, while 2.4.67 controls answer cleanly; the guard is `add_for_purge()`
  in mod_http2 2.0.37. Reproduce with `lab/apache2shell/build-l2.sh` and
  `python3 lab/apache2shell/l2-lane.py`.
  Adjacent lane L3 (CVE-2026-57941, shared `session->bbtmp` re-entrancy) is
  rung 3: on pristine ASan httpd 2.4.68, h2c GET/POST/RST_STREAM/GOAWAY
  traffic produces child SEGVs and a forced-ASan wild-jump PC in
  `h2_c1_read (h2_c1_io.c:502)`, while 2.4.69 stays clean. The race is
  intermittent and the jump target is not attacker-chosen. A body-canary pass
  (12 forced-ASan runs per byte, 8 connections × 20 streams) got wild-jump PCs
  in 8/12 runs for body byte `0x42` and 6/12 for `0x5a`, with low 12 bits from
  `{0x048, 0x228, 0x2c8, 0x7c8, 0x868}` and no byte pattern in any PC; an
  input-filter probe saw a stable `in_func` low 12 bits `0xa86` across 744
  calls while the PC varied. This is evidence against a body-steered jump,
  not proof of which slot held the target. L3 is closed at rung 3 with no
  reopen condition; rung 4 is NOT demonstrated. Reproduce with
  `bash lab/apache2shell/build-l3.sh` and
  `ASAN_OPTIONS='detect_leaks=0:handle_segv=1:allow_user_segv_handler=0:abort_on_error=0:halt_on_error=1' python3 lab/apache2shell/l3-lane.py 10 8 20`;
  add `L3_BODY_BYTE=5a L3_VERSIONS=2.4.68` before `python3` for the canary leg.
  Adjacent lane L4 (CVE-2026-56154, stale `ctx->vary` after
  `ap_destroy_sub_req()` in mod_rewrite's `%{LA-U:HTTP:...}` lookahead) is
  rung 3 confirmed: 2.4.68 gives 12/12 child SIGSEGV versus 2.4.69 0/12,
  with plain-header and absent-header controls 0/12. gdb pins the dangling
  pointer through `strlen` → `apr_pstrdup` → `apr_table_merge` at
  `mod_rewrite.c:4701`; ASan is silent inside uninstrumented system libapr.
  No chosen bytes, offset or pointer control; L4 closes at rung 3. Reuse the
  L3 2.4.68/69 ASan builds with `mod_rewrite.so` and `MaxMemFree 1`, then
  `cd lab/apache2shell && RW_VARIANT=lau RW_HEADER=yes RW_N=12 ./rw-lane.py 2.4.68 2.4.69`
  (plus the `plain` / `none` controls and `python3 rw-gdb.py`).
- **Mosquitto2Shell** — CVE-2026-110486 / GHSA-6j8m-r32v-4h38, a masked
  zero-length WebSocket frame that overruns a one-byte allocation in
  Mosquitto's built-in WebSocket backend; rung 3 + Stage A placement are
  reproduced locally, rung 4 remains UNVERIFIED.
- **Dragonfly2Shell** — GHSA-9q98-cx72-pg45, a memcached reply-builder key
  echo; rungs 1/2 are established on the stock build, stock rung 3 is
  UNVERIFIED, and the synthetic ASan write is labeled mechanics only.
- **Postgres2Shell** — CVE-2026-120149, an FDW batch-insert overcount:
  rungs 1/2 pass and rung 3 is observed under Valgrind, but it needs `PR:L`,
  so it is not a pre-auth claim.
- **Brotli2Shell** — CVE-2026-111497, a decoder block-switch over-write;
  rungs 1/2/3 pass on a standalone C harness with chosen bytes at chosen
  offsets; rung 4 is not demonstrated.
- **Freeradius2Shell** — CVE-2026-127030, an EAP-FAST SessionTicket stack
  overflow; rungs 1/2/3/4 pass in a standalone harness, with live `radiusd`
  reachability UNKNOWN.
- **Falkordb2Shell** — CVE-2026-107909, a Bolt/WebSocket extended-length heap
  over-write; rungs 1/2/3 pass in a standalone harness, rung 4 is not
  demonstrated, and the mask repeats every four bytes.
- **Freeswitch2Shell** — CVE-2026-116785 / GHSA-jj89-q47c-gh94, a WebSocket
  extended-length frame in the opt-in `mod_xml_rpc` endpoint whose truncated
  signed length passes the guard and overflows the handle. The unmodified
  pinned `ws.c` was also driven over a real 127.0.0.1 socket (with Abyss type
  stand-ins): the advisory's `FF FF FF FF` frame faults under ASan, while
  `7F FF FF FF 00 00 00 00` yields `plen=INT_MAX` and writes a chosen 8-byte
  value into `wsh->ssl` in that real function. The fixed build rejects both.
  A full vulnerable FreeSWITCH then ran on 127.0.0.1 in a private netns with
  `mod_xml_rpc` + `enable-websocket`: a real WebSocket `101` upgrade delivered
  the frame and GDB caught the chosen value dereferenced in `SSL_shutdown`
  (witness-replayed #338 with different bytes at the same fault site). Fixed and
  in-bounds controls survive. The sentinel is not code; stock heap layout,
  external reachability and the opt-in config gate stay in the claim.
- **Freerdp2Shell** — CVE-2026-114045 / GHSA-3m9q-g533-rqjq, a UINT64
  wraparound in FreeRDP's server-side rdpsnd `select_format()` that leaves
  `out_frames` unrolled back after a failed realloc, turning later audio
  sample copies into an unbounded, client-controlled sequential heap
  overwrite. Default posture is post-auth (`PR:L`); only no-auth deployments
  reach the 9.8 ceiling. Admitted 19:32Z under standing approval #6. Rungs
  1-3 and chosen-byte rung 4 are reproduced on source-built FreeRDP 3.32.0
  library bytes through the real `SNDC_FORMATS` parser, the real
  `rdpsnd_server_handle_messages()` dispatcher and, in wake 6, libfreerdp's
  real WTS virtual-channel reader with the shadow `Activated` selection path.
  Wake 6 also measured the gate: in the FFmpeg-off builds tested the stock
  server format list is PCM-only, so neither the DVI_ADPCM (tag `0x11`) nor
  the WAVE_FORMAT_ADPCM (tag `0x02`, `nBlockAlign=8`) wrap-capable record is
  selectable by default; the positive rung 4 supplies a server ADPCM record
  through `subsystem->rdpsndFormats`. Wake 7 ran a real 3.32.0
  `freerdp-shadow-cli` on 127.0.0.1:13890 and a probe completed the X.224 /
  RDP_NEG_REQ exchange over real TCP; the default NLA gate was observed when
  the TLS handshake finished but CredSSP credentials were withheld (server
  stayed at `CONNECTION_STATE_NEGO`), while a standard-RDP local-peer offer
  advanced without credentials. Wake 8 completed X.224 → MCS CONNECT →
  ERECT DOMAIN → ATTACH USER → three CHANNEL JOIN confirms against that live
  server and drove a headless `sfreerdp` to `CONNECTION_STATE_ACTIVE`;
  `SNDC_FORMATS` crossed the real wire and a subsystem-supplied ADPCM
  record logged `realloc failed!` / `SelectFormat failed with 12` in the
  live server. A synthetic playback event then produced ASan
  `WRITE of size 16384` 0 bytes after the 8820-byte region in
  `rdpsnd_server_send_samples` with a client-chosen `0xDE` at offset 8820.
  Those results used a no-auth server, a subsystem-supplied format table and
  an ASan build. A later pass repeated the live chosen-byte overwrite under
  the stock glibc allocator with no sanitizer: 7564 OOB bytes at offsets
  8820..16383, the first OOB byte client-chosen, no fault at the write, and
  glibc `double free or corruption (!prev)` on teardown; a benign-only
  control stayed in bounds. Wake 10 committed a one-command replay of that
  result, `bash lab/freerdp2shell-src/verify_live.sh`: it pins tag 3.32.0,
  applies five committed patches and drives both loopback TCP sessions with
  real readiness checks, reporting 17 PASS / 0 FAIL warm and 18 PASS / 0 FAIL
  from a clean clone (`lab/freerdp2shell-src/verify_live_run.txt`). The
  vulnerable session logs `WAKE9_COPY ... b8820=de ... b21384=00` followed by
  glibc corruption; the benign control keeps `b8820=00`. Witness W31
  independently re-ran the unmodified script from clean HEAD b25d025 in its
  own clean room: 18 PASS / 0 FAIL, RC 0, verdict ESTABLISHED with no
  corrections (#532). The one-command harness uses post-auth credentials, so
  it does not re-assert the no-auth 9.8 case. Wake 12 measured the stock
  glibc heap layout in three loopback sessions (ports 23143-23145,
  byte-identical): a 64-byte chunk at `out_buffer+9056` holds two live heap
  pointers at +9072/+9080 inside the chosen-0xDE write, so pointer-bearing
  heap data in the write path is OBSERVED
  (`lab/freerdp2shell-src/heap_layout_stock.txt`). Wake 13 identified that
  object as the wLog for `com.freerdp.channels.rdpsnd.server` and, with a
  configured `WLOG_FILTER` and a scratch log call injected right after the
  real copy, showed `mov (%rax,%r15,8)` dereferencing the eight chosen `0x41`
  bytes at `out_buffer+8904` as `rax=0x4141414141414141` in the live stock
  build (`lab/freerdp2shell-src/pointer_control_stock.txt`). Wake 14 replaced
  the scratch server log call with FreeRDP's own `SNDC_QUALITYMODE` receive
  path: with a scratch client-side delay after the second `SNDC_FORMATS` PDU,
  the unmodified live stock server faults at the same `mov (%rax,%r15,8)`
  with `rax=0x4141414141414141`
  (`lab/freerdp2shell-src/natural_log_trigger_stock.txt`). No server code was
  injected; `WLOG_FILTER` is still required and the no-filter control is clean
  with a raw log in `verify-live-out/wake14/`. The trigger and chosen playback
  bytes are lab-supplied, the object was found after the fact with no grooming,
  and only one object was controlled; arbitrary heap targeting, a real audio
  source and an FFmpeg-enabled build stay UNKNOWN.
- **Xrdp2Shell** — CVE-2026-44178 / GHSA-hh7r-2rmq-q4g4, a client-controlled
  reassembled DYNVC virtual-channel payload copied into xrdp's fixed
  8192-byte server→chansrv out stream. Default posture is post-auth (`PR:L`)
  with a dynamic channel open; only no-auth deployments reach 9.8. Admitted
  ~20:27Z under standing approval #6; rungs 1-3 and chosen-byte rung 4 are
  recorded in the brief, and a second driver reproduces them on real compiled
  xrdp 0.10.6 library bytes with markers read back in an adjacent heap chunk
  (no pointer-sized target). A third driver feeds a wire-formatted
  TPKT/X.224/MCS/channel/DYNVC PDU to the real `xrdp_rdp_recv()`: an 8191-byte
  payload overflows the sink through that chain, while the 20000-byte harness
  size is rejected by the MCS 16K limit. A completed RDP logon, a chansrv-
  negotiated dynamic channel, a socket-level PDU trace, live-session
  allocator layout and the auth gate stay UNKNOWN; loopback COTP reachability
  of the lab listener only.
- **Gst2Shell** — CVE-2026-111183 / GHSA-62fg-53h6-6f68, a high
  `channels` value in GStreamer's rtpL8/rtpL16/rtpL24 depay caps that over-writes the fixed
  64-entry `GstAudioInfo.position` array. Rungs 1-3 are reproduced in an
  extracted harness (`oob_writes=936`, caps length chooses the clobbered
  offsets, ASan `WRITE of size 4`, clean fixed control). Wake 6 corrected the
  harness's `NONE=0` model: the pinned enum is `-3`, so index 73 turns a NULL
  `order` pointer into `0x00000000fffffffd`, faulting at `depay.c:267`; a live
  GStreamer 1.24.2 ASan instance reproduces that fault and the shipping
  `rtpL16depay` plugin faults rc 139 on one caps field. A 2026-11-21 pass
  symbolicated the shipping N=1000 fault by gdb debuginfod to `srcpad->g_class`
  of a heap-adjacent GstPad (cross-object pointer corruption with a fixed `-3`
  value), and drove `a=rtpmap:96 L16/44100/N` SDP text through GStreamer's own
  parser into the same fault at N=86/1000 (the harness explicitly models the
  RTP structure name).
  A 2026-11-21 loopback RTSP server feeding a real `rtspsrc ! rtpL16depay`
  client delivered `encoding-params=(string)1000` with no auth challenge and
  faulted the client at N=1000 (rc 139, reproduced four times) against a
  clean N=8 control; gdb located that corruption in a GLib `GSource` rather
  than the direct-set_caps site. Stock `uridecodebin` auto-plumbing selects
  the same depay from that stream and aborts at N=1000 with
  `malloc(): invalid size` (rc 134), removing the explicit-link step; the
  earlier `sdpdemux` file-path negative is preserved. This is count-controlled
  impact, not chosen bytes: strong rung 4, whether any public service accepts
  attacker SDP, RCE and allocator layout stay UNKNOWN.
  A 2026-11-21 pass repeated the loopback server across the whole advisory
  family (`rtsp_server_codec.py` `1493f137…cb45c`, `run_rtsp_family.sh`
  `54e8331e…786e`): decodebin auto-plugs all three depays and N=1000 faults
  each — L8 and L24 by heap abort (rc 134), L16 by SIGSEGV/segtrap — against
  clean N=8 controls; the exact glibc message varies between runs, so the
  claim is only "attacker-chosen count faults the victim". The L8 path under
  memcheck shows three 4-byte invalid stores 0/4/12 bytes past a 1016-byte
  GObject allocation; the shipping plugin has no debug info, so that write
  is not symbolicated to a function name in that run. One command replays
  every driver: `bash lab/gst2shell-src/verify_all.sh` (add
  `VERIFY_VALGRIND=1` for the memcheck lane). A witness replay contradicted
  the earlier "43 PASS / 0 FAIL at HEAD 3b07571" assertion on its host with
  42 PASS / 1 FAIL (rc 1): the L8 N=1000 leg's allocator-abort text was not
  matched by the old regex. `verify_all.sh` now accepts the observed fault
  family or a nonzero per-leg rc while keeping 43 checks. From repaired HEAD
  31e7243 the author's `VERIFY_VALGRIND=1` replay is 43 PASS / 0 FAIL, rc 0;
  a docs-side run without that flag is 39 PASS / 0 FAIL, rc 0. These are
  author and docs replays, not independent acceptance. Witness W33 (#552,
  04:25Z) re-ran the unmodified `VERIFY_VALGRIND=1` replay from clean HEAD
  2a78ee6: 43 PASS / 0 FAIL, rc 0, REPAIR ESTABLISHED and the 42/1
  contradiction closed. Chosen-byte rung 4 stays NOT DEMONSTRATED.
  Admitted ~20:52Z under standing approval #6.
- **Babelfish2Shell** — CVE-2026-119923 / GHSA-vq28-vgj3-r26w / AWS
  2026-166-AWS, an unbounded 16-bit TDS prelogin `length` copied verbatim
  into a fixed 1024-byte `StringInfo` buffer, so both the copy count and the
  written bytes are sender-chosen. Unauthenticated TDS packet, default port
  1433; CWE-122, CVSS 3.1 9.8. Admitted ~22:2xZ under standing approval #6.
  Rungs 1-3 and harness-only chosen-byte rung 4 (bytes at OOB offsets
  1100/2000) are recorded in the brief; no live Babelfish process, `palloc`
  layout or real neighbour was observed.

- **Bzfs2Shell** — CVE-2026-130849 / GHSA-9q5f-g948-c95m, a 1024-byte TCP
  body on the unauthenticated player socket writes four chosen bytes past
  `tcpmsg[1024]` into `int tcplen`, leaving a negative read offset that
  steers the next `recv()` before the buffer. C++ game server admitted
  ~00:5xZ under standing approval #6 as an X2Shell-class extension (scope
  judgment recorded in the charter). CVSS 4.0 9.3, CWE-122, PR:N;
  affected <2.4.32, fixed 2.4.32. Rungs 1-3 and harness-only chosen-value
  rung 4 are recorded in the brief; no live bzfs, real layout or execution
  was observed.

- **Kamailio2Shell** — CVE-2026-106803, an unbounded tilde-distance `memcpy`
  into `char bufport[5]` in Kamailio's IMS P-CSCF `ims_registrar_pcscf`
  module, reachable through a crafted reginfo+xml NOTIFY Contact URI. CWE-121,
  CVSS 3.1 9.8, affected 6.1.3/6.1.4, fixed 6.1.5. Admitted ~02:2xZ under
  standing approval #6; rungs 1-3 and instrumented chosen-value rung 4 are
  recorded in the brief, with the module gate, real frame layout and any
  return-address control UNKNOWN.
- **Iperf2Shell** — CVE-2026-101283 / GHSA-pwcx-5qh6-2pxc, a 336-byte
  base64-decoded `authtoken` passed as the `BIO_read` size into a 256-byte
  RSA heap buffer in iperf3's `decrypt_rsa_message()`. CWE-122, CVSS 4.0
  9.2, affected 3.20/3.21, fixed 3.22; RSA auth must be enabled but the write
  is pre-auth. Admitted ~02:2xZ under standing approval #6; rungs 1-3 run on
  the real pinned upstream function, rung 4 is instrumented chosen-byte
  control only, and the 3.22 release-note mislabel is preserved.
- **Uftpd2Shell** — CVE-2026-59964 / GHSA-vqhc-mmjf-972h, an unbounded
  `memmove` in uftpd's `compose_path()` that shifts the capped `dir[PATH_MAX]`
  right by the configured home length and writes that many bytes past the
  stack buffer. CWE-121, CVSS 3.1 5.9 MEDIUM, affected <2.16, fixed 2.16;
  it needs a logged-in FTP client and a no-chroot server. Admitted ~02:4xZ
  under standing approval #6; rungs 1-3 run on the verbatim pinned upstream
  function, rung 4 is instrumented chosen-byte control only, and RCE is not
  demonstrated by the advisory.
- **Accelppp2Shell** — CVE-2026-123205, an unbounded chunk `memcpy` in
  accel-ppp's `unpack_msg()` that concatenates L2TP string AVPs into a fixed
  4160-byte heap buffer without a bound. CWE-122, CVSS 4.0 8.3 High
  `AV:N/AC:L/AT:P/PR:N`, affected <1.15.0, fixed 1.15.0; it needs verbose
  logging and a peer within the configured client-ip-range. Admitted ~03:1xZ
  under standing approval #6; rungs 1-3 run on the verbatim pinned upstream
  function, rung 4 is instrumented chosen-byte control only, and no RCE is
  demonstrated.
- **Indiserver2Shell** — CVE-2026-71979, an unbounded `sprintf()` diagnostic
  in INDI indiserver's XML chunk parser: a ~1.2 KB mismatched-tag packet
  writes 1237 bytes into `err[1024]` on the shared TCP/7624 client/driver
  read path, with no auth or config gate. CWE-121, CVSS 4.0 8.7 High
  `AV:N/AC:L/AT:N/PR:N`, affected through 2.2.4.2, fixed at commit `96bbd7f`.
  Admitted ~03:18Z under standing approval #6; rungs 1-3 run on verbatim
  pinned upstream `lilxml.cpp` bytes, rung 4 is instrumented chosen-byte
  control only, and the advisory claims availability only, not RCE.
- **Shairport2Shell** — GHSA-6g79-wrcj-h8xw (no CVE), an RTSP
  unrecognised-method body hex-dumped into `char obf[4096]` on AirPlay-2
  builds: 4096 input bytes clamp as bytes but write 8193 hex+NUL bytes.
  CWE-121, CVSS 3.1 7.5 High, affected `<5.5`, fixed `5.5`/`5.6-dev`.
  Admitted ~03:4xZ under standing approval #6; rungs 1-3 run on verbatim
  pinned upstream `rtsp.c:4206-4221`, rung 4 is instrumented chosen-byte
  control only, and the advisory claims availability only, not RCE.
- **Asterisk2Shell** — CVE-2026-57201 / GHSA-x348-j6c9-77f3, an unbounded
  `vsprintf` past `char logMessage[2048]` in Asterisk's H.323 `ooTrace()`
  logger. CWE-787; sources conflict (GHSA High 8.1 with C/I impact vs CVE
  7.5 availability-only), so the conservative crash-only ceiling applies.
  Affected `<= 23.4.0` and older branches; fixed 23.4.1 and matching releases.
  Needs the `chan_ooh323` addon explicitly compiled and its port exposed —
  a deployment gate, not an in-protocol auth gate. Admitted ~04:2xZ under
  standing approval #6; rungs 1-3 run on verbatim pinned upstream
  `ootrace.c:35-53`, rung 4 is instrumented chosen-byte control only.
- **Netatalk2Shell** — CVE-2026-45698 / GHSA-5443-v9xg-mqgv, an integer
  underflow in `afpd`'s `deletedir()` that turns `remain` into `SIZE_MAX` and
  lets an unbounded `strcpy` write an attacker-chosen filename past
  `char path[MAXPATHLEN + 1]`. CWE-787, High 7.5
  `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`; the maintainer's authenticated RCE
  claim stays a claim. Affected `>=3.1.19, <4.4.3`, fixed 4.4.3. Needs an
  authenticated AFP session and a cross-device rename path inside a share.
  Admitted ~05:0xZ under standing approval #6; rungs 1-3 run on verbatim
  pinned upstream `directory.c:147-203`, rung 4 is instrumented chosen-byte
  control only.

Nothing here scans the internet or talks to a real target. Sources are
downloaded from their official homes, builds and test servers run on
`127.0.0.1`, and a separate mind re-runs every claimed result before it
is called established.

## What it has achieved so far

| Target | Where it stands | Highlights |
|---|---|---|
| **Ruby2Shell** | **Rung 4 — demonstrated impact, request-reachable on both claimed default stacks; every rung-4 claim witness-ESTABLISHED** | Chosen bytes written at a chosen offset on stock glibc, 5/5 with a clean control; the same chain driven by one multipart POST through default-config Sinatra (5/5 + control) and a default `rails new` app (5/5 + control, CSRF fires too late in the controller to matter) before routing/CSRF/auth; ASan heap-buffer-overflow on the committed repro. Independent witness: in-process chain ESTABLISHED (tape #51), both HTTP sections ESTABLISHED request-reachable (tape #65) and Stage C ESTABLISHED as strengthened pointer control (tape #89). A 2026-11-21 depth pass carried Stage C onto the Sinatra request thread (3/3 attacks, 2/2 controls): the nominated address was handed out and its chosen bytes read back in the HTTP response, but the process then aborts in WEBrick worker-thread tcache teardown — no persistence or surviving process claimed. The vendor's copy-out one-byte over-read was separately reproduced under valgrind as a second observed invalid access (rung 3 class): the byte read back is the same `0x53` the overflow wrote and the returned string is correct, so it is not an information leak and raises no grade. [Full report](reports/ruby2shell-investigation.md) |
| **PHP2Shell** | **Rung 4 — constrained placement (CGI and mod_php witness-established)** | Deterministic OOM-during-request-parsing trigger (rung 1); every cheaply reachable SAPI consumer surveyed with negatives observed, not assumed; rfc1867 upload-progress PoC ported with version-discriminating behavior on affected 8.4.26 vs fixed builds. Reopened 2026-11-20 under CVE-2026-126714: both splice halves reproduced on both pinned ASan builds — an interrupted real session write leaves a replacement prefix plus carrier tail on disk and the next request promotes the object; the kill is shim-simulated, not a remote trigger. The 8.4.28 fix was verified in the lab: under the same kill the write leaves only a truncated new prefix and no promoted object. A separate Stage A chain writes chosen bytes at chosen offsets of the consumed stale HashTable: witness #138 ESTABLISHED the constrained rung-4 form on CGI and witness #258 independently re-ran the mod_php leg to the same grade (fresh logs in `lab/build/evidence/w18-apache-modphp/`); `arData` is only a length, so there is no pointer control or marker execution, and FPM stays rung 3. New descendant lane CVE-2026-129481 (session-filename use-after-free) is rung 3 on FPM 8.4.27, patch-sensitive with a benign control; no rung 4. [Status](reports/php2shell-status.md) |
| **Apache2Root** | **Rung 3 — lane closed at Stage A; rung 4 not demonstrated** | Differential child SIGSEGV on affected 2.4.70 and clean fixed control under gdb, with chosen-byte placement at a capacity boundary. Stage C is closed as unreachable on this host: a repaired Huffman probe re-ran at 19:11Z and every forbidden value still draws RST:1 (the ASCII control gets HTTP 200), and a 15-capture fault-site census plus a heap-layout check found only pointer slots, no scalar control field. The earlier bounded ASan sweep was negative and is preserved. Adjacent same-subsystem lane L1 (`H2PushDiarySize 0` + debug logging) is rung 2 only: 2.4.70 UBSan NULL-member access and ASan `SEGV on unknown address 0x00000000000c` in `h2_session_create`, 2.4.71 rc=0 clean; reproduce `python3 lab/apache2shell/pushdiary-lane.py`. [Report](reports/apache2shell-investigation.md) |
| **Mosquitto2Shell** | **Rung 3 — confirmed corruption; info disclosure witness-established** | ASan `WRITE of size 256`, 3 bytes after a 1-byte region, via `net__read_ws (net_ws.c:305)` on affected 2.1.0-2.1.2; clean close on fixed 2.1.3; Stage A places 4N chosen bytes at a chosen offset. A wire-only pre-auth 32 KiB heap read with live pointer disclosure is witness-ESTABLISHED (#246), but the enlargement is layout-dependent on fresh brokers; wire-derived code execution / tcache control remains UNVERIFIED. [Brief](reports/frontier-mosquitto2shell.md) |
| **Node2Shell** | **Rung 3/3.5 — two independent AltSvc terminators; rung 4 not demonstrated** | One-request stock-glibc abort is 10/10 deterministic on officially affected v24.22.2 (`origin_len=1048`); deterministic Memcheck differential there (`Invalid write of size 1` in `WriteOneByteV2`, 2/2) against a clean v24.22.3 control. The debugger-observed NUL shrinks a free chunk's size magnitude by 0x10..0xf0 — the earlier flags-only PREV_INUSE-clear reading was retracted. The UTF-8 low-byte-truncation channel was tested and closed (U+0100 `c4 80` rejected), leaving no binary-capable heap-byte channel in this attacker model. Wake 33 isolated the second (value/ALT) terminator as an independent rung-3 trigger: ALT 1048 aborts 4/4 then 3/3 with `malloc(): invalid next size (unsorted)`, ALT 1200 and ALT 10 complete 2/2 each; wake 34 put both on-class in one request — 8/8 SIGABRT rc=134 across `mismatching next->prev_size` 2/8, `invalid next size` 3/8, `double free or corruption (!prev)` 3/8, with the origin write dominating and no combination primitive. The value lane never captured its pre-write sizefield; the ladder stays rung 3. [Report](reports/node2shell-investigation.md) |
| **Dragonfly2Shell** | **Rungs 1/2 — established on stock** | A 20000-byte key created over RESP is echoed through memcached in a 20024-byte reply; witness gdb observed `SendValue` with `rdx=0x4e20`. Stock rung 3 and rung 4 are NOT demonstrated; the ASan 20000-byte write is a labeled synthetic harness. [Status](reports/dragonfly2shell-status.md) |
| **Postgres2Shell** | **Rung 3 — confirmed corruption under Valgrind** | FDW batch-insert overcount on stock 17.11: uninitialised 8-byte heap value used as a pointer, invalid write at `0x38`, SIGSEGV; fixed 17.12 completes. It requires `PR:L`, so pre-auth RCE is NOT demonstrated. [Status](reports/postgres2shell-status.md) |
| **Brotli2Shell** | **Rung 3 — confirmed corruption (standalone harness)** | Pinned two-stage stream drives 20 attacker-chosen bytes past an 8-byte decoder buffer into named state fields; fixed build rejects with `ERROR -17`. Rung 4 is NOT demonstrated; network reachability is a claim. [Status](reports/brotli2shell-status.md) |
| **Freerdp2Shell** | **Rung 4 — chosen bytes on real library bytes and in the live server over the wire** | A crafted `SNDC_FORMATS` record with `nChannels=2, nBlockAlign=4` passes the scalar guard, wraps `out_frames` to `0xfffffffffffffff0` after a failed realloc, and drives sequential client copies past the 8820-byte buffer. ASan reports `WRITE of size 16384` in `rdpsnd_server_send_samples` on source-built 3.32.0; a sanitizer-free replay through the real `rdpsnd_server_recv_formats()` parser places `de` at OOB offset 8820 and `ad` at 21384, with a fixed-guard control at rc 3 and no wrap. Wake 5 drove a framed PDU through the real dispatcher; wake 6 replaced its stub WTS reader with libfreerdp's real reader and shadow activation, and measured that FFmpeg-off builds offer PCM only, so the positive case needs a subsystem-supplied ADPCM server record. The ADPCM variant wraps `out_frames` to `0xfffffffffffffffc`. Wake 7 ran a real 3.32.0 `freerdp-shadow-cli` on 127.0.0.1:13890 and drove X.224 / RDP_NEG_REQ over real TCP: protocol `0x08` NLA / `0x02` TLS / `0x00` RDP, and the default NLA gate held after a completed TLS handshake with CredSSP withheld (`CONNECTION_STATE_NEGO`), while standard-RDP local-peer mode advanced without credentials. Wake 8 completed MCS/ERECT-DOMAIN/ATTACH-USER/channel-join, reached `CONNECTION_STATE_ACTIVE` with a headless `sfreerdp`, observed `SNDC_FORMATS` over the wire and the live server's `realloc failed!` / `SelectFormat failed with 12`, and reproduced the ASan `WRITE of size 16384` in the LIVE server with client-chosen `0xDE` at offset 8820. No-auth server, subsystem-supplied ADPCM table, ASan build and synthetic playback are explicit conditions; the stock-allocator live replay is one command (`bash lab/freerdp2shell-src/verify_live.sh`, 17 PASS warm / 18 PASS clean) independently accepted by witness W31 (#532, ESTABLISHED, no corrections; post-auth credentials, so no-auth 9.8 is not re-asserted). Wake 12 measured the stock glibc layout in three loopback sessions: two live heap pointers at `out_buffer+9072/+9080` lie inside the chosen-0xDE range (`heap_layout_stock.txt`). Wake 13 identified that object as the rdpsnd channel's wLog and showed a chosen `0x4141414141414141` dereference in `WLog_GetFilterLogLevel` in the live stock build, with a scratch post-copy log call, a configured `WLOG_FILTER` and lab-supplied playback bytes; no grooming or arbitrary target control (`pointer_control_stock.txt`). A real audio source and an FFmpeg-enabled build stay UNKNOWN. [Status](reports/freerdp2shell-status.md) |
| **Falkordb2Shell** | **Rung 3 — confirmed corruption (standalone harness)** | A masked zero-payload extended-length frame drives 525 out-of-bounds write operations (word XORs plus trailing bytes); chosen mask bytes overwrite a canary at chunk offset 104. ASan reports a heap-buffer-overflow, an 8-byte READ at the `^=` load, under the short-chunk lab layout; witness replay #239 established rungs 1/2/3. Rung 4 is NOT demonstrated because the mask repeats every four bytes. [Status](reports/falkordb2shell-status.md) |
| **Freeswitch2Shell** | **Rung 4 — chosen-pointer dereference in a live FreeSWITCH process over loopback; sentinel is a value, not code** | A length-127 WebSocket frame in the opt-in `mod_xml_rpc` endpoint decodes `FF FF FF FF` to `plen=-1`, passing the signed guard; ASan reports `WRITE of size 132146` in `ws_raw_read`. An 8-byte chosen value at `offsetof(wsh_t, ssl)=131112` executes a marker at rc 42 in the extracted harness; the fixed build rejects with `rc=-1009`; 5/5 repeats are identical. Unmodified pinned `ws.c` (Abyss type stand-ins only) over a real 127.0.0.1 socket: that all-FF frame gives ASan `negative-size-param (size=-5)` in `memcpy` from `ws_raw_read` (`ws.c:306`) and plain rc 134. A different length, `7F FF FF FF 00 00 00 00`, sets `plen=INT_MAX`, overflows the guard's signed add and takes the normal clamped branch: `bash lab/freeswitch2shell/live/run_pos.sh` places `0x4142434445464748` in `wsh->ssl` (`ssl_bytes=4847464544434241`, `RESULT=PASS`, rc 0), fixed `rc=-1009` with `ssl=(nil)`, ASan `WRITE of size 4096` at the end of the 131136-byte region from `ws_raw_read (ws.c:300)`. A full vulnerable FreeSWITCH then ran in a private netns on 127.0.0.1 with `mod_xml_rpc` + `enable-websocket`: a real WebSocket `101` upgrade delivered the frame and GDB caught the chosen `wsh->ssl` value dereferenced in `SSL_shutdown` from `ws_destroy (ws.c:367)` ← `websocket_hook (mod_xml_rpc.c:703)`; witness replay #338 changed only the 8 chosen bytes and saw the new value at the same fault site. Fixed and in-bounds controls survive. Stock heap layout, external reachability and the opt-in config gate stay in the claim; the sentinel is not executable code. Repaired harness driver prints `ALL CHECKS PASS` (rc 0), sources `ws_overflow.c` `75433b5d…` / `run.sh` `637cfa36…`; its 2928 OOB-write count was corrected to 1464. [Status](reports/freeswitch2shell-status.md) |
| **Freeradius2Shell** | **Rung 4 — demonstrated impact in a standalone harness** | A crafted EAP-FAST ticket writes 208 bytes into a 152-byte stack structure and executes a chosen `verify_marker()` address at rc 42; fixed build rejects the same ticket. Live `radiusd` reachability and key-unknown byte control remain UNKNOWN. [Status](reports/freeradius2shell-status.md) |
| **Xrdp2Shell** | **Rung 4 — chosen bytes on real compiled xrdp 0.10.6 code; still in-process** | A 28-byte data-first header plus 20000 client bytes writes `oob_writes=11836` from offset 8192; chosen `ab`/`cd` land at OOB offsets 8228/12028, ASan reports `WRITE of size 20000` 0 bytes after the 8192-byte region, and rung 4 places `de`/`ad` at offsets 8228/12024 across two messages. A second driver links the real ASan `libxrdp.a` / `libcommon.a` and drives `xrdp_channel_process()` → real `drdynvc_process_data_first()` → `out_uint8a`: ASan `WRITE of size 20000` in `memcpy`, 0 bytes after the 8192-byte `trans_create` region; threshold 8164 clean / 8165 OOB, 5/5 identical modulo ASLR. A non-ASan reader plants an adjacent canary chunk and reads `DEADBEEF-CR` / `C0FFEE00-CR` back at offsets 84/484, 8208 bytes past the buffer start (`CHOSEN_BYTES m1=PASS m2=PASS`); no pointer-sized field or control-flow target was controlled and a `free()` variant aborts with `malloc(): corrupted top size`. The 8128-byte cap is a synthetic control, not the real 0.10.6.1 fix; exact-size and benign controls are clean. No completed RDP logon, dynamic-channel open, network PDU trace or live-session allocator layout; loopback COTP reply only; post-auth gate intrinsic. Witness W33 (#548) ESTABLISHED both drivers as claimed, with the disclosed limit of compiling against the existing lab build tree rather than a clean-room rebuild. [Status](reports/xrdp2shell-status.md) |
| **Gst2Shell** | **Rung 3 confirmed; count-controlled rung-4 effect in live and shipping builds, including a real RTSP client across the L8/L16/L24 family** | Caps `encoding-params=(string)1000` drives `channels=1000` into the fixed 64-entry `GstAudioInfo.position` array: `oob_writes=936 first_oob=256 last_oob=3999`, caps length choosing the clobbered offsets, ASan `WRITE of size 4` 0 bytes after a 256-byte region in `vuln_create_default`, fixed control `oob_writes=0`, 5/5 identical. The harness's `NONE(0)` model was wrong — pinned `NONE=-3` writes `fd ff ff ff`, corrupting `order` to `0x00000000fffffffd`; a live ASan instance faults at `order->pos` and the shipping 1.24.2 plugin faults rc 139 at `encoding-params` 86/87/100/1000. A 2026-11-21 pass symbolicated the N=1000 shipping fault to `srcpad->g_class` in a heap-adjacent GstPad and drove SDP text through GStreamer's own parser to the same fault at N=86/1000 (RTP structure name modelled in the harness); the `sdpdemux` file path remained a bounded negative. A loopback RTSP server fed a real `rtspsrc ! rtpL16depay ! fakesink` client with no auth challenge: N=1000 faults rc 139 four times against a clean N=8, corruption in GLib's `block_source`, and stock `uridecodebin` aborts rc 134 with `malloc(): invalid size`. The family runner covers L8/L16/L24 (N=1000: L8/L24 heap abort, L16 SIGSEGV/segtrap; N=8 clean) and memcheck shows three 4-byte stores 0/4/12 bytes past a 1016-byte GObject; `bash lab/gst2shell-src/verify_all.sh` replays all drivers (43 checks). A witness replay that saw 42 PASS / 1 FAIL on its host contradicted the earlier 43/43 assertion; the fault-signature check was broadened to accept the observed allocator aborts and per-leg nonzero rc, with no grade change. Witness W33 (#552) then re-ran the repaired harness from clean HEAD 2a78ee6: 43 PASS / 0 FAIL rc 0, REPAIR ESTABLISHED and the contradiction closed. Chosen bytes, arbitrary pointer control, RCE and public-service SDP reach stay NOT DEMONSTRATED. [Status](reports/gst2shell-status.md) |
| **Babelfish2Shell** | **Rungs 1-3 in an extracted harness; harness-only chosen-byte rung 4** | An unbounded 16-bit prelogin `length=4096` copied into a 1024-byte `StringInfo`: `oob_writes=3072 first_oob=1024 last_oob=4095`; lengths 1050/1150/2100 clobber neither/first/both neighbour stamps; ASan `WRITE of size 4096` 0 bytes after a 1024-byte region in `wire_getbytes`; chosen `de ad be ef ca fe ba be` / `41 42 43 44` land byte-exact at OOB offsets 1100/2000; fixed control `rc=0 oob_writes=0`, clean under ASan, 5/5 identical. No live TDS endpoint, `palloc` layout, real neighbour or control-flow effect observed. [Status](reports/babelfish2shell-status.md) |
| **Bzfs2Shell** | **Rungs 1-3 in an extracted harness; instrumented chosen-value rung 4** | A 1024-byte body writes four sender-chosen bytes past `tcpmsg[1024]` into adjacent `tcplen`: rung 1 `tcplen=-1024` with chosen tail at `tcpmsg+1024`; rung 2 destination 936 bytes before the object, next length 1028; rung 3 ASan `heap-buffer-overflow` `WRITE of size 64` via `recv` → `traced_recv` → `receive_msg`; rung 4 `DEADBEEFCAFEBABE`/`0123456789ABCDEF` read back byte-exact from chosen preceding harness members; fixed controls reject at the first bound, ASan-clean, 5/5 identical. No live bzfs, player socket, real `NetHandler` layout, allocator neighbour or execution. [Status](reports/bzfs2shell-status.md) |
| **Kamailio2Shell** | **Rungs 1-3 in an extracted harness; instrumented chosen-value rung 4** | A `alias=host~<port>~1` Contact parameter makes the tilde distance the `memcpy` length into `bufport[5]`: `len=80`, `oob=75`, `first_oob=5`, chosen function pointer and stamp overwritten byte-exactly; ASan `stack-buffer-overflow` `WRITE of size 80` from `memcpy` ← `parse_alias`, marker executed through the instrumented pointer only; pinned 6.1.5 rejects before the copy. No live Kamailio, real `process_contact()` layout, stack protector, return-address control or SIP message. [Status](reports/kamailio2shell-status.md) |
| **Iperf2Shell** | **Rungs 1-3 on real pinned upstream code; instrumented chosen-byte rung 4** | A 336-byte decoded authtoken crosses a 256-byte RSA heap allocation: ASan `WRITE of size 336` from `BIO_read` ← `decrypt_rsa_message` at `iperf_auth.c.3.21:324`; the plain build aborts at `free(): invalid size` from overwritten next-chunk metadata; chosen `IPERF2SHELL!` and `0x1122334455667788` are supplied in the write buffer only; pinned 3.22 rejects before `BIO_read`. No live server, stock heap layout, useful pointer or execution; the release-note CVE mislabel is preserved. [Status](reports/iperf2shell-status.md) |
| **Uftpd2Shell** | **Rungs 1-3 on verbatim pinned upstream code; instrumented chosen-byte rung 4** | A 4095-byte path with a 128-byte configured home shifts `dir[PATH_MAX]` right and writes 128 bytes past it: the plain build aborts with `*** stack smashing detected ***`, ASan reports `stack-buffer-overflow` `WRITE of size 4096` at pinned `common.c.v2.15:61`, and chosen `UFTPD2SHELL!` / `0x1122334455667788` are written by the upstream `memmove` only. Pinned 2.16 rejects at the guard with `returned=null`. No live uftpd, stock frame layout, useful pointer or execution; `PR:L`, no-chroot, and the 9-byte default-home reach are UNKNOWN. [Status](reports/uftpd2shell-status.md) |
| **Accelppp2Shell** | **Rungs 1-3 on verbatim pinned upstream code; instrumented chosen-byte rung 4** | 66 AVP chunks of 64 bytes put `pos=4254` into a 4160-byte `t->buf`: ASan `heap-buffer-overflow` `WRITE of size 64` at pinned `log_tcp.c.1.14.0:63`; chosen `0x1122334455667788` is read back byte-exact at offset 4 in the adjacent harness heap object; pinned 1.15.0 clamps to 4160 with a clean neighbour. No live daemon, real L2TP AVP path, verbose-logging configuration or useful-pointer control. [Status](reports/accelppp2shell-status.md) |
| **Indiserver2Shell** | **Rungs 1-3 on verbatim pinned upstream code; instrumented chosen-byte rung 4** | A 1206-byte mismatched-tag packet formats 1237 bytes into `err[1024]`: the first byte past the buffer changes, ASan reports `stack-buffer-overflow` `WRITE of size 1237` at pinned `lilxml.cpp:1281`, and token-safe `INDI2SHELL` reads back byte-exact at requested adjacent-stack offsets 0 and 64. Fixed `96bbd7f` bounds the format with `snprintf` and the neighbour is clean. No live daemon, real TCP/7624 path, stock stack layout, canary/NX measurement, useful-pointer control or execution; advisory claims availability only. [Status](reports/indiserver2shell-status.md) |
| **Shairport2Shell** | **Rungs 1-3 on verbatim pinned upstream code; instrumented chosen-byte rung 4** | A 4096-byte unrecognised-method RTSP body writes 8193 bytes into `obf[4096]`: the first byte past the buffer changes, ASan reports `stack-buffer-overflow` `WRITE of size 3` at pinned `rtsp.c:4215`, and token-safe `INDI2SHELL` reads back byte-exact at requested harness-stack offsets 0 and 64. Fixed `c1c41c4` declares `obf[2*4096+1]` and the neighbour is clean. No live daemon, socket, AirPlay-2 auth-bypass observation, stock frame layout, canary/NX measurement, useful-pointer control or execution; advisory claims availability only. [Status](reports/shairport2shell-status.md) |
| **Asterisk2Shell** | **Rungs 1-3 on verbatim pinned upstream code; instrumented chosen-byte rung 4** | A 2432-byte `%s` argument writes 2433 bytes into `logMessage[2048]` at pinned `ootrace.c:50`: a harness caller 2272 bytes away changes first, ASan reports `stack-buffer-overflow` `WRITE of size 2433`, and token-safe `AST2SHELL` reads back byte-exact at requested harness-stack offsets 0 and 64. Fix `2d7b8c8` uses `ast_vasprintf` and the neighbour is clean. No live daemon, H.323 socket, packet-path replay, stock stack layout, canary/NX measurement, useful-pointer control or execution; advisory claims availability only. [Status](reports/asterisk2shell-status.md) |
| **Netatalk2Shell** | **Rungs 1-3 on verbatim pinned upstream code; instrumented chosen-byte rung 4** | A 255-byte `d_name` performs `strcpy(path + 1024, d_name)`, writing 256 bytes into `path[1025]`: the first saved-return-slot byte changes, ASan reports `stack-buffer-overflow` `WRITE of size 256` in `deletedir` at pinned `directory.c:181`, and token `NET2SHEL` reads back byte-exact at write offsets 0/64 and in the return slot at offset 56. Fix `33dbda7` uses `sizeof(path)` and the neighbour is clean. No live afpd, socket, AFP session, mount, useful-pointer control or execution; authenticated RCE remains a claim. [Status](reports/netatalk2shell-status.md) |
| **Iondtn2Shell** | **Rungs 1-3 on verbatim pinned upstream code; instrumented chosen-byte rung 4** | 18 rendered AMP values of 80 bytes append 1458 bytes into a 1024-byte `STAKE(1024)` heap region at pinned `nm/mgr/nm_mgr_print.c:557`: the first byte past the allocation changes, ASan reports `heap-buffer-overflow` `WRITE of size 81` in `ui_str_from_ac` at pinned line 557, and token `ION2SHL!` reads back byte-exact at chosen write offsets 1024/1088/1152/1280/1408. Fix `4b158b6` uses `istrlen()`/`istrcat()` capacity checks and returns NULL; the neighbour is clean. No live `nm_mgr`, socket, UDP CLA/AMP payload, UI, useful pointer or execution; both advisories claim availability only, and the GHSA "No known CVE" vs VulnCheck CVE assignment conflict is preserved. [Status](reports/iondtn2shell-status.md) |

Work is ongoing: PHP's path from constrained placement to pointer control
(including the reopened session-splice lane, the session-filename UAF, the
new 8.5 stale-argument read and 129182's root-caused clean replay; the
129538 lane's HTTP-to-FastCGI mapping is now observed through a real nginx
but still reaches only an offset-controlled OOB read),
Node's path from its two independent AltSvc terminator triggers to control,
Mosquitto's wire-to-code-execution gap, Dragonfly's stock rung-3/4
gap, Postgres's wrong `PR:L` pointer identity, Brotli's pointer fields beyond
index 27, FreeRADIUS's live `radiusd` replay, FalkorDB's four-byte-repeating
mask, Freeswitch's stock heap layout and any executable sentinel, Xrdp's
socket-level PDU trace and auth gate (a wire-formatted PDU parsed in-process
now reaches the sink), GStreamer's RCE and chosen-byte control beyond the
demonstrated loopback RTSP caps fault across the L8/L16/L24 depay family, and
Freerdp's real audio source, an FFmpeg-enabled build, a stock wrap-capable
server format and a chosen heap object or pointer dereference are still open
(pointer-bearing stock heap data in the write path is now observed). Apache's
Stage C route was closed as unreachable in this build on this host and is
preserved as a negative. Each open question is recorded as an UNKNOWN in its
status file rather than papered over. Failed hypotheses and negative results
stay in the reports.
Bzfs2Shell's live `bzfs` reachability, real `NetHandler` object layout and
witness replay are open; its status file records the harness-only rung-4
boundary without claiming a live result.

Kamailio2Shell's loaded `ims_registrar_pcscf` module gate, real
`process_contact()` frame layout, stack protector and return-address control
are open; Iperf2Shell's live RSA-auth server, stock heap layout and
useful-pointer control are open. Both status files record the instrumented
rung-4 boundary without claiming a live result.

## How the plant works

Each target is its own mind with its own window: **ruby2shell**,
**php2shell**, **node2shell**, **apache2shell**, **mosquitto2shell**,
**dragonfly2shell**, **postgres2shell**, **brotli2shell**,
**freeradius2shell**, **falkordb2shell**, **freeswitch2shell**,
**freerdp2shell**, **xrdp2shell**, **gst2shell**, **babelfish2shell**,
**bzfs2shell**, **kamailio2shell**, **iperf2shell**, **uftpd2shell**,
**accelppp2shell**, **indiserver2shell**, **shairport2shell**,
**asterisk2shell**, **netatalk2shell** and **iondtn2shell** pursue their lane end-to-end — build, harness, debugger,
report. Four
further minds cut
across them:

- **frontier** hunts public advisories for new X2Shell-class candidates and
  hands a reproducible harness and brief to the operator for admission.
- **docs** keeps this README and `docs/` true to the shipped code. It is
  woken by the `repo-change` git-commit signal and owns the
  [reproducibility index](docs/reproducibility.md); it is the net under
  authors, not a routine review gate.
- **witness** re-runs every claim from a clean checkout; the author's
  report is never acceptance.
- **operator** is the owner's delegate. It approves scoped work from a
  recorded list of standing permissions, admits new X2Shell-class targets
  it finds itself or receives from frontier, and creates a new mind, window
  and lab lane for each admission. Its first find was Node2Shell.

Freerdp2Shell was admitted at 19:32Z: the charter, docs entry, window and
seed wall are live; wake trigger units and the presentation.json entry are
owed from the person's full-flag sync. Its grade is recorded in the status
file, not treated as an established result.

Xrdp2Shell was admitted ~20:27Z: the charter, docs entry, window (19, inner
socket), seed wall and status file are live; wake trigger units and the
presentation.json entry are owed from the person's full-flag sync. Its
grade is recorded in the status file, not treated as an established result.

Gst2Shell was admitted ~20:52Z: the charter, docs entry, window (20, inner
socket), seed wall and status file are live; wake trigger units and the
presentation.json entry are owed from the person's full-flag sync. Its
grade is recorded in the status file, not treated as an established result.

Babelfish2Shell was admitted ~22:2xZ: the charter, docs entry, window (21,
inner socket), seed wall and status file are live from frontier's handoff;
wake trigger units and the presentation.json entry are owed from the
person's full-flag sync. Its harness-only grade is recorded in the status
file, not treated as an established live result.
Bzfs2Shell was admitted ~00:5xZ: the charter, docs entry, window (22, inner
socket), seed wall and status file are live from frontier's handoff; wake
trigger units and the presentation.json entry are owed from the person's
full-flag sync. It is a C++ game server admitted as an X2Shell-class
extension by recorded judgment, and its harness-only grade is recorded in
the status file, not treated as a live result. Frontier also reported the
earlier mapserver2shell window absent from the restarted inner tmux server;
the restorer rebuilds it, and no duplicate lane was opened.

Kamailio2Shell was admitted ~02:2xZ: the charter, docs entry, window (24,
inner socket), seed wall and status file are live from frontier's handoff;
wake trigger units and the presentation.json entry are owed from the
person's full-flag sync. The module must be configured; rung 4 is
instrumented only.

Iperf2Shell was admitted ~02:2xZ: the charter, docs entry, window (25, inner
socket), seed wall and status file are live from frontier's handoff; wake
trigger units and the presentation.json entry are owed from the person's
full-flag sync. RSA auth must be enabled and the rung-4 bytes are supplied
in the harness write buffer, not a stock process.

The rungs — **suspected → reproducible crash → confirmed memory
corruption → demonstrated impact** — are a depth investigation of how far
rung 4 can be pushed on each build, not boxes to touch. Every lane records
the precise boundary it reached; negative results, harness-only grades and
UNKNOWNs map that boundary. Every claim cites source lines or observed
bytes. All triggering, listeners, debuggers and test consumers stay on this
machine, bound to loopback or local containers; no external systems or
public-infrastructure scans.

An idle wake is not work. A target mind with no owed experiment must push
the same target deeper toward rung 4 with a bounded, falsifiable experiment
(new consumer, wire-pure replay, stock allocator, live process, stronger
marker, or a counterexample). If rung 4 is closed on the tested build, it
may mine an adjacent vulnerability in the same target/runtime — same source
tree, subsystem, descendant CVE or next bug in the same fix series — under
the same evidence ladder. Distinct products or runtimes go to
frontier/operator for a new mind. A timestamp-only advisory check is a
watch, not idle work: wait for a signal or dated trigger instead of
self-scheduling it.

## Follow along

- Live dashboards (tmux):

  ```sh
  tmux -S /tmp/tmux-1000/mishe-tauftauf2shell/tmux-1000/default attach -t mishe-tauftauf2shell-current
  ```

  The `ruby2shell`, `php2shell`, `node2shell`, `apache2shell`,
  `mosquitto2shell`, `dragonfly2shell`, `postgres2shell`, `brotli2shell`,
  `freeradius2shell`, `falkordb2shell`, `freeswitch2shell`, `freerdp2shell`,
  `xrdp2shell`, `gst2shell`, `babelfish2shell`, `bzfs2shell`,
  `kamailio2shell`, `iperf2shell`, `uftpd2shell`, `accelppp2shell`,
  `indiserver2shell`, `shairport2shell`, `asterisk2shell`, `netatalk2shell` and
  `iondtn2shell` windows show each mind's wall and wake log; `frontier`, `docs`, `witness` and `operator`
  show the cross-cutting minds' walls. `chat`, `git` and `wakes` show the
  shared tape. All minds run on `opencode-go/hy4-flash-free`.

- [docs/task.md](docs/task.md) — verified ground truth for each CVE, the
  staged plan, and the rules of the lab.
- [docs/reproducibility.md](docs/reproducibility.md) — pins, commands,
  expected outputs and evidence policy for independent verification.
- [docs/runtime-pin.md](docs/runtime-pin.md) — the pinned runtime and
  every local change made to it.
- `reports/` — the investigation reports and live status files.

## License

[CC0 1.0](LICENSE) — everything here is public domain.
