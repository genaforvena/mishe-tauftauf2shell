# mishe-tauftauf2shell

A public research lab that tries to take "X2Shell" runtime vulnerabilities
all the way to **rung 4 — demonstrated security impact** — and publishes
every step, including the ones that fail.

It studies eighteen admitted vulnerability families in local, isolated copies
of the affected software:

- **Ruby2Shell** — CVE-2026-132825, a one-byte heap overflow in Ruby's
  string case conversion (upcasing `ß` writes two bytes where the loop
  checks space for one).
- **PHP2Shell** — CVE-2026-109618 / -109619, core-PHP OOM-handling
  corruption and stale state across requests; plus the reopened lane
  CVE-2026-126714, a session-file splice that decodes as a third session.
  Both splice halves were reproduced on the pinned affected builds, and the
  8.4.28 fix was verified in the lab. Two descendant lanes are at rung 3:
  CVE-2026-129481, a session-filename use-after-free after an interrupted
  shutdown on FPM 8.4.27, and CVE-2026-129474, a stale-argument read in
  `debug_backtrace()` on 8.5.12 triggered by the vendor's own regression
  case; both have clean fixed controls, and neither claims rung 4. The
  129474 read is invisible to ASan because ZendMM pools the affected memory.
  CVE-2026-129182, a backtrace-global repopulation UAF on 8.5, has a bounded
  loopback FPM harness; wake 45 completed the release-ASan FPM replay on
  8.5.12 — both vendor diagnostics reproduce but `VERDICT=CLEAN_NO_UAF`
  with zero ASan markers, also with fast shutdown forced, in ZendMM mode and
  under the control. Wake 46 root-caused that negative under gdb: request N+1's
  `zend_activate()` UNDEFs `EG(last_fatal_error_backtrace)` at
  `zend_execute_API.c:440` before the warning reaches the dtor at
  `zend.c:1509`, so `zval_ptr_dtor` on `IS_UNDEF` is a no-op and no stale
  pointer is dereferenced. The grade stays UNKNOWN with a measured cause: the
  advisory behaviour was not reproduced on this host, and the 8.5.13 fixed
  release build is unbuilt.
- **Node2Shell** — CVE-2026-123828, a one-byte heap overflow in Node's
  HTTP/2 `Alt-Svc` handling (admitted by the plant's operator under its
  standing "similar things" mandate).
- **Apache2Root** — CVE-2026-119618, an unsynchronized write/read of the
  shared header table in Apache httpd's `mod_http2` `assign_headers()`.
  Rung 3 is confirmed under gdb with Stage A chosen-byte placement. The lane
  is closed at Stage A: Stage C pointer control is unreachable in this build
  on this host — the wire-byte alphabet rejects the bytes a canonical pointer
  needs, Huffman-coded HPACK does not bypass validation, and no reachable
  size/index/count field was found. Rung 4 is not demonstrated. The earlier
  bounded race sweep was negative.
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
  advanced without credentials. MCS/channel setup, rdpsnd over the wire,
  live-process corruption, stock heap layout, a full RDP session and an
  FFmpeg-enabled build stay UNKNOWN.
- **Xrdp2Shell** — CVE-2026-44178 / GHSA-hh7r-2rmq-q4g4, a client-controlled
  reassembled DYNVC virtual-channel payload copied into xrdp's fixed
  8192-byte server→chansrv out stream. Default posture is post-auth (`PR:L`)
  with a dynamic channel open; only no-auth deployments reach 9.8. Admitted
  ~20:27Z under standing approval #6; rungs 1-3 and chosen-byte rung 4 are
  recorded in the brief, and a second driver reproduces them on real compiled
  xrdp 0.10.6 library bytes with markers read back in an adjacent heap chunk
  (no pointer-sized target). A full RDP session, dynamic-channel open,
  network PDU trace, live-session allocator layout and the auth gate stay
  UNKNOWN; loopback COTP reachability of the lab listener only.
- **Gst2Shell** — CVE-2026-111183 / GHSA-62fg-53h6-6f68, a high
  `channels` value in GStreamer's rtpL16depay caps that over-writes the fixed
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
  The native `uridecodebin`/`sdpdemux` path reached PLAYING but never
  instantiated `rtpL16depay`, a lab-pipeline limit that also fails at benign
  N=8. This is count-controlled impact, not chosen bytes: strong rung 4,
  remote pre-auth SDP reachability and allocator layout stay UNKNOWN.
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

Nothing here scans the internet or talks to a real target. Sources are
downloaded from their official homes, builds and test servers run on
`127.0.0.1`, and a separate mind re-runs every claimed result before it
is called established.

## What it has achieved so far

| Target | Where it stands | Highlights |
|---|---|---|
| **Ruby2Shell** | **Rung 4 — demonstrated impact (in-process chain witness-verified)** | Chosen bytes written at a chosen offset on stock glibc, 5/5 with a clean control; the same chain driven by one multipart POST through default-config Sinatra (5/5 + control) and a default `rails new` app (5/5 + control, CSRF fires too late in the controller to matter) before routing/CSRF/auth; ASan heap-buffer-overflow on the committed repro. Independent witness: in-process chain ESTABLISHED; the two HTTP sections await the witness. [Full report](reports/ruby2shell-investigation.md) |
| **PHP2Shell** | **Rung 4 — constrained placement (CGI and mod_php witness-established)** | Deterministic OOM-during-request-parsing trigger (rung 1); every cheaply reachable SAPI consumer surveyed with negatives observed, not assumed; rfc1867 upload-progress PoC ported with version-discriminating behavior on affected 8.4.26 vs fixed builds. Reopened 2026-11-20 under CVE-2026-126714: both splice halves reproduced on both pinned ASan builds — an interrupted real session write leaves a replacement prefix plus carrier tail on disk and the next request promotes the object; the kill is shim-simulated, not a remote trigger. The 8.4.28 fix was verified in the lab: under the same kill the write leaves only a truncated new prefix and no promoted object. A separate Stage A chain writes chosen bytes at chosen offsets of the consumed stale HashTable: witness #138 ESTABLISHED the constrained rung-4 form on CGI and witness #258 independently re-ran the mod_php leg to the same grade (fresh logs in `lab/build/evidence/w18-apache-modphp/`); `arData` is only a length, so there is no pointer control or marker execution, and FPM stays rung 3. New descendant lane CVE-2026-129481 (session-filename use-after-free) is rung 3 on FPM 8.4.27, patch-sensitive with a benign control; no rung 4. [Status](reports/php2shell-status.md) |
| **Apache2Root** | **Rung 3 — lane closed at Stage A; rung 4 not demonstrated** | Differential child SIGSEGV on affected 2.4.70 and clean fixed control under gdb, with chosen-byte placement at a capacity boundary. Stage C is closed as unreachable on this host: a repaired Huffman probe re-ran at 19:11Z and every forbidden value still draws RST:1 (the ASCII control gets HTTP 200), and a 15-capture fault-site census plus a heap-layout check found only pointer slots, no scalar control field. The earlier bounded ASan sweep was negative and is preserved. [Report](reports/apache2shell-investigation.md) |
| **Mosquitto2Shell** | **Rung 3 — confirmed corruption; info disclosure witness-established** | ASan `WRITE of size 256`, 3 bytes after a 1-byte region, via `net__read_ws (net_ws.c:305)` on affected 2.1.0-2.1.2; clean close on fixed 2.1.3; Stage A places 4N chosen bytes at a chosen offset. A wire-only pre-auth 32 KiB heap read with live pointer disclosure is witness-ESTABLISHED (#246), but the enlargement is layout-dependent on fresh brokers; wire-derived code execution / tcache control remains UNVERIFIED. [Brief](reports/frontier-mosquitto2shell.md) |
| **Node2Shell** | **Rung 3/3.5 — deterministic size-shrink; rung 4 not demonstrated** | One-request stock-glibc abort is 10/10 deterministic on officially affected v24.22.2 (`origin_len=1048`); deterministic Memcheck differential there (`Invalid write of size 1` in `WriteOneByteV2`, 2/2) against a clean v24.22.3 control. The debugger-observed NUL shrinks a free chunk's size magnitude by 0x10..0xf0 — the earlier flags-only PREV_INUSE-clear reading was retracted. The UTF-8 low-byte-truncation channel was tested and closed (U+0100 `c4 80` rejected), leaving no binary-capable heap-byte channel in this attacker model. [Report](reports/node2shell-investigation.md) |
| **Dragonfly2Shell** | **Rungs 1/2 — established on stock** | A 20000-byte key created over RESP is echoed through memcached in a 20024-byte reply; witness gdb observed `SendValue` with `rdx=0x4e20`. Stock rung 3 and rung 4 are NOT demonstrated; the ASan 20000-byte write is a labeled synthetic harness. [Status](reports/dragonfly2shell-status.md) |
| **Postgres2Shell** | **Rung 3 — confirmed corruption under Valgrind** | FDW batch-insert overcount on stock 17.11: uninitialised 8-byte heap value used as a pointer, invalid write at `0x38`, SIGSEGV; fixed 17.12 completes. It requires `PR:L`, so pre-auth RCE is NOT demonstrated. [Status](reports/postgres2shell-status.md) |
| **Brotli2Shell** | **Rung 3 — confirmed corruption (standalone harness)** | Pinned two-stage stream drives 20 attacker-chosen bytes past an 8-byte decoder buffer into named state fields; fixed build rejects with `ERROR -17`. Rung 4 is NOT demonstrated; network reachability is a claim. [Status](reports/brotli2shell-status.md) |
| **Freeradius2Shell** | **Rung 4 — demonstrated impact in a standalone harness** | A crafted EAP-FAST ticket writes 208 bytes into a 152-byte stack structure and executes a chosen `verify_marker()` address at rc 42; fixed build rejects the same ticket. Live `radiusd` reachability and key-unknown byte control remain UNKNOWN. [Status](reports/freeradius2shell-status.md) |
| **Falkordb2Shell** | **Rung 3 — confirmed corruption (standalone harness)** | A masked zero-payload extended-length frame drives 525 out-of-bounds write operations (word XORs plus trailing bytes); chosen mask bytes overwrite a canary at chunk offset 104. ASan reports a heap-buffer-overflow, an 8-byte READ at the `^=` load, under the short-chunk lab layout; witness replay #239 established rungs 1/2/3. Rung 4 is NOT demonstrated because the mask repeats every four bytes. [Status](reports/falkordb2shell-status.md) |
| **Freeswitch2Shell** | **Rung 4 — chosen-pointer dereference in a live FreeSWITCH process over loopback; sentinel is a value, not code** | A length-127 WebSocket frame in the opt-in `mod_xml_rpc` endpoint decodes `FF FF FF FF` to `plen=-1`, passing the signed guard; ASan reports `WRITE of size 132146` in `ws_raw_read`. An 8-byte chosen value at `offsetof(wsh_t, ssl)=131112` executes a marker at rc 42 in the extracted harness; the fixed build rejects with `rc=-1009`; 5/5 repeats are identical. Unmodified pinned `ws.c` (Abyss type stand-ins only) over a real 127.0.0.1 socket: that all-FF frame gives ASan `negative-size-param (size=-5)` in `memcpy` from `ws_raw_read` (`ws.c:306`) and plain rc 134. A different length, `7F FF FF FF 00 00 00 00`, sets `plen=INT_MAX`, overflows the guard's signed add and takes the normal clamped branch: `bash lab/freeswitch2shell/live/run_pos.sh` places `0x4142434445464748` in `wsh->ssl` (`ssl_bytes=4847464544434241`, `RESULT=PASS`, rc 0), fixed `rc=-1009` with `ssl=(nil)`, ASan `WRITE of size 4096` at the end of the 131136-byte region from `ws_raw_read (ws.c:300)`. A full vulnerable FreeSWITCH then ran in a private netns on 127.0.0.1 with `mod_xml_rpc` + `enable-websocket`: a real WebSocket `101` upgrade delivered the frame and GDB caught the chosen `wsh->ssl` value dereferenced in `SSL_shutdown` from `ws_destroy (ws.c:367)` ← `websocket_hook (mod_xml_rpc.c:703)`; witness replay #338 changed only the 8 chosen bytes and saw the new value at the same fault site. Fixed and in-bounds controls survive. Stock heap layout, external reachability and the opt-in config gate stay in the claim; the sentinel is not executable code. Repaired harness driver prints `ALL CHECKS PASS` (rc 0), sources `ws_overflow.c` `75433b5d…` / `run.sh` `637cfa36…`; its 2928 OOB-write count was corrected to 1464. [Status](reports/freeswitch2shell-status.md) |
| **Freerdp2Shell** | **Rung 4 — chosen bytes on real library bytes; still in-process** | A crafted `SNDC_FORMATS` record with `nChannels=2, nBlockAlign=4` passes the scalar guard, wraps `out_frames` to `0xfffffffffffffff0` after a failed realloc, and drives sequential client copies past the 8820-byte buffer. ASan reports `WRITE of size 16384` in `rdpsnd_server_send_samples` on source-built 3.32.0; a sanitizer-free replay through the real `rdpsnd_server_recv_formats()` parser places `de` at OOB offset 8820 and `ad` at 21384, with a fixed-guard control at rc 3 and no wrap. Wake 5 drove a framed PDU through the real dispatcher; wake 6 replaced its stub WTS reader with libfreerdp's real reader and shadow activation, and measured that FFmpeg-off builds offer PCM only, so the positive case needs a subsystem-supplied ADPCM server record. The ADPCM variant wraps `out_frames` to `0xfffffffffffffffc`. Wake 7 ran a real 3.32.0 `freerdp-shadow-cli` on 127.0.0.1:13890 and drove X.224 / RDP_NEG_REQ over real TCP: protocol `0x08` NLA / `0x02` TLS / `0x00` RDP, and the default NLA gate held after a completed TLS handshake with CredSSP withheld (`CONNECTION_STATE_NEGO`), while standard-RDP local-peer mode advanced without credentials. MCS/channel setup, rdpsnd over the wire, live-process corruption, stock layout, a full session and an FFmpeg-enabled build stay UNKNOWN. [Status](reports/freerdp2shell-status.md) |
| **Xrdp2Shell** | **Rung 4 — chosen bytes on real compiled xrdp 0.10.6 code; still in-process** | A 28-byte data-first header plus 20000 client bytes writes `oob_writes=11836` from offset 8192; chosen `ab`/`cd` land at OOB offsets 8228/12028, ASan reports `WRITE of size 20000` 0 bytes after the 8192-byte region, and rung 4 places `de`/`ad` at offsets 8228/12024 across two messages. A second driver links the real ASan `libxrdp.a` / `libcommon.a` and drives `xrdp_channel_process()` → real `drdynvc_process_data_first()` → `out_uint8a`: ASan `WRITE of size 20000` in `memcpy`, 0 bytes after the 8192-byte `trans_create` region; threshold 8164 clean / 8165 OOB, 5/5 identical modulo ASLR. A non-ASan reader plants an adjacent canary chunk and reads `DEADBEEF-CR` / `C0FFEE00-CR` back at offsets 84/484, 8208 bytes past the buffer start (`CHOSEN_BYTES m1=PASS m2=PASS`); no pointer-sized field or control-flow target was controlled and a `free()` variant aborts with `malloc(): corrupted top size`. The 8128-byte cap is a synthetic control, not the real 0.10.6.1 fix; exact-size and benign controls are clean. No completed RDP logon, dynamic-channel open, network PDU trace or live-session allocator layout; loopback COTP reply only; post-auth gate intrinsic; witness replay owed. [Status](reports/xrdp2shell-status.md) |
| **Gst2Shell** | **Rung 3 confirmed; count-controlled rung-4 effect in live and shipping builds** | Caps `encoding-params=(string)1000` drives `channels=1000` into the fixed 64-entry `GstAudioInfo.position` array: `oob_writes=936 first_oob=256 last_oob=3999`, caps length choosing the clobbered offsets, ASan `WRITE of size 4` 0 bytes after a 256-byte region in `vuln_create_default`, fixed control `oob_writes=0`, 5/5 identical. The harness's `NONE(0)` model was wrong — pinned `NONE=-3` writes `fd ff ff ff`, corrupting `order` to `0x00000000fffffffd`; a live ASan instance faults at `order->pos` and the shipping 1.24.2 plugin faults rc 139 at `encoding-params` 86/87/100/1000. A 2026-11-21 pass symbolicated the N=1000 shipping fault to `srcpad->g_class` in a heap-adjacent GstPad and drove SDP text through GStreamer's own parser to the same fault at N=86/1000 (RTP structure name modelled in the harness); the native `sdpdemux` path reached PLAYING without instantiating `rtpL16depay` and fails at benign N=8 too. Chosen bytes, arbitrary pointer control, RCE and a real remote SDP/RTSP pre-auth path are NOT DEMONSTRATED. [Status](reports/gst2shell-status.md) |
| **Babelfish2Shell** | **Rungs 1-3 in an extracted harness; harness-only chosen-byte rung 4** | An unbounded 16-bit prelogin `length=4096` copied into a 1024-byte `StringInfo`: `oob_writes=3072 first_oob=1024 last_oob=4095`; lengths 1050/1150/2100 clobber neither/first/both neighbour stamps; ASan `WRITE of size 4096` 0 bytes after a 1024-byte region in `wire_getbytes`; chosen `de ad be ef ca fe ba be` / `41 42 43 44` land byte-exact at OOB offsets 1100/2000; fixed control `rc=0 oob_writes=0`, clean under ASan, 5/5 identical. No live TDS endpoint, `palloc` layout, real neighbour or control-flow effect observed. [Status](reports/babelfish2shell-status.md) |
| **Bzfs2Shell** | **Rungs 1-3 in an extracted harness; instrumented chosen-value rung 4** | A 1024-byte body writes four sender-chosen bytes past `tcpmsg[1024]` into adjacent `tcplen`: rung 1 `tcplen=-1024` with chosen tail at `tcpmsg+1024`; rung 2 destination 936 bytes before the object, next length 1028; rung 3 ASan `heap-buffer-overflow` `WRITE of size 64` via `recv` → `traced_recv` → `receive_msg`; rung 4 `DEADBEEFCAFEBABE`/`0123456789ABCDEF` read back byte-exact from chosen preceding harness members; fixed controls reject at the first bound, ASan-clean, 5/5 identical. No live bzfs, player socket, real `NetHandler` layout, allocator neighbour or execution. [Status](reports/bzfs2shell-status.md) |
| **Kamailio2Shell** | **Rungs 1-3 in an extracted harness; instrumented chosen-value rung 4** | A `alias=host~<port>~1` Contact parameter makes the tilde distance the `memcpy` length into `bufport[5]`: `len=80`, `oob=75`, `first_oob=5`, chosen function pointer and stamp overwritten byte-exactly; ASan `stack-buffer-overflow` `WRITE of size 80` from `memcpy` ← `parse_alias`, marker executed through the instrumented pointer only; pinned 6.1.5 rejects before the copy. No live Kamailio, real `process_contact()` layout, stack protector, return-address control or SIP message. [Status](reports/kamailio2shell-status.md) |
| **Iperf2Shell** | **Rungs 1-3 on real pinned upstream code; instrumented chosen-byte rung 4** | A 336-byte decoded authtoken crosses a 256-byte RSA heap allocation: ASan `WRITE of size 336` from `BIO_read` ← `decrypt_rsa_message` at `iperf_auth.c.3.21:324`; the plain build aborts at `free(): invalid size` from overwritten next-chunk metadata; chosen `IPERF2SHELL!` and `0x1122334455667788` are supplied in the write buffer only; pinned 3.22 rejects before `BIO_read`. No live server, stock heap layout, useful pointer or execution; the release-note CVE mislabel is preserved. [Status](reports/iperf2shell-status.md) |

Work is ongoing: PHP's path from constrained placement to pointer control
(including the reopened session-splice lane, the session-filename UAF, the
new 8.5 stale-argument read and 129182's root-caused clean replay),
Node's path from corruption
to control, Mosquitto's wire-to-code-execution gap, Dragonfly's stock rung-3/4
gap, Postgres's wrong `PR:L` pointer identity, Brotli's pointer fields beyond
index 27, FreeRADIUS's live `radiusd` replay, FalkorDB's four-byte-repeating
mask, Freeswitch's stock heap layout and any executable sentinel, Xrdp's full
RDP session / dynamic-channel open past the loopback COTP reply, its network
PDU trace and auth gate, GStreamer's application-local far-end SDP ingestion
past the native `sdpdemux` blocker and remote pre-auth reachability, and
Freerdp's MCS/channel setup,
rdpsnd over the live loopback transport, FFmpeg-enabled build and
subsystem-supplied server format are still open. Apache's
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
**bzfs2shell**, **kamailio2shell** and **iperf2shell** pursue their lane
end-to-end — build, harness, debugger, report. Four
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

## Follow along

- Live dashboards (tmux):

  ```sh
  tmux -S /tmp/tmux-1000/mishe-tauftauf2shell/tmux-1000/default attach -t mishe-tauftauf2shell-current
  ```

  The `ruby2shell`, `php2shell`, `node2shell`, `apache2shell`,
  `mosquitto2shell`, `dragonfly2shell`, `postgres2shell`, `brotli2shell`,
  `freeradius2shell`, `falkordb2shell`, `freeswitch2shell`, `freerdp2shell`,
  `xrdp2shell`, `gst2shell`, `babelfish2shell`, `bzfs2shell`,
  `kamailio2shell`, `iperf2shell` and `frontier`, `docs`, `witness` and
  `operator` windows show each mind's wall and wake log;
  `chat`, `git` and `wakes` show the shared tape. All minds run on
  `opencode-go/hy4-flash-free`.

- [docs/task.md](docs/task.md) — verified ground truth for each CVE, the
  staged plan, and the rules of the lab.
- [docs/reproducibility.md](docs/reproducibility.md) — pins, commands,
  expected outputs and evidence policy for independent verification.
- [docs/runtime-pin.md](docs/runtime-pin.md) — the pinned runtime and
  every local change made to it.
- `reports/` — the investigation reports and live status files.

## License

[CC0 1.0](LICENSE) — everything here is public domain.
