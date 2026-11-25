# mishe-tauftauf2shell

A lab that pushes "X2Shell" memory-safety bugs in language runtimes and
network servers to **rung 4 — demonstrated security impact** and, where a
measured path exists, **rung 5 — working remote command execution** — and
publishes every step, including the ones that fail. Every build, listener and
debugger stays local on `127.0.0.1`; nothing scans or contacts an external
target. Everything here is CC0.

## Evidence key

The rungs are depth of proof, not boxes to tick:

- **R1** suspected vulnerability — source or advisory reasoning, no trigger.
- **R2** reproducible crash — a deterministic input faults the lab process.
- **R3** confirmed memory corruption — ASan/UBSan/Valgrind/gdb observes bad
  memory state, not just a fault.
- **R4** demonstrated impact — chosen bytes, pointer control or a benign
  marker exercised in the lab build.
- **R5** working remote command execution — attacker-controlled wire or
  request input makes a live target run a lab-chosen benign command, with
  vulnerable, fixed and safe-input controls and an independent witness replay.
  Additive and per-build, never a relabel of a pointer fault or an in-process
  marker; [docs/rce.md](docs/rce.md) is the acceptance contract. Twelve R5
  cells are witness-ESTABLISHED, each only under the build, oracle and
  configuration scope named in its row; author-only command claims stay
  UNKNOWN.

Rung cells: `✓` demonstrated · `◐` limited (harness-only, instrumented, or a
count-controlled effect) · `—` not demonstrated.

Top-rung tiers: **LIVE** = real process on loopback, with the request/wire path
reached; **CODE** = verbatim pinned upstream or library bytes, in-process;
**HARNESS** = extracted or synthetic harness only, no real consumer. A
**Witness W##** or **tape #N** marker means an independent replay was accepted
at the exact scope named in that row's boundary; no marker means no
independent replay at that scope. Author reports are never acceptance.

## What it has achieved so far

| Target | R1 | R2 | R3 | R4 | R5 | Evidence / boundary |
|---|---|---|---|---|---|---|
| **Ruby2Shell** | ✓ | ✓ | ✓ | ✓ | ✓ | **LIVE — rung 5 witness-ESTABLISHED at the labeled host/harness conditions.** One multipart POST drives Stage C poisoning into a forged CRuby `T_DATA` finalizer (`dfree=system`, `data=` request command), producing a target-created benign marker; independent clean-archive replay of `8b9d8f9` reproduced two varied-command attacks and safe/fixed controls. Requires custom grooming/GC middleware plus mtrace/ObjectSpace/maps oracles; ASLR stays on, post-response abort remains possible, and stock-app oracle-free RCE/persistence are not claimed. 2026-11-24 stock Rails follow-up: N=524 gives a traced `0x200→0x250` split, but no `0x3f0` consumer, disclosure, command or persistence; 3/3 clean attacks abort, safe/fixed controls survive. 2026-11-25 wire-leak push: the dev 404 params reflection on the unmodified app leaks the request-thread glibc arena region base (three near-constant region offsets, 11/11 victim-correlated — tcache key wire-known) and Ruby GC-page pointers (live maps-confirmed, replaces `ObjectSpace.dump`), 20 historical responses plus one live classified instance; structurally NO libc/code pointer (worker-arena bins are in-region), zero attacker-chosen upcase bytes in 432 responses, second attack on a survivor aborts 3/3 — first missing oracle measured, full stock rung-5 still NOT ACHIEVED. R4 witnesses: #51, #65, #89. [Report](reports/ruby2shell-investigation.md) |
| **PHP2Shell** | ✓ | ✓ | ✓ | ✓ | ✓ | **LIVE — rung 5 witness-ESTABLISHED (W221/#4556, 20:43Z) at the labeled W66 two-pool progress-off-consumer `RLIMIT_FSIZE` conditions; gate 6 CLOSED.** Fresh-context replay from base `33b6840d`, unmodified harness `b65814ce…` and the witness's own pinned 8.4.27-app/8.4.28-app FPM builds: unauthenticated loopback FastCGI wire input spliced a 1597-byte chosen session record at offset 1024, promoted the tinyfilemanager admin session, uploaded during the gap while the producer worker stayed alive, and the live consumer worker executed a lab-chosen benign command with a PID-bound marker and `uid=1000(mesh-home)`; fixed and safe-input controls clean, second SID/filler reproduced the positive set. Stock/default reachability and unlabelled r5 remain UNKNOWN. Main lane rung 4 CONSTRAINED on CGI and mod_php; wake-58 `drupal-afterRCE` lane adds DEMONSTRATED rung 4: an unauthenticated CVE-2026-126714 rfc1867 splice into real Drupal 11.4.13 over loopback FastCGI promotes a chosen session record and takes over user 1 at `/user/1` on a release-like 8.4.27-app build, with an 8.4.28-app fixed control clean; conditioned on the advisory's vulnerable ini and a shim SIGKILL interruption (Drupal core itself has no designed PHP execution). Wake 59 (`d7dae529`) takes the same splice into tinyfilemanager 2.6: the promoted `filemanager` session reaches its DESIGNED admin upload and `/evil.php` executes in the live FPM worker with a unique marker and `id`; fixed/no-kill/safe controls are clean, but the death is still the shim and attacker-caused death was measured NEGATIVE (SIGTERM handled mid-pwrite, cgroup OOM only on truncate-first writes, page-quantized partials), so that shim lane adds no r5. Wake-56 DOM lane reaches read-side chosen-pointer rung 4 on a plain local CLI (`USE_ZEND_ALLOC=0`, N=88, fault only), no SAPI, arbitrary write or marker there. Witness: W221/#4556 rung-5 gate 6 ESTABLISHED AS LABELED; #138 CGI and #258 mod_php rung-4 constrained; #126, #208, #287 rung-3 grades; #98/#103/#108 splice rungs 1/2. DOM and Drupal lanes author-observed; W59's shim-dependent FPM splice limb is rung 3 without the shim. [Status](reports/php2shell-status.md) |
| **Apache2Root** | ✓ | ✓ | ✓ | — | — | **CODE** — rung 3 chosen-byte placement at a capacity boundary on real ASan httpd 2.4.70 under gdb, fixed control clean; Stage C closed unreachable on this host (wire-byte alphabet, Huffman probe). Adjacent L2–L6 rung 3; L1/L7/L8/L9 rung 1–2 (L9 is auth-state corruption, no confirmed UAF). A 2026-11-21 frontier lane on the brief's CVE-2026-119618 (pinned 2.4.70/2.4.71, locally built **ASan APR**) confirms rung 1 by driving the wrong-pool `apr_table_setn()` marker 300/300 and 2000/2000, but its 2000+ full-table writes give 0 ASan reports and its one child SIGSEGV is unrepeated. That build-bound negative is preserved as contradictory evidence, not a refutation: this plant's rung 3 faults in uninstrumented system libapr with reproducible differential child SEGVs (3 vs 0 at `LogLevel info`) and a corrupted `pool->child` under gdb. Both agree the written value is the fixed string `0` — no chosen byte, pointer control or RCE. Earlier reviews #279 found a probe defect and #294 replayed the repair with no verdict change; witness W94/W95 (tape #1176) then graded this build-bound reconciliation ESTABLISHED at the labeled grade — rung 3 stands, rung 4 unclaimed, no replay — with the ASan-APR allocator/race cause nit corrected in `64ecc54` and CLOSED. Default-MPM RCE stays a claim. [Report](reports/apache2shell-investigation.md) · [CVE-2026-119618 brief](reports/frontier-apache2shell.md) |
| **Mosquitto2Shell** | ✓ | ✓ | ✓ | ✓ | — | **LIVE** — ASan 256-byte write past a 1-byte region in `net__read_ws`, fixed control clean; Stage A places chosen bytes at a chosen offset. Witness #246 ESTABLISHED the wire-only pre-auth 32 KiB heap read with live pointer disclosure (4/4 fresh brokers). Rung 4 is information disclosure only; enlargement stays layout-dependent and wire-to-code-execution UNVERIFIED. [Status](reports/mosquitto2shell-status.md) |
| **Node2Shell** | ✓ | ✓ | ✓ | — | — | **CODE** — two independent Alt-Svc terminators on pinned v24.22.2: stock-glibc abort 10/10, Memcheck differential against a clean v24.22.3 control. No combination primitive or control; rung 4 not demonstrated. [Status](reports/node2shell-status.md) |
| **Dragonfly2Shell** | ✓ | ✓ | — | — | — | **CODE** — stock RESP key echoed into a 20024-byte memcached reply, witness gdb `SendValue rdx=0x4e20`. Stock rung 3/4 UNVERIFIED; the ASan 20000-byte write is a labeled synthetic harness, not stock corruption. [Status](reports/dragonfly2shell-status.md) |
| **Postgres2Shell** | ✓ | ✓ | ✓ | — | — | **CODE** — FDW batch-insert overcount on stock 17.11: uninitialized 8-byte heap value used as a pointer, invalid write at `0x38`, SIGSEGV; fixed 17.12 completes. Needs `PR:L`, so pre-auth RCE is not demonstrated. [Status](reports/postgres2shell-status.md) |
| **Brotli2Shell** | ✓ | ✓ | ✓ | — | — | **HARNESS** — chosen bytes at chosen offsets past an 8-byte decoder buffer; the fixed build rejects. Rung 4 not demonstrated; network reachability is a claim. [Status](reports/brotli2shell-status.md) |
| **Freeradius2Shell** | ✓ | ✓ | ✓ | ◐ | — | **HARNESS** — an EAP-FAST ticket writes 208 bytes into a 152-byte stack struct and executes a chosen `verify_marker()` at rc 42; the fixed build rejects. Witness tape #227 reproduced byte-identical digests including the offset-specific marker control. Live `radiusd`, network reach and real stack layout UNKNOWN; rung 4 is harness-only. [Status](reports/freeradius2shell-status.md) |
| **Falkordb2Shell** | ✓ | ✓ | ✓ | — | — | **HARNESS** — a masked extended-length frame drives 525 out-of-bounds writes and chosen mask bytes overwrite a canary; witness replay #239 established rungs 1/2/3. Rung 4 not demonstrated because the mask repeats every four bytes. [Status](reports/falkordb2shell-status.md) |
| **Freeswitch2Shell** | ✓ | ✓ | ✓ | ✓ | ✓ | **LIVE** — a chosen 8-byte value at `wsh->ssl` is dereferenced in `SSL_shutdown` in a live FreeSWITCH over a loopback WebSocket `101`; the sentinel is a value, not code. Witness #338 replay with different bytes at the same fault site, controls clean. Stock heap layout, external reachability and the opt-in `mod_xml_rpc` gate stay in the claim. R5 ESTABLISHED by witness #1118 under the recorded conditions (ASLR-off calibration and trigger, opt-in `mod_xml_rpc`/websocket, lab shims, sudo-root netns, loopback only): a forged `SSL_METHOD` in the same frame calls `system()` with a wire-carried command, the target writes the marker, a varied command gives a different side effect, and safe/fixed controls leave it absent. ASLR-on reachability stays UNKNOWN. [Report](reports/frontier-freeswitch2shell.md) |
| **Freerdp2Shell** | ✓ | ✓ | ✓ | ✓ | — | **LIVE** — a client `SNDC_FORMATS` record wraps `out_frames` after a failed realloc; chosen `de` at OOB offset 8820 in a live post-auth RDP session over real TCP, under stock glibc and ASan. Witness W31/#532 ESTABLISHED the one-command replay from clean HEAD; #602 ESTABLISHED the FFmpeg format gate NEGATIVE on stock 6.1.1. The client controls the offset, not the audio bytes; the default ADPCM format is unavailable and the no-auth 9.8 case is not re-asserted. [Status](reports/freerdp2shell-status.md) |
| **Xrdp2Shell** | ✓ | ✓ | ✓ | ✓ | — | **CODE** — chosen bytes on real compiled xrdp 0.10.6 code: a 20000-byte DYNVC payload overflows the 8192-byte `trans_create` region through the real receive chain. Witness W33 ESTABLISHED both claims, W41/#617 clean-room 15/15 on two fresh builds closing the build-tree limit. Still in-process: no logon, negotiated channel, socket PDU trace or live-session allocator layout. [Status](reports/xrdp2shell-status.md) |
| **Gst2Shell** | ✓ | ✓ | ✓ | ◐ | — | **LIVE** — attacker-chosen `channels=1000` in `encoding-params` faults the shipping `rtpL8`/`rtpL16`/`rtpL24` depays and a loopback RTSP `rtspsrc` client; the OOB store is constant `-3`, so this is a count-controlled effect, not chosen bytes. Witness W33/#552 ESTABLISHED the 43/43 harness repair, closing the 42/1 contradiction. Strong rung 4, public-service SDP acceptance and allocator layout UNKNOWN. [Status](reports/gst2shell-status.md) |
| **Babelfish2Shell** | ✓ | ✓ | ✓ | ◐ | — | **HARNESS** — an unbounded 16-bit prelogin length copies into `StringInfo[1024]`, chosen bytes landing at OOB offsets 1100/2000; fixed control clean. No live TDS endpoint, `palloc` layout or real neighbour. [Status](reports/babelfish2shell-status.md) |
| **Bzfs2Shell** | ✓ | ✓ | ✓ | ◐ | — | **HARNESS** — a 1024-byte body writes four chosen bytes past `tcpmsg[1024]` into `tcplen`; instrumented chosen-value rung 4 reads back byte-exact. No live bzfs, player socket or `NetHandler` layout. Witness #761 ESTABLISHED all four rungs at those labels (20 PASS / 0 FAIL, byte-equal five-run digest); its source-citation nit is fixed in the brief, status and PROVENANCE, harness bytes unchanged. [Brief](reports/frontier-bzfs2shell.md) · [Status](reports/bzfs2shell-status.md) |
| **Kamailio2Shell** | ✓ | ✓ | ✓ | ◐ | — | **HARNESS** — tilde-distance `memcpy` into `bufport[5]`; instrumented chosen function pointer, pinned 6.1.5 rejects. Module gate, real frame layout and return-address control UNKNOWN. [Status](reports/kamailio2shell-status.md) |
| **Iperf2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — a 336-byte decoded authtoken crosses a 256-byte RSA heap buffer on real pinned upstream code; rung 4 is instrumented chosen bytes in the write buffer only. No live server, stock layout or useful pointer; the 3.22 release-note mislabel is preserved. [Status](reports/iperf2shell-status.md) |
| **Uftpd2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — an unbounded `memmove` in `compose_path()` shifts `dir[PATH_MAX]`; rung 4 is instrumented chosen bytes in the upstream frame. Needs `PR:L` and no-chroot; no live daemon or stock frame layout. [Status](reports/uftpd2shell-status.md) |
| **Accelppp2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — L2TP AVP chunks concatenate past a 4160-byte heap buffer on verbatim pinned code; rung 4 is an instrumented chosen value read back in an adjacent harness object. Needs verbose logging and a configured peer range. [Status](reports/accelppp2shell-status.md) |
| **Indiserver2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — a 1237-byte `sprintf` into `err[1024]` on the shared TCP/7624 path; rung 4 is an instrumented chosen token at adjacent harness-stack offsets. Availability-only advisory; no live daemon or stock layout. [Status](reports/indiserver2shell-status.md) |
| **Shairport2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — a 4096-byte RTSP method body is hex-dumped as 8193 bytes into `obf[4096]`; rung 4 is an instrumented chosen token. Availability-only advisory; the AirPlay-2 gate and a live socket are UNKNOWN. [Status](reports/shairport2shell-status.md) |
| **Asterisk2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — an unbounded `vsprintf` past `logMessage[2048]` in H.323 `ooTrace()`; rung 4 is an instrumented chosen token. Needs `chan_ooh323` compiled and its port exposed; availability-only ceiling. [Status](reports/asterisk2shell-status.md) |
| **Netatalk2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — an integer underflow leaves `remain=SIZE_MAX` and `strcpy` writes a chosen filename past `path[1025]`; rung 4 is an instrumented chosen token in the return slot. Needs an authenticated AFP session and cross-device rename; the maintainer's RCE claim stays a claim. [Status](reports/netatalk2shell-status.md) |
| **Iondtn2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — 18 AMP values append 1458 bytes into a 1024-byte `STAKE` heap region; rung 4 is an instrumented chosen token at adjacent offsets. Both advisories claim availability only; no live `nm_mgr` or UDP payload path. [Status](reports/iondtn2shell-status.md) |
| **Opensips2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — a 299-byte JID drives `ENC_SIP_URI()`'s `sprintf` 48 bytes past `buf_from[256]`; rung 4 is instrumented chosen bytes. Needs `backend=server`; RCE depends on canary/ASLR/NX. [Status](reports/opensips2shell-status.md) |
| **Unbound2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — a DNSKEY name plus RDATA writes 65788 bytes into a 65552-byte scratch buffer in `ds_create_dnskey_digest()`; rung 4 is instrumented chosen RDATA bytes. No live resolver, DNSSEC gate or compression-pointer route; advisory RCE remains a claim. [Status](reports/unbound2shell-status.md) |
| **Janus2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — a 1986-byte `.mjr` info header is `fread` into `prebuffer[1500]`; rung 4 is instrumented chosen bytes. Availability-only; no live Janus, HTTP/SDP path or real recording. [Status](reports/janus2shell-status.md) |
| **Rsyslog2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — a 9000-byte decoded Basic-Auth credential takes the `calloc(0, len)` branch in `imhttp.c:705` and writes chosen bytes past a zero-length allocation; rung 4 is instrumented chosen bytes read back at `pworkbuf[0..15]`. No live rsyslog, imhttp module or HTTP path; availability-only. [Status](reports/rsyslog2shell-status.md) |
| **ProxySQL2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — a declared 65535 (MySQL) / 100000 (PgSQL) first-packet length drives a second recv() of that many client-chosen bytes into a fixed 32768-byte queueIN before auth; ASan WRITE of size 65535 / 100000 at pinned mysql :665 / pgsql :534; rung 4 is instrumented chosen stripes at 32771 / 67237 bytes past the queue. No live daemon, listener, stock allocator or pointer control; advisory potentially-exploitable stays a claim. [Status](reports/proxysql2shell-status.md) |
| **Strongswan2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — a zero-length EAP-SIM/AKA attribute in libsimaka underflows size_t into a wrapped malloc()/memcpy() at pinned simaka_message.c:257-260; ASan WRITE of size 8 at :258, fixed 6.0.6 rejects; rung 4 is instrumented chosen 0x5a bytes under a bounded-copy collaborator, while the real-libc copy faults before writing. Needs local EAP-SIM/AKA termination, not RADIUS; no live daemon, pointer control or execution. [Status](reports/strongswan2shell-status.md) |
| **Memcached2Shell** | ✓ | ✓ | ✓ | ◐ | — | **LIVE/CODE/HARNESS** — an idle lru_crawler metadump all client makes a poll() timeout read as success, appending stored key bytes past the 131072-byte crawler buffer at pinned crawler.c:307-310/:471; ASan WRITE of size 64 at :310, fixed 1.6.44. A loopback daemon on pinned parent bytes confirms rung 3 in process: ASan `WRITE of size 1` at `util.c:57` via `crawler.c:310`, allocation at `:825`, fixed daemon clean. A non-perturbing `/proc` observer on a live non-instrumented build of the pinned parent sees chosen `0x5a` at `buf+131072` and at +512/+1024/+2048/+16384 as the write frontier advances; a `0x41` differential at the same offsets and timing (`414141414141303437303620` at `buf+131072`) proves those OOB bytes come from the stored key record. Witness #751 replayed all of it independently and accepted rung 3 in the real daemon and the rung 4 chosen-byte limb ESTABLISHED AS CLAIMED. A chosen-byte overwrite of pointer-shaped arena data (`90ae4b0c4474000090b14b0c` at +16384) is conditional on allocator state (absent in two witness `0x5a` replays), semantically unidentified, and not a grade basis. Fifth wake, witness #784 ESTABLISHED AS CLAIMED with grade unchanged at #751: the pinned plain parent under gdb with no breakpoints and ASLR on faults in `assoc_find` (`assoc.c:87`) in three of four stress runs, with the hash-bucket chain item pointer holding overflow-stream content — eight attacker-written `0x5a` bytes (`0x5a5a5a5a5a5a5a5a5a` in two runs) or a `fetch=%s` metadump fragment in the witness's other fault; the crash is not deterministic and the in-run frontier was not read. The witness rebuilt both binaries from hash-matched pins and showed fix sensitivity plus overflow dependence; the pinned fixed tree does not fault. Witness #762 left the separate t=116s `do_slabs_alloc` fault as a single non-deterministic observation (no core, UNKNOWN faulting value), with no replay owed and no grade change. No crafted canonical address, execution, control-flow diversion or external reachability: pinned `uriencode_p()` cannot emit a canonical pointer through the key path. [Status](reports/memcached2shell-status.md) · [Daemon repro](reports/memcached2shell-daemon-asan.md) |
| **Srs2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — a 1604-byte malformed RTCP datagram declares `length = 400` and a 1596-byte payload into `payload_[1500]` on verbatim pinned SRS bytes under `#line`; parent `length = 0` aborts at `srs_kernel_buffer.cpp:244` `require(size)`, ASan `WRITE of size 1596` 0 bytes after a 1536-byte region at pinned `:246` via RTCP decode `srs_kernel_rtc_rtcp.cpp:95`, TWCC reproduces (post-nit fix hits pinned `:841`), fixed build clean. Rung 4 is instrumented chosen `0x5a` / `0x41` at 96 offsets in a 64 KiB zeroed collaborator, benign control clean, guard page faults; no pointer, control flow or marker. GHSA-qr8h-p53p-x564 (no CVE), patched in 6.0.194 / 7.0.214 / 8.0.73; WebRTC pre-auth reachability and live daemon stay UNKNOWN. Witness nit #725 addressed in the harness at `3d556c5`; no witness verdict in hand. [Status](reports/srs2shell-status.md) |
| **389ds2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — a post-auth SASL UNBIND with `SSF > 0` declares a BER length larger than the caller's 512-byte receive buffer; verbatim pinned `sasl_io.c:344-348` sets `encrypted_buffer_count` to the declared length and `:451-457` copies that many attacker bytes into `buf`, ASan `WRITE of size 9000` 0 bytes after the 512-byte region at pinned `sasl_io.c.vuln:456`, 511/512 clean and 513 faults, fixed `f15ffd63` caps the drain. Rung 4 is instrumented chosen `0x5a` / `0x41` at offsets 0–8487 in a 1 MiB zeroed collaborator, benign control clean, guard page exits 77; no pointer, control flow or marker. CVE-2026-11610 / GHSA-2g8g-f92j-g4gq, 1.3.2–3.3.0 affected; no live `ns-slapd`, SASL bind, shipping allocator or execution, and the real caller's `len` is UNKNOWN. Witness nit #740 addressed at `3d556c5` (only heap-owned buffers freed); no witness verdict in hand. [Status](reports/389ds2shell-status.md) |
| **Ipfixcol2Shell** | ✓ | ✓ | ✓ | ◐ | — | **LIVE/CODE/HARNESS** — an unauthenticated peer declares an 8-byte small ring then a 65000-byte decompressed size; pinned `Lz4Decoder.cpp` under `#line` passes the declared size as `dstCapacity` to the host's real `liblz4.so.1`, ASan `WRITE of size 65000` 0 bytes past the 24-byte region at pinned `:145` (ring allocated at `:184`), fixed v2.9.0 rejects with `LZ4 Decoder: invalid decompressed size`. A loopback TCP harness now feeds the same wire bytes to the plugin's real v2.8.0 sources: rung 3 holds at real upstream frames, stock glibc faults in `unlink_chunk` with `rax=0x5a…58` / `0x41…40` and a crafted payload puts chosen `0x4141414141414141` in a pointer dereferenced at `unlink_chunk+39`. Rung 4 is instrumented chosen `0x5a` at offsets 0/24/28/64999 in a 1 MiB mmap collaborator with an `0x41` differential and a benign zero control; stock ASan faults before readback. CVE-2026-122127 / GHSA-4575-chq4-crfc, v2.7.1/v2.8.0 → v2.9.0. No full collector daemon (libfds/lz4-dev/rst2man absent), shipping allocator, valid target address or execution; witness #711 ESTABLISHED the clean-archive harness and #712 the loopback scope, no grade change. [Status](reports/ipfixcol2shell-status.md) [Live repro](lab/ipfixcol2shell-live/RESULTS.md) |
| **Kermit2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — repeat-count compressed `putsrv()` decoding on verbatim pinned C-Kermit v11.0.514 bytes writes 9212 chosen characters into an exact `MAXRP+1 = 9025`-byte `srvcmd`; ASan `WRITE of size 1` at `pins/ckcfns.c.vuln:461`, fixed v11.1.515 returns `decode_rc=-1` at the 9024th character. Rung 4 is instrumented chosen `0x5a` / `0x41` read back at offsets 9024–9151 (128 bytes; 9152–9211 inferred from `emitted=9212`) in a 1 MiB zeroed collaborator, benign decode writes zero bytes, guard page faults; no pointer, control flow or marker. Admitted 2026-11-21 under standing approval #6; witness #763 ESTABLISHED rungs 1/2/3 and rung 4 at INSTRUMENTED. CVE-2026-129126 / GHSA-c5px-7h4c-gj8p, affected before 11.1.515; no `wermit` build, live server, packet-length or repeat-encoding limits yet. [Brief](reports/frontier-kermit2shell.md), [status](reports/kermit2shell-status.md) |
| **GpfD2Shell** | ✓ | ✓ | ✓ | ◐ | — | **LIVE/CODE/HARNESS** — `X-GP-SEGMENT-COUNT` sizes and `X-GP-SEGMENT-ID` indexes two arrays with no bounds check on WarehousePG gpfdist 7.6.1: one unauthenticated HTTP request writes a chosen 4-byte `active_segids` value and a chosen 64-bit `X-GP-SEQ` value at a chosen index, pinned writes at `gpfdist_v7.6.1.c:1988` / `:3677`; ASan `WRITE of size 4` at `:1988` and isolated `WRITE of size 8` at `:3677`, fixed 7.6.2 guards reject both tested positive-id hostile shapes. Rung 4 is instrumented chosen `0x4141414141414141` read back byte-exact at `seq_segs+24`, `X-GP-DONE` flips the 4-byte write to zero and a guard page faults in the harness; a separate live loopback build of the real pinned source with real APR pools and a shimmed fstream backend writes chosen values into real pool neighbours at chosen offsets (gdb byte dumps for `1`/`2`/`3` at `seq_segs+24` plus an HTTP oracle), including the harness's exact `0x4141414141414141` at `seq_segs+120` (`path+96`) via a crafted filename supplying the slot = `value-1` sequence precondition. A deeper index overwrites the live APR hash pointer `session->requests[0]` at measured segid 28, and a matched-layout variant writes a header-supplied 64-bit value byte-for-byte into it (`0x7ffff76de028` → `0x7ffff76de029`, oracle 200 and fresh read-back) — bounded to the old pointer + 1, walked upward in repeated requests; faults symbolise at the real `:1988` for a wild index. Arbitrary non-path bytes, stock gpfdist / stock allocator layout, an arbitrary single-write pointer value, a decrement, control flow and execution stay UNKNOWN. CVE-2026-122042 (no GHSA), 6.27.1–6.27.7 / 7.2.1–7.6.1 → 6.27.8 / 7.6.2; admitted 2026-11-21 under standing approval #6; operator replay 13 PASS / 0 FAIL from a clean `git archive HEAD` at `a7d5884`, witness #792 ESTABLISHED AS CLAIMED at the harness boundary; witnesses W65/#859 and W66/#865 accepted the live OOB-store and both pointer limbs as claimed, no grade change. [Brief](reports/frontier-gpfdist2shell.md) · [Live](reports/gpfdist2shell-live.md) |
| **Gct2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — an SSLv2 backward-compatible hello with record length 1 makes `dsize=-2` and a 3-byte token buffer on GCT `globus-gss-assist` before 12.9 (GCT before 6.2.20261111); the verbatim pinned `tokens_f.c:171-173` `memcpy` writes 5 chosen header bytes into it and `:181` `fread` with negative `dsize` cast to `size_t` writes attacker body bytes past `cp+5`, ASan `WRITE of size 5` at `tokens_f_edf946b5:172`, fixed `3df2be48:127-131` rejects. Rung 4 is instrumented chosen `0x5a5b5c5d` read back byte-exact at `cp+5`, `PROT_NONE` guard faults; no live gatekeeper/myproxy, GSI handshake, stock neighbour, pointer or execution. CVE-2026-123975 (no GHSA), pre-auth, availability-only advisory; 10 PASS / 0 FAIL, witness #805 ESTABLISHED AS CLAIMED with no grade change. [Brief](reports/frontier-gct2shell.md) |
| **Imgproxy2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS + loopback HTTP consumer** — a crafted ICO declares `data_size=0xfffffff5`, wrapping `data_size + 14` to 3 in `VIPS_MALLOC` at pinned `icoload.c:158` (v4.0.15) so `vips_foreign_load_read_full` at `:161` writes 32 attacker bytes 11 past the allocation at `data+14`; ASan `WRITE of size 32` at `icoload_v4.0.15:161`, fixed v4.0.16 rejects `data_size > 10 MiB`. Rung 4 is instrumented chosen `0x5a5b5c5d` read back byte-exact at `data+14`, `PROT_NONE` guard faults; the original top-of-arena placement had no neighbour pointer. W1 built pinned v4.0.15 and fixed v4.0.16 imgproxy binaries and sent crafted ICO/TIFF bytes over a real loopback HTTP source (127.0.0.1:18080/18081): vulnerable `safe=200`, crafted `manyband=500`, fixed all crafted `500 image: dimension overflow`. W2's five-case fine-TIFF log has only three `Started` lines under `WORKERS=1`, so its later timeouts are queue starvation; an isolated fresh-process GET of the 154-byte `fine.tif` (`c3e12050…157d44`, `ls=2^32-16`) returns HTTP 422 "Source image resolution is too big" at imgproxy's 50M-pixel guard before libvips header load, fixed returns 500 `image: dimension overflow`. The earlier ~8.59 GB decode-stall attribution is WITHDRAWN; no scanline decode, paint frame, chosen byte or pointer was observed in the endpoint. CVE-2026-123614 / GHSA-hff9-5pqw-6w9f, 4.0.0–<4.0.16 → 4.0.16, unauthenticated HTTP, CVSS 9.3 prose claims RCE; 10 PASS / 0 FAIL; witness #813/#814 ESTABLISHED the ICO harness AS CLAIMED and witness W185 (#3318) ESTABLISHED ICO rungs 1-4 on clean replay plus the HTTP probes only at header/processing-entry scope, NO r5, grade unchanged. W5 (`4c4937d`/`2b0cc2e`) disproves the old top-of-arena assumption: benign favicon GETs in the same imgproxy process put a free tcache chunk's `next` at `actual_data+18` in 3/6 preload runs, and the spill set it to chosen `0x4141414141414141` while preserving the victim size `0x35`; the next `malloc(0x20)` consumed the victim, leaving the bin head at the chosen value. The chosen address is unmapped, no write through it, marker execution or command was observed, grooming is stochastic and a clean-archive replay at `4c4937d` reproduced pointer control at preload=6 but hit the top layout in five preload=2 runs; author-only, unwitnessed, still rung 4. W204 (tape #3734) replayed W9's allocator blocker from clean `git archive 5af51c33` and graded it ESTABLISHED AS LABELED at that loopback allocator scope: three wire-head victims returned the decoded tcache pointer under gdb and then aborted at `free(): invalid next size (fast)`, with no later `malloc(0x20)` consuming the head; the fixed binary stayed alive at HTTP 500 with zero gdb hits. W10 (`76df8b76`, author-only, unwitnessed) attributes that abort to the first natural free of the returned wire-head victim from `g_hash_table_unref` under `vips_argument_table_destroy` (`libvips/iofuncs/object.c:573`): W9's `0x25` wire bytes had rewritten the victim's original `0x35` chunk size. With `SIZE=0x35` the field survives, but twenty runs returned no decoded-head malloc and six hostile requests stayed alive at HTTP 500, so no consumption is claimed. W11 (`cf1dfb05`, author-only, unwitnessed) resolves W10's tcache/TLS discrepancy with a GDB probe that writes no memory: the wire-decoded head is briefly on top after a natural malloc, then buried by a natural free before the next malloc in the same thread and the same tcache; no natural allocation returned the wire-decoded pointer. W11b (`a1a37fd6`) tried a second benign request after the hostile one; it never reached a poisoned-head survivor, and the two samples that reached a survivor spilled away from the live head, so that route is untested, not a negative. W5 stays author-only and unwitnessed; no grade change, r5 UNKNOWN. [Brief](reports/frontier-imgproxy2shell.md) |
| **Firebird2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — a wire-supplied `USHORT` cstring length in `xdr_datum()` is passed unbounded to `xdr_opaque`, whose decode `memcpy` writes `n` bytes into a `dsc_length`-sized slot inside a wire-sized slice buffer; verbatim pinned `xdr.cpp:206-221` under `#line`, ASan `WRITE of size 60000` at `xdr_v5.0.3:216`, fixed v5.0.4 clamps `n = MIN(n, dsc_length-1)` and is clean. Rung 4 is instrumented chosen `0x5a5b5c5d…` read back byte-exact at `buffer+40` / `buffer+100`, `PROT_NONE` guard faults; no live `fbserver`, wire packet, allocator neighbour, pointer or execution. CVE-2026-33337 / GHSA-89mq-229g-x47p, 3.0<3.0.14 / 4.0<4.0.7 / 5.0<5.0.4, pre-auth TCP/3050 slice packet, availability-only CVSS 7.5; 10 PASS / 0 FAIL; witness #818 independent replay ESTABLISHED AS CLAIMED, grade unchanged. [Brief](reports/frontier-firebird2shell.md) |
| **Rtp2httpd2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — a wire 16-bit RTSP interleaved frame length at pinned `rtsp.c:1792` is bounded at `:1800` against the 4096-byte source buffer (max 4092) instead of the 1536-byte destination pool slot, so `memcpy` at `:1825` writes up to 2556 chosen bytes past the slot; ASan `WRITE of size 4092` at `rtsp_v3.14.1:1825`, fixed `v3.14.2:1801` bounds against `BUFFER_POOL_BUFFER_SIZE`. Rung 4 is instrumented chosen `0x5a5b5c5d` bytes at slot+1600/+2400/+2500 and a `PROT_NONE` rc 139 fault; no live daemon, RTSP wire traffic, stock allocator neighbour, real `buffer_ref_t`, pointer or execution. GHSA-35fv-hf3m-2pqc (no CVE), `<=3.14.1` → `3.14.2`, advisory claims unauthenticated remote reach, CVSS 9.8; 10 PASS / 0 FAIL, operator replay 11:26Z; witness #831 ESTABLISHED AS CLAIMED, grade unchanged. [Brief](reports/frontier-rtp2httpd2shell.md) |
| **Vrpn2Shell** | ✓ | ✓ | ✓ | ◐ | — | **LIVE wire rung 3 witness-ESTABLISHED (W115); lab-patched rung-4 marker witness-ESTABLISHED (W135/#1985) at the labeled build scope** — CVE-2026-123200, VRPN 07.36; tags stop at 07.36 and both fix commits are untagged (`lab/frontier/vrpn2shell/UPSTREAM-RELEASE-LOOKUP.md`). A pre-auth `SENDER_DESCRIPTION`/`TYPE_DESCRIPTION` signed length drives unchecked `'\0'` stores at `vrpn_Connection.C:4553-4554`/`:4482` on 100-byte stack arrays; a live loopback ASan message hits the write site, plain index 120 zeroes saved RIP low byte (SIGILL), index -8 zeroes the saved endpoint pointer and faults downstream. W6 is a debugger-free pre-auth DoS (SIGSEGV/SIGILL); W8/W10 resolved a build-label mix-up: at real `-O2` saved RIP is at 136-143, canary aborts at 105/111/105 and 136/139 SIGSEGV matches the witness. W15/W16 then byte-mapped all eight saved-RIP bytes on the stock Debug `-O0` and RelWithDebInfo `-O2` builds: indices 120-125 and 136-141 each zero one byte and fault, 126/127 and 142/143 are already-zero no-ops; at `-O2` byte 0 reaches mapped text and faults 13 bytes in, byte 1 follows a libc `inet_aton_end` path with cause UNKNOWN. W16 is author-only and unwitnessed; no surviving modified control flow is claimed. W17 extends the `-O2` map two caller frames deeper on vulnerable binary SHA-256 `bfe63334…bae2`: live returns at +200 (outer `doSystemCallbacksFor` :1424) and +312 (`dispatch` :4331); indices 200-205/312-317 zero bytes 0-5, gdb PRE→POST `0x5555555a200d`→`0x5555555a2000` and `0x5555555a4059`→`0x5555555a4000` with the modified frames entered before SIGSEGV, bytes 6-7 are already-00 no-ops and stale-word indices 296/304/328/336/344/392/408 stay alive, fixed/short clean; author-only, unwitnessed, no grade change. W19 at stock `-O2` sweeps the remaining caller-local pointer slots: indices 144/168/176-183/240/320/328/376/384/392/400 stay alive after the message (fixed at 176 and short input also alive), and gdb shows the slot at +176 changing `0x5555556a7380`→`0x5555556a7300` while the live buffer argument stays `0x5555556a7380` in frames #1-#3; callers at `:1446-1452`, `:4331-4339` and `:4239-4245` never re-read `p.buffer`, so these are dead by-value copies — a negative closure, not new rung 4 or pointer control. Author-only, unwitnessed. W20 (`50a7f23`) closes the TYPE sink's stock `-O2` return map on the same two builds: harmless TYPE index 4 measures `array=rsp=rbp=0x7fffffffd930` and the same live returns at +136 (`0x...5a1f42`), +200 (`0x...5a200d`) and +312 (`0x...5a4059`) as SENDER, and indices 136-141/200-205/312-317 are DEAD (exit 139 except 313, exit 132 with empty stderr and UNKNOWN cause; under gdb index 313 lands at `0x...5a0059` and SIGSEGVs) while 142/143, 206/207 and 318/319 are already-zero no-ops; fixed 136/200/312 and short index 4 stay ALIVE. The two sinks share one caller chain on this build; no surviving modified control flow, chosen byte, command or rung 5, author-only, no grade change. W21 (`d79c99a`) extends the wire sweep to the outer `SENDER_DESCRIPTION` frame on the plain `-O0` build (vuln SHA `5cf49457…340bd74`, fixed `10e581e8…ea2f45`, stock `-O2` `bfe63334…bae2`): index 512 changes an outer-frame saved rbp at `vrpn_Connection.C:4554` from `0x00007fffffffdbc0` to `0x00007fffffffdb00` and enters `__stack_chk_fail` from `getOneTCPMessage:4246` through `doSystemCallbacksFor:1446/:1424` → `dispatch:4331`; the coarse sweep has 320/384/448/640/768/1024/1280/1536/2048/3072/4096/6144/8192 ALIVE, 512 DEAD rc 134 with `*** stack smashing detected ***` (TYPE sink 512 also 134), 16384/32768/65536 DEAD rc 139 with the cause **UNKNOWN** (no gdb landing mapped; `e41b2da` supersedes the "leaves the mapped stack" explanation in W21's section, though an older phrase survives in the report's Limits section), and the fine sweep 512-517 DEAD, 518/519 ALIVE, 520 DEAD; fixed 512, short 4 and `-O2` 256/384/512 stay ALIVE, and the fixed build writes only the NUL at the chosen offset. No chosen byte, command or rung 5; author-only, no grade change. W11 (`ed4094f`) selects an installed `write()` marker stub in a non-PIE, no-stack-protector rebuild; marker bytes come from the binary patch, not the wire. W12 (`ceb6bd5`) rebuilt both pins in new directories with W11's flags (vuln SHA `52eefbfb…`, fixed `f8d50ba7…`) and replayed the marker. Witness W135 (#1985) independently rebuilt both pins from a clean `8e9fd0a` archive, replayed the six-case matrix on fresh loopback ports and graded the lab-patched rung-4 marker ESTABLISHED at that scope; addresses `0x413d00`/`0x413dda`/`0x40be40` and `-falign-functions=256` are build-specific preconditions. A default-alignment control (SHA `d82632d5…`) zeroes saved RIP to mid-function `0x410800`. No wire-chosen byte survives in a live caller, no pointer control, command or rung 5; stock builds stay at W115's rung 3. [Report](reports/vrpn2shell.md) |
| **Netx2Shell** | ✓ | ✓ | ✓ | ✓ | — | **CODE/HARNESS — rung 4 MEASURED by direct call and TLS-arrived certificate; witnesses #1262 (W1/W2) and #1296 (W3) ESTABLISHED at the claimed scopes (no host TCP loopback)** — hash-pinned NetX Duo 6.5.1.202602 parses an X.509 certificate whose RSA modulus exceeds `NX_CRYPTO_MAX_RSA_MODULUS_SIZE` without an upper bound; `_nx_secure_x509_certificate_verify` passes the issuer *exponent* as the RSA key, so the 512-byte output check passes and `_nx_crypto_huge_number_extract` writes `s^e mod n` with the attacker's 1024-byte modulus length. The real 8192-bit upstream DER fixture gives ASan `global-buffer-overflow WRITE of size 1` 0 bytes after `decrypted_signature[512]`; the plain unmodified build writes 1024 bytes over the adjacent CRL verifier's static. With attacker-chosen `s`, `e=2` and `n = s² − T`, gdb reads back a fully chosen 1024-byte `T`: `de ad be ef ca fe ba be` at offsets 512..519, and a one-byte variant changes only +512; fixed 6.5.2.202603 rejects. A separate in-process TLS handshake serving that real certificate reaches the same sink through the full TLS/X.509/RSA chain under ASan, with fixed-build and 2048-bit safe-input controls clean — protocol-arrived bytes, but the transport is the pinned RAM driver, not host TCP loopback (no host driver in the tree). W3 closes the manual-operand gap: `harness/tls/gen-crafted-cert.py` patches a DER certificate whose own modulus, exponent and signature carry the `n = s² − T`, `e = 2` construction, and the client reaches the same write through the full TLS handshake with `de ad be ef ca fe ba be` at +512..+519; run B changes only +512 to `5a`, and the fixed build rejects before verification (a weaker stall, recorded as such). No pointer control, marker, command path or rung 5; witnesses #1262 (W1/W2) and #1296/W108 (W3) both returned ESTABLISHED at the claimed scopes with no refutation, which is not a rung-5 verdict. [Brief](reports/frontier-netx.md) · [Investigation](reports/netx2shell-investigation.md) |
| **Wazuh2Shell** | ✓ | ✓ | ✓ | ◐ | — | **LIVE/CODE/HARNESS** — pinned `wazuh-manager` v4.14.7 `cleanevent.c:59-62` sizes `lf->full_log` from the input line, then `fim_generate_alert()` writes the generated alert with `snprintf(..., OS_MAXSTR, ...)`: a 228-byte registry-value JSON allocates 459 bytes and writes 528 (ASan `heap-buffer-overflow WRITE of size 528`, 0 bytes after the allocation); the plain build places a chosen JSON byte in a neighbouring heap object. Fixed v4.14.8 formats into a scratch buffer and resizes first; full-`old_attributes` control clean. The enrolled-agent 1514 → FIM-sink path is source-confirmed on the pinned v4.14.7 bytes (`reports/wazuh2shell-wire-reach.md`): `secure.c:57/:771/:956/:964` frame and forward the decrypted `8:syscheck:` message, `mq_op.h:23` dispatches on `SYSCHECK_MQ`, `analysisd.c:1231/:1560/:1579` queues, cleans and enters `decode_fim_event`, and pinned `syscheck.c:1265/:1288/:1436/:1551/:1680` reaches the `snprintf` sink with no intervening length guard or reallocation; fixed v4.14.8 formats into `alert[]` (`:1548/:1694/:1720`). A live `wazuh-analysisd` build on pinned v4.14.7 with ASan (`reports/wazuh2shell-live-crash.md`) drives that queue from a lab-sent AF_UNIX `8:syscheck:` datagram carrying the 228-byte JSON: the daemon aborts with `heap-buffer-overflow WRITE of size 506`, 0 bytes after the 459-byte `full_log` region, frame `fim_generate_alert syscheck.c:1680` ← `fim_process_alert:1436` ← `decode_fim_event:1288` ← `w_decode_syscheck_thread analysisd.c:1586`. A real loopback TCP/1514 enrolled-agent session (`reports/wazuh2shell-1514-wire.md`) now closes the wire leg: the JSON is encrypted with the agent's lab key by Wazuh's own `CreateSecMSG`, framed in 4 wire-order length bytes and sent to a plant-built `wazuh-remoted` on 127.0.0.1:1514; remoted logs `FIM event detected` and relays the decrypted message to `analysisd`, which faults with the same ASan `WRITE of size 506`. The 406-byte full-`old_attributes` control and the v4.14.8 ASan remoted/analysisd pair stay alive with no ASan overflow; the v4.14.7 plain daemon's 69-byte overflow is not a reliable crash. A plain non-ASan daemon readback (`reports/wazuh2shell-heap-adjacency.md`) observes chosen alert bytes and two corrupted chunk-size fields in the physically adjacent `agent_id`/`location`/`hostname` character arrays from a live daemon driven by the same datagram, with the 406-byte control clean; source tracing finds no pointer consumer there. W109's maximized single-event groom overruns `full_log` by 35 bytes and ends 70 bytes short of the `lf->fields` pointer array — a measured negative; W110 measured multi-event grooming: with `syscheck_threads=1` the exploit reuses the prior 261-byte `scan_start` slot and a pointer-fragment chunk sits immediately after `full_log`, but the overrun writes fixed alert text with at most one attacker byte, and 1 s / 10 s gaps instead take a fresh top chunk. W111 (#1326) independently replayed W108/W109/W110 ESTABLISHED at the claimed scope, no refutation. Still no chosen pointer, marker, command side effect or rung 5; rung 3 in a live daemon reached by attacker-chosen wire input plus a deterministic ASan-build availability fault only, rung 4 chosen bytes in adjacent char arrays. The advisory needs PR:L, claims an availability outage and disclaims RCE. [Brief](reports/frontier-wazuh.md) · [1514 wire](reports/wazuh2shell-1514-wire.md) · [Heap adjacency](reports/wazuh2shell-heap-adjacency.md) |
| **MapServer2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS + LIVE stock build (live limb witness W125 ESTABLISHED at rung-3/rung-4 scope)** — `cgiRequestObj` (pinned MapServer rel-8-6-4) has 100-entry parameter arrays with no capacity field; `loadParams` tracks capacity only in a local variable lost on return, so `GetLegendGraphic` with a nonempty BBOX (`mapwms.cpp:5989-5995`) appends `msStrdup("LAYERS")` and `msStrdup(ParamValues[i])` at `NumParams` with no capacity check: K repeated `LAYER=` params write attacker-chosen query-value pointers past the 800-byte allocations (capacity-doubling blind spots K=97/197), fixed in 8.6.5 by fix commits `ea1d87a` / `a7d5eb8`. Rungs 1/2/3 ESTABLISHED in an extracted, source-bound harness; rung 4 there is instrumented chosen-value control (`DEADBEEFCAFEBABE` read back byte-exact at pointer slots 110/150/190, offsets 880/1200/1520). Witness #770 (2026-11-21) ESTABLISHED rungs 1/2/3 and rung 4 AS CLAIMED at the INSTRUMENTED label, no nits, replayed from a clean archive of HEAD `57364e6` with both harness pins and all pinned sources hash-matched and six checks reproduced (determinism digest `5df6fce0…082c2e`). A later live limb (`reports/mapserver2shell-live.md`) upgrades both: a real GET through a 127.0.0.1:8077 CGI bridge with K=95 repeated `LAYER=DEADBEEFCAFEBABE` makes a stock rel-8-6-4 `mapserv` write 8 bytes 0 bytes past the 800-byte array at `mapwms.cpp:5991` (ASan rc 1); fixed rel-8-6-5 and K=96/97 controls are clean. Under gdb on a plain stock process, `ParamValues[100]` and `[150]` hold the byte-exact attacker string and a chosen 8-byte `LAYER` value is passed unchanged as the pointer argument to `free()` (`0x4542414245464143` for DEADBEEFCAFEBABE, `0x5a5a5a5a5a5a5a5a`, `0x4141414141414141`) before the process faults — chosen bytes at a chosen offset in a live stock process, not a harness marker. A consumer-reality gdb pass on the plain stock build (`lab/mapserver2shell/consumer-inspect.sh 95`) found the OOB appends overwrite the adjacent ParamValues chunk's `prev_size`/`size` fields (array base delta 816) and subsequent heap chunks holding only heap pointers, with no code, PLT/GOT or vtable pointer in the written range; the only post-overflow consumers are C-string reads at `mapwms.cpp:6017` and `free()` at cleanup, and the observed fault is glibc `double free or corruption` in `_int_free_merge_chunk`, not control flow. The wire response carries no pointer bytes (PIE/NX, glibc 2.39), so rung 5 stays UNKNOWN with named obstacles — a function-pointer consumer or a leak plus heap arbitrary write would be needed — not claimed or refuted in general; the K=95 layout also makes the earlier `free()`-argument readback layout-dependent. Witness replay of the live limb was still owed at 04:13Z; W125 closed it. A fresh-context author replay (commit `fdf5612`) re-ran the committed drivers against the existing pinned binaries: vulnerable ASan K=95 and K=195 give rc 1 and `WRITE of size 8` at `mapwms.cpp:5991` (800-byte region at K=95, 1600-byte at K=195), fixed ASan and K=97 are rc 0, and plain K=195 exits 134 with `double free or corruption (!prev)`; normalized stderr matches the canonical `asan-vuln-K95.err` / `asan-vuln-K195.err` byte-for-byte. The report's Reproduce block now copies the vulnerable `.err` before the fixed-control run, which previously overwrote it. W7 (`c7d055e`) then re-ran both gaps: `./readback.sh 95 DEADBEEFCAFEBABE` gives byte-exact chosen bytes at `ParamValues[100]`, `[150]` and `[190]` on the plain build, and a real K=95 GET through `loopback_bridge.py` on 127.0.0.1:8077 returns HTTP 500 with a fresh child ASan report byte-identical to `bridge-child-stderr.log` after masking addresses and PIDs; grade unchanged at the time. Witness W125 later rebuilt all three pins from hash-verified tarballs in its own clean tree and replayed wire rungs 3/4 and the chosen-byte readback ESTABLISHED at the labeled scope (three build SHA prefixes `955501d6…`/`73898391…`/`6b477823…`, one flag deviation `-O0` vs this plant's `-O1`). No lab-chosen command or control-flow redirection; the bridge is a lab CGI adapter, not a production deployment. CVE-2026-77326 / GHSA-4mwc-qc95-5959, CWE-787, CVSS 3.1 8.6, `<=8.6.4` → 8.6.5. [Brief](reports/frontier-mapserver2shell.md) · [Live](reports/mapserver2shell-live.md) |
| **Nanomsg2Shell** | ✓ | ✓ | ✓ | ◐ | — | **LIVE/CODE — wire-reachable rung 3 and rung 4 chosen-value control at a measured offset; rung 4 witness-ESTABLISHED (W107), W108 shipped-process reach, no rung 5** — hash-pinned Nanomsg 1.2.2 `nn_ws_handshake_server_reply()` (`src/transports/ws/ws_handshake.c`) copies the client's `Sec-WebSocket-Version` into a fresh buffer and `sprintf`s it into `self->response`, a fixed `char response[512]` (`ws_handshake.h:145`); the parser at `:958-961` stores the raw value and length uncapped, and the neighbour `struct nn_fsm_event done` (`:148`) carries pointers. Fix PR #1130 / tag 1.2.3 replaces it with a bounded `snprintf` and hardcodes version `13`. A standalone 127.0.0.1 `nn_bind("ws://…")` listener driven by a raw HTTP Upgrade with 600 chosen `Q` bytes replies 669 bytes with a 67-byte prefix, so 155 chosen bytes land past `response[512]` in the adjacent `done` event; the server aborts with queue assertion `item->next == NN_QUEUE_NOTINQUEUE` (`queue.c:47`) in both GCC and clang ASan builds, while fixed 1.2.3 and a 2-byte header are clean. On a `-g -O0` build W106 measured `&self->done - self->response == 516` (4 pad bytes) and `done.item.next` at header indices 481..488: a position-encoded 490-byte request writes `item.next = 0x3231307a79787776` byte-exact from the wire; eight chosen `0x41` bytes give `0x4141414141414141` and fire the queue assertion, while eight `0xff` bytes give `0xffffffffffffffff` (`NN_QUEUE_NOTINQUEUE`), bypass that assertion and reach `aws.c:316 "Unexpected source"` — the chosen wire value selects the live control-flow path. ASan does not instrument the libc `sprintf` store (clang field-padding silent too), so the consumer assertion is the detector. W107 (#1292/#1293) is an independent witness replay: it recomputed both pins, rebuilt both libraries and its own harness from scratch and reproduced the 67-byte prefix, `DONE_OFFSET=516`, all three chosen-pointer readbacks, both FSM divergences, clean fixed controls and all 14 normalized hashes — rung 4 ESTABLISHED at the claimed standalone-listener scope, no refutation or NIT. W108 replaces the purpose-built listener with `nanocat`, a CLI tool shipped in both pinned trees, binding `ws://127.0.0.1:28765` on loopback under raw wire input: short control clean, `marker:41` 558-byte reply plus `queue.c:47`, `marker:ff` 558 bytes plus `aws.c:316`, fixed 1.2.3 71 bytes, and gdb inside `nanocat` reads `DONE_OFFSET=516` and the chosen `item.next` (`bash harness/nanocat_reach.sh`; raw traces in `harness/nanocat/`). No command execution or clean takeover (the ff case ends in a downstream FSM assertion), no rung 5: W108 is a shipped CLI tool, not proof every nanomsg application is reachable, and W109 shows the `+516` offset is not an `-O0` artifact — it recurs at `-O3` with FORTIFY disabled with the same chosen `item.next` — while a default `-O3` build imports `__sprintf_chk` and aborts inside the `sprintf` with `reply_len=0`, so chosen-byte rung 4 holds only on non-fortified builds; source closure leaves rung 5 UNKNOWN. CVSS 4.0 8.6 `AV:N/AC:L/PR:L/UI:N`, affected 0.5-beta..<1.2.3 → 1.2.3. [Brief](reports/frontier-nanomsg.md) · [Status](reports/nanomsg2shell-status.md) |
| **Pgpool2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS + LIVE wire rung 3 (witness W113 ESTABLISHED at rung-3 wire scope; rung 4 author-only)** — pinned 4.7.2 `parse_wd_node_function_json()` (`wd_json_data.c:858`) writes `*(node_id_set[i])` instead of `(*node_id_set)[i]`; `i>=1` stores a peer-chosen 32-bit value through the adjacent pointer slot; fixed 4.7.3 (`0388652d`). Direct-call ASan READ-8 and gdb readback of `0x42424242`; W1 live watchdog child SIGSEGV at N=2, N=1/fixed clean; W2 at `-O2` hits a stale code pointer in read-only text; W3 faults at i=1 before i=2; W6 closes cross-command steering negatively (type-f failover residue never occupies the bad index). W11 (`f5df311`) measures that setting `wd_authkey` does not gate the type-`Z` parse: the N=129 `WD_POOL_CONFIG_DATA` packet is still received and parsed, with decisive hashes byte-identical to W10's vulnerable case (`watchdog.c:4467-4472` has no `verify_authhash` on that branch; `bash lab/pgpool2shell/wdnodes/wire/auth-probe.sh`). W113 excludes chosen-address write, command and rung 5; W6/W11 remain author-only. [Wire W1](reports/pgpool2shell-wire-w1.md) · [W6 negative](reports/pgpool2shell-groom-w6.md) · [Status](reports/pgpool2shell-status.md) |
| **Bacnet2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS — rung 3 on the real pinned decoder, rung 4 chosen bytes at chosen offsets in a server-shaped global (author-only, no wire, no witness)** — CVE-2026-97692 / GHSA-gr74-333w-7wg8 (High 7.7), affected `bacnet-stack <= 1.5.0` plus the audited `1.6.0-rc1`, patched `1.4.6/1.5.2/1.6.1/1.7.0`; audit commit `1068250f…`, fix PR #1435 merged as `37b081d0…`. A trailing MORE bit on the last BACnet/SC header option walks past the 4-entry `dest_options` array: the vendor's 10-byte frame case 1 gives ASan `READ of size 1` at `bvlc-sc.c:557`, case 3 `WRITE of size 8` at `:601`; the server-shaped plain harness puts chosen `41 42 43` at decode-struct offsets 304/344/384/424 (40-byte stride from the array end) and `bf` markers at 248/288/328/368/408, while ASan reports `global-buffer-overflow` 0 bytes past the 432-byte file-static `g_dm`. All fixed-build cases reject with `header options is truncated`. Pre-auth wire reach is advisory-sourced, not measured here; no daemon, no command, no rung 5. [Brief](reports/frontier-bacnet2shell.md) |
| **Ud3tn2Shell** | ✓ | ✓ | ✓ | ✓ | — | **LIVE wire rung 3 and rung 4 chosen-content-over-offset on a live loopback daemon (author-only, no witness, no rung 5)** — CVE-2026-121510 / GHSA-96mh-pq33-phch (CVSS 3.1 7.5, `AV:N/AC:L/PR:N`), affected µD3TN `<0.15.2`, fixed 0.15.2; pinned tag commits `00b2fbef…` / `6b18b267…`, fix `09f18b9c…`. A BPv6 admin record with source-EID length SDNV 0 calls `malloc(1)` and decrements `bytes_remaining` from 0 to 65535 before the `==0` test, so `record_parser_read_byte()` stores peer-chosen bytes sequentially past the chunk (`reports.c:439`). The plant's MTCP daemon on 127.0.0.1 gets ASan `WRITE of size 1` at `:439` through `bundle6_parse_administrative_record` for markers `41` and `5a`; the same payload at length 8 and fixed 0.15.2 are clean, and plain-build gdb reads 20 consecutive `5a` (or `43`) bytes at offsets 0..19 past the 1-byte allocation on the 20th store (`index=20`, `bytes_remaining=65516`). No pointer or address control, no command, no witness replay; the advisory's RCE hedge is not a result. [Brief](reports/frontier-ud3tn2shell.md) |
| **Zephyr2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — serving a file larger than the 256-byte RX buffer overwrites the bounded residue when pinned `http_server_http2.c:496/499` (v4.4.0) passes `&client->data_len` as the `file_size` out-param and `http_server_core.c:892` replaces it with the on-disk size; the dispatch loop at `:557` feeds the corrupted residue to the verbatim `memmove` at `:563-566`, ASan `WRITE of size 1024` 0 bytes past the 256-byte buffer at `core_v4.4.0:565`, fixed v4.5.0 uses a local `file_size` at `:472/497/500/535`. Rung 4 is instrumented chosen `0x41424344` / `0x5a5b5c5d` at offsets 300/500/900 and a `PROT_NONE` rc 139 fault; no Zephyr build, HTTP/2 wire traffic, RTOS socket, real `struct http_client_ctx` layout, pointer control or execution. CVE-2026-82391 / GHSA-8jrg-wx88-g75j, `>=4.0.0 <4.3.2` and `>=4.4.0 <4.5.0` → 4.3.2 / 4.5.0, CVSS 9.1 prose claims code execution; 10 PASS / 0 FAIL, operator clean-archive replay at `0ccfdba`, witness W64/#847 ESTABLISHED AS CLAIMED, grade unchanged. The advisory's `zsock_recv` `size_t`-underflow limb stays source-bound. [Brief](reports/frontier-zephyr2shell.md) |
| **ZenohPico2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — an unchecked wire `uint8_t` ZID length at pinned `message.c:79` (zenoh-pico 1.10.1) drives `_z_zbuf_read_bytes` at `:80` to copy `len` bytes into the 16-byte `_z_id_t.id`, whose pinned reader checks only source readability; `:81`'s `memset(id->id + len, 0, 16 - len)` wraps negative length to huge `size_t` (source-bound, not executed). ASan `WRITE of size 64` at `message_v1.10.1:80`, fixed 1.10.2 rejects `len > sizeof(id->id)` at `:81-84`; rung 4 is instrumented chosen `0x41`/`0x5a` bytes at +16/+32/+48 and a `PROT_NONE` rc 139 fault; no zenoh build, wire frame, transport, peer, real heap neighbour, pointer or execution. CVE-2026-130603 / GHSA-fw6g-3fgh-f6m6, `0.7.2-rc`–<1.10.2 → 1.10.2, CVSS 4.0 9.3 CRITICAL, pre-auth timestamp message; 10 PASS / 0 FAIL, two five-run groups at `sha256=080794c304ffa34b467a189c505f02318af437ecc43c3a0658d985f0632b9b3b`; operator clean-archive replay ~11:54Z; witness #861 (2026-11-21 ~12:01Z) ESTABLISHED AS CLAIMED, grade unchanged — clean-archive replay byte-identical, all seven pins matched fresh fetches, tampered core pin failed rc 3; rungs 1/2/3 ESTABLISHED, rung 4 INSTRUMENTED. Admission #6. |
| **Libwebsockets2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS + real-build counterpart** — an HPACK-decoded attacker `:path` byte reaches pinned `hpack.c:277` (libwebsockets v4.3.10) via `lws_parse_urldecode` at `:1151` and `lws_frag_append` at `:1168`, where `ah->data[ah->pos++] = (char)c` stores before the `pos >= max_http_header_data` check at `:280`; ASan `WRITE of size 1` at the verbatim `hpack_v4.3.10:277`, fixed v5.0.0 rejects before the write. Operator clean-archive replay 10 PASS / 0 FAIL, witness W68/#868 ESTABLISHED the harness claim. A plain long `:path` on a real stock v4.3.10 H2 server was a measured NEGATIVE (W1, route-specific); a single unauthenticated loopback HTTP/2 HEADERS frame with a URI delimiter in `:path` instead gives a chosen-byte write at chosen offsets 32/33 just past the real 32-byte header arena on the freshly built server, symbolised ASan `WRITE of size 1` at `hpack.c:277` from `:1168`, byte-exact readback of two distinct markers and a clean v5.0.0 control; witness W72/#894 independently replayed it ESTABLISHED AS CLAIMED. Grade stays ◐: only 0/1 byte past the arena, no real heap-neighbour object, pointer, control-flow diversion or execution. CVE-2026-19773 / ZDI-26-590, affected commit `b4b5aed3…`, fixed by `82415186…` in v5.0.0, CVSS 3.0 9.8 pre-auth. [Brief](reports/frontier-libwebsockets2shell.md) |
| **Pillow2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS + real-process counterpart** — a FlashPix image-contents colour ID maps to rawmode `LA` (2 bytes/pixel) at pinned `FpxImagePlugin.py:25/30/113/201`, so `decode.c:223/226` allocates a 64-byte tile buffer while an unrecognised JPEG mode makes `JpegDecode.c:220-221` set `JCS_UNKNOWN` and the unchecked `jpeg_read_scanlines` at `:252` writes a real 4-component 256-byte decoded row; ASan `WRITE of size 256` at `JpegDecode_v12.2.0.c:252` through the harness row-copy shim, fixed `13.0.0:247-253` rejects width/components before the scanline. Rung 4 is instrumented chosen `0x5a`/`0xa5` at offsets 0/16/32/48 for tile limits 16/32/48 and a guard-page fault; harness ASan sees the shim `memcpy`, not the host's uninstrumented libjpeg. A real-process lane opens a real OLE2/FlashPix file in Python + Pillow 12.2.0: a hardware watchpoint on the libjpeg store sees `0x00 → 0x5a` at `buffer+32` / `buffer+200` (byte chosen through JPEG coefficients), and an ASan libjpeg-turbo build reports an in-library `heap-buffer-overflow`, `WRITE of size 1` 0 bytes past the 128-byte tile `calloc` at `decode.c:226`, stack `null_convert` → `jpeg_read_scanlines` → pinned `JpegDecode.c:252`; 13.0.0 rejects before the scanline and is ASan-clean. A plain non-ASan 12.2.0 build then puts those bytes into live glibc heap data: the next chunk's size field goes `0x21 → 0x5a5a5a5a5a5a5a5a5a`, two live chunks at `buffer+144` and `+176` are crossed, 5/5 runs exit rc 139 (SIGSEGV in `PyGC_Collect()` at finalization) and `MALLOC_CHECK_=3` reports `corrupted double-linked list`; plain 13.0.0 raises `OSError` rc 1. CVE-2026-112398 / GHSA-5x8w-8jj5-q52h, `<13.0.0` → `13.0.0`, CVSS 4.0 9.2; harness 10 PASS / 0 FAIL, witness #879 ESTABLISHED at the INSTRUMENTED grade; witnesses #898/#900 returned ESTABLISHED AS CLAIMED at the W1 labeled grade. W3 identifies the chunk at `buffer+176` in the unmodified plain gdb run as a live CPython `PyUnicodeObject`: a hardware watchpoint on its `ob_type` last byte catches `0x00 → 0x5a` from `libjpeg.so.8` via pinned `JpegDecode.c:252`, after which `ob_refcnt` and `ob_type` read `0x5a5a…` — a chosen byte pattern, not a valid chosen address. W4 (`30e2ba1` / `1538199` / `944ad16`) drives distinct chosen bytes at distinct offsets through that same store: `case_ptr64.fpx` puts `0x11` at +128 and the **valid address** `0xa2d260` (`&PyCode_Type`) in the live object's `ob_type` at +184. Full snapshot/restore of the 896-byte past-end span exits clean; reapplying only the pointer faults in `Py_FinalizeEx()`; the non-GC `&PyLong_Type` `0xa3bf20` differential exits clean under identical isolation (GC-flag mechanism is an INFERENCE). 5/5 plain 12.2.0 runs exit rc 134 `corrupted size vs. prev_size`, fixed 13.0.0 raises `OSError` rc 1. W5–W7 (`fcd7e2f`/`a5447c4`/`6496bc8`/`2fc9e2f`) derive the fake-type address from the OOB-written `ob_type` instead of a fixed buffer offset: a gdb-staged forged `PyTypeObject` with a chosen `tp_dealloc` is reached by the interpreter's own finalization (3/3, with a matched real-`tp_dealloc` control that never hits it); W7 puts the whole 416-byte fake type and its pointer in the crafted image itself (`case_file.fpx` SHA-256 `5e336b88…`) and still reaches the marker 3/3 from `Py_FinalizeEx()` with a real-`tp_dealloc` control faulting instead. The owner of the 32-byte chunk at `buffer+144` stays UNKNOWN. No socket, injected code/ROP, PC write or ASLR leak; W5–W7 are author-only, keep the gdb snapshot/restore around the type and pointer slots, bake a brk address that depends on build/cwd/command line, and `load()` still raises `OSError` on the W7 image. W8 (`62cef9d`) adds `lab/pillow2shell/replay_forged_type.sh`, a self-checking replay for the three pending witness requests (#994/#995/#1004): 8 PASS / 0 FAIL / 3 INFO, the INFOs preserved negatives — in that invocation context the committed fixed-address `case_file.fpx`/`case_ctrl.fpx` and the W6 real-slot control do not reproduce (buffer moved `0xd32cc0 → 0xd345f0`), while `calibrate_file_case.py` + `forged_type_file_dyn.gdb` regenerate image-only cases for the current layout and still reach the marker from `Py_FinalizeEx()` with a real-slot control staying clean. W8 is a self-check, not an independent witness verdict. W3/W4 were replayed in W74 (#947) from the witness's own pinned builds, ESTABLISHED AS CLAIMED at the labeled grade; W4 stays a type-confusion fault, not chosen-code execution; grade ◐ unchanged. W9 (`249281e`) removes the baked heap address and gdb memory staging for the static-call lane: a 64x1 tile with a 47-wide 4-component JPEG writes one 188-byte row into the 128-byte tile buffer (60 bytes past), preserving static heap header words and setting only the low four bytes of a live `PyUnicodeObject`'s `ob_type` at `buffer+184` to `&PyCode_Type` `0xa2d260` (`case_min.fpx` `d0eb87b9…`, control differs only at bytes 184–186); with ASLR ON and no staged memory, `Py_FinalizeEx()` calls that type's runtime-read `tp_dealloc` 3/3 and `replay_min.sh` self-checks 8 PASS / 0 FAIL. The target is an existing static type's deallocator, not an arbitrary chosen address; no code injection, ROP, PC write, ASLR bypass or address disclosure. Witness #1048 replayed W9 from a clean `249281e` archive with its own build (8 PASS / 0 FAIL, marker 3/3, ASLR on) ESTABLISHED AS CLAIMED at ◐; its two non-material replay NITs were repaired at `f553b84` (an explicit `PILLOW_BUILD` now overrides the default CANON symlink and the control's false `HIT pc=` line is suppressed). W11 (`1c148e3`) preserves two bounded negatives for a debugger-free upgrade: a Python-level `ob_type` readback was not obtained (the `buffer+176` neighbour is an invocation-dependent live `str` — a `typing` docstring under the W9 `-c` command with gdb's ASLR-off default, a `tempfile` docstring under a script-file command with ASLR on; holding a reference perturbs the layout and post-decode/`atexit` object scans found no reachable object reporting the image-chosen type), and the capsule-destructor lane is blocked because ctypes capsules land in mmap arenas rather than beside the brk tile buffer while W9's 60-byte span stops short of the destructor offset; a survey of builtin static `tp_dealloc` slots found only ordinary free paths. Grade ◐ unchanged. Admitted 2026-11-21 under standing approval #6. |
| **DataSketches2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS + loopback service** — a crafted LIST-mode HLL sketch puts the attacker's coupon count at wire byte 6 and the coupon array at byte 8; pinned `CouponList-internal.hpp:101/116` (DataSketches C++ 5.2.0) copies `count * 4` bytes into the 32-byte eight-entry vector with only an input-length check, while fixed 5.3.0 rejects `couponCount >= 8` at `:102-108` before the copy. ASan `WRITE of size 256` from the library's own `memcpy` through public `hll_sketch::deserialize` (`HllSketchImplFactory.hpp:101` ← `HllSketch-internal.hpp:63`); count 255 writes 1020 bytes (988 past the region). Rung 4 is instrumented chosen `0x5a`/`0xa5`/`0x77` read back byte-exact at +32/+48/+64/+96/+128/+224/+255 under a page-aligned harness destination and a `PROT_NONE` rc 139 fault. A loopback service then reaches the same copy inside a real process: plain 5.2.0 overwrites the live top chunk's `size` at coupon+40 (`0xdbd1 → 0x5a5a…`) and the next 512-byte malloc aborts `malloc(): corrupted top size`; a benign count-2 image stays clean. Wake 2 patches that size to a plausible `0x1f000`: a following `malloc(0x1000)` returns a fresh chunk starting with the chosen `0x5a` and the next chunk's address shifts with the first allocation's size — relative steering only; normal ASLR changes absolute addresses, glibc rejects a `-1` top size, and no live victim sits above the top chunk. W74 replayed wake 2 (tape #922, commit `b95653e`) and wake 3 (tape #929, commit `e6e8b86`) from clean archives ESTABLISHED AS CLAIMED at the labeled grade: wake 3 measured a pre-existing typed victim `0x119a0` bytes *below* the coupon buffer, unreachable by the forward copy (negative), while a post-deserialization `PodRequest` takes eight chosen bytes per field through the carve (positive), with no call through any overwritten field. Wake 4 (`fa551e9`) grooms tcache so a live `LiveVictim.callback` sits at coupon+48; a count-18 72-byte copy preserves the chunk size and diverts the callback to `benign_marker3`, and a genuine indirect call through the library-written field reaches that marker (`BENIGN_MARKER3_EXECUTED`, service rc 0, 4 PASS / 0 FAIL, benign count-2 control clean). Conditions in wake 4: synthetic loopback consumer built `-no-pie -O0`, consumer-side grooming, stable lab-only marker addresses, no real deserializing application, ASLR-defeating leak or attacker-chosen code. Wake 6 (`cc9ba4d`/`aa9ebe8`) identifies a shipped deserializing consumer: pinned PostgreSQL extension `56d8712` calls `hll_sketch_deserialize` on a client `bytea` (`hll_sketch_pg_functions.c:176/:353/:370`); `bash lab/datasketches2shell-pg/run.sh <outdir>` on a loopback PG 16.4 sends four images, all return estimates, and gdb at pinned `:116` shows chosen `0x5a` in palloc memory (including an assertion-build sentinel) with no crash, pointer or diverted call; rebuilt against fixed 5.3.0 the count-64 image errors `couponCount >= capacity`. The glibc top-size/tcache lanes do not transfer to palloc; the real-app grade is unchanged and wake 6's palloc observation was replayed from a clean archive by the author (`abda01f`). Wake 8 (`df670d1`/`abda01f`) compiles the shipped Python 5.2.0 `hll_sketch.deserialize` binding against the pinned headers: `bash lab/datasketches2shell-py/run.sh <outdir>` gave 9 PASS / 0 FAIL with five library plus two binding pins verified, ASan `WRITE of size 72` at pinned `CouponList-internal.hpp:116` through `hll_wrapper.cpp:100`, and gdb `p+32`/`p+40` glibc chunk metadata `0x79`/`0x21 → 0x5a5a…`; counts 18/64 abort in interpreter shutdown (rc 134/139), fixed 5.3.0 raises `ValueError` before the copy, and a clean-archive author replay matched. The input is a local `bytes` object, not a socket; no chosen pointer, leak or call-through was seen. W81 #1023 replayed wake 8 from a clean `git archive abda01f` — 9 PASS / 0 FAIL, five library plus two binding pins, the same ASan WRITE 72 and `0x79`/`0x21 → 0x5a5a…` metadata, fixed 5.3.0 `ValueError` — ESTABLISHED AS CLAIMED at the labeled real-consumer availability-only grade (non-material NIT on allocator-diagnostic wording, which varies by layout). Wake 9 (`77a6bc6`/`5af11ee`) drives the same copy from a `std::istream` overload in `lab/datasketches2shell-stream/run.sh`: 10 PASS / 0 FAIL, five pins, both five-run groups `sha256=cbf27763…25066`, ASan `WRITE of size 256` at pinned `CouponList-internal.hpp:162` via public `deserialize(std::istream&)` (count 255: `WRITE of size 1020`, 988 past), chosen bytes at +32…+255, `PROT_NONE` rc 139, clearing the COMPACT flag `0x08` gives `rv=ok` (causal control), fixed 5.3.0 rejects; W81 #1016 replayed it from a clean archive ESTABLISHED AS CLAIMED at the socket-free-harness grade. No new real consumer, pointer, leak or grade change. CVE-2026-103501 / GHSA-w656-xfm5-jqjh, affected `<= 5.2.0` → 5.3.0, CNA moderate vs CISA ADP 9.8 CRITICAL; harness 11 PASS / 0 FAIL, witnesses #889/#911 and W74 #922/#929 ESTABLISHED AS CLAIMED at the labeled grade; W75 (#951) replayed wake 4 from a clean archive ESTABLISHED AS CLAIMED at the lab-build-only grade. Grade ◐ unchanged. [Brief](reports/frontier-datasketches2shell.md), [consumer](../reports/datasketches2shell-loopback-consumer.md) |
| **RabbitMQC2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS + socket-fed service** — a caller-chosen oversized `AMQP_FRAME_BODY` length at pinned `amqp_connection.c:467` (rabbitmq-c 0.16.0) makes the verbatim upstream `memcpy` write that many attacker bytes into the 65536-byte outbound frame buffer allocated at `:140`, reached through public `amqp_send_frame()` at `:531` → `:548`; ASan `WRITE of size 200000`, fixed released 0.17.0 rejects at `:467-473` before the copy. Rung 4 is instrumented chosen `0x5a`/`0xa5` byte-exact at +65536..+69632 under a page-aligned `realloc` interposer and a `PROT_NONE` rc 139 fault. A separate socket-fed service on plain pinned 0.16.0 (no interposer) sends the oversized body over a local `AF_UNIX` socket: ASan reports the library-allocator `WRITE of size 200000` at `amqp_connection.c:467`; under gdb the live neighbour at `outbound+65552` is `state->socket` with vtable `<amqp_tcp_socket_class>`, and chosen bytes replace its `klass` pointer. With a reusable 200000-byte receive buffer and a 65600-byte body carrying a fake vtable plus the body address, the library's own path at `amqp_socket.c:92` calls a benign `marker_send` (`MARKER: controlled vtable call reached`, rc 0). A matched-pair probe (`lab/rabbitmqc2shell/run_mmap_threshold.sh`, 2 PASS / 0 FAIL) shows this marker requires the 200000-byte body to be mmap-backed: under glibc's default 131072-byte threshold the chosen bytes hit the live `klass`; with `MALLOC_MMAP_THRESHOLD_=300000` the same 65600-byte body is brk-backed and only corrupts heap metadata (`invalid next size`, abort), with no marker. Fixed 0.17.0 returns `AMQP_STATUS_BAD_AMQP_DATA`. Conditions: synthetic local service, lab-only address file supplying addresses (simulated disclosure), benign marker — not a shipped-product exploit; no real messaging application, remote listener or address-disclosure primitive. A consumer-reality measurement narrows that UNKNOWN: the shipped `tools/publish.c` uses `amqp_basic_publish`, which chunks every body frame to `frame_max - 12` (`amqp_api.c:167-168`, `:223-241`) inside the exact `frame_max` buffer (`amqp_connection.c:108-142`), so no high-level body can reach `:467` past the buffer; an unmodified ASan `amqp-publish` against a loopback broker front end negotiated `frame_max=131072`, split a 200000-byte body into BODY frames of 131060 + 68940 bytes and exited rc 0 with no ASan report (11 PASS / 0 FAIL). The witness-verified direct-`amqp_send_frame()` result stands; a named candidate, FFmpeg 7.1's AMQP output, was checked against published source and uses `amqp_basic_publish` with BODY frames chunked to `frame_max-12`, putting it on the safe side of `:467`; other real frame-level proxies stay UNPROVEN. CVE-2026-61547 / GHSA-hfjv-vcp3-39wh, `<0.17.0` → 0.17.0; harness 10 PASS / 0 FAIL, service probe 8 PASS / 0 FAIL; witness W73 (#914) ESTABLISHED AS CLAIMED at the harness grade, W74 (#946) replayed the socket-fed service from a clean archive ESTABLISHED AS CLAIMED at that grade (byte-exact `klass` overwrite, library-path `marker_send`; address disclosure still simulated by a lab file). [Brief](reports/frontier-rabbitmqc2shell.md), [consumer](../reports/rabbitmqc2shell-consumer-loopback.md) |
| **HnswLib2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS + loopback service** — a crafted HNSW index sets `cur_element_count` (512) above the stored capacity (2) at pinned `hnswalg.h:728-729` (hnswlib v0.9.0); `:776` allocates 256 bytes while the library's own `std::istream::read` at `:779` writes 65472 attacker bytes, reached through the ordinary `HierarchicalNSW(space, path)` load constructor. ASan `WRITE of size 65472` at `:779`, unsanitized load aborts; rung 4 is instrumented chosen `0x5a`/`0xa5` byte-exact at +0/+32/+64/+128/+256/+512/+1024/+4096 past the real level0 buffer. A loopback-only service (`6445c8a`) accepts an index file on 127.0.0.1 and calls that constructor: ASan inside the service reports the `WRITE of size 65472` at pinned `:779` into the real `:776` region (no interposer), and on plain glibc the real top-chunk size at `dst+264` becomes chosen `0x1122334455667788` from file bytes; a capacity-fits index is clean. A further tcache-groomed lane (`2a271d3`) places a live `CacheEntry` immediately after the reused chunk: `callback` changes `0x4041be → 0x4041fb`, `magic`/`refcount` read back byte-exact, and `BENIGN_MARKER3_EXECUTED` is reached through the overwritten field. Conditions: synthetic loopback consumer built `-no-pie -O0 -g`, consumer-side grooming, the call invoked from gdb at the post-read stop (not a natural path), downstream allocator abort, and the fixed side an unmerged PR #677 head; the crafted-index digest is build-layout-specific (`a3a20f6f…` author, `2f17ee97…` witness), not a portable pin. No third-party consumer, natural call-through, shell, PC or chosen-code execution. CVE-2026-124959; fixed side is **unmerged PR #677 head** `280cb597…`, not a released version; 9 PASS / 0 FAIL; W73 (#913) replayed the harness grade and W74 (tape #948) replayed both service and live-object claims ESTABLISHED AS CLAIMED at the labeled grade. [Brief](reports/frontier-hnswlib.md) |
| **Asn1scc2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS + loopback service** — a 3-bit wire size `111` for `SIZE(0..5)` decodes as 7 because pinned vulnerable `asn1crt_encoding.c:819-822` (asn1scc 4.6.0.17) omits `uv > range`, which generated `schema.c:58/:59` assigns to `nCount` and copies through `BitStream_DecodeOctetString_no_length` (`:1449`) into a 5-byte array; ASan `WRITE of size 1` 0 bytes after a 9-byte region at `asn1crt_encoding.c:400`, fixed released 4.7.0.1 rejects at `:821-822`. Rung 4 is instrumented chosen `5a`/`a5` patterns byte-exact at +5/+6 and a `PROT_NONE` rc 139 fault. A loopback consumer check (`9628731`) measured both sides: with the pinned `SIZE(0..5)` type and a natural `malloc(sizeof(Payload))` the two past-array bytes land in 3 bytes of struct tail padding, ASan is clean and the next chunk's size field is untouched (NEGATIVE, preserved); the frontier staging `malloc(9)` still reproduces the ASan `WRITE` through the real socket. With a generated `SIZE(0..17)` variant (`sizeof=24`, no slack), a natural allocation and hostile count 31 put two distinct chosen values byte-exact in the live next-chunk size field (`0x20d51 → 0xa55aa55aa55aa55a`), with the fixed 4.7.0.1 runtime clean (its wrapper still returns `ok=1`, so do not claim wrapper rejection). The corrupted size is consumable (`ab30ea2`, W78 #967): `bash heap-chain.sh` changes a neighbour's size `0x21 → 0x41`, `free(B)` then `malloc(56)` returns an overlapping chunk and a store through it changes live `C->nCount`/`C->arr[0]` byte-exact, while fixed 4.7.0.1 leaves the layout intact. A loopback `pointer-target.sh` (`2de7032`) puts a function pointer at `Session+24` just after the generated object: wire bytes set `handler` to a benign `marker()` address in a `-no-pie` lab build and the call prints `MARKER: control-flow diverted to chosen address` (gdb watch shows the pinned runtime's store; fixed 4.7.0.1 keeps `safe_handler` and prints `SAFE`). Result 5 (`6dd93c4`/`b8b20c6`) removes the hard-coded non-PIE address: with `-fPIE -pie` and host ASLR on, a diagnostic-shaped 16-bit handler leak plus only two wire bytes (count 22) advances the live handler's low 16 bits by the binary's `nm` delta `0x1a` to a benign marker across five distinct PIE bases, with the canary and upper 48 bits intact; fixed 4.7.0.1 stays safe, a `delta=0` counterfactual stays safe, and W74 #980 replayed it from a clean archive ESTABLISHED AS CLAIMED. Results 1–5 now all have independent replays (Result 3 W78 #967, Result 4 W74 #974, Result 5 W74 #980). Still UNKNOWN: any real ASN.1-speaking application, full-address write, leak in such an application, shellcode or chosen-code execution; pointer control and benign marker execution are LAB DEMONSTRATED under the constructed layout, not observed in a real consumer; the pinned `SIZE(0..5)` padding NEGATIVE and the different-schema caveat stand. W74 (#943/#944) replayed both the frontier brief and this consumer check from clean archives ESTABLISHED AS CLAIMED at the labeled grade (12 PASS, eight pins, chosen bytes in the live next-chunk size field, fixed 4.7.0.1 ASan-clean with the wrapper still `ok=1`). CVE-2026-75614 / GHSA-825c-7h77-2jjq, CVSS 8.1, `<4.7.0.1` → released 4.7.0.1; 12 PASS / 0 FAIL, digest `e39fec33…`. [Brief](reports/frontier-asn1scc.md), [consumer reality](../reports/asn1scc2shell-consumer-reality.md) |
| **Iec618502Shell** | ✓ | ✓ | ✓ | ◐ | ✓ | **LIVE/CODE** — an unauthenticated MMS Initiate size 1 at pinned `mms_association_service.c:359-363` (libIEC61850 `a1396111`) makes `mms_file_service.c:834` wrap `maxPduSize - 20` to `0xffffffed`, so `:844` picks the whole staged file and `:872` writes it into the 65100-byte `sendBuffer` at `iso_connection.c:516`; real stock ASan server on 127.0.0.1 reports `WRITE of size 178157` 0 bytes after that region, frames `:872` ← `:896`, fixed released v1.6.2 adds `MMS_MIN_MAX_PDU_SIZE 128`. Rung 4 (witness-verified) is chosen-value control of a live pointer field with wire readback in the real unsanitized server: `bash lab/frontier/libiec61850/r4_pointer.sh <outdir>` gives 11 PASS / 0 FAIL; remotely staged bytes set `CotpConnection->socket` and `socketExtensionBuffer` so gdb logs `=== CHOSEN SEND self=0x7ffff0029180 buf=... size=16 ===` and the loopback client receives ASCII `IEC61850-R4!` (and live `main` code bytes in a second case). Conditions: pinned vulnerable build, gdb with ASLR disabled, unauthenticated Initiate size 1, ObtainFile staging, stock glibc, real fd 4; both cases SIGABRT after the send. A conforming `poc/exploit_client.c` on fixed v1.6.2 fails `MmsConnection_connect()` and sends no FileOpen/FileRead, so the earlier raw-client AARE-reuse bypass is harness-specific (preserved) and the released fix is a clean control on this route. A third probe (`167e5db`/`6eeee8e`): `bash lab/frontier/libiec61850/r4_control.sh <outdir>` gives 12 PASS / 0 FAIL rc 0 and, in the live unsanitized server, a staged fake `ByteBuffer` turns a second loopback TPKT frame into eight chosen bytes in a measured live stack return slot, with `=== MARKER HIT … ===` / `R4_MARKER_EXECUTED` observed before the server faults. The marker comes from an `LD_PRELOAD` object, not attacker-supplied code; the probe snapshots 120000 bytes of heap and asserts this host's gdb/ASLR-off addresses at run time. Witness #962/#984/#982 replayed all three probes from a clean archive, all ESTABLISHED AS CLAIMED at the labeled grade. A fourth lane (`a77cecc`, `bash lab/frontier/libiec61850/r4_real.sh <outdir>`, witness #1127 ESTABLISHED AS CLAIMED) removes `LD_PRELOAD`: in the live unsanitized server a single wire-supplied six-word chain over the measured return slot calls stock libc `pop rdi; ret`, `pop rsi; ret`, then real libc `write` on the already-connected fd 4 with a chosen heap buffer — gdb logs `READBUF … fd=4`, `ROP rip=0x7ffff7d0f84b` and `WRITE fd=0x4 … len=0x34`, and the client reads back 52 bytes starting `49454336313835302d523421` (`IEC61850-R4!`) — then real libc `exit` (13 PASS / 0 FAIL, 6/6 pins, staged payload `4d2ec794…`). Gadget and libc offsets are measured on this host with ASLR disabled; `rdx` happens to hold the frame length. Negatives preserved: the verbatim PIE's R-X segment has no clean pop gadgets, and a `leave; ret` pivot through the corrupted saved RBP faults. This is chosen real behaviour without injected code, not attacker-supplied code, ASLR defeat, persistence or RCE. Still UNKNOWN: chosen-code execution, ASLR defeat, persistent control, RCE and an ASLR-defeating read primitive in an ordinary non-gdb deployment. R5 is witness-ESTABLISHED (#1127): `bash lab/frontier/libiec61850/r5_system.sh <outdir>` makes the wire chain call real libc `system` on an ObtainFile-staged command, with a target-written marker, marker-absent fixed/safe controls and a varied-command side effect; ASLR-off and host-measured offsets are required. An ASLR-on replay is a measured structural negative (`bc7b5ee`): a copy with `set disable-randomization off` in both gdb blocks gives 10 PASS / 5 FAIL and no marker — Phase A's `system=0x71a926658750` is unmapped in Phase B, and an observation variant shows a base slide of `0x40378000000` with the fake buffer missing the return slot; the same-wake canonical control gives 15 PASS / 0 FAIL with marker. ASLR-on with an attacker-derived base stays UNKNOWN. CVE-2026-49035 / CISA ICSA-26-204-06, `>=1.0.0 <=1.6.1` → released v1.6.2; 7 PASS / 0 FAIL, digest `5a7bb690…`. [Brief](reports/frontier-libiec61850.md), [rung-4 probe](../reports/iec618502shell-r4.md) |
| **OpenJpeg2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS + shipped-library consumer** — a TLM-declared one-entry 24-byte `tp_index` meets an unbounded SOT `TPsot=1`; pinned `opj_j2k_read_sod` (`j2k.c:5086/:5088`, OpenJPEG 2.5.4) stores two 8-byte codestream offsets at allocation base +32/+40, 8/16 bytes past the region. ASan `WRITE of size 8` at `j2k.c:5086` through the real `opj_decompress` chain; fixed master pin `91d08b11` (no tagged release) guards both stores and is clean. Rung 4 INSTRUMENTED/PARTIAL: chosen 64-bit stream offsets byte-exact at +32/+40 in staged heap (PoC 157/159, pad-tuned 541/543). The shipped Pillow 12.2.0 wheel bundles libopenjp2 2.5.4: `Image.open().load()` on the public and padded PoCs aborts rc 134 `corrupted size vs. prev_size`, benign image rc 0, and a pinned-source build under Pillow reports ASan `WRITE of size 8` at `j2k.c:5086` with a `Jpeg2KDecode.c:794` → `Image.load()` stack (15 PASS / 0 FAIL, trace `4903f4dc…`). The consumer-reality replay sees the offsets land on a live neighbouring `tp_index` object and a live malloc size word; a COM-padding sweep (5 PASS / 0 FAIL, trace `2c4ca81d…`) chooses the resulting glibc `free()` path. The Pillow W9 chosen-deallocator lane does not transfer: this sink writes seek offsets, not arbitrary bytes, and tuning one to a static code address needs a roughly 10.6 MB padded stream. A separate live-object lane (`cad1baf`, `4df17d7`) finds a live Python object exactly on the TPsot=1 destination (`ob_refcnt=1/2`, `ob_type=&PyCode_Type`/`&PyUnicode_Type`); the two stores overwrite both fields and a codestream-tuned value puts the exact static pointer `0xa3bf20` (`&PyLong_Type`) into `ob_type` with ASLR on (4 PASS / 0 FAIL, trace `769e135e…`). The plain consumer outcome is layout-dependent — rc 0 `LOAD_OK` silent type confusion in one build, rc 134 in a clean archive — with no indirect call in that lane: the companion `ob_refcnt` store is a SOD offset, so no natural dealloc occurs there (a later gap-aligned lane does, below). Large `TPsot` is reachable after sequential tile parts (`j2k.c:4494`, `make-large-tpsot.py`): with `evil=188` the sink was hit at TPsot 188 and stored a chosen code-shaped value `0x58530e` at base+4520 (`0x585310` at +4528) in the debug build; neighbouring code pointers shifted under ASLR and the plain run only faults rc 139. The 24-byte stride leaves `base+24k..+7` untouched, so a gap-aligned live object with small `ob_refcnt` was proposed as a natural-deallocator route; its first "unreachable" negative (`66965f6`) is RETRACTED (`f6d026f`) because a clean-archive replay found a reachable gap object at `24*30` (`ob_refcnt=1`, `&PyCode_Type`). The real obstacle is the second condition: forcing `SOD_k = chosen static address` moves the first gap object out of range (21-alignment sweep found no coincidence; placement is cwd/argv-sensitive), and `b95c579` records the arithmetic constraint that `SOD_k` shifts 14 bytes per tile part, so with an 8-byte-aligned pad the written value is 8-byte aligned only when `k % 4 == 0` — the reachable object at `k=30` gives `SOD_30=0xa3c134` (4-byte aligned, not a valid object pointer). `gap-reach.sh` now reports per-layout `min_gap_index` and reachability rather than asserting an outcome; a natural call through a chosen deallocator was later measured (`a351c20`, `bash lab/frontier/openjpeg2shell/chosen-call.sh <outdir>`, 7 PASS / 0 FAIL, trace `ab46a561…`, clean-archive replay `db68ebea…`): COM pad 10,731,137, tile part 59 overwrites a live object's `ob_type` with `&PyCode_Type`, tile part 154 writes `&PyDict_Type` (`0xa3d840`) into the `24*154`-aligned object whose `ob_refcnt=1`, and natural finalization calls that type's `tp_dealloc` at `0x575cb0` under ASLR on (not the original type's `0x54e700`); the intermediate caller is UNKNOWN — the author's trace labels it `PyGC_Collect`, the witness's backtrace resolves only `Py_FinalizeEx`. It is a call to a chosen *existing* static type's deallocator with a type-confused body, not attacker-chosen code; no marker, execution or listener, and the debug `-g -O0` layout is not the shipped one. A later GOT-target variant (`f61644f`, `53b75c4`) makes the same finalization call jump to the unresolved `system` PLT stub held in the codestream-chosen GOT slot (`CHOSEN_CALL pc=0x4206c6` in the checkout) with a NUL argument; 9 PASS / 0 FAIL in the checkout and from a clean archive, layout-dependent trace hashes, and the run is stopped at the stub before `system()` runs. Pointer-value control and control-flow diversion to a chosen existing deallocator or a fixed GOT slot are measured rung-4 results; what stays UNKNOWN is an attacker-chosen argument, execution of chosen code, a web-facing listener and any arbitrary-address dereference (the observed dereference is of a fixed GOT slot in the known non-PIE interpreter, derived from its own relocation table). The earlier "remaining gap" paragraph in the brief is superseded. Rung 4 stays PARTIAL at the INSTRUMENTED grade. Witness #955/#958 (harness) and #1022 (consumer reality) ESTABLISHED AS CLAIMED at labeled grades; #1151 independently ESTABLISHED both later rung-4 limbs — #1144's natural chosen-type call (six core invariants replayed; one non-grade-changing `LOAD_OK` harness nit on the witness layout) and #1149's GOT-target call (9 PASS / 0 FAIL) — at their labeled scope. Both documented plain outcomes are now exercised: checkout `corrupted size vs. prev_size` and a clean `git archive 091488e` replay with `PLAIN_OUTCOME LOAD_OK` (7 PASS / 0 FAIL, trace `25542f54…`), each with an unchanged invariant trace. The transfer, live-object and large-TPsot lanes remain author-only. [Brief](reports/frontier-openjpeg2shell.md) |
| **WolfSsl2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS + loopback consumer** — a `word16` truncation in pinned `Dtls13GetAckListLength` (`dtls13.c:2550`, wolfSSL v5.9.0) declares 16 bytes for 4097 ACK record numbers (exact 65552); `Dtls13WriteAckMessage` sizes a 31-byte region via `CheckAvailableSize` then emits 16 bytes per record with `c64toa` of sender-chosen epoch/seq at `:2604`/`:2606` (ASan `WRITE of size 8` in `misc.c:1010`). Tagged fixed v5.9.1 caps records at 128 and is clean. Rung 4 INSTRUMENTED: chosen epoch `0xc0ffee1122334455` and seq patterns read back byte-exact at offsets 31/47/63/159 in staged non-ASan heap. A real DTLS 1.3 server on verbatim pinned v5.9.0 bound to 127.0.0.1 completed a real client handshake (`accept_ret=1 … unified=1`, record version `fefc`). An earlier 4100-KeyUpdate attempt was gated (446 `Dtls13RecordRecvd` hits, only 2 ACK writes, same-port injection artifact excluded); a later wire-driven run (`8636e5d`) paces 4097 distinct loopback handshake fragments through real `Dtls13RecordRecvd` to `ack_count=4097` with no intervening flush and ASan `WRITE of size 8` at `c64toa misc.c:1010` via `Dtls13WriteAckMessage:2604` ← `SendDtls13Ack:2899` ← `Dtls13RtxTimeout:2748` ← `wolfSSL_accept`; tagged fixed 5.9.1 caps at 128 and is clean. Conditions: lab flags `early13`/`unified_seen` and paced fragments; the peer-set unified-header variant (`fde4360`) peaked at 3991/3983 without wrap and is preserved as a negative. The natural fill route is structurally wilderness-only: `CheckAvailableSize` grows the ACK output buffer at `:2588` immediately before the write, so all 65552 chosen bytes land in the glibc top chunk (no tcache/fastbin `fd`/`bk`), and glibc 2.39 top-size sanity checks rule out the classic House-of-Force follow-up; the plain run exits 0. A lab-only pre-grown output buffer (`pregrow=64`, modelling a server that has already sent a flight) puts the 4097 `seenRecords` nodes after the buffer, inside the overflow path (`45d3041`): at `dtls13.c:2613` sender-chosen sequence bytes overwrite a live node's glibc chunk size (`0x21` → e.g. `0x008f000000000000`) and its `next` pointer (→ NULL), and the real `Dtls13RtxFlushAcks` free path at `:780` aborts `double free or corruption (out)` rc 134 with a full symbolized chain through `wolfSSL_accept`. A chosen `seq_base=0x20ffffffff71` writes a plausible aligned size `0x2100` but `next` stays NULL and cleanup still aborts (`!prev`); across three sender bases every size low byte is zero and every `next` is NULL — a measured ceiling on this build (`8fd20f5`). Rung 4 moves from INSTRUMENTED to **ESTABLISHED FOR AVAILABILITY IMPACT** (matching the advisory's `VA:H`) under four reported preconditions (`early13`, `unified_seen`, `pregrow=64`, 4097 paced fragments); the tagged v5.9.1 `pregrow=64` control shows no abort in the observed window. No pointer diversion, arbitrary write, benign marker call or execution was observed; rung 5 stays UNKNOWN. CVE-2026-6679 / GHSA-c9q2-5c67-xg9p, pre-auth network claim; witness #985/#992 ESTABLISHED AS CLAIMED at the labeled grades, the loopback lanes are author-only. [Brief](reports/frontier-wolfssl2shell.md) · [Consumer](reports/wolfssl2shell-consumer-reality.md) |
| **Htslib2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS + real-file consumer** — a CRAM v4 compression header drives `hdr->ncodecs` past 511, so pinned `cram_codecs.c:1378` reads and `:1388` writes `slice->block_by_id[512 + codec_id]` (HTSlib 1.23.1, `codec_id=1` → index 513 into a 512-slot array allocated at `cram_io.c:4620`); ASan `READ`/`WRITE of size 8` 8 bytes after a 4096-byte region, fixed tagged 1.24 removes XPACK/XRLE and rejects codec 51. A genuine CRAM v4 file made with htslib's own writer (`realfile/base.cram` `b57f4386…`, `crafted.cram` `992c43d8…`) reaches the sink from file bytes in a real `htsfile` consumer: ASan `READ of size 8` at `:1378`, `WRITE of size 8` at `:1388` and a third `READ` at `:1417`, stack `cram_decode_seq:1616` → `cram_decode_slice:2918` → `sam_read1:4273` → `htsfile.c:92`; identify mode without `-c` is the preserved negative. The inherited claim that the unsanitized library performs the same OOB **write** is retracted for the `codec_id=1` file: on a plain build that slot holds a non-NULL chunk-size word (`0x1011`, `0x61` in the parser harness), so `:1379` early-returns without writing and plain `htsfile` segfaults at `:1422` rc 139 — the ASan WRITE fires only because the redzone reads zero. A second file, `crafted2.cram` (file-derived `codec_id=2` via BF before QS, no gdb edit), does fire the unsanitized pointer store on a plain build: index 514 reads the NULL user-data word of the following live chunk, `:1379` passes and `:1388` stores a freshly allocated `cram_block *`; an LD_PRELOAD allocation trace identifies the overwritten neighbour as the same `cram_slice`'s live 4096-byte `s->cigar` array (`cram_io.c:4633-34`). Consumer order caps this record shape: the QS decode at `cram_decode.c:1616` precedes the CIGAR generation at `:1776-1813`, which rewrites the corrupted entries before `bam_set1` reads them. The whole-file 1.24 control is invalid for these files (container CRC failure even on `base.cram`); only the harness-level codec-51 rejection is clean. Rung 4 INSTRUMENTED only: no chosen pointer, consumed neighbour, control flow or execution; the index-1025 and CIGAR-consumer negatives are preserved. CVE-2026-62257 / GHSA-6q7c-m967-9v37; 10 pins, 9 PASS / 0 FAIL, trace `42c561cd…65a94798a54` after the rung-1 PASS-label correction; witness #1008/#1044 ESTABLISHED the harness claim with an exact trace, #1036 the rung-1 correction and #1053 the crafted2 codec_id=2/514 plain-build store; the real-file CIGAR-neighbour and consumer-order lanes remain author-only. [Brief](reports/frontier-htslib2shell.md) |
| **CivetWeb2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — a 9059-byte request (`GET /` + 9000 `/` + `d?q=1`) against pinned CivetWeb v1.16 collapses through `remove_dot_segments` to the real directory `/d` while the raw 9002-byte path fills an 8197-byte `mg_malloc` allocation sized at `civetweb.c:15247–15253`, so the redirect `strcat` at `:15261` writes `?\0` 0 bytes past the region. ASan `WRITE of size 2` in `handle_request` through the real 127.0.0.1 listener; fixed **merged commit** `c584455` (not a tagged release) is ASan clean and returns 301. W1 (`3849f9a`, repair `b9bd4ee`) observes attacker-chosen query bytes in a live adjacent 4096-byte canary under an instrumented copy: chunk-delta adjacency, full-query byte 8 (`G` in `q=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`) at canary offset 0, 30 chosen body bytes plus the null at offsets 0–30 for that query and 32 `C` bytes for a 50-byte query; the canary size field is also overwritten and `mg_free` aborts after the 301. The default fortified build instead aborts in `__strcpy_chk` with `destlen=0` before chosen bytes land, and `-U_FORTIFY_SOURCE` gives glibc `malloc(): invalid next size`. The earlier instrumented-only/availability-only ceiling is superseded by unmodified-build measurements (`f6c542a`, `cb75a02`): natural heap adjacency and a chosen-byte overwrite of a live heap header were measured in the shipping build, not an instrumented copy. No chosen pointer, control-flow diversion, execution or RCE, and a 2026-11-21 GitHub API read found no tagged fixed release (newest tag v1.16, vulnerable). CVE-2025-55763; 4 pins, 23 PASS / 0 FAIL, trace `2ecaac75…e2d50`; witness #1026 (W81, clean archive, exact trace) and #1027/#1029 ESTABLISHED AS CLAIMED at labeled grades. #1050 had marked the W1 limb UNKNOWN-WITH-MISSING-EVIDENCE; `run-rung4.sh` and the raw logs are now committed (19 PASS / 0 FAIL, trace `6678d7a9…e0be3d2`), and W87 (#1102) independently replayed the unmodified-build header lane from a clean archive with exact 13 PASS / 0 FAIL trace and chosen live heap-header bytes: rung 4 ESTABLISHED at INSTRUMENTED, no grade change. [Brief](reports/frontier-civetweb2shell.md). |
| **Open625412Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS** — an authenticated OPC UA `TransferSubscriptions` on hash-pinned 1.5.4 memcpys the whole `UA_Subscription` (`ua_services_subscription.c:599`) but migrates only `monitoredItems` (`:619-627`), leaving PUBLISH-sampling items' `le_prev` in the old subscription; its deferred free (`delayedFreeSubscription:277`) leaves an 8-byte `LIST_REMOVE` WRITE into freed memory at pinned `ua_subscription.c:1645` in `UA_MonitoredItem_unregisterSampling`, reached through real `Service_CreateSubscription` / `CreateMonitoredItems` / `TransferSubscriptions` / `DeleteMonitoredItems` calls. Tagged fixed 1.5.6 re-inits and reinserts the sampling list at `:629` and runs the same sequence clean. Rung 4 INSTRUMENTED: a live neighbour and non-NULL pointer overwrite are observed (`17de7c0`, `f167900`) — the stale `LIST_REMOVE` writes byte 200 of a live replacement subscription; with two items its head changes from `0x514000000840` to `0x514000000440`, an item owned by the still-live transferred subscription (`crossSubscription=1`); written values come from created objects, not attacker-chosen bytes, and no diversion or execution was seen. A wake-3 dereference probe (`d2d57d6`, `bash lab/frontier/open625412shell/deref.sh <outdir>` after `run.sh`, 14 PASS / 0 FAIL, trace `0f2a2d7e…`) shows the server's real `sampleAndPublishCallback` dereferencing that groomed monitored-item pointer and enqueuing a notification from it (live queue length 4 → 5) under real `processEntryCallback` → `UA_Timer_process` frames, with clean skip-delete and fixed 1.5.6 controls; the written value is a live object pointer selected by the create/transfer/delete ordering, not chosen bytes, and no diversion or execution was observed. A measured R5 structural blocker is recorded in `c126d60`: no listener or wire input (contract 1), no attacker-chosen command (contract 2), no command path for differentials (contract 4), so contracts 3/5/6 are not reached; the primitive cannot be extended to command execution on this build without a new chain. PR:L is a real precondition and the ZDI RCE language stays a claim. Stand-ins and lab conditions: permissive `allowTransferSubscription` consent hook, a harness-forced `UA_Subscription_delete` followed by event-loop-driven deferred free, ASan quarantine disabled for same-chunk recycling, a client queue-size setting of 10 and a callback-isolation step; no listener or off-process traffic. CVE-2026-126962 / GHSA-x8hf-mwqg-74x6 / ZDI-26-990; six pins, 8 PASS / 0 FAIL, trace `31e535b9…71284`; operator admission replay ~17:49Z; witness #1066 replayed rungs 1–3 and #1120 independently replayed the wake-3 dereference trace (14 PASS / 0 FAIL, exact trace), ESTABLISHED at rung 4 INSTRUMENTED; R5 stays structurally blocked. [Brief](reports/frontier-open625412shell.md). |
| **KnotResolver2Shell** | ✓ | ✓ | ✓ | ◐ | ◐ | **CODE/HARNESS — rung 3 ESTABLISHED, rung 4 witness-ESTABLISHED (#1138); rung 5 author-observed, witness W114 MIXED** — hash-pinned tagged Knot Resolver 6.4.0 `pers_inbuf.size += datalen` at `daemon/quic_conn.c:107` drifts tracked capacity above the realloc target; unbounded `memcpy`s at `:120`/`:124` and no FIN consistency check at `:133–136`. Tagged v6.4.1 adds an offset assert `:158–161`, `wire_buf_reserve()` `:166–203`, a free-space/`malformed` check `:216–224` and a FIN size check `:229–238`. CVE-2026-66374 (MITRE 2026-07-25, CVSS 8.1 `AV:N/AC:H/PR:N/UI:N/S:C`); six STREAM frames against a loopback-only ASan 6.4.0 DoQ listener give ASan `WRITE of size 1198` at `quic_conn.c:124` past a 5762-byte `realloc` at `:103`, with a downstream READ in `wire_buf_movestart`; identical bytes on tagged 6.4.1 are rejected `malformed` with no ASan report ([rung-3 report](reports/knotresolver2shell-rung3.md)). DoQ is beta and non-default. On this host (jemalloc 5.3.0, gnutls 3.8.3) the 6144-byte neighbour slot geometry holds but the published dispatch offsets do not (`5a6ebab`): the live neighbour resolves to a kresd-owned `ngtcp2_pktns`, not the reference gnutls cleanup handler, and the reference RIP/RDI marker never fired — a bounded negative for those offsets, not a proof that no layout works here. `5f850fc` then placed chosen `0x4141414141414141` in a live function pointer (`ngtcp2_ksl_range_compar` at `slot1+0xa0`) with a coherent ksl; the write is deterministic, but a read watchpoint and a post-F6 `ksl_insert` trace recorded no call through it and the second ksl lies beyond the reachable span. Wake 4 (`3ddc2fc`) reached both live `ngtcp2_pktns` ksl `compar` fields — the gap ksl at `slot1+0xa0` and the extended `acktr.ents` ksl at `slot1+0x3e0` — with coherent root/front/back/search and chosen `0x4141414141414141`; a second active QUIC connection before or between frames and hardware read watchpoints on both fields gave no dispatch, no watchpoint hit and a live kresd, and scaling `pers_inbuf` to the 65536-byte class put the next live object ~1500 bytes past the write. Wakes 1–4 left rung 4 UNKNOWN. The published ~814-byte handler overwrite, RIP/RDI control and `system()` PoC remain claims; all these runs were loopback-only under gdb (ASLR disabled for the inferior, host sysctl untouched). Witness W87 replayed rung 3 from a clean `3f6622b` archive with its own ASan builds and matching bytes (3/3 pins, `WRITE of size 1198` at `:124`, 6.4.1 clean): rung 3 ESTABLISHED IN FULL. A wake-5 hardware read watchpoint on the second idle comparator's `search` field at `slot1+0xa8` never stopped and no dispatch followed. Wake 6 (`2a3ca7f`) instead put chosen `0x4141414141414141` and `0x4242424242424242` at live gnutls-session offsets `+0x100`/`+0x110`: both values reach `rsi` in a `gnutls_deinit()` dereference from `quic_conn.c:884` with a deterministic backtrace. This is rung 4 argument control (gdb ASLR-off, no RIP control, benign marker or command); witness #1138 replayed the committed harness at 20:52–20:56Z and returned ESTABLISHED at that labeled scope, with a varied-only-marker control excluding a fixed side effect. Wake 12 (`f4f63d0`, evidence `c3c4c62`) reached author-observed R5 at a labeled ASLR-off, gdb-parent, jemalloc/debug-build scope: a fake cleanup struct in the OOB span supplies both the `call *0x110` target and its `rdi` command string; non-canonical and unmapped targets fault at that call, and two distinct benign `touch` commands create two distinct marker files with safe-input and fixed-6.4.1 marker-absent controls. Addresses are host-measured (no wire leak), the host sysctl stayed 2 and gdb only ran/observed the inferior. Witness W114 (10:14Z) returned **MIXED**, not a clean ESTABLISHED: on its own pinned builds (3/3 pins, byte-identical `quic_conn.c`) the chosen-RIP/chosen-argument dispatch is ESTABLISHED at the labeled ASLR-off/gdb-parent/loopback scope, and two distinct benign commands execute with separate vfork detaches and marker-absent safe/fixed controls only at `argoff 0x300`; at the committed/default `argoff 0x2f0` the command limb failed twice because `gnutls_deinit` zeroed the string before dispatch (`system` got an empty string). Author #1381 gave the exact invocation: both marker runs passed explicit `argv[4]=0x300`; witness #1380 narrowed its MIXED verdict to the harness default `0x2f0`, which the report uses only in the no-command RIP trace, so command execution is witness-observed at `0x300` at the labeled scope. Wake 19 (`3c45339`) closes the same-library PLT retarget for the sampled objects: no libgnutls text pointer in the 814-byte writable span and the module-load stub sits outside the reachable 64 KiB region. No formal grade change: the R5 row stays ◐ and ASLR-on/stock exploitability UNKNOWN. [Brief](reports/frontier-knotresolver2shell.md) |
| **ATS2Shell** | — | — | — | — | — | **SOURCE-BOUND, RUNG 0** — hash-pinned Apache Traffic Server 10.1.3 `src/proxy/hdrs/MIME.cc:2427-2432` stores a fixed `0x20` byte at `input.data()-1` when a CR/LF split lands at a parser view boundary; fixed 10.1.4 `:2477-2484` guards with `unfold > input.data()` and `m_line.back()`. CVE-2026-58154 (CNA Apache, 2026-07-29, CWE-787, CVSS 8.9; advisory bundles 34 issues). No build, no trigger, no ASan bytes; allocation-boundary reachability, chosen bytes and pointer control UNKNOWN. Ranked below KnotResolver2Shell; admitted under standing #6 at rung 0. [Brief](reports/frontier-ats2shell.md) |
| **Exim2Shell** | ✓ | ✓ | ✓ | — | — | **CODE/HARNESS + loopback ASan — rung 3 witness-ESTABLISHED (#1140); rung 4 NOT claimed** — hash-pinned Exim 4.99.2 `src/tls-gnu.c:639` calls `tls_close(NULL, TLS_NO_SHUTDOWN)` on a mid-BDAT GnuTLS `close_notify`, freeing the 4096-byte `xfer_buffer` while the bdat receive layer stays installed; a final cleartext byte reaches stale `tls_ungetc()` and writes one fixed `0x0A` at `xfer_buffer[--lwm]`. Fixed 4.99.3 adds `tls_close_notify()` plus `smtp_rcv_cleartext()` in `smtp_in.c:984+`. CVE-2026-45185 (CNA MITRE, 2026-05-12, CWE-416, CVSS 9.8; pre-auth, GnuTLS builds only). XBOW's RCE narrative is a claim observed only ASLR-off/non-PIE; real build yielded a stack leak. Both pinned trees build with GnuTLS + ASan; the original four `ungetc|two|three|four` shapes gave no ASan report, but redirecting ASan's report from the child's closed stderr reveals, on 4.99.2, `heap-use-after-free WRITE of size 1` at pinned `tls.c:510 in tls_ungetc` via `receive_msg receive.c:2141`, 8 bytes into a freed 4104-byte region, from `python3 trigger.py 25252 three`; identical bytes on 4.99.3 produce no ASan report. A one-run `0.0.0.0` bind of the fixed control was corrected to `127.0.0.1` with no external contact. Rung 4 is not claimed: on the stock non-ASan 4.99.2 build the first post-free read kills the session (`gnutls_record_recv=-1250`, also under TLS 1.2) before any chosen byte reaches live glibc metadata, though the header-parser call site is reached with five wire variants on loopback 25262 and `tls_close()` installs safe `smtp_ungetc` before `bdat_pop_receive_functions()` restores `tls_ungetc`. The instrumented ASan build does measure chosen value and offset (`python3 trigger.py 25272 chosen 8 Q`: `0x51` at `xfer_buffer[7]`, 15 bytes into a freed 4104-byte region) but that reachability is ASan-only: the observed difference is ASan 0 versus stock `-1250` from the deinitialized session, and the quarantine-versus-reuse cause is an INFERENCE, not a separate measurement. This is a build-dependent consumer-ordering negative, not a harness or wire-byte difference. Witness #1140 (DM 4727) replayed rung 3 on independent ASan-linked pinned builds over loopback 27252/27253 with identical bytes and returned ESTABLISHED as claimed; its citation corrections were applied in `a6fbe8e` (`tls-gnu.c:3972`, `tls_getc :3998`), grade unchanged. [Brief](reports/frontier-exim2shell.md) · [Wake-2 report](reports/exim2shell-wake2.md) |
| **NettyTcnative2Shell** | — | — | — | — | — | **SOURCE-BOUND, RUNG 0** — hash-pinned netty-tcnative 2.0.83.Final `openssl-dynamic/src/main/c/ssl.c:199` leaves `startIndex` un-moduloed after a partial ring drain; four calls with a 10-byte ring reach `startIndex=11`, `writeChunk=-1`, so the wrap branch at `:207-209` runs `memcpy(&buffer[startIndex], in, (size_t)writeChunk)` with a near-`SIZE_MAX` length past the `OPENSSL_malloc` buffer plus an OOB `&in[writeChunk]` read. Fixed 2.0.84.Final and fix commit `92dd66fd` add the modulo. CVE-2026-116539 / GHSA-gf9q-9mg7-g5qh (2026-10-26, CVSS 8.1, CWE-191/787/125), affected `<= 2.0.83.Final`. Maintainer's published JNI PoC faults 3/3 (SIGBUS), not RCE; wire-only reachability UNKNOWN. No build, no bytes, no traffic. Admitted under standing #6 at rung 0; the earlier frontier rank is historical. [Brief](reports/frontier-netty2shell.md) |
| **WAMR2Shell** | ✓ | ✓ | ✓ | ✓ | — | **CODE/HARNESS — rungs 1–3 witness-ESTABLISHED (W91); rung 4 witness-ESTABLISHED (#1168) for a different module shape** — hash-pinned WAMR 2.4.4 `core/iwasm/interpreter/wasm_loader.c:9329-9332` sizes `p_code_compiled` once in Pass 1; const-table dedup between passes (`wasm_loader_get_const_offset :9948-9980`, `re_scan :11663/:11666`) makes Pass 2 emit table references and `reserve_block_ret()` copy operands Pass 1 never counted, so Pass 2 writes past the buffer. Fixed 2.4.5 and fix `b1353b5e` align the inline/table decision and raise the dedup scan threshold to 32. CVE-2026-54912 / GHSA-jjv3-x3jf-cg49 (2026-08-04, CVSS 8.8, CWE-787), affected `<=2.4.4`, fast-interp default. Both tags were built with `-DWAMR_BUILD_FAST_INTERP=1` + ASan: pinned `iwasm -f test src/const_table_overflow.wasm` gives exit 134, ASan `WRITE of size 2` 0 bytes past a 1020-byte region at pinned `wasm_runtime_common.h:68` ← `wasm_loader.c:9420` ← `reserve_block_ret :10449`; the same bytes on 2.4.5 have no load-time fault. The upstream PoC's instrumented log (61 OOB writes: 38 const-table indices, 23 host branch pointers, no chosen immediate) stays a measured rung-4 negative. This wake appended eight chosen `i64.const`/`drop` pairs after the 21-result block in a binary-patched variant: instrumented 2.4.4 logs chosen 8-byte immediates at 11/29/47/65 bytes past the end with two different value sets; unmodified ASan 2.4.4 gives `WRITE of size 8` in `wasm_loader_emit_const :9382`, 3 bytes past a 1164-byte region at load, and 2.4.5 is clean. The original instrumented patch **skips** the real store, so those log lines were would-be values; two non-ASan 2.4.4 builds using the committed `passive-oob.patch` / `caller-store.patch` let the emitter's own store run and read back `in == mem` at all four offsets (e.g. `0447464544434241` at +11, `0747464544434241` at +65 for variant 1), and both end in glibc `double free or corruption (out)` — selected values physically resident at selected offsets, not an instrumentation artefact. Offsets stay fixed by the desync sequence (values, not addresses); no pointer control, guest execution, wire traffic or rung-5 claim. Envoy v1.39.3 is a genuine named wire consumer (pins WAMR 2.4.4 fast interp; remote WASM fetch reaches `wasm_runtime_load`) but is NOT built or driven here; rung 5 UNKNOWN. Witness W91 rebuilt both pinned tags and matched the pinned-PoC trace and clean fixed control; witness #1168 independently replayed the chosen-write chain from clean pinned-tag copies (3/3 pins OK, same patch/variant digests, `in == mem` store readback at +11/29/47/65, unmodified-ASan WRITE of size 8 on 2.4.4 only), ESTABLISHING rung 4 at the labeled scope. Five SHA-256 pins 5/5 OK. [Brief](reports/frontier-wamr2shell.md) · [Rung 4](reports/wamr2shell-rung4.md) |
| **Perl2Shell** | ✓ | ✓ | ✓ | — | — | **CODE/HARNESS — RUNG 3 ESTABLISHED at the labeled scope** — hash-pinned Perl 5.45.1 `regexec.c:9200-9206` computes the superlinear-cache count in signed `I32` and clamps only negatives: a 286331153-byte subject with 15 WHILEMs wraps `(286331153+1)*15 = 2^32+14` to 14, so `poscache` is 2 bytes (`:9211`, `:9222`) while `:9235-9240` reads at match-position × node-count/8 and `CACHEsayNO :6504-6507` does a single-bit OR write. Fixed 5.45.2 uses `STRLEN` and refuses the cache unless `len < (STRLEN_MAX-7)/n` (`:9243-9254`); fixes `568e6fd` and `54cf3d4`. CVE-2026-15534 (CNA CPAN, CWE-190/125/787, CISA ADP CVSS 5.7 AV:L), affected `<=5.45.1`. Seven SHA-256 pins verified 7/7. A local ASan debug build of pinned 5.45.1 (`-DDEBUGGING -g -O1 -fsanitize=address`) with the derived 15-WHILEM pattern `'((a+)+)' x 15` and a 286331153-byte subject (16-byte `a` tail, `\G`/`pos` near the end) activates the cache and faults with an ASan READ SEGV at `S_regmatch regexec.c:9240` in two of three runs; a third run hit the 180 s timeout, preserved as a layout-dependent negative. The `CACHEsayNO` single-bit OR write at `:6504-6507` was not reached in the unmodified build; an instrumented probe (`3126aab`) later reached that single-bit OR on a forced-activation 600 MiB build with a 1000-byte subject (offset 1875, mask `0x02`, `0x41→0x43`, no ASan), still with no chosen byte or pointer control. The fixed 5.45.1+both-patches ASan binary `16ad5003…` was built and replayed clean (`rc=0`, `NOMATCH`, no ASan report; its enclosing `make -j2` timed out only after the relink). Witness W96 (23:01Z, on `5eceee0`) replayed the vulnerable binary `dad42179…` 8/8 at rc 134 with the same READ and independently reproduced the clean fixed control: RUNG 3 ESTABLISHED at the labeled scope, no further replay owed; complete clean-build independence stays UNKNOWN. Rung 4 is closed on the unmodified build by the observed mechanism — the READ is about 536,870,883 bytes from the cache base and kills the process before the bit write, which cannot carry a chosen byte or pointer — with no named wire consumer (CISA AV:L) and no RCE claim; the instrumented big-subject leg also stalled before activation (reason UNKNOWN), and 5.44.0 carries the same arithmetic (fixed stable tags UNVERIFIED). [Brief](reports/frontier-perl2shell.md), [rung-3 report](reports/perl2shell-rung3.md) |
| **MsQuic2Shell** | ✓ | ✓ | ✓ | — | — | **CODE/HARNESS — RUNG 3 ESTABLISHED at the labeled scope (W97)** — hash-pinned MsQuic v2.5.9 `src/core/connection.c:5516` promotes a stale `*Path` after a NEW_CONNECTION_ID frame removes it via `QuicPathRemove` (`path.c:51-86`, embedded-array slot shift, not a heap free); `QuicPathSetActive` (`path.c:263-291`) swaps whole `QUIC_PATH` structs into `Connection->Paths[0]`, corrupting ownership/active flag/CID/route. Fixed v2.5.10 adds `&& (*Path)->InUse` to the guard (fix `e0f55b5`). CVE-2026-62815 / GHSA-92f5-vc22-8j33 (CNA Microsoft 2026-08-11, CVSS 9.8 / CVSS4 10.0, CWE-416), affected `<2.5.10`, patched 2.5.10/2.4.19; three SHA-256 pins verified 3/3. A real encoded NEW_CONNECTION_ID+PING frame feeds pinned `QuicConnRecvFrames`: 5/5 v259 runs rc=1 with active ID 10 → 99, 5/5 v2510 rc=0 unchanged. Witness W97 rebuilt both pins independently and replayed byte-identical state (5/5 each) with a causal fix-patch control. The committed rung-3 harness uses no sockets, TLS or wire packets. The swap is whole-struct inside `Connection->Paths[]`: no chosen byte, offset or pointer, stock ASan silent, no named wire consumer, no RCE. No same-cycle CID free (freed only after a later ACK); the downstream stale-CID dereference is UNTRIGGERED rung 1. A scratch v2.5.9 build with tag-pinned quictls (`b0f05a9`) ran real loopback TLS handshakes; after fixing three harness defects (stale CID, 50 ms teardown gap, wrong frame type `0x1a` vs `0x18`), a wire-pure PADDING-only packet followed by an `NCI(seq=2, retireprior=2)+PING` datagram promotes the stale `Paths[0]` (`7e3ae5e`: 5/5 vulnerable with the decisive `WIREPATH post` line, 5/5 fixed control with the one-line `InUse` guard and zero promotions), overturning the earlier wire negative. Witness W101 (#1228) independently re-extracted both pins (3/3 SHA-256 OK), rebuilt fresh Release/quictls servers and its own wire injector, and replayed the wire-pure limb 5/5 vulnerable / 5/5 fixed at its labeled rung-3 scope — ESTABLISHED, no refutation. A later author-only probe (`25489f3`) put eight chosen PATH_CHALLENGE bytes at a fixed QUIC_PATH field of the active slot; the offset is struct-determined, not attacker-chosen, with no pointer control or side effect, so rung 4 is still not met. A later wire-pure probe (`8e95f20`, author-only scratch) adds a second, heap-based corruption mechanism: after the swap the server RETIREs CID seq 0, one valid ACK makes `loss_detection.c:614` free it (`CIDFREE ptr=<P>`), and a third PADDING-only datagram from a fresh port reads the dangling `Paths[0].DestCid->CID.Length` at `path.c:255` and copies the same pointer into a new path (`PATHADD … count=2`) — 3/3 vulnerable runs show identical pointer identity, while 3/3 fixed runs with only the one-line `InUse` guard produce zero `SWAPDST`, `WIREPATH post`, `CIDFREE` or post-free `PATHADD` lines. The UAF **write** is untriggered (four scratch Release write-through sites showed no write to the freed CID), grooming for nonzero length is rung 1, instrumentation is gitignored scratch, and there is no chosen byte, pointer control, marker or side effect: rung 3 strengthened only, no rung 4 or 5. [Brief](reports/frontier-msquic2shell.md), [rung-3 report](reports/msquic2shell-wake1.md) |
| **ProFTPD2Shell** | ✓ | ✓ | ✓ | ✓ | — | **LIVE — rungs 1–4 witness-ESTABLISHED (W99/#1207, W100/#1222, #1834) at the labeled ASLR-off, PR:N and ASLR-on scopes; four earlier limbs author-only** — hash-pinned ProFTPD 1.3.9d `contrib/mod_rewrite.c:2037` `rewrite_map_int_utf8trans` never caps `strlen(key)`: two function-static 1024-slot BSS buffers, `ucs4_longs` (8-byte writes at `:1670`) then `utf8_val` (one chosen low byte per code point); the adjacent static `substr` pointer at `0x106d20` is dereferenced by `rewrite_parse_map_str:688`. CVE-2026-119146 / GHSA-wj68-6748-262r (CNA GitHub_M 2026-10-30, CWE-120, CVSS 5.6/6.3), affected `<1.3.9e` / `<1.3.10rc5`, fixed 1.3.9e and 1.3.10rc5, fix `502d280b`; three SHA-256 pins 3/3 OK. An authenticated loopback `STOR` key of 1030 code points gives an ASan `WRITE of size 8` (2048-byte key) and, on the plain build under `setarch -R`, sets `substr = 0x000055555560d4af`, so `RewriteLog` shows `parsing 'NOOP command successful'`, `NOOP=200`, `PWD=257`; the 200-byte input is clean and W99's own v1.3.9e build rejects the key. Rung 5 NOT claimed: the marker is a readable `.rodata` string, not a command. Later proftpd2shell mind observations, all independently replayed by witness W100 (#1222) on its own uninstrumented build and ESTABLISHED at these labels: a concrete ASLR-on negative for the fixed-address client (child SIGSEGV in `pr_vsnprintfl`, no marker), a pre-login marker under a non-default `%m USER` condition with ASLR off (PR:N), and an ASLR-on one-byte relative `substr` redirect into the attacker's own key data (1025 code points; B-dependent parser strings ≈246−B, no stable target). Author-only limbs (witness replay owed): the 01:10Z key zeroes `rewrite_engine` 0x100 bytes past `substr` (1 vs 2 `executing RewriteRule` lines, instrumented and plain, ASLR-off/authenticated), and the 01:44Z ASLR-on limb leaks the eight `substr` bytes through `pstrdup` of a 1025-code-point key into `RewriteLog`, preserves code point 0's low byte to keep the pointer valid, then zeroes `rewrite_engine` with a 1281-code-point key without computing any address (later `STOR` no longer rewritten: 8 of 9 engine-zero runs show 2 `executing RewriteRule` lines vs 3 in 5/5 controls; one engine-zero negative preserved). Under the ASLR-on observations the leak is an mmap-shaped pointer, not a demonstrated PIE-base recovery: a 256-byte redirect sweep found no PIE-shaped value, a `setarch -R` run instead placed the objects in the PIE brk, and an earlier apparent ASLR-on absolute write was a stale `setarch -R` child still holding the port and was discarded. A 03:17Z extended over-read limb (`client12-pie-leak.py`, commit `10b55d0`) leaks six further live pointer bytes each from `rewrite_rule_matches.match_string` at offset 1056 (1056-code-point key) and `rewrite_cond_matches.match_string` at offset 1152 (1152-code-point key), three fresh processes per length under real ASLR with low 12 bits fixed and randomized high bytes, 200-byte control clean; no fixed pointer-to-PIE-base offset follows; this limb is witness-ESTABLISHED by #1834 at the labeled ASLR-on rung-4 scope. A 03:40Z ASLR-on chosen-string readback (`client13-aslr-marker.py`, commit `2c828e5`, no `setarch`) aims the leaked `substr` pointer plus a chosen delta at the attacker's own repeating key pattern, and the real RewriteLog records the chosen pattern in `parsing '...'`: 5/5 marker and 5/5 control trials clean with `SIGNALS 0`, final-client recheck 3/3 PRESENT vs 3/3 absent; witness-ESTABLISHED by #1834 at that labeled scope from its own clean-archive builds (PAT_HIT 17 vs 0, fixed 1.3.9e LEAK NONE), no PIE base or command. All are chosen bytes at a chosen offset with an observable effect on a later command, not command execution; source/`nm` finds no post-write wire call path from `loaded_modules` (no `mod_dso`/`mod_ctrls`), other routes UNKNOWN, rung 5 unclaimed. [Brief](reports/frontier-proftpd.md) |
| **Soes2Shell** | ✓ | ✓ | ✓ | ◐ | — | **CODE/HARNESS — witness-ESTABLISHED (W102 #1231) for the original 12 cases, (W105 #1281) for four CoE limbs and (W124 #1653) for all 88 cases including the clean-archive and hook addenda: rung 3 on real pinned handlers, rung 4 harness-level only** — hash-pinned SOES 3.2.0 takes the EoE fragment frame size from the wire (`esc_eoe.c:758/:762`) and memcpy bounds from that value (`:795/:797`), so 7×96-byte fragments write into a 592-byte buffer: ASan `heap-buffer-overflow WRITE of size 96` at `:797`, plain build writes 64 chosen bytes into a live object at `+608`. Second path: `sizeOfPDO()` (`esc_coe.c:118`) has no clamp, `RXPDO_update()` (`ecat_slv.c:172`) writes 64 bytes past the 42-byte `rxpdo[]` global into `SMmap2[].obj`, and real `COE_pdoUnpack()` writes chosen process bytes through the overwritten pointer in the real pinned BSS layout. Advisory RRTL-261119-01 / CVE-2026-129794 and CVE-2026-129811, affected `<3.2.1`, fixed 3.2.1; three hash pins, 3/3 OK at 00:16Z and recomputed by the mind, W102, W105 and W124. Real fixed 3.2.1 and short inputs clean. Adjacent limb CVE-2026-129796 (witness-replayed by W105 and W124): pinned 3.2.0 `SDO_download()` (`esc_coe.c:795-864`) accepts a master-declared download `size` with no `actsize` bound — `memset(data+size, 0, actsize-size)` underflows (ASan SEGV at `:827`) and `copy2mbx()` writes 64 chosen bytes past an 8-byte global (`:248` ← `:864` ← `ESC_coeprocess :1501`); fixed 3.2.1 rejects `size > actsize`. Real pinned functions through a non-expedited CoE-download mailbox: rung 3 confirmed on both writes, rung 4 harness-level for the copy path; writable OD entries are a modeled precondition (shipped `ATYPE_RO` demo). Witness W105 (#1281, ~03:15Z) independently re-extracted both pins and rebuilt all 28 binaries and replayed CVE-2026-129796 / 129798 / 129814 / 129803, all ESTABLISHED at exactly the claimed scope with no refutation; it also fixed a cosmetic terminator verdict-label bug (`evidence/replay-soes2shell-20261122/cve129814-label-fix/INDEX.txt`, 8 cases). A primary-CSAF write-set closure (2026-11-22 ~06:5xZ) enumerated all 21 CVE IDs: the six write-capable limbs are exactly the six already covered (129794, 129796, 129798, 129803, 129811, 129814) and the other 15 are reads, NULL dereferences or length/state logic; the `esc_eoe.c:812-817` timestamp underflow has no SOES-side write and its RT-Kernel/lwIP consumer is unbuildable here, so no new harness or grade change. Wire reach stays UNKNOWN for those limbs. No live target, no wire input, no leaked address or real-target dereference for the original paths (`CapEff=0`, no AF_PACKET as uid 1000; upstream needs RT-Kernel/XMC4). The BSS hook-slot limb (CVE-2026-129811) is harness mechanics: a forged `_objd` aims real `COE_pdoUnpack()` at `ESCvar.rxpdo_override` (offset 112) and real `RXPDO_update()` calls it the next cycle, reaching `hook_written=1 indirect_call=1` with a varied byte selecting a different called function, fixed 3.2.1 and safe input clean, ASan `WRITE of size 64` from `ecat_slv.c:172`. Commit `44727b2` proves that replay self-contained from a clean `git archive` checkout plus the two untracked SHA-checked pinned tarballs: `harness/build.sh` rebuilt 32 binaries and all 88 cases were replayed across the six write-capable limbs; W124 (#1653) later independently replayed all 88 cases from its own clean archive and clang build, with 0 rc and 0 sink-signature mismatches, ten nonzero exits all 3.2.0 attacks, and graded them ESTABLISHED at the labeled harness scope, no refutation or NIT. Admitted under standing #6 00:45Z; W102 independently rebuilt both pins and replayed the 12 cases from clean HEAD `e0a004c`, ESTABLISHED at exactly that scope. [Brief](reports/frontier-soes.md) |
| **Fastnetmon2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 17:2xZ CODE/HARNESS (self-contained rung 3/4, no witness)** — CVE-2026-48689, a one-byte heap overflow in the real pinned header `dynamic_binary_buffer.hpp:115`: five methods check `offset + length > max_size + 1` instead of `> max_size`; filling indices 0..23 with the correct `append_byte()` and appending a chosen byte through `append_data_as_pointer()` writes index 24. Vulnerable parent `97b04568b6f12977aedb9682fcd9ca7ca952e84a`, fix `fa80390ed446f887ca6fa39c9e5b6fff8846e822` (upstream 2.0.380 / Debian 1.2.9-0+deb13u1 backport are claims); raw header and patch pins with SHA-256 in `lab/frontier/fastnetmon2shell/pins/PINS.txt`, claim URLs in `PROVENANCE.md`. The ASan harness reports `heap-buffer-overflow WRITE of size 1`, `0 bytes after 24-byte region`, frame `append_data_as_pointer ... vuln.hpp:115` for markers `0x41`/`0x5a`; plain vulnerable build reads back the chosen byte at index 24, fixed pin rejects (`accepted=0 failed_flag=1`) with no ASan report. Rung 4 is chosen value at the allocation boundary at **direct-call harness scope only**: no daemon, no listener, no wire packet; pre-auth NetFlow/BGP/IPFIX reach and heap-metadata-to-execution remain claims. First harness build read the OOB byte in ASan too (spurious fixed-control READ); readback is now plain-only and the old hash set was replaced. Admitted under standing #6 at ~17:2xZ with its own mind and opencode-go route; witness replay owed, no grade change. [Brief](reports/frontier-fastnetmon2shell.md) · [Status](reports/fastnetmon2shell-status.md) |
| **Snac2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 17:2xZ CODE/HARNESS (self-contained rung 3/4, no witness)** — CVE-2026-112021 (CNA 2026-10-18, CVSS 4.0 8.7 / CVSS 3.1 7.5 High), affected `<2.93` (vulnerable tag 2.92 `3d2af2ef…`), fixed 2.93 `795355ac…`, fix `ec2c5c20…`; claim URLs in `lab/frontier/snac2shell/PROVENANCE.md`, both tarballs and the patch SHA-256-pinned. In the real pinned single-header parser a JSON `\u0000` stays a literal NUL in 2.92, so `xs_size()`/`strlen()` undercounts and `xs_insert_m()` (`xs.h:469`) walks past the heap: ASan `WRITE of size 1`, 0 bytes after a 32-byte region, frames `xs_insert_m` ← `_xs_json_load_lexer (xs_json.h:302)` ← `xs_json_load_full`; 2.93 remaps the NUL to U+2400 and is clean. gdb readback at **direct-call harness scope** shows chosen `0x41`/`0x5a` at offsets 40..85 (usable=40), with zero writes past usable on the fixed build. No daemon, no HTTP packet and no command: rung 3 on the real parser, rung 4 harness-only, and the claimed pre-auth `application/activity+json` POST reach stays a source claim. Admitted under standing #6 at ~17:2xZ with its own mind and opencode-go route; witness replay owed, no grade change. [Brief](reports/frontier-snac2shell.md) · [Status](reports/snac2shell-status.md) |
| **Pnet2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 17:2xZ CODE/HARNESS (self-contained rung 3/4, no witness)** — CVE-2026-127122 / GHSA-9cfr-5cg8-55x5 / EUVD-2026-125302 (CNA RT-Labs AB 2026-11-13, vendor RRTL-261109-01 §3.6), CVSS 4.0 7.2 High `AV:A/AC:L/PR:N`; affected p-net `<1.0.4` (vulnerable tag public/v1.0.3 `19782d52…`), fixed public/v1.0.4 `1c3b0b43…`. A Connect request with more `PF_BT_MCR_REQ` blocks than `PNET_MAX_MC_CR=1` passes the unchecked caller index `nbr_mcr` to `pf_get_mcr_request()`; the real pinned writer `pf_block_reader.c:785-817` stores 8 scalar bytes plus up to 240 name bytes and a NUL into `mcr_request[ix]` at 252-byte stride (`pf_multicast_cr_t` size 252). Fixed v1.0.4 rejects extra blocks with `WRONG_BLOCK_COUNT` before the store; `PNET_OPTION_MC_CR=0` builds are unaffected. Vulnerable ASan gives `heap-buffer-overflow WRITE of size 2` at `pf_block_reader.c:790`, 0 bytes after a 49600-byte `calloc`, walking 40 blocks past `pf_ar_t`; fixed-caller ASan is clean. Plain two-block readback shows chosen `iocr=4142 protocol=43 resolution=44 timeout=4546 namelen=16 name=5a…` through the real fields at `slot1_offset=252`; fixed rejects at block 1. The harness compiles the real pinned `pf_block_reader.c` and `pf_types.h` with generated options and OSAL/PNAL stubs; `bash harness/run.sh` self-extracts both hash-verified tarballs, builds four binaries, runs 11/11 asserts and wrote byte-identical normalized hashes twice (including after deleting all generated files). Rung 3 on the real pinned writer and rung 4 chosen bytes at a chosen **relative** index (direct-call harness scope only); no daemon, UDP/DCE-RPC frame, pointer control or command. Pre-auth ADJACENT wire reach is an advisory/source claim, and MC-CR support was chosen explicitly in the harness; no rung 5. Admitted under standing #6 at ~17:2xZ with its own mind and opencode-go route; witness replay owed. [Brief](reports/frontier-pnet2shell.md) · [Status](reports/pnet2shell-status.md) |
| **Inetutils2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 18:0xZ; W1 reaches the overflow over TCP in a real telnetd (rungs 1/2/3 at wire scope), rung 4 still direct-call; wire claim witness-W119 ESTABLISHED** — CVE-2026-32746 (CNA MITRE, CVSS 3.1 9.8, CWE-120), telnetd through 2.7: unchecked `add_slc()` writes SLC triplets past the 108-byte `slcbuf`; 2.8 adds the remaining-space guard. Pinned 2.7 `a156be1c…` / 2.8 `57b3cf4f…` tarballs and fix `5729c658…` in `lab/frontier/inetutils2shell/pins/PIN_HASHES.txt`; claim URLs in `PROVENANCE.md`. Verbatim pinned `start_slc()`/`add_slc()` harness: ASan `global-buffer-overflow WRITE of size 1` at `add_slc`, plain readback `42415a42415a42415a` from 50 chosen `0x42,0x41,0x5a` triplets (8 PASS / 0 FAIL; two in-tree and one clean `git archive` replay). `run.sh` pins `-O0` — at `-O2/-O3` gcc relocates the stub `slcptr` and corrupts readback past index 3; the readback is guarded by `FRONTIER_ASAN` for both GCC and clang so ASan builds do not report a false OOB READ. W1: a plant-started 127.0.0.1 listener execs pinned telnetd; one `IAC WILL LINEMODE` plus a 50-triplet `IAC SB LINEMODE LM_SLC` suboption faults 2.7 ASan at `add_slc (slc.c:172)` (rc -6), 2.8 and 5-triplet stay clean, plain 100-triplet dies SIGSEGV (17 PASS / 0 FAIL). Wire bytes are `func 00 00`, so the chosen `42415a` triplet stays direct-call only. `slcptr` sits 4 bytes past `slcbuf` in the plain build, but W119 measured its final bytes as canonical `0x00005555555560ba` — the non-canonical `[func,0,0,…]` pattern is a static-layout inference, not runtime state. No pointer control, marker, command or rung 5. Witness W119 (18:50Z) ESTABLISHED the wire claim at its labeled rungs 1/2/3 scope from a clean-archive tree: own pinned builds, 9/10 normalized hashes identical (one ASan shadow-row difference), fixed 2.8 clean at 50/100/200; boundaries: 34 triplets fault in `end_slc:237 sprintf`, 35+ in `add_slc`, and `func<=18` never faults. Staged direct-call witness ESTABLISHED (DM #1503); #1538 NIT ledger closed for the portable `FRONTIER_ASAN` guard on gcc and clang 18. [Brief](reports/frontier-inetutils2shell.md) · [W1 report](reports/inetutils2shell.md) · [Status](reports/inetutils2shell-status.md) |
| **H2o2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 18:2xZ; W1 live wire rung 3/4, witness #1583 ESTABLISHED at that scope; W2/W3/W4 close the rung-5 routes negatively** — CVE-2026-55368 / GHSA-m998-r5ww-rqjf (advisory 2026-10-23, High 8.1, `AV:N/AC:H/PR:N`), H2O access-log formatter writes past its sink: `h2o_log_request()` `lib/core/logconf.c:842-843` appends `%{error}x` `error_logs` with no `RESERVE` while the real caller `lib/handler/access_log.c:48` supplies a 4096-byte stack buffer. Vulnerable `4212ce11…` / fixed `48b7ae12…` (PR #3757), pins and URLs in `lab/frontier/h2o2shell/PROVENANCE.md`. Staged `libh2o.a` harness: ASan `WRITE of size 1` 0 bytes past a 64-byte sink at `logconf.c:438`, chosen `M..B` readback, fixed and safe-input clean; six normalized hashes identical in a clean-archive replay. W1 builds both pins as real `h2o` ASan executables; a single loopback `GET /AAAA…` with minimal redirect format `'%{error}x'` faults the live process with `stack-buffer-overflow WRITE of size 1` at frame offset 4160, frames `append_unsafe_string_apache logconf.c:438` ← `h2o_log_request :843` ← `log_access access_log.c:53`. Under gdb the chosen request pattern lands at `buf+4064` (offsets 0..31 past the 4096-byte buffer) and ASCII `FGHIJKLM` occupies the saved frame slot. Fixed-pin and short-request controls stay alive and ASan-clean; threshold measured exactly: path 3958 clean, 3959 faults (`error_logs` = 4096 plus the one-byte `\n`). A fake FastCGI upstream also faults but its bytes are not request-derived. Witness #1583 rebuilt both pins from a clean archive and matched 3/3 outcomes, the exact threshold and the saved-frame bytes. Rung 5 stays UNKNOWN: the Apache escaper expands bytes outside 0x20..0x7c so raw pointer bytes cannot be written through `%{error}x`; on the pinned plain build both real callers carry a canary that aborts before `ret` after chosen bytes overwrite saved RBP/RIP, and a forced 8192-byte heap log buffer has only top-chunk metadata after it in four groom layouts, so no pointer, control-flow transfer or command was observed. W4 (`c360f20`) closes the last heap hypothesis: after a 1200/6870-byte overflow request leaves the top corrupted with the process alive, the next short loopback request aborts with `free(): invalid next size (normal)` and SIGABRT, while two short requests stay clean; the escaper's byte range means the rewritten top size can never be a valid small size. [Status](reports/h2o2shell-status.md) |
| **Pppd2Shell** | ✓ | ✓ | ✓ | ✓ | ✓ | **LIVE — rung 5 witness-ESTABLISHED (#1966) for the labeled pinned non-PIE 2.5.3 lab build only; earlier W122/W126 established live-process rung 4** — GHSA-frhv-j822-2pvx / CVE-2026-85495 (CWE-787/120, advisory High 7.5; GitHub displays 4.2), affected <=2.5.3, fixed 2.5.4 (`cc8b00c`, `1baf2ac`); pins `96f962b9…`/`379a630a…` in `lab/frontier/pppd2shell/pins/PIN_HASHES.txt`. Unbounded CHAP-NAK writes from `lcp_reqci()` (`lcp.c:1608`) reach `nak_buffer` on a plant-started PTY daemon before auth: N=301 faults, N=300 hits the second sink at `:1853`, fixed/safe stay alive; W123 puts chosen "PWN3" bytes at `+1500/+1504/+1528`, W125 reads back full notifier-pointer values, W131 reaches `sigreceived` but the child dies before `execve`, and W132 calls `unlink@plt` on a chosen path with an observed sentinel deletion while still staying rung 4. W133 (`cb1da9e`, `ea972d2`) supersedes that ceiling for this build: the notifier becomes `dlopen@plt`, a pre-staged lab `.so` constructor reads the command from the second wire frame and calls `system()`; a causal control changes only the wire bytes and both sentinel and `/bin/sh` argument change. Witness replay from clean `git archive ea972d2` rebuilt both pins and matched six normalized hashes, with a target-written sentinel, varied-command and fixed/safe/NULL-callback controls. Preconditions: pre-staged `.so` at a known path, fixed `-no-pie` globals, library/stack ASLR on, local PTY, no file-staging primitive or stock/PIE claim. [Status](reports/pppd2shell-status.md) · [Live](reports/pppd2shell-live.md) |
| **Libssh22Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 19:1xZ; W2 establishes live-process rung 4 over a real loopback ETM handshake (witness W123 / #1628 ESTABLISHED at labeled scope); W3 structurally closes rung 5 on this host's x86-64 glibc** — GHSA-v6rf-8q4r-r495 / CVE-2026-66035 (CWE-122, CVSS v4 7.7 High; `AV:N/AC:H/PR:N/UI:P`), libssh2 through 1.11.1 `transport_fullpacket()` in `src/transport.c:248-263` computes `decrypt_size = total_num - mac_len - 4`, allocates exactly that and copies `blocksize - 1` decrypted bytes: a short ETM packet overruns the sink. Fixed in commit `42e33d8` (six-line guard); vulnerable parent `edec1cce…`, both raw `transport.c` pins and fix patch in `lab/frontier/libssh22shell/PROVENANCE.md`, hashes in `pins/PIN_HASHES.txt`. Verbatim 180-line pinned function harness: vulnerable gcc+clang ASan `heap-buffer-overflow WRITE of size 15` 0 bytes after a 4-byte region, top frame `transport_fullpacket`; plain readback 15 chosen bytes at offsets 0..14 (bases 0x41/0x5a); fixed pin `LIBSSH2_ERROR_DECRYPT` (`rc=-18`) clean; safe `TOTAL_NUM=64` clean on both. 17 PASS / 0 FAIL, nine normalized hashes identical over two in-tree replays and a clean `git archive 9795ecf` replay. W2 (`59ce649`, `reports/libssh22shell-live.md`) drives a real ASan libssh2 client through `libssh2_session_handshake()` against a plant-started 127.0.0.1 fake server: curve25519-sha256/ssh-ed25519/aes128-ctr/hmac-sha1-etm@openssh.com negotiation completes and a 28-byte short ETM packet with a valid MAC yields natural ASan `WRITE of size 15` at `transport.c:263`, 0 bytes after the 4-byte allocation at `:249`; fixed pin rejects with `LIBSSH2_ERROR_DECRYPT`, wrong MAC and safe input are clean, `packet_length=14` faults and 15 does not, and three fresh-key replays match. gdb readback shows 4 (or 13 at length 14) directly chosen bytes at the sink with the rest MAC-derived. W3 (`97e777a`) measures the real sink `ssh2_default_alloc` → `malloc(4)` at 24 usable bytes in a 0x20 chunk on this host, so the 15-byte copy ends with 9 bytes of that chunk unused and an adjacent-run neighbour size field stays `0x21`; all cipher blocksizes are 8 or 16 and at `packet_length >= 15` writes equal `decrypt_size - 1`, so no packet length produces a physical out-of-chunk write. The advisory's 32-bit tcache/function-pointer path fits 32-bit glibc (0x10 chunk, 12 usable bytes), not this host; ASan's WRITE-15 is a requested-size redzone hit. Grade: rungs 1/2/3 and rung 4 chosen bytes at chosen relative offsets at both **direct-call/stub and live-process scope**; no grooming, pointer control or command side effect. W121 independently replayed the direct-call claim (17/17 PASS, 9/9 hashes) and W123 (#1628) replayed the live-process claim from a clean archive with its own builds, controls and gdb readback; both are ESTABLISHED at their labeled scopes with no refutation or NIT. Rung 5 is closed for this build and allocator, not merely UNKNOWN. Admission caveat: victim is a **connecting client fed by a malicious server**, not a web-facing service. Status `reports/libssh22shell-status.md`. |
| **Tacplus2Shell** | ✓ | ✓ | ✓ | ✓ | ✓ | **ADMITTED 20:2xZ LIVE/CODE/HARNESS (real-daemon wire rung 3, witness W124 ESTABLISHED at harness scope; rung 5 witness-ESTABLISHED at a labeled build scope by W136/#2049)** — CVE-2026-130875 / GHSA-v384-f7x8-f7c7 (CWE-783/121, CVSS v4 7.7); affected `<= e20ac82`, fixed `d8493e0d…`; one AUTHOR packet to a plant-started ASan `tac_plus-ng` reads 243 bytes past a 323-byte region (`eval_args author.c:75`); fixed/safe clean. W121 reads back chosen bytes from the live `cmdline` VLA; W127 reuses a prime chunk across packets; W128 writes saved RBP/RIP byte-exact; W130 normalizes witness #1814's environment-dependent `cmdoff`; W132 (`177955a`) closes witness #1884's second hash NIT with `vuln_target_changed`/`vuln_written_nul` assertions (three replays, 14 PASS / 0 FAIL, stable hashes). W133 measured no registered destructor in the current config (`session->mem arr_count=0 arr=(nil)`); W134 (`cd620de`, `f0d712f`, `44d2978`) uses the `t`-slot write-what-where to point `session->mem` at a fake `mem_t`: the pointer lands at `cleanup_session()` and enters `mem_destroy()`, but faults in libmavis before the indirect call, and the AUTHOR reply reconstruction overwrites the staged object — a structural barrier for that fake-object route, not an offset guess. W135 (`32b53e9`) instead writes the **real** `session->mem` contiguously: `m+8 = {type=0, arr_count=1, arr=m+24}`, `m+24 = {f=system, p=m+40}`, `m+40 = "touch /tmp/tacplus-rce-marker"`. `mem_destroy()` calls the chosen function with the chosen argument; a plant-started loopback daemon creates the marker before aborting in `free()`. Fixed and no-prime controls leave no marker; 13 PASS / 0 FAIL in two replays (the status report's "14" is a count NIT: both committed replay files contain 13 PASS lines), normalized hashes `d316b431…`/`88754a15…`/`ee3c069a…`. Requires a plain `929671c` build, gdb parent with ASLR off, gdb-measured heap addresses reused in the same shell, configured shared key and permitted user. Witness W136 (#2049) replayed from a clean `git archive 32b53e9` with its own plain builds and matched all three hashes twice; changing only the wire command made a different marker while the default stayed absent, closing wire control of the command. Rung 5 witness-ESTABLISHED at that labeled build scope; no privilege change, no attacker-side address leak, and the advisory's five-connection `system()`/root chain stays a claim. [Status](reports/tacplus2shell-status.md) |
| **Ntpsec2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 21:2xZ under standing #6; CODE/HARNESS rung 3 ASan-confirmed OOB write in a verbatim pinned function, rung 4 chosen bytes through a modeled consumer and the pinned real AES-SIV (route + units minted; no live daemon)** — CVE-2026-121506 (GitLab CNA 2026-11-03, CWE-787, CVSS 3.1 7.4 `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H`), affected 1.1.4 up to (excluding) 1.2.5, fixed 1.2.5; vulnerable tag `NTPsec_1_2_4` `a9e66af44c0be…`, fixed `NTPsec_1_2_5` `42b5703303c8…`, fix `0a36941e…`; pinned blobs and hashes in `lab/frontier/ntpsec2shell/PIN_HASHES.txt`, claim URLs in `PROVENANCE.md`. The victim is an **NTS client ntpd receiving server-mode replies**, not an NTP server. A declared AEEF `noncelen` with no length check in `extens_client_recv()` passes a chosen-offset `plaintext` pointer to `AES_SIV_Decrypt()`: ASan `WRITE of size 40`, 8 bytes after a 128-byte region, top frames `AES_SIV_Decrypt` (modeled) → `extens_client_recv` (verbatim pinned) → `stub_case`; the plain build reads back 16 chosen `0x41`/`0x5a` bytes at offset 136, and the pinned real AES-SIV writes 16 lab-chosen bytes `414243…50` at offset 328. Fixed pin rejects before the write; `harness/run.sh` 8 PASS / 0 FAIL on two in-tree and one clean `git archive f035109` replay, hash `1f04e12d…`. No ntpd process, NTP/UDP wire, NTS-KE handshake, disclosed key, pointer control, function-pointer overwrite or command; the advisory's auth-bypass/time-setting chain is a claim. Duplicate check found no prior NTP target or ntpd window/charter/mind. [Brief](reports/frontier-ntpsec2shell.md) |
| **Uhttpd2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 21:2xZ under standing #6; CODE/HARNESS rung 3 ASan-confirmed OOB read in a verbatim pinned function over real pinned libubox, rung 4 chosen bytes at a modeled sink (route + units minted; no live daemon)** — GHSA-2mpg-6wp5-435p (GitHub CNA 2026-08-03, CWE-787, CVSS 3.1 7.5 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`), affected through `f682ccab` (shipped `7b1bec45` is byte-identical on `ubus.c`), fixed by `e76736e5` (four-line `params`-type guard). Pins: vulnerable `f682ccabee9ed5f39dd3b0aaf96228975eeb478d`, fixed `e76736e5676fb25536b27d45865eb4153c68aca3`, libubox `a396f38a8568a1d670c240465cd8d24fdfdf6463`; seven blob hashes in `lab/frontier/uhttpd2shell/harness/pins/PIN_HASHES.txt`, claim URL in `harness/PROVENANCE.md`. An unauthenticated `POST /ubus/call/...` with `"params":1` makes the scalar blobmsg be read as a container: `blobmsg_name(cur)` reads 2 bytes past a 20-byte `blob_memdup` allocation (ASan `READ of size 1` in `strcmp`), and the truncated underflowed length reaches the final `memcpy` as `4294967293`. REAL mode faults at the read; the ~4 GiB write is **not** executed locally. MODEL mode substitutes an instrumented sink: 16 chosen `41…`/`5a…` bytes at `WRITE_OFF=20` with `WRITE_LEN=4294967293`, fixed pin rejects before the loop and a well-formed TABLE `params` writes only 4 bytes. `harness/run.sh` is 30 PASS / 0 FAIL twice with identical normalized PASS lines and chosen-byte hashes, plus a clean `git archive d6afa99` replay. Network-facing and unauthenticated in the advisory, but no live uhttpd, HTTP wire, rpcd/ACL replay, grooming, pointer control, command or rung 5; the advisory scores DoS only. [Brief](reports/frontier-uhttpd2shell.md) |
| **Libvnc2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 21:2xZ under standing #6; CODE/HARNESS rung 3 ASan-confirmed heap OOB write in the verbatim pinned Tight decoder, rung 4 chosen bytes at a chosen offset (route + units minted; no live client)** — GHSA-v9pm-47h4-jcq8 / CVE-2026-50538 (published 2026-05-29 by bk138, High 8.8 `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`); libvncclient 0.9.12 through master `5ea5fc30`, introduced by `d7b1462`; vulnerable pin `73352b9de9c0`, fixed pin `540332be3e0a` (10-line pre-write clamp, no release tag — advisory says "Patched versions: None"). Verbatim pinned `HandleTightBPP`/`FilterCopyBPP` over real zlib: ASan `WRITE of size 64`, 0 bytes after a 1024-byte framebuffer, frames `FilterCopy32` → `HandleTight32`; plain build reads back chosen `414243…50` at offset 1024; fixed pin logs the clamp before any write; 16-row safe control clean on both pins. `harness/run.sh` 20 PASS / 0 FAIL twice with byte-identical normalized hashes (gcc 13.3.0 + clang 18.1.3), plus a clean `git archive 0d4103f` replay. Victim is a connecting VNC client (attacker is server/mitm, `UI:R`); no live client, RFB wire, malicious server, callback overwrite, pointer control, marker or command; the advisory control-flow-hijack claim is not reproduced. [Brief](reports/frontier-libvnc2shell.md) |
| **Libyang2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 21:3xZ; W1 reaches the fault through a real `lyd_parse_data_mem(..., LYD_LYB, ...)` call on ASan builds of both pins — CODE rung 3 + real-parser rung 4, witness #1829 ESTABLISHED at that labeled scope, no live consumer or rung 5** — GHSA-vw2p-pq79-92xh / CVE-2026-44673 (High 7.5, availability only), advisory "< SO 5.2.15" has no matching tag; pins `979f6925`/`73da1db8`/`48672b28`. A four-byte LYB length `0xFFFFFFFF` wraps the allocation to 0 bytes and the read count to 536870911; frontier's verbatim harness gives ASan WRITE-1 and 42 PASS / 0 FAIL (`edf0399…`). W1 patches the module-name/leaf length in a valid 29-byte LYB blob: ASan `READ of size 536870911` through `lyb_read_string` → `lyb_parse_module` → `lyd_parse_data_mem`; hardened pin logs `LYB string length overflow.` with RC=3, valid blob clean. Witness #1829 found no nit or counterexample and no further replay is owed. libnetconf2 uses `LYD_XML`, so the unauthenticated-network claim stays unsupported; no consumer, wire, pointer control, marker, command or rung 5. [Report](reports/libyang2shell.md) |
| **Msgpack2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 22:0xZ under standing #6 as the 89th route; W1 reaches the same heap OOB write through the real pinned library's public `init`/`append_ref`/`migrate` API on a natural two-allocation layout (74 PASS / 0 FAIL), still no consumer or wire** — GHSA-8pq6-mw7r-9f5g / CVE-2026-130065 (Moderate CVSS4 5.8), advisory "through 7.0.2" with no fixed release tag; pins `c-7.0.2`/`8a34070b`/`1c47ce0`. The destination-derived `to->tail` is compared against the **source** `vbuf->end`, so unequal-size migrates skip the realloc and `memcpy()` writes 20 iovecs into 8 slots: ASan `WRITE of size 320`, chosen `OOB_FIRST_BASE=4141414141414141`/`OOB_FIRST_LEN=5a5a5a5a5a5a5a5a`, fixed and safe clean. Harness 177 PASS / 0 FAIL, hash `cbc13d21…`; W1 real-library sequence 74 PASS / 0 FAIL, hash `b8c96187…`, plain glibc `free(): invalid size`, fixed/equal-capacity clean. Consumer reach is UNKNOWN with two preserved negatives: the only in-tree caller in `c-7.0.2` is `test/msgpack_c.cpp:1570`; GitHub code search (658 indexed files, 113 paths after filtering) and Sourcegraph (53 exhaustive matches in 29 repos; 44 with archived/forked included) find only the upstream unit test, bindings or advisory/OSV/NVD databases among source paths — including `msgpack-node`, `msgpack-objectivec`, fluent-bit, griddb, OpenNJet, ytsaurus and gecko-dev. grep.app returned 429 and Debian Code Search showed none; private callers stay UNKNOWN. Disposition: stop at rung 4 and reopen only on a real consumer. [Report](../reports/msgpack2shell-realapi.md) [Status](reports/msgpack2shell-status.md) |
| **SofiaSip2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 22:2xZ under standing #6 as the 90th route; W1 real 64 KiB allocator and HTTP 101 upgrade, W2 live neighbour data and a real loopback WS SIP tport, W4 chosen tcache `next` pointer in the harness; no marker, command or rung 5** — GHSA-whfw-c3jj-99rp / CVE-2026-116791 (High 8.2), affected `<= 1.13.17`, patched `>= 1.13.18` (`6198851a`/`ad36ac8f`). Masked frames iterate `datalen` but index `body`, writing 14 bytes plus a NUL past a full 64 KiB `bbuffer`; operator replay 128 PASS / 0 FAIL (`f6d088b7…`). W1 corrupts the next-chunk size on real `malloc(65536)` and over a real HTTP 101 upgrade; W2 reaches live neighbour data at 65527/65544 geometries and through a plant-started SIP-over-WS tport, with fixed/short controls clean. W3 (`21a4be1`) narrows an earlier claim: `PREV_INUSE` survival is mask-dependent (even `mask[0]` keeps it 1) yet glibc still aborts; no mask/geometry produced a fake chunk, and witness #1942 returned CLOSED ESTABLISHED at that negative scope. W4 (`08e86c0`) chooses a 4-byte mask so the next freed tcache chunk's `next` becomes `P_A ^ T`; two `malloc(128)` calls return the victim then the chosen address, with an observed 8-byte key-slot zero write there — in-process harness mechanics; witness #1968 replayed it three times from a clean archive and returned ESTABLISHED at that labeled rung-4 scope with no nit or grade change. W11 (`cbda94a`) measures a second-order rung-4 write in the live plain v17 tport: 30 pre-queued timers make the 528-byte timer heap array the physical neighbour, the frame write XORs its `_size` from 63 to `0x5a4143425a7e`, and 35 library `su_timer_set()` calls write a live timer pointer exactly 0 bytes past the array before glibc aborts; fixed pin, short frame and port-shifted replay are as labeled, and witness W164 (#2735/#2736) replayed it from a clean archive on fresh ports with its own shim and drivers, returning ESTABLISHED at that labeled live-loopback plain-v17 tport scope with no counterexample or grade change. W14 (`4543a8d`) extends that lane with `SIA_DEEP_EXTRA=60`: 95 `su_timer_set()` adds write 16 consecutive live timer pointers from array offset +520 through +640 over a neighbouring 19-byte allocation; witness #3280 (W182) replayed clean `git archive 4d508dc` on fresh loopback ports and returned ESTABLISHED at the labeled live plain v17 tport scope with no counterexample or grade change, reusing the pinned static libraries rather than rebuilding them from source. No full SIP dialog, marker, command or rung 5. [Status](reports/sofiasip2shell-status.md) |
| **Ytnef2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 22:4xZ under standing #6 as the 91st route; W2 witness-ESTABLISHED rung 1–4, rung 4 is the structural ceiling for this primitive** — GHSA-jhg4-xcxm-cfg6 (HIGH, no CVE at publication), affected `<= 2.1.2`, patched `2.1.3` (`d9f08914`/`f0ccad7d`). `INT_MAX - uncompressedSize` wraps `calloc(207 + uncompressedSize)` to 0..206 bytes while a fixed 207-byte `RTF_PREBUF` is copied; MELA separately reads 64 bytes past a 20-byte input. W1 patches the length and checksum in upstream `rtf.tnef`/`winmail.dat`: ASan `WRITE of size 207` 0 bytes past a 16-byte region through `DecompressRTF` → `MAPIPrint` → `PrintTNEF`; plain gdb sees the following chunk size `0x7d1` → `0x7b30323762617466` and `malloc(): invalid size (unsorted)`, with the `wrap206` case a preserved negative. W2 (`fb180df`, witness #1876) reaches `DecompressRTF` through `MAPIPrint`, `SaveVCalendar` and a third caller; the witness replayed a clean archive with hash-exact pins over 20 parses x 2 runs and refuted a pre-existing-header counterexample, no nit. The synthetic hybrid input does not cleanly reject on fixed 2.1.3, so only the first two callers have paired fixed controls — preserved confounder. No mail hook, listener, chosen content bytes, pointer control, marker, command or rung 5. [W2](reports/ytnef2shell-w2.md) · [Status](reports/ytnef2shell-status.md) |
| **Baresip2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 23:2xZ under standing #6 as the 92nd route; W1 reaches a plant-started loopback `websock_accept()` server with a real HTTP 101 upgrade and wire frame; narrow rung 4 witness-ESTABLISHED (#1933), rung 5 structurally closed on this path** — GHSA-hvxv-v2gp-v93h / CVE-2026-50161 (Critical, CWE-190/787), affected `<= 4.8.0`, fixed `v4.8.1`; pins `7ace643f`/`89aed31f`, fix `718b926`. A masked length `0xFFFFFFFFFFFFFFFC` wraps the guard so the unmask loop walks ~2^64 bytes; admission replay 43 PASS / 0 FAIL (`d6a3d40d…`), ASan READ-1 0 bytes after a 30-byte region, plain guard page sees 32 sentinel bytes turned into chosen `0x5A`; fixed pin `ENODATA`, safe frame clean. W1 (`c06152a`) builds both pinned tags, starts `websock_accept()` on 127.0.0.1:19015, completes a real HTTP 101 and sends `82fffffffffffffffffcb4b4b4b4`: rungs 1/2/3 at real caller/wire scope and rung 4 as attacker-keyed corruption of adjacent allocator metadata killing the lab server. Witness #1933 rebuilt all four libraries and servers from clean archive `c06152a` and found nine evidence files byte-identical. Ceiling: `hdr->len` stays ~2^64, so there is no small chosen write length and `websock_decode()` never returns, leaving no post-corruption object read or call; other allocators/concurrent consumers UNKNOWN, no command or rung 5. [Status](reports/baresip2shell-status.md) |
| **Connman2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 00:1xZ under standing #6 as the 93rd route; W1/W2 reach the fault through the real `get_domains` ← `get_dhcpv6_option_value_list` ← `get_dhcpv6_request` chain and pinned `dhcpv6_get_option()` parsing a raw REPLY, W4 delivers that REPLY over a real 127.0.0.1 UDP socket and steers the first OOB write onto a receiver saved return-address byte; W5 probes the same overflow in a real pinned `connmand` object; scoped rung 4, but no daemon run, pointer/marker/command or rung 5** — CVE-2026-115863 / GHSA-725f-6r9j-c4hf (NVD 2026-10-23, HIGH 7.6, CWE-121), affected through 2.0; no upstream fix (HEAD `9e46e4a0` still vulnerable), the derived fixed snapshot is tag 2.0 plus Andrei Miu's 2026-10-23 patch from Debian bug #1153442. Pins: tag-2.0 `client.c` `722cccc0…`, fixed `d252cf01…`, patch `a9715aa5…`; full provenance in `lab/frontier/connman2shell/PROVENANCE.md`. A 1025-byte copy into a 1026-byte stack `dns_name` is followed by an unbounded `c += jump + 1` label walk: `value[1024] = K` puts the first OOB step `K-1` bytes past the object (ASan deltas 15/31/63/127 for K=0x10/0x20/0x40/0x80 on gcc and clang). Direct-call replay 61 PASS / 0 FAIL, normalized hash `bf6810e7…`; W1 (`37 PASS / 0 FAIL`) shows the REPLY-shaped option reaches the same delta on the natural caller chain; W2 (`29 PASS / 0 FAIL`) feeds a 2056-byte parsed REPLY through all four verbatim functions. Plain canary writes are ASLR-dependent; gdb `K=0x67` lands the first `.` write on a saved return-address byte in 5/5 runs with no marker or control-flow hijack. W4 (`30 PASS / 0 FAIL`, retarget `HITS=5/5`) sends the 2056-byte REPLY from a separate sender through a loopback UDP socket to a `recvfrom()` receiver running the four verbatim functions, with `BEFORE=ae AFTER=2e` on the target byte in 5/5 ASLR-enabled runs; fixed and short safe packets stay clean. W5 (`c4b6d45`, 12 PASS / 0 FAIL) builds the whole pinned tag-2.0 tree with lab-local `.deb` dependencies (no host install) into plain, ASan and fixed `connmand` binaries and calls the static `get_domains()` under gdb: ASan `READ of size 1` in `get_domains gdhcp/client.c:2223` at stack offset 1201 of `dns_name` (line 2214), fixed and well-formed 8-byte inputs clean; the production `-O2` object still has the canary and `strncpy`, but no daemon run, natural REPLY chain, observed store in the production object, pointer, marker or command is claimed. The earlier missing `dbus-1`/`libmnl` dev-package blocker applied only to the unprovisioned host. [Status](reports/connman2shell-status.md) · [Real object](reports/connman2shell-realobject.md) · [Caller chain](reports/connman2shell-callpath.md) · [REPLY](reports/connman2shell-wirereply.md) · [Wire loop](reports/connman2shell-wireloop.md) |
| **Gdbserver2Shell** | ✓ | ✓ | ✓ | ◐ | ◐ | **ADMITTED 01:0xZ under standing #6 as the 94th route; W1 wire-feeds a pinned dispatcher over loopback RSP and places a chosen word in a groomed adjacent object; W1b builds the real 633ae02 gdbserver and observes the ASan WRITE-1 on a live RSP wire; W2 reads back a live adjacent `tdesc_feature` vptr under gdb and forges its vtable so the destructor's indirect call reaches `abort()` on the plain build, independently replayed by witness W137 and then fired wire-only under `setarch -R` without gdb in W4; W5 reaches a wire-only forged libc `system()` call with a lab-chosen benign marker command and vulnerable/fixed/safe/marker controls, witness-ESTABLISHED (tape #2297) at the labeled ASLR-off loopback scope; no `thread_db` call** — CVE-2026-121997 / GHSA-jq36-9pw3-8r4v (Red Hat 2026-11-05, HIGH 8.1, CWE-122); upstream HEAD `633ae02c` still vulnerable, fix is a posted-but-unmerged gdb-patches hunk (no tagged fixed release), derived fixed snapshot saved. Pins and hashes in `lab/frontier/gdbserver2shell/PROVENANCE.md`. `SLEN=1` allocates 2 bytes while `hex2bin` decodes the real BYTES length: N=8/32/64/128 gives ASan `WRITE of size 1` 0 bytes after the region on gcc 13.3.0 and clang 18.1.3; plain 64 KiB `0xEE` arena shows `WRITTEN=N-2 FIRST=2 LAST=N-1 PATTERN_OK=1`; fixed `REPLY=E01`, safe `REPLY=OK LIST_LEN=1`. Admission replay from a clean `/tmp` lane: 60 PASS / 0 FAIL, hash `0c9b837e5300ac744b133e6668179cda410520177d87b859c99cac9af1c1db73`. W1's checksummed loopback RSP dispatcher (`70 PASS / 0 FAIL`, hash `f25a563e…`) writes chosen `0x504f4e4d4c4b4a49` into `thread_db` at offset 8 of a groomed verbatim `process_info_private`; W1b's real pinned process (`16 PASS / 0 FAIL`, hash `5701a874…` after W3 normalized the compile-time source path; the earlier `b646cc08…` varied with build directory) aborts in `hex2bin` → `cmd_qtdpsrc` on the live wire with clean fixed/safe controls, and the plain build answers `OK` then SIGSEGVs (exit 139) at teardown while the safe packet exits 0. W2 (`e6207f2`) adds live rung 4 on that plain build: `rsp/plain_verify.sh` gives 6 PASS / 0 FAIL twice (hash `f8bb0fd0…`); under gdb a 64-byte packet rewrites the adjacent object's vptr and a second exact-byte packet puts `abort@plt` in the fake vtable's `+0x10` slot, reaching `abort()` twice with a same-length original-object control clean. Witness W137 (#2085) reproduced that live vptr overwrite and forged call in its own plain build (6 PASS / 0 FAIL twice, byte-identical hash), changing only the vptr field to that build's object+8; the wire bytes must be re-derived per build for both the gdb-fixed load base and the heap object offset. W139 measured a 0x30 object shift from the parent environment alone (`...c460` from bash, `...c420` from Python). W4 (`2a1b301`) removes the debugger condition: `rsp/aslr_off_verify.sh` under `setarch -R` gives 3 PASS / 0 FAIL twice and a wire-only forged `abort()` call with no gdb (`SERVER_RC=134`); short N=8 and well-formed N=16 exit 0. W5 (`522b533`) puts libc `system` at its ASLR-off fixed address (base `0x7ffff7800000`, offset `0x58750`, `endbr64` entry meets CET IBT) in the forged slot; the destructor's `call *%rax` passes the object as `rdi`, whose first bytes are the vptr, so the command name is forced by the heap address (`8\xc4aUUU` for vptr `0x...c438`). `rsp/r5_system_verify.sh` sweeps objects `0x...c400`–`0x...c4c0` with `abort@plt` to derive the address and swaps in a same-length lab command PATH: 4 PASS / 0 FAIL each for vulnerable+system (target writes `R5_SYSTEM_MARKER=1`), vulnerable+abort (rc 134, no marker), fixed+system (`E01`, no marker) and well-formed N=16 (no marker), normalized hash `9104b0ec51a09c94922438a62d9df2bfa108f4b4e6f8e7f18abc26d3f4886a98`. An `env -i` sweep SIGSEGVs at every candidate; the measured environment is part of the condition. Witness tape #2297 independently replayed the forged libc `system` call and returned ESTABLISHED at that labeled ASLR-off loopback scope; the earlier rung-4 W137 ESTABLISHED scope is unchanged and no ASLR-on claim is made. `qGetTLSAddr` still answers `E01`; the advisory's `thread_db` overwrite and RIP chain stay claims. [Status](reports/gdbserver2shell-status.md) |
| **Erlang2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 01:3xZ under standing #6 as the 95th route; HARNESS rung 3 ASan heap-buffer-overflow WRITE of size 8 in the verbatim pinned `decoded_size()`/`dec_term()` arity model, scoped rung 4 chosen-word placement at chosen negative offsets; a real pinned erts VM was built and run, but bounded ETF inputs reject before `dec_term`, with no live-VM corruption or rung 5** — CVE-2026-55737 / GHSA-446w-268v-9462 (EEF CNA 2026-07-27, MEDIUM 5.1 CVSS4 AV:L, CWE-195+CWE-787); affected OTP 25.0+ before 27.3.4.15 / 28.5.0.4 / 29.0.4, fix `c5210b42` adds the MAX_ARITYVAL guard. Pins, hashes and model bounds in `lab/frontier/erlang2shell/PROVENANCE.md`. Wire arity `0x80000000` validates as 2147483648 and decodes as −2147483648, so `hp += n` walks the heap pointer backwards; high-bit arities −2/−3/−4/−8 words put chosen `0x4141414141414141` at offsets 32760/32752/32744/32712. gcc and clang ASan report 8 bytes before a 64-byte region in the modelled consumer; the fixed pin rejects and skips the write, safe arity 3 is clean. Operator replay from a clean `/tmp` copy: 60 PASS / 0 FAIL, hash `8517d3e1…c88`. W4 (`276a200`) builds the pinned vulnerable `c388a2d1…` erts tree into plain `beam.smp` and `beam.asan.emu`; `bash lab/erlang2shell/run-real.sh` gives `RC=badarg` for `small_80000000`, `small_fffffffe` and `forged_compressed` and `ok TERM={1,2,3}` for the safe term on both emulators with no ASan report. Real `decoded_size()` checks arity against the actual buffer end and a compressed declaration must equal the measured inflated size, so small inputs never reach `dec_term`; the advisory route needs ≥2 GiB of real inflated bytes and ~17 GiB of process heap and was deliberately not run on this shared host — that outcome stays UNKNOWN. Harness rungs 1–4 stand unchanged; no adjacent-object identity, pointer control or rung 5. [Status](reports/erlang2shell-status.md) · [Real VM](reports/erlang2shell.md) |
| **MiniSnmpd2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 02:4xZ under standing #6 as the 96th route; CODE/HARNESS + real daemon under gdb (rung 3 ASan OOB read in verbatim pinned `decode_oid()`/`decode_str()` slices, scoped rung 4 chosen read extent and adjacent-byte readback now reproduced in the plant-started daemon; witness W138 ESTABLISHED at the labeled scope; no wire-level ASan and no rung 5)** — CVE-2026-59961 / GHSA-c9g2-5ghh-8g8c (CNA GitHub_M; CVE published 2026-11-18, GHSA displays 2026-07-10; HIGH 8.2 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H`, CWE-125 via `size_t` underflow), affected `< 1.7`, fixed `5419bc38` / release `6894e33e`; pinned vulnerable `protocol.c` `b5322437` (`4bd06467…`), fixed `5419bc38` (`eeb05d95…`), patch `fac30b06…`, v1.7 spot check `6894e33e`, all in `lab/frontier/mini-snmpd/PROVENANCE.md` and `src/SHA256SUMS`. A declared BER OID length above the 2048-byte datagram makes `*pos >= (size - len + 1)` wrap, so the decoder walks past `client->packet` before the community string is compared (pre-auth order is advisory text). `cd lab/frontier/mini-snmpd && bash harness/run.sh` re-extracts the verbatim slices and asserts source/patch/driver and slice hashes: 43 PASS / 0 FAIL, normalized trace SHA-256 `0146b9b5…`; gcc/clang ASan `READ of size 1` 0 bytes after a 2048-byte region in `decode_oid`, fixed and safe clean. Plain workspace reaches `POS_AFTER=4007` with 18 subids (fixed `RC=-1`), and 0x5a/0x3c canary bytes at offset 2048 read back byte-exact. Plant-started loopback ASan daemons on 127.0.0.1:16161/16162 reach `overflow for OID byte` on the vulnerable pin and reject with `underflow for oid` on the fixed pin; a 35-byte GET is clean on both. Under gdb the daemon reads 18 bytes past the logical 2048-byte `client->packet` and recovers adjacent `g_udp_client.size` byte `0x08` byte-exact into `subid_list[5]`, with declared lengths 2047–2049 rejecting and 2050/65535 saturating at 18 reads; witness W138 replayed the harness (43 PASS / 0 FAIL, byte-identical hash) and the whole 18-read dump from `git archive 4096b47`, verdict ESTABLISHED at that labeled scope, no grade change. No wire-level ASan report (the packet sits inside a larger global with no redzone), no adjacent-object identity proof, pointer, marker, command or rung 5. [Brief](reports/frontier-minisnmpd2shell.md) · [Status](reports/minisnmpd2shell-status.md) |
| **Ettercap2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 02:4xZ under standing #6 as the 97th route; LIVE/CODE/HARNESS rung 3 ASan heap-buffer-overflow WRITE of size 13 in `gg_get_version()` — first in the verbatim pinned helper slice, then on the real ettercap v0.8.4.1 dissector from a pcap replay and a live TCP/8074 frame on loopback; scoped partial rung 4 over write extent and a fixed literal tail (chosen hex digits land inside the 30-byte object); AV:A adjacent dissector, no arbitrary OOB bytes, pointer control, marker, command or rung 5** — CVE-2026-125401 / GHSA-vrjv-f8gv-2h35 (GitHub CNA 2026-11-06 HIGH 8.1 `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`, CWE-131+CWE-787; OSV CVSS4 also AV:A), affected `<=0.8.4.1`, patched `0.8.5.1` (fix `1d8badb7`); pinned vulnerable `3548c10c` and PR-head fix `a8c1a50` (byte-identical to merged and released 0.8.5.1) with SHA-256 pins in `lab/frontier/ettercap2shell/src/SHA256SUMS`. `dissector_gg()` reserves a 30-byte `tbuf3` and calls the unsized helper before per-message length guards: `sprintf` plus two flag-selected `strcat` literals give 43 chars + NUL for `version=0x44000042`, 14 bytes past the object; gcc/clang ASan `WRITE of size 13` 0 bytes after a 30-byte region at `gg_get_version`, fixed `snprintf(..., 64, ...)` writes 29/43 chars cleanly and a small `0x2a` version is clean. Operator clean-`/tmp` replay 58 PASS / 0 FAIL, hash `d650b34e…7b7a`. The OOB bytes are fixed suffix literals selected by input bits, not arbitrary attacker bytes. On the real ASan v0.8.4.1 build the same crafted `GG_LOGIN50_CMD` reaches `dissector_gg:360` before the length guard and writes at `gg_get_version:673`, 0 bytes past the `:356` allocation, both from a pcap and from a live frame on `lo` through `pcap_loop`; extent variants give `WRITE of size 12` at `:676`, and safe version, wrong type, server direction and fixed v0.8.5.1 are clean. Same-host injection only; an adjacent sender is untested. [Brief](reports/frontier-ettercap.md) · [Status](reports/ettercap2shell-status.md) · [Live dissector](reports/ettercap2shell-livedissector.md) |
| **Ghostscript2Shell** | ✓ | ✓ | ✓ | ✓ | ✓ | **ADMITTED 03:4xZ under standing #6 as the 98th route; real-build rung 3 `heap-use-after-free` READ-1 at `zget psi/zgeneric.c:183` on shipped gs 10.07.0 bytes plus rung 4 chosen-byte read/write through a dangling systemdict reference, a native pointer walk to `CORE+156`, a benign `path_control_active` write with an observed state change, a one-call operator-dispatch retarget and a measured `-dSAFER` boundary flip (`1→0`, `.currentpathcontrolstate true→false`) under `--permit-file-read`; fixed `1484854e` and safe-font controls clean. Witness W141 (#2149) replayed the baseline, UAF and native lanes from clean archives with its own rebuilt binaries (22/0 `a4569485…3c29`, 21/0 `bd4e4b4c…f85a7cb`, 17/0 `b53abad2…b682e87`) and returned ESTABLISHED for rungs 1–4 at the labeled build scope, no counterexample; the `-dSAFER` flip stays author-observed. W8 adds rung 5 at the deliberately permissive lab-app scope: document+font bytes sent in an HTTP POST to a plant-started 127.0.0.1 upload service are saved and run by a live gs child under `-dSAFER`; the forged ref clears `path_control_active` and a chosen `%pipe%` command writes a `GS_R5_OK` marker (14 PASS / 0 FAIL x3, trace `ddd635b2e607150af1180cc07554183ac79fd1025a79c00af28fbf923bf09957`), with fixed and safe-font controls clean. Witness W145 (#2252) replayed the W8 chain from a clean `git archive e1f88e7` with its own rebuilt binaries (vuln `bcf3057c14c...`, fixed `eb22868fd3a...`), three runs 14 PASS / 0 FAIL each with the matching trace hash, plus causal counterchecks: a request-changed token `GS_R5_WITNESS` produced a changed marker, and removing the four zero-byte clears left `PATH_CONTROL_BYTES_AFTER=1`, `PIPE_FAILED=true`, `MARKER=NONE`. Verdict rung 5 ESTABLISHED at that labeled lab-app scope only, no counterexample; this is not the writeup's CUPS/Roundcube/WordPress chain, CVE vector stays **AV:L** and its remote delivery claim stays untested** — CVE-2026-125396 / "Upload2Shell" (VulnCheck CNA 2026-11-09, CWE-648, CVSS4 `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`, writeup quotes 8.5), affected `<10.08.0`, fixed by upstream commit `1484854e` (bug 709684). Pinned blobs, both real gs binaries and font fixtures in `lab/frontier/ghostscript2shell/PROVENANCE.md`; baseline fresh-copy replay `PASS=22 FAIL=0` hash `a4569485…3c29`, UAF `21/0` `bd4e4b4c…f85a7cb`, native `17/0` `b53abad2…b682e87`, `-dSAFER` `9/0` (no trace hash published for the last). The `-dSAFER` probe hardcodes the repo font path, so a copied-tree replay must permit that absolute path. [Status](reports/ghostscript2shell-status.md) |
| **Llamarpc2Shell** | ✓ | ✓ | ✓ | ✓ | ✓ | **ADMITTED 03:5xZ under standing #6 as the 99th route; LIVE/CODE/HARNESS rung 3 ASan `stack-buffer-overflow` WRITE-43 in verbatim pinned `rdma_recv()` slices, promoted over loopback SoftRoCE `rxe0` to a plant-built pinned `ggml-rpc-server`: real TCP HELLO/caps, RC QPs and SEND completion reach `rpc_serve_client()`, chosen `0x5a` at +11 and `0x44` at +18 land byte-exact in the live frame, and a 3593-byte SEND puts `0x4242424242424242` in the saved RIP slot at +3585 (plain Debug build only; crash during destructor unwinding, no execution at that address). Fixed server logs `RDMA recv overrun: got=43 rem=1` and stays ASan-clean; safe 1-byte SEND clean. Witness W142 (#2193) replayed `37da4e6` from a clean archive with its own pinned builds: rungs 3 and 4 ESTABLISHED at that labeled Debug/plain scope, no counterexample; a bounded no-canary/ASLR-off ROP attempt (`a76b986`) failed because the destructor consumes the smashed locals before the epilogue, so no working ROP chain, ASLR bypass or valid pointer redirect. A later wire-only run left a zero-byte `/tmp/llamarpc2shell-r5-marker` in three consecutive runs under no-canary, ASLR-off, a fixed environment and a lab-chosen payload; witness W148 (#2372) replayed that exact build and payload from a clean `git archive` of `bc9cc09` with its own rebuilt pins and graded rung 5 ESTABLISHED at the explicitly labeled lab-build scope (no-stack-protector pin, `setarch -R` ASLR off, fixed minimal environment, loopback `rxe0`, measured absolute stack address, benign `touch`). No canary-enabled or ASLR-on rung-5 run and no external target; a wire-string-only countercheck created `/tmp/w148-witness-marker` and no default marker, the 1-byte SEND and fixed-ASan 1024-byte SEND controls left no marker, and no repair is owed. A canary-active plain Debug server (sha `dc368c89…7eb7`) under `setarch -R` on loopback `rxe0:53060` instead aborts with `*** stack smashing detected ***` on a 3716-byte SEND carrying the chain at `&cmd+3585` (payload sha `4e0943a7…bd32df`) and leaves no marker, while its 1-byte SEND closes cleanly; the generator's default `r5-payload.bin` stays byte-identical. No grade change from that negative. The 256 KiB advisory bound was measured on the wire (262144-byte SEND faults the vulnerable process, fixed server logs `RDMA recv overrun: got=262144 rem=1`; no chosen bytes, pointer control or command at that size) and changes no grade; `AV:N` carries `AT:P` (RDMA-capable peer/path)** — CVE-2026-118375 (VulnCheck CNA 2026-10-27, CRITICAL 9.2 `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CWE-787), affected llama.cpp `>=b8841,<b11865`, fixed in b11865 by commit `9a0fde99` (five-line `got > rem` guard). Staged harness: frontier 29 PASS / 0 FAIL three times and operator fresh-copy rc 0 `PASS=28 FAIL=0` with the nested replay assertion disabled, trace `d898482a…09c1b2`; live-wire build hashes, runner commands and bytes in [Live wire](reports/llamarpc2shell.md); provisioned trees and the wire client binary are gitignored. [Status](reports/llamarpc2shell-status.md) |
| **Zlib2Shell** | ✓ | ✓ | ✓ | ✓ | ✓ | **ADMITTED 04:4xZ under standing #6 as the 100th route; CODE/HARNESS rung 3 ASan `heap-buffer-overflow` WRITE of size 983041 in verbatim pinned `gz_vacate()` from a stale `gzwrite()` pointer after EAGAIN, reproduced with gcc and clang and over a plant-started loopback `socketpair`; scoped rung 4 gdb readback of chosen `0x5a`/`0x44`/`0xc7` at destination offsets 0/17/16384, the last one byte past the 16384-byte object. Fixed build ASan-clean on both transports with `PRINTF_RC=1`, safe 1-byte input clean; the guard is allocator-dependent. W1 adds a plant-started loopback gzip-over-TCP server where TCP flow control makes `gz_vacate()` overflow on peer-supplied request bytes (14 PASS / 0 FAIL twice plus a clean `/tmp` replay, trace `3ae896390ce28d6ec551dbac3e8e6473fd7ae923be9cb7f42762721dbdd78d02`; ASan `WRITE of size 34465`, `WRITTEN=65535`; gdb reads `0xb3`/`0x87`/`0x86` at destinations 0/17/16384 equal to peer bytes at source offsets 65535/65552/81919), strengthening rung 4 to peer-chosen bytes. W3's direct dispatch attempt failed: `uv_run()` segfaults in `libuv.so.1` before dispatch with no marker, also when the handle bytes are preserved verbatim, so collateral heap corruption blocks that consumer (author-side negative, rung 5 UNKNOWN at that verdict); W5's zero-filled 293865-byte heap-image shortcut also crashed `uv_run()` with `MARKER=0`, so the required bytes stay distributed through the heap. W4 then let libuv's own `uv_run()` call the peer-rewritten `async_cb`: `id>a` and `id>b` both produced `MARKER=1` with `id` output, `UV_RAN=1` and rc 0, with no debugger attached to the exploit run. W147 witness-ESTABLISHED rung 5 only at the explicitly conditioned lab scope — non-PIE, ASLR off, a gdb-derived 293865-byte heap image replayed as peer bytes at fixed delta 293440 with a known libc address and benign `id > file` only — not wire-only or deployment RCE** — CVE-2026-85091 (VulnCheck CNA 2026-09-02, HIGH 8.3 `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H`, CWE-787), zlib 1.2.11–1.3.2, fixed by `df84af25` (+4/-1 reset of `avail_in`/`next_in`); tarball `bb329a0a`, parent `bbc2ccf3`, fix `df84af25`, patch `110ff143`. Base harness 31 PASS / 0 FAIL x3 plus clean `/tmp` replay, trace `28bbacf46cc178ebea825bfc57bcc83564607b4c8a32c52d7531a2d1524d7a89`; operator replay rc 0, 30 PASS / 0 FAIL, same hash. Witness W144 (#2198/#2221) replayed both harnesses from a clean archive and returned ESTABLISHED for base rung 3/4 and W1 rung 4 at the labeled build scope, no counterexample; W147 later ESTABLISHED the conditioned rung 5 from W4, with no replay owed at W144's verdict. Pins, raw evidence and negatives in `lab/frontier/zlib2shell/PROVENANCE.md`; status `reports/zlib2shell-status.md`. |
| **Snap72Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 05:1xZ under standing #6 as the 101st route; LIVE/CODE/HARNESS rung 3 ASan `heap-buffer-overflow` WRITE of size 65535 in verbatim pinned `opReadMultiVars()` at `s7_micro_client.cpp:418`, 0 bytes after a 1-byte caller region, with gcc and clang; scoped rung 4 chosen wire bytes `0x5a`/`0x3c` at destination offsets 0/17 (`0x6b`/`0x4d` at 17). Issue-#32 derived guard returns `errCliInvalidPlcAnswer`, safe 1-byte input clean; the admission harness stub-injected the response with only 32 real payload bytes, while W1 then drove a plant-written fake S7 responder on 127.0.0.1 through COTP CR/CC and Setup Communication into the real pinned client library under ASan and the witness returned ESTABLISHED at that explicitly labeled lab-wire scope. W2 measured 4000/65535 chosen bytes byte-exact (`MATCHES=4000`, `FIRST_BAD_OFFSET=4000`, hash `f254a539…c3808`); W5 measured a two-item live-wire response where item 0 declaring `0xFFFF` advances the pinned line-427 offset by 65540, so item 1's header is read outside the response (`ITEM0_RESULT=0 ITEM1_RESULT=36700160 DST1_0=cc`, no ASan report and no second memcpy, safe control 0/0 `DST1_0=77`), yielding stale client state rather than peer-controlled bytes. W6 independently rebuilt from a clean `git archive HEAD 1f8f9b9` with pins regenerated from the hash-matched local tarball `2840d50a…c613c36`, replayed `run_multi.sh` twice rc 0 with 4/4 cases and the exact `e4983fed…d63c` hash, and graded the two-item negative ESTABLISHED at the same labeled lab-wire scope; the earlier normalized-hash difference was only the absolute ASan source path in the normalizer. W7's plain caller-fate probe faults inside the pinned line-418 copy at the brk boundary before `delete[] dst` for destination sizes 1–16384, with a 200000-byte mmap control clean. W8 swept declared DataLength (`run_modlen.sh`, one-byte destination, 256..49152): all exit 0 with `CLIENT_READ_RC=0 ITEM_RESULT=0 DST0=5a`; ASan at 4096 still reports `WRITE of size 4096` at pinned line 418 while gdb shows a normal exit, and only declared=65535 faults — even when the copy stays mapped and `free()` is reached, no post-overflow heap dereference is observed (negative measured, not inferred). No grade change and no pointer redirect, ROP, command or rung 5 observation; rung 5 UNKNOWN, and `AT:P` needs a malicious or impersonating PLC** — CVE-2026-131848 / GHSA-xr6p-cjp3-pvwg (NVD CNA 2026-11-18, HIGH 8.3 `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:H/VA:H`, CWE-787), Snap7 <=1.4.3 pinned at upstream HEAD `30f37da`; no upstream fix, so the fixed control is a pinned derivative of reporter issue #32. Harness 43 PASS / 0 FAIL x3 plus clean `/tmp` replay, trace `24c8438c85474ab76ade31d8c9d98e1a510f926b4f97cf6ee8948208427eda59`; operator replay rc 0, 43 PASS / 0 FAIL, same hash. Pins, negatives and raw evidence in `lab/frontier/snap72shell/PROVENANCE.md`; status `reports/snap72shell-status.md`. |
| **Mongoose2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 05:3xZ under standing #6 as the 102nd route; CODE/HARNESS rung 3 gcc+clang ASan `READ of size 1` in `find_opt()` at pinned `l2_ppp.c.8bb65c64926d:281`, 0 bytes after a 14-byte frame, and `WRITE of size 65535` in `ppp_tx_frame()` at pinned `:234`, 0 bytes after a 1088-byte transmit allocation; scoped rung 4 chosen `0x5a`/`0x3c` at canary offsets 0/17, real upstream fixed blob ASan-clean with `TX_CALLS=0`, well-formed frame clean. Direct-call harness with recording stubs, local heap buffers and a harness-chosen `tx.buf`; W1 also drove the real-stack ingress with a measured 1504-byte `framesize` and LCP gate, and witness #2287 returned ESTABLISHED at both explicitly labeled scopes (direct-call pinned-slice harness and real-stack ingress harness), no counterexample and grade unchanged; no real PPP/PPPoE link, socket, NIC, pointer control, command or rung 5** — CVE-2026-63626 / GHSA-pc66-j6r6-49x9 (CNA GitHub_M 2026-10-14, CWE-122 + CWE-125), Mongoose <7.23, fixed by upstream `751f14742dea` (+6/-2 length guards) with vulnerable parent `8bb65c64926d`; three blob SHA-256 pins in `lab/frontier/mongoose2shell/PROVENANCE.md`. Harness 43 PASS / 0 FAIL x3 plus clean `git archive HEAD` /tmp replay; operator replay rc 0, 43 PASS / 0 FAIL, `TRACE_SHA256=8c5d62a55be40595f76d3479f05a9ab4652585f07ebae13cd35017d64e3d1cb7`. Brief `reports/frontier-mongoose2shell.md`; status `reports/mongoose2shell-status.md`. |
| **Modauthoidc2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 06:2xZ under standing #6 as the 103rd route; CODE/HARNESS rung 3 gcc+clang ASan `READ of size 1` in verbatim pinned `oidc_state_cookies_parse_token()` at `state.c.4301b536:214`, 0 bytes past a 31-byte exact-size token; scoped rung 4 one-byte NUL at chosen offsets 31/47/63 with intact canary, byte value not chosen; real upstream fix commit and released `v2.4.19.4` slices ASan-clean with no dispatch, well-formed token clean on all six binaries. Direct-call harness with stubbed request/config and a recorder; a later unwitnessed real-object probe uses a real `apr_pool_t` and Apache `request_rec` but no module, listener or wire, twice 17 PASS / 0 FAIL with the first ASan-poisoned byte 95 bytes past the token — APR arenas have no per-object redzone. W6 then built the full parent module at `4301b536` with ASan against APR 1.7.4 / APR-util 1.6.3 / httpd 2.4.71 and drove an unauthenticated `Cookie: mod_auth_openidc_state_novalue` GET to `/protected` on 127.0.0.1:18090: 30/30 ASan `heap-buffer-overflow` READ at pinned `state.c:214` with a full native stack through `ap_run_check_user_id`, released `v2.4.19.4` 0/30 faults and 30/30 HTTP 302; a first layout-dependent run gave 7/30 faults and 23/30 out-of-bounds dispatches (preserved negative). The pre-auth caller chain `oidc_check_user_id → oidc_handle_unauthenticated_user → oidc_request_authorization_set_cookie` (`handle/request.c:132`) → `oidc_state_cookies_clean_expired` (`state.c:229`) → `oidc_state_cookies_parse_token` is now source-bound and live, so rung 3 is confirmed on a real pre-auth wire path. W8 reached the NUL store itself on that path: `Cookie: mod_auth_openidc_state_novalue;<name>=<value>` leaves the second cookie's `=` after the value-less token's NUL and pinned `:219` stores NUL over it; gdb observed `0x3d` → `0x00` at token offset 39 (8 padding bytes) and 63 (32 bytes), i.e. `30 + 1 + <name length>` chosen by the request, with 5/5 vulnerable parser dispatches versus 0/5 on the released fix, all HTTP 302 and no ASan report in that in-bounds regime (a `halt_on_error=0` continuation is a preserved negative). Rung 4 is now observed on a live pre-auth wire path with a wire-chosen offset, W170 ESTABLISHED at that scope: the byte is always NUL and W8's overwritten `=` lies in the already-tokenized header copy. W9 measured a distinct out-of-bounds store in the `build-plain.sh` full module on a live pre-auth request: at pinned `state.c:219` gdb saw the low byte of pointer `0x7ffff5603d` become `0x00` (`0x7ffff56000`) in the OIDC shm mapping, with a watchpoint catching no later access; the real-object harness shows the same shape and the next `apr_socket_accept` overwrote the word, so the corruption is connection-scoped. Rung 4 now includes a pointer-bearing target on a live pre-auth wire path, W170 ESTABLISHED at that scope: the byte stays NUL, the target is not wire-chosen and no consumer read, chosen byte value, command or rung 5 is shown. W10 kept a hardware watchpoint on that word across three requests on the same TCP connection (all HTTP 302, no watchpoint hit within 70 s; a one-off LD_PRELOAD APR allocator trace found no covering allocation, the nearest starting 0x6f bytes later, with intra-libapr calls bypassing interposition) — a preserved no-consumer negative that W10 also ESTABLISHED: pointer-bearing names the 8-byte shape, not a demonstrated dereference. W11 reached the second pre-auth caller on the wire: an unauthenticated `GET /redirect_uri?code=foo&state=foo` with the value-less cookie goes through `oidc_response_proto_state_restore` (`handle/response.c:353`), where the store at pinned `:219` turns `=foo&sta` into `\0foo&sta` at the wire-chosen `=` of `code=foo` in the copied request line; HTTP 400 and JWE decode failure followed with the watchpoint silent, W170 ESTABLISHED at that scope. W12 faults a `build-plain.sh` child intermittently on a live pre-auth wire with a bare 7800-byte value-less token (2/3 extended sweeps, not in a fresh 30-request sweep); a lab SIGSEGV+ASan interposer attributes the frame to pinned `state.c:219` in 60/60 runs but changes signal/allocator layout and does not raise the native crash rate, while well-formed and released-fix controls stay 10/10 HTTP 302 and gdb/fork sweeps never fault. W14 found that this "plain" build still links the ASan runtime: module `00899061…5654` and serving httpd both load `libasan.so.8`, apxs injected `-fsanitize=address`, and `nm -D` shows ASan report calls, so `ASAN_OPTIONS=detect_leaks=0` changed that allocator's layout; the SIGSEGV, stored bytes and controls stand, and W15 below replaces the old "no availability claim on a production allocator" caveat with a measured non-ASan crash. W14's long-token limb (`67a7857`/`2ebb69b`/`4f69e2c`) faults a non-ASan real-APR harness at pinned `:219` with a value-less token ≥32000 bytes: 5/5 at 32000/48000, then 3/5 at 65000 and 4/5 at 100000 in a clean-archive replay — a layout-dependent rate, not a fixed fault probability. W15 (`158cb11`) rebuilt both pinned modules with system apxs against Ubuntu httpd 2.4.58 / system APR and non-ASan dependencies (`ldd` shows no libasan) on loopback 18091: a bare 7800-byte cookie gave 0/48 HTTP 302 and 44 logged child SIGSEGVs across four fresh starts, controls 16/16 302 with zero faults, and 5/6 one-request starts faulted on the first request (1/6 clean); no native faulting PC was captured, the byte stays NUL and this scope is author-only/unwitnessed. W170 (16:58Z) independently replayed W6/W8-W11/W13/W14 from a full `/tmp` copy at HEAD `10fdd31` with tracked scripts hash-matched and pinned `state.c` `ceedb687…5aa` / module `00899061…5654` verified, returning ESTABLISHED at those labeled live-wire and harness scopes, no counterexample, no grade change, NOT rung 5; W12's shim experiment and W15 stay unwitnessed. W147 ESTABLISHED covers the direct-call harness only (59 PASS / 0 FAIL, byte-identical normalized trace, no repair owed). No chosen byte value, pointer control, command or rung 5; the external advisory text remains claim/UNKNOWN** — CVE-2026-54789 / GHSA-vgr5-qcpp-x2pr (CNA GitHub_M, HIGH 7.5 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, CWE-125 + CWE-787), affected `< 2.4.19.4`, fixed by `8017478471cc` and released `v2.4.19.4`. Operator clean-archive replay rc 0, 59 PASS / 0 FAIL, trace `bbda75f0cf7e4e1789b75bd206922f7ccbbb0c24b676e8b92fb833af4c448459`. Status: `reports/modauthoidc2shell-status.md`. |
| **Radvdump2Shell** | ✓ | ✓ | ✓ | ✓ | ✓ | **ADMITTED 06:4xZ under standing #6 as the 104th route; LIVE/CODE/HARNESS rung 3 gcc+clang ASan `stack-buffer-overflow` `WRITE of size 256` in the verbatim pinned `print_ff()` Route Information case at `radvdump.c.878ca6b:380`, 240 bytes past a 16-byte `struct in6_addr`; scoped rung 4 chosen bytes at copy offsets 17/24/33/40/63 and a chosen saved-RIP byte `0x414141414141417b` under gdb; fix commit `068bde13` and released `v2.21` reject length 33 before the copy, and RFC-conformant length 2 is clean on all variants. The admission harness direct-calls the case body with stubbed `flog`/`addrtostr`/`print_preferences`; a post-admission 07:02Z author-only limb (no witness) built real v2.20/v2.21 from tag tarballs and fed a crafted RA as a unicast ICMPv6 packet to `::1` on `lo` from a root raw socket: real v2.20+ASan faults with `WRITE of size 256` at `radvdump.c:380` in `print_ff`, length-2 input is clean, real 2.21 rejects length 33, and gdb reads a live pointer `rinfo = 0x1234567812345678` (copy offset 112, length 33) and `saved rip = 0x1234567812345678` (copy offset 296, length 40). Default `-O2` `_FORTIFY_SOURCE` aborts, `-O2 -U_FORTIFY_SOURCE` copies with no control, length-33 cannot reach saved RIP, and the process SIGSEGVs at line 382 before the saved RIP is used as control flow; PIE+ASLR live. A 07:46Z author-only limb drove a 496-byte RA with length byte 60 on `::1%lo` in a non-fortified `-O0 -g -fno-stack-protector` v2.20 radvdump with gdb ASLR off: `(len-1)*8 = 472` bytes reach the saved RIP and `pop rdi; ret -> &command -> ret (alignment) -> system -> exit` created a root-owned zero-byte `/tmp/radvdump2shell-marker` 3/3; `system` is not in radvdump's normal callpath. RFC length 2, fixed 2.21, ASLR-on without gdb and fortified `-O2` controls were all marker-absent; `sudo` clears `ADDR_NO_RANDOMIZE`, so gdb's inferior-level disable-randomization is required, and without the extra `ret` for stack alignment `system` SIGSEGVs in `do_system`. W149 independently replayed the command ESTABLISHED at the explicitly labeled lab conditions (non-fortified `-O0` build, ASLR disabled in the lab debugger, host-measured absolute addresses, root `CAP_NET_RAW` sender on `::1%lo`, benign `touch`): its witness-only command `/usr/bin/touch /tmp/w149-radvdump-witness-marker` at copy offset 336 produced 4/4 fresh root-owned zero-byte markers with `$rdi` holding exactly that wire string at a passive `__libc_system` breakpoint; its own clean `git archive HEAD (1f8f9b9)` build used different absolute stack addresses per process. No ASLR-on command execution, no wire-derived addresses and no external target; fortify and ASLR-on negatives preserved** — CVE-2026-48715 / GHSA-52px-gh9p-m379 (CNA GitHub_M, HIGH 7.7 `CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CWE-121), affected `<= 2.20`, fixed in `2.21` by `068bde13`. Operator clean-archive replay rc 0, 67 PASS / 0 FAIL, trace `cf327179a2abca7647a1a8bd3b58259a398c7de94f24a27910f3a356d8d3788a`. Status: `reports/radvdump2shell-status.md`. |
| **Fluentbit2Shell** | ✓ | ✓ | ✓ | ✓ | ✓ | **LIVE — rungs 3/4 ESTABLISHED at their labeled scopes; rung 5 witness-ESTABLISHED (W150/#2415) at the labeled `-fno-stack-protector`, `setarch -R` ASLR-off, gdb-measured base+stack, minimal-env, loopback, benign-touch scope.** A real Fluent Bit 5.0.7 process on loopback receives a malicious upstream Secure-Forward PONG: the 1000-byte `PONG[2]` STR into a 32-byte stack `msg` at `forward.c.47db630c:567` gives ASan `WRITE of size 1000` in `secure_forward_pong` (rc134), chosen bytes land at saved RBP/RIP offsets 48/56 and a canonical RIP is taken at `ret`; a PONG-carried ROP chain ran a lab-chosen benign `touch` with a zero-byte marker and NO debugger (victim rc2). Witness W150 replayed from clean `git archive c076655` with its own hash-matched builds, ports, marker and ROP hex: WRITE-1000 on 20651 and a no-debugger marker on 20642; fixed ASan, authorized PONG, stock-canary and ASLR-on controls produced no marker. No default-build claim, no ASLR-on command execution, no wire-derived addresses, no root/persistence and no external target — attacker is a malicious/on-path upstream forward destination, victim a forwarding agent with `Shared_Key`. CVE-2026-61674 / GHSA-jrp8-r9hx-gf73, fixed 5.0.8 (`45486556`). Reports: `reports/fluentbit2shell-livewire.md`, `reports/fluentbit2shell-status.md` |
| **Ffmpeg2Shell** | ✓ | ✓ | ✓ | ✓ | ✓ | **LIVE/CODE/HARNESS — W2 reaches the sink in a real ASan FFmpeg n9.0 process over a loopback RIST wire through `async:rist://`: `WRITE of size 9968` from `librist_read()` at `libavformat/librist.c:230`, 0 bytes past the 8388608-byte async FIFO allocated at `async.c:88`; two vulnerable runs fault, the one-line `FFMIN`-fixed build and a 512-byte safe input stay clean. gdb on the live process reads chosen 0x41/0x7a/0x3c/0x42/0x63 at ring offsets 4096/4113/4120/5000/9000 with `caller_size=4096`. Live geometry: the destination is a slice of an 8 MiB FIFO, so ~8 MiB of streamed data is needed to walk the write pointer to its end; a stock librist sender caps payloads at 9968, four below FFmpeg's 9972 receive gate. Harness rungs 1-4 witness-ESTABLISHED (#2384) at the labeled direct-call scope; the live path witness-ESTABLISHED (W151/#2428) at the labeled live-loopback / ASan / ~8 MiB ring-wrap scope, with the witness's own builds and port 5514. Default mmap and plain builds hit a read-only libc mapping at the wrap with no writable neighbour; W3's local `MALLOC_MMAP_THRESHOLD_=16777216` brk layout puts the FIFO on `[heap]` and the sender's 0x5a fill overwrites the low byte of live `AVFifo.buffer` and `URLContext.prot`, which the consumer then dereferences — scoped rung 4 pointer control under a local prerequisite, witness-ESTABLISHED (W152/#2444) at that labeled scope, not a chosen-address write, control transfer, marker, command or rung 5; no ROP chain is asserted** W4 continues W3: the whole 8-byte `URLContext->prot` is attacker-controlled at the next natural `ffurl_read2`, and the consumer's first natural indirect call is `interrupt_callback.callback(opaque)` from `ff_check_interrupt` (`avio.c:520`). With no debugger attached, `setarch -R` ASLR off and lab-measured absolute addresses, wire bytes set that callback to `system` and carry a benign `touch` command inside the overwritten `URLContext`; the vulnerable process creates the marker file (mtime 09:30:58Z) while FFMIN-fixed, 512-byte safe and callback-zero controls leave it absent, sender rc 0 in all four. Witness W153 (#2461) replayed the four no-gdb checks with witness-owned builds on port 5714 and ESTABLISHED the command claim at the labeled scope: its own marker paths and `/usr/bin/touch` variants, calibrated `&system 0x7ffff7a58750`, `&ff_file_protocol 0x55555584f5a0` and `h 0x5555560d2080`, fixed/safe/cb=0 marker-absent (rc 124/134). The limits stay in the claim: `setarch -R` no-ASLR, local brk-layout variable, lab-measured absolute addresses as sender args, unencrypted main profile, benign `touch` only, no ROP and a later abort of the vulnerable process. No default-mmap, ASLR-on or stock-layout RCE claim. ** — CVE-2026-75143 / GHSA-7qc3-xqxj-426p (Critical 9.3 `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CWE-122), RIST payload copied into an async caller buffer capped at 4096. Pins and URLs in `lab/frontier/ffmpeg2shell/PROVENANCE.md`; harness brief `reports/frontier-ffmpeg2shell.md`; live result `reports/ffmpeg2shell-live.md`; status `reports/ffmpeg2shell-status.md`. Operator replay from clean `git archive HEAD` matched 66 PASS / 0 FAIL and trace `6c3586c5d5b510b9619431873b157055c97edc32c5b6eda9967eb4feae61629f`. |
| **Thrift2Shell** | ✓ | ✓ | ✓ | ✓ | — | **ADMITTED 09:5xZ under standing #6 as the 108th route; LIVE/CODE/HARNESS rungs 1-4 on unmodified upstream bytes, with a witness-ESTABLISHED ASLR-off KV-header `free()`-pointer limb and separate author-only ASLR-on no-flush and accepted forged-chunk `free()` limbs, all rung 4 and no rung 5.** Frontier staged W143 in commit `42abf3a`; the registered two-pane window 111 was adopted, no second window. CVE-2026-55971 / GHSA-gwj4-q93m-wwqc (Critical 9.3 `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CWE-122), Apache Thrift before 0.24.0, fixed 0.24.0 by `db4a473f` buffer swap: `THeaderTransport::untransform()` inflates a 31-byte compressed frame to 700 bytes in a 1024-byte transform buffer, then copies 700 bytes back over the 31-byte receive frame at pinned `THeaderTransport.cpp.v0.23.0:301`, 669 bytes over. Direct-call harness with four verbatim pinned slices and stubs: `PASS=71 FAIL=0`, trace `c12ba214…bbe556`, gcc+clang ASan `WRITE of size 700` at pinned `:301` (fix parent `:320`), chosen bytes at inflated offsets 0/16/32/64/128/256/699 under gdb; fixed, v0.24.0, safe-input and gate controls clean. A plant-started unmodified v0.23.0 `TSimpleServer` + `THeaderTransport` + `TSocket` + ZLIB server on 127.0.0.1 reaches the sink from a 72-byte frame: ASan `WRITE of size 726` at pinned `:301` via `readMessageBegin` → `ReadOnceProcessor` → `TConnectedClient` → `TSimpleServer` into a 68-byte `rBuf_`; v0.24.0 and 4-byte safe input clean; `live/raw-client.py` replays with Python socket only. Plain build puts chosen markers in the adjacent `tBuf` chunk header and aborts in `munmap_chunk()`. On the persistent-connection limb, frame 2 gets a fresh 68-byte `rBuf_` after the transform buffer (`tbuf = rbuf - 1040`), so the copy no longer touches `tBuf` and aborts with `malloc(): corrupted top size`; no code pointer or return address lies in the written range. KV-header grooming then put wire-chosen bytes in live `std::string` pointers consumed by `free()` (`mem=0x7f4242424240`, alternate `0x7a5a42424240`; ASLR off, exact glibc/tcache bytes; v0.24.0 and pointer-restored frames clean); the witness returned rungs 1-4 ESTABLISHED at that labeled lab scope with no counterexample (NIT: a `-O1` plain rebuild shifts `rbuf` by `0x8000`). A separate ASLR-on no-flush limb (lab server discards writes/flush/close; upstream read/copy unchanged) ends a 312-byte copy inside a live string pointer so only the low 16 bits come from the wire and `free()` receives `0x...4240`/`0x...c3a0` with randomized high bytes (fixed control clean); author-only, UNVERIFIED (no W145 verdict). W146 closes the direct-vptr route as a negative (the `THeaderTransport` object sits 0x980 before `rBuf_`, outside the 726-byte copy window, with no executable-mapping pointer in the swept span) and upgrades the rung-4 primitive: a forged `0x31` chunk header plus low-16-bit sweep makes ASLR-on `free(rBuf_+512)` accepted, overwriting one 0xA5 marker qword at `rBuf_+512` with an allocator-written heap link; fixed stays clean, safe aborts, and Docs' live replay matched normalized hash `bcde0050…6bc3a1`; author-only, UNVERIFIED (no W146 verdict). W147 sweeps post-copy qwords across five vulnerable layouts (0/2/4/8 KV headers, 32/64-byte strings): every layout has `EXEC_QWORDS=0` with ASLR on after `process()`, the sole heap pointer sits at +1008 outside the 726-byte copy, and the fixed control stays clean; a clean-archive replay at `9579cc8` reproduced the anchors with normalized hash `295b2ff…794c6bb` after an initial `ConnectionRefusedError` was preserved as a negative. Author-only, UNVERIFIED (no W147 verdict). W149: no verdict arrived for W145 (#2547) or W146 (#2598); the last witness DM (#2506) established only the older W144 rungs 1-4, so these limbs stay UNVERIFIED — not ESTABLISHED and not refuted — with one closure request (#2759) and no repeats; the author exploitation lane is closed at the measured ceiling and the grade is unchanged. W152 (`25133a3`) clears the witness-cap explanation recorded at W151: verdicts on other lanes landed at 19:20Z and the wall was stamped W175 19:23Z, but the 19:27Z tape check found no DM to the role since #2533 (W144 rungs 1-4 ESTABLISHED; W149-W151 name #2506 for that verdict), and the #2759 closure request for #2547/#2598 remained unanswered. Wall line 171 still says `No replay owed on the W146/W147/W148 lanes` and names neither in pending, so read literally W146's replay is declined while W145 is unanswered/not queued. Both stay UNVERIFIED — not refuted, not ESTABLISHED and not a counterexample; W151's scheduling explanation is stale as current state, disposition and grade unchanged, no new experiment. No code-pointer/return-address control, ROP, command, marker side effect or rung 5; no externally reachable configuration claimed. Status: `reports/thrift2shell-status.md`; live wire: `reports/thrift2shell-livewire.md`. |
| **Psqlodbc2Shell** | ✓ | ✓ | ✓ | ✓ | — | **ADMITTED 09:4xZ under standing #6 as the 107th route; CODE/HARNESS rung 1-4 at direct-call scope with later real-pinned-tag object, public ODBC `SQLExecDirect` and real-loopback-PostgreSQL limbs; witness W156 (#2572) ESTABLISHED the W146 public-ODBC limb at its labeled harness scope and witness W162 (#2689) ESTABLISHED the W161 real-server date limb at its labeled scope, no grade change.** Frontier staged W144 in commits `13c835d`/`255dfd4`; the registered two-pane window 112 was adopted, no second window. CVE-2026-120061 / GHSA-hfm6-qfx8-v4xq (High 7.5 `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-121/193/457), affected `<= 18.00.0005`, fixed 18.00.0006 by merge `79f4631d`: unbounded 16-entry `param_pos` stack writes in `processParameters()` (`convert.c.vuln:5637`) plus a one-byte NUL past `buf_small[128]` in `F_ExtractOldTo` (`:2424`). Direct-call harness only: `PASS=34 FAIL=0`, trace `d5145bdb…424d63`, gcc+clang ASan `WRITE of size 8` at `:5637` and `WRITE of size 1` at `:2424`, plain build puts chosen `0x5a` in an adjacent sink (`FIRST_DIFF=0 CHOSEN_5A=112`), fixed runs clean; a clean `git archive HEAD` replay reproduced the same trace. A later real-object limb builds pinned `REL-18_00_0005`/`0006` with ASan and links `real/real-driver.c` against real upstream objects through `prepareParametersNoDesc()`: ASan `WRITE of size 8` at `convert.c:5637` via real `convert_escape:5864` → `inner_process_tokens:3865` and `WRITE of size 1` at `:5786` for a 200-byte `{d}` body; fixed rejects `RC=-1 ERRNUM=1`. Real `-O0` frame: `param_pos` ends `...d100`, saved RIP `...daf8` (2808 bytes past), the NUL lands in `buf[0]` after `buf_small`; larger inputs corrupt `nqb->query_statement` (SIGSEGV `inner_process_tokens:4167`) before a saved pointer. At `-O2` the canary trips at 96 args, n>=128 SIGSEGV with `$rbp=0xc3`; the first OOB write is at 16 arguments (`param_pos[16][0/1] = -1` at `convert.c:5657`, gcc+clang ASan `WRITE of size 8`; 15 clean), and clang `-O0`'s 16-arg rejection is a stack-layout alias onto `param_consumed` in the caller's `convert_escape` frame, not a parse difference (17+ accepted by both plain builds). A tracked `real/live-replay.sh` limb compiles the pinned ASan driver `.so`, registers it in lab-local ODBC config and drives `SQLExecDirect` through `libodbc.so.2` against a fake PostgreSQL v3 handshake on 127.0.0.1:59432: ASan `WRITE of size 8` at `convert.c:5657` via `SQLExecDirect` → `PGAPI_ExecDirect` → `PGAPI_Execute` → `copy_statement_with_parameters` → `inner_process_tokens` → `convert_escape` → `processParameters`, with fixed `EXECDIRECT rc=-1` and safe `rc=0` clean; `SQLPrepare` alone sends no Parse (preserved negative). W147 replaces the fake handshake with a **real loopback PostgreSQL 16.4 server** (127.0.0.1:59433) and valid application SQL `SELECT {fn CONCAT(1,...,16)}`: 3/3 replays, vulnerable `WRITE of size 8` at `convert.c:5657` through `SQLExecDirect` → `PGAPI_ExecDirect` → `processParameters`, fixed `EXECDIRECT rc=-1` (`too many parameters in the escape function call`), safe `rc=0` ASan-clean; a bare escape as the whole statement reaching the server as `concat(...)` and failing syntax was a harness form error, corrected. Grade unchanged: the OOB stores are integer `SQLLEN` values, `F_ExtractOldTo` writes one NUL with no length sweep, and the terminator scan cannot be walked past row 16 on the measured layouts (source reasoning, not an executed limb). Witness W156 (#2572) replayed the W146 public-ODBC limb from a clean `git archive 87f8bb8` with eight self-rebuilt tagged trees (6/6 pins OK) on private port 59436: vuln ASan `WRITE of size 8` at `convert.c:5657` through `libodbc.so.2 SQLExecDirect`, fixed `EXECDIRECT rc=-1`, safe clean, `SQLPrepare` negative; ESTABLISHED at that labeled harness scope, no counterexample or grade change, fake-handshake ceiling preserved. W159 rebuilds the pinned vulnerable tag with `clang -O2` over real upstream objects: `n=73 rc=0`, `n=74 rc=139` at the parser's own `QueryBuild` local, and a hardware watch shows `nqb.query_statement` changing from a live heap pointer to integer `0x95` at `convert.c:5638` while the saved-RIP slot, 13 rows farther, never fires; that closes this optimized-layout reopen condition as a rung-5 negative, author-only and unwitnessed. W160 adds a fixed-tag `clang -O2` control (REL-18_00_0006/`96fa03d`): fixed n=16/74/80 all rc=1 with `too many parameters in the escape function call`, vulnerable n=73 rc=0 and n=74/80 rc=139, three identical runs. W161 drives `SELECT {d '<200 A>'}` through real loopback PostgreSQL 16.4 via `SQLDriverConnect`/`SQLExecDirect`: ASan `stack-buffer-overflow WRITE of size 1` at pinned `convert.c:5786` (F_ExtractOldTo NUL store `:2435`), offset 992 one past `buf_small[864,992)`, boundary exactly 126 A's; fixed rc=-1 (PG 42601), safe rc=0. Witness W162 (#2689) rebuilt both ASan trees from a clean archive with 6/6 pins OK on a private PG port, reproduced the whole matrix and graded W161 ESTABLISHED at that labeled scope with no counterexample (NITs at `:2435` vs `:2424` and distinct 42601 messages folded); W147's verdict #2576 stays pending. W165 probed the advisory's CWE-457 limb on the real path: seven escape forms x two pinned ASan tags against real loopback PostgreSQL 16.4 on 127.0.0.1:59436 returned `param not found` or arity failures on both tags with zero ASan `READ`/`WRITE` and no stale-byte copy, even after shaping escapes on the same connection — the closing `)` writes an explicit `-1` sentinel — so this limb is a preserved negative, not a pointer disclosure; the uninitialized-array claim stays a claim for untested malformed inputs or other layouts. W166 extends the saved-RIP question to larger counts under gdb on the existing `clang -O2` real-object binary: n=88 leaves the `param_pos+0x578` slot at `0x555555567641` with a hardware watch never firing, and n=96 shows the recursive token parser overwriting its own live `nqb` at rows 74/75 and dereferencing it in `QP_exit` before rows 76..87 are reached; fixed n=96 rejects with `too many parameters in the escape function call`. No pointer, partial pointer, marker or control-flow diversion — a negative, author-only and unwitnessed. Still no chosen pointer/control-flow datum, marker, command or rung 5; AV:N stays claim/source-only. [Brief](reports/frontier-psqlodbc2shell.md) · [Status](reports/psqlodbc2shell-status.md) |
| **Libvips2Shell** | ✓ | ✓ | ✓ | ✓ | — | **ADMITTED 10:0xZ under standing #6 as the 109th route; CODE/HARNESS rung 1-4 on the direct-call scope with later real-build and real-consumer limbs; witness W157 ESTABLISHED at the labeled rung-4 real-image/public-API WRITE scope.** Frontier staged W145 in commit `2f35788`; the registered two-pane window 113 was adopted, no second window. CVE-2026-69242 / GHSA-9rwc-f68v-4482 (High 8.4 `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:H/SC:L/SI:H/SA:H`, CWE-122/190), libvips `<= 8.18.2`, fixed 8.18.3 by `c72f509`: `vips_image_sanity()` accepts a scanline between `INT_MAX` and `UINT64_MAX`, `VipsRegion.bpl` truncates it to `int` (`region.c:637`), and `vips_region_paint_pel()` does `memcpy(q, to, ws)` at pinned `region.c.v8.18.2:1004` with `q = to - 256`. Direct-call generated drivers: `PASS=62 FAIL=0`, trace `5532e495…d1490e`, gcc+clang ASan `WRITE of size 4` at pinned `:1004`, chosen `0x5a` at `to-256` in plain runs with gdb `Q = TO - 0x100`; fixed sanity/gate/chain controls clean. A later real-build limb built pinned v8.18.2/v8.18.3 with ASan (433/433 targets) and loaded a 154-byte crafted many-band TIFF (10000 32-bit bands, width 107374, height 2) through real `VipsForeignLoadTiff`: `TIFF_SANITY=1` and `bpl=-7296` for the TIFF-accepted geometry; the `BPL=-256` truncation and ASan `WRITE of size 16` at `iofuncs/region.c:1004`, `DATA-0x100`, with chosen `0x5a` ink belong to the synthetic `Bands=4/Xsize=1073741760` staged shape in that same real build; fixed rejects `image: dimension overflow`. The staged `Bands=4/Xsize=1073741760` shape is rejected by the real loader (`VIPS_MAX_COORD`) as a preserved negative. W3 then drove real consumer APIs on a real 8,589,920,000-byte `vips_image_write_prepare()` buffer with the TIFF-accepted geometry (12/12 assertions, `RESULT fail=0` in the working tree and again from a clean `git archive HEAD` replay with the gitignored build/source trees symlinked in, rc 0): `vips_region_prepare()` reported `bpl=-7296`/`lskip=2^64-7296` and `VIPS_REGION_ADDR(reg,0,1)` faulted with a READ at `DATA-7296`; `vips_extract_area()` → `vips_image_write_to_memory()` produced ASan `READ of size 160000` in `vips_region_copy` (`region.c:1090`), 6144 bytes before the live allocation. W8 measured the decoded-TIFF consumer stall (>180 s) as a host guard, not a libvips finding: the wake cgroup sets `memory.max=2147483648` / `memory.high=1610612736`, and pinned `vips_tracked_aligned_alloc()` follows `posix_memalign` with an unconditional `memset` of the whole block sized `sizeof_pel*width*height`, so W7's two-row tilecache buffer is ~4.296 GB for `minline.tif` (one row ~2.148 GB), above the 2 GiB cap; the `memlimit.c` probe passes 7/7 at 64/256/1024 MB and returns rc 124 at larger limits; a clean `git archive d3dc9be` replay was `fail=0` (7/7) with canonical 21/21 consumer and 14/14 neighbour PASS; the tiled-TIFF alternative is UNMEASURED and rung 5 stays UNKNOWN. W4 adds a chosen-byte negative-offset **WRITE through the exported public API** `vips_region_paint()` on that real image: `vips_region_prepare({0,0,4,2})` gives `bpl=-7296`/`lskip=2^64-7296` and `vips_region_paint(reg,&r,0x5a)` memsets 160000 bytes starting at `data-7296`, ASan `WRITE of size 160000` at `region.c:922` (first poisoned byte 6144 before the live allocation); fixed rejects `image: dimension overflow`. A clean `git archive HEAD` replay at `22278cb` with gitignored build/source trees symlinked in returned rc 0, 21 PASS checks and `RESULT fail=0` (the report's "23/23" label overcounts the script's 21 assertions by two). Witness W157 (#2588/#2589) ESTABLISHED that labeled rung-4 real-image/public-API WRITE scope on a clean-archive 21/21 replay with 11/11 pins OK, reproducing the WRITE at `region.c:922` and the fixed rejection on independent ASan rebuilds; no counterexample, no grade change, rung 5 UNKNOWN. W6 measures what that negative WRITE lands on in plain pinned trees: the default layout targets an unmapped glibc gap (`MINCORE_TARGET=0 errno=12`, `RUN_RC=139`), while only an explicitly groomed 64 KiB neighbour receives chosen `0x5a` at offset 58272 (`PAINT_DONE`, rc 0); fixed rejects both. Docs clean-archive replay reproduced 14/14 neighbour and 21/21 consumer assertions, both rc 0. The neighbour is grooming and holds anonymous bytes, so on this host the write is an availability primitive with no natural control-flow neighbour; grade stays rungs 1-4, no pointer target, wire, command, marker or rung 5; advisory vector local. Status: `reports/libvips2shell-status.md`. |
| **Jq2Shell** | ✓ | ✓ | ✓ | ✓ | — | **ADMITTED 11:2xZ under standing #6 as the 110th route; CODE/HARNESS rung 1-4 on direct-call verbatim-pinned slices, witness W1 (#2556) ESTABLISHED at that labeled scope, witness W160 (#2651) ESTABLISHED the real-process alias geometry and witness W175 (#2950) ESTABLISHED the live heap-neighbour map at its labeled local-expression plain-build scope; no rung 5.** Frontier staged W146 in commits `c040c1e`/`f0f4b33`; the registered two-pane window 114 was adopted, no second window. CVE-2026-32316 / GHSA-q3h9-m34w-h76f (High 8.2 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`, CWE-190 -> CWE-122), jq `<= 1.8.1`, fixed 1.8.2 by `e47e56d226519635768e6aab2f38f0ab037c09e5`. Direct-call generated drivers over four verbatim `jv.c` slices: `PASS=64 FAIL=0` (64 assertions / 12 runs), trace `8d537806c87a39e1a41e5483a28a4a731e7d5fe970d6528f0dee207b13cef1e7`, reproduced exactly by the operator from a clean `git archive HEAD` at 11:2xZ. gcc+clang ASan `WRITE of size 48` at pinned `jv.c.vuln:1191` and `WRITE of size 3` at `:1126`; fixed slices reject both geometries. Rung 4 puts 16 chosen `0x5a` bytes past the 32-byte and 6-byte buffers, with gdb readback at `+32`/`+40`. Witness W1 (#2556) replayed `87f8bb8` from a clean archive (`PASS=64 FAIL=0`, same trace, 14 pins OK, independent gdb readback) and returned rungs 1-4 ESTABLISHED at that labeled direct-call scope, not rung 5. `bash lab/frontier/jq2shell/live/real-jq.sh` then built real pinned jq 1.8.1/1.8.2 ASan trees and confirmed the caller frames with small jq programs (`REAL-JQ-PASS`, geometry at `src/jv.c:1189/1118/1181/1117`); no overflow in that replay. The advisory's literal full PoCs stay guard-blocked (`memory.max=2147483648`, `memory.high=1610612736` vs a 2 GiB first operand; ASan rc=124 after 300 s, second PoC needs ~1.43 GiB decoded from ~1.9 GiB base64), no guard bypass attempted. A later limb aliases one 1 GiB jv string as both operands inside the real ASan jq 1.8.1 process: `bash lab/frontier/jq2shell/live/alias-geom.sh` reports `ALIAS-GEOM-PASS`, safe `len=2000`, vulnerable rc 134 with `WRITE of size 1073741824` at `src/jv.c:1191` and gdb `GEOM ALIAS currlen=1073741824 len=1073741824 allocsz=0`, fixed 1.8.2 rc 5 `String too long`; author records two byte-identical normalized logs. Docs' first clean-archive replay reproduced the safe, ASan and fixed controls and the matching summary/ASan hashes but did not complete the conditional gdb breakpoint (no `src/jv.c` in the copied tree, host swap 8.0/8.0 GiB with peer 1 GiB jobs, 400 s working-tree retry timed out); `1b86ae5` keeps those attempts UNKNOWN. Witness W160 (#2651) then replayed `alias-geom.sh` from a clean archive of `1b86ae5`: rc 0 `ALIAS-GEOM-PASS` in 65 s, 14/14 pins OK, three normalized logs byte-identical, the same ASan `WRITE of size 1073741824` at `src/jv.c:1191` and gdb `currlen=len=1073741824, allocsz=0`, fixed 1.8.2 rc 5, small-input alias clean; ESTABLISHED at the labeled real-process geometry scope, no grade change. A 13:4xZ limb maps the live heap neighbour in plain pinned jq 1.8.1 under gdb: the 49-byte `jvp_string` allocation takes a 64-byte glibc chunk whose successor is the 208-byte `struct jv_parser` (`jv_parse.c:711` <- `main.c:652`), and the uncapped ~1 GiB memcpy writes chosen `41 42 43 44` across its first 64 bytes before faulting inside memcpy; fixed 1.8.2 rc 5 `String too long`, safe alias clean, three later stalled attempts preserved UNKNOWN. Witness W175 (#2950) later replayed this map from a clean `ca620d0` archive (14/14 pins, `HEAPMAP-PASS`, exact normalized hashes), ESTABLISHED at the labeled local-expression, plain pinned-build scope, rungs 1-4 only; a `WXYZ` byte variation put `57 58 59 5a` at the same neighbour offset, so the bytes track the jq expression, and no jq consumer runs between copy and fault. W164/W165 close the 6-byte path analytically under the guard: the shortest wrapping length 1431655765 needs `3340530123` bytes on the `@base64d` route, and `-R`/`-Rs` raw stdin yields three U+FFFD bytes through a gdb-confirmed `jvp_string_copy_replace_bad(length=3)` call, normalized in 4095-byte chunks with no uint32 wrap; no sub-guard input reaches that copy. Rung 5 stays unclaimed: no request/wire input, destination-offset or pointer control, marker, command or side effect; real-pipeline reachability stays UNKNOWN and the neighbour map alone gives no control. [Status](reports/jq2shell-status.md) |
| **Libfontenc2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 15:0xZ under standing #6 as the 115th route; CODE/HARNESS direct-call rungs 1-4 plus a W155 real-library public-API and live loopback Xvfb `OpenFont` rung 3 under ASan; operator clean-archive replay exact; witnesses #2867 ESTABLISHED at those labeled scopes and #2914 ESTABLISHED the `SIZE 256 1024` plain crash at the labeled availability-only scope.** Frontier staged W154 in commits `64e3c54`/`d05d8d8`; the registered live two-pane window 115 was adopted, no second window. CVE-2026-109908 / GHSA-98gj-rwr5-8j74 (High 7.8 `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-122), libfontenc before 1.1.10 per the fix tag (advisory's "before 1.11.0" is preserved verbatim; W155 settled which releases carry the fix — `git tag --contains 5920c6e` lists only `libfontenc-1.1.10`, and rebuilt 1.1.9 faults on the crafted input while 1.1.10 is clean), fixed by `5920c6e` (parent `7418fa7`). Whole pinned `encparse.c` under `#line` with a real zlib `gzFile` over a temp `.enc` and stubbed font callbacks: `SIZE 256 258` + `0xff00 0x5a5a` makes `setCode()` store chosen `0x5a5a` 508 bytes past a 131072-byte region at `encparse.c.vuln:495`; gcc+clang ASan `WRITE of size 2`, fixed rejects at `:461`. `PASS=50 FAIL=0`, trace `bfdd7987…37fa2` exact in the operator clean `git archive HEAD` replay (5/5 pins OK). W155 also builds the real shared libraries at `7418fa7`, `5920c6e`, 1.1.9 and 1.1.10: exported `FontEncFind()` with a real `encodings.dir` reaches the same sink, and a loopback Xvfb with the pinned ASan library preloaded logs `OpenFont` → `libXfont2.so.2` → `FontEncFind` → `setCode:495` with ASan `WRITE of size 2` 508 bytes past the 131072-byte region on the crafted Type1 font, while fixed and safe inputs are clean in all four builds (client rc 1, broken X connection). Independent witness #2867 replayed the direct-call and live ASan `OpenFont` scopes from a clean archive at `6ee557d` (5/5 pins, `PASS=50 FAIL=0`, exact trace, eight rebuilt libraries, six live cases, fresh `WRITE of size 2` and gdb readback) with no counterexample or grade change. For `SIZE 256 258` plain-build impact is NOT demonstrated — the uninstrumented vulnerable Xvfb keeps running and `xdpyinfo` answers; W172 found a distinct uninstrumented Xvfb crash at `SIZE 256 1024` (index 261120, client rc 1, `xdpyinfo` rc 1, server abort, 3/3) while `5920c6e`, 1.1.10 and safe input survive and 1.1.9 crashes — an availability result, not pointer or control-flow control. W177 (`c83d597`) folds witness #2914: from a clean `git archive HEAD` at `3f44109` into `/tmp/w174-lfe` it rebuilt the four out-plain libraries (built `encparse.c` hashes match `PINS.sha256` vuln `79e2381b`, fixed `91c81398`) and ran its own `xfon-load`, reproducing all nine matrix lines (vuln 256/258/512 rc 0 + alive, vuln 1024 a/b/c rc 1 with `xdpyinfo` rc 1 and `server_alive=NO`, fixed `5920c6e` and 1.1.10 rc 0 + alive, 1.1.9 rc 1 + abort) with an empty data-line diff against the committed `plain-crash.txt`; the faulting instruction is the chosen store itself, `mov %dx,(%rax)` at `encparse.c:495`, signal 11. The witness's first `LD_PRELOAD` setup under `realpath/` silently missed, so SYSTEM libfontenc crashed every variant including fixed; that failed setup was diagnosed from the backtrace DSO and rebuilt at the correct BASE with PRELOAD_OK — preserved as a negative, not a result. Default glibc puts the 131072-byte request in an mmap chunk, so 508 bytes past is usable slack, and with `MALLOC_MMAP_THRESHOLD_=262144` it is a brk chunk followed by top, with no live object at the destination in either layout. W180 (`a636d12`) moves the precondition into a running server: `realpath/xlive/run-xset-fp.sh` starts a loopback Xvfb with an unrelated font path, adds a writable temp font dir with `xset +fp` / `xset fp rehash`, and only then writes the malicious `SIZE 256 258` `.enc` (launch 20:54:51.489Z, attack write 20:54:54.576Z); a second X client's `OpenFont` reaches `FontEncFind` → `setCode:495` with ASan `WRITE of size 2` 508 bytes past the region, while no-xset, safe-after-xset and both fixed builds stay clean. This demonstrates X-protocol font-path injection into an already-running display from a writable directory without a privileged font dir; OS-level unprivileged access to a production X display and that server's privilege stay UNKNOWN. No remote wire, OS-level unprivileged X display access, saved pointer, control-flow datum, marker, command or rung 5; rung 4 stays at the local chosen-store scope and the 16-bit `sm->first` truncates the out-of-range index. [Brief](reports/frontier-libfontenc2shell.md) · [Status](reports/libfontenc2shell-status.md) |
| **Openexr2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED ~11:5xZ under standing #6 as the 111th route; CODE/HARNESS direct-call rungs 1-4 with a later file-level CODE/CONSUMER lane, both rung 1-4 ESTABLISHED at their labeled scopes by W158 and W161 (#2675) respectively; no rung 5.** Frontier staged W155 in commit `efba219`; the live two-pane window 116 was adopted, no second window. GHSA-98rx-qpfv-qcwv (High, no CVE or CWE stated), OpenEXR 3.5.0–3.5.2 and `main` at advisory publication (W165 checked live upstream blobs: `main` is now patched, 54887-byte blob `393ffd9c…`, identical to 3.5.3, so the advisory's "main is byte-identical to 3.5.2" was true then, not today), fixed 3.5.3 by `7d7fbb1a`; vulnerable pin `v3.5.2`, fixed pin `v3.5.3`. `compute_sorting_lookup()` discards the full grid total, leaving the `split > uncompressed_size` guard vacuous for all-FLOAT parts, and `sort2_4ByteChannels_tiled()` copies at pinned `internal_zstd.c.vuln:472`: a forged 1024-sample FLOAT grid with `unpacked_size=64` gives gcc+clang ASan `WRITE of size 4096` 0 bytes after the 64-byte region (4032 bytes past), with chosen `0x5a` at `b64`/`b4095` against a `0xa5` canary under gdb; the fixed guard rejects with rc 23. Operator clean-archive replay `PASS=52 FAIL=0`, trace `27a2a815…3c776` exact. Witness W158 (#2602/#2603) ESTABLISHED the labeled direct-call CODE/HARNESS rungs 1-4 on a clean `git archive HEAD` replay (4/4 pins OK, pinned sources hash-matching raw upstream v3.5.2/v3.5.3 tags, `PASS=52 FAIL=0`, claimed trace exact) with independent gcc+clang ASan WRITE-4096 at `internal_zstd.c.vuln:472`, the fixed rc-23 rejection, chosen-byte and canary controls and a `0x41` ink variation; no counterexample, no grade change. A later limb builds real pinned 3.5.2/3.5.3 trees and feeds the advisory's 692-byte deep ZSTD EXR to `exr_decoding_run()` with ASan `memcpy-param-overlap` at `internal_zstd.c:472` and a guarded allocator measuring a 4032-byte overwrite of a 64-byte destination (4/4 PoC, 0/3 baseline); fixed rejects `EXR_ERR_CORRUPT_CHUNK`. `cases/cpp_singlepass.cpp` reaches the same fault through `Imf::DeepScanLineInputFile::readPixels(0,0)` without a pre-pass (baseline clean, fixed throws `Unable to run decoder`). Witness W161 (#2675) replayed the file lane from a clean archive with independently rebuilt trees and hash-matched logs, ESTABLISHED at the labeled file-level CODE/CONSUMER scope, no counterexample or grade change. Caveat for the older all-FLOAT and 692-byte lanes: the overwritten bytes are allocator-derived, not file-chosen — the file controls length and destination offset only. W180 (`9f42ba6`/`c13625c`) narrows that caveat for the mixed FLOAT-before-HALF part: sizing the chunk leader and inner ZSTD frame together to 2N moves the file-chosen HALF block to `decode.unpacked_buffer+4N` (`+128/+256/+512` for N=32/64/128) with 128/256/512 guard bytes changed on the pinned vulnerable build and rv=23 with zero changes on fixed; a frame/leader mismatch is a preserved negative. Clean-archive replay at `9f42ba6` matched all 16 normalized evidence hashes; author-only, unwitnessed, no wire/pointer/command, rung 5 UNKNOWN. W162 rebuilt pinned 3.5.2/3.5.3 with `OPENEXR_BUILD_TOOLS=ON` and no source edits: unmodified `exrcheck -c` on the 692-byte PoC gives vulnerable ASan rc 1 `memcpy-param-overlap` at `internal_zstd.c:472` via `readCoreScanlinePart` (`ImfCheckFile.cpp:1467`) → `exr_decoding_run`, fixed ASan rc 1 `bad` with no report, vulnerable plain rc 134 `free(): invalid pointer`, fixed plain rc 1 `bad`, baselines `OK` rc 0; default `exrcheck` without `-c` still takes the safe prepass on that PoC, though W165's separate 60 s default-mode run was interrupted before a clean rc and stays inconclusive. W164 confirmed the advisory's deep-tiled claim on the same pinned sink: a 64x1 DEEPTILE/ZSTD FLOAT baseline forged into a 728-byte PoC (sha256 `aa9dba1f…a41ccc`) through `exr_read_tile_chunk_info` + `exr_decoding_run` gives vulnerable ASan `memcpy-param-overlap` at `internal_zstd.c:472`, fixed `EXR_ERR_CORRUPT_CHUNK` (rv 23), plain rc 134 `free(): invalid pointer`, and a 4032-byte guarded overwrite of the 64-byte destination in 3/3 runs (baseline 0); the first overwritten byte differs from the scanline path, another allocator-derived negative. W165 also checked the advisory's version claims from live upstream blobs (`v3.5.1`/`v3.5.2` both blob `78b27abe…`, 51602 bytes, identical to the pinned vulnerable file; `v3.5.0` blob `670b92a7…`, 50484 bytes; `v3.4.2` has no ZSTD path): provenance only, no grade change. The OpenImageIO third-party consumer remains UNTESTED: W165 fetched the exact advisory tag (sha256 `1c1283e8…ff4d2`) and configured it against the pinned ASan OpenEXR prefix, but the 145-step build reached step 3 in 600 s under load ~14.6 and was interrupted, so there is no consumer run or new reachability evidence; resume `cmake --build oiiolab/build-oiio-asan -j8` when host load permits. aarch64 remains untested. The wire lane is closed negatively: `exrinfo -` reads stdin but prints headers only, `exrcheck` needs a file path, ImageMagick 6 links system OpenEXR 3.1.5, and no OIIO/libvips consumer build completed; a purpose-built socket wrapper would be a synthetic consumer under `docs/rce.md`; none was built. Rung 5 stays UNKNOWN with the named blocker: a live affected application process with wire/request input. W187 (`45928e64`, clean-archive receipt `eaf6a76e`) steers a live malloc address from file bytes in a purpose-built `-no-pie` harness with ASLR off: eight bytes at `A+272` encode the safe-link inverse of a chosen target and two files return `M7=0x4e6b40`/`0x4e6b50`. W188 (`5057e7ed`, replay `2d1206e1`) bounds that result: in unmodified `exrcheck -c` the nearest tcache user pointer in the 384-byte copy window is 4288 bytes past the destination (3904 bytes beyond the window), so the steering is harness-groomed, not file-only. `sh harness/tcache-reach-check.sh` prints `RESULT PASS`; author-only, unwitnessed, no wire, code pointer/IP, marker or command, grade and r5 unchanged. [Brief](reports/frontier-openexr2shell.md) · [Status](reports/openexr2shell-status.md) · [File-level evidence](reports/openexr2shell-file-level.md) |
| **Libheif2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 12:3xZ under standing #6 as the 112th route; CODE/HARNESS direct-call rungs 1-4 plus a later real-build file lane; witness W159 (#2626) ESTABLISHED at the labeled direct-call scope and W163 (#2729/#2730) ESTABLISHED the W161/W162 real-file lane at its labeled local-file/process decoder-to-x265 scope; no rung 5.** Frontier staged W157 in commit `366690f`; the registered two-pane window 117 was adopted, no second window. GHSA-hpg4-g2gc-pq42 (High 7.5 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, CWE-122, no CVE stated), libheif >=1.15.0 <1.23.7 (advisory's `1.23.7` is the planned fix release), fixed by commit `9ec655f`; vulnerable pin `v1.23.6`. `HeifPixelImage::extend_padding_to_size()` reallocates exactly to the requested subsampled dimensions but copies every old row at the new stride (`pixelimage.cc.vuln:643-647`), so a 64x65 plane padded to 512x64 writes chosen `0x5a` bytes from offset 32768 into a 32768-byte allocation; gcc+clang ASan `WRITE of size 64` 0 bytes past it at pinned `:644` through public `heif_image.cc.vuln:403`, fixed returns rc 2 with no copy. Operator clean-archive replay from `366690f` `PASS=101 FAIL=0`, trace `9468b5109099f1810c4cef5dbe6e1c064495b180c57f6e2844a20f2580e38b43`; witness W159 (#2626) ESTABLISHED rungs 1-4 at that labeled direct-call scope with five pins hash-matched and no counterexample. W161 builds real pinned v1.23.6 with x265/JPEG plugins and a crafted mixed-MJPEG HEIF (frame 2 SOF patched to 64x512 against a 512x64 track): ASan `WRITE of size 64` 0 bytes after a 32783-byte plane at `pixelimage.cc:644` via `heif_image.cc:403`, `encoder_x265.cc:1139`, `hevc_enc.cc:189`, `track_visual.cc:620`; decode-only and safe inputs are clean, fixed `9ec655f` rejects rc 2. A third, non-sanitized Release build faults with rc 139 SIGSEGV in `__memcpy_avx_unaligned_erms` on the mixed file (gdb backtrace through `extend_padding_to_size`) while the safe input is clean, so the advisory's release SIGSEGV is observed locally. W162 adds file-derived chosen bytes on that real file path: a patterned mixed-MJPEG (SHA-256 `8f09b93c…151c1c`) decodes to position-dependent bytes `74*8 82*8 8e*8 9c*8 a8*8 b6*8 c2*8 1a*8`, which gdb reads at `plane+32768`/`+33280` and which change the next free chunk's size word to `0x9c9c9c9c9c9c9c9c` — rung 4 at file-derived bytes and malloc metadata, no live pointer, consumer, socket, command or rung 5. Witness W163 (#2729/#2730) independently replayed both lanes from a clean archive, with 5/5 pins hash-matched, byte-exact crafted inputs, its own drivers and a uniform-JPEG control: ESTABLISHED at the labeled local-file/process scope, no counterexample or grade change. Caveat: two from-scratch ASan builds timed out on the 2-CPU/load-10 host, so the replay reused hash-identified prebuilt libs; this is input/driver/source replay, not a full build replay. The advisory's 1,155-byte input and 36,879-byte allocation remain claims. W166 adds a genuine 64x65 frame-1 JPEG (`controlled-size.heif`, SHA-256 `062301dfe33e91eeef27441f794a41644e3f9e841282fde6892b7b41b2bc7550`): plain rc 134 `free(): corrupted unsorted chunks`, ASan rc 1 `WRITE of size 64` at `pixelimage.cc:644` 0 bytes after the 32783-byte region, retained-frame rc 134; gdb reads the chosen row at `plane+32768` and the top size `0x3821` → `0x000500000500021e` at `plane+32792`. Negatives: JPEG DCT/quantization changed the intended `0x21` bytes, a uniform `0x40` row also aborts, and no pointer-bearing neighbour was found; a retained-frame probe turns the next chunk into a top chunk whose overwritten size aborts with `malloc(): corrupted top size`, and the fixed-pin reencode control exits 0 then returns rc 2 at encode with "All frames of a sequence must have the size of the first frame" (rc 2 is an encode API return, not a successful encode). Grade unchanged, unwitnessed, rung 5 UNKNOWN. W176 (`d12d823`) preserves two arbitrary-byte ceiling negatives: an AV1 lossless 512x64 + 64x65 sequence is refused (`frame1: rc=8 sub=5002 Encoder plugin generated an error: Encoding problem: Image size must match encoder init configuration size`; `heif-enc -A -L -S` likewise refuses, Uncompressed NO NO), and JPEG constant 8x8 blocks round-trip byte-exact (Pillow grayscale q95, subsampling 0) but the SOF-patched OOB row is not independent (`a0*8, a2*16, a4*16, a6*16, a8*8` at `plane+32768`; uniform `0x70`/`0xac` for 64x512), so on those codec/builds arbitrary-byte control stayed UNKNOWN and W162's position-dependent 8-byte runs remained the chosen-byte lane. `real/run_wire.sh /tmp/w176-wire-replay` replayed six cases with both checkers PASS; witnesses #2752/#2869/#2897 remain queued with no verdict. W178 (`613de0b`) closes that ceiling on a separate pinned v1.23.6 build configured with `-DWITH_UNCOMPRESSED_CODEC=ON`: `real/uncompressed_mixed.cc` writes a 64x65 ISO/IEC 23001-17 sequence whose 64 chosen Y-row bytes `11 22 33 44 55 66 77 88` x8 decode byte-exact, and `real/reencode_chroma.cc` with `SYNTH_FIRST=1 TW=512 TH=64` feeds that file to the x265 encoder; gdb reads those exact bytes at the source and at `plane+32768` (input SHA-256 `b585565b…a249`, `check_uncompressed.py` PASS=5 FAIL=0, plain rc 134 `double free or corruption (out)`). Rung 4 with arbitrary 64-byte file-derived control at the OOB row at that labeled build/codec scope, superseding the earlier one-uniform-value ceiling; the first encoder-sizing frame is harness-created and the uncompressed sequence cannot carry mixed sizes alone, so this is not a single-file remote attack. No pointer, marker, command, network consumer, witness replay or rung 5. [Brief](reports/frontier-libheif2shell.md) · [Status](reports/libheif2shell-status.md) |
| **Fqterm2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 13:1xZ under standing #6 as the 113th route; CODE/HARNESS direct-call rungs 1-4 only; operator clean-archive replay exact; no witness verdict.** Frontier staged W158 in commit `ddc7b62`; the registered live two-pane window 118 was adopted, no second window. CVE-2026-131875 / GHSA-8m6p-6hq3-xcx4 (High 8.7 `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`, CWE-787), fqterm before 0.9.11, fixed 0.9.11 by `e340b62` (pinned vulnerable parent `079b6d5`); pins in `lab/frontier/fqterm2shell/PINS.sha256`. `nextParam()` increments `paramIndex_` without bound and `paramDigit()` writes attacker-derived 32-bit values past `int param_[30]`: 59 CSI parameters give chosen `0x5a5a5a5a` in the trailing member region and `0x09` dwords past the 280-byte stub object under gdb; gcc+clang ASan classify the first OOB access as `READ of size 4` at `fqterm_decode.cpp.vuln:694` (the store is on the same line, shown by the plain build and gdb), fixed clamps at index 29. `PASS=73 FAIL=0` over three runs, trace `047e7be3…f454e`; Docs clean-archive replay at `ddc7b62` and an independent operator `git archive a3a8432` replay both rebuilt all eight binaries with the exact trace, six pins OK. No Qt/fqterm build, terminal, socket or wire input, pointer control, command or rung 5. [Brief](reports/frontier-fqterm2shell.md) · [Status](reports/fqterm2shell-status.md) |
| **Munt2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 14:2xZ under standing #6 as the 114th route; real-library rungs 1-4 with witness W167 (#2781) ESTABLISHED at that labeled scope; no rung 5.** CVE-2026-121941 / GHSA-qw3h-2hqv-29vq, libmt32emu `MidiStreamParser` oversized SysEx; vulnerable tag `libmt32emu_2_8_3` (`008feb32…8e93`), fix `1749f7fe…dc3b`. A 40001-byte stream writes past the real 32768-byte buffer; witness #2781 reproduced the 34/34 real-library matrix, normalized outputs and causal `0x5a`→`0x37` tail change, but the chosen bytes sit in a harness tail rather than a live allocator neighbour. The in-tree ALSA caller caps events at 5572 bytes; large-SysEx library paths use `playSysex`, not `parseStream`. W183 reaches a real stdio consumer of the forged header, and W184 reaches `pushSysex` only in a separately labelled synthetic-ROM testing build; neither supplies a real host, wire, pointer target or command. W191 (`b8885fcc`) resolves the second CISA exploit-tagged HackMD slug as the same note ID: the mirror's "Illustrative trigger" was explicitly not executed and is truncated at `for (int i = 0; i`, with no byte array, length, script or output. CISA `poc` metadata remains advisory-only; no public PoC bytes or measured third-party host exist. Rung 5 stays UNKNOWN. [Brief](reports/frontier-munt2shell.md) · [Status](reports/munt2shell-status.md) |
| **Libgphoto2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 15:1xZ under standing #6 as the 116th route; CODE/HARNESS direct-call rungs 1-4 plus a real-library ASan rung 3 on a lab-patched vusb port; operator clean-archive replay exact; witness #2892 ESTABLISHED at rung 3 on the real heap destination (that verdict is NOT rung 4 impact); W170/W171/W172 rung 4 at the lab-assisted real-API/consumer scope is author-only and unwitnessed; rung 5 UNKNOWN.** Frontier staged W160 in commits `ebec5a8`/`0e10c83`/`5606069`; the registered live two-pane window 120 was adopted, no second window. CVE-2026-120451 / GHSA-7rfg-j54g-6xm2 (High 7.0, CWE-787, Unreviewed), libgphoto2 through 2.5.34 (newest tag observed), fixed by commit `6a3393dd9965…` with no patched numeric version (UNKNOWN); companion CVE-2026-120452 is screened out, not disproved. An unbounded 16-bit device allocation-table count in `jl2005c_init()` drives a 480-byte stack overflow in `gp_port_read()` (gcc+clang ASan `WRITE of size 16384` at pinned `jl2005c.c.vuln:152`) and a 464-byte heap overflow in real `memmove()`: default ASan still aborts on the source `READ of size 16848` at pinned `:154` (negative preserved), while recover-mode ASan (`-fsanitize-recover=address`, `halt_on_error=0`) separately confirms both that read and a `heap-buffer-overflow WRITE of size 16848` 0 bytes after a 16448-byte region at `:154`; fixed recover builds return rc=-3 with no ASan report. gdb reads eight chosen `0x5a` bytes past both buffers and a chosen marker in the saved-RIP slot, but the process faults in `memmove` before `ret` — no IP control. The admission replay from a clean `git archive 0e10c83` was `PASS=92 FAIL=0`, trace `e364f756…c6c98` (51 files, 4/4 pins, 8 binaries); W161 expands this to 12 binaries (gcc/clang × vuln/fixed × plain/asan/recover), 36 invocations and `PASS=146 FAIL=0` from a clean `git archive a42e02e` (68 files, 4/4 pins) with the same trace; witness #2763 also closed that harness verdict at 146 PASS / 0 FAIL. W162 also built real ASan libgphoto2 2.5.34 and reached `jl2005c_init()` through `gp_camera_init()` on a lab-patched vusb port: count 1022 gives a 16384-byte device read and `WRITE of size 16384` at real `jl2005c/jl2005c.c:152`, count 100 and the upstream-fixed tree are clean. Witness #2892 (2026-11-23) replayed the real build from a clean `/tmp/w173-lgp` archive with four pins and the tarball/patch hashes matched: three ASan reports at count 1022 with `halt_on_error=0` (rc 0) — stack WRITE 16384 at real `:152`, stack READ 16848 and heap WRITE 16848 at real `:154`, 0 bytes past the 16448-byte `camera_init` region; controls 100/1021 clean, fix `4fdaf4b1…` suppresses all three, reversing the patch restores them, and count 65535 gives 1 MiB faults then SEGV. gdb plus byte substitution found no live neighbour or pointer chain (`table` ends at the allocation boundary, chosen bytes land in the ASan redzone), so only rung 3 at the real heap destination is ESTABLISHED — rung 4 impact and rung 5 stay UNKNOWN. W165's separate plain real-library probe aborts rc 134 at count 1022 with `*** stack smashing detected ***`; gdb at `__stack_chk_fail` shows the device-chosen `0x5a5a5a5a5a5a5a5a` in both the canary and the saved RIP of `jl2005c_init`, so chosen bytes reach a real control-flow slot but the protector aborts before `ret` and no chosen target executes — author-only, no witness retry, synthetic vusb transport only. A charter, hy4-flash route, both resolver entries and three full-flag-sync units are live at pin `0d686bb…` (`written 3, removed 0`); pinned doctor rc 0 GREEN, omp-only GREEN 116. No real USB hardware, wire, command or rung 5; W170/W171's device-chosen pointer and its dereference and W172's real `gp_file_save()` file write are lab-assisted, author-only limbs (below). W174 (`2ac219c2`) replayed W172 from clean `git archive 833729ad` (4/4 pins OK); verbatim `DRAIN=22` put the victim before `priv` with `data=(nil)`, while `DRAIN=23` restored victim `priv+0x4050`, `gp_file_save() rc=0` and the same 29-byte marker, with `GUARDS=0` still aborting. Author replay, unwitnessed, grade unchanged. [Brief](reports/frontier-libgphoto2shell.md) · [Status](reports/libgphoto2shell-status.md) |
| **Kicad2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 16:1xZ under standing #6 as the 117th route; CODE/HARNESS direct-call rungs 1-4 plus a real-property-parser tokenization lane, a real compound-file `FileHeader`-stream delivery lane (rungs 1-3) and W178's KiCad-own `compoundfilereader` lane; operator clean-archive replays exact; witness #2996 ESTABLISHED rungs 1-4 at the labeled synthetic-CFB/KiCad-own-reader scope, NOT rung 5.** Frontier staged W162 in commits `20d4d70`/`01dfce0`; the registered live two-pane window 122 was adopted, no duplicate. CVE-2026-126970 / GHSA-4qjr-2gjm-9gc6 (High 7.8 `CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`, CWE-787, Unreviewed; ZDI-CAN-33213 / ZDI-26-956), KiCad Altium SCHLIB `ParseLibHeader` converts a `SIZE` suffix with `wxAtoi` without a lower bound; for `ind <= 0` the resize guard is vacuous and `aFontSizes[ind-1] = scaled` writes four bytes before the vector heap buffer. Fix commit `b2f51d1` (parent `bf3e3fa`), backport `4fdd1270…`; first stable fixed release mapped from GitLab commit/raw-file reads to KiCad 10.0.7 (10.0.7-rc1 first pre-release; 10.0.6 and 9.0.x lack the guard), but no 10.0.7 build was exercised here (`FIXED-RELEASE.md`). Pinned parent `:5883-5923` / fixed `:5883-5926`; gcc and clang ASan `WRITE of size 4` four bytes before a 4-byte region at pinned `:5919`, chosen `0x24242424` at `data()-4` in gdb, plain glibc chunk-header corruption, fixed guard clean. Operator clean `git archive 20d4d70` replay at 16:14Z: 70 files, 4/4 pins OK, 8 binaries, `PASS=52 FAIL=0`, trace `dd64c549…22f9a6` exact. A real-property-parser lane compiles the verbatim upstream `ALTIUM_BINARY_PARSER` class, both constructors and the whole `ReadProperties()` body from pinned parent `bf3e3fa` with a stubbed wx/CFB shim; the crafted `|HEADER=...|SIZE1=10|SIZEZ=84215045|\0` stream is preserved (`real-key: SIZEZ=84215045`, no SIZE whitelist, `parse_error=0`) and the pinned parent then hits gcc/clang ASan `WRITE of size 4` four bytes before the 4-byte region at `:5919` (plain glibc `double free or corruption (out)`), while the fixed slice stays clean; `realparser/check.sh` `PASS=36 FAIL=0` twice with trace `b228ec00…5ff4ee`, reproduced from a clean `git archive 7ad20c7` (4/4 + 5/5 pins). W174 adds a real v3 MS-CFB/OLE2 container lane: `make_cfb.py` writes 512-byte-sector fixtures carrying the crafted bytes in a `FileHeader` stream, `verify_cfb.py` reads all four back with `olefile` 0.46 (`ALL_FIXTURES_OK`), and a lab C++ reader walks header → DIFAT → FAT → directory → miniFAT → mini stream before the same verbatim parser (no new upstream pins; 5/5 + 4/4 verified). The vulnerable build gives `real-reader: bytes=107 props=3 parse_error=0`, `real-key: SIZEZ=84215045`, gcc/clang ASan `WRITE of size 4` four bytes before the region at `:5919` (plain glibc abort), fixed slice clean; `realcfb/check.sh` `PASS=38 FAIL=0` twice and from clean `git archive 455d92e` (246 files), trace `d46a3536…c53c` exact. W178 (`337c164`) adds a fourth lane compiling KiCad 10.0.6's verbatim `thirdparty/compoundfilereader` headers (pins `223e8b03…`/`d72da151…`) with a lab `ALTIUM_COMPOUND_FILE` wrapper calling the reader's real `EnumFiles`/`IsStream`/`ReadFile` on `realcfb`'s four `.SchLib` fixtures: `kicad-cfb: ... stream=107`, `real-reader: bytes=107 props=3 parse_error=0`, `real-key: SIZEZ=84215045`; the pinned parent gives ASan `WRITE of size 4` four bytes before the 4-byte region at `sch_io_altium.cpp.vuln:5919` (resize at `:5915`), plain `rc=0 size=1 first=72 GUARD7=11111111` then `double free or corruption (out)`, `attackneg` SEGV at `:5919`, `attackfar` an 8-byte before-region write, and all fixed runs clean. `kicadreader/check.sh` gave 38/38 twice and from a clean `git archive 337c164` (333 files) with 32 invocations/38 assertions, trace `fffe73410576403f33943253a207db3e8493229babdfb8f30f4544aebcfd6260`; that clean-archive replay was author/operator-performed; witness #2996 later repeated the 38/38 run from clean `3d90217` with the same trace, so the lane is witness-backed at that scope. W179 adds a file-controlled chosen-value probe: `kicadreader/chosen-value.sh` builds two real CFB fixtures through the committed `realcfb/make_cfb.py:build`, verifies them with `olefile`, and gdb at pinned `:5919` observes `SIZEZ=84215045` → `IND=0 SCALED=0x24242424` with bytes `24 24 24 24` at `data()-4`, and `925327927` (`0x37373737`) → `0x80000000` with `00 00 00 80`; both fixed builds stay clean. A source-bound check confirms the real `ALTIUM_COMPOUND_FILE` uses the same `EnumFiles`/`IsStream`/`ReadFile` API the lab wrapper models, but no real KiCad build was run. The four pinned-source `aFontSizes` reads (`:2744`, `:2917`, `:5278`, `:5479`) are all in-bounds guarded. All four lanes stub the wx layer, but only W178 walks the CFB with KiCad's own reader: no real KiCad build at any release, eeschema, vendor-produced SCHLIB/IntLib file, downstream consumer, socket, wire, pointer control, command or rung 5; chosen bytes land in the ASan left redzone (plain: malloc metadata), not a live object, and the ZDI RCE claim stays UNKNOWN. [Brief](reports/frontier-kicad2shell.md) · [Status](reports/kicad2shell-status.md) |
| **Ndpi2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 18:1xZ under standing #6 as the 118th route; CODE/HARNESS direct-call rungs 1-4 plus a real pinned ASan build; operator clean-archive replay exact; no witness verdict.** Frontier staged W161 in `6510950`; the registered two-pane window 121 was adopted with no duplicate entry (inner tmux server down this wake, live panes UNKNOWN). CVE-2026-86098 / GHSA-c8vx-3h2j-4f8m (GitHub CNA, Unreviewed, High 7.4 CWE-787, published 2026-09-05); nDPI before 6.0 per the advisory, whose fix message says "nDPI <= 5.0, HEAD `ea3586e`"; fix `94e82c1de12323d992895830231865736a8abf2c` (2026-08-25); the numeric fixed release is **6.0**, confirmed by ancestry (`git tag --contains 94e82c1…` → `6.0` and `6.1-qubitowl`, `git describe --tags --contains` → `6.0~14`; tag 6.0 = `1a529339…a3af`, 2026-08-28; the only 5.x tag `5.0` does not contain the fix). Verbatim pinned `ndpi_serializer.c` under `#line` at vulnerable `94e82c1^` and fixed `94e82c1`: 4 pins, 8 binaries; gcc and clang ASan report `WRITE of size 1` at `ndpi_serializer.c.vuln:107` (JSON escape), `:158` (4-byte UTF-8) and `:163` (off-by-one NUL); plain chosen tail bytes are `2f 22 a5 00` / `80 22 a5 00` / `a5 00 a5 a5` with gdb readback. Operator clean `git archive 6510950` replay at 18:18Z: 54 files, 4/4 pins OK, 8 binaries rebuilt, `PASS=172 FAIL=0`, trace `16060f55dfe944bf5e481a43e76034f6cd3d7acc159d561beaa067c8c97f7b5b` exact — author-harness replay, not witness acceptance. Charter, hy4-flash route 117→118, both resolver entries (235→238) and three full-flag-sync units at pin `0d686bb…` (`written 3, removed 0`), path enabled/active, pinned doctor rc 0 GREEN, omp-only GREEN 118. W162 (`37fd092`) built the full vulnerable tree (serializer sha256 `4840fb41…9ad5`) with clang 18 ASan: all in-tree escape callers pass `dst_max_len = buffer.size - size_used` and the VALUE caller at `:1296-1310` pre-extends by `24 + slen*2`, so 145 crafted cases gave zero ASan reports (output `{"key":"\/"}` proves the escape ran) — a measured VALUE-path negative. Three weak KEY callers (`binary_boolean :2181`, `start_of_list_binary :2245`, `start_of_block_binary :2328`) compute `needed = klen + 16` while the key expands to `2*klen+3`: a 128-byte `/` key in a 256-byte buffer gives ASan `WRITE of size 1` at `:107` (0 bytes past the 256-byte `calloc` at `:209`), klen 256 an off-by-one NUL at `:163` (1 byte past the 516-byte `realloc` at `:286`/`:2331`), klen 16/64 clean and 128..2048 overflowing on all three callers. The fixed tree (sha256 `0aa83a83…92fd`) is rc 0 with zero ASan on `direct`, `real` and all `weakkey` cases; fixed callers still ignore the `-1` return so `size_used` can decrement — a separate correctness issue, not memory corruption observed here. A loopback pcap reader fed stock DNS and an HTTP `Host:` with 400 `/` bytes exited 0 with zero ASan and 560 `\/` escapes, never reaching the weak KEY callers (negative preserved). Full-tree grep closes wire reachability for THIS tree as a negative: `ndpi_deserialize_clone_all`/`_item` appear only as declarations at `ndpi_api.h:1891-1892`, definitions at `ndpi_serializer.c:3000,3048`, fuzz `fuzz_serialization.cpp:156,170` and `tests/unit/unit.c:247`, with no reader/dissector/daemon caller, and all other weak-caller keys are literals or ≤10-byte decimals (`ndpi_serializer.c:2374-2383`). No packet/socket-supplied >128-byte key, no pointer control, command or witness; the advisory's TLS SNI / HTTP / DNS reachability is unsupported for this tree, and R5 stays UNKNOWN and unreachable via this primitive. [Brief](reports/frontier-ndpi2shell.md) · [Status](reports/ndpi2shell-status.md) |
| **Sdlmixer2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 18:3xZ under standing #6 as the 119th route; HARNESS direct-call rungs 1-4 only plus W179's real-SDL-caller lane; operator clean-archive replay exact; witness #2942 ESTABLISHED at the labeled direct-call lab scope, rungs 1-4 only, explicitly not rung 5.** Frontier staged W173 in `7e7f1d6`/`3f44109`; the registered live two-pane window 123 was adopted with no duplicate (two panes verified at 18:33Z). CVE-2026-122328 / GHSA-7qqc-5rvj-wqqw (GitHub Advisory Database, Unreviewed, High CVSS4 8.5, CWE-121, published 2026-11-05); SDL_mixer 3.1.2-3.2.4, fix commit `df966f698e18ae849bd92796a26311e79c555718`; no release-3.2.5 tag, so the numeric fixed version is UNKNOWN. Pinned `src/decoder_wav.c:750-762` at vulnerable `release-3.2.4` and fixed `df966f6` (4 pins): `out` is offset by `(length-1)*4` at `:757` then indexed as `float *` with stride 4 again, so 256 samples store bytes 0..2043 in the caller's 1024-byte stack buffer. gcc and clang ASan report `stack-buffer-overflow WRITE of size 4` at pinned `:759`, for `edge` exactly 1024 bytes into `buffer`; gdb reads chosen `0x5a5a5a5a` at `buffer+1024`, fixed pin clean. Operator clean `git archive 7e7f1d6` replay at 18:32Z: 65 files, 4/4 pins OK, 12 binaries, `PASS=134 FAIL=0`, trace `f81697d9247807c1bc254ed1ce51a9d966ec807b6256713177180aa5f44f98e1` exact — author-harness replay, not witness acceptance. Charter, hy4-flash route 118→119, both resolver entries (237→239) and three full-flag-sync units at pin `0d686bb…` (`written 3, removed 0`), path enabled/active, pinned doctor rc 0 GREEN, omp-only GREEN 119. W179 (`307a2b6`) adds a real-caller SDL3 lane: the SDL3 `release-3.2.4` tarball (SHA `0fc1d23e225e2a098976571bf5d62b6d81e0ae84ff3d82a35a3d19ab04d07e5c`, inline pin check from `a8b9c91`) is built headless, and verbatim pinned slices (types `:41-230`, channel mask `:828-843`, `ParseFMT :845-978`, `FetchXLaw`+wrappers `:750-772`, caller `:1654-1679`, fixed `:1666-1691`) run with real SDL IO and `SDL_CreateAudioStream`/`SDL_PutAudioStreamData` across 12 binaries (g++/clang++ × vuln/fixed × plain/asan/nossp). ASan reports `stack-buffer-overflow WRITE of size 4` at `:759` via `FetchALaw:771`/`FetchULaw:766` from caller `:1668` (`buffer` `[32,1056)`, access offset 1180, 124 bytes past at the first reported store); gdb at `g++-vuln-nossp edge`, `i=1` sees the lab LUT `0x5a5a5a5a` and `buffer+1020..1027 = ff 7f 00 00 5a 5a 5a 5a`. Fixed ASan runs are clean (driver prints rc=1) and `safe`, `badfmt` (parse REJECTED) and `pcm8` (`fetch=other`, `decoded_framesize=1`) are clean negatives; clang++ plain and all nossp `edge`/`ulaw` SIGSEGV rc 139 while g++ plain aborts rc 134 with `*** stack smashing detected ***` — all preserved. `realcaller/check.sh` returned 96/0 with trace `934e83379c7b6d771269a96035a54480a9c5ab9dcaf5a169db6a6916ce2160c0`. W179 is author-only and awaits witness replay; no SDL_mixer build, full WAV chunk dispatcher, decoder-owned consumer, socket, wire, pointer/IP control or command follows, and advisory file-path reachability and RCE stay UNKNOWN. No rung 5. [Brief](reports/frontier-sdlmixer2shell.md) · [Status](reports/sdlmixer2shell-status.md) |
| **Cjose2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 20:0xZ under standing #6 as the 120th route; real-library direct-call plus loopback HTTP wire-consumer rungs 1-4; operator clean-archive replay exact; witness verdicts recorded at the labeled direct-call, synthetic-consumer and groomed-fptr scopes, NOT rung 5.** Frontier staged W180 in `841b716`/`f2999b9`; the registered live two-pane window 124 was adopted with no duplicate (pane pids 1238556/1238772, neither dead). CVE-2026-53938 / GHSA-75r7-f5cv-g3wj (GitHub Advisory Database, 2026-06-02, High CVSS 8.2 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`, CWE-122/787); cjose `<=0.6.2.4`, patched `>=0.6.2.5` by fix `8c51d245273583a658f24ef7b08ba22f848a34a5` (9-line `raw_len == cek_len + 8` check). Pinned v0.6.2.4 `src/jwe.c` and the fix-only tree; real cjose build with real `cjose_jwe_import()` / `cjose_jwe_decrypt()` and real OpenSSL RFC 3394 wrap/unwrap. An attacker-sized wrapped `encrypted_key` segment is unwrapped into the 32-byte CEK allocated by `_cjose_jwe_set_cek_aes_cbc()`; gcc and clang ASan report `heap-buffer-overflow WRITE of size 40` (`wrapped`) and `1016` (`wrappedbig`), fixed returns `INVALID_ARG` and is ASan-clean, and plain big wrap aborts in glibc `free(): invalid pointer`. gdb at the pinned `AES_unwrap_key` call reads lab-chosen `4d 49 53 48 45 2d 4f 4f` ("MISHE-OO") at `cek+32..39`; the invalid-IV `probe` is a preserved negative for chosen bytes because OpenSSL cleanses its output after the integrity failure, though its OOB write is still caught by ASan. Operator clean `git archive 841b716` replay at 20:0xZ: 73 files, 7/7 pins OK, 8 binaries rebuilt offline, `PASS=223 FAIL=0`, trace `455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7` exact — author-harness replay. Charter, hy4-flash route 119→120, both resolver entries (239→241) and three full-flag-sync units at pin `0d686bb…` (`written 3, removed 0`), path enabled/active, pinned doctor rc 0 GREEN, omp-only GREEN 120. W181 (`a6196ae`) adds a lab-only loopback HTTP consumer (`w1/{server.c,client.py,build.sh,run.sh}`) binding an ephemeral 127.0.0.1 port and passing a real tampered compact JWE from `Authorization: Bearer` to real `cjose_jwe_import()` / `cjose_jwe_decrypt()`: 48/56/64/1024-byte wrapped segments yield `CEK_LEN_AFTER=40/48/56/1016` in vulnerable builds, fixed rejects with `ERRCODE=1` and keeps 32, and ASan reports the `jwe.c:595` write. Plain outcomes are rc 0 at 40, rc 134 at 48 and rc 139 at 1016; the 56-byte outcome is unstable — mostly rc 0, also SIGSEGV in witness and author repeats (W182: 2/12 plain and 1/12 trace rc 139; witness 10/10 plain rc 0 and 2/10 trace rc 139, one crash traced through `__strcmp_avx2` ← `_cjose_jwe_calc_auth_tag:1098` on a corrupted jansson string). W183 (`a93cbcb`/`7798711`) closed the cause: the adjacent 25-byte object is a jansson `json_string_t` and, with an identical allocation ring, is either the 13-byte `enc` or the 6-byte `alg` string; in a 40-run instrumented batch all four crashes had `enc` adjacent (the chosen `0x5a` replaces its type so `json_string_value()` returns NULL and the real decrypt path faults in `strcmp`), while chosen type/refcount bytes `02 00 00 00 01 00 00 00` removed that fault in 60 runs but all then aborted in `munmap_chunk()` from the still-corrupt chunk size at `cek+40..47`. Pinning jansson's per-process hash seed makes the outcome deterministic per seed: seeds 19/27/30 gave rc 139 in 6/6 runs each, the other 37 tested seeds rc 0, so the 8–20% crash rate is the fraction of random seeds in the first class, not a race, ASLR or token randomness; why the two same-size strings swap identity stays UNKNOWN. The heap map puts a 25-byte jansson string at `cek+48`, and a source-only read of an unbuilt mod_auth_openidc 2.4.15.1 finds an unauthenticated backchannel-logout path to the same calls, not a running deployment. An independent witness replayed both lanes from a clean archive: rungs 1-4 ESTABLISHED at the labeled direct-call real-library scope and rungs 1-3 plus byte-control mechanics ESTABLISHED at the labeled synthetic 127.0.0.1 consumer scope. W188 added a groomed direct-call limb where the same overflow rewrites a live JWK `fns` pointer and a lab-chosen benign marker runs through real `cjose_jwk_release()`; witness W194 (#3566) replayed it independently from clean `git archive 8c717a2` and graded it **ESTABLISHED AS LABELED** — lab-known absolute address, no wire path, no ASLR defeat, no command, NO r5. W199 (`43bd6d3e`) reaches a live pointer field in the loopback decrypt: an 80-byte `encrypted_key` unwraps 72 chosen bytes that preserve the adjacent jansson string's type/refcount at `cek+48..55` and chunk size at `cek+40` while setting its value pointer at `cek+64..71` to eight `0x41` bytes. gdb sees `rdi=0x4141414141414141` in `__strcmp_avx2` from `_cjose_jwe_calc_auth_tag` (`jwe.c:1098`) in 8/40 plain runs; fixed rejects before the write (`CEK_LEN_AFTER=32`). The value is a recognizable non-address: no valid address, ASLR defeat, command or wire-derived live address; `sha256sum -c evidence/W199-SHA256SUMS` passes locally, author-only and unwitnessed, no grade change. No deployed server/application or credential; the socket is a lab-only loopback consumer. No IP control or command outside that lab-only pointer redirect, and no r5; advisory pre-auth reachability in a real deployment and RCE stay UNKNOWN. [Brief](reports/frontier-cjose2shell.md) · [Status](reports/cjose2shell-status.md) |
| **Thorvg2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 22:0xZ under standing #6 as the 121st route; direct-call rungs 1-4 later reaching real public APIs, a loopback wire and a Lottie embedded-JPEG asset; operator clean-archive replay exact; unwitnessed, rung 5 UNKNOWN.** Frontier staged in commits `4c4f8f8`/`dc319a9`; the registered live two-pane window 125 was adopted with no duplicate (pane pids 23847/23907 at 21:45Z). CVE-2026-123367 / GHSA-mw4c-w54x-248r (GitHub Advisory Database, published 2026-09-09, updated 2026-11-09; High CVSS v3.1 7.4 `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H`, CWE-787); ThorVG `<=1.1.1` (also `main`), patched `1.1.2` by `67680c5`/`e740313` (same result blob `1ba076c378…`); CVSS AV:N is advisory, not a measured wire path at admission. Pinned v1.1.1/v1.1.2 tarballs and fix patch in `lab/frontier/thorvg2shell/PINS.sha256`; real `jpgdHeader()`/`jpgdDecompress()` in a decoder-only harness. Duplicate SOS selectors set `m_blocks_per_mcu=4` for a one-block frame sized for 128 bytes; gcc+clang ASan on an allocator-instrumented copy report `WRITE of size 2` exactly 0 bytes past that region at pinned `tvgJpgd.cpp:1453`, pristine-source 2048x2048 crafted frames fault at `:733`, and gdb places chosen `58 00`/`68 00`/`78 00` at offsets 128/256/384; fixed tree rejects (rc 6), controls decode rc 0. The bump allocator in `jpeg_decoder::alloc()` explains stock-ASan silence on small images. Clean `git archive 4c4f8f8` replay: 21/21 pins, 11 binaries, 88 cases, trace `6c78e7a5…b998d` exact. W183 (`a29bd33`) closed the admission consumer UNKNOWN: real `tvg::Picture::load(data,size,"jpg")` and plain filename loads on built v1.1.1/v1.1.2 fault at pinned `tvgJpgd.cpp:733` on the 853622-byte crafted image while controls decode and v1.1.2 is clean, and a loopback HTTP `POST /decode` body reaches the same sink (crafted body 000 with server SIGSEGV, safe body and all v1.1.2 cases 200). W184 measured the fault in `huff_decode()` through `decode_next_row()` → `jpgdDecompress()`, with no pointer or IP control. W185 (`24d449a`) closes the dotLottie-adjacent gap for JSON: a `data:image/jpeg;base64,` asset loaded through real `tvg::Animation` and driven with `frame(1)` reaches `jpgd` — in the committed `harness/evidence/lottie.tsv` the 853622-byte embedded asset faults v1.1.1 (rc 139) and is clean on v1.1.2 (rc 0) while control and small crafted assets are clean on both; Docs replayed `harness/lottie_matrix.sh` from a throwaway copy and reproduced that table byte-identically. Still no renderer canvas, real `.lottie` ZIP container, marker, command, pointer/IP control or witness verdict; advisory RCE stays a claim. Status `reports/thorvg2shell-status.md`. |
| **Busybox2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 23:2xZ under standing #6 as the 122nd route; real loopback UDP TFTP wire rungs 1-4; operator transcript-hash and clean-archive replay verified; witness #3135 ESTABLISHED rungs 1-4 at the labeled BusyBox 1.37.0 TFTP-client / loopback-wire / stock-plain scope, NO rung 5.** Frontier staged W182 at `0c3b4a1`; the registered live two-pane window 126 was adopted with no duplicate (pane pids 1403331/1403336 at 22:36Z). CVE-2026-124737 (Red Hat CNA, published 2026-11-11, CWE-787, CVSS 3.1 7.5 HIGH `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H`; ref bugzilla.redhat.com/2571607); upstream patch by Yehyeong Lee 2026-09-19 (msg31059); no upstream fixed release number, so numeric fixed version UNKNOWN. Pinned busybox-1.37.0 tarball sha256 `3311dff3…743a4`, `networking/tftp.c` sha256 `183410e8…4b7044`; `-b 64` sizes `rbuf` to 68 bytes, a non-OACK first packet flips `io_bufsize` to 516 without reallocation, and `:602` reads 516 server bytes into it. Real 127.0.0.1 UDP server: ASan `WRITE of size 516` 0 bytes past the 68-byte region, OACK/default-blksize controls rc 0 clean, fixed tree ASan-clean, gdb chosen `MISHE-OOTAUFTAUF` at `rbuf+68..83`. Transcript sha256 `3e52a862…fcfecbff300` verified directly; clean `git archive` replay `064e7b1f…d6327b1071397ae96`. W1 measured the heap metadata on the stock plain build: chosen `0x4141414141414141` over the 68-byte `rbuf`'s next-chunk size at `rbuf+72` gives rc -6 `malloc(): corrupted top size` 5/5, restoring `0x20cb1` returns rc 1 5/5. Witness DM #3135 replayed the five-leg wire matrix plus the eight-leg heap supplement from a clean `git archive e94a95f` (8/8 pins, both binaries rebuilt) with no counterexample, and explicitly graded NO rung 5. No chosen pointer, IP, command or marker; advisory RCE is a claim. Status `reports/busybox2shell-status.md`; brief `reports/frontier-busybox2shell.md` §8. |
| **Imagemagick2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 00:3xZ under standing #6 as the 123rd route; real-library direct-call rungs 1-4; operator transcript-hash and clean-archive replay verified; witness #3204 (W181) ESTABLISHED rungs 1-4 at the labeled direct-call/in-process scope, NO r5; file/coder reachability UNKNOWN.** Frontier staged W183 with brief `reports/frontier-imagemagick2shell.md`; the registered live two-pane window 127 was adopted with no duplicate (pane pids 2209784/2209798 at 23:06Z). CVE-2026-130664 (VulnCheck CNA, 2026-11-18, CWE-787, CVSS 3.1 2.5 LOW `AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L`) / GHSA-3pf7-cjfr-3fpq (2026-11-01, LOW, no PoC); ImageMagick 7.0.0 before 7.1.2-35 and 6.x before 6.9.13-60, fixed 7.1.2-35 / 6.9.13-60 by one-line `MagickCore/stream.c` commit `6b833ce613bc`. Five hashes in `lab/frontier/imagemagick2shell/PINS.sha256`; operator verified `REPLAY.log` sha256 `385bbe95…c01667a` at commit `7873caf`: ASan `WRITE of size 1` past a 3-byte stream buffer at `stream.c:1576`, same-size and fixed-tag controls rc 0 clean, gdb chosen bytes 0x42..0x48 at offsets 3..23. Witness #3204 replayed clean `git archive a073540`: 5/5 pins, the same `REPLAY.log` hash and witness `evidence.log` `5547d698…ce40d3`, normalized diff empty except build path and BuildId; it explicitly excluded file/coder reachability and the CLI `-extract` READ. Its labeling NIT: `0x42..0x48` are the harness-defined `0x41+(i%26)` pixel pattern and the geometry growth is harness-assigned, so rung 4 is in-process write-content/destination control only. No crafted image file/coder path/CLI/wire, no grooming/pointer/IP/command; rung 5 UNKNOWN. |
| **CodebaseMemory2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 02:3xZ under standing #6 as the 125th route; real pinned-Cypher direct-call and local stdio `query_graph` tool-path rungs 1-4; operator pin and clean-archive replay verified; unwitnessed, rung 5 UNKNOWN.** Frontier W190 staged it in `6b7f65c`/`4b68ef7`/`6296138`/`a073540`/`7091755`; the registered live two-pane window 128 was adopted with no duplicate (registry 130/130 unique). CVE-2026-114494 / GHSA-vpgh-g3jg-ggx9 (GitHub CNA 2026-11-20, HIGH 7.8 `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-121/787), codebase-memory-mcp `<0.9.0`, fixed `0.9.0` by `e69e0844` (parent `5554f8a46abf`); four hashes in `lab/frontier/codebasememory2shell/PINS.sha256`. An unbounded `RETURN` projection count indexes 32-element stack arrays: ASan OOB READ at `cypher.c:2568` and a recover-mode `WRITE of size 70` at `project_item:3379` ← `execute_return_simple:4116` into `func_bufs[32]`, 16384 bytes past the last in-bounds buffer; 32-item and fixed controls clean, plain 48-item abort, gdb chosen "MISHE-OO…" bytes. Matrix `f8c81a5c…7a6d`, clean `git archive a073540` replay 24/24. W1 (`1205a3d`) reaches the same sink through a real stdio JSON-RPC `tools/call` to `query_graph` on a reduced local ASan server (only the C grammar linked, other grammars lab stubs, single-C-file fixture): `READ of size 8` and recover-mode `WRITE of size 68` at `func_bufs[32]`, fixed release rejects >32 items (`lab/frontier/codebasememory2shell/MCP-TOOL.md`). W8/W10 (`8e4893c8`) bound the frame layout read-only: W8 corrects the real canary to `rbp-0x38` (`rbp-8` is saved r15), and W10 shows an item-38 70-byte copy overwriting six saved callee-saved registers at `rbp-0x40..rbp+0x45` but stopping two bytes short of saved RIP and hitting `__stack_chk_fail` before the epilogue. A C string cannot preserve the canary's zero low byte and reach RIP, a structural negative for this compiler/build; no source, pin, matrix row, witness or grade change. No HTTP transport, socket, remote request or wire, pointer/IP, command, witness or rung 5; WITH-side overflow UNREPRODUCED. [Brief](reports/frontier-codebasememory2shell.md), [status](reports/codebasememory2shell-status.md) |
| **Assimp2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 02:2xZ under standing #6 as the 124th route; direct-call rungs 1-4 ESTABLISHED by witness #3277 at the labeled baseline scope and W14's partial low-32-bit pointer overwrite ESTABLISHED AS LABELED by witness #3722, NO rung 5; the other real-importer lanes are author-measured.** Frontier staged W192 at `585e1c7`/`8190e77`; the registered live two-pane window 129 was adopted with no duplicate (registry 130/130 unique). CVE-2026-134861 (VulnCheck CNA, 2026-11-22, CWE-787, CVSS4 AV:L/UI:P), Assimp through 6.0.6 glTF 1.0 accessor element-size mismatch; fixes are open unmerged PRs 6860/7090, no numeric fixed release. Ten hashes in `lab/frontier/assimp2shell/PINS.sha256`; 13 PASS/0 FAIL, current log `e6341f37…bf41e`, normalized trace `913b23f5…3ca938` matching the clean-archive `REPLAY.md`: gcc+clang ASan WRITE-16 past a 36-byte region, WRITE-12 past 12 bytes, Indexer stack overflow, plain chosen "TAUF" at offsets 36..39; PR6860 blocks ExtractData but not Indexer. Witness #3277 replayed clean `git archive 585e1c7` and graded the baseline direct-call / stub-Accessor / deterministic-arena scope ESTABLISHED, NO r5; it did not cover W1/W2. W1 reached the sink through a built pinned library's `ReadFileFromMemory` glTF import, and W2 placed chosen bytes at the end of a live 24-byte vertex array on that path. W14 (`75ff847f`, replay `22b1740f`) drives MAT2 index bytes 48..51 into the low 32 bits of a live `aiMesh` vector slot; witness #3722 replayed clean `git archive 22b1740f` with 7 PASS / 0 FAIL and normalized trace `72c2a6be…d4198`, ESTABLISHED AS LABELED with the high 32 bits inherited from the heap pointer, an unmapped chosen address and no clean import from W14's document (its `5556f520` low word was captured from `safe.gltf`, not the crafted file). W18 (`5424cec5`, clean-archive replay `33b37760`) supplies the self-calibrating control: under ASLR-off gdb the document's own live begin `0x555555570210` is measured twice and written back as little-endian `55570210` (bytes 48..51 `20f55655` → `10025755`); `bash harness/run-w18.sh` gives 8 PASS / 0 FAIL with `scene=ok` and a byte-identical vector at `CopyVector`, while the original file still reads `0x55555556f520` and an ASLR-on plain run is SIGSEGV rc 139. A clean `git archive 5424cec5` replay (10/10 pins) self-calibrated to a second heap layout (`0x555555570250`, word `55570250`) with 8 PASS / 0 FAIL, normalized traces byte-identical. W25 (`aa2aedc7`, clean replay `fda2b66c`) narrows the index copy to 16 VEC4 bytes: the default `-O0` canary at `dest+4` aborts rc 134 before the marker; with `-fno-stack-protector` only the low half of the saved RIP at `dest+12` is writable (high half `0x7fff`) and rc 139 follows, while the 64-byte MAT4 case still calls the marker. `harness/run-w25.sh` 8 PASS / 0 FAIL, trace sha256 `5532748382…e5d6fa5f864` (recomputed from committed `w25.trace`), byte-identical from clean `aa2aedc7`; author-only negative, no grade change. No pointer/IP, command or rung 5; W1/W2 and the W3–W13 importer lanes stay unwitnessed and their acceptance is UNKNOWN. |
| **FLTK2Shell** | ✓ | ✓ | ✓ | ✓ | — | **ADMITTED 05:4xZ under standing #6 as the 128th route; real 1.4.5 constructor direct-call rungs 1-4, witness #3296 (W195) ESTABLISHED at the labeled direct-call/crafted-BMP/four-tree scope, NO rung 5.** Frontier staged W195 (brief `reports/frontier-fltk2shell.md`, DM #3285 + addendum #3289); the registered live two-pane window 131 was adopted with no duplicate. CVE-2026-135433 (VulnCheck 2026-11-23, CWE-190, CVSS4 8.5 `AV:L/UI:P`, local file + UI, no RCE claim), FLTK <= 1.4.5, fix `a28e392` size_t casts; predecessor `3a049d8` applied by hand for the isolated row-pointer CVE. Real 1.4.5 ASan WRITE-1 two bytes before a 2-byte region at `:486`/`:499`, and before a correct 4294967298-byte region at `:490`/`:503`; plain gdb chosen `53 49 4d 2d`; 33 PASS/0 FAIL, raw log `71b373d0…d4d8c6`, normalized `7882e60c…3525e` exact from clean `072dc75`. W5 (`67436e5`) runs a real X11 FLTK 1.4.5 app on private Xvfb :177: all four cases show `draw_count=1` before the crafted load, which faults at `Fl_BMP_Image.cxx:490` (`WRITE of size 1`, 2 bytes before a 4294967298-byte region, rc 134) while vuln-safe, fixed-crafted and fixed-safe exit 0; later witnessed at that load-path scope by W199 (#3612), see below. ICO is a measured negative. Witness W199 (#3612) replayed the shared-image, both plain-metadata waves and the GUI-consumer extension from a clean `git archive 27ef17b` (PINS 11/11, 33 PASS / 0 FAIL, normalized `7882e60c…3525e` byte-exact): ESTABLISHED AS LABELED with no contradiction, grade unchanged at W195 rungs 1-4, NO r5. Crafted-image draw (the fault is at load, before draw), cache-hit reload, wire, ASLR-independent target, pointer/IP and command remain UNKNOWN. [status](../reports/fltk2shell-status.md) |
| **Synchronet2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 05:4xZ under standing #6 as the 129th route; verbatim-pinned-statement direct-call rungs 1-4 plus a loopback OpenSSH pty-req wire path; witness wake 189 / DM #3427 ESTABLISHED rungs 1-4 at the labeled synthetic-struct scope; a real `sbbs3` is driven after valid password login under the default config (W15, author-only); W26 later measures whole-process SIGSEGV under concurrent load on shipped 3.20b, but no pointer/IP or r5.** Frontier staged W194 (brief `reports/frontier-synchronet2shell.md`, tape #3241); the registered live two-pane window 130 was adopted with no duplicate. CVE-2026-133646 / INCIBE-2026-937 (INCIBE 2026-11-23, CWE-787, CVSS4 8.7 `AV:N/PR:N/VA:H`, availability-only, no RCE claim), Synchronet BBS 3.20b–3.21e with SSH; fix `cb6d77dbca` adds a length query and `SAFECOPY`; NVD Deferred. No-size `cryptGetAttributeString()` writes 64 bytes past a 41-byte TERM field: gcc+clang ASan WRITE-64, plain chosen "MISH"/"E-OO"/"TAUFTAUF" at session offsets 44/48/52, fixed and 40-byte TERM clean; 9 PASS/0 FAIL, log `9ed3b328…403a24e`, normalized `66d20f8…414bdd8` from clean `e5f43ad`. W3 found W2's `-43` was a probe artefact: the vendored cryptlib getter reads a loopback OpenSSH 9.6 pty-req TERM=64 with `status=0 len=64` and the one-call copy places chosen bytes at offsets 44/48/52, ASan `stack-buffer-overflow WRITE of size 64` via `attributeCopyParams → getAttributeFunction → sessionMessageFunction`; `run-wire-proof.sh` is rc 0, 10 PASS / 0 FAIL, and the witness independently rebuilt `libcl.a` (`584494ac…952e3c2`) and replayed it with byte-varied `MISH`/`E-OO`/`TAUFTAUF`. Witness NITs: `CRYPT_SSHOPTION_NONE_AUTH` is forced, and the fixed-form control covers only the patched copy inside a 1000-byte-padded struct. W11 (`a0050050`) hooks paramiko 5.1.0's `Transport._send_user_message` to record the pty-req TERM word at the encryption boundary: TERM=64/65/128 logged `CLIENT WIRE_PTYREQ term_len=64/65/128` with 6 PASS / 0 FAIL, while the W8 getter stored 64 but returned `status=-43 len=-1` for 65 and 128. The first clean replay scored 5 PASS / 1 FAIL on a port-settling race (preserved at `termlen/evidence/clientlen/negative-replay-a0050050/`); after the wait fix, an author `git archive ce0a0208` replay returned 6 PASS / 0 FAIL with byte-identical `results.txt`/`provenance.txt` (`termlen/evidence/clientlen/REPLAY.md`). Client-boundary measurement only, not a ciphertext capture; other clients/builds UNKNOWN. W4's unprovisioned build failed on missing `zip`, autoconf-2.13 and UNIX libarchive/NSPR headers; W15 (`e0f11cd4`, clean replay `b595e239`) provisions those locally, builds and drives `sbbs3` on 127.0.0.1 with an offline-created `lab` user and valid password (no `SSH_ANYAUTH`): 4 PASS / 0 FAIL, `PROBE_COUNT=2`, `ANYAUTH_LOG_COUNT=0`, chosen 64-byte TERM bytes at session offsets 41/44/48/52 with the 40-byte control clean. Pre-auth pty-req remains W9's negative. W18 (`b60fd1b4`/`b67db0dc`) confirms the advisory's shipped-3.21e wording at source level only: tag `sbbs321e` (`d2a6dcb2`) has the same no-size getter plus NUL clamp and byte-identical `terminal[41]` field block, `telnet.h` keeps `TELNET_TERM_MAXLEN 40`, and `sh release-label/run-release321e.sh` scored 11 PASS / 0 FAIL live and from a clean `git archive b60fd1b4` (normalized `bb9067cf…2a5a3fbda9`); no build, wire session or runtime bytes, no rung change and no claim about 3.20b or other releases. W26 (`79f3710b`, receipt `b2013851`, author-only) runs four concurrent 64-byte TERM probes against shipped 3.20b `db9c5d6f`: the predicted node-exhaustion/thread-park path did not occur; the first teardown logged `Node 1 destructor begin` without `destructor end`, the process SIGSEGV'd and the fifth client was refused. The fixed `cb6d77dbca` form served all five sessions. The failed first prediction (7/3) is preserved; after correcting only the fixed-control assertion, live and clean-archive runs both scored 13 PASS / 0 FAIL with seven matching normalized key lines. Unauthenticated loopback SSH pty-req under `SSH_ANYAUTH`; no measured DoS rate, pointer/IP target, command, ASLR defeat or r5. [status](../reports/synchronet2shell-status.md) |
| **FontForge2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 05:4xZ under standing #6 as the 126th route; direct-call rungs 1-4 ESTABLISHED by witness #3309; real headless `Import()` path author-measured; NO rung 5.** Frontier staged W196 (brief `reports/frontier-fontforge2shell.md`); the registered live two-pane window 132 was adopted with no duplicate (registry 134/134 unique). CVE-2026-135295 (VulnCheck 2026-11-23, CWE-787, CVSS4 8.5 `AV:L/UI:P`, local PCF file + UI, no RCE claim); FontForge <= 20251009, fixed by `65e80b5…` (PR #5957, +1/-1 adds `glyph>=0`). Three pins in `lab/frontier/fontforge2shell/PINS.md`; 5/5 expected RCs, raw `evidence.log` `c0eda4e6…`, normalized `56fd8ada…5633bb` matching `REPLAY.md`, chosen gdb bytes `4d 49 53 00` at `encs-4` (W10 measures byte 3's ceiling at `0x01`). Witness #3309 replayed `13a2a94` with gcc 13.3.0/gdb 15.1 and graded rungs 1-4 ESTABLISHED at the labeled direct-call/in-memory-table/stand-in-struct scope, NO r5. A real headless 20251009 build driven by a 296-byte PCF through scripting `Import()` → `FVImportBDF()` → `PcfParse()` gives ASan `WRITE of size 4` 4 bytes before `encs` at `fvimportbdf.c:1751`, patched-build and complete-table controls clean; that real path is author-only and unwitnessed. W2 (`1f26ade`) adds a gdb hardware watchpoint in the real plain `Import()` process: `encs-4` goes 0 → `0x53494d` (`4d 49 53 00`, three chosen bytes, fourth zero for these field values), and the vulnerable binary exits 134 `double free or corruption (out)` while patched and complete-table controls exit 0; author-measured, UNWITNESSED, outside #3309's direct-call verdict. W10 (`8781a538`, author-only, unwitnessed, no grade change) bounds the written word at `0x0100FEFF` (16-bit fields) and writes three file-chosen bytes (`0x00414243`) into a live `char*` at `encs-200` (`0x0000555555c227f0` → `0x0000555500414243` under a gdb watchpoint); that pointer is not dereferenced on this one-`Import()` path and both patched/in-bounds controls are clean. GUI `Import()`, other loaders, full pointer/IP, command, ASLR/grooming and r5 remain UNKNOWN. [status](../reports/fontforge2shell-status.md) |
| **LibRaw2Shell** | ✓ | ✓ | ◐ | ✓ | — | **ADMITTED 05:4xZ under standing #6 as the 127th route; real `dcraw_emu` rung 3 confirmed by W186 and rung 4 ESTABLISHED by W187 (DM 3405) as a chosen-nonzero-halfword write at index 68,644; W3's WhiteLevel steering of three distinct non-saturated halfwords ESTABLISHED by DM 3413; no arbitrary byte alphabet, pointer/IP or r5.** Frontier staged W197 (brief `reports/frontier-libraw2shell.md`); the registered live two-pane window 133 was adopted with no duplicate (registry 134/134 unique). CVE-2026-135176 (VulnCheck 2026-11-23, CWE-787, CVSS4 5.8 `AV:L/AC:H/AT:P/UI:P`, no RCE claim), LibRaw exactly 0.22.3, upstream issue #894 open with no merged fix; the fixed control is the reporter's two lines. Pins in `lab/frontier/libraw2shell/PINS.md`, PoC input `c7940268…5dae2`, `evidence.log` `8ad12e49…874f57` (10 PASS/0 FAIL); ASan WRITE-2 one pixel past a 550176-byte region at `xtrans_demosaic.cpp:427`, plain rc 139, fixed/safe clean; earlier chosen-byte attempts stayed zero and are preserved as negatives. Witness W186 replayed the pinned tarball, patch and PoC from a clean room with 10 PASS/0 FAIL and confirmed rungs 1-3 plus the zero-halfword offset as labeled. W2 crafts 512x512 12-bit nonzero X-Trans pixels (input `b59f64e9…069341`, generator `004ff435…f862`): ASan WRITE-2 at `:427` and gdb chosen `0xffff` halfwords at index 68,644, with fixed and no-option controls clean; W187 (DM 3405) replayed it and upgraded rung 4 from PARTIAL to demonstrated chosen-nonzero-halfword. W3's `craft_whitelevel_poc.py` (`ab5ace42…b30d1cf`) changes one DNG WhiteLevel u32 at file offset `0x102`, deriving WL2048/4095/8191/16383 inputs and storing `ffff ea99 ffff 0000` / `afdf 7544 9c55 0000` / `57ec 3a9f 4e27 0000` / `2bf5 1d4f 2712 0000` at the chosen index (delta 0); DM 3413 ESTABLISHED that steering after regenerating all inputs in a clean room. Fully arbitrary byte values, a real camera file, GUI/network, pointer/IP, command and r5 stay UNKNOWN. [status](../reports/libraw2shell-status.md) |
| **Contiki2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 06:1xZ under standing #6 as the 130th route; real Contiki-NG 5.2 native in-process injection, rung 4 PARTIAL chosen marker at fixed offsets past `uip_aligned_buf`, witness W190 ESTABLISHED AS LABELED at that in-process scope, rung 5 UNKNOWN.** Frontier staged W198 (brief `reports/frontier-contiki2shell.md`); the registered live two-pane window 134 was adopted with no duplicate (registry 135/135 unique), with charter, hy4-flash route, both resolver keys and three wake units from the exact full-flag sync at pin `0d686bba…d528a` (`written 3, removed 0`, path enabled/active, pinned doctor GREEN rc=0). CVE-2026-135292 (VulnCheck 2026-11-23, CWE-787, CVSS4 8.3 `AV:N/AC:H/AT:P/VI:L/VA:H`, no RCE claim), Contiki-NG <= 5.2, upstream PR #3312 still open/unmerged; pinned `release/v5.2` tarball `78133c77…70819c95` and `mpl.c` in `lab/frontier/contiki2shell/PROVENANCE.md`. A truncated S=3 HBHO seed option makes the trickle-time rebuild copy 1232 bytes 16 past the 1280-byte global `uip_aligned_buf`: ASan `global-buffer-overflow WRITE of size 1232` at `mpl.c:981`, gdb chosen `MISHE-OO-TAUF!!\0` at `+1280..+1295`; fixed and safe inputs clean, `sh run-all.sh` 9 PASS / 0 FAIL, re-verified by operator at admission. Witness W190 (08:12Z) replayed a clean `git archive` with independent ASan and plain-gdb checks, 9 PASS / 0 FAIL, ESTABLISHED AS LABELED at the in-process scope — no tun device, wire-driven process, pointer/IP, command or r5; network reach UNKNOWN. [Brief](reports/frontier-contiki2shell.md), [status](reports/contiki2shell-status.md) |
| **AwsLc2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 10:2xZ under standing #6 as the 131st route; real AWS-LC v5.6.0 ASan-confirmed one-byte heap OOB write, rung 4 PARTIAL chosen byte at chosen offset in a minimal harness; witness W195 (#3550/#3551) ESTABLISHED rung-4 pointer-LSB control in a separate synthetic loopback consumer; W206 adds a plain-process heap-metadata negative and W208 a natural global-struct control datum, W209/W210 show AWS-LC's own PKCS#7 cipher BIO is an immune in-tree documented-minimum caller for every supported cipher (B=4096, b=8/16 divisors), and W211 reproduces the one-byte OOB with 3DES-EDE-CBC (b=8) into malloc(15), 11 PASS / 0 FAIL; rung 5 UNKNOWN.** Frontier staged it with brief `reports/frontier-awslc2shell.md`; the live two-pane window 136 was adopted with no duplicate (registry 137/137 unique), with charter, hy4-flash route, both resolver keys, wake-failure signal and three wake units from the exact full-flag sync at pin `0d686bba…d528a` (`written 3, removed 0`, path enabled/active, pinned doctor GREEN rc=0). CVE-2026-134056 (Amazon CNA 2026-11-23, CWE-787, CVSS 6.5 `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H`) / GHSA-h63c-583w-4qfw, AWS-LC < 5.7.0 padded CBC/ECB decryption over multiple `EVP_DecryptUpdate` calls; fixed by `ed3d805d…` (PR #3460). Replay `14 PASS / 0 FAIL`, no-ASM ASan `WRITE of size 16` via `cipher.c:411` past a 31-byte buffer, chosen canary `0xab`→`0x48`; fixed, single-call and padding-disabled controls clean. W212's synthetic `wire` mode steers attacker-supplied ciphertext bytes in a loopback consumer with a deliberately undersized destination; W213's 14-caller census finds no adjacent in-object control datum reachable from any real caller's output buffer in this tree, closing the in-tree consumer lane and leaving an out-of-tree application as the only real-consumer path (UNKNOWN). W214's source sweep of already-provisioned out-of-tree callers found no qualifying multi-update, documented-minimum-buffer shape. W215 (`93b61d8d`, source-bound, author-side) tests the highest-value unprovisioned consumer, pinned s2n-tls v1.5.16 (tarball `ab3e19f8…909214`, recomputed locally): CBC/ECB-capable decrypt sites are in-place and called once per EVP context (`s2n_cbc_cipher_aes.c:48-58`, `tls/s2n_record_read_cbc.c:55,70,77`; 3DES and composite AES-SHA share the shape), stream ciphers have b=1 and AEAD uses `EVP_AEAD_CTX_open`; pinned `cipher.c:190` clears `final_used` on every per-record re-init so the withheld-block carry cannot cross records, and no buffer is sized `in_len+b-1`. SOURCE-BOUND NEGATIVE, no build, ASan or witness replay. No real application, chosen pointer, IP, command or wire-to-command path; advisory reachability and RCE UNKNOWN. The minimal-harness limb, W206's plain-process bound, W208's natural global struct and W209-W211's source-bound BIO immunity / 8-byte-block case stay author-side and unwitnessed; the BIO store is exactly sizeof(buf) and the mem-BIO probe is only partial (EOF consumed the withheld block). [Status](reports/awslc2shell-status.md) |
| **Cicap2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 17:5xZ under standing #6 as the 132nd route; pinned upstream `process_encapsulated` and teardown functions, ASan heap-use-after-free at teardown and rung 4 PARTIAL chosen `90`/`72` in the aliased live `trash_entities[0]` slot; witness W205 (#3753) ESTABLISHED AS LABELED at the pinned-function scope; W1/W2 later reproduced the alias, chosen `trash0_start` and `header.c:631` UAF in a real ASan `C_ICAP_0.6.5` build, W2 feeding the request through an `AF_UNIX` socketpair via exported parser APIs; that W1/W2 harness boundary was closed for loopback by W3/W4; witness W211 (#3953) later replayed all real-build lanes from a clean `git archive 8cdc4281` (`REPLAY_ALL_OK 72 PASS / 0 FAIL`, ESTABLISHED AS LABELED, no grade change or r5).** Frontier staged it with brief `reports/frontier-cicap2shell.md`; the live two-pane window 140 was adopted with no duplicate (registry 141 windows / 133 unique names), with charter, hy4-flash route, both resolver keys, a wake-failure signal and three wake units from the exact full-flag sync at pin `0d686bba…d528a` (`written 3, removed 0`, path enabled/active, pinned doctor GREEN rc 0). CVE-2026-136126 (VulnCheck 2026-11-24, CWE-415, CVSS4 9.2 `AV:N/AC:H`, no RCE claim), c-icap-server `<0.5.16` and `0.6.0<=v<0.6.6`, fixed in 0.5.16/0.6.6 by master `05dcead8…`; pinned `C_ICAP_0.6.5` sources, patch and verbatim snippets hashed in `lab/frontier/cicap2shell/PROVENANCE.md`; `sh run.sh` 19 PASS / 0 FAIL operator replay plus frontier clean-archive replay `1ff81acb`, fixed/safe controls clean. W3 sends a crafted six-entity REQMOD request to the real ASan server on 127.0.0.1 and reaches its own `parse_header()`/`process_request()` and the `header.c:631` UAF; W4 reads wire-chosen `4242` in the live aliased `trash_entities[0]` slot. No traffic left loopback, no proxy or real client, no pointer/IP/command or r5; W205's verdict was pinned-function-only, W211 covers the real-build lanes. Grade: rungs 1-3 pinned functions plus W3's real-server lane, rung 4 PARTIAL chosen value in adjacent live slot, stock layout confirmed in pinned 0.6.5, wider deployment reach UNKNOWN, r5 UNKNOWN. |
| **Gpgme2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 18:5xZ under standing #6 as the 133rd route; pinned upstream `read_status`/`read_colon_line` realloc statements, ASan `attempting double-free` in `release()` after the first free by `realloc()`, and rung 4 PARTIAL chosen `0x48`/`0x5a` at offset 1000 in the stale allocation; pinned-statement scope witnessed #3796 with its bounds NIT fixed, real-build W1 author-only.** Pinned `src/engine-gpg.c` at tag `gpgme-2.2.0` (sha256 `c4ef11bda841fc6d07c83063c6968a6db50db3393af2d661054c59b979311d55`, recomputed locally from `lab/frontier/gpgme2shell/pinned/engine-gpg.c`); upstream fix `14499348b966cd7b3d72afee15a5cd51cdd0a727` (patch sha256 `2fde658ab8b32439c14f58c214f2463b4109aa68d9cbd26c432f17303049c500`, likewise recomputed) publishes the `realloc`'d pointer into the context immediately and deletes the end-of-function writeback. In `read_status()`/`read_colon_line()` a >1024-byte status line reallocs `buffer`, but a callback error early return leaves `gpg->status.buffer` holding the freed block for `gpg_release()` to free again. `sh run.sh` from `lab/frontier/gpgme2shell` verifies both pins and three source-shape assertions, builds four variants and gives 19 PASS / 0 FAIL with ASan `attempting double-free` and chosen `0x48` (ASan) / `0x5a` (plain) at offset 1000 in the stale allocation; fixed attack, vulnerable safe and fixed safe controls exit 0. The real-build plain glibc outcome was measured in W6 (glibc 2.39 tcache abort, no control primitive); the parent statement harness's contradictory plain revisions stay UNKNOWN in their own scope. Charter, hy4-flash route, both resolver keys, three wake units (exact sync `written 3, removed 0`, doctor GREEN) and frontier's two-pane window 141 are in place. Witness #3796 closed the pinned-statement scope (19 PASS after the offset-guard NIT). W1 built real GPGME 2.2.0 under ASan: the real `realloc()` at `engine-gpg.c:1494` runs through a loopback status pipe and the real early return, chosen `0x48`/`0x5a`/`0x37` appear in the real callback before the real second free at `gpg_release():602`, patched-2.2.0, stock-2.3.1 and short-line controls are clean (`PASS=21 FAIL=0`, clean-archive replay at `1ff8884b`). W1 replay #3808 is pending. W7 (`9633cfc8`, clean-archive replay `a1ecd700`) drives the advisory's second reader in real 2.2.0: a fake engine's 1024-byte no-LF colon record reaches `realloc` at `engine-gpg.c:1647`, EOF returns at `:1707` without the `:1728-1730` writeback, and the next keylist frees `gpg->colon.buffer` at real `gpg_release :604`; `sh run-colon.sh` 26 PASS / 0 FAIL, fixed and stock-2.3.1 controls clean with `byte[1000]=0x5a`. No wire input on the colon pipe, pointer/IP/command or r5; advisory `AV:N` is text, not exercised. [Brief](reports/frontier-gpgme2shell.md), [status](reports/gpgme2shell-status.md) |
| **Hping3Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 19:5xZ under standing #6 as the 134th route; verbatim pinned `display_ipopt()` RR branch, ASan global-buffer-overflow `WRITE-68`/`WRITE-86` into the 40-byte `old_rr` global, rung 4 PARTIAL packet-derived chosen bytes at chosen offsets in the adjacent live canary; witness W207 (#3822) ESTABLISHED AS LABELED at that pinned-function scope, later W1/W2 real-build wire limbs author-only, no grade change or r5.** CVE-2026-136131 (VulnCheck 2026-11-24, CWE-787, CVSS4 6.0 `AV:N/AC:H/UI:P`), affected hping commits `7257579b` through master tip `3547c769`, no fixed version; pinned `display_ipopt.c`/`waitpacket.c`/`hping2.h` and fix-patch sha256 in `lab/frontier/hping3shell/PROVENANCE.md`, 12 PASS / 0 FAIL in-tree and clean archive. W1 built the pinned tree with libpcap under ASan: crafted loopback RR replies reach `display_ipopt()` with `WRITE-68`/`WRITE-86` (9 PASS). W2 built the real plain binary: crafted loopback RR bytes land in the GDB-labelled adjacent `rc4_sbox` (4 PASS attack, 3 PASS zero baseline, 3 PASS patched control). The reachable 251-byte window contains only `old_rr.0` and `rc4_sbox`; no function pointer, GOT slot or other control-flow object. W5 measured changed RNG destinations and W6 (`650f9517`..`bf1360dd`) fills all 187 reply-reachable `rc4_sbox` bytes with a chosen constant, steering the low byte of later `--rand-dest` destinations without debugger steering (probabilistic: hidden `i`/`j`, 69 unreachable sbox bytes; 15/16 and 17/17 in the final clean replay), with baseline and patched controls 4 PASS / 0 FAIL each and `replay-rngctl.sh` 20 checks rc 0 from `659f6eb0`. No full IP, pointer/IP, command or r5; `AV:N` is advisory prose; post-fix `.bss` layout and other fortify settings stay UNKNOWN. W8 (`bea93e82`, clean-archive replay from `90d635d6` via `wire/replay-o2.sh`, `REPLAY_O2_OK: 11 checks`, rc 0) rebuilds the same pinned tree with GCC 13.3.0 at `-O2`: Ubuntu's default `_FORTIFY_SOURCE 3` turns the copy into `__memcpy_chk` with the real 40-byte bound, and the vulnerable process aborts with `*** buffer overflow detected ***` before storing crafted `i`/`j`/`rc4_seedflag`/`sbox` bytes (attack 3 PASS / 0 FAIL, no-injection baseline 4/0, patched 4/0) — a build-dependent DoS negative, not a grade change. Witness W207 covers the pinned-function stage; witness W212 (#4000) ESTABLISHED AS LABELED W6's RNG-control lane from a clean `git archive 659f6eb0` (20 PASS / 0 FAIL, `REPLAY_RNGCTL_OK`, no grade change or r5). The wire stages (#3942) and W5 (#3958) remain author-only with replay OWED. W12 narrows the distribution case only for Ubuntu 24.04 `3.a2.ds2-10build2` on this host: the shipped `/usr/sbin/hping3` (sha256 `d0181f16…edc9cd`) imports `__memcpy_chk`, the packaged source's `display_ipopt.c` is byte-identical to the pin, and a live loopback long-RR attack exits 134 with `*** buffer overflow detected ***` before any global write while a valid-RR control is clean (`sh wire/replay-distro.sh`, 5 checks, clean-archive receipt `20a65c8f`); other distributions, older packages and fortify-disabled builds stay UNKNOWN. [Status](reports/hping3shell-status.md) |
| **PxeIcmp2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 20:5xZ under standing #6 as the 135th route; verbatim pinned `PxeBcSupport.c` IPv4/IPv6 ICMP-error copy loops, ASan `heap-buffer-overflow WRITE of size 96` 0 bytes after a 720-byte region at `handlers_vuln.c:97`, rung 4 PARTIAL chosen fragment bytes `48 5a 4d 49` at `TftpError+96` and `54 41 55 46` in the adjacent plain-build canary; witness #3852 ESTABLISHED AS LABELED on a clean archive (31 PASS, independent 16-byte marker probe), no grade change or r5; no firmware build, loopback ICMP, event forging, pointer/IP/command.** CVE-2026-97631 / GHSA-99cj-7hg9-mp4m (2026-10-22, Critical CVSS4 9.5 `AV:N/AC:L/AT:P/PR:N/UI:N`), EDK II master as of 2026-09-14, pinned `edk2-stable202608` commit `2970e569…`; public fix PR #13302 merged at `fa789071…`. Four-pin `SHA256SUMS` and byte-for-byte extracted handlers in `lab/frontier/pxeicmp2shell/`; operator replay `sh harness/run.sh` = 31 PASS / 0 FAIL rc 0 with fixed, 300-byte-safe and clean-directory controls. Frontier's live two-pane window 143 adopted without duplication; hy4-flash route 134→135, both resolver keys 269→271, exact full-flag sync `written 3, removed 0`, path enabled/active, pinned doctor GREEN. |
| **N2n2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 21:2xZ under standing #6 as the 136th route; verbatim pinned `decode_REGISTER_SUPER_NAK()`/`decode_buf()` from n2n `wire.c`, ASan `heap-buffer-overflow WRITE of size 96` 0 bytes after a 64-byte region via `handlers_vuln.c:47`/`:81`, rung 4 PARTIAL chosen wire bytes `48 5a 4d 49` in the adjacent plain-build canary. W1 later reaches a real pinned supernode with one loopback UDP NAK: ASan stack `WRITE-96` in the live `nak` and 96 chosen bytes at `nak+14..109`, including two pointer-shaped slots; W2's hardware-watchpoint follow-ups saw no consumed-pointer read on that gcc `-O0`/`-O1` path.** CVE-2026-136404 (VulDB 2026-11-24, CWE-121/787), ntop n2n 3.0–3.1.1, vulnerable `dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff`, fixed `854fbbe01bbf131bf4cb88f8450d7084267668e1` (PR #1243); pinned sources and hashes in `lab/frontier/n2n2shell/PROVENANCE.md`, 15 PASS / 0 FAIL in-tree; `sh live/replay-live.sh` now replays W3's peer-forwarding lane too, 22 PASS / 0 FAIL. W6 checks the fixed build's surviving encoder read on this plain gcc `-O1` path: the rejected oversized `token_size=96` is still emitted from `nak+14`, but the wire token is 96 ZERO bytes (no stack disclosure at that size) while the fixed ASan build still aborts on the read with a peer; other builds and prior traffic stay UNKNOWN. The advisory's `sn_utils.c` stack-overflow attribution is reproduced locally. W7 (`89f256b6`, clean-room override `PLAIN=` in `b95b3d6f`) sends `token_size=600` and places chosen `0x5a48494d5a48494d` in pointer-shaped frame words past `nak+109`, with no read watchpoint in 22 s; W8 (`88e9e890`) finds that same fixed one-line build leaks 201 of 600 token bytes from wire offset 115 (`nak+129`), including stack/libc-shaped words, so the no-disclosure result does not generalize. W9/W10 (`d7d9a5a5`) supersede the blanket no-consumed-pointer clause on one specific build: clang `-O2` spills `encx` at `nak+1344` and `comm` at `nak+1696` inside a 1700-byte token's write window; garbage wire bytes fault at `sn_utils.c:2324` with those slots overwritten, and eight chosen bytes at token offset 1682 move the fault to `sn_utils.c:2344` (`encode_uint8`, `wire.c:49`). The valid replacement pointer came from a debugger pre-read with ASLR disabled, not a wire leak; both outcomes are crashes, with no benign marker, canary/RIP control or command, so the ceiling stays rung 4 and rung 5 stays UNKNOWN. `sh live/w10_pointer_control.sh` scored 9 PASS / 0 FAIL; the live limb is unwitnessed (#3909 still owed), ASLR otherwise on. Full evidence `reports/n2n2shell-live.md` §§W7/W9/W10. |
| **Pgactive2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 22:2xZ under standing #6 as the 137th route; verbatim pinned `pgactive_parse_replident_name()` (v2.1.9 `src/pgactive_catalogs.c:347-358`) with the unbounded trailing `%s` from `include/pgactive_internal.h:31`, ASan `stack-buffer-overflow WRITE of size 97` at offset 96 of the 64-byte stack `NameData`, rung 4 PARTIAL chosen `48 5a 4d 49` read inside the live function at offsets 0/64/92; witness W209 (#3898) ESTABLISHED AS LABELED from a clean archive (19 PASS / 0 FAIL), no grade change or r5. A later author-only SQL path calls the pinned wrapper in a live PostgreSQL 16.15 backend and gets ASan `WRITE-161` with a clean fixed control, but captures no chosen bytes there; no full pgactive build, replication wire path, saved pointer/return address, IP or command, and the SQL path is unwitnessed.** CVE-2026-134068 (CNA Amazon, 2026-11-24, CWE-787, CVSS4 7.7 `AV:N/AC:H/PR:L`), affected pgactive >=2.1.0 <2.1.10, fixed 2.1.10; pinned tags v2.1.9 `f34c8aa6f9f5c4ad5ee4bfdf93fef4b000be8f9e` and v2.1.10 `c3829ddb81c8c8e927b6e5a0baba3b1a016fcb52`, hashes in `lab/frontier/pgactive2shell/PROVENANCE.md`, 19 PASS / 0 FAIL in-tree. W9 (`6fb104bb`) bounds the internal catalog route on a loopback PostgreSQL 16.15 cluster with the full pinned 2.1.9 library: `pg_replication_origin_create()` accepts 66/67/99/275-byte names, so a catalog-derived name can overflow; driving it through `pgactive_get_global_locks_info()` stayed in state `b` with a "not configured for pgactive" error (UNKNOWN, not demonstrated), `pg_create_logical_replication_slot()` truncates 96→63 bytes, closing the output-plugin slot-name caller at `pgactive_output.c:382`, and a plain `LOGIN` role can create neither origins nor call the parser (owner-only `proacl`, non-`SECURITY DEFINER`). Author-side, no wire trigger or grade change; the advisory's authenticated `PR:L` precondition and command-execution claim stay claims; stand-in PG types only. |
| **Open5gs2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 02:0xZ under standing #6 as the 138th route; verbatim pinned Open5GS v2.8.0 `lib/sbi` empty-boundary multipart parser, ASan `WRITE of size 1` 0 bytes after a 65-byte region and plain build writes state-machine-forced `00 0d 0a` into an adjacent heap object — rung 4 PARTIAL, not arbitrary chosen bytes. `sh lab/frontier/open5gs2shell/harness/run.sh` 21 PASS / 0 FAIL; witness W217 replayed from a clean `git archive 22d70741` with a matching trace hash and ruled ESTABLISHED AS LABELED at that staged-harness scope.** W3 (`45560c31`) adds a real 127.0.0.1 HTTP/2 TLS listener (Go 1.22, ALPN `h2`) whose handler feeds the 396-byte request body verbatim into the pinned real-caller shim: `sh wireloop/run.sh` 13 PASS / 0 FAIL, `BOUNDARY_LEN=0`, ASan `WRITE of size 1` at `multipart_parser-v2.8.0.c:260`, plain canary `0a000d0a000d0a000d0a000d`; 394-byte, 10-byte safe and fixed controls are clean. A clean-archive four-suite replay scored 57 PASS lines / 0 FAIL with combined trace `ac435c40…da29`. W3's consumer is a synthetic shim, not an Open5GS NF, and witness #3934 stays scoped to the staged harness. W6 (`11bf8130`, clean-archive replay `d7634f20`) instead rebuilds both pinned source trees under ASan inside the live Open5GS v2.8.0 NRF: `WRITE of size 1` at `multipart_parser.c:260`, 0 bytes past the 65-byte region, with the four `CASE=` lines byte-identical on replay and vulnerable/fixed/safe/ABC controls; rung 4 DEMONSTRATED on that NF as a pre-auth loopback h2c process termination, author-only, no chosen pointer/IP/command and no r5; independent witness replay of the real-NF evidence is still owed. CVE-2026-116543 / GHSA-25v2-v588-jq8g; window 146. |
| **Yojimbo2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 02:0xZ under standing #6 as the 139th route; verbatim pinned `ReliableOrderedChannel::ProcessPacketFragment` final-fragment `memcpy` before the `blockSize` check, ASan `WRITE of size 500` 0 bytes after a 1100-byte region and plain chosen `MISHE-OO` at canary offset 300; fixed guard and safe controls clean. `sh lab/frontier/yojimbo2shell/harness/run.sh` 20 PASS / 0 FAIL with 7/7 SHA-256 pins. No CVE/GHSA or fixed release known.** W1 (`28d3c8c5`) builds the real pinned parent under ASan and drives the fix commit's regression through real `Connection::ProcessPacket` (`yojimbo_reliable_ordered_channel.cpp:716`, allocation at `yojimbo_reliable_ordered_channel.h:321`, fixed control clean), then an authenticated netcode UDP pair on 127.0.0.1 with a chosen `MISHE-LOOP` marker and a clean fixed control. W1b (`ff6c5e02`, report `30f77300`) reads the chosen marker back at `blockData+1200` under gdb after decrypt: rung 4 DEMONSTRATED only at the non-default 1100/500 config, post-auth, client and server in one process, with gdb-assisted readback — hence the `◐` cell. W2 (`f25517f8`) supersedes W1b's no-pointer bound: the 1100-byte block sits 605024 bytes into a 10 MiB TLSF arena from `BaseClient::CreateInternal`, the 0xAB filler corrupts the adjacent channel vptr at `blockData+1152` (the W1 `Connection::Reset()` SEGV), and the same encrypted final fragment carries a chosen 8-byte fake-vtable address that redirects a live virtual call to `MISHE-VTABLE-CALL` twice before a later TLSF teardown crash; the fixed-channel control is clean. Pointer control plus a benign marker in a non-PIE ASan lab build with the marker pre-placed, still post-auth and one-process; production use of a non-multiple block config stays UNKNOWN. W3 splits the victim into a second process; W4 sends two distinct wire-borne `touch /tmp/yojimbo-r5-established{,-2}` commands into the victim (two `MISHE-R5-CALL` lines, `RC 0`, 0600 markers) with a victim-argv counterexample, while W5's PIE fake-vtable negative and W6's stock-config negative stay preserved. Witness W213 (`557c58b1`, #4132) replayed both commands from a clean `git archive c9e2482e` with hash-matched vulnerable/fixed binaries and fixed/safe controls clean, and returned ESTABLISHED AS LABELED: rung-5 MECHANICS only at the stated ceiling (non-default 1100/500 config, post-auth, `-no-pie` lab build, lab-pre-placed trampoline, benign command, ASLR not defeated); NO full r5. Realistic PIE/ASLR derivation stays UNKNOWN. Upstream fix `d3d4f339…`; window 147. |
| **Libsshch2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 02:0xZ under standing #6 as the 140th route; verbatim pinned libssh `channel_rcv_data()` closed-channel data UAF, ASan heap-use-after-free `READ of size 32` 0 bytes inside a 64-byte region at `channel_default_bufferize`, plain chosen byte `M` / marker `MISHE-LIBSSH-UAF` at freed payload offset 16; fixed guard suppresses it, safe channel clean. `sh harness/run-all.sh` 24 PASS / 0 FAIL. Authenticated peer required.** W2/W3 (`c9e2482e`, `80eebc41`) drive a wire-chosen pointer write into a recycled freed channel in a clean-exit lab lane: `real/run-survive.sh` 7 PASS / 0 FAIL with `SERVER target_after=0x41414141414141c1 ... survive=1`, `CLIENT rc=0 SERVER status=0x0`, no ASan; a pure-rebuild allocation variant was measured negative (`buf_match=0 it_match=0`), and a clean archive replayed 5/0, 8/0 and 7/0. W4 (`c5ece2a9`) makes a wire-offset-112 chosen callee (`fn=0x61fe9f9fbd10`) reach `SERVER MARKER called`, and a wire string `touch evidence-wire-vuln-groom-exec.marker` runs through a lab trampoline (`SERVER EXEC rc=0`): explicit rung-5 MECHANICS, NOT ESTABLISHED as remote execution. Witness W214 (`f08fec31`, #4161) replayed five real-build suites from a clean `git archive c5ece2a9` (5/0, 8/0, 7/0, 9/0, 8/0) and returned ESTABLISHED AS LABELED for rung 3 on the real authenticated loopback wire and for rung-5 MECHANICS only at the lab ceiling: no contradiction, no grade change, NO full r5. W14 (`e4bfe196`, author-only) removes the trampoline from the callee path: `real/run-realsystem.sh` builds the same pins in plain Release with `-DW14_REALSYSTEM`, and wire offsets 0/112 select `channel->session` and real libc `&system`; 6 PASS / 0 FAIL, marker present, fixed and invalid-callee controls clean. The command is still an app-chosen static global and the addresses are fork-peer ASLR-local; authenticated peer, W3 detach, in-callback free and app-owned fake callbacks remain. No stock SSH daemon, persistent shell, IP hijack or remote command service. CVE-2026-59850 (fixed 0.12.1/0.11.5); window 148; distinct from `libssh22shell`. |
| **Socat2Shell** | ✓ | ✓ | — | — | — | **ADMITTED 03:3xZ under standing #6 as the 141st route; W2 (`1a34d2de`) dispositioned the candidate as a remote connection-abort bug on this host, NOT a memory-safety find. Real unmodified socat 1.8.1.1/1.8.1.2 ASan builds over a 127.0.0.1-only SOCKS5 listener show `W read(7, ..., -1): Bad address`, exit 255 and NO ASan report. Real `readfull()` passes SIZE_MAX to `read(2)`, which returns EFAULT before storing any byte; the harness's `WRITE of size 600` is a `memcpy` stand-in artifact. A source census finds no cap or alternate read behind any configure option, length bytes 0xf8..0xff yield negative counts (`SIZE_MAX .. SIZE_MAX-4`) after the first 5-byte read, and `sh real/run-count-probe.sh` (8 PASS / 0 FAIL) measures EFAULT-before-store for every count this bug generates on x86-64 Linux 6.8.0-149-generic; a 32-bit `size_t` build is UNKNOWN (no multilib). Harness 15 PASS / 0 FAIL, real replay 9 PASS / 0 FAIL. Rung 3 corruption and rung 4 chosen bytes NOT established, rung 5 not attempted, witness UNKNOWN.** CVE-2026-56123 / Socat advisory 10 (fixed 1.8.1.2); window 149 adopted. |
| **Ccextractor2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 04:4xZ under standing #6 as the 142nd route; rung 3 ASan-confirmed in the verbatim pinned CCExtractor `parse_mpeg_packet()` (`ccx_gxf.c:938-949`, master `2c1c1c6f…`), rung 4 PARTIAL chosen bytes at the nominal `BUFSIZE` boundary in a stand-in `buffered_read`/struct layout; `sh lab/frontier/ccextractor2shell/harness/run.sh` 17 PASS / 0 FAIL.** W1 (`22a822f2`) builds the real pinned tree and drives a crafted GXF through `read(2)`: ASan `WRITE of size 1052736` 0 bytes after a 2097272-byte region via `read` → `buffered_read_opt` (`file_functions.c:376`) → `parse_mpeg_packet` (`ccx_gxf.c:943`); safe input and the local guard exit 10 clean. W2 (`44f63207`) puts `00 00 01 B3` at `buffer+2097272` in `readback.gxf` and reads it back in-program (`got=2097348`, 76 past); `halt_on_error=0` also reports `READ of size 3900` at `boundary+76` through `memmove` → `process_data` (`general_loop.c:1041`). The brief calls rung 4 CONFIRMED at this real-build scope; no table cell, grade or witness verdict moved. No CVE/GHSA or upstream fix PR (fix UNKNOWN; the guard is a local hunk), no pointer/IP/command, no r5, witness UNKNOWN. clang ASan with default builtins did not report — preserved negative. Two-pane window 150 adopted, no duplicate. `reports/frontier-ccextractor2shell.md`, `reports/ccextractor2shell-status.md`. |
| **Mcuboot2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 08:3xZ under standing #6 as the 143rd route: hy4-flash route and three wake units minted, window 151 adopted; grade unchanged.** CVE-2026-16663 / GHSA-7c8v-m3pm (High 8.4, `AV:L`), MCUboot `>=1.9.0, <=2.5.0`; fix `6e1465c3…` merged on `main`, projected 2.5.1 not observed. Verbatim pinned `decrypt_region_inplace()` with local stand-ins: gcc ASan `dynamic-stack-buffer-overflow WRITE of size 1` 8 bytes past a 4096-byte VLA at `ih_hdr_size=4104`, clang agrees; deep `ih_hdr_size=6144` case gives a Valgrind invalid write but no ASan report (preserved negative). Rung 4 PARTIAL: chosen `4d495348452d4d4355424f4f542121` and `414243442d4d4355424f4f542d58595a` read back at `buf+6144`; 22 PASS / 0 FAIL, 22/0 from a clean archive. W1 (`ee7fe914`) builds the real pinned AES source in a host harness; W2 (`4ed74036`) drives a 127.0.0.1 loopback listener through verbatim `decrypt_region_inplace()` / `boot_enc_decrypt()` with wire-supplied `ih_hdr_size`; W3 (`3a04096d`, 10:59Z) reads client-supplied chosen plaintext back at the OOB destination (rung 4 DEMONSTRATED in the report at that live loopback scope). Still no real MCUboot serial/USB parser, pointer/IP/command, r5 or witness verdict; the README cell stays `◐` because wire bytes select the destination rather than a pointer. `reports/frontier-mcuboot2shell.md`, `reports/mcuboot2shell-status.md` (handoff 05:5xZ; admitted 08:3xZ). |
| **Drwav2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 08:3xZ under standing #6 as the 144th route: hy4-flash route and three wake units minted, window 152 adopted; witness W215 replayed 07:52Z ESTABLISHED AS LABELED at this scope, no grade change.** CVE-2026-11316 / Talos TALOS-2026-2442 (2026-11-24, CWE-787, CVSS3.1 8.8 `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`), dr_libs 0.14.5; no vendor fix commit in the advisory. Later tag `wav-0.14.6` (`35b5c392…ffe0`) adds a `metadataCursor` bound and result propagation — a source-bound control, not an advisory-confirmed fix. Verbatim pinned `dr_wav.h` 0.14.5 through real public `drwav_init_memory_with_metadata()`: a 150-byte RIFF desynchronises `smpl` pass 1/pass 2, so the next `cue` chunk writes past the reserved metadata slots; ASan WRITE through a file-low-half pointer `0x41414141` at `0x50f041414155` in `drwav__read_cue_to_metadata_obj()`. Rung 4 PARTIAL: file-chosen `0x4841434b`/`0x42424242` read back at a lab-groomed heap destination with `metadataCount=1`; the pointer's high half comes from the allocator. `sh lab/frontier/drwav2shell/harness/run-all.sh` 25 PASS / 0 FAIL under GCC and Clang, 25/0 with three pins from a clean archive (`d591751b`). Fixed 0.14.6 and matching-loop `safe` lanes clean; a global-destination variant in another allocator region was a preserved negative. No application, real wire input, vptr/return address, command or full r5; W215's ESTABLISHED verdict is scoped to the graded run (chosen target bytes, same-size-class condition), not a command-execution claim. `reports/frontier-drwav2shell.md`, `reports/drwav2shell-status.md`. |
| **Vtkdicom2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 08:3xZ under standing #6 as the 145th route: hy4-flash route and three wake units minted, window 153 adopted; grade unchanged, witness UNKNOWN.** CVE-2026-22879 / TALOS-2026-2366 (vtk-dicom 9.5.2, CWE-129, CVSS3.1 8.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`); vendor patch 2026-06-01, source-bound fix `bcc8b26` citing the CVE, vulnerable parent `2dd74234`. `sh lab/frontier/vtkdicom2shell/harness/run-all.sh` 14 PASS / 0 FAIL under GCC and Clang: ASan heap-buffer-overflow `WRITE of size 4` at pinned `e->Tag = tag` in `vtkDICOMItem::FindDataElementOrInsert()` via `Set()`; plain build writes chosen `0x4841434b` / `0x42424242` at harness-groomed store+160/+168, fixed and no-delete controls clean. Stand-in dependency classes; no real vtk-dicom build, DICOM file/wire through a real reader, pointer/IP/control-flow hijack, command, rung 5 or witness verdict. `reports/frontier-vtkdicom2shell.md`, `reports/vtkdicom2shell-status.md`. |
| **Xschem2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 08:4xZ under standing #6 as the 146th route: hy4-flash route and three wake units minted, window 154 adopted; grade unchanged, witness W216 (10:28Z) ESTABLISHED AS LABELED.** CVE-2026-128990 / GHSA-m9hw-gj2g-rvwj (xschem 2.9.9 through 3.4.7, CWE-787, CVSS4 8.5 `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`; a file converter, not network-facing). Advisory cites fix `e29af39c`; vulnerable tag 3.4.7 = `3851bc5a`. Whole pinned `src/rawtovcd.c` at both versions; real `read_dataset()` on a crafted `.raw` header gives GCC and Clang ASan `heap-buffer-overflow WRITE of size 8` at pinned `:130`, fixed rejects; `sh lab/frontier/xschem2shell/harness/run-all.sh` 25 PASS / 0 FAIL. Rung 4 PARTIAL: file-chosen signed index reads back an allocator-derived pointer, not file-chosen stored bytes (tcache-grooming negative preserved). No function-pointer overwrite, control-flow hijack, wire, command or r5; witness W216 replayed a clean `git archive 42e0f33f` (25/0 harness, 3/0 real unrenamed `main`) and graded ESTABLISHED AS LABELED with no grade change. `reports/frontier-xschem2shell.md`, `reports/xschem2shell-status.md`. |
| **StbVorbis2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 10:5xZ under standing #6 as the 147th route: hy4-flash route and three wake units minted, window 135 adopted; grade unchanged, witness UNKNOWN.** CVE-2026-89266 (VulnCheck 2026-09-11, CWE-787, CVSS4 8.8 `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H`, stb_vorbis <= 1.22); vulnerable v1.22 `2c980bb` sha256 `4c7cb2ff…e65636`, dev-branch fixed `daedcc5c…e86a5` with `CODEBOOK_LIMIT (1<<18)`, numeric fixed release UNKNOWN. `setup_malloc(vorb*, int)` truncates the file-derived `size_t` product `4 * 16519105 * 65 = 2^32+4` to `malloc(8)`; real `stb_vorbis_open_memory()` on a 205-byte OGG gives ASan `WRITE of size 4` at `stb_vorbis.c:3889`, fixed and safe inputs clean, and gdb reads file-chosen `4b 43 41 48` ("HACK") at the first OOB float (`lab/frontier/stbvorbis2shell/run-all.sh`, 9 PASS / 0 FAIL). Rung 4 PARTIAL: W202's `run-seq.sh` (4/0) replays four distinct file-derived words at consecutive OOB offsets, and W204's guarded-page harness measures 30 words / 120 bytes past the 8-byte region before `VORBIS_invalid_setup` returns (12/0); W204 also shows all 30 words overwriting an adjacent live object's canary and both halves of its pointer-typed field (`run-object.sh` 9/0, `fp_low=0x4b434148`, pointer read back, never dereferenced). The words are a float-representable progression, not per-offset arbitrary bytes; the victim is harness-placed. W206 drives the crafted OGG through real SDL_mixer's public `MIX_LoadAudio_IO()` API into its vendored v1.22 header: ASan `WRITE of size 4` at `stb_vorbis.c:4040` with fixed and safe inputs clean (`run-consumer.sh` 12/0, clean-archive receipt 12/0 plus five other scripts); no chosen word, pointer or command in that consumer. No wire, pointer control, command or witness verdict; NO r5. `reports/stbvorbis2shell-status.md`. |
| **Ctranslate22Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 11:2xZ under standing #6 as the 148th route: hy4-flash route and three wake units minted, window 155 adopted; grade unchanged, witness UNKNOWN.** CVE-2026-102566 / GHSA-7xqx-34h9-2w97 (CTranslate2 <4.8.1, CWE-787, CVSS4 8.5 `AV:L/UI:P`; file-format loader, not network-facing); fix `d9b991e` (PR #2068), vulnerable pin v4.8.0. Verbatim pinned `consume<char>()` / `Model::load()` ranges with a stand-in 16-byte `StorageView`: 16 PASS / 0 FAIL under GCC and Clang, ASan `WRITE of size 17` / `64` at pinned `model.cc:657`, fixed pin rejects, safe payload clean, chosen-byte readback; clean git-archive replay 16/0. W1 builds verbatim upstream `model.cc` against the real `StorageView`/`posix_memalign` allocator under ASan (`WRITE of size 17`/`48` into a real 16-byte region); W2 measures the real-heap pointer gap — the top chunk follows the buffer and later constructors overwrite chosen bytes at +0x40/+0x48, so no chosen pointer reached a dereference (80-byte payload aborted in `sysmalloc`), and a witness replay is requested. Rung 4 PARTIAL at one known offset; no whole-library build, pointer-IP, wire, command or r5; witness UNKNOWN. |
| **Solanum2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 13:1xZ under standing #6 as the 149th route: hy4-flash route and three wake units minted (sync `written 3, removed 0`), pinned full-flag doctor `PASS local plant out of Git` / `GREEN` rc 0, window 156 adopted; rung 3 real ircd process / rung 4 PARTIAL ESTABLISHED AS LABELED by witness W219 (#4481), no r5.** CVE-2026-121603 / GHSA-6cq2-4j8w-7hvj (Solanum IRCd before fix `2ea1382`, CWE-120, CVSS4 8.5 `AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N`); requires an authenticated linked server. Vulnerable pin parent `7bc7e34`, fixed pin `2ea1382` (+4/-0, `KILLLEN` truncation); pinned `ms_kill()` bodies verbatim with stand-in Client structs, `bash lab/frontier/solanum2shell/harness/run-all.sh` 18 PASS / 0 FAIL under GCC and Clang: ASan `global-buffer-overflow WRITE of size 533` at pinned `m_kill.c:277` for reason 510/700, safe 480 clean, fixed clean, plain chosen-byte readback past `buf+512`. Rung 4 PARTIAL: input-chosen length/bytes at a known offset of a harness static buffer; W1/W2 later confirm the ASan write (size 564) and plain chosen-byte readback in real ASan/plain IRCd builds over authenticated loopback S2S KILL, and W3 finds no writable consumer object after `buf`; still no pointer target, command or R5. W219 replayed `replay-all.sh` from clean archive `b8885fcc` (18/0, then 6/0), rebuilt both pins, matched eleven normalized evidence files and confirmed the PR:H prerequisite with an unauthenticated-peer counterexample (no KILL, no ASan). |
| **Aspell2Shell** | ✓ | ✓ | ✓ | — | — | **ADMITTED 18:1xZ under standing #6 as the 150th declared target mind; window 157 adopted; engine route delivered in the 20:27Z 152-role config (omp-only GREEN); three generated wake units still missing (doctor RED, person-reserved).** CVE-2026-75818 / CERT Polska 2026-10-06, GNU Aspell before 0.60.8.3, CWE-122, CVSS4 1.8 `AV:L/AC:H/PR:N/UI:A`; fix `15b18843`, vulnerable parent `bc7ffcb`. Full pinned `prog/prezip.c` program: crafted 22-byte stream walks 605 bytes from a 256-byte heap allocation; GCC and Clang ASan report `READ of size 1` at pinned `:173`, 0 bytes after the region, fixed rejects and encoder-round-trip safe input decodes cleanly. `bash lab/frontier/aspell2shell/harness/run-all.sh` = 14 PASS / 0 FAIL. Rung 4 NOT CLAIMED: no chosen-byte store, real dictionary consumer, pointer target, command or r5; witness UNKNOWN. [Status](reports/aspell2shell-status.md) |
| **FreeImage2Shell** | ✓ | ✓ | ✓ | ◐ | — | **ADMITTED 18:1xZ under standing #6 as the 151st declared target mind; window 158 adopted; engine route delivered in the 20:27Z 152-role config (omp-only GREEN); three generated wake units still missing (doctor RED, person-reserved).** CVE-2026-118753 / GHSA-wr69-568q-rrqg, Danoli3 FreeImage before 3.19.25, CWE-787, CVSS4 8.5 `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`; fix `0da5ddb4`, vulnerable `3.19.24` `4916e0ec`, fixed `3.19.25` `363311f1`. Real static library through public `GIF_PLAYBACK` APIs: GCC ASan heap-buffer-overflow `WRITE of size 4` at `PluginGIF.cpp:743`, 0 bytes after an 816-byte region; fixed and safe controls clean. Vulnerable plain chosen-palette runs put `TAU,ff` at `bits+400/+404/+408` past the nominal 400-byte canvas, then the far frame segfaults; `SKIP_BUILD=1 bash lab/frontier/freeimage2shell/run-all.sh` = 9 PASS / 0 FAIL. Rung 4 PARTIAL at those fixed offsets only; no adjacent-object target, pointer, remote consumer, command or r5; witness UNKNOWN. [Status](reports/freeimage2shell-status.md) |
| **Fceux2Shell** | ✓ | ✓ | ✓ | ◐ | — | **STAGED 19:2xZ, NOT ADMITTED; declared in the 20:27Z 152-role engine config with no generated wake units (doctor RED, person-reserved), window 159 adopted, witness replay UNKNOWN.** CVE-2026-136918 (FCEUX < 2.8.0, UNIF MAPR declared size `0xffffffff` wraps the board-name allocation; CNA CWE-190, CVSS4 8.5 `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`); fixed 2.8.0 (`c40fcf63`), vulnerable parent `1e1de9b`, fix `d9132c2`. Verbatim pinned `SetBoardName()` under GCC and Clang ASan: heap `WRITE of size 19`, 0 bytes after a 1-byte region; fixed and safe controls clean. Plain file-chosen bytes land at `boardname+1..+16` (`PAST_ALLOC=41552c66664d495348452d4643455558`) before the wild terminator faults; `bash lab/frontier/fceux2shell/run-all.sh` = 14 PASS / 0 FAIL. Rung 4 PARTIAL at chosen offsets only; no adjacent object, pointer control, live ROM consumer, wire path, command or r5. [Status](reports/fceux2shell-status.md) · [Brief](reports/frontier-fceux2shell.md) |

The 2026-11-25 0x–06:2xZ limbs correct four row boundaries without moving any
rung, grade, route, mind-count, witness or R5 cell. Ruby2Shell's stock Rails
N=524 "no 0x3f0 consumer" claim rested on a probe that compared a malloc user
pointer with the forged chunk start, so a P line could never fire
(`reports/ruby2shell-investigation.md` §Consumer-visibility correction). With
`process_vm_readv` window lines and `lab/repro/ruby2shell-cons-vis-tabulate.py`,
49 runs gave 5 survivors and zero window frees (Q=0/49): the forged 0x251 qword
at `case_physical+0x18` forms a pseudo-chunk whose user pointer is never freed,
so the qword is structurally inert, not merely unobserved. The same corrected
probe measured post-attack C `request=0x21c/0x1f8` pops at the victim user
pointer in two live survivors; stock/oracle-free/persistent R5 stays NOT
ACHIEVED and the harness-condition witness-ESTABLISHED R5 stays as labelled.

The 2026-11-25 third push re-smoked Ruby2Shell's harness rung-5 chain
(attack marker + `rce=OBSERVED` + target pop; safe and fixed clean) and
measured one new stock surface: a stock Sinatra dev 500 page leaks 20
GC-heap object addresses via env `to_s`/`inspect`
(`lab/repro/ruby2shell-errorpage-oracle.sh`), 12 boot-stable in-process but
0/20 low-bit overlap across fresh processes and all 20 in Ruby GC pages,
none in glibc heap, libc or code. It is not wire-reachable on a route-less
app and Rails filters it; it replaces only `ObjectSpace.dump`, not mtrace
or maps. Stock/oracle-free/persistent R5 stays NOT ACHIEVED, and the
labelled harness-condition R5 cell is unchanged.

The 2026-11-25 fourth push closes Ruby2Shell's keep-alive same-thread lead
(`lab/repro/ruby2shell-keepalive-thread.sh`): with Puma `min=3/max=3`, the
fixed pool used by `rails new`, five GETs on one reused connection rotated
across all three worker threads in 3/3 fresh processes, so HTTP keep-alive
does not enable same-thread tcache grooming on the relevant target. The
default `min=0/max=5` pool did share one thread for sequential requests, a
configuration property that leaves the no-parse-free and post-upcase-GC
blockers intact. Stock/oracle-free/persistent R5 stays NOT ACHIEVED.

The 2026-11-25 direct-session push records two more bounded negatives for
Ruby2Shell. Restoring the forged T-chunk malloc header via
`/proc/self/mem` (`RUBY2SHELL_R5_REPAIR=1` in
`lab/repro/ruby2shell-rung5-http.ru`) did **not** restore process
survival: the new `ruby2shell-rung5-http.sh survive` mode got a first
`rce=OBSERVED` plus marker, but `GET /health` and a second distinct-marker
POST both returned `HTTP 000` and the process aborted on a boot-time
0x2010-class chunk at heap offset 0x1980. A systematic survey of remaining
default Sinatra/Rack/Puma/Rails surfaces found no wire-only glibc-heap or
libc/code-base disclosure — only Ruby GC-anon `VALUE` pointers on the
already-measured Sinatra dev 500 page — so the harness oracles still have no
wire substitute on an unmodified app. The harness matrix re-verified (attack
marker + pop, safe-input and fixed 3.4.13 controls clean). Stock/oracle-free/
persistent R5 stays NOT ACHIEVED.

The 2026-11-25 sixth push (direct session) answers Ruby2Shell's named
reflection lead and measures the first missing oracle wire-only. The
48-part/filler-first arm aborts 6/6 (top-chunk pop → `sysmalloc`), but the
new committed `ruby2shell-reflect-scan.py` found the channel already firing
in the 32-part consH20-tail geometry: 20 saved stock-Rails 404 responses
(17% of surviving stage2d arms, previously never byte-parsed) reflect
post-parse allocator/Ruby metadata inside live drain bodies — fake `0x25`
chunk sizes, PREV_INUSE'd `0x91` pattern qwords and pointer pairs, i.e. a
bin insertion whose chunk overlaps a live wire-chosen string. Live
classification (`ruby2shell-stock-leakclass.sh` + `ruby2shell-leak-maps.py`,
post-response `/proc/PID/maps` read outside the request path) shows the
pair partner pins the request-thread glibc arena region base
(region+{0x8c660,0x8c760,0x8cdb0}, 11/11 victim-correlated — tcache key
wire-known) and the live instance's other pointer is a Ruby GC-page
address (`[anon:Ruby:GC:...]`), replacing `ObjectSpace.dump`. Structural
negatives: the worker-arena bin heads are in-region, so this channel can
never leak libc; zero attacker-chosen `0x53`-runs in 432 parameter-bearing
responses; a second attack on a leak survivor aborts 3/3. First oracle
measured; full stock/oracle-free/persistent R5 stays NOT ACHIEVED.

The 2026-11-25 fifth push closes Ruby2Shell's consH-20 low-byte tcache
retarget lead as a bounded negative
(`lab/repro/ruby2shell-consH20-retarget.sh`, 144 fresh processes of the
N=524 case probe on the unmodified `rails new --minimal` app). Eleven runs
survived and 52 showed a real unsorted expansion, but only one ever returned
an allocation into the forged window: its three pops were C-internal
fixed-size requests (`0x3`, `0x10`, `0x28` bytes) with one on-thread free,
and the victim content was the fixed `0x53` upcase byte, not attacker-shaped
input. The overflow byte changed the victim's size field (`0x201`→`0x253`),
not the fake `0x20` chunk's tcache `next`, so no oracle-free Stage-B analog
was steered. Stock/oracle-free/persistent R5 stays NOT ACHIEVED; the
witness-ESTABLISHED harness-condition R5 cell is unchanged.
The 2026-11-25 main-arena lead is also closed as a bounded negative
(`lab/repro/ruby2shell-mainarena-leak.sh`, 12 fresh `rails new --minimal`
processes at `MALLOC_ARENA_MAX=1`, then 12 more at an N=532 body). Victims
landed in `[heap]` 16/16, and two N=524 victims held a real libc pointer in
their `fd=bk` (`libc.so.6 +0x203b20`, maps-confirmed), but every survivor's
reflected 404 params were byte-clean: 544 parts, zero pointer-shaped qwords.
The +8 length shift changed the chunk size class, not the write offset, so
the byte still hit the victim SIZE field. No libc/code-base oracle from this
route. The same arm with 48 drain parts and filler-first order aborted 11/12
pre-response; its one survivor was byte-clean too, closing the count/order
knobs on both geometries. Stock/oracle-free/persistent R5 stays NOT ACHIEVED.

The 2026-11-25 tenth push answers Ruby2Shell's shrink-family claim
question (`lab/repro/ruby2shell-shrink-claim.sh`, 48 fresh `rails new
--minimal` processes in four arms: N=588 planted/unplanted, N=892
planted, N=988 planted with 40×920B chosen-strip plants; each run
sends an optional benign plant, the consH20-tail attack body
(byte-verified against the cov-n588 geometry), a benign
matched-class claim, then `/up`). No matched-class claim ever popped
a corrupted chunk: plant churn moves victims to tiny/fresh classes;
big unplanted binned victims abort during the attack at the request's
own unsorted consumers (7/7); surviving corrupted classes sit below
the ~809B plant floor; planted-band grown victims (0x411/0x415→0x453)
rest in their original 0x410-band bin where matched claims fit
without overshoot, and the big planted-band victims (0x411/0x471/
0x601→0x453/0x653) all abort during the attack. Two N=988 runs
complete attack, claim AND `/up` 200 carrying an untriggered corrupted
IN-USE small chunk (real pairs `0x95→0x53`/`0x35→0x53` after a B/A
pairing correction — the earlier "binned 0x453" reading spliced pairs
from different phases). Structural closure: the 0x53 byte
always sets IS_MMAPPED, so every consumer that `free()`s the
corrupted chunk aborts in `munmap_chunk` (measured); only
neighbor-consolidations survive, making Einherjar structurally the
only surviving consumer.
Stock/oracle-free/persistent R5 stays NOT ACHIEVED.

The 2026-11-25 eleventh and twelfth Ruby pushes' slice/sweep model is
superseded, not a current blocker. The measured correction is two content+9
slices plus one next-power-of-two value per embed-legal part, with glibc tcache
ending at chunk `0x420`. Order arms then falsified "big slices never sweep":
big-first freed 32 planted big slices across 3/12 runs, small-first freed 22
smalls across 2/12, and interleaving freed both classes. The earlier zero-`0x621`
result was an arm artifact, and the claimed `0x3E1` frees were mostly a
`0x3f0`-slice misread. Filler pressure does produce freed-in-unsorted victims,
but the corrected chain closes as described in the 16:3x–17:1x fold below.
Stock/oracle-free/persistent R5 stays NOT ACHIEVED.

Pgactive2Shell W11 (`e8dd96f6`) corrects W8's saved-RA layout: objdump shows
`lea -0x70(%rbp),%r12`, canary at `rbp-0x28` (+72) and the real saved RA at
`rbp+8` (+120), overwritten from N>=128 with `41 5a` but never consumed
because the pinned `!=4` path leaves via `elog(ERROR)` longjmp. The earlier
`-40`/`-32` matches were stale observations, not this function's RA
(`reports/frontier-pgactive2shell.md` §saved-RA correction); the layout lane
is author-only and witness W209 is unchanged. Synchronet2Shell W20
(`1db3684f`, `63b54b1e`) traces shipped 3.20b commit `db9c5d6f…` through eight
pinned files from the 64-byte TERM copy into the 41-byte field to
`listFreeNodes` starting at `list->first` and `free(node)`: a chosen non-NULL
field would start teardown at a chosen pointer. Source-bound only, 17 PASS /
0 FAIL live and from `git archive 1db3684f` (normalized `e74779de…`), with no
build or dereference at that point. W26 later measures the shipped build's
whole-process SIGSEGV under concurrent load; see the latest fold below.

OpenEXR W197 (`cc39716b`) supersedes the earlier file-level "no chosen code
pointer/IP" boundary: an unmodified `exrcheck -c` reaches a file-chosen
`destroy_unpacked_func_ptr=0x555555661b30`, plain rc 139, fixed rc 1, five
matching hashes and a clean-archive receipt
(`reports/openexr2shell-file-level.md` §W197), author-only with no grade or
witness change. FontForge W16 (`c9c5b891`, `f1b223ca`) supersedes W12's
"byte 3 still only 0/1": a negative divisor makes byte 3 `0xff`, moving
`BDFChar.bitmap` from `0x0000555555c227f0` to `0x00005555ff0105fe` (PIE) or
`0x00000000ff0105fe` (non-PIE), both unmapped; `replay-negdiv.sh` 20/20 rc 0
and clean-archive receipts 17/17, 15/15 and 20/20. The nonnegative-RHS ceiling
`0x01FFFE00` stands; no grade, pointer dereference or r5.

The remaining edges are bounded negatives and receipts with no row change:
libgphoto2 W185's `priv` at `rbp-0x4068` lies outside the device-only write
reach; yojimbo W6's stock 262144/1024 fragment ends exactly at the allocation;
munt W187 needs a 32768-byte preconditioned capacity; gpgme W11 (`057e2e2a`,
receipt `20a42ca6`) measures a real-build `read_status` EOF early return that
needs no callback error; W10's full 0x410
tcache bin still aborts with chosen `0x48` at offset 1000 (26/0); libraw W21's
live top-chunk size field sits 550,184 bytes past `destimage` and free aborts
`invalid next size` (11/0); open5gs W2 resolves SBI framing with a 396-byte
`\r\n\r\n` body (harness 21/0); awslc W216's Node 22.11.0 exact-fit allocation
stays ASan-clean; knotresolver W21 finds no `system`/`popen`/`exec*` in PIE
`kresd`; cjose W209 and cicap W9 close wording and fold the earlier W211
witness verdict. No rung, grade, route, mind-count, witness verdict or r5 cell
moved by any of them.

The 01:5x–02:1xZ limbs supersede the Munt2Shell row's blanket "no pointer
control, marker" and the Libgphoto2Shell/Gpgme2Shell rows' scope lists below.
Gpgme W5 (`72f3b6ad`, replay receipt `844eed91`) combines W3's loopback HKP
key fetch with W4's next-operation reclaim in real GPGME 2.2.0 under ASan:
`sh run-wire-reuse.sh` printed 55 PASS / 0 FAIL, chosen `0x48`/`0x5a`/`0x37`
at offset 1000 of the wire-supplied `[GNUPG:] IMPORTED` status line, and the
second `gpgme_op_keylist_start()` frees the stale block in
`_gpgme_op_reset → gpg_release engine-gpg.c:602` after the first free by
`realloc` at `read_status engine-gpg.c:1494`; a clean archive of `72f3b6ad`
replayed six suites 55/32/24/21/36/19 PASS, all rc 0. Author-side only;
witness request #4028 with receipt #4029 has no verdict, no pointer/IP/command
and no r5. Libgphoto2 W180 (`018f76d5`, `97c61c79`, `73a38aed`) gives a
one-command replay, `sh lab/frontier/libgphoto2shell/live/replay-real-w177.sh`
(DRAIN auto-sweep 20..40, DRAIN=20 observed), from a clean archive of
`97c61c79`: 4/4 pins OK, tarball `5df9e774…f28`, patched vusb
`2b744f67…e57dde6`, `RESULT: 20 PASS / 0 FAIL`. Three own-canary records at
k=1023 (`OWN_CANARY=8a17bc30d6578900` etc.), three code/stack-shaped words at
k=1024 matched by read-only gdb, count=100 rc=-108 and the full reply aborted
with stack smashing; the disclosure still reaches a HOST consumer through
real `gp_camera_file_get()` on a lab-patched vusb reply, with no device
readback, wire path, command or r5, author-only and unwitnessed. Munt W186
(`31fd23fe`, `e224af08`) uses a 32785-byte short SysEx through real
`DefaultMidiStreamParser::parseStream()` and a harness-created `Victim` next
to the 32768-byte buffer: one input byte at index 32784 changes the low byte
of its function pointer (`0x67…` to `0x49…`, attack byte `0x49`) and calls
benign `marker_1` in the vulnerable plain build, while fixed and safe cases
do not; vulnerable ASan reports `WRITE of size 32785` 0 bytes past the real
32768-byte region. Clean-archive replay matched all six rc cases and seven
normalized evidence files (digest `b06a4b42…e7c`, quoted from
`PARTIAL_REPLAY.md`); the pointer and victim are harness-created, no real
library object with a function pointer at that offset was found, no ASLR
defeat, host/wire input, command or witness verdict, so witness #2781's
ESTABLISHED label stays scoped to the older real-library rungs 1-4 and rung 5
stays `—`. FontForge W12's corrected ceiling `0x01FFFE00` (not `0x0100FEFF`;
byte 3 later reached 0xff on W16's negative-divisor path, see below), recomputed locally as `value-ceiling-high.pcf`
`9a6b2603…f6b82` and `gdb-value-ceiling-high.out` `540d9b0b…091a0`, is folded
below; libsshch's 01:58Z handoff reran `sh harness/run-all.sh` 24 PASS /
0 FAIL with 9/9 pins and ASan `READ of size 32` at
`channel_default_bufferize`, with no new verdict. No rung cell, route, mind
count or R5 cell moved by any edge here.

The Pgactive2Shell row's "no full pgactive build" boundary applies to the
`sqlpath/` 16.15 harness, not to commit `20123ce2`: the author then built the
complete pinned 2.1.9 extension, loaded it into a loopback cluster with
`shared_preload_libraries=pgactive`, and the real SQL call gives ASan
`stack-buffer-overflow WRITE of size 161` at offset 96 of the 64-byte
`replication_name` region, frames `:351` and `pgactive.c:1531`; 2.1.10 rejects
and the plain 2.1.9 backend errors without crashing because `elog(ERROR)`
longjmps before the canary check. No chosen bytes on that SQL path, no
PUBLIC EXECUTE in either version, no replication wire, saved-pointer/IP,
command or r5; witness #3896 still covers only the original pinned harness.
Author-run; a clean `git archive 20123ce2` replay of all three `realbuild/`
scripts matched the rc matrix and the same `WRITE of size 161` frames
(`ba19500c`), still not an independent witness verdict. No grade change.

Pgactive W8 (`3c6304ba`) closes the saved-return-address route at the real
non-ASan 2.1.9 stack-layout scope: `realbuild/layout/run-layout.sh` adds one
noinline helper in the existing error branch and logs
`__builtin_return_address(0)` and a 320-byte window around
`replication_name`. In both the `-O1 -g` and PGXS production builds
(`LAYOUT_BUILD=0`, `LAYOUT_INITDB=0`, `LAYOUT_PGSTART=0`, `LIVENESS_RC=0`,
normal library and source restored) the parser's saved RA lies BELOW the
buffer at `-40` / `-32` bytes, while a second copy at `+104` / `+120` is
overwritten from N>=128 with `41 5a` repeats but is never consumed because
control leaves via `elog(ERROR)` longjmp, not `ret`. A `%s` store grows
upward from offset 0, so no input length reaches the consumed slot; no
backend terminated at any length and `SELECT 1` still succeeds. This is a
structural negative for a stronger rung 4 at this build, not a new
capability: the chosen-byte marker and the real-SQL ASan limb stay as
labeled, with no IP, command or r5. Gdb live attach remains denied by
`ptrace_scope=1`; the first failed layout script used a socket path over
PostgreSQL's 107-byte limit and was moved to `/tmp`.
`lab/frontier/pgactive2shell/realbuild/layout/FINDINGS.md`,
`reports/frontier-pgactive2shell.md`; author-side, unwitnessed, no grade
change.


The 02:29–02:4xZ limbs record the real-build plain-glibc result now folded
into the Gpgme2Shell row and add replay/caller-boundary detail to the
Open5gs2Shell row; no rung cell, grade, route, mind count or R5 cell moved.
Gpgme W6 (`3aaa3f07`, clean-archive receipt `67a874c2`) builds real GPGME
2.2.0 and the fix-patched copy without a sanitizer (`CFLAGS=-g -O0`,
`CC=clang`, static-only into `prefix-plain`): from
`lab/frontier/gpgme2shell/realbuild`, `sh build-plain.sh && sh run-plain.sh`
documents the lane and `sh run-plain.sh` printed `PASS=13 FAIL=0` rc 0 here.
On glibc 2.39 the vulnerable driver exits 134 with
`free(): double free detected in tcache 2` after
`status_cb call=1 op_marker=H keyword=GOOD arglen=1200 byte[1000]=0x48` and
no second keylist; the patched driver exits 0 with `op2 keylist_start
err=Success`, `op_marker=Z arglen=20` and `release done`. The tcache detector
aborts before allocator metadata or control-flow use: a negative rung-5
route, not a new capability. The parent statement harness's contradictory
plain revisions stay UNKNOWN in their own scope; #4039 is a witness scope
note with no verdict. `reports/gpgme2shell-status.md` §W6.

Open5gs W1 (`6d5f8de9`, replay receipt `318023f3`) records witness message
#3934 (witness wall W210) ESTABLISHED AS LABELED at the staged-harness scope
(clean `git archive 22d70741`, `sh harness/run.sh` 21 PASS / 0 FAIL rc 0,
trace SHA-256
`6c3c5ecf1f9e4ec7ef8d907d24e033e16fe4b87d62408ef1c499c95086164253`,
no grade change and NO r5), alongside the row's W217 label.
`lab/frontier/open5gs2shell/realcaller/` derives the boundary as pinned
`message-v2.8.0.c:3356-3381` does: the staged 394-byte body gives
`BOUNDARY_LEN=2 BOUNDARY=a:` and an ASan-clean canary, while adding one
leading CRLF (396 bytes) gives `BOUNDARY_LEN=0` and ASan `WRITE of size 1` at
`multipart_parser-v2.8.0.c:260`, with plain canary `5a5a...` ->
`0a000d0a000d0a000d0a000d` and fixed `RET=-1`. `sh realcaller/run.sh`
scored 15 PASS / 0 FAIL here, and a clean `git archive HEAD` replay at
`318023f3` reproduced 21/0 and 15/0. Whether a live SBI HTTP layer preserves
that leading CRLF in `http->content` stays UNKNOWN; no wire request, pointer,
command or r5.

N2n W5 (`1029f346`) extends W1/W2's consumed-pointer negative: four batches
of four hardware read watchpoints at `&nak+128/+136/+344/+432`,
`+368/+392/+400/+424`, `+464/+488/+504/+536` and
`+1608/+1616/+1632/+1640` never hit while the registered-peer run forwarded
the 134-byte NAK with `beyond48=485a4d49485a4d49`. The excluded `+288` trip
was a `sockbuf` store in `__vsnprintf_internal`, not a consumer read;
unwatched words stay UNKNOWN and the W3 forwarding data copy is still the
only measured consumer. Witness replay #3909 remains owed.
`reports/n2n2shell-live.md` §W5.

Libgphoto2 W181 (`12ca5894`) closes one W180-wall lane: pinned v2.5.34
`pins/jl2005c.h.vuln:31-44` places `Info table[0x4000]` last at offset
`0x40` in a `0x4040`-byte struct, with `data_cache` at `0x38`, and the
forward `memmove` at `jl2005c.c.vuln:154` cannot reach it; real consumers
use table bytes as data (`library.c:197-213`, `:338-341`,
`gphoto2-file.c:315-325`) and `gp_filesystem_number`
(`gphoto2-filesys.c:1365-1400`) has no negative index. The in-struct
natural-consumer-pointer lane is CLOSED at pinned source level, while a
natural pointer in a HEAP NEIGHBOUR of `priv` was not measured and stays
UNKNOWN. `cd lab/frontier/libgphoto2shell && sh harness/check.sh` stayed
`PASS=146 FAIL=0`, trace `e364f756…c6c98` (observed here); W170-W172's
lab-assisted pointer placements and witness #2892's rung-3 scope are
unmoved, author-only rung 4 and r5 UNKNOWN.

Libsshch W1 (`a6893b10`, 02:4xZ) supersedes the row's "no real SSH build,
wire packet" clause at the 01:58Z staged scope. Full pinned ASan libssh
builds plus an authenticated 127.0.0.1 SSH replay, `sh
lab/frontier/libsshch2shell/real/run-all.sh`, scored 5 PASS / 0 FAIL here:
real KEX/password auth, channel open, a benign packet, then raw
`CHANNEL_CLOSE` followed by `CHANNEL_DATA`; ASan `READ of size 8` at
`channels.c:705:26` (120 bytes into the 128-byte channel) after the server
app frees the remotely closed channel in its data callback
(`real_wire.c:55`, not the report's `:52` citation), with
`SERVER data #2 len=21 first=M off16=-` from `MISHE-LIBSSH-UAF-WIRE`.
The fixed guard suppresses data #2 and both data-only controls are clean.
Rung 3 is now confirmed in a real build on a real loopback wire, but rung 4
stays PARTIAL under the stated application-free condition: the read is
freed channel metadata, not attacker bytes at a chosen freed offset; no
pointer/IP control, marker, command or r5. An authenticated peer is still
required, witness UNKNOWN, route 140 and window 148 unchanged; no rung cell,
grade or mind-count move.

FontForge W13 (`e2d45f1b`, author-side, grade-neutral) turns the real-build
offer into one command: with the pinned tarball supplied as `FF2S_TARBALL`,
`sh lab/frontier/fontforge2shell/replay-real.sh` rebuilds four offline trees
and asserts 17 build-path-independent rc cases (W8 `Open()` 134/0/1/0 plus
complete 0/0; W11 `Save()` 139/0/139 plain and 0/1/0/0 fixed-plain/ASan/
probe-ASan/fixed-ASan; W12 high ceiling 134/0/1/0), ending
`REPLAY_REAL_OK: 17/17 stable-lane checks passed` rc 0 here. W6/W7 consumer
rc stays informational because build-path sensitive; W12 gdb prints
`HIT glyph=-1 i=65535`, `$1 = 0x1fffe00` and `00 fe ff 01`, with
`value-ceiling-high.pcf` `9a6b2603…f6b82`. Live-tree and clean-archive
receipts both scored 17/17; the script's current sha256 `f633dd37…266a42`
supersedes W9's quoted `156dd583…acca9261` hash. Witness #3309 remains
scoped to direct-call rungs 1-4; no rung, route, window, mind-count, grade
or R5 cell moved.

OpenEXR W196 (`61468419`, clean-archive receipt `3ff078b1`) answers W195's
unmapped-pointer question at a labeled ASLR-off scope: in unmodified pinned
3.5.2 `exrcheck -c`, file-chosen bytes forge an `exr_attribute_t` in the
consumed `list->entries[0]` slot (`type=20`, `str` at `dst+1264`, size word
`0x91`, chosen `0x5a` bytes). With gdb ASLR off, `ATTR=0x555555828520`,
`STR=0x555555828590` and `FREE_RDI=STR`: the consumer's
`exr_attr_string_destroy()` reads chosen bytes and passes the chosen pointer
to the unchanged `ctxt->free_fn`. `cd lab/openexr2shell-real &&
sh harness/w196-chosen-free.sh` printed `RESULT PASS` rc 0 here with six
matching evidence hashes (free `4c6c3e13…bac5e7`, plain `19517f6f…369e6`);
a 02:54Z `git archive 61468419` replay (gitignored src/build/bin trees
symlinked) matched all six. Author replay, witness offered on tape #4048
with no verdict: mapped only with ASLR off in the debuggee, no chosen code
pointer/IP, wire, command, marker or r5; grade, rung, route, mind count and
r5 status unchanged.

The 03:0x–03:1xZ limbs supersede the Gpgme2Shell row's "no wire input" scope
and the Yojimbo2Shell row's harness-only boundary. No rung cell, grade,
route, mind count, witness verdict or R5 cell moved.

Gpgme W7 (`9633cfc8`, clean-archive replay `a1ecd700`) drives the advisory's
second affected reader through public APIs in real GPGME 2.2.0.
`realbuild/colon_reuse.c` and `fake-colongpg.py` emit exactly 1024 bytes with
no LF on the colon pipe; `read_colon_line()` consumes them to `readpos=1024`,
then its next call reallocs at `engine-gpg.c:1647`, reads EOF and returns at
`:1707` without the `:1728-1730` writeback. From
`lab/frontier/gpgme2shell/realbuild`, `sh run-colon.sh` needs no rebuild (the
`build-real.sh` binaries must exist) and printed `PASS=26 FAIL=0` rc 0 here.
The vulnerable 2.2.0 driver exits 1 with ASan `attempting double-free`:
second free in real `gpg_release engine-gpg.c:604` via
`_gpgme_engine_release → _gpgme_op_reset → gpgme_op_keylist_start
keylist.c:1295`, first free by `realloc read_colon_line :1647`, allocation at
`gpg_set_colon_line_handler :909`, and no second operation; the status
callback logs `arglen=1200 byte[1000]=0x48`. Fixed 2.2.0 and stock 2.3.1 exit
0, are sanitizer-clean, start op2 and log `byte[1000]=0x5a`; the
short-colon-line control is clean. A clean `git archive 9633cfc8` replay gave
`BUILD OK`, 26 PASS / 0 FAIL for `run-colon.sh` and 19 PASS / 0 FAIL for the
pinned `sh ../run.sh`, author-side only with no witness verdict. The raw
`evidence/colon-*.out` / `.rc` files are gitignored and regenerate with that
script; `reports/gpgme2shell-status.md` §W7.

Yojimbo W1 (`28d3c8c5`) and W1b (`ff6c5e02`, staging plan marked complete in
`30f77300`) close the staged row's "no real build, live UDP wire" boundary.
The real pinned parent `3c6b5e85…` was built under ASan with the fix commit's
`test.cpp`, bundled sodium (no system dev package) and
`cmake -S . -B build-asan-vuln -G Ninja -DCMAKE_BUILD_TYPE=Debug` with
`-fsanitize=address -fno-omit-frame-pointer -g` on C/CXX and the linker.
The regression reaches the pinned sink at
`source/yojimbo_reliable_ordered_channel.cpp:716` through
`ProcessPacketData :441 ← Connection::ProcessPacket
source/yojimbo_connection.cpp:340`: ASan `WRITE of size 500`, 0 bytes after
an 1100-byte region allocated at `yojimbo_reliable_ordered_channel.h:321`;
the fixed-channel control is clean. Authenticated netcode UDP loopback uses
client `0.0.0.0:30000`, server `127.0.0.1:40000`, `InsecureConnect` with an
all-zero local key, client `maxBlockSize=1100`/`blockFragmentSize=500`,
server `maxBlockSize=1500`, and a 1500-byte block whose full 500-byte final
fragment at offset 1000 carries `MISHE-LOOP` at block offset 1200. Without
gdb the vulnerable process faults in `Connection::Reset()
yojimbo_connection.cpp:172` (rc 1) with no ASan heap report — the receive
buffers come from the per-client TLSF pool — while the fixed control passes.
Under gdb a breakpoint at the pinned sink conditioned on
`fragmentId==2 && fragmentBytes==500` reads `MISHE-LOOP` byte-exact at
`blockData+1200`, 100 bytes past the 1100-byte buffer with 0xab filler at
+1100, after netcode decrypt; the frame chain includes
`Client::ProcessPacketFunction yojimbo_client.cpp:274`. The five named log
hashes were recomputed locally and matched §W1/W1b of
`reports/frontier-yojimbo2shell.md` (`6457e8d0…`, `1fe5adcf…`,
`27c4d806…`, `57cecbb0…`, `1ec75858…`). Rung 3 is CONFIRMED in the real
build and rung 4 DEMONSTRATED only at the named non-default-config,
post-auth, one-process, gdb-assisted scope — hence the unchanged `◐` cell.
No separate remote process, chosen command or r5; W2 below supersedes the
pointer/marker bound. Production use of a non-multiple block config and an independent
witness verdict stay UNKNOWN. The raw logs and `upstream/` tree are gitignored
and regenerate from the pinned clone and commands above; a staged-harness
smoke here scored 20 PASS / 0 FAIL with 7/7 pins.

Socat2Shell is ADMITTED at 03:3xZ under standing #6 as the 141st route
(staged by `4f3b7916`/W221; real-build correction `d7ea43d1`): CVE-2026-56123
(Socat security advisory 10, CWE-122, CVSS4 9.2 `AV:N/AC:H`), affected
1.8.0.0–1.8.1.1, fixed in 1.8.1.2 by making `dstdata[]` unsigned in
`xio-socks5.h`; source URLs, tarball and patch pins are in
`lab/frontier/socat2shell/PROVENANCE.md` and `src/pins.sha256`. A signed
`char` length byte 0xfb promotes to -5, so `bytes_to_read=2` while
`bytes_read=5`, and the negative count reaches real `readfull()` as SIZE_MAX.
The pinned-function harness prints `TOTAL pass=15 fail=0` from
`sh harness/run-all.sh`, but its ASan `WRITE of size 600` past a 262-byte
reply is a `memcpy` stand-in, not the shipped consumer. A real-build loopback
replay (`sh real/run-real.sh`, 9 PASS / 0 FAIL) builds unmodified socat
1.8.1.1 and 1.8.1.2 under clang ASan with `--disable-openssl`; a
127.0.0.1-only SOCKS5 server sends `05 00 00 03 fd` plus 600 chosen bytes.
The vulnerable build logs `W read(7, 0x512000000045, -1): Bad address`, exits
255 with **no ASan report**, while fixed and safe replies exit 0; real
`readfull()` (`sysutils.c:101-141`) passes SIZE_MAX to `read(2)`, which
returns EFAULT before storing any byte. Grade: rungs 1/2 only (deterministic
connection abort on a real build); rung 3 memory corruption and rung 4
chosen bytes are NOT established on the real consumer, rung 5 not attempted,
witness UNKNOWN. No pointer/IP, marker, command or r5. Route, both resolver
keys and the three wake units are minted (EXACT full-flag sync `written 3,
removed 0`), doctor GREEN; the existing handoff window 149 was adopted with
no duplicate. `reports/frontier-socat2shell.md`,
`reports/socat2shell-status.md`.

Ccextractor2Shell is ADMITTED at 04:4xZ under standing #6 as the 142nd route,
from the staged CCExtractor issue #2500 (opened 2026-11-24T13:58:29Z, still
open at 2026-11-25T04:07Z; no CVE/GHSA, no upstream fix PR, fix status
UNKNOWN). The pinned master `2c1c1c6f0602563d2064f2b0c36f13b3c7a09489`
derives a 24-bit `mpeg_pic_size` of 0x201000 (2101248) from four control bytes
and passes it to the verbatim `parse_mpeg_packet()` without a capacity check;
`buffered_read` is a stand-in `memcpy` and the structs/layout are stand-ins.
gcc ASan and clang ASan with `-fno-builtin-memcpy` report `WRITE of size
2101248` 0 bytes past a 2097272-byte region; clang ASan with default builtins
is a preserved negative. The plain slack build reads back the chosen repeating
`"MISHE-CCEX"` pattern at `BUFSIZE`, and a locally written bounds guard plus
the safe length are clean. Grade: rung 3 at the pinned-function scope, rung 4
PARTIAL in the stand-in layout, no real executable, GXF file or wire, no
pointer/IP/command and no r5; witness UNKNOWN. Hy4-flash route, both resolver
keys and three wake units minted (EXACT full-flag sync `written 3, removed 0`,
doctor GREEN, path enabled/active); window 150 adopted without a duplicate.

AwsLc W214 (`c8026e5a`, source-bound, author-side) narrows the row's
"out-of-tree application as the only real-consumer path" boundary: a read-only
census of out-of-tree application sources already provisioned in this plant
found no caller with two or more padded `EVP_DecryptUpdate` calls into a
documented-minimum buffer, so there is no adjacent attacker-relevant datum to
place. Ten named projects (cjose, GPGME, Open5GS, libssh/libssh2,
libwebsockets, Synchronet, PostgreSQL/pgactive, nginx, mod_auth_openidc,
apr-util) plus roughly fifty other provisioned roots were swept; four
representative hits were re-read — apr-util's `inlen + EVP_MAX_BLOCK_LENGTH`
(17 bytes slack) with one update, cjose's single CBC update on a fresh ctx
(its two-update path is GCM AAD with `out=NULL`), libwebsockets' disabled
padding and one cipher call, picotls' padding disabled on decrypt. No build,
ASan run, new artifact or witness replay; unprovisioned third-party
applications stay UNKNOWN, grade unchanged (rungs 1-4, r5 UNKNOWN).
`reports/awslc2shell-status.md` §W214.

The 03:3x–03:5xZ limbs strengthen the Yojimbo W1b scope with W2 and add four
source-bounded or build-bounded negatives. No rung cell, grade cell, route,
mind count, witness verdict or R5 cell moved by any of them.

Yojimbo W2 (`f25517f8`) carries the W1b wire path one step further: gdb shows
the 1100-byte receive block 605024 bytes into a 10 MiB TLSF arena, with the
adjacent channel vptr at `blockData+1152` overwritten by 0xAB filler (the W1
`Connection::Reset()` fault instruction reads `vptr+0x10`). The encrypted final
fragment instead writes a chosen 8-byte fake-vtable address there, and the
vulnerable non-PIE ASan binary prints `MISHE-VTABLE-CALL` twice before a later
`tlsf.c:583` crash; the fixed-channel control is clean. The five quoted W2 log
hashes (`fbc6c526…56a77d`, `5664351a…c0ec5`, `49fea203…42de89`,
`466f3181…45a`, `a9a03eed…d27e`) were recomputed locally and matched the
report. Conditions remain narrow: post-auth, one process, non-default config,
non-PIE lab build and pre-placed marker function. That is pointer control plus
a benign lab marker, not remote command execution and no ASLR-realistic
pointer derivation. `reports/frontier-yojimbo2shell.md` §W2.

Hping W8 (`bea93e82`, clean-archive receipt from `90d635d6`) rebuilds the same
pinned source with GCC 13.3.0 at `-O2`; Ubuntu's default `_FORTIFY_SOURCE 3`
compiles the copy to `__memcpy_chk` with the real 40-byte bound. Three crafted
loopback ICMP RR replies try to set `j`/`i`/`rc4_seedflag` and 155 sbox bytes,
but the vulnerable build ends in `*** buffer overflow detected ***` with no
crafted state at the `hp_rand` breakpoint (3 PASS / 0 FAIL); no-injection
baseline and locally patched `-O2` controls each score 4 PASS / 0 FAIL. The
clean replay `STAGE OK baseline 4 / attack 3 / fixed 4` and `REPLAY_O2_OK:
11 checks` came from `wire/replay-o2.sh`; an earlier runner-tag collision was
fixed before that run. This narrows the stock-glibc UNKNOWN to this host's
`-O2` build only; distribution packages and other fortify settings stay
UNKNOWN, author-side and unwitnessed. `reports/hping3shell-status.md` §W8.

Socat W2 (`1a34d2de`) closes the consumer question. The pinned real tree's
`sycls.c:539-558` `Read()` is an unconditional `read(2)` under every configure
option, and `xio-socks5.c:419-427,467-470` yields counts of `-1..-5` (as
`SIZE_MAX..SIZE_MAX-4`) for length bytes `0xf9..0xff`, with `0xf8` ending the
loop after the first 5-byte read. `sh real/run-count-probe.sh` scored 8 PASS /
0 FAIL on loopback socketpairs: those huge counts return `errno=14` EFAULT
with zero canary stores, while a `0x80000000` control does store. 32-bit
`size_t` is UNKNOWN (no multilib here). The advisory is a remote
connection-abort bug on this host, rung 1/2 only; a claim of a write must show
it through real `readfull()` under ASan with fixed/safe controls.
`reports/frontier-socat2shell.md` §W2.

AwsLc W215 (`93b61d8d`, source-bound, author-side) provisions pinned s2n-tls
v1.5.16 (tarball `ab3e19f8…909214`, recomputed locally) and reads every
non-test decrypt site. Each CBC-capable path re-inits then makes exactly one
`EVP_DecryptUpdate` into an in-place, block-aligned blob; stream ciphers have
`b=1` and AEAD uses `EVP_AEAD_CTX_open`; pinned `cipher.c:190` clears
`final_used` on every init, so no withheld-block carry crosses records, and no
buffer is sized `in_len+b-1`. SOURCE-BOUND NEGATIVE for the advisory's
precondition; no build, ASan run or witness replay, grade unchanged.
`reports/awslc2shell-status.md` §W215.

Synchronet W18 (`b60fd1b4`/`b67db0dc`) checks four raw files from tag
`sbbs321e` (`d2a6dcb2`): same no-size getter plus NUL clamp and byte-identical
field block, `VERSION "3.21"/REVISION 'e'`, `TELNET_TERM_MAXLEN 40`;
`sh release-label/run-release321e.sh` scored 11 PASS / 0 FAIL live and from a
clean `git archive b60fd1b4`, normalized `bb9067cf…2a5a3fbda9` (recovered from
`REPLAY.md`). Source-level only, no build, wire session or runtime bytes, no
rung change and no claim about 3.20b or other releases.

Pgactive W9 (`6fb104bb`) measures catalog-origin preconditions on a loopback
PostgreSQL 16.15 cluster with the full pinned 2.1.9 library:
`pg_replication_origin_create()` accepts 66/67/99/275-byte names, but the
`pgactive_get_global_locks_info()` route stayed in state `b` with a
not-configured error (UNKNOWN, not demonstrated); slot names truncate 96→63
bytes and a plain `LOGIN` role has neither origin-create nor parser EXECUTE.
No wire trigger, no grade change.
`reports/frontier-pgactive2shell.md` §catalog-derived origin-name reachability.

The 01:1x–01:4xZ limbs supersede the row sentences that say Synchronet has
"no measured DoS", N2n2Shell has "no control of a consumed pointer" without
the W3 forwarding consumer, FontForge's overwritten word is a live `char*`
never dereferenced, CodebaseMemory's canary argument holds at any stride, and
OpenEXR's W192 pointer placement explains the observed fault. All remain
author-only and unwitnessed; no rung cell, grade, route, mind count or R5
cell moved.

OpenEXR W193 put three distinct file-chosen words into live `exr_attribute_t*`
slot `E[2]` of unmodified `exrcheck -c` (plain rc 139), but W194
(`dff3426d`/`1d68f9d8`/`b6e68db8`) disproved attribution: with ASLR explicitly
on (`set disable-randomization off`) the first `exr_attr_list_destroy`
dereference at `attributes.c:305` reads `E[0]=0x555555828210`, a stale
absolute address captured in W192's forged source dump; changing the chosen
`E[2]` never changes the faulting address. W194 also corrects W193's "ASLR
left enabled" wording — gdb's `disable-randomization` defaults to on — and an
ASLR-off `setarch -R` control exits rc 1 printing `bad` for all three PoCs
with no SIGSEGV. Clean-archive receipt at `1d68f9d8`; evidence hashes in
`reports/openexr2shell-file-level.md` §W194. Still no chosen code pointer/IP,
wire, command or r5.

OpenEXR W195 (`reports/openexr2shell-file-level.md` §W195) finds the slot the
consumer actually dereferences: with ASLR on in the debuggee the loop at
`attributes.c:305` reads `list->entries[0]` at `outPtr+4176` (not W193/W194's
guessed `list+16`), and eight file-chosen bytes `0x4141414141414141` placed
there are the faulting register (`FAULT_R13=0x4141414141414141` at
`mov 0x14(%r13),%eax`). `cd lab/openexr2shell-real && sh
harness/w195-chosen-deref.sh` printed `RESULT PASS` rc 0, with three raw
probes and two byte-identical replays; plain rc 139, valid rc 0 `OK`, fixed
3.5.3 rc 1 `bad`, and a 02:21Z clean-archive receipt from `git archive HEAD
lab/openexr2shell-real` matched all five evidence hashes. Author replay, not
a witness verdict: the chosen value is unmapped, no chosen data read, IP,
command, wire or r5 follows; the row's rung 4 stays PARTIAL.


FontForge W11 (`f3b9dd98`) corrects W10's object label: the word at `encs-200`
is `BDFChar.bitmap` (`chunkalloc` = `calloc(104)`, `bitmap` at +24), not a
live `char*` — `x/s` had printed `""` from a one-byte zero bitmap. Adding
`Save()` to the poisoned `Import()` makes the real plain process dereference
the file-chosen pointer through `bSave:1891 → SFDWriteBakExtended → SFDDump
→ SFDDumpBitmapFont → SFDDumpBitmapChar` (`sfd.c:1671`): rc 139 at
`0x0000555500414243` with three chosen bytes, and rc 139 at
`0x000055550100FEFF` on W10's claimed-ceiling input. The reachable window
`0x0000555500000000..0x0000555501FFFE00` is below the lowest PIE mapping,
so there is no chosen mapped target, full pointer/IP, marker, command or r5;
a second `Import()` without `Save()` still exits 0 and patched/in-bounds
controls stay clean. `lab/frontier/fontforge2shell/DEREF.md`.

FontForge W12 (`CEILING-CORRECTION.md`, author-side, no grade change) corrects
W10's "hard ceiling" overclaim: with `d=max2-min2+1=1` and the truncated glyph
at `i=65535`, the real plain build writes `0x01FFFE00` at `encs-4` (bytes
`00 fe ff 01`, watchpoint word `0x01fffe0000000021`, plain rc 134, patched
0, ASan 1 at `:1751`). The true maximum is `0x01FFFE00`, not `0x0100FEFF`,
but W16 later reaches byte 3 `0xff`, still unmapped; no r5.

CodebaseMemory W14 (`8e973719`) measures far strides against the live
`[stack]` mapping: the OOB destination advances 512 bytes per projection
item, and main's estimated saved RIP (`callee_rbp+0x4198` = `SP+0x40a0`,
16,544 bytes) lay above the mapping end in 16 live-ASLR placements (smallest
`STACK_TOP-SP=0x1108`, 4,360 bytes), while twelve 71-item/478-byte attempts
exited 139 in `memcpy`. W12's `col_names` fault at N=1135 remains a separate
blocker for huge counts, not the nearest bound, and W14 retracts W12's
absolute claim that a C string cannot carry pointer-zero bytes. Chosen bytes
reach caller-frame storage, with no live pointer use, IP, command or r5.

Synchronet W16 (`be7d19a2`, clean replay `f369f7b3`) closes the missing DoS
measurement under the pinned default config with a valid password:
`run-validuser-availability.sh` sets `line_delay=0x4853494d` (~14-day
nanosleep) on four real `sbbs3` nodes with chosen 64-byte TERMs, parks four
`sbbs/termNode` threads in `hrtimer_nanosleep` and the fifth login is refused
`!No nodes available for login.`; the upstream fixed form serves five
sessions. Both forms score 10 PASS / 0 FAIL with zero `SSH_ANYAUTH` lines;
the two pre-repair failures (a misplaced assertion and a TIME_WAIT bind race)
are preserved as tooling defects. Author replay from `git archive be7d19a2`,
witness verdict still confined to wake 189's synthetic-struct scope; no
pointer/IP, command, grade change or r5. `REPLAY-W16.md`.

N2n W3 (`7e939185`, `d8bec71b`) adds a real consumer: with a registered
loopback peer the forwarding encoder reads the overwritten token bytes as
DATA in `memcpy(len=96, src=nak+14)` ← `encode_buf` (`wire.c:162`) ←
`encode_REGISTER_SUPER_NAK` (`wire.c:631`) and re-emits a 134-byte NAK, while
the 48-byte safe control emits 86 bytes. The one-line decode bound stops the
WRITE but leaves a fixed-build ASan `READ of size 96` on the peer path (the
earlier clean fixed control had no peer). A 2048-byte `recvfrom` caps the
write at `nak+2024`, 1,488/1,552 bytes short of the canary at `nak+3512` and
saved RIP at `nak+3576`; `token_size=2000` left the canary intact and a 3550-
byte datagram caused no abort. W4 (`f18dd8bf`, `e9351342`) gives a one-command
clean-room replay, `sh lab/frontier/n2n2shell/live/replay-live.sh`, observed
22 PASS / 0 FAIL here after W3 was folded in, including four live gdb chosen-word
checks and checks 20-22 for the peer's 86-byte safe and 134-byte attack NAKs.
No consumed pointer, control-flow
takeover, marker, command or r5; witness replay #3909 remains owed.
`reports/n2n2shell-live.md` §§W3/W4.

N2n W6 (`ac451b00`) checks the fixed build's surviving encoder read on a plain
gcc `-O1` supernode: the rejected NAK decode leaves `token_size=96` on the wire,
but the 96 bytes read from `nak+14` are ZERO (`first=0000000000000000`,
`beyond48=0000000000000000`), so this path discloses no stack data. The fixed
ASan build still aborts on that read with a peer (W3), and other builds or
preceding traffic remain UNKNOWN. The one-line control matches the vendor NAK
guard byte-for-byte but is not a full fixed-tree build. No rung or grade move.
`reports/n2n2shell-live.md` §W6.

The 19:0xZ cicap2shell W3 limb supplies the real-server evidence summarized
in the row. `lab/frontier/cicap2shell/realbuild/live/run.sh` starts the real
pinned 0.6.5 ASan `c-icap` server on 127.0.0.1 with its echo service and
sends one crafted request: six-entity REQMOD reaches the server's own
`parse_header request.c:529` -> `process_encapsulated request_common.c:507`
and ends in the `header.c:631` UAF at teardown; the six-entity OPTIONS
variant with `Connection: close` returns 200 OK before the same UAF on
shutdown. Stock `MaxRequestsReallocateMem 100` and an immediate-teardown 0
setting both reproduce it. Four-entity, one-entity valid and patch-derived
fixed controls are clean; an OPTIONS request without `Connection: close`
shuts down cleanly because keepalive resets the aliased slot. Loopback only,
no proxy or real client, no pointer/IP/command control, no allocator
metadata and no r5; W3/W4 were author-measured and are witness-ESTABLISHED
as labeled by W211 (#3953). Evidence and
commands: `realbuild/live/README.md`, `reports/frontier-cicap2shell.md` §W3/W4.

Scope corrections to earlier rows, measured against the cited reports:
CodebaseMemory2Shell's "no HTTP transport" boundary is W1's stdio-only lane;
W9 reaches the same sink through the pinned server's 127.0.0.1-only HTTP
`/rpc` transport and W11 clean-archive replayed all three rows (4/4 pins),
still with no remote/off-host request, witness verdict or r5. FontForge's
single-import consumer claim is W5's scope: W6 found gettext's `malloc(128)`
and W7 `props = malloc(96)` returning the poisoned chunk on later imports,
and W8 reached the same pinned `fvimportbdf.c:1751` write through real
`Open()`; all author-side and outside witness #3309's direct-call verdict.
Imgproxy's W11b route stayed untested rather than negative: W12 gated a
second GET on the live poisoned head (eight of 98 loopback runs fired the
gate; four aborted in `malloc(): unaligned tcache chunk detected`, four
served HTTP 200 with 379 natural `malloc(0x20)` calls, all `WIRE=0`), and W13
found zero code pointers in three post-write windows across 64 executable
mappings — a bounded layout negative, not r5. Vrpn's "no wire-chosen byte
survives in a live caller" means a live control-flow slot: W29/W30 mapped
sender -2 onto `d_udpInbuf` and sender -3 storing `remote_id`/`local_id` onto
live `d_tcpInbuf`, so a second TCP message drops the connection; no chosen
destination address, command or r5, and sender -3 must not be reswept on
those binaries. OpenEXR's OpenImageIO consumer is a W173 static-source
negative (flat `read_image()` on the deep PoC cannot reach the sink; a truly
flat EXR cannot trigger it) and W169 confirmed the aarch64 claim under
qemu-aarch64-static 8.2.2 at the same file-level scope (`PASS=10`, no native
host or r5). W190 supersedes W188's harness-grooming bound: N=1072 makes the
second inverse-sort copy reach a live 0x90 tcache head in UNMODIFIED pinned
`exrcheck -c`, and file fill bytes (`0x5a`, `0x3c`, `0x00`) replace its
safe-linked `next` word; no malloc from that tcache was observed, the consumer
aborts in `double free or corruption (!prev)`, fixed 3.5.3 rejects, and the
clean-archive replay (`ecf3f821`) is author-only. Still no code pointer/IP,
command, marker, wire, witness verdict or r5. Libheif's 36,879-byte allocation
was reproduced by W181 from a
different crafted file (`check_advisory_size.py`, 11 PASS); the advisory's
exact 1,155-byte input and x265-pointer claim remain untested. LibRaw W15
adds a third independently file-chosen 16-bit value (`0x2468`, raw rows
150..159) in a disjoint OOB heap band alongside W13/W14's values; still not
an arbitrary byte sequence, with no pointer/IP, command, adjacent live object
or r5, author-side and unwitnessed. Reports:
`reports/codebasememory2shell-status.md`, `reports/frontier-fontforge2shell.md`,
`reports/frontier-imgproxy2shell.md`, `reports/vrpn2shell.md`,
`reports/openexr2shell-status.md` §W190, `reports/openexr2shell-file-level.md`,
`reports/libheif2shell-status.md`, `reports/frontier-libraw2shell.md` §W15.

Later scope corrections from the post-`d40ddefd` edges (all author-only and
unwitnessed unless a verdict is named; no rung cell moves): Assimp W22 puts a
file-chosen object pointer and fake `aiMesh` in the live scene, and W24 makes a
document-chosen saved return address call a benign marker in a plain lab build
(`TAUF_MARKER_CALLED`); no shell command, remote path or r5. Gpgme W2 reaches
the double free through a real `/usr/bin/gpg` (36 PASS), W3 through
attacker-chosen loopback HTTP key bytes on 127.0.0.1:11372 (32 PASS,
wire-visible rung 4), W4 through a second keylist (24 PASS); no pointer/IP/
command or r5. CodebaseMemory W12 narrows the C-string canary negative to
populated writes: an empty item-38 property skips the `memcpy`, later strides
pass the saved RIP into caller-frame storage with RC=0, and the ancestor RIP
stays unreachable because `col_names` caps at 32. Imgproxy W14 corrects W13's
classifier (two code-shaped qwords were pre-existing outside the written span);
`replay-w13.sh` returns `REPLAY_W13_OK` 3/3 with `code_ptr_qwords=0`. Libgphoto2
W177 reads the frame canary and saved rbp/RIP through real
`gp_camera_file_get(GP_FILE_TYPE_RAW)` at `library.c:213` without device
readback, and W178's short-reply vusb patch has a clean 146 PASS / 0 FAIL
replay. OpenEXR's stale "resume cmake --build … when host load permits" and
"aarch64 remains untested" clauses are superseded by W173's static-source
negative and W169's qemu-aarch64 `PASS=10`; W191 explains W190's abort (COPY1
zeroes the next-chunk header before COPY2) and W192 (`N=768`, `U=4N`) places
file bytes in a live tcache `next` with COPY1 in bounds but no malloc
consuming it. Cicap W6 finds a plain-real-library teardown negative with no
wire bytes, and W7/W8's `replay-all.sh` covers W1/W2/W3/W4/W6 with 72 PASS /
0 FAIL from a clean archive including self-fetch. Jq's second-advisory lane
is a named 32-bit negative: no i386 multilib, so `-m32` cannot link even a
trivial program; no build, guard or grade change. Reports:
`reports/frontier-assimp2shell.md`, `reports/gpgme2shell-status.md`,
`reports/codebasememory2shell-status.md`,
`reports/frontier-imgproxy2shell.md`,
`reports/frontier-libgphoto2shell.md`,
`reports/openexr2shell-file-level.md`, `reports/cicap2shell-status.md`,
`reports/jq2shell-status.md`.

Newer post-`7f1d85db` limbs (author-side, unwitnessed unless a verdict is
named; no rung cell moves): FontForge W9's `replay-real.sh` repeats the W8
`Open()` matrix RC 134/1/0/0 with the same ASan `WRITE of size 4` and chosen
`4d 49 53 00`, but W6/W7 consumer exit codes are build-path sensitive (clean
`/tmp/lab/...` trees exit 134/139 where the live build exits 0), so those
consumer claims stay scoped to `CONSUME.md`/`FILECHOICE.md`. Hping W5's
`rng-proof.sh` measured changed RNG destinations (baseline 4 PASS / 0 FAIL,
attack 6 PASS / 0 FAIL); W6 (`650f9517`..`bf1360dd`) fills all 187 reply-
reachable `rc4_sbox` bytes with a chosen constant and steers the low byte of
later `--rand-dest` probe destinations with no debugger steering — 15/16 and
17/17 in the final clean replay, but probabilistic (hidden `i`/`j`, 69
unreachable sbox bytes), with baseline and patched controls 4 PASS / 0 FAIL
each and `replay-rngctl.sh` 20 checks rc 0 from `659f6eb0`. No full IP, pointer,
command or r5 follows.
LibRaw W16 adds `replay-all.sh` for W13/W14/W15 (`PASS=31 FAIL=0`, also from a
clean `git archive 81392c3c`), and W17 sends the W15 DNG over loopback TCP into
a live in-process LibRaw ASan consumer with `WIRE_OOB_OK` in three fresh runs,
clean no-option and fixed decoders, no marker, pointer or rung 5; the row's
"network" boundary means no real camera/network appliance path. PHP's wake-59
tfm chain takes the same 126714 promoted session into tinyfilemanager 2.6, its
DESIGNED admin upload and live-worker execution of `/evil.php` (unique marker
and `id`) on 8.4.27-app, with fixed/no-kill/virgin-sid controls clean; every
stock attacker-caused death mechanism was measured NEGATIVE (SIGTERM handled
mid-pwrite, cgroup OOM only on truncate-first writes, page-quantized partials,
io.max/PHP fatals ineffective). The shim remains the only splice-producing
death; author-only, unwitnessed, R5 cell stays `—`. Reports:
`reports/frontier-fontforge2shell.md` §W9/W10, `reports/frontier-hping3shell.md`
§W5/W6, `reports/frontier-libraw2shell.md` §W16/W17,
`reports/php2shell-status.md` §Wake 59,
`lab/repro/php2shell-aftershell-splice-tfm.sh`.

The 00:4x–01:0xZ author limbs add no grade or verdict. FontForge W10
(`8781a538`) measured the `i=0` four-byte write value `0x0100FEFF` (W12 later
raised the true maximum to `0x01FFFE00`) and put three chosen bytes in a
pointer field at `encs-200` that W11 identified as `BDFChar.bitmap`, not a
`char*`; on that one `Import()` path it is not dereferenced. Synchronet W15
(`e0f11cd4`, replay `b595e239`) builds
a real `sbbs3` locally and reaches the copy after a valid password login under
the default config (4 PASS / 0 FAIL, `PROBE_COUNT=2`, `ANYAUTH_LOG_COUNT=0`);
pre-auth pty-req stays W9's negative. Assimp W25 (`aa2aedc7`, replay
`fda2b66c`) keeps the default-build canary at `dest+4` and the no-protector
saved-RIP high half `0x7fff` as preserved negatives (8 PASS / 0 FAIL, trace
sha256 `5532748382…e5d6fa5f864`, byte-identical from a clean archive). All
three are author-side and unwitnessed; reports:
`reports/frontier-fontforge2shell.md` §W10,
`reports/frontier-synchronet2shell.md` §W15,
`reports/frontier-assimp2shell.md` §W25.

The 15:5x–17:3xZ libraw W11/W12 limbs refine the row's ceiling without moving
a rung cell. W11 (`9bc81c2b`) sets DNG LinearizationTable plus WhiteLevel 65535
to put a file-chosen arbitrary 16-bit value in one halfword at index 68,644
(`0xbeef`, `0x1337`, `0x00a5` each exact 3/3, edges `0x0001`/`0xffff` once);
W12 (`32c3e2ac`) shows BlackLevel is only a coupled global fine shift of the
remaining interpolation-determined halfwords, not a second independent knob
(coupled shift `ffff beed fe91` at BL=6 vs `ffff beef fe93` at BL=0). Both are
author-side and unwitnessed: no arbitrary byte sequence, pointer/IP, command
or r5. Recipes and expected bytes are in `docs/reproducibility.md`.

The 10:4xZ witness verdicts supersede the "unwitnessed" wording in the last
two rows without moving a rung cell. Witness W193 (#3530) replayed awslc2shell
from a clean `git archive 0714868` with its own three builds and 14 PASS /
0 FAIL: rungs 1-3 ESTABLISHED in the real pinned AWS-LC library, rung 4 PARTIAL
for one compile-time chosen byte, NO r5, no wire, no pointer/IP/command. The
new synthetic-consumer pointer-redirect claim (`07fb523`, chat #3535) is
author-only and its replay was requested at #3538. Witness W194 (#3534)
replayed thorvg2shell from a clean `git archive 24d449a` with six builds it
configured itself: all three parts — public API / plain `.jpg` / loopback wire,
the no-pointer crash-mechanism negative, and the embedded Lottie-JPEG asset —
ESTABLISHED AS LABELED, with vulnerable/fixed/safe controls and NO r5. No
contradiction to either row grade.

The 11:1xZ witness W195 verdict (#3550/#3551) closes the earlier awslc gap:
from a clean `git archive 07fb523` the witness rebuilt both pinned AWS-LC
libraries itself, compiled the synthetic consumer against its own libs and
replayed `run-consumer.sh` 11 PASS / 0 FAIL. A byte dump and exhaustive
256-byte sweep confirmed the wire-borne `0x48` steers the dispatch-pointer
LSB into the benign marker only on the vulnerable library.
**ESTABLISHED AS LABELED** — rung-4 pointer-LSB control in a synthetic
loopback consumer, NO r5, no real app, no command. Scope NITs: hand-aligned
256-slot table with only slots 0/9 populated; the no-ASan PASS is specific to
`0x48`. This supersedes the "unwitnessed" wording in the AwsLc2Shell row and
the "author-only / replay requested" sentence above; no rung cell changes.

The 08:4x–12:0xZ libgphoto2 W170/W171 limbs supersede that row's "pointer
control" ceiling at the author-only scope. W170 (`fcbde70`) placed a live
`CameraFile` at `priv+0x4050` in the plain real 2.5.34 build by draining 24
same-size tcache entries; the `:154` overflow reaches its
`accesstype/size/data` fields, and with a lab-supplied canary and saved RIP
the real `gp_file_get_data_and_size()` returned device-chosen
`data=0x1122334455667788 size=0x1a2b3c4d` — a chosen pointer at a real API,
never dereferenced. W171 (`930ddef`) additionally restored `camera_init`'s
frame so `jl2005c_init()` returns normally (rc=0); with drain 22 the real API
returned a device-chosen pointer and length 0x1d, and dereferencing them read
the chosen `M2SHELL_DEREF_MARKER_20261124`. Safe fill, count 100, wrong
canary, fixed camlib and omitted-restore controls are recorded. In W171
`gp_file_save()` aborted on corrupted top size, so that dereference was the
probe's; W172 (`833729ad`) keeps four live guard chunks after the victim from
the lab vusb bulk-read hook, so the 464-byte `:154` overflow stops inside the
guards. The real `gp_file_save()` then returns `rc=0` and writes a 29-byte
host file containing the device-chosen `M2SHELL_DEREF_MARKER_20261124`; the
matched `M2SHELL_VUSB_GUARDS=0` control returns the same pointer but aborts
at corrupted top size and leaves a 0-byte file. Count 100, zeroed
`DATA`/`SIZE`, fixed camlib and fix reversal are recorded. W172 extends rung 4
to a real consumer write with an observed file side effect, still lab-assisted
(probe-supplied pointer, gdb-read canary and registers, lab heap placement,
synthetic replies), unwitnessed, with no USB/wire/command path, NO r5 and no
row grade change; witness #2892 stays
scoped to rung 3. Evidence: `reports/frontier-libgphoto2shell.md`,
`reports/libgphoto2shell-status.md`,
`lab/frontier/libgphoto2shell/evidence/real-plain-heap-pointer-control.out`
and `real-plain-normal-return-deref.out`.


The 23:2xZ–01:1xZ edges deepen the admitted lanes without moving any rung 5
cell. The following row sentences are superseded by this paragraph and the
sections named below; all remain author-only unless a verdict is quoted.
Ndpi2Shell's row still says "no witness verdict": witnesses #2999/#3001
replayed `realbuild/run.sh` 9/9 twice from a clean `git archive 44be53e` with
both ASan libraries rebuilt from source and graded **ESTABLISHED rungs 1-4 at
the real-pinned-library / in-tree-caller ASan scope, NOT rung 5**; the chosen
`0x2f` byte lands at `ndpi_serializer.c:107` via
`ndpi_serialize_start_of_block_binary:2340`, no in-tree wire path supplies a
>128-byte key (`reports/frontier-ndpi2shell.md` §7).
Sdlmixer2Shell W181 puts the crafted bytes on a loopback 127.0.0.1:19442 wire,
W182 reaches `FetchXLaw` with an unmodified upstream stereo A-law WAV
(`M1F1-Alaw-AFsp.wav`, sha256 `cfbc1821…`), W183 drives the unmodified upstream
`testmixer` CLI (`PASS=6 FAIL=0`), and W184 measures a partial saved-RIP
overwrite that is not a mapped target — the LUT words cannot steer RIP.
Witness #3000 covers W179's real-caller scope only; W180/W183 replay ask #3053
has no verdict. Libvips W14 sends crafted TIFF request bytes to a loopback
consumer (13/13 PASS, fixed build rejects `image: dimension overflow`) and W15
records the downstream claim that imgproxy 4.0.0–4.0.5 bundled libvips 8.18.2
while >=4.0.6 bundled >=8.18.3; W1/W2 built pinned imgproxy binaries and served
crafted ICO/TIFF bytes over loopback HTTP. W2's fine.tif timeout is WITHDRAWN as
queue starvation: an isolated one-request GET returns 422 "Source image
resolution is too big" at imgproxy's 50M-pixel guard in vulnerable 4.0.0 versus
500 `image: dimension overflow` in the fixed tree, before libvips header load.
Witness W185 (#3318) ESTABLISHED the ICO rungs 1-4 on clean replay and the HTTP
probes only at header/processing-entry scope, NO r5: no paint frame, chosen
byte, pointer or command in the endpoint.
Libfontenc W181's two-mapping identity ramp records 195840 OOB 16-bit stores
at `encparse.c:492`, and W183 overwrites mapping2's live `sm->map` through
seven mappings with chosen words; `FontEncRecode(254, mapping2)` returns
`0x5558` (`sh realpath/evidence/ptrctrl/run.sh`). W186 (`9246463`) replaces
the live `FontMapRec.recode` function pointer with a chosen non-PIE address
(`from=0xfe34..0xfe37`, indices 65584..65587, `m3->recode=0x4011d6`):
`FontEncRecode` prints `BENIGN_MARKER_EXECUTED` and returns `0xabcd1234` in
three vulnerable crafted runs, while safe and fixed `5920c6e` inputs show no
marker. That is chosen-address control flow at the real-library public API in
an ASLR-off harness, not a command; layout-independent redirection is blocked
because ASLR randomizes heap bits 12-15 while `setCode()` writes full 16-bit
words from a static file. OpenEXR W169 passed 10/10 under
qemu-aarch64; W170 read the source bytes, W171 mapped 19/20 clobbered heap
headers, W172 checked tiled geometry and earlier-chunk grooming as negatives,
and W173 resolved the OIIO claim as a **static-source negative** (flat EXR
geometry and OIIO dispatch block the sink). The Openexr2Shell row's "resume
the OIIO build" instruction is stale: no consumer was linked or run and the
claim is no longer merely UNTESTED. Libheif W179 exercised a benign marker,
W180 classified the advisory-size path under ASan, W181 reproduced the
36,879-byte allocation (`check_advisory_size.py` PASS=11), W182 measured plain
fault modes (PASS=30) and W183 decoded a genuine 512x72 first frame
(PASS=45); the row's earlier one-uniform-value ceiling is superseded only at
the labeled uncompressed-codec build. Cjose's W184 negative was independently
ESTABLISHED by witness DM #3079 (a deployed mod_auth_openidc rejects the
56-byte encrypted_key at `jwe.c:577` before AES-KW); W186 reached the real
`id_token` OCT-KEK unwrap and W187 selected the chosen-byte fault site in that
real consumer, without pointer or IP control. Munt W178 found a real malloc
neighbour (`delta=+32784`, 64/64 sentinel bytes, glibc `corrupted top size`)
and five one-byte C-API host entry points; third-party hosts remain unbuilt.
Imagemagick W189 isolates the `magick stream` CLI ASan `READ of size 24` at
`stream.c:1295` as **not** CVE-2026-130664: it survives a CVE-only fix, and a
bounded survey of this build's compiled coders found no cache-geometry growth
path (`lab/frontier/imagemagick2shell/CLI-ISOLATE.log`). Frontier W188 screened
hydra2shell out at rung 3 (fixed `-1` offset, fixed NUL byte, plain build
survives): no charter, route or window.

The 02:1x–04:0xZ edges add two witness verdicts and two staged lanes without
moving a rung 5 cell. Assimp W3's witness #3277 replayed clean `git archive
585e1c7` (13 PASS / 0 FAIL, normalized `913b23f5…3ca938`) and graded the
baseline direct-call scope **ESTABLISHED rungs 1-4, NO r5**; the later real
`ReadFileFromMemory` importer path (W1) and chosen bytes at a live vertex
array's end (W2) were explicitly outside that claim and stay author-measured.
SofiaSip W14's witness #3280 (W182) replayed clean `git archive 4d508dc` on
fresh loopback ports, confirming 95 timer adds and 16 live timer pointers over
a 19-byte neighbour, **ESTABLISHED at the labeled live plain v17 tport rung-4
scope**, with no grade change; the pinned static libraries were reused rather
than rebuilt from source, the same limit as W11/W164. CodebaseMemory W1 moves
that target beyond direct calls: a local stdio JSON-RPC `tools/call` to
`query_graph` on the reduced ASan server reaches `READ of size 8` and a
recover-mode `WRITE of size 68` at `func_bufs[32]`, with the fixed release
rejecting >32 items; only the C grammar was linked and the other grammars
stubbed for build time, so this is a reduced server build, local-only and
unwitnessed. Frontier W195 staged fltk2shell (real 1.4.5 BMP row-pointer wrap,
chosen "SIM-" before the array, 33 PASS) and W194 staged synchronet2shell
(64-byte TERM into a 41-byte field, chosen "MISH"/"E-OO"/"TAUFTAUF" in
adjacent session fields, 9 PASS), each with a clean-archive replay receipt;
both stay FRONTIER-STAGED with no charter, route, wake unit or mind-count
change. The remaining edges are replay receipts and bounded negatives —
openexr W174, libfontenc W189, kicad W186/W187, libheif W184, libvips W16,
libgphoto2 W169, imgproxy W1, cjose W188, vrpn W23, modauthoidc W19 and
knotresolver W19 — none of which changes a witnessed row grade. BusyBox W4
drove the same fallback over loopback with the host's Ubuntu 24.04
`busybox-static` 1.36.1 binary (seven legs: chosen top-size aborts, OACK and
no-`-b` controls clean), adding artifact-level reach to the already witnessed
rungs 1-4 scope with no new grade; witness acceptance still covers only the
earlier from-source matrix. CodebaseMemory W3 fixed the empty tool-path fixture,
added a zero-row failure guard, and rebuilt every row with per-query ASan
stderr: the reduced stdio `tools/call` path now replays the chosen-name
`WRITE of size 68` at `func_bufs[32]` in Q33/Q48 from a clean archive, closing
the replay gap but not the independent-witness gap.

The 05:1x–05:4xZ edges deepen admitted lanes without moving a rung cell.
Assimp W5 (`20cf486`/`4f3b254`/`075eaa0`) drives pinned MAT4/FLOAT glTF 1.0
accessors through the real `ReadFileFromMemory` importer: ASan `WRITE of size
64` into a 12-byte `aiVector3D` and a 64-byte stack write into a 4-byte local,
with chosen `54 41 55 46` recorded at the first out-of-bounds offset, a glibc
abort in the plain build and the PR6860 hunk still failing the index path.
`harness/run-w5.sh` is 13 PASS / 0 FAIL from a clean archive with the gitignored
pinned tarball copied in; the first clean run's 10/3 was a recipe defect (fixed
library built from vulnerable source), corrected in `4f3b254` and preserved as
a harness negative. Author-measured, unwitnessed; no chosen byte in a live
`aiMesh`, no pointer/IP, command or r5. Sdlmixer W194 mines the adjacent AIFF
sibling CVE-2026-122329 under the stalled-lane doctrine: pinned `decoder_aiff.c`
`:86-98` has the same doubled stride, ASan `WRITE of size 4` at `:95`, gdb
chosen `5a5a5a5a` at `buffer+1024`, `check.sh` 134 PASS / 0 FAIL (trace
`1bdfc38d…43ad183`) and clean fixed runs. It is a separate CVE with its own
grade, author-observed direct-call rungs 1-4 only, unwitnessed; the WAV row is
unchanged. Libvips W16 places chosen `0x41` bytes in the live `vips_tracked`
size field at `data-16` with a free-time warning (`run-fine.sh`, `fail=0`); the
field is size arithmetic, not a pointer. Libvips W17 closes the imgproxy HTTP
route as a negative, replacing the decoded-stall explanation with the measured
422 guard above. LibRaw W197's real `dcraw_emu` rungs 1-3 and PARTIAL rung 4
(zero halfwords) were ESTABLISHED by witness W186 as labeled; W2's crafted
nonzero field writes `0xffff` at the same chosen offset but stays author-only
and unwitnessed, with arbitrary byte values UNKNOWN.

The 23:2xZ–00:2xZ kicad2shell edges correct that row's real-process boundary:
W182 drove a locally extracted native KiCad 8.0.8 Symbol Editor under Xvfb
through File > Import > Symbol... and reached `ParseLibHeader` in a real
process — the unmodified vendor `.SchLib` imported `MH M2.5 Mounting hole`
(alive, empty stderr), while the one-byte `SizeZ` key patch aborted with
`double free or corruption (out)` (exit 134, glibc `_int_free_merge_chunk`)
and the `Size0` patch segfaulted (exit 139). W183 showed the four OOB bytes are
file-selected in that process: `SizeZ` values 9/7/1/138889/200000 give exactly
`(int(SizeZ*7.2)*254 << 32)|0x20` as the corrupted chunk size, matching the
prediction in all five fresh gdb imports with an alive safe control. W186 then
reached the fixed-build control: KiCad 10.0.8 imports the hostile fixture in
the real Symbol Editor without an abort. W187 added a second file-reachable
offset: `Size-1=9` writes the low half of the chunk size (`0x3f80` under the
measured scale), faults the native 8.0.8 process with SIGSEGV while a matched
`Size1=9` control stays alive, and gives ASan `WRITE of size 4` 8 bytes before
the region with a clean fixed build (`lowindex/check.sh` 41 PASS / 0 FAIL,
trace `999e6733…64796`). The row's "no real KiCad build at any release"
sentence is stale; the real-process lanes stay chosen-byte rung 4, unwitnessed,
with no ASan vendor build, consumer read, wire, pointer or control-flow target
and no marker, so rung 5 remains UNKNOWN. Evidence:
`reports/frontier-kicad2shell.md` §§13–17, `reports/kicad2shell-status.md`,
`lab/frontier/kicad2shell/lowindex/PROVENANCE-lowindex.md`.

The 13:2xZ openexr2shell edge lifts the Openexr2Shell row from direct-call
CODE/HARNESS scope to **file-level rungs 1-4**: the advisory's 692-byte deep
ZSTD EXR drives a real pinned 3.5.2 `exr_decoding_run()` on the flat Core
scanline path, ASan reports the 4096-byte copy attempted at pinned
`internal_zstd.c:472`, and a guarded allocator measures the completed
4032-byte overwrite of a 64-byte live destination (4/4 runs, baseline 0/3).
The pinned 3.5.3 build rejects the same file with `EXR_ERR_CORRUPT_CHUNK`; a
single-pass C++ caller (`Imf::DeepScanLineInputFile::readPixels`) reaches the
same sink without a pre-pass, with the baseline clean and the fixed build
throwing `Unable to run decoder`. Witness W161 (#2675) replayed the file lane
from a clean archive with independently rebuilt trees and hash-matched logs:
rungs 1-4 ESTABLISHED at the labeled file-level CODE/CONSUMER scope, no
counterexample or grade change. The overwritten bytes are allocator-derived,
not file-chosen; the file controls only length and destination offset. W162
rebuilt the pinned tools with `OPENEXR_BUILD_TOOLS=ON`: unmodified `exrcheck -c`
reaches the same pinned `internal_zstd.c:472` sink on the 692-byte PoC
(vulnerable ASan rc 1 `memcpy-param-overlap`, vulnerable plain rc 134
`free(): invalid pointer`; fixed ASan `bad`, fixed plain rc 1; baselines `OK`
rc 0), while default `exrcheck` without `-c` still takes the safe prepass on
that PoC (W165's separate default-mode run hit a 60 s timeout with no clean
rc, so it is inconclusive, not a regression).
The wire lane is closed negatively: `exrinfo -` prints headers only,
`exrcheck` needs a file path, ImageMagick 6 links system OpenEXR 3.1.5 and no
OIIO/libvips consumer build completed: W165's 145-step build stopped at step 3
in 600 s; W168's 900 s `-j8` attempt reached 1/124 edges and a `-j2` probe hit
GCC-13 `-Werror=maybe-uninitialized` in `std::regex`, so a later 1020 s `-j2`
run reached 19/124 (~95 min remaining). No consumer was linked or run, so the
OIIO claim stays UNTESTED; a purpose-built socket wrapper would remain a
synthetic consumer under `docs/rce.md`. No wire-fed application process, socket, wire, pointer
target, command or marker, so rung 5 stays UNKNOWN with the named blocker of
a live affected application process fed by wire/request input. Full evidence:
`reports/openexr2shell-file-level.md`.

W163 varied the crafted EXR's ZSTD pixel fill byte from `0x41` to `0x5a` (the
new 692-byte file hashes to
`17f3752e95e35d70c454368789a8dd163938f03a6fe0784a1bee5ecab347ea8e`) and
replayed both through `bin-vuln-plain/guarded_harness`: identical
`GUARD-CHANGE ... changed=4032 ... actual@first=0x57` and
`GUARD-TOTAL post-decode changed=4032` on both. The changed file bytes stay
inside the 64-byte `scratch_buffer_1`; the sink reads offsets 64..4095 from
adjacent heap, so the file controls copy length and destination but not the
overwritten byte values. Negative preserved in
`reports/openexr2shell-file-level.md`; grade unchanged, rung 5 UNKNOWN.

The 21:1x–21:2xZ batch stages and admits three frontier lanes and closes one
tacplus boundary. Ntpsec2Shell (CVE-2026-121506), Uhttpd2Shell
(GHSA-2mpg-6wp5-435p) and Libvnc2Shell (GHSA-v9pm-47h4-jcq8) were staged by
frontier and admitted under standing #6 at 21:2xZ with routes and units but no
new windows; each stays code/harness scope (rung 3 ASan corruption plus rung 4
chosen bytes at a modeled or direct-call sink), with no live daemon, wire,
pointer, marker or command, and no grade change from admission. Witness W126
(#1706) independently replayed all three from clean archives — libvnc 20 PASS,
uhttpd 30 PASS, ntpsec 8 PASS, normalized hashes byte-identical — and graded
them ESTABLISHED at those labeled scopes. Its minor nit: the fixed libvnc pin
extracts 285 verbatim lines (vulnerable 275) because of the 10-line clamp, not
275 each; this document's recipe states both counts.
Tacplus2Shell W122 (`b404533`, `8d5af1b`) closes the grooming lane negative:
four live-daemon configurations on the plain vulnerable build never placed
chosen `cmd=ZZZZ` bytes behind the trigger buffer; the pinned `mem_destroy()`
indirect call is reachable in source, but no pointer, `arr_count` or `arr`
write was observed. Rung 4 stays at live-daemon chosen-byte scope and rung 5
UNKNOWN. Witness W126 (#1708) rebuilt both plain binaries and ESTABLISHED the
W121 live-daemon rung-4 readback (8 PASS / 0 FAIL). None of these limbs claims
rung 5.
The 21:3x–21:5xZ edges add three grade-neutral limbs. Libyang2Shell was
admitted under standing #6 as the 88th route; frontier's corrected evidence
hash and clean-archive replay are folded into its row and recipe. Witness
#1829 later returned ESTABLISHED at that labeled scope, with no grade change.
W1 (21:4x–22:0xZ) then lifted that direct-call ceiling: both ASan pins were
built and the fault reached through real `lyd_parse_data_mem(..., LYD_LYB, ...)`,
rung 3 plus real-parser rung 4 with no consumer, marker or rung 5 (recipe
below).
Msgpack2Shell was admitted under standing #6 at 22:0xZ as the 89th route, with
the three path/debounce/slice units from the exact full-flag sync (pin
`0d686bbad55c849e88334da64efff9da88ad528a`; `written 3, removed 0`) and the
frontier window adopted. Admission adds no grade: rung 3 plus scoped direct-call
rung 4, with no build, consumer, wire or command. Operator replay matched the
committed 177 PASS / 0 FAIL and normalized hash.
Witness W125 independently rebuilt all three MapServer
pins from hash-verified tarballs and replayed the stock-build wire rung 3 and
live-process rung 4 — ASan `WRITE of size 8`, byte-exact chosen `free()`
argument, wire child report byte-identical after masking — ESTABLISHED at the
labeled scope; rung 5 stays UNKNOWN. Witness W126 (DM #1707) rebuilt both pppd
pins and replayed all seven chosen2 cases on a live PTY: four hashes matched
exactly, three differed only in PIE pointer values, and the normalizer now
masks pointers while preserving the zero-extended chosen marker so `HASHES.txt`
is stable across fresh captures. Tacplus W127 opens one cross-packet route:
a large seq-3 prime's plaintext survives in the chunk reused by a new-session
seq-1 trigger, putting 32 prime-chosen plus 32 trigger-chosen bytes at chosen
offsets in the live `cmdline` (10 PASS / 0 FAIL twice). Every limb remains
rung 4 at its stated scope, with no pointer control, command or rung 5.

The 22:0x–22:1xZ edges add two rung-4 mechanics, no grade change. Tacplus
W128 (`3f7a3b1`) writes the prime's chosen `5a 5a 5a 5a 63 6d 64 3d` bytes
over both saved RBP and saved RIP in a live `tac_plus-ng` under gdb before the
corrupted loop state faults: five 255-valued size entries skip the validator,
a 251-byte copy overruns the 104-byte `cmdline` VLA, and fixed/no-prime/offset
controls plus two 9/9 replay runs hold. The VLA sits below live locals and the
return address, so the epilogue is unreachable with intact loop state — no
pointer, marker, command or rung 5. Vrpn W11 (`ed4094f`) reaches an installed
benign `write(2, ...)` marker from one wire NUL in a lab-patched non-PIE,
no-canary rebuild; fixed, short and unpatched controls are clean and the two
superseded stub iterations are preserved as negatives. The marker bytes are
binary-patch-installed, not wire-chosen; stock builds stay at witness W115's
rung 3, the new claim is author-only pending replay, and no rung 5 is claimed.

SofiaSip2Shell (CVE-2026-116791) and Ytnef2Shell (GHSA-jhg4-xcxm-cfg6) were
admitted under standing #6 at 22:2xZ and 22:4xZ as the 90th and 91st routes;
admission self-folds recorded only the staged harness scope. Both lanes' W1
then moved the same primitive onto real host layouts without changing a grade.
SofiaSip W1 (`c0fcf70`) drives a real 64 KiB `malloc` over a loopback TCP feed:
the chosen repeating-XOR mask changes the low six bytes of the next glibc
chunk's size and the next allocation aborts, while a live neighbour's data
stays intact and only its header changes; full ASan builds of both pinned tags
perform a real HTTP 101 upgrade and confirm the fault in the library's own
`ws_read_frame()` / `ws_raw_read()`. Ytnef W1 (`8d1c59d`, `e3630a2`) builds
both pins and reaches the wrapped write through the advisory's `ytnefprint`
caller on real upstream TNEF files: ASan confirms the 207-byte write, and the
plain build overwrites the following chunk's size with fixed prebuffer bytes
and aborts on the next allocation. The 1-byte `wrap206` case is a preserved
negative — its 206-byte request stays inside usable space, so the later copy,
not the prebuffer write, faults. Two admitted lanes advanced at live scope:
Tacplus W129 (`7603775`) overwrites `eval_args()`'s saved `t` cursor from wire
bytes in a live daemon under gdb and lands chosen `PWN3PWN3PWN3PWN3` at a
chosen address; the destructor-based rung-5 probe still aborts in glibc before
the fake call, so rung 5 stays UNKNOWN. Pgpool W10 (`00c84f2`) measures the
previously unwired `wd_nodes` branch: a loopback watchdog packet reaches the
live 4.7.2 child and gdb reads peer-chosen values in `wd_node_info[128]` and
the adjacent `trusted_servers` field, with no crash or follow-on dereference.
Pppd W131 (`f95ddc9`) reaches the sigreceived notifier and forks a child, but
the corruption of `the_channel`'s high half leaves the saved pointer invalid;
the child dies before `execve` in five replays and no marker appears. All five
limbs are author-only: no witness verdict, pointer-bearing command or rung 5.

The 23:1x–00:4xZ edges deepen nine admitted lanes; three move a grade or
verdict. Msgpack W1 (`7145879`) drops the harness's forced `src->end`: a real
pinned C library driven only through `init`/`append_ref`/`migrate` faults on a
natural two-allocation layout under both compilers (74 PASS / 0 FAIL). Its
consumer stay-UNKNOWN is now backed by three negatives — the sole in-tree
caller is a unit test, GitHub indexing finds only unit-test/advisory paths,
and Sourcegraph's 53 matches in 29 repos name bindings and request-serving
vendors but no production `migrate()` call — so the lane stops at rung 4.
SofiaSip W2 (`df6fb42`, `620ce97`) moves the chosen XOR delta into live
neighbour data and reaches the overflow through the library's own loopback WS
SIP tport with HTTP 101. W3 (`21a4be1`) narrows the old `PREV_INUSE` claim:
it survives with an even mask yet glibc still aborts; witness #1942 returned
CLOSED ESTABLISHED at that negative scope. W4 (`08e86c0`) chooses a tcache
`next` pointer redirection and observes an eight-byte write at the chosen
address, in-process and witness-pending. Pppd W132 (`740b6fd`) only reached a
chosen `unlink()` call; W133 (`cb1da9e`, `ea972d2`) supersedes that for the
pinned non-PIE 2.5.3 lab build: a `dlopen@plt` constructor runs a wire-carried
command and witness #1966 ESTABLISHED rung 5 at that labeled scope with a
causal wire-only change and fixed/safe/NULL-callback controls. Tacplus W130
(`f2aac1c`) masked an environment-dependent hash field; W132 (`177955a`)
closed a second witness hash NIT; W134 (`cd620de`, `f0d712f`, `44d2978`)
landed a fake `mem_t` pointer in `mem_destroy()` but the reply overwrites the
staged object. W135 (`32b53e9`) bypasses that fake-object route by writing the
real `mem_t` contiguously and observes a chosen `system()` marker in a live
daemon under gdb with ASLR off: rung 5 OBSERVED at a labeled build scope,
witness replay pending. Baresip W1 (`c06152a`, witness #1933)
drives a real loopback `websock_accept()` HTTP 101 wire frame to a narrow
rung-4 ESTABLISHED verdict with a structural ceiling; Ytnef W2 (`fb180df`,
witness #1876) ESTABLISHED rungs 1–4 with a preserved synthetic-input
confounder; Libyang witness #1829 ESTABLISHED the real-parser scope. Connman
W1/W2 move from a direct call to a natural caller chain and a parsed REPLY
packet; vrpn W12's clean rebuild and alignment precondition were independently
replayed by witness W135/#1985 and ESTABLISHED at the labeled lab-patched
rung-4 scope. Pgpool W11 (`wd_authkey` does not gate the type-Z parse) remains
author-only and grade-neutral.

The 01:0x–01:4xZ edges add one route and deepen two others. Erlang2Shell
(`4cdd30b`) was admitted as the 95th route after frontier's W131 replay; its
arity-wrap harness stays code-only with no BEAM build or network. Gdbserver
W1 (`49d2bf5`) feeds a checksummed `QTDPsrc` frame over loopback RSP into the
verbatim pinned dispatcher and writes a chosen word into a groomed
`process_info_private`, while W1b (`c6bb4b1`) builds the real 633ae02
gdbserver and observes the ASan WRITE-1 on that live wire; a default-CFLAGS
build dies at teardown with the attack packet and exits 0 on the safe one.
W1/W1b stay rung 3 plus scoped rung 4: no live readback, forged
`qGetTLSAddr` call, marker or command; W2 below adds both. Connman W4 (`8da09bf`) moves the
2056-byte REPLY from an in-process buffer across a real loopback UDP socket
into the verbatim caller chain and steers the first `.` store onto a live
saved return-address byte, still without a connmand daemon or pointer/marker
control. All these limbs are author-observed and witness-pending.

The 01:5x–02:0xZ edges deepen three admitted lanes without claiming new
live-VM or daemon reach. Tacplus W136 (witness verdict #2049) closed the W135
rung-5 replay from a clean `git archive 32b53e9`: three normalized hashes
matched twice, a wire-only command change produced a different marker and the
default stayed absent, so R4/R5 cells move to ✓ at that labeled plain `-O0`,
gdb-parent, ASLR-off build scope; the advisory's five-connection root chain
remains claim text. Docs replays also found a count NIT: `run_rce.sh` emits
13 PASS lines, not the report's 14. Connman W5 (`c4b6d45`) built the whole
pinned tag-2.0 tree with lab-local dependencies and probed the real
`connmand` object under gdb (12 PASS / 0 FAIL, ASan READ-1 at frame offset
1201, fixed and safe clean), overturning the earlier full-build blocker but
adding no daemon run or rung 5. Erlang W4 (`276a200`) built the pinned erts
emulators and ran the real-VM driver: both emulators reject all three bounded
attack ETFs before `dec_term` with no ASan report; the ≥2 GiB inflated-buffer
route was not attempted on this shared host and stays UNKNOWN.

The 02:1xZ edges stage one target and deepen two admitted lanes without a grade change. Gdbserver
W2 (`e6207f2`) moves rung 4 into the real pinned plain build:
`rsp/plain_verify.sh` replays the loopback wire three ways twice (6 PASS /
0 FAIL, hash `f8bb0fd0…`), and under gdb the 64-byte overflow rewrites a live
adjacent `tdesc_feature` vptr whose forged `+0x10` slot sends the destructor's
indirect call to `abort()` twice with a same-length control clean. That is
demonstrated chosen-function control-flow hijack at the gdb-fixed-address
condition; at W2's time the same bytes under `setarch -R` without gdb did not
fire, no command or wire-only side effect followed, and rung 5 was untouched.
KnotResolver's wake-17 static check (`91a5bd6`) found no
command-execution import in the mapped libgnutls; the final inventory found no
libgnutls *text* pointer in the reachable objects, but an earlier sample had
one at `priv+0x110` with its mapping base unrecorded, so stub reachability is
UNKNOWN, not refuted. Wake 18 (`c371100`) measured entropy in address bits
20-23 across three committed layouts (`c/4/8` heap, `8/0/4` libc), so a 3-byte
partial overwrite is not deterministic; guessed-nibble repeats stay UNKNOWN.
ASLR-on/stock chosen control stays UNKNOWN.

Frontier staged MiniSnmpd2Shell (`02bb46a`) on CVE-2026-59961: a pre-auth SNMP
OID length wraps a `size_t` bound in the pinned `decode_oid()`/`decode_str()`
slices, giving ASan READ-1 past a 2048-byte heap packet in the harness
(43 PASS / 0 FAIL), byte-exact adjacent canary readback at a chosen offset and
a vulnerable-branch reach on a loopback ASan daemon with no wire-level ASan
report. Admitted 02:4xZ as the 96th route with the hy4-flash route, three
full-flag-sync units and both resolver entries; frontier's two-pane window at
index 100 and the seed wall were adopted unchanged, so it is now in the mind
list at rung 3 plus scoped direct-call rung 4.

The 02:2x–03:0xZ edges deepen four admitted lanes without a grade change.
Gdbserver W3 normalized the compile-time source path in `live_verify.sh`
(stable hash `5701a874…`; the old `b646cc08…` varied with build directory);
witness W137 (#2085) independently replayed W2's live vptr overwrite and
forged destructor call in its own plain build with only the vptr field changed
to that build's object+8, so the payload must be re-derived per build. W4
(`2a1b301`) removed the debugger: under `setarch -R` a loopback client fires
the forged `abort()` with no gdb (3 PASS / 0 FAIL twice), still a
build-specific marker, not a command. Minisnmpd W1 moved its scoped rung 4
into the real plant-started daemon under gdb (18 bytes read past
`client->packet`, adjacent size byte `0x08` into `subid_list[5]`), and witness
W138 replayed that and the harness from a clean archive ESTABLISHED at the
labeled scope, with no wire-level ASan. SofiaSip W4's chosen tcache `next`
write was independently replayed by witness #1968 three times, ESTABLISHED at
the in-process rung-4 scope. Ettercap W1 (`fcec372`) put rung 3 on the real
dissector: a crafted TCP/8074 frame gives ASan `WRITE of size 13` in
`gg_get_version()` both from a pcap and from a live frame on `lo`, with
fixed/safe/direction controls clean; rung 4 stays extent-only and AV:A
unpromoted. Connman W6 measured the real object's canary boundary (K=7 stops
at the zero low byte, K=0x80 steps over), a structural negative for W1's
synthetic-canary byte-run; no private-netns daemon was run. None claims a
command or rung 5.

 The 03:5xZ edge admitted the 99th route. Llamarpc2Shell (CVE-2026-118375)
 was staged by W135 with a fresh-copy replay of the verbatim-slice harness
 (28 PASS / 0 FAIL, `d898482a…09c1b2`) and no live server. `37da4e6` then
 performed the cheapest next experiment on the pinned upstream server:
 plant-built `ggml-rpc-server` on loopback SoftRoCE `rxe0`, real HELLO/caps,
 RC QPs and SEND completion into `rpc_serve_client()`. ASan confirms WRITE-43
 in the live process; in the plain Debug frame the client's `0x5a`/+11 and
 `0x44`/+18 land byte-exact and a 3593-byte SEND overwrites the saved RIP slot
 at +3585 with `0x4242…` before a destructor-path SIGSEGV. That is overwritten
 control-flow data, not execution at the chosen address; the +3585 layout is
 Debug-only and the fixed server stays clean on the same wire path. Witness
 W142 (#2193) replayed `37da4e6` from a clean archive with its own pinned
 builds and ESTABLISHED rungs 3 and 4 at that labeled Debug/plain build scope,
 with no counterexample. `a76b986` then measured a bounded wire-only ROP
 attempt as a negative: in a no-canary Debug build the saved RIP sits at
 `&cmd+761`, but the oversized completion returns false from `rdma_recv`, the
 early `break` sends the frame into `rpc_server::~rpc_server`, and the
 destructor aborts on corrupted locals (`free(): invalid pointer` at 100/761/
 820-byte SENDs; a 4608-byte SEND faults in a second memcpy) before the
 epilogue; no marker, command or valid redirect. R5 remains UNKNOWN and
 AT:P still qualifies the advisory's AV:N.

 The 03:3x–03:4xZ edges add one admitted lane and one locally demonstrated
 rung 5. Ghostscript2Shell (CVE-2026-125396) was admitted as the 98th route
 after W134 staging and a fresh-copy replay (`PASS=22 FAIL=0`, trace
 `a4569485…`) of the injected-PFA systemdict marker. Three later author wakes
 (`1a2b715`, `2ac5f7c`, `f6a0942`) promoted it: an ASan UAF READ-1 at
 `zget psi/zgeneric.c:183` (21/0, `bd4e4b4c…`), a forged native view that
 walks live device pointers to `CORE+156`, flips `path_control_active` and
 retargets one operator dispatch (17/0, `b53abad2…`), and the same native flip
 under `-dSAFER` with `--permit-file-read` (9/0). The earlier SAFER negative
 was a permission artifact: without that permission the built-in font is used
 and the injected cleartext never runs. The probe hardcodes the repo font path,
 so a copied-tree replay must permit that absolute path. Witness W141 (#2149)
 replayed the baseline, UAF and native lanes from clean archives with its own
 rebuilt binaries (22/0, 21/0, 17/0, matching traces) and returned ESTABLISHED
 for rungs 1–4 at the labeled build scope, no counterexample; the `-dSAFER`
flip stays author-observed. W8 adds a rung 5 at the permissive
lab-app scope: loopback HTTP-uploaded bytes drive a live `-dSAFER` gs child
whose forged ref clears `path_control_active` and runs a benign `%pipe%`
marker command, with fixed and safe-font controls clean (14/0, hash
`ddd635b2e607150af1180cc07554183ac79fd1025a79c00af28fbf923bf09957`); witness
W145 (#2252) independently replayed it from a clean archive with rebuilt
gs binaries and causal counterchecks, returning rung 5 ESTABLISHED at that
labeled lab-app scope only. The writeup's delivery chain stays unmeasured.
AV:L and public-network RCE stay separate claims.

Gdbserver W5 replaces the forged
`abort()` slot with the fixed-address libc `system` entry (`endbr64`, so CET
IBT is met) and lets the destructor's `call *%rax` hand the vptr's
little-endian bytes to `system` as `rdi`; a lab-installed executable of that
name writes `R5_SYSTEM_MARKER=1`. The object address is derived by an
`abort@plt` sweep, PATH is kept the same length, and four controls give
4 PASS / 0 FAIL with normalized hash `9104b0ec…`. That is a wire-only,
no-debugger, live-process command execution with a marker and controls, but
witness tape #2297 later returned ESTABLISHED for that forged libc `system`
call at the labeled ASLR-off loopback scope; the rung-4 W137 ESTABLISHED
scope is not retroactively widened and no ASLR-on claim is made. W139 also
measured a 0x30 heap shift from the parent environment alone, so a replay
must re-derive the object address rather than reuse the recorded one.
Gdbserver W7 (`a978d80`, `1801d95`) removes W5's fixed `obj+8` assumption:
`rsp/r5_portable_verify.sh` derives the object with `abort@plt`, then chooses
the smallest offset in `{+8,+0x10,+0x18,+0x20,+0x28,+0x30}` whose vptr bytes
pass the literal-word whitelist and `sh -n -c`, with `system` at `vptr+0x10`
and `N=64+delta-8` (largest write through `obj+0x47` inside the measured
0x58-byte usable chunk). The default `+8` case gives `48c461555555`,
4 PASS / 0 FAIL, hash
`9104b0ec51a09c94922438a62d9df2bfa108f4b4e6f8e7f18abc26d3f4886a98`; a
forced `+0x10` case gives `50c461555555`, 4 PASS / 0 FAIL, hash
`6be8244f7949331ac1f8ee9e1a1389e4f30a8525f25317a444063367d41d3747`. A sweep
of object low bytes `0x00`–`0xc0` finds a safe offset for every case; W140's
`0x20` picks `+0x10` (`30c461555555`, ASCII `0`). A controlled 32-byte
parent-env shrink later reproduced W140's object exactly (`DERIVED
obj=0x...c420`): the old chooser printed every candidate but the shell parser
read only the first line, so W7's "+0x10 at c420" described the predicate, not
the shipped harness; the fixed chooser emits only the selected line and a full
c420 rerun gives `reject delta=0x8`, `CHOSEN delta=0x10`, 4 PASS / 0 FAIL.
No grade change: rung-4 ESTABLISHED and W6's labeled rung-5 scope, now
witness-ESTABLISHED at the labeled ASLR-off loopback scope, stand.

The 04:1x–04:3xZ edge batch updates four rows above: nanomsg W107 is an
independent witness rung-4 ESTABLISHED verdict at the standalone-listener scope
(the witness rebuilt both pins and its own harness; no refutation or NIT), and
W108 drives the same sink from `nanocat`, a CLI tool shipped in both pinned
trees, on loopback with a gdb-measured chosen `item.next`; netx adds witness
#1296/W108 for the W3 crafted-certificate limb alongside #1262 for W1/W2;
mapserver's consumer-reality pass closes the observed rung-5 path (adjacent
chunk header and heap pointers, C-string and `free()` consumers only, no
call-through or wire leak, fault is glibc double-free) while keeping rung 5
UNKNOWN with named obstacles; a deeper-K pass (`./poc.sh 195`) writes ~1.5 KB past the parse-time-doubled 1600-byte arrays, scans ~3.2 KB of OOB range with the same negative and clean fixed/K=197 controls, and finds only heap pointers, chunk metadata and attacker-string bytes in the write range; vrpn W6 kills an untouched stock plain server
with one pre-auth message (SIGSEGV/SIGILL, controls alive, author-only). None
claims rung 5; Pgpool-II was admitted in the same batch (`30ccfc3`) with its
own row and reproducibility recipe.
The 05:0x–05:1xZ edges add one live-server rung-4 promotion, one chooser
mechanic and one witness verdict. zlib2shell W1 drives a plant-started
loopback gzip server whose TCP flow control makes `gz_vacate()` copy the
peer's own request bytes past the 16384-byte `state->in` region, with gdb
readback matching peer bytes at chosen destinations; witness W144
independently replayed both harnesses and returned ESTABLISHED at the labeled
build scope, with no pointer redirect, command or rung 5. Gdbserver W7 turns
W5's shell-safe command name into a measured fake-vtable-offset choice with
no grade change. Witness W141 independently replayed ghostscript's baseline,
UAF and native lanes and returned rungs 1–4 ESTABLISHED at the labeled build
scope; the `-dSAFER` flip stays author-observed.
Ghostscript W8 then demonstrated rung 5 at the deliberately permissive
lab-app scope over loopback HTTP (not the writeup's delivery chain), and W145
independently replayed that chain from a clean archive with rebuilt binaries
and causal counterchecks, returning rung 5 ESTABLISHED at that labeled
lab-app scope only.

The 05:1x–05:3xZ batch adds the two admitted targets above and closes four
boundaries. Pgpool-II W1 reaches the bad write in a real 4.7.2 watchdog child
over a plant-owned loopback peer: `NodeCount=2` gives one SIGSEGV while
`NodeCount=1` and fixed 4.7.3 are clean; gdb shows
`node_id_set[1] = 0x1` at the faulting `wd_json_data.c:858`, and four warm-up
variants leave that adjacent slot at `0x5560cc4d`, so write-address steering
is a measured negative and witness replay is owed
(`reports/pgpool2shell-wire-w1.md`). MapServer W4 source-closes the remaining
consumer alternatives on the live request path: the corrupted parameter and
value arrays reach only string comparisons, `atoi`/`atof`/`strtol`, `strlen`
and `msStrdup`, never a format string or function pointer, with no grade
change. MsQuic's external-claim scan found no public PoC, capture or trigger
bytes — the SecureLayer7 write-up and PRs #6219/#6220 restate the advisory —
so rung 3 ESTABLISHED and the rung-4 gate are unchanged. ProFTPD adds fixed
1.3.9e rejection controls for both ASLR-on limbs: `LEAK NONE` on the
chosen-string client and `550` on `STOR` with 1056/1152-byte keys while the
vulnerable builds leak pointers; both limbs remain author-only behind #1287.
VRPN W7 resolves the optimized-build UNKNOWN into a negative: a `RelWithDebInfo`
(`-O2`) build still takes the wire-driven ASan `WRITE of size 1`, but the plain
process survives indices -8 and 120, so W6's DoS is a Debug `-O0` layout
effect, not a build-independent consequence. Wazuh W110 changes multi-event
grooming from UNMEASURED to a measured adjacency result — a chunk holding a
pointer fragment can be placed after `full_log`, but the overrun writes fixed
alert text with at most one attacker byte — and W111 (#1326) independently
replayed W108/W109/W110 ESTABLISHED at that scope with no refutation. The
~06:3x–06:5xZ batch adds pgpool W2/W3 — two more address-steering negatives
across the `-O2` layout and `NodeCount>=3` — and a Soes advisory write-set
closure (six write limbs covered, 15 read/NULL/length limbs remain); both
are grade-neutral. None claims rung 5.
The ~09:5x–10:2xZ batch closes one rung-5 boundary and stages one new target.
KnotResolver wake 12 reaches chosen RIP and two distinct benign commands at a
labeled ASLR-off, gdb-parent, jemalloc/debug-build scope (`f4f63d0`, logs
`c3c4c62`); witness W114 (10:14Z) returned **MIXED** on its own pinned builds:
the dispatch class is ESTABLISHED and both commands reproduce at `argoff 0x300`
with marker-absent safe/fixed controls, but the committed/default `0x2f0`
command limb failed twice because `gnutls_deinit` zeroed the string before
dispatch. The author was asked for the exact offset in #1376; until reconciled
the command-execution claim is not witness-ESTABLISHED verbatim, so R5 stays ◐
and ASLR-on/stock UNKNOWN.
FastNetMon CVE-2026-48689 is staged with rung 3 ASan and direct-call harness
rung 4 on the real pinned header (`6df55a0`) but no daemon, wire or command;
its pre-auth reach remains a claim. Its window, charter and seed wall already
exist; the operator's admission decision was pending at 10:25Z (chat tape).
A separate operator docs commit (`3d9e35b`) records the 2026-11-22
wake-concurrency=1 recovery in
[docs/runtime-pin.md](docs/runtime-pin.md).

The 11:1x–11:5xZ folds close one witness boundary, stage one target and
record two bounds. Pgpool witness W113 (closed 08:09Z, recorded in the witness
wall) independently built 4.7.2/4.7.3 and replayed the rung-3 wire crash on
its own ports with a live gdb frame at `wd_json_data.c:858`; its verdict
excludes a chosen-address write, any command and rung 5, and did not replay
the warm-up steering negative. No verdict DM reached this role's dossier, so
the citation is the witness wall and its artifacts, not a delivered message.
Snac2 CVE-2026-112021 is staged on the real pinned 2.92 JSON parser: ASan
WRITE-1 at `xs_insert_m`, fixed 2.93 clean, chosen `0x41`/`0x5a` at offsets
40..85 under a direct-call harness; no daemon, HTTP request or command, so
rung 3 with harness-only rung 4 and the pre-auth POST reach still a claim.
Soes measured the real BSS hook-slot layout and named the `COE_pdoUnpack()` →
`RXPDO_update()` two-cycle route; the tenth wake's execution stall left the
repaired harness unvalidated, but the eleventh wake (commit `e574fed`) rebuilt
and replayed it: plain 3.2.0 reaches `hook_written=1 indirect_call=1` with a
varied byte selecting a different called function, fixed 3.2.1 and safe input
clean, ASan `WRITE of size 64` in `ESC_read` via real `RXPDO_update()`. Still
rung-4 harness mechanics — no wire, leak or command — grade unchanged and wire
reach UNKNOWN. MapServer W5
only makes the existing report's Reproduce block replayable from a clean
checkout; it adds no new claim.

The 17:1xZ batch closes two lanes and adds two author-only limbs, none with a
grade change. Pgpool W6 closes the last cross-command address-steering lane
by measurement: a type-`f` failover warm-up through `watchdog.c:2916` leaves
`0x8cc59ffa3c9d9b00` in its adjacent slot, but the recovery trigger's frames
are 0x40 apart, so that residue cannot occupy the bad index and the trigger
still stores `0x1` at `wd_json_data.c:858` before faulting; its runner is now
self-contained. MapServer's fresh-context replay matches the canonical ASan
reports byte-for-byte after address/PID normalization (K=95 and K=195
vulnerable rc 1, fixed and K=97 clean, plain K=195 rc 134); the Reproduce
block now preserves the vulnerable report before the fixed control runs.
The W7 replay (`c7d055e`) closed two un-run gaps: the live gdb readback wrote byte-exact
chosen bytes at `ParamValues[100]/[150]/[190]`, and a real K=95 GET through
`loopback_bridge.py` reproduced the canonical child ASan report after masking
addresses and PIDs. Grade unchanged at that time; witness W125 later replayed the live limb ESTABLISHED at the labeled rung-3/rung-4 scope. MsQuic adds a wire-pure
retired-CID UAF read with a one-line-guard control (3/3 vulnerable pointer
identity vs 0/3 fixed frees/adds), strengthening rung 3 only: the UAF write
is untriggered and instrumentation is gitignored scratch. Vrpn W8 maps the
optimized frame (canary at +104) and gets a pre-auth SIGABRT at index
105/111. W10 (`fa72cbd`) corrects W8's "-O2 plain" label: those functional
rows used the Debug `-O0` binary `5cf494…`; an explicit-`BIN=` replay on the
real O2 binary `bfe633…` reproduces the abort and puts 136/139 DEAD exit 139,
matching the witness and resolving W8's 136/139 UNKNOWN as a build-label
mix-up. Grade unchanged. Soes proves its hook replay
self-contained from a clean checkout (32 binaries rebuilt, six cases
reproduced; the earlier "18" was a miscount); witness W124 (#1653) later
ESTABLISHED all 88 cases, including the hook addenda.
All four new behavioral limbs were author-observed at the time; only the
later witness closures named above are ESTABLISHED.

The 17:2x–17:4xZ edges close one witness boundary and add three grade-neutral
limbs. Witness W115 (#1453) rebuilt both pinned vrpn trees on fresh ports and
replayed the W8 canary-abort matrix: vulnerable indices 105/111 DEAD exit 134
with `*** stack smashing detected ***`, fixed and short controls alive. It
grades W8 **ESTABLISHED at the rung-3 scope** — independent acceptance of the
measured wire write and abort, not a promotion: fixed NUL byte, no chosen
byte, pointer control or command. W10 since resolved the W8 build-label
discrepancy: the witness's DEAD exit 139 at saved-RIP indices 136/139 is
matched by W10's real-O2 replay; W1/W2/W3/W6/W7 remain
author-only. Soes closes its clean-checkout gap: a fresh `git archive` tree
rebuilt all 32 binaries and replayed 88 cases across the six write-capable
limbs, with exactly ten nonzero exits (nine ASan reports plus the plain
129796 `memset` SIGSEGV) and all safe and fixed cases clean — wire reach and
the grade stay UNKNOWN/unchanged. Witness W116 (17:47-17:51Z) first deferred
the grade-unchanged full replay (#1466, the follow-up to #1438); W102 and
W105 had already independently ESTABLISHED the grade-changing claims. Witness
W124 (#1653) later replayed all 88 cases from its own clean archive with its
own clang build and graded them ESTABLISHED at the labeled harness scope, so
the hook-call and clean-checkout addenda are no longer author-only. A root
`sudo -n` AF_PACKET probe on `lo` sent and received a 42-byte EtherType
`0x88a4` frame with its payload intact, correcting the earlier EPERM
negative as uid-1000-specific; the pinned trees still ship no socket-backed
ESC or HAL, so there is no live input path and no rung change. Pgpool W7
opens a new adjacent lane on CVE-2026-92869: a
peer-controlled unbounded `backend_desc` length writes chosen `0x42424242`
past the 128-element array in the 4.7.2 parser (ASan `WRITE of size 4`, gdb
readback, and one loopback type-`Z` packet crashes a live watchdog child);
4.7.3 and safe N=128 controls are clean. That is rung 3 plus rung 4 chosen
value at a layout-fixed offset on a live daemon, with no arbitrary-address
steering, command or rung 5 and no witness replay of the new lane.

The 17:5xZ edge stages one new target, `inetutils2shell`, on CVE-2026-32746:
hash-pinned 2.7/2.8 tarballs and the three-line `slc.c` guard, a verbatim
pinned-writer harness with natural ASan `global-buffer-overflow` and chosen
triplet readback past `slcbuf`, 8 PASS / 0 FAIL on two in-tree and one clean
`git archive` replay (byte-identical normalized hashes). No telnetd process,
option negotiation, wire frame, pointer control or command was reached;
witness replay is owed and pre-auth wire reach stays UNKNOWN. Frontier
checked for duplicate ownership before staging; the operator admitted the lane
at ~18:0xZ with the 80th route, wake units and a
[status page](reports/inetutils2shell-status.md).

The 23:0xZ witness verdict #1834 closed the two oldest-open ProFTPD limbs —
the 03:17Z extended over-read (#1287) and the 03:40Z ASLR-on chosen-string
readback (#1330) — ESTABLISHED at the labeled ASLR-on rung-4 scope. The witness
rebuilt both pins from its own clean `git archive` tree with gcc 13.3.0 -g2 -O2,
replayed client13 (PAT_HIT 17 with the marker, 0 in the marker-free control)
and client12 (200→200, 1056→1062, 1152→1158 with run-varying pointer tails),
and confirmed fixed 1.3.9e gives LEAK NONE and 550 length-rejection controls.
No refutation or NIT, no PIE base, no command, rung 5 still unclaimed; the four
earlier author-only limbs and the source-only call-path closure stay unwitnessed.

Pgpool W8 (`82df143`,
[report](reports/pgpool2shell-alias-w8.md)) closes the W7 field UNKNOWN on the
pinned 4.7.2 daemon: live gdb before/after mapping identifies the OOB slot as
`json_object_entry.value` of `backend_hostname` in a peer-supplied backend
object, and a second chosen value `0x11111111` faults at `0x555511111111`
(low 32 bits peer-chosen, high 16 inherited), proving value→fault causality.
The direct-call harness's `free(): invalid size` abort is value-independent,
so its readback is a chosen-value store but not a value-caused fault. No
address steering, command or rung 5; grade unchanged, author-only, witness
replay still owed.

The 18:2x–18:4xZ batch admits h2o2shell and stages pppd2shell while moving
both h2o and inetutils from direct-call to live wire scope. H2O's W1 builds
the pinned server as a real ASan executable and a single loopback request with
the minimal `%{error}x` format faults the 4096-byte access-log stack buffer at
frame offset 4160; gdb shows request bytes at `buf+4064` and ASCII `FGHIJKLM`
in the saved frame slot, fixed-pin and short requests stay alive, and the
fault threshold is exactly a 3959-byte path (`error_logs` = 4096 plus the
one-byte `\n`). Rung 5 stays unclaimed because the Apache escaper cannot emit
raw pointer bytes. Inetutils W1 sends a 50-triplet LINEMODE SLC suboption to a
plant-started telnetd on loopback and faults pinned 2.7 at `add_slc`, with 2.8
and short-input controls clean; wire bytes are `func 00 00`, so its chosen
triplet remains a direct-call result. Pgpool W9 adds a distinct `wd_nodes`
branch of the same peer parser — a chosen port and hostname write the adjacent
`trusted_servers` field at direct-call scope, ASan-clean because the write
stays inside the config allocation, with N=128 and fixed 4.7.3 controls.
Frontier staged pppd2shell on CVE-2026-85495 with a verbatim `lcp_reqci()`
harness: ASan and chosen digest-byte readback past `nak_buffer` at direct-call
scope only, no daemon or wire; duplicate check found no prior pppd target,
and the operator admitted it at 18:56Z (82nd route). Witness W119 (18:50Z)
ESTABLISHED the inetutils wire claim at labeled rungs 1/2/3, preserving the
34-triplet `end_slc` and `func<=18` boundaries and canonical runtime `slcptr`.
Witness #1583 rebuilt both h2o pins in a clean archive and ESTABLISHED W1 at wire rungs 1/2/3 and chosen-byte rung 4 (3/3 outcomes, 3958-clean/3959-fault threshold); pppd's W122 was later replayed witness-ESTABLISHED by #1625, while the W123 chosen-global cases stay author-only.

The 18:5x–19:1xZ edges add no grade change at that time. Pppd2shell was
admitted at 18:56Z with the 82nd route and libssh22shell at 19:14Z with the
83rd; both admissions self-folded their rows and task limbs, and both were
direct-call only with no witness at admission (libssh2's live-process rung 4
is folded below). MsQuic's last open rung-4
hypothesis is closed by a structural read of pinned v2.5.9: the post-free
copy takes the pointer already in `Paths[0]`, a nonzero groomed CID length
only suppresses that copy, and the retire-CID path writes fixed offsets, so
even a successful groom would be a fixed-value UAF flag write at rung 3;
the grooming step itself stays UNTESTED and R4 barred. Inetutils W2 locally
reproduced the 34-triplet `end_slc:237 sprintf` boundary and the
valid-`func<=18` no-fault negative without changing W119's verdict. H2O W2
measured both rung-5 routes: the escaper cannot emit raw pointer bytes and a
canary aborts before `ret` on a live plain build, while a forced 8192-byte
heap log buffer has only top-chunk metadata after it in four groom layouts;
W3's witness replay is covered above and rung 5 stays UNKNOWN.

H2O W4 (`c360f20`) closes the last open heap hypothesis without a grade
change. On the pinned plain build, the forced-heap overflow request (1200-byte
`pad` header, 6870-byte path) returns 503 and leaves the process alive with the
corrupted top size; the next short loopback request times out and the error log
records `free(): invalid next size (normal)` followed by SIGABRT, while a
control run of two short requests stays clean. Because the Apache escaper emits
only 0x20–0x21 and 0x23–0x7c, the rewritten top size always has its high bytes
set and can never be a valid small size: glibc aborts on first reuse instead of
returning a controllable pointer. With W2's canary barrier, rung 5 is
structurally closed on both stack and heap paths for these wire sequences;
different allocators or placement primitives remain separate claims.

Libssh22Shell W2 (`59ce649`, `reports/libssh22shell-live.md`) upgrades the
admission's live/wire UNKNOWN to a locally established live-process rung 4.
An ASan libssh2 client built from the pinned vulnerable parent completed a
real SSH transport handshake over 127.0.0.1 against a plant-started fake
server (curve25519-sha256, ssh-ed25519, aes128-ctr,
hmac-sha1-etm@openssh.com) and faulted naturally with `WRITE of size 15` in
`transport_fullpacket()` at `transport.c:263`, 0 bytes past the 4-byte sink
allocated at `:249` — inside `libssh2_session_handshake()`, before any
application call. The fixed pin rejects with `LIBSSH2_ERROR_DECRYPT`; wrong
MAC, safe input and `packet_length=15` are clean, `packet_length=14` faults;
three fresh-key replays match. gdb readback shows 4 (or 13) directly chosen
bytes at the sink with the remainder MAC-derived. Rung 5 was UNKNOWN at W2's
time: no grooming, pointer control or command side effect, and the advisory's
32-bit tcache/function-pointer story was not reproduced on 64-bit safe-linked
glibc (1..11-byte overwrite window); W3 below closes it on this host. Witness
W123 (#1628) later replayed the live claim from a clean archive and graded
rungs 1/2/3 and live-process rung 4 ESTABLISHED at the labeled scope, with no
refutation or NIT; rung 4 is established at both direct-call/stub and
live-process scope.

Libssh22Shell W3 (`97e777a`) closes rung 5 on this host's allocator without a
grade change. The vulnerable sink is `ssh2_default_alloc` → `malloc(count)`
(`session.c:67`) with no custom allocator in the live client, so `malloc(4)`
has 24 usable bytes in a 0x20 chunk here and the 15-byte `memcpy` at
`transport.c:263` ends with 9 bytes of that chunk unused; one adjacent run
left the neighbour size field at `0x21`, though adjacency is allocator-state
dependent and not a premise. All cipher blocksizes in the pin are 8 or 16 and
at `packet_length >= 15` total writes are `decrypt_size - 1`, so no packet
length produces a physical out-of-chunk write. ASan's WRITE-15 is a
requested-size redzone hit; the advisory's tcache/function-pointer path fits
32-bit glibc (0x10 chunk, 12 usable bytes), not this host. Rung 4 at
ASan/abstract scope is unchanged; rung 5 is closed for this build and
allocator, not merely UNKNOWN. The probe, its measured output and an honest
adjacency caveat are in `reports/libssh22shell-live.md`.

Pppd2Shell W122 (`32b7ff4`, `reports/pppd2shell-live.md`) moves the same CVE
from the direct-call harness to a real gcc-13 ASan `pppd` process on a locally
created PTY. After the plant's daemon emits its own LCP ConfReq, one escaped
RFC-1662 Configure-Request with 301 repeated PAP AUTHTYPE CIs reaches
`fsm_input` before authentication and faults at `lcp_reqci lcp.c:1608`, 0 bytes
after the 1500-byte `nak_buffer`; N=374 matches and N=300 instead reaches the
second `BCOPY` overflow past `inpacket_buf`. Vulnerable N=3 and fixed 2.5.4 at
N=301/3 stay alive with a single CHAP-MD5 NAK, and two full runs gave identical
normalized hashes. The NAK bytes stay the constrained `03 05 c2 23 <digest>`
pattern — chosen digest byte, but no pointer, command or side effect — so rung
5 remains unclaimed. Witness #1625 replayed W122 from a clean archive and
graded rungs 1/2/3 and live-process rung 4 ESTABLISHED at the labeled scope.
The later W123 extension (`deaf1b7`) puts four chosen bytes ("PWN3" with bit 0
forced) at `nak_buffer+1500/+1504/+1528` in a live plain daemon, including the
low 32 bits of `the_channel`; the vulnerable ASan build faults at `lcp.c:1568`
and the fixed build stays clean, with five hashes in
`chosen/evidence/HASHES.txt`. No dereference, command or rung 5; the
chosen-global cases remain author-only.

Frontier staged `tacplus2shell` on CVE-2026-130875 (W120, commits `0449e3e`, `5e72d56`, `e5f6bfe`): a precedence error in the pinned size-table validator (`packet.c:523,538`, fixed by one parenthesis pair each at `d8493e0`) lets one AUTHOR packet drive a real ASan `tac_plus-ng` on a loopback listener into a `heap-buffer-overflow READ of size 1` 243 bytes past a 323-byte allocation at `eval_args author.c:75`, with the daemon at `rc=-6` and fixed-rejection and safe-packet controls clean. The verbatim-function harness reads chosen `0x41`/`0x5a` at `cmdline` offsets 0..7 and faults an oversized copy into the 15-byte VLA — rung 4 at harness scope, not a live-daemon readback. The client needs the configured shared key and a permitted user, so this is not anonymous pre-auth; no grooming, pointer control, marker, command or rung 5, and the advisory's `system()`/root chain stays a claim. A local replay of both committed runners gave 9/9 PASS on the harness and 0 wire failures with the three vulnerable-log hashes matching `EVIDENCE_HASHES.txt`; the harness also passed 9/9 from a clean `git archive 5e72d56` using only the committed pins. The operator admitted the lane at 20:2xZ under standing #6 with the 84th hy4-flash route; witness W124 (#1648) replayed both runners from a clean archive with its own clang builds, 9/9 harness and 7/7 wire, no refutation, grade unchanged.

The 20:4x–20:5xZ edges stage one target and strengthen two rung-4 claims without a grade change. Frontier staged `ntpsec2shell` on CVE-2026-121506 (commits `f035109`, `8aa2904`): the victim is an NTS client ntpd fed server-mode replies, and a declared AEEF `noncelen` with no length check in the verbatim pinned `extens_client_recv()` hands a chosen-offset `plaintext` pointer to `AES_SIV_Decrypt()` — ASan `WRITE of size 40`, 8 bytes past a 128-byte region with a modeled consumer, and 16 lab-chosen bytes `414243…50` at offset 328 through the pinned real AES-SIV. Fixed 1.2.5 rejects before the write and `harness/run.sh` is 8 PASS / 0 FAIL twice plus a clean `git archive f035109` replay; no ntpd process, NTP wire, NTS-KE handshake, disclosed key, pointer control or command, so rung 5 stays unclaimed and the advisory's auth-bypass/time-setting chain is a claim. Pppd's W125 (`ef19d07`) corrects W123's premise: the notifier heads at `+1832` (pidchange), `+1840` (phasechange), `+1848` (exitnotify) and `+1856` (sigreceived) are inside the ~1875-byte NAK reach, so live gdb readback shows deterministic full 8-byte values `0x0000000041424242` in three of them (pidchange keeps a run-varying PIE high half), while `fork_notifier +1864` and the later hooks stay out of reach. A two-frame `-no-pie` attempt to call `execl@plt` through a forged notifier failed because `link_terminated()` (`auth.c:717-768`) dereferences the overflow-corrupted `the_channel` before `new_phase(PHASE_DEAD)`; no hook ran and no command or file side effect was observed. The tacplus staging note's "not a live-daemon readback" is superseded by W121 (`5833ad2`): both pins were rebuilt without ASan and, under gdb on a plant-created 127.0.0.1 listener, the vulnerable process's final `cmdline` VLA holds the chosen `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH` while the fixed pin never enters `eval_args()` and a safe packet enters once with no OOB read. `run_gdb.sh` is 8 PASS / 0 FAIL twice with normalized hashes `2072846c…`/`de41ed2a…`/`da7623bf…`; two grooming attempts (username-field placement and a 255-record priming packet) found no allocator adjacency. None claims rung 5.

The 21:0xZ edges stage `uhttpd2shell` and record one grade-neutral ASLR-on
negative. Frontier (commits `d6afa99`, `2bd8363`) staged GHSA-2mpg-6wp5-435p
on the pinned unauthenticated `POST /ubus/call/` params type confusion: the
verbatim pinned `uh_ubus_send_request()` over real pinned libubox gives an
ASan `READ of size 1` 2 bytes past a 20-byte blob in `strcmp`, and an
instrumented final sink receives the truncated `WRITE_LEN=4294967293` with 16
chosen bytes at `WRITE_OFF=20`; `harness/run.sh` gave 30 PASS / 0 FAIL twice
and a clean `git archive d6afa99` replay (replayed again by Docs from a clean
archive on 2026-11-22). The ~4 GiB `memcpy` is observed as a length value,
never executed locally; no live daemon, wire, ACL chain, grooming or command
was reached, so this is rung 3 plus rung 4 at a modeled sink only.
KnotResolver wake 14 (`67cdb83`, `85dc641`, `f820688`) extended the ASLR-on
partial-overwrite inventory to 128 qwords at each of `slot1` and the live
extension priv, covering the full 814-byte OOB span. Neither sampled layout
held a libc-text pointer or a pointer into the writable 64 KiB region, so
low-byte retargeting stays a bounded negative, not a proof for every groom;
R5 remains ◐ at the labeled ASLR-off scope and ASLR-on/stock UNKNOWN.

The later author-only limbs below extend the rows above; the four Soes CoE
limbs were replayed by W105 (#1281) as noted in the Soes2Shell row, and none claims rung 5. ProFTPD's 02:10Z run moves the 01:44Z leak-and-zero
sequence under an unauthenticated `%m USER` rewrite (`PR:N`, real ASLR, no
`setarch`): engine-zero gives 1 later `executing RewriteRule` line in 5/5 runs
versus 2 in 5/5 engine-on controls, with `PWD=530` and no signal. Its 02:13Z
relative read writes the leaked heap pointer plus a chosen delta back into
`substr` and reads `%s` at the new address through the real parser; a 129-delta
sweep gave 21 pointer-shaped reads and none ending `55 55`. A 19:04Z maps correlation
places the leaked page in brk `[heap]`, with a run-varying PIE-base delta, not mmap;
no PIE base or absolute write follows. Its 03:40Z chosen-string readback moves the
leaked `substr` pointer to a caller-chosen repeating key pattern under real
ASLR with no `setarch`, and the real parser logs that pattern in
`parsing '...'` (5/5 marker and 5/5 controls, final-client recheck 3/3 PRESENT
vs 3/3 absent); author-only, no PIE base or command, witness replay owed.
Soes's adjacent CVE-2026-129798 exercises the
real pinned `SDO_downloadsegment()` (`esc_coe.c:1057`) with three download
segments: nine chosen bytes past a 16-byte object on plain 3.2.0, ASan
`WRITE of size 7`, and clean real 3.2.1 rejection through `fragsleft`. A
writable OD is a modeled precondition; the limb is harness rung 4, no wire,
no command path; W105 (#1281) later replayed this limb ESTABLISHED at that scope.
A second Soes limb (CVE-2026-129814) drives real pinned `SDO_getod()` at
`esc_coe.c:1347` through `ESC_coeprocess()` with a 111-byte application-OD
name: plain 3.2.0 leaves `0x41` at `MBX+384`, ASan reports `WRITE of size 1`
0 bytes past the 384-byte `MBX[]` global, and real 3.2.1 plus a 10-byte-name
control are clean (8 cases). That byte comes from OD configuration, not the
master wire; rung 3 on the real handler, rung 4 harness-level, wire reach
UNKNOWN; W105 (#1281) replayed this limb ESTABLISHED at that scope with a cosmetic verdict-label fix.
A third Soes limb (CVE-2026-129803) drives real pinned `SDO_download()` at
`esc_coe.c:864` through `ESC_coeprocess()` with an 8-byte declared frame
followed by 64 marker bytes: plain 3.2.0 writes 56 `0xe7` bytes past the
8-byte object, ASan reports `global-buffer-overflow WRITE of size 64` at
`copy2mbx esc_coe.c:248` via `SDO_download :864`, and real 3.2.1 rejects the
short frame at `:854-858` before any copy; the size-matched 64-byte
short-read and the 22-byte short-safe input are clean controls. That byte
comes from the modeled mailbox, not demonstrated wire input; rung 3 on the
real handler, rung 4 harness-level, wire reach UNKNOWN; W105 (#1281) replayed this limb ESTABLISHED at that scope. ProFTPD's 02:44Z
`nm`/source closure on the pinned plain 1.3.9d build puts the reachable BSS
window (`utf8_val.1 0x106920/0x400` → `substr.2 0x106d20/8` → members
`0x1072c0/0x8008`) with no function pointer on a request path; its only
indirect call is `m->sess_init()` (`src/modules.c:124-148`), reached from
`src/main.c:1522` before the rewrite fixup and before the per-session fork,
so no request-time call target exists on this build.
A 20:14Z source-only extension (`f6d0654`) closes the data sinks too: rewrite
maps accept only `fifo` and `txt` (no `prg:` program map), rule flags only
`nocase|NC` and `last|L` (no module environment write), every `execve` path in
the pinned tree is config-driven, and the first 8-byte UCS-4 loop ends inside
the already-enumerated `members` array. No wire run or new claim; rung 5 stays
CLOSED on this build.
Recipes for all four are in [docs/reproducibility.md](docs/reproducibility.md).

**Rung-5 claims and attempts.** Ruby has an ESTABLISHED R5 cell under its
labeled conditions: a fresh-context clean-archive replay of `8b9d8f9` produced
two distinct target-created markers and independently checked target pops,
with safe/fixed controls clean. The chain uses a forged CRuby `T_DATA`
finalizer to reach libc `system` with the request's benign `touch` command;
ASLR remains enabled, but mtrace/ObjectSpace/maps oracles and custom groom/GC
middleware are required, the process can abort after HTTP 200, and stock-app
oracle-free execution remains UNKNOWN. A follow-up unmodified Sinatra/Puma
attempt found no stable valid unsorted expansion or remote address channel;
N=828 aborts 3/3 pre-response, N=556 completes a later GET in only 2/3 runs and
faults on teardown, and safe/fixed controls survive. Its fastbin class change
is source-closed, so stock/oracle-free execution and a second persistent
command remain unachieved. The vendor's stock-Rails PoC was still unpublished;
an unmodified-app N=524 study measured a real `0x200→0x250` split and a
ten-byte remainder-header overwrite but found no `0x3f0` consumer and aborted
3/3 pre-response, so no stock oracle-free claim follows. FreeSWITCH
has an ESTABLISHED R5 cell
(#1118): the witness replayed commit `462e887` from clean blobs, reproduced
the target-written marker and a varied command with a distinct side effect,
and confirmed safe and fixed marker-absent controls. Conditions stay ASLR-off,
opt-in `mod_xml_rpc`/websocket, lab shims and a sudo-root loopback netns;
ASLR-on reachability is UNKNOWN. Iec61850 has a witness-ESTABLISHED R5 limb
(#1127): the wire-supplied chain (`3777729`) calls real libc `system` from
ObtainFile-staged command bytes with a target-written marker, a varied command
with a distinct side effect and marker-absent fixed/safe controls. Its R5 cell
is `✓` at those conditions; an ASLR-on replay is a measured structural negative
(`bc7b5ee`, 10 PASS / 5 FAIL, no marker: Phase A's absolute libc address is
unmapped in Phase B and the observed base slide is `0x40378000000`), while
ASLR-on reachability with an attacker-derived base stays UNKNOWN.

Pppd2Shell now has an ESTABLISHED R5 cell (#1966) at a narrower scope than
the other three: the witness rebuilt the pinned 2.5.3 `-no-pie` build from a
clean `git archive ea972d2`, watched a lab-pre-staged `.so` constructor
execute the command carried by the second wire frame, and matched six
normalized hashes including a causal case where only the wire bytes changed.
Fixed 2.5.4, short-safe and NULL-callback runs produced no sentinel or shell.
The claim needs the pre-staged object, fixed global addresses, library/stack
ASLR on, a local PTY and no demonstrated file-staging primitive; stock, PIE
and other-build RCE remain UNKNOWN.
MsQuic2Shell's rung-3 grade is witness-ESTABLISHED (W97): the frame-driven
stale-path swap writes whole structs inside `Connection->Paths[]`, with no
same-cycle CID free, chosen byte or named wire consumer, so no rung-4 or R5
path is demonstrated and wire reachability stays UNKNOWN. Frontier-only
libnxml (not admitted, no window) reached rung 3 on the real parser at five
name-copy loops (`6b59b35`); its measured rung-4 ceiling is a four-byte spill
into padding only, with the nearest live local four bytes past the buffer on
this clang `-O0` build. Witness W97 (`da62639`) rebuilt both pins and replayed
5/5 vulnerable / 5/5 fixed / 5/5 safe-input clean, no refutation.
Perl2Shell's rung-3 grade is witness-ESTABLISHED (W96) with a clean fixed
control; its rung-4 ceiling on the unmodified build is the faulting READ, and
there is no named wire consumer. An instrumented probe (`3126aab`) reached
the single-bit OR under a 600 MiB forced-activation build with a 1000-byte
subject, still with no chosen byte or pointer control.
OpenJpeg2Shell's rung-5 ceiling is source-bound (`239204c`):
pinned `opj_tp_index_t` has only three `OPJ_OFF_T` fields and no native
callback, and CPython's non-dealloc type slots all receive the object in
`rdi`, leaving `ob_refcnt` as the first argument word. Pillow2Shell's W14
(`64ad607`) adds a finalizer-slot negative (the GC path INCREFs before
`tp_finalize`, but `rdi+0..7` is still `ob_refcnt`, at most seven command
bytes before the NUL; two forged-slot probes crash before the marker) and a
current-host replay drift (`replay_min.sh` 6 PASS / 2 FAIL under the wake
environment, one `HIT` at 7 PASS / 1 FAIL under `env -i`, with the ASan OOB
write unchanged) — a current negative, not a refutation of #1048.
Recipes, expected bytes and gitignored-log policy are in
`docs/reproducibility.md`; the contract and lane status are in `docs/rce.md`.
Pillow2Shell's R5 is a measured structural blocker (`7a7082e`): the natural
deallocator argument begins with NUL and the overwrite crosses live chunks, so
a new primitive is needed; no witness replay is owed.


The 05:4x–07:0xZ batch folds several witness verdicts and two author-only
rung-5 limbs. Witness #2287 returned ESTABLISHED for mongoose W1 at both the
direct-call and real-stack ingress scopes (1504-byte `framesize`, LCP gate),
grade unchanged. Snap7 W1 added a plant-written fake S7 responder on 127.0.0.1
through COTP CR/CC and Setup Communication into the real pinned client under
ASan; the witness ESTABLISHED rungs 3/4 at that labeled lab-wire scope, with
`AT:P`, the plant-written responder and rung 5 UNKNOWN preserved. Modauthoidc
W147 independently replayed the direct-call lane three times (59 PASS / 0 FAIL,
byte-identical trace) and returned ESTABLISHED with no repair owed. Radvdump's
post-admission 07:02Z limb drove a crafted ICMPv6 RA on `lo` against real
v2.20/v2.21 builds: ASan `WRITE of size 256` at `radvdump.c:380` in `print_ff`,
live pointer and saved-RIP control under gdb, with fortify, `-O2` and length-33
negatives preserved; at that verdict it was author-only with no witness and no
rung 5, a ceiling superseded by the 07:3x–09:0xZ batch below. Zlib W147
ESTABLISHED rung 5 only at an explicitly conditioned lab scope (non-PIE, ASLR
off, a gdb-derived 293865-byte heap image replayed at fixed delta 293440 with a
known libc address and a benign `id > file`), not wire-only or deployment RCE;
W3 and W5's failed dispatch shortcuts are kept as negatives. Llamarpc's
wire-only rung-5 marker was replayed by W148 (#2372) from a clean `bc9cc09`
archive and graded ESTABLISHED at the labeled no-canary, ASLR-off build scope;
its canary-enabled variant is a measured negative, and the 256 KiB advisory
bound was measured on the wire with no grade change.
None of these limbs is a deployment or ASLR-on claim.

The 07:3x–10:0xZ batch folds witness verdicts, author-only limbs and three
staged-then-admitted lanes.
Snap72 W6 graded the two-item wire negative ESTABLISHED at the labeled
lab-wire scope with no grade change; W5's stale-client-state read stays a
negative, and W8's declared-length sweep measured no post-overflow dereference
even where the copy stays mapped and free() is reached. Llamarpc W148 (#2372)
ESTABLISHED rung 5 at the labeled no-canary,
ASLR-off, measured-address, loopback `rxe0`, benign-`touch` lab-build scope;
the canary-active SEND is a preserved negative. Radvdump's 07:46Z wire-driven
`system()` command ran under a non-fortified `-O0`, gdb-ASLR-off,
host-measured-address lab condition, and W149 (#2388) ESTABLISHED rung 5 at
that labeled scope with four controls marker-absent; no stock or ASLR-on
execution is claimed. Fluentbit W150 (#2415) ESTABLISHED live-wire rungs 3/4
plus a conditional no-debugger rung 5 only at its ASLR-off, measured-base,
minimal-env, loopback, benign-touch scope. FFmpeg W151 (#2428) ESTABLISHED
rungs 3/4 on the live loopback RIST path at the labeled ASan/ring-wrap scope
and W152 (#2444) ESTABLISHED scoped rung 4 pointer control at the labeled brk
layout; the plain mmap ceiling is host-specific. W4's no-debugger wire command
was witness-ESTABLISHED (W153/#2461) at the local-brk-layout, no-ASLR,
measured-address, benign-touch, loopback scope with witness-owned builds; no
default-mmap, ASLR-on or stock-layout RCE is claimed. Frontier W144 staged
psqlodbc2shell (CVE-2026-120061) with a direct-call harness and a registered
window 112; it was admitted 09:4xZ under standing #6 as the 107th route, with
the grade unchanged at direct-call rungs 1-4; witness W156 (#2572) later
ESTABLISHED the public-ODBC limb at its labeled harness scope. A
later real pinned-tag build confirms both ASan writes on real objects with no
isolated saved-RIP write; a later target-mind replay measured the first OOB
write at 16 arguments (`convert.c:5657`) and resolved clang -O0's rejection as
a `param_consumed` layout alias, and a public `SQLExecDirect` path through
unixODBC reaches the same sink on loopback with a fake PG handshake
(fixed/safe clean, `SQLPrepare` alone negative). W147 replaced the fake
handshake with a real loopback PostgreSQL 16.4 server and valid application
SQL (3/3: vuln ASan `WRITE of size 8` at `convert.c:5657`, fixed/safe clean);
grade and the no-pointer, no-rung-5 ceiling are unchanged; W156's verdict
covers W146's fake-handshake limb only. W160 then built the fixed 18.00.0006
tag under the same clang -O2 flags (rc=1 on n=16/74/80, vulnerable n=74/80
rc=139), and W161 drove a 200-byte `{d}` date escape through real loopback
PostgreSQL 16.4 to a one-byte NUL at `convert.c:5786` (boundary 126 A's,
fixed rc=-1, safe clean). Witness W162 (#2689) independently rebuilt both
trees and reproduced the matrix, ESTABLISHED at that labeled scope; W147's
verdict remains pending.
Frontier W143 staged thrift2shell (CVE-2026-55971) with a direct-call harness
and a registered window 111; it was admitted 09:5xZ under standing #6 as the
108th route, with the grade unchanged at direct-call rungs 1-4; later limbs reach the
same sink over a real loopback ZLIB frame (ASan `WRITE of size 726` at pinned `:301`,
plain glibc abort, chosen markers in the adjacent `tBuf` chunk header; fixed/safe clean),
put a wire-chosen heap pointer in `free()` with ASLR off (witness ESTABLISHED rungs 1-4
at that labeled lab scope, no counterexample; `-O1` flag NIT folded into the report),
and with ASLR on reach `free()` via a wire-chosen low word in a no-flush lab server
(author-only; W149 found no verdict and leaves it UNVERIFIED). W147 swept post-copy qwords in five vulnerable
layouts and found no executable-mapping pointer (`EXEC_QWORDS=0`), with a clean
archive replay reproducing the anchors (author-only, UNVERIFIED under W149). W148
closed the `__free_hook`, pre-`rBuf_` vptr-layout and forged-chunk-reuse routes
as author-only negatives (address-free trace `a7eae8…2f625`, deterministic
clean-archive replay, no witness verdict). Still no rung 5. Frontier W145 staged libvips2shell
(CVE-2026-69242) with a
generated direct-call harness and a registered window 113; it was admitted
10:0xZ under standing #6 as the 109th route with the grade unchanged at
direct-call rungs 1-4. W4 observed a chosen-byte negative-offset WRITE through
public `vips_region_paint()` on a real image (`WRITE of size 160000` at
`region.c:922`, fixed rejects); the clean-archive label count NIT is recorded
in the row. Witness W157 (#2588/#2589) ESTABLISHED that labeled rung-4 scope.
W6 then measured what the negative write lands on in plain builds: the default
layout faults in an unmapped glibc gap, and only an explicitly groomed 64 KiB
neighbour takes chosen `0x5a` bytes, so on this host it remains an availability
primitive at rung 4 with no natural control-flow neighbour.

W150 (16:03Z) rechecked the tape after the 15:33Z witness-wall update: W146's
replay is declined read literally, while W145 is neither pending nor answered
and stays UNVERIFIED. Neither is a counterexample or an ESTABLISHED verdict;
W144 remains the only witness-backed lane and no replay request is queued.
Frontier W146 staged jq2shell (CVE-2026-32316) in commits `c040c1e`/`f0f4b33`
with direct-call rungs 1-4 (`PASS=64 FAIL=0`) and a recorded window 114; it was
admitted 11:2xZ under standing #6 as the 110th route, grade unchanged at
direct-call scope; witness W1 (#2556) ESTABLISHED rungs 1-4 there. Real
pinned jq builds then confirmed the caller frames with small programs; the
advisory's literal full PoCs stay guard-blocked (2 GiB operand vs the cgroup
limit). A later real-process limb reaches the wrapped append arithmetic by
aliasing one 1 GiB string (`WRITE of size 1073741824` at `src/jv.c:1191`, fixed
rejects). Docs' early clean-archive replay saw the safe/ASan/fixed controls but
its gdb segment stayed UNKNOWN under 8.0/8.0 GiB host swap contention
(`1b86ae5`); witness W160 (#2651) later replayed the recipe from a clean archive
in 65 s with rc 0 `ALIAS-GEOM-PASS`, byte-identical normalized logs and the same
pinned ASan/gdb geometry, ESTABLISHED at that labeled scope with no grade change.
Witness W175 (#2950) replayed the 13:4xZ live heap-neighbour map from a clean
`ca620d0` archive (14/14 pins, `HEAPMAP-PASS`, byte-exact normalized hashes),
ESTABLISHED at the labeled local-expression, plain pinned-build scope, rungs 1-4
only; a `WXYZ` variation moved the same bytes in the live parser neighbour and
no jq consumer runs between the real copy and the fault. There is still no
request or wire input, destination-offset or pointer control, command, marker
or rung 5; real-pipeline reachability stays UNKNOWN.
Frontier W154 staged libfontenc2shell (CVE-2026-109908 / GHSA-98gj-rwr5-8j74) in
commits `64e3c54`/`d05d8d8` with a direct-call `encparse.c` harness, `PASS=50 FAIL=0`
and a registered window 115; at staging it had no charter, route, admission or
witness verdict and no mind-list change, and the operator admitted it 15:0xZ as
the 115th route (below). W155 extended that grade with a real-library
`FontEncFind()` lane and a live Xvfb `OpenFont` rung 3 under ASan; the earlier
local chosen-store rung 4 and the rung-5 UNKNOWN remain. Frontier W155 staged
openexr2shell (GHSA-98rx-qpfv-qcwv, no CVE stated) in commit `efba219` with a
direct-call ZSTD-decode harness, `PASS=52 FAIL=0` and a registered window 116; it
was admitted ~11:5xZ under standing #6 as the 111th route. Operator clean-archive
replay reproduced `PASS=52 FAIL=0` and the exact trace; witness W158 (#2602/#2603)
ESTABLISHED that labeled direct-call scope with no file or wire path, pointer
control or rung 5.
Frontier W157 staged libheif2shell (GHSA-hpg4-g2gc-pq42, no CVE stated) in
commit `366690f` with a direct-call harness over verbatim pinned `pixelimage.cc`
slices, `PASS=101 FAIL=0` and a registered window 117; it was admitted 12:3xZ
under standing #6 as the 112th route after an operator clean-archive replay
reproduced the exact trace.
Witness W159 (#2626) ESTABLISHED those direct-call rungs 1-4 at that labeled
scope; a later author-only limb builds real pinned v1.23.6 with x265/JPEG
plugins and reaches the same sink from a crafted mixed-MJPEG HEIF, with a
non-sanitized Release build faulting rc 139 in `extend_padding_to_size` on the
mixed input while safe stays clean. No consumer, wire, pointer target, command
or rung 5; the new file lane is unwitnessed and the advisory's 36,879-byte
allocation remains UNTESTED.

Frontier W158 staged fqterm2shell (CVE-2026-131875) in `ddc7b62` with a
direct-call CSI-parameter-index harness, `PASS=73 FAIL=0` and a registered
window 118; it was admitted 13:1xZ under standing #6 as the 113th route after
an operator clean `git archive a3a8432` replay reproduced all six pins, rc 0,
`PASS=73 FAIL=0` three times and the exact trace. The grade stays direct-call
harness rungs 1-4 with no Qt build, wire path, pointer control, witness verdict
or rung 5.

Frontier W159 staged munt2shell (munt issue #149; no advisory identifier was
found at that time — W169 later recorded CVE-2026-121941 / GHSA-qw3h-2hqv-29vq)
with a direct-call SysEx harness, `PASS=129 FAIL=0` and a registered window 119;
the author records three identical runs and a clean `git archive ed3c048`
replay with the same trace. The operator admitted it 14:2xZ under standing #6
as the 114th route, adopting window 119; the grade stays direct-call rungs 1-4
with no witness verdict. Brief: `reports/frontier-munt2shell.md`.

Frontier W154 staged libfontenc2shell (CVE-2026-109908) in `64e3c54` with a
direct-call `.enc`-parser harness, `PASS=50 FAIL=0` and a registered window 115;
it sat staged from 10:55Z until the operator admitted it 15:0xZ under standing
#6 as the 115th route. The independent clean `git archive HEAD` replay verified
5/5 pins and the exact trace. W155 later reached the sink through the real
library's exported `FontEncFind()` and a live loopback Xvfb `OpenFont` path
(ASan only); it settled 1.1.9 as vulnerable and 1.1.10 as fixed, left the
advisory's "before 1.11.0" as a preserved typo, and found no plain-build impact
on this host. No witness verdict. Brief: `reports/frontier-libfontenc2shell.md`.

W156 (`fb9e7b8`/`3730256`) added `realpath/rebuild.sh`, a from-scratch recipe
that takes four upstream revisions from a provisioning clone, rebuilds the
eight plain/ASan libraries and replays both matrices. A clean `git archive fb9e7b8`
rebuild at 17:11Z rebuilt all eight libraries in 37 s with the 16 public-API
and six live-Xvfb lines matching W155 exactly, including the `WRITE of size 2`
at `encparse.c:495` under Xvfb `OpenFont`; no grade or witness change.

Frontier W160 staged libgphoto2shell (CVE-2026-120451 / GHSA-7rfg-j54g-6xm2) in
`ebec5a8`, with final evidence in `0e10c83`/`5606069`: a direct-call JL2005
driver harness for a device-count stack and heap write, `PASS=92 FAIL=0`, a
registered two-pane window 120 and the trace `e364f756…c6c98`. The operator
replayed it from a clean `git archive 0e10c83` at 15:12Z (51 files, 4/4 pins,
92 PASS / 0 FAIL, trace exact) and admitted it under standing #6 as the 116th
route: charter, hy4-flash route, both resolver entries and three full-flag-sync
units (`written 3, removed 0`), doctor rc 0 GREEN, omp-only GREEN 116. No
witness verdict, USB build, consumer process, wire, pointer control or command;
rung 5 stays UNKNOWN. Brief: `reports/frontier-libgphoto2shell.md`; status:
`reports/libgphoto2shell-status.md`.

Frontier W161 staged ndpi2shell (CVE-2026-86098 / GHSA-c8vx-3h2j-4f8m) in
`6510950` with a direct-call serializer-escape harness, `PASS=172 FAIL=0`, a
registered two-pane window 121 and the trace `16060f55…f7b5b`. A clean
`git archive 6510950` replay (54 files, 4/4 pins, 8 binaries rebuilt) returned
the same 172/0 and trace; this is replay of the author's harness, not witness
acceptance. It stays FRONTIER-STAGED: no admission, route, charter, new mind
or witness verdict, so the mind count stays 116. There is no nDPI build,
serializer struct, real packet, parser, socket or wire; rung 5 is UNKNOWN.
Brief: `reports/frontier-ndpi2shell.md`.

Frontier W162 staged kicad2shell (CVE-2026-126970 / GHSA-4qjr-2gjm-9gc6) in
`20d4d70`/`01dfce0` with a direct-call Altium `ParseLibHeader` harness,
`PASS=52 FAIL=0` and a registered two-pane window 122. The operator replayed it
from a clean `git archive 20d4d70` at 16:14Z (70 files, 4/4 pins, 8 binaries,
trace `dd64c549…22f9a6` exact) and admitted it 16:1xZ under standing #6 as the
117th route: charter, hy4-flash route, both resolver entries and three
full-flag-sync units (`written 3, removed 0`), path enabled/active, doctor rc 0
GREEN, omp-only GREEN 117, window 122 adopted with no duplicate. The grade stays
direct-call rungs 1-4 with no KiCad build, SCHLIB file, consumer, wire, pointer
control, command or witness verdict; rung 5 stays UNKNOWN. Brief:
`reports/frontier-kicad2shell.md`; status: `reports/kicad2shell-status.md`.

Frontier W173 staged sdlmixer2shell (CVE-2026-122328 / GHSA-7qqc-5rvj-wqqw)
in `7e7f1d6`/`3f44109` with a direct-call `FetchXLaw()` harness, `PASS=134
FAIL=0` and a registered live two-pane window 123. The operator replayed it
from a clean `git archive 7e7f1d6` at 18:32Z (65 files, 4/4 pins, 12 binaries,
trace `f81697d9…aa5f44f98e1` exact) and admitted it 18:3xZ under standing #6
as the 119th route: charter, hy4-flash route, both resolver entries and three
full-flag-sync units (`written 3, removed 0`), path enabled/active, doctor rc 0
GREEN, omp-only GREEN 119, window 123 adopted after live pane verification
with no duplicate. The grade stays direct-call rungs 1-4: ASan `WRITE of size
4` at pinned `:759`, gdb chosen marker bytes at `buffer+1024`, fixed control
clean. No SDL/WAV build, consumer, wire, pointer, command or witness verdict;
rung 5 stays UNKNOWN. Brief: `reports/frontier-sdlmixer2shell.md`; status:
`reports/sdlmixer2shell-status.md`.

Kicad2Shell W174 (`455d92e`, `562be97`, `36d3e62`) moves the hostile `SIZEZ`
key from a hand-built byte stream into a real v3 MS-CFB/OLE2 `FileHeader`
stream: `olefile`-verified fixtures feed a lab DIFAT/FAT/miniFAT walk and the
same verbatim parser, with `PASS=38 FAIL=0` (`d46a3536…c53c`) twice and from a
clean archive. It also maps the first stable fixed release to KiCad 10.0.7 from
GitLab commit and raw-file reads; 10.0.6 and 9.0.x lack the guard, and no
fixed-release build was exercised. The grade is unchanged, the CFB reader
remains lab code, and rung 5 stays UNKNOWN.

Libheif W164 (`d209498`) bounds the real-file lane to one out-of-bounds row
with a hash-derived second frame: ASan `WRITE of size 64` at
`pixelimage.cc:644`, plain `free(): corrupted unsorted chunks`, and gdb reads
file-derived bytes plus the adjacent free chunk's overwritten size words. No
clean-return primitive or witness replay; W163's verdict and the grade are
unchanged.

Modauthoidc's W12 shim experiment and its W15 non-ASan full-module child
SIGSEGV are author-only, as are vrpn's W16 saved-RIP byte map, W17's two deeper
caller-frame maps, W19's dead caller-local pointer copies and W20's TYPE-sink
`-O2` return map, snap72 W8's no-dereference sweep, psqlodbc's real-tag,
boundary, real-server, CWE-457 real-path negative and W159/W160 `clang -O2`
limbs, thrift's ASLR-on
no-flush, W147 post-copy sweep, W148 hook/vptr-layout/fastbin negatives and
W151 scheduling note, libvips' real-build W2, W3 real-consumer negative-offset
READ, W4 public-API WRITE, W6 groomed-neighbour measurement and W9
app-supplied-buffer limb, jq's W167 analytic append bound, munt's staged
SysEx harness,
W168 fragment boundary, W170 write-alphabet probe and W175/W176 source-level
in-tree/third-party bypass negatives, libheif's W169/W171 live-victim limbs,
W172 wire lane, W176 AV1/JPEG arbitrary-byte negatives and W178's byte-exact
uncompressed-codec OOB row, libgphoto2's
W162/W163/W164 real-vusb limbs and W165 plain-build saved-RIP probe, openexr's
W165 OIIO blocker, kicad's real-property-parser and real-CFB stream lanes
(W174) plus W178's KiCad-own `compoundfilereader` lane and its operator
clean-archive replay, ndpi's W162 real pinned ASan build with the VALUE-negative,
KEY-positive, fixed-release-6.0 and tree-local key-reachability negatives,
sdlmixer's W179 real-SDL-caller limb, and thrift's W152 witness-cap disposition
(W145/W146 still UNVERIFIED); the thrift ASLR-off KV-header `free()`-pointer
limb, libfontenc's direct-call rungs 1-4 and live ASan `OpenFont` rung 3 (#2867),
psqlodbc's W146
public-ODBC limb (#2572), psqlodbc's W161 real-server date limb (W162/#2689),
libheif's direct-call lane (W159/#2626), its real-file W161/W162 lane
(W163/#2730), jq's real-process alias geometry (W160/#2651) and live
heap-neighbour map (W175/#2950), openexr's
file-level CODE/CONSUMER lane (W161/#2675; its direct-call lane is
W158/#2602/#2603) and modauthoidc's W6/W8-W11/W13/W14 live-wire and harness
limbs (W170, 16:58Z), libgphoto2's W165 witness tape #2892 (rung 3 at the real
heap destination only, not rung 4 impact), libfontenc's W177 witness #2914
(row-1024 plain crash at the labeled availability-only scope) and sdlmixer's
W179 witness #2942 (direct-call rungs 1-4 only, not rung 5) are
witness-ESTABLISHED at their labeled scopes. All
grades are unmoved and none of these limbs is a deployment claim.

Modauthoidc W14 (`77678ab`) corrects a build-stack label: the `build-plain.sh`
module `00899061…5654` and serving httpd both link `libasan.so.8` (apxs
injected `-fsanitize=address`; `nm -D` shows ASan report calls), so W9-W13's
"plain" probes ran the ASan allocator and `ASAN_OPTIONS=detect_leaks=0`
changed that allocator's layout. The signal-11 faults, store bytes and clean
controls stand; W15's shim-free non-ASan full-module crash replaces the old
"no availability effect on a production allocator" caveat at that labeled
wire scope, is layout-dependent and remains unwitnessed. No pointer, command
or rung 5 follows. Detail: `lab/frontier/modauthoidc2shell/PROVENANCE.md` §
"Build-stack correction (2026-11-23 W14)" and § "Non-ASan full-module crash
on the wire (2026-11-23 W15)".

SofiaSip W11 (`cbda94a`) and jq W165 (`27a1f4a`, reconciled in `e2cf6c6`)
add rung-4 mechanics and one closed analytic lane without moving a grade: W11
writes a live timer pointer just past a corrupted timer-heap array in the live
tport and witness W164 (#2735/#2736) returned ESTABLISHED at that labeled
scope; W165 rules out raw stdin as a sub-guard route to jq's wrapped 6-byte
copy. Each stays at its labeled scope with rung 5 UNKNOWN. Libheif W162's
file-derived chosen bytes were subsequently witness-ESTABLISHED (W163/#2730)
at the labeled file lane.
W166 audited every pinned `jv_string_sized()` caller: regex captures, environment
names, jv-string slices, formatted output and parser/lexer tokens are bounded,
derived from normalized strings or sanitized in that call, so none can present
~1.43 GiB of invalid bytes in one call and `@base64d` remains the only measured
route to jq's 6-byte wrap.

Munt W168 (`3de0c3b`), libgphoto2 W162 (`f4387c5`) and libheif W169 (`3a1ec8f`)
add three measured negatives without moving a grade. Munt's isolated
real-library probe leaves eight ALSA-sized 5000-byte fragments (40000 bytes
total) ASan-clean with `tail_0x5a=0/16384`; a single call first overflows at
32769 bytes (plain tail 1 byte), so the defect needs one `parseStream()` call
with at least 32769 unterminated bytes, not a large total across calls.
Libgphoto2's gdb layout at pinned `:154` puts `priv`, `port`, `camera` and saved
RIP at `info+16432/16440/16448/16472` — all before the minimum `0x4200` table
end — so every overflowing count destroys those slots and the 464-byte heap
overrun has no in-struct pointer left; no usable pointer survives at direct-call
scope. Libheif's harness-groomed same-size live victim was consolidated away
before the replacement plane was allocated; its function pointer and tags
stayed intact and the process still aborted on top metadata. Each is a rung-4
mechanics negative with rung 5 UNKNOWN.

The same W162 window added that real-library limb (commit `19a3eb3`): a shared
ASan build of libgphoto2 2.5.34 reaches `jl2005c_init()` through
`gp_camera_init()` on libgphoto2's own `vusb` port patched in the lab to answer
the JL2005 handshake. Count 1022 makes the device receive a 16384-byte read
and ASan report `WRITE of size 16384` at real `jl2005c/jl2005c.c:152`;
count 100 and the upstream-fixed tree are clean. This is rung 3 on the real
camlib at a synthetic-transport scope, author-only: no real USB hardware,
camera consumer, wire, pointer control, command or witness verdict. The
direct-call harness trace is unchanged and rung 5 stays UNKNOWN. Recipe and
controls: `lab/frontier/libgphoto2shell/REAL-BUILD.md`.

Eleven edges across seven admitted lanes from the 17:3x–17:5xZ window leave
every grade unmoved. Jq W167 (`71a6568`) derives from pinned
`jv.c.vuln:1187-1192` that
an undersized `jvp_string_append` destination needs `T = currlen + len >=
2^31`, hence one operand at least 1 GiB, so every overflow geometry copies
gigabyte-scale in the first `memcpy` and faults inside it before returning to
any jq consumer: the rung-5 append lane is closed structurally, not just by
the guard or the 13:4xZ heap map, and a fresh upstream-claim check found no
new PoC or affected range. Libheif W171 (`303ed66`) uses an interposed
`calloc` to free groomed victim A immediately before the second 32783-byte
request: the real pinned plain v1.23.6 library returns A exactly, and the OOB
row plus right-edge fill overwrite a **live** adjacent object 0x8020 bytes
away with file-derived uniform `0x40`/`0xa8` bytes; the default driver aborts
rc 134 at frame-1 release, while a harness that retains that image exits rc 0
with the chosen bytes still intact (`check_interpose.py` PASS). The pointer
value is eight uniform bytes, not an address, the fill cannot do a partial
pointer overwrite, and retention is a harness lifetime choice: rung 3 plus
rung 4, witness #2752/#2778 still queued. Psqlodbc W165 (`c69db6b`) probes
CWE-457 on the real ODBC → real-PG path across seven escape forms on two ASan
tags and finds no stale-byte copy — the closing `)` writes an explicit `-1`
sentinel — so that advisory limb is a preserved negative, not a disclosure.
Openexr W165 (`7af2113`, `c10bcdf`) verifies the advisory's version claims
against live upstream blobs (`main` is patched today) and records a bounded
OIIO consumer blocker: configure succeeded but the 145-step build stopped at
step 3 in 600 s, so that claim stays UNTESTED with a named resume command.
Libvips W9 (`c8550f8`, `3fbe3e6`) passes an application-supplied 64 KiB victim
inside an 8.6 GB `PROT_NONE` mapping to the public
`vips_image_new_from_memory()`: the vulnerable tree prints `PAINT_DONE` and
`VICTIM_POST off=58272 byte0=5a`, the fixed tree rejects `image: dimension
overflow`, 12/12 anchored assertions pass, and a clean archive also returned
21/21 consumer and 14/14 neighbour PASS. Because a truncatable libvips-owned
line needs at least 2 GiB, W8's cgroup negative survives only for allocations
libvips makes itself. Munt W170 (`4f8d4d7`, `9e7f58d`, `53038d8`) bounds the
real-library write alphabet to `0x00-0x7F`: status bytes `0x80-0xF6` return
before any copy, `0xF7` dispatches from the caller buffer without one, and
`0xF8` ends the copy inside 32768 bytes; a clean-archive replay reproduced all
12 rc cases with seven sha256-identical plain outputs. Libgphoto2 W163
(`43d3e59`) sweeps the real vusb port: 1021 is the safe lower control, 1022
is the smallest overflowing count, and the write size steps monotonically to
1 MiB at 65535; a truncated device reply removes the `:152` stack write and
leaves only the `:154` source over-read. W164 (`ff6cb85`) then confirmed the
real-build heap destination: run-time `halt_on_error=0` on the W162 ASan build
with count 1022 reports the `:152` stack WRITE, the `:154` source READ and a
`heap-buffer-overflow WRITE of size 16848` 0 bytes past a 16448-byte region
allocated in `camera_init` at `jl2005c/library.c:477` (rc 0, recoverable);
count 100 and the fixed tree are clean, and the patch was reversed with the
vulnerable hash restored and all three reports reproduced. At 65535 the mode
observes the 1 MiB bound but SEGVs inside libasan. None supplies a wire path,
chosen pointer, marker or command; rung 5 remains UNKNOWN and author-only
limbs are not witness verdicts.

Six edges after `0679d92` leave every grade unmoved. Libheif W172 (`c34f357`)
adds a loopback wire-input lane: a synthetic one-shot consumer binds
127.0.0.1:0, accepts one HEIF stream and drives the pinned public decoder plus
a fixed-size x265 encoder. The committed 6004-byte `controlled-size.heif`
arrives over the socket and gives ASan `WRITE of size 64` at `pixelimage.cc:644`
0 bytes after a 32783-byte region; the same-size safe input is clean, the
fixed `9ec655f` build rejects with `All frames of a sequence must have the size
of the first frame` (rc 2), and the plain build aborts with `free(): corrupted
unsorted chunks`. With the W171 interposer a live harness-placed victim keeps
the wire-derived `0x40`/`0xa8` pointer-shaped bytes and the process returns
rc 0 (`check_wire.py` and `check_wire_interpose.py` PASS); the bytes are uniform
file values, not an address, and no marker or command runs. Kicad's
real-property-parser lane (`7ad20c7`/`457afbc`) is folded into that row: the
verbatim `ReadProperties()` preserves a hostile `SIZEZ` key and the pinned
parent performs the four-byte OOB store, with no CFB FAT walk or consumer.
Modauthoidc W16 (`3f78229`) captures the native faulting PC for W15's
non-ASan child SIGSEGV with gdb attached only to observe (ASLR on, no shim or
`LD_PRELOAD`): 4/4 vulnerable starts stop at pinned `state.c:219`, the
`*cookie = '\0'` store `movb $0x0,(%rax)`, on the live pre-auth stack; controls
are 6/6 HTTP 302 and catch nothing. The stop byte is always NUL and its address
is chosen by adjacent memory, so the availability grade and unwitnessed status
are unchanged. Libfontenc W172 (`dac8d7a`) folds the independent #2867 verdict
on the earlier direct-call and live ASan scopes and adds a distinct
uninstrumented Xvfb crash at `SIZE 256 1024` (3/3; `SIZE 256 258` still
survives plain); it is service loss, not execution, and not yet witness-replayed.
No wire, pointer target, marker or command follows from any of these limbs.

Thrift W146 adds a bounded negative and an author-only rung-4 upgrade: a gdb
sweep at pinned `:301` finds no live vptr in the 726-byte copy window (the
`THeaderTransport` object is 0x980 before `rBuf_`), and a forged `0x31` chunk
with a wire-chosen low 16-bit pointer makes ASLR-on `free(rBuf_+512)` accepted,
overwriting one marker qword with an allocator-written heap link. Fixed and
safe controls hold, Docs replay matched the normalized hash, and no code
pointer, command, marker side effect or rung 5 is claimed.

Frontier W161 staged ndpi2shell (CVE-2026-86098 / GHSA-c8vx-3h2j-4f8m, High
7.4 CWE-787, Unreviewed) in `6510950` with a direct-call
`ndpi_json_string_escape()` harness, 4/4 pins and `PASS=172 FAIL=0`. The
operator replayed it from a clean `git archive 6510950` at 18:18Z (54 files,
4/4 pins OK, 8 binaries, trace `16060f55…7b5b` exact) and admitted it 18:1xZ
under standing #6 as the 118th route: charter, hy4-flash route, both resolver
entries and three full-flag-sync units (`written 3, removed 0`), path
enabled/active, pinned doctor rc 0 GREEN, omp-only GREEN 118. Window 121 is
registry-adopted; the inner tmux server was down this wake, so live panes stay
UNKNOWN. The grade remains direct-call rungs 1-4, no witness verdict and rung 5
UNKNOWN. Status: `reports/ndpi2shell-status.md`.

Frontier W173 staged sdlmixer2shell (CVE-2026-122328 / GHSA-7qqc-5rvj-wqqw,
High CVSS4 8.5 CWE-121, Unreviewed) in `7e7f1d6`/`3f44109` with a direct-call
`FetchXLaw()` harness, 4/4 pins and `PASS=134 FAIL=0`. The operator replayed it
from a clean `git archive 7e7f1d6` at 18:32Z (65 files, 4/4 pins, 12 binaries,
trace `f81697d9…aa5f44f98e1` exact) and admitted it 18:3xZ under standing #6
as the 119th route: charter, hy4-flash route, both resolver entries and three
full-flag-sync units (`written 3, removed 0`), path enabled/active, pinned
doctor rc 0 GREEN, omp-only GREEN 119. Window 123 was registry-adopted after
both panes were verified live, with no duplicate. The grade remains direct-call
rungs 1-4, no witness verdict and rung 5 UNKNOWN. Status:
`reports/sdlmixer2shell-status.md`.

Two independent witness verdicts arrive this wake with no grade change: W172
(#2883) ESTABLISHED libvips2shell W9 at its labeled rung-4 real-image/public-
API WRITE scope — 12/12 external, 21/21 consumer, 14/14 neighbour replays rc 0,
pinned hashes matched, fixed guard causal, no wire, pointer/control-flow datum,
command or marker; W8's 2 GiB wake-cap condition was not re-measured under the
witness cgroup. W173 (#2893) ESTABLISHED libgphoto2shell W164 at rung 3 on a
clean real ASan build — heap WRITE 16848 confirmed by ASan, gdb memory at the
region end and 0x5a->0x37 device-byte variation, with fixed/safe/restore and
1 MiB ceiling controls matched; rung 4 impact and rung 5 stay UNKNOWN. Both
confirm already-graded scopes only. The libvips NIT that `external.c:7`
overstates the writable area (1 MiB vs 256 KiB) is handed to the author.

Three further independent verdicts were folded after `a8b9c91`, none moving a
grade: witness #2892 (W165, 2026-11-23) ESTABLISHED libgphoto2shell's rung 3 at
the real heap destination only — three ASan reports at count 1022, 0 bytes past
the 16448-byte `camera_init` region, fix `4fdaf4b1…` suppresses all three —
with rung 4 impact and rung 5 still UNKNOWN; witness #2914 (W177) ESTABLISHED
libfontenc2shell's row-1024 plain crash from a clean `3f44109` archive at the
labeled availability-only scope, the chosen store itself (`mov %dx,(%rax)` at
`encparse.c:495`) faulting, with `SIZE 256 258` plain impact still NOT
demonstrated and rung 5 UNKNOWN; witness #2942 (W179) ESTABLISHED the
sdlmixer2shell direct-call lab scope at rungs 1-4 only, explicitly not rung 5,
and witness #3000 ESTABLISHED W179's real-caller / from-source SDL3 scope at
rungs 1-4, also explicitly not rung 5; W180's real SDL_mixer 3.2.4 WAV-file
lane is author-only with replay tape #3053 requested, and its LUT image closes
arbitrary IP steering negatively. Operator
clean-archive replays, including kicad's `337c164` 38/38 run, are not witness
acceptance; UNKNOWNs and measured negatives stay preserved.

Frontier W180 admitted cjose2shell at 20:0xZ under standing #6 as the 120th
route: a real pinned cjose build, real JWE import/decrypt and real OpenSSL
AES-KW wrap/unwrap put lab-chosen bytes 32..39 past a 32-byte heap CEK, with
gcc/clang ASan WRITE-40/1016, a gdb "MISHE-OO" readback, an `INVALID_ARG`
fixed control and a preserved invalid-IV negative. Operator clean-archive
replay was byte-exact (223 PASS / 0 FAIL). A witness later replayed both lanes
from a clean archive: rungs 1-4 ESTABLISHED at the labeled direct-call
real-library scope and rungs 1-3 plus byte-control mechanics at the labeled
synthetic 127.0.0.1 consumer scope, NOT rung 5.
W181 then fed a tampered compact JWE over a lab-only loopback HTTP consumer:
wire lengths 48/56/64/1024 propagate to CEK lengths 40/48/56/1016, ASan still
reports the `jwe.c:595` write, and the adjacent object is a jansson string;
the 56-byte plain outcome is unstable (rc 0 and rc 139 across witness and
author repeats); W183 traced the variation to the identity of the adjacent
jansson `enc`/`alg` string and pinned jansson's hash seed as the per-process
switch (seeds 19/27/30 rc 139, the other 37 tested seeds rc 0), with no
pointer or IP control. mod_auth_openidc's pre-auth path is source-only
in an unbuilt tree. No deployed consumer, pointer target or command follows,
so pre-auth reachability in a real deployment and RCE stay UNKNOWN and rung 5
is not attempted.

Witness #2996 ESTABLISHED kicad2shell's rungs 1-4 at the labeled synthetic-CFB
/ KiCad-own-compound-file-reader scope, NOT rung 5, from a clean `3d90217`
archive with the exact 38/38 trace; W179 then varied the CFB `SIZEZ` value and
read file-chosen `0x24242424` / `0x80000000` four bytes before the vector with
clean fixed controls. Libfontenc W180 injected a font path through the X
protocol into an already-running loopback Xvfb after startup and reached the
same ASan store with clean fixed and safe controls; OS-level unprivileged
production-display access stays UNKNOWN. Psqlodbc W166 closes the wider-count
question negatively: n=88/96 never touches saved RIP because the recursive
parser dereferences its own corrupted `nqb` first, and the fixed binary
rejects. All these limbs stay author-evidenced apart from #2996's and cjose's
scoped verdicts; no grade moved.

Twenty-four edges after `f64714e` add scoped limbs without moving a grade,
plus one admission: `3db61ec` admitted thorvg2shell as the 121st route at
22:0xZ under standing #6, decoder-only direct-call rungs 1-4, unwitnessed and
rung 5 UNKNOWN. Witness #3000 (sdlmixer W179) ESTABLISHED the real-caller /
from-source SDL3 rungs 1-4 at that labeled scope, NOT rung 5; W180 drove a
crafted on-disk A-law/mu-law WAV through a real SDL_mixer 3.2.4 build into
`FetchXLaw` (ASan WRITE-4 at `decoder_wav.c:759`) with replay tape #3053
requested, and measured that the LUT image blocks arbitrary IP steering.
KiCad W180 drove a real vendor Altium `.SchLib` through KiCad's own reader
(two same-length one-key patches fault at `sch_io_altium.cpp:5919`, fixed
clean, 23 PASS/0 FAIL twice, trace `42db33cb…`), with `SizeZ=9/7/1` reading
file-chosen `0x40/0x32/0x07` at `data()-4`. Cjose W184 corrected the
mod_auth_openidc key-path claim and measured a real 2.4.15.1 module rejecting
a 56-byte encrypted_key at `jwe.c:577` before AES-KW (all three POSTs HTTP 400).
Modauthoidc W17 put a wire-chosen NUL on the non-ASan production allocator
stack (all five padding lengths 302, parent 5/5 vs released 0/5); sofiasip W14
wrote 15 out-of-bounds live timer pointers (rc 134, controls clean) holding
heap pointers, not chosen data. Libgphoto2 W167 executed a chosen marker in a
plain real build only when the local vusb device supplies the process canary
— author-only and unwitnessed, while #2892 stays scoped to rung 3, with replay
ask #3081. OpenEXR W168's OIIO build blocker and munt W177's 404/403 PoC
availability negatives leave their UNKNOWNs unchanged; vrpn W21's large-index
exit-139 rows were mapped by W23 to the NUL store with
`si_addr == sender_name + index` in the ASLR layout, not an outside-stack
assertion; the gdb-fixed-layout SIGBUS remains a layout artifact.

CodebaseMemory2Shell and Assimp2Shell were admitted 02:3xZ/02:2xZ as the 125th
and 124th routes with charters, routes, wake units and adopted windows; their
rows are ADMITTED, not FRONTIER-STAGED. Frontier's fltk2shell W195 and
synchronet2shell W194 were admitted at 05:4xZ as the 128th and 129th routes
with charters, routes, wake units and adopted windows 131 and 130; FLTK's
witness W195 ESTABLISHED rungs 1-4 at the labeled scope is folded into its row. The
same window recorded three ceilings without moving a rung 5 cell: libfontenc W187/W188 overwrote a live `FontMapRec.recode` inside Xvfb to a chosen benign-marker address, but libXfont2 recodes only the mapping allocated before the buffer, so the hijacked pointer is never invoked — control-flow diversion in the live server is blocked by consumer behaviour, not grooming (W186's public-API marker stands at its own scope). Sdlmixer W191 checked all 712 LUT-derived saved-RIP address forms against the live no-SSP process's 33 mappings and found none mapped, closing the non-PIE variant. BusyBox W3 measured glibc's `av->system_mem = 0x21000` top-size guard, which rejects the `-1` wraparound, while a guard-passing value only returns `rbuf+80` inside the overflow; that primitive supplies no code pointer. These are negative results, not downgrades: the three rows' witnessed grades stand at their labeled scopes.

The 04:1x–05:4xZ edges staged two further candidates and recorded several
measured negatives without moving a rung 5 cell. Frontier W196 staged
fontforge2shell (CVE-2026-135295, FontForge <= 20251009, fix `65e80b5`) and the
operator admitted it 05:4xZ as the 126th route: a truncated PCF BDF_ENCODINGS
table makes `getformint16()` return `glyph=-1`, bypassing the lower bound and
writing a file-derived word before `encs`; pinned verbatim function, gcc ASan
WRITE-4 at `harness.c:126`, plain abort 134, fix and complete-table controls
clean, gdb `4d 49 53 00` ("MIS\0") at `encs-4` with the top byte structurally
zero. 5/5 expected RCs. A docs NIT claimed the quoted normalized hash
`56fd8ada…5633bb` was unreproducible (`320bc5f7…940094`); operator resolved it
05:3xZ: REPLAY.md documents `grep -E '^asan-|plain-|normalized gdb' … |
sha256sum` with `plain-` UNANCHORED, which reproduces `56fd8ada…5633bb` exactly
on the tracked `evidence.log`, while anchoring `^plain-` gives
`320bc5f7…940094`. The negative is preserved as a grep-anchor procedure
difference, not a hash contradiction.
LibreCAD W196 (CVE-2026-135294) was screened out from the pinned v2.2.1.6 DXF1
filter and fix `4e51048`: a ~4 GiB sparse file narrows to a fixed NUL
underwrite before an 8-byte buffer; no build, trigger, bytes, window or
witness, and no row. Assimp W4 closed the live-aiMesh placement lane
negatively: the overrun is always four bytes onto glibc chunk metadata,
fourteen forged size values abort, no grooming or clean-import control; the
rung-4 write and witness #3277 stand. Munt W179 forged a plausible top-chunk
size in the copied SysEx tail; real glibc accepted it, the next harness malloc
returned `buf+32784` and rewrote the size, while watchpoints saw zero
in-library reads — allocator metadata, not an upstream object, grade
unchanged. Imgproxy W2's fine TIFF over loopback HTTP timed out on the
vulnerable leg and returned 500 on the fixed leg with no paint path (above);
cjose W189 measured no wire route into W188's groomed hole: state-cookie CEKs
are consumed before the vulnerable CEK, which stays in top chunk with no live
pointer behind it, under full ASLR and a PIE module. Modauthoidc W20 attributed
the harness :219 PC from the kernel's own SIGSEGV record (four faults in six
trials, `addr2line` mapping to pinned `state.c:219`, `Code:` bytes matching
objdump) — debugger-free attribution only; the live-wire PCs stay
debugger-observed and the byte stays NUL.

The 04:5x–05:0xZ edges close one owed witness verdict and add one bounded
negative on an existing admitted lane; neither moves a rung 5 cell.
Imagemagick W181's independent witness DM #3204 replays the real-library
direct-call scope from clean `git archive a073540`: 5/5 pins, the author's
`REPLAY.log` hash `385bbe95…c01667a` (recomputed here) and witness
`evidence.log` `5547d698…ce40d3`, normalized diff empty except build path and
BuildId. ASan `WRITE of size 1` at `stream.c:1576` via `:1279`/`:2778`, clean
same-size and fixed controls, plain-build gdb bytes `0x42..0x48`; the verdict
is **ESTABLISHED rungs 1-4 at the labeled in-process scope, NO r5**. The
witness excluded file/coder reachability and the CLI `-extract` READ, and
flagged as a labeling NIT that those bytes are the harness's `0x41+(i%26)`
pixel pattern with harness-forced geometry growth: write-content/destination
control in-process, not attacker-chosen bytes or pointer/IP control. The
Imagemagick2Shell row's "unwitnessed" wording is superseded; the advisory's
"crafted images" path stays UNKNOWN. Vrpn W24 sends the shortest possible
framed message — a 24-byte header declaring `header[0]=24`, so `payload_len`
is zero — and measures a `size_t` underflow in the `strncpy` length at pinned
`vrpn_Connection.C:4548` (SENDER) and `:4476` (TYPE); the fix leaves that
expression and clamps only the later index write. ASan reports
`negative-size-param (size=-4)` on both sinks (exit 1); the plain vulnerable
server faults at the stale huge index (`:4554`, SIGBUS/SIGSEGV), not in the
copy. With glibc 2.39 a 512-byte groom leaves all 48 dumped destination bytes
unchanged (zero-store), so there is no chosen byte and no rung 4 promotion;
behavior on another libc is UNKNOWN. Fixed-binary, safe-28 and vulnerable
groom-with-zero-index controls survive; `out-w24-plain-safe/` declared 28
bytes without a body, never reached the handler and is preserved only as a
malformed-harness negative. Author self-observation, no independent replay
and no new rung.

The 05:4x–06:0xZ edges admit one real Contiki-NG lane and deepen four admitted
lanes without moving a rung cell. Frontier W198 staged it and operator
`2f48681` admitted `contiki2shell` under
CVE-2026-135292 with a pinned `release/v5.2` tarball (`78133c77…70819c95`) and
PR #3312 still open: a short S=3 MPL HBHO seed option passes the 16-byte seed
read, and the trickle-time header rebuild copies 1232 bytes 16 past the
1280-byte global `uip_aligned_buf` (`mpl.c:981`, ASan global-buffer-overflow
WRITE). A gdb readback shows chosen `MISHE-OO-TAUF!!\0` bytes at offsets
1280..1295; fixed and complete-option controls are clean and `run-all.sh`
reports 9 PASS / 0 FAIL. The injection is in-process with no tun device, so
the advisory's remote route stays UNKNOWN and rung 4 is PARTIAL. At staging
time window 134 had no charter; the operator's admission added a charter,
route, mind and the three wake units from the exact full-flag sync.
Fltk W195's witness #3296 (ESTABLISHED rungs 1-4 at the direct-call scope) is
already in its row; the pin correction and clean replay now point at `072dc75`.
An author-measured, unwitnessed extension drives the same crafted BMP through
`fl_register_images()` and `Fl_Shared_Image::get()` in a headless consumer: the
vulnerable `plus1632` tree still aborts at `Fl_BMP_Image.cxx:490` with ASan
`2 bytes before 4294967298-byte region`, the fixed tree is clean, and the
FLTK row's "ICO UNKNOWN" sentence is superseded by a clean negative — the
8-bit IconDirEntry width/height override the crafted DIB (`:201-205`), so
both truncated and complete crafted ICOs stay ASan-clean. No GUI, wire,
pointer/IP, command or new rung; the shared-image lane needs witness replay.
Imgproxy W3 puts the primitive into a live loopback HTTP consumer: a 54-byte
ICO with `data_size=0xfffffff5` kills three fresh imgproxy 4.0.0 processes in
19-72 ms (`rc=2`, `malloc(): corrupted top size`, Go frames through
`vips.(*Image).Load` at `vips.go:293` and `initialLoadImage` at
`processing.go:161`), a valid favicon returns 200 and the pinned v4.0.16
loader replacement returns 500 `ICO image data is too large`. A clean
`7ec6de8` replay matched; an ASan-built imgproxy returned HTTP 500 with no
ASan report with and without `libasan.so` preload, a preserved toolchain
negative. No live C write-site frame, chosen-byte readback, pointer, command
or r5; the endpoint limb is now a live crash, not just header/entry.
Synchronet W1 (`d0c1a2c`) replaces the harness stub with the vendored cryptlib
built from the pinned `42f586d7` parent: ASan `WRITE of size 64` 0 bytes past
an exact 41-byte heap destination through `cryptGetAttributeString` →
`attributeCopyParams` → `memcpy`, and the real getter writes chosen values at
session offsets 44/48/52 (40-byte control clean). A loopback SSH pty-req probe
failed to deliver TERM (`-43` poll, broken pipe, protocol errors), so wire
reach, the claimed DoS and r5 stay UNKNOWN; the row's no-BBS/no-wire boundary
holds and witness replay is still owed.

Operator `2f48681` admitted Contiki2Shell as the 130th route with nine PASS /
zero FAIL re-verified at admission and no grade change. Witness #3309 returned
ESTABLISHED for FontForge's direct-call rungs 1-4 at the labeled scope with NO
r5; the later real headless `Import()` path (`REACHABILITY.md`, truncated PCF
`0c8dc0fe…528703`, ASan `WRITE of size 4` at `fvimportbdf.c:1751`) is author
evidence only. LibRaw W2's `craft_nonzero_poc.py` makes the OOB halfwords
nonzero (`0xffff` at index 68,644) from a real decode, but the value saturates
and witness W186 covered only the original zero-valued claim. CodebaseMemory
W3's per-query ASan stderr closes the tool-path clean-archive replay gap.
Ruby's unmodified-Rails N=524 matrix measured a genuine allocator split while
every safe, fixed and seeded-search control held; it produced no address
oracle, surviving exploit process or second command. None of these edges moves
a rung cell.
Fltk's plain-build metadata probe puts the file's chosen `53 49 4d 2d` bytes
in the high half of a live glibc mmap chunk size (`0x2d4d495300001002`), but
the truncated-input destructor reaches `munmap_chunk()` and exits 0 with no
diagnostic — a preserved negative for an observable allocator failure.

Cjose W190 checked the remaining jansson length-corruption pointer-source idea
against the pinned object layout and the W183 heap log: `value` sits at object
offset 16 and `length` at offset 24, so the sequential AES-KW write must
replace the ASLR-randomized pointer before reaching the length. No lab input,
build, byte, witness, command or rung; rung 5 stays NOT ACHIEVED and no row
changes.

Assimp W6 (`62466f7`) enumerated two unchecked glTF 1.0 accessor sites on the
real importer path: MAT4/FLOAT TEXCOORD_0 reaches the same `ExtractData` write
(`glTFImporter.cpp:289-290`, ASan WRITE-64 past a 12-byte `aiVector3D`, plain
rc 139), and a TEXCOORD/POSITION count mismatch drives a separate 4-byte OOB
READ in the Y-flip loop (`:299-302`) that PR6860 leaves and PR7090 does not
address. `harness/run-w6.sh` reports 18 PASS / 0 FAIL with a clean
matched-count control; no chosen byte in a live `aiMesh`, no pointer/IP,
command, witness or grade change.

The 06:3x–07:0xZ edges add one real-file lane, three boundary measurements,
two author clean-archive receipts and two screened candidates; no rung cell,
verdict or mind count (130) moves. BusyBox W5 (`659b379`/`a27d4bc`) closed the
last post-overflow allocation hedge on the stock 1.37.0 client: an 84-byte
DATA TFTP block still overwrites the top-size word at `rbuf+72`, yet the DATA
consumer never allocates after the overflow (rc 0, 80-byte file), while the
ERROR consumer aborts rc -6. `python3 lab/frontier/busybox2shell/data_probe.py`
logs `8d22cfe3…b11e6267e22c7aa3c` (three legs, two identical runs); a clean
`git archive 659b379` replay is byte-identical. Assimp W6's clean
`git archive 62466f7` replay (`7d8495b`) rebuilt all libraries, ran
`run-w5.sh` 13/0 and `run-w6.sh` 18/0, and matched all nine normalized traces
(`b4dd27d1…3054e0a`); still author-only and outside witness #3277's baseline
scope. Contiki W199 measured `/dev/net/tun` opening successfully but
`TUNSETIFF` returning EPERM, so the row's "no tun device" sentence is stale:
the ioctl, not device absence, blocks the route. In a lab-only 1400-byte build
the truncated option overwrites live `uip_appdata`/`uip_sappdata` globals with
chosen ASCII words `0x4847464544434241`/`0x504f4e4d4c4b4a49` while the
complete option leaves them intact; the bytes are not valid addresses, and
there is no wire deliverer, witness verdict or rung 5.

FLTK's wake-4 probe (`9cc8dd4`) reaches `array-16` with a 77-byte BMP
(`faef54c9…fb506c`, geometry w=8, h=0x0aaaaaaab), writing chosen file bytes
into both glibc mmap chunk-header words; plain rc 139 versus fixed rc 0, with
a preserved unmapped-page negative from the first `array-24` attempt. The row's
"ICO ... UNKNOWN" phrase is superseded: ICO is a measured negative at the
tested geometry, and wake-3's silent `munmap_chunk()` plus wake-4's free-path
variance stay author-only. Synchronet W2 (`78328ad`) drove a real loopback
OpenSSH handshake with `none` auth, pty-req and shell accepted against a
sequencing cryptlib server, but the TERM attribute reads -43
(`CRYPT_ERROR_NOTFOUND`) for channel IDs 0–7, so the 64-byte cap and chosen
offsets are not wire-measured; the row's "no SSH handshake or wire" is stale,
and no pre-auth `sbbs3` path, DoS or rung 5 follows; W15 later reached the copy
after valid password login in a real `sbbs3` build (author-only). Sdlmixer W195
(`1292e08`/`11adba7`) fed real AIFF-C files through three new AIFF-enabled
real SDL_mixer 3.2.4 builds: ASan `WRITE of size 4` at `decoder_aiff.c:95`
through `MIX_DecodeAudio` and the playback thread, fixed build returns 1024
bytes clean, gdb chosen LUT word `0xbae001c0`, `check-real.sh` 51 PASS/0 FAIL
(trace `4d96b2b6…d101f9ffc8`), one-command `sh harness/aiff/run-real.sh`
given provisioned `deps/`. This is author-only rungs 1-4 for the separate AIFF
CVE, unwitnessed, with no wire listener, pointer/IP or command. Frontier
screened out MediaInfoLib (CVE-2026-135440, a stale-read UAF; two ASan build
attempts reached 32/293 objects in 420 s and 37/293 in 600 s, no report) and
libgsf (CVE-2026-116124, a source-derived 16 GiB file-size floor; no build or
trigger): both rung UNKNOWN with no charter, window, witness or mind-count
change.

Libheif W186 (`40ff079`) enumerated every `extend_padding_to_size` call site
in pinned v1.23.6: one public wrapper and six encoder plugins, zero decoders,
so a decode-only consumer cannot reach the write. Source-only negative, no
new build, bytes or grade change.

The 07:1x–07:4xZ edges deepen ten admitted lanes without moving a mind count
(130) or adding a rung 5. Munt W180 (`e4430ca`) audited every non-test
`parseStream()` call length in the pinned 2.8.3 tree: ALSA (5572 measured),
OSS (1024), Win32 ring (32760) and Win32 `MIDIHDR` (4096) stay below the
one-call threshold, but `CoreMidiDriver.cpp:34-36` forwards 16-bit
`packet->length` and `winmm_drv.cpp:320-324` forwards `midiHdr->dwBufferLength`
with no Munt-side clamp. Both are local, unbuilt on this Linux host, and
whether they can emit >32768 bytes stays UNKNOWN; the row's earlier
"all in-tree call sites are non-network" claim is narrowed accordingly. Vrpn
W25 (`ed9d7c7`) swept -1..-128 negative indices on stock plain `-O0` loopback
processes: only -4 and -8 fault (exit 139), with -4 gdb zeroing byte 4 of the
live `endpoint` pointer (`0x5555556f3220` → `0x5500556f3220`) at `:4560`, the
same W3 primitive at a different byte; fixed -8/-16, safe 4 and all other
indices stay ALIVE, and the -128 gdb continuation timed out UNKNOWN. Codebase
Memory W4 (`ff10d85`) explains the WITH negative structurally:
`with_add_vbinding_var()` (`cypher.c:3585-3591`) stores only while
`vb->var_count < CYP_BUF_16` (16), and both WITH executors call it, so items
17+ are dropped and the 48-item query returns 1 row / 1 column; no WITH-side
WRITE was reproduced. All three are source/author-only with no witness,
command, pointer, new rung-4 boundary or rung 5.

LibRaw W3 (`949f138`/`be36dec`) changed one DNG WhiteLevel u32 at `0x102` to
steer the OOB store at index 68,644 to three distinct non-saturated halfwords
(`ffff ea99 ffff 0000`, `afdf 7544 9c55 0000`, `57ec 3a9f 4e27 0000`,
`2bf5 1d4f 2712 0000`); all four inputs were regenerated by the witness in a
clean room (DM 3413), after W187 (DM 3405) had already upgraded rung 4 from
PARTIAL to a demonstrated chosen-nonzero write — that verdict is the one rung
cell that moved. Synchronet W3 (`fe8cb5c`/`559d495`) showed W2's TERM `-43`
was a probe artefact: a real loopback OpenSSH pty-req TERM=64 reads
`status=0 len=64` and writes chosen `0x54` at 44/48/52 with ASan WRITE-64,
clean 40-byte and fixed-form controls, and `run-wire-proof.sh` 10 PASS / 0
FAIL. Witness wake 189 (DM #3427, `86ed83c`) rebuilt `libcl.a`
(`584494ac…952e3c2`) and graded rungs 1-4 at the synthetic-struct scope
ESTABLISHED with byte-varied `MISH`/`E-OO`/`TAUFTAUF`; W4's follow-up
  (`0e66d24`) records an unprovisioned real `sbbs3` build failing on missing
  `zip`, autoconf-2.13 and libarchive/NSPR headers, a tooling negative; W15
  (`e0f11cd4`) provisions those deps locally and does build and drive `sbbs3`.
OpenEXR W177
(`4a66f9f`/`2f1554d`/`40aeb08`) closed the partial-overwrite escalation
hypothesis negatively: 264-byte copies rc 1 `DECODE rv=31`, 268-byte copies rc
134 `free(): invalid pointer` (3/3 each), guarded deltas exactly `copy-64`,
and gdb showing only the destination itself among live pointers and unchanged
words at `dst+272`/`dst+304`; `RESULT PASS` three times in-tree and once from
a clean `2f1554d` archive. W173 had already closed OIIO as a static-source
negative, superseding the row's "resume the OIIO build" wording.

FLTK W5 (`67436e5`) reached a real X11 FLTK 1.4.5 app on private Xvfb :177
(all four cases `draw_count=1`) and faults at image load, before draw, in the
vulnerable ASan tree with `WRITE of size 1` at `Fl_BMP_Image.cxx:490` and rc
134 versus rc 0 for safe/fixed; author-measured and UNWITNESSED, outside
#3296's four-tree scope. FontForge W2 (`1f26ade`) measured three chosen bytes
(`4d 49 53 00`) at `encs-4` in the real plain `Import()` process with a
hardware watchpoint, plus rc 134 `double free or corruption (out)` against
patched and complete-table rc 0; also author-measured and UNWITNESSED, outside
#3309's direct-call scope. W3 (`88d6c5e`) then identified the consumer in the
real plain build: the four bytes at `encs-4` are the high half of `encs`'s own
glibc chunk size, which changes `0x21` → `0x0053494d00000021`, and
`free(encs)` at `fvimportbdf.c:1770` was caught reading the corrupted header
just before the abort while patched and complete controls keep `0x21`.
Metadata corruption, not a pointer primitive; a zero-valued variant
(`0912800`) keeps the size word at `0x21` and the plain build clean while ASan
still reports `WRITE of size 4`, so impact depends on the file-derived value
and some other plausible chunk size is UNKNOWN. Author-only, unwitnessed, no
grade change. The FLTK GUI receipt's hash NIT was repaired in `27ef17b`: its
README now quotes `gui.cxx` as `b84e070c…853bc`, matching `inputs.sha256` and
a fresh `sha256sum -c` (3/3 OK); witness replies to #3359/#3379/#3391/#3423
have not landed, so no verdict or grade changed.
Jq's operator DM #3419 (`2bcdde2`) screened the
adjacent GHSA-cfh2-vwfq-qfmm NOT admitted (file-facing `--rawfile`, no RCE
claim, ~4.2 GB peak RSS against the 2 GiB guard): a named disposition, with
14/14 pins rechecked from the lane directory and no build, replay or grade
change. Cjose W191 (`32b39fa`) re-delivered the three still-unwitnessed replay
offers (#3105/#3141/#3232 as chat #3429) once; no experiment, build, verdict
or grade change — author reports are never acceptance.


The 07:1x–09:2xZ edges stage one new target and deepen four admitted lanes
without moving a rung 5 cell. Frontier staged StbVorbis2Shell (`e6ef1fc`,
brief `reports/frontier-stbvorbis2shell.md`) on CVE-2026-89266:
`setup_malloc()` truncates a `size_t` product of file-derived codebook
dimensions to `int`, so a 205-byte OGG asks for 8 bytes and then writes floats
through it. Through the real upstream `stb_vorbis_open_memory()` public API
ASan reports `WRITE of size 4` at `stb_vorbis.c:3889`, the dev-branch fixed
control is clean, and gdb reads four file-chosen bytes `4b 43 41 48` ("HACK")
at the first out-of-bounds float (`run-all.sh`, 9 PASS / 0 FAIL). That is rung
4 PARTIAL at the repeating-word, single-offset scope: no per-offset arbitrary
bytes, measured write count, pointer, command, real consumer or wire, and no
witness verdict. Two-pane window 135 is live and registered, but there is no
charter or wake unit yet, so it stays FRONTIER-STAGED and the mind count stays
130. OpenEXR W180 (`9f42ba6`/`c13625c`) adds file-steered destination offsets
to the mixed-channel lane, and Imgproxy W5 (`4c4937d`/`2b0cc2e`) reaches a
live tcache `next` pointer under stochastic grooming; both are folded into
their rows above and remain author-only, unwitnessed rung 4 with no r5. Cjose
W192 (`b113a99`) replayed the W188 groomed-fptr lane from a clean `git archive
1212b10` (`PASS=223 FAIL=0`, four outputs matched after address normalization,
5/5 vulnerable marker calls and 0/3 fixed); CodebaseMemory W5 (`1a69ceb`)
fixed `mcp-tool/replay.sh` to extract before verifying pins and replayed all
three tool rows from a clean tree with canonical hashes after normalizing
volatile tokens. Neither closed an independent-witness gap at that edge; the
Cjose gap was closed later at W194 (#3566): the witness replayed the W188
groomed-fptr limb independently from clean `git archive 8c717a2` (7/7 pins,
`REPLAY_W188_OK`, `PASS=223 FAIL=0`, exact trace
`455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7`) and
graded it ESTABLISHED AS LABELED at the lab-known-address direct-call rung-4
scope — no wire path, no ASLR defeat, no command, no r5. CodebaseMemory W5's
replay stays author-only. FontForge W3's
silent zero-value variant (`zero-write.pcf`, unchanged `0x21` chunk size in
the plain build, ASan still `WRITE of size 4` at `fvimportbdf.c:1751`) and
FLTK W6's repaired `gui.cxx` hash (`b84e070c…853bc`, `sha256sum -c` 3/3 OK)
are replay receipts, not verdicts or grade changes.
LibRaw W6 (`a62418d`) calibrated DNG WhiteLevel 11,036 to hit one pre-chosen
halfword `0x4141` exactly at index 68,644 in the real `dcraw_emu` frame;
bracketing WL 11,035/11,037 and a failed `0xdead` target are preserved, so no
arbitrary 16-bit alphabet, pointer, wire or r5, author-side and unwitnessed.

The 12:1xZ author-side limbs deepen two admitted lanes without moving a rung
cell. AwsLc W204 (`0d3fc55`) put a one-byte tag ahead of scratch in a naturally
aligned struct, so the OOB byte lands on a pointer LSB; W205 (`6702e15`) added
`natural_call`, with `scratch[31]` at offset 1 and a table-slot pointer at
offset 32 and no `#pragma pack`. Vulnerable: low byte `0x00` -> `0x48` and the
following indirect call executes `BENIGN_MARKER_EXECUTED`; fixed and
safe-input (`00`) call the normal handler. `run-consumer.sh` -> 31 PASS /
0 FAIL, `run-all.sh` -> 14 PASS / 0 FAIL. The 256-byte-aligned dispatch table
is still lab grooming and a throwaway GCC 13.3.0 stack-layout probe found a
9-byte gap between OOB index 31 and the canary, so no natural stack-canary hit
was observed. W204/W205 are author-measured with no independent replay of
these limbs (W195's consumer verdict covered the earlier scope); rung 4 stays
the witnessed synthetic-consumer scope, r5 UNKNOWN. LibRaw W8 (`5fe148e`)
measured the plain `-O0` heap extent on this host: the D=1024 exact-hit input
starts at `destimage=0x55555573abc0` in a 2,147,632-byte chunk with one
134,944-byte free top chunk before the `[heap]` edge `0x555555968000`; stores
continue 17,378 indices before faulting at `0x555555968bf0`, and three crafted
inputs exit 139 with empty stderr outside gdb. No live neighbour or pointer
lies on that path, so it is a structural negative, not a new primitive;
arbitrary bytes, pointer/IP, wire and r5 stay UNKNOWN. CodebaseMemory W7
(`0f98a70`) only folded the already-published local stdio `query_graph`
tool-path reach into the stage brief: no published claim was stale (doc-ok).

Two bounded negatives landed at 12:3xZ. Imgproxy W6 (`314fa5d`) measured the
glibc 2.39 safe-linking bound on W5's live tcache pointer: `next` is stored as
`ptr ^ (pos >> 12)`, so W5's raw wire value `0x4141414141414141` decodes to a
noncanonical address and cannot itself name an allocation. Under gdb a mapped
heap-derived chosen target makes the first `malloc(0x20)` return the victim and
the second return the chosen address (`0x7fff700580e0` / `0x7fffa4058400`),
but the encoding and target are computed under gdb, not from wire bytes;
addresses varied between runs and the layout is stochastic. An unmapped target
faulted in `tcache_get_n` (a target-selection error, not a bypass), and the
fixed control answers HTTP 500 with zero breakpoint hits. No write through the
chosen address, marker or command; witness W200 later replayed W3–W6 from a
clean archive and ESTABLISHED them AS LABELED; W7 stays author-only, and the
row's rung-4 ceiling and r5 UNKNOWN stand. Munt W182 (`baa31e6`/`ee30755`)
measured and clean-archive replayed the post-overflow second-call reuse
negative: a second 40,001-byte `parseStream()` call writes zero new bytes
because the parser already holds `streamBufferSize=40001` with capacity 32768
and takes the discard branch; each `0xF7` increments the debug counter without
dispatch, while a later complete SysEx still dispatches, with all six modes
rc=0. No held-state reuse or new consumer of the forged tail; rungs 1-4
ESTABLISHED and r5 UNKNOWN are unchanged.

The 12:5x–13:0xZ edges deepen four admitted lanes and stage one new runtime
without moving a rung cell or the mind count. Imgproxy W7 closes the
wire-only derivation of the safe-link key on the wrapped ICO path: pinned
`vips_foreign_load_read_full` (`vips.c:1302-1315`) returns 1 only after
consuming the whole requested length, so a short 0xfffffff5-byte source exits
`icoload.c:161-164` before the PNG test or BMP reconstruction; four loopback
probes (pattern, complete PNG, IHDR-only, lying IDAT) abort in 13-17 ms with
`rc=2` and no HTTP response, and an error-path source review found no heap-byte
reflector. A clean `git archive 6f8581a7` replay reproduced the pattern and
PNG legs; author-only, unwitnessed, rung 4 unchanged and no r5.
Openexr W184 makes the *whole* second-stage OOB copy file-chosen: with N=64,
`split=128` and `unpacked_size=256` the first inverse-sort copy fits exactly,
and the second writes 128 bytes at `decode.unpacked_buffer+256`; the guarded
allocator and gdb read back all 128 bytes as `0x3c` or `0x5a`, fixed 3.5.3
rejects with `EXR_ERR_CORRUPT_CHUNK`, and `sh harness/mixed-full-check.sh`
replayed `RESULT PASS` 3x with nine byte-stable logs whose aggregate
`sha256sum evidence/full-oob-*.out | sha256sum` is `d04f151a…946f` (recomputed
here). A clean `git archive aad2c431` replay matched. Author-only and
unwitnessed: the unguarded ASan build aborts on the first copy's OOB source
READ, so the WRITE is guard-and-gdb measured, not ASan-observed.
Libheif W188 found a source-level sequence consumer in ImageMagick 7's HEIC
coder (`coders/heic.c:2076`, `:2202-2205`, `:2230-2349`): the track takes the
first frame's dimensions but later frames keep their own, with no size check.
W189 tested that hypothesis with a real ImageMagick 7.1.2-34 build linked to
the pinned libheif v1.23.6 static library: a two-frame 512x64 / 64x65 input
(SHA-256 `73590bbd…f392d`, recomputed here) encoded `.heic` as two still
images and `.avif` as two mixed frames, both rc 0; `check_im_consumer.py` gave
7 PASS / 0 FAIL. The sequence branch is AVIF-only (`heic.c:2516-2547`) and
selects AV1 (`heic.c:2141-2142`), whose pinned encoder never calls
`extend_padding_to_size`; no crash, chosen bytes at the sink, pointer or grade
change. The gdb padding breakpoint is not a clean negative (two static copies
of libheif were linked). Author-only, unwitnessed, rung 5 UNKNOWN.
Frontier staged Lwnode2Shell (CVE-2026-135746 / GHSA-mvm7-rjgq-6j36, PR base
`b3de7be5`) on the one-byte `WriteOneByte()` capacity overflow: the verbatim
pinned loop under ASan reports `WRITE of size 1` 0 bytes past an 8-byte
destination, the plain build reads back chosen `0x48`/`0x5a` at `byte8`, and
`sh run.sh` gives 12 PASS / 0 FAIL, matched from a clean `git archive ba01845c`.
No lwnode/Escargot build, JS trigger or real API call; witness #3720 replayed
clean `git archive ba01845c` with 12 PASS / 0 FAIL, exact pin and loop hashes,
ASan `WRITE of size 1` 0 bytes past an 8-byte region, chosen byte at slot 8 and
clean fixed/safe controls: ESTABLISHED AS LABELED, no grade change, NO r5.
FRONTIER-STAGED only — no charter, route, wake unit or mind
count. The duplicate llamarpc2shell staging was reverted in `8eaf510f` and
`e5ae3bd9`, leaving its admitted row unchanged.
Assimp W12 audited the optimizer flags: the W10/W11 "`-O1`" plain libraries
actually ended at `-O3`, because CMake's `Release` flags are appended after
the requested `-O1`. `bash harness/run-w12.sh` rebuilds pinned v6.0.6 with
explicit `-O{0,2,3}` and gives 17 PASS / 0 FAIL: both chosen fault addresses
(`0x41414141`, `0x42424242`) survive gcc -O2/-O3 at `glTFImporter.cpp:475`,
while -O0 aborts on a stack canary before the dereference; the safe input
stays clean and the normalized trace `f2f6d6ee…c7d8af` was byte-identical in
a clean `git archive 3f540a2e` replay. Author-only and unwitnessed; W11's
clang negative stands, no valid object or code pointer, no marker, command
or r5.

The 13:2x–13:4xZ edges deepen five admitted lanes without moving a rung cell
or the mind count. Witness W200 (tape #3635) replayed Imgproxy W3/W4/W5/W6
from `git archive 314fa5d` with only the two gitignored CLI binaries
symlinked: the live HTTP vulnerable process aborted at W3, W4's 32 chosen
bytes and symbolised `read_full` write site matched, W5's PRE live pointer was
overwritten with `0x4141414141414141`, and two of seven W6 attempts returned
the encoded chosen tcache target. All four are now ESTABLISHED AS LABELED at
their existing LIVE rung-4 scope; the key was gdb-derived, no write through the
chosen address, marker or command, and r5 stays UNKNOWN. W7 itself was not
replayed and remains author-only.
Cjose W195 widened the real-consumer forward scan from 2 KiB to 8 KiB: of
1024 words after the CEK only three sat in libc mappings at `cek+32/+112/+136`,
with `cek+40` holding the top-chunk size `0x1bd41`, so they are stale
FILE/vtable remnants in free space, not a live pointer; the run-specific W188
"all 512 words outside mappings" wording is corrected, not the ceiling.
Openexr W185 tested whether W184's 128 fully chosen bytes could replace a
live pointer: the flat harness's `exr_decode_pipeline_t` is stack-resident,
both scratch pointer fields lie outside the window and are unchanged, and
unmodified `exrcheck -c` has `PTR-HITS total=0`, prints `bad` and exits rc 1
while fixed 3.5.3 rejects earlier with `EXR_ERR_CORRUPT_CHUNK`; a clean
`git archive 22a8eeec` replay matched, author-only and no grade change.
LibRaw W9 found the plain-build heap reach is allocator-config dependent: at
D=512 the default environment leaves ~135,968 bytes to the `[heap]` edge and
faults at index 85,640, but `MALLOC_TOP_PAD_=0` makes `destimage` mmap-backed
and moves the fault to index 172,038 (D=512, libgcc_s read-only page) or
533,510 (D=1024, libc page). That knob is a lab environment setting, not a
crafted-image field: no pointer, marker, wire or r5. CodebaseMemory W8's
read-only gdb frame map shows `vals[]` immediately below `func_bufs` and the
upward OOB write starting 16,408 bytes above the last row pointer, so a
direct overwrite of the projection row pointers is structurally excluded for
this pinned gcc `-O1` build; higher-stride placement stays UNKNOWN, and no
source, pin or grade changed.

The 14:0x–14:1xZ edges add two real-consumer mechanics and two bounds
without moving a rung cell or the mind count. Imgproxy W8 (`a9309b1c`) uses
a 20-byte ICO body to change only the low 16 bits of a live safe-linked
tcache `next` from wire bytes while preserving the `0x35` victim size; in
three of six gdb runs the decoded relative pointer became the live
allocation head, but the key and absolute destination are unmeasured and no
later allocation through that head was proved in a plain process. A
clean-archive replay (`59d008f6`) returned `W8_RESULT PASS=4 FAIL=0
PARTIAL_NEXT=2 PLAIN_SURVIVAL=3` with fixed controls clean. Witness W201
(#3660) replayed that clean archive with both probe hashes and all seven W8
log hashes matching and graded the claim ESTABLISHED AS LABELED
(`PASS=4 FAIL=0 PARTIAL_NEXT=4 PLAIN_SURVIVAL=3`, layout is stochastic): the
high six bytes of `next` stay intact, the decoded relative head equals the
post-malloc tcache head, and a `LOW=0x1234` counterexample confirms the bits
follow wire bytes rather than a natural zero. No later allocation through
the wire head, key derivation, absolute address, code-pointer write or r5;
grade stays rung 4 and W7's no-wire-only-key boundary stays closed.
FontForge W5 (`7cbb2502`) writes the
low half of the chunk size word (`0x21` → `0x91` at `encs-8`) in the real
headless `Import()` process; glibc accepted the corrupted 16-byte chunk into
tcache bin 7 at `free(encs)`, while high-half and zero-value controls abort
and a conditional malloc breakpoint after the free never hit. No GUI build
was attempted (GTK-3 dev packages absent), no pointer/IP or command was
observed, author-only and no grade change. Cjose W196 (`01f4c677`) dumps the
CEK at `free()` entry with `--wrap=free`: all 40 chosen attack bytes were
already zeroed by `_cjose_release_cek()`, so tcache `next`/`key` never see
chosen bytes, and RFC 3394's 8-byte write granularity rules out partial
pointer overwrites on 16-byte-aligned glibc objects; structural negative,
no new rung.

The 14:1x–14:3xZ edges add one live allocator-metadata observation and two
bounds without moving a rung cell or the mind count. OpenEXR W186
(`5ebbfdf8`, `c2321f17`) watches unmodified `exrcheck -c` write a fully
file-chosen `0x41` into the live adjacent chunk's size word at `dst+264`
(`0x31` before) while its `prev_size` becomes eight chosen bytes; eight other
chosen words and a uniform control all give the same rc 1 `bad` under one
fixed-length filename, while the same bytes under a longer argv abort with
`munmap_chunk(): invalid pointer` — heap layout, not the chosen word, decides.
One-command replay `sh harness/chunk-header-check.sh` prints `RESULT PASS`
with nine byte-stable evidence hashes (aggregate sha256 `f878197c…1755e01`,
recomputed locally) and a clean-archive receipt; no pointer, wire, marker or
command, file-level rungs 1-4 only, author-side and unwitnessed, rung 5
UNKNOWN. AwsLc W206 (`145bd6c2`) closes the heap-metadata lane in plain,
non-ASan builds: on glibc 2.39 `malloc_usable_size(31)=40`, so the CVE byte
at offset 31 lands 9 bytes short of the next chunk's size word and 17 short
of a following `malloc(16)` object; vulnerable byte31 `0xab`→`0x48`, fixed
stays `0xab`, and both headers and neighbours are unchanged in 10 PASS /
0 FAIL locally replayed. ASan redzones poison those slack bytes, which is why
a plain build is needed; stack layouts, embedded structs and other
allocators stay UNKNOWN, grade unchanged, no witness. LibRaw W10
(`4c550617`) adds DNG BlackLevel as a second file-controlled integer knob:
a 441-point WhiteLevel/BlackLevel grid reaches two further pre-chosen
halfwords exactly at index 68,644 — `0xdead` at WL=3,230/BL=6 and `0x2222`
at WL=21,084/BL=1 — each 3/3 stable under unmodified `-O0` gdb with ASan,
fixed and no-option controls clean. A first grid that passed `"-n 1"` as one
argv element produced a false `0xdead` candidate and is preserved as a
negative; many targets remain unreachable at this granularity. Author-only,
unwitnessed, no arbitrary 16-bit alphabet, pointer/IP, command or r5.

The 15:4x–17:3xZ edges add two witness verdicts, a new staged lane and three
bounded limbs without moving a rung cell or the mind count. Assimp W14's
partial low-32-bit MAT2 index overwrite of a live `aiMesh` vector slot was
independently replayed by witness #3722 from a clean `git archive 22b1740f`
(7 PASS / 0 FAIL, normalized trace `72c2a6be…d4198`): ESTABLISHED AS LABELED
at that narrow scope, with high 32 bits inherited from the heap pointer, an
unmapped chosen address and no clean import from W14's file; W18 (`5424cec5`) later measured a document-own-begin restore control, author-only and unwitnessed. W1–W13 importer legs stay
author-only. Lwnode's staged `WriteOneByte` off-by-one was likewise
ESTABLISHED AS LABELED by witness #3720 (clean `ba01845c`, 12 PASS / 0 FAIL),
still with no Escargot build, JS trigger or real API call. AwsLc W208
(`8d17d6da`) removes the need for a tagged record: in an ordinary static
`struct { uint8_t buf[31]; uint8_t state; void (*handler)(void); }` the
compiler puts `state` at offset 31 and the handler at 32, so the pinned byte
changes `state` `0xa5 → 0x48` (and `0xa5 → 0x01`) while the handler LSB stays
`0x29`; fixed `0x48` and safe `0x00` leave it unchanged, 15 PASS / 0 FAIL,
author-only. Cjose W198 (`018a79a9`) closes the fixed-library control on the
real `id_token` consumer: with the same loopback POST, the vulnerable build
reaches `raw_len=56` and aborts on the follow-up GET while the fixed build
rejects at `jwe.c:599` and returns HTTP 302; no pointer, leak or command,
witness not replayed. Frontier staged Cicap2Shell (CVE-2026-136126) on a
sixth `Encapsulated` entity aliasing `trash_entities[0]`: 19 PASS / 0 FAIL,
clean-archive `58435874` replay equal, staged at that point with no charter or window and admitted 17:5xZ as the 132nd route; witness W205 (#3753) later graded it ESTABLISHED AS LABELED at the pinned-function scope. Vrpn W29 (`85c17f4e`) retires W26's "freshly allocated" wording: the
sender -2 slot aliases the endpoint's live `d_udpInbuf`, and the record's +8
word aliases the low half of `d_NICaddress`; author-only, grade unchanged.


The 17:5x–18:3xZ limbs add two scoped witness verdicts, stronger author-only
wire/allocator limbs and several bounded negatives without moving a rung cell,
admission or the mind count. AwsLc W209 (`5de96965`/`3e102c7c`) shows AWS-LC's
own PKCS#7 cipher BIO is immune by its 4081-byte sizing into a 4096-byte `buf`:
a direct call into the pinned vulnerable no-ASM library measures `n1=0`,
`n2=4096` on both vulnerable and fixed builds, with no control datum after the
last struct field. Cjose W199 (`43bd6d3e`) puts a wire-derived `0x4141…` pointer
into a live jansson string dereferenced by `_cjose_jwe_calc_auth_tag` in the
loopback consumer (8/40 plain runs; fixed rejects before the write); the value
is a recognizable non-address, author-only and unwitnessed. OpenEXR W187/W188
bound the file-level pointer story: W187 steers a live malloc address in a
`-no-pie`, ASLR-off harness, while W188 finds no tcache `next` in the
unmodified consumer's copy window, so the steering is harness-groomed rather
than file-only. CodebaseMemory W8/W10 (`8e4893c8`) correct the canary to
`rbp-0x38` and show the canary check blocks saved-register use before saved RIP,
a structural negative for that build. Cicap W205 (#3753) was ESTABLISHED AS
LABELED at the pinned-function scope and Imgproxy W204 (#3734) at W9's loopback
allocator-blocker scope, both with no grade change or r5; Imgproxy W10 also
attributes W9's abort to a natural free from `g_hash_table_unref` and measures
no consumption after a size-preserving body.

The 18:2x–18:3xZ edges close one synchronet residual and replay one real
libgphoto2 consumer write. Synchronet W11 (`a0050050`, `ce0a0208`, `90ad0c88`)
records the exact pty-req TERM length at the encryption boundary (6 PASS /
0 FAIL), preserves the first replay's 5 PASS / 1 FAIL port-settling race and
replays clean `git archive ce0a0208` with matching digests; it excludes
client-side truncation at that measured boundary but is not a ciphertext
capture. Libgphoto2 W174 (`2ac219c2`) replays W172's real `gp_file_save()` write
from clean `git archive 833729ad` and finds layout, not the primitive, as the
sensitivity: `DRAIN=22` missed `priv`, `DRAIN=23` restored the victim and the
29-byte marker. Assimp W18 (`5424cec5`) measures a document-own-begin restore
control and corrects W14's over-broad "no clean import" wording. AwsLc
W210/W211 (`3826ca48`, `e9b02506`) generalize the in-tree BIO bound to `B=kb+r`
and confirm the OOB with 3DES-EDE-CBC (`b=8`) into `malloc(15)`, 11 PASS /
0 FAIL. Frontier staged Gpgme2Shell on CVE-2026-129975 (GPGME status `realloc`
double free): 19 PASS / 0 FAIL from the pinned-statement harness with chosen
`0x48`/`0x5a` in the stale allocation; rung 3 confirmed, rung 4 PARTIAL,
author-only at staging. The operator later admitted it as the 133rd route, and
witness #3796 later ESTABLISHED the pinned-statement scope with its bounds NIT
fixed; the W1-W5 real-build and wire limbs stay author-side, no grade change.
All other limbs stay author-side/unwitnessed except the named witness verdicts;
rung 5 stays UNKNOWN throughout.
The 02:0xZ operator wake admitted the three frontier-staged families under
standing #6 as routes 138–140 (`open5gs2shell`, `yojimbo2shell`,
`libsshch2shell`), each with a hy4-flash route, both resolver entries, three
wake units from the EXACT full-flag sync at pin `0d686bba…d528a`
(`written 9, removed 0`), its existing two-pane window (146/147/148), and a
row above. The trace below is the staged evidence the admissions were checked
against; the new rows are the current record.
`open5gs2shell`: CVE-2026-116543 / GHSA-25v2-v588-jq8g, pinned Open5GS v2.8.0
empty-boundary SBI multipart parser, ASan `WRITE of size 1` 0 bytes after a
65-byte region, plain state-machine-forced `00 0d 0a` in an adjacent object,
21 PASS / 0 FAIL; witness W217 replayed from clean `git archive 22d70741`
with a matching trace hash, ESTABLISHED AS LABELED, no grade change or r5.
`yojimbo2shell`: CVE/GHSA-UNKNOWN, upstream fix `d3d4f339…`, pinned
`ProcessPacketFragment` final-fragment `memcpy` before the `blockSize` check,
ASan `WRITE of size 500` 0 bytes after a 1100-byte region, chosen `MISHE-OO`
at canary offset 300, 20 PASS / 0 FAIL with 7/7 pins, post-authentication,
witness UNKNOWN. `libsshch2shell`: CVE-2026-59850 (fixed 0.12.1/0.11.5),
pinned `channel_rcv_data()` closed-channel UAF, ASan heap-use-after-free
`READ of size 32` 0 bytes inside a 64-byte region, chosen `M` /
`MISHE-LIBSSH-UAF` at freed offset 16, 24 PASS / 0 FAIL, authenticated peer
required, witness UNKNOWN. At that 02:0xZ admission scope no real builds,
listeners, wire paths, pointer/IP control, commands or r5 in any of the
three; the 03:0x–03:1xZ lane above supersedes this boundary for yojimbo,
and the later open5gs/libsshch lanes supersede it for those two. Evidence:
`reports/frontier-open5gs2shell.md`, `reports/frontier-yojimbo2shell.md`,
`reports/frontier-libsshch2shell.md` and each `-status.md`.

The 07:0x–07:3xZ limbs add one staged family, two scoped witness verdicts and
two build-scope corrections without moving a rung cell, grade cell, route,
mind count or R5 cell. Drwav2Shell is FRONTIER-STAGED with a charter and live
window 152 but no route or admission: CVE-2026-11316, real public
`drwav_init_memory_with_metadata()` on pinned dr_libs 0.14.5, ASan WRITE through
a file-low-half pointer and 25/0 under GCC and Clang, with fixed 0.14.6 and
`safe` controls clean (`reports/frontier-drwav2shell.md`). Witness W213 (#4132)
returned ESTABLISHED AS LABELED for Yojimbo2Shell's rung-5 MECHANICS only at
the non-default, post-auth, `-no-pie`, lab-trampoline ceiling, with NO full r5;
W214 (#4161) did the same for Libsshch2Shell's five clean-archive real-build
suites, explicitly NOT ESTABLISHED as remote execution. N2n2Shell W9/W10 put a
wire-chosen consumed pointer in a clang `-O2` spill slot (valid value from a
debugger pre-read with ASLR off, both outcomes crashes, no marker, IP or
command); Open5GS W3 feeds a 396-byte body from a real 127.0.0.1 HTTP/2
listener into the pinned parser shim (13/0, 57/0 across four suites), still
not an Open5GS NF. Munt W188 is an author clean-archive determinism replay,
not a verdict. Frontier screened aribb24 CVE-2026-112280 out (AV:L, no fix
commit, crash-only claim); no row or mind was added. The earlier "no wire
request" and "no consumed pointer" sentences in the Open5GS/N2n rows are
superseded at those named build scopes by the row text above.

Peer edge `7a02ca45` (Synchronet W21) builds the shipped 3.20b release
(`db9c5d6f…`), sends a 64-byte chosen TERM over a loopback SSH pty-req and
observes `savedlines.first=0x465541544f4f2d45` /
`savedlines.last=0x5a5a5a5a46554154`; a separate gdb replay faults in
`listFreeNodes` (`link_list.c:78`) from that chosen list head. The 40-byte
control leaves both pointers nil; 4 PASS / 0 FAIL, author-only, no chosen IP,
shell, command, ASLR defeat, fixed-release control or r5. This strengthens the
earlier source-bound W20 teardown claim to a live shipped-build availability
result at the labeled scope; the witness verdict and rung cells are unmoved.

The 07:4x–08:5xZ limbs add one live real-NF availability result, a measured
pre-auth consumer path and a set of bounded negatives; no rung cell, grade,
route, mind count or R5 cell moved here. Open5gs2Shell W4 re-read the W3 wire
path in source (`wire.go` reads the h2 body into the child's stdin; `want`
checks received length, it is not a parser fixture) and replayed four suites
from `git archive dd55be12` (13/15/21/8 PASS, 0 FAIL); its "no NF available"
line was too narrow, and W5 provisioned a lab-local NRF: 21 `.deb`s extracted
under `lab/`, v2.8.0 tarball `a04d66f6…b56ab`, unmodified `open5gs-nrfd`
built 1886/1886 on 127.0.0.1:18777. A 396-byte h2c POST (fixture sha256
`0c46e003…e0ba`, one leading CRLF before the staged 394 bytes) kills the
vulnerable NF (curl rc 56, nrf rc 134, SIGABRT in `ogs_talloc_free` via
`parse_multipart` `message.c:3498` → `nrf_state_operational` `nrf-sm.c:78`);
the patched build, safe and staged bodies and a 396-byte `ABC` counterexample
all answer HTTP 400 with the NF alive. The author calls this rung 4
DEMONSTRATED process termination and asks for witness replay (pending); a
`git archive 56363d35` rebuild reproduced the four CASE lines with hashes
`71b4b7e2…7c8e` / `2b31633e…41a7`. The cell stays `◐`: the effect is
count-controlled, with no chosen pointer, IP or command and r5 UNKNOWN.

Cjose2Shell W212 measures the advisory's pre-auth claim inside the lab Apache
consumer: an unauthenticated `GET /private` with `Authorization: Bearer`
compact JWE (56-byte `encrypted_key`) reaches real `cjose_jwe_import()` and
`AES_unwrap_key` through pinned mod_auth_openidc 2.4.15.1 and logs
`W2B_AES_UNWRAP_KEY_REACHED`; with the lab 16-byte KEK, gdb at `jwe.c:602`
reads 48 chosen bytes in `cek[0..47]` while the patched module rejects with
`CJOSE_ERR_INVALID_ARG`. `sh lab/frontier/cjose2shell/w2/run-oauth-bearer.sh`
scores 9 PASS / 0 FAIL live and from a clean `git archive 35e02887` with the
four provisioned build trees copied in; deployed reachability, ASLR defeat
and witness replay stay out of scope. W213's private gdb probe finds only the
next `0x41` chunk's size word changed (`0x41` → `0x4853494d2d323132`) with no
live pointer adjacent; its two logs hash to `dc77299a…4ec49` and
`74fcd254…e387cb4` (recomputed here). N2n2Shell W11 removes W9/W10's debugger
pre-read: a non-PIE clang `-O2` supernode dereferences wire-chosen `0x42f3e8`
at token+1682 as `comm` and stays alive on a zeroed `.bss` target, while
garbage bytes fault at `sn_utils.c:2324`; `sh live/w11_fixed_pointer.sh`
scores 13 PASS / 0 FAIL. The address is binary-known only, not an ASLR-defeating
leak, with no marker, control-flow hijack, command or witness verdict (#3909
still owed). Ccextractor2Shell W5 closes the truncated-MEDIA hypothesis with
4160/64-byte GXF inputs (`669ad202…0745`, `e2b32bf3…4ee2`) that produce only
an ASan `READ of size 3` at `boundary+3973` through `memmove` → `process_data`,
no `read()` WRITE, no write primitive and no rung change.

Pgactive2Shell W12 checks the shipped non-instrumented 2.1.9 `.so`
(`3177a37c…162998`) without starting a cluster: the parser inlines at
`0x16290`, the consumed saved RA sits at `rbp+8`, and the cold `elog(ERROR)`
path longjmps; a glibc probe returns 4 for the only accepted conversion set
with the `%s` destination untouched and 5 for any non-empty tail, so the
pinned `!=4` test cannot be passed by an overflowing store. Libraw2Shell W24
forces the top-size field to `0x21001` under gdb and watches it and the OOB
halfword through `border_interpolate()` — neither changes and the inferior
exits normally; the setup is debugger-forced, no report grade moved.
Libgphoto2Shell W189 rechecks the GitHub and advisory APIs at 08:17Z: newest
tag still v2.5.34 (`a4ec9cc8…`), GHSA patched versions still Unknown, no
numeric fixed version.

Ruby2Shell's 08:1x–08:2xZ limbs close the consumer-provenance question:
shaping wire headers (L=0/60/120/240) and routes (+100/+300) leaves the
post-attack `request=0x21c/0x1f8` pops unchanged in ten survivors, so those
consumers are fixed-size framework allocations, not a request-shaped Stage-B
analog. A surviving `consH-20` geometry does carve a fake 0x20 chunk that the
request thread recycles with an on-thread free (Q), and a dev error page
reflects about 169 KB of params, but the first 60-run carve-landing sweep
(N=508/524/556 × drain 1024/1152/1280) found 11 survivors and zero reflected
corruption — an unproven oracle preserved as a negative. Stock, oracle-free
and persistent r5 stays NOT ACHIEVED; the harness-condition witness label is
unchanged.

Synchronet2Shell W22 applies the pinned `cb6d77dbca` fixed-form hunk to the
same shipped 3.20b build and replays the 64-byte TERM: 5 PASS / 0 FAIL twice,
`off41=00`, nil `first`/`last` and completed teardown, with an author
`git archive 7d3a0088` receipt (`evidence/CLEAN-ARCHIVE.md`); no measured DoS
rate, pointer/IP, command or witness verdict. Drwav2Shell's witness DM #4189,
folded at `f5dce89c`, replayed 25/0 with 3/3 pins and graded the chosen
target-bytes / same-size-class scope ESTABLISHED AS LABELED; the
different-size-class `CHOSEN_WORD_PRESENT=0` counterexample and the no-grade,
no-r5 boundary stay. Xschem2Shell's window 154 is registered 155/155 unique
and the clean archive of `6081c45b` replays 25/0 with both pin hashes. All
limbs above are author-side unless a witness marker is named; none moved a
rung cell, grade, route, mind count or R5 cell.


The 2026-11-25 10:5xZ fold admits StbVorbis2Shell as the 147th route and
supersedes its earlier FRONTIER-STAGED note above: the charter, hy4-flash
route, both resolver keys and three wake units now exist, and window 135 was
adopted without duplication. The exact full-flag sync reported `written 3,
removed 0` and the pinned full-flag doctor returned PASS / GREEN rc 0. The
staged real-library grade is unchanged: rung 3 ASan and rung 4 PARTIAL at a
repeating file-chosen word written past an 8-byte allocation, with NO r5 and
no witness verdict. No grade, rung, witness or R5 cell moved by admission.

The 2026-11-25 11:2xZ fold admits Ctranslate22Shell as the 148th route and
supersedes its earlier FRONTIER-STAGED note above: the charter already
existed, the hy4-flash route and both resolver keys were added, and the exact
full-flag sync reported `written 3, removed 0`; path enabled/active and the
pinned full-flag doctor returned PASS / GREEN rc 0. Window 155 was already
live and registered and was adopted without duplication. The staged grade is
unchanged: rung 3 pinned functions with ASan `WRITE`, rung 4 PARTIAL
file-chosen bytes at one offset of a stand-in 16-byte region, NO r5 and
witness UNKNOWN. No grade, rung, witness or R5 cell moved by admission.

The 2026-11-25 08:5x–13:0xZ fold covers 98 author edges and corrects the
Open5gs2Shell, Mcuboot2Shell, Xschem2Shell, StbVorbis2Shell and
Ctranslate22Shell rows above; rung cells, the route/mind count and the R5
cells stay put. Xschem2Shell W2 is the one new independent verdict in this
window: witness W216 replayed a clean `git archive 42e0f33f` (25/0 harness,
3/0 real unrenamed `main`, same ASan `WRITE of size 8` at pinned `:130`,
allocator-derived readback, fixed rejecting) and graded ESTABLISHED AS
LABELED with no grade change; the row's earlier "witness UNKNOWN" is
superseded. Cjose2Shell W216 and Gpgme2Shell W15 only verified queued replay
offers and corrected a stale verdict line; neither returned a new verdict.
Gpgme2Shell's #4333 W11 offer is UNKNOWN (wake started 12:33:50Z, no settled
output at 12:49Z), not GREEN and not declined.

Drwav2Shell W4 (`0a16d1ef`) adds a file-chosen control-flow diversion in a
non-PIE `libsndfile` consumer: six consecutive cue-desync u32 writes take
`libsndfile__sf_close`/`sf_readf_short`/`sf_readf_int` at `0x41e118..0x41e130`
and call an `LD_PRELOAD` benign marker at `0x50000000`, observed in a gdb
backtrace; fixed 0.14.6 and a safe loop count produce no marker, 14 PASS /
0 FAIL, author-only, no wire or r5. Libsshch2Shell W12 (`d9ef7b38`) derives
the callee address from the compiled ELF symbol table and drives a separate
client process (7/0) while a source-level survey closes the
library-internal close-free shortcut; Synchronet2Shell W24 (`3e681d41`,
clean-archive receipt `3c85349e`) shows the W21 faulting load reads
`0x20(%rax)` with `rax` equal to the wire-chosen `savedlines.first`, 7/0,
with the direct `si_addr` cross-check preserved as a negative because gdb
returned `(nil)`. Open5GS W6 and Mcuboot W1/W2/W3 moved their evidence into
real NF / real pinned decryptor lanes as recorded in their rows, still
without a witness verdict on those new scopes.

Stbvorbis2Shell W203 supersedes the staged "~1.07e9 writes" loop-bound
description with a measured bounded extent (corrected by W204 to 30 words /
120 bytes below); Ctranslate22Shell W1/W2 add a
real-source ASan consumer and a bounded real-heap pointer-control negative.
Vtkdicom2Shell W3/W4 localize the plain-build SIGSEGV to a stale OOB
`Value.V` decref that a nine-size OB sweep leaves unchanged, not file bytes
or a file-influenced pointer. OpenEXR W200 scans the modules loaded by the
pinned `exrcheck` and finds no `rsi`→`rdi` one-gadget route to an `exec*`
call from the W197 shape (bounded negative, receipt `d5aef12d`). Hping3 W11
surveys six more rebuild layouts and extends the chosen `i`/`j` replay to
clang `-O2` without finding a pointer or GOT entry in the 251-byte span.
Ruby2Shell closes the named stock leads — keep-alive same-thread pairing at
Puma `min=3/max=3`, T-header repair, consH-20 tcache retarget, main-arena
libc oracle, 48-part/filler-first, and a Sinatra 500-page GC-address oracle —
and pins wire-only chosen-header coverage to `N ∈ [540,588]`; stock,
oracle-free and persistent r5 stays NOT ACHIEVED and the labelled
harness-condition R5 cell is unchanged. Libraw W26, Munt W189, OpenEXR W200,
Libsshch W10–W12, Open5GS W6, Mcuboot W1–W3 and Synchronet W24 add
clean-archive receipts. Solanum2Shell was staged by frontier W230 with a
clean-archive 18/0 receipt and was subsequently admitted as the 149th route;
see `docs/task.md` and `docs/reproducibility.md`. No grade, rung, route, mind
count, witness cell (except Xschem's verdict text) or R5 cell moved by this
fold.

The 2026-11-25 13:1x–15:3xZ fold covers the 39 author edges after the solanum
admission and corrects the StbVorbis and Hping3 rows above. No commit in this
window carries an independent witness verdict: every replay offer asked for
one (Ctranslate2 W3/W4, Solanum W1/W2, Cjose W217/W218, Gpgme #4333, Codebase
W19/W20, Synchronet #4421, Drwav #4238, Mcuboot #4236, Stbvorbis #4336,
Vtkdicom #4276) stayed UNKNOWN, and the witness wake at 14:02Z failed to
start for the known person-owned engine-cap reason. No rung cell, grade,
route, mind count or R5 cell moved.

The row corrections are the real-consumer and real-build boundaries.
Stbvorbis2Shell W204 sets the guarded extent to 30 words / 120 bytes and
shows all 30 file-chosen words in an
adjacent live object's canary and pointer-typed field (`run-object.sh` 9/0,
pointer read back but never dereferenced); W206 drives the crafted OGG through
real SDL_mixer's public `MIX_LoadAudio_IO()` into its vendored v1.22 header
with ASan `WRITE of size 4` at `stb_vorbis.c:4040`, clean fixed and safe
controls, 12/0 live and from a clean archive. Hping3Shell W12 provisions the
Ubuntu 24.04 `3.a2.ds2-10build2` package: its source `display_ipopt.c` is
byte-identical to the pin, but the shipped binary imports `__memcpy_chk` and
aborts before the store under the crafted long RR (rc 134, valid-RR control
clean, `wire/replay-distro.sh` 5 checks from a clean archive) — a
build-dependent DoS on that package only, not a fix and not a grade change.

Other author limbs deepen admitted lanes without a new capability. Mcuboot W4
drives a real loopback SMP image-upload packet through the real
`boot_serial_input()`/`bs_upload()`/TinyCrypt path into the pinned OOB sink
and reads 16 wire-chosen bytes at the OOB destination (6144/7168) while 4104
SIGSEGVs and 2048 is in-bounds. Solanum W1/W2 move the ASan
`WRITE of size 564` and the plain chosen-byte readback into a real ASan IRCd
over authenticated loopback S2S KILL. Pgactive W-W crashes both apply workers
with an ASan `WRITE of size 8` in a two-node 2.1.9 conflict race; the 2.1.10
library is clean and the earlier crash proved to be a harness bug. Cjose
W217/W218 measure 144 chosen bytes in a real bearer lane and identify the far
object as OpenSSL's 56-byte RNG `CRYPTO_RWLOCK`, written at +0x18 with no
dereference. Ctranslate2 W4 sees a file-derived value in a live
`StorageView._size` but the `size != _size` guard blocks the copy, and its
`sysmalloc`-prev_size redirect hypothesis is disproved. PHP wake 61 repeats
the tinyfilemanager exec chain with two changed attacker constants (8.4.27
marker/id, 8.4.28 clean), still conditioned on the shim SIGKILL. The rest are
bounded negatives and receipts: FontForge W23's tcache-disabled sweep finds
no code pointer, Drwav W5/W6 finds a network-facing metadata caller only on
patched 0.14.6, Libraw W27/W28, Vtkdicom W5, Libsshch W13, Libgphoto2 W192,
Synchronet W25 (19/0 one-command replay of W21–W24), CodebaseMemory W19/W20
and the roughly 300-process Ruby result chain (order arms answered,
deterministic splitter measured, 0x650-band and giant-pop claims closed,
honeypot parity negative) leave stock/oracle-free/persistent R5 NOT ACHIEVED.
Recipes and pins are in `docs/reproducibility.md` and `docs/task.md`.

The 2026-11-25 16:1x–16:2xZ fold covers the 19 commits after `913d0415`
(signal head `a3321f38`, live head `624df6c1`). None touched README or
`docs/*`; none carries an independent witness verdict. No rung cell, grade,
route, mind count or R5 cell moved. The Solanum row above is corrected in
place: its "no real ircd build, S2S wire path" boundary was stale after W1/W2.

Openexr W202 reaches a command in the unmodified pinned 3.5.2 `exrcheck -c`
(`reports/openexr2shell-file-level.md` §W202). The file chooses `memcpy` as
the indirect-call target and a 104-byte source whose bytes 96..103 hold libc
`__libc_system`, so `memcpy(ctxt, …)` overwrites `ctxt->free_fn` and the
trailing `attr_destroy()` call runs `system("touch /tmp/w202m")`; the PoC
sha256 is `7f3eda1b00f54b56ec75108f9012be6b035c8b6393ec1d7c2241f94be91e412e`.
Under gdb the arguments, the overwritten pointer and the command string were
read at the call, with the debugger forcing neither pointer nor call. Plain
`setarch -R` runs give vulnerable rc 139 plus marker, fixed 3.5.3 rc 1 `bad`
with no marker, and a valid baseline rc 0 with no marker; the ASan build
reports `heap-buffer-overflow READ of size 3072` at `internal_zstd.c:472`.
`sh harness/w202-benign-command.sh` printed `RESULT PASS` twice with five
byte-identical evidence hashes, and a clean `git archive 043a0d41` repeated
them. This is rung-4 mechanics at the rung-5 boundary, not R5: every run has
ASLR off for file-carried absolute addresses, the input is a local path, the
command is a benign `touch`, and the process then faults. The row's W188
"no command" sentence is scoped to that earlier steering limb.

Stbvorbis W207 observes the full OOB run in a real SDL_mixer consumer built
without ASan: `evidence/chosen.ogg` aborts rc 134 with
`malloc(): invalid size (unsorted)` and the safe input exits 0. gdb snapshots
all 30 file-chosen `0x4b434148` words at `c->multiplicands+8..+124`; the word
at `+24` rewrites the next free chunk's size from `0x91` to `0x4b434148`, and
no live allocation occupies the range. Padding the file to 4096, 65536 or
1048576 bytes leaves the address, neighbour and clobber unchanged.
`sh lab/frontier/stbvorbis2shell/run-consumer-heap.sh` passes 11 shell and
14 heap-word checks with the 12/0 ASan and fixed controls replayed. This is
chosen bytes in allocator metadata, still not a chosen word in a live
consumer-owned field; no pointer, command, wire or witness verdict.
A clean archive of `624df6c1` (SDL/SDL_mixer dependencies symlinked read-only
from the live lab) replayed every committed script at 16:27Z: 11/0 plus 14/0
heap-word, 12/0 consumer controls, 9/0 `run-all.sh`, 4/0 `run-seq.sh`, 12/0
`run-guard.sh`, 9/0 `run-object.sh` and 9/0 `run-neighbor.sh`, all rc 0. An
earlier archive of `0c8b7c75` failed because the gitignored safe input was
absent; `624df6c1` regenerates it inside the replay. Author receipt only.

Hping3 W13 writes a linear permutation to 187 reachable sbox bytes through
the crafted RR reply. The first RNG output byte is reply-chosen only when the
hidden `j` lands the index inside that reach: `j=222` gave index 5, `S[5]=4`
and observed low byte 4 (counterfactual 22), a clean run with `j=92` gave
index 131, `S[131]=130` and byte 130 (counterfactual 237), and `j=156` sent it
to index 195 outside the reach. A `127.0.x.x` template moved the destination
off `127.0.0.1` and was rejected by `waitpacket.c:94`; a full chosen IP is
not available. `sh wire/replay-perm.sh` runs baseline 3, attack 5 and fixed 3
checks (`REPLAY_PERM_OK: 3 stages`) from a clean archive of `feb3f33f`.

The remaining limbs are bounded negatives and receipts. Open5GS W8 proves
the OOB values are forced `00 0d 0a` repeats: arbitrary 36-byte suffixes
write nothing, substitutions break the chain, and CRLF injection only
re-arms it (`harness/bytechoice/run.sh` 11/0; clean-archive receipt at
`0a6c868d` gives 11/0 plus 21/0). Cjose W219/W219b sweep the real pre-auth
bearer lane over `enc`-selected CEK sizes: two plain builds fault in
`OPENSSL_sk_dup` and `_cjose_release_cek`, a 168-byte write replaces
pointer-shaped fields at `cek+0x80..0xa8` with `0x4141…`, but no vulnerable
case faults on the written value and all return HTTP 401 (18/0 and 11/0
receipts). Awslc W223 synthesizes W213–W216: no checked real caller has both
the withheld-block carry and the documented-minimum destination, W216's Node
22.11.0 has one slack byte, and unprovisioned applications stay UNKNOWN.
N2n W16 adds `sh live/replay-all.sh` with seven passing lanes from a clean
archive of `a2284de2`; its first 4/3 run was a missing gitignored
`community.list`, fixed by reading the pinned tarball. Solanum W3 reads the
post-buffer window in a plain real ircd: `buf` sits at vaddr `0x5220`, size
`0x200`, in `.bss` ending at `0x5420`, with no writable object following it
(18/0 harness, 6/0 ASan controls). All replay offers stayed UNKNOWN.

The 2026-11-25 16:3x–17:1xZ fold covers the author/config edges after
`827436b5` (signal and live head `4e5ec955`). No independent witness verdict
arrived; no rung cell, grade, route, mind count or R5 cell moved. The signal's
vrpn correction is already present: W23 maps the large-index exit-139 rows to
the NUL store at `sender_name + index`, not an outside-stack assertion.

Ruby2Shell's stock-app allocator model was corrected again: glibc tcache ends
at chunk size `0x420`; each embed-legal multipart part makes two
content+9 slices and one next-power-of-two value buffer. Order arms falsified
the earlier "never swept" closure, but the upcase's own result allocation
deterministically splits the forged grown victim. Sacrificial-shield runs
completed the full sequence 6/12; honeypot-parity arms survived 8/12 and 7/12,
yet every `0x648` claim pop landed on a merged value chunk, never the grown
victim. The exact-fit giant-pop claim has no physical overshoot, so the poison
chain is structurally closed for stock/oracle-free/persistent R5 after roughly
300 fresh processes. Two arms produced the first stock Ruby-VM SIGSEGVs when
prettyprint consumed the split-cascade corruption: a wire-driven crash, not a
steered allocation, command or grade change.

Cjose W220 identifies W219b's far object as the live Jansson header hashtable
`jwe->hdr`, not an unknown allocation. The overflow replaces its type and
buckets, but pinned `value.c:106-113` checks `json_is_object()` before
`hashtable_get`; the first post-unwrap lookup fails closed and returns HTTP 401.
The identity/use replays scored 7/0 and 11/0. Libsshch W14 removes the harness
trampoline from the callee path: an authenticated loopback client selects real
libc `system()` and its `channel->session` argument from recycled wire bytes,
creating the benign marker in 6 PASS / 0 FAIL. The command string remains an
app-chosen static global and the addresses are fork-peer ASLR-local; this is
unwitnessed rung-5 mechanics, not established remote execution.

Synchronet W26 measured shipped 3.20b under four concurrent loopback SSH
pty-req probes. The imported node-exhaustion prediction failed (7/3, preserved):
the process instead SIGSEGVs at first teardown and the fifth client is refused.
After correcting only the fixed-control assertion, the replay and a clean
archive both scored 13/0; the fixed form served all five sessions. Openexr W203
closes W202's fixed-address staging route: all ten ASLR-on PIE/non-PIE runs
faulted without a marker, and no file-filled fixed-address staging buffer was
found. W202 remains an ASLR-off, local-file, benign-command rung-4 limb.

The remaining edges are replay/provenance work: Solanum W4 adds one-command
18/0 harness plus 6/0 real-ircd controls; CodebaseMemory W21 repairs witness
wrapper assertions and TERM/INT/HUP evidence restoration, with 44/0 assertions
checked lane-by-lane but no uninterrupted final-wrapper run; Munt W191 resolves
the second CISA exploit-tagged link as the same inaccessible note, whose mirror
contains only an unexecuted, truncated illustrative trigger. Route policy now
keeps exactly one `opencode-go/hy4-flash-free` candidate per role at
`max_parallel: 5`; the same-day hungerg-free fallback was retired after rate
limiting, and `docs/runtime-pin.md` carries the exact allowlist and limits.


The 2026-11-25 17:1x–17:4xZ fold covers the ten author edges after
`869e8435`. Only one carries an independent verdict: witness W219 (#4481)
returned **ESTABLISHED AS LABELED** for Solanum2Shell W5, replaying
`bash lab/frontier/solanum2shell/replay-all.sh` from a clean `b8885fcc`
archive (18 PASS / 0 FAIL, then 6 PASS / 0 FAIL), hash-checking both pins and
rebuilding them into its own prefixes. Its unauthenticated-peer counterexample
got `Incompatible TS version`, no KILL and zero ASan, confirming the PR:H
prerequisite. The published grade is rung 3 confirmed in a real ircd process
and rung 4 PARTIAL with chosen length and bytes at a known global offset; no
pointer, command or r5. This verdict text supersedes the row's earlier
"witness UNKNOWN"; no rung cell, grade, route, mind count or R5 cell moved.

Ruby2Shell's corrected-model tcache consumer was confirmed, but the stock
chain stays closed. On the class that genuinely has glibc tcache (`<=0x420`),
`bash lab/repro/ruby2shell-stageC.sh` got 5/5 `verdict=poisoned` with an mtrace
pop at the forged target and 3/3 clean controls. The HTTP replay
`lab/repro/ruby2shell-stageC-http.sh 3 2` got 3/3 request-thread attacks with
16 chosen bytes at the nominated address (`7a` repeated) and a pop line there,
2/2 clean controls, and all three attack processes aborting at teardown. The
wire-only class probe then failed in 12 fresh unmodified processes
(lab/repro/ruby2shell-stock-leakclass.sh with
`RUBY2SHELL_LEAKCLASS_COUNT=12`): 0 `q38=0x251` tcache-`next`
landings, 0 window `P` allocations, 0 window `Q` frees, and no arena base on
the wire in the one surviving response pair. Stock/oracle-free/persistent r5
remains NOT ACHIEVED; the harness-condition r5 cell is unchanged.

Hping3Shell W14 extends chosen-byte control from W9's zero fill to two measured
nonzero values: with `S[0]=0x7e` or `0xc3` and `i=0x20`, `j=0x10` in the clang
`-O0` build, 8/8 attack checks passed with 16/16 chosen low bytes and
counterfactual bytes `e7`/`e3`, against 4/4 clean no-inject and locally patched
controls. `bash lab/frontier/hping3shell/wire/replay-target-byte.sh` scores 4
baseline, 8 attack, 4 fixed checks, rc 0; the same frames also passed 8/0 under
clang `-O2` (author-side rebuild). This is one IP octet, no full IP, pointer,
command or grade change.

The remaining limbs are bounded negatives and replay receipts. PHP W62's
deployment-style `RLIMIT_FSIZE` at the calibrated cut K=1019 makes the kernel
write exactly 1019 of 1892 bytes with no SIGXFSZ, but the live FPM worker stays
alive and the splice is gone at consume time: no promotion, takeover or marker
on 8.4.27-app, 8.4.28-app clean, full r5 still UNCLAIMED. Libraw W29 writes a
file-chosen, glibc-plausible top-chunk size that turns W21's allocator abort
into a clean exit; the low word varies across rebuilt binaries (`b5e1`/`b621`
observed), so only the size-class claim is build-stable, with no later
allocation overlapping the span and no grade change. Gpgme W17 adds one
clean-archive wrapper (`lab/frontier/gpgme2shell/realbuild/run-witness.sh` with
an output directory) scoring 25 PASS / 0 FAIL here; the queued #4333 replay offer stays
UNKNOWN. KiCad's redundant 302243840-byte AppImage tar was removed after both
tar and extracted hashes were verified; the extracted binary hash and replay
recipe are unchanged.

The 2026-11-25 18:1xZ operator wake admits Aspell2Shell and FreeImage2Shell
as declared target minds under standing #6 after replaying both staged
harnesses: Aspell 14 PASS / 0 FAIL and FreeImage 9 PASS / 0 FAIL, with the
primary advisories, pins, fixes, charters, walls and live two-pane windows
157/158 checked. Both lanes keep their staged grade and witness UNKNOWN.
Both resolver-key pairs are registered. Engine-route registration and the
generated path, debounce and per-role slice units remain missing because
engine-config changes and full-flag sync are person-reserved. The route
registry therefore remains at 149 roles while 151 target minds are declared;
the repository OMP-only checker is RED for exactly those two missing routes,
and doctor is RED for the six missing unit files. No route or operational
unit delivery is claimed. The pinned single-model OMP checker also remains
stale against the owner-directed two-model routes; it is not hand-greened.

The 2026-11-25 18:0x–18:5xZ fold covers the 30 author edges after
`77a552ce`; only the operator admission `fde6f94e` touched docs paths and
self-folded its two rows. No edge outside that admission carries an
independent witness verdict. The new verdict is Openexr2Shell W204, already
folded into its report: witness wake W218 (#4457) returned ESTABLISHED AS
LABELED for the benign `touch` through an unmodified `exrcheck -c`, matching
all five committed hashes from a clean `34832cb6` archive; ASLR was off, the
EXR was local, no wire target existed, full r5 stays UNKNOWN and the verdict
does not cover W203's ASLR-on negative. PHP2Shell W63 extends the preserved
W62 short-write negative: a native `RLIMIT_CPU=1s`/`RLIMIT_FSIZE=1024` chain
(`DEATH_MODE=rlimit PREBURN=1`, ASLR on, no phase-2 LD_PRELOAD) reaches the
author-side rung-5 gates 1–5 in a live 8.4.27 FPM worker, with marker
`php2shell-r5-w63-final-1837` and output hash `7df36e9a…`; the fixed 8.4.28
build leaves exactly 1024 bytes and no marker. Gate 6 stays OPEN: without a
clean-checkout replay that varies the command, full r5 is NOT ESTABLISHED.
Libsshch2Shell W16 puts a wire-resident `touch` string at a probe-derived
slot and calls the real libc `system()` (6 PASS / 0 FAIL, marker side effect,
fixed and bad-callee controls clean); a stale hard-coded slot scored 2 PASS /
4 FAIL, and the callee address remains forked-peer ASLR-local, so this is
author-only rung-5 mechanics, not r5.

The remaining limbs are chosen-byte reaches, replay receipts and negatives,
all with unchanged grades. Stbvorbis2Shell W208 drives file-chosen bytes
into a live glibc `_IO_save_base` in a real consumer (17/0; `_IO_save_base`
`0x4b4341484b434148` at k=27, plain rc 139, fixed and safe rc 0) but only
rung 4 PARTIAL. Vtkdicom2Shell W6 pins the exact VTK 9.5.2 bundled source,
ASan `WRITE of size 4` 32 bytes past a 136-byte region, and W7's
predecessor-item grooming yields only stale `Value` headers, no pointer.
Openexr2Shell W205 finds no libc-resident alternate `ctxt` victim under
ASLR on (`COMMAND_PLT_CALLS=0`), W206 finds no same-mapping command call
among the eight function-pointer slots; Fontforge2Shell W24's third PIE
build and W25's late Save state both score `CAND_COUNT 0` for a code pointer.
Libgphoto2Shell W193 overwrites 16 bits of `priv` with one ASLR-on fork-sweep
hit (16/0) but no absolute target or command. Pgactive2Shell's
`local==NULL` delete/delete conflict aborts with signal 6 live (fixed clean,
clean-archive replay exact) with a fixed boolean, not an attacker byte.
Synchronet2Shell W27 finds a 52-byte wire TERM threshold (13/0) on shipped
3.20b; the 48-byte arm corrupts only `line_delay`. Hping3 W15, N2n W17,
Openexr W205/W206, Fontforge W24/W25, Libsshch W16 and Pgactive receipts
were replayed from clean archives, and Ruby's free-order map, tcache
saturation, escaped disposition and stock small-class overlap arms remain
bounded negatives: no claim/pop, command or persistence, and stock RCE
stays NOT ACHIEVED. No rung cell, grade, route, mind count or R5 cell moved
by any of these limbs.

The 2026-11-25 18:56–19:2xZ fold covers the eleven author edges after
`f777c40d` (through `08e18012`); none touched docs paths and none carried an
independent witness verdict. Vtkdicom2Shell W8 only re-points both reports at
the exact-source replay material in DM #4503 (unanswered; #4276 is the earlier
W3 offer), leaving its witness UNKNOWN. PHP2Shell W64 extends W63's native
`RLIMIT` chain with a two-pool `RLIMIT_FSIZE=1024` unlock gap: a size-limited
FPM producer stays alive while a second, unlimited pool consumes the session,
so no CPU freeze, SIGKILL or phase-2 `LD_PRELOAD` is needed. The armed wire
request creates `php2shell-r5-w64-gap-chain` under `uid=1000(mesh-home)`
(hash `91a18f97…`); a varied SID creates `php2shell-r5-w64-gap-varying`
(`6bd15181…`); fixed 8.4.28 leaves a 78-byte session and no marker
(`2a38515d…`). Author-side rung-5 gates 1–5 are reached, gate 6 stays OPEN
and full r5 is NOT ESTABLISHED.

Libsshch2Shell's pinned-tree survey finds five callback registrations and no
in-callback channel free in any of them; `ssh_channel_close()` itself does not
free, so the in-callback free remains harness/app-owned. Ruby2Shell adds opt-in
`MTRACE_TID=1` tracing: in seven surviving N=972 processes all 22 planted
`0x3f1` allocations and frees, the last `0x400` free and the `0x3f8` upcase
allocation carry one worker tid, closing same-thread attribution; the tcache
arm's upcase took a newer planted slice, wrote `0x53` and aborted in
`munmap_chunk(): invalid pointer`, with no claim pop or command. Hping3Shell
W16 makes `--rand-dest 127.T.T.T` emit three chosen octets (the first fixed by
the template): T=1 predicted 20/20 destinations and got 15/16 `127.1.1.1`,
T=`0x2a` got 10/16 `127.42.42.42`, and a clean-archive replay scored
`REPLAY_MULTIOCTET_OK: 12 checks`; no pointer, command or witness.

Openexr2Shell W207 tests the file-to-argv address-leak lead and returns
NEGATIVE: all 12 ASLR-on `exrcheck -c` cases have `CASES_WITH_HEX_OUTPUT=0`,
`sh lab/openexr2shell-real/harness/w207-leak-negative.sh` gives `RESULT PASS`
with hash `d5d7b448…`, and a clean `git archive 2f12c2e5` replay with the
gitignored cases symlinked is byte-identical; `-s` on a FIFO timed out at 40 s
and stays UNKNOWN. Drwav2Shell W8 replays three exact consumer headers:
Moondust, Sphaira and Yup each keep `CHOSEN_WORD_PRESENT=1` and rc 0 for the
chosen metadata, fault the bad arm at `drwav__read_cue_to_metadata_obj:2281`
and leave the safe arm clean. Sphaira's mount-to-browser-to-audio path is
user-driven remote-file playback, not a listener, and its build is
switch-only; no exactly-0.14.5 consumer was found (absence unproved), so no
r5. This supersedes the Drwav2Shell row's earlier no-application boundary at
the exact-source-header level only; no running Linux application or listener
was exercised. Aspell2Shell's full release ASan build dumps 255–511-byte
words at rc 0, with complete NUL-terminated bytes and no ASan report or
crash; the `aspell -a` suggestion probe is UNKNOWN.
No rung cell, grade, route, mind count or R5 cell moved by any of these
limbs; all offers remain unanswered.

Three further author edges landed while this fold was in progress and are
recorded here rather than left as new stale boundaries. Hping3Shell W17
replaces W16's repeated-octet fill with a 187-byte reply-chosen pattern that
puts three **distinct** octets into one loopback packet: `127.11.22.33` and
`127.44.55.66` were each seen with all 20 full destinations predicted from
read-only GDB state and 1/16 post-attack hits, and a 500,000-trial search
found no swap-stable pattern for repeated packets. A clean `git archive
266144f0` replay scored `REPLAY_PATTERN_OK: 3 stages` (baseline 4, attack 5,
fixed 4 PASS) with the pinned source hashes rechecked; still no full IP,
pointer, command or witness verdict. FCEUX2Shell W233 is **staged, NOT
admitted**: CVE-2026-136918's UNIF `MAPR` chunk wraps a malloc argument at
`0xffffffff`, and the pinned `SetBoardName()` harness scores 14 PASS /
0 FAIL with ASan `WRITE of size 19` just past a 1-byte region and file-chosen
bytes through rc 42; no row, route, live emulator, command or verdict follows
from staging. No rung cell, grade or R5 cell moved by these limbs either.


## How the plant works

Each admitted family is its own mind with its own tmux window: 151 target
minds — `ruby2shell`, `php2shell`, `node2shell`, `apache2shell`,
`mosquitto2shell`, `dragonfly2shell`, `postgres2shell`, `brotli2shell`,
`freeradius2shell`, `falkordb2shell`, `freeswitch2shell`, `freerdp2shell`,
`xrdp2shell`, `gst2shell`, `babelfish2shell`, `bzfs2shell`,
`kamailio2shell`, `iperf2shell`, `uftpd2shell`, `accelppp2shell`,
`indiserver2shell`, `shairport2shell`, `asterisk2shell`, `netatalk2shell`,
`iondtn2shell`, `unbound2shell`, `opensips2shell`, `janus2shell`,
`rsyslog2shell`, `proxysql2shell`, `strongswan2shell`, `memcached2shell`,
`ipfixcol2shell`, `srs2shell`, `389ds2shell`, `kermit2shell`,
`gpfdist2shell`, `gct2shell`, `imgproxy2shell`, `firebird2shell`,
`rtp2httpd2shell`, `zephyr2shell`, `zenohpico2shell`, `libwebsockets2shell`,
`pillow2shell`, `datasketches2shell`, `rabbitmqc2shell`, `hnswlib2shell`,
`asn1scc2shell`, `awslc2shell`, `iec618502shell`, `openjpeg2shell`,
`wolfssl2shell`, `htslib2shell`, `civetweb2shell`, `cicap2shell`,
`open625412shell`, `knotresolver2shell`, `ats2shell`, `exim2shell`,
`netty2shell`, `wamr2shell`, `perl2shell`, `msquic2shell`,
`proftpd2shell`, `soes2shell`, `vrpn2shell`, `netx2shell`, `wazuh2shell`,
`mapserver2shell`, `nanomsg2shell`, `pgpool2shell`, `pgactive2shell`,
`ud3tn2shell`, `bacnet2shell`, `fastnetmon2shell`, `pnet2shell`,
`snac2shell`, `inetutils2shell`, `h2o2shell`, `hping3shell`,
`libyang2shell`, `msgpack2shell`, `sofiasip2shell`, `ytnef2shell`,
`baresip2shell`, `connman2shell`, `pppd2shell`, `pxeicmp2shell`,
`libssh22shell`, `tacplus2shell`, `ntpsec2shell`, `uhttpd2shell`,
`libvnc2shell`, `gdbserver2shell`, `erlang2shell`, `minisnmpd2shell`,
`ettercap2shell`, `ghostscript2shell`, `llamarpc2shell`, `zlib2shell`,
`snap72shell`, `mongoose2shell`, `modauthoidc2shell`, `radvdump2shell`,
`fluentbit2shell`, `ffmpeg2shell`, `psqlodbc2shell`, `thrift2shell`,
`libvips2shell`, `jq2shell`, `openexr2shell`, `libheif2shell`,
`fqterm2shell`, `munt2shell`, `libfontenc2shell`, `libgphoto2shell`,
`kicad2shell`, `ndpi2shell`, `n2n2shell`, `synchronet2shell`,
`sdlmixer2shell`, `cjose2shell`, `thorvg2shell`, `busybox2shell`,
`fontforge2shell`, `fltk2shell`, `contiki2shell`, `libraw2shell`,
`gpgme2shell`, `imagemagick2shell`, `codebasememory2shell`, `assimp2shell`,
`open5gs2shell`, `yojimbo2shell`, `libsshch2shell`, `socat2shell`,
`ccextractor2shell`, `mcuboot2shell`, `drwav2shell`, `vtkdicom2shell`,
`xschem2shell`, `stbvorbis2shell`, `ctranslate22shell`, `solanum2shell`,
`aspell2shell` and `freeimage2shell`. Each builds
affected harnesses, drives toward rung 4 and authors its report under
`reports/`.

Four cross-cutting minds: **frontier** hunts public advisories and hands a
reproducible harness to the operator; **docs** keeps this README and `docs/`
true to the shipped code and is woken by the `repo-change` commit signal;
**witness** re-runs every claim from a clean checkout; **operator** is the
owner's delegate for scoped approvals and admissions under recorded standing
permissions.

An idle wake owes a bounded, falsifiable experiment deeper toward rung 4 (or
rung 5 where a measured path exists) — or, once that rung is closed on the
tested build, an adjacent lane in the same source tree. New products and runtimes go to frontier/operator for a new mind.
Negative results and UNKNOWNs are preserved in the reports; the columns above
map the boundary actually reached. All minds run on
`opencode-go/hy4-flash-free`; the 2026-11-25 hungerg-free fallback was
retired the same day after rate limiting.

## Follow along

- Live dashboards:
  `tmux -S /tmp/tmux-1000/mishe-tauftauf2shell/tmux-1000/default attach -t mishe-tauftauf2shell-current`
  — one window per target mind above, plus `frontier`, `docs`, `witness`,
  `operator`, `chat`, `git` and `wakes`.
- [docs/task.md](docs/task.md) — verified ground truth for each CVE, the
  staged plan and the rules of the lab.
- [docs/reproducibility.md](docs/reproducibility.md) — pins, commands,
  expected bytes and evidence policy for independent verification.
- [docs/rce.md](docs/rce.md) — the rung-5 acceptance contract and first lane.
- [docs/runtime-pin.md](docs/runtime-pin.md) — the pinned runtime and every
  local change made to it.
- [docs/self-healing.md](docs/self-healing.md) — duties, signals and the
  no-force publication/reconciliation design.
- `reports/` — the investigation reports and live status files; `lab/` — the
  builds and harnesses.

## License

[CC0 1.0](LICENSE) — everything here is public domain.
