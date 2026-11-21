# mishe-tauftauf2shell

A lab that pushes "X2Shell" memory-safety bugs in language runtimes and
network servers to **rung 4 — demonstrated security impact** — and publishes
every step, including the ones that fail. Every build, listener and debugger
stays local on `127.0.0.1`; nothing scans or contacts an external target.
Everything here is CC0.

## Evidence key

The rungs are depth of proof, not boxes to tick:

- **R1** suspected vulnerability — source or advisory reasoning, no trigger.
- **R2** reproducible crash — a deterministic input faults the lab process.
- **R3** confirmed memory corruption — ASan/UBSan/Valgrind/gdb observes bad
  memory state, not just a fault.
- **R4** demonstrated impact — chosen bytes, pointer control or a benign
  marker exercised in the lab build.

Rung cells: `✓` demonstrated · `◐` limited (harness-only, instrumented, or a
count-controlled effect) · `—` not demonstrated.

Top-rung tiers: **LIVE** = real process on loopback, with the request/wire path
reached; **CODE** = verbatim pinned upstream or library bytes, in-process;
**HARNESS** = extracted or synthetic harness only, no real consumer. A
**Witness W##** or **tape #N** marker means an independent replay was accepted
at the exact scope named in that row's boundary; no marker means no
independent replay at that scope. Author reports are never acceptance.

## What it has achieved so far

| Target | R1 | R2 | R3 | R4 | Evidence / boundary |
|---|---|---|---|---|---|
| **Ruby2Shell** | ✓ | ✓ | ✓ | ✓ | **LIVE** — chosen bytes at a chosen offset on stock glibc, driven by one multipart POST through default Sinatra and `rails new` before routing/CSRF; Stage C tcache/pointer control in-process. Witness: #51 in-process chain, #65 HTTP request-reachable on both stacks, #89 Stage C pointer control. Not witnessed: control-flow hijack, target chosen from attacker string content, persistence. [Report](reports/ruby2shell-investigation.md) |
| **PHP2Shell** | ✓ | ✓ | ✓ | ✓ | **LIVE/CODE** — main lane rung 4 CONSTRAINED on CGI and mod_php; wake-56 DOM lane reaches read-side chosen-pointer rung 4 on a plain local CLI (`USE_ZEND_ALLOC=0`, N=88, fault only), no SAPI, arbitrary write or marker there. Witness: #138 CGI and #258 mod_php rung-4 constrained; #126, #208, #287 rung-3 grades; #98/#103/#108 splice rungs 1/2. DOM lane author-observed; FPM stays rung 3. [Status](reports/php2shell-status.md) |
| **Apache2Root** | ✓ | ✓ | ✓ | — | **CODE** — rung 3 chosen-byte placement at a capacity boundary on real ASan httpd 2.4.70 under gdb, fixed control clean; Stage C closed unreachable on this host (wire-byte alphabet, Huffman probe). Adjacent L2–L6 rung 3; L1/L7/L8/L9 rung 1–2 (L9 is auth-state corruption, no confirmed UAF). No independent ESTABLISHED verdict: #279 found a probe defect, #294 replayed the repair with no verdict change; default-MPM RCE stays a claim. [Report](reports/apache2shell-investigation.md) |
| **Mosquitto2Shell** | ✓ | ✓ | ✓ | ✓ | **LIVE** — ASan 256-byte write past a 1-byte region in `net__read_ws`, fixed control clean; Stage A places chosen bytes at a chosen offset. Witness #246 ESTABLISHED the wire-only pre-auth 32 KiB heap read with live pointer disclosure (4/4 fresh brokers). Rung 4 is information disclosure only; enlargement stays layout-dependent and wire-to-code-execution UNVERIFIED. [Status](reports/mosquitto2shell-status.md) |
| **Node2Shell** | ✓ | ✓ | ✓ | — | **CODE** — two independent Alt-Svc terminators on pinned v24.22.2: stock-glibc abort 10/10, Memcheck differential against a clean v24.22.3 control. No combination primitive or control; rung 4 not demonstrated. [Status](reports/node2shell-status.md) |
| **Dragonfly2Shell** | ✓ | ✓ | — | — | **CODE** — stock RESP key echoed into a 20024-byte memcached reply, witness gdb `SendValue rdx=0x4e20`. Stock rung 3/4 UNVERIFIED; the ASan 20000-byte write is a labeled synthetic harness, not stock corruption. [Status](reports/dragonfly2shell-status.md) |
| **Postgres2Shell** | ✓ | ✓ | ✓ | — | **CODE** — FDW batch-insert overcount on stock 17.11: uninitialized 8-byte heap value used as a pointer, invalid write at `0x38`, SIGSEGV; fixed 17.12 completes. Needs `PR:L`, so pre-auth RCE is not demonstrated. [Status](reports/postgres2shell-status.md) |
| **Brotli2Shell** | ✓ | ✓ | ✓ | — | **HARNESS** — chosen bytes at chosen offsets past an 8-byte decoder buffer; the fixed build rejects. Rung 4 not demonstrated; network reachability is a claim. [Status](reports/brotli2shell-status.md) |
| **Freeradius2Shell** | ✓ | ✓ | ✓ | ◐ | **HARNESS** — an EAP-FAST ticket writes 208 bytes into a 152-byte stack struct and executes a chosen `verify_marker()` at rc 42; the fixed build rejects. Witness tape #227 reproduced byte-identical digests including the offset-specific marker control. Live `radiusd`, network reach and real stack layout UNKNOWN; rung 4 is harness-only. [Status](reports/freeradius2shell-status.md) |
| **Falkordb2Shell** | ✓ | ✓ | ✓ | — | **HARNESS** — a masked extended-length frame drives 525 out-of-bounds writes and chosen mask bytes overwrite a canary; witness replay #239 established rungs 1/2/3. Rung 4 not demonstrated because the mask repeats every four bytes. [Status](reports/falkordb2shell-status.md) |
| **Freeswitch2Shell** | ✓ | ✓ | ✓ | ✓ | **LIVE** — a chosen 8-byte value at `wsh->ssl` is dereferenced in `SSL_shutdown` in a live FreeSWITCH over a loopback WebSocket `101`; the sentinel is a value, not code. Witness #338 replay with different bytes at the same fault site, controls clean. Stock heap layout, external reachability and the opt-in `mod_xml_rpc` gate stay in the claim. [Status](reports/freeswitch2shell-status.md) |
| **Freerdp2Shell** | ✓ | ✓ | ✓ | ✓ | **LIVE** — a client `SNDC_FORMATS` record wraps `out_frames` after a failed realloc; chosen `de` at OOB offset 8820 in a live post-auth RDP session over real TCP, under stock glibc and ASan. Witness W31/#532 ESTABLISHED the one-command replay from clean HEAD; #602 ESTABLISHED the FFmpeg format gate NEGATIVE on stock 6.1.1. The client controls the offset, not the audio bytes; the default ADPCM format is unavailable and the no-auth 9.8 case is not re-asserted. [Status](reports/freerdp2shell-status.md) |
| **Xrdp2Shell** | ✓ | ✓ | ✓ | ✓ | **CODE** — chosen bytes on real compiled xrdp 0.10.6 code: a 20000-byte DYNVC payload overflows the 8192-byte `trans_create` region through the real receive chain. Witness W33 ESTABLISHED both claims, W41/#617 clean-room 15/15 on two fresh builds closing the build-tree limit. Still in-process: no logon, negotiated channel, socket PDU trace or live-session allocator layout. [Status](reports/xrdp2shell-status.md) |
| **Gst2Shell** | ✓ | ✓ | ✓ | ◐ | **LIVE** — attacker-chosen `channels=1000` in `encoding-params` faults the shipping `rtpL8`/`rtpL16`/`rtpL24` depays and a loopback RTSP `rtspsrc` client; the OOB store is constant `-3`, so this is a count-controlled effect, not chosen bytes. Witness W33/#552 ESTABLISHED the 43/43 harness repair, closing the 42/1 contradiction. Strong rung 4, public-service SDP acceptance and allocator layout UNKNOWN. [Status](reports/gst2shell-status.md) |
| **Babelfish2Shell** | ✓ | ✓ | ✓ | ◐ | **HARNESS** — an unbounded 16-bit prelogin length copies into `StringInfo[1024]`, chosen bytes landing at OOB offsets 1100/2000; fixed control clean. No live TDS endpoint, `palloc` layout or real neighbour. [Status](reports/babelfish2shell-status.md) |
| **Bzfs2Shell** | ✓ | ✓ | ✓ | ◐ | **HARNESS** — a 1024-byte body writes four chosen bytes past `tcpmsg[1024]` into `tcplen`; instrumented chosen-value rung 4 reads back byte-exact. No live bzfs, player socket or `NetHandler` layout. Witness #761 ESTABLISHED all four rungs at those labels (20 PASS / 0 FAIL, byte-equal five-run digest); its source-citation nit is fixed in the brief, status and PROVENANCE, harness bytes unchanged. [Brief](reports/frontier-bzfs2shell.md) · [Status](reports/bzfs2shell-status.md) |
| **Kamailio2Shell** | ✓ | ✓ | ✓ | ◐ | **HARNESS** — tilde-distance `memcpy` into `bufport[5]`; instrumented chosen function pointer, pinned 6.1.5 rejects. Module gate, real frame layout and return-address control UNKNOWN. [Status](reports/kamailio2shell-status.md) |
| **Iperf2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — a 336-byte decoded authtoken crosses a 256-byte RSA heap buffer on real pinned upstream code; rung 4 is instrumented chosen bytes in the write buffer only. No live server, stock layout or useful pointer; the 3.22 release-note mislabel is preserved. [Status](reports/iperf2shell-status.md) |
| **Uftpd2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — an unbounded `memmove` in `compose_path()` shifts `dir[PATH_MAX]`; rung 4 is instrumented chosen bytes in the upstream frame. Needs `PR:L` and no-chroot; no live daemon or stock frame layout. [Status](reports/uftpd2shell-status.md) |
| **Accelppp2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — L2TP AVP chunks concatenate past a 4160-byte heap buffer on verbatim pinned code; rung 4 is an instrumented chosen value read back in an adjacent harness object. Needs verbose logging and a configured peer range. [Status](reports/accelppp2shell-status.md) |
| **Indiserver2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — a 1237-byte `sprintf` into `err[1024]` on the shared TCP/7624 path; rung 4 is an instrumented chosen token at adjacent harness-stack offsets. Availability-only advisory; no live daemon or stock layout. [Status](reports/indiserver2shell-status.md) |
| **Shairport2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — a 4096-byte RTSP method body is hex-dumped as 8193 bytes into `obf[4096]`; rung 4 is an instrumented chosen token. Availability-only advisory; the AirPlay-2 gate and a live socket are UNKNOWN. [Status](reports/shairport2shell-status.md) |
| **Asterisk2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — an unbounded `vsprintf` past `logMessage[2048]` in H.323 `ooTrace()`; rung 4 is an instrumented chosen token. Needs `chan_ooh323` compiled and its port exposed; availability-only ceiling. [Status](reports/asterisk2shell-status.md) |
| **Netatalk2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — an integer underflow leaves `remain=SIZE_MAX` and `strcpy` writes a chosen filename past `path[1025]`; rung 4 is an instrumented chosen token in the return slot. Needs an authenticated AFP session and cross-device rename; the maintainer's RCE claim stays a claim. [Status](reports/netatalk2shell-status.md) |
| **Iondtn2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — 18 AMP values append 1458 bytes into a 1024-byte `STAKE` heap region; rung 4 is an instrumented chosen token at adjacent offsets. Both advisories claim availability only; no live `nm_mgr` or UDP payload path. [Status](reports/iondtn2shell-status.md) |
| **Opensips2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — a 299-byte JID drives `ENC_SIP_URI()`'s `sprintf` 48 bytes past `buf_from[256]`; rung 4 is instrumented chosen bytes. Needs `backend=server`; RCE depends on canary/ASLR/NX. [Status](reports/opensips2shell-status.md) |
| **Unbound2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — a DNSKEY name plus RDATA writes 65788 bytes into a 65552-byte scratch buffer in `ds_create_dnskey_digest()`; rung 4 is instrumented chosen RDATA bytes. No live resolver, DNSSEC gate or compression-pointer route; advisory RCE remains a claim. [Status](reports/unbound2shell-status.md) |
| **Janus2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — a 1986-byte `.mjr` info header is `fread` into `prebuffer[1500]`; rung 4 is instrumented chosen bytes. Availability-only; no live Janus, HTTP/SDP path or real recording. [Status](reports/janus2shell-status.md) |
| **Rsyslog2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — a 9000-byte decoded Basic-Auth credential takes the `calloc(0, len)` branch in `imhttp.c:705` and writes chosen bytes past a zero-length allocation; rung 4 is instrumented chosen bytes read back at `pworkbuf[0..15]`. No live rsyslog, imhttp module or HTTP path; availability-only. [Status](reports/rsyslog2shell-status.md) |
| **ProxySQL2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — a declared 65535 (MySQL) / 100000 (PgSQL) first-packet length drives a second recv() of that many client-chosen bytes into a fixed 32768-byte queueIN before auth; ASan WRITE of size 65535 / 100000 at pinned mysql :665 / pgsql :534; rung 4 is instrumented chosen stripes at 32771 / 67237 bytes past the queue. No live daemon, listener, stock allocator or pointer control; advisory potentially-exploitable stays a claim. [Status](reports/proxysql2shell-status.md) |
| **Strongswan2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — a zero-length EAP-SIM/AKA attribute in libsimaka underflows size_t into a wrapped malloc()/memcpy() at pinned simaka_message.c:257-260; ASan WRITE of size 8 at :258, fixed 6.0.6 rejects; rung 4 is instrumented chosen 0x5a bytes under a bounded-copy collaborator, while the real-libc copy faults before writing. Needs local EAP-SIM/AKA termination, not RADIUS; no live daemon, pointer control or execution. [Status](reports/strongswan2shell-status.md) |
| **Memcached2Shell** | ✓ | ✓ | ✓ | ◐ | **LIVE/CODE/HARNESS** — an idle lru_crawler metadump all client makes a poll() timeout read as success, appending stored key bytes past the 131072-byte crawler buffer at pinned crawler.c:307-310/:471; ASan WRITE of size 64 at :310, fixed 1.6.44. A loopback daemon on pinned parent bytes confirms rung 3 in process: ASan `WRITE of size 1` at `util.c:57` via `crawler.c:310`, allocation at `:825`, fixed daemon clean. A non-perturbing `/proc` observer on a live non-instrumented build of the pinned parent sees chosen `0x5a` at `buf+131072` and at +512/+1024/+2048/+16384 as the write frontier advances; a `0x41` differential at the same offsets and timing (`414141414141303437303620` at `buf+131072`) proves those OOB bytes come from the stored key record. Witness #751 replayed all of it independently and accepted rung 3 in the real daemon and the rung 4 chosen-byte limb ESTABLISHED AS CLAIMED. A chosen-byte overwrite of pointer-shaped arena data (`90ae4b0c4474000090b14b0c` at +16384) is conditional on allocator state (absent in two witness `0x5a` replays), semantically unidentified, and not a grade basis. Fifth wake, witness #784 ESTABLISHED AS CLAIMED with grade unchanged at #751: the pinned plain parent under gdb with no breakpoints and ASLR on faults in `assoc_find` (`assoc.c:87`) in three of four stress runs, with the hash-bucket chain item pointer holding overflow-stream content — eight attacker-written `0x5a` bytes (`0x5a5a5a5a5a5a5a5a5a` in two runs) or a `fetch=%s` metadump fragment in the witness's other fault; the crash is not deterministic and the in-run frontier was not read. The witness rebuilt both binaries from hash-matched pins and showed fix sensitivity plus overflow dependence; the pinned fixed tree does not fault. Witness #762 left the separate t=116s `do_slabs_alloc` fault as a single non-deterministic observation (no core, UNKNOWN faulting value), with no replay owed and no grade change. No crafted canonical address, execution, control-flow diversion or external reachability: pinned `uriencode_p()` cannot emit a canonical pointer through the key path. [Status](reports/memcached2shell-status.md) · [Daemon repro](reports/memcached2shell-daemon-asan.md) |
| **Srs2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — a 1604-byte malformed RTCP datagram declares `length = 400` and a 1596-byte payload into `payload_[1500]` on verbatim pinned SRS bytes under `#line`; parent `length = 0` aborts at `srs_kernel_buffer.cpp:244` `require(size)`, ASan `WRITE of size 1596` 0 bytes after a 1536-byte region at pinned `:246` via RTCP decode `srs_kernel_rtc_rtcp.cpp:95`, TWCC reproduces (post-nit fix hits pinned `:841`), fixed build clean. Rung 4 is instrumented chosen `0x5a` / `0x41` at 96 offsets in a 64 KiB zeroed collaborator, benign control clean, guard page faults; no pointer, control flow or marker. GHSA-qr8h-p53p-x564 (no CVE), patched in 6.0.194 / 7.0.214 / 8.0.73; WebRTC pre-auth reachability and live daemon stay UNKNOWN. Witness nit #725 addressed in the harness at `3d556c5`; no witness verdict in hand. [Status](reports/srs2shell-status.md) |
| **389ds2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — a post-auth SASL UNBIND with `SSF > 0` declares a BER length larger than the caller's 512-byte receive buffer; verbatim pinned `sasl_io.c:344-348` sets `encrypted_buffer_count` to the declared length and `:451-457` copies that many attacker bytes into `buf`, ASan `WRITE of size 9000` 0 bytes after the 512-byte region at pinned `sasl_io.c.vuln:456`, 511/512 clean and 513 faults, fixed `f15ffd63` caps the drain. Rung 4 is instrumented chosen `0x5a` / `0x41` at offsets 0–8487 in a 1 MiB zeroed collaborator, benign control clean, guard page exits 77; no pointer, control flow or marker. CVE-2026-11610 / GHSA-2g8g-f92j-g4gq, 1.3.2–3.3.0 affected; no live `ns-slapd`, SASL bind, shipping allocator or execution, and the real caller's `len` is UNKNOWN. Witness nit #740 addressed at `3d556c5` (only heap-owned buffers freed); no witness verdict in hand. [Status](reports/389ds2shell-status.md) |
| **Ipfixcol2Shell** | ✓ | ✓ | ✓ | ◐ | **LIVE/CODE/HARNESS** — an unauthenticated peer declares an 8-byte small ring then a 65000-byte decompressed size; pinned `Lz4Decoder.cpp` under `#line` passes the declared size as `dstCapacity` to the host's real `liblz4.so.1`, ASan `WRITE of size 65000` 0 bytes past the 24-byte region at pinned `:145` (ring allocated at `:184`), fixed v2.9.0 rejects with `LZ4 Decoder: invalid decompressed size`. A loopback TCP harness now feeds the same wire bytes to the plugin's real v2.8.0 sources: rung 3 holds at real upstream frames, stock glibc faults in `unlink_chunk` with `rax=0x5a…58` / `0x41…40` and a crafted payload puts chosen `0x4141414141414141` in a pointer dereferenced at `unlink_chunk+39`. Rung 4 is instrumented chosen `0x5a` at offsets 0/24/28/64999 in a 1 MiB mmap collaborator with an `0x41` differential and a benign zero control; stock ASan faults before readback. CVE-2026-122127 / GHSA-4575-chq4-crfc, v2.7.1/v2.8.0 → v2.9.0. No full collector daemon (libfds/lz4-dev/rst2man absent), shipping allocator, valid target address or execution; witness #711 ESTABLISHED the clean-archive harness and #712 the loopback scope, no grade change. [Status](reports/ipfixcol2shell-status.md) [Live repro](lab/ipfixcol2shell-live/RESULTS.md) |
| **Kermit2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — repeat-count compressed `putsrv()` decoding on verbatim pinned C-Kermit v11.0.514 bytes writes 9212 chosen characters into an exact `MAXRP+1 = 9025`-byte `srvcmd`; ASan `WRITE of size 1` at `pins/ckcfns.c.vuln:461`, fixed v11.1.515 returns `decode_rc=-1` at the 9024th character. Rung 4 is instrumented chosen `0x5a` / `0x41` read back at offsets 9024–9151 (128 bytes; 9152–9211 inferred from `emitted=9212`) in a 1 MiB zeroed collaborator, benign decode writes zero bytes, guard page faults; no pointer, control flow or marker. Admitted 2026-11-21 under standing approval #6; witness #763 ESTABLISHED rungs 1/2/3 and rung 4 at INSTRUMENTED. CVE-2026-129126 / GHSA-c5px-7h4c-gj8p, affected before 11.1.515; no `wermit` build, live server, packet-length or repeat-encoding limits yet. [Brief](reports/frontier-kermit2shell.md), [status](reports/kermit2shell-status.md) |
| **GpfD2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — `X-GP-SEGMENT-COUNT` sizes and `X-GP-SEGMENT-ID` indexes two arrays with no bounds check on WarehousePG gpfdist 7.6.1: one unauthenticated HTTP request writes a chosen 4-byte `active_segids` value and a chosen 64-bit `X-GP-SEQ` value at a chosen index, pinned writes at `gpfdist_v7.6.1.c:1988` / `:3677`; ASan `WRITE of size 4` at `:1988` and isolated `WRITE of size 8` at `:3677`, fixed 7.6.2 guards reject. Rung 4 is instrumented chosen `0x4141414141414141` read back byte-exact at `seq_segs+24`, `X-GP-DONE` flips the 4-byte write to zero and a guard page faults; no live gpfdist, APR pool neighbour, pointer control or execution. CVE-2026-122042 (no GHSA), 6.27.1–6.27.7 / 7.2.1–7.6.1 → 6.27.8 / 7.6.2; admitted 2026-11-21 under standing approval #6, operator replay 13 PASS / 0 FAIL from a clean `git archive HEAD` at `a7d5884` with two five-run groups at one digest. [Brief](reports/frontier-gpfdist2shell.md) |
| **Gct2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — an SSLv2 backward-compatible hello with record length 1 makes `dsize=-2` and a 3-byte token buffer on GCT `globus-gss-assist` before 12.9 (GCT before 6.2.20261111); the verbatim pinned `tokens_f.c:171-173` `memcpy` writes 5 chosen header bytes into it and `:181` `fread` with negative `dsize` cast to `size_t` writes attacker body bytes past `cp+5`, ASan `WRITE of size 5` at `tokens_f_edf946b5:172`, fixed `3df2be48:127-131` rejects. Rung 4 is instrumented chosen `0x5a5b5c5d` read back byte-exact at `cp+5`, `PROT_NONE` guard faults; no live gatekeeper/myproxy, GSI handshake, stock neighbour, pointer or execution. CVE-2026-123975 (no GHSA), pre-auth, availability-only advisory; 10 PASS / 0 FAIL, witness #805 ESTABLISHED AS CLAIMED with no grade change. [Brief](reports/frontier-gct2shell.md) |
| **Imgproxy2Shell** | ✓ | ✓ | ✓ | ◐ | **CODE/HARNESS** — a crafted ICO declares `data_size=0xfffffff5`, wrapping `data_size + 14` to 3 in `VIPS_MALLOC` at pinned `icoload.c:158` (v4.0.15) so `vips_foreign_load_read_full` at `:161` writes 32 attacker bytes 11 past the allocation at `data+14`; ASan `WRITE of size 32` at `icoload_v4.0.15:161`, fixed v4.0.16 rejects `data_size > 10 MiB`. Rung 4 is instrumented chosen `0x5a5b5c5d` read back byte-exact at `data+14`, `PROT_NONE` guard faults; no live imgproxy HTTP server, libvips runtime, real ICO, stock neighbour, pointer or execution. CVE-2026-123614 / GHSA-hff9-5pqw-6w9f, 4.0.0–<4.0.16 → 4.0.16, unauthenticated HTTP, CVSS 9.3 prose claims RCE; 10 PASS / 0 FAIL, no independent replay yet. [Brief](reports/frontier-imgproxy2shell.md) |

## How the plant works

Each admitted family is its own mind with its own tmux window: 39 target
minds — `ruby2shell`, `php2shell`, `node2shell`, `apache2shell`,
`mosquitto2shell`, `dragonfly2shell`, `postgres2shell`, `brotli2shell`,
`freeradius2shell`, `falkordb2shell`, `freeswitch2shell`, `freerdp2shell`,
`xrdp2shell`, `gst2shell`, `babelfish2shell`, `bzfs2shell`,
`kamailio2shell`, `iperf2shell`, `uftpd2shell`, `accelppp2shell`,
`indiserver2shell`, `shairport2shell`, `asterisk2shell`, `netatalk2shell`,
`iondtn2shell`, `unbound2shell`, `opensips2shell`, `janus2shell`,
`rsyslog2shell`, `proxysql2shell`, `strongswan2shell`, `memcached2shell`,
`ipfixcol2shell`, `srs2shell`, `389ds2shell`, `kermit2shell`,
`gpfdist2shell`, `gct2shell` and `imgproxy2shell`. Each builds
affected and fixed versions locally, writes harnesses, drives toward rung 4
and authors its report under `reports/`.

Four cross-cutting minds: **frontier** hunts public advisories and hands a
reproducible harness to the operator; **docs** keeps this README and `docs/`
true to the shipped code and is woken by the `repo-change` commit signal;
**witness** re-runs every claim from a clean checkout; **operator** is the
owner's delegate for scoped approvals and admissions under recorded standing
permissions.

An idle wake owes a bounded, falsifiable experiment deeper toward rung 4 — or,
once that rung is closed on the tested build, an adjacent lane in the same
source tree. New products and runtimes go to frontier/operator for a new mind.
Negative results and UNKNOWNs are preserved in the reports; the columns above
map the boundary actually reached. All minds run on
`opencode-go/hy4-flash-free`.

## Follow along

- Live dashboards:
  `tmux -S /tmp/tmux-1000/mishe-tauftauf2shell/tmux-1000/default attach -t mishe-tauftauf2shell-current`
  — one window per target mind above, plus `frontier`, `docs`, `witness`,
  `operator`, `chat`, `git` and `wakes`.
- [docs/task.md](docs/task.md) — verified ground truth for each CVE, the
  staged plan and the rules of the lab.
- [docs/reproducibility.md](docs/reproducibility.md) — pins, commands,
  expected bytes and evidence policy for independent verification.
- [docs/runtime-pin.md](docs/runtime-pin.md) — the pinned runtime and every
  local change made to it.
- [docs/self-healing.md](docs/self-healing.md) — duties, signals and the
  no-force publication/reconciliation design.
- `reports/` — the investigation reports and live status files; `lab/` — the
  builds and harnesses.

## License

[CC0 1.0](LICENSE) — everything here is public domain.
