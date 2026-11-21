# Research task: investigate how far rung 4 goes

General goal: for memory-safety vulnerabilities in language runtimes and
web-facing servers — the "X2Shell" class — reproduce the failures in a
local, isolated laboratory and investigate how far **rung 4 (demonstrated
security impact: chosen bytes at chosen offsets, pointer control, benign
marker execution, per-build labeled)** can be pushed for each target.

Rungs are not boxes to touch. They are a depth investigation: each rung
states what evidence is strong enough to support, and the lane records the
exact boundary where the evidence stops. A negative result, a harness-only
grade, or an UNKNOWN is part of the answer — it says how far rung 4 goes
on that build, not that the lane failed. Preserve failed hypotheses and
contradictory results; treat unknowns as unknowns.

## Stalled-lane doctrine

An idle wake is not work. When a target has no owed experiment, the mind
must either (a) push the same target deeper toward rung 4 with a bounded,
falsifiable experiment that could change a grade — a new consumer, a
wire-pure version of a debugger-assisted step, stock-allocator placement,
a live process, a stronger marker, or a counterexample to an existing
claim — or (b) if rung 4 is genuinely closed on this host/build, mine an
**adjacent vulnerability in the same target/runtime**: same source tree,
same subsystem, a descendant CVE, or the next bug in the same fix series.
Adjacent work keeps the same evidence ladder and is logged as a named
lane; a distinct product or runtime goes to frontier/operator for a new
mind, never a silent scope drift. A wake that only re-reads a page for a
timestamp with no new claim is a watch, not an experiment: do not
self-schedule it; wait for a signal or a dated trigger.

All triggering, listeners, debuggers and test consumers stay on this
machine, bound to loopback or local containers. Never contact external
systems or scan public infrastructure. Read-only provisioning from official
source homes and public advisories is the sole exception, and it never
sends a trigger off this machine. Publish reproducible reports.

## Targets (verified ground truth, 2026-11-20)

Read from the vendor/researcher pages and the CVE records. Starting
claims, not conclusions.

### PHP2Shell — CVE-2026-109618 / CVE-2026-109619 (php2shell.com)

- OOM-handling corruption (618) and stale global state across requests
  (619) in core PHP; CVSS 9.2 both; pre-auth RCE demonstrated on
  WordPress/Drupal/Joomla; application-agnostic memory disclosure.
- Affected/fixed: 8.2<8.2.35, 8.3<8.3.36, 8.4<8.4.27, 8.5<8.5.12.
- 2026-10-23 update: a circulating PoC vector needs
  `session.serialize_handler` set to `php_binary`/`php_serialize` and
  changed to `php` at runtime before `session_start()`, with
  `session.upload_progress` enabled — the same family as the public
  `murrez/php2shell` framework's CVE-2026-115560 claims. PHP recommends
  `session.upload_progress.enabled = 0` pending the next bugfix release.
- 2026-11-20 reopened lane (**CVE-2026-126714** / GHSA-fm2m-fjf5-v3cp,
  CVSS 9.2, from the 2026-11-19 vendor release): `ps_files_write()` does
  not clear the old session before writing the replacement; an interrupted
  write can leave new prefix + old tail that decodes as a third session.
  Affected 8.2<8.2.36, 8.3<8.3.37, 8.4<8.4.28, 8.5<8.5.13; both pinned
  8.4.26 and 8.4.27 are affected. Both halves are reproduced on both
  ASan builds (commits 741c677, 8440254): a real session write interrupted
  at a syscall boundary leaves the spliced file on disk and the next
  request promotes the object. The kill is shim-simulated (the advisory's
  hard-OOM worker death), not a demonstrated remote trigger. Fix VERIFIED
  on 8.4.28 (pinned in `lab/php2shell/provision.sh`, commits ab3ee16 and
  02bd370): unconditional `ftruncate(0)` first leaves the same interrupted
  write as a 100-byte new prefix with no object promoted
  (`aftershell-producer-8.4.28-asan.log`). Hand-assembled splice bytes still
  decode on 8.4.28, but a fixed handler cannot produce them.
- 2026-11-20 new descendant lane (**CVE-2026-129481** /
  GHSA-g3vh-838c-65v7): an incomplete fix for 109619. A fatal in a user
  stream wrapper's `stream_close()` interrupts session shutdown, leaving
  the recorded script-filename pointer live into the next request on the
  same FPM worker. Affected 8.4.27-fpm-asan; no ASan on fixed 8.4.28 or on
  a benign-close control. `lab/repro/php2shell-cve129481-fpm.py` observes an
  ASan 4-byte use-after-free read at
  `php_session_cleanup_filename (session.c:128)`. Rung 3 CONFIRMED, no
  rung 4 and no pre-auth reachability claim. Wake 29 reproduced the
  129474 stale-argument read on 8.5.12 CLI from the vendor's own regression
  case. Wake 31 added a bounded loopback FPM harness for 129182
  (`lab/repro/php2shell-cve129182-fpm.py`, with release-ASan build support in
  `lab/php2shell/build-fpm-release.sh`); the debug ASan build preserves a
  negative. Wake 45 finished the release-ASan
  8.5.12 replay: both vendor diagnostics reproduce but
  `VERDICT=CLEAN_NO_UAF` with zero ASan markers, also with fast shutdown
  forced, in ZendMM mode and under `--control`. Wake 46 root-caused it under
  gdb; wake 47 corrected the label and fixed the ordering: the 8.5.12 → 8.5.13
  fix is two `if (EG(active))` guards at `zend.c:1509` (dtor) and `:1534`
  (repop). Request 1's fatal repopulates the array; its own
  `zend_shutdown_executor_values()` then clears `EG(active)` and UNDEFs the
  global at `zend_execute_API.c:440` while the type is still `IS_ARRAY`
  (`type=775`), leaving only `value.arr`. Request 2's PHP_VALUE warning sees
  `active=0, flags=7, type=IS_UNDEF`, so `zval_ptr_dtor` is a no-op and the
  `:1534` branch is unreachable; `zend_activate()` was wake 46's wrong label
  for the `:440` site. Grade stays UNKNOWN with a fully ordered measured
  cause; no fixed 8.5.13 release build was started.
  129289 remains untested (smuggling, not memory corruption).
- Rung-4 angle: the disclosed RCEs are runtime-level; the lab reproduces
  the memory-safety failures (OOM longjmp path; stale-state UAF) in
  ASan/UBSan builds of an affected PHP, then attempts placement and
  control exactly as in the staged plan below.

### Ruby2Shell — CVE-2026-132825 / GHSA-34m4-m9fh-gqp5 (verialabs.com/ruby2shell/)

- **One-byte heap overflow** in Ruby's single-byte-encoding case
  conversion: upcasing `ß` writes two bytes (`SS`) while the loop
  bounds-checks only one; output buffer is input length + 20, so 21 `ß`
  overflow by one byte. Written byte is fixed (`S` on upcase, `s` on
  fold); attacker controls the buffer size through input length. In the
  loop for several ISO-8859 and Windows-125x encodings since Ruby 2.4.0;
  reached by `upcase`, `swapcase`, `downcase(:fold)`, `casecmp?`; UTF-8
  unaffected. Rails and classic Sinatra exposed in default configs.
- Affected/fixed: 3.3<3.3.14, 3.4<3.4.13, 4.0<4.0.10; 3.2 and older EOL.
  Fix commit `ruby/ruby@d582f8f`.
- Veria Labs demonstrated RCE on stock Rails and publishes a PoC on
  **2026-11-25**.
- Rung-4 angle: the most tractable subject in the class — a *controlled*
  single-byte write with attacker-chosen heap placement via buffer size.
  Classic one-byte-off exploitation (heap grooming to an adjacent
  length/size field or pointer's low byte) applies directly.

### Node2Shell — CVE-2026-123828 (admitted 2026-11-20, standing approval #6)

- **One-byte heap overflow** in Node.js HTTP/2 `session.altsvc()`
  (`src/node_http2.cc`): the buffer is sized to the origin length and
  the null terminator is written one byte past its end. Remote
  unauthenticated single-request trigger: a long valid `:authority`
  that an application forwards to altsvc. Attacker controls the
  allocation size through the authority length — same class as
  Ruby2Shell.
- Affected 24.x, 26.x per the official advisory; fixed 24.22.3 /
  26.13.1 (2026-11-11); fix commit `nodejs/node@ae9ab37d62`
  (nodejs-private#1035). Snyk also claims 22.x<22.23.5, but the fix
  is absent from the 22.23.5 release notes — backport unverified;
  check the 22.x source before building it.
- Rung-4 angle: attacker-chosen allocation size and pre-overflow
  content; Node ASan/UBSan source builds fit this lab. Fallback
  candidate in the same release if altsvc is structurally gated:
  CVE-2026-123874 (Http2Stream use-after-free via respondWithFile
  reset, unauthenticated).

### Similar things (operator's standing mandate)

The operator actively watches for new X2Shell-class public claims and
advisories (runtime-level memory-safety failures with pre-auth web
reachability), proposes targets with evidence, and admits them to the
plate under the standing approvals. Each admission records: the claim
source, the CVE/GHSA, affected and fixed versions, the claimed primitive,
and why a rung-4 attempt is plausible in this lab.

#### Admitted 2026-11-20 ~17:10Z: Brotli2Shell (CVE-2026-111497 / GHSA-9v8h-qqgm-4m35)

Claim source: the CVE record, Envoy advisory GHSA-3wvj-j6qm-62mr and upstream
fix `google/brotli@0ed4268`. Affected C library 1.0.3–1.0.9, 1.1.0 and
1.2.0; fixed 1.0.10 / 1.1.1 / 1.2.1, with downstream Node.js, Python
`Brotli`, Bun and Envoy copies. Claimed primitive: a crafted stream writes
attacker-chosen bytes past the decoder's 8-byte `buffer.u8` into adjacent
state; CVSS 4.0 9.2 (`PR:N`). Frontier observed rungs 1/2/3 on a standalone
file-only harness: v1.2.0 stage-1 spin plus stage-2 SIGSEGV, v1.2.1 hard
error `-17`, 20 chosen bytes at indices 8..27 setting three state fields to
`0x7fffffff`. Small C target, exact tags, public patch and no hardware
gate make a rung-4 attempt plausible. Rung 4 is NOT demonstrated; network
reachability and public RCE claims stay unverified, and the
`ikow/brotli2crash` non-exploitability claim is preserved. Evidence:
`reports/frontier-brotli2shell.md` (commits `fb821a2`, `02d34fa`). The
dedicated `brotli2shell` mind owns this lane; details in
`.mishe-tauftauf/charters/brotli2shell.md`.

#### Admitted 2026-11-20 ~17:45Z: Freeradius2Shell (CVE-2026-127030)

Claim source: the cve.org record and Red Hat CVE page for CVE-2026-127030
(CNA Red Hat, published 2026-11-12, CVSS 3.1 7.5 `AV:N/AC:L/PR:N/UI:N/A:H`,
CWE-787) plus upstream fix `064567a08f3b` against vulnerable parent
`3f802d74deef`. Affected RHEL 10/9/8/7 per Red Hat; the exact fixed release
tag is UNKNOWN — the fix commit is the version boundary. Claimed primitive:
a remote unauthenticated oversized EAP-FAST SessionTicket drives
`hdr.length`-sized AES-GCM decrypt bytes into a 152-byte stack struct before
tag verification, overwriting the saved return address. Frontier observed
rungs 1/2/3 and a harness-only rung 4 on a standalone file-only harness:
chosen `0x4242…` at the saved-RIP slot, canary abort rc 134, chosen marker
executes rc 42, fixed build rejects `PAC is too long` rc 0; ASan is honestly
blind because the write occurs inside libcrypto. Small C module, exact
vulnerable/fixed commits, public diff, no hardware gate and unauthenticated
network framing make a rung-4 attempt plausible. Rung 4 is harness-only:
live `radiusd`, network reachability, real stack layout and the key-unknown
byte-control case remain UNKNOWN. Evidence: `reports/frontier-freeradius2shell.md`
(commit `2d708ec`, witness replay tape #227). The dedicated `freeradius2shell`
mind owns this lane; details in `.mishe-tauftauf/charters/freeradius2shell.md`.

#### Admitted 2026-11-20 ~18:12Z: FalkorDB2shell (CVE-2026-107909 / GHSA-x67x-q5pm-p9h7)

Claim source: the CVE record and GitHub advisory for CVE-2026-107909 /
GHSA-x67x-q5pm-p9h7 (NVD-sourced, published 2026-10-09, CVSS 4.0 8.8,
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H`, CWE-787). Claimed primitive: a
remote unauthenticated WebSocket frame with a 64-bit extended payload length
to the Bolt port drives `buffer_apply_mask()` past the receive buffer
because the only bounds check is an `ASSERT()` compiled out of release.
Affected FalkorDB before 4.20.0; upstream fix `0b11a00b34b25c4d4fdfe55f0a35c8a00593bd7d`
(2026-07-08, PR #2170) deletes the entire Bolt/WebSocket subsystem, so there
is no patched `ws_read_frame()` to diff; the lab `FIXED` build is a local
length guard, not the upstream fix. Bolt is disabled by default. Frontier
observed rungs 1/2/3 on a standalone extracted-C harness: declared length
4144 with zero payload bytes gives 525 OOB XOR writes, a chosen mask flips a
zero canary to `0x4242…` or `0x4141…`, the in-bounds control gives zero OOB
writes, and ASan names `buffer_apply_mask_single` under a short-chunk lab
layout. Small C subsystem, exact vulnerable parent, public fix commit, no
hardware gate and unauthenticated framing make a rung-4 attempt plausible.
Rung 4 is NOT demonstrated: every 8-byte word is the repeating 4-byte mask
(`K:K`), not a chosen pointer; live `BOLT_PORT` reachability, handshake path,
real heap layout and the first OOB `chunks[]` pointer remain UNKNOWN.
Evidence: `reports/frontier-falkordb2shell.md` (commit `b140144`). The
dedicated `falkordb2shell` mind owns this lane; details in
`.mishe-tauftauf/charters/falkordb2shell.md`.

#### Admitted 2026-11-20 ~17:52Z: Freeswitch2Shell (CVE-2026-116785 / GHSA-jj89-q47c-gh94)

Claim source: GitHub advisory GHSA-jj89-q47c-gh94 and the CVE record for
CVE-2026-116785 (CNA GitHub, CVSS 3.1 9.1
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`, CWE-122/681/787). Claimed primitive:
an unauthenticated WebSocket frame on an enabled `mod_xml_rpc` endpoint uses
the 8-byte extended length field; `ws_read_frame()` swaps only its low 32 bits
into signed `int plen`, so `FF FF FF FF` gives `plen=-1`, the signed guard
passes and the unbounded `size_t` copy writes sender-chosen bytes from
`buffer+14` across `wbuffer` into the handle's tail fields, including
`SSL *`. Affected `<= 1.11.1`, fixed `>= 1.11.2`; upstream fix
`d557ca6d29e6da4f10824dc158100906a592b91a` against vulnerable parent
`fbac12b451a1` adds `ws_get_be64()` and an unsigned length guard. Both
`mod_xml_rpc` and `enable-websocket` are off by default; where enabled the
endpoint is HTTP/WebSocket, not SIP (the separate, earlier FreeSWITCH decline
was the SIP-facing GHSA-f73w-xph4-pjp3). This candidate is distinct from the
screened-out GHSA-294g-hq4w-c275, whose overflow bytes are the configured
credential's base64 tail and not sender-chosen.

Small single-file subsystem, exact vulnerable/fixed commits, no hardware gate
and unauthenticated HTTP framing make a rung-4 attempt plausible. Operator
reproduction 18:28Z (throwaway copy of digests-pinned sources) observed
rungs 1/2 placement, an ASan `heap-buffer-overflow` `WRITE of size 132146` in
`memcpy` from `ws_raw_read`, and a chosen 8-byte value at
`offsetof(wsh_t, ssl)=131112` executing a marker with `rc=42`; in-bounds and
fixed-build controls pass and five repeats are identical. Frontier repaired
the harness accounting and exit codes at 19:02Z; the driver now prints
`ALL CHECKS PASS` (rc 0) with pinned sources `ws_overflow.c` `75433b5d…` and
`run.sh` `637cfa36…`. The earlier 2928 OOB-write count was double the real
extent because a zero-byte read underflowed `trace_copy()`; 1464 is correct.
This is a harness-only rung 4 for marker execution. Two real-source checks
compiled the unmodified pinned `ws.c` with Abyss type stand-ins over a
127.0.0.1 socket (`lab/freeswitch2shell/live/`). With the advisory's
`FF FF FF FF` frame (`plen=-1`) ASan reports `negative-size-param (size=-5)`,
the plain build aborts rc 134 and the fixed source returns `rc=-1009` with
`wsh->ssl` untouched. `bash lab/freeswitch2shell/live/run_pos.sh` adds a
positive length, `7F FF FF FF 00 00 00 00` (`plen=INT_MAX`): the guard's
signed add overflows, the real `ws_raw_read` copies sender bytes verbatim,
and the plain build writes `0x4142434445464748` to `wsh->ssl`
(`ssl_bytes=4847464544434241`, `RESULT=PASS`, rc 0); fixed `rc=-1009` with
`ssl=(nil)` and ASan `WRITE of size 4096` at the end of a 131136-byte region.
Chosen-pointer control is therefore demonstrated in the real function over
loopback, not just in the extracted harness.
Wake 4 (20:29Z) closed the live gap: a full vulnerable FreeSWITCH ran in a
private `unshare -n` netns with `mod_xml_rpc` + `enable-websocket`, bound
`127.0.0.1:18080`, completed a WebSocket `101` upgrade and took a crafted
unmasked extended-127 frame. GDB captured `wsh->ssl=0x4847464544434241` and
the same value in `$rdi` at the SIGSEGV in `SSL_shutdown` from `ws_destroy
(ws.c:367)` ← `websocket_hook (mod_xml_rpc.c:703)`. Fixed-source and
in-bounds-frame controls both survive. The opt-in module/flag gate, lab-only
build shims and 127.0.0.1-only scope stay in the claim; the sentinel is not
executable code. Evidence: `lab/freeswitch2shell/live/logs/live_gdb/`,
`live_fixed/`, `live_safe/`, scripts `run_live_gdb.sh` / `run_live.sh`.
Durable evidence:
`reports/frontier-freeswitch2shell.md` (reproduction section), harness
`lab/frontier/freeswitch2shell/{ws_overflow.c,run.sh}`. The dedicated
`freeswitch2shell` mind owns this lane; details in
`.mishe-tauftauf/charters/freeswitch2shell.md`.

#### Admitted 2026-11-20 ~19:32Z: Freerdp2Shell (CVE-2026-114045 / GHSA-3m9q-g533-rqjq)

Claim sources: the GitHub advisory GHSA-3m9q-g533-rqjq, the CVE/OSV and NVD
records for CVE-2026-114045, FreeRDP's 3.32.1 release notes and the 3.32.0 to
3.32.1 diff, read as provisioning, not lab findings. CWE-122 via CWE-190;
CVSS 3.1 8.8 High post-auth (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`), 9.8
Critical only in no-auth deployments. Affected `master <= 8ec6d3923b…` and
stable `<= 3.32.0`, fixed `>= 3.32.1` (tag `bf217a5`); lineage: a bypass of
the CVE-2026-63117 fix (`b7ca093`). Claimed primitive: a client
`WAVE_FORMAT_DVI_ADPCM` `SNDC_FORMATS` record with `nBlockAlign=4,
nChannels=2` passes the scalar `>= 4` floor but violates the unchecked codec
relation `nBlockAlign >= 4*nChannels`; `select_format()` wraps a UINT64 block
size to `0xfffffffffffffff0`, commits it to `out_frames`, fails the `realloc`
without rollback, and `send_samples()` then `CopyMemory`s client audio bytes
into the still-8820-byte buffer at monotonically advancing offsets — an
unbounded sequential heap write of client-chosen bytes. Default posture is
**post-authentication (`PR:L`)**: keep that gate prominent in every impact
claim. This is a native C RDP server component, in the plant's admitted
"similar things" class alongside FreeSWITCH, FreeRADIUS and Brotli.

Small single-subsystem diff, exact vulnerable/fixed commits, no hardware gate
and a full bulk `memcpy` of client-supplied bytes (no reliance on glibc
tail-first/store-first zero-store windows) make a rung-4 attempt plausible.
The operator re-ran the digests-pinned harness at 19:30Z from committed
sources: `ALL CHECKS PASS`, rc 0, digests `d0a31487…` / `c5186500…`; rungs
1/2/3 with `out_frames=0xfffffffffffffff0`, `oob_writes=7564` starting at
offset 8820, chosen bytes at offsets 8820/12000, and ASan
`heap-buffer-overflow` `WRITE of size 16384` `0 bytes after an 8820-byte
region`; rung 4 places chosen `de`/`ad` at offsets 8820/21384 with
`out_pending_frames=8192`; benign PCM and the 3.32.1 guard are clean and five
vulnerable traces are byte-identical. Wake 4 drove the crafted PDU through
the real `rdpsnd_server_recv_formats()` parser on source-built 3.32.0
library bytes: ASan `WRITE of size 16384` 0 bytes after an 8820-byte region
from `rdpsnd_server_send_samples`, and a sanitizer-free replay placed `de`
at OOB offset 8820 and `ad` at 21384, fixed-guard control rc 3 with no
wrap. This was a chosen-byte rung 4 on real library bytes, still in-process at
wake 4: MCS/channel setup, rdpsnd over the wire, live-process corruption,
stock allocator layout and a full RDP session were UNKNOWN then; wake 8 below
moves the transport and live-server items to observed.
Wake 5 framed a complete SNDC_FORMATS PDU and drove the real exported
`rdpsnd_server_handle_messages()` dispatcher (rdpsnd_main.c:1204-1298) with a
stub WTS read callback, including body reassembly across reads and msgType
demux. A read-only source survey corrected the earlier implication that the
DVI record was shadow-reachable: `select_format()` is called from the server's
`Activated` callback, and shadow's default format list has no DVI_ADPCM
(tag `0x11`), so that variant is a library-level path only. A
WAVE_FORMAT_ADPCM record (tag `0x02`, `nBlockAlign=8`, `nChannels=2`) wraps
`out_frames` to `0xfffffffffffffffc`. Wake 6 then replaced the stub with
libfreerdp's real WTS reader (`FreeRDP_WTSVirtualChannelRead`), a real
`wMessageQueue` and the shadow `Activated` selection logic, and corrected the
reachability claim again: `freerdp_dsp_supports_format()` leaves only PCM in
the FFmpeg-off builds tested here, so neither wrap-capable tag is selected
from the stock server list. The positive rung 4 supplies an ADPCM server
record through `subsystem->rdpsndFormats`; with that condition explicit,
chosen-byte readback and the ASan `WRITE of size 16384` hold through the real
reader, dispatcher, activation and parser. Wake 7 ran a real 3.32.0
`freerdp-shadow-cli` on 127.0.0.1:13890 and the committed probe completed
X.224 / RDP_NEG_REQ over real TCP: protocol selection `0x08`/`0x02`/`0x00`,
and a TLS handshake that stops at `CONNECTION_STATE_NEGO` when CredSSP is
withheld under default NLA, while standard-RDP local-peer mode advances
without credentials. Wake 8 completed MCS CONNECT / ERECT DOMAIN / ATTACH
USER / three CHANNEL JOIN confirms via `live_mcs_join_probe.py` and drove a
headless `sfreerdp` to `CONNECTION_STATE_ACTIVE`; `SNDC_FORMATS` crossed the
wire and a subsystem-supplied ADPCM record made the live server log
`realloc failed!` / `SelectFormat failed with 12`. A synthetic playback
event then gave the live ASan server `WRITE of size 16384`, 0 bytes after an
8820-byte region, from `rdpsnd_server_send_samples`, with client-chosen
`0xDE` at offset 8820. No-auth posture, subsystem-supplied format table,
ASan build and synthetic audio are explicit conditions; stock allocator
layout, a real audio source, an FFmpeg-enabled build and a stock
wrap-capable format stay UNKNOWN.
Evidence: `reports/frontier-freerdp2shell.md`, extracted harness
`lab/frontier/freerdp2shell/{rdpsnd_overflow.c,run.sh}`, real-library
harness `lab/freerdp2shell-src/{run.sh,*.c}` with committed traces, seed
status `reports/freerdp2shell-status.md`. The dedicated `freerdp2shell`
mind owns this lane; details in `.mishe-tauftauf/charters/freerdp2shell.md`.
Wake trigger units and the presentation.json entry are owed from the
person's full-flag sync, never a bare `mishe sync`.

#### Admitted 2026-11-20 ~20:27Z: Xrdp2Shell (CVE-2026-44178 / GHSA-hh7r-2rmq-q4g4)

Claim sources: the GitHub advisory GHSA-hh7r-2rmq-q4g4, the CVE/OSV/NVD
records for CVE-2026-44178, xrdp's v0.10.6.1 release notes and the
`v0.10.6...v0.10.6.1` diff, read as provisioning, not lab findings. CWE-122;
CVSS 3.1 8.8 High post-auth (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`), 9.8
Critical only in no-auth deployments. Affected `< 0.10.6.1`; fixed in
`0.10.6.1` (tag `v0.10.6.1`, fix commit
`43dc9c3b71e5e46733d70ec0239c482ee264cd9f`). Claimed primitive: an
authenticated client's reassembled DYNVC virtual-channel message exceeds the
fixed 8192-byte xrdp→chansrv out stream; all three writers ask
`trans_get_out_s(trans, 8192)` on an exactly-8192-byte stream, `init_stream`
keeps that buffer, and `out_uint8a` is a plain `g_memcpy` with a bounds check
gated behind `USE_DEVEL_STREAMCHECK`, absent in ordinary builds. The client
controls the length (`drdynvc_process_data_first()` checks only
`total_bytes >= 1590 && bytes <= total_bytes`; DYNVC reassembly stages a
client-sized stream), so a multi-chunk message drives the copy far past the
8164/8168/8166-byte thresholds. Default posture is **post-authentication
(`PR:L`) with a dynamic channel open**: keep that gate prominent in every
impact claim. Native C RDP server component, in the admitted "similar things"
class alongside FreeRDP, FreeSWITCH, FreeRADIUS and Brotli.

Exact vulnerable/fixed tags, a public single-file subsystem diff, no hardware
gate and a full bulk `memcpy` of client-supplied bytes (no reliance on glibc
tail-first/store-first zero-store windows) make a rung-4 attempt plausible.
The operator re-ran the digests-pinned harness at ~20:25Z from committed
sources: `ALL CHECKS PASS`, rc 0, digests `46735a43…` / `2da4d3ea…`; rung 1
28+20000 bytes gives `oob_writes=11836 first_oob=8192 last_oob=20027`
(static 26-byte path 11834), rung 2 chosen `ab`/`cd` at OOB offsets
8228/12028, rung 3 ASan `heap-buffer-overflow` `WRITE of size 20000` 0 bytes
after the 8192-byte region via `do_copy` -> `drdynvc_data_first`, rung 4
`de`/`ad` at OOB offsets 8228/12024 across two messages; exact-size 0.10.6.1
and benign controls show `oob_writes=0` and 5/5 traces are byte-identical.
The claimed harness-only boundary was advanced on 2026-11-21: a second driver
(`lab/xrdp2shell-real/`, digests `a05ba8ac…` / `ecfe9f7e…`) links the real ASan
xrdp 0.10.6 `libxrdp.a` / `libcommon.a` and calls `xrdp_channel_process()` →
real `drdynvc_process_data_first()` → real `out_uint8a` on the `trans_create`
buffer: ASan `WRITE of size 20000` 0 bytes after the 8192-byte region, 8164
clean / 8165 OOB, 5/5 identical. A non-ASan reader plants an adjacent canary
chunk and reads chosen `DEADBEEF-CR` / `C0FFEE00-CR` back at offsets 84/484,
8208 bytes past the buffer start; no pointer-sized field or control-flow
target was controlled, and a `free()` variant aborts `malloc(): corrupted
top size`. The 8128-byte cap is a synthetic control, not the real 0.10.6.1
fix. It is still in-process: a completed RDP logon, dynamic-channel open,
network PDU trace, stock live-session allocator layout and the auth gate stay
UNKNOWN; loopback COTP reachability of the lab listener is the only network
observation and witness replay is owed. Evidence:
`reports/frontier-xrdp2shell.md`, harness
`lab/frontier/xrdp2shell/{xrdp_overflow.c,run.sh}`, real-path drivers and
runbook `lab/xrdp2shell-real/{real_drdynvc_driver.c,chosen_bytes_real_path.c,RUNBOOK.md}`,
status `reports/xrdp2shell-status.md`. The dedicated `xrdp2shell` mind owns this
lane; details in `.mishe-tauftauf/charters/xrdp2shell.md`. Wake trigger units
and the presentation.json entry are owed from the person's full-flag sync,
never a bare `mishe sync`.

#### Admitted 2026-11-20 ~20:52Z: Gst2Shell (CVE-2026-111183 / GHSA-62fg-53h6-6f68)

Claim sources: GHSA-62fg-53h6-6f68 / CVE-2026-111183 / ZDI-26-775
("GStreamer rtpL16depay Heap-based Buffer Overflow Remote Code Execution",
2026-10-15), the NVD/GHSA and ZDI advisories, and the fix commit
`80c184b4c5ee8ba28b2540ba58f40b8d44b61622` (2026-10-08) against vulnerable
parent `0b70c356345335dacc0acdc45d07a8a33bdf5eab`, read as provisioning, not
lab findings. CWE-122, CVSS 3.0 **9.8 Critical**
(`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) — pre-auth by the vector; a loopback
RTSP server → `rtspsrc` caps path was later demonstrated locally (see below),
but whether any public service accepts attacker SDP and the claimed RCE stay
UNKNOWN. Claimed
primitive: caps `encoding-params` is parsed into `channels` with no upper
bound (`gstrtpL16depay.c:181-189`), stored in the heap-embedded
`GstAudioInfo`; for `channels > 8` no channel order exists, so
`:201-216` calls `gst_rtp_channels_create_default (channels, info->position)`,
whose loop at `gstrtpchannels.c:301-310` writes
`GST_AUDIO_CHANNEL_POSITION_NONE` to `posn[0..channels-1]` with no bound.
`info->position` holds 64 elements, so `channels=1000` writes 936 elements /
3744 bytes out of bounds. The fix adds `gsize n_posn = G_N_ELEMENTS
(info->position)` and clamps with `channels = MIN (channels, n_posn)`.

An exact vulnerable/fixed commit pair, a pure length-check omission in one
small C function with a three-line fix, no hardware gate and a pre-auth
vector make a rung-4 attempt plausible. The operator re-ran the digests-pinned
harness at 20:47Z from committed sources: digests `3d2b8e06…` / `7dde5da7…`
match, `ALL CHECKS PASS`, rc 0. Rung 1 `channels=1000 position_capacity=64
oob_writes=936 first_oob=256 last_oob=3999` with 3744 counted zeroed OOB
bytes; rung 2 a caps value of 200 clobbers OOB offset 768 but not 1792, a
value of 1000 clobbers both; rung 3 ASan `heap-buffer-overflow`, `WRITE of
size 4`, 0 bytes after a 256-byte region in `vuln_create_default`; the
`MIN`-clamped fixed control gives `oob_writes=0` and 5/5 traces are
byte-identical. The extracted harness's `NONE=0` model was wrong: pinned
`audio-channels.h:101` defines `NONE=-3`, so the OOB writes store
`fd ff ff ff` and index 73 corrupts the low half of the `order` pointer from
NULL to `0x00000000fffffffd`. A live GStreamer 1.24.2 ASan harness
(`bash lab/gst2shell-src/run_live.sh`) faults at the real `depay.c:267`
`order->pos` dereference; the shipping `rtpL16depay` plugin
(`bash lab/gst2shell-src/run_real.sh`) faults rc 139 for `encoding-params`
86/87/100/1000, with a second glibc `free()` fault mode at N=86. A 2026-11-21
pass symbolicated the N=1000 shipping fault by gdb debuginfod to `srcpad->g_class`
of a heap-adjacent GstPad, and `bash lab/gst2shell-src/run_sdp.sh` drove
`a=rtpmap:96 L16/44100/N` SDP text through GStreamer's own SDP parser into the
fault at N=86/1000 (the harness explicitly models the RTP structure name); the
`sdpdemux` file path reached PLAYING without instantiating `rtpL16depay` and
fails at benign N=8 too, a bounded negative. A loopback RTSP server then fed a
real `rtspsrc ! rtpL16depay ! fakesink` victim pipeline with no auth challenge
(`rtsp_server.py` digest `f812d844…e0668`, `run_rtsp.sh` digest
`9841c920…2a5d`): N=8 is clean, N=1000 faults rc 139 four times with the
corruption in GLib's `block_source` (`rbx = 0xfffffffdfffffffd`); stock
`uridecodebin` auto-plumbing selects the same depay and aborts rc 134 with
`malloc(): invalid size`, removing the explicit-link step. This is a
count-controlled rung-4 effect, not chosen bytes: strong rung 4; whether a
public service ingests attacker SDP, RCE and allocator layout stay UNKNOWN.
Evidence:
`reports/frontier-gst2shell.md`, harness
`lab/frontier/gst2shell/{rtp_channels_overflow.c,run.sh}`, seed status
`reports/gst2shell-status.md`; the SDP harness `lab/gst2shell-src/sdp_caps.c`
and `run_sdp.sh` (digest `6ba2e707…c4f`), the gdb trace
`lab/gst2shell-src/gdb_symbolicated_1000.txt`, the RTSP driver
`lab/gst2shell-src/{rtsp_server.py,run_rtsp.sh}` and its tracked
`rtsp_evidence.txt` / `rtsp_gdb_1000.txt` are tracked. The dedicated
`gst2shell` mind owns this lane;
details in `.mishe-tauftauf/charters/gst2shell.md`. Wake trigger units and
the presentation.json entry are owed from the person's full-flag sync, never
a bare `mishe sync`.

#### Admitted 2026-11-20 ~22:2xZ: Babelfish2Shell (CVE-2026-119923 / GHSA-vq28-vgj3-r26w)

Claim sources: CVE-2026-119923 / GHSA-vq28-vgj3-r26w / AWS bulletin
2026-166-AWS, the AWS/GHSA/NVD advisories, and the fix commit
`ab820bddaffa540af82f2f689c3e535f82f14d89` (backports
`66fe10002e37`/5.6, `f0b8bd54aad1`/6.1) against vulnerable tag
`BABEL_4_8_0`, fixed tag `BABEL_4_10_0`, read as provisioning, not lab
findings. CWE-122, CVSS 3.1 **9.8 Critical**
(`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), CVSS 4.0 9.3 — a remote
unauthenticated crafted prelogin packet to the TDS port (default 1433); the
claimed RCE is a claim, not a demonstration. Claimed primitive:
`tdslogin.c:342-363` `ParsePreLoginRequest` reads an unbounded 16-bit
network-order `length`; `initStringInfo` allocates exactly 1024 bytes;
`tdslogin.c:377-383` calls `TdsGetbytes(prev->val.data, prev->length)` and
`tdscomm.c:634-659` `memcpy`s `length` sender bytes verbatim into that
buffer with no resize — both copy count and written bytes are
attacker-controlled. The fix rejects `length > 4096` and calls
`enlargeStringInfo` before the copy.

An exact vulnerable/fixed tag pair, a pure missing-bounds-check, no hardware
gate or credentials for rungs 1–3 and a pre-auth vector make a rung-4
attempt plausible; unlike Gst2Shell's fixed `-3` write pattern, the OOB bytes are
sender-chosen. Frontier re-ran the pins-pinned harness at handoff: pins
`c5559f08…` / `d4b09e8c…` match the brief and `ALL CHECKS PASS`, rc 0. Rung 1
`length=4096 si_capacity=1024 oob_writes=3072 first_oob=1024
last_oob=4095`; rung 2 lengths 1050/1150/2100 clobber neither/first/both
neighbour stamps; rung 3 ASan `WRITE of size 4096`, `0 bytes after
1024-byte region` in `wire_getbytes`; rung 4 sender bytes `de ad be ef ca fe
ba be` and `41 42 43 44` land byte-exact at OOB offsets 1100/2000; the fixed
control gives `rc=0 oob_writes=0`, clean under ASan, and 5/5 traces are
byte-identical. Rungs 1/2/3 are established only in the extracted harness;
rung 4 shows chosen bytes at chosen offsets there, **not** in a live
process. No real Babelfish/PostgreSQL process, TDS endpoint, `palloc`/heap
layout, real neighbouring object, pointer control or marker execution was
observed — the consumer-reality check is still owed. Distinct from the
`postgres2shell` FDW lane and CVE-2026-119924. Evidence:
`reports/frontier-babelfish2shell.md`, harness
`lab/frontier/babelfish2shell/{prelogin_overflow.c,run.sh}` with raw sources
and `PROVENANCE.md` under `src/`, seed status
`reports/babelfish2shell-status.md`. The dedicated `babelfish2shell` mind
owns this lane; details in `.mishe-tauftauf/charters/babelfish2shell.md`. The
two-pane window (inner socket, window 21), registry entry and seed wall are
already live from frontier; wake trigger units and the presentation.json
entry are owed from the person's full-flag sync, never a bare `mishe sync`.

#### Admitted 2026-11-21 ~00:5xZ: Bzfs2Shell (CVE-2026-130849 / GHSA-9q5f-g948-c95m)

Claim sources: CVE-2026-130849 / GHSA-9q5f-g948-c95m / EUVD-2026-127253 (CNA
VulnCheck, published 2026-11-17), "BZFlag bzfs before 2.4.32 Heap
Out-of-Bounds Write via NetHandler::tcpReceive()", CWE-122, CVSS 4.0 **9.3
Critical** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/...`), read as
provisioning, not lab findings. Affected `< 2.4.32` (including v2.4.30), fixed
`2.4.32`; fix commit `8e501d685aef549090b363260979a4eb93484ea1` (OSV also
resolves the tag to `f11f05485d7406c78159aac00ace3c58b4b17ec2`), vulnerable
tag `v2.4.30`. Claimed primitive: a TCP body length of exactly 1024 passes a
guard that rejects only `len > MaxPacketLen`, so `recv(fd, tcpmsg + 4, 1024)`
writes four body bytes past `tcpmsg[1024]` into the adjacent `int tcplen`;
choosing those bytes negative leaves `tcplen` below zero after `tcplen +=
size`, so the next `receive()` writes chosen bytes before the object. The fix
bounds the body to `MaxPacketLen - 4` and rejects a bad offset or length
before `recv`.

Scope: `bzfs` is a dedicated C++ game server, not a language runtime or HTTP
server; it is admitted as an X2Shell-class extension under the same precedent
that admitted FreeRADIUS, Brotli and FalkorDB — a pre-auth network-reachable
heap OOB write with sender-chosen bytes, exact tags and an advisory RCE claim.
The judgment is recorded, not buried; revisit this lane first if the class is
later narrowed. Distinct from every other admitted lane.

One off-by-header bound in one function, a 13-line fix diff, a one-packet-pair
unauthenticated trigger and OOB bytes that are the tail of the attacker's own
body make a rung-4 attempt plausible. Frontier re-ran the digests-pinned
harness at handoff: `bash lab/frontier/bzfs2shell/run.sh out` printed `ALL
CHECKS PASS`, rc 0; pins `1a16963f…` / `f2686d5b…`. Rung 1 `tcplen=-1024` with
the chosen tail at `tcpmsg+1024`; rung 2 destination 936 bytes before the
object, next length 1028; rung 3 ASan `heap-buffer-overflow`, `WRITE of size
64`, `recv` → `traced_recv` → `receive_msg`; rung 4 `DEADBEEFCAFEBABE` and
`0123456789ABCDEF` read back byte-exact from chosen preceding members; fixed
controls reject at the first bound and are ASan-clean, five runs byte-identical
(`sha256=cea3b92e…`). Rungs 1/2/3 are established only in the extracted
harness; rung 4 is INSTRUMENTED CHOSEN-VALUE CONTROL — a real syscall writes
chosen bytes at a chosen harness member offset, but the prefix stand-in is not
the stock `NetHandler` layout. No live `bzfs` process, player socket, real
object layout, allocator neighbour, function pointer or execution was
observed; the advisory's RCE claim is untested here, and the consumer-reality
check is owed before any stock-build rung-4 claim. Evidence:
`reports/frontier-bzfs2shell.md`, harness `lab/frontier/bzfs2shell/` with
`PROVENANCE.md`, seed status `reports/bzfs2shell-status.md`. The dedicated
`bzfs2shell` mind owns this lane; details in
`.mishe-tauftauf/charters/bzfs2shell.md`. The two-pane window (inner socket,
window 22), registry entry and seed wall are already live from frontier; wake
trigger units and the presentation.json entry are owed from the person's
full-flag sync, never a bare `mishe sync`. Witness replay was requested
separately (#429).

#### Admitted 2026-11-21 ~02:2xZ: Kamailio2Shell (CVE-2026-106803)

Claim sources: OSV and cvelistV5 records for CVE-2026-106803 (CNA MITRE,
published 2026-11-02), upstream issue #4954, fix PR #4958 and fix commit
`21261436492f0014930e804e20586e3833bb91b9` with patch, and raw `notify.c` /
`save.c` at tags `6.1.4` and `6.1.5` (hashes and URLs in
`lab/frontier/kamailio2shell/PROVENANCE.md`). CWE-121, CVSS 3.1 **9.8
Critical** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Affected 6.1.3/6.1.4,
fixed 6.1.5, which enlarges `bufport`/`portbuf` to 6 bytes and adds a bound
check. Claimed primitive: a crafted `application/reginfo+xml` NOTIFY Contact
URI supplies `alias=<host>~<port>~<proto>`; `process_contact()` uses the
tilde distance as the `memcpy` length into `char bufport[5]` and then stores
an unchecked NUL, while `update_contacts()` has the same flaw with
`portbuf[5]`. The advisory claims unauthenticated process termination; its
`C:H/I:H` vector is a separate claim, not a lab result.

Scope: `ims_registrar_pcscf` is an IMS P-CSCF SIP module that must be loaded
and configured, not a default-on HTTP path. It is a C network-facing server
component, admitted as an X2Shell-class extension under the same precedent
that admitted FreeRADIUS, FreeSWITCH and Bzfs2Shell; the judgment is recorded
in `.mishe-tauftauf/charters/kamailio2shell.md` and this is the second lane
to revisit if the class is narrowed.

The overwrite length is a URI distance, not the numeric port, so long chosen
writes pass the 5-byte buffer; exact affected/fixed tags, a patch, no
hardware gate and a claimed unauthenticated trigger make a rung-4 attempt
plausible. The operator replayed the committed harness at ~02:1xZ: 15 PASS,
`ALL CHECKS PASS rc 0`, deterministic trace
`sha256=94ef79641b081f850cb04f95d0f0945e7de7f84f9505462f23bf8aa054fa1cb8`.
Rung 1 `len=80` with `oob=75`, rung 2 chosen function pointer and stamp
overwritten byte-exactly, rung 3 ASan `stack-buffer-overflow` `WRITE of size
80` from `memcpy` ← `parse_alias`, rung 4 `MARKER EXECUTED` through the
instrumented pointer only; the pinned 6.1.5 rule rejects `len=80` before the
copy. Rungs 1/2/3 are established in the extracted harness; rung 4 is
INSTRUMENTED chosen-value control. No live Kamailio, real frame layout,
stack protector, return-address control or execution was observed.
Evidence: `reports/frontier-kamailio2shell.md`, seed status
`reports/kamailio2shell-status.md`, harness `lab/frontier/kamailio2shell/`.
The dedicated `kamailio2shell` mind owns this lane. Its two-pane window
(inner socket, window 24), registry entry and seed wall were live from
frontier's handoff; wake trigger units and the presentation.json entry are
owed from the person's full-flag sync, never a bare `mishe sync`.

#### Admitted 2026-11-21 ~02:2xZ: Iperf2Shell (CVE-2026-101283 / GHSA-pwcx-5qh6-2pxc)

Claim sources: cvelistV5 record
`https://cveawg.mitre.org/api/cve/CVE-2026-101283` (CNA Anthropic, analyst
Ada Logics, published 2026-09-30), GitHub advisory GHSA-pwcx-5qh6-2pxc, the
esnet 3.22 release page and tag
`926bd905501b792bd082d2200d1d1a84aa543e3a`, the fix commit
`d08588aceee48fa45832cae5e32616abb33cb0fc` and raw `iperf_auth.c` at tags
3.20, 3.21 and 3.22 (hashes in `lab/frontier/iperf2shell/PROVENANCE.md`).
CWE-122, CVSS 4.0 **9.2 Critical**
`AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`. Affected 3.20 and
3.21, fixed 3.22; the one-line fix turns the warn-only length guard into a
rejection before `BIO_read`. Claimed primitive: the base64-decoded client
`authtoken` length is passed as the `BIO_read` size into a 256-byte RSA heap
buffer, so the overflow length and bytes are attacker-chosen. The server
must have RSA auth enabled, but the oversized token is the input being
parsed, so the write is still pre-auth. Preserved conflict: 3.22 release
notes call this CVE a use-after-free in `iperf_server_api.c` and name a
separate CVE for the `iperf_auth.c` overflow; the CVE record, GHSA and fix
commit point at `decrypt_rsa_message()`.

Scope: `iperf3` is a C network-listening daemon, admitted as an X2Shell-class
extension under the same "similar things" precedent as FreeRADIUS,
FreeSWITCH and Bzfs2Shell; the judgment is recorded in
`.mishe-tauftauf/charters/iperf2shell.md`.

The write consumer is a real OpenSSL 3 `BIO_read` → `memcpy`, so the
nginx-plant zero-store lesson does not apply; a pre-auth network input,
exact tags and an exact patch make a rung-4 attempt plausible. The operator
replayed the committed harness at ~02:1xZ: 17 PASS, `ALL CHECKS PASS rc 0`,
trace
`sha256=bd3efc4cb4720e7fe5cc2e83e79cc7e89010f75a7e93579360a215eb5f029caf`.
Rung 1 decoded length 336 against a 256-byte modulus (`oob_bytes=80`), rung 2
glibc aborts at `free(): invalid size` from the next chunk's overwritten
metadata, rung 3 ASan `heap-buffer-overflow` `WRITE of size 336` from
`BIO_read` ← `decrypt_rsa_message` at `iperf_auth.c.3.21:324`, rung 4 chosen
`IPERF2SHELL!` and `0x1122334455667788` supplied in the write buffer only;
the pinned 3.22 rule rejects before `BIO_read`. Rungs 1/2/3 are established
on the real pinned upstream function; rung 4 is INSTRUMENTED chosen-byte
control, not pointer control in a stock binary. No live `iperf3`, stock heap
layout, useful-pointer control or execution was observed. Evidence:
`reports/frontier-iperf2shell.md`, seed status
`reports/iperf2shell-status.md`, harness `lab/frontier/iperf2shell/`. The
dedicated `iperf2shell` mind owns this lane. Its two-pane window (inner
socket, window 25), registry entry and seed wall were live from frontier's
handoff; wake trigger units and the presentation.json entry are owed from
the person's full-flag sync, never a bare `mishe sync`.

#### Held 2026-11-21 ~01:12Z: Gdbserver2Shell (CVE-2026-121997 / GHSA-jq36-9pw3-8r4v) — not admitted under #6

Frontier handed this find over on tape #448 after committing
`reports/frontier-gdbserver2shell.md` (5261154) and the harness
`lab/frontier/gdbserver2shell/`. Claim sources: the CVE record (CNA Red Hat,
published 2026-11-05), the GHSA API and RHBZ 2565679 comment 0; CWE-122, CVSS
3.1 **8.1 High** `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`. Claimed primitive:
`cmd_qtdpsrc` allocates `slen+1` from the packet's declared length but calls
`hex2bin` on the actual hex length, so a declared/actual mismatch writes
sender-chosen bytes past the heap buffer; a following `qGetTLSAddr` packet is
claimed to call through the overwritten `td_ta_map_lwp2thr_p` pointer.
Affected products are Red Hat names (RHEL 6-10, gcc-toolset-14/15, hardened
images); **upstream version range, fixed version and fix commit are UNKNOWN**.
Upstream sourceware gitweb returned 503; no upstream bytes were pinned.

The operator replayed the committed harness independently at 01:0xZ: 14 PASS,
`ALL CHECKS PASS rc 0`, `sha256=c81092bd…`. That digest differs from
frontier's `61826865…` because `run.sh` hashes ASan text, not a deterministic
five-run trace; no harness pins, ASan log or PROVENANCE.md are committed.
Rungs 1/2/3 are ESTABLISHED only for the extracted model, and rung 4 calls a
pointer inside a `process_info_private` struct the harness itself invented —
no live gdbserver, stock layout, real function pointer, RIP control or shell
execution. The window's claimed `01:21Z`/`01:22Z` creation and capture times
contradict the files' `00:58:5xZ` mtimes and #448's `00:59:06Z` tape stamp;
those timestamps stay UNKNOWN.

Decision: **held, not admitted** under standing approval #6. That approval
lists "affected/fixed versions" among the evidence required for admission;
a debugger daemon with no upstream version, no fix, no pinned source bytes,
AC:H and instrumented-only rung 4 sits further outside this plant's
runtime/web-server class than Bzfs2Shell, already recorded as the first lane
to revisit if the class is narrowed. No charter, status file, docs/README
admission entry or engine route is created, and none is requested from the
person for this candidate. Frontier's two-pane window 23, registry entry
(status file still the brief) and seed wall remain a **frontier dashboard,
not a declared target**; no wake unit or presentation entry is owed.

Revisit trigger: a reachable mirror supplies pinned vulnerable upstream bytes
and a fixed version/commit, the real `gdbserver/tracepoint.cc` handler is
compiled into the ASan harness, and the stock `process_info_private` layout
and `qGetTLSAddr` dispatch are exercised. Until then this is an examined
candidate, not a mind.

#### Examined 2026-11-20: GHSA-87fm-7w84-j2px (Ruby case-conversion integer overflow)

Flagged by ruby2shell on tape #84. Claim source: the vendor's
2026-11-18/19 batch advisory and the GHSA; affected Ruby
3.3 <=3.3.13, 3.4.0-3.4.12, 4.0.0-4.0.9, fixed 3.3.14/3.4.13/4.0.10; CWE-190
`rb_str_casemap` intermediate `int` length overflows to a small positive
value, so `rb_str_new` allocates a tiny string and ~4 GiB of converted
data is written past it; vendor says RCE-proving PoCs exist. This is
**not a new target** — it is Ruby, already admitted as Ruby2Shell, so no
new mind, charter, window or trigger unit is owed. **Lane not opened**
under the current guard: the published minimal reproduction is
`"\u0390" * 715_827_883` (~1.4 GiB input, ~4 GiB output, Rack <=3.2.1
for the Rails path), while a plant wake service is capped at
`memory.max=2 GiB`, `memory.high=1.5 GiB` inside a slice capped at 5 GiB
and already holding ~2.5 GiB. This is the same structural-limit lesson
as the nginx2root consumer check: no amount of grooming changes a budget
that cannot hold the input. Revisit only if a person-owned guard or
dedicated larger-budget lane changes that ceiling. The other five GHSAs
in the batch are triaged in the next section (seven total; two handled here).

#### Triaged 2026-11-20: remaining five GHSAs in the 2026-11-18 Ruby batch

Claim source: ruby-lang.org's 2026-11-18 advisory
`multiple-vulnerabilities-in-regexp-and-string/`, which states **seven**
bugs (all Ruby, affected <=3.3.13 / 3.4.0-3.4.12 / 4.0.0-4.0.9, fixed by
3.3.14/3.4.13/4.0.10) and says PoCs prove RCE for some of them. The note
above said "six other" — corrected: seven total, two handled
(34m4-m9fh-gqp5 admitted as Ruby2Shell, 87fm-7w84-j2px examined above),
five remaining:

- GHSA-7x2q-68qv-6p8x — double free in Regexp compilation, RCE PoCs;
  vendor conditions impact on applications that compile
  attacker-controlled patterns.
- GHSA-wpqw-5qxg-m68r — out-of-bounds read in case-insensitive Regexp
  matching with attacker-controlled patterns; claimed
  attacker-controlled memory corruption.
- GHSA-3p8q-wmhx-vm2w — CWE-190 integer overflow in Regexp compilation
  causing a heap overflow, RCE PoCs; attacker-controlled patterns.
- GHSA-7whj-cfh7-xgm4 — CWE-787 heap overflow in `Regexp#to_s`,
  disclosure/RCE PoCs; attacker-controlled patterns.
- GHSA-pvgc-g7gj-pv6h — out-of-bounds read in case-insensitive
  backreference matching; disclosure or crash only, no RCE claim;
  trigger is a crafted string against a pattern.

Decision: **no new target** (all Ruby, already admitted) and **no lane
opened**. Reachability is the blocker, not the memory budget: the admitted
CVE-2026-132825 is default-reachable in Rails/Sinatra through ordinary
case conversion of user strings, whereas four of these five need the
application to compile attacker-controlled regex patterns — a specific
application behavior, not a default web-framework path. The fifth is a
read-only disclosure/crash bug with no write/control primitive for rung 4.
Repro sizes for the regexp bugs are UNKNOWN — not measured, so no budget
claim is made. No new mind/charter/window/trigger is owed; ruby2shell owns
any decision to open a secondary lane (noted to it on tape).

#### Examined 2026-11-20: NGINX HTTP/2 RCE cluster (CVE-2026-123007 / CVE-2026-123633)

Claim sources: Wiz Research's 2026-11-18 post
(`wiz.io/blog/nginx-http2-rce-vulnerabilities`), Rapid7's 2026-11-18
analysis (updated 11-20) and F5 advisory K000163926. Both are CVSS 9.2,
pre-auth, and need `http2 on`; Wiz reports RCE confirmation for both in
its own labs. **CVE-2026-123007** (CWE-191):
`ngx_http_v2_filter_cleanup()` refunds queued DATA beyond
`NGX_HTTP_V2_MAX_WINDOW`, the next connection WINDOW_UPDATE's unsigned
subtraction underflows, the excessive `h2c->send_window` becomes a
negative `off_t` length, and buffered TLS output performs an out-of-bounds
`memcpy`. Affected 1.9.5-1.31.8; fixed 1.30.7 stable / 1.31.9 mainline.
**CVE-2026-123633**: HTTP/2 connection use-after-free when a partial
HEADERS frame leaves a connection on the reusable list and free-slot
pressure closes it mid-request; proxy configuration required. Affected
1.19.7-1.31.8; fixed 1.30.7 / 1.31.9.

Decision: **no new target admitted, no lane opened.** The published
CVE-2026-123007 RCE handoff (`sfewer-r7/CVE-2026-123007`,
`NGINX_HTTP2_STANDALONE_REPRODUCTION.md`) states its calibrated profile
requires `avx512f` and `avx512vl`, a Debian glibc 2.41 nginx 1.31.8
image, and about 119.02 GiB plaintext per attempt (about 60 GiB for the
standalone crash trigger). This host is an AMD Ryzen 7 5700X with
**avx2 only** and glibc 2.39: the published copy consumer is structurally
unavailable here, the exact consumer-reality failure the staged plan
screens for first. Wiz's RCE claim for this CVE used an undisclosed
method, so an alternative route is UNKNOWN, not established.
CVE-2026-123633 has no public PoC and is the dedicated mission of the
sibling `nginx2root` plant; cross-plant scope is reserved to the person.
Revisit 123007 only with a different consumer or a person-owned larger
budget; revisit 123633 only on a person's cross-plant decision. Tape
#105/#106. No mind, charter, window or trigger unit is owed.

#### Scanned 2026-11-20: Java4Shell (CVE-2026-114938) — screened out here

Claim sources: JFrog and Wiz (both 2026-11-17), CCB Belgium. OpenJDK's
x86-64 AVX-512 VBMI Base64 decoder intrinsic underflows its tail mask on
input such as 64 `A`s plus `=` (JDK 17): `(len/4)*3 - padding` wraps to
-1, `BZHI` reads 255, and a 64-byte masked store starts at offset 48 of
a 50-byte output array, writing ~62 bytes past it. Affected 17.0.6
through 17.0.21.0.3, 21 through 21.0.13.0.3, 25 through 25.0.5.0.3,
27 through 27.0.1.0.3 (and the Java 8 Enterprise Performance Pack);
fixed 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1. Claims of pre-auth
RCE in default-configured Keycloak, Jira, Confluence, Artifactory,
Jenkins and PingFederate are vendor/researcher claims, not lab findings.
**Decision: no admission, no lane.** All four flags `avx512f`,
`avx512bw`, `avx512vbmi`, `bmi2` are required; observed 2026-11-20
12:19Z that this host's Ryzen 7 5700X (Zen 3) exposes **zero** avx512
flags, so the vulnerable assembly path cannot run here. Same
structural-consumer screen that ruled out nginx CVE-2026-123007.
Revisit only on a person-owned AVX-512-capable lane.

#### Frontier brief 2026-11-20: Apache2Root (CVE-2026-119618)

Claim sources: Apache's 2.4.71 advisory (released 2026-11-11), the CVE
record (CWE-362) and Red Hat's CVE page. Unauthenticated heap
corruption/RCE claim in mod_http2's `assign_headers()` when HTTP/2 is
negotiated (`h2`/`h2c`); affects httpd 2.4.55-2.4.70 and mod_h2
2.0.8-2.0.42, fixed in 2.4.71. The one-line fix
`apache/httpd@824beab` changes `apr_table_setn(req->headers,
"Content-Length", "0")` to `apr_table_setn(r->headers_in, ...)`, i.e.
the buggy path mutates the shared stream table after cloning it into
the request. Red Hat reports a reliable exploit against a default
event-MPM server; Wiz and CSA could not locate that primary research,
and CVE.org scores `AC:H` against Red Hat's `AC:L` — reliability stays
UNVERIFIED. No CPU blocker on this host, so this is the top tractability
candidate. Full source-bound mechanism, unknowns and the cheapest
loopback h2c experiment are in `reports/frontier-apache2root.md`.
**No mind/charter/window owed yet**: rung 0 only, no local build or
trigger. `lab/apache2root/` is a PHP2Shell fixture, not this lane.
Hand to the operator for admission only if a local rung 1-2 observation
appears; frontier then moves to the next candidate.

Local update 2026-11-20 13:00Z (`frontier`, commit pending): rung 2
observed on two gcc ASan/UBSan builds under
`lab/frontier/apache2root/` — the loopback h2c CGI oracle returns
`CONTENT_LENGTH=[<UNSET>]` on 2.4.70 and `CONTENT_LENGTH=[0]` on 2.4.71
for HEADERS with Content-Type, no Content-Length, END_STREAM
(`logs/oracle-run5.log`). This confirms the wrong-table write, not heap
corruption: no ASan report yet. Build/harness are
`build.sh` / `oracle.sh`; full evidence in
`reports/frontier-apache2root.md`. Operator notified for a dedicated
mind if rung 3 appears; frontier does not duplicate an admitted lane.

## Staged rung-4 plan (per target, revised from the nginx2root experience)

These stages are successive depth probes, not checkboxes. Stop at the first
observed limit and document it; a lane that reaches Stage C on one build
and only Stage A on another reports both boundaries separately.

1. **Consumer reality first.** Before exploitation mechanics, determine
   the consumer's behavior on this host's hardware and glibc (for
   memcpy-style consumers: dispatch order, store-first vs tail-first,
   zero-store windows). A structural zero-store consumer kills the path —
   record it and move to the next consumer or target.
2. **Rungs 1–3.** Suspected → reproducible crash → confirmed corruption,
   ASan/UBSan builds of affected and fixed versions, patch diff read as a
   specification first.
3. **Stage A — placement control.** Heap-groom the lab process and prove
   chosen bytes at a chosen offset via a canary. LD_PRELOAD
   synthetic-memcpy experiments are approved for mechanics but labeled
   synthetic; no stock-build rung-4 claim derives from them.
4. **Stage B — wire-pure trigger** where the debugger was used to force
   ledger or state values; bulk local traffic is approved with the
   operator's purpose gate.
5. **Stage C — control-flow hijack.** Pointer control / benign marker
   execution, ASLR disabled where needed, honestly labeled per-build.

## Deliverable

`reports/<target>-investigation.md` per target plus committed
reproduction scripts; a failed stage is preserved as a negative result
and per-build boundaries are part of the deliverable.

## Frontier finding — Mosquitto CVE-2026-110486 (2026-11-20 15:40Z)

`frontier` selected the next candidate after the Apache handoff and drove
it locally: **Mosquitto 2.1.0–2.1.2 built-in WebSocket "MASKerade"**,
CVE-2026-110486 / GHSA-6j8m-r32v-4h38 (Critical), fixed 2.1.3. A masked
zero-length frame makes `net__read_ws()` return 4 while copying 0 bytes;
`packet__read_single()` underflows `to_process` and advances `pos` past a
1-byte allocation. Full source-bound mechanism, claim sources and honest
rung grading are in `reports/frontier-mosquitto2shell.md`.

Observed on gcc ASan/UBSan builds under
`lab/frontier/mosquitto2shell/` (`build.sh`, `trigger.py`, `run.sh`,
`placement.sh`): rung 1 deterministic 3-frame pre-auth trigger over a
loopback WS upgrade; rung 3 ASan `WRITE of size 256` 3 bytes past a 1-byte
region on 2.1.2 (`logs/differential-run1.log`), clean on 2.1.3; Stage A
placement control — the write offset grows exactly 4 bytes per empty
frame (0 → in-bounds, 1 → +4, 2 → +8, 4 → +16, 8 → +32) with chosen
payload bytes (`logs/placement-run1.log`). Rung 4 (the published
tcache → dlsym → shell chain) is NOT demonstrated locally and stays a
claim; ASan's allocator cannot host the glibc tcache chain.

Handed to the operator with evidence for a decision on a dedicated
`mosquitto2shell` mind; frontier does not duplicate that lane. Next cheap
rung: non-ASan `-O0 -g` build under gdb, reproduce the PONG-adjacency
groom and confirm a controlled `malloc()` return before claiming rung 4.
