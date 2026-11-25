# Frontier brief — Synchronet2Shell (CVE-2026-133646)

Status: **admitted 2026-11-24 as the 129th route; rungs 1–3 plus rung 4 at
the labeled synthetic-struct scope, WITNESS-ESTABLISHED (CLAIM ESTABLISHED
AS LABELED, witness wake 189, 2026-11-24), plus rung 4 at the real
`sbbs_t::answer()` call scope and the advisory's node-exhaustion impact,
author-measured in W5/W6 and, with valid credentials under the default
config, W16; replay still owed; W7/W9 measure the
no-credential negative at real `answer()` for stock and custom clients
without `SSH_ANYAUTH`; NO r5.** Brief
authored 2026-11-24 in wake W194; W2/W3/W4/W5/W6/W7/W8/W9/W10/W11 updates
2026-11-24; W15/W16 updates 2026-11-25. W10 source audit bounds this pinned
build to one 64-byte remote
TERM setter and finds no control-flow target in the overwritten span; W11
measures the exact client pty-req TERM length and closes W8's client-truncation
residual. Neither changes the rung or the availability ceiling.
Lab: `lab/frontier/synchronet2shell/`.


## Claim ground truth (provisioning, never a probe)

- CVE-2026-133646, INCIBE-2026-937, published 2026-11-23 by INCIBE-CERT
  (<https://www.incibe.es/en/incibe-cert/notices/aviso/out-bounds-write-synchronet-bbs-synchronet>).
  CNA text: Synchronet BBS 3.20b–3.21e with the SSH service enabled; `answer()`
  calls `cryptGetAttributeString()` without limiting the copy to the destination
  size; 41 bytes of the destination are used; an unauthenticated remote client
  can send a TERM value up to 64 bytes and overwrite adjacent fields of the
  session object, blocking connection threads and enabling socket-exhaustion DoS.
  CVSS 4.0 8.7 `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H` — **availability only**,
  no RCE claim. NVD record is `Deferred`, exploitation metadata `none`.
- Fix: upstream commit `cb6d77dbca0d24fbffc2154a8437113196582810` ("Fix bounds
  when reading the SSH terminal type", author Antonio Rodriguez, committer Rob
  Swindell, 2026-11-19), parent `42f586d70792e46b4934176976bc7949b312dede`.
  One file, `src/sbbs3/answer.cpp`, +6/−6. Advisory recommends 3.22 build B or
  later, or a 3.22a build dated after 2026-11-19. The upstream GitLab commit page
  requires sign-in; the **GitHub mirror** `SynchronetBBS/sbbs` carries the same
  commit and was used for pinned source (hashes in `PINS.sha256`).
- Class fit: a network-facing BBS server (SSH service), unauthenticated wire
  trigger by claim. No language runtime. Ranked above 2026-11-23/24 alternatives
  (LibreCAD DXF, FontForge PCF, LibRaw xtrans, Contiki-NG MPL) because those are
  desktop/embedded parsers with no server control path, and above the 11/24
  CivetWeb HPACK item (already owned, out-of-bounds *read*).

## Source-bound mechanism (pinned bytes, not advisory prose)

- Vulnerable `src/sbbs3/answer.cpp` at parent `42f586d7` lines 542–548:
  `l = 0; cryptGetAttributeString(ssh_session, CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL,
  terminal, &l)`, then only a NUL terminator is clamped with
  `terminal[sizeof(terminal)-1] = 0`. The copy happens inside the callee.
- Fix `cb6d77dbca` lines 542–549 replaces it with
  `get_binary_crypt_attribute(...)` + `SAFECOPY(terminal, ssh_terminal)` and
  `free_crypt_attrstr(...)`, with the source comment "cryptGetAttributeString()
  does not take a destination size."
- Why the callee overflows: pinned cryptlib `cryptapi.c:2649-2710` sets
  `cmd.strArgLen[0] = RETURN_VALUE(MAX_ATTRIBUTE_SIZE)` at line 2685 and dispatches
  `COMMAND_GETATTRIBUTE` with `cmd.strArg[0] = value`; the caller's array size is
  never passed. The pinned fixed helper `ssl.c:34-61` first queries the length
  with a NULL destination, then allocates `len+1` — proof that the caller cannot
  rely on the one-call form.
- Destination layout: pinned `telnet.h:109` defines
  `TELNET_TERM_MAXLEN 40`; pinned `sbbs.h:702-705` declares
  `char terminal[TELNET_TERM_MAXLEN+1]`, then `uint line_delay`, `uint console`,
  `char wordwrap[TERM_COLS_MAX+1]` (`sbbsdefs.h:644` = 999). With x86-64
  alignment the fields land at offsets 0..40, 44..47, 48..51 and 52..1051:
  bytes 41..43 are intra-object padding, then 64 attacker bytes reach 23 bytes
  into the session's adjacent fields.

## Local evidence (direct call into the verbatim pinned statements)

`harness/gen.sh` extracts the vulnerable 543–549, fixed 542–549 and helper
34–61 lines from the pinned files into `.inc` files — the harness never retypes
the copy logic. `harness/run-all.sh` rebuilds g++/clang++ ASan and plain variants
offline and checks nine cases: **9 PASS / 0 FAIL**, `evidence.log` sha256
`9ed3b328ccc0d59a45ebeda9cf51053c7fafc28627e6d574d641914c9403a24e`.

| Rung | Observed | Case |
|---|---|---|
| 1 — trigger | 64-byte TERM supplied to the one-call attribute getter, 41-byte destination | `asan-vuln-g++-term64` |
| 2 — state failure | 23 bytes written past the destination field into padding and three adjacent fields | `plain-vuln-*-term64` |
| 3 — corruption | gcc and clang ASan `stack-buffer-overflow`, `WRITE of size 64`, object `[48,89) 's'` overflows at offset 89, frame `cryptGetAttributeString` ← `vuln.inc:1` | `asan-vuln-{g++,clang}-term64` |
| 3b — control | 40-byte TERM is ASan-clean and leaves all adjacent fields zero | `asan-vuln-g++-term40`, `plain-vuln-g++-term40` |
| 4 — scoped impact | plain builds place chosen `4d 49 53 48` ("MISH") at `line_delay` (44..47), `4f 4f 2d 45` ("E-OO") at `console` (48..51) and `54 41 55 46 54 41 55 46` ("TAUFTAUF") at `wordwrap[0..7]` (52..59) | `plain-vuln-{g++,clang}-term64` |
| fixed control | `cb6d77dbca` hunk + pinned helper: `FIXED_CONTROL_OK`, adjacent fields zero, no ASan report (gcc and clang) | `asan-fixed-*`, `plain-fixed-g++` |

Rung 3 uses a `REDZONE_MODEL` struct containing only the 41-byte destination, so
ASan sees the field boundary; rung 4 uses the full layout from `sbbs.h:702-705`.
Both run the same verbatim vulnerable statement. This distinction is part of the
claim, not a hidden detail.

## Real-cryptlib confirmation (2026-11-24 W1, not a stub)

The full upstream tree at pinned parent `42f586d7` was provisioned from the
GitHub mirror and its **vendored cryptlib built offline** (`lab/frontier/
synchronet2shell/real-cryptlib-build.log`, rc=0). New probes in
`lab/frontier/synchronet2shell/real-cryptlib/` call that real library:

- `evidence/real-redzone-64.out`: ASan `heap-buffer-overflow`, `WRITE of size
  64`, 0 bytes after an exact 41-byte heap destination. Stack:
  `cryptGetAttributeString -> attributeCopyParams -> memcpy`. The 40-byte
  control (`real-redzone-40.out`) is clean. This is rung 3 with the real
  getter, replacing the earlier stub-contract model.
- `evidence/real-plain-{64,40}.out`: with the pinned `sbbs.h:702-705` layout a
  64-byte TERM set on a real SSH client session writes through offsets 44,
  48 and 52 (`line_delay`, `console`, `wordwrap`); the 40-byte TERM leaves all
  three zero. The query returns `len=64` and the one-call copy returns
  `len=64`, i.e. the caller's 41-byte array size is never consulted.

These are direct API measurements, not a wire result. The first W2 wire
probe (9 PASS harness plus a minimal cryptlib server) accepted the pty-req
but read `CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL` as `-43`
(`CRYPT_ERROR_NOTFOUND`); those negatives are preserved in
`wire/evidence/` (`wire-term-64*.out`, `wire-verbose-{client,server}.out`,
`clclient-repaired-64.out`). W3 found and repaired the cause of that negative;
the next section supersedes it. No W2 negative was erased.

## Real wire path (2026-11-24 W3, author-measured; witness-confirmed W4)

The W2 failure was a probe artefact, not a property of the wire. Under gdb,
the pty-req handler does store the network TERM on channel 1:
`SET attr=6038 len=64 cid=1 data=TTTT…` (`gdb-setter-cid.out`). The probe's
reader thread blocked in `cryptPopData`; a read timeout left the current read
channel deselected (`GET attr=6038 cid=0 readNo=-1`, `gdb-getter-cid.out`)
and the main thread's channel selects then failed `-25 TIMEOUT` followed by
`-43 NOTFOUND`. Holding the channel open (`wire-held-term64.out`) did not
help; feeding live client data so `cryptPopData` returns bytes instead of
timing out does. With that one change, a loopback OpenSSH 9.6 client's
64-byte TERM is read back by the vendored cryptlib getter with
`status=0 len=64`, and the pinned one-call copy into the 41-byte field
places chosen `0x54` bytes at `line_delay` (offset 44), `console` (48) and
`wordwrap[0..7]` (52): `wire13-datastream-term64.out`.

The same wire path compiled with ASan reports
`stack-buffer-overflow ... WRITE of size 64` in `memcpy` reached through
`attributeCopyParams -> getAttributeFunction -> sessionMessageFunction` from
the network-serving reader thread (`wire15-asan-term64.out`). A 40-byte TERM
leaves offsets 44..63 zero (`wire14-datastream-term40.out`), and the
`cb6d77dbca` fixed-form copy (length query then bounded copy) leaves byte 40
zero with no ASan report (`wire16-asan-fixed-term64.out`). That control
exercises only the patched copy form; other one-call copies remain inside a
1000-byte-padded session struct, so it is not a clean whole binary. One-command
`bash lab/frontier/synchronet2shell/wire/run-wire-proof.sh` gives
10 PASS / 0 FAIL; raw transcripts are `wire/evidence/proof-*.out`. The author
clean `git archive fe8cb5c lab/frontier/synchronet2shell` replay, with the
gitignored provisioned `src-tree/` symlinked in, reproduced the same 10/0.
That author replay was subsequently confirmed by the independent witness
replay below.

This closes the network pty-req gap at the real cryptlib API and the pinned
field layout. It is still not a real `sbbs3` build or a call into real
`sbbs_t::answer()`: the probe copies the pinned one-call statement itself.
No measured DoS, pointer/IP control or command; no rung 5.

## Witness verdict (witness wake 189, DM #3427, 2026-11-24)

Independent clean-room replay of W3 (`fe8cb5c`/`559d495`): `git archive fe8cb5c`
to `/tmp/w189-synchronet` with the live tree untouched; 8/8 `PINS.sha256` OK;
vendored cryptlib rebuilt from the git-clean pinned parent `42f586d7` (HEAD
exact, status clean, static-obj removed); independent `libcl.a` sha256
`584494acfcd7c531878fb951c848a97b8a9a84960f1ff477935303cae952e3c2`
byte-identical to the live prebuilt library. Unmodified `run-wire-proof.sh`:
rc 0, **PASS=10 FAIL=0**; all four clean proof outputs byte-identical to the
committed evidence after normalizing only path/PID/ASLR-address/BuildId tokens.

Verdict: **CLAIM ESTABLISHED AS LABELED** — rungs 1–3 plus rung 4 at the
labeled synthetic-struct scope; NO r5. Witness-observed loopback OpenSSH
TERM=64 -> `READER TERM status=0 len=64`, offsets 0/44/48/52,
`line_delay=0x54545454 console=0x54545454 wordwrap[0..7]=TTTTTTTT`; 40-byte
control leaves 44..63 zero; ASan `stack-buffer-overflow WRITE of size 64` in
`memcpy` via `attributeCopyParams -> getAttributeFunction ->
sessionMessageFunction -> cryptGetAttributeString -> reader_thread
ssh_server7.c:124`; fixed-form copy `status=0 len=64 byte40=00`, no ASan report.
A witness counterexample probe with TERM = 44x'A' + 'MISH' + 'E-OO' +
'TAUFTAUF' + 4x'Z' gave `line_delay=0x4853494d`, `console=0x4f4f2d45`,
`wordwrap[0..7]='TAUFTAUF'` — byte placement is wire-controlled, not an
artifact of repeated 0x54.

Scope caveats (witness NITs, wording only): the probe forces
`CRYPT_SSHOPTION_NONE_AUTH` (`ssh_server6.c:155-157`), so "unauthenticated"
remains the advisory claim, not measured at real `answer()`; the fixed-form
ASan-clean result exercises only the patched copy form — other one-call
copies remain inside a 1000-byte-padded struct, so it is not a clean whole
binary. The witness ceiling matches this report's: no real `sbbs3`, no
measured DoS, no pointer/IP or command, no r5.

## W5 real `sbbs3` build and real `answer()` call (2026-11-24, author-measured)

The W4 tooling negative was repaired locally, without host package changes:
Ubuntu noble `.deb` packages `zip`, `libarchive-dev`, `libnspr4-dev` and
`autoconf2.13` were fetched with `apt-get download` into
`lab/frontier/synchronet2shell/provision/debs/` and extracted into
`provision/local/`; the vendored mozjs build then succeeded and
`make -C src/sbbs3 FILE_LIBS="... -larchive -lnettle -lacl -llzma -lzstd
-llz4 -lbz2 -lz -lxml2"` linked the real `sbbs` binary from pinned parent
`42f586d7` (rc 0, `gcc.linux.x64.exe.debug/sbbs`). Two earlier negatives were
kept: `-j2` raced the mozjs header install (`jsversion.h: No such file or
directory`) and a parallel link produced a corrupt `libsbbs.so`. The replay
script builds jslib and sbbs3 serially.

The real server was bound only to `127.0.0.1:22222` with `SSH_ANYAUTH` so an
OpenSSH client could send pty-req without credentials. Without streamed client
data the real `answer()` failed with `-43` channel-not-found or an `exec`
channel, matching the W2/W3 probe negatives; with streamed stdin the loopback
pty-req reached the verbatim one-call copy inside real `sbbs_t::answer()`.
An instrumentation-only `lprintf` was added after that statement (the copy
itself is unchanged; patches in `real-answer/`). Observed with a 64-byte TERM
of 41×A + 3×B + `MISH` + `E-OO` + `TAUFTAUF` + 4×Z:
`sizeof=41 l=64 off41=42 off44=4853494d off48=4f4f2d45 off52=TAUFTAUF`; a
40-byte TERM gives `l=40 off41=00 off44=00000000 off48=00000000 off52=`.
The upstream `cb6d77dbca` fixed-form copy plus the same probe gives
`len=64 off40=00 off44=00000000 off48=00000000 off52=` for the 64-byte TERM.
This is chosen bytes at chosen offsets inside a real `sbbs_t` object, called
through a live loopback SSH server — rung 4 at the real-call scope. It is
author evidence; witness replay is still owed. No measured thread-block/DoS,
pointer/IP control, command execution or rung 5.

One-command replay: `bash
lab/frontier/synchronet2shell/real-answer/run-real-answer.sh`. It provisions a
pinned tree if absent, builds serially, drives both forms on loopback ports
22222/22223 and checks all three behavioral cases; transcripts are under
`real-answer/evidence/`. The author replay was run to completion: 4 PASS /
0 FAIL.

## W6 measured node-exhaustion impact (2026-11-24, author-measured)

Pinned `terminal.h:275` calls `SLEEP(sbbs->line_delay)` after each line feed;
`genwrap.h:343-350` turns that value into a `timespec` and `nanosleep`. The
W5 64-byte TERM sets `line_delay` to `0x4853494d` (1,213,040,461 ms, about
14 days), so the node thread parks after the copy.

`bash lab/frontier/synchronet2shell/real-answer/availability/run-availability.sh`
starts one loopback-only `sbbs` with nodes 1-4 on 127.0.0.1:22224, opens four
concurrent OpenSSH pty-req sessions with that TERM, then a fifth with a
40-byte control TERM. Vulnerable form: four `REAL_ANSWER_PROBE` lines with
`off44=4853494d`, four `sbbs/termNode` threads in `hrtimer_nanosleep`
(`vuln-threads.txt`), and the fifth connection logged
`!No nodes available for login.` at 09:34:42Z, 12 s after the last probe.
Upstream `cb6d77dbca` fixed form: four `REAL_FIXED_PROBE` lines with
`off44=00000000`, no parked node threads, no refusal, and the fifth
connection served (`Errors: 0`, five clients served). One-command replay:
6 PASS / 0 FAIL. Evidence sha256: `vuln-server.log`
`c73e6db2f42c533242aa6c04396dfb2c63aa9add25174354daafa6145e22a397`,
`vuln-threads.txt` `62eee568498eb354965bcc5fb04c55840a29eca608c5e20d3653d71c996c47aa`,
`fixed-server.log` `f4c5ee1b5834b925fbdf0002c03dda5ada7a85e970d752c2154834d0e3174fb2`.

A first run scored 5 PASS / 1 FAIL because `$SPID` tracked the wrapper shell
rather than the exec'd server and `gdb -p` is blocked by Yama ptrace_scope;
those transcripts are kept in `availability/evidence/negative/`, and the
probe now reads `/proc/<pid>/task/*/{comm,wchan,syscall}` after `exec`.
This demonstrates the advisory's availability impact in a real `sbbs3`
build with vulnerable/fixed controls; it is author evidence with replay
owed, and implies nothing about pointer/IP control or code execution.

## W7 default-config, no-credential negative (2026-11-24, author-measured)

`SSH_ANYAUTH` is a non-default option: pinned `main.cpp:6047-6050` sets
`CRYPT_SSHOPTION_NONE_AUTH` only under it, and `answer.cpp:270-295` takes a
separate no-credential activation path. To test the advisory's
"unauthenticated" wording at real `answer()`,
`bash lab/frontier/synchronet2shell/real-answer/noauth/run-noauth.sh` builds
the same vulnerable verbatim statement plus the instrumentation-only probe,
then runs the same binary on loopback port 22225 with `SSH_ANYAUTH` and on
22226 with that one token removed. Both cases use stock OpenSSH with
`PreferredAuthentications=none`, no password or key, and the W5/W6 64-byte
chosen TERM. The W5/W6 replay scripts are byte-unchanged.

The control logged one
`REAL_ANSWER_PROBE sizeof=41 l=64 off41=42 off44=4853494d off48=4f4f2d45
off52=TAUFTAUF`; the no-`SSH_ANYAUTH` server accepted the TCP connection,
attached node 1 and logged one `SESSINFO_ACTIVE`, but logged **zero** probes.
The client saw `lab@127.0.0.1: Permission denied (publickey,password).` and
the session failed before the TERM copy. Transcripts:
`real-answer/noauth/evidence/`.

This is a negative result, kept rather than retried away: with `SSH_ANYAUTH`
the W5/W6 measurements used no credentials, so no-credential reach is real
on that configuration. At a config without it, a stock OpenSSH client sends
pty-req only after authentication, so this probe does **not** refute the
advisory's unauthenticated claim for a custom client that sends pty-req
earlier, nor for other authentication configurations. Default-config remote
reach stays UNKNOWN; no rung change and no new witness replay request.

Author clean `git archive a209194 lab/frontier/synchronet2shell` replay with
the gitignored `src-tree/` and `provision/` symlinked in reproduced rc 0 and
the same counts (1 control probe, 0 no-ANYAUTH probes, one
`Permission denied (publickey,password)`).


## W8 source-bounded 64-byte TERM cap (2026-11-24, author-measured)

The charter called the 64-byte cap an advisory claim. It is now pinned in
source and corroborated on the wire. In the vendored cryptlib built from
pinned parent `42f586d7`, `session/ssh2_msgsvr.c:564` declares
`BYTE stringBuffer[ CRYPT_MAX_TEXTSIZE + 8 ]`, and the `REQUEST_PTY` case at
line 668 reads the pty-req TERM with
`readString32( stream, stringBuffer, CRYPT_MAX_TEXTSIZE, &stringLength )`;
`cryptlib.h:1821` sets `CRYPT_MAX_TEXTSIZE 64` (the separate
`MAX_ATTRIBUTE_SIZE 4096` at `misc/consts.h:250` is the getter's declared
return buffer, not this parser bound), and `enc_dec/misc_rw.c:332-334`
rejects `length > dataMaxLength` with `CRYPT_ERROR_BADDATA`, setting
`*dataLength = 0` — there is no truncation.
The call at line 668 is guarded by `if (stringLength > 0)` before
`setChannelAttributeS`, so an over-64-byte TERM never becomes a readable
terminal attribute. The 64-byte cap is therefore a property of this pinned
parser, not only of the advisory text.

`bash lab/frontier/synchronet2shell/termlen/run-termlen.sh` measures the
consequence on loopback port 22227 with the verbatim W3 server source changed
only in port (22222->22227) and getter-probe buffer (128->4096) by recorded
build-time `sed` (`evidence/provenance.txt`, including the witness-verified
libcl.a sha256 `584494acfcd7c531…e952e3c2`). OpenSSH 9.6 clients configured
with TERM lengths 40, 64, 65, 128 and 256 produced getter results
`status=0 len=40`, `status=0 len=64`, and `status=-43 len=-1`
(`CRYPT_ERROR_NOTFOUND`) for all three over-64 cases: **5 PASS / 0 FAIL**.
A `-vvv` client transcript (`term65-debug-client.out`) confirms that the
65-byte case still sent a pty-req (`channel 0: request pty-req confirm 1`,
`PTY allocation request accepted`); the exact on-wire TERM byte count was
not independently decoded, so client-side truncation cannot be excluded by
this measurement alone. The source bound does not depend on that ambiguity.

Consequence and limit: on this pinned pty-req path the no-size copy receives
at most 64 bytes, so the measured 23-byte reach past the 41-byte field is a
cap, not a lower bound. This bounds the availability-only characterization;
it says nothing about other attribute sources or other Synchronet builds.
No rung change; author evidence, not a witness verdict.

Author clean `git archive b14dafc lab/frontier/synchronet2shell` replay, with
the gitignored provisioned `src-tree/` symlinked in and the live tree
untouched, reproduced rc 0, 5 PASS / 0 FAIL, and all 13 evidence files
(getter transcripts, client logs, provenance and pass/fail counts)
byte-identical to the committed evidence. That is an author replay, not an
independent verdict.

## W9 custom-client pre-auth pty-req negative (2026-11-24, author-measured)

W7 left one wording gap: a stock OpenSSH client sends pty-req only after
authentication, so its no-`SSH_ANYAUTH` negative did not test a custom client
that sends pty-req earlier. `bash
lab/frontier/synchronet2shell/real-answer/noauth/run-preauth.sh` closes that
gap on the same real `sbbs3` binary and verbatim `sbbs_t::answer()` copy
probe. It drives a scripted paramiko 5.1.0 client (installed into the
gitignored `provision/local-py`) over loopback only, with the pinned tree at
parent `42f586d7` and the same 64-byte chosen TERM as W5/W6.

The client sends `SSH_MSG_SERVICE_REQUEST` first, then `SSH_MSG_CHANNEL_OPEN`
and a pty-req carrying the 64-byte TERM, with **no** authentication request.
Two earlier client-side artefacts were observed and preserved rather than
retried away: without a service request cryptlib answers `Invalid handshake
packet SSH_MSG_CHANNEL_OPEN (90), expected SSH_MSG_SERVICE_REQUEST (5)`; with
a service request but paramiko's RFC-shaped 24-byte channel-open it answers
`Invalid length 24 for SSH_MSG_CHANNEL_OPEN (90) packet, should be
26...16384`. The recorded run appends two bytes to that one channel-open
packet so the parser reaches the state-machine check; the same accommodation
is used in both configurations and is not part of the claim.

On port 22228 without `SSH_ANYAUTH`, the server then logs `Invalid handshake
packet SSH_MSG_CHANNEL_OPEN (90), expected SSH_MSG_USERAUTH_REQUEST (50)`
while activating the session, the client reports `Unable to open channel`,
and **zero** `REAL_ANSWER_PROBE` lines are logged: the pinned SSH auth-phase
state machine refuses channel establishment until a userauth request arrives,
so a pre-auth pty-req cannot set the terminal attribute on this build.
Positive control on port 22229 with `SSH_ANYAUTH` and the ordinary none-auth
request before channel-open reaches the copy with the same client and TERM:
one `REAL_ANSWER_PROBE sizeof=41 l=64 off41=42 off44=4853494d
off48=4f4f2d45 off52=TAUFTAUF`.

This resolves W7's custom-client unknown as a **negative for this pinned
build/config**: the only measured no-credential route to the copy remains
the `none` authentication accepted under `SSH_ANYAUTH`. Other builds or
configurations with valid credentials, and other attribute sources, stay
UNKNOWN. No rung change and no rung 5 inference. Author evidence with a
one-command replay, not a witness verdict.

`run-preauth.sh` reports **9 PASS / 0 FAIL** with `PREAUTH_PROBE_COUNT=0`
and `ANYAUTH_PROBE_COUNT=1`; transcripts are
`real-answer/noauth/evidence-preauth/{server-noauth,server-anyauth,
client-preauth,client-positive}.log`.

Author clean `git archive 60df1168 lab/frontier/synchronet2shell` replay,
with the gitignored `src-tree/` and `provision/` symlinked in and the live
tree untouched, reproduced rc 0, 9 PASS / 0 FAIL and the same two probe
counts. This is an author replay, not an independent verdict.


## W10 pinned-source ceiling: one 64-byte TERM setter, no control-flow target (2026-11-24, author source audit)

A read-only audit of the gitignored pinned tree at parent `42f586d7` closes the
"other attribute sources" limit left in W8/W9 and the charter's control-flow
question, without a new build or probe. Every cited line was re-read in the
pinned tree:

- The pinned cryptlib has only `CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL`
  (`3rdp/src/cl/cryptlib.h:1285`); there is no `CRYPT_SESSINFO_TERMINAL` in
  the active headers or sources. Its sole remotely reachable setter is the
  SSH pty-req handler: `session/ssh2_msgsvr.c:533` maps `"pty-req"` to
  `REQUEST_PTY`, and `:668-670` reads `readString32(stream, stringBuffer,
  CRYPT_MAX_TEXTSIZE /* 64 */, &stringLength)` then calls
  `setChannelAttributeS(...)` only when `stringLength > 0`. SSH `env` is a
  `REQUEST_NOOP` at `:543`; telnet and rlogin TERM handling never sets the
  attribute (`src/sbbs3/main.cpp:1793-1794`, `answer.cpp:145-151`,
  `answer.cpp:590-591`).
- Local/generic sets are capped too: `session/ssh2_channel.c:723-727` passes
  `CRYPT_MAX_TEXTSIZE` as the destination bound to `attributeCopyParams`,
  which rejects `sourceLength > destMaxLength` at
  `3rdp/src/cl/misc/int_api.c:328-330`; the attribute ACL range is
  `1..CRYPT_MAX_TEXTSIZE` (`kernel/attr_acl.c:3693-3704`). The asymmetry is
  in the GET: `cryptapi.c:2599-2603` advertises `MAX_ATTRIBUTE_SIZE` (4096)
  capacity and overwrites the caller's `*valueLength`, while
  `answer.cpp:542-547` supplies a 41-byte array with `l = 0`.
- No control-flow target lies in the reachable 23 bytes. `src/sbbs3/sbbs.h:485`
  declares `class sbbs_t` with no `virtual` member anywhere in that header;
  `:702-705` places `terminal[41]`, `line_delay`, `console` and
  `wordwrap[1001]` at offsets 0/44/48/52. Bytes 44..63 are two `uint32`
  scalars and `wordwrap[0..11]`. Consumers use them as a delay
  (`terminal.h:275-276`, measured in W6), `CON_*` flag bits, and string data;
  the only pointer exposures are data pointers for Baja (`exec.cpp:96`
  `(char*)wordwrap` and `:241` `(int32_t*)&console`). No function pointer,
  vtable entry or computed call target.

This is a structural source result, not a new wire or probe measurement and
not a witness verdict. It keeps the rung and availability ceiling unchanged:
inside this pinned build, "other attribute sources" is now a bounded negative
rather than UNKNOWN, while other builds, versions and configurations remain
UNKNOWN. No RCE inference.

## W11 exact client TERM length: W8 truncation residual closed (2026-11-24, author-measured)

W8 preserved one explicit residual: the OpenSSH `-vvv` transcript showed a
pty-req for the 65-byte TERM but the exact on-wire TERM byte count was not
decoded, so client-side truncation could not be excluded by that wire alone.
W11 closes that residual with a client whose pty-req construction is visible.
`termlen/term_client.py` uses paramiko 5.1.0 against the same W8 verbatim
`wire/ssh_server6.c` server (port 22227; only the port and getter buffer
changed by the recorded build-time `sed`). The provisioned
`paramiko/channel.py:188-200` builds the request with `m.add_string(term)` and
no length cap. A hook on `Transport._send_user_message` reads the message
bytes at the exact point they are handed to transport encryption, parses the
`pty-req` TERM string and logs its length; it does not alter the message.

`bash lab/frontier/synchronet2shell/termlen/run-clientlen.sh` ran TERM=64,
65 and 128 on loopback: **6 PASS / 0 FAIL** at 18:26Z. Client logs record
`CLIENT WIRE_PTYREQ term_len=64`, `term_len=65` and `term_len=128` (each with
`head=b'TTTTTTTT'`) followed by `PASS exact wire TERM length N`; the W8 server
logged `READER TERM status=0 len=64 data=TTTT…` for 64 and only
`READER TERM status=-43 len=-1` (`CRYPT_ERROR_NOTFOUND`, no attribute stored)
for 65 and 128. Evidence: `termlen/evidence/clientlen/{term64,term65,term128}{.out,-client.log}`,
`provenance.txt` and `results.txt`. The 64-byte client hits `Socket is closed`
after the getter because that probe server exits once it has copied the TERM;
the pty-req and getter result were already recorded.

This excludes client-side truncation before encryption at the measured client
boundary. It is not a decrypted ciphertext capture: the server's differential
getter result (64 readable, 65/128 not stored) is the independent counterpart,
and the parser cap remains pinned in `session/ssh2_msgsvr.c:661-670` and
`enc_dec/misc_rw.c:332-334`. No new rung, no real `answer()` call here, no
witness verdict; other builds and clients stay UNKNOWN.

The first clean-archive replay (commit `a0050050`, 18:29Z) scored
**5 PASS / 1 FAIL**: the 128-byte client timed out because the fresh server
logged `ACTIVE attempt=0 status=-41` (`CRYPT_ERROR_READ`) and never opened a
channel, while 64 and 65 passed. The transcripts are preserved in
`termlen/evidence/clientlen/negative-replay-a0050050/`, together with the
diagnosis: the script killed the previous server and started the next one
without waiting for the port to settle. `run-clientlen.sh` now waits for
127.0.0.1:22227 to be free before each case and for the new server to listen
before connecting. The live rerun after that repair is 6 PASS / 0 FAIL; this
is a tooling repair, not a change to the TERM-bound claim.

Author clean `git archive ce0a0208 lab/frontier/synchronet2shell` replay at
18:31Z, with the gitignored `src-tree/` and `provision/` symlinked in and the
live tree untouched, reproduced rc 0 and **6 PASS / 0 FAIL**. Raw
`results.txt` and `provenance.txt` are byte-identical; the six case transcripts
differ only in client-relative timestamps and in the timing/line order of the
thread-scheduled `CHANNEL TYPE` lines, and all six normalized digests match
(`termlen/evidence/clientlen/REPLAY.md`). This is an author replay, not a
witness verdict.

## W15 valid credentials under the default config (2026-11-25, author-measured)

W7/W9 left "default-config reach with valid credentials" UNKNOWN because the
pinned tree had no BBS user database. That prerequisite was not structural:
the pinned tree carries `src/sbbs3/gcc.linux.x64.exe.debug/makeuser`, which
creates `data/user/user.tab` offline from the existing ctrl config; passwords
are stored cleartext and uppercased (`makeuser.c:174-177`, `answer.cpp:353`
`stricmp`). The utility resolves `data_dir` under `ctrl/`, so the lab adds a
`ctrl/data -> ../data` symlink. The created user `lab` has `LABPASS123` in its
1000-byte record.

`bash lab/frontier/synchronet2shell/real-answer/validuser/run-validuser.sh`
builds the same verbatim vulnerable statement plus instrumentation-only probe
used in W5/W7/W9, starts a real `sbbs3` on loopback 22229 with
`Options = XTRN_MINIMIZED | ALLOW_SSH | NO_TELNET | NO_HOST_LOOKUP | NO_EVENTS`
(no `SSH_ANYAUTH`), and connects with stock OpenSSH using `sshpass` and
`PreferredAuthentications=password`. Both sessions logged
`SSH login: 'lab'` and `SSH password authentication successful`; the server
log has zero `SSH_ANYAUTH` lines. Result: **4 PASS / 0 FAIL** at
2026-11-25T00:58Z: chosen 64-byte TERM `sizeof=41 l=64 off41=42
off44=4853494d off48=4f4f2d45 off52=TAUFTAUF`; the 40-byte control logged
`l=40` with zero adjacent bytes. Raw logs:
`real-answer/validuser/evidence/{server.log,client-chosen64.log,client-control40.log}`.

This closes the valid-credential/default-config UNKNOWN for this pinned build:
the overflow is reachable after ordinary password login, not only with the
non-default `SSH_ANYAUTH` token. It does **not** re-establish the advisory's
unauthenticated reach: pre-auth pty-req remains the W9 negative, and the
no-credential positive remains W7's `SSH_ANYAUTH` configuration. No grade
change (rungs 1-4), no pointer/IP/command, no r5, no witness verdict.

Author clean `git archive e0f11cd4 lab/frontier/synchronet2shell` replay at
01:01Z, with the gitignored `src-tree/` and `provision/` symlinked in, scored
**4 PASS / 0 FAIL**, rc 0, `PROBE_COUNT=2`, `ANYAUTH_LOG_COUNT=0`. The two
client logs are byte-identical to the author run; the server's login,
password-success and both probe lines are identical after removing only the
volatile timestamp prefix (same node numbers, socket numbers and hexdumps).
This is an author replay, not a witness verdict.



## W16 default-config node exhaustion with valid credentials (2026-11-25, author-measured)

W15 established that a valid password login reaches the copy without
`SSH_ANYAUTH`; W6's measured node-exhaustion impact still used that non-default
token. `lab/frontier/synchronet2shell/real-answer/validuser/
run-validuser-availability.sh` combines the W15 config and `sshpass` login with
the W6 four-client burst: four chosen 64-byte TERMs set `line_delay` to
`0x4853494d` (~14-day nanosleep) on a real pinned-parent `sbbs3`, then a fifth
client sends a clean 40-byte TERM. Upstream `cb6d77dbca` fixed form is the
control. Result at 2026-11-25T01:27Z: **10 PASS / 0 FAIL**, rc 0.

Vulnerable form: four `REAL_ANSWER_PROBE sizeof=41 l=64 off41=42
off44=4853494d off48=4f4f2d45 off52=TAUFTAUF` lines and four
`SSH login: 'lab'` lines on nodes 1–4; four `sbbs/termNode hrtimer_nanosleep`
threads in `/proc`; the fifth session got `!No nodes available for login.`
Fixed form: four `REAL_FIXED_PROBE sizeof=41 len=64 off40=00 off44=00000000
off48=00000000` lines, five `Attaching to Node` lines, five password
successes, no refusal. Both server logs have zero `SSH_ANYAUTH` lines. Raw
transcripts and thread snapshots: `real-answer/validuser/
availability-evidence/`; replay recipe `REPLAY-W16.md`.

Two pre-repair negatives are kept rather than erased: the first driver run
scored 9 PASS / 1 FAIL because an assertion looked for a server-side login
message in client logs (the server log had four such lines); the second scored
2 PASS / 8 FAIL because port 22230 was still in TIME_WAIT, so Synchronet
printed `SSH Server listening` before `!ERROR 98 binding SSH Server socket`
and retried 15 s late, letting only the 40-byte control through. The driver
now tests real bindability and waits for the four node threads before
starting the burst. Neither failure was target behavior.

This closes the measured availability gap under the pinned default config
with valid credentials for this one offline-provisioned user and build. Grade
unchanged (rungs 1–4): chosen field bytes and a thread-park/node-exhaustion
effect, with a fixed control; no pointer/IP control, command or r5. Author
evidence, not a witness verdict; no claim about other builds, configs or
credentials.

## Ceiling and cheapest next experiment

Not measured: pointer/IP control, command execution, rung 5, independent
replay of W5/W6/W8/W9/W15/W16. No-credential TERM reach at a config without
`SSH_ANYAUTH` is now a measured negative for this pinned build (W7 stock
client and W9 custom pre-auth client), not an open gap inside this build;
the complementary valid-credential default-config reach is a measured positive
in W15 for one provisioned user in this pinned build, and W16 measures its
node-exhaustion impact with a fixed control. Other builds,
configurations and credentials stay UNKNOWN. Inside
this pinned build W10 also closes the "other attribute sources" wording:
the pty-req handler is the only remote terminal setter and every setter path
is capped at 64 bytes; offsets 44..63 hold scalar timing/flag data and string
bytes, with no function pointer, vtable entry or computed call target. Those
are source bounds, not a new probe measurement; other builds stay UNKNOWN.
The advisory's claimed thread-block/socket-exhaustion DoS is measured at real
`answer()` scope in W6 (SSH_ANYAUTH) and W16 (default config, valid password)
with a fixed control. The 64-byte TERM and the no-size
copy are measured at the real cryptlib API, from a network pty-req through the
real vendored cryptlib getter, inside a real `sbbs3` build's
`sbbs_t::answer()` on loopback; W8 pins the 64-byte maximum to the vendored
pty-req parser and corroborates it on the wire, and W11 measures the client's
exact pty-req TERM length to close W8's client-truncation residual. No claim
that the adjacent-field overwrite yields code execution: the advisory's own impact
vector is availability-only (`VC:N/VI:N`). W5, W6, W15 and W16 are author evidence with
one-command replays, not yet independently replayed.


`gdb.txt` (sha256 `968fa2093607c70425343fe569fe91ee7bc467d7077dc52ff4914cd24691f128`)
is a batch gdb transcript of the same plain vulnerable binary at the statement
after the copy: `&s.terminal=0x…dd20`, `&s.line_delay=…dd4c` (offset 44),
`&s.console=…dd50` (48), `&s.wordwrap=…dd54` (52), with `4d 49 53 48` at
offsets 44..47, `45 2d 4f 4f` at 48..51 and `54 41 55 46` twice at 52..59.

`REPLAY.md` records an author clean `git archive e5f43ad` replay: 9 PASS /
0 FAIL, normalized trace `66d20f8…414bdd8` identical to the author tree. Raw
hashes differ only in PIDs, ASLR addresses, timestamps, checkout paths and
build ids. The verbatim-statement harness is covered by the witness verdict
section above.

The former next step — build `sbbs3` from the pinned tree and drive the
oversized TERM through real `answer()` — is complete in W5, and W6 measures
the resulting node exhaustion. The cheapest remaining evidence-producing
step is independent witness replay of `real-answer/run-real-answer.sh` and
`real-answer/availability/run-availability.sh`; the stand-alone wire probe
remains author evidence about a standalone probe (independently replayed in
W4) and is not a real `answer()` call.

W4 bounded build-feasibility probe (negative, no source edit, no host package
change): a direct `g++ -fsyntax-only` of `src/sbbs3/answer.cpp` at parent
`42f586d7` with the tree's vendored win32 headers fails because `jscpucfg.h`
is "supposed to be auto-generated on UNIX platforms" and the mozjs headers use
MSVC-only `__int8`/`__int16`/`__int32`/`__int64`; the win32 header set cannot
stand in for a UNIX build. Then `make -C src/sbbs3 -j2` fails in the vendored
mozjs configure step: `autoconf-2.13`/`autoconf2.13 not found` (ignored), then
`configure: error: zip not found in $PATH` and
`make: *** [.../Common.gmake:780: js] Error 2`. The real-build lane is therefore
blocked on local provisioning of `zip`, autoconf-2.13 and UNIX libarchive/NSPR
headers before any real `answer()` call. This is a tooling negative, not a
claim about the vulnerability; the witness-established rungs above are
unchanged.
