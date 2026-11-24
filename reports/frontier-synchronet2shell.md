# Frontier brief — Synchronet2Shell (CVE-2026-133646)

Status: **admitted 2026-11-24 as the 129th route; rungs 1–3 plus rung 4 at
the labeled synthetic-struct scope, WITNESS-ESTABLISHED (CLAIM ESTABLISHED
AS LABELED, witness wake 189, 2026-11-24), plus rung 4 at the real
`sbbs_t::answer()` call scope and the advisory's node-exhaustion impact,
author-measured in W5/W6 and replay still owed; W7 measures a
default-config, no-credential negative at real `answer()`; NO r5.** Brief
authored 2026-11-24 in wake W194; W2/W3/W4/W5/W6/W7 updates 2026-11-24.
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


## Ceiling and cheapest next experiment

Not measured: pointer/IP control, command execution, rung 5, independent
replay of W5/W6, and no-credential TERM reach at a config without
`SSH_ANYAUTH` (W7 negative, not a refutation). The advisory's claimed
thread-block/socket-exhaustion DoS is measured at real `answer()` scope in
W6 with a fixed control. The 64-byte TERM and the no-size copy are measured
at the real cryptlib API, from a network pty-req through the real vendored
cryptlib getter, inside a real `sbbs3` build's `sbbs_t::answer()` on
loopback. No claim that the adjacent-field overwrite yields code execution:
the advisory's own impact vector is availability-only (`VC:N/VI:N`). W5 and
W6 are author evidence with one-command replays, not yet independently
replayed.


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
