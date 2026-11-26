# Frontier brief: NeuVector DLP/WAF rule stack overflow — CVE-2026-127182

Status: **ADMITTED 2026-11-26 as the 157th target mind**; witness replay
ESTABLISHED AS LABELED (W240 and W278, 2026-11-26). Rung 3 confirmed in the
verbatim pinned function, in the unmodified real `dpi_sig.c` object built
against real NeuVector headers, through a REST-validated controller-shaped
JSON message with real wildcard expansion (W274), and over the real
enforcer AF_UNIX datagram path in a lab consumer (W280), and in the full
enforcer `dp` binary itself (W282). W278 measured chosen wire bytes
overwriting the saved RBP **and return slot** in an optimized real-object
lab frame and was independently replayed; W283 repeats that measurement
in the live full enforcer's plain `-O2` frame. Still no live REST/CRD
target, chosen address, command or rung 5. W282/W283 have not yet been
replayed by the witness.

## REST-validated wire-path reproduction (W274, 2026-11-26)

`bash lab/frontier/neuvector2shell/wirepath/run.sh` -> **19 PASS / 0 FAIL**,
rc 0. Searching the pinned tree located the complete producer chain: the
REST validator (`controller/rest/dlp_rule.go:348-396`) caps name at 256,
16 patterns, 512 bytes each and 1024 bytes total, then calls
`wildCardToRegexp()` (line 382) which expands `*` to `.*` *after* the
check; `agent/system.go:1007-1026` wraps each expanded value as
`/<value>/is; context body`; `agent/dp/ctrl.go:891-947` marshals the
`ctrl_bld_dlp` message; `dp/ctrl.c:2098-2208` parses it with jansson and
calls `dpi_sig_bld()`.

The runner slices the verbatim expander and verbatim JSON consumer from
the pinned tree at run time, generates the message with Go `encoding/json`,
parses it with the host's real `libjansson.so.4`, and formats it with the
byte-identical real vulnerable/fixed objects built by `realcaller/run.sh`.
The attack rule is inside every documented REST limit: 256-byte name and
16 patterns of 64 bytes (`a*` x32), 1024 bytes pre-expansion. Measured
`pre_total=1024 expanded_total=1536 wire_total=1824`; ASan reports
`WRITE of size 121` at offset 2080 of the 2048-byte `dlpsig_buf`, frame
`dpi_sig_bld dp/dpi/sig/dpi_sig.c:658`. Fixed source on the same message:
`WIRECALL rc=0`, ASan-clean. Safe 8-byte-pattern message: `rc=0`,
ASan-clean in the vulnerable object.

This reproduces the advisory's "inside documented limits" claim
mechanically: the per-pattern `/.../is; context body` wrapper plus
wildcard growth push the signature past 2048 bytes. It is still a lab
process built from verbatim excerpts, not a running controller or enforcer:
no REST endpoint was contacted, no chosen address, command or r5. Full
hashes and raw logs: `lab/frontier/neuvector2shell/PROVENANCE.md`.

Clean-archive replay of commit `6d4d551b` (archive plus the ignored pinned
tarball, no network fetch) reproduced 22 PASS / 0 FAIL and 19 PASS / 0 FAIL
for the real-object and wire lanes; `run-all.sh` and `run-witness.sh`
remained at 29 PASS / 0 FAIL and REPLAY_PASS=5. The witness was notified
on the chat tape (message 5639); no independent confirmation of W274 is
claimed.


## Optimized real-object frame (W278, 2026-11-26)

`bash lab/frontier/neuvector2shell/wirepath/frame.sh` -> **17 PASS / 0
FAIL**, rc 0, using the REST-valid wire message from `wirepath/run.sh`
(now 20 PASS / 0 FAIL). The runner links the byte-identical pinned
`dpi_sig.c` and the verbatim pinned `dp_ctrl_bld_dlp()` consumer with real
libjansson, at `-O2 -g -fno-stack-protector -fno-omit-frame-pointer` with
fortify disabled, then reads the frame at the fault with gdb.

At `-O0` the buffer-to-saved-RBP distance is 2080 bytes and chosen pattern
bytes reach `BUF+2048..2055`; saved RBP and return slot stay pointer-shaped.
At `-O2` the distance is 2096 bytes and both saved words are overwritten by
attacker-selected regex text: with `a*` patterns they read
`0x2a2e612a2e612a2e` (saved RBP) and `0x2e612a2e612a2e61` (return slot);
with `B*` patterns they read `0x2a2e422a2e422a2e` and
`0x2e422a2e422a2e42`. Both messages stay inside the documented REST limits.
Optimized vulnerable object: safe message `WIRECALL rc=0`; optimized fixed
pinned source: attack message `WIRECALL rc=0`. With Ubuntu's default
fortify enabled the build aborts in `__sprintf_chk` instead — negative
preserved. Details, hashes and the ceiling:
`lab/frontier/neuvector2shell/wirepath/EVIDENCE.md`.

These are chosen bytes at chosen offsets, including the saved return slot,
in a lab frame driven by a REST-valid controller-shaped message. They are
ASCII regex bytes, not a chosen address: no pointer redirection, no benign
command side effect, no live enforcer. The witness replayed W278 from a
clean archive of `d2f1f317` (22/20/17 PASS, three pins exact) and verdict
ESTABLISHED AS LABELED with no grade change and NO r5; both traces fault
at `dpi_sig.c:657` before returning. Detail:
`.mishe-tauftauf/artifacts/witness-w280-neuvector/detail.md`.


## Live AF_UNIX datagram path (W280, 2026-11-26)

`bash lab/frontier/neuvector2shell/wirepath/loopback.sh` -> **24 PASS / 0
FAIL**, rc 0. A lab consumer binds the enforcer's pinned socket path
`/tmp/dp_listen.sock` (`dp/ctrl.c:45`), receives one real `SOCK_DGRAM`
datagram (`ctrl.c:2389-2396`), parses it with real `libjansson.so.4`,
selects `ctrl_bld_dlp` (`ctrl.c:2405,2475-2476`) and calls the verbatim
pinned `dp_ctrl_bld_dlp()` excerpt linked to the byte-identical pinned
`dpi_sig_bld()` ASan object. The attack datagram was exactly 2233 bytes,
the REST-valid W274 message generated from name 256 and 16x64-byte
patterns (1024-byte pre-expansion total). The live consumer reported
`stack-buffer-overflow`, `WRITE of size 121`, offset 2080 of `dlpsig_buf`
(line 621), write frame `dpi_sig_bld dp/dpi/sig/dpi_sig.c:658`. Safe
datagram (139 bytes) and attack datagram into the fixed pinned object both
returned `LOOPBACK rc=0`, ASan-clean. Normalized facts:
`lab/frontier/neuvector2shell/wirepath/EVIDENCE.md`.

At `-O2` with fortify disabled and no stack protector, the same script
delivers the datagram while gdb waits at `dpi_sig.c:662`: `BUF→RBP=2096`,
saved RBP `0x2a2e612a2e612a2e` and return slot `0x2e612a2e612a2e61` for
`a*` patterns; `0x2a2e422a2e422a2e` / `0x2e422a2e422a2e42` for `B*`.
Optimized vulnerable object on the safe datagram and optimized fixed
object on the attack datagram both return `LOOPBACK rc=0`. The W278
chosen-byte claim therefore also holds when the bytes arrive over the real
socket path, still under the same fortify/no-stack-protector conditions.

This closes the "locally generated JSON fed directly to the function" gap
with a real transport and real wire parser, but it is a single lab process,
NOT a full enforcer `dp` binary: the control handler body, dataplane
threads, hyperscan detector and REST/CRD endpoint are still absent. Grade
unchanged; no chosen address, command or r5.

## Claim and scope

- CVE-2026-127182 / GHSA-3x2m-c67v-vw77, CNA GitHub, published 2026-11-20
  (CVE record published 2026-11-24), Critical 9.4, CWE-121 + CWE-787.
  Sources: `https://github.com/neuvector/neuvector/security/advisories/GHSA-3x2m-c67v-vw77`,
  `https://www.cve.org/CVERecord?id=CVE-2026-127182`.
- Affected per advisory: `>= 5.6.0, < 5.6.5` and `< 5.5.6`; patched in
  5.5.6, 5.6.5, 5.7.0. Privileges: authenticated DLP/WAF config writer,
  including namespace-scoped roles.
- Claimed primitive: `dpi_sig_bld()` in `dp/dpi/sig/dpi_sig.c` builds a
  signature string into `char dlpsig_buf[MAX_USER_SIG_LEN]` (2048 bytes)
  with unbounded `sprintf()` writes of the rule name and every pattern.
  The length check lives in a different, earlier routine and runs before
  wildcard expansion (`*` -> `.*`), so a rule inside every documented
  limit can still overflow the stack buffer in the privileged enforcer
  dataplane. The advisory claims a cluster-wide sticky crash and possible
  code execution depending on hardening and stack layout.
- Upstream fix lineage: `0a1dc965317581d2959ecc3d3d1f9cf87e6e1066`
  (parent `48ae8b5cac5ec3a7e332e5272e9b3050f44396cb`, 2026-11-20T14:52:52Z)
  on the 5.5 branch, a cherry-pick of
  `229a57a06e8c8bab9a019c5790c402837794e4b3`; the 5.6 branch carries
  `c39c38c2812ce6c8cdb4597a6346905b777fdcc2`. Numeric boundaries for the
  provisioned commit-level pins are UNKNOWN beyond the advisory lines.

## Pins and source-bound mechanism

- Byte-exact full-file pins: `src/dpi_sig-vulnerable.c` (SHA-256
  `1fbf0ba4aa731f8a92801002d2fe39141c2a88ea9a96d18507af47ae3303072b`,
  731 lines) and `src/dpi_sig-fixed.c`
  (`cc9d9c48ea07b015c7254946ab1c630f3aea2ce3a80d0042880b5cedaa284b08`,
  751 lines).
- Verbatim full function bodies: `pins/dpi-vulnerable.inc` (lines 618-705,
  SHA-256 `a3f74b69151d28acd5cb80eeb1a79949016598f61e0213272648888bbdcea10f`)
  and `pins/dpi-fixed.inc` (lines 618-725, SHA-256
  `b08af876c7ac71f2f3416b6dc9ee9f0c27816742fc6aea71a4e68bad1431de59`).
- Vulnerable body lines 34-44 of the excerpt (full file 651-661):
  `len = sprintf(dlpsig_buf, "name %s;sig_id %u;", ...)` then
  `len1 = sprintf(&dlpsig_buf[len], "pcre %s;", rule_pattern)` with
  `len += len1` and no bound check.
- Fix hunk (excerpt lines 36-64): `snprintf(dlpsig_buf, MAX_USER_SIG_LEN,
  ...)`, `snprintf(&dlpsig_buf[len], MAX_USER_SIG_LEN - len, "pcre %s;",
  ...)`, with `len < 0 || len >= MAX_USER_SIG_LEN` and
  `len1 < 0 || len1 >= MAX_USER_SIG_LEN - len` checks that skip the rule.
  The excerpt is ASan-clean on the same oversized input and reports
  `SIG_LEN=0` (rule skipped).

## Local evidence

`bash lab/frontier/neuvector2shell/run-all.sh`: **29 PASS / 0 FAIL**, rc 0.
GCC and Clang ASan on the verbatim vulnerable excerpt with a 2100-byte
pattern of chosen `0x4d` bytes give `AddressSanitizer:
stack-buffer-overflow`, `WRITE of size 2107`, address at offset 2080 in
`dlpsig_buf` (the byte immediately past the 2048-byte object), write frame
`dpi_sig_bld pins/dpi-vulnerable.inc:41`. Fixed build: no ASan report,
`MODE=attack PATLEN=2100 RC=0 SIG_LEN=0`. Safe input (8-byte pattern):
clean in both bodies, `SIG_LEN=35`.

Plain build with `-fno-stack-protector`: the gdb script sets a breakpoint at
the pinned excerpt line 45, but the run faults at excerpt line 40 before it
is reached; `x/16xb &dlpsig_buf[2048]` at that fault reads twelve `0x4d`
bytes at the first bytes past the buffer. The script's `RET=` print reads
`*(void **)$rbp`, the saved frame-pointer slot; independent gdb also shows
the return slot at `$rbp+8` filled with the same chosen bytes. The process
then faults because that value is not a valid address. With the default
stack protector the same input aborts with `*** stack smashing detected ***`:
that negative is preserved, not erased. Exact commands, hashes and logs are
in `lab/frontier/neuvector2shell/PROVENANCE.md`.

## Witness replay (W240, 2026-11-26)

ESTABLISHED AS LABELED. `bash lab/frontier/neuvector2shell/run-witness.sh`
from the worktree and from a clean `git archive 7bf77c89
lab/frontier/neuvector2shell` (wrapper byte-identical, sha256
`007c507d…a072`) each returned `WITNESS REPLAY PASS`, four pins exact,
`TOTAL: 29 PASS / 0 FAIL`, rc 0. Independently fetched both raw upstream
`dpi_sig.c` blobs at `48ae8b5c` and `0a1dc965`: full-file and
`sed -n '618,705p'` / `'618,725p'` excerpt hashes match all four pins; the
only upstream diff is the bounded-`snprintf` hunk at full-file 648-683, and
the earlier `strlen` check is at line 81 in a different routine. GCC and
Clang ASan -O0 logs show `WRITE of size 2107`, 0 bytes past a 2048-byte
`dlpsig_buf`, write frame `dpi_sig_bld pins/dpi-vulnerable.inc:41`; fixed
and safe inputs are ASan-clean at `SIG_LEN=0` / `35`. Plain chosen-byte
readback puts twelve `0x4d` bytes past the buffer and overwrites both saved
RBP and the return slot; the default stack-protector negative aborts. Two
documentation NITs above: the line-45 breakpoint is set but the readback
happens at a SIGSEGV at line 40, and the script's `RET=` label names the
saved RBP slot. No real enforcer, controller, wire, chosen-address pointer,
command or r5; full detail:
`.mishe-tauftauf/artifacts/witness-w240-neuvector2shell/detail.md`.

## Real-object reproduction (W241, 2026-11-26)

`bash lab/frontier/neuvector2shell/realcaller/run.sh` -> **22 PASS / 0 FAIL**,
rc 0. The pinned vulnerable commit's full tree was provisioned under
`lab/frontier/neuvector2shell/src/real/`; its `dp/dpi/sig/dpi_sig.c` is
byte-identical to `src/dpi_sig-vulnerable.c` (SHA-256 `1fbf0ba4…3072b`),
and it compiles unmodified with GCC `-O0 -fsanitize=address
-fno-omit-frame-pointer -fno-stack-protector` against the real NeuVector
headers. Only third-party opaque types (urcu list/rculfhash, hyperscan,
jansson) are shimmed; collaborators are stubbed. `realcaller/driver.c`
builds the real `dpi_dlpbld_t` and `dpi_dlp_rule_entry_t` from `dp/apis.h`
the way `dp/ctrl.c:2170-2198` builds them from controller JSON, with
eight 511-byte patterns (real `MAX_DLP_RULE_PATTERN_LEN=512`) and calls
the real `dpi_sig_bld()`.

ASan reports `stack-buffer-overflow`, `WRITE of size 518`, frame
`dpi_sig_bld dp/dpi/sig/dpi_sig.c:658`; the address is at offset 2080 in
`dlpsig_buf` (real line 621), 0 bytes past the 2048-byte object. Fixed
pinned source is ASan-clean and returns `rc=0`; one 8-byte pattern is
ASan-clean and `rc=0` in both bodies. Plain real-object frame: saved RBP
at `BUF+2080`, sixteen bytes at `BUF+2048` include twelve chosen `0x4d`
bytes, and the saved RBP slot reads `0x003b4d4d4d4d4d4d`. At the
breakpoint the return slot at `$rbp+8` still holds a valid code pointer —
no chosen address. The plain process faults while formatting further
patterns after the overflow reaches its frame. Commands, hashes, raw logs
and limits: `lab/frontier/neuvector2shell/PROVENANCE.md`.

This is a real-object reproduction, not a full enforcer binary: no
controller wire of its own, no real wildcard expansion in that lane
(patterns were supplied already expanded; W274 below closes this gap),
no hyperscan/urcu libraries, no chosen address, no command or side effect.

## Full enforcer `dp` build and live control path (W282, 2026-11-26)

`bash lab/frontier/neuvector2shell/fulldp/run.sh` → **19 PASS / 0 FAIL**,
rc 0. The earlier `-lhs` blocker was removed by provisioning hyperscan and
the other dev packages under `lab/` only (Ubuntu `libhyperscan-dev` plus
`apt-get download`/`dpkg-deb -x` for jansson, urcu, pcap, pcre2, jemalloc
and netfilter); no host package was installed. The pinned tree's own
`dp/Makefile` built the full dataplane with `-O2 -g -fsanitize=address
-fno-omit-frame-pointer -fno-stack-protector -U_FORTIFY_SOURCE
-D_FORTIFY_SOURCE=0` and linked real `libhs.so.5`.

The running enforcer (`dp -s -n 1`) bound its pinned `/tmp/dp_listen.sock`
and received the exact REST-valid 2233-byte W274 datagram over a real
`AF_UNIX SOCK_DGRAM` client. ASan reported `stack-buffer-overflow`,
`WRITE of size 121`, `[32, 2080) 'dlpsig_buf' (line 621) <== Memory access
at offset 2080 overflows this variable`, write frame
`dpi_sig_bld dp/dpi/sig/dpi_sig.c:658`, reached from the real
`dp_ctrl_bld_dlp dp/ctrl.c:2191`. Controls over the same socket: the
139-byte safe datagram into the vulnerable binary and the attack datagram
into the fixed-commit binary were ASan-clean, and the fixed binary logged
`exceeds max sig len(2048) … skip rule`. Hashes, flags, normalized facts and
raw logs: `lab/frontier/neuvector2shell/fulldp/EVIDENCE.md` and
`PROVENANCE.md`.

## Full-enforcer saved frame (W283, 2026-11-26)

`bash lab/frontier/neuvector2shell/fulldp/frame.sh` → **22 PASS / 0
FAIL**, rc 0. The same pinned full `dp` is rebuilt at `-O2 -g` with no
ASan, fortify or stack protector (`nm` confirms zero `__asan` symbols),
and the REST-valid 2233-byte datagram is sent over the real control socket
while the enforcer runs under gdb. The breakpoint at `dpi_sig.c:662` is
installed but not reached: a SIGSEGV occurs inside the pattern loop at
`dpi_sig.c:657`, where the live frame reads `BUF→RBP=2096`, `LEN=2194`.
Saved RBP and return slot hold chosen wire bytes: `0x2a2e612a2e612a2e` /
`0x2e612a2e612a2e61` for `a*`, `0x2a2e422a2e422a2e` /
`0x2e422a2e422a2e42` for `B*`. Without gdb the attack faults (`RC=139`);
the safe and fixed-binary controls survive and the fixed binary skips the
rule. Full flags, hashes, addresses and logs:
`lab/frontier/neuvector2shell/fulldp/EVIDENCE.md`.

This moves the W278/W280 measured chosen-byte frame into the **live full
enforcer**. Grade is unchanged: the bytes are ASCII regex text, not a
chosen address, and the process faults before returning. No pointer
redirection, command or side effect.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed stack OOB WRITE in the verbatim
  pinned `dpi_sig_bld()`, in the byte-identical real `dpi_sig.c` object,
  through a REST-validated controller-shaped JSON message with real
  wildcard expansion, and now in the **full pinned enforcer `dp` binary**
  on its real AF_UNIX control socket. Every lane has vulnerable, fixed and
  safe-input controls.
- **Rung 4 lab mechanics (W278, witness ESTABLISHED AS LABELED):** chosen
  bytes observed at chosen offsets past the logical buffer in a synthetic
  frame, in the saved RBP slot of an `-O0` real-object frame, and in *both*
  saved RBP and saved return slot of an `-O2` real-object frame driven by a
  REST-valid wire message; W283 repeats that measurement in the live full
  enforcer's `-O2` frame. Both attack traces fault inside `dpi_sig_bld()`
  before returning: the overwritten words hold ASCII regex bytes, not a
  chosen address. No pointer redirection, command or observed side effect.
  Grade stays rung 4 PARTIAL by label, not advanced.
- **Not rung 5:** no REST/CRD endpoint is contacted, the enforcer is run in
  standalone loopback mode (ASan and plain builds), and there is no benign
  effect. The Go agent cannot be built here (host Go 1.22.2, `go.mod`
  requires 1.27.4).

Next experiment: the live `-O2` frame is now measured, so the remaining
gap is a non-ASCII chosen word that survives to a return, plus a reachable
authenticated REST/CRD target with a benign command side effect. Any
chosen-address marker stays an in-process rung-4 mechanic until then. Keep
the no-command / no-rung-5 ceiling; the witness has not yet replayed W282
or W283.

## Duplicate check

`reports/frontier-*.md`, the wall's do-not-duplicate list and
`lab/frontier/` were checked before provisioning. `stbvorbis2shell` is a
different library (stb_vorbis single header); no NeuVector brief, lab or
window exists. Three other advisories screened this wake were duplicates
or unstageable: libmt32emu (munt2shell), SOES EoE (soes2shell), and Zyxel
libclinkc (no public source or fix bytes).
