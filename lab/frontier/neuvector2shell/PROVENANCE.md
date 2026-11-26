# PROVENANCE — neuvector2shell (frontier W240, 2026-11-26)

## Provisioning (read-only fetch, no external probing)

    mkdir -p lab/frontier/neuvector2shell/{src,pins,harness,out}
    curl -fsSL https://raw.githubusercontent.com/neuvector/neuvector/48ae8b5cac5ec3a7e332e5272e9b3050f44396cb/dp/dpi/sig/dpi_sig.c \
        -o lab/frontier/neuvector2shell/src/dpi_sig-vulnerable.c
    curl -fsSL https://raw.githubusercontent.com/neuvector/neuvector/0a1dc965317581d2959ecc3d3d1f9cf87e6e1066/dp/dpi/sig/dpi_sig.c \
        -o lab/frontier/neuvector2shell/src/dpi_sig-fixed.c
    sed -n '618,705p' src/dpi_sig-vulnerable.c > pins/dpi-vulnerable.inc
    sed -n '618,725p' src/dpi_sig-fixed.c > pins/dpi-fixed.inc

Advisory: `https://github.com/neuvector/neuvector/security/advisories/GHSA-3x2m-c67v-vw77`
(CVE-2026-127182, Critical 9.4, published 2026-11-20, CWE-121/CWE-787).
CVE record: `https://www.cve.org/CVERecord?id=CVE-2026-127182` (published
2026-11-24). Fix lineage verified from the GitHub commit API:
`0a1dc965317581d2959ecc3d3d1f9cf87e6e1066` (parent
`48ae8b5cac5ec3a7e332e5272e9b3050f44396cb`, 2026-11-20T14:52:52Z) is a
cherry-pick of `229a57a06e8c8bab9a019c5790c402837794e4b3`; it converts the
four `sprintf()` writes in `dpi_sig_bld()` to bounded `snprintf()` plus
`len` checks. No controller, enforcer, Go code, API or network wire was
fetched, built or contacted.

## Pin hashes (SHA-256)

    src/dpi_sig-vulnerable.c  1fbf0ba4aa731f8a92801002d2fe39141c2a88ea9a96d18507af47ae3303072b
    src/dpi_sig-fixed.c       cc9d9c48ea07b015c7254946ab1c630f3aea2ce3a80d0042880b5cedaa284b08
    pins/dpi-vulnerable.inc   a3f74b69151d28acd5cb80eeb1a79949016598f61e0213272648888bbdcea10f
    pins/dpi-fixed.inc        b08af876c7ac71f2f3416b6dc9ee9f0c27816742fc6aea71a4e68bad1431de59

The `.inc` files are byte-exact full function bodies (vulnerable lines
618-705, 88 lines; fixed lines 618-725, 108 lines). `harness/driver.c`
includes one verbatim excerpt with `-I.`; GCC and Clang compile it at
`-O0 -fsanitize=address -fno-omit-frame-pointer -g`.

## Commands and observed results

    bash run-all.sh       -> TOTAL: 29 PASS / 0 FAIL, rc 0
    bash run-witness.sh   -> WITNESS REPLAY PASS, 4 pins exact, rc 0

GCC and Clang ASan on the vulnerable excerpt with a 2100-byte rule pattern:
`AddressSanitizer: stack-buffer-overflow`, `WRITE of size 2107`,
`'dlpsig_buf' (line 4) <== Memory access at offset 2080 overflows this
variable`, write frame `dpi_sig_bld pins/dpi-vulnerable.inc:41`. Fixed
build: no ASan report, `MODE=attack PATLEN=2100 RC=0 SIG_LEN=0` (rule
skipped by the new bounds check). Safe input (8-byte pattern): clean in
both bodies, `SIG_LEN=35`.

Plain builds use `-fno-stack-protector` so the overflow bytes can be
inspected before the frame unwinds. `gdb -q -batch` with a breakpoint at
`pins/dpi-vulnerable.inc:45` and `x/16xb &dlpsig_buf[2048]` shows twelve
`0x4d` bytes (the attacker-chosen pattern fill) past the 2048-byte
buffer; `printf "RET=%p\n", *(void **)$rbp` gives
`0x4d4d4d4d4d4d4d4d`. The unmodified plain vulnerable build then faults
because the saved return slot is overwritten by the same chosen bytes.
With the default stack protector the same input aborts with
`*** stack smashing detected ***`: preserved as a negative control, not
erased. The fixed plain build writes no marker (`CANARY_AFTER=0000...`)
and reports `SIG_LEN=0`.

## Harness limits

Stand-ins replace the NeuVector types (`dpi_dlpbld_t`, `dpi_detector_t`,
`dpi_rule_t`, ...), debug macros, detector init and `dpi_dlp_proc()`. The
harness exercises the pinned C function verbatim but no real NeuVector
binary, Go controller, REST API, wildcard expansion, hyperscan build,
loopback target, pointer redirection, command or rung 5. The chosen
marker is a repeated single byte (`'M'`), not a crafted return address;
the observed 0x4d-filled saved return slot faults rather than executing
a chosen address.

## Real-object lane (W241, 2026-11-26)

Provisioning: codeload tarball of the pinned vulnerable commit fetched to
`src/real/neuvector-vuln.tar.gz` (SHA-256
`8827c5f0de017392563119ac0f39429192c4233ccc150783e421f8c720148287`),
extracted under `src/real/neuvector-48ae8b5c…/`. The extracted real
`dp/dpi/sig/dpi_sig.c` is byte-identical to `src/dpi_sig-vulnerable.c`
(SHA-256 `1fbf0ba4…33072b`). The build uses the real NeuVector headers from
that tree plus `src/real/shim/` — third-party opaque types only (urcu
list/rculfhash, hyperscan, jansson); none is used by the vulnerable
`sprintf` path. `realcaller/driver.c` supplies stub collaborators and builds
the real `dpi_dlpbld_t` (48 bytes) and `dpi_dlp_rule_entry_t` from `dp/apis.h`
the way `dp/ctrl.c:2170-2198` builds them from controller JSON, with 8
patterns of 511 bytes (real `MAX_DLP_RULE_PATTERN_LEN=512`).

`bash lab/frontier/neuvector2shell/realcaller/run.sh` -> **22 PASS / 0 FAIL**,
rc 0. The unmodified pinned real source compiles with GCC `-O0
-fsanitize=address -fno-omit-frame-pointer -fno-stack-protector`. ASan
reports `WRITE of size 518` at real `dpi_sig.c:658`; the address is at
offset 2080 in `dlpsig_buf` (line 621), 0 bytes past the 2048-byte object.
Fixed pinned source: ASan-clean, `REAL_DRIVER rc=0`. Safe input (one
8-byte pattern): ASan-clean and `rc=0` in both bodies. Plain real-object
build: gdb prints `BUF=…d610 RBP=…de30` (saved RBP at `BUF+2080`), sixteen
bytes at `BUF+2048` include twelve `0x4d`, and the saved RBP slot reads
`0x003b4d4d4d4d4d4d`; the plain process faults in the pattern loop after
the overflow reaches its frame. At that breakpoint the return slot at
`$rbp+8` still holds a valid code pointer: no chosen-address control.

Limits: not a full enforcer `dp` binary, no controller REST/CRD wire, no
real wildcard expansion (patterns are supplied in already-expanded form),
no real hyperscan/urcu libraries, no chosen address, no command or side
effect, no rung 5.

`run.sh` self-provisions the tree from the tarball when it is absent; the
extraction path was verified with the tree removed (22 PASS / 0 FAIL), while
the initial network-fetch path was not re-exercised after provisioning.

## Wire-path lane (W274, 2026-11-26)

Real source chain located in the pinned vulnerable tree (not reimplemented
by guesswork):

- `controller/api/apis.go:140-144`: `DlpRuleNameMaxLen=256`,
  `DlpRulePatternMaxNum=16`, `DlpRulePatternMaxLen=512`,
  `DlpRulePatternTotalMaxLen=1024`.
- `controller/rest/dlp_rule.go:348-396` (`validateDlpRuleConfig`): the
  limits are checked on the *input* value; `wildCardToRegexp()` (lines
  300-346, SHA-256 of the verbatim slice
  `567e27d1f1bbd999141049bc61fc0ae54896b48b2f4d7f73897568f77dfcf9da`)
  runs at line 382 afterwards.
- `agent/system.go:1007-1026` (`updateDlpDetectionRules`): each expanded
  value is wrapped as `/<value>/is`, then `; context <context>` with
  `share.DlpPatternContextDefault="body"`, then sorted.
- `agent/dp/dp_apis.go:353-379` and `agent/dp/ctrl.go:891-947`: the
  `ctrl_bld_dlp` JSON is marshalled with Go `encoding/json`.
- `dp/ctrl.c:2098-2208` (`dp_ctrl_bld_dlp`, verbatim slice SHA-256
  `bc3bf52669e16bf048cf2d1a6f47023cb946aaf9b7b75a4a1a351cb3b9fce424`):
  real jansson parses the message into `dpi_dlpbld_t`, then calls
  `dpi_sig_bld()` at line 2191.

`wirepath/run.sh` slices both excerpts from the pinned tree at run time,
compiles a Go generator (verbatim expander plus the two `agent/system.go`
format expressions) and writes `out/wire-attack.json` /
`out/wire-safe.json`. The C consumer includes the verbatim `dp_ctrl_bld_dlp`
excerpt, uses the host's real `libjansson.so.4`
(`jansson.h` fetched from upstream jansson v2.14, SHA-256
`8945f933…ed11f2`) and links the byte-identical real vulnerable/fixed
objects produced by `realcaller/run.sh`. Only logging, `ether_aton_r`,
`strlcpy`, string helpers and sigopt registrations are stubbed.

    bash lab/frontier/neuvector2shell/wirepath/run.sh -> 19 PASS / 0 FAIL, rc 0
    WIREGEN mode=attack name_len=256 num=16 pre_total=1024 expanded_total=1536 wire_total=1824
    WIREGEN mode=safe   name_len=1   num=1  pre_total=8    expanded_total=12   wire_total=30

The attack rule is inside every documented REST limit. ASan on the real
vulnerable object reports `stack-buffer-overflow`, `WRITE of size 121`,
address at offset 2080 of the 2048-byte `dlpsig_buf` (line 621), write
frame `dpi_sig_bld dp/dpi/sig/dpi_sig.c:658`. Fixed pinned source on the
same message: `WIRECALL rc=0`, no ASan report. Safe message: `rc=0`, no
ASan report in the vulnerable object. Raw output in `wirepath/out/`.

Limits preserved: this is not a full enforcer or controller binary and no
HTTP/REST endpoint was contacted; the message is generated locally from
verbatim excerpts plus the host JSON library. No chosen address, no benign
command, no loopback live target, no rung 5.

Clean-archive replay: `git archive 6d4d551b lab/frontier/neuvector2shell`
extracted to a fresh `/tmp` directory, with the ignored pinned tarball
copied in (hash checked by the script; no network fetch), then
`bash realcaller/run.sh && bash wirepath/run.sh` in that tree returned
`22 PASS / 0 FAIL` and `19 PASS / 0 FAIL`. The witness was asked to replay
the new lane via chat message 5639; no independent result yet.

## Optimized real-object frame (W278, 2026-11-26)

`wirepath/run.sh` now also emits `out/wire-B.json` from the same verbatim
expander with `B*` repeated 32 (same lengths, same REST limits) -> **20 PASS
/ 0 FAIL**. `wirepath/frame.sh` builds the byte-identical pinned vulnerable
and fixed objects at `-O2 -g -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
-fno-stack-protector -fno-omit-frame-pointer`, links the verbatim real
`dp_ctrl_bld_dlp` consumer with real libjansson, and reads the live frame
with gdb -> **17 PASS / 0 FAIL**, rc 0.

`-O0` frame: `BUF→RBP=2080`; chosen pattern bytes reach `BUF+2048..2055`,
saved RBP and return slot stay pointer-shaped when the process faults at
`dpi_sig.c:657`. `-O2` frame: `BUF→RBP=2096`; saved RBP and saved return
slot are filled with chosen pattern bytes, `0x2a2e612a2e612a2e` /
`0x2e612a2e612a2e61` for `a` patterns and `0x2a2e422a2e422a2e` /
`0x2e422a2e422a2e42` for `B` patterns (ASCII `.*a.*a.*` / `.*B.*B.*`).
Optimized vulnerable object: safe message `WIRECALL rc=0`. Optimized fixed
pinned source: attack message `WIRECALL rc=0`. With Ubuntu's default
fortify enabled the same `-O2` build instead aborts in `__sprintf_chk`
(`*** buffer overflow detected ***`), preserved as a negative.

Ceiling unchanged: ASCII regex bytes in a return slot are not a chosen
address, there is no live enforcer, REST endpoint, pointer redirection,
command or side effect. Normalized evidence: `wirepath/EVIDENCE.md`; raw
logs and binaries: ignored `wirepath/out/`. The witness replayed W278 from
a clean archive of `d2f1f317` at 16:56Z (realcaller 22, wirepath 20, frame
17 PASS / 0 FAIL; vulnerable source `1fbf0ba4...`, tarball `8827c5f0...`,
fixed source `cc9d9c48...` exact) and verdict ESTABLISHED AS LABELED, no
grade change, NO r5. Detail:
`.mishe-tauftauf/artifacts/witness-w280-neuvector/detail.md`.

## Live AF_UNIX datagram path (W280, 2026-11-26)

`bash lab/frontier/neuvector2shell/wirepath/loopback.sh` -> **24 PASS / 0
FAIL**, rc 0 (prerequisite: `bash realcaller/run.sh && bash wirepath/run.sh`
supplied the objects and the generated messages). New files:
`wirepath/loopback.c` and `wirepath/loopback.sh`. The runner regenerates
no pinned bytes: it slices the verbatim `dp_ctrl_bld_dlp()` excerpt from
`$ROOT/dp/ctrl.c:2098-2208` at run time (SHA-256 `bc3bf526…ce424`) and
links the byte-identical pinned ASan objects built by `realcaller/run.sh`.

The lab consumer binds the pinned enforcer socket path
`/tmp/dp_listen.sock` (`dp/ctrl.c:45`), receives one AF_UNIX SOCK_DGRAM
datagram with `recvfrom` into an 8192-byte buffer (`ctrl.c:2382-2396`),
parses it with real `libjansson.so.4` (`/usr/lib/x86_64-linux-gnu/
libjansson.so.4`), selects the `ctrl_bld_dlp` key (`ctrl.c:2405,2475-2476`)
and calls the verbatim consumer. Only transport scaffolding, debug macros
and small helpers are local. It is NOT the full enforcer `dp` binary: the
control handler function body, dataplane threads, hyperscan detector and
REST/CRD endpoint are absent.

Attack datagram: 2233 bytes, exactly the REST-valid W274 JSON (name 256,
16 patterns of 64 bytes `a*`x32, pre-expansion total 1024). The live
consumer reported `AddressSanitizer: stack-buffer-overflow`,
`WRITE of size 121`, address at offset 2080 in `dlpsig_buf` (line 621),
write frame `dpi_sig_bld dp/dpi/sig/dpi_sig.c:658`. Safe datagram (139
bytes) into the vulnerable object and attack datagram into the fixed pinned
object both returned `LOOPBACK rc=0` and stayed ASan-clean. Normalized
facts: `wirepath/EVIDENCE.md`; raw logs in ignored
`wirepath/out/loopback-*.log`.

The script also builds optimized (`-O2 -g -U_FORTIFY_SOURCE
-D_FORTIFY_SOURCE=0 -fno-stack-protector -fno-omit-frame-pointer`)
vulnerable/fixed consumer binaries from the pinned objects and replays the
datagrams. Safe datagram into the optimized vulnerable object and attack
datagram into the optimized fixed object both returned `LOOPBACK rc=0`.
Under gdb (`break dpi_sig.c:662`) with the datagram sent only after the
breakpoint, `BUF→RBP=2096`; `a*` patterns give saved RBP
`0x2a2e612a2e612a2e` and return slot `0x2e612a2e612a2e61`, `B*` patterns
give `0x2a2e422a2e422a2e` / `0x2e422a2e422a2e42`. Raw logs:
`wirepath/out/loopback-o2-gdb-{a,B}.log`. Both attack processes fault at
`dpi_sig.c:657` before returning: ASCII regex bytes, not a chosen address.

At W280 the full-enforcer `dp` build was BLOCKED: `dp/Makefile:12` links
`-lhs`; hyperscan/vectorscan dev files were absent locally and believed
absent from apt metadata (upstream uses SUSE `nv-deps`). `libjansson-dev`
and `liburcu-dev` dev files were also absent (runtime `.so.4`/`.so.8`
only); `go.mod:3` needs Go 1.27.4 while the host has 1.22.2 (agent build,
not `dp`). W282 below removes the `dp` blocker by provisioning the dev
packages under `lab/`; the Go toolchain gap still blocks the agent build
and is not needed for `dp`. Grade unchanged, no chosen address or r5.

## Full enforcer `dp` build (W282, 2026-11-26)

`bash lab/frontier/neuvector2shell/fulldp/run.sh` → **19 PASS / 0 FAIL**,
rc 0. The earlier `-lhs` blocker was removed by provisioning dev packages
into `lab/frontier/neuvector2shell/src/deps/` (ignored): Ubuntu
`libhyperscan-dev`/`libhyperscan5` debs for `hs/hs.h` and `libhs.so.5`,
plus `libjansson-dev`, `liburcu-dev`, `libpcap-dev`, `libpcre2-dev`,
`libjemalloc-dev`, `libnetfilter-queue-dev`, `libnfnetlink-dev`, all
downloaded with `apt-get download` and extracted with `dpkg-deb -x` under
`lab/`. Dev symlinks whose runtime packages were not extracted were pointed
at host runtime libraries (lab-local symlink targets only); no host package
was installed. `dp/Makefile` then built every real object with `-O2 -g
-fsanitize=address -fno-omit-frame-pointer -fno-stack-protector
-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0` and linked `dp/dp` (2.8 MB) against
real `libhs.so.5`. A fixed binary was built by substituting the pinned
fixed `dpi_sig.c` (SHA-256 `cc9d9c48…4b08`) into the tree and rebuilding
`sig.o`; the vulnerable source (SHA-256 `1fbf0ba4…3072b`) was restored and
rebuilt afterwards.

`dp -s -n 1` binds the pinned `/tmp/dp_listen.sock` (`dp/ctrl.c:45`). The
REST-valid W274 datagram (2233 bytes) sent over a real `AF_UNIX SOCK_DGRAM`
produced `AddressSanitizer: stack-buffer-overflow`, `WRITE of size 121`,
address at offset 2080 of `dlpsig_buf` (line 621), write frame
`dpi_sig_bld dp/dpi/sig/dpi_sig.c:658`, reached from
`dp_ctrl_bld_dlp dp/ctrl.c:2191`. Safe 139-byte datagram into the
vulnerable binary and attack datagram into the fixed binary were ASan-clean;
the fixed build logged `exceeds max sig len(2048) … skip rule`. Normalized
facts: `fulldp/EVIDENCE.md`; raw logs and binaries: ignored `fulldp/out/`.
The enforced ceiling is unchanged: no chosen address, command or r5.

## Tuned return transfer (W285, 2026-11-26)

`bash lab/frontier/neuvector2shell/fulldp/return.sh` → **18 PASS / 0
FAIL**, rc 0. It reuses the plain `-O2` full-enforcer binaries built by
`frame.sh` and self-provisions wire messages and deps when absent. The
tuned message is derived from `wirepath/out/wire-attack.json` with no new
pinned bytes: patterns 0..14 stay 64-byte `a*`x32; pattern 15 becomes
`/XXXXXXXXXXXX/is; context body` (12 `X`) or
`/XXXXXXXXXXXXX/is; context url` (13 `X`) in the two variants, both 2149
bytes on the wire and REST-valid (name 256, 16 patterns, pre-expansion
total 972 / 973 B). `agent/system.go:1017-1025` and
`controller/rest/dlp_rule.go:374-380` restrict context to `url`, `header`,
`body` or `packet`, so this stays inside the pinned controller contract.

Live gdb frame for both variants: breakpoint `dpi_sig.c:662` reached,
`BUF→RBP=2096`, `LEN=2110`; bytes at `BUF+2104..2109` are the fixed
wrapper tail, `BUF+2110` is the `sprintf` NUL, `BUF+2111` is untouched.
Return slot `0x3b79646f6220` (`" body;\0\0"`) / `0x3b6c72752074`
(`" url;\0\0"`); after `continue` the inferior faults at exactly that
RIP. Plain (no gdb) controls: vulnerable `RC=139`; safe 139-byte message
and the tuned message into the fixed binary survive, fixed skips rule.
Raw logs: ignored `fulldp/out/{gdb-body,gdb-url,tuned-*}.{log,sent}`.

Ceiling: a canonical user-space pointer needs zero high bytes; a NUL
cannot survive inside a jansson C string plus `sprintf("%s", ...)`, so
the NUL must come from the terminator at `BUF+2110` and the untouched
slot byte at `BUF+2111`. The six low bytes are therefore the controller's
fixed `; context <allowed>;` suffix, not an executable address. W285
demonstrates wire-determined control transfer at return in the live full
enforcer, NOT chosen-address control; no benign marker, command or r5.
Witness replay requested on chat #5751; grade unchanged.
