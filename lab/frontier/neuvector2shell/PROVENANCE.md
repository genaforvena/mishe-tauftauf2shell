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
