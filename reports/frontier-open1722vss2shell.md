# frontier-open1722vss2shell — VSS path-length OOB READ and uint16 wrap (CVE-2026-136616)

## Claim source and scope

- VulnCheck advisory, published 2026-11-25:
  https://www.vulncheck.com/advisories/covesa-open1722-before-0.9.8-out-of-bounds-read-via-avtp-vss-calcvsspathlength
  — COVESA Open1722 `< 0.9.8` contains an out-of-bounds read in
  `Avtp_Vss_CalcVssPathLength()` (`src/avtp/acf/custom/Vss.c`). The advisory
  also claims prefixes `0xFFFE`/`0xFFFF` wrap uint16 arithmetic and make
  `Avtp_Vss_SetVssData()` overwrite the path area. LOW severity, CVSS 2.3,
  CWE-125; attacker framing ("send header-only 12-byte INTEROP frames") is a
  claim reproduced locally only as an in-process frame build.
- References: GHSA-xvmx-7qq5-34q6, fix commit
  `714067b0134cf36f89464dbc6ec25529c0e189c7`, v0.9.8 release notes, and the
  v0.9.7 source pin `src/avtp/acf/custom/Vss.c#L295-L310`. The fix commit is
  the v0.9.8 tag; `git ls-remote` gave `v0.9.7 =
  b78c3877bcf0258c76fdaca7f4551e58b708b7ce`, `v0.9.8 = 714067b0…`, HEAD
  `714067b0…`. Credit: Serhii Shunko.
- Checked before staging: no report, charter, lab lane or manifest row for
  Open1722/ICU-style VSS work; no shared CVE with an admitted target.

## Source-bound mechanism

In the v0.9.7 tarball, `Avtp_Vss_CalcVssPathLength()` at
`src/avtp/acf/custom/Vss.c:295-310` computes
`vss_path_ptr = (uint8_t *)pdu + AVTP_VSS_FIXED_HEADER_LEN` (12 bytes) and,
for INTEROP mode, returns `vss_load_be16(vss_path_ptr) + 2` in `uint16_t`
arithmetic. It never consults the declared ACF message length. The shallow
`Avtp_Vss_IsValid()` at `:175-197` accepts a header-only frame when the
declared length is 12 and the buffer is 12 bytes, so a conforming consumer can
call the accessor on a frame with no path prefix at all. `Avtp_Vss_SetVssData()`
at `:619-624` derives its write pointer from that result:
`pdu + 12 + Avtp_Vss_CalcVssPathLength(pdu)`.

The fix commit changes this function to read the declared length first, reject
frames with no room for the prefix, accumulate `total_length` in `uint32_t`,
reject `total_length > available` and overflow past `UINT16_MAX`, and return
zero for unknown modes. `Avtp_Vss_SetVssData()` gains an `if (vss_path_length
== 0) return;` guard. The commit also adds unit tests asserting `0` for a
header-only frame and for the `0xFFFF` prefix.

## Local evidence

Harness `lab/frontier/open1722vss2shell/`: a driver that uses only the public
API (`Avtp_Vss_Init`, `Avtp_Vss_SetAddrMode`, `Avtp_AcfCommon_SetAcfMsgLength`,
`Avtp_Vss_CalcVssPathLength`, `Avtp_Vss_SetVssData`) linked against the
**unmodified** `Vss.c` and `InlineExports.c` from both pinned tarballs. No
socket, listener, pcap or external system. Canonical runner
`run-all.sh` sha256
`5da4f917cc7b5d9e8f04a1d7dfccc6ba6acff132ff3d2cee0eeb73ebc1a72a52`:
**RESULT PASS=34 FAIL=0**, rc 0, GCC and Clang ASan/plain builds.

- Vulnerable ASan (`read_oob`): `ERROR: AddressSanitizer:
  heap-buffer-overflow`, `READ of size 2`, `0 bytes after 12-byte region`,
  `calloc(12)` at `poc.c:16`, read in `vss_load_be16` at `Vss.c:66` called
  from `Avtp_Vss_CalcVssPathLength` at `Vss.c:307` — both compilers.
- Vulnerable `adjacent`: the frame declares 12 bytes but chosen prefix bytes
  `0x41`/`0x42` sit at offsets 12/13 of the same allocation; the accessor
  returns `16708` (`0x4144`) while the fixed build returns `0`. Plain and ASan
  agree; no ASan report because the bytes are inside the allocation.
- Vulnerable `wrap`: prefix `0xFFFF` returns `1`; `SetVssData()` with chosen
  byte `0x5a` writes it at offset 13, overwriting the path prefix area, while
  the fixed build returns `0` and leaves offset 13 as `0xff`.
- Safe control: prefix `0x0004` gives path length 6 and writes `0x5a` at
  offset 18 in both builds, with no ASan report.
- Negative preserved: the first runner invocation scored 30 PASS / 4 FAIL
  because two plain-build assertions searched for a substring that omitted
  the `b12=ff` field; the logs themselves held the correct bytes. The
  assertions were corrected and the rerun scored 34/0 with unchanged source.

## Author and witness replays

Author clean-archive replay from `git archive f52dd1b5` into
`.mishe-tauftauf/replays/open1722vss2shell-w262/` at 11:00:55Z: rc 0,
**RESULT PASS=34 FAIL=0**, runner SHA-256 unchanged `5da4f917…1a72a52`.
Independent witness replay (W264, 11:19:00–11:19:07Z): clean `git archive
f52dd1b5` into `.mishe-tauftauf/artifacts/witness-w264-open1722/` with all
committed logs and generated trees removed, all three sources fetched fresh by
commit SHA and hash-matched to the runner pins; the unmodified runner returned
rc 0 and **RESULT PASS=34 FAIL=0**, byte-identical to the author's console
apart from timestamps. Fresh GCC+Clang logs reproduce the READ-2 and
`0 bytes after 12-byte region` at `Vss.c:66` ← `:307`, the chosen-byte length
16708 and the wrap byte at offset 13, with all fixed and safe controls clean.
Verdict: **ESTABLISHED AS LABELED**; no contradiction, no grade change, NO r5.
Detail: `.mishe-tauftauf/artifacts/witness-w264-open1722/detail.md`.

## Honest rung-4 feasibility assessment

Grade: **rung 3 real-source ASan-confirmed OOB READ; rung 4 PARTIAL**. The
OOB read and the wrap-driven overwrite are observed in the pinned library's
own code, not a hand-copied function body. Chosen bytes in an adjacent raw
byte array determine the returned path length in the plain build, and the
chosen payload byte lands at a chosen offset in the path area. What is NOT
shown: a named adjacent object or field whose identity/pointer is controlled,
pointer control, an AVTP wire consumer, a live loopback service, a command, or
r5. The advisory's LOW severity and DoS framing are consistent with the
observed primitive; no RCE claim is made.

## Cheapest next rung-moving experiment

Compile the pinned vulnerable library into a small local AVTP frame consumer
that takes a 12-byte INTEROP VSS frame from a loopback-only UDP socket (or a
local pcap) and calls `IsValid` → `CalcVssPathLength` → `SetVssData`, then
repeat with the fix commit. Place a named heap object with a pointer field
immediately after the frame and measure whether the over-read bytes drive a
pointer-derived length; that would be the first step toward a named-object
rung-4 claim. Absent that, the honest ceiling stays a length-corruption /
DoS primitive. Would change the assessment: an ASan report in a fixed build,
a named adjacent field or pointer under attacker control, a wire-path replay,
or a witness counterexample.
