# Frontier brief — Brotli decoder block-switch over-write ("Broccoli2Shell")

**Status: candidate brief from claim sources + source-bound patch read. NO local
experiment has been run for this candidate. All rungs below are UNKNOWN, not
passes.** Ranked HIGH for a cheap rung-1/2 attempt, MEDIUM for rung 3, and
uncertain for rung 4 for the structural reason given below. This is an unowned
target: the `node2shell` charter is scoped strictly to CVE-2026-123828
(HTTP/2 Alt-Svc one-byte overflow), not to the Brotli C decoder.

## Verified ground truth (claim sources, read-only provisioning)

- **Advisory**: CVE-2026-111497 / GHSA-9v8h-qqgm-4m35, "Out-of-Bounds Write in
  Google Brotli Decoder" (CNA Google LLC, published 2026-10-22, updated
  2026-10-27). CWE-252 (unchecked return value) + CWE-787 (out-of-bounds
  write). CVSS 4.0 9.2 Critical,
  `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`.
- **Affected / fixed** (per the CVE record): `google/brotli` C library
  1.0.3–1.0.9, 1.1.0, 1.2.0; fixed in 1.0.10 / 1.1.1 / 1.2.1. Consumers with
  their own copies: Node.js <22.23.4 / <24.22.1 / <26.12.1 (EOL lines never
  fixed), Python `Brotli` <1.2.1 and `brotlicffi` <1.2.1.0, Bun <1.4.4,
  brotli4j <1.24.0, .NET 8/9/10 before the 2026-10-25 out-of-band update,
  Envoy <1.36.12/1.37.8/1.38.6/1.39.3/1.40.0, Istio <1.29.9/1.30.6/1.31.2.
- **Claimed primitive**: a remote unauthenticated attacker who can get a
  crafted Brotli stream in front of any vulnerable decoder can corrupt
  adjacent decoder state, disclose heap memory, or (claimed) execute code.
  CISA added the CVE to its KEV catalog 2026-10-27 (a claim about the wild,
  not lab evidence here).
- **Claim sources read (all external claims, not lab findings)**:
  - CVE record `cve.org/CVERecord?id=CVE-2026-111497` (CNA text, versions, CVSS).
  - Envoy advisory `github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr`
    (CVSS 9.2, "corrupt adjacent decoder state memory, disclose sensitive
    memory contents, cause a denial of service, or potentially execute
    arbitrary code using a crafted Brotli-compressed stream"; credit OpenAI
    Security Research).
  - Upstream fix `github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b`
    (full patch fetched, read below).
  - `broccoli2shell.com` (inventory, timeline, exploitation-status claims).
  - Mondoo `Broccoli2Shell` article (2026-10-26) and Datadog Security Labs
    `Node2Shell: Reproducing CVE-2026-111497 in the Node.js Brotli decoder`
    (2026-10-29) — mechanism and reproduction detail below, treated as claims.

## Source-bound mechanism (read from the fix patch, not inferred)

The fix changes one helper's return type and the macros that consume it, in
`c/dec/decode.c`:

- `DecodeBlockTypeAndLength()` (was `BROTLI_INLINE BROTLI_BOOL`) now returns
  `BrotliDecoderErrorCode`. The three branches previously collapsed into
  `BROTLI_FALSE` are now distinguished:
  - `max_block_type <= 1` (block switch impossible for this tree) → new hard
    error `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (`-17`);
  - `SafeReadSymbol()` / `SafeReadBlockLength()` running dry →
    `BROTLI_DECODER_NEEDS_MORE_INPUT`;
  - normal completion → `BROTLI_DECODER_SUCCESS`.
- `c/include/brotli/decode.h` replaces the reserved `-17` slot with
  `BROTLI_ERROR_CODE(_ERROR_FORMAT_, BLOCK_SWITCH, -17)`.
- The three callers (`DecodeLiteralBlockSwitch`, `DecodeCommandBlockSwitch`,
  `DecodeDistanceBlockSwitch`) changed from `void` on the fast path /
  `BROTLI_BOOL` on the safe path to returning the code. On the fast path the
  old `BROTLI_SAFE(...)` macro discarded the return value entirely; the fix
  adds `BROTLI_SAFE_WITH_STATUS(...)` which assigns any non-`SUCCESS` status
  to `result` and `goto saveStateAndReturn`. It is applied at the command,
  distance and literal block-switch sites inside `ProcessCommandsInternal`.
- Net effect: on a vulnerable build, a stream that requests a block switch
  with `max_block_type <= 1` returns `BROTLI_FALSE`. The safe path reads that
  as "need more input" and keeps buffering attacker bytes; the fast path
  ignores it. Per the advisory prose (a claim, not verified here), the
  unbounded copy into a small internal buffer writes past its end into
  adjacent decoder state. The fix stops with `-17` before that write.

Datadog's reproduction article adds mechanism claims worth testing, not
accepting: a ~23 MB stream of ordinary commands drains the block-length
budget, and the closing commands request the forbidden switch. Two arms are
described — an intra-allocation over-write, and a CPU-spin DoS arm where the
decoder retries the forbidden switch forever. They report a repeatable heap
read (leaked bytes leaving in decompressed output) and a redirected write
(aimed at an unmapped page, giving a deterministic SIGSEGV). **Critical
caveat from the same source: "the write happens inside a single heap
allocation, so the tooling built to catch memory corruption never sees it"**
— the 8-byte buffer and adjacent decoder state are fields of one allocation,
so ASan redzones will not flag the intra-object write. This is the nginx2root
lesson directly: determine the consumer's actual memory layout and what the
tool can observe before investing in exploitation mechanics.

## Rung ladder — honest grading (all UNKNOWN, no local bytes yet)

- **Rung 1 (reproducible trigger): UNKNOWN.** Need a local decoder build and a
  crafted stream. Public PoC repositories exist (GitHub API search for
  `CVE-2026-111497` surfaced `dimasma0305/CVE-2026-111497-POC`,
  `syrex1013/CVE-2026-111497-node2shell`, `ikow/brotli2crash`, among others);
  none fetched or run. Treat every one as a claim.
- **Rung 2 (observed state failure): UNKNOWN.** Datadog claims a vulnerable
  build returns `Z_BUF_ERROR`/"unexpected end of file" while a patched build
  returns `ERR__ERROR_FORMAT_BLOCK_SWITCH` / Python "decoder is unhealthy";
  also a CPU-spin arm. Not observed here.
- **Rung 3 (confirmed memory corruption): UNKNOWN, and ASan may be blind to
  the write.** Because the overflow is inside one allocation, a plain ASan
  heap-buffer-overflow report is not the expected detector. Feasible
  alternatives: instrument the decoder state with canary fields around the
  buffer and observe chosen bytes land there, or observe the *redirected*
  write to an unmapped address under Valgrind/gdb. Both need source build work.
- **Rung 4 (demonstrated security impact): UNKNOWN, structurally constrained
  but not obviously impossible.** Public claims: standard builds give a crash
  plus limited memory read; Imperva reports code execution on an unmodified
  Node.js 24.22.0 **arm64** image (exploit unreleased). Datadog names three
  obstacles: heap-layout randomization, corruption bytes doubling as decoder
  input, and a managed runtime between corrupted C state and control flow.
  **A standalone C harness removes the third obstacle** — that is this lab's
  structural advantage over a Node-based replay. Counterclaim preserved:
  `ikow/brotli2crash` asserts `MLEN_MAX = BLOCK_SIZE_CAP = 2^24` makes RCE
  structurally unreachable. That is a claim to test against actual bytes,
  not a reason to skip the experiment.

## Feasibility assessment and cheapest next experiment

Tractability for rungs 1–2: **HIGH**. `google/brotli` is a small C library,
CMake-buildable here (cmake/clang/gcc/valgrind all present), with an exact
vulnerable tag (v1.2.0) and fixed tag (v1.2.1) and a clean public patch.
No hardware feature is needed (unlike the AVX-512-blocked Java4Shell).
Reachability is stronger than PostgreSQL's: `PR:N`, network-triggerable via
`Content-Encoding: br` on inbound bodies or auto-decoded outbound responses,
and the bug sits in one small library rather than a large server.

Cheapest experiment that would move this up a rung (loopback only, no external
probe):

1. Provisioning (allowed): clone `google/brotli`, checkout tag `v1.2.0` and
   `v1.2.1` into `lab/frontier/brotli2shell/`; fetch one public PoC stream and
   pin its SHA-256. Do not run any PoC against non-loopback systems.
2. Build two local decoder harnesses with ASan (and a non-ASan build for
   layout/canary work): a tiny program calling `BrotliDecoderDecompressStream`
   on the crafted bytes, plus a version that maps the input from a file.
3. Rung 1/2: replay the same stream on both builds. Expect v1.2.0 to accept/
   spin/crash and v1.2.1 to return `-17` quickly; record exact bytes, return
   codes and wall time. The version-sensitive differential is the gate.
4. Rung 3: because ASan will not see an intra-allocation write, add canaries
   around the 8-byte buffer in `BrotliDecoderState` (source edit in the lab
   build only) and check whether chosen stream bytes land in them; separately
   look for the redirected invalid write under Valgrind/gdb.
5. Rung 4: only after a chosen byte at a chosen offset is observed, attempt a
   controlled pointer/redirect in the standalone C harness. Preserve the
   fixed-build differential and the negative results if it fails.

**No target window or handoff is owed yet** — this is a screening brief. The
charter's two-artifact rule applies when a candidate is worth local work and
gets driven up the ladder, not to a screened candidate. Next wake: either run
step 1–3 if time allows or hand the brief to the witness for a source-binding
check.

## What would change this assessment

- A local v1.2.0/v1.2.1 differential that does NOT reproduce (both return
  `-17`, or neither does) would break the candidate's premise → screen out.
- Observing that the overflow is confined to a field with no pointer after it
  would confirm the `brotli2crash` structural-unreachability claim → rung 4
  closed, keep rungs 1–2 as a DoS/memory-disclosure finding only.
- A chosen byte landing in an adjacent decoder-state pointer on the standalone
  C harness would justify a dedicated `brotli2shell` mind/window.
