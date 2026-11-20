# Frontier brief — Brotli decoder block-switch over-write ("Broccoli2Shell")

**Status: candidate promoted to a live find. Rungs 1/2/3 PASS on a standalone
loopback/file-only C harness; rung 4 NOT demonstrated (chosen-byte state control
observed, no marker execution).** This target is unowned: the `node2shell`
charter is scoped strictly to CVE-2026-123828 (HTTP/2 Alt-Svc one-byte
overflow), not to the Brotli C decoder.

## Verified ground truth (claim sources + this lab, 2026-11-20)

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
- **Claim sources read (external claims, not lab findings)**: CVE record
  `cve.org/CVERecord?id=CVE-2026-111497`; Envoy advisory
  `GHSA-3wvj-j6qm-62mr`; upstream fix
  `google/brotli@0ed4268a4401abcb4472096340477cf4af7d1a2b` (full patch read);
  `broccoli2shell.com`; Mondoo Broccoli2Shell article (2026-10-26); Datadog
  `Node2Shell: Reproducing CVE-2026-111497...` (2026-10-29).

## Source-bound mechanism (read from the fix patch, not inferred)

In `c/dec/decode.c`, `DecodeBlockTypeAndLength()` used to return
`BROTLI_BOOL`. The fix changes it to `BrotliDecoderErrorCode` and separates
the collapsed `BROTLI_FALSE` cases:

- `max_block_type <= 1` (block switch impossible) → new hard error
  `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (`-17`, added to `decode.h`);
- `SafeReadSymbol()` / `SafeReadBlockLength()` running dry →
  `BROTLI_DECODER_NEEDS_MORE_INPUT`; normal completion → `SUCCESS`.
- The three callers (`DecodeLiteralBlockSwitch`, `DecodeCommandBlockSwitch`,
  `DecodeDistanceBlockSwitch`) change from `void` on the fast path /
  `BROTLI_BOOL` on the safe path to returning the code. The old `BROTLI_SAFE`
  macro discarded the fast-path return; the fix adds
  `BROTLI_SAFE_WITH_STATUS` which assigns any non-`SUCCESS` status to `result`
  and `goto saveStateAndReturn` at the command/distance/literal switch sites
  in `ProcessCommandsInternal`.

**The vulnerable write site, located and instrumented in this lab** —
`BrotliDecoderDecompressStream()` in v1.2.0:

```c
uint8_t u8[8];           /* s->buffer, state.h:266 */
...
BROTLI_DCHECK(s->buffer_length < 8);   /* disabled in release */
s->buffer.u8[s->buffer_length] = **next_in;   /* site1, decode.c:2449 */
s->buffer_length++;
...
while (*available_in) {
  s->buffer.u8[s->buffer_length] = **next_in; /* site2, decode.c:2464 */
  s->buffer_length++;
  ...
}
```

No runtime bound check. In `BrotliDecoderStateStruct` (state.h:250+) the
8-byte `buffer` is followed by `brotli_reg_t buffer_length`, then `int pos`,
`int max_backward_distance`, `int max_distance`, `int ringbuffer_size`, …,
then pointers (`ringbuffer`, `htree_command`, `context_map_slice`, …). Writing
past index 7 therefore walks into control fields and eventually pointers,
all inside one heap allocation.

## Lab result — deterministic differential and observed over-write

Harness `lab/frontier/brotli2shell/{run.sh,decoder_harness_2stage.c,
oob-guard.patch}`; full reproduction in the Reproduce section. Pinned inputs:

- PoC generator `poc.py` SHA-256
  `3f6d79b00daf87e0ff69914ef25dc3331afd5ef319b261bd8fdc2403a24a3d9d`
  (fetched from `dimasma0305/CVE-2026-111497-POC`, a **claim**, not trusted).
- Generated `trigger.br` 23,068,690 bytes,
  `b7a6508eb39ef57ae5e3fdf9aa85540071a06eff5d5b5a2d359fc8e1768e4df4`
  (matches the generator's own `TRIGGER_SHA256`).
- Two stages: `stage1.br` 23,068,693 bytes
  `a6b86e18e1a835684fbea9896ed49ea73d739493b5633688b7652fe98da7bebd`;
  `stage2.bin` 127 bytes `64cd80075f99345bd621dfc24ceb83bfa47bd18d05773d1dda6b1f9600c7f724`.
- Upstream tags: v1.2.0 `028fb5a23661f123017c060daa546b55cf4bde29`,
  v1.2.1 `db24a98aed38a16de78cc05ca15cdd8dc2a0d92d`.

Observed (unmodified builds, one decoder state reused across two stages):

| build | stage 1 | stage 2 | rc |
|---|---|---|---|
| v1.2.0 (vulnerable) | `NEEDS_MORE_INPUT` 200000 calls, 0 output, 0.22s | SIGSEGV during stage 2 | 139 |
| v1.2.1 (fixed) | `ERROR`, `error_code=-17`, 3 input bytes unconsumed | `ERROR`, `-17`, 127 bytes unconsumed | 0 |

An ASan build of v1.2.0 on the single-shot 23 MB trigger produced **no**
ASan report — expected, because the write stays inside the one
`BrotliDecoderState` allocation. This is the nginx2root lesson: the tool's
redzones cannot see an intra-object write; a source-level canary/assert is
the detector.

Instrumented v1.2.0 (`oob-guard.patch` logs every `buffer_length >= 8` write
without changing control flow) produced **20 out-of-bounds writes at indices
8..27**, then the same SIGSEGV. The bytes are the attacker's chosen stage-2
bytes:

```
OOB site1 idx=8  byte=0x08   -> low byte of buffer_length set to 8
OOB site1 idx=16 byte=0xff   \
OOB site1 idx=17 byte=0xff    > pos = 0x7fffffff
OOB site1 idx=18 byte=0xff   /
OOB site1 idx=19 byte=0x7f
OOB site1 idx=20..23 byte=ff ff ff 7f  -> max_backward_distance = 0x7fffffff
OOB site1 idx=24..27 byte=ff ff ff 7f  -> max_distance = 0x7fffffff
```

Stage-2 bytes 7, 15..18, 19..22 and 23..26 are exactly `08`, `ff ff ff 7f`,
`ff ff ff 7f`, `ff ff ff 7f`; the mapping is byte-exact. Logs:
`lab/frontier/brotli2shell/logs/{v120-2stage.out,v121-2stage.out,instr-2stage.out}`.

## Rung ladder — honest grading

- **Rung 1 (reproducible trigger): PASS.** Deterministic version differential
  on pinned local inputs; no external probe.
- **Rung 2 (observed state failure): PASS.** Vulnerable build returns
  `NEEDS_MORE_INPUT` forever with zero output and crashes on stage 2; fixed
  build returns `-17` for both stages and exits clean.
- **Rung 3 (confirmed memory corruption): PASS.** Instrumented build observes
  20 writes past the 8-byte buffer into named adjacent fields, followed by
  SIGSEGV on the unmodified build. Detector is a lab source patch, not ASan.
- **Rung 4 (demonstrated security impact): NOT DEMONSTRATED.** Chosen bytes
  land at chosen offsets (indices 8..27) and set `pos`, `max_backward_distance`
  and `max_distance` to `0x7fffffff` — state control, not yet control-flow
  hijack. No chosen pointer, no GOT overwrite, no benign marker execution.
  Public claims of code execution (Imperva on unmodified Node 24.22.0 arm64,
  exploit unreleased) and a counterclaim (`ikow/brotli2crash`, `MLEN_MAX` makes
  RCE unreachable) both remain claims to test. Network reachability via
  `Content-Encoding: br` is also a claim — this lab exercised the standalone C
  primitive, not a networked server.

## Feasibility and cheapest next step

Tractability **HIGH for rungs 1–3** (done), **MEDIUM for rung 4**: small C
library, exact vulnerable/fixed tags, public patch, no hardware feature
(unlike AVX-512-blocked Java4Shell). The standalone C harness removes Datadog's
"managed runtime stands in the way" obstacle. Remaining obstacles from that
source: heap-layout randomization and the corrupted bytes also being decoder
input. Further offsets (28+) reach the pointer fields (`ringbuffer`,
`htree_command`, `context_map_slice`) — that is the natural rung-4 lane.

Cheapest next rung: extend stage 2 to write chosen bytes through indices 28+
and observe a chosen pointer value in a `BrotliDecoderState*` field; then try
to make a benign marker execute through a redirected read/write. Preserve the
fixed `-17` differential and every negative result.

## Reproduce

```
cd lab/frontier/brotli2shell
bash run.sh          # fetches poc.py + upstream source, builds both tags,
                     # generates pinned streams, runs the differential,
                     # writes logs/ and prints digests
```

All inputs are local files; only provisioning fetches (PoC generator, upstream
source) leave the host. No network probe, no listener, no external target.

## What would change this assessment

- A clean v1.2.0/v1.2.1 differential that failed would break the premise —
  both runs observed, so this would need a contradictory upstream tag.
- A chosen 8-byte value landing in `ringbuffer`/`htree_command` followed by a
  controlled read or write would promote rung 4; marker execution would close
  it.
- A primary source showing the `-17` path was already present in v1.2.0 would
  break the source binding; both tags were independently compiled here.
