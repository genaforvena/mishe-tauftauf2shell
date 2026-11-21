# Frontier brief — Gdbserver2Shell

Candidate: **gdbserver `cmd_qtdpsrc` heap overflow**, CVE-2026-121997 /
GHSA-jq36-9pw3-8r4v. Grade: **rungs 1/2/3 ESTABLISHED in an extracted
harness; rung 4 INSTRUMENTED chosen-value control only** (no live gdbserver,
no stock layout, no real RIP control). Produced 2026-11-21 in the frontier
wake starting 00:28Z. This is a research find, not an admission; the operator
decides targets.

## Verified ground truth

- Sources read this wake (read-only provisioning, no off-loopback probe):
  CVE record JSON `https://cveawg.mitre.org/api/cve/CVE-2026-121997`; GHSA API
  `https://api.github.com/advisories/GHSA-jq36-9pw3-8r4v`; Red Hat Bugzilla
  2565679 HTML and XML (`show_bug.cgi?id=2565679&ctype=xml`, comment 0).
  Upstream sourceware gitweb returned HTTP 503 for `gdbserver/tracepoint.cc`
  on every attempt; **no pinned upstream source bytes were obtained**.
- CNA: Red Hat, Inc. Published 2026-11-05, updated 2026-11-06. Title:
  "Gdb: gdbserver: heap buffer overflow in cmd_qtdpsrc via qtdpsrc
  declared/actual length mismatch". CWE-122. CVSS 3.1
  8.1 High `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`. Credit: Pulkit Singh
  Singaria. Reported 2026-10-21, public 2026-11-05.
- Affected: RHEL 6/7/8/9/10 `gdb`, gcc-toolset-14/15-gdb, RHEL Hardened
  Images `gdb`. The CVE record lists Red Hat products, **not upstream gdb
  version numbers** — those stay UNKNOWN. GHSA has no package/version list.
- Claimed primitive (CNA description): "a mismatch between a packet's
  declared source length and the actual data length, causing hex2bin to
  write beyond the allocated heap buffer", allowing "an unauthenticated
  remote attacker to achieve native code execution in the gdbserver
  process." CNA workaround: no mitigation; gdbserver has no authentication;
  exposure is network reachability to its port. CISA ADP: exploitation
  `none`, automatable `no`, technical impact `total`. Treat all as claims.

## Source-bound mechanism (from RHBZ 2565679 comment 0)

Quoted verbatim from the bug comment — the only raw advisory text with the
two decisive lines:

> Heap buffer overflow in cmd_qtdpsrc (gdbserver/tracepoint.cc). The function
> allocates `xmalloc(slen+1)` sized by the packet's declared `slen` field,
> but calls `hex2bin(packet, src, strlen(packet)/2)` using the actual hex
> data length independently. When actual data exceeds declared `slen`,
> `hex2bin` overflows the heap buffer by the difference with
> attacker-controlled content. Demonstrated exploitation: overflow corrupts
> `process_info_private::thread_db`, replacing the `td_ta_map_lwp2thr_p`
> function pointer with an attacker-chosen address. A subsequent
> `qGetTLSAddr` packet causes gdbserver to call through the forged pointer,
> achieving RIP control and native code execution.

Because upstream bytes were unavailable, the harness models exactly those
two operations; it is **not** a build of gdbserver. The declared-vs-actual
mismatch, byte-exact chosen content and the following function-pointer call
are reproduced; the real packet parser, `slen` integer semantics,
`process_info_private` layout and `qGetTLSAddr` dispatch are UNKNOWN here.

## Local evidence

Committed harness: `lab/frontier/gdbserver2shell/{qtdpsrc_overflow.c,run.sh}`.
Replay from clean HEAD: `bash lab/frontier/gdbserver2shell/run.sh out`
→ `ALL CHECKS PASS rc 0`, every `PASS` line present. gcc 13.3.0,
`-fsanitize=address` for the rung-3 binary.

- **Rung 1 (trigger):** declared `slen=8`, 32 actual decoded bytes → 23 OOB
  writes, first at offset 9 (`src[9]=0xa9`), last at 31 (`src[31]=0xbf`).
- **Rung 2 (state failure):** neighbouring `struct process_info_private`
  allocated directly after `src`; `delta=32`, 39 OOB writes. Both
  `td_ta_map_lwp2thr_p` and the `stamp` member change to chosen values
  (`fn_changed=1 stamp_changed=1`).
- **Rung 3 (confirmed corruption):** ASan `heap-buffer-overflow`, `WRITE of
  size 1`, stack `hex2bin` ← `cmd_qtdpsrc` at the exact allocation line.
- **Rung 4 (instrumented only):** an 8-byte chosen address
  (`&benign_marker`) and chosen `0x1122334455667788` stamp land byte-exact
  at their chosen offsets; calling through the overwritten pointer executes
  `MARKER EXECUTED`. This is chosen-value control **in the harness**, not a
  live gdbserver RIP demonstration. No real function pointer, no ASLR/DEP
  bypass, no shellcode.
- **Fixed control:** a `actual > declared` rejection before allocation
  gives `FIXED REJECT`, `src_null=1 oob_writes=0`.

## Feasibility assessment (tractability ranking)

Strengths: unauthenticated network handler; allocation size and source bytes
are both packet-controlled; advisory claims a direct function-pointer
overwrite and a second packet to trigger the call — a short path to rung 4
in a real build. Weaknesses: AC:H; gdbserver is a developer tool, not a
default-on server; upstream source fetch failed this wake, so no stock build
or layout was exercised; the CVE gives no upstream version range, so
provisioning a specific vulnerable tag needs further work. Ranks below the
default-on, PR:N web-server lanes but above speculative protocol-RCE claims.

## Cheapest next rung-producing experiment

Provision an upstream gdb tag via a reachable mirror (sourceware retry,
Debian sources, or a GitHub mirror once identified), then compile the real
`gdbserver/tracepoint.cc` handler into a harness with ASan and observe the
same `slen` mismatch against real `xmalloc`/`hex2bin`. Second step: a live
loopback gdbserver with a crafted `QTDPsrc` packet followed by `qGetTLSAddr`,
checking whether the chosen pointer is actually called in the stock layout.
Until that is done, rung 4 stays INSTRUMENTED-only.

Scope note for the operator: gdbserver is a debugger daemon, not a web server
or language runtime. Proposed under the standing "similar things" mandate
only because the primitive is an unauthenticated remote heap write with
chosen bytes plus a claimed code-execution trigger. No off-loopback probe.
