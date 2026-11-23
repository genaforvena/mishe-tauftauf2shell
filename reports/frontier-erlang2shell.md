# Frontier brief — Erlang2Shell (candidate)

Candidate: **Erlang OTP erts `LARGE_TUPLE_EXT` arity signed/unsigned mismatch**,
CVE-2026-55737 / GHSA-446w-268v-9462. Grade: **rungs 1/2/3 ESTABLISHED in an
extracted harness; rung 4 INSTRUMENTED chosen-value control only** (no BEAM
build, no live VM, no network, no control-flow hijack). Produced 2026-11-23 in
the frontier wake starting 01:17:53Z. This is a research find, not an
admission; the operator decides targets. Harness and pins:
`lab/frontier/erlang2shell/`, provenance in `PROVENANCE.md`.

## Verified ground truth

- Sources read this wake (read-only provisioning, no off-loopback probe):
  MITRE CVE JSON, EEF CNA page, GitHub vendor advisory HTML, the fix commit
  and its `.patch`, pinned raw `external.c` / `erl_term.h` at the fix and its
  parent. The CraftedSignal feed item was the discovery lead only. The GHSA
  JSON API returned 404; the HTML advisory was authoritative.
- CNA: Erlang Ecosystem Foundation. Published 2026-07-27, updated
  2026-11-20. Title "Heap pointer corruption via signed/unsigned mismatch in
  LARGE_TUPLE_EXT decoding in erts external term format decoder". CWE-195
  (signed→unsigned) + CWE-787 (OOB write), CAPEC-92.
  CVSS 4.0 **5.1 MEDIUM, `AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L`**.
  The third-party feed's "HIGH 7.5" is a different scoring source; the
  plant records the CNA vector. Credit: Nick Gunn (finder), Kiko
  Fernandez-Reyes (remediation developer), Sverker Eriksson (reviewer).
- Affected: OTP from 25.0 before 27.3.4.15 / 28.5.0.4 / 29.0.4; erts from
  13.0 before 15.2.7.11 / 16.4.0.4 / 17.0.4. Git range
  `ebcbb97b4ec223464cac3d94375739a248ddef6e` <
  `c5210b42a9d3d96f3d25601942ce8122be0f3761`.
- Claimed primitive (CNA): a caller supplying a crafted external-term-format
  (ETF) binary to `binary_to_term/1,2` makes `decoded_size()` read the 32-bit
  tuple arity as unsigned (`get_uint32()`) while `dec_term()` reads the same
  bytes as signed (`get_int32()`); wire `0x80000000` validates as 2147483648
  and decodes as −2147483648, so `hp += n` moves the BEAM heap pointer
  backwards. Neither pass enforces `MAX_ARITYVAL`. The CNA says the VM
  usually detects an impossible heap size and aborts (DoS); it claims the
  padding is large uncompressed but small on the wire via a compressed-ETF
  envelope. AV:L means the CNA does **not** claim a network attack vector;
  reachability from a network-facing distributed-Erlang listener is UNKNOWN.
  All impact language beyond the heap-pointer corruption stays a claim.

## Source-bound mechanism (pinned bytes and fix hunk)

Pinned `external.c` at the fix parent `c388a2d1` (SHA-256
`39afd73a…3098549`) and at the fix `c5210b42` (`53fb1c2e…28ac457`); the
diff is exactly the 5-line patch. At `external.c:4467` the vulnerable decode
pass is `n = get_int32(ep)` into `int n`; after `*hp++ = make_arityval(n)`,
`hp += n` (`:4485`) and `objp = hp - 1`. At `:5211` the function commits
`factory->hp = hp` — the corrupted pointer becomes the process allocator's
next write position. The validation pass at `:6041` reads `n = get_uint32(ep)`
into `Uint n`, then `CHKSIZE(n)` and `heap_size += n + 1` with no cap.
`ERTS_MAX_TUPLE_SIZE == MAX_ARITYVAL == (1<<24)-1` (`erl_term.h:314–315`).

The fix adds `if (n > ERTS_MAX_TUPLE_SIZE) goto error;` in `decoded_size()`
plus a debug `ASSERT(n > 0 && n <= ERTS_MAX_TUPLE_SIZE)` in `dec_term()`.
The rejection is in the validation pass; the ASSERT is not a runtime guard.

## Local evidence

Committed harness: `lab/frontier/erlang2shell/harness/{driver.c,run.sh}`.
Replay from the working tree and from a clean `/tmp` copy both give
`PASS=60 FAIL=0`, normalized trace SHA-256
`8517d3e127b0b6ded35b030fea3f6728ac1e7e34416a8c65efab21feece06c88`.
gcc 13.3.0 and clang ASan; every run re-extracts the four verbatim slices
and asserts all four source/patch hashes plus four slice hashes plus a
driver hash.

- **Rung 1 (trigger):** advisory wire `0x80000000` → unsigned 2147483648,
  signed −2147483648, `hp += n` = −17,179,869,184 bytes; vulnerable
  `decoded_size` returns 2147483649 words, fixed variant returns −1 (reject).
- **Rung 2 (state failure):** with high-bit arities −2, −3, −4 and −8 words
  (wire `0xfffffffe`, `0xfffffffd`, `0xfffffffc`, `0xfffffff8`) the committed
  `factory->hp` lands 1, 2, 3 and 7 words before the heap base in a plain
  mmap arena; the 0xEE canary at each chosen offset is read back as the
  chosen word.
- **Rung 3 (ASan):** gcc and clang both report `heap-buffer-overflow`,
  `WRITE of size 8`, `8 bytes before 64-byte region` in
  `model_consumer_write` ← `main`; the write is at the corrupted `hp`.
- **Rung 4 (instrumented only):** chosen 8-byte Eterm `0x4141414141414141`
  lands byte-exact at the four chosen negative offsets (32760, 32752,
  32744, 32712 in the arena); a second chosen value lands under ASan. This
  is chosen-offset/chosen-value control in the direct-call harness, **not** a
  live BEAM demonstration, pointer control, or command execution.
- **Controls:** fixed variant rejects the backward arity, skips the write and
  is ASan-clean; small positive arity 3 writes in bounds, leaves the
  preceding canary at 0xEE and is ASan-clean on both builds.

## Feasibility assessment (tractability ranking)

Tractable as a staged target: open-source runtime, upstream fix pinned and
five lines, both vulnerable and fixed raw bytes hash-pinned, and the fault
statements are short enough to extract verbatim. Higher rung-4 depth needs a
real build, not a better harness: the next step is a pinned `OTP-28.5.0.3`
erts ASan build with an Erlang driver calling `binary_to_term/1` on the
crafted ETF (compressed envelope for the padding), checking whether ASan
sees a heap-buffer-overflow at the `hp += n` consumer and whether chosen
bytes reach a chosen offset before the heap. Cheapest network-relevance test
is a read-only source check of whether distributed-Erlang message decode
calls `binary_to_term/2` on attacker-supplied ETF before any authentication;
the CNA's AV:L says do not assume it. No rung-5 claim is in scope: the CNA
itself describes an abort/DoS, not code execution, and this lab has no
grooming or control-flow evidence.

## Disposition / handoff

Staged as its own target mind on 2026-11-23 (brief, charter/seed wall,
two-pane window, registry, operator DM). Frontier owns no further work on
this target. Mind-changers: consumer writes only into poison with no
reachable object (measured ceiling), no real caller reaches the branch, or
the fix patch proves inapplicable to a shipped release.
