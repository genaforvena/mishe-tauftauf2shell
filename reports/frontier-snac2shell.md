# Frontier brief: snac2 — CVE-2026-112021 (snac2shell)

**Verdict:** SCREENED IN. Rung 3 measured on the real pinned parser; rung 4
chosen-byte writes at direct-call harness scope; no daemon, no wire, no rung 5.
Pinned 2026-11-22. Ranked above the queued pppd candidate because the vulnerable
unit is one single-header parser: the whole before/after experiment is one small
C file and two tarballs.

## 1. Verified ground truth

| Field | Value |
| --- | --- |
| CVE | CVE-2026-112021 |
| Claim sources | VulnCheck CNA record `https://cveawg.mitre.org/api/cve/CVE-2026-112021` (PUBLISHED 2026-10-18); NVD `https://nvd.nist.gov/vuln/detail/cve-2026-112021` (Deferred, same text); GHSA-6hv3-2r7g-774j (Unreviewed); finder writeup `https://nullenvk.pl/posts/02-snac2-json/`; public PoC gist `https://gist.github.com/nullenvk/2bf288e2d34cb3d4b7143e61dbf7d90b` |
| Product | snac2 (grunfink's ActivityPub daemon, portable C, Codeberg) |
| Affected | all versions < 2.93 (CNA: version 0, lessThan 2.93). Vulnerable tag **2.92**, commit `3d2af2ef63e0b79b0b4fe5398928291df9cb8c24` |
| Fixed | tag **2.93**, commit `795355acb496a8a8f015a80edf48f38786894f86`; fix commit `ec2c5c2046e0381bc942ec5d0d05ec861fe377e7` (2026-06-25) |
| Claimed primitive | Heap-based buffer overflow (CWE-122) in `_xs_json_load_lexer()`: a JSON `\u0000` escape decodes to a literal NUL, so `xs_size()`/`strlen()` undercounts on each subsequent `xs_expand()`/`xs_insert_m()`, and the following characters are written past the heap allocation. A single pre-auth `application/activity+json` POST reaches the parser in `activitypub_post_handler()` before signature checking. Claimed impact: unauthenticated remote crash/DoS. |
| Scoring | CVSS 4.0 AV:N/AC:L/AT:N/PR:N/UI:N/VA:H = 8.7 High; CVSS 3.1 = 7.5 High. CISA SSVC Exploitation=poc, Automatable=yes, Technical Impact=partial. |
| Reachability claim status | Pre-auth parse site is visible in the pinned 2.92 source (`activitypub.c`: content-type check then `xs_json_loads(payload)` before the signature check). No daemon was built and no HTTP packet was sent here, so the wire-to-crash chain remains a claim. |

## 2. Source-bound mechanism (from the pinned fix, not from prose)

The fix is one line in `xs_json.h:283`; both pinned files were fetched and read:

```c
/* vulnerable pin, tag 2.92 */
if (cp < ' ' && !strchr("\r\n\t", cp))
    cp += 0x2400;
/* fixed pin, tag 2.93 */
if (cp == 0 || (cp < ' ' && !strchr("\r\n\t", cp)))
    cp += 0x2400;
```

`strchr("\r\n\t", 0)` returns a pointer to the string's terminator, so cp=0 is
*not* remapped in 2.92. The NUL is inserted via `xs_utf8_insert()` at
`xs_json.h:291`; each following ordinary character goes through `xs_insert_m()`
(`xs.h:467`), which calls `xs_expand()`. `xs_expand()` sizes the reallocation
with `xs_size(data)`, and for strings that is `strlen(data) + 1` — which stops
at the embedded NUL. The allocation never grows, while `offset` keeps
increasing: `memcpy(data + offset, mem, size)` at `xs.h:469` walks off the end.
In 2.93 the NUL becomes U+2400 (three UTF-8 bytes, no embedded zero), `strlen`
sees the growth, and the reallocation keeps pace.

## 3. Cheapest local experiment (performed this wake)

`lab/frontier/snac2shell/harness/parse_json.c` compiles the **real pinned
single-header parser** (no reimplementation): plain `cc -g -O0` and
`-fsanitize=address` builds against both tag 2.92 and tag 2.93 trees.
Input is the finder's exact JSON bytes with the post-NUL characters chosen:
`["", "dummy\u0000` + 80×marker + `", ""]`, markers `0x41` and `0x5a`.

- **Vulnerable ASan** (both markers):
  `AddressSanitizer: heap-buffer-overflow`, `WRITE of size 1`, `0 bytes after
  32-byte region`, frames `xs_insert_m (xs.h:469)` ← `_xs_json_load_lexer
  (xs_json.h:302)` ← `xs_json_load_full (xs_json.h:569)`. `out-vuln-asan/{41,5a}.log`.
- **Fixed ASan** (both markers): `rc=0`, `parsed=0x…`, no report. `out-fixed-asan/`.
- **Plain vulnerable + gdb readback** (break at `xs_insert_m`, print
  `offset`, `malloc_usable_size(data)`, `*(unsigned char*)mem`): 46 writes per
  marker at offsets 40..85 with `usable=40` and `byte=0x41` / `0x5a`
  — chosen value at chosen offset, past the usable allocation. `out-vuln-plain/`.
- **Plain fixed + gdb**: the allocation grows from usable 40 to 72 at offset 31
  (the U+2400 encoding is now visible to `strlen`); **zero** writes at or past
  the usable size. `out-fixed-plain/`.

`bash harness/run.sh` rebuilds from the pinned sources, runs all four matrix
cells, asserts the ASan and readback conditions, normalizes PIDs/addresses/paths
and writes `EVIDENCE_HASHES.txt` and `PIN_HASHES.txt`. Two back-to-back replays
produced identical normalized hashes.

## 4. Rung-4 feasibility and honest grade

- **Rung 1/2** — reproducible trigger and observed state failure: yes.
  Vulnerable rc=1 with ASan report; fixed rc=0; plain vulnerable shows offsets
  past the usable allocation, fixed shows the allocation growing in step.
- **Rung 3** — ASan-confirmed corruption: yes, WRITE-1 at the exact
  `xs_insert_m` memcpy in the real pinned parser.
- **Rung 4** — chosen bytes at chosen offsets: yes at **direct-call harness
  scope** (gdb readback of the chosen 0x41/0x5a at offsets 40..85). The value
  comes straight from the JSON string; the offset is the running insert offset.
- **Rung 5** — no. No daemon, no listener, no HTTP request. The pre-auth POST
  reach and the finder's "needs an info leak to defeat ASLR/safe-linking"
  ceiling remain claims. The finder explicitly did not demonstrate RCE; the
  PoC gist's tcache target is marked unused. Do not upgrade the availability-
  only CVSS into a code-execution claim.

## 5. Next experiment that would move it up a rung

Build the pinned 2.92 `snac` daemon and send the finder's single
`Content-Type: application/activity+json` POST to 127.0.0.1 under ASan; the
decisive observation is a WRITE-1 whose frame chain includes
`activitypub_post_handler` → `xs_json_loads` → `_xs_json_load_lexer` →
`xs_insert_m`. If the wire path reproduces cleanly and 2.93 rejects it, the
candidate's honest grade is rung 4 on a live loopback process; a rung-5 attempt
would still need an independent ASLR/safe-linking bypass and is not warranted
from this evidence alone.

## 6. Candidates parked, not worked this wake

- **pppd CVE-2026-85495** — verified on primary sources (upstream GHSA-frhv-j822-
  2pvx; fix commits `cc8b00c96646f858fbd4e2699077701c72ef9e1c` and
  `1baf2ac29e4456f095c4ebe15230881201ce4ffb`, shipped in v2.5.4). Pre-auth
  LCP Configure-NAK 4→5 amplification into `nak_buffer[1500]` in `.bss`, chosen
  count drives a multi-byte write. Pins were fetched locally to
  `lab/frontier/pppd2shell/pins/` (gitignored, not staged; v2.5.3 `96f962b9…`,
  v2.5.4 `379a630a…`) but no harness was built: the advisory
  links no PoC code and the FSM/config preconditions (CHAP-only, usable secret,
  REQSENT) make it the more expensive next candidate. MITRE record is still
  RESERVED and NVD has no record.
- Libreswan CVE-2026-94453 (pre-auth pluto UAF, needs `listen-tcp=yes`), P-Net
  CVE-2026-127122 (adjacent PROFINET chosen write), H2O/FRR/llama.cpp remain
  queued below these two.
