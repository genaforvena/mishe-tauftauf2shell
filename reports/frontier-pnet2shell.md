# Frontier brief: p-net — CVE-2026-127122 (pnet2shell)

**Verdict:** SCREENED IN and staged. Rung 3 measured on the real pinned writer
and real pinned `pf_ar_t` layout; rung 4 chosen bytes at a chosen relative index
(direct-call harness scope). No daemon, no wire frame, no command execution; no
rung 5. Ranked above the other 2026 candidates found this wake because the
primitive is chosen bytes, not a NULL pointer or a pattern-derived write, and
the vendor ships a one-hunk fix with exact tags.

## 1. Verified ground truth

| Field | Value |
| --- | --- |
| CVE | CVE-2026-127122, GHSA-9cfr-5cg8-55x5, EUVD-2026-125302 |
| Claim sources | CNA record `https://www.cve.org/CVERecord?id=CVE-2026-127122` (RT-Labs AB, 2026-11-13); vendor advisory `RRTL-261109-01` §3.6 (2026-11-09); release `https://github.com/rtlabs-com/p-net/releases/tag/public/v1.0.4` issue 2692; compare diff `https://github.com/rtlabs-com/p-net/compare/public/v1.0.3...public/v1.0.4.diff` |
| Product | rt-labs p-net, embedded PROFINET device stack (C) |
| Affected | before 1.0.4; vulnerable tag **public/v1.0.3**, commit `19782d52c56640526156f8db04efe93317f9c530` |
| Fixed | tag **public/v1.0.4**, commit `1c3b0b435b2ee2c6cea86849c14ee98f6ee579f1` |
| Claimed primitive | CWE-787: a Connect request with more `PF_BT_MCR_REQ` blocks than `PNET_MAX_MC_CR` (default 1) writes request bytes past `pf_ar_t.mcr_request[]`, first into the rest of the AR and then into following ARs. No established AR and no credentials; attacker needs ADJACENT network access. Builds with `PNET_OPTION_MC_CR=0` are not affected. |
| Scoring | CVSS 4.0 7.2 HIGH, `AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N` |
| PoC status | No public finder writeup or PoC found. Vendor advisory has no "Reported by" line for 3.6. Pre-auth wire reach remains a claim from the advisory and the pinned source, not a locally replayed packet. |

Vendor fix quote: "A Connect request with more MCR request blocks than
PNET_MAX_MC_CR is rejected with 'Wrong block count', before the block is
stored." Technical quote: "The index was the number of blocks received so far,
and it was not checked against the size of the array."

## 2. Source-bound mechanism

`pf_cmrpc.c` case `PF_BT_MCR_REQ` in v1.0.3 passes `p_ar->nbr_mcr` as `ix` to
`pf_get_mcr_request()` and increments it after a successful block, with no
comparison against `PNET_MAX_MC_CR`. The real writer in pinned
`src/device/pf_block_reader.c:785-817` stores eight attacker-controlled scalar
bytes and up to 240 attacker-controlled name bytes plus a NUL into
`p_ar->mcr_request[ix]`. `pf_multicast_cr_t` is 252 bytes in this configuration
(`bool valid` at offset 0, `iocr_reference` at 2, name at 12), so each accepted
block advances the write destination by 252 bytes.

The v1.0.4 fix adds, before the call:

```c
if (!(p_ar->nbr_mcr < PNET_MAX_MC_CR)) {
   LOG_ERROR (PF_RPC_LOG, "CMRPC(%d): Too many MCR given. Max %u MCR per AR supported\n", ...);
   pf_set_error (&p_sess->rpc_result, PNET_ERROR_CODE_CONNECT,
                 PNET_ERROR_DECODE_PNIO, PNET_ERROR_CODE_1_CMRPC,
                 PNET_ERROR_CODE_2_CMRPC_WRONG_BLOCK_COUNT);
   ret = -1;
} else { /* original parse and nbr_mcr++ */ }
```

The writer itself is unchanged; causality is the missing caller check.

## 3. Local experiment performed

`lab/frontier/pnet2shell/harness/harness.c` compiles the **real pinned**
`pf_block_reader.c` from each tarball against the **real pinned** `pf_types.h`
layout. The release tarballs contain no CMake files or external OSAL/PNAL
dependency, so a generated `pnet_options.h` (from the pinned template, with
`PNET_OPTION_MC_CR=1`, `PNET_MAX_MC_CR=1`) and small OSAL/PNAL shims supply only
compile-time configuration and no-op logging; the struct layouts and the
exercised writer are the upstream bytes. The harness models the caller index
and increment from the pinned `pf_cmrpc.c`; the fixed build adds the exact
upstream bound condition (session/RPC error reporting omitted).

Input per block: big-endian `iocr=0x4142`, protocol `0x43`, resolution `0x44`,
timeout `0x4546`, name length 16, name `16*0x5a`. Four cells:

- **Vulnerable ASan**: `heap-buffer-overflow`, `WRITE of size 2`, 0 bytes after
  a 49600-byte `calloc` region, top frame `pf_get_mcr_request
  (pf_block_reader.c:790)` ← `main (harness.c:81)`. Forty blocks walk past the
  `pf_ar_t` allocation. `evidence/norm-vuln-asan.log`.
- **Fixed-caller ASan**: rc=0, no ASan report. `evidence/norm-fixed-asan.log`.
- **Vulnerable plain** (2 blocks, readback): `slot1_offset=252`,
  `iocr=4142 protocol=43 resolution=44 timeout=4546 namelen=16
  name=5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a` read through the real
  `pf_multicast_cr_t` fields at index 1. `evidence/norm-vuln-plain.log`.
- **Fixed-caller plain**: rejects at block 1 with `WRONG_BLOCK_COUNT`; no
  chosen-byte write at index 1. `evidence/norm-fixed-plain.log`.

`bash harness/run.sh` self-extracts both hashes-verified tarballs, builds all
four binaries, runs 11 asserts, normalizes PID/address fields and writes
`EVIDENCE_HASHES.txt`. Two replays, including one after deleting `src/`, all
generated headers and binaries, produced 11/11 passes and four byte-identical
normalized hashes.

## 4. Honest grade

- **Rung 1/2** — deterministic trigger and state failure: yes at harness scope;
  `nbr_mcr` advances without bound and writes walk out of `pf_ar_t`.
- **Rung 3** — ASan-confirmed heap corruption: yes, real pinned writer, WRITE-2
  at the allocation boundary.
- **Rung 4** — chosen bytes at chosen *relative* index: yes at direct-call
  scope. Chosen index is the count of previously accepted blocks (stride 252),
  not an absolute address; no pointer control and no arbitrary-address write.
- **Rung 5** — no. No daemon, no UDP/DCE/RPC frame, no command. The ADJACENT
  pre-auth surface is an advisory claim plus pinned-source observation; the
  required `PNET_OPTION_MC_CR=1` build configuration was chosen explicitly in
  the harness.

## 5. Cheapest next experiment

Build the pinned v1.0.3 stack with its sample application on loopback, enable
`listen-tcp` equivalent for PROFINET management UDP, and replay a canned Connect
request from `test/test_cmrpc.cpp` with two appended `0x0106` MCR blocks under
ASan. Decisive observation: `WRITE of size N` in `pf_get_mcr_request` with
`pf_cmrpc_rm_connect_interpret_ind` in the frame chain, and a v1.0.4 reject with
`WRONG_BLOCK_COUNT` for the same frame. Only after that would pointer control or
a benign marker be worth attempting; neither follows from this evidence.

## 6. Candidates parked this wake

- **rsync CVE-2026-70456 / GHSA-78jc-79jv-v6rw** — network-facing daemon,
  one-slot `argv[argc]=NULL` write; primary sources and fix hunk verified by
  scout, but the bytes are fixed NULL, not chosen. Next candidate if p-net
  stalls.
- **msgpack-c CVE-2026-130065** — one-line `msgpack_vrefbuffer_migrate` fix and
  iovec (pointer+length) overflow; interesting pointer-shaped data, but local
  library API only, no fixed release tag, consumer/wire reach a claim.
- **PCRE2 CVE-2026-86145** — two-line DFA workspace fix and `pcre2test` trigger;
  pattern-derived write, no daemon in the project.
- **Libreswan CVE-2026-94453** — verified primary sources and patches, but UAF
  with no chosen-data write, full pluto IKE state machine required: PARK.
