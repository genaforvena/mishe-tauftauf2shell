# Frontier brief — iperf2Shell

Candidate: **iperf3 `decrypt_rsa_message()` oversized-authtoken heap overflow**,
CVE-2026-101283 / GHSA-pwcx-5qh6-2pxc. Grade: **rungs 1/2/3 ESTABLISHED in a
harness that compiles the real pinned upstream `iperf_auth.c`; rung 4
INSTRUMENTED chosen-byte control only** (no live stock iperf3 process, no
useful-pointer control in the real binary). Produced 2026-11-21 in the frontier
wake starting 01:56Z. This is a research find, not an admission; the operator
decides targets.

Why this candidate is worth a dedicated mind: affected (`3.20`, `3.21`) and
fixed (`3.22`) **releases are pinned**, the **fix commit is pinned and its
one-line patch matches the CVE text exactly**, vulnerable and fixed **source
bytes are pinned**, and the advisory claims unauthenticated network
reachability with full C/I/A impact (CVSS 4.0 9.2 Critical). Those are the same
conditions whose absence held gdbserver2shell.

## Verified ground truth

- Sources read this wake (read-only provisioning; no off-loopback probe): the
  authoritative cvelistV5 JSON at
  `https://cveawg.mitre.org/api/cve/CVE-2026-101283`, the GitHub advisory API
  at `https://api.github.com/advisories/GHSA-pwcx-5qh6-2pxc`, the esnet/iperf
  `3.22` release page and its tag commit `926bd905501b792bd082d2200d1d1a84aa543e3a`,
  the fix commit API, and raw `iperf_auth.c` at tags `3.20`, `3.21`, `3.22`.
  Hashes, URLs and the preserved source discrepancy are in
  `lab/frontier/iperf2shell/PROVENANCE.md`.
- CNA Anthropic (with Ada Logics as analyst), published 2026-09-30. CWE-122
  heap-based buffer overflow. CVSS 4.0
  `AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` — 9.2 Critical.
  Affected versions are listed explicitly as 3.20 and 3.21; fixed in 3.22
  (released 2026-09-29).
- Claimed primitive (CVE text): a 256-byte RSA buffer is `BIO_read` with the
  attacker-controlled ciphertext length — the guard only warns — so an
  unauthenticated client overflows the heap through an oversized authtoken.
- Precondition worth stating plainly: the server must run with an RSA private
  key configured (authentication enabled). The overflow is still *pre-auth*:
  the oversized token is the very input being parsed, not a credential that
  must first succeed. Scope note: iperf3 is a C network-listening daemon, an
  X2Shell-class extension under the same precedent that admitted other
  non-HTTP daemons. Operator decides admission.
- **Conflicting claim preserved**: the 3.22 release notes call CVE-2026-101283
  a "remote use-after-free in iperf_server_api.c (ANT-2026-E5BA80X9)" and list
  a separate CVE-2026-101276 as the `iperf_auth.c` heap overflow. The CVE
  record, GHSA and the exact fix commit all point at `decrypt_rsa_message()`;
  the release-note label is recorded, not silently corrected.

## Source-bound mechanism

Verbatim from pinned `src/iperf_auth.c.3.21`, `decrypt_rsa_message()` (lines
316–324):

```c
if (encryptedtext_len > output_buffer_len) {
    fprintf(stderr, "Encrypted text of size %d truncated to %d; likely invalid input.\n",
            encryptedtext_len, output_buffer_len);
}                                        /* warn only — execution continues */
rsa_buffer  = OPENSSL_malloc(output_buffer_len);   /* 256 bytes, RSA-2048 */
*plaintext = (unsigned char*)OPENSSL_malloc(output_buffer_len + 1);
BIO *bioBuff = BIO_new_mem_buf((void*)encryptedtext, encryptedtext_len);
rsa_buffer_len = BIO_read(bioBuff, rsa_buffer, encryptedtext_len);
```

`output_buffer_len` comes from `OSSL_PKEY_PARAM_MAX_SIZE` (256 for RSA-2048).
`encryptedtext_len` is the decoded length of the client's base64 `authtoken`.
The guard prints a warning but does not return, so `BIO_read` copies
`encryptedtext_len` bytes into a 256-byte heap allocation. The attacker chooses
both the overflow length and the bytes.

Trigger path pinned at tag 3.21: `iperf_api.c:2654-2655` copies the client JSON
`"authtoken"` into `test->settings->authtoken`; `iperf_api.c:2318-2321` calls
`decode_auth_setting()` on the server; `iperf_auth.c:392-400` base64-decodes it
and calls `decrypt_rsa_message()` with the decoded length.

The fix commit `d08588aceee48fa45832cae5e32616abb33cb0fc` ("Fix for possible
heap buffer overflow in iperf_auth.c.", 2026-07-10) changes exactly that guard:

```diff
-        fprintf(stderr, "Encrypted text of size %d truncated to %d; likely invalid input.\n", ...);
+        fprintf(stderr, "Encrypted text of size %d exceeds RSA modulus %d; rejecting.\n", ...);
+        goto errreturn;   /* or: return 0; — never read more than output_buffer_len bytes */
```

Pinned tag `3.22` carries that `goto errreturn`; tags `3.20` and `3.21` carry
the warn-only guard (all three hashed in `PROVENANCE.md`).

## Local evidence

Harness: `lab/frontier/iperf2shell/{driver.c,iperf_config.h,run.sh}` plus pinned
`src/` bytes and `PROVENANCE.md`. Unlike a reimplementation, `run.sh` compiles
the **real pinned upstream `iperf_auth.c`** at 3.21 and 3.22; the driver only
generates a real RSA-2048 key, builds an oversized decoded token with chosen
bytes, and calls `decrypt_rsa_message()`. Clean replay from committed HEAD:

```
bash lab/frontier/iperf2shell/run.sh <outdir>
-> 17 PASS lines, ALL CHECKS PASS rc 0
   sha256=bd3efc4cb4720e7fe5cc2e83e79cc7e89010f75a7e93579360a215eb5f029caf
```

That hash is over a deterministic trace (`<outdir>/trace.txt`) with ASan
PID/address/path text excluded. Three independent replays were byte-identical
(explicitly avoiding the unreproducible-log problem from the gdbserver find).
gcc 13.3.0, OpenSSL 3.0.13, `-O0 -g`.

- Rung 1 — deterministic trigger: decoded length 336 against a 256-byte
  modulus; `oob_bytes=80`; the warn-only line is observed; ASan reports
  `WRITE of size 336` starting exactly 0 bytes after the 256-byte region.
- Rung 2 — observed state failure: the plain (non-ASan) build's OOB run corrupts
  the next heap chunk's metadata; glibc aborts with `free(): invalid size` at
  the function's `OPENSSL_free`. The allocator itself detects the corrupted
  accounting; no claim of useful-pointer control is made from this.
- Rung 3 — ASan `heap-buffer-overflow`, `WRITE of size 336`, frame
  `BIO_read` ← `decrypt_rsa_message` at the pinned upstream
  `iperf_auth.c.3.21:324`, allocation at `:319` (256 bytes).
- Rung 4 — chosen bytes `IPERF2SHELL!` (`49504552…`) at offset +8 and
  `0x1122334455667788` at offset +48 past the 256-byte boundary are supplied
  in the write buffer; ASan proves that exact 336-byte write crosses the
  boundary. **INSTRUMENTED only** — no live stock iperf3 process and no
  pointer-value control in the real binary.
- Fixed control: the same 336-byte token is rejected before `BIO_read` by the
  pinned 3.22 rule (`exceeds RSA modulus 256; rejecting`); the adjacent
  allocation stays clean (`plaintext_null=1`).

## Rung-4 feasibility

Favourable: the overflow length and every overflowed byte are attacker-chosen
and cross a heap-allocation boundary; the primitive is a pre-auth network
input; a fixed release and an exact patch pin the intended semantics. A real
OpenSSL 3 `BIO_read` → `memcpy` is the confirmed write consumer, so the
nginx-plant lesson (structural zero-store consumer) does not apply here — the
write is a real, byte-exact `memcpy`.

Unfavourable / UNKNOWN: the real 3.21 process's heap layout, allocator, OpenSSL
build, and the layout of `process_info`-adjacent heap objects are UNKNOWN here;
the server must run with auth enabled (non-default configuration); whether the
overflow can reach a heap metadata pointer, a function pointer, or a
`FILE*`/vtable in a stock build is UNKNOWN and must be measured. The advisory
claims native code execution but publishes no exploit; treat that as a claim.

## Cheapest experiment to move a rung

Build pinned iperf3 `3.21` with `--enable-openssl` and ASan, start `iperf3 -s`
on 127.0.0.1 with an RSA private key, and send a normal client setup whose
JSON `"authtoken"` is a long base64 blob. Observe the ASan report in the real
server path (`iperf_api.c:2654` → `decode_auth_setting` → `decrypt_rsa_message`)
and whether the chosen bytes reach an adjacent heap object's function pointer
or allocator metadata. A positive result moves rung 4 from instrumented to
real-process chosen-value control; a negative result is a structural blocker
worth recording.

## Failed hypotheses and negatives

- The first plain-build replay expected `rc 0` and a byte-exact readback from
  the adjacent `plaintext` allocation. Instead the process aborted at
  `free(): invalid size` before the readback. Diagnosed as the OOB run
  overwriting the next chunk's metadata; the abort is now a rung-2 check and
  no readback claim is made. No claim was published from failing runs.
- Recoverable ASan (`-fsanitize-recover=address`, `halt_on_error=0`) did let the
  process continue, but redzones put the chosen bytes in ASan poison rather
  than the adjacent object, so `marker_at=-1`. That route was discarded rather
  than reported as chosen-byte control.
- A `61826865…`-style unreproducible log hash was deliberately avoided: the
  trace hash excludes ASan text and was verified byte-identical three times.
- No live iperf3 process, no stock layout, no real useful-pointer control.

## Next owner

Witness re-runs the replay; operator decides admission. If admitted, the new
target mind owns the real-build experiment above; frontier does not duplicate
that lane.
