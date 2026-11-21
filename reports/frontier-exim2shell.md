# Exim2Shell — frontier brief: CVE-2026-45185 (BDAT/GnuTLS one-byte UAF write)

**State: RANKED CANDIDATE / RUNG 0 (no local build, no traffic, no window).**
Scouted and source-pinned read-only in W86 (2026-11-21). Not admitted; the operator
owns admission. Nothing here is an independent acceptance — the witness re-runs
any published claim. Ranked **above** ATS CVE-2026-58154: same one-byte-write
shape, but a public exploit narrative demonstrates the downstream allocator
escalation, and the fixed tag and fix hunk are pinned byte-for-byte.

## Verified ground truth

- **Claim source (primary, read this wake):**
  - Vendor advisory `https://www.exim.org/static/doc/security/CVE-2026-45185/EXIM-Security-2026-05-01.1.txt`:
    "Affects: Exim 4.97 up to and including 4.99.2", "Corrected: Exim 4.99.3",
    "Type: Remote Use-After-Free (UAF)", "Severity: Critical (CVSS 9.8)",
    reporter federic.kirschbaum@xbow.com, announced 2026-05-12. It states the
    trigger: a TLS `close_notify` mid-BDAT from a CHUNKING client, then a final
    cleartext byte on the same TCP connection; the fix "ensures that the input
    processing stack is cleanly reset when a TLS close notification is received
    during an active BDAT transfer".
  - MITRE CVE record (CNA MITRE, published/updated 2026-05-12, CWE-416,
    `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, 9.8): "Exim before 4.99.3,
    in certain GnuTLS configurations, has a remotely reachable use-after-free in
    the BDAT body parsing path ... An unauthenticated network attacker exploiting
    this vulnerability could execute arbitrary code." Range: affected 4.97 to
    before 4.99.3. Only `USE_GNUTLS=yes` builds; OpenSSL/other TLS not affected.
  - Exploit narrative (claim, not fact): Federico Kirschbaum,
    `https://xbow.com/blog/dead-letter-cve-2026-45185-xbow-found-rce-exim`
    (2026-05-12). Read this wake (all 1023 lines). Also oss-security
    `/2026/05/12/4` located but page body not retrieved — do not treat as read.
- **Claimed primitive:** During `read_message_bdat_smtp()`, GnuTLS end-of-record
  (`inbytes == 0`) frees the 4096-byte `xfer_buffer` via `tls_close()` while the
  nested `bdat_*` receive layer is still installed. The next cleartext byte
  reaches the stale `tls_ungetc()` and writes one `\n` (0x0A) at
  `xfer_buffer[--lwm]` — one byte into freed heap metadata. XBOW claims
  escalation by corrupting a glibc largebin pointer or an Exim `storeblock`
  length field (e.g. `0x1fe0` → `0xa1fe0`), then FSOP/setcontext to RCE. Real
  (ASLR-on, PIE-on) production build: only a **stack-address leak** was
  demonstrated; full RCE was on ASLR-off, non-PIE CTF builds. Treat the RCE as
  a claim under labeled conditions, not an observed fact.

## Pinned source (raw bytes, verified this wake)

- Vulnerable release tarball `exim-4.99.2.tar.gz`, sha256
  `e9e33c8cde9dddc117eaab40ae529ed703537b14e1257a06b98460738f75da84`.
- Fixed release tarball `exim-4.99.3.tar.gz`, sha256
  `714efe07930ec902224c62c86d446a85b1ee341abdd6c76699949d4de2b52524`.
- Both fetched from `https://code.exim.org/exim/exim/releases/download/exim-<ver>/exim-<ver>.tar.gz`
  (HTTP 200; the `ftp.exim.org` and `downloads.exim.org` paths 404). SHA256SUMS
  written to `lab/frontier/exim2shell/src/SHA256SUMS`. No published sidecar
  hashes checked — the advisory page has no hash table; this is our own hashing.
- Full release-to-release source diff is small: `doc/*`, `src/functions.h`,
  `src/smtp_in.c`, `src/tls-gnu.c`, `src/tls-openssl.c`, `src/version.*`.
  The relevant hunks (from `diff -u exim-4.99.2/src/... exim-4.99.3/src/...`):

  `src/tls-gnu.c`, hunk `@@ -636,7 +636,7 @@` (TLS_EOF branch inside
  `tls_refill()`): 4.99.2 line 639 `tls_close(NULL, TLS_NO_SHUTDOWN);`
  → 4.99.3 `tls_close_notify();`. (Two other hunks in that file are whitespace.)

  `src/smtp_in.c` adds, at `@@ -971,6 +984,32 @@`:

      #ifndef DISABLE_TLS
      /* The TLS layer has received a Close notification alert ... pop the bdat
         layer, reset to plaintext processing then re-push the bdat layer ... */
      void
      tls_close_notify(void)
      {
      if (chunking_state > CHUNKING_OFFERED)
        {
        bdat_pop_receive_functions();
        smtp_rcv_cleartext();
        bdat_push_receive_functions();
        }
      tls_close(NULL, TLS_NO_SHUTDOWN);
      }
      #endif

  and a new helper `smtp_rcv_cleartext()` at `@@ -720,6 +720,18 @@` that resets
  `receive_getc/getbuf/get_cache/hasc/ungetc/feof/ferror` to the `smtp_*`
  plaintext functions; the old inline reset block at 4.99.2 `:2432-2440`
  becomes a call to it. Net effect: in 4.99.2 the stale `tls_ungetc` survives
  the free; in 4.99.3 the receive stack is restored to plaintext before the
  free, so the cleartext final byte cannot write into the freed buffer.
- **Exact commit ID / branch ancestry: UNKNOWN** — only release tarballs were
  fetched (a Gitea commit hash was not pinned this wake). Do not present a
  commit hash for this fix.
- **Line numbers are from raw pinned 4.99.2/4.99.3 tarballs**, not rendered
  source; the XBOW blog's quoted line numbers/labels are claims.

## Rung-4 feasibility assessment

- **Rung 1 (reproducible trigger):** cheap and high confidence. Needs an Exim
  `USE_GNUTLS=yes` build, a loopback SMTP listener, STARTTLS, `BDAT` with
  `chunking_data_left > 0`, then a TLS close_notify followed by one cleartext
  byte. No special server config per the vendor advisory and blog.
- **Rung 2/3 (state failure / ASan):** an ASan build should flag the one-byte
  write at `tls_ungetc` into the freed `xfer_buffer`. Main unknown: whether the
  stale-write window is reachable in a current distro build — the blog notes a
  version-dependent allocation order change (older Debian 4.97 allocates
  `xfer_buffer` after `verify_certificate`; newer builds the other way), which
  changes geometry but not the stale free/use sequence itself. UNKNOWN until
  replayed.
- **Rung 4 (demonstrated impact):** the public narrative documents allocator-
  metadata corruption → controlled allocation → FILE/vtable overwrite →
  setcontext ROP, but only with ASLR off / non-PIE; the real production build
  yielded a stack leak. The plant's rung-4 ladder counts "chosen bytes at
  chosen offsets; pointer control; benign marker execution" in the lab build,
  so the honest target is: reproduce the one-byte write under ASan, then show a
  benign marker at a chosen allocator-metadata offset. That is a plausible
  local path, not a claim of RCE. Biggest risk: glibc/hardening differences on
  this host may make the byte land in an unusable position — the plant's own
  standing lesson (nginx2root) is to measure the consumer's actual behavior
  before investing in grooming.
- **Ranking:** above ATS (one-byte fixed-value write with no published
  escalation path), below an already-admitted dedicated-target lane. Cheap to
  test; requires only GnuTLS dev headers and an SMTP client.

## Cheapest local experiment to move up a rung

Build Exim 4.99.2 with `USE_GNUTLS=yes` and ASan, bind a 127.0.0.1 SMTP
listener, drive STARTTLS → `BDAT <n>` with fewer than `n` body bytes →
`close_notify` → one cleartext byte. Expect an ASan heap-use-after-free WRITE
of a single byte in `tls_ungetc()`. Then replay the same input against a
4.99.3 build and confirm the write is gone (plaintext receive stack restored).
No off-loopback probing; no external targets. Keep all artifacts under
`lab/frontier/exim2shell/`.

## Negative results / unknowns preserved

- Published hashes for the tarballs: none located; our sha256 values are
  self-computed, not vendor-signed.
- No local build, no ASan report, no traffic, no chosen-byte control observed.
- The XBOW RCE claim is external narrative, not verified here; ASLR-off / CTF
  conditions must stay labeled if reused.
- `oss-security /2026/05/12/4` not fully read (body not retrieved); the vendor
  advisory and MITRE record are the primary ground truth used.
