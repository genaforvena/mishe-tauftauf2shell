# Frontier brief — ATS MIME obs-fold one-byte underflow write (ATS2Shell)

**Status: RANKED CANDIDATE / RUNG 0, not admitted, no window.** Pinned tagged
sources, published checksums, the fix patch and the vulnerable/fixed `MIME.cc`
bytes were verified 2026-11-21; no build, no trigger request, no ASan bytes.
This promotes the first alternate in `reports/frontier-knotresolver2shell.md` to
the pinned-byte standard the operator set in #1074. Ranked **below**
KnotResolver2Shell (814-byte heap OOB write, claimed function-pointer control)
because the byte written here is the fixed value `0x20` and the reachability of
an *allocation* boundary is UNKNOWN without a build.

## Verified ground truth (claim sources, 2026-11-21)

- **CVE record**: CVE-2026-58154, CNA Apache, `PUBLISHED`, datePublished
  2026-07-29T08:24:02.078Z, dateUpdated 2026-10-01T16:58:40.837Z. Exact scoped
  description: "Apache Traffic Server can write out of bounds or overflow
  integers while parsing MIME and HTTP headers. This issue affects Apache
  Traffic Server: from 8.0.0 through 8.1.11, from 9.0.0 through 9.2.14, from
  10.0.0 through 10.1.3. Users are recommended to upgrade to version 9.2.15 or
  10.1.4, which fix the issue." CWE-787, CVSS 3.1 8.9
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:H` (textual severity
  "important"). Records: `https://cveawg.mitre.org/api/cve/CVE-2026-58154`,
  `https://www.cve.org/CVERecord?id=CVE-2026-58154`. The advisory bundles 34
  memory-safety issues, so the high score is not evidence for this one hunk.
- **Vendor**: `https://trafficserver.apache.org/security-2026-07.html` lists
  CVE-2026-58154 under "Memory-safety errors in MIME and header parsing",
  component "Header parsing (MIME)", fixed in 9.2.15 / 10.1.4, reported by
  Michael Bommarito, Apache Community, Omkhar Arasaratnam. Announcement
  `https://lists.apache.org/thread/5prl9glcm9g2swnq9hqxvnokylm1gr6d`; full text
  `https://seclists.org/oss-sec/2026/q3/338` says "9.x users should upgrade to
  9.2.15 or later versions / 10.x users should upgrade to 10.1.4 or later
  versions".
- **Fix**: master commit `f4561a945ac52010a598e0cd19b12d058044c3d2`
  ("Fix out-of-bounds write in MIME obs-fold handling", +49/−3 across
  `src/proxy/hdrs/MIME.cc` and `src/proxy/hdrs/unit_tests/test_Hdrs.cc`); patch
  bytes raw-fetched to `lab/frontier/ats2shell/src/fix-f4561a94.patch`. The
  10.1.x equivalent is `5642692b888fcc9cf26a43ec2f39a05f938c4963`; GitHub
  compare API `5642692b…...10.1.4` returns `status: ahead`, `ahead_by: 128`,
  `behind_by: 0`, merge base equal to the fix commit, so the fix is an ancestor
  of tagged 10.1.4 (`f8be6725daee427fbf88f166f14b10cb5525b220`). The 9.2.x
  line carries the same hunk in the legacy path `proxy/hdrs/MIME.cc` (verified
  by raw reads of 9.2.14 vulnerable / 9.2.15 fixed; those two files are not
  pinned tarballs here).
- **Pins**: two tagged ATS tarballs, their published `.sha512` sidecars and the
  fix patch, exact SHA-256 in `lab/frontier/ats2shell/src/SHA256SUMS`; URL and
  digest table in `lab/frontier/ats2shell/PROVENANCE.md`. `sha512sum -c` on the
  sidecars was 2/2 OK at fetch time. Vulnerable is tagged **10.1.3**, fixed is
  tagged **10.1.4**.

## Source-bound mechanism (raw bytes in the pinned tarballs)

Only `src/proxy/hdrs/MIME.cc` was extracted from each tarball. In vulnerable
10.1.3, `MIMEScanner::get()`'s `MIME_PARSE_AFTER` case at `:2427–2432`:

```
if (ParseRules::is_ws(*text)) { // folded line.
  char *unfold = const_cast<char *>(text.data() - 1);
  *unfold--    = ' ';
  if (ParseRules::is_cr(*unfold)) {
    *unfold = ' ';
  }
```

`text.data()` is the continuation whitespace of a folded header; `unfold`
first addresses the LF at `text.data()-1` and the first store replaces that LF
with `0x20` (in bounds when the LF is inside the current input view). The
post-decrement pointer is then `input.data()-1` when the LF is the *first* byte
of the current input view: the CR check reads one byte before the view and,
if it is CR, the second store writes the same fixed `0x20` there. Fixed 10.1.4
at `:2477–2484` keeps only the in-bounds store and guards the second with
`unfold > input.data()`, falling back to `m_line.back()` when the preceding CR
belongs to the accumulated line:

```
*unfold      = ' ';
if (unfold > input.data() && ParseRules::is_cr(*(unfold - 1))) {
  *(unfold - 1) = ' ';
} else if (!m_line.empty() && ParseRules::is_cr(m_line.back())) {
  m_line.back() = ' ';
}
```

The fix patch adds a two-fragment unit test: first `get()` with
`"Foo: bar\r"` expects `CONT` (state stays `MIME_PARSE_INSIDE`, no LF found),
second `get()` with `"\n baz\r\n"` expects `OK` with `shares_input == false` —
exactly the shape that puts the LF at the start of the second view. The same
patch's NOTE records a limit: when the CRLF falls at the end of an input
buffer, post-loop cleanup (raw 10.1.3 `:2463–2471`) sets `MIME_PARSE_BEFORE`
and returns `OK`, so the fold is lost and this code is not reached. Both facts
bound the trigger to a CR|LF split across parser input views.

## Rung-4 feasibility and ranking

Honest ceiling: this is a **one-byte, fixed-value `0x20` write** one byte before
the current input view, conditional on the preceding byte being CR. Nothing in
the patch gives chosen-byte or pointer control, and no public RCE claim was
found — the advisory covers 34 issues at once. The position is attacker-
influenced (where the CR|LF split lands) but the value is not. If consecutive
parser views are slices of one contiguous IO buffer, address `-1` is the
previous view's CR and the store is in bounds of the allocation; making it an
allocation underflow requires the LF view to begin at an allocation boundary.
Whether ATS's header feeder can produce that shape is **UNKNOWN** without a
build. That, plus the small fixed value, puts it below KnotResolver2Shell and
below a clean chosen-byte heap write. It still merits a bounded harness: a
deterministic `0x20` store into an adjacent heap byte can establish rung 2
(accounting/state failure) and possibly a flag/length-byte control path, and
both tags plus the exact regression input are already pinned.

## Cheapest next experiment

Build the pinned 10.1.3 and 10.1.4 MIMEScanner unit-test targets with ASan
(standing provisioning approval #5), run the patch's two-fragment input
verbatim and record the first failing access and its address relative to the
input view and allocation base. Discriminators: ASan WRITE of size 1 with value
`0x20` at `input.data()-1` on 10.1.3, clean `OK`/`shares_input == false` on
10.1.4 for the same bytes. Only if the address is an allocation boundary, drive
the same CR|LF split through a loopback-only ATS instance with TCP segmentation
at the CR; label any ASLR-off or non-stock configuration. Until bytes are
observed, no rung is claimed and no window should be opened.

## Scope and boundaries

Read-only provisioning of two tagged tarballs, two checksum sidecars and one
patch; no target process was built or run, no traffic off loopback, no other
plant's lane. Trigger reachability through a real network parser, allocation
adjacency, and any security impact are UNKNOWN; the fix's own NOTE limits one
fragment-split class. The CVE/vendor severity and the bundled RCE-class prose
are claims, not lab observations.
