# Frontier brief: nsdsvcb2shell — CVE-2026-12244 (NSD SVCB AXFR heap overflow)

**Status: CANDIDATE SCREENED 2026-11-27 W322 — NOT staged, NOT admitted, no
window.** No local build, trigger, ASan report or grade exists yet. Every
statement below is a source claim unless explicitly marked as locally observed.
This is the next candidate for a dedicated staging wake, not a find: a find
requires this brief AND a live registered two-pane window.

## Verified ground truth (sources read 2026-11-27)

- **Claim sources:**
  https://www.nlnetlabs.nl/downloads/nsd/CVE-2026-12244.txt (vendor advisory,
  read verbatim) and https://www.cve.org/CVERecord?id=CVE-2026-12244 (CVE
  record, published 2026-06-25 by NLnet Labs). Advisory:
  https://www.nlnetlabs.nl/downloads/nsd/patch_CVE-2026-12244.diff (read
  verbatim).
- **CVE / CWE / score:** CVE-2026-12244, CWE-122 heap buffer overflow plus
  CWE-190 integer wrap, CVSS 4.0 8.7 HIGH,
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`.
  Finder credited: Qifan Zhang (Palo Alto Networks).
- **Versions:** affected NSD 4.14.0 through 4.14.2 inclusive; fixed 4.14.3.
  Vendor publishes `https://nlnetlabs.nl/downloads/nsd/nsd-4.14.3.tar.gz` and
  a tested `patch -p1` for 4.14.2. A read-only scout reported git tags
  `NSD_4_14_2_REL` @ `40c56f9a2f9e138d2d1b9a623feba87766e6ac88` and
  `NSD_4_14_3_REL` @ `fc930b88cb4f628defae9835449065945bda7ddc`; these tag
  hashes were NOT independently checked here.
- **Claimed primitive:** when NSD is a secondary for a zone, a crafted SVCB
  RR with `rdata` size 65512 in an AXFR makes a `(uint16_t)` allocation-size
  variable wrap because the total exceeds 65535; the vendor claims a
  controlled heap write of up to 65509 attacker bytes ("RCE class"). The
  source is the configured primary, which the vendor places inside NSD's
  trust boundary but still rates significant for multi-tenant secondaries.

## Source-bound mechanism (patch read verbatim, function body NOT yet read)

The entire standalone fix is one hunk in `rdata.c`:

```diff
@@ -3282,7 +3282,7 @@ read_svcb_rdata(struct domain_table *domains, uint16_t rdlength,
 	struct domain *domain;
 	struct dname_buffer target;
 	uint16_t length = 2, svcparams_length = 0;
-	uint16_t size;
+	size_t size;
 	const size_t mark = buffer_position(packet);
```

So the causal type is the local `size` in `read_svcb_rdata()`, used to size
storage for the SVCB target name plus svc_params. The patch alone proves the
type widening; the exact allocation call, copy loop, write offset and the
relation between `rdlength=65512` and the 65509-byte claim are NOT established
until the pinned 4.14.2 `rdata.c` body is read. Treat those as UNKNOWN, not as
verified mechanism. Cheap source-bound confirmation: download the pinned
4.14.2 tarball, read `read_svcb_rdata()` around line 3282, and locate the
`size`-based allocation and subsequent copy.

## Rung-4 feasibility (honest, pre-experiment)

R1 / R2 / R3 / R4 / R5 all **UNKNOWN**: nothing was built or run locally.
Favorable: one-line fix, vendor-published patch and tarballs, network-reachable
secondary path, a claimed long controlled write rather than a one-byte
overflow, and a plausible ASan-visible heap failure. Unfavorable: no public
repro found, the attacker must be the configured primary (PR:L), a 65512-byte
RR demands an AXFR-carrying DNS message above the classic 65535-byte limit
(the exact wire framing is UNKNOWN), and a long attacker-controlled write does
not by itself demonstrate pointer control or control-flow takeover on 64-bit
glibc. Even if R3 is reached, R4 needs chosen bytes at a chosen offset with a
named consumer; R5 would additionally need a marker/command side effect on a
live loopback target. Ranked above OpenSSL CVE-2026-18798 (65/18-line QUIC
refcount patch, vendor says RCE highly improbable) and Tasmota
CVE-2026-119756 (embedded target, conflicting GHSA identifiers) on build cost
and primitive clarity, not on CVSS.

## Cheapest experiment that moves it up a rung

1. Provision, loopback only: NSD 4.14.2 and 4.14.3 tarballs from nlnetlabs.nl,
   plus `patch_CVE-2026-12244.diff`; record SHA-256 of each in
   `lab/frontier/nsdsvcb2shell/PROVENANCE.md`.
2. Read pinned `rdata.c:3282` and identify the `size` allocation/copy sink.
3. Build both pins with ASan. Cheapest path is a harness that calls
   `read_svcb_rdata()` with minimal stubs and a crafted 65512-byte SVCB rdata;
   the real path is a loopback AXFR from a locally started primary into an NSD
   secondary configured by this lab. Expect an ASan WRITE on 4.14.2 and a
   clean fixed/control run; preserve negatives.
4. Only if R3 is observed, probe chosen bytes at the overwritten offsets and
   name the consumer before claiming R4. Do not claim R5 without a live
   loopback command side effect and vulnerable/fixed/safe controls.

## Duplicate check and backups

`grep -R '12244|NSD_4_14|svcb_rdata' reports/` returned no matches. The
frontier wall lists NSD only as an unrelated backup label "NSD 12245" (W309),
not this CVE, and the window registry has no nsdsvcb target. Backups retained
from the same read-only scout: OpenSSL CVE-2026-18798 (QUIC QRX double free,
3 files +65/-18, pre-auth but vendor rates RCE improbable) and Tasmota
CVE-2026-119756 (UDP device-groups heap OOB write through 16.0.0, fix commit
`e97e1e4f7e319a55caa1613aef1f25fc81bdb554`, GHSA-ID discrepancy between EUVD
and the patch comment). Both are unstaged and unverified locally.
