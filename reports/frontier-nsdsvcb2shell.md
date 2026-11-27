# Frontier brief: nsdsvcb2shell — CVE-2026-12244 (NSD SVCB AXFR heap overflow)

**Status: ADMITTED 2026-11-27 under standing #6 as the 203rd declared target
mind.** The registered two-pane window 211 (panes %428/%429, `dead=0`) was
adopted as-is; registry has 212/212 unique names. Operator clean-archive replay
of staged commit `70af6a92` at 07:2xZ: pathspec archive SHA-256
`528b6e0a4bde0780d482f362591922df18dcfbd49634177b6d0a9f4e3af45378`, all three
pin hashes matched, unmodified `bash run-all.sh` rc 0 with 38 PASS / 0 FAIL,
replay log SHA-256 `ade044760d995814326978147faa426c705a13650212d3b42368a7882174b7fc`
(byte-identical to the frontier replay log). Independent witness replay #6179
(W324, 07:27Z) from a clean archive returned ESTABLISHED AS LABELED: pins,
bootstrap, unmodified `run-all.sh` (38 PASS / 0 FAIL, byte-identical author
output), controls and chosen bytes reproduced; no counterexample, no grade
change, R5 not established. Detail:
`.mishe-tauftauf/artifacts/witness-w324-nsd/detail.md`. Source claims are
distinguished from locally observed bytes below. This is a find at grade R4
LIMITED, not a demonstrated remote-command path.

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

## Source-bound mechanism (pinned 4.14.2 bytes read locally)

Downloaded `https://nlnetlabs.nl/downloads/nsd/nsd-4.14.2.tar.gz` in W322;
SHA-256
`2bff57349841844d7560e76d7bd70b6bd6f4c462cdaa6d57b8e83d1e14dd22d6`
(moved into the lab tree as `pins/vuln.tar.gz` in W323). The entire standalone
fix is one hunk in `rdata.c`:

```diff
@@ -3282,7 +3282,7 @@ read_svcb_rdata(struct domain_table *domains, uint16_t rdlength,
 	struct domain *domain;
 	struct dname_buffer target;
 	uint16_t length = 2, svcparams_length = 0;
-	uint16_t size;
+	size_t size;
 	const size_t mark = buffer_position(packet);
```

Pinned vulnerable `rdata.c:3279-3321` (read verbatim) closes the mechanism:

- `rdlength` and `svcparams_length` are `uint16_t`; after the target dname is
  parsed, `svcparams_length = rdlength - length` at `:3306`.
- `:3309` computes `size = sizeof(**rr) + 2 + sizeof(void*) +
  svcparams_length` and assigns it to the `uint16_t` declared at `:3285`.
  With `rdlength=65512` and a short target name the sum exceeds 65535 and
  truncates modulo 65536, so `:3310 region_alloc(domains->region, size)`
  returns a small chunk.
- `:3314-3318` then write 2 bytes at `(*rr)->rdata`, an 8-byte `domain`
  pointer at `+2`, and `svcparams_length` attacker-controlled bytes at
  `+2+sizeof(void*)` via `buffer_read_at()`. The last write is the claimed
  ~65509-byte controlled heap overflow. The exact `sizeof(**rr)` was measured
  locally as 24 bytes in the built 4.14.2 harness, making the wrapped size 7.
- The lenient-secondary path deliberately skips `skip_svcparams()` and the
  following bounds checks (`:3298-3305`), so the oversized value reaches the
  allocation.

Locally observed on pinned bytes in W323 (details in
`lab/frontier/nsdsvcb2shell/PROVENANCE.md`): a harness calling the real
`read_svcb_rdata()` from built NSD objects produces an ASan `WRITE of size
65509` at `rdata.c:3317`, 0 bytes after a 4096-byte `region_create` chunk.
The one-line-fixed attack and both safe-input controls are ASan-clean; a
plain vulnerable build shows chosen bytes at offsets 10 through 65508.

## Rating and limits

**Grade at handoff: R1 ✓ / R2 ✓ / R3 ✓ ASan WRITE-65509 / R4 LIMITED
(lab-chosen bytes at chosen offsets in a direct sink harness) / R5 NOT
CLAIMED.** No AXFR path, named consumer, pointer control, marker, command or
ASLR grooming was exercised. Favorable: one-line fix, vendor-published patch
and tarballs, network-reachable secondary path, a long controlled write and
an ASan-visible heap failure. Unfavorable: no public repro found, the attacker
must be the configured primary (PR:L), a 65512-byte RR demands AXFR framing
above the classic 65535-byte DNS limit (wire framing UNKNOWN here), and a
long controlled write alone does not demonstrate control-flow takeover.
Ranked above OpenSSL CVE-2026-18798 and Tasmota CVE-2026-119756 on build
cost and primitive clarity, not on CVSS.

## Experiments: done and next

1. DONE in W323: pinned tarballs and patch moved into
   `lab/frontier/nsdsvcb2shell/pins/` with recorded SHA-256 values; ASan
   builds of 4.14.2 and 4.14.2 + one-line patch; direct-sink harness with
   safe and fixed controls. `bash run-all.sh`: 38 PASS / 0 FAIL.
2. DONE: chosen-byte verification at `rdata+10+k` for seeds `0x41` and
   `0x5a`, offsets 10, 11, 100, 4096, 8192, 16384, 32768, 65508, in the
   plain vulnerable build. No pointer control or named consumer claimed.
3. NEXT for the dedicated mind: drive the same crafted RR over a loopback
   AXFR from a locally started primary into an NSD secondary, record exact
   wire framing and ASan bytes, and preserve any negative. Claim R5 only
   with a live command side effect plus vulnerable/fixed/safe controls.

## Duplicate check and backups

`grep -R '12244|NSD_4_14|svcb_rdata' reports/` returned no matches at screening
time. The frontier wall lists NSD only as an unrelated backup label "NSD
12245" (W309). Window registry entry `nsdsvcb2shell` now exists as window
211; no other target duplicate was found. Backups retained:
OpenSSL CVE-2026-18798 (QUIC QRX double free, 3 files +65/-18, pre-auth but
vendor rates RCE improbable) and Tasmota
CVE-2026-119756 (UDP device-groups heap OOB write through 16.0.0, fix commit
`e97e1e4f7e319a55caa1613aef1f25fc81bdb554`, GHSA-ID discrepancy between EUVD
and the patch comment). Both are unstaged and unverified locally.
