# frontier-frrbgpd2shell — SCREENED OUT: bgpd Cease/Hard Reset OOB READ (CVE-2026-129217)

Status: **SCREENED OUT for X2Shell staging (W282, 2026-11-26)**. Source-only
review: no local build, no local input, no observed bytes. Everything quoted
below is a claim from advisories, upstream source or the upstream reporter's
ASan log, preserved as a claim, not as this lab's evidence. No window, no mind,
no rung claimed.

## Claim source and scope

- CVE record, CNA Network Device Education Foundation:
  `https://www.cve.org/CVERecord?id=CVE-2026-129217` (published 2026-11-13),
  JSON `https://cveawg.mitre.org/api/cve/CVE-2026-129217`. Title: "bgpd:
  out-of-bounds heap read and crash on NOTIFICATION Cease/Hard Reset with one
  data byte"; CWE-125 + CWE-191; CVSS 4.0 6.0 MEDIUM
  `CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:N/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N`.
  NVD: Awaiting Analysis. OSV: `https://api.osv.dev/v1/vulns/CVE-2026-129217`.
- Affected: 8.3 up to 10.0.5, 10.1 up to 10.1.5, 10.2 up to 10.2.6,
  10.3 up to 10.3.4, 10.4 up to 10.4.3, 10.5.0 up to 10.5.2; unaffected
  before 8.3. Fixed in 10.0.5, 10.1.5, 10.2.6, 10.3.4, 10.4.3, 10.5.2,
  10.6.0 (advisory quote). Fixed tag `frr-10.5.2`, release commit
  `fa68c0ca04f95125cb993b5cacb64fc1495348eb`; fix PR
  `https://github.com/FRRouting/frr/pull/20796`, code-fix commit
  `72a2f165e4e901cb3eaf4d928a7b222b7ff75664`, merge
  `9fa702b010a72591179d67fa5d66f8fb70ffd5a5`. Report issue
  `https://github.com/FRRouting/frr/issues/20793` on vulnerable master
  `2b7160c931aca007fbf8acf31d28cfbcc2a559ae` includes a loopback PoC and
  the reporter's ASan log.

## Source-bound mechanism (as read from the patch)

`bgp_notify_receive()` (`bgpd/bgp_packet.c`, vulnerable sha `2b7160c9`,
around :2590) allocates `outer.raw_data` with `outer.length = size - 2`
after parsing a NOTIFICATION. With a one-byte data field that is a one-byte
heap region. If the peer negotiated the Graceful Restart Notification (N) bit
both ways and the code/subcode are Cease/Hard Reset (9), the gate
`bgp_notify_received_hard_reset()` (:871-884) calls
`bgp_notify_decapsulate_hard_reset()` (:807-819):

```c
bn.code = notify->raw_data[0];
bn.subcode = notify->raw_data[1];       /* 1-byte read past the region */
bn.length = notify->length - 2;        /* bgp_size_t = uint16_t: 1-2 -> 65535 */
bn.raw_data = XMALLOC(MTYPE_BGP_NOTIFICATION, bn.length);
memcpy(bn.raw_data, notify->raw_data + 2, bn.length); /* 65535-byte OOB read */
```

`typedef uint16_t bgp_size_t` in `bgpd/bgpd.h:81` establishes the wrap. Fix
commit `72a2f16` rejects `length < 2` before indexing, skips the inner
`memcpy` at length 0, handles zero/one-byte data in the caller and fixes a
cleanup double-free. Upstream ASan quote (reporter, not reproduced here):
`READ of size 1 ... bgp_notify_decapsulate_hard_reset bgpd/bgp_packet.c:807
... 0 bytes to the right of 1-byte region`.

## Rung-4 feasibility assessment

The primitive is a **read**, with a large underflowed read length and a crash.
There is no write, no chosen-offset store, no pointer overwrite and no
control-flow steering; the advisory's impact is session teardown/DoS. The
wire path also needs a full BGP OPEN/capability handshake with GR-N negotiated
on an established peer (`PR:H`, `AT:P`), so it is not an unauthenticated
pre-session trigger. No route from this bug to rung 4 or rung 5 is visible
from the source; do not stage it as an X2Shell candidate.

Cheapest experiment **if** a rung-3 DoS demonstration is ever wanted: build
vulnerable sha `2b7160c9` with `./configure --enable-address-sanitizer`,
run the issue's attached `bgpd.conf.txt` and `poc.py` (loopback 127.0.0.x:
51433 to 179), then send marker `16*FF`, length `0x0016`, type `0x03`,
code `0x06`, subcode `0x09` plus one data byte. Fixed tag `frr-10.5.2` is
the control. That would only confirm a read/abort; it does not change the
screen-out verdict.
