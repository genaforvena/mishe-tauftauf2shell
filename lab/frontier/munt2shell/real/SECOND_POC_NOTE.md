# W191 (2026-11-25): the second CISA `exploit`-tagged HackMD link

No build, no probe, no lab process. Public-record check only; all fetches were
read-only and loopback was never contacted.

## What is new

The cveawg record for CVE-2026-121941 has two HackMD URLs in different
containers:

- CNA (VulnCheck) reference, tag `third-party-advisory`:
  `https://hackmd.io/@haindpwn/munt-midistreamparser-oversized-sysex-heap-overflow`
  — the note W181 already examined (HackMD note ID `7QnP1XDcRUWb6UMRQhfDJQ`).
- CISA-ADP reference, tag `exploit`, `dateUpdated 2026-11-04T20:18:07.407Z`:
  `https://hackmd.io/@haindpwn/cve-2026-121941-munt-midistreamparser-oversized-sysex-heap-overflow`

Tenable's CVE page lists both slugs. The second slug was **not** examined by
W181, so this wake tested it as a possible source of real PoC bytes.

## Route-by-route result (all observed 2026-11-25 ~17:07Z)

| Route | Result |
| --- | --- |
| direct read of the second slug | HTTP 403 |
| `https://r.jina.ai/https://hackmd.io/@haindpwn/cve-2026-121941-munt-midistreamparser-oversized-sysex-heap-overflow` | 403 Forbidden page ("You don't have permission to access this resource.") |
| second slug `+ /download` | HTTP 403 |
| Wayback CDX, exact URL, `filter=statuscode:200` | `[]` |
| Wayback CDX, exact URL, no status filter | `[]` |
| web search `site:hackmd.io/@haindpwn "CVE-2026-121941" PoC ...` | no result on the site constraint (relaxed to unrelated CVE mirrors) |

EUVD-2026-116898 returned only the site shell, no PoC material.

## The mirror resolves the lead

ThreatCluster article
`https://threatcluster.io/article/munt-midistreamparser-oversized-sysex-heap-overflow-c93362b0`
(published 2026-11-04T21:31:08.377053Z, JSON-LD `mainEntityOfPage` = the
**second** slug) carries a text mirror of the note. Its hero image URL is
`https://hackmd.io/api/_/preview/7QnP1XDcRUWb6UMRQhfDJQ` — the **same note ID**
W181 resolved for the first slug. The two slugs are aliases, not two write-ups.

The mirror's code block is introduced verbatim as:

> Illustrative trigger, not executed during this source review:

and its last complete lines are the ROM-image setup,
`DefaultMidiStreamParser parser(synth); // default capacity 1000, hard max 32768`,
the comment `// One SysEx that opens correctly, never closes, and carries no
status byte.` and a truncated `for (int i = 0; i ` that runs straight into the
reporter's signature. There is no byte array, no literal length, no script, no
captured allocation and no output in the mirror or in the issue.

Other aggregators do not supply bytes either: Exploit-DB.ai's page says
"public exploit available", but its "Public exploit & PoC references" list is
only the upstream source link, the fix commit and issue #149; its own analysis
is labeled AI-generated. ThreatCluster's cluster summary says "While a
proof-of-concept exists" — aggregator prose contradicted by the mirrored note
it summarizes. CISA's `Exploitation: poc` / `poc` metadata is advisory-only.

## Disposition

KEEP as a negative. The newly discovered `exploit`-tagged link does not change
W181's conclusion: no public PoC bytes exist on either slug. The missing piece
for rung 5 is still a measured real caller supplying one >=32769-byte block
from real input. No build or probe was run, so no replay is owed. Grade
unchanged: real-library rungs 1-4 ESTABLISHED (witness #2781), rung 5 UNKNOWN.
