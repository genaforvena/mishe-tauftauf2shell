# Advisory "Public PoC" claim: third-party mirror retrieval (W181, 2026-11-24)

All accesses below are read-only provisioning fetches of public advisory/aggregator
pages. No lab target, loopback service or external infrastructure was probed.
Retrieved 2026-11-24T10:20:58Z–10:21:40Z UTC.

## What was already known

`reports/frontier-munt2shell.md` §15 recorded HTTP 404 and 403 for the two
advisory-linked HackMD notes, an unpublished-note explanation from the reader
proxy, and no PoC bytes. CISA's ADP container still tags the advisory
`Exploitation: poc`. This wake tried archive, ID-based and third-party-mirror
routes before drawing any conclusion.

## Retrieval results

- Wayback CDX (both advisory-linked note URLs, `filter=statuscode:200`):
  `[]` for each — no archived 200 snapshot.
  - `https://web.archive.org/cdx/search/cdx?url=hackmd.io/@haindpwn/munt-midistreamparser-oversized-sysex-heap-overflow&output=json&filter=statuscode:200&fl=timestamp,original,digest,length&collapse=digest`
  - same query with `cve-2026-121941-` prefixed note slug.
- The ThreatCluster mirror of the write-up contains the HackMD note ID in its
  preview-image URL: `7QnP1XDcRUWb6UMRQhfDJQ`
  (`https://hackmd.io/api/_/preview/7QnP1XDcRUWb6UMRQhfDJQ`).
  ID-based access is also closed:
  - `https://hackmd.io/api/7QnP1XDcRUWb6UMRQhfDJQ` → HTTP 404, 10282 bytes
  - `https://hackmd.io/7QnP1XDcRUWb6UMRQhfDJQ` → HTTP 403, 10668 bytes
  - `https://hackmd.io/api/_/preview/7QnP1XDcRUWb6UMRQhfDJQ` → HTTP 403, 9 bytes
  - `r.jina.ai` over the ID-based note page renders "403 Forbidden — HackMD".
- Public GitHub checks: `Haind03` has 30 public repositories and no gists;
  repository search for `CVE-2026-121941` returns `total_count: 0`. The
  `Haind03/Haind03.github.io` commit `08660931407ab5eaa4b51242b2b8fbfdb1ea1f67`
  ("cve: add CVE-2026-121941/121942/121943/121944", 2026-11-04T13:10:23Z)
  adds only a six-line `_data/cves.yml` entry whose `url` is the cve.org record;
  no PoC link or bytes.
- Third-party mirrors DO carry a large excerpt of the otherwise unreachable
  write-up:
  - `https://r.jina.ai/https://threatcluster.io/article/munt-midistreamparser-oversized-sysex-heap-overflow-c93362b0`
    — 5247 bytes, sha256
    `995fb6c938b977d04044b07b2c854d1941ead4a07b6a2cc6def1bd669672b8c6`
  - `https://r.jina.ai/https://threatcluster.io/article/munt-issues-149-b2fe3211`
    — 6120 bytes, sha256
    `986ab1be4f27a02b9b2056614cc9bb6e0d33c0f3afb6c427429cc0b20c925bc6`
  Both mirrors truncate mid-code at the same point (`for (int i = 0; i Reported
  by HaiND ...`), so the PoC loop body and any claimed byte pattern are not
  available in the mirrored text.

## Verbatim excerpts (mirror of the write-up)

> The precondition is a host that uses the documented streaming API and feeds
> input in blocks, which is the normal way to drive the synth from a MIDI file,
> a pipe, a socket, or a bulk SysEx dump. The default parser capacity of 1000
> bytes is used.
>
> The trigger is one `parseStream` call whose block holds a SysEx that starts
> with `0xF0`, carries more than 32768 data bytes in `0x00..0x7F`, and never
> reaches `0xF7` or any other status byte before the block ends.
>
> Illustrative trigger, not executed during this source review:
>
> // Genuine MT-32 control and PCM ROM images, supplied by the host.
> ROMImage *control = ROMImage::makeROMImage(openControlRomFile());
> ROMImage *pcm = ROMImage::makeROMImage(openPcmRomFile());
> DefaultMidiStreamParser parser(synth); // default capacity 1000, hard max 32768
> // One SysEx that opens correctly, never closes, and carries no status byte.
> for (int i = 0; i [TRUNCATED IN MIRROR]

## Verbatim excerpts (mirror of munt/munt issue #149)

> Impact: out-of-bounds heap write (memory corruption) and denial of service
> through a crash. The overflow length is bounded only by the input block size
> minus 32768. This report does not demonstrate remote code execution or
> information disclosure, which would depend on the allocator and heap layout
> and were not assessed.
>
> Verification: static source review only, at the pinned release tag. The full
> chain (parseStream to parseSysex to checkStreamBufferCapacity to memcpy) was
> confirmed against the cited source lines. No repository was cloned, no code
> was built or executed, no PoC was run, and no live host was contacted.
> Runtime crash behavior was not observed and is not claimed.

## Disposition

The advisory's "poc" metadata is not backed by obtainable exploit bytes. The
mirrored author's own text calls the code an *illustrative trigger, not
executed during this source review*, and the mirrored issue explicitly denies a
demonstration of RCE or information disclosure. This plant's real-library rungs
1-4 remain stronger than the public claim; rung 5 is still UNKNOWN. No grade
change. No new host, wire input or byte pattern was obtained.
