# Frontier brief: awssdkbase642shell — Base64 decoder heap OOB write

**Status: QUEUED for lab work (frontier W345 screen); no harness, window or
admission yet.** This brief records primary-source ground truth and the
cheapest local experiment. No local trigger has been run; grades are UNKNOWN,
not passes. No candidate was probed outside the public advisory/commit pages.

## Verified ground truth

- CVE-2026-19642 / GHSA-wxx3-prfc-69xx, GitHub advisory published 2026-08-12
  by the AWS SDK for C++ maintainers: "certain inputs to the Base64 decoder
  might cause the decoder to write past the end of its heap-allocated output
  buffer", reachable from generated C++ service clients. Severity Moderate
  (5.9), CVSS v3.1 `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H`, CWE-787. The
  advisory explicitly says **remote code execution has not been demonstrated**
  and there is no runtime workaround.
- Affected `aws-cpp-sdk-core <= 1.11.861`; patched `1.11.862`. Fix is a
  single-parent commit
  `8eeac049c37b2c4cca2a94bfb53f07ea7e4550f7` ("swap base64 implementation to
  CRT (#3882)"), parent `2857dbc70b4b780810e304ba14514fa52d932a23`, read
  directly from the commit page and `.patch` URL. The patch removes the
  hand-written decoder in
  `src/aws-cpp-sdk-core/source/utils/base64/Base64.cpp` and delegates
  `Encode`/`Decode`/length calculations to `Aws::Crt::Base64*`; its new
  regression test feeds malformed inputs (`"AAAA="`, `"AB=D"`, high-bit
  strings `0x80..0xFF` plus `"AAA"`) and asserts decoded length never exceeds
  `CalculateBase64DecodedLength()`.
- Vulnerable parent sink, read from the patch's deleted lines:
  `Base64::Decode()` computes `decodedLength =
  CalculateBase64DecodedLength(str)`, allocates
  `Aws::Utils::ByteBuffer buffer(decodedLength)`, sets
  `blockCount = str.length() / 4`, then writes `buffer[bufferIndex]` at
  `bufferIndex = i*3` plus two more bytes when characters 3 and 4 are not
  the `SENTINEL_VALUE 255`. `CalculateBase64DecodedLength()` returns
  `len*3/4 - padding` where padding is 1 or 2 for trailing `=`.
- Duplicate check: the frontier wall has `awslc2shell` (AWS-LC TLS library)
  but no AWS SDK for C++ / Base64 lane. UxPlay, pgactive, OpenSSL CMS and
  this candidate are new scouts' finds and none has a lab tree or window.
- Boundary arithmetic is source-bound but not yet executed: for length 5
  with one trailing `=` (`AAAA=`), the calculator returns `2` while the
  single loop iteration writes three bytes, so a one-byte heap overrun is
  predicted. For length 9 the prediction is also one byte (5 allocated, 6
  written). For canonical 4/8-character inputs the write stays in bounds.

## Rung-4 feasibility and limits

The primitive is a heap OOB write of **one byte per malformed 4-character
block**, not a bulk overflow. In the canonical `AAAA=` case, the fourth
decoded value is the sentinel 255 and the third written byte becomes
`((value3 & 3) << 6) | 255`, i.e. `0xFF` regardless of the first three
characters — so the out-of-bounds byte is not obviously attacker-chosen.
The patch's high-bit regression inputs matter because the parent indexes
`m_mimeBase64DecodingTable[uint32_t(rawString[i])]` with a possibly signed
`char`; negative values index outside the 256-byte member table. Whether
that yields a controllable byte at the OOB offset is **UNKNOWN** until the
real decoder is run under ASan/GDB. Do not claim chosen-byte control from
the arithmetic alone.

Fix-side caveat: the fixed arm delegates to `aws-crt-cpp` v0.43.2, so a
clean replay needs the CRT submodule (the patch changes the pinned
subproject from v0.42.2) or a clearly-labeled source-bound control using the
patch's own length assertion. The public advisory's "RCE not demonstrated"
is consistent with this bounded primitive; no control-flow, pointer or
command claim is warranted.

## Cheapest local experiment

1. Provision the parent tarball at `2857dbc7` and the fix patch into
   `lab/frontier/awssdkbase642shell/pins/` with SHA-256 pins; fetch is
   provisioning, no probes.
2. Compile the vulnerable `Base64.cpp` plus a tiny C++ harness calling
   `Aws::Utils::Base64::Base64().Decode(input)` under ASan with `-g -O0`,
   using the SDK core headers from the same pinned tree. If headers demand
   more of the core library, copy the few needed headers verbatim with
   hashes rather than linking the full SDK.
3. Feed `AAAA=`, `AAAAA=`, 9-character padded strings, canonical `AAAA`,
   and the patch's `0x80..0xFF` + `"AAA"` inputs. Record ASan write size and
   offset, the OOB byte value, and fixed/safe controls. Under GDB on a plain
   build, reset the offending byte to distinct values to test whether a
   chosen byte reaches a live neighbour.
4. Only if a chosen byte reaches a useful adjacent object should this be
   staged with a window; otherwise close the lane as a bounded availability
   bug and move to UxPlay's pre-auth RTSP stack write (fix `746ec0e`).

## Ranking context

Ranked first among the scout's new finds because the sink is one file, the
input is a short string, the parent/fix pair is exact, and the advisory
already supplies malformed test vectors. Its ceiling is constrained: a
one-byte heap overrun with no observed pointer control. Backups from the
same scout batch: UxPlay RTSP `raop_handler_pairsetup_pin()` 64-byte stack
write (pre-auth wire path, fix `746ec0e`), AWS pgactive `sscanf` into
`NameData` (fix `7eb5d25`, related to the admitted pgactive family), OpenSSL
CMS `cms_kek_cipher`/`cms_kemri` under-allocation (fix `2a3dac8`, heavier
build). From the other scout: VMime `uuEncoder` stack overflow
(CVE-2026-116738, fix `e85925ed`, parent `b34fa2d2`), osmo-msc SGsAP
MME-name stack write (fix `cd347bbe`), fetchmail NTLM stack write with a
maintainer exploitability dispute. GCT and BZFlag entries in that scout
report overlap the already-admitted `gct2shell` and `bzfs2shell` lanes and
are excluded.
