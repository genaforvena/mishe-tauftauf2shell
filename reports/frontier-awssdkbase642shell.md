# Frontier brief: awssdkbase642shell — Base64 decoder heap OOB write

**Status: LAB VERIFIED (frontier W345-W348), staging and window owed.**
Both gates named by the operator are closed: the fixed v1.11.862 Base64 arm
against fixed CRT v0.43.2 is a clean control, and a generated REST-JSON client
model caller carries a wire-format JSON string to the vulnerable sink. No
dedicated window or admission yet; no candidate was probed outside the public
advisory/commit pages.

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
- Executed boundary (corrected from the initial arithmetic guess): the loop
  consumes only complete 4-character blocks. For a 5-character input such as
  `AAAA=` the trailing `=` lies outside the single block, so `value4` is the
  fourth `A` (table value 0), not the sentinel. All three writes execute
  into a 2-byte allocation; GDB confirms `m_length=2` and the third write at
  offset 2.

## Rung-4 feasibility and limits

The primitive is a **one-byte heap OOB write** at offset 2 of a 2-byte
decoded buffer. Debug builds abort before the write on `Array::GetItem`'s
`assert(index < m_length)`; `-DNDEBUG` builds reach the sink, an assertion
condition rather than a different allocator behavior. On the plain
`-DNDEBUG` build the OOB byte follows
`((value3 & 0x03) << 6) | value4`: with `AABa=` the chosen byte is `0x5A`
and with `AADa=` it is `0xDA`, both read back in a live heap region at
offset 2. Canonical `AAAA` and a 9-character all-`A` input stay in bounds.
That is rung-4 chosen bytes at a chosen heap offset in the direct-call lab
build; no pointer, saved RIP, marker, command or wire path was observed.
Lab condition to disclose: the AWS core allocator is a separate translation
unit, so the harness defines `Aws::Malloc`/`Aws::Free` as `malloc`/`free`;
the pinned `Base64.cpp` body is verbatim and the heap region is real.

Fixed arm closed (W348): the fix's two Base64 hunks apply to a staging copy and
compile against fixed `aws-crt-cpp` v0.43.2 `Types.cpp`, pinned common
`encoding.c`/allocator/byte_buf/error sources and a disclosed four-symbol
link shim. `AAAA=`, `AABa=`, `AADa=`, `AB=D`, `=` and `==` all decode to zero
bytes with no ASan report; canonical `AAAA` still decodes to three bytes.
This is a source-bound fixed control on the Base64 path, not a full CRT
runtime build; the fixed SDK release itself was not built.
Generated-client caller closed (W348): `JsonBlobsResult.cpp:21-27` (verbatim
pinned generated model) parses a CLI wire-format JSON payload into
`JsonValue`, calls `HashingUtils::Base64Decode` (`HashingUtils.cpp:40-42`) and
reaches `Base64.cpp:115`. ASan reports WRITE-1 into a 2-byte region with the
full call chain model -> wrapper -> decoder; the fixed generated-client arm
rejects `AAAA=`/`AABa=` cleanly. The protocol-test model is generated SDK
code, not a live AWS service endpoint; no socket or network I/O.

## Local evidence and next experiment

and eleven CRT dependency archives (21 SHA-256 pins). `sh run-all.sh`
rebuilds the offline g++ consumers from those archives with `-g -O0`,
ASan/plain and plain-without-asserts; its original summary stays byte-identical
at `RUN_ALL_OK 17 PASS / 0 FAIL`, SHA-256
`504bb8e541ebc6bfd16d73715bd144fdfffb3b42c8562e9db7a410c57903d234`.
W348 added two replay phases after that summary: `FIXED_OK 15 PASS / 0 FAIL`
and `CLIENT_OK 15 PASS / 0 FAIL`, so the original summary hash is unchanged.

Observed: debug build aborts at `Array.h:208`'s `index < m_length` assertion;
the `-DNDEBUG` ASan build reports `heap-buffer-overflow`, `WRITE of size 1`
at pinned `Base64.cpp:115`, zero bytes after the 2-byte region for `AAAA=`;
canonical `AAAA` and 9-`A` inputs are clean. Read-only GDB on the plain
`-DNDEBUG` build, stopped at `Base64.cpp:120`, reads `m_length=2` and the
chosen `0x5A` / `0xDA` at the OOB offset for `AABa=` / `AADa=`.
A clean `git archive --format=tar 77c246b2 lab/frontier/awssdkbase642shell`
replay into `/tmp/w345-aws-clean` matched 18/18 pins, rebuilt all three
consumers offline and returned the byte-identical 17/0 summary; plain-tar
SHA-256 `0c01bf691a0f9117ac323a03309fdab904d5fa23a751de5b0471b08724e119ed`.

A clean `git archive --format=tar 3134d73a lab/frontier/awssdkbase642shell`
replay into `/tmp/w348-aws-clean` matched 21/21 pins and returned the
byte-identical three summaries (`504bb8e5…`, `da2bde79…`, `7a819c41…`);
plain-tar SHA-256
`d8d18d9eaf287b358d9c7453457604c726608445c86b42a2391410bfb67d978c`.
This is an author durability check, not witness acceptance.

Next: both operator gates are closed, so stage the target window and request
admission. The remaining ceiling is unchanged: a wire path to a chosen-byte
one-byte heap overrun, with no pointer, control-flow or command side effect;
R5 remains NO. A future mind may seek a live loopback service endpoint and
grooming that turns the one-byte write into pointer control; nothing here
claims it.

## Ranking context

Ranked first among the scout's new finds because the sink is one file, the
input is a short string, the parent/fix pair is exact, and the advisory
already supplies malformed test vectors. Its ceiling is constrained: a
chosen-byte one-byte heap overrun with no pointer or control-flow control. Backups from the
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
