# MsQuic2Shell candidate — pin provenance

Provisioned 2026-11-21 ~19:23Z from public primary sources only. No target
software was built or run, no packets were sent, no external system was
probed. Digests are sha256 of the exact bytes in `src/`, also recorded in
`src/SHA256SUMS` (`sha256sum -c`: 3/3 OK).

| File | Source | sha256 |
| --- | --- | --- |
| `src/msquic-v2.5.9.tar.gz` (vulnerable) | `https://github.com/microsoft/msquic/archive/refs/tags/v2.5.9.tar.gz` | `ccf4170e96f834f6c417ea5e0039bbd67d8bb40a42b5d3966ef75f48f5f5fa38` |
| `src/msquic-v2.5.10.tar.gz` (fixed) | `https://github.com/microsoft/msquic/archive/refs/tags/v2.5.10.tar.gz` | `b77be2c956bee31809eb6138064b6471d7f697a7226d1b9faddf01df36b166d5` |
| `src/fix-e0f55b5.patch` | `https://github.com/microsoft/msquic/commit/e0f55b5fdc9fff0b4465976d066ebd22fb7e2b3b.patch` | `c74bfda59f7585223b9d92188d2a1e70764b8dcdd2dc16e17ae8b2ab9b8e61af` |

GitHub auto-generated source archives carry no published hash sidecar; these
digests are our own hashing of the fetched bytes. Tag objects confirmed by
read-only `git ls-remote`:

- `refs/tags/v2.5.9` → `87b53085d76bd7920d490a6f226c9999b6614d14`
- `refs/tags/v2.5.10` → `9ff06b71fd4b4d5258361598ada5b24cbc1beb20`
- `refs/tags/v2.4.19` → `583e7d5b509bb0bfa3518482d98879b6eda41ad0`

The fix commit SHA `e0f55b5fdc9fff0b4465976d066ebd22fb7e2b3b` is stated by the
GHSA as the patch, and the fixed/vulnerable state is verified directly in the
two pinned tarballs (raw hunk below), which is the authoritative check.

## Raw hunk read from the pinned bytes

`src/core/connection.c` inside the tarballs, function
`QuicConnRecvPostProcessing`, path-promotion condition:

- v2.5.9, file line 5516: `        !(*Path)->IsActive) {`
- v2.5.10, file line 5534: `        !(*Path)->IsActive && (*Path)->InUse) {`

GitHub patch applies to the default branch (`@@ -5572,7 +5572,7 @@`); release
tag line numbers above are the authoritative ones for these pins.

Supporting raw reads (v2.5.9): `src/core/path.c:51-86` `QuicPathRemove` shifts
the inline `Connection->Paths[]` array and clears `Paths[PathsCount].InUse =
FALSE` — an embedded slot invalidation, not a `free()` of a malloc object.
`src/core/path.c:263-291` `QuicPathSetActive` swaps whole `QUIC_PATH` structs
(`QUIC_PATH PrevActivePath = Connection->Paths[0]; Connection->Paths[0] =
*Path; *Path = PrevActivePath;`). `src/core/path.h:55` declares
`BOOLEAN InUse : 1;`.

Claim records read this wake: MITRE CVE API `CVE-2026-62815` (CNA Microsoft,
published 2026-08-11T17:04:30.645Z, updated 2026-11-19T22:17:01.881Z, CWE-416,
CVSS 3.1 9.8 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C`,
CISA SSVC exploitation none / automatable yes / technical impact total), and
GHSA `GHSA-92f5-vc22-8j33` (published 2026-08-11 by `guhetier`, NuGet packages
`Microsoft.Native.Quic.MsQuic.OpenSSL` and `.Schannel`, affected `< 2.5.10`,
patched `2.5.10, 2.4.19`, CVSS 4.0 10.0). MSRC vendor URL is recorded in the
brief but its page body was not retrieved; do not treat it as independently
read.
