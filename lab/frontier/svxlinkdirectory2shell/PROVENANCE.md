# Provenance — svxlinkdirectory2shell

All sources here were fetched as public provisioning (no probes, no lab client
contacting any external host). Every later command ran locally with no
listener. SHA-256 pins are in `SHA256SUMS`; the four immutable source/patch
pins are re-checked by `gen_driver.py` on every run (exit 2 on drift). The
advisory HTML is a dynamic public page kept as a provenance snapshot:
`bootstrap.sh` fetches it only when absent and the generator never gates on it.

| Artifact | URL / identifier | SHA-256 |
|---|---|---|
| Vulnerable `StationData::setData` source | `https://raw.githubusercontent.com/sm0svx/svxlink/d6451c1e5ff7070537fb5763d316b21ba6c68796/src/echolib/EchoLinkStationData.cpp` | `a7daf3c031e715be25cdfdb10757c816d4e814dec8485a0302e536732bc14969` |
| Fixed source (upstream fix commit) | `https://raw.githubusercontent.com/sm0svx/svxlink/8eb1008f822a97a42184097ee57e51a302181c75/src/echolib/EchoLinkStationData.cpp` | `dc2e2b8a95364c7e747553d1b2f40b23630d8da97e3098364ce97ee9368e60c3` |
| Class header (`MAXDATA=45`) | `https://raw.githubusercontent.com/sm0svx/svxlink/d6451c1e5ff7070537fb5763d316b21ba6c68796/src/echolib/EchoLinkStationData.h` | `510c51a3cc2c22c6cd478ed05104184ce7c508b4ddef69404e8029a6293f537a` |
| Fix patch | `https://github.com/sm0svx/svxlink/commit/8eb1008f822a97a42184097ee57e51a302181c75.patch` | `f7848f9f0d62766426fcbfb6990e61412cd86a16d89687507bb2a3d4f8ef02f4` |
| GitHub advisory HTML | `https://github.com/sm0svx/svxlink/security/advisories/GHSA-5g48-xjmf-7p4q` | `da77e4d191d0241d63778f20b1a506306f281db52c5202a664f060c970d892ff` |
GitHub advisory HTML is dynamic: the hash above records the snapshot fetched
at provisioning and is not re-checked by `gen_driver.py`; `bootstrap.sh`
refetches it only when absent.

Advisory: GHSA-5g48-xjmf-7p4q, published 2026-07-12, Critical 9.8, CWE-121;
all versions `<= 26.05` affected, patched in `26.05.0.99.0`; GHSA says **No
known CVE** (OSV mirrors it as `UBUNTU-CVE-2026-73154`, a record discrepancy).
Fix commit `8eb1008f822a97a42184097ee57e51a302181c75`, parent
`d6451c1e5ff7070537fb5763d316b21ba6c68796`; the pinned source pair is
exactly fix-parent → fix. The patch clamps `desc_len` to `MAXDATA-1` at
`src/echolib/EchoLinkStationData.cpp:217-223`.

`gen_driver.py` extracts the complete pinned `StationData::setData()` body
verbatim from each pin into `harness/driver-{vuln,fixed}.cpp` under a `#line`
directive. Only the class stub, helper and `main()` are harness-authored.
The upstream wire path is source-bound, not run here: directory-server TCP
line → `Directory::ctrlSockDataReceived` → `handleCallList`
(`src/echolib/EchoLinkDirectory.cpp:534`) → `setData(buf)`.
