# Frontier brief: BZFlag bzfs — CVE-2026-130849 (bzflag2shell)

Status W116 (2026-11-22 17:40Z): screened in and staged as `bzflag2shell`.
Brief and harness are frontier work; admission remains the operator's call and
wake units/presentation remain the person's.

## 1. Verified ground truth (claim, not local wire proof)

- Claim: CVE-2026-130849 / GHSA-9q5f-g948-c95m, pre-auth heap out-of-bounds
  write in `NetHandler::tcpReceive()`/`receive()` before bzflag 2.4.32.
- Primary sources read: OSV `https://osv.dev/vulnerability/CVE-2026-130849`,
  CVE record `https://www.cve.org/CVERecord?id=CVE-2026-130849`, upstream fix
  `https://github.com/BZFlag-Dev/bzflag/commit/8e501d685aef549090b363260979a4eb93484ea1`,
  release `https://github.com/BZFlag-Dev/bzflag/releases/tag/v2.4.32`
  (tag f11f05485d7406c78159aac00ace3c58b4b17ec2, 2026-11-16). Affected range
  from VulnCheck: bzfs < 2.4.32. CVSS 4.0 AV:N/AC:L/AT:N/PR:N/UI:N as claimed
  by the advisory; the local harness does not establish that reach.
- Pins: vulnerable tag `v2.4.30`, fixed tag `v2.4.32`, upstream patch; sha256
  in `lab/frontier/bzflag2shell/PROVENANCE.md` (three pins plus four pinned
  source files and three harness files). The fixed tag was read back and
  carries both upstream guards; the patch applies to the vulnerable pin.

## 2. Source-bound mechanism and exact fix

Pinned `src/game/NetHandler.cxx` (v2.4.30):

- `:578` `if (len > MaxPacketLen)` — does not count the 4-byte header, which
  is already in `tcpmsg`; `:594` `e = receive(4 + (int) len);`.
- With `len=1024`, `receive(1028)` executes `:630`
  `int size = recv(fd, tcpmsg + tcplen, (int)length - tcplen, 0);` with
  `tcplen=4`, so 1024 body bytes fill `tcpmsg[4..1027]`; `tcpmsg[1024..1027]`
  is the adjacent `int tcplen` (`include/NetHandler.h:236,238`;
  `MaxPacketLen=1024` at `include/Protocol.h:47`).
- `:633` `tcplen += size` uses the overwritten int. Chosen bytes `0x00f0ffff`
  (LE -4096) make `tcplen=-3072`; `tcplen != length` returns `ReadPart`, so
  the `:602` `tcplen = 0` reset is skipped. The next `tcpReceive()` calls
  `receive(4)`, whose `recv()` destination is `tcpmsg-3072` and whose length
  is `4-(-3072)=3076`: a chosen-offset, chosen-byte write before the buffer.
- Fix `8e501d6` changes the length check to `len > MaxPacketLen - 4` and adds
  in `receive()`:
  `if ((tcplen < 0) || ((size_t)tcplen > sizeof(tcpmsg)) || (length > sizeof(tcpmsg))) return returnValue;`.

The second guard is the structural point: even if any other caller corrupts
`tcplen`, it can no longer become a wild `recv()` destination.

## 3. Measured evidence (lab, loopback only)

`lab/frontier/bzflag2shell/harness/` extracts both pinned functions verbatim
(`gen_functions.py`), stubs only framing/PlayerInfo/logging, drives one
AF_UNIX socketpair, and builds vulnerable/fixed ASan and plain variants.
`bash harness/run.sh`: rc 0, 14 PASS / 0 FAIL; two replays produced four
byte-identical normalized hashes (see `PROVENANCE.md`, `EVIDENCE_HASHES.txt`).

- Vulnerable plain: `stage1_tcplen=-3072`, `stage2_offset=-3072`, chosen bytes
  `5a…`, `41…`, `42…`, `43…` read back at offsets +0/+16/+32/+48 in a real
  region adjacent to `tcpmsg`.
- Vulnerable ASan: `use-after-poison`, `WRITE of size 64`, frame
  `NetHandler::receive` at generated line 69 (pinned source `:630`). The
  adjacent region is deliberately poisoned in this build so the genuine
  negative write is observable; this is instrumented detection, not a
  natural allocator-redzone report.
- Fixed ASan clean rc 0; fixed plain rejects with `ReadHuge` and no chosen
  readback.

Rung 1/2: observed deterministic trigger and corrupted accounting in the real
pinned functions. Rung 3: observed write with ASan at the pinned `recv()`, with
the manual-poison caveat. Rung 4: chosen bytes at a chosen relative offset in
a plain adjacent region, at direct-call/harness scope only. Rung 5: no — no
bzfs process, no TCP listener, no controller/command; UNKNOWN.

## 4. Cheapest next experiment

Build the pinned v2.4.30 bzfs with ASan and a loopback listener, replay the
same 4-byte `len=1024` header plus 1028 body bytes from a raw TCP client, and
observe whether `tcpReceive()` returns `ReadPart` with `tcplen<0` on a
production compiler. Decisive: a second negative-offset `recv()` on the real
connection, and a v2.4.32 reject with `ReadHuge` for the same frame. If that
holds, test whether a staged heap object before `tcpmsg` receives chosen bytes
and whether any pointer-sized field is reachable; command execution is not
implied. No probing outside loopback.

## 5. Candidates parked this wake (with reasons)

All were screened read-only on primary sources; none duplicates an owned mind.

- **GNU inetutils telnetd CVE-2026-32746** — pre-auth port-23 SLC suboption
  overflow, tiny wire PoC and 3-line merged fix (`add_slc`, 2.8). Strong
  runner-up; needs the real telnetd option FSM and a full daemon build.
- **core-moos MOOSDB CVE-2026-85440** — pre-auth TCP header drives a 32768-byte
  write into a 4-byte heap object, but the 16-line fix is a proposed unmerged
  commit; no fixed upstream release bytes to pin.
- **PJSIP CVE-2026-57159 / GHSA-rfwg-w9gq-9mw2** — chosen SDP payload-type
  index into fixed maps; written values are small derived ints, not request
  bytes, and the map path is behind a non-default compile flag.
- **Cesanta Mongoose CVE-2026-52048** — MQTT v5 property-parser bounds/pointer
  issue fixed in 7.22; needs full message/length context before choosing.
- **NanoMQ CVE-2026-32135** — REST URI-parameter off-by-one (0.24.11 fix);
  smaller primitive, lower priority than the two-stage chosen-offset write.
- **libyang GHSA-44h9-v855-6rj3** — chosen-length/chosen-byte stack memcpy from
  a 277-byte LYB blob with an exact fix, but no upstream network listener.
- **fqterm CVE-2026-131875** — 4-byte chosen-int heap write past `param_[30]`,
  one-line clamp; client-side only.
- **X.Org CVE-2026-109093 / GHSA-4www-pr66-hmg8** — chosen int32 stack writes
  via DeviceValuator events; authenticated client, high-axis device needed.
- **H2O CVE-2026-55368** (fixed NUL only), **FRR CVE-2026-129456** (UAF,
  BGP FSM), **llama.cpp CVE-2026-133710 / 116816 / 21869** (model file local;
  server n_discard needs model load) — lower tractability this wake.

Witness replay request is on the chat tape after staging. Failed hypotheses
from this wake are preserved in `PROVENANCE.md` (natural ASan redzone attempt
returned EFAULT; instrumented poison used for rung 3 instead).
