# Frontier brief: pppd — CVE-2026-85495 (pppd2shell)

Status W118 (2026-11-22): screened in, driven to rung 3/4 locally and staged as
`pppd2shell`, find commit `b3ec18d`. Duplicate check before provisioning: no
prior `reports/frontier-*ppp*`, no pppd window or mind on the tape; the only
earlier pppd note was the parked candidate in `frontier-snac2shell.md` §6 and
the W112 wall (pins fetched, no harness). Admission remains the operator's
call; wake units and full-flag sync stay with the person.

## 1. Verified ground truth

- Claim: GHSA-frhv-j822-2pvx / CVE-2026-85495, "ppp: `lcp_reqci` writes a
  5-byte NAK suggestion per 4-byte rejected AUTHTYPE option into
  `nak_buffer[1500]` with no room check — one legal pre-auth Configure-Request
  with repeated options overflows `.bss` globals in the root daemon" (CWE-787
  and CWE-120). Advisory severity Moderate / CVSS v3.1 7.5 High
  (`AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`); GitHub's displayed 4.2
  (`C:L/I:L/A:N`) is the repo's lower score. MITRE record is RESERVED; NVD has
  no record.
- Sources read (read-only provisioning, no external probe):
  `https://github.com/ppp-project/ppp/security/advisories/GHSA-frhv-j822-2pvx`,
  fix commits `cc8b00c96646f858fbd4e2699077701c72ef9e1c` and
  `1baf2ac29e4456f095c4ebe15230881201ce4ffb`, and both pinned tarballs.
- Affected <= 2.5.3; patched 2.5.4. Precondition: the victim runs the CHAP-only
  hardening configuration (`refuse-pap refuse-eap require-chap`), giving
  `ao->neg_upap=0, neg_eap=0, neg_chap=1`; the default accept-anything config
  takes the CONFREJ path instead. LCP is processed before authentication and
  pppd runs as root.
- Pins: 2.5.3 `96f962b9…`, 2.5.4 `379a630a…`, fix patches `8593bced…` and
  `4fa8b23a…`; full SHA256 in `lab/frontier/pppd2shell/pins/PIN_HASHES.txt`,
  re-verified at the top of `harness/run.sh`.

The advisory also claims a real-daemon ASan crash over a PTY serial link at
N=301/374 with a 19-byte normal CONFNAK control at N=3, plus a thin TCP
harness replay. Those are **claims from the advisory**, not local observations;
this brief does not rely on them for its grade.

## 2. Source-bound mechanism and fix

`pppd/lcp.c:221` declares `static u_char nak_buffer[PPP_MRU]` (1500 bytes) in
`.bss`. Vulnerable `lcp_reqci()` (`lcp.c:1482`) validates only each CI's own
length; it neither deduplicates options nor bounds `nakp`. With the CHAP-only
`ao` state, every 4-byte `CI_AUTHTYPE=PPP_PAP` CI (`03 04 c0 23`) takes the NAK
branch at `lcp.c:1609-1618` and writes a 5-byte CHAP suggestion
(`03 05 c2 23 <digest>`): 4→5 amplification. `ho->neg_upap` is only set on the
ACK path, so the duplicate never arms a guard; N CIs write 5N bytes. The 5th
byte is `CHAP_DIGEST(ao->chap_mdtype)`, chosen via the config (MD5 -> `0x05`,
Microsoft -> `0x80`). After the loop, `lcp.c:1852-1853` copies the whole NAK
back into the caller's 1504-byte input buffer — a second overflow the advisory
describes; this lab's harness sizes `req[]` to 4096 so only the first sink is
exercised.

Upstream 2.5.4 carries two fixes: `cc8b00c` adds a `seenci[]` table to
`lcp_reqci` (and the other `reqci` functions) so duplicate CIs are ignored;
`1baf2ac` additionally resets `nakp` on reject and turns CONFNAK into CONFREJ
once `nakp - nak_buffer > PPP_MRU - 8`. Both markers were grepped in the fixed
pin and asserted absent from the vulnerable pin by `run.sh`.

## 3. Measured evidence (this lab)

`lab/frontier/pppd2shell/harness/` extracts `lcp_reqci()` and the seven
`CILEN_*` defines verbatim from each pinned `lcp.c`, and compiles them against
the real pinned headers with only globals and debug stubs local (full inventory
in `PROVENANCE.md`). 320 repeated PAP CIs (1280 bytes in) request 1600 NAK
bytes. `bash harness/run.sh`: rc 0, 12 PASS / 0 FAIL, nine normalized logs.

- Vulnerable gcc and clang ASan: `global-buffer-overflow`, `WRITE of size 1`,
  top frame `lcp_reqci` in the verbatim pinned function, 0 bytes after
  `nak_buffer` of size 1500; nonzero rc.
- Vulnerable plain: `readback+1500=0305c223800305c2238…` past the sink — chosen
  `0x80` at offsets 1504, 1509, 1514 … . With `CHOSEN_MDTYPE=MDTYPE_MD5` the
  same offsets read `…0305c22305…`: the byte is chosen, not incidental.
- Fixed 2.5.4 ASan clean on gcc and clang; plain `out=5` (first CI NAKed once,
  duplicates ignored), readback zeros.
- Safe-input control (`CI_COUNT=2`) on both pins: `in=8`, no chosen bytes.
- Nine normalized hashes in `EVIDENCE_HASHES.txt`; two in-tree replays and a
  clean `git archive b3ec18d` replay produced byte-identical hashes (12/12
  PASS in the archive too). Normalization strips PID, paths, addresses,
  BuildId and frame prefixes.

## 4. Rung-4 feasibility and honest ceiling

Rung 1/2: deterministic trigger and observed buffer-accounting failure at the
real pinned function. Rung 3: natural ASan corruption in that function. Rung 4:
chosen byte (`0x80` or `0x05`) at a chosen relative offset past the sink, at
**direct-call scope only**. No pppd process, pty, kernel PPP device, wire
negotiation, pointer control or command execution: **no rung 5**. The advisory
claims a real daemon crash and near-adjacent `.bss` globals; reproducing that
here is the next experiment, not an established result. Content is constrained
to the repeating `03 05 c2 23 <digest>` pattern by the NAK builder; arbitrary
bytes at arbitrary offsets are NOT established.

Tractability: high for the lab's pattern — two pins, one 390-line C function,
real headers, no daemon or build system. This outranks the remaining queue
(FRR's OOB read is a weaker primitive; llama.cpp needs RDMA; Libreswan needs
non-default `listen-tcp` and a UAF).

## 5. Cheapest next experiment to move up a rung

Reproduce the advisory's real-daemon path locally: build pinned 2.5.3 pppd with
ASan, create a pty pair, spawn pppd on the slave with the CHAP-only config and
an explicit `chap-secrets` file, and send one RFC-1662 HDLC-framed LCP
Configure-Request with N=301 repeated PAP AUTHTYPE options from the master
side. Decisive controls: N=3 gives a normal 19-byte CONFNAK on the wire with
pppd alive; pinned 2.5.4 with the same frame stays clean; N=300 should expose
the second `BCOPY` overflow. Keep everything on the local pty. A successful
replay upgrades rung 4 from direct-call to a real process; it still is not
rung 5 without a chosen pointer or command side effect.

## 6. Candidates parked / screened this wake

- The two witness inbox verdicts (inetutils #1504, pgpool #1532) were
  grade-unchanged; the inetutils harness NIT was fixed in commit `0b8cc5e`.
- FRRouting CVE-2026-129217, llama.cpp CVE-2026-118375, Libreswan
  CVE-2026-94453 remain queued below this find, unchanged.
- Do not duplicate the admitted list in `walls/frontier.md`; NGINX/Node belong
  to other minds.
