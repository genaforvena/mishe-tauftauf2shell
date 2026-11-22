# Frontier brief: GNU inetutils telnetd — CVE-2026-32746 (inetutils2shell)

Status W116 (2026-11-22 17:56Z): screened in and staged as `inetutils2shell`,
find commit `b1c02f3`. Duplicate check done before provisioning: no prior
`reports/frontier-*telnet*`, no telnet/inetutils window or mind on the tape.
Admission remains the operator's call; wake units/presentation stay with the
person.

## 1. Verified ground truth

- Claim: MITRE CVE-2026-32746, telnetd through 2.7 writes past its LINEMODE
  SLC triplet buffer because `add_slc()` never checks remaining space;
  CVSS 3.1 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-120. Fixed in 2.8.
- Sources read: CVE record
  `https://www.cve.org/CVERecord?id=CVE-2026-32746`, GNU bug report
  `https://lists.gnu.org/r/bug-inetutils/2026-03/msg00031.html`, Finder
  writeup `https://labs.watchtowr.com/a-32-year-old-bug-walks-into-a-telnet-server-gnu-inetutils-telnetd-cve-2026-32746`,
  upstream fix commit `1ffb28a2ff7bef89b5f1e407b82c1f76ce8d9858`, and both
  pinned release tarballs. No external host was probed.
- Pins: vulnerable 2.7 `a156be1c…`, fixed 2.8 `57b3cf4f…`, fix patch
  `5729c658…`; full hashes in `lab/frontier/inetutils2shell/pins/PIN_HASHES.txt`
  and `PROVENANCE.md`. The 2.8 release was read back and contains the guard;
  the patch is a 3-line addition to `slc.c`.

## 2. Source-bound mechanism and fix

`NSLC=18` from arpa/telnet.h makes `static unsigned char slcbuf[NSLC*6]` a
108-byte global (`telnetd/slc.c:59`); `start_slc()` sets `slcptr=slcbuf+4`.
Vulnerable `add_slc()` (2.7 `:163-175`) writes func, flag and val bytes,
doubling any 0xff byte, without comparing `slcptr` to `slcbuf+sizeof slcbuf`.
Client-controlled SLC triplets are processed pre-auth after LINEMODE/WILL
negotiation (source-observed, not measured locally). The upstream fix adds
`if (slcbuf + sizeof slcbuf - slcptr <= 6) return;` at 2.8 `slc.c:165-166`.

## 3. Measured evidence

`lab/frontier/inetutils2shell/harness/` extracts both pinned functions
verbatim, supplies only the pinned globals and `init_termbuf()` stub, and
calls `start_slc(0)` then 50 chosen triplets over an ASan/plain build matrix.
`bash harness/run.sh`: rc 0, 8 PASS / 0 FAIL; two in-tree replays and a clean
`git archive b1c02f3` replay produced byte-identical normalized hashes.

- Vulnerable ASan: natural `global-buffer-overflow`, `WRITE of size 1`, top
  frame `add_slc` in the verbatim pinned function, 0 bytes after 108-byte
  `slcbuf`; rc nonzero.
- Vulnerable plain: `slcbuf_size=108 slcptr_offset=154` and
  `readback+0=42415a42415a42415a` past the buffer end — chosen bytes at a
  chosen relative offset.
- Fixed 2.8 ASan clean rc 0; fixed plain has no chosen readback.
- Four normalized hashes in `PROVENANCE.md` / `EVIDENCE_HASHES.txt`.

Rung 1/2: deterministic trigger and observed buffer accounting failure.
Rung 3: natural ASan on the real pinned global writer. Rung 4: chosen bytes
at a chosen relative offset, direct-call scope only. Rung 5: no — no telnetd
process, wire negotiation, pointer control or command. Finder writeup reports
no direct RCE route on observed 64-bit systems; our exploitability is UNKNOWN.

## 4. Cheapest next experiment

Compile pinned 2.7 telnetd with ASan and a loopback-only listener, send
`IAC DO LINEMODE`, `IAC WILL LINEMODE` and one `IAC SB LINEMODE LM_SLC`
subnegotiation with enough >NSLC function-byte triplets to pass 108 bytes,
and observe the `add_slc` global overflow in a real daemon. Decisive controls:
2.8 rejects/truncates without ASan report and a short subnegotiation is clean.
If that holds, map which adjacent BSS objects the triplet constraints can
reach before claiming any pointer or control-flow result.

## 5. Candidates parked this wake

See the duplicate-retracted BZFlag episode in `walls/frontier.md` W116: BZFlag
CVE-2026-130849 was already owned as `bzfs2shell`. Other read-only screens:
MOOSDB CVE-2026-85440 (unmerged fix), PJSIP CVE-2026-57159 (derived bytes,
non-default flag), Cesanta Mongoose CVE-2026-52048 and NanoMQ CVE-2026-32135
(lower primitive), libyang GHSA-44h9-v855-6rj3 (no listener), fqterm
CVE-2026-131875 (client-only), X.Org CVE-2026-109093 (authenticated client),
H2O/FRR/llama.cpp (fixed NUL, FSM, local files). Witness replay requested.
