# Provenance — inetutils2shell frontier harness (W116)

## Claim and pins

CVE-2026-32746 / MITRE CNA, CVSS 3.1 9.8
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-120: telnetd through 2.7 overflows
the SLC triplet buffer because `add_slc()` does not check remaining space.
Primary sources read: CVE record `https://www.cve.org/CVERecord?id=CVE-2026-32746`,
GNU bug report `https://lists.gnu.org/r/bug-inetutils/2026-03/msg00031.html`,
finder analysis `https://labs.watchtowr.com/a-32-year-old-bug-walks-into-a-telnet-server-gnu-inetutils-telnetd-cve-2026-32746`,
upstream fix `https://codeberg.org/inetutils/inetutils/commit/1ffb28a2ff7bef89b5f1e407b82c1f76ce8d9858`.

```
a156be1cde3c5c0ffefc262180d9369a60484087907aa554c62787d2f40ec086  pins/inetutils-2.7.tar.gz
57b3cf4f77555992881e5ba2a09a63b05aa2c56342a60ed4305b5f45938390b5  pins/inetutils-2.8.tar.gz
5729c658790c422e5b1301f14de046f791a2ad56ab8368d45e9784fcf891d988  pins/fix-slc.patch
1adbf6d42a4ecd81157125b2b03815a5f761efe16d0cf3fee11f022cfb72dfc3  src/inetutils-2.7/telnetd/slc.c
1331bbe30fcc0a1393010b619b6da13a07ae34c25a2f981d4ce6de8435c9af7b  src/inetutils-2.8/telnetd/slc.c
b8ad6d38b4dfb3eb2867e9d8f8da1a527208fef68991bf616049d18de6a284c8  harness/gen_slc.py
9923e3908dbf613c27cf33eb50461ba09c26f873e751a4e2759bdb6f2e17e904  harness/harness.c
e72e3719c92d51aa338162e6bf3b5a3e959853a46328d5b9a29c02e017adeb8b  harness/run.sh
```

Pinned source facts: `NSLC=18` (`/usr/include/arpa/telnet.h:196`), so
`slcbuf[NSLC*6]` is 108 bytes (`telnetd/slc.c:59`); `slcptr` starts at
`slcbuf+4` in `start_slc()`. Vulnerable `add_slc()` at `slc.c:163-175` writes
one to three bytes per triplet with no space check, doubling any 0xff byte.
Fixed 2.8 adds at `slc.c:165-166`:
`if (slcbuf + sizeof slcbuf - slcptr <= 6) return;`.

## What the harness executes

`gen_slc.py` extracts `start_slc()` and `add_slc()` verbatim from each pinned
`telnetd/slc.c`, including the `void` return type line. The harness supplies
only the pinned global declarations, `init_termbuf()` and the arpa/telnet.h
constants. It calls `start_slc(0)` then 50 `add_slc(0x42, 0x41, 0x5a)` calls:
the 35th triplet crosses the 108-byte buffer end. ASan builds detect the
natural global redzone hit in the verbatim pinned writer; plain builds read
the chosen triplet bytes back past `slcbuf`. The readback loop is compiled out
of ASan builds so the fixed ASan control stays clean. No telnet listener,
option FSM, process or non-loopback traffic is involved.

## Observed output (2026-11-22 17:55Z, two replays, byte-identical)

`bash harness/run.sh` rc 0, 8 PASS / 0 FAIL. Vulnerable plain:
`slcbuf_size=108 slcptr_offset=154`,
`readback+0=42415a42415a42415a`. Vulnerable ASan:
`global-buffer-overflow`, `WRITE of size 1`, frame `add_slc` at
`gen-vuln/slc_functions.inc:24`, 0 bytes after 108-byte `slcbuf`. Fixed ASan
clean rc 0; fixed plain has no chosen readback.

Normalized hashes (`EVIDENCE_HASHES.txt`); normalization strips PID, addresses,
BuildId and absolute lab/harness paths:

```
22d3fd2d93f3815cee2f35aed09724579ea10d8ce09fb924c3b39c005dffc88b  norm-fixed-asan.log
671a6186850e6af3e449473156e7534cee8814a0f73bbfb791b333bf71affc35  norm-fixed-plain.log
e52445a882a51e09b89722b8678e795094de702bd2434b823d81b773b158e1bd  norm-vuln-asan.log
0ec51f6c10b7f0f176339f6cf37363731e2cd0bd2a6910313139262e0c254551  norm-vuln-plain.log
```

## Limits / unknowns

Rung 3 natural ASan on the verbatim pinned global writer; rung 4 chosen bytes
at a chosen relative offset past the global at direct-call scope. No real
telnetd option negotiation, socket, allocator neighbour, pointer control,
command or rung 5. Finder analysis explicitly found no direct RCE route on
their observed 64-bit systems; exploitability constraints (func/flag/val byte
restraints, 0xff doubling, subnegotiation length) remain UNKNOWN locally.
Witness replay owed.
