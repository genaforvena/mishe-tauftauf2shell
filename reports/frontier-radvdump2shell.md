# Frontier brief: radvd (radvdump) — CVE-2026-48715 (radvdump2shell)

**STAGED 2026-11-23 W140 — direct-call harness evidence and a live two-pane
target window exist; no operator admission yet.** Provenance and byte-exact
pins: `lab/frontier/radvdump2shell/PROVENANCE.md`. Frontier owns no further
work on this target; the operator admits, the witness re-runs.

## 1. Verified ground truth

- Advisory: GHSA-52px-gh9p-m379, "Stack Buffer Overflow in radvdump Route
  Information Option Parser", published 2026-05-25, HIGH, CVSS 7.7
  `CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`,
  CWE-121 — https://github.com/radvd-project/radvd/security/advisories/GHSA-52px-gh9p-m379
- CVE: https://www.cve.org/CVERecord?id=CVE-2026-48715
- Affected `radvd <= 2.20`; patched `2.21`. Advisory explicitly excludes the
  main `radvd` daemon; only the `radvdump` RA-dump utility is affected. The
  advisory confirms 2.20 and HEAD `878ca6b` as vulnerable.
- Fix commit `068bde13e3fd6a5fcdb6859e6a2acd293a325dc5`, "feat: harden
  radvdump (CVE-2026-48715)" —
  https://github.com/radvd-project/radvd/commit/068bde13e3fd6a5fcdb6859e6a2acd293a325dc5
- Claimed primitive: a crafted ICMPv6 Router Advertisement Route Information
  option carries a length byte up to 255, so `print_ff()` copies up to
  `(255-1)*8 = 2032` attacker-controlled bytes into a 16-byte stack
  `struct in6_addr`. RFC 4191 section 2.3 permits length 1, 2 or 3 only.
  Pre-auth, network-adjacent, no credentials. The advisory claims saved
  RBP/RIP corruption; it publishes no exploit or wire PoC.

## 2. Source-bound mechanism and fix

Byte-exact pins (SHA-256 in `src/SHA256SUMS`): `radvdump.c.878ca6b` and
`radvdump.c.v2.20` are identical (sha256 `0beaaaf7…86b355b`);
`radvdump.c.068bde13` and `radvdump.c.v2.21` are identical
(`bfe1f0f6…cb47b48b5`). Rendered line numbers are claims; raw bytes rule.

Vulnerable `print_ff()`, pinned `radvdump.c.878ca6b:371-383`:

```c
case ND_OPT_ROUTE_INFORMATION: {
    struct nd_opt_route_info_local *rinfo = (struct nd_opt_route_info_local *)opt_str;
    if (optlen == 8) { ... } else {
        struct in6_addr addr;                       /* 16 bytes */
        memset(&addr, 0, sizeof(addr));
        if (rinfo->nd_opt_ri_len > 1)               /* no upper bound */
            memcpy(&addr, &rinfo->nd_opt_ri_prefix, (rinfo->nd_opt_ri_len - 1) * 8);
        addrtostr(&addr, prefix_str, sizeof(prefix_str));
        ...
```

The outer option loop only checks the whole option's `optlen = (byte[1]<<3)`
against the remaining RA length, so length 33 gives a 264-byte option that
passes and a 256-byte copy into a 16-byte object. The length byte and the
copied source bytes are both attacker-controlled.

Fix `068bde13` adds, before the unchanged `memcpy` (pinned
`radvdump.c.068bde13:432-443`):

```c
if ((rinfo->nd_opt_ri_len > 3)
    || (rinfo->nd_opt_ri_len == 0)
    || (rinfo->nd_opt_ri_prefix_len > 64 && rinfo->nd_opt_ri_len < 3)
    || (rinfo->nd_opt_ri_prefix_len > 0 && rinfo->nd_opt_ri_len < 1)) {
    flog(LOG_ERR, "Invalid Route Information option length %d from %s", ...);
    printf("# Invalid Route Information option length %d, per RFC4191 section 2.3 ", ...);
    break;
}
```

The same commit also drops root, zeroes buffers and fixes jumbo-packet
truncation; those hunks are outside this harness's callpath and are not
claimed as reproduced. The fix's earlier-loop `break` → `goto
end_of_interface` change is likewise outside the extracted second-loop case.

## 3. Cheapest local experiment

One C file, no daemon, no codec, no socket. Build a 280-byte RA: 16-byte
`struct nd_router_advert` (type 134) plus one option with type 24
(`ND_OPT_ROUTE_INFORMATION`), length byte 33 (`optlen=264`), prefix length 0,
and source bytes chosen by the harness. Call the verbatim case body with that
packet. An RFC-conformant option (length byte 2, copy 8) is the safe control;
the fixed commit and release 2.21 are the fixed controls; release 2.20 is a
second vulnerable control.

## 4. Rung-4 feasibility and risks

Feasible locally: a 16-byte destination and fully controlled 256-byte source
give a clean write primitive. Risks measured below: the plain build must be
compiled `-fno-stack-protector` (Ubuntu's default `-fstack-protector-strong`
turns the overflow into a "stack smashing detected" abort before observation);
ASan faults on the WRITE before any later control-flow effect; the harness
uses a direct call with stubbed `flog`/`addrtostr`/`print_preferences`, not a
real `radvdump` process, raw socket or live RA. Control of the saved RIP is
observed under gdb but not turned into a working return chain, command or
witness. No remote execution is claimed.

## 5. W140 local result — staged, rung 4 scoped

Harness: `lab/frontier/radvdump2shell/harness/run.sh`. It re-extracts four
verbatim case bodies from the pinned blobs on every run (`#line` directives
preserve pinned line numbers), checks a 6-file source manifest and a 12-file
harness manifest, builds four plain and four sanitizer binaries, and drives
rungs 1-4. **67 PASS / 0 FAIL three times**, plus a clean `/tmp` replay;
normalized trace hash
`cf327179a2abca7647a1a8bd3b58259a398c7de94f24a27910f3a356d8d3788a`.

- Rung 1 — arithmetic with no vulnerable call: length 33 passes the `>1`
  gate; copy 256 vs destination 16, overflow 240.
- Rung 2 — state failure: vulnerable and release 2.20 accept the 264-byte
  option, copy attacker bytes into the destination and reach formatting with
  no length rejection; fixed commit and release 2.21 log "Invalid Route
  Information option length 33" and never reach the copy or formatter.
- Rung 3 — gcc and clang ASan: `stack-buffer-overflow`, `WRITE of size 256`
  at pinned `radvdump.c.878ca6b:380`, in `route_case`; fixed and release 2.21
  ASan builds clean; RFC-conformant safe input clean on all six ASan/plain
  variants.
- Rung 4 — chosen bytes at chosen offsets past the 16-byte object
  (17=`5a`, 24=`7a`, 33=`3c`, 40=`7b`, 63=`7e`) observed both by the plain
  harness and by gdb at pinned line 381; gdb `info frame` reports
  `saved rip = 0x414141414141417b`, i.e. a chosen byte in the saved return
  address. The plain process subsequently faults at pinned line 382.
  `evidence/gdb-frame.out` carries the normalized frame dump.

Ceiling: direct call, stubbed radvd plumbing, `-fno-stack-protector` plain
builds, harness-chosen 280-byte RA; no live `radvdump`, raw socket, IPv6
neighbour, groomed allocator, ROP chain, pointer-sized control beyond the
saved-RIP byte, command or witness.
