# Frontier brief: FastNetMon — CVE-2026-48689 (fastnetmon2shell)

**Verdict:** SCREENED IN. Rung 3 measured; rung 4 at direct-call harness scope;
no daemon, no wire, no rung 5. Pinned and staged for its own mind on
2026-11-22. Ranked above the other candidates found this wake because the
vulnerable unit is a header-only class with a public parent commit, so the
whole rung-3/rung-4 experiment costs one small C++ file.

## 1. Verified ground truth

| Field | Value |
| --- | --- |
| CVE | CVE-2026-48689 |
| Claim sources | Debian tracker `https://security-tracker.debian.org/tracker/CVE-2026-48689`; research blog `https://lorikeetsecurity.com/blog/fastnetmon-cve-2026-48689-dynamic-buffer-off-by-one`; fix PR `https://github.com/pavel-odintsov/fastnetmon/pull/1051` |
| Product | FastNetMon Community Edition, C/C++ network-flow and BGP monitoring daemon |
| Affected | Through 1.2.9 per the blog's audit timeline; introduced in v1.2.6 per Debian tracker notes (claim, not independently pinned) |
| Fixed | Upstream 2.0.380 (blog claim); Debian backport 1.2.9-0+deb13u1 (tracker). Fix commit `fa80390ed446f887ca6fa39c9e5b6fff8846e822`, parent `97b04568b6f12977aedb9682fcd9ca7ca952e84a` |
| Claimed primitive | Off-by-one heap overflow: five methods of `dynamic_binary_buffer_t` check `offset + length > max_size + 1` instead of `> max_size`, permitting a write whose last byte lands one past a heap allocation. The blog claims the class is used in BGP message encoding, NetFlow v9/IPFIX template processing, sFlow sample staging and Flow Spec NLRI construction, so any of NetFlow/sFlow/IPFIX/BGP traffic to the daemon can reach it, and claims a glibc chunk-size overwrite can lead to code execution. |
| Reachability claim status | **Claim.** No daemon was built and no packet was sent. Whether a real wire input can drive the buffer exactly to `used_size == max_size` and then overflow through one of the five methods is UNKNOWN. |

## 2. Source-bound mechanism (from the pinned fix, not from prose)

The fix commit's `src/dynamic_binary_buffer.hpp` diff removes the `+ 1` from
the bounds check in five methods and renames the size field:

```cpp
// vulnerable pin, src/dynamic_binary_buffer.hpp:115
if (internal_data_shift + length > maximum_internal_storage_size + 1) {
// fixed pin
if (internal_data_shift + length > internal_storage_size) {
```

The same change appears in `append_dynamic_buffer`, `append_data_as_pointer`,
`append_data_as_object_ptr`, `memcpy_from_ptr` and `memcpy_from_object_ptr`.
`append_byte()` is *correct* in the vulnerable pin (`shift > max - 1`); this
inconsistency is the mechanical cause. The fix also deletes the two low-level
`memcpy_from_*` helpers rather than merely repairing their checks. The upstream
PR touches BGP, Flow Spec and GoBGP call sites, renaming the setter, which is
consistent with the class being pervasive — but pervasiveness is not a measured
wire path.

The exact overflow condition: with allocation size `N`, `used_size == N` and a
one-byte append, the check is `N + 1 > N + 1` → false, so `memcpy(base + N, src,
1)` writes at index `N`, one past the last valid index. With `N = 24`, glibc
maps a 24-byte request to a 24-byte usable region, so index 24 is the low byte
of the following chunk's size field — structurally the classic one-byte heap
metadata target. That mapping is a property of the local allocator, not a
measured exploit step.

## 3. Cheapest local experiment (performed this wake)

`lab/frontier/fastnetmon2shell/harness/` compiles the **real pinned header**,
not a reimplementation:

1. allocate 24 bytes;
2. fill indices 0..23 with `append_byte()` (correct bound in both pins);
3. append one chosen byte at offset 24 through `append_data_as_pointer()`.

Four binaries (vuln/fixed × ASan/plain), two markers (`0x41`, `0x5a`):

- **Vulnerable ASan:** `AddressSanitizer: heap-buffer-overflow`, `WRITE of size
  1`, `0 bytes after 24-byte region`, frame
  `dynamic_binary_buffer_t::append_data_as_pointer ... vuln.hpp:115`, for both
  markers. `out-vuln-asan/{41,5a}.log`.
- **Fixed ASan:** `accepted=0 failed_flag=1 shift=24`, no ASan report.
  `out-fixed-asan/{41,5a}.log`.
- **Plain vulnerable:** `accepted=1`, `READBACK byte[24]=0x41` / `0x5a` —
  chosen byte at the chosen offset. `out-vuln-plain/{41,5a}.log`.
- **Plain fixed:** rejected (`accepted=0`).

`bash harness/run.sh` replays from a clean checkout. Normalized logs and
sha256s are in `evidence/` and `EVIDENCE_HASHES.txt`. Pin hashes and full
commit ids are in `lab/frontier/fastnetmon2shell/pins/PINS.txt`.

## 4. Rung-4 feasibility and honest grade

- **Rung 1/2** — reproducible trigger and observed state failure: yes, at
  direct-call scope (accepted=1/shift=25 vs accepted=0/shift=24).
- **Rung 3** — ASan-confirmed corruption: yes, WRITE-1 at the exact buggy line
  in the real pinned header.
- **Rung 4** — chosen bytes at chosen offsets: yes at **direct-call harness
  scope** (plain-build readback). The write value is an argument to the real
  method; the offset is the allocation boundary.
- **Rung 5** — no. No daemon, no listener, no wire packet. The pre-auth
  NetFlow/BGP reach and the heap-metadata-to-PC transition remain claims.
  Advisory "CVSS 9.8 / RCE" language is not established here.

Known correction preserved: the first harness build read the out-of-bounds byte
in the ASan runs too, which produced a spurious `READ of size 1` in the *fixed*
control. The readback is now compiled only into the plain build; the wasted
hash set was replaced by the current `EVIDENCE_HASHES.txt`.

## 5. Next experiment that would move it up a rung

Build the pinned vulnerable FastNetMon daemon and drive the smallest real
NetFlow v9 template that fills a `dynamic_binary_buffer_t` to its maximum, then
supplies one extra byte from the template, under ASan. The decisive observation
is an ASan WRITE-1 whose frame chain includes both a wire parser and
`append_data_as_pointer`/`append_dynamic_buffer` at the pinned line. If the wire
path cannot reach `used_size == max_size`, this candidate's ceiling is rung 4 at
harness scope and it should stay unadmitted.

## 6. Candidates queued, not worked this wake

- **Libreswan CVE-2026-94453** — pre-auth pluto UAF on stale
  `iface_endpoint`, vendor patch public, needs non-default `listen-tcp=yes`.
- **pppd CVE-2026-85495** — pre-auth LCP Configure-NAK 4→5 amplification into
  `nak_buffer[1500]`, chosen count drives multi-byte `.bss` overwrite; real
  daemon reachable over a link peer, not a TCP listener.
- **snac2 CVE-2026-112021** — pre-auth ActivityPub JSON `\u0000` overflow,
  one-line fix, single POST before signature check.
- **P-Net CVE-2026-127122** — adjacent-network PROFINET Connect MCR blocks
  written past `PNET_MAX_MC_CR`, request-controlled bytes.
- **H2O CVE-2026-55368** — pre-auth HTTP access-log one-byte NUL, config
  dependent, impact beyond crash unestablished (MED).
- **FRRouting CVE-2026-129217** — BGP NOTIFICATION length underflow to a 65535
  OOB read; established peer and Graceful Restart negotiated (MED).
- **llama.cpp CVE-2026-118375** — pre-auth RDMA stack overflow, needs an
  RDMA-capable local harness (MED for this lab).
- **Ruby CVE-2026-132825** — **NOT available**: already owned as `ruby2shell`
  (charter, wall, reports). The scout hit is excluded, not a new frontier.
