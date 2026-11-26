# frontier-libx11xkb2shell — libX11 XKB action parser OOB WRITE (CVE-2026-88806)

## Claim source and scope

- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-88806 — "libX11
  XkbGetMap Reply Heap-based Buffer Overflow", CWE-122, CVSS 3.1 7.5
  (`AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H`), CNA SUSE, published 2026-09-21.
  Affected: libX11 before 1.8.14. The RCE implications are the advisory's
  claim, not a local result.
- X.Org security advisory 2026-10-16:
  https://lists.x.org/archives/xorg/2026-October/062301.html — "Out-of-bounds
  write vulnerability in libX11's XKB action parser. A malicious server could
  send a XkbGetMap reply with keycode values exceeding max_keycode + 1,
  causing a write past the end of the allocated array during reply handling."
  Found by Adam Bedard with ZDI (ZDI-CAN-32061).
- ZDI-26-906: https://www.zerodayinitiative.com/advisories/ZDI-26-906/ calls
  it RCE; that rating is a claim. Fix commit:
  https://gitlab.freedesktop.org/xorg/lib/libx11/-/commit/6d4432b13c0b3b6a644c13de9c793a14db48d545
  (`dd9ecf20…` as fetched raw patch), merge request 309.

## Source-bound mechanism

In libX11 1.8.13 `src/xkb/XKBGetMap.c`, `_XkbReadKeyActions()` sets
`symMap = &info->map->key_sym_map[rep->firstKeyAct]`, then loops over
`rep->nKeyActs` descriptors from the reply. The per-key zero-action branch
at verbatim line 277 checks only `i + firstKeyAct > max_key_code + 1` and
then writes `info->server->key_acts[i + firstKeyAct] = 0`; the nonzero branch
calls `XkbResizeKeyActions()` (XKBMAlloc.c), which writes the same array.
`key_acts` is allocated with `max_key_code + 1` entries by
`XkbAllocServerMap()`. `firstKeyAct` is CARD8, so the reachable index is at
most 255 plus `nKeyActs`.

The fix adds, before the loop:
`if (((int) rep->firstKeyAct + rep->nKeyActs) > (info->max_key_code + 1)) return BadLength;`
It is present at verbatim 1.8.14 `src/xkb/XKBGetMap.c:256` and absent in
1.8.13. No other logic change in that commit.

## Local experiment (rung 3 observed, rung 4 PARTIAL)

`lab/frontier/libx11xkb2shell/run-all.sh` rebuilds pinned upstream tarballs
(1.8.13 vulnerable, 1.8.14 patched) under GCC+Clang ASan and GCC plain,
applies the linkage-only `expose.patch` (static -> external; no logic change)
and calls the real `_XkbReadKeyActions()` with a synthetic
`xkbGetMapReply`/`XkbReadBuffer`. No socket, X server or external target is
involved. `poc.c` sets `max_key_code = 8`, `key_acts` to 9 entries,
`firstKeyAct = 8`, `nKeyActs = 2`, and reply descriptors `[1, 0]`.

Observed on 1.8.13 under both compilers:
`ERROR: AddressSanitizer: heap-buffer-overflow`, `WRITE of size 2`, at
verbatim `src/xkb/XKBGetMap.c:277` in `_XkbReadKeyActions`, 0 bytes after the
18-byte `key_acts` allocation. On 1.8.14 the same reply returns `BadLength`
(status 1) with no ASan report; safe inputs (`firstKeyAct = 1`) succeed in
both trees. Full pins, hashes, trace files and preserved negatives are in
`lab/frontier/libx11xkb2shell/PROVENANCE.md`.

Grade: **rung 3 verbatim / rung 4 PARTIAL**. Server-controlled length and
index produce a deterministic 2-byte OOB write, but the written value is
zero from a synthetic in-process reply; no named adjacent object, pointer
control, live X wire, command execution or r5.

## Cheapest next rung-moving experiment

Drive public `XkbGetMap()` through a loopback-only mock X server (X11 setup
handshake, XKB extension negotiation, forged `xkbGetMapReply`) so the same
overflow occurs on a real library entry point with wire-derived bytes; then
measure whether a nonzero acts offset can land in an adjacent heap object.
Absent that measurement, keep the PARTIAL rung-4 label. Would change the
assessment: a fixed-tag ASan WRITE, a witness counterexample, or a plain
allocator layout showing chosen bytes in a named adjacent field.
