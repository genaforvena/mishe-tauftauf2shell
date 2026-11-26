# libx11xkb2shell — provisioning provenance

All fetches were read-only public provisioning. The harness is entirely
in-process: no X server, socket, scan or connection to any external system.

## Advisory and tags

- CVE-2026-88806 (CNA SUSE, published 2026-09-21):
  https://www.cve.org/CVERecord?id=CVE-2026-88806 — libX11 before 1.8.14,
  XkbGetMap reply overflows `key_sym_map`; CVSS 3.1 7.5 and RCE prose are
  advisory claims, not local results.
- X.Org security advisory 2026-10-16:
  https://lists.x.org/archives/xorg/2026-October/062301.html — keycode values
  exceeding max_keycode + 1 write past the end of an allocated array; fixed
  in libX11 1.8.14. ZDI-26-906 / ZDI-CAN-32061.
- Fix commit `6d4432b13c0b3b6a644c13de9c793a14db48d545` (Peter Hutterer,
  2026-09-16): https://gitlab.freedesktop.org/xorg/lib/libx11/-/commit/6d4432b13c0b3b6a644c13de9c793a14db48d545
  adds one bound check in `src/xkb/XKBGetMap.c` before the actions loop.
- Tarballs from https://www.x.org/archive/individual/lib/ are authoritative
  for the released tags; `configure.ac` in each reports `AC_INIT([libX11],
  [1.8.13|1.8.14])`. x.org publishes no per-file SHA256SUMS here; the hashes
  below were computed from the fetched bytes and are rechecked each run.

## SHA-256 pins (verified 2026-11-26)

| artifact | SHA-256 |
| --- | --- |
| `src/libX11-1.8.13.tar.xz` | `69606f485c2c07c14ef64f75b7bb326d48587af33795d9ab3e607c0b5f94f11c` |
| `src/libX11-1.8.14.tar.xz` | `bbc78c46217174655c2b32b138ad119f3ac15f50808b4d0b3a2677a4b1afc950` |
| `src/fix-6d4432b13.patch` (raw GitLab commit patch) | `dd9ecf20d2ca40c7ec3d8cdf3727c729f9fae3b6cc010e9436f152ae7cd6da31` |
| `expose.patch` (linkage-only harness change) | `bdd621bf41ad6408d90440d507ab6d157746471905cf7ac1fc688bd4e10a4e18` |
| `poc.c` (local harness) | `6fb103171874e308a5da4609f566bc087e9f4dbff40ad85d03e3482cb859ad7d` |

## Pinned source facts

- 1.8.13 `src/xkb/XKBGetMap.c:245` defines `static Status
  _XkbReadKeyActions(...)`; verbatim `:277` writes
  `info->server->key_acts[i + rep->firstKeyAct] = 0` after an
  `i + firstKeyAct > max_key_code + 1` check. Nonzero descriptors go through
  `XkbResizeKeyActions()` (verbatim `src/xkb/XKBMAlloc.c:808`), which writes
  the same array.
- 1.8.14 `src/xkb/XKBGetMap.c:256` adds
  `if (((int) rep->firstKeyAct + rep->nKeyActs) > (info->max_key_code + 1)) return BadLength;`
  before allocating `numDesc` and entering the loop.
- `expose.patch` removes only `static` from `_XkbReadKeyActions` in both
  trees; no branch, index or allocation is changed. It applies with a one-line
  offset in both tags. The harness calls that real function with a synthetic
  `XkbReadBufferRec` and `xkbGetMapReply`, not a reimplementation.
- `rep->firstKeyAct` is CARD8: values such as 256 wrap to 0, so the reachable
  index is bounded by 255 + `nKeyActs`. The reproducer uses 8 + 2 against
  `max_key_code = 8` and a 9-entry `key_acts` array. `key_sym_map` is
  intentionally given 64 entries so no earlier out-of-bounds read masks the
  write under ASan. The chosen `0x5a` action bytes are in-bounds payload;
  the value written out of bounds is the constant zero from the zero-action
  branch.

## Negatives and dead ends preserved

- First attempt used `firstKeyAct = 256`; CARD8 truncated it to 0 and the
  harness exited 0. Replaced with an 8 + 2 index split.
- Second attempt used eight nonzero descriptors. ASan's first report was a
  read at `XKBMAlloc.c:804` from a NULL `acts` array in the resize slow path,
  before the intended write. Priming `acts` then still left the same index
  read at `:804` ahead of the write. The final zero-action branch has no
  preceding read of the out-of-range index and produces a clean WRITE-2.
- Advisory RCE and "malicious server" framing are claims: the harness does
  not perform an X11 handshake and contacts no server, so no wire-path,
  pointer-control, command-execution or rung-5 claim is made.
- No named adjacent object was measured. Rung 4 stays PARTIAL until a plain
  allocator layout shows bytes landing in a named field.
