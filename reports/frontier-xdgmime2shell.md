# frontier-xdgmime2shell — xdgmime magic byte-swap heap OOB WRITE (CVE-2026-16118)

## Claim source and scope

- Upstream public issue: https://gitlab.freedesktop.org/xdg/xdgmime/-/work_items/41
  ("CVE-2026-16118", YesWeHack report #YWH-PGM9867-233, reported 2026-02-14,
  published after the 90-day disclosure deadline, discovery credit asotyc).
  It claims a heap-buffer-overflow write in
  `_xdg_mime_magic_parse_magic_line()` in `xdgmimemagic.c` on little-endian
  builds, reachable from attacker-controlled MIME magic content in a
  user-writable XDG data location.
- Fix commits: GLib
  `ca75aff83af9875ea2ad2bfbe48a85dfd99c2ce5` (parent
  `4ef012af942d517b84fac2d25c9031016818bb3d`, 2026-08-05) and the standalone
  xdg/xdgmime equivalent `1debecbfe5a643dd7bd1a70f40cf86b007edbd43` (parent
  `0305e05c8b8efa98e69880597f79c7cd1ba3c150`, 2026-08-05). Both change the
  same four lines. Distro fold: Oracle Linux ELSA-2026-98557, glib2 2.80.4-23.
- The issue includes a PoC magic file (`value_length=4`, `~2`) and an ASan
  trace at `xdgmimemagic.c:486` through
  `g_content_type_guess()` → `xdg_mime_init_from_directory()` →
  `_xdg_mime_magic_read_from_file()`. That GLib consumer trace is a *claim*
  reproduced here only as an in-process file-fed harness, not as a live
  service or wire request.
- Checked before staging: no report, charter, manifest row or lab lane for
  xdgmime/GLib magic parsing; no shared CVE with an admitted target.

## Source-bound mechanism

In the pinned vulnerable `src/xdgmimemagic.c:483-493`, after a magic line is
parsed, the little-endian byte-swap loop steps `i` by `word_size` **bytes**:

```c
for (i = 0; i < matchlet->value_length; i = i + matchlet->word_size)
  if (matchlet->word_size == 2)
    *((xdg_uint16_t *) matchlet->value + i) = SWAP_BE16_TO_LE16 (*((xdg_uint16_t *) (matchlet->value + i)));
```

The right-hand side casts *after* adding the byte offset (correct); the
left-hand side casts *before* adding it, so C pointer arithmetic scales the
step by `sizeof(xdg_uint16_t)` (or 4 for `word_size == 4`). With
`value_length=4, word_size=2` the loop runs at `i=0` and `i=2`: the second
iteration writes 2 bytes at `value+4`, immediately past the 4-byte
`malloc` at `:392`. The same defect applies to `matchlet->mask` when `&` is
present. The fix parenthesizes `(value + i)` / `(mask + i)` on the write side;
the read side is unchanged.

The standalone project's own `meson.build` does not define `LITTLE_ENDIAN`, so
the swap branch is compiled out in an unmodified standalone build. The harness
passes `-DLITTLE_ENDIAN=1` (a build-configuration flag, not a source edit) to
select the same branch that GLib's little-endian build config selects and that
the public issue's ASan trace shows executing. Both pinned source trees are
otherwise byte-for-byte as fetched.

## Local evidence

Harness `lab/frontier/xdgmime2shell/`: `poc.c` uses only the public
`_xdg_mime_magic_new()` / `_xdg_mime_magic_read_from_file()` /
`_xdg_mime_magic_get_buffer_extents()` / `_xdg_mime_magic_free()` API;
`probe.c` includes the **unmodified** pinned `xdgmimemagic.c` so an
ASan-recover run can read back the bytes the parser wrote. All eight library
sources come from the pinned tarballs; no socket, listener, pcap or external
system. Canonical runner `run-all.sh` sha256
`f19f15d9f5dcd292353a82030b590dc7aeac48f1fea136e4e872855fd2e17205`:
**RESULT PASS=39 FAIL=0**, rc 0, GCC 13.3 and Clang 18.1.3, 16.5 s.

- Vulnerable ASan, `word_size=2`: `ERROR: AddressSanitizer:
  heap-buffer-overflow`, `WRITE of size 2`, `0 bytes after 4-byte region`,
  write at real pinned `xdgmimemagic.c:486`, allocation at `:392`, called from
  `_xdg_mime_magic_read_magic_file:773` and `_xdg_test_magic_read_from_file:815`
  from `poc.c:19`. Both compilers.
- Chosen bytes: magic value `41 42 43 44`; recover-mode readback of the parsed
  matchlet shows `42 41 43 44 | 44 43` — the chosen `43 44` second word is
  byte-swapped and written as `44 43` at offsets 4/5, in ASan poison. Plain
  builds show the same bytes. The in-bounds second word is *not* rewritten.
- `word_size=4`, value `41..48`: ASan `WRITE of size 4`, `8 bytes after
  8-byte region`; chosen last word lands at offsets 16..19.
- With `&EFGH` mask: two `WRITE of size 2` reports, 0 bytes past both the
  4-byte value and 4-byte mask regions; mask readback `46 45 47 48 | 48 47`.
- Controls: fixed commit `1debecbf` on the same input is ASan-clean, prints
  `extents=5` (matchlet parsed) and leaves offsets 4/5 at `00 00`; safe
  `word_size=1` on the vulnerable build is also ASan-clean.

## Author clean-archive replay

Replayed the unmodified runner from `git archive 0856b508` (the staging
commit) into `.mishe-tauftauf/replays/xdgmime2shell-w264/` at 11:28:03Z:
rc 0, **RESULT PASS=39 FAIL=0**, runner SHA-256 unchanged
`f19f15d9…e17205`. The pinned tarballs, patch and drivers came from the
archive; no generated evidence was reused. Author replay is not witness
acceptance; an independent replay is owed.

## Honest rung-4 feasibility assessment

Grade: **rung 3 real-source ASan-confirmed OOB WRITE; rung 4 PARTIAL**. The
write is in the pinned library's own function, reached through its public file
API, and chosen magic bytes determine the bytes written out of bounds at a
chosen offset (value or mask). What is NOT shown: a named adjacent heap object
or field whose identity/pointer is controlled, pointer control, an XDG data
file supplied to a live `g_content_type_guess()` consumer, a loopback service,
a command, or r5. Recoverable ASan redzones put the chosen bytes in poison,
not in a named adjacent object. The issue's own language ("potential code
execution in favorable conditions") is a claim; no exploitability beyond the
documented OOB write is claimed here.

## Cheapest next rung-moving experiment

Build unmodified pinned GLib (fix parent `4ef012af…`) with ASan, set
`XDG_DATA_HOME` to a lab-only directory containing the crafted
`mime/magic`, and call `g_content_type_guess()` from a small driver. That
would confirm the public consumer path locally. Then place a named heap
object with a pointer field immediately after the `matchlet->value`
allocation (malloc grooming in the lab build) and measure whether the two
written bytes become the low half of a controlled pointer; that is the first
step toward a named-object rung-4 claim. Would change the assessment: an ASan
report in the fixed build, a named/pointer target under attacker control, a
reproduced wire/request path, or a witness counterexample.
