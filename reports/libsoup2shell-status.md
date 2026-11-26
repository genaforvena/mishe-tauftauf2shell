# libsoup2shell — ADMITTED 12:5xZ under standing #6 (witness replay owed)

CVE-2026-102555: libsoup before 3.7.3 treats base64 data-URI content as
NUL-terminated, so `g_base64_decode_inplace()` fails its precondition on an
embedded `%00` and leaves the decoded length uninitialized; the resulting
`GBytes` size can exceed the allocation. Brief:
`reports/frontier-libsoup2shell.md`.

## Evidence (author, W268 2026-11-26)

- Pins from public GitLab: vulnerable fix parent
  `a4294044466df66ea98492d67bb74172ed3f8762` (3.7.2), fix
  `e4f032268fa18f691a6c34d6adcb5b666f3e3f77`. Verbatim pinned
  `soup-uri-utils.c` sha256 `45e37054…d82b7` (vulnerable) and
  `77d21acf…58fd5d` (fixed); the runner checks both. The fetched git worktrees
  are deliberately uncommitted; refetch commands are in `PROVENANCE.md`.
- Runner `lab/frontier/libsoup2shell/run-all.sh` sha256
  `4dadfa600b8f7b6b8b45faf8c867e159d09dd84752ee7a14a97f76c99ce9fd83`:
  **RESULT PASS=19 FAIL=0**, rc 0, 12:45Z–12:46Z, three identical re-runs.
  Console `evidence-run-console.log` sha256
  `d8df99724290a0b7b84e9eb70137f429ced99d20f450615d79c95a8b3ce175ce`.
- GCC ASan: heap-buffer-overflow READ of size 1, `0 bytes after a 128-byte
  region` allocated through `g_uri_unescape_bytes` from
  `soup_uri_decode_data_uri()` at pinned `soup-uri-utils.c:405`. A fresh
  `data:;base64,%00%00%00` triggers it; a 1024-byte valid base64 URI followed
  by `data:;base64,A%00B` also triggers it; plain build rc 139. GLib's own
  precondition leaves the length sentinel untouched (direct probe).
- Fixed build: ASan-clean, size 0 for `A%00B`, full 5-byte `hello` for
  `aGVs%00bG8=` (vulnerable reports 3). Safe inputs clean in both builds.
  Clang stale lengths 7/4 remain inside the 128-byte allocation: preserved
  negative, no Clang ASan report. Full meson build blocked locally by
  missing `libnghttp2`/`libpsl` and no root; standalone verbatim compile with
  lab-only shims used instead.
- Grade: rung 3 real-source ASan OOB READ; rung 4 **NOT CLAIMED**. No named
  adjacent object, chosen bytes at chosen offsets, pointer control, wire
  request-to-decoder path, command or r5. `AV:N` is advisory prose only.

## Next

Window 181 adopted on the inner tmux socket (panes %366/%367 live, no
duplicate). Operator admission under standing #6 landed 12:5xZ; independent
witness W269 replay is in progress before ESTABLISHED. This report is not
acceptance. The cheapest rung-moving experiment: find a loopback consumer
that calls `soup_uri_decode_data_uri()` on attacker-supplied URI input, build
it against the pinned vulnerable tree and observe an ASan READ in that
consumer; otherwise preserve the negative. Re-run the unmodified runner after
any change. Would change the mind: a real consumer ASan report, fixed-build
counterexample or replay contradiction.
