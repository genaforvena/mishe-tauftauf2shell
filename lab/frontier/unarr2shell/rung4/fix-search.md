# unarr2shell lane 2 — upstream fix search (2026-11-26 ~15:17Z)

Question: does a genuine upstream patch for `tar_get_name()` exist, so the
synthetic `malloc(256 + 2)` fixed control can be replaced by vendor bytes?

Read-only provisioning queries (public GitHub; no target probing):

- `GET https://api.github.com/search/issues?q=GHSA-fj4h-mpx9-46qj&per_page=100`
  → `"total_count": 0`, `incomplete_results: false`. No issue or PR in the
  public GitHub issue search names the advisory ID.
- `GET https://api.github.com/repos/selmf/unarr/commits?path=tar/parse-tar.c&per_page=100`
  → the only commits after 2020 touching this file are
  `509bd0feec36771beac37f3b97af446068d4563d` (2026-02-01,
  "Fix calculation of max_size in tar_handle_pax_extended", fixes issue #33)
  and `31ab60c88305d8c5315e0ec817ed25e3407b04ae` (2020-05-05,
  "API:_Add ar_entry_get_raw_name function"). Neither changes `tar_get_name`.
- `GET https://api.github.com/repos/selmf/unarr/commits?per_page=10` → repository
  head `704ea083dd384b52ee375d5a786155d9b2642986` ("Release v1.2.1",
  2026-11-22T14:20:31Z); preceding commits are a versioning regression fix and
  packaging changes. No security patch in the visible head history.
- `GET https://raw.githubusercontent.com/selmf/unarr/master/tar/parse-tar.c`
  → saved as `pinned/parse-tar-master.c`, SHA-256
  `bd9bf8d99e1274ba6a870c39ee694c80843dc3b7821fca7b219bef480f3a4482`,
  byte-identical to `pinned/parse-tar-v1.2.1.c` (`diff -u` empty, rc 0).
  The master head sink still reads `malloc(256 + 1)`, `prefixed[156] = '\0'`,
  `strcat(prefixed, "/")`, `strcat(prefixed, name)`.

Two further searches (`CVE-2026-111273` and `tar_get_name repo:selmf/unarr`)
returned HTTP 403 (search rate limit) and are **UNKNOWN**, not negative
results. They are not used below.

Conclusion: lane 2 is a NEGATIVE RESULT as of 2026-11-26 ~15:17Z. Neither the
visible upstream commit history nor the current master bytes contain a fix for
this advisory; the advisory's "patched 1.2.0" claim remains contradicted by
raw bytes. No vendor fixed control is available; the lab's +1-byte control stays
explicitly synthetic. Grade unchanged: rung 3 verbatim / rung 4 PARTIAL fixed
NUL; no pointer, chosen byte, command, wire or r5.

Would change mind: an upstream commit/PR/fork patch that changes `tar_get_name`
or the 257-byte allocation, with raw bytes showing the change.
