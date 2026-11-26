# unarr2shell lane 3 — caller search and vendor changelog contradiction

Read-only public-source provisioning, 2026-11-26 ~16:2xZ. No external system
was probed; all local runs were loopback-only.

## Vendor's own changelog claims the fix; the v1.2.0 bytes do not contain it

FreeBSD's vuxml commit `00464e86f937` (2026-11-01) cites
`https://github.com/selmf/unarr/blob/v1.2.0/CHANGELOG.md` and quotes:

> `tar: Fix off-by-1 heap overflow in tar_get_name when concatenating USTAR filename and prefix at full length`

Fetched raw `https://raw.githubusercontent.com/selmf/unarr/v1.2.0/CHANGELOG.md`
(`## 1.2.0 (2026-10-31)`, Security section) contains that exact claim with the
CVE-2026-111273 link. Raw `https://api.github.com/repos/selmf/unarr/compare/v1.1.0...v1.2.0`
(`status: ahead`, 36 changed files) gives the complete tar hunk:

```
diff --git a/tar/parse-tar.c b/tar/parse-tar.c
@@ -136,7 +136,7 @@ bool tar_handle_pax_extended(ar_archive *ar)
-        size_t length, max_size = line - data + size;
+        size_t length, max_size = size - (size_t)(line - data);
```

That is a PAX parser length fix, not `tar_get_name`. The only changed line in
`zip/parse-zip.c` is the separate real ZIP64 fix
(`if (size + idx + 1 > entry->extralen)` → `... + 4 > ...`); `common/unarr.c`
gains only `ar_get_version` / `ar_get_version_str`. `pinned/parse-tar-v1.2.0.c`,
`pinned/parse-tar-v1.2.1.c` and `pinned/parse-tar-master.c` are byte-identical
(SHA-256 `bd9bf8d99e1274ba6a870c39ee694c80843dc3b7821fca7b219bef480f3a4482`)
and all keep `malloc(256 + 1)` plus the overflowing `strcat(prefixed, name)`.

Conclusion: the advisory "patched 1.2.0" claim, the vendor CHANGELOG claim and
the vendor source bytes contradict each other. This **strengthens** the lane-2
negative result; it does not reopen it. The lab's +1-byte fixed control stays
synthetic and no vendor fixed control exists. Recorded as a negative result,
not retried into existence.

## Real caller search

- GitHub code search (`https://api.github.com/search/code?q=ar_entry_get_name`)
  returns HTTP 401 "Requires authentication" without a token — UNKNOWN, not a
  negative result. Repository search over public descriptions/readmes found
  the Go bindings `gen2brain/go-unarr`, whose `unarr.go` exposes
  `NewArchiveFromReader(r io.Reader)`, `Entry()`/`List()` and `Name()` →
  `ar_entry_get_name`. Any caller that feeds a request body to that API would
  reach the sink, but the bindings are a library, not a deployed caller.
- Closest real network-facing candidate found: `gmelchett/jomics` ("Simple
  comic server"). Its `main.go` calls `unarr.NewArchive(fname)` and `r.List()`
  (lines 162–169) and serves `http.ListenAndServe` handlers (lines 646–674).
  However, `listComics` only admits local files with `.cbz` or `.cbr`
  extensions (line 143) and there is no upload/multipart handler: request
  bytes never become an archive file, and a `.tar` entry is never selected.
  The USTAR prefix/name sink is therefore not reachable from jomics' HTTP
  listeners. This is a bounded negative for that candidate, not proof that no
  other caller exists.
- No real caller that takes attacker-supplied tar bytes across a network
  boundary was identified. Status: **UNKNOWN**, not demonstrated.

## Synthetic wire mechanic (measured, labeled)

`bash lab/frontier/unarr2shell/rung4/wire/run-wire-probe.sh` → **8 PASS / 0
FAIL**. A local process accepts one 127.0.0.1 TCP connection, reads 1536 bytes
into memory and calls `ar_open_memory` → `ar_open_tar_archive` →
`ar_parse_entry` → `ar_entry_get_name`. The crafted tar gives GCC ASan
`WRITE of size 101` in `tar_get_name`; both safe controls and the synthetic
fixed build return rc 0 with a clean entry name. Evidence:
`rung4/wire/wire-evidence.md` and `rung4/wire/evidence/`.

This establishes wire-to-sink mechanics with a **synthetic consumer** only:
no real application caller, no command, no chosen byte, no pointer control,
no r5. Grade unchanged: rung 3 verbatim / rung 4 PARTIAL fixed NUL.
