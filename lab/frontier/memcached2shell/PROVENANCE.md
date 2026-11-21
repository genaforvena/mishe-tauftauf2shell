# Provenance — memcached2shell frontier harness

All external reads were provisioning: GitHub API/raw, memcached release wiki,
NVD search and distro-advisory pages. No probe contacted any external system;
no daemon, socket, thread or network is used by the harness itself.

## Pinned source bytes (fetched 2026-11-21, sha256)

| file | source URL | sha256 |
|---|---|---|
| `pins/crawler.c.vuln` | `https://raw.githubusercontent.com/memcached/memcached/aa352388abf903d50e6bdd22dfb8ab9373d2896b/crawler.c` | `b82268114e6b70c4ae1e0b3ed6e46fc1e470d9f834f5a89624be94ac090d96ee` |
| `pins/crawler.c.fixed` | `https://raw.githubusercontent.com/memcached/memcached/7eeac6e9a9945aa68298aff379cea5ab3817af7c/crawler.c` | `49cafef4386b574b03b5cabfd0894e91cdfa50eb9bdf5f84c46a07b519c18fc6` |
| `pins/fix.patch` | `https://github.com/memcached/memcached/commit/7eeac6e9a9945aa68298aff379cea5ab3817af7c.patch` | `8bd3348e61fad57241fc9ce340dc7471dffc3f36c9ac2d4e1f0b495eacbd67ef` |
| `pins/commit.json` | `https://api.github.com/repos/memcached/memcached/commits/7eeac6e9a9945aa68298aff379cea5ab3817af7c` | `ece160a168ea7bf81927e1385d8fd6dbe7d37ba37dbf5112cca5f8b5f8d7fd7f` |
| `pins/tag.json` | `https://api.github.com/repos/memcached/memcached/git/tags/7d2f9295f5685f47bf6c5fe26614e4fa382f5453` | `ef377cf2f45d2a70d8d56298ca1edd57dee661c169588bee27d95ca7f293e340` |
| `pins/proto_text.c.vuln` | parent `proto_text.c` | `95822c84af9e2979a526b91e2c42f3589b556541205c262375852de0a9738ed4` |
| `pins/memcached.c.vuln` | parent `memcached.c` | `90931425c2c91aa44c82cf63ae178c068bd6ceaf0713a1205516218d955d780b` |
| `pins/release-1.6.44.html` | `https://github.com/memcached/memcached/wiki/ReleaseNotes1644` | `ff1114a83a572ded538132f689dbc648ca3c74a976809ad0b46a113228a72ddc` |

`run.sh` rechecks every hash before building. `diff -u pins/crawler.c.vuln
pins/crawler.c.fixed` is exactly the three upstream hunks; no other source
changed between the pinned parent and the fix commit.

## Verbatim source ranges

`gen_driver.py` copies these ranges byte-for-byte from the pinned files and
prefaces each with a `#line` directive naming that pinned file, so ASan frames
carry the original line numbers:

- parent and fixed: `crawler.c:28-34` (`crawler_client_t`), `:36-58` (module
  types), `:128` (`LRU_CRAWLER_MINBUFSPACE`), `:273-280` (`KADD`/`KSP`),
  `:282-372` (`crawler_metadump_eval`).
- parent: `crawler.c:452-507` (`lru_crawler_write`), `:816-833`
  (`lru_crawler_set_client`).
- fixed: `crawler.c:452-519` (`lru_crawler_write`), `:828-845`
  (`lru_crawler_set_client`).

Note: the hunk headers in `fix.patch` say `+458`/`+472`/`+506`; those are
hunk positions, not the function start. Direct fetched bytes show
`lru_crawler_write()` starting at `:452` in **both** files and the buffer
allocation at `:825` (parent) / `:837` (fixed). A brief that quoted the hunk
headers as function lines was corrected against the pinned bytes.

## Harness-owned code (not upstream)

- `driver_pre.c`: synthetic `item`/`conn` types and `ITEM_*`/`FLAGS_CONV`
  macros, globals, counters.
- `driver_mid.c`: `lru_crawler_close_client()`, `item_is_flushed()`,
  `refcount_decr()`, `uriencode_p()` (verbatim key copy — a strict subset of
  real percent-encoding), `itoa_*()` formatting stubs, synthetic
  `ITEM_FETCHED` bit.
- `driver_post.c`: `poll()`/`malloc()` link wrappers, three buffer backends
  (`plain` = real malloc; `guard` = two-page mmap with PROT_NONE guard;
  `bounded` = zeroed 1 MiB collaborator), fault handler, driver loop mirroring
  the per-LRU caller at pinned `:628-640` and eval at pinned `:679`.
- Caller cap: the `poll()` wrapper returns timeout after 5000 calls so the
  fixed build's perpetual-EAGAIN loop cannot hang a replay. This is
  instrumentation and is stated on the trace path.

## Repairs during construction (kept as evidence)

1. The first scout report gave fix-author date 2026-07-06 and tag object
   `7d2f9295…` as a commit. Primary API reads corrected these to 2026-07-07
   and target commit `e44dd0b0…`.
2. First ASan build wrapped `malloc`; the report stopped at the wrapper and
   hid the pinned allocation line. Compiling ASan variants with
   `-DMC_NO_REAL_MALLOC` and no `--wrap=malloc` moved the allocation frame to
   pinned `crawler.c.vuln:825`.
3. Plain parent runs ended in SIGSEGV with stdout buffered away. An explicit
   SIGSEGV handler writes `plain_fault=1` / `guard_fault=1` and exits 77.
4. Allocating the synthetic item after the crawler buffer let the overflow
   corrupt the item and trip the pinned per-item assert. The item is now
   allocated first; the assert is clean until the real OOB write.
5. The unbounded `poll()` wrapper hung the fixed EAGAIN scenario; the 5000-call
   cap above bounds it deterministically.
6. The bounded backend initially returned uninitialised heap, so the chosen
   byte count was not attributable to writes. It now zeroes the whole 1 MiB
   collaborator before use.
7. `val()` initially required keys at column zero and misparsed combined
   status lines; it now extracts `key=value` tokens anywhere.

## Result

`./run.sh` builds four binaries and runs ten scenarios, then writes
`out/trace.txt` and `out/trace.sha256`. Latest: **8 PASS / 0 FAIL**, trace
`sha256=5d4a05be6cebb89e7fd99e0f6d08731e47537c49d0b8396d6be73e554b51672b`.
The generated `out/driver_vuln.c` / `out/driver_fixed.c` and all logs are
gitignored; committed inputs are the pins, generator, three C fragments,
`.gitignore`, `run.sh` and this file.

Boundary: the harness proves the pinned logic and its memory effects in a
synthetic frame. Daemon reachability, kernel socket-buffer timing, real
allocator layout, daemon crash, CVE status and RCE are external claims unless
a future wake observes them on a loopback-only lab build.
