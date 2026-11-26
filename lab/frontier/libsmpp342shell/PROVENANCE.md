# PROVENANCE — libsmpp342shell lab (W271, 2026-11-26)

## Pins and claim sources

- CVE-2026-75895 / GHSA-fpm9-38vr-4gp8:
  https://github.com/advisories/ghsa-fpm9-38vr-4gp8 (unreviewed, published
  2026-09-18). The advisory names "libsmpp35 0.1.0 through 1.8.0"; the fix is
  in `osmocom/libsmpp34` at 1.14.6. That label mismatch is recorded, not
  resolved, in `reports/frontier-libsmpp342shell.md`.
- Fix commit: `af0e2912057551dab97bbe26e6a41f18a75f3bbb`, fetched from
  `https://github.com/osmocom/libsmpp34/commit/af0e2912057551dab97bbe26e6a41f18a75f3bbb.patch`.
  It changes one line in `src/smpp34_unpack.c` (`strlen` -> `strnlen` bounded
  by `left`); the commit text assigns candidate ID CAN-2026-2051038.
- Tags resolved by `git ls-remote --tags https://github.com/osmocom/libsmpp34.git 'refs/tags/1.14.*'`:
  vulnerable 1.14.5 tag object `46707ad426764992b1f5e180fba17fbc89b0114b`,
  peeled commit `d6ac32fde99f08b2019a5ca095471456583dc93a`; fixed 1.14.6 tag
  object `77965468429a1abcf20bb48b98adb1f93dab158c`, peeled commit
  `f93991bd19b6715a6e1782711734cfc52760432e`. Raw source at both peeled
  commits was fetched and checked before staging.

## Exact delivered bytes (all fetched from the public upstream mirror)

| artifact | sha256 |
| --- | --- |
| `src/libsmpp34-1.14.5.tar.gz` (peeled commit d6ac32fd…) | `6a275907cd72db49aca1519a2df061869be280862fb2ce7395055f17e366d6e3` |
| `src/libsmpp34-1.14.6.tar.gz` (peeled commit f93991bd…) | `c85f8d09522b6600a51a2fb28d2872baceb5fd00f7dd119437d05a1aafc5a1ab` |
| verbatim `src/smpp34_unpack.c` at 1.14.5 | `37c0a175455dbc1bf03de5ecc2607e902522cc2562e6abe6b6192c0da091585e` |
| verbatim `src/smpp34_unpack.c` at 1.14.6 | `9863e806952cd7381c7dbc4bbb31736395cdb0bfb36985ae178ce028ec0032f8` |
| `run-all.sh` (staged) | `373fcdc9a182485efc38dbb3b7fa99908a57f80cd4e4977838058be708405637` |
| `harness/driver.c` (staged) | `f2d0ceed853889e2f84246bd321d16744f5ea5f37c3114a5c86fa04e22c4cabd` |
| `evidence-run-console.log` (staged) | `cbd591997570a70ca4645719f4a5dab841d09400add9970b4f4b07f4d4562ccb` |

Tarballs and extracted `build/` trees are gitignored; refetch with:

```
curl -fsSL -o src/libsmpp34-1.14.5.tar.gz \
  https://github.com/osmocom/libsmpp34/archive/d6ac32fde99f08b2019a5ca095471456583dc93a.tar.gz
curl -fsSL -o src/libsmpp34-1.14.6.tar.gz \
  https://github.com/osmocom/libsmpp34/archive/f93991bd19b6715a6e1782711734cfc52760432e.tar.gz
./run-all.sh > evidence-run-console.log 2>&1
```

## Build and observation

- `harness/driver.c` is lab-only and calls the public `smpp34_unpack()` with a
  `bind_transmitter_t` output struct. It compiles against `smpp34_unpack.c`,
  `smpp34_structs.c`, `smpp34_params.c` and `smpp34_heap.c` extracted verbatim
  from each tarball; only include paths (`-I build/<side>/src -I build/<side>`)
  are supplied so the upstream `#include "def_frame/..."` directives resolve.
  No upstream source line is edited.
- Compilers: GCC (Ubuntu 12) and Clang 18, each with `-fsanitize=address -O0
  -g -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L`. The POSIX define only
  declares `strnlen` in the fixed build; it does not change upstream bytes.
- Runner checks tarball hashes, verbatim source hashes, that the upstream diff
  changes exactly one line pair, both sanitizer reports, the fixed rejection,
  valid-PDU safe controls, and a guard-page fault in a plain build.
  Measured `RESULT PASS=31 FAIL=0 rc 0` at 13:51Z, rerun after the grep fix
  noted below.
- Attack bytes (17): `00000011 00000002 00000000 00000001 41` — header fields
  are big-endian and `41` is an unterminated C-Octet at offset 16.
- GCC ASan: `heap-buffer-overflow`, `READ of size 2`, `0 bytes after 17-byte
  region`, `smpp34_unpack build/vuln/def_frame/bind_transmitter.frame:1`.
  Clang ASan reports the same site. Plain guard-page build exits 139.
- Fixed: `rv=-1`, `len(system_id):2(Value length exceed buffer length)`, rc 0,
  no sanitizer report. Safe 31-byte valid PDU parses to `rv=0` in both builds
  with `system_id=sys password=pw address_range=r`.

## Preserved negatives and corrections

- First runner draft had `RESULT PASS=30 FAIL=1`: the `has()` check used a
  basic-regex grep for the literal `strnlen((char *)aux, left)` pattern, so
  `*` was read as a quantifier. Changed both `has`/`hasnt` helpers to
  `grep -qF` (fixed strings) and removed the duplicated helper line; rerun
  PASS=31 FAIL=0. The failing console was overwritten by the corrected run;
  this note preserves the negative.
- A "safe-short" driver mode (18 bytes: `A` followed by a NUL) was tried and
  **still over-read** in the vulnerable build: after `system_id` consumed two
  bytes, `left` became zero and the next `C_OCTET` (`password`) called
  `strlen()` again at the end of the buffer. It was dropped as a safe control;
  the complete valid 31-byte PDU is used instead. This is an additional
  instance of the same missing bound, not a separate finding.
- The scout that ranked this candidate reported 1.14.5/1.14.6 commit hashes
  matching the peeled commits, but omitted that the `git ls-remote` names also
  resolve annotated tag objects with different hashes. Both forms are recorded
  above; all reported hashes were independently re-verified here.
- No wire consumer, chosen-offset read-back, pointer steering, command or r5
  was observed. No external host was contacted beyond public source fetches.
