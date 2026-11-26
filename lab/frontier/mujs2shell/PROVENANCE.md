# PROVENANCE — mujs2shell lab (W271, 2026-11-26)

## Pins and claim sources

- CVE-2026-110715 / GHSA-45w2-9pc7-5crm:
  https://github.com/advisories/GHSA-45w2-9pc7-5crm (Moderate 6.9, AV:L).
- Upstream Codeberg `ccxvii/mujs`; fix commit
  `32064e10caa45e68fc87331ca53d042049cc9396` (tag 1.3.9). Vulnerable pin
  `307f18c4216420f2f56e22d8e7040baa39a6304a` (v1.3.8). Both were fetched from
  the public GitHub mirror archive URLs below; witness should re-verify
  against the Codeberg pins cited by the advisory.
- Fix diff read: three hunks in `jsarray.c` — two `idx_b < flat_length`
  guards and one heapsort child comparison change. Advisory writeup URL
  returned 404; no trigger text came from it. Trigger derived from pinned
  `jsrun.c:692-702` (`length` setter leaves `flat_length` unchanged on grow).

## Exact delivered bytes

| artifact | sha256 |
| --- | --- |
| `src/mujs-v1.3.8.tar.gz` (commit 307f18c4…) | `8af271bda905241b7b64d73000924666d0fd297b72da316374afecb088e7616c` |
| `src/mujs-fix.tar.gz` (commit 32064e10…) | `26bd43fcff1d8d7888cb507dc4121b5af12b129162d979679fc682ee20c023d1` |
| verbatim `jsarray.c` at 307f18c4… | `d3bf5010e0f73621b599fcc9cdd9e6888c9bff24589d65a313dc37b695892472` |
| verbatim `jsarray.c` at 32064e10… | `27361ae1d9f883164a71f0e7227d4ea3e4f378a5889a6f456ccdbc074e05792e` |
| `harness/attack.js` | `32a2e164beef2b7042543b567bac3fd1a3bfe581d3e086974fa6285efb24fc81` |
| `run-all.sh` (staged) | `5aca123ab59aae54f9bd9f96896b61ef290516d22867a6acfd655cf913f59e68` |
| `evidence-run-console.log` (staged) | `3377a2b374caee8a478a4a9eb2d9c3d00e61ffb5d312d131ed21b34b7ffa3be7` |

Tarballs and extracted `build/` trees are gitignored; refetch with:

```
curl -fsSL -o src/mujs-v1.3.8.tar.gz \
  https://github.com/ArtifexSoftware/mujs/archive/307f18c4216420f2f56e22d8e7040baa39a6304a.tar.gz
curl -fsSL -o src/mujs-fix.tar.gz \
  https://github.com/ArtifexSoftware/mujs/archive/32064e10caa45e68fc87331ca53d042049cc9396.tar.gz
./run-all.sh > evidence-run-console.log 2>&1
```

## Build and observation

- Both pinned trees are built by upstream `make`:
  `HAVE_READLINE=no CFLAGS='-std=c99 -g -O0 -fsanitize=address
  -fno-omit-frame-pointer -Wall' build/debug/mujs`. No upstream `.c` line is
  edited; `genucd.py` generates `utfdata.h` from upstream Unicode data as the
  normal Makefile does.
- Measured `RESULT PASS=23 FAIL=0 rc 0` at 14:06Z.
- Attack document: `var a = [3,1,2]; a.length = 1000; a.sort();`
- Vulnerable: ASan `heap-buffer-overflow`, `READ of size 1`, frame
  `Ap_sort_cmp .../build/vuln/jsarray.c:246` via the real `js_dofile`/CLI call
  chain; rc 1. ASan describes the address as a wild pointer in a 1-byte
  access range (the index is far beyond the small flat allocation).
- Fixed: rc 0, `sorted-length=1000`, no ASan report. Normal-sort control:
  rc 0, `normal=3 1,2,3`, no ASan report on either pin.

## Preserved negatives and corrections

- Advisory writeup 404 (recorded in brief); trigger was derived from pinned
  source, not from the writeup.
- No OOB WRITE was observed: the comparator READ aborts first. The runner
  does not claim `Ap_sort_swap` was reached.
- The first manual trial created `harness/safe.js` by shell printf; the staged
  runner now regenerates that exact control itself so a clean replay needs no
  untracked file.
- No wire consumer, chosen-offset read-back, pointer steering, command or r5
  was observed. No external host was contacted beyond public source fetches.
