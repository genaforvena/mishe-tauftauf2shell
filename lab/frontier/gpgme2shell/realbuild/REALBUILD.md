# Real GPGME build — CVE-2026-129975

This directory holds a real GPGME build driven through a status pipe, not the
statement-extract harness in the parent directory. All sources were fetched
from gnupg.org (provisioning only); no probe left loopback.

## Provisioned tarballs

| file | URL | sha256 |
| --- | --- | --- |
| `src/gpgme-2.2.0.tar.bz2` | `https://gnupg.org/ftp/gcrypt/gpgme/gpgme-2.2.0.tar.bz2` | `7160e80e84dafd00d956c84891c533bb7ab16a6a54fbe1574b2f3acf0496977b` |
| `src/gpgme-2.3.1.tar.bz2` | `https://gnupg.org/ftp/gcrypt/gpgme/gpgme-2.3.1.tar.bz2` | `2bf94e0e677e5a8fc31f79dd323f91c5416b36fb851058bc1e8bce39f2642434` |
| `src/libgpg-error-1.50.tar.bz2` | `https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.50.tar.bz2` | `69405349e0a633e444a28c5b35ce8f14484684518a508dc48a089992fe93e20a` |
| `src/libassuan-2.5.7.tar.bz2` | `https://gnupg.org/ftp/gcrypt/libassuan/libassuan-2.5.7.tar.bz2` | `0103081ffc27838a2e50479153ca105e873d3d65d8a9593282e9c94c7e6afb76` |

Built `gpgme-2.2.0/src/engine-gpg.c` hashes to the pinned
`c4ef11bda841fc6d07c83063c6968a6db50db3393af2d661054c59b979311d55`.
The patched control applies `../pinned/fix.patch` (sha256
`2fde658ab8b32439c14f58c214f2463b4109aa68d9cbd26c432f17303049c500`)
to a copy of the 2.2.0 tree; its `engine-gpg.c` hashes to
`10179f7853d9284a21af4ad4ab94753654aa40119f9bdef43852e98482b75b08`.
Stock 2.3.1 has the immediate writeback at `engine-gpg.c:1501`.

## Build commands

From the repository root, one command provisions and builds everything;
`build-real.sh` is the canonical route and needs only `curl`, `tar`,
`clang`, autotools and Python 3. The prefix is absolute because the
generated autotools scripts record it.

`build-real.sh` fetches and sha256-checks the four tarballs into `src/`,
extracts them, copies `gpgme-2.2.0` to `gpgme-fixed` and applies
`../pinned/fix.patch`, then configures libgpg-error, libassuan and the three
GPGME trees with `CC=clang CFLAGS='-fsanitize=address -fno-omit-frame-pointer
-g -O0' LDFLAGS='-fsanitize=address'`, static only, prefix
`realbuild/prefix`. It builds/installs the two dependencies and the three
GPGME static libraries with `ASAN_OPTIONS=detect_leaks=0`, then links the
six drivers against `libgpgme.a`, `libassuan.a` and `libgpg-error.a`.
`ASAN_OPTIONS=detect_leaks=0` is needed only while building: libgpg-error's
`yat2m` doc tool leaks under LeakSanitizer. Each GPGME `make` ends with a
tests-directory link error; the static library is complete before that point.
```
cd lab/frontier/gpgme2shell/realbuild
sh build-real.sh
sh run-real.sh
sh make-realkeys.sh
sh run-real-gpg.sh
```

`sh run-real.sh` runs the six fake-gpg cases and 21 assertions; it makes no
network contact and writes raw output to `evidence/real-*.out` / `.rc`.

`make-realkeys.sh` generates four loopback-only throwaway OpenPGP keys with
the host `/usr/bin/gpg` (empty passphrase, no network). A 1200-character UID
places a chosen marker at argument offset 1000 of gpg's `[GNUPG:] IMPORTED`
status line; a 120-character UID is the short-line control. Generated keys,
homes and traces stay in `realgpg/` and are gitignored. `run-real-gpg.sh`
links three `status_trigger_realgpg.c` drivers (vulnerable, patched, stock
2.3.1) from the same ASan builds, imports each key through public GPGME APIs
with a fresh GNUPGHOME, and asserts 36 checks with raw output in
`realgpg/evidence/realgpg-*.out` / `.rc`.

## Real-engine trigger

`status_trigger_realgpg.c` uses `gpgme_set_engine_info()` with the host
`/usr/bin/gpg`, `gpgme_data_new_from_file()` on the armored key,
`gpgme_set_ctx_flag(ctx, "full-status", "1")` and a status callback that
returns `GPG_ERR_GENERAL` for args longer than 500 bytes. The chosen byte is
visible in the real `IMPORTED` status callback before the early return;
`gpgme_release()` then frees the stale pointer. The patched build, stock
2.3.1 and the short-UID key stay sanitizer-clean. No wire consumer is used.

## Limits

The real gpg process is driven by local key material; there is still no
network-facing consumer, no wire input, no allocator metadata claim, no
pointer/IP/command control and no rung 5. Plain (non-ASan) glibc outcome for
the real build is UNKNOWN; only the ASan builds are asserted. Witness replay
of the real paths is pending; an author transcript is not acceptance.

## Fake-engine trigger (pinned control)

`status_trigger.c` uses public APIs only: `gpgme_set_engine_info()` points at
`fake-gpg.py`; `gpgme_set_ctx_flag(ctx, "full-status", "1")` makes the engine
install the monitor callback; `gpgme_set_status_cb()` returns
`GPG_ERR_GENERAL` for args longer than 500 bytes. `fake-gpg.py` answers
`--version` with a synthetic 2.2.40 string and writes one
`[GNUPG:] GOOD <1200 bytes>\n` line to the fd supplied via `--status-fd`,
with a runtime-chosen byte at status-args offset 1000.
