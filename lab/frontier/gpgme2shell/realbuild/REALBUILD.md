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
twelve drivers against `libgpgme.a`, `libassuan.a` and `libgpg-error.a`.
`ASAN_OPTIONS=detect_leaks=0` is needed only while building: libgpg-error's
`yat2m` doc tool leaks under LeakSanitizer. Each GPGME `make` ends with a
tests-directory link error; the static library is complete before that point.
```
cd lab/frontier/gpgme2shell/realbuild
sh build-real.sh
sh run-real.sh
sh make-realkeys.sh
sh run-real-gpg.sh
sh run-wire.sh
sh run-wire-reuse.sh
sh run-reuse.sh
sh run-colon.sh
sh build-plain.sh
sh run-plain.sh
sh run-groom.sh
sh run-internal.sh
```

`sh run-real.sh` runs the six fake-gpg cases and 21 assertions; it makes no
network contact and writes raw output to `evidence/real-*.out` / `.rc`.
`sh run-reuse.sh` adds 24 assertions on the second-operation path below.
`sh run-wire-reuse.sh` adds 55 assertions on the wire-fed second-operation
path; raw output is in `realgpg/evidence/wire-reuse-*.out` / `.rc` (gitignored).
`sh run-colon.sh` adds 26 assertions on the colon-line path below; raw
output is in `evidence/colon-*.out` / `.rc` (gitignored).
`sh build-plain.sh` reuses the provisioned trees to build libgpg-error,
libassuan and GPGME 2.2.0 plus the patched copy with plain `CFLAGS='-g -O0'`
and no sanitizer, into a separate `prefix-plain`; `sh run-plain.sh` adds 13
assertions on the plain-glibc outcome below.

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

`run-real-gpg.sh` uses local key material; the wire section below adds a
loopback-only HKP response. There is no allocator-metadata claim, no
pointer/IP/command control and no rung 5. The real-build plain-glibc outcome
is measured below: an un-groomed second free aborts on glibc 2.39; a
lab-allocated same-size buffer in the failing callback drains tcache and
yields a rung-4 alias instead. Only the ASan builds are asserted for the
deeper call-site evidence. Witness replay of the real paths is pending; an
author transcript is not acceptance.

## Fake-engine trigger (pinned control)

`status_trigger.c` uses public APIs only: `gpgme_set_engine_info()` points at
`fake-gpg.py`; `gpgme_set_ctx_flag(ctx, "full-status", "1")` makes the engine
install the monitor callback; `gpgme_set_status_cb()` returns
`GPG_ERR_GENERAL` for args longer than 500 bytes. `fake-gpg.py` answers
`--version` with a synthetic 2.2.40 string and writes one
`[GNUPG:] GOOD <1200 bytes>\n` line to the fd supplied via `--status-fd`,
with a runtime-chosen byte at status-args offset 1000.

## Second-operation trigger

`status_reuse.c` issues one failing long-line keylist and then a second,
short-line keylist on the same context. In 2.2.0 the second
`gpgme_op_keylist_start()` calls `_gpgme_op_reset()`, which releases the
still-attached engine and frees the stale `gpg->status.buffer` at
`engine-gpg.c:602` before the second operation starts. ASan reports the
double free with the realloc at `read_status engine-gpg.c:1494` as the
first free; the patched build and stock 2.3.1 run both operations and
receive the second callback's bytes. Raw output is in
`evidence/reuse-{vuln,fixed,231}.out` / `.rc`. This is still ASan-only
rung-4 mechanics: no allocator-metadata, pointer, IP or command control.

## Plain-glibc outcome (no sanitizer)

`build-plain.sh` builds real GPGME 2.2.0 and the fix-patched copy without
ASan (plain `CFLAGS='-g -O0'`, separate `prefix-plain`) and links
`status_reuse.c` against both. On glibc 2.39, `run-plain.sh` gives
`PASS=13 FAIL=0`: the vulnerable driver rc 134 with `free(): double free
detected in tcache 2` after its callback printed `arglen=1200
byte[1000]=0x48`, and op2 never starts; the patched driver rc 0, starts op2
and receives `op_marker=Z arglen=20` before a clean release. Raw output is
in `evidence/reuse-plain-{vuln,fixed}.out` / `.rc`. With no intervening
same-size allocation the allocator's detector aborts before any metadata or
control-flow use: a negative result for the ungroomed plain-glibc path, not
an exploit. The W8 section below shows that a same-size allocation in the
failing callback changes this outcome. The parent statement harness's
contradictory plain revisions remain recorded separately.

## Plain-glibc tcache drain (no sanitizer)

`status_groom.c` uses public APIs only. The realloc at
`engine-gpg.c:1494` frees the original 1024-byte status buffer into glibc's
tcache before the monitor callback runs at `:1549`. The failing callback
allocates and retains `malloc(1024)` (filled with `0x47`); after op2 and
`gpgme_release()` a second `malloc(1024)` (filled with `0x41`) compares its
address with the callback's buffer. `build-plain.sh` links the driver
against both plain builds; `sh run-groom.sh` gives `PASS=23 FAIL=0`.

Vulnerable 2.2.0 with the callback allocation exits 0, no tcache-abort
message, op2 starts, `aliased=1` and `groom_buf byte[1000]=0x41` — the later
write is visible through the retained pointer. With `GROOM_ALLOC=0` the same
driver exits 134 with `free(): double free detected in tcache 2`, matching
`run-plain.sh`. Fix-patched 2.2.0 exits 0 with `aliased=0` and the callback's
buffer unchanged (`0x47`). Raw output is in
`evidence/groom-*.out` / `.rc` (gitignored).

This is harness-driven rung-4 heap aliasing: the groom allocation is lab
code, not attacker-controlled wire or request input. There is no
pointer/IP/command control, no chosen-address write, no benign side effect
and no rung 5. Witness replay of all real paths remains pending.

## Loopback wire path

`wireloop.py` starts an HKP HTTP listener on 127.0.0.1:11372 serving one
armored key, signs a fixed message with the throwaway key, and runs a
verifying GNUPGHOME configured with `auto-key-retrieve` and that keyserver.
`status_trigger_realgpg_verify.c` calls `gpgme_op_verify()` with the same
failing status callback. The attacker-controlled wire response supplies the
long UID; gpg emits `[GNUPG:] IMPORTED` with `args[1000]` set by the key.

```
cd lab/frontier/gpgme2shell/realbuild
sh run-wire.sh
```

`run-wire.sh` asserts 32 checks with raw output in
`realgpg/evidence/wire-*.out` / `.rc`. Vulnerable long-key cases fault with
the three chosen bytes; patched, stock 2.3.1 and short-key cases are clean.
This is a wire-visible rung 4 in the lab, not rung 5: no pointer/IP/command
control, no benign command side effect and no claim about stock layouts or
live targets. Witness replay of all real paths is still pending.

## Wire-fed second-operation trigger

`status_wire_reuse.c` combines the two paths: operation 1 is a real gpg
verify whose public key arrives from the loopback HKP response; its long
`[GNUPG:] IMPORTED` line fails the status callback and takes the pinned early
return. Operation 2 is a keylist on the same context. In 2.2.0 under ASan the
stale `gpg->status.buffer` is freed in `gpg_release engine-gpg.c:602` through
`_gpgme_op_reset → gpgme_op_keylist_start keylist.c:1295`, before op2 starts;
the first free is `realloc read_status engine-gpg.c:1494`. `sh
run-wire-reuse.sh` asserts 55 checks: byte[1000] is `0x48` / `0x5a` / `0x37`
from the wire key, the patched build and stock 2.3.1 start op2 and receive a
callback, and short-wire-key controls stay sanitizer-clean.

This is earlier rung-4 mechanics driven by attacker-chosen loopback bytes;
it adds no allocator-metadata, pointer, IP or command control and no r5.
Witness replay of this path is pending.

## Colon-line path (the advisory's second reader)

`colon_reuse.c` uses public APIs only: `gpgme_set_engine_info()` points at
`fake-colongpg.py`, whose stdout is GPGME's `--with-colons` pipe. It answers
`--version`, writes a 1200-byte `[GNUPG:] GOOD` status line with a chosen
byte at offset 1000 (logged by a non-failing status callback), then writes
exactly 1024 bytes with no LF to stdout and exits. `read_colon_line()`
consumes all 1024 bytes to `readpos=1024`; its next call takes the
`realloc()` at `engine-gpg.c:1647`, reads EOF and returns at `:1707` without
the pointer writeback at `:1728-1730`. No callback error is used on either
pipe. A second keylist on the same context fault in 2.2.0: ASan reports the
second free in `gpg_release engine-gpg.c:604` via `_gpgme_op_reset →
gpgme_op_keylist_start keylist.c:1295`, first free by `realloc
read_colon_line engine-gpg.c:1647`, allocation by `gpg_set_colon_line_handler
engine-gpg.c:909`. `COLON_SAFE=1` shortens the colon line to 20 bytes and
stays clean. Patched 2.2.0 and stock 2.3.1 start op2 and log marker `Z`.
`sh run-colon.sh` gives `PASS=26 FAIL=0`. Grade unchanged: rung-4 mechanics,
no pointer/IP/command control and no r5.

## Attacker-sized internal groom (no sanitizer)

`status_internal_groom.c` tests the W8 gap without lab callback allocation.
`gpgme_set_passphrase_cb()` arms `gpg_set_command_handler()` (`cmd.used = 1`)
on the first operation, an export. `fake-internal-gpg.py` writes a
`[GNUPG:] GET_LINE` line whose keyword is 1020 bytes with `0x48` at offset
1000, so no LF appears in the first 1024 bytes: `read_status()` takes the
realloc at `engine-gpg.c:1494`, freeing the 0x410 status chunk into tcache.
The GET_LINE branch then makes GPGME itself call `strdup(rest)` at
`engine-gpg.c:1567`; the request is attacker-sized and its bytes are
attacker-chosen. A following 600-byte `[GNUPG:] GOOD` line makes the monitor
callback return `GPG_ERR_GENERAL`, so the writeback at `:1610` is skipped.

`sh run-internal.sh` gives `PASS=18 FAIL=0`. Under gdb at the strdup site
`gpg->status.buffer == gpg->cmd.keyword` (`equal=1`): the library's own
attacker-sized allocation reclaimed the stale block. Vulnerable 2.2.0 still
exits 134 with `free(): double free detected in tcache 2` at the next
operation's reset — the reclaiming chunk is also owned by `cmd.keyword` and
is freed twice in `gpg_release()`. Fix-patched 2.2.0, the short-line
vulnerable control and short-line patched control all exit 0 and start op2.
Raw output is in `evidence/internal-*.out` / `.rc` (gitignored).

This closes the lab-groom-free limb as a negative result: GPGME-internal
allocation driven by attacker status bytes does not make the stale free
silent under plain glibc. The outcome is a crash, not a silent alias; there
is no pointer/IP/command control, no chosen-address write, no side effect
and no rung 5. Witness replay of all real paths remains pending.
