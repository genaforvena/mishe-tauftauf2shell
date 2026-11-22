# Provenance and scope — uhttpd GHSA-2mpg-6wp5-435p harness

## Claim source

Advisory: https://github.com/openwrt/uhttpd/security/advisories/GHSA-2mpg-6wp5-435p
("uhttpd: unauthenticated out-of-bounds write via `params` type confusion in
POST /ubus/call/", published 2026-08-03).

The advisory's own conclusion is quoted here for scope discipline:

> **Demonstrated:** an unauthenticated remote attacker sends one HTTP POST and
> uhttpd dies with SIGSEGV ...
> **Not demonstrated:** controlled corruption. ... I did not build a
> controlled-corruption or code-execution PoC, so I do not score
> confidentiality or integrity impact.

So this harness is evidence for the advisory's demonstrated DoS-class memory
safety failure only. **RCE is not proven by the advisory or by this harness.**

## Exact pins

| Role | Repository | Full 40-hex commit |
|---|---|---|
| Vulnerable `uh_ubus_send_request()` | `src/uhttpd` (`ubus.c`) | `f682ccabee9ed5f39dd3b0aaf96228975eeb478d` |
| Fixed `uh_ubus_send_request()` | `src/uhttpd` (`ubus.c`) | `e76736e5676fb25536b27d45865eb4153c68aca3` |
| Real blob/blobmsg implementation | `src/libubox` | `a396f38a8568a1d670c240465cd8d24fdfdf6463` |

The fix is exactly the 4-line guard added at the top of
`uh_ubus_send_request()`:

```c
if (args && blobmsg_type(args) != BLOBMSG_TYPE_TABLE)
        return uh_ubus_json_rpc_error(cl, ERROR_PARAMS);
```

`gen.py` runs `git show PIN:ubus.c` in the local clone, extracts the whole
function, and applies **one** transformation: the function name becomes
`<pin>_uh_ubus_send_request`. Every other byte is preserved. The results are
stored in `pins/vuln_fn.inc` and `pins/fixed_fn.inc`; `gen.py PIN --verify`
re-extracts from git and compares byte-for-byte (sha256 printed). Hashes of
both includes and of the libubox files used are in `pins/PIN_HASHES.txt` and
are rechecked with `sha256sum -c` on every run.

sha256 of the generated includes:

- `vuln_fn.inc`  `8442ab8d703fd9fe759e4b48d4f254ef31b63500b5e1a097eb902be6b9235b74`
- `fixed_fn.inc` `70e3891260cdf9dba60a8fa69b32b808ae457eed6267031a54602bce3cf3fb0a`

## Self-contained libubox copy

`pins/blob.c`, `pins/blob.h`, `pins/blobmsg.c`, `pins/blobmsg.h` and
`pins/utils.h` are byte-identical copies of the pinned libubox files; their
sha256 values are recorded in `pins/PIN_HASHES.txt`. No network access and no
system libubox are used by the build.

## Self-contained uhttpd source blobs

`pins/ubus-vuln.c` and `pins/ubus-fixed.c` are byte-identical copies of
`git show PIN:ubus.c` at the two pins above (sha256 in `pins/PIN_HASHES.txt`).
`gen.py` reads those committed blobs first and only falls back to `git show`
in `src/uhttpd` when they are absent, so a clean `git archive` replay needs no
cloned repository and no network. The `src/` clones are provisioning only and
are gitignored.

## Modeled vs real

**REAL mode** (`real-*-asan`) links the pinned, unmodified `blob.c` and
`blobmsg.c`. The `args` argument is an exact 20-byte `malloc()` shaped like
`blob_memdup()` of an INT32 `params` attribute:
`id_len = be32(BLOB_ATTR_EXTENDED | (BLOBMSG_TYPE_INT32 << 24) | 20)`
(i.e. bytes `85 00 00 14`), `blobmsg_hdr` with `namelen=6` and `"params"`,
then payload `be32(1)` at offset 16.

The `BLOB_ATTR_EXTENDED` bit is required for `blobmsg_data()` to skip the
12-byte name header; it is always set by `blobmsg_add_field()` in real libubox
and is implicit in the advisory's 20-byte layout. Without it the loop guard
does not enter. This is the only byte-level clarification relative to the
task's shorthand `be32((5<<24)|20)`.

ASan observes the advisory's first fault: `strcmp` reads `blobmsg_name(cur)`
at `args+22`, i.e. **2 bytes after the 20-byte region**, with frames
`strcmp` → `<pin>_uh_ubus_send_request`. The fixed pin returns
`ERROR_PARAMS` before the loop; no ASan fault and no `ubus_invoke_async`.

The full 4 GiB `memcpy` is **not** reproduced in REAL mode: with default
ASan settings the process stops at the preceding OOB read. The advisory
needed `-fsanitize-recover=address` to continue to the giant write. That is
not modeled away or emulated here; instead:

**MODEL mode** (`model-*-asan`, `model-*-plain`) keeps the real libubox
`blob.c` and `blobmsg.c` but renames the real `blobmsg_add_field` definition
in its own translation unit and supplies an instrumented shim with the
**same signature**. It logs `WRITE_LEN=<len>` from the truncated `unsigned
int` argument, then copies **exactly 16 bytes** from the same `data` pointer
the real `blobmsg_add_blob()` passes, and logs
`WRITE_OFF=<offset> BYTES=<hex>` (plus a combined
`MODEL_RESULT WRITE_OFF=... WRITE_LEN=... BYTES=...` line). The modeled
region is a 128-byte attacker-controlled allocation: the exact 20-byte blob
at offset 0 and chosen filler (`0x41` or `0x5a`) from offset 20, so
`data = args+20`. With ASan the destination is `malloc(8)`, producing a
deterministic `heap-buffer-overflow WRITE of size 16`; in plain `-O0 -g`
builds the destination is `malloc(64)`, so the 16 chosen bytes can be read
back and hashed. The fixed pin never calls the shim.

**SAFE control** uses a well-formed TABLE `params` containing one TABLE
attribute: no giant `WRITE_LEN`, no ASan fault, normal small write only.

Only uhttpd-side dependencies are stubbed: `struct client`, `struct dispatch`,
`struct dispatch_ubus`, the error enum, `uh_ubus_json_rpc_error()`,
`ubus_invoke_async()`, `ubus_complete_request_async()`, `uloop_timeout_set()`,
the three callback symbols, `conf.script_timeout` and `ctx`. `struct blob_buf`
and all blob/blobmsg macros come from the real pinned libubox headers.

## Honest scope statement

Rung 3/4 evidence **at the direct-call / libubox scope only**:

- No live uhttpd process, no HTTP wire, no socket of any kind.
- No rpcd, no ubus daemon, no ACL claim replay, no session handling.
- No pointer control, no command, no controlled corruption, no rung 5.
- The `0xFFFFFFFD` length is observed as a value and modeled as a 16-byte
  copy; it is not executed as a real ~4 GiB `memcpy`.
- The advisory demonstrates DoS (SIGSEGV) and explicitly states that RCE is
  not proven; this harness does not change that.

From the repository root:

```sh
bash harness/run.sh
```

`run.sh` builds with gcc `-fsanitize=address -fno-omit-frame-pointer -O0 -g`
and plain `-O0 -g`, also compiles both pins with clang when available, sets
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:print_summary=1`, runs two
full rounds, writes all raw output to `harness/evidence/`, checks that the
normalized PASS lines and chosen-byte line hashes are identical across
rounds, and prints `TOTAL pass=N fail=M`. Verified gcc 13.3.0 and clang
18.1.3; 30 PASS / 0 FAIL.
