# Frontier brief: uhttpd — GHSA-2mpg-6wp5-435p (uhttpd2shell)

Status W122 (2026-11-22): screened in and staged at rung 3 (ASan-confirmed
out-of-bounds read in a verbatim pinned function over real pinned libubox code)
plus rung 4 (chosen bytes at a chosen offset at direct-call/modified-sink scope).
The giant `memcpy` itself is observed as a truncated length value, not executed
locally — see section 3. Duplicate check before provisioning: no prior
`reports/frontier-*uhttpd*`, no uhttpd window, charter or mind on the tape, and
uhttpd is not on the do-not-duplicate list in `walls/frontier.md`. This is a
**network-facing, unauthenticated** HTTP server bug, unlike several recent
client-side finds; the victim is the router's web management plane. The
operator owns final admission; wake units and full-flag sync stay with the
person.

## 1. Verified ground truth

- Claim: GHSA-2mpg-6wp5-435p, "uhttpd: unauthenticated out-of-bounds write via
  `params` type confusion in POST /ubus/call/", published 2026-08-03 by `jow-`,
  severity High, CVSS v3.1 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`). The
  advisory demonstrates **denial of service only** (one unauthenticated HTTP
  POST kills the daemon, plain `-O2` build exits SIGSEGV, rc=139). It explicitly
  states controlled corruption and code execution were **not** demonstrated:
  "The primitive is a linear ~4 GiB heap write whose source bytes are
  attacker-influenced ... I did not build a controlled-corruption or
  code-execution PoC, so I do not score confidentiality or integrity impact."
  Any RCE scoring here is a claim, not an advisory fact.
- Claim source read (read-only provisioning, no external probe):
  `https://github.com/openwrt/uhttpd/security/advisories/GHSA-2mpg-6wp5-435p`.
- Affected: all revisions up to and including `f682ccab`; `ubus.c` is
  byte-identical between `f682ccab` (HEAD at disclosure) and `7b1bec45` (the
  revision OpenWrt currently packages), so shipped OpenWrt is affected exactly
  as HEAD. Patched by upstream commit
  `e76736e5676fb25536b27d45865eb4153c68aca3` (2026-08-03,
  "ubus: guard params type in uh_ubus_send_request()").
- Pins used locally: vulnerable `f682ccabee9ed5f39dd3b0aaf96228975eeb478d`
  (2026-07-24); fixed `e76736e5676fb25536b27d45865eb4153c68aca3`; libubox
  `a396f38a8568a1d670c240465cd8d24fdfdf6463`. Exact pin hashes are in
  `lab/frontier/uhttpd2shell/harness/PROVENANCE.md` and
  `harness/pins/PIN_HASHES.txt`.
- Access prerequisites: `ubus_prefix` must be set, which is stock LuCI config
  (`files/ubus.default` sets `ubus_prefix=/ubus`), so `/ubus/call/...` is
  served. No `Authorization: Bearer` header is needed: `uh_ubus_get_auth()`
  returns the null SID `00000000000000000000000000000000`, rpcd grants that
  session the `unauthenticated` ACL group and
  `rpcd/unauthenticated.json` gives it `session: ["access", "login"]`, so
  `uh_ubus_allowed(sid, "session", "login")` passes. The advisory confirms the
  ACL gate was cleared rather than bypassed: a well-formed login with a wrong
  password returns `{"code":6,"message":"Permission denied"}` from rpcd's own
  handler. This ACL chain is reported by the advisory, not re-run in this lab.
- Distinctness: the four other published uhttpd advisories are all in
  `client.c` HTTP framing (`GHSA-vhx4-3p5q-m59q`, `GHSA-wgwp-64hh-f52p`,
  `GHSA-p55c-rmhc-qfm5`, `GHSA-mcfg-c4r7-pjpf`); none involves `params`,
  `blobmsg_add_blob`, `uh_ubus_send_request` or `blobmsg_add_field`.

## 2. Source-bound mechanism and fix

In the vulnerable pin, the JSON-RPC policy declares the `params` slot as
`{ .name = "params", .type = BLOBMSG_TYPE_UNSPEC }`, i.e. it accepts **any**
blobmsg type. `parse_json_rpc()` copies the attribute verbatim with
`blob_memdup()` and `uh_ubus_call()` passes it straight to
`uh_ubus_send_request()`, which assumes a container:

```c
blob_buf_init(&req, 0);
blobmsg_for_each_attr(cur, args, rem) {
        if (!strcmp(blobmsg_name(cur), "ubus_rpc_session"))
                return uh_ubus_json_rpc_error(cl, ERROR_PARAMS);
        blobmsg_add_blob(&req, cur);
}
```

With `"params": 1` the attribute is a 20-byte `BLOBMSG_TYPE_INT32`: a 4-byte
`struct blob_attr` header (`id_len = be32(BLOB_ATTR_EXTENDED | (5<<24) | 20)`,
bytes `85 00 00 14`; real `blobmsg_add_field()` always sets the extended bit,
which makes `blobmsg_data()` skip the name header), a 12-byte `struct
blobmsg_hdr` (`namelen=6`, name `params\0` padded), and a 4-byte payload
`00 00 00 01`. `blobmsg_data_len(args)` is 4, so the iterator's guard
`rem >= sizeof(struct blob_attr)` passes and the payload is reinterpreted as
a `struct blob_attr`:

- `blob_len(cur) = (1 & 0x00ffffff) - sizeof(struct blob_attr)` underflows to
  `0xFFFFFFFD`, while `blob_pad_len(cur)` rounds back to 4, satisfying the
  remaining loop guards.
- `blobmsg_name(cur)` is `blob_data(cur) + 2`, i.e. 2 bytes past the 20-byte
  `blob_memdup` allocation. `strcmp()` therefore performs an out-of-bounds
  read above.
- `blobmsg_add_blob()` calls `blobmsg_add_field(buf, type, name,
  blobmsg_data(cur), blobmsg_data_len(cur))`. `blobmsg_data_len(cur)` is
  `0xFFFFFFFD` as `size_t`; `blobmsg_add_field`'s `unsigned int len` parameter
  truncates it to `4294967293` and its `memcpy(data_dest, data, len)` performs
  the ~4 GiB write.

The advisory maps the whole input range deterministically: low 24 bits 1–3
give the giant `memcpy`, 4 gives the out-of-bounds read only, ≥5 fails
`blob_pad_len(pos) <= rem` and is filtered, and 0 fails
`blob_pad_len(pos) >= sizeof(struct blob_attr)`.

The fix is a single guard in `uh_ubus_send_request()`, verified verbatim in
the pin diff (the legacy/batch path already pins the type via
`parse_call_params()` declaring slot 3 as `BLOBMSG_TYPE_TABLE`):

```c
if (args && blobmsg_type(args) != BLOBMSG_TYPE_TABLE)
        return uh_ubus_json_rpc_error(cl, ERROR_PARAMS);
```

## 3. Measured evidence (this lab)

Everything lives in `lab/frontier/uhttpd2shell/`. `harness/gen.py` extracts
`uh_ubus_send_request()` byte-for-byte from the pinned `git show PIN:ubus.c`
blobs (only the function name is changed); `harness/pins/` carries the pinned
libubox `blob.c`/`blob.h`/`blobmsg.c`/`blobmsg.h`/`utils.h` so the build is
self-contained. `harness/run.sh` builds both pins with gcc and clang, ASan and
plain, and runs two full rounds with normalized PASS-line and chosen-byte-hash
equality. No sockets, no external systems. Verified locally from the repo root
with gcc 13.3.0 and clang 18.1.3: **30 PASS / 0 FAIL**, `rc=0`.

- **REAL mode, ASan (exact 20-byte `blob_memdup`-shaped allocation):** the
  vulnerable pin gives `ERROR: AddressSanitizer: heap-buffer-overflow`,
  `READ of size 1`, **2 bytes after a 20-byte region**, top frames `strcmp` →
  `vuln_uh_ubus_send_request` (`harness/fn.inc`). This is the advisory's first
  fault. The fixed pin returns `ERROR_PARAMS` before the loop (`ERROR=3`,
  `INVOKED=0`, no ASan fault). The full 4 GiB `memcpy` is **not** executed in
  REAL mode: default ASan stops at the preceding OOB read; the advisory also
  needed `-fsanitize-recover=address` to reach the giant write. We do not run
  a recover-mode 4 GiB write (it would risk the lab's memory guard) and do not
  claim it as a local observation.
- **MODEL mode (real libubox arithmetic, instrumented final sink):** the sink
  receives the truncated `WRITE_LEN=4294967293` from the same
  `blobmsg_add_blob` call the verbatim function makes. Its `data` pointer is
  `args+20`, 20 bytes into a 128-byte attacker-controlled region, so the
  copied bytes are chosen filler. The ASan build copies 16 bytes into
  `malloc(8)` and reports `heap-buffer-overflow WRITE of size 16` with
  `WRITE_OFF=20`; plain builds read back `MODEL_RESULT WRITE_OFF=20
  WRITE_LEN=4294967293 BYTES=41414141414141414141414141414141` for fill
  `0x41` and `...5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a` for fill `0x5a`. The fixed
  pin never calls the shim; a well-formed TABLE `params` yields only the
  ordinary small `WRITE_LEN=4` on both pins. This is rung 4 at the
  modeled-sink scope only.
- `harness/evidence/round2-pass.txt` (sha256 `c3b2b9d1...`),
  `round2-chosen-hashes.txt` (`8966ae93...`), and the per-case raw logs hold
  every observation. The pinned-function sha256s are `8442ab8d...`
  (vulnerable) and `70e38912...` (fixed), rechecked with `sha256sum -c` on
  every run; full hashes and the libubox pin are in `harness/PROVENANCE.md`
  and `harness/pins/PIN_HASHES.txt`.

## 4. Rung-4 feasibility and honest ceiling

Rung 1 (one deterministic crafted `params` scalar), rung 2 (iterator treats a
scalar as a container and the length underflow passes the guards) and rung 3
(ASan-confirmed OOB read in the verbatim pinned function over real libubox
code) are direct-call facts. The truncated `0xFFFFFFFD` length is observed as
a value, and rung 4 is chosen bytes at a chosen offset with an instrumented
sink standing in for the final `memcpy`. That substitution is required because
the real primitive is a ~4 GiB linear write whose source bytes are adjacent
heap contents; control over those bytes is a separate grooming claim. Every
such result is labeled `MODELED SINK`.

Ceiling: no live uhttpd process, no HTTP wire, no rpcd, no ACL-chain replay,
no reenactment of the unauthenticated gate, no heap grooming, no pointer
control, no marker execution, no command and no rung 5. The advisory's own
impact score stops at `A:H`; moving above it requires a controlled-corruption
PoC that neither the advisory nor this lab supplies.

Tractability: high. Two adjacent pins, a four-line fix, a small C codebase,
public source, and a self-contained blobmsg arithmetic path. It outranks the
parked FRR/llama.cpp/Libreswan tail and the weaker NanoMQ off-by-one
(GHSA-6w96-9qw7-m599, no fix, authenticated, NUL-byte overwrite): uhttpd has a
precise deterministic primitive, a network trigger, and an exact upstream fix.

## 5. Cheapest next experiment to move up a rung

Build the pinned vulnerable `uhttpd` against pinned libubox with ASan, configure
`ubus_prefix=/ubus`, and start it on a plant-started 127.0.0.1 listener with a
plant-started local rpcd (or a stub that reproduces the null-SID ACL result).
Send the advisory's single POST and observe the OOB read in the live process;
a plain build should exit SIGSEGV. The decisive second question is whether
attacker-influenced heap bytes can be placed at the source pointer
(`blob_data(cur)+4`, 20 bytes past the `blob_memdup` allocation) by a bounded
grooming sequence, and whether the destination can be steered to a useful
object before the write faults — that is what separates rung 4 from the
advisory's DoS-only demonstration. Fixed pin, a table-typed `params`, and a
request with `Authorization: Bearer` remain controls.

## 6. Candidates screened this wake

- **Selected:** uhttpd GHSA-2mpg-6wp5-435p (above).
- **Screened lower:** NanoMQ GHSA-6w96-9qw7-m599 / CVE-2026-32135,
  `uri_param_parse()` off-by-one NUL write in `rest_api.c:538`, affected 0.24.8
  with **no patched version**. Advertised trigger needs `curl ... -u
  admin:public` (authenticated), the overwrite is a 2-byte NUL and the impact
  claim is generic heap corruption. Weak on authentication and control.
- **Rejected as already owned:** FreeSWITCH `mod_verto` CVE-2026-49841
  (`freeswitch2shell`), C-Kermit (`kermit2shell`), Wazuh
  (`wazuh2shell`), Netatalk (`netatalk2shell`), bRPC CVE-2026-56388
  (screened out with a prior brief), llama.cpp CVE-2026-118375 (already in the
  parked tail).
- **Rejected on ceiling:** Palo Alto GlobalProtect CVE-2026-46580 and Fortinet
  CVE-2026-126245 (proprietary, no pin or fix bytes), NGINX CVEs (other minds).
- Do not duplicate the admitted list in `walls/frontier.md`; NGINX/Node belong
  to other minds.
