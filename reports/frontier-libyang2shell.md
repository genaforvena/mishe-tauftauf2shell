# Frontier brief: libyang LYB `lyb_read_string()` — GHSA-vw2p-pq79-92xh / CVE-2026-44673 (libyang2shell)

Status W124 (2026-11-22): screened in and staged at rung 3 (ASan-confirmed heap
out-of-bounds write in a verbatim pinned function) plus a scoped rung 4 (chosen
bytes at a chosen offset in a 0-byte allocation, direct-call/stub scope).
Duplicate check before provisioning: no prior `reports/frontier-*libyang*`, no
libyang window/charter/mind on the tape, and libyang is absent from the
do-not-duplicate list in `walls/frontier.md`. The advisory claims DoS only;
"potential RCE if heap layout is controllable" is its claim, not a local
observation. Operator owns final admission; wake units and full-flag sync stay
with the person.

## 1. Verified ground truth

- Claim: GHSA-vw2p-pq79-92xh, "lyb_read_string() integer overflow → heap buffer
  overflow (CWE-190/CWE-122)", CVE-2026-44673, published 2026-04-07 by
  `michalvasko`, credit `@BlainerIP`. High / CVSS v3.1 7.5
  (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) — availability only.
- Claim source read (read-only provisioning, no external probe):
  `https://github.com/CESNET/libyang/security/advisories/GHSA-vw2p-pq79-92xh`.
- Affected / patched fields on the advisory: "< SO 5.2.15" / "SO 5.2.15".
  **Recorded discrepancy:** no matching `SO-5.2.15` (or `v5.2.x`) tag is visible
  in this repo's tag list; two real upstream commits address the same lines:
  `73da1db8fc14802e4f8fc64d022011a6f9d514db` (2026-04-07, "parser lyb BUGFIX
  avoid uint overflow", two 64-bit casts) and
  `48672b289e2e4c6773712c3ee0abae6b7fffe1f3` (2026-05-06, PR #2513, adds an
  explicit `str_len == UINT32_MAX` rejection). Both pins are real commits;
  neither discrepancy is silently corrected here.
- Primitive claimed: a malicious LYB blob sets a four-byte little-endian string
  length to `0xFFFFFFFF`. `malloc((str_len + 1) * sizeof **str)` wraps to
  `malloc(0)`; `str_len * 8` wraps in `uint32_t`; with a memory input
  (`in->length == 0`) `ly_in_read()` skips its bounds check and memcpy's a huge
  count into the zero-sized allocation; the unconditional
  `(*str)[UINT32_MAX] = '\0'` writes 4 GiB past it. Consumers named by the
  advisory: NETCONF servers using libnetconf2, sysrepo, any
  `lyd_parse_data(..., LYD_LYB, ...)` caller.

## 2. Source-bound mechanism and fix

Verbatim vulnerable pin `979f6925cf1f0918915613022e9e9dfc751bf647` (parent of
`73da1db8`), `src/parser_lyb.c:278-298`:

```c
static LY_ERR
lyb_read_string(char **str, struct lylyb_parse_ctx *lybctx)
{
    uint32_t str_len = 0;
    *str = NULL;
    lyb_read_size(&str_len, lybctx);
    *str = malloc((str_len + 1) * sizeof **str);
    LY_CHECK_ERR_RET(!*str, LOGMEM(lybctx->ctx), LY_EMEM);
    if (str_len) {
        lyb_read(*str, str_len * 8, lybctx);
    }
    (*str)[str_len] = '\0';
    return LY_SUCCESS;
}
```

`lyb_read_size()` reads four bytes LE in non-shrink mode. `lyb_read()` passes
`LYPLG_BITS2BYTES(str_len * 8)` to `ly_in_read()`; pinned `src/in.c` shows
`if (in->length && (in->length - (in->current - in->start) < count)) return
LY_EDENIED;` followed by `memcpy(buf, in->current, count)` — so a memory input
with `length == 0` is unbounded. glibc `malloc(0)` returns non-NULL, so the
error check passes. The advisory says the memcpy count is 536,870,910 bytes;
the pinned expression measures **536,870,911** here (`(0xFFFFFFF8 / 8) + 1`),
recorded as a claim discrepancy rather than adopted.

The 2026-04-07 fix casts both expressions to `uint64_t`: the allocation becomes
4 GiB and the read count 4,294,967,295 bytes. That removes the 32-bit wrap but
still attempts a 4 GiB allocation and places the terminator at the last byte of
that allocation. The 2026-05-06 fix adds, before allocation:

```c
LY_CHECK_ERR_RET(str_len == UINT32_MAX,
        LOGERR(lybctx->ctx, LY_EINVAL, "LYB string length overflow."), LY_EINVAL);
```

The harness uses the parent pin as vulnerable, `48672b28` as the clean fixed
control, and `73da1db8` as an explicitly labeled partial-fix control.

## 3. Measured evidence (this lab)

Everything lives in `lab/frontier/libyang2shell/`. `harness/gen_fn.py` extracts
`lyb_read`, `lyb_read_size`, `lyb_read_string` and `ly_in_read` byte-for-byte
from the pinned sources (three `.inc` files, verified by
`harness/verify_verbatim.py`). `harness/harness.c` supplies only the types,
log macros, scripted four-byte length + 16 chosen bytes, and a **bounded memcpy
sink**: it records the exact requested count but copies at most 16 bytes, so
the real 536 MB copy is not executed while the real out-of-bounds destination
write remains observable. No socket, no consumer, no libyang build.

`bash lab/frontier/libyang2shell/harness/run.sh` — **42 PASS / 0 FAIL**, `rc=0`,
two rounds with byte-identical normalized evidence hash
`edf0399fb7c5e5aef309e460d60286394a324d149cf600305c9f6bfffdda51f2f2`
(gcc 13.3.0 + clang 18.1.3). Full logs and pin hashes: `harness/evidence/`,
`harness/PROVENANCE.md`.

- Vulnerable pin with `str_len=0xFFFFFFFF`, gcc and clang ASan:
  `ERROR: AddressSanitizer: heap-buffer-overflow`, `WRITE of size 1`,
  `0 bytes after 1-byte region`, frames `instrumented_memcpy` -> `ly_in_read`
  -> `lyb_read` -> `lyb_read_string`; `MALLOC_REQ=0` precedes the fault.
- Vulnerable pin, plain build with a 4 GiB `PROT_NONE` arena and two writable
  pages: 16 chosen bytes `414243...4f50` (base `0x41`) or `5a5b5c...6869`
  (base `0x5a`) at offset 0 of the 0-byte allocation, `SINK_REQ=536870911`,
  and a terminator byte `00` observed at offset `4294967295`.
- Partial-fix pin: `MALLOC_REQ=4294967296`, `SINK_REQ=4294967295`, terminator
  at `4294967295` inside that 4 GiB allocation — wrap gone, oversized
  allocation and read remain.
- Hardened pin: logs `LYB string length overflow.`, returns `-2`, no malloc,
  no read, no write, on both compilers and both modes.
- Safe control (`str_len=8`): `MALLOC_REQ=9`, `SINK_REQ=8 SINK_COPY=8`, chosen
  bytes and in-bounds terminator; clean on both pins/compilers/modes.

## 4. Honest ceiling / rung-4 feasibility

Reached: rung 3 (ASan-confirmed heap corruption in verbatim pinned code) and a
scoped rung 4 (chosen bytes at a chosen offset, direct-call/stub scope).
**Not** reached: no libyang build, no real `lyd_parse_data()` call, no crafted
LYB framing, no NETCONF/sysrepo consumer, no wire, no full 536 MB copy (bounded
sink), no pointer control, no marker execution, no command, no rung 5. The
terminator observation uses a mapped arena in the plain build, not a real
4 GiB heap allocation; ASan sees the earlier offset-0 write instead. The
advisory's "potential RCE" and its network-reachability claim are unchanged
claims awaiting a consumer-level replay.

Cheapest next experiments for the owning mind, in order: (1) build the pinned
vulnerable libyang and call `lyd_parse_data(ctx, buf, len, LYD_LYB, ...)`
directly with a minimal crafted LYB blob to confirm the string-length field is
actually reachable at the claimed offset; (2) on a plant-started loopback
libnetconf2/sysrepo instance, determine whether unauthenticated LYB input is
accepted at all and whether `in->length` is 0 on that path; (3) measure the
host's 4 GiB allocation behavior before considering any heap-shaping. Rung 5
stays additive and per-build.

## 5. Ranking and disposition

Tractability: high — a 21-line self-contained function, small two-commit fix
chain, no consumer build needed for current evidence. Impact ceiling is honest
but narrow: advisory claims availability only, and the client/consumer path is
unverified. Staged by frontier at 2026-11-22 with this brief, a charter, a seed
wall and a live two-pane window; the operator owns final admission. Frontier
owns no further work on this lane after staging.
