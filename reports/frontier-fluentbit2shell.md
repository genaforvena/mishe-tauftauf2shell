# Frontier brief: Fluent Bit `out_forward` — CVE-2026-61674 (fluentbit2shell)

**STAGED 2026-11-23 W141 — direct-call harness evidence and a live two-pane
target window exist; no operator admission yet.** Provenance and byte-exact
pins: `lab/frontier/fluentbit2shell/PROVENANCE.md`. Frontier owns no further
work on this target; the operator admits, the witness re-runs.

## 1. Verified ground truth

- Advisory: GHSA-jrp8-r9hx-gf73, "Remote stack buffer overflow in Fluent Bit
  `out_forward` Secure-Forward `PONG` handler", published 2026-09-08,
  Critical, CVSS 9.2
  `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`,
  CWE-121/787/843 —
  https://github.com/fluent/fluent-bit/security/advisories/GHSA-jrp8-r9hx-gf73
- CVE: https://www.cve.org/CVERecord?id=CVE-2026-61674 — published
  2026-09-21, affected `>= 0.11.0, < 5.0.8`, fixed 5.0.8. The GHSA's
  "Patched versions: None" field is stale; the CVE record, fix commit and
  v5.0.8 release agree on 5.0.8.
- Fix commit `45486556be9d023e194665e243f156b228e195e0` ("out_forward:
  Process more strict length and type checks", parent `47db630cbfc5`) —
  https://github.com/fluent/fluent-bit/commit/45486556be9d023e194665e243f156b228e195e0
- Claimed primitive: during the first flush over a non-keepalive connection
  with `Shared_Key`/`Empty_Shared_Key` configured, `secure_forward_pong()`
  copies the server-supplied `PONG[2]` "reason" msgpack string into a 32-byte
  stack `char msg[32]` with `memcpy`, checking neither type nor length. A
  malicious or on-path upstream forward destination controls both. The
  advisory documents byte-precise saved-RBP (reason offset 48) and saved-RIP
  (offset 56) control, ROP → `system()` → root in a no-canary build, and a
  leakless BROP path under opt-in `--supervisor`.

## 2. Source-bound mechanism and fix

Byte-exact pins (SHA-256 in `src/SHA256SUMS`): `forward.c.47db630c` and
`forward.c.v5.0.7` are identical (`406f2d22…c9687`); `forward.c.45486556` and
`forward.c.v5.0.8` are identical (`cb2f62d7…1ea7`). Rendered line numbers are
claims; raw bytes rule.

Vulnerable `secure_forward_pong()`, pinned
`forward.c.47db630c:523-574`:

```c
static int secure_forward_pong(struct flb_forward *ctx, char *buf, int buf_size)
{
    int ret;
    char msg[32] = {0};                                  /* 32-byte stack buffer */
    ...
    o = root.via.array.ptr[0];
    if (o.type != MSGPACK_OBJECT_STR) goto error;
    if (strncmp(o.via.str.ptr, "PONG", 4) != 0 || o.via.str.size != 4) goto error;
    o = root.via.array.ptr[1];
    if (o.type != MSGPACK_OBJECT_BOOLEAN) goto error;
    if (o.via.boolean) { ... return 0; }
    else {
        o = root.via.array.ptr[2];
        memcpy(msg, o.via.str.ptr, o.via.str.size);      /* no bound, no type check */
        flb_plg_error(ctx->ins, "failed authorization: %s", msg);
    }
 error: ...
}
```

`PONG[0]` is type- and size-checked; only `PONG[2]` is not. The PONG is read
into a 1024-byte stack buffer in `secure_forward_handshake()`, bounding the
reason at roughly 1015 bytes → ~983 bytes past `msg`. The missing type check
also admits a `BIN`/`EXT` element (the msgpack `str`/`bin` unions share
`{uint32_t size; const char *ptr;}`).

Fix `45486556` adds, at pinned `forward.c.45486556:583-594`:

```c
o = root.via.array.ptr[2];
if (o.type != MSGPACK_OBJECT_STR) { goto error; }
if (o.via.str.size >= sizeof(msg)) {
    memcpy(msg, o.via.str.ptr, sizeof(msg) - 1);
    msg[sizeof(msg) - 1] = '\0';
} else {
    memcpy(msg, o.via.str.ptr, o.via.str.size);
    msg[o.via.str.size] = '\0';
}
```

The same commit adds type checks to `secure_forward_set_ping()`, the HELO
reader and `forward_read_ack()`; those hunks are outside this harness's
callpath and are not claimed as reproduced.

## 3. Cheapest local experiment

One C file, no daemon, TLS or socket. Include the **complete** verbatim
`secure_forward_pong()` from each of four pinned blobs (vulnerable parent,
v5.0.7, fix commit, v5.0.8) in a driver with stubbed msgpack-c object/unpack
types, `flb_forward`/`flb_input_instance` and `flb_plg_error`. Build a
synthetic `["PONG", false, <reason>, "h", "d"]` object and call the function
with a 1000-byte reason carrying chosen markers. The fixed commit and v5.0.8
are fixed controls; v5.0.7 is a second vulnerable control; a 4-byte reason is
the safe control in every variant.

## 4. Rung-4 feasibility and risks

Feasible locally: a 32-byte destination and a fully controlled 1000-byte
source give a clean write primitive. Measured constraints: plain builds need
`-fno-stack-protector` (the default protector aborts before observation);
ASan faults on the WRITE before any control-flow effect, so the saved-RIP
byte is observed only in the plain build under gdb; the fixed variants copy
at most 31 bytes and NUL-terminate, so their bytes past 31 are uninitialized
and excluded from the normalized trace. The chosen saved RIP
`0x414141414141417b` is a byte pattern, not a gadget or a command.

## 5. Observations

- Harness `PASS=65 FAIL=0` three times plus clean `/tmp` and git-archive
  replays; normalized trace
  `35e7c470871e94379158696aa6899f13db4413b61153d53c4df6296f04061d96`.
- Rung 1: 1000-byte reason vs 32-byte destination, 968 bytes over.
- Rung 2: vulnerable parent and v5.0.7 copy the chosen bytes and emit
  `MSG_BYTE31=41`; fix and v5.0.8 bound the copy and NUL-terminate
  (`MSG_BYTE31=00`).
- Rung 3: gcc and clang ASan `WRITE of size 1000` at pinned
  `forward.c.47db630c:567` in `secure_forward_pong`, object `msg` `[256,288)`
  at line 526; fixed, v5.0.8 and safe inputs clean.
- Rung 4: gdb breakpoint at pinned line 568 shows
  `saved rip = 0x414141414141417b` and a stack byte `0x5a`; the process then
  faults at pinned line 574 with the chosen RIP in backtrace frame 1.

## 6. Prior rejection, explicitly revisited

An earlier frontier brief (`reports/frontier-nanomsg.md:128-129`) listed this
CVE as "rejected: attacker is a malicious server, victim is a client." That
one-line note is not a staged report and is overridden: this plant already
stages network-initiator/client bugs, and the evidence ladder tests
attacker-controlled wire bytes reaching a target process, which this sink
satisfies. The threat model (malicious or MITM'd upstream forward destination
corrupting every connecting agent on first flush) is recorded honestly below.

## 7. Ceiling / handoff

Direct call with stubbed msgpack/flb plumbing; no real `fluent-bit` process,
socket, TLS/SRP, HELO/PONG wire exchange, event loop or attacker server; no
stack canary (plain builds use `-fno-stack-protector`), no ROP chain, command,
`/tmp/PWNED` side effect, canary/BROP exercise or witness verdict. The
advisory's RCE and `--supervisor` claims stay claims. A dedicated target mind
should first reproduce the sink in a real 5.0.7 `fluent-bit` over loopback
with a malicious forward server, then look for usable frame state before any
benign marker. Do not relabel a chosen saved-RIP byte as remote execution.
