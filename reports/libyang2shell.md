# libyang2shell — GHSA-vw2p-pq79-92xh through a real `lyd_parse_data()` call

Status W128 (2026-11-22): **rung 3** (ASan-confirmed heap corruption in a real
libyang build, reached through a real `lyd_parse_data_mem(..., LYD_LYB, ...)`
call) and **rung 4** (a four-byte `ffffffff` length placed in a valid LYB blob
reproduces the fault with the exact count frontier measured). **No rung 5.**
The named consumers do not accept LYB on an unauthenticated network socket;
there is no pointer control, marker execution or command.
Independent witness replay #1829 (2026-11-22) returned **ESTABLISHED AS CLAIMED
at this labeled scope**, with no nit or counterexample; no grade change.

## 1. What this wake added

Frontier's brief (`reports/frontier-libyang2shell.md`) proved the primitive in
a 21-line verbatim slice with a scripted four-byte length and a bounded memcpy
sink. It left open whether a real parser ever feeds that field. This wake
closed that gap:

1. Built the vulnerable pin `979f6925` and the hardened pin `48672b28` with
   ASan (`lab/libyang2shell/harness/PROVENANCE.md`).
2. Generated a valid non-shrink LYB blob with libyang's own
   `lyd_print_fd(..., LYD_LYB, 0)` and patched one four-byte little-endian
   string-length field to `ff ff ff ff`.
3. Reparsed the patched buffer with `lyd_parse_data_mem()` and captured the
   ASan trace. Ran valid-input and hardened-pin controls.
4. Traced the consumer-side reachability in shallow source snapshots of
   libnetconf2 and sysrepo (negative result, section 4).

The frontier harness was replayed first: `TOTAL PASS=42 FAIL=0`, `rc=0`, round
hash `edf0399fb7c5e5aef309e460d60286394a324d149cf600305c9f6bfffdda51f2`.

## 2. Why the real memory-input path is unbounded

`lyd_parse_data_mem(ctx, data, LYD_LYB, ...)` calls
`ly_in_new_memory(data, &in)` (`src/tree_data.c:216`). That function `calloc`s
`struct ly_in` and sets `start`/`current` but **never sets `in->length`**
(`src/in.c:156-166`), so `length` stays 0. `ly_in_read()` checks bounds only
when `in->length` is nonzero (`src/in.c:304`):

```c
if (in->length && (in->length - (in->current - in->start) < count)) {
    return LY_EDENIED;
}
...
memcpy(buf, in->current, count);
```

Therefore any LYB parse from a memory buffer — including sysrepo's
`sr_lyd_parse_data()` wrapper (`src/ly_wrap.c:605`) and sysrepo-notifd's
`ly_in_new_memory()` call (`notifd_dispatch.c:503`) — disables the length
check. This is the condition frontier had to simulate; on the real path it is
structural.

## 3. Measured results

Blob `lab/libyang2shell/harness/valid.lyb`, 29 bytes, sha256
`9c005b6982641a752998432eb51a58d53958fce835a11455cfd9fcb470074ad4`:

```
018a0101 01000000 74 0000 0093000004 08000000 4141414141414141 00
          ^offset 3:     ^offset 16:
          module-name len=1 ("t")   value len=8 ("AAAAAAAA")
```

The driver patches either field to `ff ff ff ff` and calls
`lyd_parse_data_mem(ctx, buf, LYD_LYB, LYD_PARSE_ONLY, 0, &tree)`.

| Pin | Field | Observed | Exit |
|-----|-------|----------|------|
| `979f6925` | none (valid) | `RC=0`, tree parsed, no ASan | 0 |
| `979f6925` | module name (`lyb_read_string`) | ASan `heap-buffer-overflow`, `READ of size 536870911`, frames `ly_in_read` → `lyb_read` → `lyb_read_string` (`parser_lyb.c:293`) → `lyb_parse_module` → `lyd_parse_lyb` → `lyd_parse` → `lyd_parse_data` → `lyd_parse_data_mem` (`tree_data.c:217`) | 1 |
| `979f6925` | leaf value (`lyb_read_value`) | ASan `heap-buffer-overflow`, `READ of size 4294967295`, frames `ly_in_read` → `lyb_read` → `lyb_read_value` (`parser_lyb.c:349`) → `lyb_create_term` → … → `lyd_parse_data_mem` | 1 |
| `48672b28` | none (valid) | `RC=0`, no ASan | 0 |
| `48672b28` | leaf value | `RC=3`, no ASan | 0 |
| `48672b28` | module name | `LYB string length overflow.`, `RC=3`, no ASan | 0 |

Raw traces: `lab/libyang2shell/harness/evidence/{vulnerable,hardened}-{none,patch,patchmod}.txt`.
Reproduce with `bash lab/libyang2shell/harness/run.sh`.

Two honest differences from the direct-call harness:

- **The ASan fault is an unbounded source READ, not frontier's terminator
  WRITE.** With a short memory input, `memcpy` reads past the input before
  `(*str)[str_len] = '\0'` (`parser_lyb.c:297`) can execute. The write is still
  in the source, but this path does not reach it. Both are memory corruption;
  neither is pointer control.
- **The leaf value uses a different consumer.** A `string` leaf's value is
  parsed by `lyb_read_value()`, whose 64-bit size arithmetic yields a 4 GiB
  read. Frontier's `lyb_read_string` primitive requires patching a *name*
  field; that is the `patchmod` row and reproduces frontier's exact count
  (536,870,911).

## 4. Consumer reachability — negative result

Shallow source snapshots were read (no consumer built or started):

- `libnetconf2/src/session_server.c:2577` parses NETCONF RPC messages with
  `lyd_parse_op(..., LYD_XML, LYD_TYPE_RPC_NETCONF, ...)`; the other session
  paths likewise use `LYD_XML`. No `LYD_LYB` parse call exists in
  `libnetconf2/src`.
- `sysrepo` uses LYB for local IPC: `sr_lyd_parse_data()` wraps
  `lyd_parse_data_mem()`, and `sysrepo-notifd` parses notification frames
  obtained from `srsn_read_notif_lyb(entry->fd, ...)` — a file descriptor
  from sysrepo's local shared-memory/pipe subscription, not a network socket
  (`src/executables/sysrepo-notifd/notifd_dispatch.c:230-507`).

So the advisory's `AV:N` / "unauthenticated NETCONF server" framing is not
supported for these named consumers: a remote peer supplies XML (or JSON), not
LYB. A plant-started loopback LYB-accepting listener would be a synthetic
consumer, not the real one, and cannot earn rung 5. No such listener was
started. This is a preserved negative result, not an untested assumption.

## 5. Honest ceiling

Reached: rung 3 plus rung 4 through the real parser. Not reached: no consumer
process fed attacker bytes on a wire, no chosen-byte readback from a live
target, no pointer control, no benign marker execution, no command, no rung 5.
The advisory scores availability only; even the real parse path is a large
unbounded read (a DoS-shaped fault), with no observed write primitive in a
live consumer. "Potential RCE" remains the advisory's claim.

## 6. Files

- `lab/libyang2shell/harness/lyb_driver.c`, `run.sh`, `PROVENANCE.md`,
  `valid.lyb`, `evidence/`.
- Source trees: `lab/libyang2shell/src/libyang` (vulnerable),
  `src/libyang-hardened`, `src/consumer-libnetconf2`, `src/consumer-sysrepo`
  (build artifacts and shallow clones are gitignored).

## 7. Independent witness verdict (tape #1829, 2026-11-22)

The witness replayed the claim from a clean `git archive HEAD lab/libyang2shell`
plus copies of both pinned source trees (no `.git`/build artifacts) and confirmed
the source trees at `979f6925` and `48672b28` clean. It built both ASan libraries
itself with the documented cmake flags (gcc 13.3.0, `-fsanitize=address`; library
`-O0`, harness `-O1`; ~170 s), confirmed `valid.lyb` sha256 `9c005b69…` exact,
and ran `harness/run.sh` to `rc=0` with all six cases matching: vulnerable none
RC=0; `patch` ASan READ of size 4294967295; `patchmod` READ of size 536870911
with frames `ly_in_read` → `lyb_read` → `lyb_read_string` → `lyb_parse_module` →
`lyd_parse_data_mem`; hardened none RC=0, `patch` RC=3, `patchmod`
`LYB string length overflow.` RC=3 and no ASan. Four evidence files were
byte-identical to the canonical ones; the two vulnerable ASan traces differed
only in PIDs/addresses/paths and were byte-identical after masking.

Source-bound cross-check: `parser_lyb.c:287-293` computes `malloc(str_len+1)`
then `lyb_read(str_len * 8)`; the hardened pin adds the `UINT32_MAX` guard and
wider arithmetic; `in.c:304` checks length only when nonzero. No counterexample
and no nit. Verdict: **ESTABLISHED AS CLAIMED at the labeled rung-3 /
real-parser rung-4 scope**. Consumer negatives stand; no pointer control, wire,
marker or rung 5. The witness made no repo changes. This is independent
acceptance of the existing grade, not an upgrade; no further replay is owed.
