# Provenance and harness boundary — strongSwan2Shell (CVE-2026-35330)

## Pins (fetched 2026-11-21, provisioning only, no external probe)

All pins are in `pins/`. Hashes are sha256 of the exact bytes on disk and are
asserted by `run.sh`.

| file | sha256 |
| --- | --- |
| `advisory-CVE-2026-35330.html` | `2673aa1c6197b9c92ad2eb0f095ec39e41b0d023f4d03a8a2cd4925cc77c6a73` |
| `fix-aa5aaebc.patch` | `7a67fda25fd9808ed06589ed2918145715b70e30ba804f337079357644aa37df` |
| `simaka_message.c.v6.0.5` | `934cc1fd3c322da69f542b01e7fdf5314e6cd8db7b1aa6fd5ae17a774dbe97cb` |
| `simaka_message.c.v6.0.6` | `ee91a54e7316afb4af18540f908bb4c8af04aeed795d76ee1809f136d7cc84b0` |
| `simaka_message.h.v6.0.5` | `c7d35ba1e53686ae3acea6eb6c007a05c97e839dafc1928b1077011c3766ca52` |

Sources: `https://www.strongswan.org/security/CVE-2026-35330.html`,
`https://github.com/strongswan/strongswan/commit/aa5aaebc33e0f326d8a0dbe01b236f2bfa0e6ea1.patch`,
and `https://raw.githubusercontent.com/strongswan/strongswan/{6.0.5,6.0.6}/src/libsimaka/simaka_message.c`
plus the `6.0.5` header at the same path.

## Verbatim extracted blocks

`run.sh` extracts three contiguous ranges from each pinned `.c` file and
inserts them under `#line N "src/libsimaka/simaka_message.c"` into
`driver.template.c`:

- `252-263` — `add_attribute()`: the wrapped `malloc()`, the `attr->len`
  store and the unbounded `memcpy()` sink.
- `415-450` — the `AT_ENCR_DATA` / `AT_RAND` branch (`- 4`) and the
  `AT_PADDING` / default branch (`- 2`), with their original missing guards.
- `452-480` — the special-attribute switch that routes non-PADDING types to
  `add_attribute()`.

The fixed pin differs only by the two added `hdr->length == 0 ||` checks at
`:419` and `:442`. Nothing in these ranges was edited by hand.

## Synthetic collaborators and what is NOT in scope

- `chunk_t`, `chunk_create()`, `chunk_skip()` — harness stand-ins for the
  upstream `utils/chunk.h` shape; `chunk_skip()` reproduces the no-op on the
  underflowed zero length.
- `simaka_attribute_t` values, `attr_hdr_t` and `attr_t` — verbatim pinned
  shapes/values; only a typedef alias is added for C compilation.
- `private_simaka_message_t`, `linked_list_t::insert_last`, `invalid_length()`,
  `not_encrypted()`, `DBG1()` and `call_hook()` — stubs. No IKE daemon, EAP
  state machine, RADIUS, socket, listener, network or client is used.
- `__wrap_malloc` (`-Wl,--wrap=malloc`) logs the pinned allocation size and
  pointer. In the ASan build it forwards to `__real_malloc` (ASan's allocator,
  so real redzones apply). In the plain build it redirects the one pinned
  allocation into a 1 MiB anonymous mapping with a `PROT_NONE` guard page.
- The 1 MiB source mapping is filled with a chosen `0x5a/0xa5` pattern and
  followed by a `PROT_NONE` guard page. It stands in for attacker-controlled
  EAP attribute bytes; there is no packet parser above it.

No pointer, saved return address, heap metadata field forging, function
pointer, control-flow diversion or code execution was attempted or observed.
All oom/daemon-reachability claims from the advisory remain external claims.

## Two distinct copy modes — preserved negative result

1. **Real libc (default plain build).** With the genuine wrapped length,
   glibc's `memcpy` faults at `src_base - 0x20` before writing the chosen
   pattern into the region past the allocation: the guarded destination
   offsets `16/32/64/4096/65536` all read `0x00` and `match=0`. A standalone
   probe (`/tmp/sw2-memcpy-probe.c`, throwaway, not committed) reproduced the
   same fault address pattern. This is a real negative result: on this host,
   the raw underflowed copy does not itself deliver chosen bytes past the
   allocation.
2. **Bounded-copy collaborator (`-DBOUNDED_COPY=131072`).** The pinned
   `memcpy()` is capped at 131072 bytes by a synthetic collaborator that still
   logs the requested (wrapped) length. Both vulnerable branches then write
   the attacker-chosen pattern at offsets 16, 32, 64, 4096 and 65536 past
   `attr->data` (`match=1`). This is instrumentation showing what the
   attacker-controlled source bytes would write if the copy were bounded; it
   is NOT an observation of real libc behavior and is labeled INSTRUMENTED
   in the brief.

## Replay

`./run.sh` cleans `build/` and `out/`, verifies every pin hash and source line,
regenerates both variants, builds plain/ASan/bounded binaries, runs 18 cases
and writes `out/trace.txt`. Pointer and fault-address values are normalized to
`ADDR` in the trace so replays are byte-identical.

Working-tree replay 2026-11-21, 3 consecutive runs at commit `cda059a`:
**54 PASS / 0 FAIL**, raw trace
`sha256=57cd8943825f35a14f45ce134f3987c489aacbd080c6249a94c9dc808f1f3d6a`.
Two clean `git archive HEAD` extractions at `cda059a` into separate absolute
directories gave the same 54 PASS / 0 FAIL and the same raw trace hash,
byte-identical to each other and to the working tree.

## Failed hypotheses / repairs (preserved)

- Initial ASan check expected the pinned caller at `:260` (the `memcpy`);
  ASan actually stops one statement earlier at `:258` (`attr->len = data.len`)
  because `malloc(14)` / `malloc(12)` is smaller than `sizeof(attr_t) == 16`.
  Checks and brief were corrected to `:258`; the huge `memcpy` at `:260`
  remains the advisory's primary sink.
- The plain-build SIGSEGV handler initially lost all buffered stdout; added
  `setvbuf(_IONBF)` and `fflush()` before `_exit`.
- The destination pointer was initially captured in `insert_stub()`, which is
  never reached because the copy faults first; moved capture into
  `__wrap_malloc()` with `offsetof(struct attr_t, data)`.
- First bounded run produced no `CHOSEN` lines because the capped copy does
  not fault; added a post-copy inspection block guarded by `BOUNDED_COPY`.
- RAND requested length is `0 - 4 = 18446744073709551612`, not `...613`.
