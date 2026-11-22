# pgpool2shell — adjacent lane W7: CVE-2026-92869 peer config JSON OOB write

Date: 2026-11-22 ~17:26–17:3xZ. Operator DM #1462 directed: do not retire;
mine one adjacent same-target lane under the same evidence ladder. This is a
**new, named lane**, not a continuation of the six closed CVE-2026-92867
address-steering lanes (see the main status report and the W3/W4/W6 negatives).

## Claim and fix provenance

- Upstream primary source: [Release 4.7.3 notes](https://www.pgpool.net/docs/4.7/en/html/release-4-7-3.html)
  list CVE-2026-92869 alongside CVE-2026-92867: watchdog "configuration
  information received from watchdog peers" parses `backend_desc` and
  `wd_nodes` JSON arrays with insufficient upper-bound checks; crafted peer
  messages may crash the process or corrupt memory. Reported by Emond
  Papegaaij; affected 3.5–4.2, 4.3.0–4.3.20, 4.4.0–4.4.17, 4.5.0–4.5.12,
  4.6.0–4.6.7, 4.7.0–4.7.2; fixed 4.3.21/4.4.18/4.5.13/4.6.8/4.7.3.
- Pins already verified on this plant: 4.7.2
  `e72b9d0ff3620f7da7e33a58dda44b77919d056752dc9bd86b2985c4988d1938`, 4.7.3
  `4bf9df3e13feb8e64bee486b4ea54c9076296c2d9406165b0b68d32086fce250`
  (`lab/frontier/pgpool2shell/src/SHA256SUMS`, 2/2 locally verified).
- Pinned-source diff of
  `src/watchdog/wd_json_data.c` shows the 4.7.3 fix adds `parse_peer_count()`:
  `backend_desc` length capped at `MAX_NUM_BACKENDS` (128,
  `include/pcp/libpcp_ext.h:57`), `wd_nodes` length capped at
  `MAX_WATCHDOG_NUM` (128, `include/pool_config.h:39`), plus a
  `node_count > MAX_NUM_BACKENDS` check before the 92867 loop and
  `strncpy` → `strlcpy` for the hostname. This lane measures the
  `backend_desc` bound: in 4.7.2, `num_backends` is copied straight from the
  peer JSON and the loop at `wd_json_data.c:130-142` writes
  `backend_info[i].backend_port` and `.backend_hostname` past the fixed
  128-element array in the separately palloc'd `BackendDesc`.

## Measured evidence

All binaries are the plant's pinned builds (`-g -O0 -fno-omit-frame-pointer`;
ASan builds from the same hash-verified tarballs with
`-fsanitize=address`). Replay assets: `lab/pgpool2shell/config/`
(`harness.c`, `run-harness.sh`, `peer.py`, `gen_config_json.py`, `run.sh`,
`gdb-run.sh`, `gdb-w7.cmd`, `gdb-write.cmd`, `pgpool-w7.conf`, evidence files,
`EVIDENCE_HASHES.txt` with PID/address/path-normalized SHA-256).

### Direct call on the real parser object (A–G)

| Case | Build / input | Observed |
|---|---|---|
| A | 4.7.2 plain, `backend_desc` N=128 | `num_backends=128`, rc 0 |
| B | 4.7.2 plain, N=129, chosen `0x42424242` | `free(): invalid size`, rc 134 (heap corrupted) |
| C | 4.7.3 plain, N=129 | `ERROR: invalid watchdog JSON payload`, rc 0 |
| D | 4.7.2 ASan, N=128 | clean, rc 0 (leak detection off: harness does not free the returned config) |
| E | 4.7.2 ASan, N=129 | `AddressSanitizer: heap-buffer-overflow`, **WRITE of size 4** at `utils/json.c:1189` called from `wd_json_data.c:136`; address is 256 bytes after the 113672-byte `BackendDesc` allocation (`palloc0` at `wd_json_data.c:44`); rc 1 |
| F | 4.7.3 ASan, N=129 | clean rejection, rc 0 |
| G | 4.7.2 plain under gdb, N=129 | at `i=128`: `&config->backend_desc->backend_info[128].backend_port = 0x555555586038`, `x/wx` = `0x42424242`, `num_backends=129` |

E is confirmed memory corruption (rung 3): the store is through the parser's
own pointer, not a harness write. G is a chosen-value write at a chosen offset
on the real parser object (rung 4 at direct-call scope).

### Wire reach on a real plant-started daemon (A–C + live gdb)

`peer.py` binds only 127.0.0.1:19005, accepts the daemon's watchdog connection,
and sends one `WD_POOL_CONFIG_DATA` packet (type `Z`, `watchdog.c:137`) with a
peer-generated config JSON. The runner refuses to start if 19003–19006 are
busy and kills only PIDs it started.

| Case | Build / input | Observed |
|---|---|---|
| A | 4.7.2, N=128 | `received packet ... type:[CONFIG DATA] state:[LEADER]`, no fault |
| B | 4.7.2, N=129 | same packet reception, then `watchdog child ... was terminated by segmentation fault` and `watchdog is recovering from the crash` |
| C | 4.7.3, N=129 | packet received, `ERROR: invalid watchdog JSON payload`, no fault |

Live gdb on the 4.7.2 watchdog child (`gdb-run.sh`, `gdb-w7.out`) confirms the
wire path and the write: breakpoint `wd_json_data.c:138 if i == 128` hit with
`$1 = 128`, `$2 = 129`, destination `0x55555591dbe0`, `x/wx` =
`0x42424242`, and backtrace
`get_pool_config_from_json` ← `standard_packet_processor` (`watchdog.c:4472`)
← `watchdog_state_machine_coordinator` (`watchdog.c:6638`) ← `watchdog_main`.
Continuing gives SIGSEGV at `json_value_free_ex` (`utils/json.c:1079`) with
`value=0x555542424242`: the faulting pointer's low 32 bits equal the peer's
chosen `0x42424242`. Exact identity of the clobbered pointer field is
**UNKNOWN**; the observation is consistent with the OOB store overwriting an
adjacent heap pointer, but no alias analysis or before/after object map proves
which one. Do not claim arbitrary-address steering from this alone: the write
offset is fixed by the array layout; the peer chooses the 32-bit value, not
the destination address.

**W8 addendum (2026-11-22 ~18:0xZ):** the UNKNOWN above is resolved on this
build by `reports/pgpool2shell-alias-w8.md`. Live gdb before/after mapping
identifies the slot as `json_object_entry.value` for the `backend_hostname`
key of a peer-supplied backend object (name length 16 at
`0x55555591dbd8`, value at `0x55555591dbe0`), and a second chosen value
`0x11111111` yields fault pointer `0x555511111111`, proving value→fault
causality. The destination stays layout-fixed and the pointer's upper 16
bits are inherited, so no address steering is established. The harness's
own `free(): invalid size` abort is value-independent (chosen `0` and
`0x11111111` abort identically); the W7 case-G readback of the chosen
store remains valid. Grade unchanged, witness replay of this lane still
owed.

## Grade

- Rung 3: confirmed memory corruption on the real parser (ASan WRITE) and on
  a real daemon reached by a single loopback peer packet (SIGSEGV).
- Rung 4: chosen `0x42424242` written at the OOB slot both in the direct-call
  harness and in the live daemon via wire input, with fixed-build and
  safe-input controls. Honest condition: `wd_authkey = ''` and a loopback peer
  that the daemon accepts as a configured watchdog node; PR:L equivalent.
- Rung 5: **not claimed**. No command, no side-effect marker, no witness
  replay of this new lane. The 92867 witness replay covers only that lane.
- Open, unresolved: whether any peer-controlled field can place the write at
  an attacker-selected address rather than a layout-fixed slot; whether the
  faulting `0x555542424242` pointer is a specific parser object; `wd_nodes`
  OOB path is source-confirmed but unmeasured; no test with `wd_authkey` set.

## Replay

    cd lab/pgpool2shell/config
    bash run-harness.sh          # cases A–G, writes evidence-*.txt and hashes
    bash run.sh                  # loopback wire A/B/C (~70 s)
    bash gdb-run.sh              # live daemon gdb readback (~15 s)

Everything above was exercised on this host; no non-loopback probe, no other
plant or node. The old W6 steering negatives remain closed and were not
retried.
