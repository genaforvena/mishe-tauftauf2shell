# wazuh2shell — live-daemon heap adjacency at the CVE-2026-74045 sink

Status (2026-11-22, wake W108): the chosen-byte/heap-metadata write is now
observed in a live plain (non-ASan) `wazuh-analysisd`, not only in frontier's
in-process harness. The physically adjacent chunks in this configuration are
the decode thread's small **character arrays** (`agent_id`, `location`,
`hostname`), not pointer-bearing objects. No pointer consumer was reached; the
groomed-heap lane remains UNMEASURED. Rung 5 is not claimed.

## Method

- Built a plain v4.14.7 `wazuh-analysisd` from the pinned tree
  (`a42268a27c555d9348d5598fb8751eaf4c8e9024`) with only the two previously
  ASan-instrumented objects recompiled without ASan (`CFLAGS="-g -O0"`,
  `DEBUG=1`); verified `nm -D wazuh-analysisd | grep -c __asan` = 0. The
  original ASan build was preserved in `live-src/` for witness replay.
- Ran that binary under `gdb -batch`, breaking at `syscheck.c:1680` (before the
  overflowing `snprintf`) and `syscheck.c:1706` (immediately after it). The
  breakpoint commands print `lf->full_log`, its glibc chunk size word, and the
  bytes/words from `full_log+400` to `full_log+600`.
- Drove the exact advisory JSON into the real analysisd input queue with the
  W105 `inject.py` datagram (`8:[001] (lab-agent) 127.0.0.1->syscheck:<json>`).
  No 1514 session in this experiment; the wire leg is already established in
  `reports/wazuh2shell-1514-wire.md`.
- Controls: the 406-byte full-`old_attributes` JSON (safe input) was run
  through the same `before` and `after` breakpoints.

Logs: `lab/frontier/wazuh2shell/readback-plain-{exploit,control}{,-before}.gdb.log`.
Scripts: `live-src-plain/{readback,before}.gdb`, `run-readback.sh` (gitignored
lab tree).

## Observed heap layout and overflow (exploit input)

`full_log = 0x7fffdc002600`; own chunk size word at `F-8` = `0x1e5`, i.e. a
480-byte chunk (usable 472) for the 459-byte `malloc(2*loglen+1)` request.
The generated alert is 505 characters plus NUL = **506 bytes**, overrunning the
459-byte request by 47 bytes and the chunk's usable space by 34.

Before the sink (`before.gdb`), the physically following chunks are:

| offset | glibc field | before value | identity |
| --- | --- | --- | --- |
| `F+464` | chunk A `prev_size` | `0` | — |
| `F+472` | chunk A `size` | `0x25` (0x20 chunk + flags) | 32-byte chunk |
| `F+480` | chunk A user | `"001\0"` | `lf->agent_id` |
| `F+496` | chunk B `prev_size` | `0` | — |
| `F+504` | chunk B `size` | `0x35` (0x30 chunk + flags) | 48-byte chunk |
| `F+512` | chunk B user | `"(lab-agent) 127.0.0.1->syscheck\0"` | `lf->location` |
| `F+544` | chunk C `size` | `0x35` | 48-byte chunk |
| `F+560` | chunk C user | `"lab-agent\0 127.0.0.1->syscheck\0"` | `lf->hostname` |

After the sink, bytes `F+400..505` are the generated alert; the overflow
region is `F+459..505`:

- `F+461` = `0x51` (`Q`), the attacker's `hash_sha256` value — still *inside*
  `full_log`'s own 472-byte usable space, not in an adjacent chunk.
- `F+472..479` (chunk A `size`) = ASCII `"ibutes w"` =
  `0x7720736574756269`, an invalid huge size with `PREV_INUSE` set.
- `F+480..495` (chunk A user, the `agent_id` string) = `"ere: ''\nNow they"`.
- `F+496..503` (chunk B `prev_size`) = `" are 'a'"`; the `a` at `F+502` is the
  attacker's `"attributes":"a"` JSON value.
- `F+504..505` (first two bytes of chunk B `size`) = `0x0a 0x00`, making that
  size field `0x000000000000000a`.
- `F+506` onward is untouched: chunk B's user string and chunk C are intact.

The safe-input control (`poc-control.json`, 406 bytes → `malloc` chunk `0x345`,
824 usable bytes) produced a 74-character alert: no overrun, and the bytes past
the buffer are unchanged unrelated heap data.

## Source-side consumer analysis (independent read-only trace)

- After the `snprintf`, `fim_generate_alert` only calls `cJSON_Delete(tmp)` at
  `syscheck.c:1705` and returns; `full_log` is never freed, reallocated, copied
  or reinterpreted there. The v4.14.8 fix formats into a stack buffer, frees
  `full_log` and re-`os_strdup`s it, confirming the vulnerable aliasing.
- Downstream (`fim_process_alert`, `decode_fim_event`,
  `w_decode_syscheck_thread`, the process loop, `eventinfo.c`,
  `alerts/log.c`, `to_json.c`, `json_extended.c`, `prelude.c`) uses `full_log`
  only as a C string: save/restore pointer, `os_strdup`, `%s`, `strncpy`,
  `regexec`, `cJSON_AddStringToObject`, `free`. Nothing casts its bytes at a
  fixed offset to a pointer, length, or function pointer.
- Genuine pointer consumers do exist in the immediate post-overflow path —
  `cJSON_Delete(root_json)` at `syscheck.c:1306`,
  `cJSON_DeleteItemFromObject`/`cJSON_PrintUnformatted` at `:1452-1461`, and
  `cJSON_Delete(tmp)` at `:1705` — each walking `next`/`child`/`valuestring`
  pointers in 64-byte `cJSON` nodes (`external/cJSON/cJSON.c:258-270`). Those
  nodes are allocated by `cJSON_Parse(lf->log)` at `:1278`, i.e. *after* the
  small `agent_id`/`location`/`hostname` chunks that physically follow
  `full_log`; with this payload they are **not** the immediate neighbours, so
  the overflow does not reach their pointers.
- `full_log` reaches only ~506 bytes with this PoC because each `change_*`
  buffer is bounded (`change_win_attributes` is `OS_SIZE_256+1`), so a longer
  attacker string does not simply extend the write: it also lengthens the
  input and hence `malloc(2*loglen+1)`. Whether a groomed input can place a
  pointer-bearing chunk directly after `full_log` and land attacker bytes in
  its `next`/`child` fields is **UNKNOWN**, not measured here.

## Boundary

- Upgraded: chosen bytes and corrupted chunk metadata are now observed in a
  live daemon (plain build), not only a synthetic harness. The adjacent chunks
  are char arrays; two chunk size fields are rendered invalid.
- Not reached: no attacker-controlled byte lands in a pointer, no cJSON node
  pointer is overwritten, no tcache poisoning, no control flow, no marker, no
  command, no benign side effect, no witness replay of this experiment.
- A plain (non-ASan) daemon did not reliably crash in prior W105 observation;
  this readback does not change that availability verdict.
- Rung 5 remains UNKNOWN and is not claimed. The honest grade is rung 4 in a
  live process with a structural negative for the direct pointer-consumer lane
  and an unmeasured groomed-heap lane.
