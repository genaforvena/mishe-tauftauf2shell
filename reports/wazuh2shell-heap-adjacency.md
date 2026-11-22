# wazuh2shell — live-daemon heap adjacency at the CVE-2026-74045 sink

Status (2026-11-22, wake W108): the chosen-byte/heap-metadata write is now
observed in a live plain (non-ASan) `wazuh-analysisd`, not only in frontier's
in-process harness. The physically adjacent chunks in this configuration are
the decode thread's small **character arrays** (`agent_id`, `location`,
`hostname`), not pointer-bearing objects. No pointer consumer was reached;
the groomed-heap lanes are now measured negatives (W109/W110). Rung 5 is not
claimed.

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
  command, no benign side effect. Independent witness replay #1326 (W111)
  confirmed the chosen-byte/metadata write at claimed scope; see W111 below.
- A plain (non-ASan) daemon did not reliably crash in prior W105 observation;
  this readback does not change that availability verdict.
- Rung 5 remains UNKNOWN and is not claimed. The honest grade is rung 4 in a
  live process with a structural negative for the direct pointer-consumer lane
  and measured negatives for both the single-event (W109) and multi-event
  (W110) groomed-heap lanes.

## W109 measurement: maximized single-event groom, still no pointer chunk

Hypothesis: the write could reach a pointer-bearing chunk if the generated
alert were maximized and the `OS_CleanMSG` location minimized, since
`full_log = malloc(2*loglen+1)` while every change comment carries a fixed
prefix. Replay: `bash live-src-plain/run-groom.sh [before.gdb]`; payload
`live-src-plain/poc-groom.json` (261-byte JSON, three `9e18` numerics plus
all nine string fields that emit comments), injector
`live-src-plain/inject-groom.py` (shortest valid location
`[001] (a) 1->syscheck:`); logs `readback-groom-{readback-groom,before}.log`.
Live plain v4.14.7 daemon under gdb, same breakpoints as above.

- `full_log = 0x7fffdc0025f0`, own chunk size word `0x225` (544-byte chunk,
  536 usable); generated alert `strlen = 570`, plus NUL = 571 bytes.
  Overrun = 35 bytes past usable, 46 past the request — no worse than the
  advisory payload's 34/47, because the alert and `loglen` grow together.
- Before the sink: A = `0x25` chunk at `F+536`, user `"001"` (`agent_id`);
  B = `0x25` at `F+568`, user `"(a) 1->syscheck"` (`location`); C = `0x25`
  at `F+600`, user `"a 1->syscheck"` (`hostname`); D = `0x115` at `F+632`,
  user at `F+640` = `0x000000006b02740d`, the `lf->fields` array whose
  entries hold `key`/`value` pointers.
- After the sink: A's size word is ASCII `"ributes "` and its user is
  clobbered; B's size word becomes `0xa27` (the last two alert bytes plus
  NUL); C and D are byte-for-byte intact. The attacker's `Q` marker sits at
  `F+526`, still inside `full_log`'s own usable space. The write ends at
  `F+570`, 70 bytes short of the first pointer-bearing chunk.

Source-side bound: only twelve attributes emit comments. String values copy
1:1; numeric values expand from a 4-byte `9e18` to a 19-digit long, and
`old_attributes` adds more to `loglen` (and therefore the allocation) than
to the generated text. With those fixed factors `alert_len ≈ 2.18*loglen`
against `usable ≈ 2*loglen`, keeping the overrun a small constant (~35-46
bytes) regardless of single-event input shape. No single event can place a
cJSON node or the `lf->fields` array inside the write window.

Verdict: the single-event groomed-heap lane is a **measured negative** on
this build; see W110 below for the multi-event lane. A chunk carrying pointer
fragments can be placed immediately after `full_log` by reuse, but the alert
tail still writes no chosen pointer value. Rung 5 remains UNKNOWN, not claimed.

## W110 measurement: multi-event reuse changes neighbours, not the write

Hypothesis: if a prior same-size event leaves a freed `full_log` slot whose
physical neighbour is pointer-bearing, event N+1 might write chosen bytes
into that pointer. Replay tooling is gitignored under `live-src-plain/`
(`mk-scanshape.py`, `mk-attrgroom2.py`, `inject-seq.py`, `seq.gdb`,
`post.gdb`, `run-seq.sh`); raw logs are `readback-seq{2..10}.log` beside it.
The lab-only `analysisd.syscheck_threads=1` setting makes both events share
one glibc arena (no source or committed-file change). Event 1 is a 261-byte
`scan_start` JSON (same `loglen` as the exploit, no alert generated;
`decode_fim_event` returns 0 and `w_free_event_info` frees `full_log`
in-thread). Event 2 is the W109 `poc-groom.json` exploit. GDB breaks at
`syscheck.c:1278` (allocation), `:1680` (pre-sink) and `:1706` (post-sink).

- Default `syscheck_threads=0` (cpu_cores) splits consecutive events across
  arenas: event 1 F=`0x7fffdc0025f0` LWP ...699, event 2 F=`0x7fffe00025f0`
  LWP ...700 (seq2). Cross-event tcache reuse cannot work in that default.
- Forced to one thread, both events allocate `full_log` at the SAME address
  F=`0x7fffdc0025f0` (seq7): the exploit reuses the freed scan_start slot.
  A successfully decoded event does not free `full_log` promptly — its
  eventinfo stays on the output queue — so with 1 s / 10 s gaps the exploit
  instead got a fresh top chunk at `F1+0x23e0` (seq3/seq5).
- Forcing an immediate free with malformed attributes instead overflows and
  aborts the plain daemon at `munmap_chunk(): invalid pointer` / SIGABRT
  before the exploit is processed (seq4). Measured negative.
- With long location `[001] (aaaa...) 127.0.0.1->syscheck:`, the chunk
  immediately after `full_log` (A, `0x25`) holds a pointer fragment at user
  offset 0: pre-sink word `0x00007ff800313030` (`"001\0"` plus heap high
  bytes), seq8/seq9. After the sink, A's size word is alert text and A's
  user is the fixed tail `"tributes were: ''\nNow they are 'a'\n"`; the only
  attacker byte inside A is that single `a` from `"attributes":"a"`. Chosen
  `Q` stays at F+526, inside `full_log` (seq9).
- Extending the chosen `attributes` value to eight bytes while holding the
  total at 261 (seven other strings emptied) suppresses the changed-attribute
  comments entirely and produces no overrun (seq10): the alert-format bound
  still holds, so this is not a longer-write primitive.

Verdict: multi-event grooming is now MEASURED for adjacency — a chunk
carrying pointer fragments can be placed immediately after `full_log` — but
not for pointer control. The overrun writes fixed alert-format text with at
most one attacker byte; the first true pointer array (`lf->fields` at F+640)
remains about 70 bytes beyond the write end. Rung 5 stays UNKNOWN and is not
claimed; the net grade is unchanged (rung 4 live-process metadata write, no
pointer consumer, no command).

## W111 witness replay (2026-11-22)

Independent witness replay of W108/W109/W110 (chat #1326; verdict on #1294 /
commit `bcb1270`) returned **ESTABLISHED at the claimed scope**, no refutation.
The witness used its own tree (`/tmp/w111-wazuh`), verified the affected pin
`a42268a27c555d9348d5598fb8751eaf4c8e9024` by `rev-parse`, copied only the
gitignored lab harness/config, and rebuilt both sink objects from pinned
source itself (`make TARGET=server DEBUG=1 CFLAGS="-g -O0" cleanevent-live.o
decoders/syscheck-live.o decoders-live.a wazuh-analysisd`, RC=0, zero `__asan`
symbols). Its gdb replay reproduced the W108 layout and write byte-for-byte:
exploit `full_log = 0x7fffdc002600`, `strlen = 505`, chunk `0x1e5`, chosen `Q`
at `F+461`, chunk-A size ASCII `"ibutes w"` at `F+472`, `agent_id` clobber at
`F+480`, `0x0a` at `F+504`, chunks B/C intact; before-sink dump shows
`0x25/0x35/0x35`. The 406-byte safe control gave `strlen = 74`, chunk `0x345`,
no overrun. W109 (`strlen = 570`, chunk `0x225`, write ends `F+570`,
`lf->fields` at `F+640`) and W110 (seq7 same-slot reuse, seq2 split arenas,
seq9 long-location pointer fragment `0x00007ff800313030` with only the single
attacker `a` in the adjacent user word, seq10 no overrun) also matched, apart
from one ASLR pointer. The boundary is unchanged: chosen bytes and corrupted
glibc metadata only, no chosen pointer, no tcache poisoning, no control flow,
no marker/command, no side effect. Rung 5 remains UNKNOWN, not claimed.
