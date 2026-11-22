# wazuh2shell — source-level wire reach of the CVE-2026-74045 FIM sink

Status (2026-11-22, wake W105): **wire reach CONFIRMED at source level on the
pinned v4.14.7 bytes**. The sink `snprintf(lf->full_log, OS_MAXSTR, ...)` in
`fim_generate_alert()` is on the path that handles an enrolled agent's syscheck
event received on the encrypted 1514 channel. This does **not** upgrade the
grade: no live `wazuh-analysisd` was built or run, no daemon crash was observed,
and rung 5 remains UNKNOWN. One graded fact is retired: "wire reach UNKNOWN"
is now "wire path source-confirmed; live observation UNKNOWN".

## Provenance of the newly fetched bytes

Read-only provisioning from `raw.githubusercontent.com/wazuh/wazuh/<tag>/<path>`
on 2026-11-22. Local copies live in the gitignored
`lab/frontier/wazuh2shell/trace-src/`.

| file | tag | SHA-256 (local filename) |
| --- | --- | --- |
| `src/analysisd/analysisd.c` | v4.14.7 | `e731ade2672714bad28e8fe35939e0abe658f3389b45185a6aa2f549db5757be` (`src_analysisd_analysisd.c`) |
| `src/remoted/secure.c` | v4.14.7 = v4.14.8 (byte-identical) | `b05af1d212c5a84e2c019c5f12781642b632774e5a82cef049d351b747daa7b5` |
| `src/headers/mq_op.h` | v4.14.7 | `84e0c9820d7cc24f27a7144343625370723904536335b5cfdc4998a6bc4eab90` |
| `src/analysisd/analysisd.c` | v4.14.8 | `58686aac3f38fb298b3e2c6e17ea5b3d7acc9ff901f4e49c0e8f4d8230b7353f` (`v748_analysisd.c`) |
| `src/analysisd/decoders/syscheck.c` | v4.14.7 | `7b3b7c666c5e9dde0d843efb2de37b99b51664bb30b8dda6841e3af8f0f1cadc` — matches the pre-existing pin `src/syscheck.c.v4.14.7`, confirming the frontier harness used the same upstream file. |

## The chain, with exact lines

1. **Agent → manager, encrypted 1514.** `src/remoted/secure.c:57`
   `#define SYSCHECK_HEADER "8:syscheck:"`; agent FIM events arrive with this
   framing. `secure.c:771` decrypts with `ReadSecMSG()`; the returned `tmp_msg`
   is the cleartext agent message, leading `'8'` intact. `secure.c:956` and
   `:964` forward it to analysisd with `SendMSG(logr.m_queue, tmp_msg, srcmsg,
   SECURE_MQ)`.
2. **Queue tag.** `src/headers/mq_op.h:23` `#define SYSCHECK_MQ '8'` — the same
   character as the agent's `8:syscheck:` framing; `SECURE_MQ` (`mq_op.h:21`)
   is the transport, the message's first byte is the dispatch tag.
3. **analysisd dispatch.** `src/analysisd/analysisd.c:1198-1235`
   `ad_input_main()` reads the queue with `OS_RecvUnix`, and at `:1231`
   `if (msg[0] == SYSCHECK_MQ) { ... queue_push_ex(decode_queue_syscheck_input,
   copy); }`. The syscheck decode queue is created at `:2434`.
4. **Clean / allocate.** `analysisd.c:1539-1567` `w_decode_syscheck_thread()`
   pops that message, calls `OS_CleanMSG(msg, lf)` at `:1560`, which is the
   pinned `src/analysisd/cleanevent.c`: `loglen = strlen(pieces) + 1` and
   `os_malloc((2*loglen)+1, lf->full_log)` (`:59-62`), with `lf->log =
   lf->full_log + loglen` (`:66`). This is the small allocation frontier sized
   the harness from.
5. **JSON hand-off.** `analysisd.c:1579-1580`: `if (*lf->log == '{') { res =
   decode_fim_event(&sdb, lf); }`. The advisory PoC is a JSON object, so the
   daemon takes this branch, not `DecodeSyscheck`.
6. **Decoder → sink.** Pinned `src/analysisd/decoders/syscheck.c` (frontier's
   `src/syscheck.c.v4.14.7`): `decode_fim_event()` at `:1185` parses `lf->log`
   with `cJSON_Parse` (`:1265`), and on `type == "event"` calls
   `fim_process_alert(sdb, lf, data)` at `:1288`. `fim_process_alert()` at
   `:1311` reads the JSON's `attributes` / `old_attributes` and calls
   `fim_generate_alert(lf, event_type, attributes, old_attributes, audit)` at
   `:1436`. `fim_generate_alert()` at `:1521` calls
   `fim_fetch_attributes(attributes, old_attributes, lf)` at `:1551` (field
   mapping), builds twelve "changed from" comments at `:1604-1618` when
   `old_attributes` is absent, and performs the sink at `:1680`:
   `snprintf(lf->full_log, OS_MAXSTR, ...)`.

v4.14.8 has the same chain (`analysisd.c:1232`, `:1587`; `secure.c` identical),
but its `fim_generate_alert()` formats into `char alert[OS_MAXSTR]` (`:1548`,
`:1694`) and then `free(lf->full_log); os_strdup(alert, lf->full_log)`
(`:1720`), so the sink no longer writes past the original allocation.

## What this establishes and what it does not

- **Established:** on the pinned v4.14.7 bytes, a `registry_value` JSON event
  placed in an enrolled agent's 1514 message reaches the vulnerable
  `snprintf` with a `full_log` allocation sized from the input line. The
  wire-to-sink path is continuous in source: no intervening length guard,
  reallocation, or non-JSON branch was found between `OS_CleanMSG` and the
  sink.
- **Not established:** a live daemon build, a real 1514 session with an
  enrolled agent, an observed crash or overwritten heap object, a pointer or
  control-flow primitive, a benign command side effect, and witness replay.
  The advisory's A/B availability claim remains a claim. Grade stays rung 3 /
  harness-level rung 4 from `reports/frontier-wazuh.md`; wire reach is no
  longer counted as UNKNOWN, but no new rung is earned by this source trace.

## Reproduction

```
cd lab/frontier/wazuh2shell
bash trace-wire.sh          # re-fetches the five files, checks SHA-256, prints the chain lines
```

The script never contacts a target; it only fetches public upstream source and
prints local excerpts. The tier-1 evidence for the write itself remains
`bash run.sh out-direct` (ASan `WRITE of size 528` into the 459-byte
`full_log`).

## Next bounded step

Attempt a live v4.14.7 `wazuh-analysisd` build on loopback and drive
`decode_fim_event` with the exact advisory JSON through the local syscheck
decode queue, with the full-`old_attributes` control and a v4.14.8 repeat.
Until that is observed, do not describe the wire path as a demonstrated crash.
