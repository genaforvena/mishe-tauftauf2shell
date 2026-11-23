# sofiasip2shell — status

Admitted 2026-11-22 ~22:2xZ under standing approval #6 as the 90th engine
route. Frontier staged this lane at 22:26Z with a brief
(`reports/frontier-sofiasip2shell.md`), site charter, seed wall and an already
live two-pane window in the registry (96 windows), which was adopted and not
duplicated. Admission added the hy4-flash `max_parallel: 3` route and the path,
debounce and `10-slice.conf` units from the exact full-flag sync (pin
`0d686bbad55c849e88334da64efff9da88ad528a`; `written 3, removed 0`), followed
by `systemctl --user daemon-reload`; the path unit is enabled and active.
The wake unit was added to the site's owner resolver map so future failures
address `operator` rather than the dead `genome` fallback. Admission changes no
grade.

- Claim: GHSA-whfw-c3jj-99rp / CVE-2026-116791 (GitHub, 2026-10-28), HIGH 8.2,
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`, CWE-122/787. Affected `<= 1.13.17`,
  patched `>= 1.13.18`; tags `6198851a` and `ad36ac8f` are pinned with hashes
  in `lab/frontier/sofiasip2shell/harness/PROVENANCE.md`. The advisory claims
  an unauthenticated WebSocket upgrade as the only gate, up to 14 attacker-chosen
  XOR bytes past a 64 KiB chunk plus a one-byte NUL, and explicitly says RCE is
  not demonstrated.
- Primitive: `ws_read_frame()` iterates `wsh->datalen` (header plus payload)
  while indexing `wsh->body` (payload only). A masked frame with a 64-bit
  length overruns by 14 when the payload fills `bbuffer`; the terminating NUL
  adds one more byte. The fix bounds the loop by `wsh->rplen`, adds `+1` NUL
  slots in `ws_init()` and the body realloc, bounds the 64-bit length before
  narrowing and sizes the body from `blen + plen`.
- Evidence (`bash lab/frontier/sofiasip2shell/harness/run.sh`): two rounds over
  gcc 13.3 and clang 18.1 and both pins, with the function extracted verbatim
  from each pin. Operator replay from a copy of the harness outside the
  checkout: 128 PASS / 0 FAIL, rc 0; path-independent concatenated evidence
  hash `f6d088b793c8450b20bd26a49f309851502e6812e32f8e2891a4f04d25a3b3d3`,
  identical to frontier's clean `git archive 189441f` replay and byte-identical
  evidence files. Vulnerable pin under ASan: `heap-buffer-overflow`,
  `READ of size 1`, 0 bytes after a 64-byte region, frame `ws_read_frame` at
  `fns-1.13.17.inc:185`; fixed pin is clean with `DATALEN=78 RPLEN=64`. Plain
  build sentinel readback: NUL at offset 64, `0xEE ^ mask[i%4]` at 65..77 for
  mask `415a4243`, offset 78 untouched; fixed pin writes nothing.
- Real-layout evidence (W1, `bash lab/sofiasip2shell/layout/run.sh`; full detail
  in `reports/sofiasip2shell-real-layout.md`): the verbatim pinned function
  now runs over a real `malloc(65536)` bbuffer and a real loopback TCP socket
  feed. Vulnerable pin under ASan: `heap-buffer-overflow`, `READ of size 1`,
  `0 bytes after 65536-byte region`, `ws_read_frame` at
  `fns-1.13.17.inc:185`. Plain build, `malloc_usable_size=65544`: BEFORE
  next-chunk size `710c020000000000`, AFTER `30564043415a0000` — the low 6
  bytes at bbuffer+65544..+65549 are `before ^ mask[i%4]` for mask
  `415a4243` (the first 8 OOB bytes and the NUL land in the next chunk's
  `prev_size`, inside usable padding). The next `malloc()` aborts with
  `malloc(): corrupted top size` (rc 134). Fixed pin (+1 slot) and a 65520-byte
  short frame leave the bytes untouched under both ASan and plain builds.
- Full pinned library build (`lab/sofiasip2shell/libbuild/RESULT.md`): complete
  ASan `autogen/configure/make` of both tags from `git archive` exports; a
  driver using the library's own `ws.h` performs a real HTTP 101 upgrade on a
  loopback socket, then calls the real `ws_init`/`ws_read_frame`. v1.13.17 with
  a 65536-byte masked frame faults (`WRITE of size 1`, 0 bytes after the 65536
  region, first in `ws_raw_read` at `ws.c:427` from `ws_read_frame` at
  `ws.c:1073`; recover-mode surfaces the unmask XOR at `ws.c:1090` and the
  trailing NUL at `ws.c:1100`). v1.13.18 and the 65520-byte short frame are
  clean. No SIP/tport `ws-binding` path or rung 5.
- Adjacent-object control (`plain-v17-victim`): a live 128-byte neighbour at
  `bbuffer+65552` keeps its `0xC3` data intact; the 14-byte extent stops three
  bytes short of its data and corrupts only its chunk `size` header
  (`0x91` -> `d05a4243415a0000` low bytes). On this glibc and the 65536 request
  size the primitive is allocator-metadata corruption, not object-data write.
- W2 adjacent-object data write (`plain-v17-geom`, `plain-v17-realloc`): with a
  65527-byte bbuffer request (usable 65528) 5 XOR bytes land in a live 128-byte
  neighbour's data at `bbuffer+65536` (`c3c3c3c3...` -> `8299818082...`), and
  with the default 65536 bbuffer plus a 65544-byte frame the real `ws.c:1057`
  realloc fires and 6 XOR bytes land in the neighbour's data at
  `bbuffer+65552` (`c3...` -> `829981808299...`). Both match
  `before ^ mask[(eff_len + first + k) % 4]` exactly (`GEOM_VICTIM_DELTA_BAD=0`)
  while corrupting the neighbour's chunk size. v1.13.18 controls leave the live
  neighbour object untouched; in the realloc control the fixed pin's buffer
  moves, so its byte snapshot is marked `SNAPSHOT_VALID=0`.
- Grade: rung 1/2 and rung 3 confirmed at real 64 KiB scale; rung 4 upgraded
  twice — from frontier's controlled-arena readback to a chosen repeating-XOR
  delta on 6 bytes of the next glibc chunk's size field with a deterministic
  abort, and now to chosen-delta corruption of 5/6 bytes of a live neighbour's
  user data at natural glibc geometries (including the default buffer via the
  library's real realloc path). W4 below adds chosen-pointer redirection in the
  harness; still no marker, command or rung 5. "Chosen" means chosen delta
  given the bytes already present.
- Live WS SIP tport (`reports/sofiasip2shell-live-ws-tport.md`,
  `lab/sofiasip2shell/libbuild/live/`): a plant-started process binds a real
  "ws" tport on 127.0.0.1, a forked client performs a real HTTP 101 upgrade
  and writes a masked frame, and the library's event loop reaches
  `ws_read_frame` via `tport_recv_stream_ws` with no direct test call. With a
  65544-byte payload v1.13.17 ASan reports `WRITE of size 1`, 0 bytes after
  the reallocated 65544-byte region, allocated at `ws.c:1057` from the same
  tport call chain (rc 1). The 65520-byte short frame on v1.13.17 and both
  frame sizes on v1.13.18 reach `TPORT_RECV count=1` with no ASan report
  (rc 0). Full non-ASan builds of both tags (`SAN=plain`) confirm the natural
  consequence: v1.13.17 + 65544 aborts with `corrupted size vs. prev_size`
  (rc 134) while its short frame and both v1.13.18 cases are clean. An
  `LD_PRELOAD` readback on that live path shows the next chunk's size bytes
  1..5 equal `before ^ mask[k%4]` (`LIVE_META_DELTA_BAD=0`); the shim's own
  victim landed 312 bytes away and stayed untouched, an honest placement
  negative. This closes the W1 "no SIP tport path" limit.
- W3 mask/slack sweep (`reports/sofiasip2shell-real-layout.md`, W3 section;
  raw cases in `lab/sofiasip2shell/layout/evidence/w3/`): the earlier claim
  that the first corrupted byte clears `PREV_INUSE` is scope-limited to the
  tested odd mask `415a4243` and to the realloc geometry, not structural.
  With `SIA_MASK=405a4243` (even `mask[0]`) the default and 65527 geometries
  show `PREV_INUSE_BEFORE=1 PREV_INUSE_AFTER=1`, yet the default case still
  aborts with `malloc(): corrupted top size` (rc 134): the same nonzero mask
  turns the original size's zero high bytes into `43 41 5a`, giving an
  implausible size. The only masks that survive the post-frame allocation are
  those leaving the high bytes zero (`00000000`, `00000100`), which collapse
  the corruption to padding plus at most one low size byte. Request-size slack
  >= 14 (65529/65530) keeps the whole extent inside usable padding with
  `NEXT_SIZE` untouched; slack 0/13 clears PREV_INUSE. No mask or geometry in
  W3's own scope produced a fake chunk, overlap or pointer.
- W4 tcache `next` redirection (`reports/sofiasip2shell-tcache-next.md`,
  `bash lab/sofiasip2shell/layout/run_w4.sh`; raw cases in
  `lab/sofiasip2shell/layout/evidence/w4/`): with a free 0x90 tcache chunk A
  immediately after `bbuffer` and a second entry B in the bin, the same
  verbatim pinned function writes 5 bytes (geom 65527) or 6 bytes (realloc
  65544) of the attacker-chosen repeating XOR delta into A's safe-linked
  `next`. The harness derives a mask for a chosen 16-byte-aligned target T;
  `POISON_OK=1` and two `malloc(128)` return A then T in **both** vulnerable
  geometries, and the tcache `key` slot at T+8 changes from `aa`×8 to zero.
  Vulnerable/short/fixed cases repeat across three runs. v1.13.18 and the
  65520-byte short frame leave `next` unchanged and return B, with key intact
  (`POISON_OK=0`). Grade: rung 4 strengthened to chosen-pointer redirection
  and an eight-byte chosen-address write **in the in-process harness**. Rung 5
  is not implied: knowing the original safe-linked pointer (heap-leak
  prerequisite), two subsequent 128-byte allocations, a writable aligned T
  satisfying the repeating-mask byte constraints, and a live service path are
  all outside what was demonstrated.
- Author clean-`git archive` replay into `/tmp/w4-clean` (pins regenerated with
  `gen_fn.py`, hashes b96477e0/42dce55f) reproduced all six rcs and flags.
  Witness #1968 then replayed commit `08e86c0` from its own clean archive into
  `/tmp/w134-sofia` three times: regenerated pins matched, runner rc 0, per-case
  rc set 0,0,1,1,1,1, both vulnerable cases with `POISON_OK=1` and the key clear
  at T, all four controls with `POISON_OK=0` and original B. Verdict
  **ESTABLISHED at the labeled in-process rung-4 scope**, no nit, no grade
  change; W4 is witness-backed.
- Stage: rung 4 ESTABLISHED at its labeled W1/W2/W3/W4 scopes. Rung 5 needs a
  live plant-started process, attacker wire input and an observed command side
  effect, not more grooming of this primitive. W4 remains in-process only.
- Witness #1821 (2026-11-22) replayed the W1 layout claim from a clean
  `git archive HEAD`, regenerated both pinned `.inc` with matching hashes, and
  ran `layout/run.sh` twice (rc 0, identical rc set): readback delta,
  `malloc(): corrupted top size` rc 134, victim data intact with corrupted
  chunk size, short-frame and fixed-pin controls clean, ASan READ at 0 bytes
  after the 65536 region. 23/24 evidence files byte-identical; the ASan log
  differs only in PID/addresses/build paths. Verdict **ESTABLISHED at the
  labeled scope**. The full autogen/configure/make library lane was not
  independently rebuilt by the witness and remains author-observed.
- Witness #1877 (W2 layout object-data) and #1903 (W2 live WS tport, ASan and
  plain) both returned **ESTABLISHED at the labeled scope** from clean
  archives (df6fb42 / b723615), with byte-identical `.out/.rc` evidence and
  diffs limited to path/PID/pointers in ASan logs. No nit from either. The
  witness did not rebuild the full autogen/configure/make library lane; that
  lane stays author-observed.
- Witness #1942 (W3 mask/slack) returned **CLOSED ESTABLISHED** at the labeled
  negative-result scope: clean archive `21a4be1`, pinned `fns-1.13.17.inc` SHA
  `b96477e0` verified, own gcc build of `real_layout.c`, all 15 cases matching
  the report table, 44/46 evidence files byte-identical (two `.err` differ
  only in volatile ASLR `POST_MALLOC_PTR`), one stale `compile.log` line-number
  NIT with no grade impact.
- Full stage: `reports/frontier-sofiasip2shell.md`. W1, W2 layout, W2 live
  tport, W3 and W4 are ESTABLISHED at their labeled scopes (W4 witness #1968).
  Rung 5 not implied.
