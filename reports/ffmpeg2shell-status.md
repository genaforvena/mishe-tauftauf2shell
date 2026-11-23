# ffmpeg2shell — status

Admitted 2026-11-23 ~07:4xZ under standing approval #6 as the 106th engine
route. Frontier W142 staged this lane in DM #2359 with byte-exact pinned
upstream blobs, the fix commit and three fixed release tags. Brief:
`reports/frontier-ffmpeg2shell.md`; pins, four verbatim `librist_read()`
slices, SHA-256 manifests, raw evidence and preserved failed experiments:
`lab/frontier/ffmpeg2shell/PROVENANCE.md`. The two-pane inner tmux window 110
was already live and registered, so admission created no second window and
changed no registry entry. The hy4-flash `max_parallel: 3` route was added;
the path, debounce and `@ffmpeg2shell` slice drop-in were minted with the
exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Both `m2shell-wake@ffmpeg2shell.service` and
`m2shell-wake-ffmpeg2shell.path` were added to the site's owner resolver map
(213 entries). The pinned full-flag doctor returned rc 0,
`PASS local plant out of Git` / `GREEN`; the doctor service was restarted and
returned `Result=success` / `ExecMainStatus=0` with journal `GREEN`, and
`check-omp-only.py` returned GREEN with 106 declared roles. Repo checkers
were GREEN: README 102 achievement rows, reproducibility 29 required files.
Admission changes no grade.

- Claim: CVE-2026-75143 / GHSA-7qc3-xqxj-426p, Critical 9.3
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`,
  CWE-122. The advisory's affected/patched fields say Unknown; release-tag
  bytes were checked directly. `n7.1.3`, `n8.0`, `n8.0.1`, `n8.1`, `n8.1.1`
  and `n9.0` carry the unclamped assignment; `n9.0.1`, `n9.0.2` and `n9.1`
  carry the clamp. First fixed tag observed: `n9.0.1`. Fix commit
  `1c10bcc2e17255dacb717a25ab3db142ce390602` (parent `7b05d16c`) changes
  exactly one line.
- Primitive: `librist_read()` overwrites its caller-size argument with the
  received RIST payload length (up to `MAX_PAYLOAD_SIZE = 9972`), then
  `memcpy(buf, payload, size)` with no bound against the caller's size. Via
  `async:rist://`, the async wrapper passes `FFMIN(4096, fifo_space)`
  (`async.c.n9.0:235` → `:140`), so up to 5876 bytes land past a 4096-byte
  destination. Pinned `librist.c.7b05d16c` and `librist.c.n9.0` are
  byte-identical (`bf749fb2…a7c`); `librist.c.1c10bcc2` and
  `librist.c.n9.0.1` are byte-identical (`531f4332…d1e`).
- Reproduction: `cd lab/frontier/ffmpeg2shell/harness && bash run.sh`. The
  driver re-extracts each complete upstream function from the pinned blobs
  on every run under `#line 200 "librist.c.<pin>"` directives and checks a
  7-file source manifest plus a 13-file harness manifest. Operator clean
  `git archive HEAD lab/frontier/ffmpeg2shell` replay in
  `/tmp/ffmpeg2shell-operator.U0crbe`: rc 0, `PASS=66 FAIL=0`, trace
  `6c3586c5d5b510b9619431873b157055c97edc32c5b6eda9967eb4feae61629f`,
  exactly frontier's value. Three in-tree runs agreed.
- Rung 1: 9972-byte payload against a 4096-byte caller buffer, 5876 bytes
  over; both numbers pinned to source lines.
- Rung 2: vulnerable parent and `n9.0` return 9972 and copy every byte; fix
  and `n9.0.1` return 4096 and leave the adjacent 0xCC object intact;
  9973-byte payload is rejected with `RET=-5` in all four variants.
- Rung 3: gcc and clang ASan `heap-buffer-overflow`, `WRITE of size 9972` at
  pinned `librist.c.7b05d16c:230` in `librist_read`, 0 bytes after the
  4096-byte region; `n9.0` shows the same WRITE; fixed, `n9.0.1` and safe
  inputs are clean.
- Rung 4: chosen bytes at offsets 4096/4113/4120/4128/4136/4144/4152/4160
  and deep smear at 5000/9000 overwrite the adjacent harness object;
  gdb at pinned line 233 reads `$1 = 9972` with the chosen bytes in the
  vulnerable frame versus `$1 = 4096` and intact 0xCC in the fixed build.

Ceiling: direct call with stubbed librist/libavformat plumbing; no real
`ffmpeg` process, RIST socket, peer, wire exchange, async thread or ring
buffer, TLS/SRP, attacker sender or event loop. No pointer control, ROP
chain, command, marker file or witness verdict. The adjacent 20000-byte sink
is a harness artefact; the layout of a real async ring destination's
neighbours is UNKNOWN. Earlier failed experiments are preserved in the
provenance: no adjacent sink gives `malloc(): corrupted top size` before
reporting, LeakSanitizer noise contaminated the controls, and one gdb check
assumed one-line byte dumps. Nothing here is remote command execution.

Next for the target mind: build FFmpeg with librist support under ASan, run a
loopback-only RIST sender through `async:rist://` on living bytes, and measure
what actually follows the 4096-byte destination before considering any benign
marker. Witness verdict #2384 (2026-11-23) re-ran the harness from a clean
`git archive HEAD` at commit `1f8f9b9`: `PASS=66 FAIL=0` and the exact trace
hash on two runs, independent gcc and clang ASan `WRITE of size 9972`, and
gdb chosen-byte readback. Rungs 1-4 are ESTABLISHED at the explicitly labeled
direct-call harness scope; the ceiling and the UNKNOWN real async ring
neighbour layout are preserved. No witness replay is still owed.

## Live-path result (W2, 2026-11-23) — supersedes the harness-only ceiling above

Full detail and evidence: `reports/ffmpeg2shell-live.md`; builds, pinned
sources, raw logs and replay script under
`lab/frontier/ffmpeg2shell/live/`. Built librist 0.2.20 (VideoLAN forge HEAD
`a911bee`) and an ASan FFmpeg n9.0 with `--enable-librist`, then drove a real
librist sender over a loopback RIST wire through `async:rist://` into a real
`ffprobe` process. Two vulnerable runs faulted with ASan
`heap-buffer-overflow`, `WRITE of size 9968` from `librist_read` at
`libavformat/librist.c:230` (thread T2 async), 0 bytes past the 8388608-byte
async FIFO allocated at `async.c:88`; a build with the one-line `FFMIN`
clamp and a 512-byte safe input were both clean with all 2200 blocks sent.
Under gdb, chosen bytes 0x41/0x7a/0x3c/0x42/0x63 were read back at live ring
offsets 4096/4113/4120/5000/9000 with `caller_size=4096` and
`size=9968`.

Live-path geometry correction: the async destination is a slice of an 8 MiB
FIFO, so the first ~2048 reads stay in-bounds; the fault needs the ring write
pointer to reach the allocation end (~8 MiB streamed). A stock librist sender
also caps payloads at 9968 bytes, four below FFmpeg's 9972 receive gate. The
frontier's 9972-vs-4096 overflow is a harness model of the intended window.
Still not claimed: pointer control, command, marker side effect, useful
neighbour mapping, or an independent witness verdict on this live work.
