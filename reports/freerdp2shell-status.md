# Freerdp2Shell status

Admitted by the operator 2026-11-20 ~19:32Z under standing approval #6;
handed off from frontier ~19:2xZ. Dedicated two-pane window (inner socket,
window 18) and restorer registry entry are live; seed wall at
`.mishe-tauftauf/walls/freerdp2shell.md`, charter at
`.mishe-tauftauf/charters/freerdp2shell.md`, and the docs/task.md entry is
committed. Wake trigger units and the presentation.json `active` entry are
still owed from the person's full-flag sync (docs/runtime-pin.md — never a
bare `mishe sync`). Frontier re-ran the committed harness from clean HEAD;
the operator re-ran it at 19:30Z: `bash lab/frontier/freerdp2shell/run.sh`
prints `ALL CHECKS PASS`, rc 0, twice; digests `d0a31487…` / `c5186500…`.

## Target

FreeRDP server-side rdpsnd channel `rdpsnd_server_select_format()` integer
wraparound, GHSA-3m9q-g533-rqjq / CVE-2026-114045 (CWE-122 via CWE-190,
CVSS 3.1 8.8 High post-auth / 9.8 Critical no-auth),
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`. Advisory boundary: affected
`master <= 8ec6d3923b` and stable `<= 3.32.0`; fixed `>= 3.32.1`. Lineage: a
bypass of the CVE-2026-63117 fix (`b7ca093`). Default posture is
post-authentication (PR:L); only no-auth RDP deployments reach 9.8.

## Mechanism and reproduction
Line numbers for `rdpsnd_main.c` below are raw-file lines at the named tag
(the earlier reader-displayed numbers were +6).

- Parse-time check (`rdpsnd_main.c:252-259`, 3.32.0) enforces only
  `nBlockAlign >= 4` for DVI_ADPCM, never `nBlockAlign >= 4*nChannels`, so a
  client sends `nBlockAlign=4, nChannels=2` in an `SNDC_FORMATS` record.
- `select_format()` (3.32.0, :409-418) computes
  `bs = 4ULL*(4 - 4ULL*2) = 0xFFFFFFFFFFFFFFF0`, all `WINPR_ASSERT`s pass,
  `out_frames` becomes that wrapped value, `out_buffer_size` wraps to
  `0xFFFFFFFFFFFFFFC0`, `realloc` fails, and `out_frames` is **not rolled back**
  (:446-451).
- `send_samples()` (:765-785) then `CopyMemory`s client sample bytes into the
  still-8820-byte `out_buffer`; `out_pending_frames` never reaches the huge
  `out_frames`, so successive calls append at monotonically advancing offsets
  — an unbounded, sequential, attacker-controlled heap write.
- Harness (pinned digests above): rung 1 `rc2=2 out_frames=0xfffffffffffffff0
  realloc_failed=1`, `oob_writes=7564 first_oob=8820 last_oob=16383`; rung 2
  chosen bytes `ab`/`cd` land at OOB offsets 8820/12000; rung 3 ASan
  `heap-buffer-overflow`, `WRITE of size 16384`, `0 bytes after an 8820-byte
  region`, from `memcpy` via `send_samples`; rung 4 two calls place `de` at
  offset 8820 and `ad` at 21384 with `out_pending_frames=8192`; benign and
  3.32.1-guard controls show `oob_writes=0`; five traces byte-identical.

## Evidence boundary

Rungs 1/2/3 established, rung 4 PASS in the extracted harness with
client-chosen bytes at client-chosen offsets. Live FreeRDP process, real
`SNDC_FORMATS` PDU parse path, RDP session, stock allocator layout, network
reachability and the auth gate remain UNKNOWN. No off-loopback probe.

Brief: `reports/frontier-freerdp2shell.md`; harness:
`lab/frontier/freerdp2shell/{rdpsnd_overflow.c,run.sh}`. Witness replay
requested; author report is not acceptance.
