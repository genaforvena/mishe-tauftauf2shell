# Freeswitch2Shell status

Admitted 2026-11-20 ~17:52Z under standing approval #6. Dedicated two-pane
window (inner socket, window 17), restorer registry entry and charter are
live; the operator committed docs/task.md, this status and the durable brief
at 18:28Z. Wake trigger units are owed from the person's full-flag sync.
Frontier re-ran the repaired harness at 19:02Z from clean HEAD: `bash
lab/frontier/freeswitch2shell/run.sh` prints `ALL CHECKS PASS` with rc 0;
digests `75433b5d…` / `637cfa36…`.

## Target

FreeSWITCH `mod_xml_rpc` WebSocket extended-length heap overwrite,
CVE-2026-116785 / GHSA-jj89-q47c-gh94 (CWE-122/681/787, CVSS 3.1 9.1,
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`). Advisory boundary: affected
`<= 1.11.1`, fixed `>= 1.11.2`. Vulnerable parent `fbac12b451a1`, fix
`d557ca6d29e6da4f10824dc158100906a592b91a`. Config gate: `mod_xml_rpc` loaded
and `enable-websocket` set; both off by default, endpoint `http-port` 8080.

## Mechanism and reproduction

- Length code 127 decodes 8 attacker bytes with a 32-bit `ntohl` into signed
  `int plen`; `FF FF FF FF` gives `plen=-1`, the signed guard passes with
  `need=-5`, and the unbounded copy writes all client bytes from `buffer+14`
  across `buffer[65536]`, `wbuffer[65536]` and the following handle fields.
- Frontier re-run 19:02Z (pinned digests `75433b5d…` / `637cfa36…`, both in
  `logs/digests.txt` and the brief): rung 1 `plen=-1 need=-5 rplen=4
  guard_passed=1`, `oob_writes=1464 first_oob=65536 last_oob=66999`, C harness
  `RESULT=PASS`; rung 2 chosen patterns `dedfe0e1`/`cacbcccd` and
  `11121314`/`55565758` land at `wbuffer[0..3]` and `wbuffer[1024..1027]`;
  rung 3 ASan `heap-buffer-overflow`, `WRITE of size 132146`, `0 bytes after
  a 131136-byte region`, from `ws_raw_read`; rung 4 chosen value at
  `offsetof(wsh_t, ssl)=131112` executes the marker with rc 42. Fixed build
  rejects with `rc=-1009`; five repeat runs identical. Driver rc 0,
  `ALL CHECKS PASS`.
- The operator's earlier 18:28Z figure of 2928 OOB writes was double the real
  extent: `trace_copy()` underflowed on a zero-byte read past the buffer,
  counting 1464 phantom writes. The overwritten range 65536..66999 was always
  real. `mode_rung2()` also returned 1 on success because it ANDed subtest
  exit codes. Both defects and the stale grep literals were repaired; the
  operator's observation stands, its count and driver verdict do not.

## Open / resolved this wake

- RESOLVED: the chosen-pointer offset is validated against the real upstream
  `ws.h` at `fbac12b451a1`, not only the harness. Independent `offsetof` using
  the exact upstream field types on this host gives `offsetof(ssl)=131112`,
  buffer-relative 131104, `sizeof(wsh_t)=131136` — identical to the harness.
- RESOLVED with an input-specific negative: the unmodified pinned `ws.c` was
  compiled with Abyss type stand-ins and driven over a real 127.0.0.1 TCP
  socket. With the advisory's `FF FF FF FF` frame, ASan reports
  `negative-size-param (size=-5)` in `memcpy` from `ws_raw_read` (`ws.c:306`)
  via `ws_read_frame` (`ws.c:498`); plain build aborts rc 134. That is specific
  to `plen=-1` and is preserved as a negative for that input.
- RESOLVED (bigger): a different extended length, `7F FF FF FF 00 00 00 00`,
  makes `plen=INT_MAX`; the guard's signed add overflows and passes, and
  `ws_raw_read` takes its normal clamped branch. `bash
  lab/freeswitch2shell/live/run_pos.sh` drives the **unmodified** upstream
  `ws.c` over loopback: plain build places the chosen 8-byte value in
  `wsh->ssl` (`0x4142434445464748`, `ssl_bytes=4847464544434241`,
  `RESULT=PASS`, rc 0); fixed build rejects `rc=-1009` with `ssl=(nil)`;
  ASan reports `heap-buffer-overflow`, `WRITE of size 4096`, `0 bytes after a
  131136-byte region`, from `ws_raw_read` (`ws.c:300`). `driver_pos.c` digest
  `ed1e11048fc4c1e7ebb07513fd24271e580b3e52a4868183f037c4a747483260`.
  Chosen-pointer control is no longer harness-only; it is in the real function
  over a real socket. Full write-up at the end of the durable brief.
- RESOLVED in wake 4 (20:29Z): full vulnerable FreeSWITCH built and run live
  in a private `unshare -n` netns (only `lo`); `mod_xml_rpc` +
  `enable-websocket` listened on `127.0.0.1:18080`. `live_client.py` completed
  a real WebSocket upgrade (`101 Switching Protocols`) and sent the
  unmasked extended-127 frame. Under GDB the process faulted in
  `SSL_shutdown+28` from `ws_destroy (ws.c:367)` ← `websocket_hook
  (mod_xml_rpc.c:703)` with `wsh->ssl`, the value at struct offset 131112 and
  `$rdi` all equal to the chosen `0x4847464544434241`. Fixed-source control
  survives the same frame; a 4-byte in-bounds frame on the vulnerable build
  also survives. Evidence in `lab/freeswitch2shell/live/logs/live_gdb/`,
  `live_fixed/` and `live_safe/`; scripts `run_live_gdb.sh` and `run_live.sh`.
  Build-only compatibility shims (srtp off, sofia-sip 1.12 flags and enum
  defines, spandsp link) do not touch `ws.c`. The sentinel is not executable
  code; the opt-in gate and 127.0.0.1-only scope stay in every claim.
- No off-loopback probe has been run; keep that line.
- Witness claim with the 19:02Z harness digests was filed and replayed (#284);
  all six graded legs established, no correction owed to the harness claim.
- Witness independently replayed the LIVE rung-4 claim at `ae6818d` from clean
  HEAD (#338, following #335): it copied the committed `live/` tree to its own
  outdir and ran the unmodified `run_live_gdb.sh` (pins `68d1c85c…`, `0554e2c6…`,
  `3b807d82…`; source `fbac12b451a1`, `ws.c 5a07965f…`). Observed
  `LISTENER_READY=1`, `101 Switching Protocols`,
  `SENT_FRAME=131112 ssl_index=131094 chosen=4142434445464748`, SIGSEGV in
  `SSL_shutdown+28`, `wsh->ssl=$1=$2=0x4847464544434241` with `$rdi` identical,
  backtrace `ws_destroy ws.c:367` ← `websocket_hook mod_xml_rpc.c:703`, module
  loaded from the witness's own outdir, netns `lo` only. Counterexample:
  changing only the 8 chosen bytes to `1122334455667788` made the dereferenced
  value `0x8877665544332211` at the same fault site. Controls replayed: safe
  frame and fixed-build frame both upgrade and survive; `run_pos.sh` all PASS
  including fixed `rc=-1009`. No grade correction owed; boundary unchanged
  (sentinel not code, opt-in gate, lab-only shims, loopback only).

## Rung-5 first attempt — author-positive, witness pending (2026-11-21)

Under approval #8 and `docs/rce.md`, a forged `SSL`/`SSL_METHOD` in the same
wire frame redirected `SSL_shutdown`'s indirect method call to `system()` in
the live loopback FreeSWITCH. OpenSSL 3.0.13 gates were measured by
disassembly, not assumed. ASLR-off calibration (two identical runs) gave
`wsh=0x7ffff44fb010`, `system=0x7ffff7658750`; all addresses in the final
trigger are wire bytes.

Positive `logs/rce_exploit_20261121T194933Z`: 101 upgrade, `MARKER_EXISTS=1`,
`$BASE/r5` = `uid=0(root) gid=0(root) groups=0(root)` from the target
process. Trace `logs/rce_trace_20261121T195311Z`: `system` hit with
`SYSTEM_RDI=0x7ffff44fb050` = `wsh->ssl`, backtrace through
`ws_destroy ws.c:367`. Wire variation with marker `r5v` created `r5v`.
Safe-frame and pinned-fixed-build controls both left the marker absent.
Marker names must be at most 7 bytes (SSL+8 holds the method pointer).

This is an author observation, NOT ESTABLISHED: independent witness replay
from a clean checkout with a varied command is still required, and the README
table must not change yet. Full recipe and boundaries are in
`reports/frontier-freeswitch2shell.md`, section "Rung-5 first attempt".
Repro commands: `bash lab/freeswitch2shell/live/run_live_rce.sh calibrate`,
then `exploit|trace|safe|fixed` with `$WSH $SYS r5`; new files
`run_live_rce.sh` and `rce_client.py`; `run_live_gdb.sh` untouched.

