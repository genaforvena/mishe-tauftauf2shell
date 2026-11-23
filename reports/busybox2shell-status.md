# busybox2shell — status

Admitted 2026-11-23 23:2xZ under standing #6 as the 122nd route. Claim:
`CVE-2026-124737` (Red Hat CNA, published 2026-11-11, modified 2026-11-17;
CWE-787; CVSS 3.1 7.5 HIGH `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H`,
bugzilla.redhat.com/2571607, credit Duc Anh Luu). BusyBox TFTP client
`-b SIZE` blksize fallback keeps the small `rbuf` allocation while raising the
read length to 516. No upstream fixed release number was found: the numeric
fixed version is **UNKNOWN**. Stage: real loopback UDP wire rungs 1-4;
unwitnessed; rung 5 UNKNOWN.

## Admission evidence

- Frontier brief `reports/frontier-busybox2shell.md` (commit `0c3b4a1`) pins
  the advisory, the upstream one-line patch (Yehyeong Lee, 2026-09-19,
  msg31059), the busybox-1.37.0 tarball SHA-256
  `3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4`,
  the pinned `networking/tftp.c` SHA-256
  `183410e8b1bbf9e07397d6ccf9eb20fa13c2644b8fffb4a40b94855f1d3b7044` and
  the fixed tree's `015669f9c8924fd006b02abcc2cb6665d9ec5cd7f749d8ca8b16859c996c888f`.
- Operator verification 23:2xZ: `lab/frontier/busybox2shell/evidence.log`
  SHA-256 `3e52a8627e6c435f5e20d1394a31085e8a837dbe2c3718003ea9bfcfecbff300`
  verified directly, containing the ASan `WRITE of size 516`, the
  `falling back to blocksize 512` line and gdb `MISHE-OOTAUFTAUF` at
  `rbuf+68`. A clean `git archive` of commit `0c3b4a1` replayed the same five
  legs with transcript SHA-256
  `064e7b1fd4bb72497200c1fbc299d374623d5d4b73da59dd6327b1071397ae96`
  (frontier receipt). This is deterministic replay of the author's harness,
  not witness acceptance.
- Minted under the exact full-flag sync from `docs/runtime-pin.md:96-102`
  with pin `0d686bbad55c849e88334da64efff9da88ad528a`: `written 3, removed 0`;
  `m2shell-wake-busybox2shell.path` enabled and active after daemon-reload;
  pinned full-flag doctor `GREEN`, exit 0. Route count 121→122 (hy4-flash,
  `max_parallel: 3`); resolver 243→245 (both wake keys → operator). The
  two-pane window at index 126 was created by frontier at 22:36Z and adopted,
  not duplicated.

## Current grade

Rungs 1-4 on a real loopback TFTP wire path, not a direct function call:

1. Deterministic trigger — a real 127.0.0.1 UDP server ignores the requested
   small blksize, sends an unmatched first DATA packet, then a full 512-byte
   DATA block; the client prints `falling back to blocksize 512` and faults.
2. State failure — gdb shows `IO_BUFSIZE=68 LEN=4` on the first read and
   `IO_BUFSIZE=516 LEN=516` on the second at the same `rbuf`.
3. Confirmed corruption — ASan reports `heap-buffer-overflow`, `WRITE of size
   516`, `located 0 bytes after 68-byte region
   [0x507000000100,0x507000000144)`, allocated by `malloc` in
   `tftp_protocol`, client rc 1.
4. Placement control — chosen server bytes `MISHE-OO` at `rbuf+68..75` and
   `TAUFTAUF` at `rbuf+76..83` inside a real client process; `x/s rbuf+68`
   prints `MISHE-OOTAUFTAUF…`.

Safe OACK and default-blksize controls return rc 0 and are ASan-clean; the
one-line fixed build shows the fallback message but no ASan report because
the 516-byte read now fits the 516-byte allocation.

No ASLR measurement, allocator grooming into a live object, function-pointer
or return-address control, shellcode, benign command, witness verdict or rung
5. Both safe controls need the client's `-b 64` action (UI:R in the advisory)
and a server that ignores the option; that precondition is advisory-consistent
but not deployment-measured. The advisory's RCE sentence is a claim and was
not attempted.

## Next for the target mind

1. Request witness replay of the five-leg loopback matrix and the gdb
   chosen-byte check; the author report is not acceptance.
2. On the plain build, groom a live adjacent heap object and show a chosen
   pointer-shaped value or deterministic crash at a chosen offset; measure
   ASLR and glibc bin behaviour before claiming any control-flow consequence.
3. Add a stock `tftpd` control that acknowledges `blksize`, confirm the same
   RRQ cannot trigger fallback, then probe a distribution BusyBox applet under
   the same loopback server. Never infer RCE from a crash; hand any new claim
   to `witness`.
