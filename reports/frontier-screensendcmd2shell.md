# Frontier brief: screensendcmd2shell — GNU Screen global buffer overflow

Status 2026-11-27 W370: **ADMITTED 21:4xZ as the 222nd declared target mind**;
window 230 adopted as-is. Operator clean replay at 21:47Z from HEAD `95161177`:
6/6 pins, own BUILD_OK and `RUN_ALL_OK 13 PASS / 0 FAIL`; independent witness
replay owed. Grade: R3 CONFIRMED on the real unmodified client; R4 **LIMITED**
to chosen bytes in a real adjacent global of the ASan lab build; R5 **NOT
CLAIMED**. Harness `lab/frontier/screensendcmd2shell`; clean plain-tar SHA-256
`519f6fde02eebd02da0bc1857cddb9a61a3d5c9494aa3ebacfabeda02bf2bb42`.


## Verified ground truth (claim, not assumed)

- CVE-2026-71409, published by CERT Polska 2026-11-26, CWE-120, CVSS 4.0 4.6
  (`AV:L/AC:L/AT:N/PR:N/UI:A/...`). All versions before 5.0.2 affected; fixed
  in 5.0.2.
  https://cert.pl/en/posts/2026/11/CVE-2026-71409/
  https://www.cve.org/CVERecord?id=CVE-2026-71409
- Claim: unchecked `sprintf()` in `SendCmdMessage()` (`attacher.c`) appends
  attacker-controlled `STY` to the global `SocketPath[]`; long `HOME` and `STY`
  values overflow it. The same advisory reports CVE-2026-71410
  (`utf8_handle_comb()` UAF in `encoding.c`) and CVE-2026-71411 (hardcopy
  ruid/euid TOCTOU LPE), both fixed in 5.0.2; neither is built here.
- Source pins: GNU tarballs 5.0.1 `2dae36f4…09869d` and 5.0.2 `ca9a2c7e…b332`
  from https://ftp.gnu.org/gnu/screen/. Full provenance in
  `lab/frontier/screensendcmd2shell/PROVENANCE.md`.


## Source-bound mechanism

`screen.c:107` declares `char SocketPath[MAXPATHLEN + 2]`; with
`MAXPATHLEN == PATH_MAX == 4096` on this host the global is 4098 bytes.
`screen.c:685-688` takes `sty` from `getenv("STY")` without `-S`; `screen.c:950`
calls `SendCmdMessage(sty, ...)` for `-X`/`-Q` commands. `SCREENDIR` is capped
below `MAXPATHLEN - 1` at `screen.c:797` and copied into `SocketPath` at
`:828`, so only a few bytes can remain. Vulnerable 5.0.1 `attacher.c:434`:

```c
sprintf(SocketPath + strlen(SocketPath), "/%s", sty);
```

`sty` is capped only at `FILENAME_MAX` and `2 * MAXSTR - 1` (1535, with
`MAXSTR 768` at `screen.h:44`). Fixed 5.0.2 `attacher.c:435-438` rejects
`used + 1 + strlen(sty) >= sizeof(SocketPath)` and uses bounded `snprintf`.
The same release bounds `FindSocket()`'s `sprintf()` at `socket.c:196`; 5.0.3
later bounds the identical pattern in `SendCreateMsg()` at `socket.c:447`.
Both siblings belong to this mind, not separate stages.


## Local experiment

`harness/build.sh` builds three in-tree arms from the pinned tarballs:
5.0.1 ASan, 5.0.2 ASan, and a recover-ASan 5.0.1 build. `harness/run-all.sh`
creates a loopback-local directory whose absolute path is exactly 3899 bytes,
then runs the **real** `screen -X echo hi` binary with `SCREENDIR` pointing at
it. No server, listener, wire request, shell or command is used.

- Vulnerable ASan, `STY` = 300 `C`: `global-buffer-overflow`, `WRITE of size
  302`, 0 bytes after the 4098-byte `SocketPath`, 62 bytes before the real
  global `attach_tty_name_in_ns` (4096 bytes), stack
  `SendCmdMessage attacher.c:434` ← `main screen.c:950`.
- Fixed 5.0.2 ASan, same input: rc 1, `Socket path too long.`, no ASan report.
- Vulnerable ASan with `STY=ok`: no ASan report.
- Recover-ASan with `STY` = 600 `C`, examined under GDB at the breakpoint after
  the `sprintf`: `SOCKETPATH_LEN=4500`, `ATTACK_STY_LEN=600`, and
  `attach_tty_name_in_ns` offsets 0, 16, 32, 48, 64, 100, 200, 239 and 240 all
  read `0x43`, the attacker-chosen byte.
- Input pins and stable path-independent observations are checked before and
  after regeneration; two consecutive replays gave `RUN_ALL_OK 13 PASS / 0 FAIL`.
  Volatile PID/address logs are gitignored.


## Rung assessment and scope

- R1: deterministic trigger through the unmodified `screen -X` client binary.
- R2: attacker-chosen `STY` bytes land at chosen offsets of the real adjacent
  global; the offset is set by `SCREENDIR` length.
- R3: ASan-confirmed global-buffer-overflow WRITE on the real binary.
- R4 **LIMITED**: GDB observes chosen `0x43` at nine distinct offsets in the
  real `attach_tty_name_in_ns` global of the ASan lab build. No function
  pointer, callback, control-flow transfer, shell or command was exercised;
  global ordering is toolchain-specific. Independent plain GCC builds (PIE
  and -no-pie) abort under FORTIFY with rc 134 before any write — a
  preserved negative, not a pass; no plain-build chosen-byte write was
  measured.
- R5: NOT CLAIMED. No loopback service, wire/request input or command side
  effect; the input is local attacker-controlled environment.


## Cheapest next experiments for the dedicated mind

1. Rebuild with a linker layout placing a pointer-bearing global after
   `SocketPath` and measure whether a chosen `STY` can redirect it; preserve
   the current ASan-real-neighbor and plain-build FORTIFY-abort negatives.
2. Reach `SendCreateMsg()` (5.0.2, fixed in 5.0.3) through `screen -X` with a
   crafted new-window command and replay the same ASan/GDB pair.
3. Examine `FindSocket()`'s `socket.c:196` sink with directory entries whose
   names exceed the remaining `SocketPath` space.
4. Only after a real consumer transfer is measured, test a benign command side
   effect with vulnerable/fixed/safe controls.

A Clang cross-compiler smoke preserved a layout negative: the same real-binary
ASan report appears with the same sink and caller, but no named adjacent
global, and the recover-build victim bytes stay zero (11 PASS / 2 FAIL). The
R4 observation is thus GCC/layout-specific; GCC arms were rebuilt and the
pins restored to 13/0 afterwards.


## Selection notes

Tractable because the fix is a small bounds check, the sink is reached by a
stock client command with environment inputs, and the real binary produces a
deterministic ASan report with chosen bytes in a real adjacent global. The
local-environment precondition, toolchain-specific global layout and absence
of any control-flow consumer cap the grade at R4 LIMITED with no R5 claim.
