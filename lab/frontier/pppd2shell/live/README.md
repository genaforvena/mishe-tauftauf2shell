# Live-process replay: CVE-2026-85495 on pinned pppd over a local PTY

`run_matrix.sh` builds the two pinned trees from `../pins/` with gcc 13 ASan,
spawns the real `pppd` binary as root on a locally created PTY slave with the
CHAP-only hardening configuration, and sends one RFC-1662 HDLC-framed LCP
Configure-Request from the master. No network, no external host, no wire
outside this plant. The kernel `ppp_async` line discipline is loaded locally
with `sudo modprobe ppp_async`.

Run from this directory:

```
bash run_matrix.sh
```

The script verifies the four pin hashes, extracts and builds both trees under
the ignored `raw/` directory, runs six cases, and writes normalized evidence
and hashes to `evidence/`. Two consecutive full runs produced byte-identical
normalized hashes (`LIVE_HASHES.txt`).

## Driver contract

`pty_driver.py` uses `sudo -n` only to start the locally built pppd, install a
root-owned 0600 `chap-secrets` in `/run/pppd2shell-live/`, and relax permissions
on ASan's root-owned logs. Daemon options:

```
nodetach passive local refuse-pap refuse-eap noip noipv6 noproxyarp
nolock debug chap-secrets /run/pppd2shell-live/chap-secrets
name labserver <pty-slave>
```

The driver waits for pppd's own LCP ConfReq (the FSM must leave INITIAL before
it processes a peer ConfReq), then writes one frame: FF03 C021, code 01 id 01
length 4+4N, N x `03 04 c0 23`, FCS-16, leading/trailing flag. All bytes below
0x20 and 0x7e/0x7d are escaped with 0x7d/xor 0x20, matching pppd's default
receive ACCM; without that escaping the kernel de-framer discards the frame.

## Cases and results

| tag | pin | N | observed |
| --- | --- | --- | --- |
| `w122-vuln-n3f` | 2.5.3 | 3 | alive; real CONFNAK with three CHAP-MD5 suggestions |
| `w122-vuln-n301` | 2.5.3 | 301 | ASan `WRITE of size 1`, 0 bytes after `nak_buffer` in `lcp_reqci:1608`; rc 1 |
| `w122-vuln-n374` | 2.5.3 | 374 | same sink and offset |
| `w122-vuln-n300` | 2.5.3 | 300 | ASan `WRITE of size 1500` at `lcp_reqci:1853`, 0 bytes after `inpacket_buf` (second BCOPY) |
| `w122-fixed-n301b` | 2.5.4 | 301 | alive; duplicate options ignored, one CHAP-MD5 NAK |
| `w122-fixed-n3b` | 2.5.4 | 3 | alive; duplicate options ignored, one CHAP-MD5 NAK |

All ASan reports show the real receive path
`main:614 -> get_input:1207 -> lcp_input:509 -> fsm_input:365 ->
fsm_rconfreq:436 -> lcp_reqci`. Every case receives the frame before
authentication. Raw pppd logs, ASan reports and frame bytes are in `raw/`;
normalized deterministic copies are in `evidence/`.

## Grade boundary

This establishes rung 3 and rung 4 at **live-process wire scope**: a real
daemon, real PTY, real HDLC frame, real `fsm_input` path, first contact,
pre-auth. The NAK pattern is still constrained to `03 05 c2 23 <digest>`;
no chosen pointer, control-flow object, lab command or side effect was
observed. This is **not rung 5**. Rung 5 still needs a measured pointer or
command path, vulnerable/fixed/safe controls and independent witness replay.

A confounded early control (`w122-fixed-n301`) used a 0644 secrets file that
the fixed pin refused; the 0600 rerun above is the valid control.
