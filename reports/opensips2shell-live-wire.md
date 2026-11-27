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
- **Not claimed in the first replay**: control-flow diversion. At that time
  the saved-RIP slot in the instrumented frame was 904 bytes past `buf_from`
  and received only the final NUL (`ripbytes=0007c310837e0000`); stock 4.0.1
  disassembly places the saved RIP at `rbp+8` (`buf_from+888`), but the stock
  process died inside `tm` before return. A later early-return bypass did
  reach the stock saved RIP (section below). **Rung 5 UNKNOWN**: no benign
  marker, no valid executed target, no ASLR/NX measurement, no remote path
  outside this plant's loopback listener. The independent witness replay
  below confirmed the earlier labels and found no rung-5 evidence.

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
(`xmpp.c:291-294`, exact `return -1` at line 294; `run_tm_api` at :300):
`uri_xmpp2sip(to, &tostr.len)` has that early return before `run_tm_api`.
With `sip_domain` unset in this config the helper returns NULL when
`5 + strlen(to) > 256`; a 260-byte `to` therefore makes
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

Partial-overwrite probe (09:30Z): an 886-byte JID with `from[884:886]="j/"`
left only the low two return-address bytes chosen; the `sprintf` terminator
NUL landed on byte 2 and bytes 3-7 kept the original return address. The CPU
transferred control to a **canonical** target `0x7ffff7002f6a` (gdb `#0` at
the target, not at the `ret`) and faulted because it is unmapped: the module
base was `0x7ffff7eda000`, so the target was ~0xed70000 bytes below it. The
`xmpp:destroy: cleaning up...` line in that capture came from the parent's
normal shutdown, not from executed chosen code. Evidence:
`artifacts-early/gdb-partial-886.log` sha256
`a8e72754c85d3050ac4f567fb4e27be09b95a4aa47a0872ee547302c469f445b`,
`artifacts-early/wire-partial-886.log` sha256
`086b626be327d5efe91574835713448e945ed1a6af4ec8e754b178bcd8a4effd`,
gdb script `gdb-partial.cmd` sha256
`c67c342c5239d80107402e1b95aca2905e1a9633494017eba9c75b1ff72dfa12`.

This closes the two-byte partial-overwrite route: XML-encodable attribute
bytes plus the terminating NUL cannot produce a mapped code address here.
Rung 5 remains UNKNOWN — no valid executed target, no benign command, no
observed side effect from chosen bytes. A future attempt needs a different
measured way to keep the original high return-address bytes while controlling
the low ones, or a separate writable-and-executable primitive.
Independent replay (W331, 2026-11-27 09:55–09:58Z, inbox #6274/#6278):
**ESTABLISHED AS LABELED**, no grade change, NO rung 5. Detail at
`.mishe-tauftauf/artifacts/witness-w331-opensips/detail.md`. Clean
`git archive c2fb10c5` SHA-256
`de368ed06bfe9376691a11e8fc97033e0aafce9271ef3c1e9d35ddc09b2de350`;
pinned script/tarball hashes matched; the witness's own stock 4.0.1 rebuild
produced `xmpp.so` `09d4c0b6…` byte-identical to this report with zero
`__stack_chk_fail`. A peer held 5269, so the private replay used 5270 with a
port-only sender copy; all traffic stayed on loopback and no listener was
left. Fresh runs reproduced `RIPCNTRL` → saved RIP `0x4c52544e43504952` and
`ABCDEFGH` → `0x4847464544434241` with the same early-return ERROR pair and
`ret` fault, plus the 886-byte canonical-but-unmapped `0x7ffff7002f6a`. NITs:
the exact `return -1` line is `xmpp.c:294` (the original inbox said 299; the
report's `291-294` range is now precise); the witness's core `opensips` hash
differs from the author's build tree (rebuild reproducibility, not a module
byte mismatch). No chosen code executed.


## One-byte return-address overwrite (2026-11-27 09:53–09:56Z)

Bounded follow-up to DM #6307 (standing #8). The two-byte route above left a
canonical but unmapped target. This test asked whether a **one-byte** overwrite
can keep enough of the original return address to land in mapped code, and
whether that code can do anything chosen. All traffic 127.0.0.1:5269; stock
no-canary `401-plain` build; gdb `set follow-fork-mode child`; no marker or
external action.

Byte map, measured before any overwrite: a baseline run with a 299-byte `from`
and 260-byte `to` takes the same early return but leaves the saved RIP intact.
At `uri_xmpp2sip` frame `#1` is `xmpp_send_sip_msg` with
`[rbp+8] = 0x7ffff7ee66bb` (`xmpp.so` offset `0xc6bb`, caller
`in_stream_node_callback`); saved bytes little-endian are
`bb 66 ee f7 ff 7f 00 00`. `info proc mappings` gives module base
`0x7ffff7eda000`, executable segment `0x7ffff7ede000`–`0x7ffff7eed000`.
JID byte `j` is stored at `buf_from[4+j]` and the saved RIP is `buf_from+888`,
so a 885-byte `from` writes JID byte 884 into RIP byte 0 and the `sprintf`
terminator NUL into RIP byte 1; bytes 2–7 stay original. The target is
therefore always `xmpp.so base + 0x60XX`, with `XX` chosen by the sender —
mapped and executable under ASLR as well as under gdb.

Run with `from[884]='A'` (0x41), `to` 260 bytes: at `xmpp_send_sip_msg+631`
(`0x7ffff7ee329a`) `[rsp] = 0x00007ffff7ee0041` and
`[rbp] = 0x5a59585756555453` (`STUVWXYZ`, non-canonical). The `ret` executed:
`rip` became `0x7ffff7ee0041` (`xmpp.so` offset `0x6041`, `sha_hash+411`,
`add %eax,%edx`); gdb frame `#0` is the target, not the `ret`. The backtrace
stopped at `0x5a5958575655545b` because the saved RBP is non-canonical, and
the next instruction `0x6043: mov -0x18(%rbp),%eax` would fault on it. No
attacker-chosen code ran; the chosen byte only selected a pre-existing
mid-function instruction.

This is a stronger rung-4 mechanic than the two-byte case (a real mapped
transfer) but still **rung 4**. The reachable window is `xmpp.so` offsets
`0x6000`–`0x60ff`, the body of `sha_hash`: static inspection finds **zero**
`0xc3` bytes, no `ret` and no `call`, only rbp-relative local accesses and
short relative jumps. A raw `0xa8` byte (the value needed by any high-byte
gadget) is rejected by expat — the receiver logged
`instream callback: 4: error` / `instream error` and no message callback, so
the high-byte route is also closed. Saved RBP cannot be made canonical: bytes
882–883 would both need to be NUL, and raw NULs do not reach the sink (gate
recorded above). Controls: fixed 4.0.2 ASan with the same 885/260 input logged
`ignoring message stanza before dialback authentication`, no ASan report, no
crash; the 299-byte baseline left the saved RIP intact. Rung 5 stays UNKNOWN
— no benign command, no side effect from chosen bytes, no valid executed
target, no independent replay of this new case.

Evidence (untracked raw logs, hashes here): `gdb-baseline.cmd` sha256
`443bfb78babbdffe1de711f88024b196f2fc89d277b3db5a7486a0af3df2a619`,
`gdb-onebyte.cmd` sha256
`e315e626b9b5d402ad4af43949b58c428fc442241942f8c7ce357a645773d4c5`,
`artifacts-early/gdb-baseline.log` sha256
`38d2a5cbce62a6a84c3c615b4b988ab20535d140b0ad4b1d23ab7bb3e54c9d9f`,
`artifacts-early/gdb-onebyte-2.log` sha256
`cbedd2d70906ae4d63ecf48d29a41b7d93672ea552cf1bcd32ae7714efae7688`, wire
logs `1adbeb8f0f2febba650161a432d369e899b51741c81154ab2ec0c439fb7bcfe3`
(baseline) and
`83ff1a83e1c253a31410576b9c32405dca7e32e97dbce5c553ff72aa8a29f4f1`
(one-byte). Raw-byte gate: `artifacts-early/send_raw.py` sha256
`647932eeac836ad5e6a5175872dcb168dff7c20f2f558e276e6571a3736f5584`,
`wire-raw-a8.log`
`487caf706dc8d9c1bbbb250997a1b158c0548d262b97ce8dbccae045db7884a2`,
`daemon-raw.log`
`35bb2c955b7521e325963acfb69b0686a3d836635bf5ded7b215cb3c5b5f7dda`.
Fixed control: `artifacts-early/daemon-402-early.log` sha256
`7736a7c0b88267a7a2a73a9e65b7653baeb3b9417cb8ba760ef54e5beacd3895`.
All listeners were stopped; port 5269 was closed at handoff.

## Static closure of the NUL-low-byte variant (2026-11-27 10:20Z)

One further partial-overwrite variant needs no new live run. The saved RIP
is `buf_from+888`, so an 884-byte JID puts the `sprintf` terminator on RIP
byte 0 and leaves bytes 1–7 intact: the target would be
`0x7ffff7ee6600`, module offset `0xc600`, inside the caller
`in_stream_node_callback` rather than `sha_hash`. On the pinned stock
no-canary module (sha256
`09d4c0b647950ee6545c810beec954e6565d093b2e6f3ed9881847482204a1cd`),
static disassembly shows `0xc600: mov 0xd8ff(%rip),%rax` (log level),
`0xc609: jle c76d`; both the log and no-log arms converge at
`0xc76e: mov -0xc0(%rbp),%rax`, then `0xc782: pop %rbx` … `0xc78a: ret`.
An 884-byte JID also writes JID bytes 876–883 into all eight saved-RBP
bytes, so RBP holds ASCII and is non-canonical; the RBP-relative load at
`0xc76e` would fault before any clean return. This is a **static
prediction**, not an observed run: it closes the NUL-low-byte variant by
the same RBP coupling as the one-byte case and adds no rung-5 evidence.
No chosen code, no command, no side effect; rung 5 stays UNKNOWN.

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
