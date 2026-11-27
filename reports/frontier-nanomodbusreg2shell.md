# Frontier brief: nanomodbusreg2shell — malicious-server register response overflow

**Status: STAGED 2026-11-27 W351 under standing #6; operator admission and
independent witness replay owed.** Brief and lab only; no external probing,
all execution on 127.0.0.1.

## Verified ground truth

- GitHub advisory GHSA-5hc8-p74q-47pp / CVE-2026-29972, published 2026-05-08,
  High, CWE-121. nanoMODBUS through v1.22.0: a client calling
  `nmbs_read_holding_registers()` or `nmbs_read_input_registers()` writes
  register data from the server response into the caller's buffer using the
  response `byte_count` **before** checking it against the requested
  quantity. A malicious Modbus TCP server sends `byte_count=250` (125
  registers) and up to 248 chosen bytes past the caller's buffer. Advisory
  and discoverer's gist read from GitHub; no external host probed.
- Tags verified with `git ls-remote`: affected v1.22.0
  `035b8d596a954c2dd4bc40e3fa28a7cb2a8c0ec1`, fixed v1.22.1
  `11317b18a60f7b21583d909ba8201686a1b21fc3`. Fix commit
  `a3a67f7bc1a06a5697d06772cf5f4386a32e37be` ("validate registers_bytes
  before write") moves the quantity check from after the store loop to
  before `recv()`. The pinned source and verbatim one-hunk diff are in
  `lab/frontier/nanomodbusreg2shell/src/` and `SHA256SUMS`.
- Duplicate check: no `nanomodbus*` lane in the frontier wall, manifest,
  `reports/` or `lab/frontier/` before this wake; nanoMODBUS is not in the
  admitted list. Other fresh advisory candidates screened this wake but not
  staged: Hitachi RTU500 (no source/fix pair), Danfoss AK-SM 8xxA (embedded
  appliance, no source), mod_vhost_alias (Apache2 lane already admitted).

## Source-bound mechanism

Pinned v1.22.0 `nanomodbus.c:580` `recv_read_registers_res(nmbs, quantity,
registers)`: `:589` reads `registers_bytes = get_1(nmbs)` from the server
response; `:592` rejects only `> 250`; `:595` receives that many bytes into
the message buffer; `:600-604` loops `i < registers_bytes / 2` and writes
`registers[i] = get_2(nmbs)`. The `registers_bytes != quantity * 2` check is
at `:611`, after every store. A request for two registers therefore accepts
250 response bytes and writes 125 `uint16_t` words into a four-byte caller
array. The upstream example `examples/linux/client-tcp.c:82-83` declares
`uint16_t r_regs[2]` and calls the affected API over a real TCP socket.

## Observed result

`lab/frontier/nanomodbusreg2shell/` pins both library versions, the
unmodified example client and the unmodified Linux platform transport.
`harness/server.py` is a loopback-only malicious Modbus TCP server;
`harness/client-wire.c` is a minimal real-socket caller with a small frame
so the saved return address is in range (full disclosure in
`PROVENANCE.md`). Builds are offline gcc `-g -O0`; ASan for corruption arms,
`-fno-stack-protector -no-pie -D_FORTIFY_SOURCE=0` for the control arm.

- Upstream example client, ASan, attack response: `stack-buffer-overflow`,
  `WRITE of size 2` at pinned `nanomodbus-v1.22.0.c:603`, called from
  `client-tcp.c:83` over a real TCP connection after four valid responses.
- Minimal wire caller, ASan: same sink, destination `regs[2]`
  (`harness/client-wire.c`), all 250 chosen bytes accepted from the wire.
- Fixed v1.22.1 with the identical payload: `READ_RC -2 REG0 0000 REG1 0000`,
  no ASan and no marker — the check now precedes the store.
- Safe input (`byte_count=4`): `REG0 4141 REG1 4141`, no ASan.
- Plain no-PIE, no-canary build with chosen `0x43` bytes: SIGSEGV and an
  unwind whose caller frames are `0x4343434343434343`.
- Plain build with the saved-RIP slot set from wire bytes to the address of
  an unreferenced lab function: `BENIGN_MARKER` printed by the live
  loopback-fed client; the same payload against the fixed build prints no
  marker. No debugger write participates.
- Negative preserved: the upstream example's own `main()` frame places
  `r_regs` 800 bytes below its saved RIP, so 250 bytes do not reach that
  saved RIP; that is why the small-frame caller exists. The wire, library
  and sink are identical in both callers.
- `sh harness/run-all.sh`: 11 pins OK, `RUN_ALL_OK 17 PASS / 0 FAIL`, summary
  SHA-256 `c8489055177859c647d4718101f1feaf61dc20a7d2e6e2dfa04dcc6b33ea909d`.
Clean replay: private `git archive --format=tar 48360585
lab/frontier/nanomodbusreg2shell` gave plain-tar SHA-256
`d47d2b11984cf56ab01374de7cde90f97e8583be3120758a3fb85d6e413a0252`;
unmodified `sha256sum -c SHA256SUMS` was 11/11 OK and `sh harness/run-all.sh`
exited 0 with `RUN_ALL_OK 17 PASS / 0 FAIL` and the same summary
`c8489055…`, including the `BENIGN_MARKER` arm.

Grade: R1/R2/R3 ✓; **R4 DEMONSTRATED at the real-wire/loopback lab scope**,
including chosen bytes at a saved return address and execution at a chosen
code address under disclosed no-PIE/no-canary/no-fortify conditions. **R5 NOT
CLAIMED**: the side effect is a function writing a label, not a shell
command; the caller is a lab client with a compiled-in marker address; no
witness replay yet; hardened builds, production callers and persistency are
UNKNOWN.

## Cheapest next experiments

1. Independent witness replay of a clean archive of the staging commit:
   `sha256sum -c SHA256SUMS` 11/11, `sh harness/run-all.sh` rc 0,
   `RUN_ALL_OK 17 PASS / 0 FAIL` and the same summary SHA-256, plus the
   `BENIGN_MARKER` arm. Counterexample hunt: does the fixed arm ever store,
   is the marker address only reachable with ASLR/no-PIE, and does the
   chosen-byte swap preserve the intended saved-RIP word?
2. If a target mind seeks rung 5: replace the label-writing `marker()` with
   a lab-chosen benign command executed by a live loopback-fed client, keep
   fixed/safe controls, and record whether the redirect survives a PIE
   build with a real leaked code address. No command side effect is claimed
   here.
3. Measure a hardened caller (canary, PIE, fortify) and a real deployed
   nanoMODBUS client application to see whether the 250-byte write reaches
   any pointer or control-flow word there.

## Ranking context

Ranked above the other fresh advisories because the primitive is a plain
store-first write, the parent/fix pair is exact, the input arrives over a
real TCP connection, and the upstream example already supplies the small
caller buffer. Its ceiling is chosen-address execution in a lab build;
whether that survives hardening is the open question.
