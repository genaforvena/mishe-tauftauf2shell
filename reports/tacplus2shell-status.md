# tacplus2shell — status

Admitted 2026-11-22 ~20:2xZ under standing approval #6 as the 80th target
mind and 84th engine route. Charter `.mishe-tauftauf/charters/tacplus2shell.md`,
seed wall `.mishe-tauftauf/walls/tacplus2shell.md`; staged by frontier at
commits `0449e3e` (harness, pins, brief), `5e72d56` (clean-archive replay) and
`e5f6bfe` (brief repair). Frontier's #1630 recorded the already-live two-pane
window (inner index 89, registry entry 90); admission adopted it and added the
hy4-flash route, a 7-day operator wake-failure signal and the three units from
the exact full-flag sync — no duplicate window, no hand-cleared signal.

- Claim: CVE-2026-130875 / GHSA-v384-f7x8-f7c7, "tac_plus-ng before commit
  `d8493e0` contains a stack-based buffer overflow that allows clients holding
  the TACACS+ shared key to overflow a stack buffer due to an operator
  precedence error in `author_pak_looks_bogus()` and
  `accounting_pak_looks_bogus()`" (CWE-783 / CWE-121). VulnCheck, 2026-11-17,
  CVSS v4 7.7 High (`AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H`). No fixed
  release number is asserted by the vendor: affected `<= e20ac82`, fixed
  commit `d8493e0d6420b91737fa34c2cd7bbd365d023b5b`; the advisory's own PoC
  was built from `929671c`. Source URLs, the fix patch and both pinned blobs
  are in `lab/frontier/tacplus2shell/PROVENANCE.md`.
- Primitive: in `tac_plus-ng/packet.c:523,538` the vulnerable return is
  `return (i != arg_cnt) || flag ? (len > datalength) : (len != datalength);`.
  Because `?:` binds below `||`, a truncated argument-size table with
  `i != arg_cnt` is accepted whenever `len <= datalength`. `eval_args()`
  (`author.c:66-97`) then walks attacker-supplied sizes into adjacent heap
  and `memcpy()`s `cmd=`-prefixed arguments into `cmdline`, a stack VLA sized
  from the packet length. The fix adds one pair of parentheses to each return;
  `author.c` is byte-identical on both pins.
- Pins: vulnerable `929671c22ff9f390f22decd7eb97dffaece8aebe`, fixed
  `d8493e0d6420b91737fa34c2cd7bbd365d023b5b`. `packet.c` SHA-256
  `a0c911f8…` → `4f3174de…`, `author.c` `bc36763f…` unchanged; full digests in
  `lab/frontier/tacplus2shell/PIN_HASHES.txt`.
- Evidence: real-daemon wire (operator replay ~20:1xZ,
  `bash lab/frontier/tacplus2shell/harness/run_wire.sh`): one crafted AUTHOR
  packet (body 267, `arg_cnt=255`, table `4` + 254×`0xff`, data `cmd=`, pinned
  `md5_xor()` pad) to a plant-started 127.0.0.1 listener passed as fd 0 makes
  the ASan vulnerable daemon report `heap-buffer-overflow READ of size 1`,
  243 bytes past a 323-byte `calloc` region, top frames
  `eval_args author.c:75` → `author :141` → `tac_read packet.c:892`, `rc=-6`,
  no reply. Fixed pin: 57-byte rejection, `rc=0`, empty ASan log; vulnerable
  pin with a safe packet: 18-byte reply, `rc=0`, empty log. Normalized
  vulnerable hash `599ab1f0d59faa209f09b721079467df6f363d46a69859797f8ecfeca583b78c`
  matches both frontier replays and this one; both controls hash the empty-log
  digest `e3b0c442…`. Verbatim-function harness (`harness/run.sh`, operator
  replay 9 PASS / 0 FAIL): vulnerable accepts and copies chosen `0x41`/`0x5a`
  at `cmdline` offsets 0..7 under gcc and clang; fixed rejects with
  `cmdline_len=0`; a 40-byte copy into the 15-byte VLA gives ASan
  `dynamic-stack-buffer-overflow`.
- Grade: rungs 1/2 and 3 at **real-daemon wire scope**; rung 4 chosen bytes at
  chosen offsets at **verbatim-harness scope only**. No daemon-side readback,
  allocator grooming, pointer control, function-pointer overwrite, marker,
  command or rung 5. The attacker must hold the configured shared key (or use
  a keyless host entry) and name a permitted `service=shell` user; no password
  is required, but this is not anonymous pre-auth. The advisory's
  five-connection heap-leak / `system()` / root chain remains **claim text**,
  not a lab observation.
- Witness replay **CLOSED** (W124, 2026-11-22 20:19Z, tape #1648): ESTABLISHED
  at the labeled scope. From a clean `git archive` of HEAD `f6d0654` the
  witness hash-verified the raw `929671c`/`d8493e0` blobs against
  `PIN_HASHES.txt` (checked-out `*.c` hashes differ only from `$Id$`
  expansion by `.gitattributes`), built both pins with its own clang ASan,
  and got 9 PASS / 0 FAIL from `run.sh` and 7 PASS / 0 FAIL from
  `run_wire.sh`: the same READ-1 at `eval_args author.c:75` with fixed and
  safe controls clean. Its raw vulnerable-log digest differed only because
  `norm()` hardcodes the `/home` prefix; with `/tmp` substitution and the
  compile-time source path it reproduced `599ab1f0…` byte-for-byte, controls
  `e3b0c442…`. Source-bound at `packet.c:523,538` and `author.c:75,77`.
  No refutation; rung 5 still UNKNOWN. Minor NIT to the harness author:
  the `stack_overflow` PASS line embeds a volatile ASan PID/stack address,
  so "identical PASS lines" is not literal across replays (all nine
  substantive checks match). Replay commands remain:
  `bash lab/frontier/tacplus2shell/harness/run.sh` then
  `bash lab/frontier/tacplus2shell/harness/run_wire.sh`; full stage
  `reports/frontier-tacplus2shell.md`.
- Next bounded experiment to move up a rung: build the vulnerable pin without
  ASan (`./configure --debug --minimum tac_plus-ng mavis`), start it on a
  plant-started loopback listener and break at `author.c:77` under gdb after
  the crafted packet to dump the `memcpy()` source and `cmdline`, with a
  two-connection priming variant testing the advisory's `calloc()`-reuse
  claim. Fixed pin and safe packet stay as controls; a live-daemon readback
  would promote rung 4 from harness to live process but still would not be
  rung 5 without a pointer or command side effect.
