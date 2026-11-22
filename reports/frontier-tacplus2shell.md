# Frontier brief: tac_plus-ng — CVE-2026-130875 (tacplus2shell)

Status W120 (2026-11-22): screened in, driven locally to rung 1/2 on a real
daemon wire and rung 3/4 on both wire and verbatim-function harness, staged as
`tacplus2shell`. Duplicate check before provisioning: no prior
`reports/frontier-*tac*`, no tacplus window, charter or mind on the tape. This
find outranks the parked FRR/llama.cpp/Libreswan tail because it is a
network-facing server with a one-line fix and a documented single-packet wire
trigger. Admission remains the operator's call; wake units and full-flag sync
stay with the person.

## 1. Verified ground truth

- Claim: CVE-2026-130875 / GHSA-v384-f7x8-f7c7, "tac_plus-ng before commit
  `d8493e0` contains a stack-based buffer overflow that allows clients holding
  the TACACS+ shared key to overflow a stack buffer due to an operator
  precedence error in `author_pak_looks_bogus()` and
  `accounting_pak_looks_bogus()`" (CWE-783 / CWE-121). High, CVSS v4 7.7
  (`AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H`). Published 2026-11-17 by
  VulnCheck; advisory published by MarcJHuber the same day. No version numbers
  are asserted by the vendor: the affected range is
  `<= commit e20ac82`, fixed at `d8493e0d6420b91737fa34c2cd7bbd365d023b5b`;
  the advisory's own PoC was built from `929671c`.
- Sources read (read-only provisioning; no probe of any external system):
  `https://github.com/tacplus-ng/event-driven-servers/security/advisories/GHSA-v384-f7x8-f7c7`,
  `https://api.osv.dev/v1/vulns/CVE-2026-130875`, the fix commit and its
  `.patch`, and the pinned raw `tac_plus-ng/packet.c` and `author.c` blobs.
- Pins used here: vulnerable `929671c22ff9f390f22decd7eb97dffaece8aebe`
  (2026-11-13, the advisory's PoC base), fixed
  `d8493e0d6420b91737fa34c2cd7bbd365d023b5b` (2026-11-17). Both blobs were
  checked in the clone: vulnerable `packet.c:523,538` has the unparenthesized
  expression; fixed `packet.c:523,538` has the two added parentheses. The
  pinned `author.c:66-97` (`eval_args()`) is byte-identical on both pins —
  the fix is entirely in the validator.
- Access prerequisites stated by the advisory: attacker can reach the TACACS+
  port from an address matching a configured host entry, knows that entry's
  shared key (or the entry has `key = ""`), and names a user whose profile
  permits `service=shell`. **No user password is required.** Keep this
  "key-holding client, not anonymous pre-auth" ceiling honest at admission;
  CVSS `PR:L`, `AT:P` agrees.
- The advisory further claims full code execution via a five-connection chain
  (heap pointer leak, groom, session-pointer redirect, libc leak, second groom,
  `cleanup_session()` → `mem_destroy()` calling `system()` through a fake
  `mem_t`, yielding `uid=0(root)`). That is a **claim, not a local
  observation**. Nothing in this lab reached pointer control or command
  execution.

## 2. Source-bound mechanism and fix

In the vulnerable pin, `author_pak_looks_bogus()` (`tac_plus-ng/packet.c:511-524`)
sums the argument-size table until `len >= datalength`, then returns:

```c
return (i != pak->arg_cnt) || (ctx->host->bug_compatibility & CLIENT_BUG_HEADER_LENGTH) ? (len > datalength) : (len != datalength);
```

`?:` binds less tightly than `||`, so this is
`((i != arg_cnt) || flag) ? (len > datalength) : (len != datalength)`. When the
loop stops early with arguments still unread, `i != arg_cnt` is true and the
function accepts any packet with `len <= datalength` — including a size table
whose total exceeds the real payload. `accounting_pak_looks_bogus()` repeats
the same statement at `:538`.

`eval_args()` (`tac_plus-ng/author.c:66-97`) then walks every declared argument.
`a` advances by attacker-supplied sizes, so arguments past the packet are read
from adjacent heap memory; any that begin `cmd=`, `cmd*` or `cmd-arg=` are
`memcpy()`d into `cmdline`, a stack VLA of `session->ctx->in->length` bytes
(`author.c:69,75,77,84`). `mem_alloc()` uses `calloc()` (`misc/memops.c:229`),
which is the advisory's stated route for placing chosen bytes behind a small
buffer on a reused allocation.

Upstream fix `d8493e0` changes only those two lines, adding one pair of
parentheses each:

```c
return (i != pak->arg_cnt) || ((ctx->host->bug_compatibility & CLIENT_BUG_HEADER_LENGTH) ? (len > datalength) : (len != datalength));
```

Now `i != arg_cnt` alone makes the packet bogus, so a truncated size table is
rejected before `eval_args()` runs.

## 3. Measured evidence (this lab)

All builds and instances are under `lab/frontier/tacplus2shell/`, source clone
at the two pinned commits, build `./configure --asan --minimum tac_plus-ng
mavis && make`. Instances bind only a plant-started 127.0.0.1 listener passed
as fd 0 (inetd-style), never a wildcard bind. Inventory in `PROVENANCE.md`.

### 3.1 Real daemon, wire trigger (`harness/run_wire.sh`, 0 failures)

- Vulnerable pin, one crafted AUTHOR packet (version `0xc0`, type 2, seq 1,
  session `0x11223344`, body 267 bytes: method 6, priv 1, authen_type 1,
  service 1, user/port/rem_addr 0, `arg_cnt=255`, size table `4` + 254×`0xff`,
  data `cmd=`, obfuscated with the pinned `md5_xor()` pad):
  `AddressSanitizer: heap-buffer-overflow`, `READ of size 1`, **243 bytes after
  a 323-byte region**, top frames `eval_args` at `author.c:75` → `author` at
  `:141` → `tac_read` at `packet.c:892`; daemon `rc=-6`, no reply. The 323-byte
  region was allocated by `mem_alloc()` → `calloc()` at `misc/memops.c:229`.
- Fixed pin, same packet: no ASan report, daemon `rc=0`, 57-byte TACACS+ reply
  (`c0020200…`) — the validator rejects it.
- Vulnerable pin, safe packet (size table `4`, `arg_cnt=1`, payload `cmd=`):
  no ASan report, daemon `rc=0`, 18-byte reply.
- Two in-tree replays produced identical normalized hashes: the vulnerable log
  hashes `599ab1f0d59faa209f09b721079467df6f363d46a69859797f8ecfeca583b78c`
  in both; both clean controls hash the empty-log digest
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
  Normalization strips PID, addresses, BuildId and the repo prefix.

### 3.2 Verbatim-function chosen-byte harness (`harness/run.sh`, 9 PASS / 0 FAIL)

`harness/gen.py` extracts `author_pak_looks_bogus()`,
`accounting_pak_looks_bogus()` and `eval_args()` byte-for-byte from each pinned
blob into `fn.inc`; only structs/macros, allocation stubs and the driver are
local. A smaller crafted table (`arg_cnt=3`, sizes `4,12,0`, payload `cmd=`,
body `datalength=15`) passes the buggy validator (`validator_bogus=0`) and is
rejected by the fixed pin (`validator_bogus=1`). Bytes placed at heap offsets
past the accepted packet are copied into `cmdline` at offsets 0..7:

- chosen fill `0x41` → `cmdline=AAAAAAAA`; fill `0x5a` → `cmdline=ZZZZZZZZ`.
  The bytes are chosen, not incidental.
- gcc and clang ASan agree on the chosen bytes; the fixed pin performs no copy
  (`cmdline_len=0`) and is ASan-clean.
- A 40-byte oversized copy into the 15-byte VLA produces an ASan
  `dynamic-stack-buffer-overflow` on the vulnerable pin, the direct consequence
  the advisory describes.

Two in-tree replays of `harness/run.sh` were 9/9 PASS with identical PASS
lines. The `cmdline` content here is a harness observation of the verbatim
pinned function, not a daemon-side readback.

## 4. Rung-4 feasibility and honest ceiling

Rung 1 (deterministic trigger) and rung 2 (size accounting accepts a table that
sums past the payload) are established on a real daemon over a loopback wire.
Rung 3 is an ASan-confirmed heap OOB **read** on that same real wire, plus an
ASan-confirmed stack **write** in the verbatim-function harness. Rung 4 is
chosen bytes at chosen offsets, demonstrated in the harness; the daemon-side
OOB read is at the exact `eval_args()` line that feeds `memcpy`, but no
daemon-side readback of chosen `cmdline` bytes was performed.

Ceiling: no allocator grooming was replayed on the live daemon, no pointer
control, no function-pointer overwrite, no benign marker execution, no
command and no rung 5. The advisory's `system()`/root chain is unverified. ASan
also aborts at the first OOB read, so the natural daemon path stops before the
`memcpy`; a plain-build + debugger readback is the cheapest way to close that
gap. The required shared key keeps this in the "key-holding client" class even
though the service is network-facing.

Tractability: high — two pinned blobs, a one-line fix, a plain C build with no
external runtime, and a documented packet that faults the real binary. This
outranks FRR CVE-2026-129217 (OOB read), llama.cpp CVE-2026-118375 (RDMA) and
Libreswan CVE-2026-94453 (non-default `listen-tcp` plus a UAF).

## 5. Cheapest next experiment to move up a rung

Build the vulnerable pin **without** ASan (configure `--debug` for `-g -O0`),
start it on a plant-started loopback listener, and use gdb to break at
`author.c:77` after sending a crafted packet whose argument table points into
attacker-arranged heap bytes; dump `cmdline` and the `memcpy` source bytes to
show chosen bytes in the live process. A two-connection variant (a large
priming packet carrying a marker, then the short trigger) tests the advisory's
`calloc()` reuse claim; the fixed pin and a safe packet stay as controls. That
would upgrade rung 4 from harness to live daemon; it still would not be rung 5
without an observed pointer/command side effect.

## 6. Candidates parked / screened this wake

- Web-screened and rejected as owned or out of scope: Ruby `Regexp#to_s`
  GHSA-7whj-cfh7-xgm4 (`ruby2shell`), FreeSWITCH GHSA-f73w-xph4-pjp3
  (`freeswitch2shell`), Babelfish GHSA-vq28-vgj3-r26w (`babelfish2shell`),
  shairport-sync GHSA-vfxr-hxq9-9h35 (`shairport`), Netty CVE-2026-116539
  (`netty2shell`), Valkey GHSA-f4q9-j22m-xqq9 (screened out), Git
  CVE-2026-105437 (screened out), SonicWall CVE-2026-82308 (proprietary,
  no source). libheif GHSA-hpg4-g2gc-pq42 (image decoder, less network-facing)
  and opencryptoki GHSA-9f33-5pv5-wfcf (crypto token, not a wire service) rank
  below this find and remain unprovisioned.
- FRRouting CVE-2026-129217, llama.cpp CVE-2026-118375 and Libreswan
  CVE-2026-94453 remain queued below this find, unchanged.
- Do not duplicate the admitted list in `walls/frontier.md`; NGINX/Node belong
  to other minds.
