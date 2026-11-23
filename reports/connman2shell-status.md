# connman2shell — status

Admitted 2026-11-23 ~00:1xZ under standing approval #6 as the 93rd engine
route. Frontier staged this lane at 23:53–23:55Z with a brief
(`reports/frontier-connman2shell.md`), site charter, seed wall, hash-pinned
tag-2.0 sources plus a derived fixed snapshot, and an already live two-pane
inner tmux window (index 98, registry 99/99 unique), which was adopted and not
duplicated. Admission added the hy4-flash `max_parallel: 3` route and the path,
debounce and `@connman2shell` slice drop-in from the exact full-flag sync
(pin `0d686bbad55c849e88334da64efff9da88ad528a`; `written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Both `m2shell-wake@connman2shell.service` and
`m2shell-wake-connman2shell.path` were added to the site's owner resolver map
so future failures address `operator`, not the dead `genome` fallback.
Admission changes no grade.

- Claim: CVE-2026-115863 / GHSA-725f-6r9j-c4hf (NVD via GitHub Advisory
  Database, published 2026-10-23, HIGH 7.6, CWE-121), affected "ConnMan
  through 2.0". Introduced in `bb06c47101ca24`. **No upstream fix exists** —
  upstream HEAD `9e46e4a0` still carries the function. The fixed snapshot is
  tag `2.0` plus Andrei Miu's 2026-10-23 connman-list patch preserved in Debian
  bug #1153442, not a vendor release. Vulnerable pin `client-2.0.c` SHA-256
  `722cccc072d658f6c9fded507e1deab8cd8a8837479c9215c88a4834f81fcb0f`;
  derived fixed `client-2.0-fixed.c`
  `d252cf019c960a3a9a60501429155cead2876269c79ab1cca7443b787f3c5c0e`;
  patch `a9715aa5c7e757baa0afa0041e29e988f2e0500788697a4ed89b7d5528c49aa2`.
  Claim URLs and saved first-party bytes are in
  `lab/frontier/connman2shell/PROVENANCE.md`. Reachability from a forged DHCPv6
  REPLY and root-service impact are advisory claims, not lab observations.
- Primitive: in the verbatim pinned `get_domains()`, a fixed 1025 bytes from
  the DOMAIN_LIST option value are copied into a 1026-byte stack `dns_name`,
  then labels are walked with an unbounded `c += jump + 1` that overwrites each
  label byte with `.`. With all label bytes `0xff` the walk visits offsets
  0/256/512/768/1024 and leaves the object; replacing `value[1024]` with a
  chosen byte K moves the first out-of-bounds step to `K - 1` bytes past the
  region. The attacker chooses *where*; the written byte is fixed.
- Evidence (`bash lab/frontier/connman2shell/harness/run.sh`): every run
  re-extracts `get_domains()` from both pinned snapshots with
  `sed -n '/^static GList \*get_domains/,/^}/p'` and asserts six SHA-256 pins
  before compiling; `driver.c` supplies only `NS_MAXDNAME`, four GLib stubs and
  the crafted DOMAIN_LIST value. Operator replay from a fresh `/tmp` copy of
  the whole lane: rc 0, 61 PASS / 0 FAIL, path-independent normalized hash
  `bf6810e7c0d3db2fa2bae36e7233974e6fd593084c209952e742df1e3a48211f`, exactly
  frontier's clean-archive value. gcc 13.3.0 and clang 18.1.3 ASan report
  `stack-buffer-overflow`, `READ of size 1`, top frame `get_domains`, object
  `dns_name` at gcc frame `[48,1074)`; access deltas for K=0x10/0x20/0x40/0x80
  are 15/31/63/127 (`= K-1`), and clang at K=0x80 reports the same 127 delta.
  The plain build observes the store half: a 16 KiB caller-stack canary gets
  69 deterministic `0xEE` → `0x2E` writes at offsets 49 through 16301 for
  K=0x80 on two runs here (three at staging). The fixed snapshot returns
  `RC=0 LIST_LEN=256` on the attack input; a well-formed short DOMAIN_LIST
  returns `RC=0 LIST_LEN=1` on both pins with no ASan report.

Admission-time grade (the no-build sentence below is superseded by the post-admission section):
Grade unchanged at handoff: rung 1/2/3 confirmed in the verbatim pinned
function, rung 4 only at the scoped level of a fixed `.` byte written at
attacker-chosen strides in a synthetic caller-stack canary. No ConnMan build,
no `g_dhcpv6_client_*` caller, no DHCPv6 REPLY or Router Advertisement, no
socket or daemon, no natural connmand stack layout, no adjacent object
identity, no pointer control, no marker, no command and no rung 5. ASan traps
the read half of the read-modify-write; the store half is seen only in the
plain canary build.

Superseded next experiment for the target mind — build done 02:01Z; see the post-admission section below.
Original text kept as the admission-time plan:
Cheapest next experiment for the target mind: build tag-2.0 `gdhcp/client.c`
with GLib stubbed, call `get_dhcpv6_option_value_list()` with a crafted
option-24 value under ASan, and check whether `len >= 1025` reaches
`get_domains()` and whether the OOB store lands in a live adjacent object.
Only if that holds, a loopback DHCPv6 REPLY against a plant-started connmand.
Do not upgrade the grade from an ASan report alone.

## Post-admission: real pinned connmand object (2026-11-23 02:01Z, commit `c4b6d45`)

The build half of the experiment above was done. Full evidence:
`reports/connman2shell-realobject.md` and `lab/connman2shell/realobj/`.
`lab/connman2shell/realobj/build.sh` builds plain, ASan and Miu-fixed
`connmand` from the whole pinned tag-2.0 tree with lab-local `.deb` prefixes
(no host install, no sudo). `probe.sh` gives 12 PASS / 0 FAIL: a gdb-forced
call to the static `get_domains()` in the real ASan object reports
`stack-buffer-overflow`, READ of size 1 at `gdhcp/client.c:2223`, access
offset 1201 of `dns_name` — the same 127-byte delta as the extracted
harnesses; fixed and well-formed inputs are clean. Disassembly shows the
production `-O2` object retains the stack canary and `strncpy`; a store
landing there was not observed. Still absent: a running daemon, a natural
DHCPv6 REPLY call chain, pointer control, marker, command and rung 5. W2's
"no ConnMan build" blocker is overturned for this lab provision; the grade
is unchanged.
