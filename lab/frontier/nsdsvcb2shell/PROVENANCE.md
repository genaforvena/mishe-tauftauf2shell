# nsdsvcb2shell provenance and observations (2026-11-27 W323)

All fetches were read-only provisioning from NLnet Labs public URLs. All
execution stayed in this lab directory; no socket, external target, scan or
probe was used. The harness calls the real `read_svcb_rdata()` from the built
NSD objects: no sink code is copied or reimplemented.

## Claim sources and pins

- Vendor advisory `https://www.nlnetlabs.nl/downloads/nsd/CVE-2026-12244.txt`;
  CVE record `https://www.cve.org/CVERecord?id=CVE-2026-12244`; vendor patch
  `https://www.nlnetlabs.nl/downloads/nsd/patch_CVE-2026-12244.diff`; brief
  `reports/frontier-nsdsvcb2shell.md`. Claim: NSD 4.14.0–4.14.2 secondary,
  crafted SVCB RR with `rdata` size 65512 in AXFR, controlled heap write of
  up to 65509 bytes, fixed in 4.14.3. Finder credited Qifan Zhang.
- Vulnerable tarball `https://nlnetlabs.nl/downloads/nsd/nsd-4.14.2.tar.gz`
  → `pins/vuln.tar.gz`, SHA-256
  `2bff57349841844d7560e76d7bd70b6bd6f4c462cdaa6d57b8e83d1e14dd22d6`.
- Official fixed tarball `https://nlnetlabs.nl/downloads/nsd/nsd-4.14.3.tar.gz`
  → `pins/fixed.tar.gz`, SHA-256
  `9629ad64d9c1b019bbe22296d5148d7ae65f588ce265a6424750740f052bb12b`.
- One-line vendor patch → `pins/fix.patch`, SHA-256
  `6d145e23945777a077149e045fc6ac1f76c25d8c3d55fac9bb71a3734aa436d1`;
  `patch -p1` applies cleanly to `pins/vuln.tar.gz`. The fixed control used
  for the differential is this one-line patch on 4.14.2, not the 4.14.3 source
  (which also contains unrelated APL fixes). `fixed/rdata.c` was checked to
  carry the same `size_t size;` declaration.

## Source-bound mechanism (pinned bytes)

`vuln/rdata.c:3279-3321` declares `uint16_t size` at :3285. With a root
target name, `length = 3` and `svcparams_length = rdlength - 3`. At :3309
`size = sizeof(struct rr) + 2 + sizeof(void*) + svcparams_length` is truncated
modulo 65536; `region_alloc` at :3310 receives the wrapped size. The harness
printed `sizeof_rr=24` on this build: with `rdlength=65512` it computes
`svcparams_length=65509`, `uint16_size=7`, `unwrapped_size=65543`. The
`(uint8_t*)rdata + 10` destination then receives 65509 attacker bytes via
`buffer_read_at` (:3314-3318; inlined at :3317 in the ASan frame).

## Reproduction

`bash run-all.sh` (from a clean archive: `bash bootstrap.sh` first) rebuilds
three trees from `pins/vuln.tar.gz`:

| Tree | Flags | Purpose |
|---|---|---|
| `vuln/` | `-O1 -g -fsanitize=address -fno-omit-frame-pointer` | vulnerable ASan |
| `patched/` | same, plus `pins/fix.patch` | one-line-fixed control |
| `plain/` | default `-g -O2 -flto` | chosen-byte observation |

The crafted wire is 2-byte priority `0x0001`, a one-byte root target, then
`rdlength-3` svcparams bytes with value `seed + k`. `rdata+10+k` therefore
receives wire byte `3+k`, i.e. `seed + k` modulo 256.

Observed on 2026-11-27 W323, pinned bytes, all outputs in `runs/`:

- Vulnerable ASan attack (`65512`, seed `0x41`): rc 1,
  `AddressSanitizer: heap-buffer-overflow`, `WRITE of size 65509`, stack
  `buffer_read_at buffer.h:437` → `read_svcb_rdata rdata.c:3317`,
  `0 bytes after 4096-byte region`, allocation frame `region_create
  region-allocator.c:135`. Region size 4096 is `DEFAULT_CHUNK_SIZE`, so the
  write exits the allocator chunk after 4086 attacker bytes.
- Vulnerable ASan safe input (`512`): rc 0, ASan-clean.
- Patched (one-line fix) ASan attack (`65512`): rc 0, `rc=65512`, ASan-clean.
  Patched safe input: rc 0, ASan-clean.
- Plain vulnerable attack with `NSD_SVCB_VERIFY=1`: rc 0 and every probed
  offset matched the chosen byte for seeds `0x41` and `0x5a`: offsets
  10, 11, 100, 4096, 8192, 16384, 32768, 65508 (values `0x41/0x5a`,
  `0x42/0x5b`, `0x9b/0xb4`, `0x37/0x50`, …, `0x1b/0x34`).
  `fflush`/stdio allocation after the overflow aborts with
  `malloc(): corrupted top size`; the probe therefore writes to stderr only.

## Rating and limits

R1 (deterministic trigger), R2 (allocator state corrupted in plain build),
R3 (ASan-confirmed 65509-byte heap overflow at the pinned sink),
R4 LIMITED (lab-chosen bytes verified at selected offsets up to `rdata+65508`
in the vulnerable plain build; fixed and safe controls clean). R5 NOT
CLAIMED: no remote/AXFR path was exercised in this wake, no named consumer,
no pointer control, no marker or command side effect, no ASLR grooming.
The direct sink harness is not the network path; the advisory's configured-
primary trust requirement is unchanged. The loopback AXFR path is the next
experiment for the target mind.

No external systems were contacted with probes; fetching tarballs, CVE data
and the vendor patch is provisioning only.
