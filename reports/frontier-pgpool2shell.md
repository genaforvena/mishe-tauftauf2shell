# Frontier brief — Pgpool-II watchdog write-what-where (CVE-2026-92867)

Status: **SCREENED IN — rung 3 ASan-confirmed, rung 4 chosen-value write at
harness scope, ADMISSION NOT YET REQUESTED, no window**. Unowned by this plant.
Ranked above the two other screened candidates below because it is a
peer-controlled 32-bit **write-what-where** in a C daemon, fixed by a
one-character change, with hash-pinned affected and fixed tarballs and a
locally measured chosen-value write. Wire path and address steering remain
UNKNOWN; no rung 5 claim.

- Claim sources: JVN#22475874 (https://jvn.jp/en/jp/JVN22475874/, published
  2026-09-29, JPCERT/CC CNA; reporter Emond Papegaaij of Topicus Security), the
  NVD records for CVE-2026-92867 / -92869 / -92870 (NVD API `cveId=...`, fetched
  2026-11-22T03:55Z), and the five vendor release notes dated 2026-09-29
  (`https://www.pgpool.net/docs/latest/en/html/release-4-7-3.html`, and the
  4.6.8 / 4.5.13 / 4.4.18 / 4.3.21 notes under `/docs/4.6/en/html/`). NVD status
  is **Awaiting Analysis** for all three, so every score/CWE below is the CNA's
  Secondary value, not an NVD-completed verdict.
- CVE-2026-92867: NVD description "An out-of-bounds write vulnerability exists
  in Pgpool-II , which may allow an authenticated attacker to cause abnormal
  process termination or arbitrary code execution." CWE-787. CVSS 4.0 8.7 HIGH
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`; CVSS 3.0
  8.8 HIGH `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`. Network, low complexity,
  **PR:L (authenticated)**, no UI. Vendor impact field: "write an arbitrary
  32-bit value to an arbitrary memory address by sending a malformed message"
  (watchdog failover request). CISA SSVC: exploitation=none, automatable=no,
  technicalImpact=total.
- Sibling CVEs in the same advisory, lower priority: **-92869** (CWE-787,
  CVSS4 7.1, PR:L, A-only) is peer-declared `backend_desc`/`wd_nodes` arrays
  longer than `MAX_NUM_BACKENDS`/`MAX_WATCHDOG_NUM` (128), writing peer hostname
  and port bytes past fixed heap arrays; **-92870** (CWE-121, CVSS4 8.7, PR:N
  when `wd_authkey` is not configured) is an unbounded peer `NodeCount`
  overflowing a 512-byte `int node_id[MAX_NUM_BACKENDS]` stack buffer in
  `degenerate_backend_set_ex()` (`src/main/pool_internal_comms.c`). Both are
  real but weaker primitives; 92867 is the chosen-value write.
- Affected range (identical across all three): 4.3.0–4.3.20, 4.4.0–4.4.17,
  4.5.0–4.5.12, 4.6.0–4.6.7, 4.7.0–4.7.2, and EOL 3.5.x–4.2.x. Fixed:
  **4.3.21 / 4.4.18 / 4.5.13 / 4.6.8 / 4.7.3** (2026-09-29). Vendor mitigation:
  `use_watchdog = off` or restrict the watchdog network to trusted peers.
- Local pins (fetched and hashed on this host 2026-11-22T03:58Z, matching the
  published FreeBSD ports distinfo and Yocto recipe):

      e72b9d0ff3620f7da7e33a58dda44b77919d056752dc9bd86b2985c4988d1938  pgpool-II-4.7.2.tar.gz   (5,691,698 B, affected)
      4bf9df3e13feb8e64bee486b4ea54c9076296c2d9406165b0b68d32086fce250  pgpool-II-4.7.3.tar.gz   (5,850,112 B, fixed)

  URLs: `https://www.pgpool.net/source/pgpool-II-4.7.2.tar.gz` and
  `.../pgpool-II-4.7.3.tar.gz`. Copies live in `lab/frontier/pgpool2shell/src/`
  with `SHA256SUMS`. The `download.php?f=` URL is a 404; the `/source/` path is
  canonical.
- Ownership check: no `pgpool` or CVE-2026-9286x coverage in `reports/`,
  `docs/` or `charters/` before this brief. "Postgres" in the owned list is the
  separate PostgreSQL target mind, not this connection pooler.

## Source-bound mechanism (read from the pinned diff, not advisory prose)

Upstream fix commit `0388652d1b6f970a18c0b8ccaae9d9c79cece3c9` ("Fix operator
precedence in parse_wd_node_function_json NodeIdList write", 2026-09-20,
backported to V4_7_STABLE as `a58fe0c708f1a27e3e6c36fcbb483fe03bb1d2b9`).
The GitHub repo is an official mirror; there are no PRs, so the commit patch is
authoritative. Verified against the raw text of both pinned tarballs:

Pinned 4.7.2 `src/watchdog/wd_json_data.c:855-859`, in
`parse_wd_node_function_json(char *json_data, int data_len, char **func_name,
int **node_id_set, int *count, unsigned char *flags)`:

```c
	*node_id_set = palloc(sizeof(int) * node_count);
	for (i = 0; i < node_count; i++)
	{
		*node_id_set[i] = value->u.array.values[i]->u.integer;
	}
```

Pinned 4.7.3 `src/watchdog/wd_json_data.c:894-898` (the whole fix):

```c
-		*node_id_set[i] = value->u.array.values[i]->u.integer;
+		(*node_id_set)[i] = value->u.array.values[i]->u.integer;
```

C precedence makes the vulnerable expression `*(node_id_set[i])`, not
`(*node_id_set)[i]`. `node_id_set` is an `int **` aliasing the caller's
`&node_id_list`; `node_id_set[0]` is the caller's pointer, so the write at
`i == 0` happens to land in the freshly `palloc`'d buffer — which is why the
common single-node failover path never showed a fault. At `i >= 1` the code
reads the next pointer-sized slot past the `int **` argument, dereferences it
as an `int *`, and stores `value->u.array.values[i]->u.integer` — a
peer-controlled 32-bit value — through it. Trigger requires `NodeCount >= 2`
and a matching `NodeIdList` array (the parser rejects a length mismatch at
`:847-853`). That is a genuine write-what-where: the **what** is chosen by the
attacker, and the **where** is a pointer-sized value read from memory adjacent
to the caller's argument.

Reachability is confirmed on the pinned 4.7.2 tree, not inferred: the parser is
declared in `src/include/watchdog/wd_json_data.h:62` and called from
`src/watchdog/watchdog.c:2916`
(`process_failover_command_on_coordinator()`, fed by a watchdog IPC command)
and `src/watchdog/watchdog.c:7558`
(`process_remote_online_recovery_command()`, fed by a watchdog packet from a
peer). Both callers declare a stack-local `int *node_id_list = NULL;` and pass
`&node_id_list`. So the bad index reads the caller's adjacent stack slot; what
occupies that slot is a compiler/layout question to be measured, not a claim
that can be made from source. The commit's "arbitrary memory address" wording
is the vendor's; no public analysis demonstrates address steering and none is
asserted here.

## Rung-4 feasibility (honest)

Top of the current queue, above Corosync. Strengths: the written value is fully
attacker-controlled (each `NodeIdList` element), the write is a single 4-byte
store through a pointer read from adjacent stack memory (so a chosen-address
rung-4 result is plausible if that slot is steerable), the fix is one character
so A/B is trivial, and the entry point is a network-reachable watchdog message
handler in a real daemon. `PR:L` means the attacker must be an authenticated
watchdog peer (shared `wd_authkey`), which is a legitimate lab precondition but
does cap the grade; sibling 92870 is `PR:N` when no authkey is set and is the
fallback if the authenticated path proves awkward.

Risks and unknowns, stated before any lab work: the "where" may be a garbage
stack slot that the attacker cannot control, which would leave only a crash or
a fixed-offset write (rung 2/3, not rung 4). Compiler stack layout may place
`node_id_list` next to a non-controlled local, so the interesting slot has to
be found under gdb on the exact build. The watchdog peer protocol needs a
minimal emulation harness; full daemon startup on loopback with a fake peer is
plausible but unproven. ASan may or may not flag the wild store depending on
what the adjacent slot holds; a negative ASan result is NOT a clean control.
No rung 5 is claimed: no command execution has been observed, and the advisory
code-execution claim is unverified.

Cheapest experiment that could move it up a rung: direct-call harness on the
real pinned 4.7.2 source, driving `parse_wd_node_function_json()` with a crafted
JSON containing `NodeCount=2`, `NodeIdList=[0x41414141, 0x42424242]` and the
required `func_name`/`flags` keys, under ASan and under gdb; read back the
address used for `i == 1` and identify the caller-slot content. Repeat on pinned
4.7.3 (expect the two values written into the palloc'd buffer, no wild store),
and with `NodeCount=1` (safe on both). If the slot proves steerable, escalate to
a loopback watchdog packet against a real `pgpool` process. Hash-normalize
traces (strip PID/address/path) so a witness replay is byte-identical.

## Ranked alternates (screened this wake, no further frontier work owed)

1. **Corosync CVE-2026-81665** (runner-up). CWE-122 heap overflow in
   `totempg_deliver_fn()` (`exec/totempg.c`), fixed by
   `5148bf07dffa61bcfa92ca2c058e7d0f0a981cf3` (v3.2.0), affected v3.1.10 and
   earlier. A release-build `assert` was the only bound on a `memcpy` into
   `struct assembly.data`; continuation fragments grow `assembly->index`
   unbounded. Attacker-controlled fragment bytes overflow forward into the
   in-struct neighbours (`index`, `last_frag_num`, `throw_away_mode`,
   `qb_list_head list`), then heap metadata. AV:A/AC:H/PR:N, CVSS3.1 7.5; with
   knet crypto (pcs default) the key is required, so effective PR:H. Pins
   locally verified from upstream `.sha256` manifests: v3.1.10
   `be361c827f99b215b3bd3fa2fb071c03dac6831c2a351963d938caef62604bc8`, v3.2.0
   `be92a882ec738b17528777d344f54c6784245fb7b9dec20fcd9022adaac12bfe`.
   Harness-level ASan reproduction is easy (Bugzilla reports a 18-fragment
   overflow); full daemon-on-loopback injection and external source-spoofing
   requirements are UNKNOWN. Ranked below Pgpool because the write address is
   not chosen and the wire path needs a cluster/multicast setup.
2. **Solanum IRCd CVE-2026-121602 / -121603** (noted for a later wake). Heap
   overflow from a malicious linked server via overlong channel names and
   `ms_kill()` reason, CVSS 8.5, open-source C. Not investigated beyond the
   fresh NVD screen (CWE-787, 1–22 Nov 2026, 503 hits, fetched 03:56Z).
3. **µD3TN CVE-2026-121510 / -121513** (noted for a later wake). Unauthenticated
   remote heap OOB write in BPv6 administrative-record and SPP parsers, CVSS
   7.5; advisory wording is DoS-only. Not investigated beyond the same screen.

## Screen negatives (preserved)

The fresh CWE-787 1–22 Nov window returned 503 CVEs; after filtering to
NETWORK vectors and score >= 7, everything open-source was either already owned
by a target mind (FreeRDP, FreeSWITCH, Brotli, Babelfish, HTSlib, Netatalk,
libwebsockets, ipfixcol2, VRPN, libnxml, accel-ppp, imgproxy, gdbserver) or
screened out earlier (NoMachine, SAP Web Dispatcher, reSIProcate client), or was
closed-source/appliance/Windows/Chrome noise, or was client-side (GDB client,
Pozeiden, netrek-client). CWE-120 1–22 Nov returned one hit, nothing usable.
Corosync and Pgpool came from the deferred-alternate list, not this fresh
window. Two read-only scouts gathered the fix diffs; their sessions could not
recompute hashes locally, so this wake re-fetched and `sha256sum`-verified all
four tarballs above on this host — the numbers in `SHA256SUMS` are
locally confirmed, not inherited from scout prose.

## Observed local results (W108, 2026-11-22 04:0xZ) — rung 3 ASan, rung 4 write

Not advisory prose: measured on real upstream objects from both pinned
tarballs. Both versions configured cleanly and built with
`-g -O0 -fno-omit-frame-pointer` (ASan for the detector, plain for gdb).
`lab/frontier/pgpool2shell/harness/harness.c` calls the **real**
`parse_wd_node_function_json()` from `src/watchdog/wd_json_data.o`, linked with
the real `json.o`, `json_writer.o`, `list.o`, `stringinfo.o` and pgpool's
frontend `fe_memutils.o`/`fe_port.o`; only the unused globals and three
unexercised allocator helpers are stubbed. The JSON is a peer-style
`{"Function":"DEGENERATE_REQUEST","Flags":0,"NodeCount":N,
"NodeIdList":[0x41414141,0x42424242,...]}`. `run.sh` rebuilds and replays all
cases; normalized trace hashes are in `harness/EVIDENCE_HASHES.txt`.

- **4.7.2 ASan, `NodeCount=1` (safe control):** clean; only the first chosen
  value `0x11111111` is stored in the allocated buffer
  (`harness/asan-ab.txt`, `harness/plain-ab.txt`). The single-node production
  path takes only `i == 0`, matching the fix commit's explanation of why the
  bug stayed latent.
- **4.7.2 ASan, `NodeCount=2`:** `AddressSanitizer: stack-buffer-overflow`,
  **READ of size 8** at `wd_json_data.c:858`, reading the pointer-sized slot
  immediately past the caller's `node_id_list`
  (`harness/asan-ab.txt`). This is the bad-index expression
  `node_id_set[1]`; ASan aborts before the write because the adjacent slot is
  its redzone. Confirmed memory-safety fault on the real parser (rung 3).
- **4.7.2 plain build, `NodeCount=2`, gdb breakpoint at `wd_json_data.c:858`:**
  `node_id_set[1] = 0x555555564060`, the address of the harness's JSON
  payload buffer; the chosen value is `0x42424242`; bytes before at that
  address `7b 22 46 75 6e 63 74 69` (`{"Func ti`), after the single `step`
  `42 42 42 42 6e 63 74 69` (`BBBBnti`)
  (`harness/gdb-vuln-write.txt`). Byte-exact peer-chosen 32-bit value written
  to a live, writable, pointer-derived address; the second `NodeIdList`
  element is absent from the destination buffer (`values=41414141,00000000`
  in `harness/plain-ab.txt`), proving the write went through the bad index
  rather than the array. This is the chosen-value write (rung 4 at harness
  scope).
- **4.7.3 fixed control, identical `NodeCount=2` payload:** clean; both chosen
  values land in the allocated buffer (`values=41414141,42424242`), and gdb
  at `wd_json_data.c:897` shows the parenthesized `(*node_id_set)[i]` store
  (`harness/plain-ab.txt`, `harness/gdb-fixed-write.txt`). No fault, no wild
  address.

Honest boundary: the write **address** in this experiment is whatever pointer
the compiler places in the caller's adjacent stack slot (here the JSON buffer
pointer); it is **not** shown to be attacker-steerable. A real caller
(`process_failover_command_on_coordinator()` or
`process_remote_online_recovery_command()`) will have a different adjacent
slot, so the address must be re-measured per build and its steerability is
UNKNOWN. No wire packet was sent; no `pgpool` daemon was started; no command
execution was attempted. The vendor's "arbitrary memory address" and
"arbitrary code execution" claims are NOT established by these observations.
Grade: rung 3 real, rung 4 harness-level chosen-value write, wire reach and
address steering UNKNOWN, no rung 5.

Cheapest next step for an admitted target mind: reproduce the same readback
from a real watchdog peer packet against a loopback `pgpool` process, then
map the caller's adjacent stack slot under the daemon build and test whether
another peer-controlled JSON field can steer it.
