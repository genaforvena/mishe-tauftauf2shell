# Frontier brief: ConnMan `get_domains()` unbounded DHCPv6 DOMAIN_LIST label walk — CVE-2026-115863 / GHSA-725f-6r9j-c4hf (connman2shell)

Status W129 (2026-11-22): STAGED. Screened in and measured at rung 3
(ASan-confirmed out-of-bounds access in a verbatim pinned function) plus a
scoped rung 4 (attacker-chosen out-of-bounds offset with an observed '.'
store in caller stack, direct-call/stub scope). Duplicate check before
provisioning: no prior `reports/frontier-*connman*`, no ConnMan window, charter
or mind on the tape, no `connman` entry in the do-not-duplicate list in
`walls/frontier.md`. Distinct from dnsmasq2shell (different project, different
function, different input path) and iondtn2shell (different protocol stack).
Ranked above the other candidates read this wake (pi-hole FTL's stale-length
shrink-realloc writes only victim-owned content; otel-webserver-module is an
nginx-module lane that risks overlap with the nginx-owning minds; Zyxel
libclinkc has no source or fix bytes). The operator owns final admission; wake
units and full-flag sync stay with the person.

## 1. Verified ground truth

- Claim: CVE-2026-115863 / GHSA-725f-6r9j-c4hf, published 2026-10-23 by NVD,
  HIGH 7.6 (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H`), CWE-121
  stack-based buffer overflow. Affected "ConnMan through 2.0"; GitHub's
  affected/patched version fields are Unknown.
- Claim source read (read-only provisioning, no external probe):
  `https://github.com/advisories/GHSA-725f-6r9j-c4hf`. The source snapshot is
  ConnMan tag `2.0` from `git.kernel.org`, pin recorded in
  `lab/frontier/connman2shell/PROVENANCE.md`.
- Primitive claimed: `get_domains()` in `gdhcp/client.c` copies a fixed
  `NS_MAXDNAME` (1025) bytes from a DHCPv6 DOMAIN_LIST (option 24) value into
  a 1026-byte stack buffer regardless of the option's actual length, then
  walks DNS labels with an unbounded `c += jump + 1`. A REPLY carrying at
  least 1025 non-zero bytes makes the walk leave the buffer and read/write
  '.' past it in strides chosen by the label bytes. The advisory states a
  forged Router Advertisement (O=1) plus a DHCPv6 REPLY matching xid/CLIENTID
  is sufficient, pre-authentication, against connmand running as root.
- The bug was introduced in `bb06c47101ca24`. **No upstream fix exists**:
  Debian bug #1153442 reports upstream HEAD `9e46e4a0` still carries the
  function. Andrei Miu posted a fix to the connman list on 2026-10-23; it is
  preserved in the bug archive and is the hunk applied here to derive the
  fixed snapshot. There is no tagged fixed release to pin.
- Real caller (source-bound, not exercised here): `get_dhcpv6_option_value_list()`
  calls `get_domains(len, value)` on `G_DHCPV6_DOMAIN_LIST` in the same pinned
  file; `len` and `value` come from the DHCPv6 REPLY option.

## 2. Source-bound mechanism and fix

Vulnerable pin, ConnMan tag `2.0`, `gdhcp/client.c` inside `get_domains()`:

```c
	while (pos < maxlen) {
		strncpy(dns_name, (char *)&value[pos], NS_MAXDNAME);

		c = (unsigned char *)dns_name;
		while (c && *c) {
			int jump;
			jump = *c;
			*c = '.';
			c += jump + 1;
		}
		list = g_list_prepend(list, g_strdup(&dns_name[1]));
		pos += (char *)c - dns_name + 1;
	}
```

`strncpy` writes 1025 of the 1026 bytes; the walk overwrites each label byte
with '.' and advances by `jump + 1`. With every copied byte `0xff`, the walk
lands on offsets 0, 256, 512, 768, 1024, then leaves the region. Replacing
`value[1024]` with a chosen byte K moves the first out-of-bounds address to
`dns_name + 1024 + K + 1`, i.e. `K - 1` bytes past the 1026-byte region, so
the attacker chooses *where* the first out-of-bounds access happens; the
written value is always '.'.

The posted fix bounds the copy to the remaining option length, NUL-terminates
it, and stops the walk at `name_end`:

```c
		int name_len = maxlen - pos;
		char *name_end;
		if (name_len > NS_MAXDNAME)
			name_len = NS_MAXDNAME;
		memcpy(dns_name, &value[pos], name_len);
		dns_name[name_len] = '\0';
		name_end = dns_name + name_len;
		...
			char *label = (char *)c;
			if (label + jump + 1 > name_end)
				break;
```

The saved diff is `lab/frontier/connman2shell/src/fix-miu-20261023.patch`
(sha256 `a9715aa5...`). The mail-archive rendering drops one trailing context
line; the saved patch restores it so the hunk applies cleanly to the pinned
tag-2.0 bytes. The changed lines are the posted fix; the fixed snapshot is not
a vendor release.

## 3. Local reproduction — observed bytes

Harness `lab/frontier/connman2shell/harness/run.sh`; full pin hashes,
toolchain and instrumentation boundary in
`lab/frontier/connman2shell/PROVENANCE.md`. The verbatim 29-line vulnerable and
41-line fixed `get_domains()` slices are re-extracted from saved pinned bytes
and SHA-256-asserted on every run.

- **61 PASS / 0 FAIL three times**, gcc 13.3.0 and clang 18.1.3; path-independent
  normalized content hash
  `bf6810e7c0d3db2fa2bae36e7233974e6fd593084c209952e742df1e3a48211f`.
- Attack input printed before every call: `USEDLEN=2048 LASTJUMP=K
  FIRST_OOB_OFFSET=K-1`, with 2047 bytes `0xff` and `value[1024] = K`.
- gcc ASan reports `ERROR: AddressSanitizer: stack-buffer-overflow`,
  `READ of size 1`, top frame `get_domains`, object `dns_name` at frame
  `[48, 1074)`. Access frame offsets for K=0x10/0x20/0x40/0x80 are
  1089/1105/1137/1201, i.e. **15/31/63/127 bytes past the 1026-byte region** —
  exactly `K - 1`.
- clang ASan (K=0x80) reports `dns_name` at `[32, 1058)` and the access at
  frame offset 1185 — again 127 bytes past the region. The attacker-chosen
  delta is compiler-independent even though the absolute frame offset is not.
- Plain 16 KiB caller-stack canary, K=0x80, three consecutive runs:
  `CANARY DOTS=69 FIRST=49 LAST=16301` — 69 bytes changed from the prefilled
  `0xEE` to the chosen `0x2E` ('.'), at deterministic offsets. This is the
  observed out-of-bounds **store**; ASan traps on the read half of the
  read-modify-write before reaching it.
- Fixed snapshot on the same attack input: `RC=0 LIST_LEN=256`, no ASan report.
  A well-formed safe DOMAIN_LIST (two short labels plus a terminator) gives
  `RC=0 LIST_LEN=1` on both pins, no ASan report.

## 4. Honest grade and what is *not* established

- **Rung 1 (reproducible trigger)**: yes, deterministic direct call with a
  synthesised 2048-byte DOMAIN_LIST value.
- **Rung 2 (state failure)**: yes, the unbounded label walk leaves a 1026-byte
  stack object while the pinned fix bounds the copy and the walk; the fixed
  snapshot returns cleanly on the same bytes.
- **Rung 3 (confirmed corruption)**: yes, ASan stack-buffer-overflow in the
  verbatim pinned function on two compilers, with clean fixed-pin and
  safe-input controls. The ASan report names the read half; the plain canary
  readback proves the write half.
- **Rung 4 (scoped)**: yes, in the direct-call/stub sense — the attacker picks
  the label byte K and therefore the offset of the first out-of-bounds access,
  and 69 '.' writes are observed in caller stack memory at deterministic
  offsets. The written byte is fixed by the source, not arbitrary.
- **Not established**: no ConnMan build, no `g_dhcpv6_client_*` call path, no
  DHCPv6 REPLY or Router Advertisement, no socket or daemon, no natural
  connmand stack layout, no adjacent object identity, no pointer or control-
  flow corruption, no marker execution, no command execution, no rung 5. The
  claim that a REPLY carries a ≥1025-byte DOMAIN_LIST and reaches this function
  is source/advisory-bound, not reproduced here. The fix is a mailing-list
  patch, not an upstream release; the witness should treat that as the primary
  caveat.

## 5. Cheapest next experiment

Build gdhcp/client.c from tag 2.0 with the GLib dependency stubbed and call
`get_dhcpv6_option_value_list()` with a crafted option-24 value under ASan,
to test whether a real REPLY-shaped option reaches `get_domains()` with
`len >= 1025` and whether the OOB store lands in a live adjacent object rather
than a canary. A negative result caps this candidate at rung 4; a positive
one justifies a loopback DHCPv6 REPLY against a plant-started connmand before
any admission decision.
