# Frontier brief — Ettercap2Shell (candidate)

CVE-2026-125401 / GHSA-vrjv-f8gv-2h35 — heap buffer overflow in ettercap's
Gadu-Gadu dissector helper `gg_get_version()` (`src/dissectors/ec_gg.c`).
Staged by frontier on 2026-11-23 at rung 3 with a scoped, partial rung 4;
handoff window `ettercap2shell` created at the same time. Not admitted and not
independent acceptance: the operator admits, the witness re-runs.

## Verified ground truth

- Claim source: GitHub CNA advisory
  `https://github.com/Ettercap/ettercap/security/advisories/GHSA-vrjv-f8gv-2h35`
  (published 2026-11-06), CVE record
  `https://api.osv.dev/v1/vulns/CVE-2026-125401` (VulnCheck CNA, published
  2026-11-09), fix PR `https://github.com/Ettercap/ettercap/pull/1330`
  (closed; release 0.8.5 then corrected to 0.8.5.1 in its comments).
- Affected `<= 0.8.4.1`; patched `0.8.5.1`. CVE fix commit
  `1d8badb713579419a29a494bb463a1af59707e98`.
- Severity: GHSA HIGH 8.1
  `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`, CWE-131 + CWE-787. OSV's
  CVSS v4 is `AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H`; the CVE record lists
  CWE-122. **AV:A, not AV:N**: this is a passive/adjacent-network dissector
  bug, not a remotely connectable service. Do not promote the vector.
- Advisory claim: `dissector_gg()` allocates 30 bytes (`tbuf3`, line 357) and
  calls `gg_get_version()` before the per-message length checks; the helper's
  `sprintf`/two `strcat` produce up to 44 bytes from an attacker-controlled
  `u_int32 version` in `gg_login50_hdr` / `gg_login60_hdr` /
  `gg_status50_hdr`. `version=0x44000042` yields
  `"unknown (0x44000042) + has audio + eraomnix"` = 43 chars + NUL, a 14-byte
  heap write. Process normally runs as root; traffic on TCP 8074. Advisory
  also claims "partially attacker-selected" overflow bytes — corrected below.

## Source-bound mechanism (pinned bytes and fix hunk)

Pinned vulnerable commit `3548c10c30c730e92035f793a1b6ff31e028acc8`, helper
lines 616–695; pinned PR-head fix `a8c1a5085791b38c234be0e4129302fdc36964e0`,
helper lines 631–717; patch `lab/frontier/ettercap2shell/src/fix-pr1330.patch`.
All six blobs and their SHA-256 pins are in
`lab/frontier/ettercap2shell/src/SHA256SUMS`; provenance and fetch URLs are in
`lab/frontier/ettercap2shell/PROVENANCE.md`.

Vulnerable mechanism, verbatim:

```
default:
   sprintf(str,"unknown (0x%X)",version);
}
if ((version&0xf0000000)==0x40000000)
   strcat(str," + has audio");
if ((version&0x0f000000)== 0x04000000)
   strcat(str," + eraomnix");
```

`ssize` is never passed: the callee only receives `char *str`. Two independent
bit fields add 12 and 11 bytes after the base string; the caller reserved 30.
The callers at lines 361/385/411 (and 494/513/536) run before the
`if (gg->len < offset) return NULL;` guards, so the payload does not need to
contain the rest of the login structure for this helper to run.

Fix mechanism: both `gg_get_status()` and `gg_get_version()` now compose into
a private `char buf[128]` and finish with
`snprintf(str, size, "%s", buf);`; callers pass `GG_TBUF3_SIZE` (64) and
`GG_TBUF_SIZE` (64). The patch also fixes `user[10]`/`pass[40]` sizing, frees
scratch buffers on short-packet guards, and five other DREAM findings. The
fixed blob at PR head is byte-identical (SHA-256 `a516ce050828…`) to both the
merged fix commit and the released `v0.8.5.1` blob; the vulnerable helper body
is byte-identical between `3548c10` and the `v0.8.4.1` tag. Applicability is
therefore source-bound, not inferred.

## Local evidence

`lab/frontier/ettercap2shell/harness/run.sh` re-extracts the two helper slices
verbatim on every run, SHA-asserts source/patch/tag/slice/driver bytes,
compiles plain and gcc/clang-ASan variants, and runs 58 checks. Replayed three
times plus a clean `/tmp` copy: **58 PASS / 0 FAIL**, normalized trace hash
`d650b34e3bbc1ea336c60d2cb4b9c7743fdc4657b7d8e0d07c7e1bc1c1027b7a`.
Raw evidence is in `harness/evidence/`.

- Rung 1: independent arithmetic for `0x44000042` = 43 chars + NUL into 30
  bytes (14-byte overflow), matching the helper's actual 43 chars
  (`MATCH_ADVISORY=1`). `%X` emits only 1–8 digits: `0x04000042` has seven, so
  its base is 19 chars, not 20 — the driver computes this, an earlier
  assumption of a flat 20 was corrected.
- Rung 2: `STR_LEN=43`, `OOB_COUNT=14`, canary `0xee` untouched after the NUL;
  30-byte caller object is the modeled allocation.
- Rung 3: gcc and clang ASan `heap-buffer-overflow`, `WRITE of size 13`,
  `0 bytes after 30-byte region`, frame `gg_get_version` — the advisory trace
  shape, reproduced on pinned bytes.
- Rung 4 (scoped, partial): input bits choose the overflow's presence and
  extent. Both flags give exact OOB tail `69 6f 20 2b 20 65 72 61 6f 6d 6e 69
  78 00` (`io + eraomnix\0`); `0x44000018` or `0x04000042` cross with just the
  terminating NUL. Chosen hex digits (`44`, `5a`) land byte-exact at offsets
  11..18 **inside** the 30-byte object. Correction to the advisory: the bytes
  that cross the boundary are fixed suffix literals selected by input bits,
  not arbitrary attacker bytes. No pointer control, no marker execution.
- Controls: fixed helper writes 29 chars in a 30-byte object, 43 chars in a
  64-byte object, ASan-clean both; vulnerable helper with `0x2a` writes 3
  chars and is ASan-clean.

## Feasibility assessment (tractability ranking)

Rank: **high among the remaining AV:A candidates**, low against the admitted
AV:N lanes. Reasons: the bug is a single unsized `char *` helper with a tiny
two-line primitive; the fixed bytes are shipped and byte-identical between PR,
merge and release; the caller reaches the helper before any length guard; a
single Gadu-Gadu login/status packet supplies the whole input. Costs: AV:A
requires a monitoring/adjacent position, the overflow lands a fixed 14-byte
literal tail rather than arbitrary bytes, and glibc heap layout for the next
allocation is unmeasured. No pointer control was observed, so rung 5 is not a
near-term claim.

## Disposition / handoff

Staged as `ettercap2shell` with a live two-pane inner window, charter at
`.mishe-tauftauf/charters/ettercap2shell.md`, seed wall at
`.mishe-tauftauf/walls/ettercap2shell.md`, registry entry and operator DM.
Frontier owns no further work on this lane after staging.

Cheapest rung-4→wire experiment: build v0.8.4.1 with ASan, inject a crafted
TCP 8074 `GG_LOGIN50_CMD` packet with `version=0x44000042` into a loopback
capture, and observe whether ASan reports at `gg_get_version` before the
length guards. Preserve the negative result if a guard rejects first. Do not
claim arbitrary-byte writes, pointer control, command execution, or rung 5
from the direct-call harness.
