# Frontier brief — Kamailio2Shell

Candidate: **Kamailio `ims_registrar_pcscf` alias-port stack overflow**,
CVE-2026-106803. Grade: **rungs 1/2/3 ESTABLISHED in an extracted harness;
rung 4 INSTRUMENTED chosen-value control only** (no live Kamailio, no stock
stack layout, no demonstrated return-address control in the real function).
Produced 2026-11-21 in the frontier wake starting 01:31Z. This is a research
find, not an admission; the operator decides targets.

Why this candidate outranks the held gdbserver find: affected (`6.1.3`,
`6.1.4`) and fixed (`6.1.5`) **releases are pinned**, the **fix commit and
patch are pinned**, the vulnerable source bytes are pinned, and the advisory
claims unauthenticated network reachability with `C:H/I:H/A:H`. None of those
were available for gdbserver2shell.

## Verified ground truth

- Sources read this wake (read-only provisioning; no off-loopback probe):
  OSV API record for CVE-2026-106803, cvelistV5 source record, upstream issue
  #4954, fix PR #4958, fix commit
  `21261436492f0014930e804e20586e3833bb91b9` and its `.patch`, the claim/PoC
  gist, and raw `notify.c` / `save.c` at tags `6.1.4` and `6.1.5`. Hashes and
  URLs: `lab/frontier/kamailio2shell/PROVENANCE.md`.
- CNA MITRE, published 2026-11-02. CWE-121 (stack-based buffer overflow).
  CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — 9.8 Critical,
  unauthenticated, full confidentiality/integrity/availability impact.
- Affected: Kamailio `v6.1.3` and `v6.1.4`; the OSV GIT range is
  `introduced: 0` → `fixed: 21261436492f...`. The pinned `6.1.5` tree carries
  the fix (`bufport[6]`, bound check), so `6.1.5` is a fixed release.
- Claimed primitive (advisory): processing a crafted
  `application/reginfo+xml` NOTIFY, `process_contact()` copies an
  attacker-controlled `port` from the `alias=<host>~<port>~<proto>` NAT
  parameter into a fixed 5-byte stack buffer without validating its length;
  an unauthenticated remote attacker can corrupt the stack and terminate the
  P-CSCF process. The advisory claims DoS; `C:H/I:H` in the CVSS vector is a
  separate claim about impact that this harness does not establish. Treat
  both as claims to reproduce.
- Scope note: `ims_registrar_pcscf` is an IMS P-CSCF SIP server module that
  must be loaded and configured; it is not a default-on generic HTTP path.
  It is a C network-facing server component, an X2Shell-class extension under
  the same precedent that admitted other non-HTTP daemons. Operator decides
  admission.

## Source-bound mechanism

Verbatim from pinned `src/notify.c.6.1.4`, `process_contact()`:

```c
char bufport[5], *rest, *sep, *val, *port, *trans;
...
received_port_len = trans - port;
trans = trans + 1;
received_proto = *trans - 48 /* char 0 */;
memcpy(bufport, port, received_port_len);
bufport[received_port_len] = 0;
```

`port` and `trans` are the positions of the first and second `~` in the
`alias=` value taken from the Contact URI, so `received_port_len` is
attacker-chosen. Both the `memcpy` length and the following NUL index are
unbounded relative to the 5-byte buffer. The pinned fix commit says so
directly:

> copies the port field into a 5 bytes stack buffer without checking the
> length, allowing a stack buffer overflow up to MAX_URI_SIZE bytes. Even a
> 5 digits port (65535) writes one byte past the end since the buffer needs
> 6 bytes for 5 digits plus the null terminator.

The same defect exists in pinned `src/save.c.6.1.4`, `update_contacts()`:
`char portbuf[5]; memset(portbuf,0,5); memcpy(portbuf, port_s, (p-port_s));`
with no length check. The fix enlarges both buffers to 6 bytes and rejects
oversized port values; pinned `6.1.5` shows exactly that.

The harness reproduces the `notify.c` branch: the alias search, both tilde
finds, `received_port_len = trans - port`, the unchecked `memcpy` and the
NUL store. It is **not** a Kamailio build: `parse_uri()`, the libxml reginfo
parser, usrloc calls and the real `process_contact()` frame layout are not
exercised.

## Local evidence

Harness: `lab/frontier/kamailio2shell/{alias_overflow.c,run.sh}` plus pinned
sources and `PROVENANCE.md`. Clean replay from committed HEAD:

```
bash lab/frontier/kamailio2shell/run.sh <outdir>
-> 16 PASS lines, ALL CHECKS PASS rc 0
   sha256=94ef79641b081f850cb04f95d0f0945e7de7f84f9505462f23bf8aa054fa1cb8
```

That hash is over a deterministic trace (`<outdir>/trace.txt`), not ASan's
PID/address-bearing text. gcc 13.3.0, `-O0 -g`.

- Rung 1 — deterministic trigger: input `alias=10.0.0.1~65535~1`. The pinned
  fix comment's edge case holds: `len=5` fits the five data bytes but
  `bufport[5]=0` is one byte past. Harness also drives `len=80`, `oob=75`,
  `first_oob=5`.
- Rung 2 — observed state failure: `len=80` chosen bytes overwrite the
  instrumented adjacent frame region byte-exactly; chosen function pointer
  and `KAMAILIO` stamp both read back (`fn_changed=1`, `stamp_changed=1`).
- Rung 3 — ASan `stack-buffer-overflow`, `WRITE of size 80`, in
  `memcpy` ← `parse_alias` (alias_overflow.c:142), with the report naming a
  5-byte `bufport` object overflowed at offset 37.
- Rung 4 — `MARKER EXECUTED` through the chosen pointer, **INSTRUMENTED
  only**. The pointer is an instrumentation field standing in for adjacent
  frame state; no saved return address of the real function is controlled.
- Fixed control: the same 80-byte input is rejected before the copy by the
  pinned 6.1.5 rule (`REJECTED len=80`), adjacent region stays clean.

## Rung-4 feasibility

Favourable: the overflow length is not bounded by the port's numeric value
but by the URI length, so long chosen writes reach beyond the local buffer;
the advisory claims unauthenticated reachability; a fixed release and patch
pin the intended semantics.

Unfavourable / UNKNOWN: the real `process_contact()` local layout, stack
protector, compiler version and the exact `MAX_URI_SIZE` bound are unknown
here; the input is URI text, so non-ASCII/NUL bytes in a real SIP message are
constrained; the advisory only claims process termination. Whether the
unchecked NUL store or `memcpy` can reach a saved return address or a useful
pointer in a stock 6.1.4 build is UNKNOWN and must be measured, not assumed.

## Cheapest experiment to move a rung

Build pinned Kamailio `6.1.4` with the `ims_registrar_pcscf` module and ASan,
place a `process_contact()` unit harness at the alias branch with a stack
canary and a saved-return-address probe, and feed a reginfo+xml NOTIFY with a
long `alias=host~<chosen>~1` Contact URI. Observe whether the overwrite
reaches the return address under the stock compiler and stack protector. A
positive result would move rung 4 from instrumented to real-code chosen-pointer
control; a negative result is a valuable structural blocker to record.

## Failed hypotheses and negatives

- An earlier attempt to observe the overflow with ASan directly on the
  instrumented `struct frame` produced no ASan report: the copy stayed inside
  one object. Corrected by a standalone `bufport[5]` local in `ASAN_MODE`,
  matching the pinned declaration; ASan then reported the 80-byte write.
- The first harness build crashed in the fixed control because rung 4 ran
  against an uninitialised overlay; rungs are now compile-mode gated. No
  claim was published from the failing runs.
- No live Kamailio process, no stock layout, no real stack-protector result.

## Next owner

Witness re-runs the replay; operator decides admission. If admitted, the new
target mind owns the real-build experiment above; frontier does not duplicate
that lane.
