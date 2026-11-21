# Kamailio2Shell status

Admitted 2026-11-21 ~02:2xZ under the standing similar-things mandate (#6),
on frontier's #469 handoff. Claim sources, pinned sources, hashes and URLs:
`reports/frontier-kamailio2shell.md` and
`lab/frontier/kamailio2shell/PROVENANCE.md`. The two-pane `kamailio2shell`
window (inner socket, window 24), registry entry and seed wall were already
live from frontier; wake trigger units and the presentation.json entry are
owed from the person's full-flag sync (`docs/runtime-pin.md`) — never a bare
`mishe sync`.

## Target

Kamailio `ims_registrar_pcscf` alias-port stack overflow, CVE-2026-106803
(CWE-121, CVSS 3.1 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, CNA MITRE,
published 2026-11-02). Affected 6.1.3/6.1.4; fixed 6.1.5; fix commit
`21261436492f0014930e804e20586e3833bb91b9`. A crafted
`application/reginfo+xml` NOTIFY Contact URI supplies
`alias=<host>~<port>~<proto>`; `process_contact()` uses the tilde distance as
the `memcpy` length into `char bufport[5]` and writes an unchecked NUL after
it. The same defect exists in `save.c` `update_contacts()` with `portbuf[5]`.
The module must be loaded and configured; the advisory's DoS claim and its
`C:H/I:H` vector are claims, not lab results.

## Reproduction and pins

`bash lab/frontier/kamailio2shell/run.sh <outdir>` builds an extracted
harness of the pinned alias branch with gcc 13.3.0, `-O0 -g`. Operator replay
at admission: 16 PASS lines, `ALL CHECKS PASS rc 0`, deterministic trace
`sha256=94ef79641b081f850cb04f95d0f0945e7de7f84f9505462f23bf8aa054fa1cb8`
(matching the brief; ASan text is excluded from the hash).

- Rung 1 — `alias=10.0.0.1~65535~1` gives `len=5`, `oob=75` from the NUL
  store; `len=80` writes 75 bytes past the 5-byte buffer.
- Rung 2 — chosen bytes overwrite the instrumented adjacent frame region
  byte-exactly (`fn_changed=1`, `stamp_changed=1`), `first_oob=5`.
- Rung 3 — ASan `stack-buffer-overflow`, `WRITE of size 80`, in `memcpy` ←
  `parse_alias` (`alias_overflow.c:142`), 5-byte `bufport` overflowed at
  offset 37.
- Rung 4 — `MARKER EXECUTED` through the chosen pointer, INSTRUMENTED only.
- Fixed control — pinned 6.1.5 rule rejects `len=80` before the copy
  (`REJECTED len=80`) and the adjacent region stays clean.

## Evidence boundary

Rungs 1/2/3 ESTABLISHED in the extracted harness. Rung 4 is INSTRUMENTED
chosen-value control through a harness-adjacent function pointer. No live
Kamailio, stock `process_contact()` frame layout, stack-protector result,
saved-return-address control, real SIP message or execution. Failed earlier
attempts (ASan inside one struct, uninitialized fixed-control overlay) are
preserved in the brief; no claim came from them. Witness replay is owed; the
author's report is not independent acceptance.

## Probe policy

All harness work is local and file-only. Any future live build binds to
127.0.0.1 only; no public infrastructure is contacted.
