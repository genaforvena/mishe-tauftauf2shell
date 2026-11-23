# Provenance — CVE-2026-55737 / GHSA-446w-268v-9462 (Erlang OTP erts)

Read-only provisioning, 2026-11-23 ~01:19–01:24Z. No off-loopback probe.
Every URL below is a public advisory or the official `erlang/otp` source home.

## Records

- MITRE CVE JSON `https://cveawg.mitre.org/api/cve/CVE-2026-55737`
  (CNA EEF; reserved 2026-06-17, published 2026-07-27, updated 2026-11-20).
- CNA page `https://cna.erlef.org/cves/CVE-2026-55737.html`.
- GitHub vendor advisory `https://github.com/erlang/otp/security/advisories/GHSA-446w-268v-9462`
  (the GHSA JSON API path `api.github.com/advisories/GHSA-446w-268v-9462`
  returned HTTP 404; the HTML advisory was read instead).
- Fix commit `https://github.com/erlang/otp/commit/c5210b42a9d3d96f3d25601942ce8122be0f3761`
  (Kiko Fernandez-Reyes, committer date 2026-06-25, parent `c388a2d1b3f9918652276d4798692dd4d8ef97fc`).
- Introducing commit `ebcbb97b4ec223464cac3d94375739a248ddef6e` (from CVE JSON).
- Feed discovery item `https://feed.craftedsignal.io/briefs/2026-11-erlang-otp-vulnerability-cve-2026-55737/`
  (third-party; its "HIGH 7.5" severity conflicts with the CNA's MEDIUM 5.1 AV:L — CNA wins).

## Pinned bytes (SHA-256, re-asserted on every harness run)

| File | Commit | SHA-256 |
| --- | --- | --- |
| `src/external-c388a2d1.vuln.c` | `c388a2d1` (parent of fix) | `39afd73a7e0ab02b1fbdcd3309333c812365cae17c5b4f20726837f2b3098549` |
| `src/external-c5210b42.fixed.c` | `c5210b42` (fix) | `53fb1c2eef8a418c2c4d92d05bda9b653992f7702cb8015c274e15a6f28ac457` |
| `src/erl_term-c388a2d1.h` | `c388a2d1` | `8cc7eef5c9c3d3dcbd0ad96fad3aa79b53c9e8e3bf4351a3869c0726b8c93f2d` |
| `src/fix-c5210b42.patch` | commit patch endpoint | `456ac0bca8145bf4c51f508fc6d108b137b24702778dca5d736bc3577e5c1b6a` |

Raw source URL form:
`https://raw.githubusercontent.com/erlang/otp/<sha>/erts/emulator/beam/external.c`
and `.../erts/emulator/beam/erl_term.h`.
The diff between the two pinned `external.c` files is exactly the five
insertions in the fix patch (one include, one ASSERT, one 3-line guard).

## Verbatim slices re-extracted every run

`run.sh` cuts these line ranges from the pinned files and includes them under
`#line` into the driver; SHA-256 of each generated `.inc` is asserted:

| Slice | Vulnerable file lines | Fixed file lines |
| --- | --- | --- |
| `decoded_size` LARGE_TUPLE_EXT case | 6041–6051 | 6043–6056 |
| `dec_term` LARGE_TUPLE_EXT case + `tuple_loop` | 4467–4474, 4482–4501 | 4468–4475, 4483–4503 |

Constants from pinned headers: `LARGE_TUPLE_EXT == 'i'` (external.h:45),
`MAX_ARITYVAL == ((Uint)1 << 24) - 1` and
`ERTS_MAX_TUPLE_SIZE == MAX_ARITYVAL` (erl_term.h:314–315).

## Model boundaries (what the harness is not)

- No BEAM/erts build. The two fault statements are verbatim; the surrounding
  decode loop, `factory->hp = hp` commit (external.c:5211) and the subsequent
  heap write are modelled scaffolding.
- `CHKSIZE(n)` is evaluated against a 64-bit post-inflation logical length
  rather than `endp - ep`; the advisory says compressed ETF supplies that
  padding. No >2GiB pointer is formed and no large buffer is allocated.
- High-bit arities `-2..-8` words are used for the memory-corruption runs;
  the advisory's exact `0x80000000` is used for the arithmetic-only run.
  A real BEAM would move `hp` by 2^31 words (17,179,869,184 bytes).
- The chosen Eterm word models the next allocation through the corrupted
  heap pointer; this is chosen-offset/chosen-value control in a direct-call
  harness, not evidence of live VM control flow, ASLR/DEP bypass or RCE.
