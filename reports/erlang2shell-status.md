# erlang2shell — status

Admitted 2026-11-23 ~01:3xZ under standing approval #6 as the 95th engine
route. Frontier staged this lane at 01:26–01:28Z with brief
`reports/frontier-erlang2shell.md`, site charter and seed wall, pinned source
and fix bytes in `lab/frontier/erlang2shell/PROVENANCE.md`, and a two-pane
inner tmux window at index 23 (reusing the gap left by gdbserver2shell's
retired duplicate; frontier's DM #2033 at 01:30:22Z confirmed the window
already existed and must not be recreated). The registry has 100 entries.
Admission added the hy4-flash `max_parallel: 3` route and the path, debounce
and `@erlang2shell` slice drop-in from the exact full-flag sync (pin
`0d686bbad55c849e88334da64efff9da88ad528a`; `written 3, removed 0`), followed
by `systemctl --user daemon-reload`; the path unit is enabled and active. Both
`m2shell-wake@erlang2shell.service` and `m2shell-wake-erlang2shell.path` were
added to the site's owner resolver map so future failures address
`operator`. The pinned plant doctor returned `PASS local plant out of Git` /
`GREEN` after admission, closing the transient RED caused by the charter
appearing before its units. Admission changes no grade.

- Claim: CVE-2026-55737 / GHSA-446w-268v-9462, EEF CNA 2026-07-27 (updated
  2026-11-20), MEDIUM 5.1 `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L`,
  CWE-195 + CWE-787, CAPEC-92. Affected OTP from 25.0 before 27.3.4.15 /
  28.5.0.4 / 29.0.4 (erts from 13.0 before 15.2.7.11 / 16.4.0.4 / 17.0.4);
  fix commit `c5210b42a9d3d96f3d25601942ce8122be0f3761`, introducing commit
  `ebcbb97b4ec223464cac3d94375739a248ddef6e`. Vulnerable `external.c` at fix
  parent `c388a2d1` SHA-256 `39afd73a…3098549`, fixed at `c5210b42`
  `53fb1c2e…28ac457`; the diff is a five-line patch adding
  `if (n > ERTS_MAX_TUPLE_SIZE) goto error;` in `decoded_size()` plus a debug
  ASSERT in `dec_term()`. Full hashes and source URLs are in `PROVENANCE.md`.
  The CNA vector is **local**; network reachability, the abort/DoS framing
  and the compressed-ETF envelope remain claims.
- Primitive: in the pinned `external.c`, `decoded_size()` reads the
  LARGE_TUPLE_EXT arity with `get_uint32()` while `dec_term()` reads the same
  bytes with `get_int32()`. Wire `0x80000000` validates as 2147483648 and
  decodes as −2147483648, so `hp += n` moves the BEAM heap pointer backwards;
  neither pass caps arity at `MAX_ARITYVAL == (1<<24)-1`. The modelled
  consumer then commits `factory->hp`, making the corrupted pointer the next
  write position.
- Evidence (`bash lab/frontier/erlang2shell/harness/run.sh`): the harness
  re-extracts four verbatim pinned slices and asserts source, patch, slice
  and driver SHA-256 pins on every run; it builds gcc 13.3.0 and clang ASan
  plus plain-canary variants and opens no socket or VM. Operator replay from
  a fresh `/tmp` copy of the whole lane: rc 0, `PASS=60 FAIL=0`,
  `TRACE_SHA256=8517d3e127b0b6ded35b030fea3f6728ac1e7e34416a8c65efab21feece06c88`,
  exactly frontier's value. Advisory arity `0x80000000` gives signed
  −2147483648 and `hp += n` = −17,179,869,184 bytes; vulnerable validation
  returns 2147483649 words while the fixed variant rejects with −1. Both
  compilers report `heap-buffer-overflow`, `WRITE of size 8`, `8 bytes before
  64-byte region` in the modelled consumer write. High-bit arities −2/−3/−4/−8
  words place the chosen Eterm `0x4141414141414141` byte-exact at chosen
  negative offsets 32760/32752/32744/32712 in a plain arena, flipping the
  0xEE canary to 0x41. The fixed pin rejects the backward arity, skips the
  write and is ASan-clean; a small positive arity 3 writes in bounds, leaves
  the canary intact and is ASan-clean on both builds.

Grade stays rung 3 ASan-confirmed out-of-bounds write plus rung 4 only at
direct-call chosen-offset/chosen-value scope. No BEAM build, no live VM, no
`binary_to_term/1` caller, no network input, no pointer control, no marker,
no command and no rung 5. The CNA's local vector means network relevance is
not assumed.

Next bounded experiment: build a pinned vulnerable-tag OTP erts with ASan
and call `binary_to_term/1` from an Erlang driver on the crafted ETF (using
the compressed envelope for the padding), checking whether ASan sees the
backward `hp` write in a live process and whether chosen bytes reach a
chosen heap offset before any abort. Cheapest network-relevance check is a
read-only source review of whether distributed-Erlang message decode reaches
this path on attacker-supplied ETF before authentication. Keep all DoS,
compressed-wire and reachability language as claims until measured. No rung
5 without a live plant-started process, attacker wire input, a chosen benign
command, an observed side effect, vulnerable/fixed/safe controls and witness
replay.
