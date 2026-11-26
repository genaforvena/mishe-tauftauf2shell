# pcre2jit2shell — status (STAGED 2026-11-26 19:3xZ)

STAGED by frontier W285; awaiting operator admission under standing #6. Brief
`reports/frontier-pcre2jit2shell.md`, charter `charters/pcre2jit2shell.md`,
seed wall `.mishe-tauftauf/walls/pcre2jit2shell.md`, harness
`lab/frontier/pcre2jit2shell/` (`PROVENANCE.md` has pins, traces and negatives).
Target window 194 is live on the inner tmux socket (panes %392/%393, dead=0,
tail/python3); the registry has 195/195 unique window names.

- Pins: 10.48 tarball SHA-256
  `ebcc25aadf2a51fa1fefa9b8bc9e7a79b3dae86870a0f1152a22e42befd46888`, 10.49
  tarball SHA-256 `929f0b20e62879252a15886b06c89f1edef61a363cbd5826fb041080a5e557ae`,
  fix.patch SHA-256 `38f740cb52919619945f3cf4b68a7c0892f68b564ef14879266781ee70b4165f`
  (commit `2b4038298072684b0fae29b15bedfb1a75bda46d`), hash-matched advisory
  PoC SHA-256 `2bda01bc0d70ac7888a8205aa9141e4bf8efcc0e7b48cc50eb23adca56756cd4`.
- Claim source: GHSA-r9hj-j2rw-4q3m / CVE-2026-103111, published 2026-09-28 /
  2026-09-30, High CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L`, CWE-787;
  affected `<= 10.48`, patched `10.49`. Requires JIT with a growable
  `pcre2_jit_stack_create()`/`pcre2_jit_stack_assign()` stack and an
  attacker-controlled pattern; interpreter and default-stack JIT unaffected.
- Mechanism from pinned 10.48: `allocate_stack()` subtracts the whole frame
  from `STACK_TOP` (`pcre2_jit_compile.c:3531`) before the limit check
  (`:3543`); the resize stub lowers `STACK_LIMIT` by a fixed 8192 (`:14088`,
  `STACK_GROWTH_RATE` at `:102`) without rechecking the adjusted top. A frame
  larger than the increment makes JIT frame stores cross below the stack. The
  fix tracks `large_stack_allocation` and resizes from the real top.
- Author harness `sh run-all.sh` from clean pinned tarballs: `RESULT PASS=46
  FAIL=0` at 19:31Z, runner rc 0.
- Rung 2, shipped CLI: the fix's own regression line through `pcre2test` on
  10.48 segfaults (rc 139); on 10.49 it reports `JIT stack limit reached`,
  rc 0.
- Rung 4, physical PoC against unmodified pinned 10.48: separate 1 MiB victim
  mapping immediately below the 192 KiB JIT stack; 139,976 victim bytes
  clobbered, deepest write 139,976 bytes below PCRE2's mapping, 15 aligned
  words holding pointers into the 10-byte subject; match -46. No-jit,
  100-capture small frame, and pinned 10.49 JIT controls are all clean (0
  clobbered bytes, 0 subject pointers).
- Grade: **rung 2 shipped-CLI crash + rung 4 physical separate-mapping control
  exercised / rung 3 ASan NOT CLAIMED / rung 5 NOT CLAIMED**. Escaping stores
  are JIT-generated into mmapped regions; no ASan report is evidence here.
  Conditions: fixed-address victim placement can collide under ASLR (failed
  attempts preserved), the PoC reads SLJIT stack fields to find the mapping
  boundary without changing library state, and the written words are JIT frame
  state (subject pointers observed, not arbitrary chosen bytes). No command,
  socket, control-flow target or live wire consumer.
- Owed: operator admission, independent witness clean-archive replay, and the
  loopback consumer experiment — drive the same pattern through a live local
  JIT-with-growable-stack service, then seek chosen-offset readback and a
  benign marker. Keep all four controls; do not infer RCE from advisory prose.
