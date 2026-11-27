# Frontier brief: berryformat2shell — Berry 1.1.0 string.format stack overwrite

**Status: STAGED for operator admission (W326, 2026-11-27).** This is a
separate stack-write finding from the lexer OOB read described by
CVE-2026-3285 / GHSA-92ph-pr79-cv5g. No CVE/GHSA was found for the format
write. The reproducible lab is `lab/frontier/berryformat2shell/`; live
two-pane inner-socket window 213 (`%432`/`%433`, `dead=0`) is registered in
`.mishe-tauftauf/operator/window-registry.json` (214/214 unique names). Stage
replay commit `c235017a`; author evidence is not independent acceptance.

## Verified ground truth

- **Related primary sources:** https://github.com/advisories/GHSA-92ph-pr79-cv5g,
  https://nvd.nist.gov/vuln/detail/CVE-2026-3285,
  https://github.com/berry-lang/berry/issues/509,
  https://github.com/berry-lang/berry/pull/511 and
  https://github.com/berry-lang/berry/commit/7149c59a39ba44feca261b12f06089f265fec176.
  The advisory claims a local one-byte OOB read in `scan_string`, fixed by
  `7149c59a`; it does not claim a write or RCE. The same commit also changes
  `string.format`, but its hunk targets post-1.1.0 source.
- **Pinned vulnerable version:** Berry 1.1.0, tag
  `b5ede66721937533fbf5c286ef44a5111ea30c75`, official codeload tarball SHA-256
  `b8eb94a44378ecd2f281cf7e244b8617b99f51d500638622b6126e60e730a693`.
  CNA/OSV list 1.1.0 in the related advisory's affected range. There is no
  numbered upstream release after v1.1.0; the fix is commit-level.
- **Exact fix control:** commit `7149c59a39ba44feca261b12f06089f265fec176`
  source SHA-256
  `96afb4d8ed598e2185e50e66af286543ce8eff5a5e52cb45d171ca9c0f866439`.
  Its `be_strlib.c` blob is `9112b0fb…`; the vulnerable 1.1.0 blob is
  `23fdf978…`.
- **Claimed primitive versus local finding:** public material claims a
  one-byte static OOB read. Locally, an ordinary script statement reaches an
  unbounded `strncpy` into `char mode[32]`, giving an attacker-length,
  restricted-alphabet stack write. That write is the reason this candidate is
  worth a dedicated mind.

## Source-bound mechanism

Pinned `src/be_strlib.c:517-545` defines `MAX_FORMAT_MODE 32` and
`FLAGES "+- #0"`. `get_mode` skips an unlimited flag run, then copies
`p - str + 1` bytes into the caller's 32-byte `mode` array and appends NUL,
with no destination size. `str_format:564-572` declares `mode[32]` and calls
`get_mode(p + 1, mode)`.

The 263-byte input `inputs/format-overflow.be` executes:

```berry
import string
string.format("%#0-+#0-+...s", "A")
```

with `#0-+` repeated 56 times (224 flag bytes). The resulting copy is 225
bytes into `mode+1`. In the O0 ASan frame, `mode` occupies `[32,64)` and the
first invalid byte is its redzone at offset 64. In the O0 plain frame, the
saved RIP starts 215 bytes after the copy start, so all eight saved-RIP bytes
are overwritten.

The upstream patch adds `buf_len` and truncation. The local 1.1.0 backport
mirrors that logic; the original patch's `be_strlib.c` hunk cannot apply to
1.1.0 because the function signature and surrounding code changed. A separate
residual remains in the exact fix: `mode_fixlen` can see `strlen(mode)==31`
and append `"ll"` with `strcpy`, producing a three-byte write across the
32-byte array for long integer formats.

## Locally observed evidence

- Vulnerable 1.1.0 ASan: rc 134, `stack-buffer-overflow`, `WRITE of size 225`,
  `get_mode src/be_strlib.c:542` → `str_format:572`.
- Local backport and exact upstream-fix ASan, same long-`%s` input: rc 0,
  clean. Safe format and safe numeric controls are clean on all three.
- Vulnerable O0 plain built explicitly without stack protector/fortify:
  rc 139 in 5/5. Patched plain: rc 0. Default O2 hardened vulnerable build:
  rc 134 with `buffer overflow detected`; patched hardened: rc 0.
- GDB read after the real copy, with no debugger write:
  `SAVED_RIP_BYTES=2b23302d2b23302d`,
  `SAVED_RIP_VALUE=0x2d30232b2d30232b`. This is noncanonical. Corrupted locals
  crash the process before a return to that value; no chosen branch target was
  observed.
- Exact upstream fix still reproduces a distinct numeric-format ASan
  `WRITE of size 3` in `mode_fixlen src/be_strlib.c:627`; the 1.1.0 backport
  reproduces it at `:561`.
- Related lexer control: vulnerable ASan READ-1 one byte after static `eos`;
  backport and exact fix return `unfinished string`; safe source clean.
- `bash run-all.sh`: **59 PASS / 0 FAIL**, rc 0. Pins, input hashes, runner hash
  and raw logs are in `lab/frontier/berryformat2shell/PROVENANCE.md`.

## Rung-4 feasibility and grade

**R1 ✓ / R2 ✓ / R3 ✓ ASan WRITE-225 / R4 LIMITED / R5 NOT CLAIMED.**

R4 is limited to chosen restricted-alphabet bytes at a measured saved-return
slot in an explicitly unprotected O0 build. The byte alphabet is flag bytes
`+ - space # 0`, at most two width digits, optional precision digits, and the
conversion byte; `%n` is not reachable. The observed value is noncanonical,
no controlled branch or executable address was observed, and default compiler
hardening aborts. No real consumer, network request, pointer dereference,
marker or command was exercised. A Berry context that executes
attacker-influenced script or format text is a prerequisite; Tasmota and
NuttX are plausible public consumers, not verified exposure here.

Tractability is moderate: the interpreter is tiny, the trigger is an ordinary
script statement, the stack geometry is reproducible, and the exact upstream
fix exposes a residual. It ranks below a demonstrated wire-reachable heap
write because no untrusted-format consumer has been measured.

## Cheapest next experiments

1. Find a real Berry consumer where untrusted text controls a format string;
   name the API/configuration and reproduce locally on loopback or in-process.
2. Map production stack layout and hardening. Determine whether any allowed
   flag/conversion sequence can preserve the corrupted locals long enough to
   reach a chosen branch; preserve the noncanonical-RIP negative.
3. Repair `mode_fixlen` with space reserved for `BE_INT_FMTLEN`, then replay
   both the long-`%s` and long-integer controls. The current exact-fix residual
   must remain in the historical evidence.
4. Seek rung 5 only after a named consumer accepts attacker-controlled format
   text and a live process executes a lab-chosen benign command with
   vulnerable/fixed/safe controls and independent witness replay.

## Duplicate check and disposition

No existing Berry target or window was present. `berrylexer2shell` was the
unknown W325 working name; its only durable finding was the related
one-byte lexer read, while W326 found the stronger format write. The clean
replacement lane is `berryformat2shell`; do not stage a second Berry lexer
mind for CVE-2026-3285 unless new evidence changes that disposition.

## Handoff evidence (W326)

Stage replay commit `c235017a1b0bbeaebd9d8e65181a3d0f5e79aec7`. Clean
`git archive c235017a lab/frontier/berryformat2shell` SHA-256
`2cbd8cb5ec449779cead31a7748e9c9e91e21c739fe72ecf582ee8888fce9cd3`;
all pin/harness hashes matched, unmodified `bash run-all.sh` returned
59 PASS / 0 FAIL, summary log SHA-256
`e8ebb940ead8be84c98665a1bdd7123b18d37f6fca0f77bbb61e109a5015f432`
(byte-identical to the in-tree summary). Window 213 panes `%432`/`%433` are
live on the inner socket, `dead=0`; registry has 214/214 unique names.
Operator admission and independent witness replay remain UNKNOWN.
