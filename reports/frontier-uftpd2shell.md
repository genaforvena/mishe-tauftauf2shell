# Frontier brief — uftpd2Shell

Candidate: **uftpd `compose_path()` overlong-path stack overflow**,
CVE-2026-59964 / GHSA-vqhc-mmjf-972h. Grade: **rungs 1/2/3 ESTABLISHED in a
harness that compiles the verbatim pinned upstream `compose_path()`; rung 4
INSTRUMENTED chosen-byte control only** (no live stock uftpd, no useful-pointer
control). Produced 2026-11-21 in the frontier wake starting 02:16Z. This is a
research find, not an admission; the operator decides targets.

Ranking: **high tractability, medium priority**. Affected/fixed releases, the
fix commit and vulnerable/fixed bytes are all pinned, and the harness is small
and deterministic. Against it: CVSS 3.1 5.9 MEDIUM, `PR:L` (a logged-in client;
anonymous or guest counts where enabled), and the advisory itself states RCE
has not been demonstrated. Work this lane only after higher-ranked PR:N
candidates are exhausted or held.

## Verified ground truth

- Sources read this wake (read-only provisioning; no off-loopback probe): the
  authoritative cvelistV5 JSON at
  `https://cveawg.mitre.org/api/cve/CVE-2026-59964`, the maintainer advisory
  page `GHSA-vqhc-mmjf-972h`, the fix commit and its `.patch`, and raw
  `src/common.c` at tags `v2.15` and `v2.16`. Hashes and URLs are in
  `lab/frontier/uftpd2shell/PROVENANCE.md`.
- CNA GitHub_M (maintainer), published 2026-11-18, updated 2026-11-19. CWE-121
  stack-based buffer overflow. CVSS 3.1 5.9 MEDIUM
  `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H`. Affected `< 2.16`, fixed in `2.16`.
  CISA ADP SSVC: Exploitation `poc`, Automatable `no`, Technical Impact
  `partial`.
- Claimed primitive: with the server running **without chroot**, `compose_path()`
  in `src/common.c` prepends the configured home directory to a near-`PATH_MAX`
  attacker path using `memmove`, overflowing the local `dir[PATH_MAX]` stack
  buffer. A logged-in FTP client (anonymous/guest where enabled) reaches it via
  CWD, RETR, STOR or LIST. The advisory claims memory corruption and a reliable
  crash; it explicitly says remote code execution has not been demonstrated.
  The 404 on the GitHub advisory API is recorded in `PROVENANCE.md`; the
  cvelistV5 record and advisory page were the sources actually read.

## Source-bound mechanism

Verbatim from pinned `src/common.c` at tag `v2.15`:

```c
char dir[PATH_MAX] = { 0 };
...
strlcpy(dir, ctrl->cwd, sizeof(dir));
...
strlcat(dir, path, sizeof(dir));     /* dir length <= PATH_MAX-1 */
...
if (!chrooted) {
    size_t len = strlen(home);
    if (len > 0 && home[len - 1] == '/')
        len--;
    memmove(dir + len, dir, strlen(dir) + 1);   /* v2.15:61 — writes len bytes past dir */
    memcpy(dir, home, len);                     /* v2.15:62 */
}
```

`strlcat` caps `dir` at `PATH_MAX-1` bytes, so `strlen(dir)+1 == PATH_MAX`;
shifting that string right by `len` writes `PATH_MAX + len` bytes into a
`PATH_MAX` buffer — exactly `len` bytes out of bounds. The overflowed bytes are
the tail of the attacker's path, so both the length (via the configured home
prefix) and the bytes are attacker-influenced.

Fix commit `f5552a8c6a5f14691f51bef1f3373747259d7ac8` ("Bound path length when
composing non-chroot paths") adds 11 lines before the `memmove`:

```c
if (len >= sizeof(dir))
    len = sizeof(dir) - 1;
if (strlen(dir) + 1 > sizeof(dir) - len)
    dir[sizeof(dir) - len - 1] = 0;
memmove(dir + len, dir, strlen(dir) + 1);   /* now in bounds */
```

Pinned v2.16 carries that guard; v2.15 does not (hashes in `PROVENANCE.md`).

## Local evidence

Harness: `lab/frontier/uftpd2shell/{driver.c,uftpd.h,run.sh,PROVENANCE.md}` plus
pinned `src/` bytes. `run.sh` extracts the **verbatim** `compose_path()` from
each pinned `common.c` at replay time and pads line numbers so ASan frames match
the upstream file. `uftpd.h` is a minimal stand-in header (real `cwd[PATH_MAX]`
field, `home`/`chrooted` globals, no-op log macros); the function body is not
reimplemented. gcc 13.3.0, `-O0 -g`, glibc `strlcpy/strlcat`.

```
bash lab/frontier/uftpd2shell/run.sh <outdir>
-> 23 PASS lines, ALL CHECKS PASS rc 0
   sha256=ad11094aa03e898df6c3b00a83b6b8ba8a9b049e0a0a18bf5fd952475d09d33b
```

Three independent replays were byte-identical; relative and absolute outdirs
both pass (the script absolutizes `out` after `mkdir`). The trace hash excludes
ASan PID/address/path text.

- Rung 1 — deterministic trigger: `path_len=4095` (`PATH_MAX-1`), configured
  `home_len=128`, `expected_oob=128`; the vulnerable upstream line is reached.
- Rung 2 — observed state failure: the plain build (`-fstack-protector-all`)
  aborts with `*** stack smashing detected ***` — the 128-byte OOB memmove
  overwrote the frame's stack canary. No readback claim is made from it.
- Rung 3 — ASan `stack-buffer-overflow`, `WRITE of size 4096`, victim `dir`
  object `[256, 4352)` in `compose_path`'s frame, first bad address at offset
  `4352` (`overflows this variable`). Frame `compose_path` at pinned
  `common.c.v2.15:61`; the buffer is declared at `:36`.
- Rung 4 — chosen `UFTPD2SHELL!` marker (first four bytes `55465450`) at the
  start of the OOB slice and `0x1122334455667788` at `+40` are supplied in the
  client path and written by the upstream memmove. **INSTRUMENTED only** — no
  live uftpd process, no stock frame layout, no return-address/pointer control.
- Fixed control: v2.16's guard NUL-terminates `dir` before the memmove; same
  input gives rc 0, no canary abort, `returned=null`, guard present in the
  pinned source.

## Rung-4 feasibility

Favourable: a real byte-exact `memmove` stack write, attacker-supplied bytes,
a pinned 11-line fix that pins the intended semantics, and a published PoC
marker (SSVC `Exploitation: poc`) — the write consumer is a real libc intrinsic,
so the nginx-plant structural-zero-store lesson does not apply.

Unfavourable / UNKNOWN: `PR:L` — a logged-in client (anonymous/guest only where
enabled); non-default no-chroot configuration; whether a stock build's stack
canary, saved registers or return address are reachable with the default
`/srv/ftp` home (9-byte overflow) is UNKNOWN and was not tested here; the real
server's frame layout and allocator are UNKNOWN; RCE is not demonstrated by the
advisory and is not claimed here. Downgrade to rung 3 if a stock build shows the
overflow cannot reach a useful control datum.

## Cheapest experiment to move a rung

Build pinned uftpd `v2.15` with ASan and stack-protector disabled, run it as a
non-root user with `-h` pointing at a non-chroot directory and anonymous (or a
test account) enabled on 127.0.0.1, then send `CWD`/`RETR` with a 4095-byte path.
Observe the ASan frame and dump the bytes written past `dir[]`, then repeat with
the default `/srv/ftp` home to see whether a 9-byte overwrite still reaches a
control datum. A positive result moves rung 4 to real-process chosen-value
control; a negative one is a structural blocker worth recording.

## Failed hypotheses and negatives

- The harness initially failed extraction because the generated filename ends
  in `.v2.15`, so gcc treated it as an object file; fixed with `-x c` and an
  explicit stub-header `-include`. No evidence claim was made from failing runs.
- A first attempt at multi-line `awk` extraction produced blank-only files;
  replaced with an explicit line-range copy keyed on the pinned signature line.
- No live uftpd process, no stock layout, no real useful-pointer control.

## Next owner

Witness re-runs the replay; operator decides admission. If admitted, the new
target mind owns the real-build experiment above; frontier does not duplicate
that lane.
