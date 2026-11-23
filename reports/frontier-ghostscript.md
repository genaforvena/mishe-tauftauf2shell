# Frontier brief — Ghostscript2Shell (STAGED — ghostscript2shell)

CVE-2026-125396 / "Upload2Shell" — Ghostscript `-dSAFER` bypass via
`.putgstringcopy` operand-type confusion, recovered `.forceput`, and a
save/restore use-after-free. Provisioned on 2026-11-23; on 2026-11-23 W134
a real-build rung-1/2 differential was measured and the find was staged as
ghostscript2shell. The native UAF/RCE chain remains a claim: no pointer
control, no command execution and no ASan corruption was exercised here.

## Verified ground truth

- Claim sources read 2026-11-23: OSV/CVE record
  `https://api.osv.dev/v1/vulns/CVE-2026-125396` (VulnCheck CNA, published
  2026-11-09, CWE-648, CVSS v4 vector
  `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`; the research page quotes 8.5),
  researcher index `https://pwn.ai/upload2shell` and technical writeup
  `https://pwn.ai/upload2shell/research.html`, upstream bug 709684, upstream
  fix commit `1484854e0c8ddfda1baa4ad4cd965b8a9790aa81`, oss-sec thread
  `https://seclists.org/oss-sec/2026/q4/806`.
- Affected `< 10.08.0`; fixed in `10.08.0` and in distribution updates
  (Debian `10.05.1~dfsg-1+deb13u3`, Ubuntu USN-8949-1). OSV lists fixed
  commits `05631c2c...` and `1484854e...`.
- Claimed primitive: a crafted Type 1 font load raises `typecheck` inside the
  privileged `.putgstringcopy` helper; a custom error handler returns with the
  stack arranged so execution resumes at `.forceput`, writing a local object
  into a surviving global dictionary. `restore` frees the object; allocation
  reuse leaves a dangling reference. The writeup demonstrates a native
  write-what-where, a one-shot function-pointer retarget (`mul` returned 18
  for 29×11 while `sub`-pointer was installed, then restored), and flipping
  four bytes of `path_control_active` to bypass `-dSAFER` and run a `%pipe%`
  command. Those are **claims with published proof excerpts, not local
  observations**; the case-study PoCs are marked "Not published".
- Attack-vector discrepancy worth preserving: the CVE CVSS vector is AV:L;
  the researcher demonstrates remote delivery through Debian 13 CUPS IPP
  Print-Job, Roundcube attachment thumbnails, WordPress/Forminator/Elementor
  public uploads, MediaWiki and DokuWiki. The interpreter flaw and the
  application delivery chain are different claims; do not merge them.

## Source-bound mechanism (pinned bytes and fix hunk)

Pins in `lab/frontier/ghostscript2shell/src/SHA256SUMS` (fetch URLs are
`raw.githubusercontent.com/ArtifexSoftware/ghostpdl/<ref>/Resource/Init/gs_fonts.ps`):

| Blob | Ref | SHA-256 (first 12) |
|---|---|---|
| `gs_fonts.ps.ghostpdl-10.07.0` | tag `ghostpdl-10.07.0` | `844ca0cb12ec` |
| `gs_fonts.ps.ghostpdl-10.07.1` | tag `ghostpdl-10.07.1` | `844ca0cb12ec` (byte-identical to 10.07.0) |
| `gs_fonts.ps.1484854e` | fix commit `1484854e` | `1ad111af10bc` |
| `fix-1484854e.patch` | commit patch | `8a279018297e` |

Vulnerable helper (`gs_fonts.ps:1024-1035`), verbatim:

```
/.putgstringcopy  %   <dict> <name> <string> .putgstringcopy -
{ 2 index gcheck currentglobal
  2 copy eq {
    pop pop .forceput
  } executeonly {
    5 1 roll setglobal
    dup length string copy
    .forceput setglobal
  } executeonly ifelse
} .forcebind odef % must be bound and hidden for .forceput
```

The fix wraps the body in an operand-type guard
(`dup type /stringtype eq 2 index type /nametype eq and 3 index type /dicttype
eq and`) and otherwise signals `typecheck`, preventing the error path from
reaching `.forceput`. The patch is a 10-line PostScript change (GitHub renders
it as a binary delta because of file encoding); the fetched fixed blob is the
authoritative post-fix bytes. This is a source-bound, shipped-code fix, not a
synthetic model.

## Feasibility assessment and cheapest next experiment

Rank: **high** among unowned candidates. The root fix is small and the exact
error-handler stack trick is described in the writeup; no special CPU feature
is needed (this host has `bmi2` but no AVX-512 VBMI, which is why Java4Shell is
hardware-blocked here). Downsides: the trigger is PostScript program logic
rather than a simple wire field; a faithful local proof needs a Ghostscript
build under ASan, a Type 1 font/Fontmap setup, and careful stack surgery; the
root CVE vector is AV:L, so remote impact depends on an application chain.

Local negative results (preserved): host `gs` is GPL Ghostscript 10.02.1
(`10.02.1~dfsg1-0ubuntu7.10`), whose `gs_fonts.ps` already carries the
backported type guard, so it is a usable FIXED control. A direct PostScript
call to `.putgstringcopy` with wrong operands returns `/undefined`, not
`typecheck`: the helper is hidden by `.bind executeonly odef`
(`systemdict /.putgstringcopy known` is false). Loading the pinned 10.07.0
resource into that binary via `-I/tmp/gsres` works (verified with strace) but
fails at startup with `/undefined in .internalbind`, so the newer resource is
not compatible with the older binary. The simple direct-call experiment is
therefore **ruled out**.

## W134 local result (2026-11-23 03:2x–03:3xZ) — rung 1/2, STAGED

Real builds, not a synthetic model. Ghostpdl 10.07.0 source tarball
(`ghostpdl-10.07.0.tar.gz`, sha256 `6e7c0c61c8df…0e6529a`, codeload tag
`ghostpdl-10.07.0`), extracted tree `ghostpdl-ghostpdl-10.07.0`; its bundled
`Resource/Init/gs_fonts.ps` hashes `844ca0cb12ec…d1a9c3233`, byte-identical
to the pinned vulnerable blob. Built with `./autogen.sh` (X11 probe fails,
`configure` is still generated), then `./configure --without-x --disable-cups`,
then `make -j2 gs`. Two binaries were produced from the same tree by swapping
only `Resource/Init/gs_fonts.ps` between the vulnerable tag blob and the
`1484854e` fixed blob and rebuilding: `harness/bin/gs-vuln` (sha256
`59e8c548cf6d…b67f0d852031ed1`) and `harness/bin/gs-fixed` (sha256
`0f3c962cd3e…d3ebe89291ce831163b816e495419fa4d6167f`). The tree was restored
to the vulnerable blob after both builds.

Reachability was established from shipped bytes: `.putgstringcopy` is defined
at `gs_fonts.ps:1026`, called only from `.loadfontloop` at `:1138` and `:1150`,
and hidden from systemdict by `.undefinternalnames` at `:1372`. A real Type 1
font (NimbusSans from `/usr/share/fonts/X11/Type1/NimbusSans-Regular.pfb`,
converted to PFA with the shipped `lib/pfbtopfa`) was given four injected
cleartext lines before `10 dict begin` that replace the loader filename string
at operand-stack depth 2 with a local array (`3 -1 roll pop [ … ] 3 1 roll`).
Font-file execution was measured directly: `DEPTH2_BEFORE=stringtype`,
`DEPTH2_AFTER=arraytype`, `count=10`. At the `.putgstringcopy` typecheck the
stack carries `--.putgstringcopy--`, `PathLoad` and the saved allocation-mode
boolean; the writeup's five-pop errordict `/typecheck` handler leaves that
boolean and pushes target/key/value so execution resumes at the bound
`.forceput`.

Harness `lab/frontier/ghostscript2shell/harness/`: `run.sh`, `rung1.ps`,
`font-injected.pfa`, `font-safe.pfa`, two binaries, `evidence/`. Three cases:

- vulnerable 10.07.0 + injected font → `TRAP_FIRED=true`,
  `GS_FORCEPUT_RESULT=true`: the recovered `.forceput` wrote a benign marker
  into the **readonly systemdict** (rung 1 trigger + rung 2 observed state
  failure, on shipped interpreter bytes).
- fixed `1484854e` + same font → `TRAP_FIRED=true`,
  `GS_FORCEPUT_RESULT=false`: the operand-type guard signals `typecheck`
  before the privileged path; the stack at the guard has count 14 vs 16 and
  no saved global boolean.
- vulnerable 10.07.0 + unmodified font → `TRAP_FIRED=false`,
  `GS_FORCEPUT_RESULT=false` (safe-input control).

22 PASS / 0 FAIL three times and from a clean minimal `/tmp` replay;
normalized trace `a4569485cb1fb98ab74b7d186e1566f18ede6bdb263cdb4e5e34f631e5683c29`.
Pins and hashes in `harness/run.sh`, `src/SHA256SUMS` and `PROVENANCE.md`.

Preserved negatives: host gs 10.02.1 is already patched and hides `.forceput`,
`.forcebind`, `.currentglobal` and `.undefinternalnames`, so a stock-binary
verbatim-slice harness is impossible. `-I` resource overrides never win over
the ROMFS-baked resource; the fixed control required a rebuilt binary. A first
stack-surgery attempt used `2 1 roll`/`2 -1 roll` (wrong: `roll`'s first
operand is an element count, not a depth) and left the filename a string;
corrected to `3 -1 roll`/`3 1 roll`. A naive save/restore UAF probe observed
`STALE_KEY=true` but `UAF_READ=null` — the 8-byte array did not reuse the freed
allocation, so no aliasing was demonstrated; the writeup's 2048-byte-string
marker scan was not attempted. No native ASan report, no pointer control, no
`-dSAFER` bypass exercised, no command execution, no application or network
delivery chain. The CVE CVSS vector is AV:L; the remote application paths are
separate claims.

## Disposition

STAGED as `ghostscript2shell` (charter, seed wall, two-pane window, registry
entry, operator DM). Frontier owns no further work on this lane. Frontier
continues with the next candidate; do not treat the researcher's remote RCE
claims as established. No pointer, marker or command was exercised at rung 5.

Mind-changer: a rebuild that lets the guard fire yet still writes, or a
reproducible allocated-object aliasing after `restore`.
