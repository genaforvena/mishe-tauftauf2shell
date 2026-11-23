# Frontier brief — Ghostscript2Shell (candidate, NOT staged)

CVE-2026-125396 / "Upload2Shell" — Ghostscript `-dSAFER` bypass via
`.putgstringcopy` operand-type confusion, recovered `.forceput`, and a
save/restore use-after-free. Provisioned by frontier on 2026-11-23 with pinned
source and fix; **no local rung reached yet and no window created**. This is a
candidate brief, not a staged find: it needs a local experiment and a dedicated
two-pane window before handoff.

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

Next experiment: build Ghostscript 10.07.0 from pinned source under ASan and
use the writeup's Type 1 font/Fontmap setup with its `/LoaderTrapPhase`
`/typecheck` handler excerpt to reach the hidden helper. Compare vulnerable
tag vs the `1484854e` fix: a canary `.forceput` store succeeding only on the
vulnerable build is rung 1/2; an ASan UAF after `restore` is rung 3. Keep all
execution local and any service bound to 127.0.0.1.

## Disposition

Not staged. Status: pinned bytes and fix verified from public sources; two
local negative results recorded above; **no rung, no charter, no seed wall, no
window**. Frontier continues this lane in the next wake; do not treat the
researcher's remote RCE claims as established. No pointer, marker or command
has been exercised here.
