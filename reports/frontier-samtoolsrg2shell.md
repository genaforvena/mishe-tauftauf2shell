# Frontier brief: samtoolsrg2shell — mpileup `-G` read-group stack overflow

**Status: FRONTIER-STAGED 2026-11-27 W339; ADMITTED 13:2xZ by the operator
under standing #6 as the 212th declared target mind; independent witness
replay UNKNOWN.**
Claim: GHSA-vh3p-9c59-j3hv (no CVE
assigned in the fetched advisory), CWE-121/CWE-787. Lab:
`lab/frontier/samtoolsrg2shell/`; exact source archives, patch, advisory,
reproduction commands and preserved negatives are in that tree. Live dedicated
inner-socket window 220 (`%446`/`%447`, `dead=0`) is registered 221/221 unique.
The trigger is a **local file** passed to `samtools mpileup -G`; no network
listener or wire input was run.

## Verified ground truth

- Primary source: `https://github.com/samtools/samtools/security/advisories/GHSA-vh3p-9c59-j3hv`
  (published 2026-10-27). Severity High; CVSS v4 vector
  `AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N`.
- Affected: `<=1.21.2`, `1.22.3`, `1.23.2`, `1.24`. Patched: `1.21.3`,
  `1.22.4`, `1.23.3`, `1.24.1`, `1.25`.
- Exact fix-parent `d177071e7b0ca1c622eb544a8698870040f23833` to fix
  `bd8b5dc8ade12e575ff2f02e8c0b7e384848a328` (2026-08-13). The patch changes
  one conversion width: `fscanf(fp_rg, "%s", buf)` to `"%1023s"`.
- Duplicate check: no samtools target or brief existed. Admitted
  `htslib2shell` is a different repository, advisory, sink and input; both
  merely touch BAM-related code.

## Source-bound mechanism

In vulnerable `bam_mpileup()`, case `G` declares `char buf[1024]` at pinned
`bam_plcmd.c:1292`, opens the `-G` file, then reads whitespace-free tokens with
unbounded `fscanf(fp_rg, "%s", buf)` at `:1298`. The file controls both bytes
and length; the write includes the terminating NUL. The fixed width caps each
conversion at 1023 bytes. No BAM input is needed: option parsing reaches the
sink before the later missing-input check.

The executed consumer was the real pinned `samtools mpileup` CLI, not a copied
sink or synthetic caller. Four binaries were rebuilt from immutable git
archives: vulnerable/fixed × ASan/plain, with pinned HTSlib `36ef0a191cf1c9ec2b2236640384926454a503fe`
and htscodecs `b9fc194f772e45bb0a1f44b08cbf8697a1384bae`.


`sh run-all.sh` verifies 8 source/advisory/patch pins and 4 harness pins,
rebuilds if needed, and returned `RUN_ALL_OK 24 PASS / 0 FAIL`. Summary SHA-256
`df418572e9065af5e64d12527f736ba420b61dc9fed0d0f97dac1401d31b414a`.
A clean `git archive 721ce2fc` extraction rebuilt all four binaries and
returned the same 24 PASS / 0 FAIL and byte-identical summary; author replay
is not witness acceptance.

- Vulnerable ASan: 1023-byte token clean; 1024 gives `WRITE of size 1025` at
  `bam_plcmd.c:1298`; 1200/2048/4096 give the same real-frame overflow.
- Fixed ASan: 1023/1024/1200/2048/4096 all clean, returning the ordinary
  `[mpileup] no input file/data given` error.
- Vulnerable plain: 1024 survives; 1200/2048/4096 terminate with SIGSEGV.
  Fixed plain remains clean at every length.
- Read-only GDB after `fscanf` sees 32 chosen `0x42` bytes at `buf+1024`.
  At 1200 bytes, `kh_put_str2int` receives `h=0x4242424242424242`. At 2048
  bytes, the saved return address is `0x4242424242424242` and the unwinder
  shows chosen return frames. The process faults first in `kh_put_str2int`;
  redirect to a chosen executable address was **not** observed.

Build conditions: GCC 13.3.0, glibc 2.39, x86-64, `-O0 -g`, stack protector
off; plain also uses `-fno-pie`. Default distro hardening and optimized-frame
geometry remain UNKNOWN.

## Grade and next experiment

R1/R2/R3 ✓ in the real CLI. **R4 DEMONSTRATED in this lab build**: chosen bytes
at chosen stack offsets, a chosen hash pointer, and a chosen saved return
address were observed. This is local-file control-data corruption, not code
execution. **R5 NOT CLAIMED**: no benign marker, command, live service or side
effect was observed.

The next useful work is a default/hardened vulnerable build to measure stack
canary and PIE effects, followed by the real consumer workflow that supplies
`-G` files. Any rung-5 claim still requires attacker-controlled input to make a
live target process execute a lab-chosen benign command with an observed side
effect and vulnerable/fixed/safe controls.

## Ranking context

Selected over lrzsz CVE-2026-105842 after source review: on this host lrzsz's
`malloc(PATH_MAX*2)` is 8192 bytes, matching the advisory's advertised filename
ceiling, while samtools provides a bulk chosen stack write and an immediately
reproducible real CLI. OpenColorIO CVE-2026-42450 remains a file-only backup;
Pigeonhole and Suricata remain screened weak primitives.
