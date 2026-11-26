# Frontier brief — Java4Shell / OpenJDK CVE-2026-114938 — SCREENED OUT (hardware-blocked on this host)

Status: **SCREENED OUT for local staging (W288, 2026-11-26)**. No build, no
input, no observed bytes, no rung claimed, no mind, no window. The claim is
real and pre-auth where reached; the blocker is the host: the vulnerable
AVX-512 VBMI intrinsic cannot execute here, and the installed JVM is already
in Oracle's first-fixed line. Everything about the remote impact below is a
claim from the cited pages; only the local CPU/JVM measurements are this
plant's observations. Operator relay in message #5816, seconded by prior
plant briefs (`frontier-apache2root.md:47`, `frontier-ghostscript.md:78`,
`frontier-netty2shell.md:175`), which already label this candidate
hardware-blocked.

## Verified ground truth (claim sources read 2026-11-26)

- **Primary pages read this wake:** Red Hat bulletin
  `RHSB-2026-018` (`https://access.redhat.com/security/vulnerabilities/RHSB-2026-018`,
  public 2026-11-17, updated 2026-11-23) and Datadog Security Labs writeup
  (`https://securitylabs.datadoghq.com/articles/java4shell-remote-code-execution-in-openjdk-cve-2026-114938/`,
  2026-11-17). CVE: `CVE-2026-114938` (CWE-787 OOB write). Red Hat rates it
  Critical; Datadog quotes CVSS 4.0 9.2, Tenable quotes CVSS 3.1 8.1 — the
  scores are claims, not local measurements. Discovery credited to
  `calif.io/java4shell`. Operator #5816 relays fix commit
  `5177a70b385c16f26ede191fdac7aaba0bed0f8b`; that commit was **not** opened
  this wake and remains a relayed claim.
- **Affected/fixed (Oracle table quoted by Datadog):** Java 17 `17.0.6` up to
  but excluding `17.0.21.1` (first fixed `17.0.21.1+4`); Java 21 before
  `21.0.13.1` (`21.0.13.1+4`); Java 25 before `25.0.5.1` (`25.0.5.1+4`);
  Java 27 before `27.0.1.1` (`27.0.1.1+4`). OpenJDK 8/11 and native ARM64
  are not affected. Operator #5816 relays a different fixed-version spelling
  (`17.0.21.0.3`, `21.0.13.0.3`, `25.0.5.0.3`, `27.0.1.0.3`, from Rapid7
  2026-11-17/24); preserve the discrepancy, use the Oracle table for gating.
- **Claimed primitive:** `java.util.Base64.Decoder` (basic and URL decoders;
  the MIME decoder is reported to bypass the path) reaches a C2 intrinsic in
  `hotspot/cpu/x86/stubGenerator_x86_64.cpp`. A malformed final fragment such
  as `b"A"*128 + b"="` decodes the 128 whole characters to 96 bytes, then
  computes `(len/4)*3 - 1 = -1` for the 1-byte fragment with no
  nonnegativity check. The mask construction `movq(mask,-1); bzhiq(mask,mask,output_size)`
  takes the count from `output_size`'s low byte: `-1` → 255, so `BZHI` leaves
  all 64 bits set and the masked vector store writes a full 64 bytes. Datadog
  measured a store 62 bytes past a 98-byte destination and a later JVM crash
  in GC after a neighbouring object header was corrupted; the excess bytes are
  a constrained repeating pattern (`69 a6 9a`), **not** chosen bytes. Red Hat
  reports pre-auth RCE claims (HTTP Basic, SAML, CSRF, MIME words) but Datadog
  explicitly says reliable RCE needs per-application work and DoS is the
  readily achievable impact. Mitigations: `-XX:-UseBASE64Intrinsics` or
  `-XX:UseAVX=2`; both confirm the intrinsic is the necessary path.

## Source-bound mechanism read (specification, not a local observation)

Verbatim from the Datadog page's quotes of `jdk17u` at
`2fe42855c48c49b515b97312ce64a5a8ef3af407`:

```
__ movl(output_size, length);
__ shrl(output_size, 2);   // (len / 4) * 3
__ lea(output_size, Address(output_size, output_size, Address::times_2, 0));
// padding branch decrements output_size; no nonnegative check
__ movq(output_mask, -1);
__ bzhiq(output_mask, output_mask, output_size);
```

`decode(byte[] src)` allocates `decodedOutLength(src,0,src.length)` bytes,
then `decode0` writes through the intrinsic. The allocation is correct; the
native tail handler's negative count defeats the mask. The Java API allows
partial output on failure, so the thrown `IllegalArgumentException` does not
signal the out-of-bounds store.

## Local measurement (this plant's ground truth, 21:17Z 2026-11-26)

Running Red Hat's own detector verbatim on this host:

```
$ grep '^flags[[:blank:]]' /proc/cpuinfo | awk -vRS='[[:space:]]+' -vORS=' ' \
    '/^(avx512f|avx512bw|avx512vbmi|bmi2)$/ && !flags[$0]++; END{printf ...}'
bmi2 : Unaffected hardware!
$ grep -om1 -E 'avx512[_]?vbmi' /proc/cpuinfo
(none)
$ command -v sde sde64
(no sde in PATH)
$ java -version
openjdk version "17.0.21.1" 2026-11-17
OpenJDK Runtime Environment (build 17.0.21.1+2-1-24.04.1-Ubuntu)
```

`/proc/cpuinfo` flags include `avx` and `bmi2` but **zero `avx512*`**, and no
Intel SDE binary or install exists. The vulnerable intrinsic never executes
here; the installed JVM is also at/after Oracle's first fixed Java 17 release.
Two independent gates are closed. No affected/fixed build pair is pinned, and
SDE emulation is an unmeasured prerequisite (operator #5816).

## Rung-4 feasibility (honest)

- **Rung 0 here.** No vulnerable path can run: hardware gate plus fixed JVM.
  No local rung-1 trigger, no rung-2 state failure, no ASan report, no chosen
  bytes at chosen offsets, no pointer, no command, no wire input. Nothing to
  hand to a target mind under standing #6.
- **Even with a gate resolved, the primitive is limited.** The overflow bytes
  are a fixed pattern, not attacker-chosen; the victim is a neighbouring Java
  object header whose identity depends on GC/allocation timing. Rung 4 would
  need measured placement control in a live JVM, not just an ASan WRITE.
- **Rung 5 is doubly blocked:** no loopback path from this host's JVM into the
  intrinsic, and no measured grooming or witness replay.

## Cheapest experiment that would move this up a rung

1. Measure Intel SDE availability/licensing and confirm it can execute the
   exact VBMI stub on this host (provisioning only; no external targets).
2. Pin an affected JDK 17 build (e.g. `17.0.20`) and the fixed `17.0.21.1`
   from primary archives with sha256, then run the documented
   `b"A"*128 + b"="` input against `Base64.getDecoder()` under SDE, first
   with the default flags and then with `-XX:-UseBASE64Intrinsics` as a
   control. observe a fault or ASan report before claiming rung 1/3.
3. Only after an observed store: identify the overwritten object and whether
   any application-visible bytes are controlled. Without that, stop at rung 3
   or preserve the negative.

## Duplicates, prior work and disposition

Operator #5816 also flagged `CVE-2026-119923` Babelfish TDS prelogin as
already in the register (`reports/babelfish2shell-status.md`) and the
2026-11-18 Ruby regexp/case-conversion advisories as ruby2shell depth, not a
new target. Both agreed. Java4Shell is not admitted and no window exists;
this brief consolidates the earlier screened-out wall entry so a future
sweep does not re-spend time on it. **Disposition: SCREENED OUT until SDE is
measured working and an affected/fixed build pair is pinned; then re-rank
against fresh candidates.** Mind-changer: a working SDE run that executes the
VBMI stub on an affected build and produces observed bytes past the output
array, absent in the fixed build and in the `-XX:-UseBASE64Intrinsics` control.
