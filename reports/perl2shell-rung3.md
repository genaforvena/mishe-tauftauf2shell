# Perl2Shell rung 3 — CVE-2026-15534 local ASan confirmation

Status: **RUNG 3 (confirmed memory corruption) on a local loopback-only build.**
No rung 4 (chosen bytes / pointer control), no rung 5 (wire / RCE), no
independent witness replay yet. Written 2026-11-21 ~22:13Z by `perl2shell`.

## Claim and pin

- Claim: CPAN Security Group CVE-2026-15534, published 2026-08-09; fix commits
  `568e6fd238867bb9e99fa3f47cba3169009239e0` and
  `54cf3d44cbbedd17d774e9a37921963e8fd5d0cb`. Full provenance in
  `lab/frontier/perl2shell/PROVENANCE.md` and `reports/frontier-perl2shell.md`.
- Provisioned `https://www.cpan.org/src/5.0/perl-5.45.1.tar.gz` (21,350,704
  bytes). Extracted `regexec.c` and `regexp.h` are byte-identical (`cmp`) to
  the admission-pinned `lab/frontier/perl2shell/src/v5.45.1-regexec.c` and
  `v5.45.1-regexp.h`.
- Build: `./Configure -des -Dusedevel -DDEBUGGING
  -Doptimize='-g -O1 -fsanitize=address' -Aldflags='-fsanitize=address'`,
  `make -j2`, Linux x86-64, 2 CPUs, GCC/ASan. No service, no network probe,
  no traffic off host.

## Vulnerable arithmetic and derived trigger

`v5.45.1-regexec.c:9200-9206` computes `poscache_maxiter` in signed `I32`
from subject length × participating WHILEM count and clamps only negatives.
With 286331153 bytes and 15 WHILEMs:
`(286331153+1)*15 = 4294967310 = 2^32+14`, so the field wraps to **14** and
`regexec.c:9211` allocates `(14+7)/8 = 2` bytes. The read at `:9235-9240`
indexes by match position × 15.

The advisory names the length and count but publishes no pattern. Derived
locally: `'((a+)+)' x 15`. The pinned debug build prints `WHILEM[1/15]` …
`WHILEM[15/15]`, matching the source note at `:9189-9192` that the high nibble
of `FLAGS(scan)` is the number of relevant CURLYX/WHILEM pairs.

Harness `lab/frontier/perl2shell/repro.pl`: a 286331153-byte subject whose
last 16 bytes are `a`, `pos = len-16`, and `qr/\G((a+)+)…b/` (15 groups,
trailing `b` cannot match). The full length drives the wrap; `\G`/`pos` place
the working match near the end so `locinput-strbeg` is huge; the short tail
bounds backtracking. 16 is required: with 15, optimizer `minlen=16` made the
engine skip the match entirely ("Regex match can't succeed, so not even
tried"), recorded in `trace-vuln.txt`. A first attempt with a 256-byte tail
on the host perl did not finish in 60 s and was superseded by this bounded
tail, not retried into existence.

## Observed bytes / trace

Debug run (`trace-vuln2.txt`):

```
WHILEM: Detected a super-linear match, switching on caching...
==2193179==ERROR: AddressSanitizer: SEGV on unknown address 0x5020200126af
==2193179==The signal is caused by a READ memory access.
    #0 S_regmatch .../perl-5.45.1/regexec.c:9240
    #1 S_regtry .../regexec.c:4529
    #2 Perl_regexec_flags .../regexec.c:4077
SUMMARY: AddressSanitizer: SEGV .../regexec.c:9240 in S_regmatch
```

Clean replay (`evidence-vuln.txt`, `ASAN_OPTIONS=detect_leaks=0,
abort_on_error=1, allocator_may_return_null=1`, status 134) shows the same
fault; PID/address/path-normalised trace hash
`5848bedd0f6193eecc381247e416e47c7d1a57c7d5b68a46d4fe46c80bf9baac`.
This is an ASan-observed invalid READ at the exact vulnerable source line,
reached only after the cache activated: rung 3, not merely a crash.

The single-bit OR write `CACHEsayNO` (`regexec.c:6504-6507`) is **not**
observed: the process faults on the read first, before any write path. No
chosen byte, no pointer control, no bit flip in a live heap neighbour — no
rung 4 claim.

## Reproducibility limit (observed contradiction)

A second clean replay (`evidence-vuln2.txt`, same binary, same harness) did
**not** fault: it hit the 180 s `timeout` with `STATUS 124` and a different
normalised hash `80f27151ef0d18ada6ee40e43d7046f84295357eb76965f11175014b552622ef`.
Two of three runs (one `-Dr`, one clean) produced the ASan READ fault at
`:9240`; one timed out. The likely cause is layout: the wrapped 2-byte cache
is indexed ~536 MB away, so whether the read lands in mapped memory varies
with ASan heap placement. This is preserved as a negative result; the fault
is not claimed deterministic on every launch. A deterministic rung-1 trigger
would need a follow-up that pins the heap layout or maps the target region.

## Controls and limits

- 5.38.2 host perl with the same harness exits in 4.65 s with `NOMATCH`,
  `SUBJECT_CHANGES=0` (no ASan there; only a liveness/harness check, NOT a
  fixed-version control).
- The two CNA patches apply cleanly in sequence to the pinned source, but the
  resulting files are not byte-identical to the 5.45.2 tag (unrelated commits
  between them). The intended fixed control is "5.45.1 + both CNA fixes",
  verified by the STRLEN guard at `regexec.c:9208` and `STRLEN` field in
  `regexp.h`. **No fixed binary was produced in this wake**: resuming the
  interrupted `make -j2` hit the 1200 s job deadline while rebuilding Unicode
  tables (`build-vuln-resume.log`), before patching. Fixed-control replay is
  therefore UNKNOWN, not a pass. `build-fixed.sh` is staged for the next wake.
- Wire reachability UNKNOWN. CNA/CISA score `AV:L` and name no network
  consumer; no fixed pattern applied to attacker bytes on a live server is
  established here. No RCE wording or command execution belongs to this bug
  without a named wire-pure consumer and benign-command side effect.

## Reproduction

```sh
cd lab/frontier/perl2shell
./perl-5.45.1/perl -Dr -I./perl-5.45.1/lib repro.pl   # cache activation + trace
./run-asan.sh ./perl-5.45.1/perl vuln                 # evidence-vuln.txt + hash
```

Witness replay is owed on this exact build and harness before any rung is
marked ESTABLISHED.
