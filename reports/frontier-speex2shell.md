# Frontier brief — speex2shell (CVE-2026-116741 / GHSA-jmfj-jxhf-c4c3)

Status: **staged 2026-11-26 by `frontier`, window 170, not admitted.**
Witness W245 (2026-11-26 04:35Z): replay ESTABLISHED AS LABELED, no grade
change, NO r5; evidence in the witness wall and its W245 detail artifact.
Rungs 1–4 observed locally against a real libspeex build through public APIs;
rung 4 is demonstrated impact in the lab (attacker-chosen bytes at chosen
offsets in a live adjacent heap object), with explicit conditions below. The
witness verdict covers no pointer control; an additive in-process pointer
control result is recorded in §6. No command execution and no rung 5.
Duplicate check before provisioning: no `reports/frontier-*speex*`, no speex
window/charter/mind on the tape, absent from the do-not-duplicate list.
Admission is the operator's; wake units and full-flag sync stay with the person.

Update 2026-11-26 (speex2shell wake): an in-process function-pointer overwrite
and benign marker are now demonstrated under the same four conditions (§6),
and the bundled-decoder reachability experiment returned a negative (§6).
No wire consumer, no command and no r5; W245 witness verdict is unchanged and
does not cover these additive observations.

Update 2026-11-26 ~17:15Z (speex2shell wake): the corrupted neighbour chunk
size field was turned into a controlled tcache-bin confusion with an
overlapping allocation in the vendor-vulnerable build and a clean fixed
control (§6). This probe deliberately adds a `free()` of the corrupted
chunk, so its conditions differ from the staged rung-4 claim; no command,
wire path or r5.

Update 2026-11-26 ~17:45Z (speex2shell wake): the advisory's stack-corruption
claim was driven with the pinned builds — ASan `stack-buffer-overflow` at
verbatim `bits.c:184` and chosen bytes in an adjacent stack canary, both with
clean vendor-fixed controls (§6). No wire consumer, command or r5; the two
stack-related UNKNOWNs are now answered as lab observations.

## 1. Verified ground truth

- Claim: https://github.com/advisories/GHSA-jmfj-jxhf-c4c3
  (CVE-2026-116741, published 2026-10-27), and reporter issue
  https://github.com/xiph/speex/issues/42 (opened 2026-10-22, closed).
  Claimed primitive: out-of-bounds write in
  `speex_bits_read_whole_bytes()` when the `SpeexBits` does not own its
  buffer (`speex_bits_init_buffer()` / `speex_bits_set_bit_buffer()`),
  corrupting heap or stack memory and crashing applications.
- Vendor fix: https://gitlab.xiph.org/xiph/speex/-/merge_requests/32,
  MR !32 head commit `09b569d1b437e5edccf3406a38714ad795e46d38`, one security
  hunk plus an unrelated signed-shift cleanup. A direct GitLab refs query
  (2026-11-26 ~16:40Z) finds that commit on branches
  `fix/read-whole-bytes-oob-write` and `main` and on **no tag**; GitHub and
  GitLab tag lists both top out at `Speex-1.2.1`. No released fixed version
  exists as of that query, so the fix commit is pinned as the fixed control.
  Raw output: `lab/frontier/speex2shell/evidence/released-tag-check.txt`.
- Source pins: tarball `beaf2642e81a822eaade4d9ebf92e1678f301abfc74a29159c4e721ee70fdce0`
  (tag `Speex-1.2.1`); raw `libspeex/bits.c` at that tag
  `bd36b8081282f5a6e9558b2ed8a0acace0a6c3c976587802b466ff8c628a335a`; at
  the fix commit `cc326d16a06cf3758fd8c7182d0bae58d09ecf6947c957c820de1ea800f99461`.
  Full ledger in `lab/frontier/speex2shell/PROVENANCE.md`.

## 2. Source-bound mechanism read from the patch

Verbatim `libspeex/bits.c:156-185` at `Speex-1.2.1`:

```
int nchars = nbytes/BYTES_PER_CHAR;
if (((bits->nbBits+7)>>3)+nchars > bits->buf_size) {
    if (bits->owner) { ... realloc/truncate ... }
    else {
        speex_warning("Do not own input buffer: truncating oversize input");
        nchars=bits->buf_size;          /* line 177: ignores bytes already buffered */
    }
}
speex_bits_flush(bits);
pos=bits->nbBits>>LOG2_BITS_PER_CHAR;
for (i=0;i<nchars;i++)
    bits->chars[pos+i]=HTOLS(chars[i]); /* line 184: sink */
bits->nbBits+=nchars<<LOG2_BITS_PER_CHAR;
```

`nchars` is set to the whole `buf_size`, not the remaining space. The vendor
fix replaces line 177 with
`nchars=bits->buf_size-(bits->nbBits>>LOG2_BITS_PER_CHAR)-1;`, i.e. remaining
capacity. With a 16-byte non-owned buffer, 8 bytes already buffered (`nbBits=64`,
`pos=8`) and a 16-byte input, the loop writes bytes 0..15 at offsets 8..23: 8
bytes land past the allocation. The overflowed byte values are the caller's
input bytes, not a fixed constant.

## 3. Local evidence

`bash lab/frontier/speex2shell/harness/run-all.sh` → **28 PASS / 0 FAIL, rc 0**.
Four real static libspeex builds are made from the pinned tarball via
autotools: ASan (clang) vulnerable and vendor-fixed, plain (gcc) vulnerable
and vendor-fixed. Drivers use only public headers/APIs.

- **Rung 1 (reproducible trigger)**: deterministic in every run; no ASan on
  safe input (8-byte read) and no ASan on the vendor-fixed build.
- **Rung 2 (state failure)**: plain vulnerable `nbytes=24`, `nbBits=192` for
  a 16-byte buffer; safe `nbytes=16`; vendor-fixed attack `nbytes=15`,
  `nbBits=120`.
- **Rung 3 (confirmed corruption)**: GCC and Clang ASan both report
  `heap-buffer-overflow`, `WRITE of size 1`, 0 bytes after a 16-byte region,
  frame `speex_bits_read_whole_bytes` at verbatim `bits.c:184`, allocation at
  `harness/driver.c:15`. Outputs:
  `evidence/asan-gcc-vuln-attack.out`, `evidence/asan-clang-vuln-attack.out`.
- **Rung 4 (demonstrated impact, conditions)**: with the plain allocator,
  two sequential oversize reads grow `nbBits` to 192, so the second write
  starts at `buf+24`; `harness/adjacent.c` mallocs a 16-byte canary
  immediately after `buf` (`delta=32`) and records
  `canary=696a6b6c6d6e6f705a5a5a5a5a5a5a5a5a` — the caller-chosen bytes
  `i..p` at canary offsets 0..7 — with `changed=8 chosen=1`. The vendor-fixed
  build gives `changed=0 chosen=0` under the identical input. Conditions:
  non-owner `SpeexBits`, glibc sequential `malloc(16)` adjacency, two calls,
  and no `free()` of the corrupted canary chunk header (the probe deliberately
  exits without freeing). Outputs: `evidence/adjacent-vuln-plain.out`,
  `evidence/adjacent-fixed-plain.out`.

Witness replay: `bash lab/frontier/speex2shell/run-witness.sh` rehashes six
pins, deletes every build and evidence file, rebuilds from the tarball and
re-asserts the sink and the adjacent bytes; result recorded in the wall.

## 4. Ceiling and negatives

- A function-pointer overwrite and an in-process benign marker are now
  demonstrated (§6): chosen bytes at canary offsets 0..7 replace a live
  neighbour's function pointer and a call through it fires the marker. That
  is rung-4 mechanics; it is not command execution, not a wire path and not
  r5. The underlying primitive remains chosen bytes at code-determined
  offsets in an adjacent live object under the stated allocator conditions.
- No benign command, no live wire consumer and no r5.
- The advisory's stack-corruption claim is now driven (§6): a stack-backed
  non-owner `SpeexBits` produces an ASan `stack-buffer-overflow WRITE of size
  1` at verbatim `bits.c:184`, and the plain build lands chosen bytes in an
  adjacent stack canary. Still no command, wire path or r5.
- The later issue #42 comment's already-full-buffer case was measured at the
  pinned fix commit (§6): UBSan `left shift of negative value -1` at
  `bits-fix-09b569d1.c:185:24`, `nbytes=8`. That is a separate bug in the fix,
  not part of this OOB claim; the main harness primes only 8 of 16 bytes.
- The reporter's hackmd write-up returned no text when first fetched and
  HTTP 404 on a 2026-11-26 ~17:47Z retry; the mechanism above comes from raw
  pinned source and the vendor diff, not from that page.

## 5. Cheapest next experiments

1. **Answered negative for the bundled source tree.** No production caller
   of `speex_bits_read_whole_bytes` exists in `src-vuln/`; every real
   consumer (`src/speexdec.c:678`, OSS-Fuzz `speexdec_fuzzer.cc:294`,
   `speexclient/speex_jitter_buffer.c:70`, `doc/sampledec.c:46`, TI decoders)
   uses `speex_bits_read_from`, which resets `nbBits` and writes from offset
   0, so a crafted bitstream through those paths cannot reach `bits.c:184`.
   Reaching the sink requires an external application that uses the append
   API on a non-owned, already-buffered `SpeexBits`; no such consumer was
   identified. Wire reachability stays UNKNOWN.
2. **Answered additively (§6).** The corrupted neighbour chunk `size` field
   (`p2[0..7]` at `buf+24..31`) was forged to `0x31`; after a deliberately
   added `free(v)` the 0x20 chunk enters the 0x30 tcache bin, `malloc(32)`
   returns it with a 32-byte user area overlapping the next chunk's header,
   and the fixed control does neither. Conditions differ from the staged
   claim, which frees nothing.
3. **Answered negative at query time.** GitLab's refs query lists the fix
   commit on two branches and no tag, and both mirrors' newest tag is
   `Speex-1.2.1`; there is no released fixed build to replace the pinned fix
   commit control. Raw evidence:
   `lab/frontier/speex2shell/evidence/released-tag-check.txt`.

## Witness verdict — W245 (tape #4847, 2026-11-26 04:35Z)

The unmodified top-level `run-witness.sh` (sha256 `1dc5d05c…1a7b84f`) passed
`REPLAY_PASS=10 REPLAY_FAIL=0`, `TOTAL: 28 PASS / 0 FAIL`, rc 0 from a clean
`git archive 2daaa4ee` tree and, serially, in the worktree. Independent raw
GETs reproduced all three source/tarball pins; GitLab MR !32 is merged at the
pinned head commit with exactly the security hunk, and the pinned vulnerable
and fixed files differ in only that hunk plus the unrelated signed-shift
cleanup. GCC+Clang ASan `WRITE of size 1` at verbatim `bits.c:184`, chosen
`i..p` in the adjacent canary with `changed=8 chosen=1`, fixed and safe
controls clean. A first replay attempt run concurrently with the clean-tree
replay failed in autotools setup; serial reruns in both trees passed, so the
failure is preserved as a concurrency artifact, not a reproduced claim defect.
VERDICT: ESTABLISHED AS LABELED, grade unchanged (rung 3 verbatim / rung 4
lab impact under stated conditions), NO pointer control, command, wire path
or r5. Stack path, released fixed tag and the follow-up UBSan observation
stay UNKNOWN. Full evidence:
`.mishe-tauftauf/artifacts/witness-w245-speex2shell/detail.md`.
Two wording NITs are folded above and in `PROVENANCE.md`: the wrapper path
and the "merge commit" label for the one-parent MR head commit.

Later additive check (not part of the W245 verdict): the released-fixed-tag
item above was resolved negative as of 2026-11-26 ~16:40Z by a direct GitLab
refs query (§1 and §5.3); the witness's UNKNOWN stands as its own observation.

## 6. Additive wake 2026-11-26 (speex2shell, author-observed)

Consumer-path check (read-only source inspection of the pinned tree):
`grep -n 'speex_bits_read_from|speex_bits_read_whole_bytes' src-vuln/`
shows the vulnerable append function only at its definition
(`libspeex/bits.c:156`) and declaration (`include/speex/speex_bits.h:88`).
`speex_bits_read_from` (`bits.c:109-145`) truncates non-owner oversize input
to `buf_size`, writes at `chars[0..]`, and sets `nbBits=nchars<<3`, so it has
no `pos`-offset overflow. No in-tree bitstream path reaches `bits.c:184`.

Pointer-control probe `harness/ptr-control.c`, run by
`bash lab/frontier/speex2shell/harness/ptr-control.sh` (8 PASS / 0 FAIL,
rc 0) against the existing plain gcc libspeex static libraries, no rebuild
of the pinned trees. Conditions unchanged: `speex_bits_init_buffer` with a
16-byte heap buffer, `owner=0`, an 8-byte seed read, then two 16-byte
oversize reads, `delta=32`, no free. The neighbour is a 16-byte struct
`{ void (*fn)(void); unsigned long tag; }`; the second read's bytes 8..15
land at its `fn` field. The address of `benign_marker` is resolved at
runtime and copied into `p2[8..15]`, so ASLR is handled by the input itself.

Vulnerable build (`evidence/ptr-vuln-plain.out`, one observed run):
`delta=32`, `target=0x56c8c6b362a9 bytes=a962b3c6c8560000`,
`vfn=0x56c8c6b362a9 tag=5a5a5a5a5a5a5a5a`, `BENIGN_MARKER_CALLED`,
`marker_called=1`, rc 0. Vendor-fixed build
(`evidence/ptr-fixed-plain.out`): `delta=32`, `vfn` remains the original
`noop` pointer, `marker_called=0`, rc 0, and `tag` intact in both. The
script also asserts `vfn` equals the printed chosen target. This upgrades
rung 4 from data bytes to in-process function-pointer control plus benign
marker execution; it remains rung-4 mechanics because the consumer is a
harness, no command runs and no wire or request input is involved. The two
reads still corrupt the neighbouring chunk header, which is never freed, as
in the staged claim. Not independently replayed by the witness.

### Allocator-size / overlapping-allocation probe (~17:15Z)

`harness/alloc-primitive.c` and `harness/alloc-primitive.sh` (new, unpinned)
use the same non-owner 16-byte `SpeexBits`, 8-byte seed and two oversize
reads. `adjacent.c` put caller bytes at canary offsets 0..7; the same bytes
can instead be read as the neighbour's malloc **chunk size** field: the
second read's `p2[0..7]` land at `buf+24..31`. The probe sets that field to
`0x31` while the original chunk size is `0x21`, sets a plausible next-chunk
size in harness-controlled heap layout, then calls `free(v)` and
`malloc(32)`. Vulnerable plain gcc (`evidence/alloc-vuln-plain.out`):
`bsize_before=0x21 bsize_after=0x31`, `reuse=1 re=v`,
`csize_after=0xabababababababab overlap=1`. Vendor-fixed
(`evidence/alloc-fixed-plain.out`): `bsize_after=0x21`, `reuse=0`,
`overlap=0`. `bash lab/frontier/speex2shell/harness/alloc-primitive.sh`
reported 9 PASS / 0 FAIL, rc 0; six direct repeat runs also rc 0.
This is a controlled heap-layout primitive in the lab, not a command or a
wire path. **Condition change:** unlike the staged rung-4 claim and the
pointer probe, this experiment *does* free the corrupted chunk; glibc
tcache behaviour and the harness-seeded next-chunk size are part of the
observation. Not replayed by the witness.

### Stack path (~17:45Z)

`harness/stack-asan.c` puts the non-owner 16-byte buffer on the **stack** and
reuses the pinned clang ASan libs. Vulnerable run
(`evidence/stack-asan-vuln.out`): `ERROR: AddressSanitizer:
stack-buffer-overflow`, `WRITE of size 1`, frame
`speex_bits_read_whole_bytes ... bits.c:184:25`, rc 1. Vendor-fixed
(`evidence/stack-asan-fixed.out`): rc 0, `nbytes=15`, no ASan report.
`harness/stack-canary.c` uses a stack struct
`{ char buf[16]; char canary[16]; }` and the two sequential oversize reads
with the plain gcc libs: `delta=16`,
`canary=7172737475767778696a6b6c6d6e6f70` (payload[8..15] then
payload[0..7]), `changed=16 chosen=8` vulnerable
(`evidence/stack-canary-vuln.out`); `canary=5051…5f`, `changed=0 chosen=0`
fixed (`evidence/stack-canary-fixed.out`). `bash harness/stack-path.sh` →
12 PASS / 0 FAIL rc 0; five repeat runs also rc 0. The harnesses are unpinned
and not replayed by the witness. This resolves the advisory's stack-corruption
UNKNOWN as a lab rung-3/rung-4 observation under the same non-owner/oversize
conditions; no pointer, command, wire path or r5.

### Already-full-buffer UBSan case at the pinned fix (~17:49Z)

Issue #42 comment by @GeekQAQ (2026-11-20) supplies an exact reproducer and
claims a negative truncated length at the vendor fix. `harness/ubsan-fixed-
case.c` is that input verbatim; `harness/ubsan-fixed-case.sh` compiles the
pinned `pinned/bits-fix-09b569d1.c` with `-fsanitize=undefined` and links it
ahead of the pinned fixed libspeex archive so the library shift is
instrumented. Result (`evidence/ubsan-fixed-case.out`):
`UndefinedBehaviorSanitizer`, `left shift of negative value -1` at
`bits-fix-09b569d1.c:185:24`, `nbytes=8`, rc 0; 5 PASS / 0 FAIL. The comment's
two-line clamp (`if (nchars<0) nchars=0;`) was also checked in a throwaway
build: no UBSan report, `nbytes=9`, matching the claim. This resolves the
previously UNKNOWN follow-up observation as a measured, separate bug at the
fix commit; it is not CVE-2026-116741's OOB write, not a wire path, command or
r5, and not witness-replayed.
