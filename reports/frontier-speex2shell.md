# Frontier brief — speex2shell (CVE-2026-116741 / GHSA-jmfj-jxhf-c4c3)

Status: **staged 2026-11-26 by `frontier`, window 170, not admitted.**
Rungs 1–4 observed locally against a real libspeex build through public APIs;
rung 4 is demonstrated impact in the lab (attacker-chosen bytes at chosen
offsets in a live adjacent heap object), with explicit conditions below. No
pointer control, no command execution and no rung 5. Duplicate check before
provisioning: no `reports/frontier-*speex*`, no speex window/charter/mind on
the tape, absent from the do-not-duplicate list. Admission is the operator's;
wake units and full-flag sync stay with the person.

## 1. Verified ground truth

- Claim: https://github.com/advisories/GHSA-jmfj-jxhf-c4c3
  (CVE-2026-116741, published 2026-10-27), and reporter issue
  https://github.com/xiph/speex/issues/42 (opened 2026-10-22, closed).
  Claimed primitive: out-of-bounds write in
  `speex_bits_read_whole_bytes()` when the `SpeexBits` does not own its
  buffer (`speex_bits_init_buffer()` / `speex_bits_set_bit_buffer()`),
  corrupting heap or stack memory and crashing applications.
- Vendor fix: https://gitlab.xiph.org/xiph/speex/-/merge_requests/32,
  merge commit `09b569d1b437e5edccf3406a38714ad795e46d38`, one security
  hunk plus an unrelated signed-shift cleanup. GitHub tag listing at
  2026-11-26 shows no tag newer than `Speex-1.2.1`, so the fix commit is not
  in any public release; first released fixed tag is **UNKNOWN/NONE** and
  the fix commit is pinned as the fixed control.
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

- No pointer overwrite, no function-pointer control, no benign command
  marker, no live wire consumer and no r5. Rung 4 is limited to chosen bytes
  at code-determined offsets in an adjacent live object under the stated
  allocator conditions.
- The advisory also claims stack corruption; only the heap path was driven.
  Stack reachability is **UNKNOWN**.
- A later issue comment reports a negative truncated length / UBSan
  left-shift when the non-owned buffer is already full at the fix commit.
  That adjacent bug is preserved as a separate UNKNOWN and is not part of
  this claim; the harness primes only 8 of 16 bytes.
- The reporter's hackmd write-up was fetched but returned no text through
  the reader; the mechanism above comes from raw pinned source and the
  vendor diff, not from that page.

## 5. Cheapest next experiments

1. Drive the sink from a real decoder entry point (crafted Speex bitstream
   through `speex_decode`/`speex_bits_read_whole_bytes` on a non-owned
   buffer) to establish whether any network-facing consumer reaches it with
   attacker-controlled bytes.
2. Test whether the corrupted adjacent chunk metadata can be turned into a
   controlled allocation/layout primitive before any `free`, with safe
   controls; do not assume the current 8-byte data overwrite is enough.
3. Check upstream for a released tag containing `09b569d1` and replace the
   fix-commit control with the release if one exists.
