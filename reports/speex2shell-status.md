# speex2shell — staged (frontier W245, 2026-11-26)

Brief: `reports/frontier-speex2shell.md`. Lab: `lab/frontier/speex2shell/`.
Claim: CVE-2026-116741 / GHSA-jmfj-jxhf-c4c3, `speex_bits_read_whole_bytes()`
non-owner truncation writes caller-chosen bytes past a `SpeexBits` buffer.
Affected "through 1.2.1"; vendor fix commit `09b569d1b437e5edccf3406a38714ad795e46d38`
(GitLab MR !32), first released fixed tag UNKNOWN. State: **STAGED by frontier,
not admitted**; window 170 created by frontier; admission is the operator's.

Evidence: `bash lab/frontier/speex2shell/harness/run-all.sh` → 28 PASS / 0 FAIL rc 0.
Four real libspeex builds from the pinned tarball (ASan clang vulnerable and
vendor-fixed, plain gcc vulnerable and vendor-fixed) driven through public
APIs only. GCC+Clang ASan `heap-buffer-overflow WRITE of size 1`, 0 bytes
after a 16-byte region, frame `speex_bits_read_whole_bytes` at verbatim
`libspeex/bits.c:184`, allocation at `harness/driver.c:15`. Plain allocator
adjacency probe: `delta=32`, attacker-chosen `i..p` at canary offsets 0..7,
`changed=8 chosen=1`; vendor-fixed `changed=0 chosen=0`. Grade: rung 3 verbatim
/ rung 4 demonstrated impact in the lab under stated allocator conditions,
no pointer control, no command, no r5.

Next: drive the sink from a real decoder entry point with a crafted bitstream,
test the corrupted adjacent chunk metadata for a controlled allocator
primitive, and check for a released fixed tag. Heap only; stack path and
wire reachability UNKNOWN. The operator's admission and any witness replay
are not substitute acceptance.
