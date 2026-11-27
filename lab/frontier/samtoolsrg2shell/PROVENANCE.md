# Provenance — samtoolsrg2shell

All sources were fetched as public provisioning. No external host was probed,
no listener was started, and every executed harness was local. The four source
archives and four text pins are immutable and verified by `SHA256SUMS` before
every run; four harness scripts are verified by `HARNESS_SHA256.txt`.
`build-real.sh` uses only those archives; it performs no network I/O.

| Artifact | URL / identifier | SHA-256 |
|---|---|---|
| Vulnerable `bam_plcmd.c` | `https://raw.githubusercontent.com/samtools/samtools/d177071e7b0ca1c622eb544a8698870040f23833/bam_plcmd.c` | `9031350b1d61dd71aed3a4cb7902ba6a3afad6b2e5843ff1b54d0c2c7074e51b` |
| Fixed `bam_plcmd.c` | `https://raw.githubusercontent.com/samtools/samtools/bd8b5dc8ade12e575ff2f02e8c0b7e384848a328/bam_plcmd.c` | `53092d00ad38c32ffefd11633fd7b535594c7599170e40d2502341c2b69845ef` |
| Full upstream fix patch | `https://github.com/samtools/samtools/commit/bd8b5dc8ade12e575ff2f02e8c0b7e384848a328.patch` | `ab206d61fb1f17dca4227c09a5be3b7e5ea851aa42c42979b5f8a0730beb778b` |
| Primary advisory HTML | `https://github.com/samtools/samtools/security/advisories/GHSA-vh3p-9c59-j3hv` | `70d5c8018a937689702dbdd66a3f9b987216a8efc8394e534e9948c35c8e44c3` |
| Vulnerable samtools source archive | exact commit `d177071e7b0ca1c622eb544a8698870040f23833` | `64193d53700a6054324f05c5fe8038f5ebf0dd4a1630e3780a2e7a9c68dcc94f` |
| Fixed samtools source archive | exact commit `bd8b5dc8ade12e575ff2f02e8c0b7e384848a328` | `76df38216c2f07af42cf9827c3607b319d4faf5aa63ccb171b769df40c3f2df6` |
| HTSlib source archive | exact commit `36ef0a191cf1c9ec2b2236640384926454a503fe` | `8b81e23f05cafc879065d698628645169798eb7b9a0896a58842242060ca05b8` |
| htscodecs source archive | exact commit `b9fc194f772e45bb0a1f44b08cbf8697a1384bae` | `4e608cd4015b6c6447c289e7c3c296f77fca2e8912623823363c9c26cd0579f0` |

Advisory: GHSA-vh3p-9c59-j3hv, published 2026-10-27, High, CWE-121/CWE-787,
CVSS v4 vector `AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N`.
No CVE was assigned in the fetched advisory. Affected releases are `<=1.21.2`,
`1.22.3`, `1.23.2`, and `1.24`; patched releases are `1.21.3`, `1.22.4`,
`1.23.3`, `1.24.1`, and `1.25`. The fix commit is dated 2026-08-13.

The pinned pair is exact fix-parent `d177071e` to fix `bd8b5dc8`. In the
vulnerable `bam_mpileup()` option parser, case `G` declares `char buf[1024]`
at `bam_plcmd.c:1292`, opens the user-selected read-groups file, and calls
`fscanf(fp_rg, "%s", buf)` at `:1298`. A whitespace-free token supplies both
the bytes and length. The fix changes only the conversion width to `%1023s`.
The terminating NUL is included in the observed write size.

`build-real.sh` builds real `samtools mpileup` binaries, not a copied sink:
vulnerable/fixed × ASan/plain, with pinned HTSlib. Toolchain observed here:
GCC 13.3.0, glibc 2.39, x86-64. HTSlib is built with libcurl, bzip2 and lzma
disabled; curses is disabled. ASan uses `-O0 -g -fsanitize=address
-fno-omit-frame-pointer -fno-stack-protector`. Plain uses `-O0 -g
-fno-omit-frame-pointer -fno-stack-protector -fno-pie`. These are lab
conditions; default distro hardening and optimized-frame geometry are UNKNOWN.

The htscodecs archive intentionally omits its ignored generated
`htscodecs/version.h`; `build-real.sh` writes the observed `1.6.7` version
string before building. No htscodecs source is modified.

Observed real-CLI results:

- Vulnerable ASan: 1023-byte token is clean; 1024 gives `WRITE of size 1025`
  at `bam_plcmd.c:1298`; 1200/2048/4096 give the same source-bound overflow.
- Fixed ASan: 1023/1024/1200/2048/4096 all return the ordinary
  `[mpileup] no input file/data given` error, with no ASan report.
- Vulnerable plain: 1024 survives; 1200/2048/4096 terminate with SIGSEGV.
  Fixed plain remains clean for every length.
- Read-only GDB at the post-`fscanf` line sees 32 chosen `0x42` bytes at
  `buf+1024`. At 1200 bytes, `kh_put_str2int` receives
  `h=0x4242424242424242`. At 2048 bytes, the saved return address is
  `0x4242424242424242` and the unwinder shows chosen return frames. The
  process still faults first in `kh_put_str2int`; no redirect to a chosen
  executable address was observed.

The trigger is a local file passed to `samtools mpileup -G`. No BAM input is
needed because option parsing reaches the sink before the missing-input
check. This is not a network-delivered primitive. No benign marker, shell
command, live service, or command side effect was observed; rung 5 is not
claimed.
