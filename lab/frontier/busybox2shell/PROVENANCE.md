# Provenance — busybox2shell W182 (2026-11-23)

All fetches were public-source provisioning; every packet in the harness binds
only to 127.0.0.1. No external target was contacted.

## Claim sources

- NVD `https://nvd.nist.gov/vuln/detail/CVE-2026-124737` (fetched 2026-11-23,
  Awaiting Analysis, published 2026-11-11, modified 2026-11-17).
- Red Hat `https://access.redhat.com/security/cve/CVE-2026-124737`.
- Red Hat Bugzilla `https://bugzilla.redhat.com/show_bug.cgi?id=2571607`.
- Debian/OSV `https://osv.dev/vulnerability/DEBIAN-CVE-2026-124737`.
- Upstream patch, Yehyeong Lee, 2026-09-19:
  `https://lists.busybox.net/pipermail/busybox/2026-September/092488.html`
  (mirror `http://www.mail-archive.com/busybox@busybox.net/msg31059.html`).

## Pins and rebuild

`PINS.sha256` lists the tarball, the vulnerable and fixed `networking/tftp.c`
copies, the one-line fix diff, the minimal config and all three binaries.
Tarball: `https://busybox.net/downloads/busybox-1.37.0.tar.bz2`.

Rebuild of the vulnerable ASan binary (all commands from this directory):

```
tar xjf busybox-1.37.0.tar.bz2
cp busybox.config busybox-1.37.0/.config
(cd busybox-1.37.0 && make -j8 \
  CFLAGS="-g -O1 -fsanitize=address -fno-omit-frame-pointer" \
  LDFLAGS="-fsanitize=address")
cp busybox-1.37.0/busybox busybox-asan
```

The fixed tree is a second extract of the same tarball with `fix.patch`
applied to `networking/tftp.c`, built identically into `busybox-fixed`. The
plain build uses `make clean`, `CFLAGS="-g -O0 -fno-omit-frame-pointer"`
`STRIP=true`, and the resulting `busybox_unstripped` copied to
`busybox-plain` (symbols are required for the gdb chosen-byte leg). The
unrelated `networking/tc.c` build break of 1.37.0 against current kernel
headers is why the shipped config starts from `make allnoconfig` and enables
only `CONFIG_TFTP`, `CONFIG_FEATURE_TFTP_GET` and
`CONFIG_FEATURE_TFTP_BLOCKSIZE`.

`sh run-all.sh` replays the five legs from the committed binaries;
`evidence.log` is the unedited transcript. `vuln-tftp.c` and `fixed-tftp.c`
are byte copies of the two pinned source files; `fix.patch` is their `diff -u`.
The up-to-four-hundred-forty-eight-byte overwrite is driven only by UDP
datagrams sent from `malicious_tftp.py` to the client on loopback.

## W1 heap-metadata follow-up (2026-11-23 23:5xZ)

`heap_probe.py` is a second loopback-only server: after forcing the
fallback with a 4-byte DATA block 0, it sends a 516-byte TFTP ERROR packet
whose bytes at wire offset 68 overwrite the top-chunk size word at
`rbuf+72`, and whose 511-byte NUL-free text makes BusyBox's `bb_verror_msg`
allocate on the corrupted heap. `run-heap.sh` replays the ASLR/layout,
chosen-value, isolation, no-small-block, fixed-build and gdb legs;
`heap_evidence.log` is the unedited transcript (SHA-256
`9aef785cdd5f5386d65c9afc369c917f0e63ecb2e0cd171162ef8b37d75966c6`).
All sockets bind 127.0.0.1 only. No code is injected into the client.
