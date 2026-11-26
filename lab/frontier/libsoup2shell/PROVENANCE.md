# PROVENANCE — libsoup2shell (CVE-2026-102555)

Author: frontier, W268, 2026-11-26. All work loopback-only; no request,
socket, external probe or command execution. This is a harness reproduction
of a real libsoup source file, **not** a live wire path.

## Pins (provisioning, public GitLab)

The runner needs only two verbatim files; refetch from the public GitLab
commit tarballs on a clean replay:

```
cd lab/frontier/libsoup2shell
for c in a4294044466df66ea98492d67bb74172ed3f8762 \
         e4f032268fa18f691a6c34d6adcb5b666f3e3f77; do
  curl -sSL -O "https://gitlab.gnome.org/GNOME/libsoup/-/archive/$c/libsoup-$c.tar.gz"
done
# tarball sha256: 2f0cd5f2441a104d24034e3be8bfafa8e52f5474c2f9e70d95cffaa63670f50f
#                 88b0bb3ff19be196b80e60dfa263fbb4d246207f634e37616f86e716268cddaa
mkdir -p vuln/libsoup fixed/libsoup
tar xzf libsoup-a4294044466df66ea98492d67bb74172ed3f8762.tar.gz \
  --strip-components=2 -C vuln/libsoup libsoup-a4294044466df66ea98492d67bb74172ed3f8762/libsoup/soup-uri-utils.c
tar xzf libsoup-e4f032268fa18f691a6c34d6adcb5b666f3e3f77.tar.gz \
  --strip-components=2 -C fixed/libsoup libsoup-e4f032268fa18f691a6c34d6adcb5b666f3e3f77/libsoup/soup-uri-utils.c
./run-all.sh
```

- Vulnerable fix parent `a4294044466df66ea98492d67bb74172ed3f8762`
  (libsoup 3.7.2). Verbatim pinned
  `vuln/libsoup/soup-uri-utils.c` sha256
  `45e37054e8d06e2c8cfa1cc3e0da7780575f01926e8ee7c2d0c04dea0b3d82b7`.
- Fix `e4f032268fa18f691a6c34d6adcb5b666f3e3f77` ("uri-utils: Don't treat
  base64 data URI content as a NUL-terminated string"). Verbatim pinned
  `fixed/libsoup/soup-uri-utils.c` sha256
  `77d21acf5f769a6e92a641a16f2754d162ec7b766e84189f98e8d1e66158fd5d`.
  Fix hunk replaces `g_base64_decode_inplace()` +
  `unescaped_array->len = content_length` with
  `g_base64_decode_step()` using the real byte count.
- The tarballs, extracted source trees, build outputs and the provisioning
  git directory are intentionally **uncommitted**; the git directory was
  parked under the site's ignored `artifacts/libsoup2shell-git` so the outer
  checkout can track this lane's small files. A clean-archive replay must
  fetch the two tarballs and hash-check them before `run-all.sh`; the runner
  independently hashes both pinned source files.

## Build path and its limits

A full `meson setup` of the pinned tree fails on this host:
`Dependency "libnghttp2" not found` at `meson.build:118`; `libpsl` is also
absent and the session has no root for apt. This is a provisioning negative,
not a vulnerability result. Instead `run-all.sh` compiles the **verbatim**
pinned `soup-uri-utils.c` as an object and links it to a lab-only driver.

Lab-only shims in `shim/` supply generated build artefacts the standalone
compile needs: `soup.h` (only the private uri header), `soup-misc.h` (one
prototype for the unrelated `soup_str_case_hash`, defined in the driver), and
`soup-version.h` (version macros). No libsoup source line is edited; the
runner copies each pinned file into `build/` and hashes it first.

Host: GCC 13.3.0, Clang, GLib/GIO/GObject 2.80.0 (`pkg-config`), Linux x64.
Flags: `-fno-omit-frame-pointer -g -O0 -fsanitize=address`, ASAN_OPTIONS
`detect_leaks=0:detect_stack_use_after_return=0`.

## Runner and observed result

`run-all.sh` sha256
`4dadfa600b8f7b6b8b45faf8c867e159d09dd84752ee7a14a97f76c99ce9fd83`.
Executed 12:45Z–12:46Z, rc 0, `RESULT PASS=19 FAIL=0 plain_rc=139`; re-run
three times with the same result and unchanged runner hash. Console:
`evidence-run-console.log` (sha256 recorded in the status brief).

Key observed bytes and trace (GCC ASan, `groom 1024` harness sequence: one
valid 1024-byte base64 data URI decodes first, then `data:;base64,A%00B`):

```
GLib-CRITICAL: g_base64_decode_inplace: assertion 'input_length > 1' failed
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 1 at ...
0x... is located 0 bytes after 128-byte region
  allocated by g_uri_unescape_bytes  (GString via g_realloc)
  ... in soup_uri_decode_data_uri build/soup-uri-utils-vuln.c:405
  ... in probe_one harness/driver.c:28 (lab-only consumer)
```

The vulnerable decoder sets `GBytes.len` to a stale stack value; the
driver's byte-sum loop reads past the 128-byte allocation. A fresh process
whose first URI is `data:;base64,%00%00%00` reproduces the same ASan READ
without an explicit grooming call. `glib-probe` shows the GLib precondition
fails and leaves the caller's `out` length at the sentinel
`4702111234474983745`, proving the length is not written on that path.

Controls: fixed build under the same sequence is ASan-clean and reports
size 0 for `A%00B`; fixed `aGVs%00bG8=` decodes the full 5-byte `hello`
where the vulnerable build reports 3 bytes. Safe inputs (`data:,hello`,
`data:;base64,aGVsbG8=`) are ASan-clean in both builds. A plain (no ASan)
vulnerable build crashes with rc 139 on the stale length. Clang ASan compiles
and runs but its stack slot holds small stale values (7 and 4) that stay
inside the 128-byte GString allocation, so no Clang ASan report; recorded as
a compiler-dependent negative, not a pass.

Failed hypotheses preserved: (1) default `ASAN_OPTIONS` with the fake stack
enabled zeroes the slot and gives size 0 / no report, hence the explicit
`detect_stack_use_after_return=0`; (2) `detect_stack_use_after_return=0`
with a base64 URI whose embedded NUL is at position 0 makes the first
fresh-process vector itself fault, so "safe vectors" are run in their own
harness mode.

## Grade

Rung 3: ASan-confirmed heap OOB READ in the verbatim pinned libsoup source,
with fixed-build and safe-input controls. Rung 4 **NOT CLAIMED**: the read
occurs in a lab-only synthetic consumer, no named adjacent object, no
chosen bytes at chosen offsets, no pointer control, and no request-to-decoder
call path was built. No command execution, no r5. The CVE's `AV:N` is
advisory prose only. Would change the assessment: a real consumer that calls
`soup_uri_decode_data_uri()` on attacker-supplied URI input on loopback,
an ASan report in that consumer, or a fixed-build counterexample.
