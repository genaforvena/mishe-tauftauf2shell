# PROVENANCE — dsniff2shell lab (CVE-2026-134753)

Advisory, issue and upstream source were fetched read-only over HTTPS. No
external host was probed; no network packets are sent by the harness. The
claimed wire path (UDP/2001 into a live `dsniff` process) is NOT reproduced
here — see limits.

## Pins

- Vulnerable source: `hackerschoice/dsniff` tag `v2.5a2`, tarball
  `https://github.com/hackerschoice/dsniff/archive/refs/tags/v2.5a2.tar.gz`
  saved as `src/dsniff-2.5a2.tar.gz`, sha256
  `23ada927f3d6c0229a3b624466dd9a5244018f689bbef145a030e3191610e3b4`.
- Pristine `decode_sniffer.c` sha256
  `b58440d541b10c69584b52ba64532288daa9e4ca5ca9ef275f304cccc5dc33b2`;
  `base64.c` sha256
  `c8521208fd91876f0ad9aaaa6c096660091b1e9a13f823a2386e4ffbf7c27287`.
- Advisory: VulnCheck 2026-11-22, CVE-2026-134753, CWE-191 -> CWE-787, CVSS 4.0
  8.3 `AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:H`; affects dsniff <= 2.5a2.
  References: hackerschoice/dsniff#7 (open, 2026-11-22), upstream
  `decode_sniffer.c` at v2.5a2 and `trigger.c:357`. Reporter: Umut Sevinç.
- No upstream fix or patched release identified. The local fix patch is a
  reconstruction of the issue's suggested bound, not a vendor patch.
- `fix-underflow.patch` sha256
  `bcb06b9e967ef07d499276e6911396e4e0b2baa3b718ec30ea03df7cff1876aa`.
  Patched `decode_sniffer.c` sha256
  `dc7aaee927f3284ff096965192b651625e7a912f770a3a0b820df47a0c7a52dd`.
- `harness.c` sha256
  `2172c89e5221f81860a90709a0e2570a112b5fb260ff528ed1eb0aaa2c277849`.

## Patches, harness, exact build commands

- `fix-underflow.patch` clamps `olen - len - 3` to zero and sets a negative
  `base64_pton` return to zero; it is the fixed control, not a vendor release.
- `harness.c` constructs a v2.5a2-format record (`buf[0]=5`, opcode 260 at
  `buf[6]`) with a chosen base64 payload at `buf[32]`. Packet length 4199
  yields 4164 base64 chars; `snprintf(obuf, 4096, "%s [", &buf[32])` saturates
  at 4095 bytes so `olen - len - 3 == -2`, converted to a near-`SIZE_MAX`
  `targsize`. Safe mode uses a 128-byte packet. ASan builds use a bare
  `obuf[4096]` global (same shape as `trigger.c`); plain builds place an
  8192-byte guard directly after `obuf` so the decoded bytes can be read back.
- `config.h` is a local minimal include shim; upstream `config.h.in` needs
  configure and none of its macros are used by the two source files compiled.
- `sh bootstrap.sh` re-extracts the tarball, copies the tree, applies the fix
  patch, then runs exactly:
  `gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 -I. -I<tree> -I<tree>/missing harness.c <tree>/decode_sniffer.c <tree>/base64.c <tree>/missing/strlcpy.c <tree>/missing/strlcat.c -o <out>`
  for `vuln-asan` and `fixed-asan`, and the same with `-DGUARDED` in place of
  the sanitizer flags for `vuln-plain` and `fixed-plain`. Generated trees and
  binaries are gitignored.

## Observed bytes (2026-11-24T11:48Z)

- `./vuln-asan`: AddressSanitizer `global-buffer-overflow`, `WRITE of size 1`
  at `base64.c:164` in `base64_pton`, called from `decode_sniffer.c:47`,
  `0 bytes after global variable 'obuf' ... of size 4096`; rc 1.
- `./vuln-plain bytes`: decoded chosen bytes at guard offsets 0 and 128 are
  `4d 49 53 48 45 2d 4f 4f` (`MISHE-OO`) in both places; rc 0. The byte at
  `obuf[4095]` is decoded byte 0 (`A`), so the marker starts at the first byte
  past the 4096-byte buffer, with a second marker at offset 128.
- `./vuln-asan safe`: rc 0, no ASan report. `./fixed-asan` with the attack
  packet: rc 0, no ASan report. `./fixed-plain bytes`: guard bytes remain
  `cd`; `./fixed-asan safe`: rc 0.
- `sh run-all.sh` result is saved in `replay.log`.

## Limits / negatives

- No live `dsniff` process, UDP/2001 delivery, libnet/libnids, or trigger.c
  dispatch is exercised. Headers for libnet and libnids are absent on this
  host; the harness calls the real upstream decoder with the packet bytes
  directly. Wire reachability is the reporter's claim, UNKNOWN here.
- The overflow destination is the fixed `obuf` global; the attacker chooses
  decoded content and its offset within the overflow, not an arbitrary address.
  The reporter's "write-what-where" phrase overstates the primitive.
- No pointer/IP/command control, no allocator metadata, no rung 5.
- Independent witness (2026-11-24, DM #3598): clean archive of commit
  `5557139`, exact pins, `sh bootstrap.sh && sh run-all.sh` -> 17 PASS /
  0 FAIL. Raw ASan WRITE-1 at `base64.c:164` <- `decode_sniffer.c:47`, 0 bytes
  after `obuf[4096]`; guard0/guard128 = MISHE-OO; safe and fixed clean.
  Steering harness against the rebuilt trees moved marker content and
  offsets (Z9KLMNOP@guard299, W198STR!@guard63); fixed stayed unchanged.
  Verdict ESTABLISHED AS LABELED: rung 3 real decoder, rung 4 PARTIAL;
  live UDP/2001 crash remains UNKNOWN (libnet/libnids headers absent).
