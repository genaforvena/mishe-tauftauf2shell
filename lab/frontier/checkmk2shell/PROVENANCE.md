# checkmk2shell — provenance and pins (W367, 2026-11-27)

## Claim and source pins

- CVE-2026-110470 / GHSA-p7hw-9hjv-7jpq, CWE-121, CVSS4 2.3 Low.
  Vendor werk: https://checkmk.com/werk/22918 ; CVE record:
  https://cveawg.mitre.org/api/cve/CVE-2026-110470
- Affected: Checkmk 2.5.0 before 2.5.0p21, 2.4.0 before 2.4.0p42, and
  2.3.0 (EOL). The werk also lists 2.2.0 (EOL). Fixed source commit
  `265c0ab68fb50bedd0102536eb92612a3eb1af91`; pinned pre-fix parent
  `9a64b94964c5cc34d82daa888d675b86f835e861`.
- Pinned blobs, fetched read-only from GitHub raw:
  - `src/vuln/mkevent.cc` SHA256
    `a1e641eded876f70ecab5649e78c40d6e81cb343b12cb3426e37e23a5c106db5`
  - `src/fixed/mkevent.cc` SHA256
    `9ddfa9e1d704f077742c022f7c73f683a93ecf908fb20e4d4d49f5c4cd28379b`
  - `src/fix.patch` SHA256
    `7d1a44094d23151f0fc34e4fcda232c388387c2d4e48cc0414750127b21d8012`
  - `src/advisory.json` SHA256
    `11047198af5e50571a095625cd8f0e3e37fb9f56bf57bb93a6c2e54c55088106`
  - `src/cve.json` SHA256
    `8490fbbf3c73b4c1b6493f1f1ea7e8b722cd28aebaf45e49407a210f9a9f2412`
- OSV returned HTTP 404 for this CVE at observation time; no OSV claim is used.

## Source-bound mechanism

Vulnerable `src/vuln/mkevent.cc:124-146` builds a syslog notification in
`char message[8192]`. `append_str()` at `:45-47` is:

```cpp
char *append_str(std::string_view str, char *dest) {
    memcpy(dest, str.data(), str.size());
    return dest + str.size();
}
```

`parse_notification()` takes the check output from `args[5]` into `text` and
calls `w = append_str(text, w)` at `:144` without checking the remaining
capacity. For the fixed harness arguments the header before `text` is 44
bytes, so 8148 text bytes fill the array and text byte 8149 is the first OOB
write. The same unbounded helper also processes contact, host and service.

The fix replaces the stack array and append helpers with `std::string`, adds
`truncated_length()` (`src/fixed/mkevent.cc:43-63`) and resizes the final
message at `:418`. The limit is 8191 bytes and the helper avoids splitting a
UTF-8 continuation sequence.

## Harness and commands

- `harness/driver.cc` includes the pinned `mkevent.cc` translation unit with
  `main` renamed, then calls the real `parse_notification()` using the real
  `-n` argument layout: facility `1`, remote `127.0.0.1`, state `2`, host
  `myhost`, service `myservice`, chosen text, SL `10`, contact `admin`.
  The fixed arm applies the same final `truncated_length()` resize as main.
- `harness/direct_driver.cc` includes the same vulnerable translation unit
  and calls the verbatim `append_str()` sink with `message + 44`. This
  isolated wrapper deliberately excludes the real parser's C++ return-object
  locals so saved-RIP control can be measured without debugger writes.
- `harness/build.sh` builds ASan (`-O1 -g -fsanitize=address`) and plain
  (`-O0 -g -fno-stack-protector -fno-pie -no-pie`) arms. Plain hardening is
  disabled only in the lab build; no claim is made about stock Checkmk builds.
- `harness/gdb-fill.cmd` is read-only: run, backtrace, registers, stack dump.
- `./harness/run-all.sh` rebuilds and exercises safe/overflow/fixed arms,
  real-parser GDB chosen-RIP evidence, the isolated marker transfer, and
  one-byte-left/right negative controls.

## Observed evidence

- Real parser, vulnerable ASan, 100-byte text: rc 0, message size 144.
- Real parser, vulnerable ASan, 10000 bytes of `0x43`: rc 134,
  `stack-buffer-overflow`, `WRITE of size 10000`, `append_str` at
  `mkevent.cc:46`, called from `parse_notification` at `:144`.
- Real parser, fixed ASan, 10000 bytes: rc 0, message size 8191.
- Real parser, vulnerable plain, 10000 bytes: rc 139. Read-only GDB reaches
  `mkevent.cc:146` with frame #1 equal to chosen `0x4343434343434343`; the
  parser crashes while constructing the return object, before `ret`.
- Isolated vulnerable sink, plain no-canary/no-PIE: text offset 8172 writes
  the low three bytes of the local `benign_marker()` address at saved RIP;
  the function returns to the marker and prints `BENIGN_MARKER`. Offsets 8171
  and 8173 crash without the marker.

- Fixed plain 10000-byte arm: rc 0, message size 8191.

Replay result: `RUN_ALL_OK 11 PASS / 0 FAIL` (`evidence/last-run.out`).

## Scope limits

R3 is ASan-confirmed on the real pinned parser. R4 is LIMITED to the isolated
verbatim-sink/no-canary/no-PIE build: chosen saved-RIP transfer and benign
marker execution were observed, but not through the full `parse_notification()`
return path. The real parser demonstrates chosen saved-RIP bytes but crashes
earlier in return-object construction. No Checkmk service, notification
spooler, Event Console, wire request, remote target, shell or command was used.
R5 is NOT CLAIMED. ASan/GDB logs contain volatile addresses and are token-checked
rather than byte-pinned.
