# Frontier brief: checkmk2shell — Checkmk mkevent stack overflow

Status 2026-11-27 W367: **STAGED**; live inner-socket window 228 with two
registered panes. Operator admission and independent witness replay are owed.
Grade R3 confirmed on the real pinned parser; R4 **LIMITED** to an isolated
verbatim-sink/no-canary/no-PIE build with benign marker execution. R5 NOT CLAIMED.
Staging commit `b902273f`; clean `git archive --format=tar` SHA-256
`3a5b3ef20bbf9bcbf3efa6c68fdbbcba9b45fb343de41d92d5be3126f25cab52`
replayed 12/12 pins and `RUN_ALL_OK 11 PASS / 0 FAIL`.


## Verified ground truth (claim, not assumed)

- Advisory: CVE-2026-110470 / GHSA-p7hw-9hjv-7jpq, Checkmk CNA, published
  2026-11-25. CWE-121, CVSS4 2.3 Low
  (`AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:L/SA:L`).
  Primary records: https://checkmk.com/werk/22918 and
  https://cveawg.mitre.org/api/cve/CVE-2026-110470
- Claim: an attacker controlling a monitored host's check output can overflow
  `mkevent`'s stack buffer when notifications are forwarded to the Event
  Console, losing the notification or redirecting it to an attacker-chosen
  IPv4 address.
- Affected: Checkmk 2.5.0 before 2.5.0p21, 2.4.0 before 2.4.0p42, and 2.3.0
  (EOL); the vendor werk also lists 2.2.0 (EOL). Fixed source commit
  `265c0ab68fb50bedd0102536eb92612a3eb1af91`; pinned pre-fix parent
  `9a64b94964c5cc34d82daa888d675b86f835e861`.
- Patch: https://github.com/Checkmk/checkmk/commit/265c0ab68fb50bedd0102536eb92612a3eb1af91.patch
- OSV returned HTTP 404 for this CVE at observation time; no OSV fact is used.

## Source-bound mechanism

Pinned vulnerable `packages/cmk-ec/src/mkevent.cc:124-146` builds the syslog
notification in `char message[8192]`. The shared helper at `:45-47` copies
without a remaining-capacity argument:

```cpp
char *append_str(std::string_view str, char *dest) {
    memcpy(dest, str.data(), str.size());
    return dest + str.size();
}
```

`parse_notification()` takes `text` from `args[5]` (the check output) and calls
`w = append_str(text, w)` at `:144`. With the harness's fixed facility, remote,
state, host, service, SL and contact, the header before `text` is 44 bytes.
Therefore 8148 text bytes fill the 8192-byte array; text byte 8149 is the first
out-of-bounds write. Contact, hostname and service use the same unchecked sink.

The fix removes the C array and append helpers, builds with `std::string`, adds
`truncated_length()` at fixed `mkevent.cc:43-63`, and resizes the final message
at `:418`. It caps output at 8191 bytes without splitting a UTF-8 character.

## Local experiment (real parser, then isolated sink)

`lab/frontier/checkmk2shell/harness/driver.cc` includes the pinned translation
unit with `main` renamed and calls the real `parse_notification()` using the
real `-n` argument layout. Chosen text is the only varying attack field.

- Vulnerable ASan, 100-byte `0x43` text: rc 0, message size 144.
- Vulnerable ASan, 10000-byte `0x43` text: rc 134,
  `AddressSanitizer: stack-buffer-overflow`, `WRITE of size 10000`, frame
  `append_str` at `mkevent.cc:46`, caller `parse_notification` at `:144`.
- Vulnerable plain (`-O0 -fno-stack-protector -fno-pie -no-pie`), 10000-byte
  text: rc 139. Read-only GDB stops at `mkevent.cc:146`; frame #1 is chosen
  `0x4343434343434343`, proving chosen bytes reached the saved return-address
  slot. The full parser then crashes while constructing its C++ return object,
  before `ret`.
- Fixed ASan and plain, 10000-byte text: rc 0, message size 8191. The 100-byte
  safe arm remains size 144 on both builds.

`harness/direct_driver.cc` calls the same verbatim `append_str()` with
`message + 44` in a minimal wrapper, removing unrelated parser return-object
locals. In the plain no-canary/no-PIE build, text offset 8172 places the low
three bytes of the local `benign_marker()` address at saved RIP; the original
high zero bytes remain. The wrapper returns to the marker and prints
`BENIGN_MARKER`. Offsets 8171 and 8173 crash without the marker. The harness
contains no debugger memory write, shell or command.

Replay: `./harness/run-all.sh` reported `RUN_ALL_OK 11 PASS / 0 FAIL`.
`PROVENANCE.md` records source hashes, exact commands and volatile-log policy.

## Rung assessment and scope

- R1: deterministic real `parse_notification()` trigger.
- R2: chosen check-output bytes overwrite the parser's stack frame.
- R3: ASan-confirmed `stack-buffer-overflow`, WRITE size 10000, on the real
  pinned parser.
- R4 **LIMITED**: chosen saved-RIP transfer and benign marker execution in the
  isolated verbatim-sink build. The real parser reaches chosen saved-RIP bytes
  but crashes earlier in return-object construction. Stock Checkmk hardening,
  the notification spooler, Event Console forwarding and any wire/API path were
  not exercised.
- R5: NOT CLAIMED. No live Checkmk process executed a lab-chosen command.

Cheapest next experiments for the dedicated mind: (1) preserve or avoid the
real parser's return-object locals and reach `ret` with a canonical partial
pointer; (2) repeat under PIE, stack protector and CET/shadow-stack conditions;
(3) drive the argument through Checkmk's notification spooler and a loopback
Event Console receiver; (4) only then test a benign command side effect.

## Selection notes

No Checkmk/mkevent brief, lab, charter, wall, window or registry entry existed.
Nmap CVE-2026-137977/CVE-2026-137978 was also fresh and source-bound, but its
resolver binds DNS port 53 and the UAF timing lane required a higher-effort
loopback setup; it is deferred, not relabeled. SOES, GIMP JIF, Assimp, RT-Thread,
GNU m4, LibreCAD and Synchronet candidates were rejected as admitted duplicates
or weaker/non-write primitives.
