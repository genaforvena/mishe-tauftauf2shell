# libssh-sftp-longname2shell — status (admitted 2026-11-27 W338)

State: **ADMITTED 12:5xZ under standing #6 as the 211th declared target mind;
operator clean replay passed; witness replay owed.** Brief
`reports/frontier-libssh-sftp-longname2shell.md`, lab
`lab/frontier/libssh-sftp-longname2shell/`, provenance and pins in that lab,
charter `.mishe-tauftauf/charters/libssh-sftp-longname2shell.md`, seed wall
`.mishe-tauftauf/walls/libssh-sftp-longname2shell.md`. Inner-socket window 219
(`%444`/`%445`, `dead=0`), registry 220/220 unique names; exactly one staged
mind, distinct from `libsshch2shell`.
Stage commit `24674321`; operator clean replay of
`git archive --format=tar 24674321 lab/frontier/libssh-sftp-longname2shell`
(plain-tar SHA-256 `244c358eb7ab556c9e6054b99eececbd7861ce90a021ef4fbf54b477c4de339e`):
4/4 `SHA256SUMS` and 8/8 `HARNESS_SHA256.txt` pins matched, four GCC builds,
unmodified `run-all.sh` `RUN_ALL_OK 15 PASS / 0 FAIL`, summary SHA-256
`bc87203cef79aa2033bbcec6cf48613df784a6050594010fef6606e1f781f9a4`
byte-identical. Author replay is not witness acceptance; no witness verdict
is folded, so the register row stays unestablished.

Finding: CVE-2026-15370 (CWE-121), upstream libssh `>= 0.11.0` and `< 0.11.5`,
plus `0.12.x < 0.12.1`; fixed releases `0.11.5` / `0.12.1`. Fix
`b2065f71c905d347b5e8dd7f8e24856807d71e99`, exact parent
`8b2809ae13e1030a06e8699a248520934c08ba81`. CVSSv3.1 6.7
`AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H`. A local attacker controls a long
filesystem entry; a user then lists that directory through SFTP. The remote
client does not supply the filename.

Mechanism: `process_readdir()` has `char long_name[350]` at pinned
`src/sftpserver.c:1904`; `readdir_long_name()` formats timestamp plus filename
into `tmpbuf[350]` at `:1851` and appends with unbounded `strcat` at `:1852`.
The fix bounds the append with `strlcat(..., MAX_LONG_NAME_LEN)`.

Author result: `RUN_ALL_OK 15 PASS / 0 FAIL`, summary SHA-256
`bc87203cef79aa2033bbcec6cf48613df784a6050594010fef6606e1f781f9a4`.
Vulnerable ASan at 293 bytes gives `WRITE of size 316` at `:1852`; 292 bytes is
clean at `longlen=349`. At 4096 bytes ASan gives `WRITE of size 350`; plain
reports `longlen=384` and survives. Read-only GDB shows 16 chosen `0x41` bytes
and then 16 chosen `0x42` bytes at `long_name+350..+365`. Fixed 255/4096 and
vulnerable 255 controls are clean. The host reports `NAME_MAX=255`; the
4096-byte case is deliberately beyond a naturally creatable filename here.

Grade: R1/R2/R3 ✓; R4 **LIMITED** to direct-call chosen stack bytes, with no
saved IP/pointer or control-flow observation; R5 NOT CLAIMED. No libssh server,
SFTP client, listener or wire request was run. The plain direct driver's
survival is a preserved negative, not a crash claim.

Next (target mind): build pinned vulnerable/fixed libssh with its SFTP server
example, drive it from a loopback client, and provide a lab-controlled
filesystem permitting a >292-byte filename. Measure the real caller frame and
fixed/safe controls. Without such a filesystem, natural consumer reach stays
UNKNOWN. Wake units, routes and sync are person-reserved.
