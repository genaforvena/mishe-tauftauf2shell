# Provenance — libssh-sftp-longname2shell

All sources were fetched as public provisioning. No external host was probed,
no listener was started, and every executed harness was local. SHA-256 pins are
in `SHA256SUMS`; `gen_driver.py` gates the three immutable source/patch pins on
every run (exit 2 on drift). The advisory text remains provenance and is
fetched by `bootstrap.sh` only when absent.

| Artifact | URL / identifier | SHA-256 |
|---|---|---|
| Vulnerable `src/sftpserver.c` | `https://gitlab.com/libssh/libssh-mirror/-/raw/8b2809ae13e1030a06e8699a248520934c08ba81/src/sftpserver.c` | `15400761c6235858d491ea9ac4e7838f0c88439e8250629a58f70569932bcd47` |
| Fixed `src/sftpserver.c` | `https://gitlab.com/libssh/libssh-mirror/-/raw/b2065f71c905d347b5e8dd7f8e24856807d71e99/src/sftpserver.c` | `715fe64f08b2e1edd9ad1fbdb49c2815f704a0425e071ad863eacfe249ff2a83` |
| Full upstream fix patch | `https://gitlab.com/libssh/libssh-mirror/-/commit/b2065f71c905d347b5e8dd7f8e24856807d71e99.patch` | `9100025b606d07d45df258377aa15ff29f16f2021a16987e442997d418dd8be4` |
| Primary advisory text | `https://www.libssh.org/security/advisories/CVE-2026-15370.txt` | `3498df5e5a0ae922284af521520e40e4847eb911a94c69172a92800eb840ddaa` |

Advisory: CVE-2026-15370, published 2026-07-21, CWE-121. libssh `>= 0.11.0`
and `< 0.11.5`, plus `0.12.x < 0.12.1`, are affected; `0.11.5` and `0.12.1`
are fixed releases. CVSSv3.1 is 6.7 `AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H`.
This is **not** remote client control of a filename: a local attacker controls
a directory entry, and a user causes the SFTP server to list that directory.
The filename bytes must be valid on the underlying filesystem.

The pinned pair is exact fix-parent `8b2809ae13e1030a06e8699a248520934c08ba81`
to fix `b2065f71c905d347b5e8dd7f8e24856807d71e99`. In the vulnerable pin,
`MAX_LONG_NAME_LEN` is 350 (`src/sftpserver.c:62`), the caller declares
`char long_name[MAX_LONG_NAME_LEN]` (`:1904`) and calls `readdir_long_name()`
(`:1920`). The sink formats the timestamp and filename into `tmpbuf[350]`
(`:1851`) then appends it with unbounded `strcat(z_long_name, tmpbuf)` (`:1852`).
The fix bounds the append with `strlcat(..., MAX_LONG_NAME_LEN)`.

`gen_driver.py` extracts the complete pinned `readdir_long_name()` body
verbatim (1588 vulnerable / 1623 fixed bytes) under a `#line` directive. Only
constants, includes and `main()` are harness-authored. The real caller and
wire path are source-bound, not executed: authenticated SFTP `READDIR` →
`process_readdir()` → `readdir()` → `readdir_long_name()`.

The lab filesystem reports `NAME_MAX=255` (`getconf NAME_MAX`). With the
harness metadata, 292 filename bytes produce `longlen=349`; 293 bytes trigger
the first ASan fault. Inputs of 4096 bytes deliberately exercise the sink past
this host's filename limit and are **not** claimed as creatable filenames here.
A natural server reproduction needs a filesystem that permits longer names.
The plain direct driver survives the 4096-byte case with `longlen=384`; its
34 chosen bytes plus NUL do not reach saved control data in that layout.
