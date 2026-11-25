# libsshch2shell — pin provenance and harness scope

## Claim source (public, read-only provisioning)

- Advisory: CVE-2026-59850, "Possible UAF while processing data on closed
  channels", https://www.libssh.org/security/advisories/CVE-2026-59850.txt —
  pinned verbatim as `src/advisory.txt`. It states libssh < 0.12.1 and
  < 0.11.5 are affected, server and client components, 0.12.1/0.11.5 fixed,
  CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L (4.3), reported by Zhou
  Qingyang, patch by Jakub Jelen. USN-9187-1 (published 2026-11-23) was
  supplied by the read-only scout and is not independently fetched here.
- Fix commit: `7dfabb1fd213196c4912c314b418ff36c882ea54` —
  "CVE-2026-59850 channels: Avoid processing DATA packets on closed channels",
  2026-07-01T14:43:08Z, cherry-picked from master
  `a8a3fa352bb5213e08a35e4494c6e44360e2e38a`. Its direct parent, confirmed
  via GitHub commit API, is the vulnerable commit
  `a540e27659b08828ef61f2910a790f7cf2af9f8d`. Release tag on the mirror is
  named `libssh-0.12.1`; 0.11.5 backport
  `6edfb52b3b364577d2db0334c0514a977efceed2` exists and serves channels.c
  (HTTP 200) but was not needed because both requested exact commits resolve.
- Repository: https://github.com/libssh/libssh-mirror. All source bytes came
  from `raw.githubusercontent.com` GETs; nothing was probed, compiled or
  executed upstream. Exact SHA-256 for every pinned byte is in `pins.sha256`.

## Exact fetch commands (run from repository root)

```
curl -fsSL https://www.libssh.org/security/advisories/CVE-2026-59850.txt -o lab/frontier/libsshch2shell/src/advisory.txt
for c in a540e27659b08828ef61f2910a790f7cf2af9f8d 7dfabb1fd213196c4912c314b418ff36c882ea54; do
  s=vuln; [ "$c" = 7dfabb1fd213196c4912c314b418ff36c882ea54 ] && s=fixed
  curl -fsSL "https://raw.githubusercontent.com/libssh/libssh-mirror/$c/src/channels.c" -o "lab/frontier/libsshch2shell/src/channels.c.$s"
  for h in channels.h ssh2.h libssh.h; do
    curl -fsSL "https://raw.githubusercontent.com/libssh/libssh-mirror/$c/include/libssh/$h" -o "lab/frontier/libsshch2shell/src/$h.$s"
  done
done
sha256sum lab/frontier/libsshch2shell/src/*
```

Commit metadata was read with `curl -fsSL
https://api.github.com/repos/libssh/libssh-mirror/commits/<sha>` (message,
parents, dates) and `.../tags?per_page=100` (tag name).
Pinned sizes: channels.c 4077 lines (vuln) / 4084 lines (fixed); both header
triples are byte-identical across the two commits. The only channels.c change
in this pair is the 7-line guard at fixed lines 656-661. `channels.h.vuln`
line 55 pins `SSH_CHANNEL_FLAG_CLOSED_REMOTE 0x0001`, used by the stand-in.

## Harness inputs and construction

- `harness/channel_rcv_data.inc` is pin lines 594-719 verbatim. The only
  additions are `#ifdef LIBSSH_FIXED` / `#endif` around the exact upstream
  guard (fixed pin lines 656-661). A line-by-line comparison of the include
  with the pin after removing those wrappers and the 7 guard lines confirms
  equality (126/126 lines).
- `harness/harness.c` supplies compact stand-ins: `ssh_channel`, `ssh_session`,
  `ssh_buffer`, `ssh_string`, `ssh_packet`, `channel_from_msg`,
  `ssh_buffer_get_ssh_string`, `ssh_string_data/len`, `channel_default_bufferize`,
  callback iterator macros, `grow_window`, SSH constants and log/error macros.
- The crafted `SSH2_MSG_CHANNEL_DATA` (type 94) carries recipient channel 1,
  string length 32, and a 64-byte payload chunk whose bytes 16..31 are
  `MISHE-LIBSSH-UAF` (remaining bytes 0x41). The chunk is freed immediately
  before `channel_rcv_data()` is called, so `ssh_string_data()` in the pinned
  callback returns a dangling pointer. Attack channel has
  `SSH_CHANNEL_FLAG_CLOSED_REMOTE`; safe control clears the flag and keeps the
  chunk allocated. Fixed build adds only the upstream guard.
- The sink `memcpy(buf->data + buf->len, src, len)` at `harness.c:152` reads the
  freed 32 bytes; a no-ASan probe prints `src[16]` and `src+16` before the copy.

## Build and run commands

```
cd lab/frontier/libsshch2shell
CFLAGS="-std=c99 -O0 -g -fno-omit-frame-pointer -I harness"
clang $CFLAGS -fsanitize=address harness/harness.c -o harness/vuln-asan
clang $CFLAGS -fsanitize=address -DLIBSSH_FIXED harness/harness.c -o harness/fixed-asan
gcc $CFLAGS -DLIBSSH_PLAIN_PROBE harness/harness.c -o harness/vuln-plain
gcc $CFLAGS -DLIBSSH_FIXED -DLIBSSH_PLAIN_PROBE harness/harness.c -o harness/fixed-plain
sh harness/run-all.sh
```

Observed: `RESULT 24 PASS / 0 FAIL`, rc 0. Vulnerable ASan attack exits rc 1;
fixed ASan attack, vulnerable ASan safe, fixed ASan safe, and all plain builds
exit rc 0. Full stdout/stderr is captured under `harness/evidence/` (addresses
and PIDs are run-specific; line numbers are harness-layer, pin hashes and the
verbatim guard text are authoritative).

## Ceilings

Rung 3 ASan-confirmed heap-use-after-free read in the pinned verbatim callback;
rung 4 PARTIAL chosen marker bytes in the plain build. No real libssh build,
no SSH wire session, no pointer/IP control, no command execution, no rung 5.
