# PROVENANCE — VRPNShell candidate (CVE-2026-123200)

All sources fetched read-only from public origins on 2026-11-22. All dynamic
tests ran on 127.0.0.1 ports only; no external system received a trigger.

| Artifact | URL | SHA-256 |
| --- | --- | --- |
| `src/cve.json` | <https://cveawg.mitre.org/api/cve/CVE-2026-123200> | `f4ee321265a09811497bce9aa154d7f0d6bc363f1d0bbaa970355fb010df1320` |
| `src/fix-0da5b0b...patch` | <https://github.com/vrpn/vrpn/commit/0da5b0b71e06e8c318a4e674c84caee12251a782.patch> | `96942c5fa0a9c3b8d03ac1cd73656f8011974b3c86e3f3d1b4fc3834afb4f2c6` |
| `src/fix-c893b58...patch` | <https://github.com/vrpn/vrpn/commit/c893b583d928fd17d756b39271b2eae71766e7f2.patch> | `d8ff87e8f156145d74d8a19a259eacc7035ef06e32ef602bb44a66ad0328838c` |
| `src/vrpn_Connection.C.pinned` (commit `79deb000...`) | <https://raw.githubusercontent.com/vrpn/vrpn/79deb000cc0b47ae49a80c92c78167c02d8a04d8/vrpn_Connection.C> | `9eaa10458e6aed834ac88d0e30aed831322db9e5b5a520e01b7abab91fe45226` |
| `src/vrpn-fixed.tar.gz` (fix commit `0da5b0b...`) | <https://github.com/vrpn/vrpn/archive/0da5b0b71e06e8c318a4e674c84caee12251a782.tar.gz> | `b5258e996f295c3310310f4d81096dc03cf1ffbe62d06f26b57c494e431a0643` |
| `src/vrpn-07.36/` HEAD | shallow clone of tag `v07.36` | `79deb000cc0b47ae49a80c92c78167c02d8a04d8` |
| `harness/handler_direct.cpp` | local | `db8bbadfae35ba6478c7076baa4a8033b31144d771f8f265d1398b82e2ef5fd8` |
| `wire_inject.py` | local | `b48c85d3696c0b3ccebd57091e5ee73528c7940e6608749c2846811d0426213c` |

## Build and observation records

- Vulnerable ASan server: CMake `-DCMAKE_CXX_FLAGS='-fsanitize=address
  -fno-omit-frame-pointer -g'`, `cfg-asan.log`, `build-asan.log`; executable
  `build-asan-07.36/server_src/vrpn_server`.
- Fixed ASan library: same flags, `cfg-fixed.log`, `build-fixed.log`.
- Direct ASan harness: `g++ -fsanitize=address -fno-omit-frame-pointer -g
  -I src/vrpn-07.36 harness/handler_direct.cpp
  build-asan-07.36/libvrpnserver.a`; output `out-direct-01/`. Fixed counterpart
  `out-control-fixed/`.
- Wire dispatch: `out-gdb-01/gdb.log` (index `-64`) and
  `out-gdb-wire-100b/gdb.log` (index `100`), both showing handler entry and
  `dispatch` frames from a real TCP message.
- Wire ASan negative sweep: `out-wire-sweep-02/server.err`, no ASan report.
- Compiler: system `g++` on this host; exact version not recorded this wake —
  UNKNOWN, must be recorded before any witness-facing claim of layout detail.

Screened out this wake (no new source work): JSON::XS CVE-2026-129114
(one-byte NUL write with no rung-4 route), image/parser-only and closed-source
CWE-787 hits, and GCT/GStreamer/FreeRDP/dnsmasq/NGINX/Mosquitto hits already
owned by their own minds.
