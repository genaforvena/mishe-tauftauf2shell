# Frontier brief — Mosquitto built-in WebSocket "MASKerade"

- **CVE**: CVE-2026-110486 / GHSA-6j8m-r32v-4h38, severity Critical.
- **Affected**: Eclipse Mosquitto 2.1.0–2.1.2, built-in WebSocket backend
  (`WITH_WEBSOCKETS` and `WITH_WEBSOCKETS_BUILTIN` both default ON in CMake).
  The older libwebsockets backend does not use this read path. Fixed in 2.1.3.
- **Weakness**: CWE-787 (out-of-bounds write) + CWE-191 (integer underflow),
  with a derived CWE-125 (out-of-bounds read).
- **Claim sources (read-only provisioning, treated as claims)**:
  - DZONERZY, "MASKerade — Phantom Bytes, Real Shell", 2026-08-02
    (`libdzonerzy.so/articles/maskerade-phantom-bytes-real-shell.html`),
    full pre-auth heap-overflow → tcache poisoning → shell narrative.
  - Eclipse advisory GHSA-6j8m-r32v-4h38 (published 2026-11-17), NVD/CVE-2026-110486,
    mosquitto blog 2026-11-17 ("2.1.3 is a critical security release"),
    oss-sec 2026/q4/740, fix commit `eclipse-mosquitto/mosquitto@021b063` (2026-11-06).

## Verified ground truth (this lab, 2026-11-20)

Build: `lab/frontier/mosquitto2shell/build.sh` — gcc 13.3.0,
`-fsanitize=address,undefined -O1 -g`, built-in WebSockets ON, cJSON 1.7.17
built locally into `deps/` (no host package changes), binaries
`build-<ver>-asan/src/mosquitto`. Sources in `lab/src/mosquitto-2.1.{2,3}.tar.gz`;
gzip integrity checked; the fix difference was read directly from the
tarballs: 2.1.2 `lib/net_ws.c:345` returns `len`; 2.1.3 returns `mqtt_len`
(line 350) with an explicit "Empty frame" EAGAIN case (line 337) and adds
the `read_length > to_process → MOSQ_ERR_PROTOCOL` guard in
`lib/packet_mosq.c:592`. No published `.sha256` sidecar exists at the
mosquitto.org source path; version identity was established from source
content above, not from a checksum.

Exact input (`lab/frontier/mosquitto2shell/trigger.py`, loopback only):
a valid WebSocket upgrade over `127.0.0.1:27080` (`Sec-WebSocket-Protocol:
mqtt`), then three masked binary frames:

1. `b"\x10\x01"` — MQTT CONNECT fixed header, Remaining Length 1, body withheld;
2. `b""` — masked zero-length data frame;
3. `b"A"*256` — written at `payload+4`.

Observed bytes (`logs/differential-run1.log`):

- 2.1.2: `101 Switching Protocols`, then ASan `WRITE of size 256` at
  `0x50200000a414`, "3 bytes after 1-byte region [0x50200000a410,0x50200000a411)",
  stack `net__read_ws (net_ws.c:305) → net__read (net_mosq.c:1049) → read`,
  allocation at `packet__read_single (packet_mosq.c:559)`. Broker aborts.
- 2.1.3: no ASan report; broker logs `Protocol error ... CONNECT with
  missing protocol string length` and closes cleanly. Control passes.

## Source-bound mechanism (from the fix diff)

`net__read_ws()` reused a single `len` for opcode, length, mask and payload
bytes. A masked empty frame consumes 4 mask bytes, copies nothing, and
returns 4. `packet__read_single()` subtracts that from `to_process` without
`read_length <= to_process`, so `1 - 4` underflows to `0xfffffffd` while
`pos` becomes 4 — a cursor three bytes past a one-byte allocation with
~4 GiB of apparent remaining body. The fix separates `mqtt_len` from
framing `len`, returns EAGAIN for empty frames, and adds the bounds guard.

## Rung ladder — honest grading

- **Rung 1 (reproducible trigger): PASS.** Deterministic 3-frame sequence,
  pre-auth, no race, no external probe.
- **Rung 2 (observed state failure): PASS.** `pos`/`to_process` accounting
  breaks; `logs/placement-run1.log` shows the write cursor moving exactly
  4 bytes per empty frame (see Stage A below), matching the underflow.
- **Rung 3 (ASan-confirmed corruption): PASS.** 256-byte heap
  buffer-overflow write on 2.1.2 with the allocation and write sites named;
  clean on 2.1.3.
- **Stage A (placement control): PARTIAL PASS under ASan.**
  `lab/frontier/mosquitto2shell/placement.sh` varies the empty-frame count
  with an 8-byte chosen payload (`0x41`): 0 frames → no report (in-bounds);
  1 → 3 bytes after the 1-byte region (offset +4); 2 → 7 bytes (+8);
  4 → 15 bytes (+16); 8 → 31 bytes (+32). Chosen bytes land at a chosen
  offset, with a non-destructive 4-byte-step cursor, exactly as the
  write-up describes. This is placement evidence only: ASan's allocator
  is not glibc's, so no tcache object was actually overwritten.
- **Rung 4 (demonstrated security impact): NOT DEMONSTRATED locally.**
  The full chain — PONG packet_length enlargement for a 32 KiB pre-auth
  heap read, tcache poison + safe-linking bypass via uthash metadata to
  forge `listener.security_options.allow_anonymous`, PIE leak via the
  static "client context" string, plugin tick callback → `dlsym@plt` →
  `setcontext` ROP → `system("sh >&0 2>&0")` on a dup'd broker-side fd —
  remains the author's CLAIM. PoCs were withheld pending disclosure; the
  article itself calls the chain build-specific (AC:H, exact offsets/gadgets).
  No pointer control or marker execution was exercised in this lab.

## Feasibility assessment and cheapest next step

Tractability **HIGH**, above the Apache lane: deterministic wire trigger,
pre-auth, default-compiled backend, loopback-able, pure C/glibc heap
(no AVX/AVX-512 hardware blocker), and the write primitive is a direct
`recv()`/XOR into `payload+pos` with attacker-chosen bytes at a chosen
offset — not a memcpy-style consumer with a zero-store window. glibc here
is 2.39 with safe-linking active, matching the write-up.

Cheapest next rung: build **2.1.2 without sanitizers** with symbols
(`-O0 -g`, same local cJSON), run under gdb with a WS listener on
127.0.0.1 only, and reproduce the write-up's PONG-adjacency groom
(174-byte CONNECT source, 125-byte held PING target, same `0xc0` bin) to
see whether the first `packet_length` overwrite is stable on this build.
Then attempt the tcache poison and confirm a controlled `malloc()` return;
only after that should a mind claim rung 4. Preserve any negative: heap
groom reliability is the author's stated limitation.

## Reproduce

```
cd lab/frontier/mosquitto2shell
./build.sh                       # ASan 2.1.2 + 2.1.3
./run.sh                         # differential; logs/differential-run1.log
./placement.sh                   # chosen-offset table; logs/placement-run1.log
```

All listeners bind 127.0.0.1 on ports 27080–27082; no external probes.
No untracked lab bulk is committed.
