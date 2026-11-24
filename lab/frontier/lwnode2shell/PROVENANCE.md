# PROVENANCE — lwnode2shell lab (CVE-2026-135746)

Advisory, PR and pinned upstream source were fetched read-only. No network
traffic from the harness, no external probe, no lwnode/Escargot build.

## Pins

- Vulnerable upstream: `Samsung/lwnode` PR #188 base `main` commit
  `b3de7be5c117cf2b03929a45cab6dc02a842743c`. Raw
  `src/api-data.cc` saved as `src/api-data.cc`, sha256
  `e4930859e42e2923150c61f87fb497f151199484dd3a9698071f5d9b7825bf7b`.
  The extracted loop is pinned verbatim from that file at lines 2194-2203;
  its exact-byte sha256 is
  `91051bee0f65e04c42ed2ef77a8449dda7405985e9605aa7b722d445c2a520b4`,
  rechecked by `sh run.sh` on every replay.
- Fix: PR `Samsung/lwnode#188`, head `442b6ebf52cb82aa055841d22ca367bd8fda0fc8`,
  merge `6571beaf7ec95be3b36a41676f69f1bfab608887` (2026-11-24T01:37:22Z).
  Pull patch fetched read-only to `/tmp/lwnode-188.patch`, sha256
  `4f83b4d609d79ed54cb8a883f9a3ee97c06b1334e5a57c5bd4bdd8ccf940054c`.
  Its `src/api-data.cc` hunk replaces the loop with a
  `std::min(bufferCapacity, bufferData.length - start)` bound and writes the
  low byte of each UTF-16 code unit directly. The harness `fixed_write()`
  is that replacement, not a reconstruction.
- Advisory: CVE-2026-135746 / GHSA-mvm7-rjgq-6j36, NVD/GHSA published
  2026-11-24, CWE-787, CVSS 3.1 6.8 `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L`.
  Description: off-by-one in `String::WriteOneByte()` copying a UTF-16 string.

## Harness and exact build commands

`harness.cpp` contains the **verbatim** pinned loop as `vuln_write()` and the
upstream replacement as `fixed_write()`. It models the UTF-16-backed
`oneByteBufferData` as a byte array of code-unit low bytes, calls the copy
with `start=0` and an 8-byte destination, and reads back a canary in the
plain build. `bufferCapacity=8`; the attack source has 20 code units so the
loop reaches `j == 8` and writes `buffer[8]`.

`sh run.sh` checks the pinned loop hash, then runs exactly:

```
g++ -std=c++17 -O0 -g -fno-omit-frame-pointer -fsanitize=address harness.cpp -o asan
g++ -std=c++17 -O0 -g -fno-omit-frame-pointer harness.cpp -o plain
```

and replays vuln/fixed × attack/safe × ASan/plain, including steering fill
bytes `0x48` and `0x5a`. Raw output in gitignored `evidence/`, summary in
`replay.log`.

## Observed bytes (2026-11-24T12:56Z)

- `./asan vuln attack 48`: ASan `heap-buffer-overflow`, `WRITE of size 1`,
  0 bytes past the 8-byte destination, rc 1. The written byte is `0x48`.
- `./plain vuln attack 48`: `vuln attack n=9 byte8=0x48`;
  `./plain vuln attack 5a`: `byte8=0x5a`. Chosen low byte at the chosen
  one-past-capacity offset.
- `./plain vuln safe`: `n=8 byte8=0xcc` (no overrun).
- `./asan fixed attack 48`, `./plain fixed attack 48`,
  `./plain fixed safe`: `n=8`, canary `0xcc`, no ASan report.
- `sh run.sh` -> 11 PASS / 0 FAIL, log `replay.log`.

## Known limits / negatives

- Extracted loop with stand-in byte arrays. No lwnode or Escargot build, no
  JS script, no `Isolate`, no `String::WriteOneByte` call from a real runtime,
  no V8 API shim. The stock object layout and whether a script can place a
  UTF-16-backed string and an exactly-sized buffer in the needed state are
  UNKNOWN.
- `AV:L` in the advisory: this is a local runtime bug, not a network-facing
  server. No wire, pointer/IP/command control, no allocator metadata, no r5.
- The PR also fixes UTF-8 truncation and shebang handling; those defects are
  out of scope here. Only the `WriteOneByte` off-by-one is exercised.
- No independent witness verdict yet.
