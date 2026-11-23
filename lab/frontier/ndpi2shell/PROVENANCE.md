# ndpi2shell — provenance, pins, negatives

W161, 2026-11-23. Everything here is provisioning + lab-local execution. No
external host was probed; advisories and source were fetched read-only.

## Claim

- GHSA-c8vx-3h2j-4f8m / CVE-2026-86098, GitHub Advisory Database, Unreviewed,
  High 7.4, CWE-787. Advisory summary: nDPI versions before 6.0 contain a heap
  buffer overflow in `ndpi_json_string_escape()` that writes beyond a
  caller-supplied buffer; crafted network packet data including TLS SNI, HTTP
  headers or DNS names can reach it. The advisory's numeric fixed version
  ("6.0") is a claim recorded from the advisory text; the fix itself is
  verified at the commit below.
- Upstream fix commit referenced by the advisory:
  `94e82c1de12323d992895830231865736a8abf2c` ("Fixes the following bug",
  Luca Deri, 2026-08-25). Its commit message is a reporter write-up naming
  `ndpi_serializer.c:90-163`, CWE-787, CVSS 7.4, affected "nDPI <= 5.0, HEAD
  commit ea3586e" and "Lab verified (ASan confirmed)". Treated as a claim,
  reproduced locally below.
- Advisory references: NVD CVE-2026-86098, the fix commit above,
  `https://github.com/ntop/nDPI/blob/5.0/src/lib/ndpi_serializer.c`, and a
  VulnCheck advisory page. Only GitHub advisory API + raw GitHub source were
  fetched; none of the linked third-party pages were used as evidence.

## Provisioning commands (verbatim shape)

```
curl -sS -H 'Accept: application/vnd.github+json' \
  https://api.github.com/advisories/GHSA-c8vx-3h2j-4f8m
curl -sSL https://github.com/ntop/nDPI/commit/94e82c1de12323d992895830231865736a8abf2c.patch
curl -sSL https://raw.githubusercontent.com/ntop/nDPI/94e82c1de12323d992895830231865736a8abf2c%5E/src/lib/ndpi_serializer.c \
  -o lab/frontier/ndpi2shell/src/ndpi_serializer.c.vuln
curl -sSL https://raw.githubusercontent.com/ntop/nDPI/94e82c1de12323d992895830231865736a8abf2c/src/lib/ndpi_serializer.c \
  -o lab/frontier/ndpi2shell/src/ndpi_serializer.c.fixed
```

## Pins

`PINS.sha256` records all four hashes: the two full raw files and the two
verbatim slices extracted by `harness/run.sh` (vulnerable lines 90-166, fixed
lines 90-226). `run.sh` calls `sha256sum -c` before generating drivers.
Rendered line numbers are claims; the raw bytes and `PINS.sha256` are
authoritative.

- Vulnerable function `ndpi_serializer.c.vuln:90-166`.
- Fixed function `ndpi_serializer.c.fixed:90-226`.

## Declared stubs and lab-only code

- `u_char` typedef (upstream typedef from a project header).
- Exact-size `malloc` for ASan builds; `malloc(dst_max_len+32)` with a `0xa5`
  canary for plain builds so bytes past the caller size are observable.
- Driver scenarios `baseline`, `escape`, `utf8`, `nul`; no ndpi library, no
  serializer struct, no packet capture, no socket, no wire, no consumer.
- Pinned slices are included under `#line 90 "ndpi_serializer.c.<variant>"`;
  all driver code is after `#line 1 "driver-tail.c"`.

## Mechanism read from pinned bytes

`:94` writes the opening quote without a bounds check. The loop guard at
`:96` is `j < dst_max_len`, tested once per source character, while a 2-byte
escape writes at `:106-107` and a 4-byte UTF-8 sequence writes at `:155-158`;
a check passing with `j == dst_max_len-1` therefore permits stores past the
caller size. After the loop, `:162` writes the closing quote and `:163` writes
the NUL at `dst[j+1]` rather than `dst[j]`, an unconditional off-by-one.

Fix `94e82c1` rejects `dst_max_len < 3`, sets `safe_max_len = dst_max_len - 2`,
adds a `j+N > safe_max_len` precheck to every escape branch, moves the
lookahead length checks ahead of the UTF-8 reads, writes NUL at `dst[j]`
(`:219`), and returns `-1` via an `overflow` label (`:222-225`).

## Observed evidence

- `harness/run.sh` builds 8 binaries (gcc/clang x vuln/fixed x plain/asan).
- `harness/check.sh`: 32 invocations + 2 gdb probes, `172 PASS / 0 FAIL` on
  three consecutive runs, trace
  `16060f55dfe944bf5e481a43e76034f6cd3d7acc159d561beaa067c8c97f7b5b`.
- gcc and clang ASan both report `heap-buffer-overflow`, `WRITE of size 1` at
  pinned `:107` (escape), `:158` (4-byte UTF-8) and `:163` (off-by-one NUL).
- Plain vulnerable tail bytes: escape `2f 22 a5 00`, utf8 `80 22 a5 00`,
  nul `a5 00 a5 a5` at offsets `dst_max_len..dst_max_len+3` (canary `a5`
  shows the skipped byte between closing quote and misplaced NUL).
- Fixed build returns `rc=-1` on all three attacks, leaves the canary intact,
  and triggers no ASan report. Baseline returns `rc=5` in all variants.
- gdb: at `:107`, `J=8 C=0x2f` — chosen `0x2f` is the byte stored at
  `dst[8]`, one past an 8-byte caller buffer. After return, `x/8xb dst+8`
  shows `0x2f 0x22 0xa5 0x00`, matching the plain tail.

## Preserved negatives / limits

- ASan aborts before stdout flush in vulnerable attack runs, so those outputs
  have no `scenario=`/`rc=` line; `check.sh` does not assert one there.
- The advisory's wire reachability (TLS SNI / HTTP / DNS) is a claim. The
  reporter's own patch text says internal callers are protected by a +24-byte
  over-allocation; this harness reproduces the external public-API condition
  (exact-size caller buffer), not an in-tree caller. No real nDPI build,
  packet, parser path, socket, pointer chain, command or witness replay.
- Fixed release "6.0" is advisory prose; only the fix commit bytes were
  fetched. Numeric fixed version is treated as UNKNOWN until a release tag is
  checked against the commit.
- Rung 5 UNKNOWN.
