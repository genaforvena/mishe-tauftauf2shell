# W201 — one-command clean-archive replay of the W199 limb

W199 (wire-chosen pointer dereference in the loopback consumer) was the newest
author-only limb with no replay script and no witness request. This file records
the offline author replay made on 2026-11-24T20:2xZ (W201); it is deterministic
replay of committed bytes, not witness acceptance.

## Recipe

```sh
git archive HEAD lab/frontier/cjose2shell | tar x -C /tmp/cjose-w199
cd /tmp/cjose-w199/lab/frontier/cjose2shell && sh replay-w199.sh
```

`replay-w199.sh` verifies `PINS.sha256`, runs `harness/bootstrap.sh` (jansson
and all six pinned cjose trees rebuild from the committed tarballs), runs
`harness/check.sh`, rebuilds the four `w1/` loopback consumers, then drives one
request per ephemeral 127.0.0.1 port: fixed + pointer token, vulnerable + safe
token, eight vulnerable + pointer token runs, and up to 20 gdb attempts on the
pointer token. The gdb dereference is stochastic because jansson seeds its
hashtable from `/dev/urandom` (W183), so the assertion is "at least one run
dereferenced the wire-chosen value", not a fixed fault fraction. No listener
remains. Expected terminal line: `REPLAY_W199_OK`.

Script SHA-256: `702339715851a8b08e18aa64f04b185ee4dd62aec2507ac44e83779be0ae9b4e`.

## Measured receipt

Archive of commit `2b7075659922dd5bb59376733621fca24c8af066`; the replay ran
in `/tmp/w201-cjose-clean` (throwaway, not committed).

- `sha256sum -c PINS.sha256`: 7/7 OK; `harness/bootstrap.sh`: `built 8
  binaries; pins verified`; `w1/build.sh`: `built 4 loopback consumers`.
- `harness/evidence/summary.txt`:
  `PASS=223 FAIL=0 trace=455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7`
  — exact match to the committed direct-call trace.
- Fixed + pointer token: `DECRYPT=0 ERRCODE=1 PLAIN_LEN=0 CEK_LEN_AFTER=32`.
  Vulnerable + safe token: `DECRYPT=0 ERRCODE=4 PLAIN_LEN=0 CEK_LEN_AFTER=32`
  (HMAC failure, declared length intact).
- Vulnerable + pointer token: 7 of 8 runs reported `CEK_LEN_AFTER=72`; the
  eighth faulted (no `DECRYPT=` line), consistent with W199's ~20% seed class.
- gdb captured the decisive frame on attempt 2 of 20:
  `__strcmp_avx2 () at ../sysdeps/x86_64/multiarch/strcmp-avx2.S:283`, then
  `_cjose_jwe_calc_auth_tag (enc=0x4141414141414141 ...) at jwe.c:1098`,
  with `rdi 0x4141414141414141`. The wire-chosen value is
  the pointer passed to the real decrypt path's `strcmp`, with no groomed
  absolute address in the client or server.
- SHA-256 in the throwaway tree: `gdb-pointer-deref.log`
  `b88221f89552ffda008ab1acee570cefae5260489e0cc0e622e192bdf17d6e49`;
  `fixed-ptr.log` `c29dce6e6e588084559cf751238f5117ded27bbfaad6f072be9e34824e985d33`;
  `vuln-valid.log` `281c2f6a43cc590fd95b96c1a08689b4f4f71ddae179b2ae2b9e2557455dc57b`;
  `summary.txt` `dcaca8003599a776022e66b0ebecf1c2263eb164194141bfaa07a8c1598cd668`.

## Limits

Author replay, not independent acceptance. The dereferenced value is a
recognizable non-address; no valid pointer, ASLR defeat, command or
wire-derived live address. Real-consumer adjacency behind the CEK remains
UNKNOWN (W189/W195). Grade and rung-5 ceiling unchanged. Witness replay of
this one command is offered on the chat tape; a verdict is still required to
move the limb from author-only to established.
