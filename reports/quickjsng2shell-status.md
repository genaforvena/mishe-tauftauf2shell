# quickjsng2shell — status (staged W279, ADMITTED 17:4xZ)

ADMITTED 17:4xZ under standing #6 as the 180th declared target mind.
GHSA-r6vf-p8wr-4vg9 (no CVE), quickjs-ng fast-array
use-after-free. Brief `reports/frontier-quickjsng2shell.md`, charter
`charters/quickjsng2shell.md`, harness `lab/frontier/quickjsng2shell/`
(PROVENANCE.md has pins, hashes and preserved negatives).

- Pins: vulnerable tag v0.14.0 `3c051980ab7e783dfbfb1c70c014ce5e05ecf24c`;
  fixed tag v0.15.0 `433941b99fb3c5e7f98b7ebd78727972bcf467ee`; fix commit
  `da49a37041e78ba7148b24bf6500c4c18c8ecbb0` (one line plus upstream test).
- Input: six-line upstream PoC (shrink fast array to 2, regrow to 5, push,
  read `arr[3]`), byte-identical to the fix commit's regression test.
- `sh run-all.sh && sh verify.sh`: `RESULT PASS=28 FAIL=0` and
  `RESULT PASS=11 FAIL=0`; vulnerable GCC ASan `heap-use-after-free` READ-4
  at verbatim quickjs.c:1546 via :9478, 0 bytes inside a 72-byte freed region;
  fixed prints `undefined` clean; safe control clean on both pins.
- Operator isolated-copy replay at 17:4xZ matched both runs (28/0 and 11/0);
  `run-all.sh` sha256
  `f6e6c59f01b95073ed9d5b8521abfa162f3eb9efcd9e691d2088cbbb652cab59`,
  `verify.sh` sha256
  `967c1f7d467d8dec7ebd9513a6ab42e3cd98b104b1f425f0eb2eda6c6a37706b`.
  Replay ASan evidence: `evidence/vuln-asan-poc.out` names `js_dup
  build/vuln/quickjs.c:1546` and "0 bytes inside of 72-byte region".
- Grade: rung 3 ASan in verbatim pinned source / rung 4 NOT CLAIMED — no
  chosen-offset readback, pointer steering, wire consumer, command or r5.
- Preserve: advisory metadata says affected <0.14.0 / patched None but tag
  bytes contradict it; no CVE and OSV 404; os-module command claim untested;
  distinct project from staged quickjsbcode2shell; GCC-only build.
- Owed: witness clean-archive replay and plain-build chosen-object readback.
  Window 190 adopted (panes %384/%385, dead=0, no duplicate).
