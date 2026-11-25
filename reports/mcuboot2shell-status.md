# mcuboot2shell — admitted status (2026-11-25 08:35Z)

## 2026-11-25 08:35Z — ADMITTED under standing #6 (143rd route)

- Verified staged claim, charter, wall, lab and pre-existing window 151
  (panes %304/%305); no second window created.
- Added the hy4-flash `max_parallel: 3` route in `.mishe-tauftauf/engine/routes.json`
  and both resolver keys in `.mishe-tauftauf/resolvers.json`; re-read and
  JSON-parsed both files after the edit.
- EXACT full-flag sync from `docs/runtime-pin.md:96-102` at pin
  `0d686bba…d528a`: `written 9, removed 0` (three roles x three units),
  daemon-reload, slice/debounce/path present, path enabled and active.
- Pinned full-flag doctor `PASS local plant out of Git` / `GREEN`, rc 0;
  `for_role` returns `RoutedEngine`; `doctor` and `omp-only` GREEN.
- Grade unchanged from handoff: rung 3 pinned function / rung 4 PARTIAL chosen
  bytes, harness 22 PASS / 0 FAIL; no real build, serial wire, AES image,
  pointer/IP/command, r5; witness UNKNOWN.

The staged record below is preserved as the pre-admission evidence.

CVE-2026-16663 / GHSA-7c8v-m3pm-wh74, MCUboot encrypted serial-recovery
`decrypt_region_inplace()` absolute-header-index OOB write. Brief:
`reports/frontier-mcuboot2shell.md`. Lab: `lab/frontier/mcuboot2shell/`.

Grade: rung 3 CONFIRMED in the verbatim pinned function with stand-ins
(ASan dynamic-stack-buffer-overflow WRITE; clang agreement; Valgrind invalid
write in the deep case). Rung 4 PARTIAL: caller-chosen bytes read back at
`buf+6144` and a different caller-chosen string at the same OOB destination.
No real MCUboot build, no serial/USB wire, no real AES image, no pointer/IP/
command control, no rung 5. Witness UNKNOWN. AV:L, pre-authentication.
Upstream fix `6e1465c38e3d` merged on main; patched 2.5.1 release projected
by the advisory, not observed.

`sh lab/frontier/mcuboot2shell/harness/run.sh`: 22 PASS / 0 FAIL; log at
`harness/evidence/run-all.log`. Fixed and safe controls are clean; GCC/Clang
ASan do not flag the deep 2048-byte jump (preserved negative), Valgrind does.
Target window 151 on the inner tmux socket; operator owns final admission.

Handoff receipt 05:59Z: commit `bf2a32ff`; clean git-archive replay 22 PASS /
0 FAIL; window 151 alive (panes %304/%305), registry 152/152 unique; operator
DM #4142 (window already exists), witness DM #4143. No grade change.

## 2026-11-25 09:03Z — W1 real-source host build (target mind)

- Provisioned the parent and fix MCUboot trees locally under
  `lab/frontier/mcuboot2shell/{upstream-parent,upstream}` (fetching only;
  no external probe). Pinned whole files hash-identical to upstream.
- Built the real pinned vulnerable and fixed `boot_serial_encryption.c` with
  the real `encrypted.c` + TinyCrypt AES-CTR and a 4096-byte flash shim;
  interposed only a logging wrapper around `boot_enc_decrypt` (upstream body
  compiled unchanged via a rename macro). Recipe, hashes and evidence:
  `lab/frontier/mcuboot2shell/real/PROVENANCE.md`.
- Parent ASan `edge`: real OOB access at `buf+4104` in the AES-CTR path
  (`READ of size 1`, pinned `:175` → `encrypted.c:722`). Parent plain
  `attack`/`attack2`: real decryptor wrote chosen `MISHE-REAL-AES!!` at
  `buf+6144`/`buf+1024`, with adjacent-stack ciphertext grooming as an
  explicit condition. Fixed source: `buf+8`/`buf+2048`/`buf+1024`, rc 0,
  ASan clean. Valgrind 0 errors in the real build; deep ASan negative kept.
- Grade moved from rung 4 PARTIAL to **rung 4 DEMONSTRATED in the lab host
  build** (real pinned source and real AES decryptor, stated grooming
  condition). Still no live bootloader process, wire, real encrypted image,
  pointer/IP/command, rung 5. Witness UNKNOWN; author evidence only.

### W1 replay receipt (2026-11-25 09:05Z)

Scoped commit `ee7fe914`. A `git archive HEAD` replay of
`lab/frontier/mcuboot2shell/{real,src}` into a throwaway directory, with the
ignored `upstream-parent/` tree symlinked for provisioning, ran `sh run.sh`
again: `REPLAY_OK`; `asan-edge.out` contains two
`dynamic-stack-buffer-overflow` lines; `plain-attack.out` reads back
`4d495348452d5245414c2d4145532121`; `fixed-asan-attack.out` has zero
`ERROR: AddressSanitizer` lines. Addressed DM #4236 to witness (independent
replay requested) and #4237 to operator (material grade change) on the
shared chat tape.
