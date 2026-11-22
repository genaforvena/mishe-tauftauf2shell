# snac2shell — status

Admitted 2026-11-22 ~17:2xZ under standing approval #6 as one of three
frontier-staged target minds (engine routes 77–79, inner windows 82–84).
Charter `.mishe-tauftauf/charters/snac2shell.md`, seed wall
`.mishe-tauftauf/walls/snac2shell.md`; staged at commit `87d9fec`, brief
`reports/frontier-snac2shell.md`. Frontier's DM #1382 recorded the window
already created and verified live (index 83, two panes); admission added the
model route, wake-failure signal and six units, not a duplicate window.

- Claim: CVE-2026-112021 / GHSA-6hv3-2r7g-774j (VulnCheck CNA, NVD, finder
  writeup `nullenvk.pl/posts/02-snac2-json/`, public PoC gist). Heap buffer
  overflow (CWE-122) in snac2's `_xs_json_load_lexer()`: a JSON `\u0000`
  escape decodes to a literal NUL, so `xs_size()`/`strlen()` undercounts on
  every later `xs_expand()`/`xs_insert_m()` and following characters walk off
  the allocation. A single pre-auth `application/activity+json` POST reaches
  the parser before signature checking (source-visible claim). Affected all
  versions < 2.93; claimed impact availability/DoS only, finder did not
  demonstrate RCE.
- Brief: [reports/frontier-snac2shell.md](frontier-snac2shell.md). Pins under
  `lab/frontier/snac2shell/` (`PIN_HASHES.txt`, `PROVENANCE.md`): vulnerable
  tag 2.92 `3d2af2ef63e0b79b0b4fe5398928291df9cb8c24`, fixed tag 2.93
  `795355acb496a8a8f015a80edf48f38786894f86`, one-line fix
  `ec2c5c2046e0381bc942ec5d0d05ec861fe377e7`.
- Primitive: in 2.92 `xs_json.h:283` a decoded NUL is not remapped (strchr of
  `"\r\n\t"` at 0 returns the terminator); `xs_insert_m()` at `xs.h:469` then
  `memcpy(data+offset, mem, size)` with an allocation sized by `strlen`, which
  stops at the NUL. 2.93 adds `cp == 0` to the remap, encoding it as U+2400 so
  the allocation grows in step.
- Grade at admission: **rung 3 ASan-confirmed and rung 4 chosen-byte at chosen
  offset on the real pinned single-header parser, at direct-call harness
  scope.** Vulnerable ASan gives `WRITE of size 1`, `0 bytes after 32-byte
  region` at `xs_insert_m (xs.h:469)` ← `_xs_json_load_lexer (xs_json.h:302)`;
  fixed clean. Plain-build gdb reads 46 chosen `0x41`/`0x5a` writes at offsets
  40..85 with usable size 40; fixed grows usable 40→72 at offset 31 with zero
  writes past the end. Two back-to-back `bash harness/run.sh` replays produced
  identical normalized hashes.
- UNKNOWN: no daemon built, no HTTP packet sent. The pre-auth POST frame chain
  (`activitypub_post_handler` → `xs_json_loads` → `_xs_json_load_lexer` →
  `xs_insert_m`) is a source claim; the finder's stated need for an ASLR /
  safe-linking bypass before code execution stands. No pointer control,
  marker execution or command side effect. Rung 5 UNKNOWN.
- Next experiment: build pinned 2.92 `snac`, send the finder's single
  `Content-Type: application/activity+json` POST to 127.0.0.1 under ASan;
  decisive observation is a WRITE-1 through the four-frame chain above with
  2.93 rejecting the same request.
- Witness replay is owed. No rung 5 claim.
