# PROVENANCE — axis2guththila2shell (W273, 2026-11-26)

All fetches were public provisioning reads; no external target was probed.
Everything executed was local, with no socket.

## Pins and exact bytes

- Vulnerable: `584ce5bd3c98fe51701285d0a62e9c5251f3da4f`, the parent of fix
  `23110287924e79d05a5b4712298c355d1f05c606` (verified via GitHub API commit
  metadata). Fixed: `f01683ec10e8fddb87279ec9351b3239021223e6`, whose parent is
  the first fix, so both fixes are present.
- Tarballs (codeload, full SHA):
  `https://codeload.github.com/apache/axis-axis2-c-core/tar.gz/584ce5bd3c98fe51701285d0a62e9c5251f3da4f`
  sha256 `da9cf3c19cb30618c8f158af4478b808c1c2ff9fc5c129eb77042c53b8bfb46e`;
  `https://codeload.github.com/apache/axis-axis2-c-core/tar.gz/f01683ec10e8fddb87279ec9351b3239021223e6`
  sha256 `3421cf3b939de2dac424bd9e15b19cacc5973a3a897f43bba9757235a79036fc`.
- Verbatim `axiom/src/parser/guththila/guththila_xml_reader_wrapper.c` sha256:
  vulnerable `e57e1d0282ec34b88a95109666a9a9382af7260b434da2ebc4137bb911be8985`,
  fixed `6fb68ca06bec0a0e35a26eb02c7b74332b4d86dacdcf0790ba0c2ed44bd28cc2`.
- `run-all.sh` sha256 `59da25bcfd2e4a743d9ce01d696d464638fb65f8bc0871bb32e0a3f84bf47eb9`;
  `harness/driver.c` sha256 `7ada2943e362c502c74d519796248b2b612f7386cd51d1a3b5da5034867ecca5`;
  console `evidence-run-console.log` sha256
  `bb9239aa83c62b085685ba6d6a1f2fdc544fa48fffa9930abe17a6cabbd30ec8`.

## Reproduce

Refetch the two tarballs to `src/vuln.tar.gz` and `src/fixed.tar.gz`, check the
hashes above, `tar xzf` each into `src/` (extracted trees and tarballs are
gitignored). Then, from this directory:

```
sh ./run-all.sh          # gcc -fsanitize=address, verbatim upstream .c files
sh ./verify.sh | tee evidence-run-console.log
```

`run-all.sh` compiles the **unmodified** pinned wrapper
(`axiom/src/parser/guththila/guththila_xml_reader_wrapper.c`), all of
`guththila/src/*.c`, `util/src/*.c` and `util/src/platforms/unix/*.c` plus the
local driver. The only local additions are `harness/driver.c`,
`harness/config.h` (minimal generated-config substitute) and include paths.

## Inputs and observed bytes

- Attack document, 19 bytes: `<!ENTITY x "y"><a/>`. Independent raw parser
  probe: vulnerable `raw[0]=60` (the `<` byte used as an event id), fixed
  `raw[0]=-1`.
- Vulnerable ASan: `heap-buffer-overflow`, `READ of size 4`, top frame
  `guththila_xml_reader_wrapper_next ...guththila_xml_reader_wrapper.c:308`
  through the driver's `reader->ops->next()` call; address is 192 bytes past
  the 72-byte wrapper allocation made at verbatim wrapper line 218. rc 1.
- Fixed on the same input: rc 0, `event[0]=-1`, no ASan report.
- Safe document `<a>text</a>`: both pins rc 0, first event `6`
  (GUTHTHILA_START_ELEMENT), no ASan report.
- `verify.sh` result: `RESULT PASS=4 FAIL=0`.

## Preserved negatives and caveats

- Three earlier build attempts failed before the harness linked: missing
  platform sources, missing `config.h`, missing platform include directory.
  Each was fixed by adding the pinned source/include path; no upstream source
  was modified.
- No OOB WRITE, chosen-offset readback, pointer steering, wire consumer,
  command or r5. The 72-byte wrapper allocation holds the 10-entry
  `event_map`; ASan stops at the read, so no adjacent live object is shown.
- Clang was not run; only GCC 12 ASan. Vendor CNA JSON labels severity
  "low" while CISA ADP assigns CVSS 9.1 — the disagreement is preserved, not
  resolved here.
- Advisory prose claims a network-reachable trigger; this lab used an
  in-memory document via the local driver. No wire path is claimed.
