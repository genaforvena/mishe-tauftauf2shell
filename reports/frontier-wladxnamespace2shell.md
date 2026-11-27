# Frontier brief: wladxnamespace2shell — WLA DX `wlalink` stack overflow

Status 2026-11-27 W379: **ADMITTED 23:1xZ under standing #6 as the 224th
declared target mind**, inner-socket window 232 (`%470`/`%471`) adopted as-is;
operator clean-archive replay `d87c8e50` 16/0, independent witness replay owed.
Grade: R1/R2/R3 on the real pinned `wlalink` binary; R4 **LIMITED** to
attacker-chosen bytes in adjacent stack memory of the lab build; R5 **NO**.
Harness `lab/frontier/wladxnamespace2shell`; `RUN_ALL_OK 16 PASS / 0 FAIL`
twice in-tree, from clean archive `41a8e1d5` and from operator replay at
`d87c8e50`; independent witness replay owed.

- CVE-2026-131871, NVD published 2026-11-18T03:17Z, last modified
  2026-11-27T02:16Z; CWE-121. Claim: WLA DX 9.7 through 10.7
  `parse_data_blocks()` copies a section namespace into a 256-byte stack
  buffer without a length check; a crafted object/library file with a long or
  unterminated namespace overflows it during linking.
  https://nvd.nist.gov/vuln/detail/CVE-2026-131871
- Upstream fix `63755ffcd12f78d3bbadf3b24796383c734c4d77` ("Fixed buffer
  overflows in the linker", 2026-11-06) in release v10.8:
  https://github.com/vhelin/wla-dx/commit/63755ffcd12f78d3bbadf3b24796383c734c4d77
  https://github.com/vhelin/wla-dx/releases/tag/v10.8
- Pinned source: v10.7 HEAD `91c52b1f4ef3cc8ba3c0638f7536539579af6a9f`,
  v10.8 HEAD `887e74809d26d4f58130e62ae525f1c29790b490`, both shallow clones
  of https://github.com/vhelin/wla-dx. Fix patch SHA-256
  `5c330d0201e00d0bbcd5ce1a922a6429dfb49adf214f2cce5ad41cc04a5b041a`;
  full provenance in `lab/frontier/wladxnamespace2shell/PROVENANCE.md`.

## Source-bound mechanism

Pinned vulnerable `wlalink/analyze.c:2102-2176` declares `char buf[256]`, then:

```c
i = 0;
while (*t != 0)
  buf[i++] = *(t++);
buf[i] = 0;
```

`t` walks the object file's data block; a NUL-terminated section namespace is
copied byte by byte with no bound. The same function has three unbounded
siblings: section name (`s->name`), bank list (`s->banks`), and SPAN bank list
(`s->span_banks`). Fix `63755ff` changes `buf` to `char buf[MAX_NAME_LENGTH +
1]` (2048 bytes on this non-Amiga host), bounds every copy against its
destination, and rejects unterminated fields. Because the fixed buffer is
2048 bytes, a 2044-byte namespace remains *valid* in v10.8; the fixed clean
run is a safety control, not an expected rejection.

The real `wla-6502` assembler accepts a namespace up to 2044 characters
(2045+ is rejected by `parse.c`'s 2047-character string check), so the
reproducible input is a genuine object file produced by the pinned assembler,
not a hand-built binary.

## Local experiment

`harness/build.sh` builds three arms from the pinned clones: vulnerable v10.7
with ASan, fixed v10.8 with ASan, and vulnerable v10.7 plain (`-O0 -g
-fno-stack-protector`). `harness/run-all.sh` regenerates assembly inputs,
checks input pins, assembles with the matching pinned assembler and drives the
**real** `wlalink` binary with a linker configuration naming the object.

- Vulnerable ASan, namespace `C`×270: `AddressSanitizer: stack-buffer-overflow`,
  `WRITE of size 1`, fault `analyze.c:2155` in `parse_data_blocks()` called
  from `wlalink/main.c:1416`; ASan names a 256-byte `buf` in that frame.
- Fixed v10.8 ASan, same input: rc 0, no ASan report, normal 1-byte output.
- Vulnerable ASan and fixed ASan with namespace `ok`: rc 0, no report.
- Plain vulnerable build, pattern namespace `A`×256 + `D`×14: GDB breakpoint
  after the copy at `analyze.c:2156` reads `V256=44 V260=44 V269=44 V270=00`;
  the attacker-chosen `0x44` bytes occupy offsets 256..269 immediately past
  `buf`, then the written NUL. The process continues to a normal exit.
- Preserved negatives: 280-byte and 2044-byte namespaces corrupt enough of
  the plain stack that the process aborts (rc 135 and rc 139); no chosen-byte
  readback is claimed for those lengths. The fixed buffer accepts 2044 bytes
  cleanly, so the fix removes the overflow without narrowing valid input.

Evidence pins, exact commands and volatile-log handling are in
`lab/frontier/wladxnamespace2shell/PROVENANCE.md`; the pinned observations are
`harness/evidence/{vuln-asan.log,controls.log,gdb-pattern.log}`.

## Rung assessment and scope

- R1: deterministic trigger through the real linker with an object produced
  by the real assembler; no synthetic consumer.
- R2: chosen bytes from the object namespace land at chosen offsets just past
  the declared 256-byte buffer; a 14-byte overrun still links normally.
- R3: ASan-confirmed stack-buffer-overflow WRITE at the pinned sink.
- R4 **LIMITED**: GDB observes chosen `0x44` at offsets 256/260/269 of `buf`
  in the plain lab build; no function pointer, return address or control-flow
  transfer was measured, and larger overruns crash. This is a real store but
  not pointer control.
- R5: **NO**. Input is a local object/library file; no loopback service, wire
  request, shell or command side effect.

## Cheapest next experiments for a dedicated mind

1. Use GDB to identify what occupies the bytes after `buf` in the plain frame
   and test whether a modest overrun can reach a pointer-bearing slot without
   corrupting the loop's own `t`/`p` locals; preserve the 280/2044 crash
   negatives.
2. Exercise the sibling unbounded copies (section name, bank and SPAN bank
   lists) from the same fix and check whether their destinations have a more
   useful adjacent consumer.
3. Craft an object directly (bypassing the assembler's 2044-character string
   cap) to test unterminated-namespace and large-overflow paths, with the
   fixed binary as control.
4. Only after a real consumer store is measured, consider any benign command
   side effect; none is claimed here.

## Selection notes

Tractable: small C code base, released fix with an exact commit, real
file-format input from the project's own assembler, deterministic ASan report
and a measured chosen-byte store. Capped at R4 LIMITED by the absence of a
pointer consumer and by the plain-build crash on longer overruns; no R5 path.
