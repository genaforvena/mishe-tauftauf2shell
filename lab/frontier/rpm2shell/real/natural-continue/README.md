# Natural adjacency: measured dereference negative (2026-11-26)

Question: does the *natural* pointer-valued qword at `buf+0x20`, overwritten by
the crafted cpio payload in real `rpm2cpio`, reach a downstream dereference?
No `LD_PRELOAD`, allocator groom or debugger-forced execution was used.

Runner: `bash lab/frontier/rpm2shell/real/run-natural-deref.sh` from the repo
root (or `bash real/run-natural-deref.sh` from `lab/frontier/rpm2shell`). It
needs the existing untracked plain build `../build-vuln-plain/tools/rpm2cpio`
and fixture `real/attack.rpm`. Raw logs land in the gitignored `raw/` directory.
Verified run: `NATURAL_DEREF_PASS=52 NATURAL_DEREF_FAIL=0`,
`NATURAL_POINTER_ADJACENCY=4/20 READ_WATCHPOINT=20/20 INSPECT_POINTER=0/12`.

Three GDB scripts, all breaking at pinned `lib/rpmfi.cc:2242`/`:2243`:

- `layout-continue.gdb` dumps before/after and *continues* instead of quitting.
  20/20 runs: `exited with code 01`, no `SIGSEGV`. The consumer takes the
  `RPMERR_READ_FAILED` path: with `lsize = -1`, an actual 64-byte copy can
  never equal the declared `UINT64_MAX`, so line 2242 sets `rc`, line 2245
  frees `buf`, and line 2253 returns the error. No later code consumes the
  adjacent object on this path.
- `rwatch-after.gdb` sets a hardware read watchpoint on `*(long *)(buf+0x20)`
  immediately after the copy, then continues. Natural adjacency is
  nondeterministic: an earlier 20-run set had 6/20 pointer-bearing qwords
  (`0x5555555a20f0`, `0x5555555ec890`), the verified replay had 4/20
  (`raw/rwatch-1.log`: before `ADJacent=0x5555555f3e20`, after
  `ADJacent=0x4141414141414141`); the committed sample is
  `samples/rwatch-replay-pointer.log`, and sample
  `samples/rwatch-pointer.log` has `0x5555555a20f0` before the overwrite.
  The watchpoint fires in 20/20 runs, *including runs where the qword was
  nil before the copy*, and stops at
  `iterReadArchiveNext ... rpmfi.cc:2245` with PC one instruction before
  `call free@plt`. The disassembly in `samples/rwatch-disasm.log` shows the
  surrounding instructions (`mov -0x10(%rbp),%rax`, `mov %rax,%rdi`,
  `call free@plt`). Since the trigger is value-independent, it does not
  establish a semantic dereference of the corrupted pointer.
- `inspect-adjacent.gdb` dereferences the pre-copy qword for identification.
  In pointer-bearing samples (earlier set: 3/12, e.g.
  `samples/inspect-pointer.log`, pointer `0x55555559d640`) the
  target is a live rpm header-data region holding tag strings (`sin`,
  `/dev/n...`), and the adjacent object itself has tag word `0x00122204`,
  count `6` and inline string `return`. Verified replay had 0/12 such runs.
  The object type is header-import data, not a vtable, function pointer or
  callback slot.

Conclusion: **no natural semantic pointer dereference was observed** in this
consumer. The natural qword is pointer-bearing only intermittently and its
overwrite is followed by an immediate error return; the observed reads at
`free(buf)` are not value-dependent. Keep the grade at rung 4 DEMONSTRATED
(64 chosen bytes past a 1-byte allocation; lab-groomed live pointer-bearing
victim), with natural pointer hijack still UNKNOWN. A different consumer or a
path that continues past `RPMERR_READ_FAILED` would be needed to advance.
