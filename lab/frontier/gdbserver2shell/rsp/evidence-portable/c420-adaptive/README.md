# c420 adaptive-offset evidence (W8)

Parent environment: the wake environment with one long variable
(`MEMORY_PRESSURE_WATCH`) shortened by exactly 32 bytes. The harness takes
no new argument; any parent environment whose abort sweep derives
`obj=0x55555561c420` is equivalent (W140's Python parent was one).

Command from repo root:

    bash lab/frontier/gdbserver2shell/rsp/r5_portable_verify.sh \
      $PWD/lab/build/gdbserver-633ae02-plain/gdbserver/gdbserver \
      $PWD/lab/build/gdbserver-633ae02-asan/gdbserver/gdbserver-fixed

`run.out` is captured stdout/stderr after the chooser parser repair:
`reject delta=0x8 name=28c461555555`, `CHOSEN delta=0x10`,
`COMMAND_HEX=30c461555555`, `SLOT_LEN=72`, four PASS lines,
`P_SYSTEM_NORMALIZED_HASH=6be8244f7949331ac1f8ee9e1a1389e4f30a8525f25317a444063367d41d3747`.
The `p-system-*` files are the four case transcripts and marker records
copied from the harness evidence directory; the hash covers them in the
script's fixed case order. `p-system-sweep-2.*` is the abort probe that
identified c420.
