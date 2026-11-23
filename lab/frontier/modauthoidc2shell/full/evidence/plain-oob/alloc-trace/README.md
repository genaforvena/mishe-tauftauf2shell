# APR allocation-trace check (2026-11-23 W10)

`aprtrace.c` is a throwaway `LD_PRELOAD` interposer for `apr_palloc` and
`apr_pcalloc`. It writes `kind address size caller` lines with `write(2)`, so it
does not allocate while logging. The live plain-module probe was run under gdb
with `LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8:/tmp/aprtrace.so`:
`libasan.so.8` must come first because this httpd binary links ASan, and the
preload order shifts the lab layout while keeping the store shape.

At pinned `state.c:219` the store was `0x7ffff6ddd221`, with the same
pointer-low-byte shape (`WORD` ends in `0x3d`). The 594-line trace has
**no allocation covering that address**: the nearest following allocation
starts at `0x7ffff6ddd290` (0x6f bytes later, size 0xd0, caller
`0x5555556440a2`). The closest preceding allocation ends at
`0x7ffff6ddb034`, leaving the store in a gap.

Interpretation limit: calls made *inside* libapr to its own `apr_palloc` are
bound locally and do not pass through the interposer. This trace therefore
cannot prove the word is unowned; it is consistent with the W9
`apr_socket_accept` result that the word is connection-pool slack/stale data,
not a live long-lived object. No consumer effect follows from this trace.

Raw: `aprtrace.log`, `apr-oob-gdb.txt`. No repository script depends on the
tracer; it was run once as a negative instrument.
