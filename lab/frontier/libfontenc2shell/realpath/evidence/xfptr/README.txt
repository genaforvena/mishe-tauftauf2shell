W187 — chosen-address function-pointer overwrite inside a live Xvfb, and why
the hijacked pointer is never invoked
=============================================================================
2026-11-24.  Vulnerable pinned 7418fa7 vs fixed 5920c6e, plain shared
libraries, loopback-only Xvfb started by xlive/run-xfptr.sh.

Method
------
A test-only LD_PRELOAD interposer (xlive/interpose.c, not pinned upstream
source) logs:
  - LF_BUF from reallocarray when the 131072-byte encoding buffer is allocated,
  - each live FontMapRec and recode field from FontEncFind,
  - every FontEncRecode target,
  - its own benign marker address from a constructor.
The .enc uses two `cmap 3 1` decoy mappings so the first `unicode` mapping is
m3, which the parser allocates AFTER the buffer.  Phase 1 runs an in-bounds
input and reads buffer, m3 and marker addresses; phase 2 computes
idx = (m3 + 0x10 - buffer)/2, decomposes it with row_size 258 into four `from`
values, splits the marker address into four 16-bit words, and writes them into
mappings 4..7.  Fixed and safe-input controls use the same runner.

Results (matrix.txt and the four filtered *.xvfb.txt logs)
----------------------------------------------------------
vuln-crafted-a/b: m3->recode = 0x7ffff7fb9159, exactly the benign marker
  address reported by the interposer; client_rc=0, no crash, 0 marker calls.
vuln-safe (SIZE 256 256): m3->recode = 0x7ffff7fb2885 (library's
  FontEncSimpleRecode), 0 marker calls.
fixed-crafted: m3->recode = 0x7ffff7fb2891 (fixed library's recode), 0 marker
  calls; the fixed guard rejects every out-of-range mapping.
In all cases FontEncRecode is called only on 0x5555558424b0, i.e. m1.

Structural finding (the nginx2root lesson applied)
---------------------------------------------------
The chosen-address overwrite of a live function pointer DOES work inside a
real X server.  But libXfont2 calls FontEncRecode only on the encoding's FIRST
mapping (m1), which the parser allocates before the buffer.  The forward
out-of-bounds store cannot reach m1 no matter how the later mappings are
groomed, so the hijacked m3->recode is never invoked.  Reordering mapping types
did not change which mapping is recoded.  This is a consumer-behaviour limit,
not a grooming failure: it kills control-flow diversion through recode in this
live path.

Scope
-----
Rung 4 memory control in a live server (chosen bytes at a chosen offset into
a live function pointer, with fixed/safe controls); NOT control-flow diversion
in Xvfb, not a command, not remote input, not privileged context.  The
benign-marker EXECUTION demonstrated in W186 remains a direct public-API
harness result.  Layout depends on ASLR-off plus a fixed malloc threshold; the
runner recalibrates the index each time because LD_PRELOAD path length shifts
the heap by 0x20.  Rung 5 stays UNKNOWN; witness has not replayed W187.
