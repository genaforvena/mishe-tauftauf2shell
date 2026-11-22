# W125 — reachable notifier pointers, and a failed rung-5 attempt (2026-11-22)

Extension of the witnessed W123 result. Grade remains **rung 4**. This wake
corrected the W123 note's premise (hooks at ~1952+ are out of reach) and
demonstrated full deterministic 8-byte control of three NULL-initialized
notifier pointers in a live 2.5.3 daemon. A separate two-frame attempt at
command execution failed for named structural reasons; it is preserved as a
negative result, not a rung-5 claim.

## Correction to the W123 plan

`nm -n -S` on the plain 2.5.3 build locates `nak_buffer` at the link-time
offset 0 and the notifier heads at these relative offsets:

| global | offset | reachable with info <=1500? |
| --- | --- | --- |
| `last_pkts_in` | +1500 | yes |
| `ifname` | +1504 | yes |
| `the_channel` | +1528 | yes (low half only if a later frame overwrites the high half) |
| `hostname` | +1568 | yes |
| `uid` | +1824 | yes |
| `pidchange` | +1832 | yes, but non-deterministic high half (points into PIE heap at startup) |
| `phasechange` | +1840 | yes, high half stays zero |
| `exitnotify` | +1848 | yes, high half stays zero |
| `sigreceived` | +1856 | yes, high half stays zero |
| `fork_notifier` | +1864 | no (`frame_for` count goes negative) |
| `holdoff_hook`, `new_phase_hook`, `snoop_*` | +1952.. | no |

The maximum NAK stream is ~1875 bytes because the receive buffer is a fixed
`inpacket_buf[PPP_MRU+PPP_HDRLEN]`. No negotiated MRU changes that. The
earlier hooks at +1832..+1856 are reachable without any multi-step handshake.

## Primitive and byte order

`chosen_write.py` NAKs `CI_ASYNCMAP` with
`PUTLONG(ao->asyncmap | cilong, nakp)` (`lcp.c:1566-1569`). `PUTLONG` is
**big-endian**. A little-endian 32-bit value written into a pointer therefore
appears byte-reversed; W123's `50 57 4e 33` was symmetric in effect, which
masked this. For a chosen LE pointer `P`, the request CI must carry
`bswap(P)` with the `escape` option's forced bit cleared. `escape NN` sets
`lcp_allowoptions[0].asyncmap = 1 << (NN & 31)` (`tty.c:405-421`).

## Observed cases

All from the real receive path `main -> get_input -> lcp_input -> fsm_input
-> fsm_rconfreq -> lcp_reqci`, pre-auth, first frame. `sudo gdb -p` read
memory only; it wrote nothing.

| tag | observation |
| --- | --- |
| `w125-ctrl-t1500` | safe offset; all five notifier pointers remain zero except `pidchange` (its normal heap value); `the_channel` intact. |
| `w125-hook-pidchange` | target +1832; `pidchange` low half becomes the marker, high half remains the run's PIE-base value — non-deterministic. Daemon later faults on the corrupted `the_channel` during shutdown. |
| `w125-hook-t1840` | target +1840; `phasechange = 0x0000000041424242`. |
| `w125-hook-t1848` | target +1848; `exitnotify = 0x0000000041424242`. |
| `w125-hook-t1856` | target +1856; `sigreceived = 0x0000000041424242`, `fork_notifier` still zero. |
| `w125-asan-vuln` | target +1856 on 2.5.3 ASan: `global-buffer-overflow`, `WRITE of size 1`, 0 bytes after `nak_buffer[1500]`, top frame `lcp_reqci lcp.c:1608`; rc 1. |
| `w125-asan-fixed` | same frame on 2.5.4 ASan: alive, `LCP: ignoring duplicate configuration option(s)`, one ASYNCMAP NAK, chosen bytes absent. |

Normalized files and `HASHES.txt` are in `evidence/`. Raw logs stay in the
ignored `live/raw/`. `normalize_chosen2.py` masks build paths, process ids, gdb
addresses and PIE pointer values; it keeps zero-extended chosen markers such as
`0x0000000041424242` and deterministic NAK byte data verbatim. Hashes are
stable across fresh captures whose only difference is PIE randomisation. A
blanket long-hex mask would erase the marker and was rejected.

## Failed rung-5 attempt (`rce_attempt.py`, non-PIE build)

Hypothesis: with a `-no-pie` pinned 2.5.3 build, all addresses are fixed, so a
NULL notifier pointer set to a chosen `.bss` address could be made to call
`execl@plt("/bin/sh", NULL, ...)`, yielding a shell on the local pty. The
driver sends two frames: a NAK frame setting `phasechange` to an address in
`inpacket_buf`, then a malformed LCP ConfReq whose body is rejected verbatim
into `inpacket_buf` as a fake `struct notifier` (`next=NULL`,
`func=execl@plt`, `arg="/bin/sh"`). A SIGTERM should reach
`new_phase(PHASE_DEAD)` and `notify(phasechange, 0)`.

Three replays (`raw/nopie1..3-*`) failed:

1. `escape 00` forces bit 0; because `PUTLONG` is big-endian, the pointer
   arrived byte-reversed (`phasechange = 0x000000002b884600`). Fixed by
   `escape 09` and clearing bit 9 in the request CI.
2. With the pointer correct, pppd reached `Connection terminated.` and then
   `Fatal signal 11`. `link_terminated()` (`auth.c:717-768`) dereferences the
   overflow-corrupted `the_channel` at `disestablish_ppp`, `disconnect` and
   `cleanup` *before* the final `new_phase(PHASE_DEAD)`. The hook is never
   called. No file side effect, no shell, no rung 5.

The attempt also exposes why a simpler `sigreceived` route fails: `notify`
calls `func(arg, val)` with `val` an `int` (signal number / phase number),
and the pinned binary has no one-argument command-execution function at a
known address (`system` is not in the PLT; `execl` needs a valid `argv[0]`;
`device_script` and `run_program` need `uid` and multiple arguments while
`uid` is itself overwritten by the same NAK stream). `-no-pie` is a
lab-only hardening change and would need its own vulnerable/fixed controls
even if a callback existed.

## Grade boundary

Rung 4 is strengthened: four attacker-chosen bytes at an absolute global in
a live daemon now include deterministic full 8-byte values in three
notifier-pointer objects, with vulnerable ASan, fixed and safe-input
controls. No hook was called with a controlled target, no command or side
effect. The witness replayed all seven cases (below): **no rung 5**.

## Independent witness replay (W126, 2026-11-22, DM #1707)

The witness rebuilt both pins from a clean `git archive HEAD` tree with its own
gcc 13.3 (ASan and plain), replayed all seven `chosen_write.py` cases on a live
PTY under sudo gdb, and reproduced every observation: `0x0000000041424242` in
`phasechange`, `exitnotify` and `sigreceived`, `fork_notifier` zero, fixed-pin
duplicate-CI rejection, and the 2.5.3 ASan `WRITE of size 1` at
`lcp_reqci lcp.c:1608` 0 bytes past `nak_buffer[1500]`. Four normalized hashes
matched exactly; the other three differed only in PIE pointer values in gdb
readback, which `normalize_chosen2.py` now masks. Verdict: **rung 4 ESTABLISHED
at live-process wire scope**. Rung 5 stays UNKNOWN; the two-frame command
attempt above is a preserved negative. The witness made no repo changes.
