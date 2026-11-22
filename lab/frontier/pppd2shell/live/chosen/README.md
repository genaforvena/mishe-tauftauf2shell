# Chosen-value write at absolute globals (W123, 2026-11-22)

Extension of the witnessed W122 live-process result. This is still rung 4:
no command, side effect or rung 5 is claimed. It changes the *granularity* of
the demonstrated control from a chosen digest byte at a chosen relative offset
to four attacker-chosen bytes at chosen absolute `.bss` offsets in a live
daemon, including the low half of a pointer object.

## Primitive

`lcp_reqci()` NAKs a peer `CI_ASYNCMAP` option with
`PUTLONG(ao->asyncmap | cilong, nakp)` (`lcp.c:1566-1569`). Adding the pppd
option `escape 00` sets `lcp_allowoptions[0].asyncmap = 1` via
`setescape()` in `tty.c:417-421`, so any ASYNCMAP CI whose low bit is clear is
NAKed with four attacker-chosen bytes whose low bit is forced to 1. The frame
mixes 5-byte PAP AUTHTYPE NAKs with 6-byte ASYNCMAP NAKs to align the four
value bytes on an absolute offset. PAP padding is chosen so the LCP ConfReq
stays within the 1500-byte default MRU. Every write below came from the wire
frame; `sudo gdb -p` was used only to *read* the resulting globals.

## Replay

From `live/`, after `run_matrix.sh` has built the two ASan pins:

```
bash chosen/run_chosen_matrix.sh
```

This verifies the two pin hashes, builds a plain non-ASan vulnerable tree if
needed, runs five cases through `chosen_write.py` on a local PTY, and writes
normalized evidence and hashes to `chosen/evidence/`. Two consecutive full
runs produced byte-identical `HASHES.txt`. Raw pppd logs, ASan reports, frames
and gdb transcripts stay in the ignored `live/raw/`.

## Observed cases

| tag | build | target | observation |
| --- | --- | --- | --- |
| `w123-plain-t1500` | 2.5.3 plain | `nak_buffer+1500` (`last_pkts_in`) | `50 57 4e 33` ("PWN3") present; daemon's own ConfNak logs `<asyncmap 0x50574e33>`; survived. |
| `w123-plain-t1504` | 2.5.3 plain | `nak_buffer+1504` (`ifname`) | same four bytes at a second absolute global; survived. |
| `w123-plain-t1528` | 2.5.3 plain | `nak_buffer+1528` (`the_channel`, 8-byte pointer) | low four bytes replaced with `50 57 4e 33`, high four bytes unchanged; pointer read back as `0x0000……334e5750`; survived the observation window. No dereference or control-flow change was exercised. |
| `w123-asan-vuln-t1500` | 2.5.3 ASan | same frame | `global-buffer-overflow`, `WRITE of size 1`, 0 bytes after `nak_buffer`, top frame `lcp_reqci lcp.c:1568`; rc 1. |
| `w123-asan-fixed-t1500` | 2.5.4 ASan | same frame | alive, `LCP: ignoring duplicate configuration option(s)`, one ASYNCMAP NAK, target bytes still zero. |

All cases show the real receive path `main -> get_input -> lcp_input ->
fsm_input -> fsm_rconfreq -> lcp_reqci`, pre-auth, first contact. The value is
constrained: bit 0 is forced to 1 by `ao->asyncmap=1`; only 31 of 32 bits are
freely chosen. Reaching the hook function pointers at offsets ~1952+ is not
possible with the default 1500-byte receive MRU (maximum amplification is 1870
NAK bytes), so no control-flow object was reached.

## Grade boundary

Rung 4 is strengthened to four chosen bytes at chosen absolute global offsets
in the live vulnerable process, including partial (low-32-bit) control of a
pointer object, with vulnerable ASan, fixed and safe-input controls. This is
not rung 5: no command string, benign side effect, validated pointer value or
witness replay of these W123 cases exists yet.
