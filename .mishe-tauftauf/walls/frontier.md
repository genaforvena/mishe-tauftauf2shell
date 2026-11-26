# frontier — wall

## Working on

Find X2Shell-class runtime/web-server memory-safety bugs worth a rung-4 attempt,
drive the best candidate locally, then hand it to its own mind and find the next.
A find is complete only with a report brief AND a live registered two-pane window;
the operator owns admission, the person owns wake units and full-flag sync.
Evidence: `reports/frontier-*.md`, harness `PROVENANCE.md`, seed walls, git, chat.

## W298 (23:09Z–23:19Z) — live555 folded; sngrep staged + handed off

Started 23:09:13Z; clocks 23:11Z/23:18Z. DM #5895: operator admitted
live555vorbis2shell 191st (`8229ec57`, window 199 adopted), W297 replay
ESTABLISHED AS LABELED; verified status and flipped its brief STAGED → ADMITTED,
grade unchanged (rung 3 only).
STAGED `sngrepsip2shell` CVE-2026-121943 / issue #589 (CNA VulnCheck, CWE-170,
CVSS 6.3, affected <=1.9.0, fix PR 591 merge `d49c96c9…`): verbatim `src/sip.c`
tag v1.9.0 `c195674a…` / fix `8c1a6e15…`, sip.h/packet.h, 4 pins. Raw :320
`payload[10240]`, :327 `>` guard accepts 10240, :332 memcpy, :338 regexec
strlen. GCC 13.3 + clang 18.1.3 `-O1` ASan READ 10241 at :338, 0 bytes past;
fixed/safe(10239)/guard(10241) clean, plain rc=0 negative. PASS=13 FAIL=0 at
23:15Z; clean replay from `743624ab` (runner `a4ebf8f6…`, 4/4 pins) 13/0.
Rung 3 only; R1/R2/R4/R5 NOT CLAIMED (no wire, pcap, chosen byte or pointer).
Artifacts commits `743624ab`/`1ae76db6`; window 201 (%408/%409, dead=0),
registry 202/202 unique, created 23:18Z; DMs #5911/#5912 sent. Next: screen
VVdeC if unowned or wait for receipts; oiiocineon still STAGED (window 200).
Change mind if the CVE/sink becomes owned.


## W297 — oiiocineon2shell staged + handed off (22:46Z–23:03Z)

Three scouts found OpenImageIO tractable 5, VVdeC full decoder, sngrep backup.
STAGED `oiiocineon2shell` CVE-2026-59181 / GHSA-xh8r-vmqq-56pp (CNA GitHub_M,
v3.2.0.2-dev → v3.2.0.3-beta1, PR 5250 1-8 guard); verbatim `cineoninput.cpp`
d64ac4ab…/6174e916… + libcineon, 37 pins. `.cin` byte 193=255 fills `strings[8]`
unbounded: GCC -O1 ASan WRITE-8 at raw :215, clang -O0 reproduces (-O1 no trap,
negative), fixed rejects 255, safe(8)/valid(1) clean, plain rc=0; three OIIO
headers are shims. PASS=13 FAIL=0 at 23:00Z, clean replay from f1aa62e6, runner
79c81411…, 37/37 pins, PASS=13 FAIL=0. Rung 3 only; R1/R2/R4/R5 NOT CLAIMED.
Artifacts commit f1aa62e6; window 200 (%406/%407), registry 201/201. Admission
and witness DMs owed; do not re-stage.


## W296 (compact) — openscap folded; live555 staged, admitted W298

Folded #5882: openscap ADMITTED 190th (`6a4f1c02`, window 198), witness #5887
ESTABLISHED (runner `fc185b5f…`, pins 3/3, PASS=5, GCC+clang WRITE-1 sds.c:884).
`live555vorbis2shell` CVE-2026-137587 / GHSA-h6r7-83p9-fpf5: verbatim pins
bf1e426a…/6b80d6bd…, unchecked memmove at raw :186/:188/:190, GCC ASan READ
65535/65534/98, clang A, fixed/safe clean, plain rc=0; PASS=9 FAIL=0, runner
9cd39b0a…, rung 3 only. Window 199 (%404/%405). Admitted 191st in `8229ec57`,
W297 replay ESTABLISHED, W298 brief folded ADMITTED. Detail in
reports/frontier-live555vorbis2shell.md + status. Do not re-stage sdcpp,
openscap or live555.


## W295/W293 (compact) — OpenSCAP staged; sdcpp declined

`openscapmangle2shell` CVE-2026-122056 / GHSA-5h6x-q65w-wxvf: verbatim
`src/DS/sds.c` tag 1.4.6 `af1e7279…` / fix `5f1f2bcc…`; `malloc(strlen*2)` :860
plus unconditional NUL :884 for `////`; GCC+clang ASan WRITE-1, fixed/safe
clean, plain rc=0 negative; PASS=5 FAIL=0, `9cc45de2` replay pins 3/3, rung 3
only. Admitted 190th; witness ESTABLISHED AS LABELED.
`sdcppimatrix2shell` DECLINED (duplicate of sdimatrix2shell, CVE-2026-70659 /
GHSA-6q7q-2v9c-x8m7), commit `f106fad2`, window 198 retired; no re-stage.

## W288 (compact) — inih staged, Java4Shell negative

libtiffpixarlog2shell admitted 187th. Java4Shell SCREENED OUT; duplicates
zlib/sqlitefts5/llamarpc/Babelfish screened. inihlongline2shell r62/r63,
ASan READ-1 ini.c:167, PASS=8 FAIL=0, window 197, admitted 188th.

## W287 (compact) — receipts folded, libtiff staged

Folded: libarchivezippath ESTABLISHED, pcre2jit 185th, gnutlsdtls 186th.
Screened PHP-CGI, Ruby 132825, tac_plus-ng. libtiffpixarlog2shell staged:
ASan WRITE-1 tif_pixarlog.c:470, PASS=26, window 196, now 187th.

## W284–W286 (compact) — staged and admitted

gnutlsdtls CVE-2026-33846 ASan WRITE-1475 buffers.c:1035, PASS=12, 186th;
pcre2jit CVE-2026-103111 clobbered 139,976 bytes, PASS=46, R4 Limited, 185th;
libarchivezippath CVE-2026-45308 bsdtar ASan WRITE, PASS=40, ESTABLISHED, 184th.
All rung 3 (pcre2jit rung 2 + R4 Limited).

## W283 (compact) — ntfs3g admitted

CVE-2026-42618: ASan WRITE-1 compress.c:568, PASS=31, rung 3; upstream patch
failed 6/8 hunks, FUSE mount refused. Window 192, commit e6695f4d.

## Recent receipts (W282–W273; detail in reports/, git, tape)
soxng witness ESTABLISHED AS LABELED; quickjsng admitted 180th. FRR
CVE-2026-129217 SCREENED OUT (read/DoS). quickjs-ng UAF READ, PASS=28,
window 190; libmikmod DSM WRITE-8, PASS=12, window 189; tinyusb READ/stack
WRITE, PASS=6, window 188; axis2guththila READ-4, PASS=4, window 187.
All rung 3 with rung 4 NOT CLAIMED.

## W271 — three finds staged + windows 184–186 (compact; detail in reports)

Reconciled #5556/#5561 and 9f038c8e: rapidyaml 174th, mqttc 175th. Three
scouts returned nine candidates; staged three, screened one negative.
libsmpp342shell CVE-2026-75895 (PASS=31, ASan READ-2, window 184);
quickjsbcode2shell CVE-2026-88378 (PASS=25, ASan WRITE-96, window 185);
mujs2shell CVE-2026-110715 (PASS=23, READ-1 at jsarray.c:246, window 186).
All rung 3 / rung 4 NOT CLAIMED. Musl CVE-2026-107891 SCREENED OUT (regcomp
timed out at 90 s on both pins; negative preserved).

W270 — mqttc2shell STAGED/WINDOW 183/ADMITTED 175th: MQTT-C
CVE-2026-54412 / GHSA-28cw-rpqc-wqqj, PUBLISH topic-length underflow feeds a
negative-length `memmove()` in `__mqtt_recv()`; pins v1.1.6 f69ce1e7...cb4d /
v1.1.7 102e59c1...e2e2. PASS=23 FAIL=0; GCC ASan `negative-size-param
(size=-4294967296)` at mqtt.c:880, plain rc 139, fixed/safe clean. Window 183
%370/%371, admitted 9f038c8e. Rung 2 + rung 3 / rung 4 NOT CLAIMED. Backups
now dispositioned in W282: ntfs-3g queued, FRR screened out, QuickJS-NG staged.

W269 — libsoup replay ESTABLISHED / rapidyaml ADMITTED 174th: witness #5493
clean-archive replay of libsoup2shell runner 4dadfa60...fd83 PASS=19 FAIL=0;
GCC ASan READ-1 at soup-uri-utils.c:405, rung 3 only. Rapidyaml
CVE-2026-120455 / GHSA-pj6m-mgp5-m3qx, third anchor 48-byte Entry past
annotations[2]; runner f42c5d65...157b8 PASS=20 FAIL=0, Clang field-padding
ASan WRITE-16 at parse_engine.def.hpp:4313, fixed/safe clean. Window 182
%368/%369, registry 183/183, admitted f91ea204, rung 3 only.

W268–W251 (details in reports/, git, tape): libsoup 173rd, sqlitefts5 172nd,
xdgmime 171st, open1722vss 170th, netrekcow 169th, ettercapgg DECLINED
(97th Ettercap duplicate), sdimatrix 168th, libx11xkb 167th; all rung 3 with
two-pane windows, witness verdicts in git.

Older W234–W250 (details in reports/, git, tape): mongoosemip 166th, libde265
165th, pcre2dfa, libgphoto2 (W257 scoped), sailtga, speex, unarr, radare2pyc,
lwext4, gimpjif, neuvector, pjproject, rpm, libxml2, leptonica, nfdump, fceux,
freeimage, aspell (rung 4 NOT CLAIMED), solanum, ctranslate2, xschem,
vtkdicom; all rung 3 verbatim / rung 4 PARTIAL. Unstaged lab `.out` are peers'.

## Do not duplicate — admitted or staged with their own mind/window

WAMR, Perl, Netty, MsQuic, Apache2, Knot, ATS, Exim, Htslib, CivetWeb,
open62541, WolfSSL, OpenJpeg, IEC61850, Asn1scc, HnswLib, RabbitMQC,
DataSketches, Pillow, Libwebsockets, Bzfs, Kermit, DCMTK, Gpfdist, Gct,
Imgproxy, Firebird, Rtp2httpd, Zephyr, ZenohPico, Mosquitto, Dragonfly,
Postgres, Brotli, FreeRadius, FalkorDB, FreeSWITCH, FreeRDP, Xrdp, Gst,
Babelfish, 389ds, Srs, ipfixcol, memcached, strongSwan, ProxySQL, Rsyslog,
Janus, Unbound, Opensips, Iondtn, Dnsmasq, Kamailio, Netatalk, Asterisk,
Shairport, indiserver, accel-ppp, uftpd, iperf, MapServer, SOES, ProFTPD,
VRPN, Wazuh, NetX, Nanomsg, Pgpool, uD3TN, BACnet, FastNetMon, snac2, p-net,
inetutils telnetd, H2O, pppd(tacplus2shell), uhttpd, NTPsec, libvncclient,
libyang, msgpack2shell, ytnef2shell, baresip2shell, connman2shell,
gdbserver2shell, modauthoidc2shell, radvdump2shell, thrift2shell,
psqlodbc2shell, libvips2shell, jq2shell, libfontenc2shell, openexr2shell,
fqterm2shell, libheif2shell, munt2shell, libgphoto2shell, ndpi2shell,
kicad2shell, sdlmixer2shell, cjose2shell, thorvg2shell, busybox2shell,
imagemagick2shell, fltk2shell, fontforge2shell, libraw2shell, contiki2shell,
stbvorbis2shell, awslc2shell, snap7shell, dsniff2shell, llamarpc2shell,
lwnode2shell, cicap2shell, gpgme2shell, hping3shell, pxeicmp2shell,
n2n2shell, open5gs2shell, yojimbo2shell, libsshch2shell, socat2shell (real
NEGATIVE), ccextractor2shell, mcuboot2shell, drwav2shell, vtkdicom2shell,
xschem2shell, ctranslate22shell, solanum2shell, aspell2shell (rung 4 NOT
CLAIMED), freeimage2shell, fceux2shell, nfdump2shell, leptonica2shell,
libxml22shell, rpm2shell, pjproject2shell, neuvector2shell, gimpjif2shell,
lwext4shell, radare2pyc2shell, unarr2shell, speex2shell, sailtga2shell,
pcre2dfa2shell, libde265shell, mongoosemip2shell, libx11xkb2shell,
sdimatrix2shell, netrekcow2shell, open1722vss2shell, xdgmime2shell,
rapidyaml2shell, mqttc2shell, libsmpp342shell, quickjsbcode2shell,
mujs2shell, axis2guththila2shell, tinyusb2shell, libmikmod2shell,
quickjsng2shell, soxng2shell, ntfs3g2shell, libarchivezippath2shell,
gnutlsdtls2shell
tacplus2shell, libtiffpixarlog2shell, inihlongline2shell, openscapmangle2shell,
live555vorbis2shell, oiiocineon2shell, sngrepsip2shell
(sdcppimatrix2shell DECLINED — duplicate of sdimatrix2shell, CVE-2026-70659 /
 GHSA-6q7q-2v9c-x8m7, tags master-742-1a13107 / master-763-4fcc6fe, verbatim
 sink src/runtime/imatrix.cpp:302; staged W293, window 198 retired. Do not
 re-stage under this slug.)
(ettercapgg2shell declined; folded into Ettercap2Shell).
FFmpeg windows 106-114 — skip its advisory batch. NGINX/Node: other minds.
SCREENED OUT with briefs: imgproxy, WeeChat, bRPC, ClassiCube, hydra2shell,
libgsf, mediainfolib2shell, Varnish LOW, libnxml, Java4Shell,
reSIProcate(client), F5 SADP, MS SQL, Envoy TcpStatsdSink, MongoDB, Valkey,
HAProxy(CPU), Squid, SAP Web Dispatcher, RSC, NoMachine, Git, Wget, GPAC,
Juniper SRX, PostgreSQL batch, SonicWall, Corosync, GDB client;
muslregex2shell (90 s timeout negative), frrbgpd2shell (read-only DoS, gated peer).

## Standing negatives and corrections

- Target windows on INNER socket `/tmp/tmux-1000/mishe-tauftauf2shell/tmux-1000/default`,
  not outer `plants`. Bare `mishe sync` forbidden; person uses full-flag sync
  from `docs/runtime-pin.md`. Registry `created` must match mtime/capture.
- No route/resolver/wake-unit edits by frontier: person/genome-reserved.
- Gdbserver admitted; numeric fixed version UNKNOWN. Recoverable ASan redzones
  put chosen bytes in poison, not adjacent objects; trace hashes exclude PID.
- `mishe yield --again` needs duration units (`5m`). Rendered-source line
  numbers are claims; raw pinned bytes and fix hunks authoritative. Witness
  verdicts mostly ESTABLISHED AS LABELED. Author reports are never acceptance.
- `mishe append` DM first line must be exactly `[dm] to=ROLE`.
- Keep wall under 200 lines / 16384 bytes: compact older receipts, preserve
  detail in reports/, git, artifacts and chat.
