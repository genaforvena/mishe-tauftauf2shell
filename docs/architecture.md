# Autonomous organisation

| Role | Responsibility |
|---|---|
| Research minds | Independent investigations |
| Frontier | Research intake |
| Witness | Independent verification |
| Docs | Maintaining the public record |
| Operator | Governance and scoped approvals |

The **research mind** that produces a claim never accepts it. The **witness** replays the claim from a clean checkout, with its own builds and controls, and grades only the scope it actually observed. Author-only verdicts stay UNKNOWN.

## How the plant works

Current counts are generated in `README.md` and `docs/results.md` (173
declared / 170 active at 2026-11-26). The roster below is the historical
163-mind list, preserved as such, not a current count.

Each admitted family is its own mind with its own tmux window: 163 target
minds — `ruby2shell`, `php2shell`, `node2shell`, `apache2shell`,
`mosquitto2shell`, `dragonfly2shell`, `postgres2shell`, `brotli2shell`,
`freeradius2shell`, `falkordb2shell`, `freeswitch2shell`, `freerdp2shell`,
`xrdp2shell`, `gst2shell`, `babelfish2shell`, `bzfs2shell`,
`kamailio2shell`, `iperf2shell`, `uftpd2shell`, `accelppp2shell`,
`indiserver2shell`, `shairport2shell`, `asterisk2shell`, `netatalk2shell`,
`iondtn2shell`, `unbound2shell`, `opensips2shell`, `janus2shell`,
`rsyslog2shell`, `proxysql2shell`, `strongswan2shell`, `memcached2shell`,
`ipfixcol2shell`, `srs2shell`, `389ds2shell`, `kermit2shell`,
`gpfdist2shell`, `gct2shell`, `imgproxy2shell`, `firebird2shell`,
`rtp2httpd2shell`, `zephyr2shell`, `zenohpico2shell`, `libwebsockets2shell`,
`pillow2shell`, `datasketches2shell`, `rabbitmqc2shell`, `hnswlib2shell`,
`asn1scc2shell`, `awslc2shell`, `iec618502shell`, `openjpeg2shell`,
`wolfssl2shell`, `htslib2shell`, `civetweb2shell`, `cicap2shell`,
`open625412shell`, `knotresolver2shell`, `ats2shell`, `exim2shell`,
`netty2shell`, `wamr2shell`, `perl2shell`, `msquic2shell`,
`proftpd2shell`, `soes2shell`, `vrpn2shell`, `netx2shell`, `wazuh2shell`,
`mapserver2shell`, `nanomsg2shell`, `pgpool2shell`, `pgactive2shell`,
`ud3tn2shell`, `bacnet2shell`, `fastnetmon2shell`, `pnet2shell`,
`snac2shell`, `inetutils2shell`, `h2o2shell`, `hping3shell`,
`libyang2shell`, `msgpack2shell`, `sofiasip2shell`, `ytnef2shell`,
`baresip2shell`, `connman2shell`, `pppd2shell`, `pxeicmp2shell`,
`libssh22shell`, `tacplus2shell`, `ntpsec2shell`, `uhttpd2shell`,
`libvnc2shell`, `gdbserver2shell`, `erlang2shell`, `minisnmpd2shell`,
`ettercap2shell`, `ghostscript2shell`, `llamarpc2shell`, `zlib2shell`,
`snap72shell`, `mongoose2shell`, `modauthoidc2shell`, `radvdump2shell`,
`fluentbit2shell`, `ffmpeg2shell`, `psqlodbc2shell`, `thrift2shell`,
`libvips2shell`, `jq2shell`, `openexr2shell`, `libheif2shell`,
`fqterm2shell`, `munt2shell`, `libfontenc2shell`, `libgphoto2shell`,
`kicad2shell`, `ndpi2shell`, `n2n2shell`, `synchronet2shell`,
`sdlmixer2shell`, `cjose2shell`, `thorvg2shell`, `busybox2shell`,
`fontforge2shell`, `fltk2shell`, `contiki2shell`, `libraw2shell`,
`gpgme2shell`, `imagemagick2shell`, `codebasememory2shell`, `assimp2shell`,
`open5gs2shell`, `yojimbo2shell`, `libsshch2shell`, `socat2shell`,
`ccextractor2shell`, `mcuboot2shell`, `drwav2shell`, `vtkdicom2shell`,
`xschem2shell`, `stbvorbis2shell`, `ctranslate22shell`, `solanum2shell`,
`aspell2shell`, `freeimage2shell`, `nfdump2shell`, `leptonica2shell`,
`libxml22shell`, `rpm2shell`, `pjproject2shell`, `neuvector2shell`,
`gimpjif2shell`, `lwext4shell`, `radare2pyc2shell`, `unarr2shell`,
`speex2shell` and `sailtga2shell`. Each builds
affected harnesses, drives toward rung 4 and authors its report under
`reports/`.

Four cross-cutting minds: **frontier** hunts public advisories and hands a
reproducible harness to the operator; **docs** keeps this README and `docs/`
true to the shipped code and is woken by the `repo-change` commit signal;
**witness** re-runs every claim from a clean checkout; **operator** is the
owner's delegate for scoped approvals and admissions under recorded standing
permissions.

An idle wake owes a bounded, falsifiable experiment deeper toward rung 4 (or
rung 5 where a measured path exists) — or, once that rung is closed on the
tested build, an adjacent lane in the same source tree. New products and runtimes go to frontier/operator for a new mind.
Negative results and UNKNOWNs are preserved in the reports; the columns above
map the boundary actually reached. All minds route through OMP with
`opencode-go/hy4-flash-free` as the tier-0 primary (`max_parallel: 5`) and
`opencode-go/hungerg-free` as the tier-1 fallback (`max_parallel: 1`). The
2026-11-25 fallback was retired after rate limiting and reinstated by the
owner on 2026-11-26.
