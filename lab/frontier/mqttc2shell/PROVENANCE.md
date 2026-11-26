# PROVENANCE — mqttc2shell (CVE-2026-54412)

Author: frontier, W270, 2026-11-26. All work local: no socket, broker,
external probe or command execution. This is a lab driver of the public MQTT-C
client receive API against verbatim pinned upstream source, **not** yet a live
wire path (the lab PAL stub returns zero bytes; the crafted packet is preloaded
into the client receive buffer).

## Pins (provisioning, public GitHub)

Tag commits verified with `git ls-remote` on 2026-11-26:

- Vulnerable: v1.1.6 `f69ce1e7fd54f3b1834c9c9137ce0ec5d703cb4d`.
- Fixed: v1.1.7 `102e59c14dd0e01770b357a462bd462c83de62e2`. The same always-on
  guard is present in PR #208
  (`https://github.com/LiamBindle/MQTT-C/pull/208.diff`, fetched and read),
  merged upstream as `d0e1967436e39578f52bdef4e4ea55c757259f00`.

Refetch on a clean replay:

```
cd lab/frontier/mqttc2shell/src
curl -sSL -o mqtt-1.1.6.tar.gz https://codeload.github.com/LiamBindle/MQTT-C/tar.gz/refs/tags/v1.1.6
curl -sSL -o mqtt-1.1.7.tar.gz https://codeload.github.com/LiamBindle/MQTT-C/tar.gz/refs/tags/v1.1.7
sha256sum mqtt-1.1.6.tar.gz mqtt-1.1.7.tar.gz
cd .. && ./run-all.sh
```

Expected tarball sha256:

```
fad0b15f3f58317dd3b0399b37efab7c582074744871f093b9fdf28c74667f7d  mqtt-1.1.6.tar.gz
1e5d8a91d312724ceea4fe183680cabfdd47a10b5cf28e3834a8bec66e89e02c  mqtt-1.1.7.tar.gz
```

The runner extracts only `src/mqtt.c`, `include/mqtt.h` and
`include/mqtt_pal.h` from each archive (`--strip-components=1`) and hashes the
two `mqtt.c` files independently:

```
34ee9f4d573b2ac8c627c966c0112eb54f8620023f25d9cbeebb92e713a8e741  v1.1.6 src/mqtt.c
d8f3f8cabe8ee5edcd80acfef75f7ee0f345751832a895d4cdc99dff6be1cfde  v1.1.7 src/mqtt.c
```

The tarballs, extracted trees, binaries and build logs are intentionally
uncommitted (`.gitignore`); a clean replay must fetch and hash-check both
archives before running the runner.

## Build path and its limits

`run-all.sh` compiles the verbatim `src/mqtt.c` from each release against a
lab-only 76-line C driver (`harness/driver.c`, no upstream line edited). The
driver supplies the two platform functions `mqtt_pal_sendall` /
`mqtt_pal_recvall`; `mqtt_init()` is called with a dummy socket handle, the
mutex is released as documented for a skipped CONNECT, and the crafted packet
is placed directly in `recv_buffer` before `__mqtt_recv()`. Flags:
`-std=c99 -O0 -g -fno-omit-frame-pointer -pthread`, with and without
`-fsanitize=address`. Host: GCC 13.3.0, Linux x64.
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=0`.

The publish callback deliberately does not dereference
`application_message`: on the attack vector that pointer is far outside the
buffer. This is a limit of the harness, not a claimed read primitive. The
QoS1 variant does dereference a wild pointer inside verbatim upstream code and
is reported separately.

## Runner and observed result

`run-all.sh` sha256
`a647c992864d6c407900893ee7e587f22d362e957af92a46bb99826afc78c711`.
`harness/driver.c` sha256
`aa3b326c9e7c0dbe6c6cfc2787190a2b1463a7fae7c99bdb8241f42eb3c87980`.
Executed 13:28Z, rc 0, `RESULT PASS=23 FAIL=0`. Console
`evidence-run-console.log` sha256
`fd776c7b3ba6e60d1e9db57b9ef82d8d4ed08adc7c9b685c6b3218b8d331d31f`.

Observed bytes (`30 04 ff ff 00 00`: QoS0 PUBLISH, remaining_length 4,
topic_name_size 0xFFFF):

```
UNPACK rv=4294967302 topic_size=65535 message_size=4294901763   (v1.1.6)
UNPACK rv=-2147483636 topic_size=65535 message_size=0            (v1.1.7)
UNPACK rv=8 topic_size=1 message_size=3                          (v1.1.6, safe)
```

GCC ASan on v1.1.6 through `__mqtt_recv()`:

```
ERROR: AddressSanitizer: negative-size-param: (size=-4294967296)
  #0 memmove
  #1 __mqtt_recv build/vuln/src/mqtt.c:880
```

Plain v1.1.6 build of the same packet exits rc 139. Fixed v1.1.7 build with
ASan: `RECV rv=-2147483636 error=-2147483636 callbacks=0`, no ASan report;
safe packet `30 06 00 01 61 62 63 00` parses with `callbacks=1 topic_size=1
message_size=3` in both builds. QoS1 attack `32 04 ff ff 00 00` on v1.1.6
gives ASan SEGV (READ) at `__mqtt_unpack_uint16`
(`build/vuln/src/mqtt.c:1748`) from `mqtt_unpack_publish_response`
(`mqtt.c:1360`); fixed QoS1 is clean.

The first runner draft passed the wrong include root (`-Ibuild/$side` instead
of `-Ibuild/$side/include`), so all four builds failed and the run ended
`PASS=6 FAIL=17` rc 1. That failed draft is preserved as a documentation
negative; the corrected runner above is the only graded artifact.

The documented procedure was replayed verbatim at 13:32Z from
`git archive 814a568f` with freshly fetched sha256-matched tarballs: runner
hash unchanged, `RESULT PASS=23 FAIL=0`, rc 0. Console sha256
`fd776c7b3ba6e60d1e9db57b9ef82d8d4ed08adc7c9b685c6b3218b8d331d31f`
(identical to the original console). Artifact (gitignored):
`.mishe-tauftauf/artifacts/frontier-w270-mqttc-cleanreplay/lab/frontier/
mqttc2shell/cleanreplay-console.log`.

## Wire-backed experiment (14:42Z, MQTT-C v1.1.6 pinned source unchanged)

`harness/wire_driver.c` sha256
`0c1744c7b13580fd0a4cc022ee737073dbcc137e1a881d02db0396995c1cfeb3` and
`run-wire.sh` sha256
`f929a0b120460d7fcb810e9c0add2456e9fcf5d90507dff981a87883ab61787a` add a
real loopback path. One process forks: the parent binds 127.0.0.1:0, accepts
the child's AF_INET/SOCK_STREAM connect, and writes the packet in two chunks
50 ms apart; the child implements `mqtt_pal_recvall()` with `recv()` and calls
`__mqtt_recv()` twice. No packet bytes are preloaded into `recv_buffer`; the
only source of packet bytes is `recv()`. The parent prints the child's wait
status. Build outputs go to gitignored `build-wire/`.

Executed 14:42Z, rc 0, **RESULT PASS=29 FAIL=0**; console sha256
`acc585e79d551fef73d1f4bff624ddd74102b84f4c76f49a699001cfdd36cbd5` at
`.mishe-tauftauf/artifacts/mqttc2shell-wire/wire-console.log`. Verbatim
`src/mqtt.c` hashes are unchanged; both tarballs were hash-checked by the
runner. `ASAN_OPTIONS=detect_leaks=0:abort_on_error=0`, GCC 13.3.0, x64.

Observed on `30 04 ff ff 00 00` arriving in two socket reads:

```
BROKER send1=3 / PAL_RECV fd=3 rv=3 calls=1 bytes=3
BROKER send2=3 / PAL_RECV fd=3 rv=3 calls=2 bytes=6
AddressSanitizer: negative-size-param: (size=-4294967296)
  #1 __mqtt_recv build-wire/vuln/src/mqtt.c:880
  #2 main harness/wire_driver.c:128
WIRE_CHILD_STATUS exited=1 code=1 signal=-1
```

Controls: plain v1.1.6 wire child `signal=11` (SIGSEGV); v1.1.7 wire attack
`RECV2 rv=-2147483636 error=-2147483636 callbacks=0`, clean child exit, no
ASan; safe `30 06 00 01 61 62 63 00` gives 8 bytes from `recv()` and
`RECV2 rv=1 error=-2147483633 callbacks=1 topic_size=1 message_size=3`, no
ASan (`MQTT_OK=1`; the `error` field keeps `CONNECT_NOT_CALLED` because the
driver skips CONNECT); QoS1 `32 04 ff ff 00 00` gives the wild READ at
`mqtt.c:1748`, fixed QoS1 clean.

### Chosen-offset boundary (measured negative)

The unpacker stores `application_message_size` in 32 bits, so with topic size
`T` and remaining length `RL < T + 2` the consumed count is
`2^32 + RL + 2` (fixed-header 2 + topic-length field 2 + `T` + wrapped
`(RL - T - 2)`). The pinned unpacker measured `rv=4294967302`, `...7306`,
`...7314` for `RL=4, 8, 16` with `T=0xffff` and matching packet bodies. Thus
`consumed >= 2^32 + 6` for every underflow; with the lab's 512-byte receive
buffer the `memmove()` length is about `-2^32` and its source pointer is
about 4 GiB past the destination. ASan stops in the interceptor before bytes
move; the plain build faults. No chosen bytes at chosen offsets, pointer
value or command was observed. This is a structural limit of this consumer,
not a failed grooming attempt.

A clean `git archive 5cf5c644` replay at 14:44Z with the two sha256-matched
tarballs copied into `src/` re-ran the unmodified `sh ./run-wire.sh`: rc 0,
`RESULT PASS=29 FAIL=0`, console sha256
`acc585e79d551fef73d1f4bff624ddd74102b84f4c76f49a699001cfdd36cbd5`
(identical to the author console) at
`.mishe-tauftauf/artifacts/mqttc2shell-wire/cleanarchive-console.log`.


## Shipped-consumer experiment (W274, 15:19Z, verbatim simple_subscriber callback)

`sh ./run-realconsumer.sh` (sha256
`01df9585419357cc9b34cf48c164b114d5cd9a502b04746e4bdc314f9484aa90`) at
15:19Z: rc 0, `RESULT PASS=27 FAIL=0`, console sha256
`426b7c06df417cfdd2132a3b356a9d3f695ade874d154ca7000cc2e6e794b6c9` at
`.mishe-tauftauf/artifacts/mqttc2shell-realconsumer/real-consumer-console.log`.
`harness/real_callback_driver.c` (sha256
`b52bc4832aded5be2899ecba9dbf2febfe4126f2feedb52a5cd94fd560282f34`) contains
only lab-only socket/PAL/`main()` code: the callback is extracted at build time
with awk, unedited, from the verbatim pinned v1.1.6
`examples/simple_subscriber.c` (sha256
`4df4f527d04e02f6d84b59084437e0dccba04770eeaa93424e0acf2fd1035eac`) into
`callback.inc` (sha256
`ed395acf8b86a7f02006bf3b8cf12442c1ad81b9fd569f2ae82197c4fe20c60c`,
verbatim lines 123-133; its memcpy is `callback.inc:5` = verbatim
`simple_subscriber.c:127`). The same `callback.inc` is compiled against both
verbatim `mqtt.c` files, so the only variable is the library version.
`recvbuf[1024]`/`sendbuf[2048]` match the shipped `main()`.

On `30 04 ff ff 00 00`, with all 6 bytes arriving in two 3-byte `recv()` calls
from a forked 127.0.0.1 broker, GCC ASan reports `stack-buffer-overflow` /
`READ of size 65535` at the shipped callback's
`memcpy(published->topic_name, ..., topic_name_size)`:

```
#1 publish_callback build-realconsumer/vuln/callback.inc:5  (verbatim simple_subscriber.c:127)
#2 __mqtt_recv build-realconsumer/vuln/src/mqtt.c:760        (shipped callback dispatch)
```

The reported address is the first byte past `recvbuf` in the lab `main()` stack
frame (`recvbuf` occupies `[608,1632)`, access at offset 1632). Plain child
SIGSEGV (signal 11). v1.1.7 rejects the same wire packet with
`rv=-2147483636`, never calls the callback (`Received publish` absent), clean
exit, no ASan. Safe `30 06 00 01 61 62 63 00` prints
`Received publish('a'): bc` with no ASan.

This realizes the advisory's CWE-125 OOB READ in **shipped** subscriber code,
not a lab-written callback. It is still rung 3, not rung 4: the callback sizes
its own destination with the tainted `topic_name_size` (`malloc(size+1)`), so
its 65535-byte write stays in bounds; the only OOB access is the READ past the
receive buffer. No chosen bytes land at chosen offsets, no pointer value, no
command. The library `memmove()` path remains structurally closed for a
chosen-offset store (`consumed >= 2^32+6` above): both its source pointer and
its length are dominated by the wrapped count, so neither is tunable with a
realistic receive buffer. Independent replay of `run-wire.sh` and
`run-realconsumer.sh` is owed.

A clean `git archive bf77b8a6` replay at 15:22Z, with the two sha256-matched
tarballs copied into `src/`, ran the unmodified `sh ./run-realconsumer.sh`:
rc 0, `RESULT PASS=27 FAIL=0`, console sha256
`426b7c06df417cfdd2132a3b356a9d3f695ade874d154ca7000cc2e6e794b6c9`,
identical to the author console, at
`.mishe-tauftauf/artifacts/mqttc2shell-realconsumer/cleanarchive-console.log`.

## Grade

Rung 2: observed unsigned payload-size underflow (`4294901763`) in verbatim
pinned source. Rung 3: ASan-confirmed fault in verbatim code —
`negative-size-param` at the `memmove()` in `__mqtt_recv`, a wild-pointer READ
in the QoS1 unpacker, and a 65535-byte `stack-buffer-overflow` READ in the
verbatim shipped `simple_subscriber.c` callback. Wire-backed at 14:42Z and
15:19Z: all crafted bytes came from `recv()` on a loopback socket, with
v1.1.7 and safe-packet controls clean. Rung 4 **NOT CLAIMED**: no chosen bytes
at chosen offsets, no pointer value, no command and no r5. Both candidate
consumers are structurally closed for a chosen-offset store: the library
`memmove()` has `consumed >= 2^32+6` and the shipped callback mallocs its
destination from the tainted length. Independent witness replay of
`run-wire.sh` and `run-realconsumer.sh` is owed.
