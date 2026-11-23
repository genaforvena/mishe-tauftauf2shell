# W171 — synthetic loopback wire-input lane and live-victim readback

**Grade: rung 3+4 mechanics only. Rung 5 remains UNKNOWN.** The consumer here
is one we wrote for the lab. Its socket is a loopback input to a synthetic
host, not a real libmt32emu service, and the overwritten object is a
host-side sentinel with a pointer-shaped field, not a library object whose
later use was steered. No command, marker side effect, valid post-overwrite
pointer or witness verdict at this rung exists.

## What changed against W170

W170 fed chosen bytes with a direct call. W171 adds two measured properties
on the same pinned real-library static builds (`build/vuln-2_8_3-*`,
`build/fixed-1749f7f-*`, no rebuild):

1. The bytes arrive over a one-shot 127.0.0.1 TCP connection
   (`wire_client.py`), are read until EOF, and are passed in **one**
   `DefaultMidiStreamParser::parseStream()` call (`wire_driver.cpp:163-164`).
   This is the single large call W168 identified as necessary.
2. In the plain consumer only, `operator new[]` places the library's
   32768-byte `streamBuffer` at the start of a 1 MiB anonymous mmap arena and
   constructs a live `Victim` object immediately after it (offset 32768).
   An initial snapshot is copied at construction and printed after the call
   together with the post-call object, so the overwrite is observed in an
   object that existed during the call and was read before destruction.
   The mmap arena avoids glibc metadata; the arena is intentionally not
   freed. All other allocations use `malloc` normally. ASan consumers leave
   the real allocator in place and report the fault.

The object fields are `prefix[8]` (`0x11`), a `uintptr_t ptr` initially
pointing to a valid 64-byte host buffer, `magic=0xcafebabe`, and
`suffix[8]` (`0x22`). The 7-bit attack tail (W170 alphabet) overwrites all
of them with `0x6a`. `initial_victim` is the snapshot taken before the
library returns from its allocation; `after_victim` is the live object.

## Payloads

| kind | bytes | shape |
| --- | --- | --- |
| `attack` | 40001 | `0xF0` + 40000 `0x6A`, unterminated |
| `safe` | 1000 | `0xF0` + 998 `0x6A` + `0xF7`, short and terminated |
| `safe-fit` | 32768 | `0xF0` + 32767 `0x6A`, unterminated; grows the buffer but copies exactly 32768 bytes |

## Observed cases (`evidence/wire-results.txt`, 8/8)
| case | rc | observation |
| --- | --- | --- |
| `vuln-plain-attack` | 0 | `initial_victim prefix=1111 ptr=0x<valid> magic=0xcafebabe suffix=2222`; `after_victim prefix=6a6a ptr=0x6a6a6a6a6a6a6a6a magic=0x6a6a6a6a suffix=6a6a` |
| `vuln-plain-safe` | 0 | short terminated SysEx dispatched; no 32768 allocation, so no victim is created |
| `vuln-plain-safe-fit` | 0 | victim exists; initial and after values are byte-identical (pointer, magic, prefix, suffix) |
| `fixed-plain-attack` | 0 | pinned fix clamps the copy; no victim and no dispatch |
| `vuln-asan-attack` | 1 | ASan `WRITE of size 40001`, 0 bytes after the 32768-byte region, at `MidiStreamParser.cpp:250` from `parseStream` `:106` |
| `vuln-asan-safe` | 0 | short terminated input clean |
| `fixed-asan-attack` | 0 | pinned fix clean under ASan |
| `fixed-plain-safe-fit` | 0 | pinned fix clean, no victim |

Quoted raw lines from `evidence/wire-server-vuln-plain-attack.out`:

```
wire_bytes=40001 first=f0 last=6a
parse sysex=0 lastlen=0 short=0 realtime=0 debug=0
initial_victim prefix=1111 ptr=0x000059b5061af5e0 magic=0xcafebabe suffix=2222
after_victim prefix=6a6a ptr=0x6a6a6a6a6a6a6a6a magic=0x6a6a6a6a suffix=6a6a
```

The pointer address is ASLR-dependent; only its replacement by wire-derived
`0x6a` bytes is the invariant. Under ASan the same wire block reaches the
same real allocation and copy:

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 40001 at 0x... thread T0
    #2 ... MidiStreamParserImpl::parseSysex ... MidiStreamParser.cpp:250
    #3 ... MidiStreamParserImpl::parseStream ... MidiStreamParser.cpp:106
0x... is located 0 bytes after 32768-byte region
```

## Failed first shape (preserved)

The first plain build carved the victim from `malloc(n + sizeof(Victim) +
64)` instead of an mmap arena. The 7233-byte tail ran past that chunk into
glibc metadata and the process aborted with `double free or corruption
(!prev)` (rc 134) before a clean return. That was a harness artifact, not a
library result; the mmap arena keeps the overflow inside mapped memory and
yields the rc 0 readback above. The abort was observed, not assumed.

## Replay and normalization

```
cd lab/frontier/munt2shell/real
sh wire_probe.sh
sh normalize_wire.sh | sha256sum
```

Two consecutive full replays produced the same normalized digest
`857c13a634fb8c53f1347ae1b51d70e53bf58073d75beace897bd8133da03a65`.
`normalize_wire.sh` removes ephemeral TCP ports, ASan PIDs/ASLR addresses,
the absolute checkout prefix, ELF build IDs and the victim's ASLR pointer,
while keeping the intact magic and the `0x6a` overwrite fields comparable.
Raw evidence is in `evidence/wire-*`.

A clean-archive replay from commit b80ccf1 (`git archive HEAD
lab/frontier/munt2shell` into `/tmp/w171-munt`, pinned tarball copied into the
ignored `real/src/`, then `prepare_src.sh`, `build_and_run.sh` and
`wire_probe.sh`) rebuilt both pinned static-library variants and matched all
8 rc cases plus the same normalized digest. The build ID differs between
checkouts, so `normalize_wire.sh` also folds ELF build IDs. The `/tmp` copy
was not retained; committed sources, pins, scripts and evidence are the
durable record.

## What this does not establish

No real network-facing host, no real MIDI device/file path, no library
object consumed after the overwrite, no valid pointer target, no branch or
command selected by the overwritten bytes, and no independent witness
verdict at this rung. A real consumer that can supply one >32768-byte
SysEx in a single `parseStream()` call is still missing; all in-tree hosts
remain closed by their own limits (§7, §8 of the report). Do not relabel the
wire-derived live-object overwrite as remote command execution.
