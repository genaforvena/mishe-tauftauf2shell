# Frontier brief — imgproxy ICO `data_size` wrap (Imgproxy2Shell)

**Status: ADMITTED (operator commit `5008efe`, tape #809/#810; charters and
wake units minted, tape #812) and witness verdict ESTABLISHED AS CLAIMED with
no grade change (tape #813/#814, 2026-11-21 11:01Z).** Rungs 1/2/3 are
ESTABLISHED in an extracted, verbatim-pin harness; rung 4 is ESTABLISHED AS
INSTRUMENTED chosen bytes at a chosen offset. Both artifacts exist: this brief
and the inner-socket `imgproxy2shell` window. Wake units and the presentation
entry remain the person's full-flag sync. The CVE's RCE prose stays a claim;
the lab demonstrates chosen bytes only.
**Witness W185 (2026-11-24, tape #3318):** ICO harness rungs 1-4 ESTABLISHED on
clean replay; the then-available HTTP consumer probes were graded only at the
header/processing-entry scope, with the fine.tif stall attribution
CONTRADICTED and corrected below. No r5 anywhere.
**Witness closure #3407 (2026-11-24):** the W2 repair at `24221c9` was verified
against W185; W1/W2 are CLOSED, not reopened.
**W3/W4 (2026-11-24, this lab, witness replay pending):** a real loopback HTTP
GET into a real imgproxy 4.0.0 process reproduces the wrapped-size abort with
an ICO-fixed control (W3), and gdb in that live process captures the C
write-site frame and reads back 32 attacker-chosen bytes at `data+14` (W4).
The consumer limb therefore reaches rung 4 at the chosen-byte/chosen-offset
scope. Pointer/IP control, marker execution, remote command and rung 5 stay
UNKNOWN.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-123614 / GHSA-hff9-5pqw-6w9f, published 2026-11-08,
  CNA GitHub. CWE-122, CVSS 4.0 **9.3 Critical**
  `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CVSS 3.1 9.8.
  Claim: a remote attacker submits a crafted ICO image whose `data_size`
  wraps the allocation in `vips/icoload.c`, corrupting heap memory to crash
  the process or achieve code execution. RCE is claimed by the CVE prose, not
  demonstrated here.
- **Affected/fixed**: `pkg:golang/github.com/imgproxy/imgproxy/v4` from 4.0.0
  before 4.0.16; 4.0.16 is the fixed version. imgproxy is an HTTP image
  processing service; the crafted image is supplied through its normal
  unauthenticated request path (CVSS `PR:N/UI:N`).
- **Fix**: commit `a821b6a4cb07a1bf2bb9077431d1c1e734d79917` (2026-09-24,
  "Fix segfaults during invalid ICO load"), which adds a 10 MiB bound on
  `data_size`, computes `full_data_size` after that guard, and adds three
  regression ICO files plus Go tests.
- **Sources read**: CVE Program JSON, GitHub security advisory, fix patch, and
  raw `vips/icoload.c` at tags `v4.0.15` (affected) and `v4.0.16` (fixed).
  URLs and SHA-256 digests are in `lab/frontier/imgproxy2shell/PROVENANCE.md`.
  Read-only provisioning only; **no probe, listener or traffic to any
  non-loopback system**.
- **Scope separation**: distinct from every owned X2Shell target and from
  GpfD2Shell, Kermit2Shell, Dcmtk2Shell and Gct2Shell. A Go HTTP image server
  with a C/libvips loader: stronger claim class (unauthenticated HTTP,
  confidentiality/integrity impact scored) than the availability-only
  advisories behind several earlier finds.
- **Ranking**: highest tractability of the current queue. One unchecked
  `uint32_t` addition, one small fix, and a write through a `read_full` call
  into a buffer 11 bytes past a 3-byte allocation. No full build needed for
  the pinned statements.

## Source-bound mechanism (read from both pinned tags)

Line numbers are from `v4.0.15` unless marked fixed.

1. `icoload.c:154` — `uint32_t data_size` comes from the largest ICO directory
   entry's `data_size`, read from the uploaded file with `GUINT32_FROM_LE`.
2. `:158` — `VIPS_MALLOC(NULL, data_size + BMP_FILE_HEADER_LEN)` performs
   `uint32_t` arithmetic; `data_size = 0xfffffff5` plus 14 wraps to 3.
3. `:159` — `actual_data = data + 14`, so the destination begins 11 bytes
   past that 3-byte allocation.
4. `:161` — `vips_foreign_load_read_full(ico->source, actual_data, data_size)`
   writes the attacker's ICO payload into `actual_data`. A short source can
   still copy the bytes it has; the function returns a positive count, so the
   error branch at `:162-164` is not taken and the loader continues with the
   corrupted buffer.
5. Fixed `v4.0.16:165-168` rejects `data_size > 10 * 1024 * 1024` before the
   addition; `:172-173` allocate `full_data_size` and check the allocation.

The CVE's code-execution claim is an advisory claim only; this lab claims no
execution.

## Consumer-reality check

The write is a `memcpy` performed by a stand-in for `vips_foreign_load_read_full`
compiled from the pinned call site, not a libc routine whose dispatch depends
on the host. Exact-size `malloc` under ASan detects the first past-end store;
a 1 MiB mmap collaborator places the 3-byte allocation at a known offset so
chosen body bytes can be read back; an `mprotect` guard page turns the first
past-end store into a fault. Real libvips source/read behaviour, the Go/cgo
callback boundary and the live glibc chunk header are now measured in W3/W4
below; what remains UNKNOWN is control of a live pointer or return address,
not the reachability of the write.

## Local harness evidence (10 PASS / 0 FAIL, replayed)

Harness `lab/frontier/imgproxy2shell/{gen_driver.py,run.sh}` plus
`PROVENANCE.md`, `.gitignore` and five pinned `src/` artifacts.
`gen_driver.py` verifies every pin and copies the affected statements
(`:154-164`) and fixed statements (`:162-185`) verbatim under `#line`; the
generator aborts on drift. From committed HEAD,
`bash lab/frontier/imgproxy2shell/run.sh <outdir>` prints **10 PASS / 0 FAIL**,
`ALL CHECKS PASS rc 0`, with two five-run groups at
`sha256=6b0391599520bc899f169268e08699155888f0018274f9c2a2e12bcd31c2dad5`.

- **Rung 1 (reproducible trigger)**: `data_size = 0xfffffff5` → `alloc=3`
  despite a declared ~4 GiB payload.
- **Rung 2 (observed state failure)**: in the collaborator, 32 chosen bytes
  are read back at `data+14`, 11 bytes past the 3-byte allocation.
- **Rung 3 (ASan-confirmed corruption)**: exact 3-byte allocation gives
  `heap-buffer-overflow`, `WRITE of size 32`, frame pinned at
  `icoload_v4.0.15:161`.
- **Rung 4 (instrumented chosen-value control)**: seed `0x5a` reads back
  byte-exact as `5a5b5c5d…` at `data+14`; a `PROT_NONE` guard page faults on
  the first past-end store; the fixed commit rejects the hostile size before
  allocation and is ASan-clean on hostile and benign inputs.
- **Determinism**: two independent five-run groups hash identically; ASan
  PID/address/path text is excluded from the digest.

The same result was replayed from a clean `git archive HEAD` extraction at
commit `2366ef4`: 10 PASS / 0 FAIL, rc 0, identical trace digest.

**Grade**: rungs 1/2/3 ESTABLISHED in the extracted harness; rung 4 is
INSTRUMENTED chosen-byte control at a chosen offset, not a live imgproxy
demonstration. No HTTP request, libvips process, stock neighbour, pointer
control or execution claim. Witness W185 (2026-11-24) replayed this claim and
graded rungs 1-4 ESTABLISHED with no grade change; see below.

## Consumer-limb HTTP probes (W1/W2, 2026-11-24)

A real imgproxy 4.0.0 CLI built against pinned libvips 8.18.2 and the fixed
tree was driven over loopback-only HTTP with crafted many-band TIFFs. Safe
control 200 in both builds. Vulnerable: many-band requests reach real
processing and reject at `vips.(*Image).Flatten` for default JPEG output;
`f:tiff` requests with many-band/tiff9999 fixtures stall under this 2 GiB
cgroup (the witness isolated a tiff9999 timeout). Fixed: crafted requests 500
at `vips.(*Image).Load ... image: dimension overflow` in <2 ms. No scanline
decode, paint frame, chosen byte, pointer or marker was observed.

W2 attempted libvips2shell's fine geometry (89478485x2, 12 bands, 32-bit)
over the same route. Its five-case vulnerable log has only three `Started`
lines, so the later `fine_tiff`/`tiff9999_tiff` timeouts with WORKERS=1 are
queue starvation. An isolated fresh-process GET returns HTTP 422 "Source
image resolution is too big" in the vulnerable build (imgproxy's 50M-pixel
guard) and HTTP 500 "image: dimension overflow" in the fixed build. W2's
earlier 8.59 GB fine.tif decode-stall attribution is withdrawn. Grade
unchanged: rung 4 at header/processing entry in a live process; rung 5
UNKNOWN. Full evidence, digests and the W185 verdict are in
`lab/frontier/imgproxy2shell/PROVENANCE.md` sections W1/W2.

### W3 — the ICO primitive in a live imgproxy process

imgproxy vendors `vips/icoload.c` inside its CGO package; the copy in the
built 4.0.0 tree is byte-identical to the pinned affected v4.0.15 loader, and
its symbols are present in the real CLI. A 54-byte ICO with
`data_size=0xfffffff5` and 32 chosen body bytes, served from 127.0.0.1 and
requested through `/insecure/rs:fill:16:16/plain/hostile.ico`, killed three
fresh imgproxy processes in 19-72 ms (`rc=2`). Each log records
`malloc(): corrupted top size` / `SIGABRT` during cgo execution, with
`vips.(*Image).Load` at `vips/vips.go:293` and
`processing.(*Processor).initialLoadImage` at `processing.go:161`. A valid
favicon ICO returned HTTP 200 on the same binary. A control built with only
`vips/icoload.c` replaced by the pinned v4.0.16 loader returned HTTP 500 with
`vips_foreign_load_ico_header: ICO image data is too large` and stayed alive.
This upgrades the consumer limb from header/entry to a real-process crash
and allocator-detected heap corruption. W4 below adds the live chosen-byte
readback and the symbolised C write site; pointer control and rung 5 remain
UNKNOWN. See PROVENANCE section W3.

### W4 — live chosen-byte readback at the C write site (2026-11-24, unwitnessed)

`provision/ico_gdb_readback.py` serves the same 54-byte hostile ICO on
127.0.0.1:18081, launches the unmodified `imgproxy-vuln` CLI under gdb on
127.0.0.1:18080 against libvips 8.18.2 from `build-vuln-plain/libvips`, sends
one unauthenticated GET, and breaks conditionally on
`vips_foreign_load_read_full` with `len == 0xfffffff5`. Raw output:
`provision/http-ico-vuln-gdb-readback.log`.

Observed in that live process (addresses are ASLR-dependent):

- Breakpoint hit at `vips.c:1304` with `len@entry=4294967285`, called from
  `vips_foreign_load_ico_header` at `icoload.c:161`. Frames 0-10 run
  `icoload.c:161` -> libvips `foreign.c:1154` -> `vips_icoload_source_go`
  (`icoload.c:501`) -> `_cgo_...Cfunc_vips_icoload_source_go` ->
  `runtime.asmcgocall` -> the HTTP handler: the C write site is symbolised in
  the real imgproxy process, not only in the harness.
- `buf = actual_data = 0x...7be`; `data = actual_data - 14 = 0x...7b0`.
  `read_full` returns 0 (source EOF after 32 bytes); a 48-byte dump at
  `actual_data` begins `5a 5b 5c 5d` four times (32 chosen bytes), then zeros.
- The malloc chunk size field at `data-8` reads `0x25` = 0x20 (a 32-byte chunk)
  plus `PREV_INUSE|NON_MAIN_ARENA` (non-main arena because the cgo call runs on
  a worker thread). A 3-byte `g_malloc0` request has 24 usable bytes, so a
  32-byte write starting at offset +14 runs 22 bytes past usable space into
  the next chunk. That is the concrete live layout glibc later reports as
  `malloc(): corrupted top size` in W3.
- Control: the same breakpoint and request against the ICO-fixed binary
  (`http-ico-icofixed-gdb-control.log`) produced HTTP 500
  `ICO image data is too large`, **no breakpoint hit**, process alive: the
  fixed loader rejects the size before allocating or calling `read_full`.

Grade: the consumer limb now has rung-4 evidence — attacker-chosen bytes at a
chosen offset in a real imgproxy process reached over unauthenticated loopback
HTTP, at the symbolised C write site. This is not rung 5: the overwritten
object is heap metadata / the next chunk, not a function pointer or return
address, and no marker execution or remote command was observed. The harness
grade (rungs 1-4, witness W185) is unchanged; W3/W4 await witness replay.

## Cheapest next experiment to move a rung

The live write site and chosen-byte placement are measured. A pointer or
marker claim would need the 32-byte write to land on a live code pointer;
the measured layout puts it on the next chunk's header/data, so that path is
likely blocked and must be disproved before any r5 work. No external target
is ever contacted.

## What would change my mind

A primary source showing the addition happens in 64-bit arithmetic, a replay
losing ASan or chosen-byte readback, evidence that the endpoint requires
authentication, or a measured live layout that puts every reachable write in
unmapped memory would all lower the grade.
