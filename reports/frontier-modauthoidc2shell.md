# Frontier brief: mod_auth_openidc — CVE-2026-54789 (modauthoidc2shell)

**STAGED 2026-11-23 W139, admitted 06:2xZ; W147 direct-call verdict
ESTABLISHED; W170 independently ESTABLISHED W6/W8-W11/W13/W14 at their labeled
live-wire and harness scopes (16:58Z), no grade change, NOT rung 5.**
Prepared in W138 from public advisory and upstream fix pins; the harness,
measurements and handoff were added in W139.
Pins are byte-exact and hash-verified; full raw evidence is in
`lab/frontier/modauthoidc2shell/PROVENANCE.md`. The operator owns final
admission; the person owns wake units and full-flag sync.

## 1. Verified ground truth

- Claim: an unauthenticated client can send a Cookie token beginning with the
  state-cookie prefix (`mod_auth_openidc_state_` by default) but without `=`.
  `oidc_state_cookies_parse_token()` scans for `=` without checking the string
  terminator, reads past the token into adjacent memory and, if it finds `=`,
  writes a NUL there — out-of-bounds read and a one-byte write. GHSA advisory
  titled "Out-of-bounds read and write in state cookie parsing", HIGH 7.5,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, CWE-125 + CWE-787; affected
  `< 2.4.19.4`, patched `>= 2.4.19.4`.
- Sources: <https://github.com/OpenIDC/mod_auth_openidc/security/advisories/GHSA-vgr5-qcpp-x2pr>,
  <https://www.cve.org/CVERecord?id=CVE-2026-54789>,
  <https://osv.dev/vulnerability/CVE-2026-54789>,
  fix commit <https://github.com/OpenIDC/mod_auth_openidc/commit/8017478471cc071c49aa073c5c9be652a73a8630>.
- Fix: commit `8017478471cc` (2026-06-09, Hans Zandbelt), 3 files +22/-1, adds a
  `test_state_cookies_clean_no_value` unit test. Released in tag `v2.4.19.4`
  (release commit `cd1534e5`, 2026-07-01); `v2.4.19.3` still has the bad loop.
- Pins in `lab/frontier/modauthoidc2shell/src/` (SHA-256 manifest `SHA256SUMS`):
  - `state.c.4301b536` — parent of the fix, git blob
    `0122cde76014f077d349489eb6fca9273de6e45a`, sha256
    `ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa`;
  - `state.c.8017478` — fix-commit blob
    `92bd078a3a4a079b6d4ee8f904b08e10473c16ec`, sha256
    `3492207546885aae00363de14b30947ce73c48b8361b33516d95fc6df774c1cc`;
  - `state.c.v2.4.19.4` — released fixed tag, git blob
    `13009c17da25d008d6d245a5133f8dd4158716e2`, sha256
    `f02d8ddb60927b9da1402c6430d179e4418ff6751ecda6c78db34424ccf77ce5`;
  - `fix-8017478.patch`, sha256
    `d8ae4b4e8cda366a985368bd885591d2aaa702b463d989b140a9621a226b3e38`.
  All blob ids were checked with `git hash-object` after download.

## 2. Source-bound mechanism and fix

Read from the pinned parent blob. `oidc_state_cookies_parse_token()` at
`state.c.4301b536:204-222`:

- Line 210 gates on the state-cookie prefix, which an unauthenticated client
  can supply verbatim.
- Lines 214-215 are the bug:
  `while (cookie != NULL && *cookie != OIDC_CHAR_EQUAL) cookie++;`.
  `cookie` is only incremented, never reassigned to NULL, so the NULL test is
  dead and the only exit is finding `=` beyond the token.
- Line 219 then stores `*cookie = '\0';` at that out-of-bounds offset.
- The token comes from `oidc_state_cookies_clean_expired()` at lines 230-244:
  `apr_pstrdup(r->pool, oidc_http_hdr_in_cookie_get(r))` followed by
  `apr_strtok(cookies, ";")`. Pre-auth callers are
  `src/handle/request.c:132` (new auth flow) and
  `src/handle/response.c:353` (redirect callback).

The fix changes the loop to
`while ((*cookie != '\0') && (*cookie != OIDC_CHAR_EQUAL))`; the following
`if (*cookie != OIDC_CHAR_EQUAL) return 0;` then rejects a value-less token.
The same bound is present at line 217 of both the fix-commit blob and the
released `v2.4.19.4` blob; the bad loop is present at line 214 of the parent.

## 3. Cheapest local experiment

Mirror `lab/frontier/mongoose2shell/harness/`: re-extract
`oidc_state_cookies_parse_token()` verbatim from the parent and both fixed
blobs on every run, check a SHA-256 manifest, stub the request/config types,
`_oidc_strstr` and the cookie-processing recorder, and allocate the token as
an exact-size heap object. A token `mod_auth_openidc_state_novalue` with no
`=` should give gcc and clang ASan `READ of size 1` in the sliced loop and a
NUL store at an adjacent offset; the fixed slices must return 0 cleanly and a
well-formed `mod_auth_openidc_state_abc=1` must be clean in all variants.
That would establish rungs 1-3 and possibly a scoped rung 4 (one NUL byte, not
chosen data). No Apache, APR pool or network is needed for the first step.

## 4. Rung-4 feasibility and risks

- Ranked ahead of remaining candidates because it has a public advisory, a
  real fix commit, a released fixed version and pre-auth reachability verified
  in two source callers.
- Ceiling risk: the primitive is a blind scan plus a single NUL byte; CVSS says
  `I:N/A:H`, so pointer control, chosen-byte control and rung 5 are doubtful.
  Controllability of the byte that terminates the scan in a real APR pool is
  UNKNOWN and must not be assumed.
- A full-module ASan build may not flag the source object because
  `apr_pstrdup()` allocates from an APR pool arena, not a per-object
  malloc redzone [INFERENCE from source, untested]. The verbatim-slice harness
  is therefore the first measurement; a real-daemon attempt comes only after
  the slice works.
- NVD status is `Deferred`; distro/RHSA references were not read and remain
  UNKNOWN. At provisioning time no duplicate brief, charter, window or owning
  mind existed; W139 then created the charter, seed wall and target window.


## 5. W139 local result — staged, rung 4 scoped

`lab/frontier/modauthoidc2shell/harness/run.sh` re-extracts the record struct
and the entire `oidc_state_cookies_parse_token()` verbatim from all three
pinned blobs on every run, checks two SHA-256 manifests (12 files, including
the driver and runner), and builds plain and ASan variants for the vulnerable
parent, the fix commit and the released tag. It reports **59 PASS / 0 FAIL**
on three consecutive runs, a clean-directory replay and a clean `git archive
HEAD` replay after handoff commit `05acfc6`, all with
`TRACE_SHA256=bbda75f0cf7e4e1789b75bd206922f7ccbbb0c24b676e8b92fb833af4c448459`
(raw logs in `harness/evidence/`).

- Rung 1: valueless state-prefixed token, dead `cookie != NULL` test, NUL at
  logical index 30, predicted write offset 47; no vulnerable call.
- Rung 2: the vulnerable slice scans past the token, overwrites an adjacent
  `=` and dispatches `PROCESS_CALLS=1`; both fixed slices return `RC=0` with
  no dispatch and leave the `=` byte intact.
- Rung 3: gcc and clang ASan `READ of size 1`, 0 bytes past a 31-byte exact-size
  token, in the verbatim slice at pinned `state.c.4301b536:214`.
- Rung 4 (scoped): the one-byte NUL store lands at chosen offsets 31, 47 and
  63 in the plain-build block, with an intact canary. The byte value is not
  chosen; only its location is. No ASan WRITE is observable because the read
  faults first.
- Controls: fix-commit and released `v2.4.19.4` slices ASan-clean; well-formed
  `mod_auth_openidc_state_abc=1` clean on all six binaries.

Ceiling: no Apache/APR pool, request object, listener, socket or wire; scanner
called directly with stubbed config and a recorder for the downstream cookie
processor. The exact-size heap token is an instrument; a real APR arena has no
per-object redzone [INFERENCE, untested]. No pointer control or chosen command.
W147 independently replayed the lane: rungs 1–3 and scoped rung 4 ESTABLISHED at
the direct-call scope, no repair owed; no rung 5. Rung 5 must not be inferred
from this.

No external system was probed; all URLs above were read for provisioning only.

## 6. Full-module ASan loopback result (2026-11-23 W6)

The full parent module was provisioned and built with ASan against the local
ASan APR/httpd stack, with jansson and cjose provisioned under `lab/`. A
released `v2.4.19.4` module is the control; both bind only `127.0.0.1:18090`.
The caller is source-bound and live: an unauthenticated GET of `/protected`
reaches `oidc_check_user_id` → `oidc_handle_unauthenticated_user` →
`oidc_request_authorization_set_cookie` (`handle/request.c:132`) →
`oidc_state_cookies_clean_expired` → `oidc_state_cookies_parse_token` before
authentication. `cd lab/frontier/modauthoidc2shell/full && bash run.sh`:
parent 30/30 ASan `READ of size 1` faults at pinned `state.c:214` with a full
native stack through `ap_run_check_user_id` and 30/30 empty replies; fixed tag
0/30 reports and 30/30 HTTP 302. An earlier layout-dependent run gave 7/30
faults and 23/30 OOB dispatches of the value-less cookie name. The overflowed
8192-byte region is a real APR arena. Evidence and limits:
`lab/frontier/modauthoidc2shell/full/evidence/README.md`.

This confirms rung 3 on a real pre-auth wire path; at this point rung 4 stayed
scoped to the direct-call harness (ASan faults before the NUL store; byte value
always NUL, offset chosen by adjacent memory, no pointer control or command).
Section 7 later reached the store on the same wire path. This probe is
unwitnessed; W147's verdict covers the earlier harness only.

## 7. Wire-chosen NUL store (2026-11-23 W8)

The full-module probe now reaches the store itself. With
`Cookie: mod_auth_openidc_state_novalue;<name>=<value>`, `apr_strtok` leaves
the second cookie's `=` after the value-less token's NUL in the copied header,
so the pinned scan finds it in bounds and line 219 writes NUL there. gdb on
the live child read `0x3d` before and `0x00` after the store at pinned
`:219`, with the full pre-auth stack; arena dumps put the store at token
offset `30 + 1 + len(<name>)` — 39 for eight `z` bytes, 63 for 32
(`full/evidence/store/gdb-dump*.txt`). Five wire lengths all returned 302;
the parent dispatched `oidc_state_cookies_process_one` with the second
cookie's value 5/5, the released tag 0/5. `halt_on_error=0` did not continue
past the value-only READ fault (negative preserved).

Rung 4 is therefore also observed on a live pre-auth wire path with a
wire-chosen offset, still unwitnessed at that scope. No chosen byte value, no
pointer-bearing target, command or rung 5. Replay: `cd
lab/frontier/modauthoidc2shell/full && bash probe-store.sh && bash probe-gdb.sh`;
evidence and limits in `full/evidence/store/README.md`.

## 8. Pointer-bearing OOB store in the plain full module (2026-11-23 W9)

The earlier "no pointer-bearing target" line applies to W8's **in-bounds** header-copy store.
A `build-plain.sh` build of the same pinned module (labelled "plain"; see the
W14 build-stack correction at the end of this section)
(`full/build-plain.sh`, module sha256
`008990618887dde66e4371d1a354c64dccf29c40d36d17c4ac1d8e5f8b375654`,
plain httpd 2.4.70 / APR, 127.0.0.1:18090) allows the **out-of-bounds** scan
to reach its store. With a value-less state cookie, gdb at pinned `state.c:219`
on the live pre-auth stack measured the store at `0x7ffff6de2221`: the byte
`0x3d` is the low byte of pointer `0x7ffff5603d`; after the store the byte is
`0x00` and the pointer `0x7ffff56000`. The target is zeroed OIDC shared-memory
data; a hardware watchpoint caught no consumer read, and non-gdb value-less
and well-formed requests both return 302. The real-object harness reproduces
the same pointer-low-byte shape stably across six pool fills.

Grade unchanged: rung 4 scoped, now with a pointer-bearing target on a live
pre-auth wire path, still unwitnessed at that scope. Byte always NUL, target
not wire-chosen, no consumer effect, chosen byte, command or rung 5;
gdb disables ASLR, so addresses are lab-layout facts. Replay: `cd
lab/frontier/modauthoidc2shell/full && bash build-plain.sh &&
bash probe-plain-oob.sh && bash probe-plain-detail.sh`; raw evidence and
limits `full/evidence/plain-oob/README.md`.

### W10 consumer check (2026-11-23)

`full/probe-plain-keepalive.sh` arms a hardware watchpoint on the corrupted
word after the store, deletes the source breakpoint, and sends three requests
on the **same TCP connection** so no new accept can clear the word. It
measured the same store (`0x7ffff6de2221`, `0x7ffff5603d` → `0x7ffff56000`),
got three HTTP 302 replies, and recorded no watchpoint hit or watch-stop
backtrace within 70 seconds. A one-off `LD_PRELOAD` allocation tracer also
found no traced APR allocation covering the word (nearest starts 0x6f bytes
later), with the caveat that intra-libapr calls bypass interposition.

Both are negative results. The word is connection-pool state with no observed
consumer in the same request or two later requests on that connection; the
"pointer-bearing" wording describes the 8-byte shape at the store, not a
demonstrated dereference. Grade stays rung 4 scoped, byte always NUL, target
not wire-chosen, no chosen byte, command or rung 5. Raw:
`full/evidence/plain-oob/keepalive/` and `alloc-trace/`.

### W11 second caller: callback path (2026-11-23)

With `<Location /redirect_uri>` enabled in the lab config, an unauthenticated
`GET /redirect_uri?code=foo&state=foo` plus a value-less state cookie reaches
the other source caller: `handle/response.c:353` →
`oidc_state_cookies_clean_expired` → pinned `:219`. `full/probe-plain-response.sh`
measured the store at `0x7ffff6ddc05e`: the eight bytes `=foo&sta` are the
wire-chosen `=` of `code=foo` in the copied request line, becoming
`\0foo&sta` after the store. The request returned HTTP 400; the module
dispatched the adjacent request-line text to
`oidc_state_cookies_process_one`, whose JWE decode failed and deleted the
value-less cookie. A watchpoint on the corrupted word saw no consumer
read/write.

This reaches the second pre-auth caller and places the NUL in wire-chosen
adjacent request-line data, not a pointer field or pool slack. Grade remains
rung 4 scoped, unwitnessed at live-wire scope: byte always NUL, no dereference
of the corrupted word, chosen byte, pointer control, command or rung 5. Raw:
`full/evidence/plain-oob/response/`.

### W12 long value-less token: intermittent fault (2026-11-23)

On the live pre-auth wire path, a bare 7800-byte state token intermittently
faulted the plain-module child (`AH00051` SIGSEGV 11) in two of three extended
sweeps and in none of a fresh-server 30-request sweep. A SIGSEGV-backtrace
shim with libasan preloaded attributed the fault to pinned `state.c:219` in
`oidc_state_cookies_parse_token` (60/60 faults), while the same-length
well-formed token and released `v2.4.19.4` under the same shim were clean
(10/10 each). The shim changes signal handling and allocation layout, and
gdb runs reproduced no fault, so this is frame attribution, not a
deterministic native crash claim. Grade unchanged: rung 3 on the live
pre-auth wire path, rung 4 scoped and unwitnessed there; byte always NUL, no
chosen byte, pointer control, command or rung 5. Raw and replay:
`full/evidence/plain-crash/README.md`.


### W13 native child SIGSEGV, bimodal per server start (2026-11-23)

The child fault is now reproduced **natively**: pinned plain module, no shim,
no `LD_PRELOAD`, no ptrace. Starting the plain httpd/APR stack with
`ASAN_OPTIONS=detect_leaks=0` makes the crash state depend on the master start,
not on the individual request. Six fresh identical starts gave 12/12 HTTP
302 with zero faults, then four starts with 0/12 HTTP 302 and 11 `AH00051`
SIGSEGV children each, then 12/12 clean. A 60-request A/B run gave 60/60 clean
with default `ASAN_OPTIONS` and 59/60 crashing children with
`detect_leaks=0`; an earlier 240-request run in the crashing state logged 240
faults. The first A/B crash follows the logged 7800-`a` value-less Cookie by
0.98 s on the live pre-auth path.

Controls in the same env over four fresh starts each: well-formed 7800-byte
token on the vulnerable module and value-less 7800-byte token on released
`v2.4.19.4` each gave 8/8 HTTP 302 and zero faults in every start. strace
(54 requests, lengths to 65000) and gdb (250 default-env, 120 `detect_leaks=0`)
stayed clean — ptrace runs land in the safe layout — so no native frame was
captured; W12's shim remains the only `:219` attribution. Cores are blocked by
Apache's child `RLIMIT_CORE=0` without `CoreDumpDirectory` and an apport core
pattern.

Grade unchanged: rung 3 on the live pre-auth wire path, rung 4 scoped and
unwitnessed at that scope. This is a native availability effect from one
unauthenticated request, but bimodal across restarts, with no fault address
without the shim. Byte always NUL; no chosen byte, pointer target, consumer
dereference, command or rung 5. Replay: `cd lab/frontier/modauthoidc2shell/full
&& bash probe-plain-native.sh`; raw transcripts and limits in
`full/evidence/w13-native/README.md`.

**W14 build-stack correction.** The W9-W13 "non-ASan plain build" label is
wrong: `ldd` on the pinned module `00899061…5654` and the serving httpd shows
`libasan.so.8`, apxs injected `-fsanitize=address` into the compile, and
`nm -D` shows ASan report calls. W13's fault had no added shim or preload but
ran the ASan runtime; `ASAN_OPTIONS=detect_leaks=0` altered that allocator's
layout. The SIGSEGV and controls stand, but no availability effect is shown
on a production allocator. Grade unchanged; detail in `PROVENANCE.md` §
"Build-stack correction (2026-11-23 W14)".

**W14 long-token plain-allocator result.** `realobj/probe-long-token.sh` with
`driver_long.c` (verbatim pinned parser) shows a genuinely non-ASan process
(no libasan) faulting 5/5 at 32000/48000 in both runs but 3/5 at 65000 and
4/5 at 100000 in a clean-archive replay (rc 139), 4/5 at 29000-31000, clean
with dispatch at <= 28000; fixed/release clean at all
lengths, well-formed clean and dispatched. gdb attributes the plain SIGSEGV
to pinned `state.c.4301b536:219`. Harness availability only, no module or
wire, no grade change; detail in `PROVENANCE.md` § "Long value-less token
faults a non-ASan real-APR process (2026-11-23 W14)".

**W15 non-ASan full-module crash (2026-11-23).** The W14 caveat that no
availability effect was shown on a production allocator is now closed for
this lab scope: both pinned modules were rebuilt with system apxs against
Ubuntu httpd 2.4.58 / system APR and non-ASan dependencies (no `libasan` in
`ldd`), served on 127.0.0.1:18091. A bare 7800-byte value-less state cookie
gave 0/48 HTTP 302 and 44 logged child SIGSEGVs over four fresh starts;
well-formed and fixed controls were 16/16 302 with zero faults. One request
per fresh start faulted on the first request in 5/6 starts (1/6 clean):
layout-dependent across starts, not deterministic per request. Apache logs
the child signal but no shim-free faulting PC is captured. Byte always NUL;
no chosen byte, pointer target, consumer dereference, command or rung 5.
Author-only and unwitnessed at this scope. Detail: `PROVENANCE.md` §
"Non-ASan full-module crash on the wire (2026-11-23 W15)" and
`full/evidence/sys-native/README.md`.

**Native faulting PC on the non-ASan full module (2026-11-23 W16).** W15's
production-allocator crash had only Apache's `AH00051` signal line: children
have `RLIMIT_CORE=0` and core_pattern pipes to apport.
`full/probe-sys-gdb.sh` attaches gdb **only to observe** (no shim,
`LD_PRELOAD` or `ASAN_OPTIONS`; ASLR left on) to the same system httpd /
non-ASan module stack on 127.0.0.1:18091. A bare
`Cookie: mod_auth_openidc_state_<7800 a>` on each fresh start stopped on
SIGSEGV in **4/4** vulnerable starts (first request per start); controls
were 6/6 HTTP 302 each with no catch. All four stops are at pinned
`state.c:219` (`*cookie = '\0'`), instruction `movb $0x0,(%rax)`, with the
live pre-auth stack `ap_run_check_user_id` → `oidc_check_user_id` →
`handle/request.c:132` → `state.c:244` → `:219`. The PC is native but observed
with a debugger attached; W15's non-debugger crashes remain the availability
claim. The `=` stop byte is in read-only library pages or unmapped gaps past
a writable/shm mapping, chosen by adjacent memory, not the client. Byte
always NUL, no chosen byte, pointer control, consumer dereference, command or
rung 5; grade unchanged, author-only/unwitnessed. Raw:
`full/evidence/sys-gdb/README.md`; replay `cd
lab/frontier/modauthoidc2shell/full && bash probe-sys-gdb.sh`.

**Wire-chosen store on the non-ASan stack (2026-11-23 W17).** The W8
second-cookie input now runs on W15's system httpd / system APR full modules
with no `libasan` (`full/probe-sys-store.sh`, 127.0.0.1:18091). Five padding
lengths returned 302 on both modules; the vulnerable parent dispatched the
second cookie's value 5/5 while the released tag dispatched 0/5, no child
fault. gdb at pinned `state.c:219` read `0x3d` before and `0x00` after at
token offsets 39 and 63, with the copied header and the pre-auth stack
through `handle/request.c:132` visible in raw transcripts. The store is
in bounds on the header copy, not a pointer field; the byte is always NUL,
the client chooses only its offset, and there is no consumer dereference,
command or rung 5. Grade unchanged; author-only/unwitnessed. Raw:
`full/evidence/sys-store/README.md`; replay `cd
lab/frontier/modauthoidc2shell/full && bash probe-sys-store.sh`.


### W19 OOB store through the response caller (2026-11-24)

The long-token OOB crash was measured only through `handle/request.c:132`
(W12-W16); W11 reached the callback caller `handle/response.c:353` only with
an in-bounds store. W19 closes that gap on the W15 non-ASan system stack
(127.0.0.1:18091). `full/probe-sys-response.sh` sends
`GET /redirect_uri?code=foo&state=foo` with a bare 7800-byte value-less state
cookie: response caller entered 8/8 per start; vulnerable start 1 faulted
7 children (8/8 failed connections), starts 2-4 were clean with HTTP 400;
well-formed and released-tag controls 16/16 clean each.
`full/probe-sys-response-gdb.sh` captured a native PC on vulnerable start 1:
`movb $0x0,(%rax)` at pinned `state.c:219` (raw symbol
`oidc_state_cookies_clean_expired+265`), stack `:219` → `state.c:244` →
`handle/response.c:353` → `:426` → `:614` → `:765` → `mod_auth_openidc.c:1056`
→ `:1258` → `:1309` → `:1388` → `ap_run_check_user_id`; the stopping `=` lay
in read-only `libcom_err.so.2.1` pages. Grade unchanged: rung 4 scoped, native
PC but debugger-observed, byte always NUL, no chosen byte, pointer control,
consumer dereference, command or rung 5; author-only and unwitnessed at this
scope. Raw: `full/evidence/sys-response/README.md` and
`full/evidence/sys-response-gdb/README.md`.

### W20 kernel-recorded native PC (2026-11-24)

The W14 non-ASan realobj fault can be attributed without a debugger. The
kernel's own SIGSEGV report (read via `journalctl -k`; `dmesg` is denied here)
recorded four faults in six unchanged `MO_TOKEN_LEN=65000 ./pl-vuln read 0`
trials, all with IP low bits `0x563`, distinct ASLR bases and `error 7` (user
write protection fault). The ELF text LOAD starts at vaddr `0x1000`, the
mapping base the kernel prints, so the IP is `0x1563`: `addr2line` maps it to
`oidc_state_cookies_parse_token` at pinned `state.c.4301b536:219`, `objdump`
shows `movb $0x0,(%rax)` there, and the kernel `Code:` bytes match the
instruction stream byte-exact with the faulting `c6` marked. Fixed and
released binaries were 3/3 clean with no kernel record. Full raw capture and
hashes: `lab/frontier/modauthoidc2shell/realobj/evidence/kernel-pc/README.md`.

This removes gdb from the **harness** PC attribution only. Grade stays rung 4
scoped and author-only: no wire path, consumed pointer side effect, chosen
byte value or rung 5; the byte is always NUL. The live-wire W15/W16/W19 PCs
remain debugger-observed — Apache children produce no kernel SIGSEGV lines on
this host.
