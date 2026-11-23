# kicad2shell — provenance and verbatim pins

## Claim (external, to be reproduced — not fact)

- GHSA: https://github.com/advisories/GHSA-4qjr-2gjm-9gc6
- CVE: CVE-2026-126970, published to GHADB 2026-11-18, High 7.8,
  CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H, CWE-787, Unreviewed.
  GHSA affected/patched version fields: **Unknown** (numeric fixed version UNKNOWN).
- ZDI: ZDI-CAN-33213 / ZDI-26-956 (RCE claim with user interaction — a claim;
  not reproduced here).
- Fix: GitLab commit `b2f51d113425cf12398eb44dd97dfc30309beccf`, "Toss out
  invalid SIZE keys in corrupt Altium libraries", 2026-08-29, fixes work item
  25174. Parent `bf3e3fa5497882f5b0975d03e4a74b2c086db0e2`. Patch:
  https://gitlab.com/kicad/code/kicad/-/commit/b2f51d113425cf12398eb44dd97dfc30309beccf.patch
  It adds exactly `if( ind < 1 ) continue;` (3 lines) in
  `eeschema/sch_io/altium/sch_io_altium.cpp`.

## Raw pinned source (provisioning only; fetched 2026-11-23)

- `src/sch_io_altium.cpp.vuln` — raw file at parent `bf3e3fa...`, 5989 lines,
  sha256 `73f28d51f3c6cdfe2983a052a5c3e735725f2c735e21a58ca0d4f1bf89b4f982`.
- `src/sch_io_altium.cpp.fixed` — raw file at fix `b2f51d1...`, 5992 lines,
  sha256 `663035d5b3182efde046913eba5a4fb3f4ae89ec04b8686c14b23b27677fceac`.
- Fetched from `https://gitlab.com/kicad/code/kicad/-/raw/<sha>/eeschema/sch_io/altium/sch_io_altium.cpp`.

## Verbatim slices (harness pins, byte-for-byte)

- `pins/sch_io_altium.cpp.vuln.slice` — parent lines 5883-5923, sha256
  `1c90ea097c653be8c2fc5ebad642e0cc9e1a47c0b5546607976422d0388a1cd9`.
- `pins/sch_io_altium.cpp.fixed.slice` — fix lines 5883-5926, sha256
  `517d2a59b76305a7ab395f232425b38056f808e644624e4291dec57eafe725b8`.
- `PINS.sha256` holds all four hashes; `harness/run.sh` re-extracts and
  verifies them before generating drivers. Upstream bytes appear only between
  `#line 5883` and the `#line reset`; all wxString/parser/scale/driver code is
  lab stub code.

## Source-bound mechanism

`SCH_IO_ALTIUM::ParseLibHeader` iterates `FileHeader` properties. For a key
starting with `SIZE`, the suffix is converted with `wxAtoi`:

```
int ind = wxAtoi( remaining );                       // parent :5912
if( static_cast<int>( aFontSizes.size() ) < ind )    // parent :5914
    aFontSizes.resize( ind );
int scaled = schIUScale.MilsToIU( wxAtoi( value ) * 72.0 / 10.0 );
aFontSizes[ind - 1] = scaled;                        // parent :5919  <-- OOB
```

For `ind <= 0` the resize guard is vacuous and the unchecked `operator[]`
writes before `aFontSizes`' heap buffer. The fix rejects `ind < 1` at
`:5914-5915` (fixed slice), making `:5922` unreachable for the hostile key.

## Observed (lab, direct call)

- `attack`: valid `SIZE1=10` first (map order), then `SIZEz=84215045`
  (`wxAtoi("z")==0` → `ind==0`; `84215045*72/10 == 606348324 == 0x24242424`).
  gcc and clang ASan: `heap-buffer-overflow`, `WRITE of size 4`,
  `4 bytes before 4-byte region`, top frame `sch_io_altium.cpp.vuln:5919`.
- Plain build: glibc `double free or corruption (out)` — the same store
  overwrites the malloc chunk header; allocator abort, not a simulation.
- `far`: hostile keys with no valid first allocation → ASan `DEADLYSIGNAL`
  at `:5919`; preserved as a negative/edge case, not a separate claim.
- Fixed control, identical hostile input: `rc=0 size=1 first=72
  GUARD7=11111111`, no ASan report, under both compilers.
- gdb on `g++-vuln-plain`, second hit of `:5919`: `IND=0
  SCALED=0x24242424`; after stepping the store, four bytes at
  `aFontSizes._M_impl._M_start-4` read `0x24 0x24 0x24 0x24`.
- gdb on `g++-fixed-plain`: guard `:5914` sees `FIXED_IND=1` then
  `FIXED_IND=0`; both continue past the write; process exits normally.
- `harness/check.sh`: 52 PASS/0 FAIL, three identical runs, trace
  `dd64c549fa2ddc57559f0aa66a043ab6e64e20d5f8799da5181ca6678d22f9a6`.

## Negatives and ceiling

- No real KiCad build, no wxWidgets, no compound-file/SCHLIB parser, no
  malicious file, no socket or wire: the hostile `properties` map is injected
  directly into the pinned function.
- The chosen 4 bytes land in the allocation's ASan left redzone (plain build:
  the malloc chunk header); no adjacent live object, pointer/IP control,
  command execution or witness. Rung 4 only. ZDI's RCE claim and any wire or
  file reachability stay **UNKNOWN / claim**. Rung 5 not attempted.
- `far` scenario's ASan SEGV is recorded as observed behavior, not promoted
  to a separate vulnerability claim.
