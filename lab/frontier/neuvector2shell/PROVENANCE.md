# PROVENANCE — neuvector2shell (frontier W240, 2026-11-26)

## Provisioning (read-only fetch, no external probing)

    mkdir -p lab/frontier/neuvector2shell/{src,pins,harness,out}
    curl -fsSL https://raw.githubusercontent.com/neuvector/neuvector/48ae8b5cac5ec3a7e332e5272e9b3050f44396cb/dp/dpi/sig/dpi_sig.c \
        -o lab/frontier/neuvector2shell/src/dpi_sig-vulnerable.c
    curl -fsSL https://raw.githubusercontent.com/neuvector/neuvector/0a1dc965317581d2959ecc3d3d1f9cf87e6e1066/dp/dpi/sig/dpi_sig.c \
        -o lab/frontier/neuvector2shell/src/dpi_sig-fixed.c
    sed -n '618,705p' src/dpi_sig-vulnerable.c > pins/dpi-vulnerable.inc
    sed -n '618,725p' src/dpi_sig-fixed.c > pins/dpi-fixed.inc

Advisory: `https://github.com/neuvector/neuvector/security/advisories/GHSA-3x2m-c67v-vw77`
(CVE-2026-127182, Critical 9.4, published 2026-11-20, CWE-121/CWE-787).
CVE record: `https://www.cve.org/CVERecord?id=CVE-2026-127182` (published
2026-11-24). Fix lineage verified from the GitHub commit API:
`0a1dc965317581d2959ecc3d3d1f9cf87e6e1066` (parent
`48ae8b5cac5ec3a7e332e5272e9b3050f44396cb`, 2026-11-20T14:52:52Z) is a
cherry-pick of `229a57a06e8c8bab9a019c5790c402837794e4b3`; it converts the
four `sprintf()` writes in `dpi_sig_bld()` to bounded `snprintf()` plus
`len` checks. No controller, enforcer, Go code, API or network wire was
fetched, built or contacted.

## Pin hashes (SHA-256)

    src/dpi_sig-vulnerable.c  1fbf0ba4aa731f8a92801002d2fe39141c2a88ea9a96d18507af47ae3303072b
    src/dpi_sig-fixed.c       cc9d9c48ea07b015c7254946ab1c630f3aea2ce3a80d0042880b5cedaa284b08
    pins/dpi-vulnerable.inc   a3f74b69151d28acd5cb80eeb1a79949016598f61e0213272648888bbdcea10f
    pins/dpi-fixed.inc        b08af876c7ac71f2f3416b6dc9ee9f0c27816742fc6aea71a4e68bad1431de59

The `.inc` files are byte-exact full function bodies (vulnerable lines
618-705, 88 lines; fixed lines 618-725, 108 lines). `harness/driver.c`
includes one verbatim excerpt with `-I.`; GCC and Clang compile it at
`-O0 -fsanitize=address -fno-omit-frame-pointer -g`.

## Commands and observed results

    bash run-all.sh       -> TOTAL: 29 PASS / 0 FAIL, rc 0
    bash run-witness.sh   -> WITNESS REPLAY PASS, 4 pins exact, rc 0

GCC and Clang ASan on the vulnerable excerpt with a 2100-byte rule pattern:
`AddressSanitizer: stack-buffer-overflow`, `WRITE of size 2107`,
`'dlpsig_buf' (line 4) <== Memory access at offset 2080 overflows this
variable`, write frame `dpi_sig_bld pins/dpi-vulnerable.inc:41`. Fixed
build: no ASan report, `MODE=attack PATLEN=2100 RC=0 SIG_LEN=0` (rule
skipped by the new bounds check). Safe input (8-byte pattern): clean in
both bodies, `SIG_LEN=35`.

Plain builds use `-fno-stack-protector` so the overflow bytes can be
inspected before the frame unwinds. `gdb -q -batch` with a breakpoint at
`pins/dpi-vulnerable.inc:45` and `x/16xb &dlpsig_buf[2048]` shows twelve
`0x4d` bytes (the attacker-chosen pattern fill) past the 2048-byte
buffer; `printf "RET=%p\n", *(void **)$rbp` gives
`0x4d4d4d4d4d4d4d4d`. The unmodified plain vulnerable build then faults
because the saved return slot is overwritten by the same chosen bytes.
With the default stack protector the same input aborts with
`*** stack smashing detected ***`: preserved as a negative control, not
erased. The fixed plain build writes no marker (`CANARY_AFTER=0000...`)
and reports `SIG_LEN=0`.

## Harness limits

Stand-ins replace the NeuVector types (`dpi_dlpbld_t`, `dpi_detector_t`,
`dpi_rule_t`, ...), debug macros, detector init and `dpi_dlp_proc()`. The
harness exercises the pinned C function verbatim but no real NeuVector
binary, Go controller, REST API, wildcard expansion, hyperscan build,
loopback target, pointer redirection, command or rung 5. The chosen
marker is a repeated single byte (`'M'`), not a crafted return address;
the observed 0x4d-filled saved return slot faults rather than executing
a chosen address.
