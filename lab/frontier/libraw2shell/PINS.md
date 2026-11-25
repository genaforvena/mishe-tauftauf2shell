# PINS — libraw2shell (W197)

| Artifact | Origin | sha256 |
|---|---|---|
| `pinned/LibRaw-0.22.3.tar.gz` | `https://github.com/LibRaw/LibRaw/archive/refs/tags/0.22.3.tar.gz` | `7edf96c5b70cff88980a02ab0fc8af125cb6a4a377985573c654439d9d02355c` |
| `pinned/poc_xtrans_oob_write.zip` | GitHub user attachment linked in issue #894 | `619e741e27bd0394270ec4eadc149d24b10aa03415de63cc479b2a16512abe61` |
| `pinned/poc_xtrans_oob_write.input` | extracted from the zip | `c7940268cfb817adc4d5d42e9327a93fd042d7cd4cda8bc4b4ed6f1c4435dae2` |
| `pinned/fix-894.patch` | verbatim two-line fix proposed in issue #894, hunk counts corrected | `32fc61e5a52c0b393fd09175bf9b1283c29065767613d15a16e421dd1a2afc9c` |
| `craft_poc.py` | lab-only negative-result artifact (chosen-pixel attempts) | `cb53b7c1b0ae10652214215e1b969d4f57e8bef67bb4425e1da8a375c363ff44` |
| `craft_nonzero_poc.py` | lab-only nonzero-pixel variant generator (W2) | `004ff4350d66000a0c941956bfc910ea16d561c0f9a7300477f448e1917cf862` |
| `evidence/nonzero-oob.input` | derived from pinned PoC by `craft_nonzero_poc.py` | `b59f64e9837b06a8f0ca07a3776e961e7d0493794e0d6cb38fbcb80022069341` |
| `craft_whitelevel_poc.py` | lab-only WhiteLevel steering generator (W3) | `ab5ace42392c8558d4c939d1524a9ffb29a112acb021b8141ce9a0dd8b30d1cf` |
| `evidence/whitelevel2048.input` | W3 variant, WhiteLevel 2,048 | `d398d0e78077a07cb0fb4572fce16805de1d3d31bf5d0718355b2b80c52c35f5` |
| `evidence/whitelevel4095.input` | W3 variant, WhiteLevel 4,095 | `8d9b520418207522efb8450c2aa80dbbdb3eb6fbe6da97ffe484e2f86d7cb905` |
| `evidence/whitelevel8191.input` | W3 variant, WhiteLevel 8,191 | `50c91fbbdbd49baba44ab2eab51fe19d726245c1d8aca6fe056cd09e7c3ce42b` |
| `evidence/whitelevel16383.input` | W3 variant, WhiteLevel 16,383 | `2547a078ca25f315e957d30614a9c4370e0657262036487d0fcdda2390c78bc8` |
| `craft_dimension_poc.py` | lab-only frame-size steering generator (W5) | `2703d113236f4baf8b6a164b8198448d4b4b89d33d7e9c81f2831d91c27f3e55` |
| `evidence/dim1024.input` | W5 variant, 1024x1024 frame from `evidence/nonzero-oob.input` | `a0e318197405aa5df29a3f5c1a0916487e0eb8c67c55ec00c03dd0308ff2da3a` |
| `evidence/wl-probe-11036.input` | W6 variant, WhiteLevel 11,036, exact `0x4141` at index 68,644 | `b856c1c62d48a63f9c3d42a4d32be11033c0dc405fcbcc063f6b9ddaa6d61215` |
| `evidence/wl-probe-11035.input` | W6 calibration neighbour, `0x4142` | `8d865153c01b4128e270fa1e5bcc9988865dae48829c94bca5eb955d1d1cce09` |
| `evidence/wl-dead.input` | W6 negative target, WL 3,234 -> `0xdeb3`, not `0xdead` | `6ed079d8c97e89bdd3eff5367064ef32fffa4b4d66e5746cbc53a24f6c5192da` |
| `evidence/dim1024-wl11036.input` | W7 negative: W6 WL does not transfer to D=1024 | `6df37eb18792169d21fbd60179a1368a992fe1e1537c22d89ed7a7e40e76ae70` |
| `evidence/dim1024-wl6864.input` | W7 target-1 probe at far index, `0x4146` | `805e7b4007e4ae49dfde1badd8c8a67d4ed93d9b2d4e20b55ed94158e02ef502` |
| `evidence/dim1024-wl6866.input` | W7 target-1 probe, `0x4142` | `65dca5a48b6f48d6a316632bd8ddc9cb6cb17be2da138d12b9ee927f728d2049` |
| `evidence/dim1024-wl6867.input` | W7 target-1 probe, `0x413e` | `aab51772ae94f86efd3faf89457b3944a0d1d2142da1f196713b97f9e8caf4f3` |
| `evidence/dim1024-wl24600.input` | W7 target-2 bracket, `0x1235` | `c0c5df90f5f03a4b8625b784e4e653e240a548f2e47e76a06398b6ed2ab50fbc` |
| `evidence/dim1024-wl24601.input` | W7 exact pre-chosen `0x1234` at index 268,324 | `b894e63c5e70cf685bb1a309e9c14ee265bcec8068a6bbe4aac55023138c0f77` |
| `evidence/dim1024-wl24602.input` | W7 target-2 bracket, `0x1233` | `d35f0d336eab74161fe9cef1fc936a882b516df8a69b747af412edb9b3d35f93` |
| `evidence/dim1024-wl24603.input` | W7 second exact `0x1234` hit | `1fedbfcf3f4807ac37e2cce3467a2fb34b29d04e56b48ee5f366f264482ffa55` |
| `evidence/dim1024-wl24606.input` | W7 sweep, `0x1233` | `566c84a57ce21f5e73128a02104c2e0bc1549806f0a4c0ec85a9c9d2581f0b68` |
| `evidence/dim1024-wl24607.input` | W7 sweep, `0x1233` | `0d2d9e00f52fbd90f2973bfb85a9c343267ab3c1a4b609b8ef2e4f8907b40191` |
| `evidence/dim1024-wl24608.input` | W7 sweep, `0x1233` | `f01be451f0051806b18aa820b759c231e11579fd9aca2e731e1d2a5ed7a99782` |
| `evidence/dim1024-wl24609.input` | W7 sweep, `0x1233` | `37cebe51c26b055895d07d0cffa1d0ef7c0875fa8bca43f30a5f825bedaea5d9` |

| `w8/segv.gdb` | lab-only W8 OOB-extent and SIGSEGV-site gdb probe | `fb47491baca20db3556968257de1e78d743084457390d977a312537e9eabe1ee` |
| `w8/heapwalk.gdb` | lab-only W8 first (misaligned) heap-chunk walk | `fab6b78468798de7f5e9649f9b384bdf0b6798e3fa5d9dca475705f0ae64d599` |
| `w8/heapwalk2.gdb` | lab-only W8 corrected heap-chunk walk | `b4793d59a87f2ebeb9252c15b0a41c52dc843b721fd0ad1f1d9a83cb29b6c451` |
| `w8/mallocstat.gdb` | lab-only W8 `malloc_usable_size`/`malloc_stats` probe | `fffab9c35ab3f4368f3a687c490a04b8fa962c37ed32793d27e3d6d3ed5845cb` |

| `w9/extent512.gdb` | lab-only W9 D=512 default-env heap-extent probe | `6db2b4d3ffe6b1e3335a8754ac373c5d1517c497afc870a5d2c948e23d98fafb` |
| `w9/toppad.gdb` | lab-only W9 `MALLOC_TOP_PAD_=0` reach probe template | `eba879bd760eacf805bbfc0ed3731e5e073ebba7191f2f2290413a29fb72f6f3` |
| `w9/toppad-nonzero-oob.gdb` | W9 D=512 top-pad=0 reach run | `9c8a681fa0f85922d13fbde1afec4ee6f2440c6c2f0c219bdbe5e93174242c50` |
| `w9/toppad-dim1024-wl24601.gdb` | W9 D=1024 top-pad=0 reach run | `0751391a88fd73f546d034bf3e4f8d7211c809b89e4a8e90d6590a921ccd5e33` |
| `w9/toppad-map.gdb` | W9 D=512 top-pad=0 mapping probe | `cdd0c0436d4743d42cf8ee02580153a3926399ce186ae579a7a86c5a9a065917` |
| `w9/walk512.gdb` | W9 D=512 chunk-header walk (header read did not yield a usable size) | `5218f8861647e8c9674ab6eb1010bdf533f900d050cbdba033f3da21471b6bf6` |
| `w9/hashes.sha256` | W9 input/script hash record | `2384a3b5ee4541c0fe31f90277cde3abdbc2e74de483ecffd138fef8fda84557` |
| `craft_blacklevel_poc.py` | lab-only W10 BlackLevel steering generator | `cf7245af95b8636ea8a06acaabdbc6d3fd3f7c1aa9a674ce17078ad892869cac` |
| `w10/targetdead.input` | W10 WL=3230 BL=6, exact `0xdead` at index 68,644 | `a1367d1e73606b183ef5175174c64d3a54070827e1184643c1a24a526772553c` |
| `w10/target2222.input` | W10 WL=21084 BL=1, exact `0x2222` at index 68,644 | `eb69f4e3ffd3f288f9244f0da73e12071a753c546a7accaac501d8eeeabf90c3` |
| `w10/instrument.patch` | lab-only one-shot fprintf calibration patch (not the claimed consumer) | `f2b2843645656d0f3c33a36ad7e11f574a91bf032ea983f8e63af7f7ad5c02cb` |
| `w10/grid-wide-results.txt` | corrected 441-point WL/BL calibration grid | `a4e71e340d673ae49bfc5ea77847de1d0126f0e86387097393652f2c46f3ae8b` |
| `w10/grid-invalid-argv.txt` | invalid `"-n 1"` single-argv grid, preserved negative | `6317735c71496a81acf8d513b92583fbcce7192df6cee8404721777bb2eaefd8` |
| `craft_linearization_poc.py` | lab-only W11 DNG LinearizationTable generator | `74ca3ee9a74e410682bb3588c0e99fa9c499f294ca79eb76e1055d4fb213cc1c` |
| `w11/targetbeef.input` | W11 LinearizationTable=0xbeef WL=65535, exact `0xbeef` channel 1 at index 68,644 | `cf5030ebfa46f3badc4498e4ec4230c670ba010b70f5ace3a872d8fcbc33d33b` |
| `w11/target1337.input` | W11 LinearizationTable=0x1337 WL=65535, exact `0x1337` channel 1 at index 68,644 | `b10072878cda73d1530a3156789e9742ccd791a9389f589516548dd9bd23cd8f` |
| `w11/target00a5.input` | W11 LinearizationTable=0x00a5 WL=65535, exact `0x00a5` channel 1 at index 68,644 | `d01e8cba907216b7fab1fad070e52f4d529271074b9f93c0b75573bfb440d548` |
| `w11/target0001.input` | W11 low edge, exact `0x0001` channel 1 at index 68,644 | `1ca11ebfa5fdcfbd02fe85f13c6690023c3c588e193dbb9c1d124121385a769d` |
| `w11/targetffff.input` | W11 high edge, all three channels `0xffff` at index 68,644 | `93ad684af7b1fe11846711293cb0f998d27de67cfb96666df6570242ef8bf7d4` |
| `w11/results.txt` | W11 full method, hashes, values, controls and limits | `9ca25f6c7421f81a14a1e620b52d8c206153c4f689e37aaca86ec19d82f7c1dd` |
| `w12/results.txt` | W12 BlackLevel negative result: IFD1 no effect, IFD0 coupled global shift, controls | `f57f1da2e741f9950dbbe176467397672335c24f46766239ec9bad315ab88ab1` |
| `craft_dual_knob_poc.py` | lab-only W12 generator: IFD1 slot 0 -> `0xc61a` SHORT/1 | `040d072625aa6e7394754232ede77585b2a3bed7502ecf4223487f134c908441` |
| `w12/ifd0.gdb` | W12 exact-first-OOB-index probe (unmodified `-O0` build) | `af4020f4e24052988cc8fda5ab0046545346ce1ae66a77aa9bc260f75c912f01` |
| `w12/dualbeef-bl1.input` | W12 IFD1 BlackLevel=1, byte-identical to W11 `ffff beef fe93 0` | `d8eb73adecdcbb09115d73855e7e9ae143edac4a398923aa6d06b5a58fda101d` |
| `w12/ifd0beef-bl6.input` | W12 IFD0 BlackLevel=6, coupled shift `ffff beed fe91 0`, controls clean | `caab59d6c1a562ddd09aa9329d0b7e1368834e2f11413b435f33ab517199fc9d` |
| `w12/ifd0-bl6-exact.txt` | W12 raw gdb trace at exact index 68,644, BlackLevel=6 | `4d4764a0fcf0704a1aacba75d23987cc599279caf747c902e5d85b1972acad2f` |
| `craft_uncompressed_poc.py` | lab-only W13 generator: compression 1 + packed 12-bit samples + 4096-entry LinearizationTable | `0d91b5a8324a814fb7097051a456949dac610ff9d21d8c22d717beedddf1749c` |
| `w13/colors1234.json` | W13 CFA-separated spec: red 0x1234, green 0xbeef, blue 0x5678 | `d0554dee56d3a7e8478be06c8d6ae40861161f9bf19a1edac0a0ec0996338a14` |
| `w13/colors1234.input` | W13 separation result `8e74 beef 9c1c 0` at index 68,644 | `4f3834f74172df0c1014e3365e563b2246b089d509c7720edaa21d4a66cac9a4` |
| `w13/dead-target.json` | W13 final spec for pre-chosen `9000 beef dead` | `b3e416486b13e0fb2994b1c194c9ed50dbea573febe15894ef9f0ff830eea43e` |
| `w13/dead-target.input` | W13 final uncompressed DNG, three chosen halfwords, controls clean | `18b012c98809a9f4822a173ee591b046db3b6eb612326e30e259984467149e78` |
| `w13/rgb.gdb` | W13 probe of the per-direction rgb inputs at the first OOB store | `20e39aebee889c35619f005939b49e9fa7f666953af5b13f5c6ced213ffa7a85` |
| `w13/dead-gdb-1.txt` | W13 first of three byte-identical exact-index traces (`9000 beef dead 0`) | `d40f2de88afe353eb5fa7901ed81a7c587e75427d6f428e8e17f442798a542a3` |
| `w13/dead-asan-vuln.out` | W13 ASan vulnerable -n 1, rc 1, WRITE of size 2 at xtrans_demosaic.cpp:427 | `45fee4b2324b4ab4c674f4efc1137b240e95f4b5bda4d1d122f66f4984acf6b1` |
| `w13/results.txt` | W13 full method, calibration, negatives, controls and limits | `729d273bc41a954058cc53c70fc9dbed1045a5d88be0af1b9d35d112aef0f265` |
| `w14/two-offset.json` | W14 spec: W13 triple plus curve[3]=0x1357 and raw rows 138..147 overridden to sample 3 | `9f09737465417c9dcbfb030c1a5339ad6c588942d9f33d308f8c19220b1a5929` |
| `w14/two-offset.input` | W14 DNG: chosen 0x1357 channel at a second OOB offset 16,800 halfwords past index 68,644 | `4fb6e951e06db573f818b2377f71320578afaf61edf12c30ee5748b90618a8c2` |
| `w14/oobmulti.gdb` | W14 multi-offset OOB store dump probe (unmodified -O0 build) | `b5be385159a6c354648c7936da8784bdba50e89ac9308b86359ef8ca415f8546` |
| `w14/results.txt` | W14 two-offset result, reproducibility, controls and limits | `0eb32bea8a14c79e527cf91bbc96f51605cb308212fbe2a099bb97773e591192` |
| `w15/oobwide.gdb` | lab-only W15 wide multi-OOB map probe | `ee1b3088b2ea35039584d27ce754ce3b81aae3e0af19b30c6eb0081d633cc452` |
| `w15/exact.gdb` | lab-only W15 exact six-offset dump probe | `d63183221d2cc2798f83bf38f0ed7c73fd3bbba8fd736082974d51b19114ef91` |
| `w15/band150.json` | W15 spec: W14 plus curve[5]=0x2468 on raw rows 150..159 | `08de8dd7d3bf8b9bdb9bac9c72868f3afebf174b55fc43c98f4aedc8ffb1308f` |
| `w15/band150.input` | W15 DNG: third chosen channel-1 value 0x2468 at OOB offset 33,000..40,000 | `86b5e7c7912437f16bc73b273d41e6ae15cfb6fcd976d7431bb02cb7f7441b1e` |
| `w15/wide-band150.txt` | W15 wide map dump with third value band | `d455894f29338cdd358875d8187d5de4d97ff89b4be6c59f41ea1566d4f5fb50` |
| `w15/results.txt` | W15 third-offset result, negatives, controls and limits | `73118f309920675c105b2599361de62d6c393bc73937d051dba6a84f1ff7183a` |
| `w15/three-offset.json` | W15 preserved negative: rows 250..259 -> sample 0 | `1c6486e9566cc4c35db4fea9d2991f728b534a0dea249585a28e3452f11e09a2` |
| `w15/rows90.json` | W15 preserved negative: rows 90..99 -> sample 0 | `efad91dbe45180b17a7de09b8841ad2e3f2086098947c6b3350a124f1706c051` |
| `replay-all.sh` | W16 one-command clean-archive replay for W13/W14/W15 | `c53ed205d02c251516076f4d57c7af40f755fbb4d5bce04e7f79a126aec87828` |
| `wire/wire_decoder.cpp` | W17 loopback in-process LibRaw consumer | `d6e54904fed35a2cfabc53c9fbc6ed7c6cb239756a707a989eb497c3547dfece` |
| `wire/send.py` | W17 loopback file sender | `5852dedc2fab7913a631ff9ffe8f3762ca5fccd28cafe38e6c9ab81841915b0f` |
| `wire/run.sh` | W17 three-lane wire replay driver | `159850e72c747a54795e40f948c9b91c97de9f5d1c45e6edfbf92e1474385407` |
| `wire/results.txt` | W17 wire-visible rung-4 result and controls | `bd14eb7e1ef96888ec9d0d93c56e04a4e2b1b13f80bc9715e3e1ee0c96a0309f` |
| `w19/heapwalk-extra.gdb` | W19 chunk walk from `destimage` to `main_arena.top` at first OOB store | `3feb2a0c157b3b31250c8a012d1145ba39d038344778018679eee82d86cf0b06` |
| `w19/heapwalk-extra.txt` | W19 direct measurement: top chunk is the only chunk after the scratch buffer | `ee563c2d39f0671ce1e88f06820b3a7824dcc421bb762c6ac1806c8a33e60238` |
| `w19/results.txt` | W19 negative result: live-object lane closed, source-bound corroboration | `1363326b8311d5a2652ecf166d099fa04a067d244128de60acbff5cbbdd0c693` |


Advisory: `https://www.vulncheck.com/advisories/libraw-0.22.3-heap-out-of-bounds-write-via-xtrans-interpolate`
(CVE-2026-135176, 2026-11-23). Report: `https://github.com/LibRaw/LibRaw/issues/894`.

Vulnerable lines verified against the pinned bytes, not rendered web line numbers:
`src/demosaic/xtrans_demosaic.cpp:176-179` (allocation/memmove), `:427` (store),
`src/demosaic/misc_demosaic.cpp:68-79` (stale `iwidth`/`iheight`).

No upstream merged fix was found; the fixed control is the reporter's proposed
patch. Fixed status is UNKNOWN.
