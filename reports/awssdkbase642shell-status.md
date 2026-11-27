# awssdkbase642shell — status (frontier W348, 2026-11-27)

State: **STAGED by frontier W348; operator admission and independent witness
replay owed.** Brief: `reports/frontier-awssdkbase642shell.md`. Lab, pins and
provenance: `lab/frontier/awssdkbase642shell/PROVENANCE.md`. Charter and seed
wall exist; live inner-socket window 223 (`%452`/`%453`, `dead=0`), registry
224/224 unique. Wake units, routes and sync stay person-reserved.

CVE-2026-19642 / GHSA-wxx3-prfc-69xx, `aws-cpp-sdk-core <= 1.11.861`, exact
parent `2857dbc70b4b780810e304ba14514fa52d932a23` → fix
`8eeac049c37b2c4cca2a94bfb53f07ea7e4550f7`. The pinned `Base64::Decode()`
writes a third byte into a 2-byte `ByteBuffer` for `AAAA=`; the generated
REST-JSON model `JsonBlobsResult.cpp:27` passes a wire JSON blob string to
`HashingUtils::Base64Decode` and reaches the sink.

Author result: `sh run-all.sh` at 21 pins gives `RUN_ALL_OK 17 PASS / 0 FAIL`
(summary SHA-256
`504bb8e541ebc6bfd16d73715bd144fdfffb3b42c8562e9db7a410c57903d234`),
`FIXED_OK 15 PASS / 0 FAIL` and `CLIENT_OK 15 PASS / 0 FAIL`. Clean
`git archive --format=tar 3134d73a` replay: 21/21 pins and all three
summaries byte-identical; plain tar SHA-256
`d8d18d9eaf287b358d9c7453457604c726608445c86b42a2391410bfb67d978c`.

Grade: R1/R2/R3 ✓; R4 DEMONSTRATED at the generated-model/wire-JSON lab
scope (ASan WRITE-1 at `Base64.cpp:115`, chosen `0x5a`/`0xda` at heap offset
2 in GDB); fixed CRT v0.43.2 path clean; R5 NOT CLAIMED. No witness verdict
yet; witness replay has been requested separately.
