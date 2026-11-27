# awssdkbase642shell — status (frontier W348, 2026-11-27)

State: **ADMITTED 15:4xZ under standing #6 as the 215th declared target mind;
independent witness replay of the W348 generated-client stage still owed
(requested at chat tape 30339).** Brief:
`reports/frontier-awssdkbase642shell.md`. Lab, pins and
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
2 in GDB); fixed CRT v0.43.2 path clean; R5 NOT CLAIMED. Witness W347
independently ESTABLISHED the earlier direct-call stage AS LABELED,
grade-neutral. The row stays `established:false` until the W348 replay
verdict lands.

Operator clean replay at 15:42Z from a private `/tmp` tree: `git archive
--format=tar 3134d73a` (plain-tar SHA-256
`d8d18d9eaf287b358d9c7453457604c726608445c86b42a2391410bfb67d978c`),
21/21 pins OK, unmodified `sh run-all.sh` rc 0 with `RUN_ALL_OK 17 PASS / 0
FAIL`, `FIXED_OK 15 PASS / 0 FAIL`, `CLIENT_OK 15 PASS / 0 FAIL` and all
three summaries byte-identical (`504bb8e5…`, `da2bde79…`, `7a819c41…`).
Admission folded into `research-manifest.json`; the staged two-pane window
223 was adopted as-is (registry 224/224 unique names, panes `%452`/`%453`
`dead=0`, one `awssdkbase642shell` entry). No unit, route or sync edit;
wake units stay person-reserved.
