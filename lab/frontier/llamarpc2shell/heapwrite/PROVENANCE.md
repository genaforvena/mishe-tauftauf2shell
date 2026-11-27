# PROVENANCE — llamarpc2shell, distinct CVE-2026-137567 TCP heap-write lane

Provisioned 2026-11-27 under operator DEPTH PICK #6041. Fetching sources and
advisories is provisioning; every test ran against a server this lab started
on 127.0.0.1. This lane is separate from the RDMA lane in `../PROVENANCE.md`.

## Pins (sha256, re-verified after extraction)

| Artifact | sha256 |
|---|---|
| `src/b11450.tar.gz` (GitHub tag archive) | `bc717d30da4d3c0546aded0f254349fd272a65fd1c87638ab06b98f781d7a54b` |
| `src/b12658.tar.gz` (GitHub tag archive) | `bad8484091c673e440e69647af47b66061fd6b94c89ee5b2773fdbdbf4e0da15` |
| `src/ggml-rpc.b11450.cpp` | `c599171b0df40a3ecb2759b3a8d0ed1c8890b0c5694be993156dd6dd07f62181` |
| `src/ggml-rpc.b12658.cpp` | `7b4f1a834eee8d34030e7af0c3c5245c60e7a2cfc57ef45cf6549155c91685a7` |
| `src/fix-03813c56.patch` | `ebe53f862f7ea3a619b18db091cf00654bbecf5251d727fc125afc05adfcb3a6` |
| `tcp_client.cpp` | `a6b076debbcb16be9d12bc94db00c16877a4c0ed2297ffa588f9548d5d44f1f6` |
| `tcp_client` (built g++ -std=c++17 -O0 -g -Wall) | `bb785b25e7185f3eebf694259a823536a4d65583bbda73825c81bba41c12cc76` |
| `run.sh` | `d8ac0d409fa0139996d8623f657def390b03ca0a3b3b41a81ba3510c504de597` |

The extracted trees `src/llama.cpp-b11450/ggml/src/ggml-rpc/ggml-rpc.cpp` and
`src/llama.cpp-b12658/ggml/src/ggml-rpc/ggml-rpc.cpp` hash to the same two
values above. The fix hunk is the upstream `03813c56` patch, whose
`copy_tensor` replacement changed the vulnerable upper-bound-only check into
`rpc_check_region(...)`. Tarballs and extracted trees are gitignored.

## Builds

All three used `-DGGML_RPC=ON -DGGML_RPC_RDMA=OFF -DLLAMA_BUILD_TESTS=OFF
-DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=OFF -DLLAMA_BUILD_APP=OFF
-DLLAMA_BUILD_TOOLS=ON` with `-G Ninja -DCMAKE_BUILD_TYPE=Debug`, target
`ggml-rpc-server -j3/4`. Vulnerable ASan also used
`-DLLAMA_SANITIZE_ADDRESS=ON -DGGML_SANITIZE_ADDRESS=ON`.

| Build | sha256 of `bin/ggml-rpc-server` | log |
|---|---|---|
| b11450 plain | `ed9972c82e7ed23443fcec431b83c8a0b8214c5d22bc2263b685afa7c510cc50` | `build-vuln.log` |
| b11450 ASan | `3c5b77fce00cb30ac9f0ae8ac3ca915e9100a56241e3da23c0b33cb165781180` | `build-vuln-asan.log` |
| b12658 plain | `29d6e4236fb57b5e2ff3ef2aa3f7dc6c42b85577cce0814ebd521ec9616367bd` | `build-fixed.log` |

## Decisive evidence (committed logs; other runs gitignored)

| Log | sha256 |
|---|---|
| `evidence/rb3-client.log` | `bb9111115bb2169185619edada61292c04b48b42eac5a9569279ef1b591c3067` |
| `evidence/rb4-client.log` | `288bb8d20f793f74fae8e2b38496634d9bf201a67ee6ce57dd5e5e4cebe61643` |
| `evidence/rb5-client.log` | `25b36a006767b8c902ae14e073b8b21b4ebf9f5d8e21aede28ee3ea64315bf99` |
| `evidence/asan1-server.log` | `3b619aead806d83fbd100719b6bfe10c7dfefd953384ac1650c566e174d2c887` |
| `evidence/asan1-client.log` | `13a774d5bf73e7b944163ee5e00270d2dce73af68b4af110dde58eb67d06b33e` |
| `evidence/fixed1-server.log` | `cf0f2f22f7a445ee47e5823c5a3aff4139be3a26d421bdb8fdc8cdeefc869a40` |
| `evidence/fixed1-client.log` | `c077f73938da9514bed8c82a6b335ba62356dc5c59322c405e2cc9fdb0c0393f` |
| `evidence/safe2-client.log` | `6a234a76b0423172fb24290f20f3e46e478dc0a3090098e553d832d4817610cf` |

Full narrative, grade and limits: `reports/llamarpc2shell-cve137567.md`.
The `rb1`/`rb2` opcode-confusion failures and their server logs are kept
locally but gitignored; they are a preserved negative, not evidence.
