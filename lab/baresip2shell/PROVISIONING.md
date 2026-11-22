# Provisioning — baresip/re pinned wire experiment

Read-only fetch from `https://github.com/baresip/re.git` on 2026-11-22. No
probe or connection to any external target; every runtime action in this lane
is against a plant-started 127.0.0.1 listener.

```
mkdir -p lab/baresip2shell/src
git clone --no-checkout https://github.com/baresip/re.git lab/baresip2shell/src/re
git -C lab/baresip2shell/src/re checkout --detach \
  7ace643fef58b0cc0d5d6b3fa434f56f027879f9
git -C lab/baresip2shell/src/re worktree add --detach ../re-fixed \
  89aed31f37449da32004ba608e5d1aa483b8bb21
```

`git worktree add` may warn `FICLONE unsupported`; the checkout still succeeds.

Hash assertions (verify before building):

```
02a4af85ef7c842c442a5ff8138dea9b849ed5c02216f7aa5dfabadb22516ec0  src/re/src/websock/websock.c
1af5a0603974ee1020af39cc4fa154e93f1956e49991fc4125c785da2e2f861a  src/re-fixed/src/websock/websock.c
```

These are the same bytes frontier saved in
`lab/frontier/baresip2shell/src/websock-v4.8.0.c` and `websock-v4.8.1.c`.

Toolchain: gcc 13.3.0, cmake 3.28.3, OpenSSL 3.0.13 development headers,
gdb 15.1, python3. `-DUSE_OPENSSL=ON` is required: with `OFF` the build fails
in `src/hmac/hmac_sha1.c` with `missing HMAC-SHA1 backend`.

Build and run (all paths relative to the repository root):

```
bash lab/baresip2shell/live/build.sh      # four libre.a builds + four servers
bash lab/baresip2shell/live/run.sh        # ASan wire cases + controls
bash lab/baresip2shell/live/run-probes.sh # gdb probes on fixed and plain pins
```

`build.sh` skips a library build when its `libre.a` already exists; remove
`lab/baresip2shell/build/` for a full rebuild. All source clones, build trees
and server binaries are gitignored.
