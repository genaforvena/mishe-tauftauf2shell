#!/usr/bin/env bash
# Identical server environment for the dump and attack runs; ASLR disabled.
exec /usr/bin/env -i PATH=/usr/bin:/bin HOME=/home/mesh-home TERM=dumb \
  /usr/bin/setarch "$(uname -m)" -R \
  /home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin-nocanary/bin/ggml-rpc-server "$@"
