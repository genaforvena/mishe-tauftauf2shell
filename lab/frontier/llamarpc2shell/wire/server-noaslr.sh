#!/usr/bin/env bash
# Lab wrapper: run the no-stack-protector pinned RPC server with ASLR disabled.
exec setarch "$(uname -m)" -R /home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin-nocanary/bin/ggml-rpc-server "$@"
