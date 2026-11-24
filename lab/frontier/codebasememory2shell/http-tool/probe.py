#!/usr/bin/env python3
"""Drive the pinned codebase-memory-mcp loopback HTTP /rpc transport.

Usage: probe.py BINARY TAG PORT EVIDENCE_DIR [ASAN_OPTIONS]

One server process stays alive with stdin held open; all calls are real HTTP
POSTs to http://127.0.0.1:PORT/rpc. The fixture and cache are local throwaway
directories under /tmp. Nothing leaves the host.
"""
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

CHOSEN = "MISHE_OO0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx"


def main():
    binary = os.path.abspath(sys.argv[1])
    tag = sys.argv[2]
    port = int(sys.argv[3])
    evdir = pathlib.Path(sys.argv[4])
    root = "/tmp/cbm-http-" + tag
    cache = root + "/cache"
    fixture = root + "/fixture"
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(cache, exist_ok=True)
    os.makedirs(fixture, exist_ok=True)
    pathlib.Path(fixture + "/probe.c").write_text(
        "int %s(void){return 1;}\n" % CHOSEN)

    env = os.environ.copy()
    env["CBM_CACHE_DIR"] = cache
    env["CBM_INDEX_SUPERVISOR"] = "0"
    if len(sys.argv) > 5:
        env["ASAN_OPTIONS"] = sys.argv[5]
    else:
        env["ASAN_OPTIONS"] = os.environ.get("CBM_ASAN_OPTIONS", "detect_leaks=0")
    out = open(root + "/stdout.log", "wb")
    err = open(root + "/stderr.log", "wb")
    proc = subprocess.Popen([binary, "--ui=true", "--port=%d" % port],
                            stdin=subprocess.PIPE, stdout=out, stderr=err, env=env)
    print("BIN=" + binary)
    print("ROOT=" + root + " PORT=%d CHOSEN_LEN=%d" % (port, len(CHOSEN)))
    print("ASAN_OPTIONS=" + env["ASAN_OPTIONS"])

    def rpc(name, arguments):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": name, "arguments": arguments}},
                          separators=(",", ":")).encode()
        req = urllib.request.Request("http://127.0.0.1:%d/rpc" % port, data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                return resp.status, resp.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")
        except Exception as e:
            return -1, "%s: %s" % (type(e).__name__, e)

    def ready():
        for _ in range(100):
            if proc.poll() is not None:
                return False
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    def show(label, status, body, maxlen=900):
        print("=== %s === HTTP=%s RC=%s" % (label, status, proc.poll()))
        print(body[:maxlen])

    if not ready():
        print("SERVER DID NOT BIND; rc=%s" % proc.poll())
    else:
        show("INDEX", *rpc("index_repository", {
            "repo_path": fixture, "mode": "fast", "name": "probe"}))
        for n in (1, 32, 33, 48):
            q = "MATCH (f:Function) RETURN " + ", ".join(["f.name"] * n)
            show("QUERY_%d" % n, *rpc("query_graph", {
                "query": q, "project": "probe", "max_rows": 10}))
            if proc.poll() is not None:
                print("server exited after N=%d" % n)
                break

    try:
        proc.stdin.close()
    except Exception:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    out.close()
    err.close()
    evdir.mkdir(parents=True, exist_ok=True)
    (evdir / ("http-%s-stderr.log" % tag)).write_bytes(
        pathlib.Path(root + "/stderr.log").read_bytes())
    print("FINAL_RC=%s" % proc.returncode)


if __name__ == "__main__":
    main()
