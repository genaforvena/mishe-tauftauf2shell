#!/usr/bin/env python3
"""Drive the real pinned codebase-memory-mcp stdio tool path, one tools/call per line.

Usage: probe.py BINARY TAG [CACHE_DIR] [FIXTURE_DIR]
The server is a subprocess; each JSON-RPC call is a fresh process, as in the
recorded author run. No network, no other host.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys

CHOSEN = "MISHE_OO0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx"  # 68-byte C identifier


def env():
    e = os.environ.copy()
    e["ASAN_OPTIONS"] = e.get("CBM_ASAN_OPTIONS", "detect_leaks=0")
    e["CBM_INDEX_SUPERVISOR"] = "0"
    return e


def call(binary, method, params, timeout=120):
    line = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                      separators=(",", ":")) + "\n"
    p = subprocess.run([binary], input=line, capture_output=True, text=True,
                       env=env(), timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def show(label, rc, out, err, maxerr=60):
    print("=== " + label + " ===")
    print("RC=" + str(rc))
    print("STDOUT=" + out[:1500])
    lines = err.splitlines()
    print("STDERR_LINES=" + str(len(lines)))
    for ln in lines[:maxerr]:
        print("  " + ln[:300])
    print()


def main():
    binary = os.path.abspath(sys.argv[1])
    tag = sys.argv[2]
    cache = sys.argv[3] if len(sys.argv) > 3 else "/tmp/cbm-mcp-cache-" + tag
    fixture = sys.argv[4] if len(sys.argv) > 4 else "/tmp/cbm-mcp-fixture-" + tag
    shutil.rmtree(cache, ignore_errors=True)
    os.makedirs(cache, exist_ok=True)
    shutil.rmtree(fixture, ignore_errors=True)
    os.makedirs(fixture, exist_ok=True)
    os.environ["CBM_CACHE_DIR"] = cache
    print("CBM_CACHE_DIR=" + cache)
    print("BINARY=" + binary)
    print("CHOSEN_LEN=" + str(len(CHOSEN)) + " CHOSEN=" + CHOSEN)
    print("CACHE=" + cache)
    print()

    rc, out, err = call(binary, "tools/call",
                        {"name": "index_repository",
                         "arguments": {"repo_path": fixture, "mode": "fast", "name": "probe"}})
    show("INDEX", rc, out, err, maxerr=12)

    rc, out, err = query(binary, 1)
    show("QUERY_1_CONTROL", rc, out, err, maxerr=12)
    if '"total":0' in out.replace(" ", ""):
        print("WARNING: no rows; projection loop will not run")

    for n in (32, 33, 48):
        rc, out, err = query(binary, n)
        show("QUERY_%d" % n, rc, out, err)


def query(binary, n):
    q = "MATCH (f:Function) RETURN " + ", ".join(["f.name"] * n)
    return call(binary, "tools/call",
                {"name": "query_graph",
                 "arguments": {"query": q, "project": "probe", "max_rows": 10}})


if __name__ == "__main__":
    main()
