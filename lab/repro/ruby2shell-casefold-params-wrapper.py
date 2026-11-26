#!/usr/bin/env python3
"""Bounded request-path probe for the case-fold OOB via Rails ParamsWrapper.

A stock `rails new` app is copied to lab/build/rails-params-wrapper-app. The
only app edits are one scaffold-shaped ASCII controller whose `controller_name`
returns a sharp-s string plus its ASCII route, and an ASCII-named control
controller. Rails' router rejects non-ASCII controller names in routes, so
the sharp-s text here comes from app code, NOT from the wire. Every case boots
a fresh unmodified Rails server with a pinned ASan Ruby and sends one ordinary
loopback request. No middleware, preload, debugger or app hook is in the path.
This is an analysis reproducer, not an RCE claim.

Evidence: lab/build/evidence/casefold-params-wrapper/
"""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
EV = ROOT / "lab/build/evidence/casefold-params-wrapper"
APP_SRC = ROOT / "lab/build/rails-stock-app"
APP = ROOT / "lab/build/rails-params-wrapper-app"
RUBIES = {
    "affected": ROOT / "lab/build/ruby-3.4.12-asan/bin/ruby",
    "fixed": ROOT / "lab/build/ruby-3.4.13-asan/bin/ruby",
}
GEMS = {
    "affected": ROOT / "lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0",
    "fixed": ROOT / "lab/build/plain/ruby-3.4.13-plain/lib/ruby/gems/3.4.0",
}
CASES = [
    ("json-sharps", "POST", "/sink", True),
    ("get-sharps", "GET", "/sink", False),
    ("json-ascii", "POST", "/ascii", True),
]
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36"


def no_core() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def prepare_app() -> None:
    if APP.exists():
        shutil.rmtree(APP)
    shutil.copytree(APP_SRC, APP)
    (APP / "app/controllers/sharps_controller.rb").write_text(
        'class SharpsController < ApplicationController\n'
        '  skip_forgery_protection\n'
        '  def self.controller_name\n'
        '    "statusßs"\n'
        '  end\n'
        '  def index\n'
        '    render plain: "ok"\n'
        '  end\n'
        'end\n', encoding="utf-8")
    routes = APP / "config/routes.rb"
    text = routes.read_text(encoding="utf-8")
    routes.write_text(text.rstrip()[:-3].rstrip() + '\n  match "sink" => "sharps#index", via: :all\n'
                      '  match "ascii" => "statuses#index", via: :all\nend\n', encoding="utf-8")
    (APP / "app/controllers/statuses_controller.rb").write_text(
        'class StatusesController < ApplicationController\n'
        '  skip_forgery_protection\n'
        '  def index\n'
        '    render plain: "ok"\n'
        '  end\n'
        'end\n', encoding="utf-8")

def wait_ready(proc: subprocess.Popen, port: int, seconds: float = 40) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", "/up")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            return resp.status == 200
        except OSError:
            time.sleep(0.3)
    return False


def request(port: int, method: str, path: str, json_body: bool):
    body = b'{"name":"x"}' if json_body else None
    headers = {"User-Agent": UA}
    if json_body:
        headers["Content-Type"] = "application/json"
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    out = resp.read()
    conn.close()
    return resp.status, len(out), out[:80].decode("utf-8", "replace")


def run_case(label: str, case: str, method: str, path: str, json_body: bool,
             port: int) -> dict:
    ruby, gems = RUBIES[label], GEMS[label]
    log_path = EV / f"{label}-{case}.server.log"
    env = os.environ.copy()
    env["GEM_PATH"] = str(gems) + ((":" + env["GEM_PATH"]) if env.get("GEM_PATH") else "")
    env["RAILS_MAX_THREADS"] = "1"
    env["UBSAN_OPTIONS"] = "halt_on_error=0:print_stacktrace=0"
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0"
    pid_path = EV / f"{label}-{case}.pid"
    command = [str(ruby), str(APP / "bin/rails"), "server", "-b", "127.0.0.1",
               "-p", str(port), "--pid", str(pid_path)]
    row = {"label": label, "case": case, "method": method, "path": path}
    with log_path.open("wb") as log:
        proc = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log,
                                stderr=subprocess.STDOUT, preexec_fn=no_core)
        try:
            row["ready"] = wait_ready(proc, port)
            if row["ready"]:
                before = log_path.read_bytes().count(b"ERROR: AddressSanitizer")
                try:
                    status, nbytes, head = request(port, method, path, json_body)
                    row.update(status=status, bytes=nbytes, head=head)
                except OSError as exc:
                    row["status"] = repr(exc)
                after = log_path.read_bytes().count(b"ERROR: AddressSanitizer")
                row["asan_new"] = after - before
                text = log_path.read_text(errors="replace")
                row["asan_summary"] = next((line for line in reversed(text.splitlines())
                                            if "SUMMARY: AddressSanitizer" in line), None)
                row["sink_stack"] = [line.strip() for line in text.splitlines()
                                     if "params_wrapper.rb:" in line or
                                     "inflector/methods.rb:" in line or
                                     "str_lower_case_match" in line][-12:]
                try:
                    alive_status, _, _ = request(port, "GET", "/up", False)
                    row["alive_after"] = alive_status
                except OSError:
                    row["alive_after"] = None
            row["proc_rc"] = proc.poll()
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            pid_path.unlink(missing_ok=True)
    return row


def main() -> None:
    EV.mkdir(parents=True, exist_ok=True)
    prepare_app()
    rows = []
    port = 4640
    for label in ("affected", "fixed"):
        for case, method, path, json_body in CASES:
            rows.append(run_case(label, case, method, path, json_body, port))
            port += 1
    (EV / "summary.json").write_text(
        json.dumps({"app": str(APP.relative_to(ROOT)), "rows": rows},
                   ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for row in rows:
        print(json.dumps({k: row.get(k) for k in
                          ("label", "case", "ready", "status", "bytes",
                           "asan_new", "alive_after", "asan_summary")},
                         ensure_ascii=False))


if __name__ == "__main__":
    main()
