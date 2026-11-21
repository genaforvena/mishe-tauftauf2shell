#!/usr/bin/env python3
"""gdb breakpoint trace for L5 (loopback only).

Runs the 2.4.68 ASan build under `httpd -X` and stops at every
dump_content() call, printing the caller and the varbuf state.
"""
import importlib.util
import os
import socket
import subprocess
import time

BASE = "/home/mesh-home/mishe-tauftauf2shell/lab/apache2shell"
os.environ["L5_SUFFIX"] = "gdb"
spec = importlib.util.spec_from_file_location("l5lane", os.path.join(BASE, "l5-lane.py"))
lane = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lane)

PORT = 7290
conf = os.path.join(lane.RUN, "l5-gdb.conf")
open(conf, "w").write(lane.conf_for("2.4.68", PORT))
os.makedirs(lane.DOCROOT, exist_ok=True)
body = os.environ.get("L5_BODY", '<p title="AAAAAAAAAA">x</p><!--trigger-->')
open(os.path.join(lane.DOCROOT, "index.html"), "w").write(body)

root = lane.os.path.join(lane.ROOT, "install-2.4.68-asan")
err = os.path.join(lane.LOGS, "l5-gdb-error.log")
if os.path.exists(err):
    os.unlink(err)

env = dict(os.environ)
env["ASAN_OPTIONS"] = "detect_leaks=0:handle_segv=0:abort_on_error=0"
cmds_file = os.path.join(lane.RUN, "l5-gdb.cmds")
open(cmds_file, "w").write("\n".join([
    "set pagination off",
    "set breakpoint pending on",
    "break dump_content",
    "commands",
    "silent",
    'printf "==== HIT dump_content ====\\n"',
    "bt 8",
    "print ctx->vb.strlen",
    "print ctx->vb.buf",
    "print ctx->map",
    "print *ctx->map",
    "print *ctx->cfg",
    "continue",
    "end",
    "run",
    "",
]))
cmd = ["gdb", "-q", "-batch", "-x", cmds_file,
       "--args", os.path.join(root, "bin", "httpd"), "-X", "-f", conf]
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, env=env, cwd=root)
time.sleep(6.0)
for i in range(2):
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=3)
        s.sendall(("GET /index.html HTTP/1.1\r\nHost: localhost\r\n"
                   "Connection: close\r\n\r\n").encode())
        data = s.recv(65536)
        print("response head:", data.split(b"\r\n", 1)[0].decode(errors="replace"))
        print("response body:", data.split(b"\r\n\r\n", 1)[-1][:200])
        s.close()
    except Exception as e:
        print("request %d: %s" % (i, e))
time.sleep(1.0)
try:
    p.stdin.write(b"kill\n")
    p.stdin.flush()
except (BrokenPipeError, OSError):
    pass
try:
    out, _ = p.communicate(timeout=20)
except subprocess.TimeoutExpired:
    p.kill()
    out, _ = p.communicate()
text = out.decode(errors="replace")
path = os.path.join(lane.LOGS, "l5-gdb-trace.txt")
open(path, "w").write(text)
print("gdb output saved ->", path)
for line in text.splitlines():
    if "HIT dump_content" in line or "dump_content (" in line or "pcomment" in line or "vb.strlen" in line or "vb.buf" in line:
        print(line)
