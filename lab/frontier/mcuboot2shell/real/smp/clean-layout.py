"""GDB probe of the clean-groom no-groom build's OOB window.

Runs smp-serial-nogroom under gdb on 127.0.0.1, drives one fragmented SMP
image upload, and dumps the stack words around the saved return slots just
before the pinned decryptor's OOB write. Usage: python3 clean-layout.py HDR.
Output: evidence/clean-layout.txt. No external traffic.
"""
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
HDR = int(sys.argv[1]) if len(sys.argv) > 1 else 4104
TMP = tempfile.mkdtemp(prefix="m2s-clean-layout-")
OUT = os.path.join(HERE, "evidence", "clean-layout.txt")

SCRIPT = f"""set pagination off
set confirm off
break smp-host.c:78 if off == 4096
commands
 silent
 printf "=== BEFORE_DECRYPT base=%p buf=%p off=%u ===\\n", g_buf_base, buf, off
 x/8gx g_buf_base+5040
 x/8gx g_buf_base+5080
 x/8gx g_buf_base+5680
 continue
end
run > {TMP}/server.log
bt 8
"""

open(os.path.join(TMP, "probe.gdb"), "w").write(SCRIPT)
with open(OUT, "w") as out:
    gdb = subprocess.Popen(["gdb", "-q", "-batch", "-x", os.path.join(TMP, "probe.gdb"),
                            "./smp-serial-nogroom"], cwd=HERE,
                           stdout=out, stderr=subprocess.STDOUT)
    port = None
    for _ in range(100):
        try:
            port = open(os.path.join(TMP, "server.log")).readline().strip().split("=")[1]
        except (FileNotFoundError, IndexError):
            port = None
        if port:
            break
        time.sleep(0.1)
    if not port:
        gdb.kill()
        raise SystemExit("no PORT from loopback server")
    with open(os.path.join(TMP, "client.log"), "w") as clog:
        client = subprocess.Popen(["python3", "client.py", port, str(HDR),
                                   "fragmented", "clean"], cwd=HERE,
                                  stdout=clog, stderr=subprocess.STDOUT)
        gdb.wait(timeout=90)
        client.wait(timeout=30)
print("CLEAN_LAYOUT_DONE", OUT)
