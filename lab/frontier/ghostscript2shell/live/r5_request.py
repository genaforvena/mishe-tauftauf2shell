#!/usr/bin/env python3
"""Send one lab upload request to the loopback r5 service.

Usage: r5_request.py PORT DOC_PATH FONT_PATH
Prints the service's JSON response verbatim. No external network access.
"""

import base64
import json
import sys
import urllib.request

port, docpath, fontpath = int(sys.argv[1]), sys.argv[2], sys.argv[3]
body = json.dumps({
    "doc": base64.b64encode(open(docpath, "rb").read()).decode(),
    "font": base64.b64encode(open(fontpath, "rb").read()).decode(),
}).encode()
request = urllib.request.Request(
    f"http://127.0.0.1:{port}/upload",
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(request, timeout=60) as response:
    print(response.read().decode())
