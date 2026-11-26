#!/usr/bin/env python3
"""Loopback-only static server that reports its ephemeral port to a file.

Used by run-wire-consumer.sh to feed a crafted rpm to rpm's own %_urlhelper.
Nothing outside 127.0.0.1 is served or contacted.
"""
import http.server
import os
import sys


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))
        sys.stderr.flush()


def main():
    os.chdir(sys.argv[1])
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    with open(sys.argv[2], "w") as port_file:
        port_file.write("%d\n" % server.server_address[1])
    server.serve_forever()


if __name__ == "__main__":
    main()
