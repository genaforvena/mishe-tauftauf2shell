#!/usr/bin/env python3
"""Analysis driver: send all requests of one ruby2shell chain over ONE TCP
connection (HTTP/1.1 keep-alive). Loopback only. No payload generation, no
instrumentation: bodies are the files built by ruby2shell-shrink-claim.sh.

Usage: python3 ruby2shell-keepalive-post.py PORT LABEL:ROUTE:BODYFILE [ ... ]
       a GET request has BODYFILE '-' and uses ROUTE directly.
Prints LABEL=status lines; 000 means the connection/process died.
"""
import http.client
import sys


def main():
    port = int(sys.argv[1])
    specs = sys.argv[2:]
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=40)
    dead = False
    for spec in specs:
        label, route, bodyfile = spec.split(':', 2)
        status = '000'
        if not dead:
            try:
                if bodyfile == '-':
                    conn.request('GET', route)
                else:
                    with open(bodyfile, 'rb') as fh:
                        body = fh.read()
                    conn.request('POST', route, body=body,
                                 headers={'Content-Type':
                                          'multipart/form-data; boundary=XB'})
                res = conn.getresponse()
                res.read()
                status = str(res.status)
                if status == '000' or res.will_close:
                    dead = True
            except Exception as exc:  # server aborted / connection closed
                print(f'# {label}: {type(exc).__name__}: {exc}',
                      file=sys.stderr)
                dead = True
                status = '000'
        print(f'{label}={status}', flush=True)
    try:
        conn.close()
    except Exception:
        pass


if __name__ == '__main__':
    main()
