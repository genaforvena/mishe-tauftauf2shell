'use strict';
const http2 = require('http2');
const port = Number(process.argv[2]);
const n = Number(process.argv[3] || 1040);
const client = http2.connect('http://127.0.0.1:' + port);
client.on('error', () => process.exit(1));
client.on('altsvc', (alt, origin, stream) => {
  console.log('ALTSVC origin_len=' + origin.length); process.exit(0);
});
const req = client.request({ ':authority': 'a'.repeat(n) });
req.resume();
setTimeout(() => process.exit(2), 8000).unref();
