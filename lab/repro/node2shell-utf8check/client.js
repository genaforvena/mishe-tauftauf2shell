// node2shell — closed-channel check (wake 24), client side.
//
// Sends one :authority built from a repeated UTF-8 hex pattern, so we can
// test whether Node decodes multi-byte UTF-8 into a JS code point whose
// low byte is 0x00 (U+0100 from c4 80). WriteOneByteV2 would emit that low
// byte into the origin buffer if nghttp2 accepted the header.
//
// Usage: node client.js <port> <hex-pattern> <repetitions>
'use strict';
const http2 = require('http2');

const port = Number(process.argv[2]);
const hex = process.argv[3];
const reps = Number(process.argv[4]);
if (!port || !hex || !reps) {
  console.log('usage: node client.js <port> <hex-pattern> <repetitions>');
  process.exit(1);
}

const unit = Buffer.from(hex, 'hex').toString('utf8');
const authority = unit.repeat(reps);
console.log('AUTHORITY codeunits=' + authority.length +
            ' first4=' + JSON.stringify(authority.slice(0, 4)));

const client = http2.connect('http://127.0.0.1:' + port);
client.on('error', (e) => { console.log('CLIENT-ERROR ' + e.message); process.exit(1); });
client.on('altsvc', (alt, origin, stream) => {
  console.log('ALTSVC origin_len=' + origin.length + ' stream=' + stream);
  client.destroy();
  process.exit(0);
});

const req = client.request({ ':authority': authority });
req.resume();
req.on('error', (e) => { console.log('STREAM-ERROR ' + e.message); });
req.on('end', () => {});
setTimeout(() => { console.log('TIMEOUT'); process.exit(2); }, 5000).unref();
