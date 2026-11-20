// node2shell rung-1 harness — server side (CVE-2026-123828)
//
// Mirrors the application precondition named in the official advisory:
// the app passes the request :authority (attacker-controlled) into
// Http2Session.altsvc() as the origin argument. Loopback only.
//
// Usage: node node2shell-rung1-server.js [port] [alt]
//   port — 127.0.0.1 port to listen on (0 = ephemeral; prints LISTEN <port>)
//   alt  — ALTSVC field value (default short constant 'h2=":8000"')
//
// origin handed to session.altsvc is 'https://' + :authority, so the
// attacker controls the MaybeStackBuffer allocation length as
// origin_len = 8 + authority_len. Heap-backed requires origin_len > 1024
// (MaybeStackBuffer stack storage), and the C++ CHECK caps
// origin_len + value_len <= 16382.
//
// Uses the raw 'stream' event (compat request-callback streams do not
// expose .session), matching the shape of Node's own upstream test
// test/parallel/test-http2-altsvc.js.

'use strict';
const http2 = require('http2');

const port = Number(process.argv[2]) || 0;
// Wake 11: ALT_HEX carries arbitrary ALTSVC value bytes (including NUL)
// as hex; process.argv cannot carry NUL. Used to place an attacker-
// controlled [odd][NUL][zeros] fake sizefield inside the frame copy.
const alt = process.env.ALT_HEX
  ? Buffer.from(process.env.ALT_HEX, 'hex').toString('latin1')
  : (process.argv[3] || 'h2=":8000"');

const server = http2.createServer();

server.on('stream', (stream, headers) => {
  const origin = 'https://' + headers[':authority'];
  stream.session.altsvc(alt, origin);
  stream.respond({ ':status': 200 });
  stream.end('ok');
});

server.on('error', (e) => {
  console.log('SERVER-ERROR ' + e.message);
  process.exit(3);
});

server.listen(port, '127.0.0.1', () => {
  console.log('LISTEN ' + server.address().port);
});
