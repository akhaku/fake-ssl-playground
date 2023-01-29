const http = require('http');
const {
  RecordType,
  TlsRecord,
} = require('./types');

const server = http.createServer((req, res) => {
  const path = req.url.split('?')[0]
  const buffers = [];
  req.on('data', chunk => buffers.push(chunk));
  req.on('end', () => {
    try {
      const byteArray = new Uint8Array(Buffer.concat(buffers));
      const tlsRecord = new TlsRecord(byteArray);
      switch (tlsRecord.getRecordType()) {
        case RecordType.HANDSHAKE:
          // proceed to next phase if path == ClientHello
          break;
        default:
          // other handling?
          break;
      }
      res.writeHead(200);
      res.end(`Hello world for ${path} with record ${tlsRecord.getRecordType()}`);
    } catch (error) {
      console.error(error);
      res.writeHead(500).end("foo");
    }
  });
});
server.listen(8000, 'localhost', () => {
  console.log('Server active at localhost:8000');
});
