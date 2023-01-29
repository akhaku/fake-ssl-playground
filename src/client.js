const http = require('http');
const {createClientHello} = require('./tls-handler');

const req = http.request({
  host: 'localhost',
  port: 8000,
  method: 'POST',
  path: '/ClientHello?foo',
}, res => {
  const status = res.statusCode;
  if (status !== 200) {
    console.warn(`Error ${status}`);
    res.resume();
    return;
  }
  let body = '';
  res.on('data', chunk => body += chunk);
  res.on('close', () => {
    console.log(body);
  });
});

req.write(createClientHello().getByteArray());
req.end();
