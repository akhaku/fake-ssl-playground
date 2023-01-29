const http = require('http');

const req = http.request({
  host: '127.0.0.1',
  port: 8000,
  method: 'POST',
  path: '/ClientHello',
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

req.write(new ClientHello().getByteArray());
req.end();
