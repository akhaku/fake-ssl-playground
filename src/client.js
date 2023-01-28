const http = require('http');

http.get('http://localhost:8000/', res => {
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
