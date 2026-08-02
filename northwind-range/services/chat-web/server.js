const http = require('http');

const STUB_NOTE = 'chat-web stub -- milestone 7 replaces this with the real Next.js chat UI';

http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200);
    res.end('ok');
  } else {
    res.writeHead(404);
    res.end(STUB_NOTE);
  }
}).listen(3000, '0.0.0.0');
