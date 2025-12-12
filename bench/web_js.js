const http = require("http");

const handler = (_req, res) => {
  res.statusCode = 200;
  res.setHeader("Content-Type", "text/plain");
  res.end("ok");
};

const server = http.createServer(handler);
server.listen(9311, () => {
  // keep running
});
