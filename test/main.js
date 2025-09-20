const http = require("http");
const fs = require("fs");

const server = http.createServer((req, res) => {
    fs.readFile("file.txt", "utf8", (err, data) => {
        if (err || !data) {
            res.writeHead(404, { "Content-Type": "text/plain" });
            res.end("Not found");
        } else {
            res.writeHead(200, { "Content-Type": "text/html" });
            res.end(data);
        }
    });
});

server.listen(8080, () => {
    console.log("Server running on http://localhost:8080");
});