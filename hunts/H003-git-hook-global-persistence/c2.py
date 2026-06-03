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
