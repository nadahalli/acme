from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler

class AcmeChallengeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()
        self.wfile.write(b"Hello World !")
        return

with ThreadPoolExecutor(max_workers=1) as executor:
    acme_challenge_server = HTTPServer(('', 5002), AcmeChallengeHandler)
    future = acme_challenge_server.serve_forever()
    print(future.result())

