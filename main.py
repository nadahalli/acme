from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import ProcessPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
from ssl import wrap_socket

import os

class AcmeChallengeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()
        self.wfile.write(b"Hello World!\n")
        return

class CertificateHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()
        self.wfile.write(b"Hello World!\n")
        return

class ShutdownHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if (self.path == '/shutdown'):
            os.kill(os.getpid(), 9)

def ShutdownHandlerCreator(servers):
    return lambda *args: ShutdownHandler(servers, *args)

with ThreadPoolExecutor(max_workers=3) as executor:
    acme_challenge_server = HTTPServer(('', 5002), AcmeChallengeHandler)

    certificate_server = HTTPServer(('', 5001), CertificateHandler)
    certificate_server.socket = wrap_socket(certificate_server.socket,
                                            keyfile='./key.pem',
                                            certfile='./cert.pem',
                                            server_side=True)
    shutdown_server = HTTPServer(('', 5003), ShutdownHandler)

    executor.submit(acme_challenge_server.serve_forever)
    executor.submit(certificate_server.serve_forever)
    executor.submit(shutdown_server.serve_forever)
