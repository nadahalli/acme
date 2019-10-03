from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import ProcessPoolExecutor
from dnslib import DNSRecord
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import BaseRequestHandler, UDPServer
from ssl import wrap_socket

import os

class AcmeDNSChallengeHandler(BaseRequestHandler):
    def parse(self, data):
        dns_request = DNSRecord.parse(data)
        print(dns_request)
        
    def handle(self):
        data = self.request[0].strip()
        self.parse(data)
        socket = self.request[1]
        socket.sendto('Ack', self.client_address)

class AcmeHTTPChallengeHandler(BaseHTTPRequestHandler):
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

with ThreadPoolExecutor(max_workers=4) as executor:
    acme_dns_challenge_server = UDPServer(('', 10053), AcmeDNSChallengeHandler)
    
    acme_http_challenge_server = HTTPServer(('', 5002), AcmeHTTPChallengeHandler)

    certificate_server = HTTPServer(('', 5001), CertificateHandler)
    certificate_server.socket = wrap_socket(certificate_server.socket,
                                            keyfile='./key.pem',
                                            certfile='./cert.pem',
                                            server_side=True)
    shutdown_server = HTTPServer(('', 5003), ShutdownHandler)

    executor.submit(acme_dns_challenge_server.serve_forever)
    executor.submit(acme_http_challenge_server.serve_forever)
    executor.submit(certificate_server.serve_forever)
    executor.submit(shutdown_server.serve_forever)
