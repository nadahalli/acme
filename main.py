#!/usr/bin/python3

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import ProcessPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import BaseRequestHandler, UDPServer
from ssl import wrap_socket

import argparse
import io
import os
import struct
import re
import sys

FILE_PATH = 'files/'
DNS_HEADER = '!HBBHHHH'
DNS_HEADER_SIZE = struct.calcsize(DNS_HEADER)
DNS_DOMAIN_PATTERN = re.compile('^[A-Za-z0-9\-\.\_]+$')

class AcmeDNSChallengeHandler(BaseRequestHandler):
    def parse(self, data):
        dns_request = DNSRecord.parse(data)
        print(dns_request)
        
    def handle(self):
        socket = self.request[1]
        data = self.request[0]
        data_stream = io.BytesIO(data)

        (request_id, header_a, header_b, qd_count, an_count, ns_count, ar_count) = struct.unpack(DNS_HEADER, data_stream.read(DNS_HEADER_SIZE))

        q = None

        if qd_count != 1:
            return
        
        name_parts = []
        length = struct.unpack('B', data_stream.read(1))[0]
        while length != 0:
            name_parts.append(data_stream.read(length).decode('us-ascii'))
            length = struct.unpack('B', data_stream.read(1))[0]
        name = '.'.join(name_parts)

        (qtype, qclass) = struct.unpack('!HH', data_stream.read(4))

        q = {'name': name,
             'type': qtype,
             'class': qclass};

        ans = ''

        try:
            apath = FILE_PATH + q['name'].lower()
            afile = open(apath, 'r')
            ans = afile.read().strip()
            afile.close()
        except:
            pass

        response = io.BytesIO()

        response_header = struct.pack(DNS_HEADER, request_id, 0b10000100, 0b00000000, qd_count, 1, 0, 0)
        response.write(response_header)

        for part in q['name'].split('.'):
            response.write(struct.pack('B', len(part)))
            response.write(part.encode('us-ascii'))
        response.write(b'\x00')
        response.write(struct.pack('!HH', q['type'], q['class']))

        response.write(b'\xc0\x0c')
        response.write(struct.pack('!HH', 16, 1))
        response.write(struct.pack('!I', 0))
        response.write(struct.pack('!H', len(ans) + 1))
        response.write(struct.pack('B', len(ans)))
        response.write(ans.encode('us-ascii'))

        print('Asked about', q['name'], 'and anwered with', response.getvalue())
        socket.sendto(response.getvalue(), self.client_address)

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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Do some stuff')
    parser.add_argument('challenge', metavar='CHALLENGE', help='Type of challenge')
    parser.add_argument('--dir', metavar='DIR_URL', help='URL of the ACME server', required=True)
    parser.add_argument('--record', metavar='IPv4 ADDRESS', help='IPv4 address which must be returned by the DNS server for all A-record queries', required=True)
    parser.add_argument('--domain', metavar='DOMAIN', help='DOMAIN is the domain for which to request the certificate', required=True, action='append')
    parser.add_argument('--revoke', metavar='REVOKE', help='Should be a revoked certificate')
    
    args = parser.parse_args()

    with ThreadPoolExecutor(max_workers=4) as executor:
        acme_dns_challenge_server = UDPServer(('', 10053), AcmeDNSChallengeHandler)
        
        acme_http_challenge_server = HTTPServer(('', 5002), AcmeHTTPChallengeHandler)

        certificate_server = HTTPServer(('', 5001), CertificateHandler)
        """
        certificate_server.socket = wrap_socket(certificate_server.socket,
                                            keyfile='./key.pem',
                                            certfile='./cert.pem',
                                            server_side=True)
        """
        shutdown_server = HTTPServer(('', 5003), ShutdownHandler)
        
        executor.submit(acme_dns_challenge_server.serve_forever)
        executor.submit(acme_http_challenge_server.serve_forever)
        executor.submit(certificate_server.serve_forever)
        executor.submit(shutdown_server.serve_forever)
