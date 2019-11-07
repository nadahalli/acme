#!/usr/bin/python3

from binascii import hexlify, unhexlify
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import ProcessPoolExecutor
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography import x509
from cryptography.x509.oid import NameOID
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import BaseRequestHandler, UDPServer
from ssl import wrap_socket

import argparse
import base64
import io
import json
import os
import prettyprinter
import random
import re
import requests
import struct
import struct
import sys
import time

FILE_PATH = 'files/'
DNS_HEADER = '!HBBHHHH'
DNS_HEADER_SIZE = struct.calcsize(DNS_HEADER)
DNS_DOMAIN_PATTERN = re.compile('^[A-Za-z0-9\-\.\_]+$')

NEW_ACCOUNT_URL = None
NONCE_URL = None
NEW_ORDER_URL = None
REVOKE_CERT_URL = None

ACME_SERVER_CERT = './pebble_https_ca.pem'

prettyprinter.install_extras(['requests'])

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

def encode_json_as_bytes(j):
    return json.dumps(j, separators=(',', ':'), sort_keys=True).encode('utf-8')

def base64_encode_as_bytes(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=').encode('utf-8')

def base64_encode_as_string(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def get_nonce():
    r = requests.head(NONCE_URL, verify=ACME_SERVER_CERT)
    return r.headers['Replay-Nonce']

def get_large_int_as_bytes(i, size):
    padding = ((size + 7) // 8) * 2
    hi = hex(i).rstrip("L").lstrip("0x")
    length = len(hi)
    if padding > length:
        padding -= length
    else:
        padding = length % 2
    return unhexlify(padding * '0' + hi)

def get_large_int_as_base64(i, size):
    return base64_encode_as_string(get_large_int_as_bytes(i, size))

def get_jwk(private_key):
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers
    size = public_numbers.curve.key_size
    jwk = {}
    jwk['kty'] = 'EC'
    jwk['crv'] = 'P-256'
    jwk['x'] = get_large_int_as_base64(public_numbers.x, size)
    jwk['y'] = get_large_int_as_base64(public_numbers.y, size)
    return jwk

def sign(private_key, data):
    signature = decode_dss_signature(private_key.sign(data, ec.ECDSA(hashes.SHA256())))
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers
    size = public_numbers.curve.key_size
    return base64_encode_as_string(get_large_int_as_bytes(signature[0], size) + get_large_int_as_bytes(signature[1], size))

def hash_256(data_as_bytes):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data_as_bytes)
    return digest.finalize()

def get_jwk_thumbprint(private_key):
    return base64_encode_as_bytes(hash_256(encode_json_as_bytes(get_jwk(private_key))))

def get_jws_params(private_key, url, kid=None):
    jws_params = {}
    jws_params['typ'] = 'JWT'
    jws_params['alg'] = 'ES256'
    jws_params['url'] = url
    jws_params['nonce'] = get_nonce()

    if kid:
        jws_params['kid'] = kid
    else:
        jws_params['jwk'] = get_jwk(private_key)

    return jws_params


def jws_encode_sign(private_key, payload_dict, jws_params):
    to_be_signed = base64_encode_as_bytes(encode_json_as_bytes(jws_params)) + b'.'
    if payload_dict != None:
        to_be_signed +=  base64_encode_as_bytes(
            encode_json_as_bytes(payload_dict))
    else:
        to_be_signed += b''

    return sign(private_key, to_be_signed)

def make_request(private_key, account, url, payload, count = 10):
    if (count == 0):
        return
    request_headers = {}
    request_headers['Content-Type'] = 'application/jose+json'

    jws_params = get_jws_params(private_key, url, account)

    data = {
        'payload': base64_encode_as_string(encode_json_as_bytes(payload)) if payload != None else '',
        'signature': jws_encode_sign(private_key, payload, jws_params),
        'protected': base64_encode_as_string(encode_json_as_bytes(jws_params)),
    }

    r = requests.post(url, data=json.dumps(data), headers=request_headers, verify=ACME_SERVER_CERT)

    prettyprinter.pprint(r.headers)

    try:
        if r.json().get('type') == 'urn:ietf:params:acme:error:badNonce':
            print('Retrying due to bad nonce....')
            return make_request(private_key, account, url, payload, count - 1)
        else:
            return r.headers, r.json()
    except json.decoder.JSONDecodeError:
        return r.headers, r.text

def new_account(private_key):
    payload = {}
    payload['Contact'] = []
    payload['TermsOfServiceAgreed'] = True
    payload['OnlyReturnExisting'] = False

    headers, response = make_request(private_key, None, NEW_ACCOUNT_URL, payload)

    print('ACCOUNT')
    prettyprinter.pprint(response)

    return headers['Location']

def new_order(domains, private_key, account):
    payload = {}
    ids = []
    for domain in domains:
        ids.append({
            'type': 'dns',
            'value': domain
        })
    payload['identifiers'] = ids

    headers, response = make_request(private_key, account, NEW_ORDER_URL, payload)
    response['order_url'] = headers['Location']
    print('ORDER')
    prettyprinter.pprint(response)
    return response

def auths(private_key, account, auths):
    payload = None
    result = []
    for url in auths:
        _, response = make_request(private_key, account, url, payload)
        print('AUTH_RESPONSE')
        prettyprinter.pprint(response)
        challenges = response['challenges']
        for c in challenges:
            c['domain'] = response['identifier']['value']
        result.extend(response['challenges'])
    return result

def prompt_dns_challenge(private_key, account, url):
    payload = {}
    make_request(private_key, account, url, payload)

def prepare_dns_response(private_key, challenge):
    to_be_hashed = bytes(challenge['token'], 'utf-8') + b'.' + get_jwk_thumbprint(private_key)
    txt_record = base64_encode_as_string(hash_256(to_be_hashed))
    f = open(FILE_PATH + '_acme-challenge.' + challenge['domain'], 'w')
    f.write(txt_record)
    f.close()

def do_dns_challenge(domains, private_key, account, order):
    challenges = auths(private_key, account, order['authorizations'])
    for c in challenges:
        if c['type'] == 'dns-01':
            prepare_dns_response(private_key, c)

    for c in challenges:
        if c['type'] == 'dns-01':
            prompt_dns_challenge(private_key, account, c['url'])

def make_csr_request(domains, private_key, account, order):
    x509_dnsnames = []
    for domain in domains:
        x509_dnsnames.append(x509.DNSName(domain))
                             
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'CH'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Schwyz'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'Wollerau'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Intamin'),
    ])).add_extension(x509.SubjectAlternativeName(x509_dnsnames), critical=False).sign(private_key, hashes.SHA256(), default_backend())

    payload = {}
    payload['csr'] = base64_encode_as_string(csr.public_bytes(serialization.Encoding.DER))
    headers, response = make_request(private_key, account, order['finalize'], payload)
    print('CSR_RESPONSE')
    prettyprinter.pprint(response)

def poll_order(private_key, account, order):
    payload = None
    headers, response = make_request(private_key, account, order['order_url'], payload)
    print('Polling response')
    prettyprinter.pprint(response)
    return response

def download_certificate(private_key, account, order):
    payload = None
    headers, response = make_request(private_key, account, order['certificate'], payload)
    print('CERTIFICATE_RESPONSE')
    prettyprinter.pprint(response)
    return response
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Do some stuff')
    parser.add_argument('challenge', metavar='CHALLENGE', help='Type of challenge')
    parser.add_argument('--dir', metavar='DIR_URL', help='URL of the ACME server', required=True, dest='dir_url')
    parser.add_argument('--record', metavar='IPv4 ADDRESS', help='IPv4 address which must be returned by the DNS server for all A-record queries', required=True)
    parser.add_argument('--domain', metavar='DOMAIN', help='DOMAIN is the domain for which to request the certificate', required=True, action='append', dest='domains')
    parser.add_argument('--revoke', metavar='REVOKE', help='Should be a revoked certificate')
    
    args = parser.parse_args()

    executor = ThreadPoolExecutor(max_workers=4)

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
    print('here')

    dir_listing = requests.get(args.dir_url, verify=ACME_SERVER_CERT).json()
    NEW_ACCOUNT_URL = dir_listing['newAccount']
    NONCE_URL = dir_listing['newNonce']
    NEW_ORDER_URL = dir_listing['newOrder']
    REVOKE_CERT_URL = dir_listing['revokeCert']

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    account = new_account(private_key)
    order = new_order(args.domains, private_key, account)
    do_dns_challenge(args.domains, private_key, account, order)
    time.sleep(10)
    print('------------FIRST---------------')
    make_csr_request(args.domains, private_key, account, order)
    time.sleep(10)
    print('------------SECOND---------------')
    order = poll_order(private_key, account, order)
    certificate = download_certificate(private_key, account, order)
    certf = open('cert.pem', 'w')
    certf.write(certificate)
    certf.close()
        

    

