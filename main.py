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
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, A, DNSQuestion, TXT, QTYPE
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.client import parse_headers
from socketserver import BaseRequestHandler, UDPServer

import argparse
import base64
import io
import json
import os
import random
import re
import requests
import socket
import ssl
import struct
import struct
import sys
import time

import socketserver
import argparse
import io

FILE_PATH = 'files/'
try:
    os.mkdir(FILE_PATH)
except:
    pass

DEBUG = True

DNS_HEADER = '!HBBHHHH'
DNS_HEADER_SIZE = struct.calcsize(DNS_HEADER)
DNS_DOMAIN_PATTERN = re.compile('^[A-Za-z0-9\-\.\_]+$')

NEW_ACCOUNT_URL = None
NONCE_URL = None
NEW_ORDER_URL = None
REVOKE_CERT_URL = None

ACME_SERVER_CERT = './pebble_https_ca.pem'

if DEBUG:
    import prettyprinter
    prettyprinter.install_extras(['requests'])

def read_answer(name):
    ans = ''
    try:
        apath = FILE_PATH + name.lower()
        print('Trying to open file ', apath)
        afile = open(apath, 'r')
        ans = afile.read().strip()
        afile.close()
    except:
        pass
    return ans


class AcmeDNSChallengeHandler(BaseRequestHandler):
    ip = None
        
    def handle(self):
        data = self.request[0]
        socket = self.request[1]
    
        d = DNSRecord.parse(data)
        q = d.questions[0]
        name = 'dns.' + '.'.join(map(lambda x: x.decode('utf-8'), q.qname.label[1:]))

        ans = read_answer(name)

        a = d.reply()
        a.add_answer(RR(name, QTYPE.A, rdata=A(self.ip)))
        a.add_answer(RR(name, QTYPE.TXT,rdata=TXT(ans)))
        print('Asked about', name, 'and anwered with', a.pack())
        socket.sendto(a.pack(), self.client_address)


class AcmeHTTPChallengeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()
        name = 'http.' + self.headers['Host'].split(':')[0]
        answer = read_answer(name)
        print('-' * 10, answer)
        self.wfile.write(answer.encode('utf-8'))
        return

class CertificateServer:
    def __init__(self, host, port, cert, key):
        self.sock = socket.socket()
        self.sock.bind((host, port))
        self.sock.listen(5)
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile=cert, keyfile=key)

    def handle(self, conn):
        conn.write(b'HTTP/1.1 200 OK\n\n%s' % conn.getpeername()[0].encode())
        
    def serve_forever(self):
        while True:
            conn = None
            ssock, addr = self.sock.accept()
            try:
                conn = self.context.wrap_socket(ssock, server_side=True)
                self.handle(conn)
            except ssl.SSLError as e:
                print(e)
            finally:
                if conn:
                    conn.close()

class ShutdownHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if DEBUG:
            print('Shutdown called')
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

    if DEBUG: prettyprinter.pprint(r.headers)

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

    if DEBUG:
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

    if DEBUG:
        print('ORDER')
        prettyprinter.pprint(response)
        
    return response

def auths(private_key, account, auths):
    payload = None
    result = []
    for url in auths:
        _, response = make_request(private_key, account, url, payload)
        if DEBUG:
            print('AUTH_RESPONSE')
            prettyprinter.pprint(response)
        challenges = response['challenges']
        for c in challenges:
            c['domain'] = response['identifier']['value']
            result.append(c)
    return result

def prompt_challenge(private_key, account, url):
    payload = {} # this is important
    make_request(private_key, account, url, payload)

def prepare_response(private_key, challenge):
    to_be_hashed = bytes(challenge['token'], 'utf-8') + b'.' + get_jwk_thumbprint(private_key)
    f = open(FILE_PATH + 'http.' + challenge['domain'], 'w')
    f.write(to_be_hashed.decode('utf-8'))
    f.close()
    txt_record = base64_encode_as_string(hash_256(to_be_hashed))
    f = open(FILE_PATH + 'dns.' + challenge['domain'], 'w')
    f.write(txt_record)
    f.close()

def do_challenge(challenge_type, domains, private_key, account, order):
    challenges = auths(private_key, account, order['authorizations'])
    to_look_for = ''
    if challenge_type == 'dns01': to_look_for = 'dns-01'
    if challenge_type == 'http01': to_look_for = 'http-01'
    for c in challenges:
        if c['type'] == to_look_for:
            prepare_response(private_key, c)
            prompt_challenge(private_key, account, c['url'])

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
    if DEBUG:
        print('CSR_RESPONSE')
        prettyprinter.pprint(response)

def poll_order(private_key, account, order):
    payload = None
    headers, response = make_request(private_key, account, order['order_url'], payload)
    if DEBUG:
        print('Polling response')
        prettyprinter.pprint(response)
    return response

def download_certificate(private_key, account, order):
    payload = None
    headers, response = make_request(private_key, account, order['certificate'], payload)
    if DEBUG:
        print('CERTIFICATE_RESPONSE')
        prettyprinter.pprint(response)
    return response

def revoke_certificate(private_key, account, certificate_pem):
    cert = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8'), default_backend())
    payload = {}
    payload['certificate'] = base64_encode_as_string(cert.public_bytes(serialization.Encoding.DER))
    payload['reason'] = 4
    headers, response = make_request(private_key, account, REVOKE_CERT_URL, payload)
    if DEBUG:
        print('REVOKE_HEADERS')
        prettyprinter.pprint(headers)
        print('REVOKE_RESPONSE')
        prettyprinter.pprint(response)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Do some stuff')
    parser.add_argument('challenge', help='Type of challenge')
    parser.add_argument('--dir', help='URL of the ACME server', required=True, dest='dir_url')
    parser.add_argument('--record', help='IPv4 address which must be returned by the DNS server for all A-record queries', required=True)
    parser.add_argument('--domain', help='DOMAIN is the domain for which to request the certificate', required=True, action='append', dest='domains')
    parser.add_argument('--revoke', help='Should be a revoked certificate', action='store_true', dest='revoke')
    parser.add_argument('--no-revoke', help='Should be a revoked certificate', action='store_true', dest='revoke')
    parser.set_defaults(feature=False)
    
    args = parser.parse_args()

    executor = ThreadPoolExecutor(max_workers=4)

    AcmeDNSChallengeHandler.ip = args.record

    acme_dns_challenge_server = UDPServer(('', 10053), AcmeDNSChallengeHandler)
    acme_http_challenge_server = HTTPServer((args.record, 5002), AcmeHTTPChallengeHandler)
    shutdown_server = HTTPServer(('', 5003), ShutdownHandler)
        
    executor.submit(acme_dns_challenge_server.serve_forever)
    executor.submit(acme_http_challenge_server.serve_forever)
    executor.submit(shutdown_server.serve_forever)

    dir_listing = requests.get(args.dir_url, verify=ACME_SERVER_CERT).json()
    NEW_ACCOUNT_URL = dir_listing['newAccount']
    NONCE_URL = dir_listing['newNonce']
    NEW_ORDER_URL = dir_listing['newOrder']
    REVOKE_CERT_URL = dir_listing['revokeCert']

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
    )
    keyf = open('./key.pem', 'wb')
    keyf.write(pem)
    keyf.close()

    account = new_account(private_key)
    order = new_order(args.domains, private_key, account)
    do_challenge(args.challenge, args.domains, private_key, account, order)
    time.sleep(10)
    if DEBUG: print('------------FIRST---------------')
    make_csr_request(args.domains, private_key, account, order)
    time.sleep(10)
    if DEBUG: print('------------SECOND---------------')
    order = poll_order(private_key, account, order)
    certificate_pem = download_certificate(private_key, account, order)
    certf = open('./cert.pem', 'w')
    certf.write(certificate_pem)
    certf.close()

    if (args.revoke):
        revoke_certificate(private_key, account, certificate_pem)

    certificate_server = CertificateServer('', 5001, './cert.pem', './key.pem')

    
    
    executor.submit(certificate_server.serve_forever())
        

    

