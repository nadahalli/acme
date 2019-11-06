import base64
import json
import requests
import struct
import random
import prettyprinter
import time
from binascii import hexlify, unhexlify
prettyprinter.install_extras(['requests'])

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def encode_json_as_bytes(j):
    return json.dumps(j, separators=(',', ':'), sort_keys=True).encode('utf-8')


def base64_encode_as_bytes(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=').encode('utf-8')


def base64_encode_as_string(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def get_nonce():
    r = requests.head(
        'https://localhost:14000/nonce-plz',
        verify=
        '/home/tejaswi/go/src/github.com/letsencrypt/pebble/test/certs/pebble.minica.pem'
    )
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

def make_request(private_key, account, url, payload):
    request_headers = {}
    request_headers['Content-Type'] = 'application/jose+json'

    jws_params = get_jws_params(private_key, url, account)

    data = {
        'payload': base64_encode_as_string(encode_json_as_bytes(payload)) if payload != None else '',
        'signature': jws_encode_sign(private_key, payload, jws_params),
        'protected': base64_encode_as_string(encode_json_as_bytes(jws_params)),
    }

    r = requests.post(
        url,
        data=json.dumps(data),
        headers=request_headers,
        verify=
        '/home/tejaswi/go/src/github.com/letsencrypt/pebble/test/certs/pebble.minica.pem'
    )

    return r.headers, r.json()


def new_account(private_key):
    payload = {}
    payload['Contact'] = []
    payload['TermsOfServiceAgreed'] = True
    payload['OnlyReturnExisting'] = False

    request_headers = {}
    request_headers['Content-Type'] = 'application/jose+json'

    url = 'https://localhost:14000/sign-me-up'

    headers, response = make_request(private_key, None, url, payload)

    prettyprinter.pprint(headers)
    prettyprinter.pprint(response)

    return headers['Location']

def new_order(private_key, account):
    payload = {}
    payload['identifiers'] = [{
        'type': 'dns',
        'value': 'example.org'
    }]

    url = 'https://localhost:14000/order-plz'

    headers, response = make_request(private_key, account, url, payload)
    return response

def auths(private_key, account, auths):
    payload = None
    result = []
    for url in auths:
        _, response = make_request(private_key, account, url, payload)
        result.extend(response['challenges'])
    return result

def prompt_challenge(private_key, account, url):
    payload = {}
    make_request(private_key, account, url, payload)

def do_dns(private_key, challenge):
    to_be_hashed = bytes(challenge['token'], 'utf-8') + b'.' + get_jwk_thumbprint(private_key)
    txt_record = base64_encode_as_string(hash_256(to_be_hashed))
    f = open('x/_acme-challenge.example.org', 'w')
    f.write(txt_record)
    f.close()

def do_dns_challenge(private_key, account, order):
    challenges = auths(private_key, account, order['authorizations'])
    for c in challenges:
        if c['type'] == 'dns-01':
            do_dns(private_key, c)

    for c in challenges:
        if c['type'] == 'dns-01':
            prompt_challenge(private_key, account, c['url'])

    time.sleep(2)

    
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
account = new_account(private_key)
order = new_order(private_key, account)
prettyprinter.pprint(order)
challenges = auths(private_key, account, order['authorizations'])
for c in challenges:
    if c['type'] == 'dns-01':
        do_dns(private_key, c)

for c in challenges:
    if c['type'] == 'dns-01':
        prompt_challenge(private_key, account, c['url'])

"""

account = new_account(private_key)
order = new_order(private_key, account)
do_dns_challenge_and_finalize(private_key, account, order)

prettyprinter.pprint(order)
"""
        

    

