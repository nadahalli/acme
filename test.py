import base64
import json
import requests
import struct
import random
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS


def encode_json_as_bytes(j):
    return json.dumps(j).encode('utf-8')


def base64_encode_as_bytes(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=').encode('utf-8')


def base64_encode_as_string(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def get_jws_params(private_key, url, nonce):
    public_key = private_key.public_key()
    jwk = {}
    jwk['kty'] = 'EC'
    jwk['crv'] = 'P-256'
    jwk['x'] = base64_encode_as_string(public_key.pointQ.x.to_bytes())
    jwk['y'] = base64_encode_as_string(public_key.pointQ.y.to_bytes())

    jws_params = {}
    jws_params['typ'] = 'JWT'
    jws_params['alg'] = 'ES256'
    jws_params['jwk'] = jwk
    jws_params['url'] = url
    jws_params['nonce'] = nonce
    return jws_params


def jws_encode_sign(private_key, payload_dict, jws_params):
    to_be_signed = base64_encode_as_bytes(
        encode_json_as_bytes(jws_params)) + b'.' + base64_encode_as_bytes(
            encode_json_as_bytes(payload_dict))

    h = SHA256.new(to_be_signed)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(h)
    return base64_encode_as_string(signature)


    #return base64_encode_as_string(to_be_signed + b'.' + base64_encode_as_bytes(signature))


private_key = ECC.generate(curve='P-256')

payload = {}
payload['Contact'] = []
payload['TermsOfServiceAgreed'] = True
payload['OnlyReturnExisting'] = False

request_headers = {}
request_headers['Content-Type'] = 'application/jose+json'

url = 'https://localhost:14000/sign-me-up'
nonce = open('nonce.txt', 'r').read()

jws_params = get_jws_params(private_key, url, nonce)


data = {
    'payload': base64_encode_as_string(encode_json_as_bytes(payload)),
    'signatures': [],
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

f = open('nonce.txt', 'w')
f.write(r.headers['Replay-Nonce'])
f.close()
print(r.headers)
print(r.json())
