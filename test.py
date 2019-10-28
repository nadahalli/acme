import base64
import json
import requests
import struct
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS


def encode_json_as_bytes(j):
    return bytes(json.dumps(j), encoding='utf-8')


def base64_encode_as_string(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def jws_encode_sign_and_return_bytes(private_key, payload_dict):
    public_key = private_key.public_key()
    jwk = {}
    jwk['kty'] = 'EC'
    jwk['crv'] = 'P-256'
    jwk['x'] = base64_encode_as_string(public_key.pointQ.x.to_bytes())
    jwk['y'] = base64_encode_as_string(public_key.pointQ.x.to_bytes())

    jws_params = {}
    jws_params['typ'] = 'JWT'
    jws_params['alg'] = 'ES256'
    jws_params['jwk'] = jwk

    to_be_signed = base64_encode_as_string(
        encode_json_as_bytes(jws_params)) + '.' + base64_encode_as_string(
            encode_json_as_bytes(payload_dict))
    to_be_signed_bytes = to_be_signed.encode('utf-8')

    h = SHA256.new(to_be_signed_bytes)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(h)

    return to_be_signed_bytes + b'.' + base64_encode_as_string(
        signature).encode('utf-8')


private_key = ECC.generate(curve='P-256')
f = open('private_key.pem', 'w')
f.write(private_key.export_key(format = 'PEM'))
f.close()
f = open('public_key.pem', 'w')
f.write(private_key.public_key().export_key(format = 'PEM'))
f.close()

new_account_params = {}
new_account_params['Contact'] = 'Tejaswi'
new_account_params['TermsOfServiceAgreed'] = True

request_headers = {}
request_headers['Content-Type'] = 'application/jose+json'

data = jws_encode_sign_and_return_bytes(private_key, new_account_params)

print(data)

r = requests.post(
    'https://localhost:14000/sign-me-up',
    data=data,
    headers=request_headers,
    verify=
    '/home/tejaswi/go/src/github.com/letsencrypt/pebble/test/certs/pebble.minica.pem'
)

print(json.dumps(r.json(), indent=2))
