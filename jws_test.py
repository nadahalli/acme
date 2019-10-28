import jws

public_key = open('public_key.pem').read()

jwk_pub_key = jws.CleartextJwkSetReader.from_pem(
    public_key.encode('utf-8'), 'ES256')
# Set up verifier with expected issuer, subject and audiences.
verifier = jws.JwtPublicKeyVerify(jwk_pub_key, 'issuer1', 'subject1', ['aud1'])
try:
  verified_payload = verifier.verify(b'eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJFUzI1NiIsICJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJETGpkQUF1OWxpeXB3QTRuSzIzN1ZqV21hYXpRUnEzUnVLcTRmOTlCcnVnIiwgInkiOiAiRExqZEFBdTlsaXlwd0E0bksyMzdWaldtYWF6UVJxM1J1S3E0Zjk5QnJ1ZyJ9fQ.eyJDb250YWN0IjogIlRlamFzd2kiLCAiVGVybXNPZlNlcnZpY2VBZ3JlZWQiOiB0cnVlfQ.0Qm5dMnayjsd1UKFQbxWH2p0e-VbCM00T9NPweKTicNzE42dObQYlmGMdpbYObnhPND95-Ek8mkFMOexg_uzmA')
  print('JWT successfully verified.', verified_payload)
except jws.SecurityException as e:
  print('JWT could not be verified!', e)
