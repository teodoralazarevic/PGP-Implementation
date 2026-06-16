import os

from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import CAST

# generates a pair of RSA keys
def generate_rsa_key_pair(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return public_key, private_key


seed = os.urandom(16)

def generate_session_key(length: int) -> bytes: # length in bytes
    global seed

    key = b''

    while len(key) < length:
        random_bytes = os.urandom(8) # 8 bajta

        encrypted_bytes = CAST.new(seed, CAST.MODE_ECB).encrypt(random_bytes)

        key += encrypted_bytes
        seed = encrypted_bytes + encrypted_bytes

    return key

def generate_3DES_session_key() -> bytes:
    return generate_session_key(24)

def generate_AES128_session_key() -> bytes:
    return generate_session_key(16)