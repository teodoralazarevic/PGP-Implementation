import json
from enum import Enum

from Crypto.Cipher import DES3, AES
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.algorithms import AES128
from cryptography.hazmat.primitives.ciphers.modes import CBC

from KeyGenerators import generate_3DES_session_key, generate_AES128_session_key


class EncryptionAlgorithm(Enum):
    TDES = 0
    AES128 = 1

# 0 - 3DES
# 1 - AES-128
def encrypt(message: bytes, public_key: RSAPublicKey, encryption_algorithm: EncryptionAlgorithm) -> bytes:

    match encryption_algorithm:
        case EncryptionAlgorithm.TDES:
            session_key = generate_3DES_session_key()
            encrypted_message = DES3.new(session_key, DES3.MODE_CBC).encrypt(message)
        case EncryptionAlgorithm.AES128:
            session_key = generate_AES128_session_key()
            encrypted_message = AES.new(session_key, AES.MODE_CBC).encrypt(message)
        case _:
            raise ValueError("Invalid encryption algorithm")

    encrypted_message = {
        "reciever_key_id": public_key.public_numbers().n % (2 ** 64),
        "encrypted_session_key": public_key.encrypt(session_key, padding.OAEP), # warning, ali trebalo bi da radi
        "encrypted_message": encrypted_message
    }

    return json.dumps(encrypted_message).encode('utf-8')

def decrypt(message: bytes, private_key: RSAPrivateKey) -> bytes:
    # TODO
    pass