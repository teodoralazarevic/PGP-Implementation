import json
import base64
import os
from enum import Enum

from Crypto.Cipher import DES3, AES
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import hashes

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
            iv = os.urandom(8)
            padded_message = pad(message, 8)
            encrypted_message = DES3.new(session_key, DES3.MODE_CBC, iv=iv).encrypt(padded_message)
        case EncryptionAlgorithm.AES128:
            session_key = generate_AES128_session_key()
            iv = os.urandom(16)
            padded_message = pad(message, 16)
            encrypted_message = AES.new(session_key, AES.MODE_CBC, iv=iv).encrypt(padded_message)
        case _:
            raise ValueError("Invalid encryption algorithm")

    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_data = {
        "receiver_key_id": public_key.public_numbers().n % (2 ** 64),
        "encrypted_session_key": base64.b64encode(encrypted_session_key).decode('utf-8'),
        "encrypted_message": base64.b64encode(encrypted_message).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8')
    }

    return json.dumps(encrypted_data).encode('utf-8')

def decrypt(message: bytes, private_key: RSAPrivateKey, encryption_algorithm: EncryptionAlgorithm) -> bytes:
    data = json.loads(message.decode('utf-8'))
    required_fields = ['receiver_key_id', 'encrypted_session_key', 'encrypted_message', 'iv']

    if not all(field in data for field in required_fields):
        raise ValueError("Missing required fields")

    receiver_key_id = data['receiver_key_id']
    encrypted_session_key = base64.b64decode(data['encrypted_session_key'])
    encrypted_message = base64.b64decode(data['encrypted_message'])
    iv = base64.b64decode(data['iv'])

    computed_key_id = private_key.public_key().public_numbers().n % (2 ** 64)
    if receiver_key_id != computed_key_id:
        raise ValueError("Key ID mismatch")

    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    match encryption_algorithm:
        case EncryptionAlgorithm.TDES:
            cipher = DES3.new(session_key, DES3.MODE_CBC, iv=iv)
            decrypted_padded = cipher.decrypt(encrypted_message)
            decrypted_message = unpad(decrypted_padded, 8)
        case EncryptionAlgorithm.AES128:
            cipher = AES.new(session_key, AES.MODE_CBC, iv=iv)
            decrypted_padded = cipher.decrypt(encrypted_message)
            decrypted_message = unpad(decrypted_padded, 16)
        case _:
            raise ValueError("Invalid encryption algorithm")

    return decrypted_message