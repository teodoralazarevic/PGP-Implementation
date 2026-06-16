import json
from time import time
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def sign(message: bytes, private_key: RSAPrivateKey) -> bytes:
    timestamp = int(time()).to_bytes(8)

    signature_and_message = {
        "timestamp": timestamp,
        "sender_key_id": private_key.public_key().public_numbers().n % (2 ** 64),
        "leading_two_octets": timestamp[:2], # vodeca dva okteta (bajta) su prva 2 bajta 8-bajtnog timestamp-a
        "message_digest": private_key.sign(timestamp + message, padding.PKCS1v15(), hashes.SHA1()), # warning, ali trebalo bi da radi
        "message": message
    }

    return json.dumps(signature_and_message).encode('utf-8')

def verify_signature(message: bytes, public_key: RSAPublicKey) -> bool:
    # TODO
    pass