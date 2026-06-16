import json
from time import time

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from Authentication import sign
from Compression import compress
from Confidentiality import encrypt, EncryptionAlgorithm
from Conversion import conversion_encode
from Files import make_file
from KeyGenerators import generate_rsa_key_pair

from PrivateKeyRing import PrivateKeyRing
from PublicKeyRing import PublicKeyRing


class PGP_Service:
    def __init__(self):
        self.public_key_ring = PublicKeyRing()
        self.private_key_ring = PrivateKeyRing()

    def generate_private_key_pair(self, name, email, key_size, password):
        public_key, private_key = generate_rsa_key_pair(key_size)

        encrypted_private_key = self.private_key_ring.encrypt_private_key(password, private_key)

        # add record to private key ring
        self.private_key_ring.add_private_key(public_key, encrypted_private_key, name, email)

    def send_message(self, data: str, filename: str, authetication: bool, sender_private_key: RSAPrivateKey, confidentiality: bool, reciever_public_key: RSAPublicKey, encryption_algorithm: EncryptionAlgorithm, compression: bool, conversion: bool):
        message = {
            "filename": filename,
            "timestamp": time(),
            "data": data
        }

        message_bytes = json.dumps(message).encode('utf-8')

        if authetication:
            message_bytes = sign(message_bytes, sender_private_key)

        if compression:
            message_bytes = compress(message_bytes)

        if confidentiality:
            message_bytes = encrypt(message_bytes, reciever_public_key, encryption_algorithm)

        if conversion:
            message_bytes = conversion_encode(message_bytes)

        make_file(message_bytes, filename)

    def recieve_message(self):
        # TODO
        pass