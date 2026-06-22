import base64
import json

from time import time
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from Authentication import sign, verify_signature
from Compression import compress, decompress
from Confidentiality import encrypt, EncryptionAlgorithm, decrypt
from Conversion import conversion_encode, conversion_decode
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
        # ZA TESTIRANJE
        self.public_key_ring.add_public_key(public_key, name, email)

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

        message_bytes_encoded = base64.b64encode(message_bytes).decode('utf-8')

        full_message = {
            "services": {
                "authentication": authetication,
                "confidentiality": confidentiality,
                "encryption_algorithm": encryption_algorithm.value,
                "compression": compression,
                "conversion": conversion
            },
            "message": message_bytes_encoded
        }

        make_file(json.dumps(full_message).encode('utf-8'), filename)
        # json_data = json.dumps(full_message).encode('utf-8')
        # with open(filename, 'wb') as f:
        #     f.write(json_data)

    def receive_message(self, filename: str, private_key: RSAPrivateKey, sender_public_key: RSAPublicKey):
        with open(filename, 'rb') as f:
            full_message = json.loads(f.read().decode('utf-8'))

        services = full_message["services"]
        message_bytes = base64.b64decode(full_message["message"])

        if services["conversion"]:
            message_bytes = conversion_decode(message_bytes)

        if services["confidentiality"]:
            encryption_algorithm_val = services["encryption_algorithm"]
            encryption_algorithm = EncryptionAlgorithm(encryption_algorithm_val)
            message_bytes = decrypt(message_bytes, private_key, encryption_algorithm)

        if services["compression"]:
            message_bytes = decompress(message_bytes)

        if services["authentication"]:
            is_valid = verify_signature(message_bytes, sender_public_key)
            if not is_valid:
                raise Exception("Signature verification failed")

            sig_data = json.loads(message_bytes.decode('utf-8'))
            original_message = base64.b64decode(sig_data['message'])
            message_bytes = original_message

        message = json.loads(message_bytes.decode('utf-8'))

        return {
            "filename": message.get("filename"),
            "timestamp": message.get("timestamp"),
            "data": message.get("data")
        }



