from KeyGenerators import generate_rsa_key_pair

from PrivateKeyRing import PrivateKeyRing
from PublicKeyRing import PublicKeyRing


class PGP_Service:
    def __init__(self, public_key_ring, private_key_ring):
        self.public_key_ring = public_key_ring
        self.private_key_ring = private_key_ring

    def generate_private_key_pair(self, name, email, key_size, password):
        public_key, private_key = generate_rsa_key_pair(key_size)

        encrypted_private_key = self.private_key_ring.encrypt_private_key(password, private_key)

        # add record to private key ring
        self.private_key_ring.add_private_key(public_key, encrypted_private_key, name, email)


