from time import time
import hashlib
from Crypto.Cipher import CAST
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization


class PrivateKeyRing:

    instance = None

    def __new__(cls):
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    def __init__(self):
        if not hasattr(self, '_initialized'):
            self.private_key_ring = {}
            self.private_key_ring_by_name = {}
            self.private_key_ring_by_email = {}
            self._initialized = True

    class PrivateKeyRingRecord:
        def __init__(self, timestamp, public_key, enc_private_key, name, email):
            self.timestamp = timestamp
            self.public_key = public_key
            self.enc_private_key = enc_private_key # stores encoded private key
            self.name = name
            self.email = email


    # returns encoded private key
    def get_private_key_ring_by_name(self, name):
        if name in self.private_key_ring_by_name:
            key_id = self.private_key_ring_by_name[name]
            if key_id in self.private_key_ring:
                return self.private_key_ring[key_id].enc_private_key
        return None

    # returns encoded private key
    def get_private_key_ring_by_email(self, email):
        if email in self.private_key_ring_by_email:
            key_id = self.private_key_ring_by_email[email]
            if key_id in self.private_key_ring:
                return self.private_key_ring[key_id].enc_private_key
        return None

    def add_private_key(self, public_key, enc_private_key, name, email):
        timestamp = time()
        record = PrivateKeyRing.PrivateKeyRingRecord(
            timestamp, public_key, enc_private_key, name, email
        )
        key_id = record.public_key.public_numbers().n % (2 ** 64)
        self.private_key_ring[key_id]=record
        self.private_key_ring_by_name[name]=key_id
        self.private_key_ring_by_email[email]=key_id


    def remove_private_key(self, public_key):
        public_key = public_key.public_numbers().n
        key_id = public_key % (2 ** 64)
        record = self.private_key_ring.pop(key_id, None)

        if record is None:
            return

        self.private_key_ring_by_name.pop(record.name, None)
        self.private_key_ring_by_email.pop(record.email, None)

    def encrypt_private_key(self, password, private_key):
        # serialize private key
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # print("Plain private key:")
        # print(private_key_bytes)
        # print("\n")

        # SHA1 -> 128b key
        sha1 = hashlib.sha1(password.encode()).digest()
        key = sha1[:16]  # 128 bits hash code is key for CAST-128

        # CAST-128 encrypt
        cipher = CAST.new(key, CAST.MODE_ECB)
        encrypted_private_key = cipher.encrypt(pad(private_key_bytes, 8))

        # print("Encrypted private key:")
        # print(encrypted_private_key)
        # print("\n")

        return encrypted_private_key

    def decrypt_private_key(self, encrypted_private_key, password):
        try:
            # SHA1 → 128-bit key
            sha1 = hashlib.sha1(password.encode()).digest()
            key = sha1[:16]

            # CAST decrypt
            cipher = CAST.new(key, CAST.MODE_ECB)
            decrypted_padded = cipher.decrypt(encrypted_private_key)

            # remove padding
            private_key_bytes = unpad(decrypted_padded, 8)

            # print("Decrypted private key:")
            # print(private_key_bytes)
            # print("\n")
            return private_key_bytes
        except ValueError:
            print("Wrong password. Private key can not be decrypted.")