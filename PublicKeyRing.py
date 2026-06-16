from time import time

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


class PublicKeyRing:
    instance = None

    def __new__(cls):
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance



    class PublicKeyRingRecord:
        def __init__(self, public_key: RSAPublicKey, timestamp: float, name: str): #, owner_trust = None, key_legitimacy = None, signatures = None, signature_trusts = None):
            self.public_key = public_key
            self.timestamp = timestamp
            self.name = name
            # self.owner_trust = owner_trust
            # self.key_legitimacy = key_legitimacy
            # self.signatures = signatures
            # self.signature_trusts = signature_trusts

    public_key_ring = {}
    # public_key_ring_by_name = {}
    public_key_ring_by_email = {}



    # def get_public_key_by_name(self, name):
    #     if name in self.public_key_ring_by_name and self.public_key_ring_by_name[name] in self.public_key_ring:
    #         return self.public_key_ring[self.public_key_ring_by_name[name]].public_key
    #     return None

    def get_public_key_by_email(self, email: str) -> RSAPublicKey | None:
        if email in self.public_key_ring_by_email and self.public_key_ring_by_email[email] in self.public_key_ring:
            return self.public_key_ring[self.public_key_ring_by_email[email]].public_key
        return None



    def add_public_key(self, public_key: RSAPublicKey, name: str, email: str, timestamp: float = time()):
        key_id = public_key.public_numbers().n % (2 ** 64)
        self.public_key_ring[key_id] = PublicKeyRing.PublicKeyRingRecord(public_key, timestamp, name)

        # self.public_key_ring_by_name[name] = key_id
        self.public_key_ring_by_email[email] = key_id



    def remove_public_key(self, public_key: RSAPublicKey):
        key_id = public_key.public_numbers().n % (2 ** 64)

        record = self.public_key_ring.pop(key_id, None)

        if record is None:
            return

        # self.public_key_ring_by_name.pop(record.name, None)
        self.public_key_ring_by_email.pop(record.email, None)