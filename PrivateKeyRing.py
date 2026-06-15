from time import time


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
        key_id = public_key % (2 ** 64)
        timestamp = time()
        self.private_key_ring[key_id]=PrivateKeyRing.PrivateKeyRingRecord(
            timestamp, public_key, enc_private_key, name, email
        )
        self.private_key_ring_by_name[name]=key_id
        self.private_key_ring_by_email[email]=key_id


    def remove_private_key(self, public_key):
        key_id = public_key % (2 ** 64)
        record = self.private_key_ring.pop(key_id, None)

        if record is None:
            return

        self.private_key_ring_by_name.pop(record.name, None)
        self.private_key_ring_by_email.pop(record.email, None)