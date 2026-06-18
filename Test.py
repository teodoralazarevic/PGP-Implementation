from time import time

import PgpService
from PublicKeyRing import PublicKeyRing
from PrivateKeyRing import PrivateKeyRing
from PemFiles import export_key_pair, import_key_pair

"""
Test for encryption and decryption of generated private key
Uncomment print statements in encrypion and decryption functions in PrivateKeyRing class to see results
"""

pgp = PgpService.PGP_Service()

name = "Marko"
email = "marko@gmail.com"
key_size = 2048
password1 = "1234"
password2 = "1235"


# Testing generating

pgp.generate_private_key_pair(name, email, key_size, password1)

key_id = list(pgp.private_key_ring.private_key_ring.keys())[0]
record = pgp.private_key_ring.private_key_ring[key_id]
encrypted_private_key = record.enc_private_key
decrypted_bytes = pgp.private_key_ring.decrypt_private_key(encrypted_private_key, password1)

public_key = record.public_key

# Testing export and import of key pair

# export_key_pair(encrypted_private_key, public_key, name, email, time(), password1)
#
# PrivateKeyRing().private_key_ring_by_name = {}
# print(PrivateKeyRing().private_key_ring_by_name)
#
# import_key_pair("Marko-marko@gmail.com-keypair.pem", password2)
# print(PrivateKeyRing().private_key_ring_by_name)