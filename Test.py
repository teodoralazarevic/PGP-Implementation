from time import time

import PgpService
from PublicKeyRing import PublicKeyRing
from PrivateKeyRing import PrivateKeyRing
from PemFiles import export_key_pair, import_key_pair
from Authentication import sign, verify_signature
from cryptography.hazmat.primitives.asymmetric import rsa
from Confidentiality import encrypt, decrypt, EncryptionAlgorithm


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


# 1. TEST - generating key pair

pgp.generate_private_key_pair(name, email, key_size, password1)

key_id = list(pgp.private_key_ring.private_key_ring.keys())[0]
record = pgp.private_key_ring.private_key_ring[key_id]
encrypted_private_key = record.enc_private_key
private_key = pgp.private_key_ring.decrypt_private_key(encrypted_private_key, password1)

public_key = record.public_key

# 2. TEST - export and import of key pair

# export_key_pair(encrypted_private_key, public_key, name, email, time(), password1)
#
# PrivateKeyRing().private_key_ring_by_name = {}
# print(PrivateKeyRing().private_key_ring_by_name)
#
# import_key_pair("Marko-marko@gmail.com-keypair.pem", password2)
# print(PrivateKeyRing().private_key_ring_by_name)


# TEST - Signing and verifying signature
# private_key1 = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )
#
# public_key1 = private_key.public_key()
# original_message = b"Ovo je test poruka"
# signed_data = sign(original_message, private_key1)
# print(verify_signature(signed_data, public_key1))


# TEST - encryption and decryption of message
# private_key2 = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )
#
# public_key2 = private_key2.public_key()
# message = b"Najjaci projekat ikada"
#
# enc = encrypt(message, public_key2, EncryptionAlgorithm.TDES)
# print("ENCRYPTED:", enc)
#
# dec = decrypt(enc, private_key2, EncryptionAlgorithm.TDES)
# print("DECRYPTED:", dec)

