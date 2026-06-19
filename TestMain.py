#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from cryptography.hazmat.primitives.asymmetric import rsa

import PgpService
from Confidentiality import EncryptionAlgorithm


def test_simple():
    print("\n1. Generisanje RSA kljuceva...")
    sender_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sender_public = sender_private.public_key()

    receiver_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    receiver_public = receiver_private.public_key()


    print("\n2. Kreiranje PGP servisa...")
    pgp = PgpService.PGP_Service()

    print("\n3. Slanje poruke...")
    original = "Hello World! Ovo je PGP test."

    pgp.send_message(
        data=original,
        filename="poruka.txt",
        authetication=True,
        sender_private_key=sender_private,
        confidentiality=True,
        reciever_public_key=receiver_public,
        encryption_algorithm=EncryptionAlgorithm.AES128,
        compression=True,
        conversion=True
    )
    print(f"Poruka poslata: '{original}'")


    print("\n4. Prijem poruke...")
    received = pgp.receive_message(
        filename="sent_messages/poruka.txt",
        private_key=receiver_private,
        sender_public_key=sender_public
    )
    print(f"Poruka primljena: '{received['data']}'")


    print("\n5. Provera...")
    if original == received['data']:
        print("TEST USPESAN!")
    else:
        print("TEST NEUSPESAN!")
        print(f"  Original: {original}")
        print(f"  Primljeno: {received['data']}")

if __name__ == "__main__":
    test_simple()