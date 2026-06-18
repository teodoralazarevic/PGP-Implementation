import base64
import json
from typing import cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from PublicKeyRing import PublicKeyRing
from PrivateKeyRing import PrivateKeyRing


def import_public_key(pem_file_name: str):
    with open(pem_file_name, "r") as f:
        lines = f.readlines()

    base_64_lines = [line.strip() for line in lines if "BEGIN USER IDENTITY" not in line and "END USER IDENTITY" not in line]

    base_64_string = "".join(base_64_lines)
    json_bytes = base64.b64decode(base_64_string)
    public_key_data = json.loads(json_bytes.decode('utf-8'))

    public_key, name, email, timestamp = cast(RSAPublicKey, serialization.load_pem_public_key(public_key_data["public_key"].encode('utf-8'))), public_key_data["name"], public_key_data["email"], public_key_data["timestamp"]

    PublicKeyRing().add_public_key(public_key, name, email, timestamp = timestamp)

def export_public_key(public_key: RSAPublicKey, name: str, email: str, timestamp: float):
    pem_text = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

    data = {
        "name" : name,
        "email" : email,
        "timestamp" : timestamp,
        "public_key" : pem_text
    }

    json_bytes = json.dumps(data).encode('utf-8')
    base_64_string = base64.b64encode(json_bytes).decode('utf-8')

    with open(name + '-' + email + ".pem", "w") as f:
        f.write("-----BEGIN USER IDENTITY-----\n")
        f.write(base_64_string)
        f.write("-----END USER IDENTITY-----\n")

def import_key_pair(pem_file_name: str, password: str) -> None:
    with open(pem_file_name, "r") as f:
        lines = f.readlines()

    base_64_lines = [line.strip() for line in lines
                     if "BEGIN PGP KEY PAIR" not in line and "END PGP KEY PAIR" not in line]
    base_64_string = "".join(base_64_lines)

    json_bytes = base64.b64decode(base_64_string)

    data = json.loads(json_bytes.decode('utf-8'))

    private_key = serialization.load_pem_private_key(data["private_key"].encode('utf-8'), None)
    public_key = cast(RSAPublicKey, serialization.load_pem_public_key(data["public_key"].encode('utf-8')))

    encrypted_private_key = PrivateKeyRing().encrypt_private_key(password, private_key)

    PrivateKeyRing().add_private_key(public_key, encrypted_private_key, data["name"], data["email"])
    PublicKeyRing().add_public_key(public_key, data["name"], data["email"], data["timestamp"])


def export_key_pair(encrypted_private_key: bytes, public_key: RSAPublicKey, name: str,
                    email: str, timestamp: float, password: str) -> None:
    private_key_bytes = PrivateKeyRing().decrypt_private_key(encrypted_private_key, password)
    private_key = serialization.load_der_private_key(private_key_bytes, password=None)

    private_pem = private_key.private_bytes(encoding = serialization.Encoding.PEM,
                                            format = serialization.PrivateFormat.PKCS8,
                                            encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
    public_pem = public_key.public_bytes(encoding = serialization.Encoding.PEM,
                                         format = serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

    data = {
        "name" : name,
        "email" : email,
        "timestamp" : timestamp,
        "private_key" : private_pem,
        "public_key" : public_pem
    }

    json_bytes = json.dumps(data).encode('utf-8')
    base_64_string = base64.b64encode(json_bytes).decode('utf-8')

    filename = f"{name}-{email}-keypair.pem"
    with open(filename, "w") as f:
        f.write("-----BEGIN PGP KEY PAIR-----\n")
        f.write(base_64_string)
        f.write("\n")
        f.write("-----END PGP KEY PAIR-----\n")
