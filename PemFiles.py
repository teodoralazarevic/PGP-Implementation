import base64
import json

from cryptography.hazmat.primitives import serialization

from PublicKeyRing import PublicKeyRing


# PRETPOSTAVKA: tipovi privatnog i javnog kljuca su RSAPrivateKey i RSAPublicKey iz cryptography paketa

def import_public_key(pem_file_name):
    with open(pem_file_name, "r") as f:
        lines = f.readlines()

    base_64_lines = [line.strip() for line in lines if "BEGIN USER IDENTITY" not in line and "END USER IDENTITY" not in line]

    base_64_string = "".join(base_64_lines)
    json_bytes = base64.b64decode(base_64_string)
    public_key_data = json.loads(json_bytes.decode('utf-8'))

    public_key, name, email, timestamp = serialization.load_pem_public_key(public_key_data["public_key"].encode('utf-8')), public_key_data["name"], public_key_data["email"], public_key_data["timestamp"]

    PublicKeyRing().add_public_key(public_key, name, email, timestamp = timestamp)

def export_public_key(public_key, name, email, timestamp):
    pem_text = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

    data = {
        "name" : name,
        "email" : email,
        "timestamp" : timestamp,
        "public_key" : pem_text
    }

    json_bytes = json.dumps(data).encode('utf-8')
    base_64_string = base64.encodebytes(json_bytes).decode('utf-8')

    with open(name + '-' + email + ".pem", "w") as f:
        f.write("-----BEGIN USER IDENTITY-----\n")
        f.write(base_64_string)
        f.write("-----END USER IDENTITY-----\n")

def import_key_pair(pem_file_name):
    # TODO
    pass

def export_key_pair(private_key, public_key):
    # TODO
    pass
