import base64
import json
from time import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def sign(message: bytes, private_key: RSAPrivateKey) -> bytes:
    timestamp = int(time()).to_bytes(8, byteorder='big')

    signature = private_key.sign(timestamp + message,padding.PKCS1v15(), hashes.SHA1())

    signature_and_message = {
        "timestamp": base64.b64encode(timestamp).decode('utf-8'),
        "sender_key_id": private_key.public_key().public_numbers().n % (2 ** 64),
        "leading_two_octets": base64.b64encode(timestamp[:2]).decode('utf-8'),
        "message_digest": base64.b64encode(signature).decode('utf-8'),
        "message": base64.b64encode(message).decode('utf-8')
    }

    return json.dumps(signature_and_message).encode('utf-8')

def verify_signature(message: bytes, public_key: RSAPublicKey) -> bool:
    try:
        data = json.loads(message.decode('utf-8'))

        required_fields = ['timestamp', 'sender_key_id', 'leading_two_octets', 'message_digest', 'message']
        # does signature contain all required fields
        if not all(field in data for field in required_fields):
            return False

        timestamp = base64.b64decode(data['timestamp'])
        leading_two_octets = base64.b64decode(data['leading_two_octets'])
        message_digest = base64.b64decode(data['message_digest'])
        original_message = base64.b64decode(data['message'])

        sender_key_id = data['sender_key_id']

        # is sender_id ok
        computed_key_id = public_key.public_numbers().n % (2 ** 64)
        if sender_key_id != computed_key_id:
            return False

        # check leading two octets
        if len(timestamp) >= 2 and leading_two_octets != timestamp[:2]:
            return False

        # data which are signed
        data_to_verify = timestamp + original_message

        # verify signature
        public_key.verify(
            message_digest,
            data_to_verify,
            padding.PKCS1v15(),
            hashes.SHA1()
        )
        return True
    except:
        return False