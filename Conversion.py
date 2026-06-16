import base64


def conversion_encode(data: bytes) -> bytes:
    return base64.b64encode(data)

def conversion_decode(data: bytes) -> bytes:
    return base64.b64decode(data)