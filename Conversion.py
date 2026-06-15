import base64


def conversion_encode(data):
    return base64.b64encode(data.encode('utf-8'))

def conversion_decode(data):
    return base64.b64decode(data).decode('utf-8')