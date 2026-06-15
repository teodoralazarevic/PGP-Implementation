from cryptography.hazmat.primitives.asymmetric import rsa

# generates a pair of RSA keys
def generate_rsa_key_pair(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return public_key, private_key