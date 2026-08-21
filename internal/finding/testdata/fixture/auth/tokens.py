import hashlib

def derive_token(secret, nonce):
    return hashlib.md5((secret + nonce).encode()).hexdigest()

def check(a, b):
    return a == b
