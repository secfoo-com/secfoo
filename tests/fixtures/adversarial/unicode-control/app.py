import hashlib

def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()
