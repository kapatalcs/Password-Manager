import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

KEY_SIZE = 32
PBKDF2_ITERATIONS = 100_000

def derive_key(password: str, salt: bytes):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt(data: bytes, password: str) -> bytes:
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    nonce = get_random_bytes(12)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return salt + nonce + ciphertext + tag

def decrypt(enc_data: bytes, password: str) -> bytes:
    salt = enc_data[:16]
    nonce = enc_data[16:28]
    ciphertext = enc_data[28:-16]
    tag = enc_data[-16:]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()
