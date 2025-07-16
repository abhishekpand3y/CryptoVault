import bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from flask import current_app  # type: ignore
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

# Bcrypt

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

# AES-256

def get_aes_key():
    key = current_app.config['AES_KEY']
    if isinstance(key, str):
        key = key.encode()
    return key[:32]

def encrypt_pii(plaintext: str) -> bytes:
    key = get_aes_key()
    iv = os.urandom(16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ct

def decrypt_pii(ciphertext: bytes) -> str:
    key = get_aes_key()
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

# RSA signing

def load_private_key():
    key_path = current_app.config['JWT_PRIVATE_KEY']
    with open(key_path, 'rb') as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def load_public_key():
    key_path = current_app.config['JWT_PUBLIC_KEY']
    with open(key_path, 'rb') as key_file:
        return serialization.load_pem_public_key(key_file.read())

def sign_data(data: bytes) -> bytes:
    private_key = load_private_key()
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(data: bytes, signature: bytes) -> bool:
    public_key = load_public_key()
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False 