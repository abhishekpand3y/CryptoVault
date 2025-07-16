import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from flask import current_app
from app.services.key_management import get_latest_key_version, get_key

def save_encrypted_file(file_stream, filename):
    key_version = get_latest_key_version()
    key = get_key(key_version)
    if isinstance(key, str):
        key = key.encode()
    key = key[:32]
    iv = os.urandom(16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    data = file_stream.read()
    padded_data = padder.update(data) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    # Save encrypted file
    storage_dir = current_app.config.get('ENCRYPTED_FILE_DIR', 'encrypted_uploads')
    os.makedirs(storage_dir, exist_ok=True)
    encrypted_path = os.path.join(storage_dir, filename)
    with open(encrypted_path, 'wb') as f:
        f.write(ct)
    return encrypted_path, iv, key_version

def stream_decrypted_file(encrypted_path, iv, key_version):
    key = get_key(key_version)
    if isinstance(key, str):
        key = key.encode()
    key = key[:32]
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    def generate():
        with open(encrypted_path, 'rb') as f:
            chunk = f.read(4096)
            while chunk:
                decrypted = decryptor.update(chunk)
                chunk = f.read(4096)
                if not chunk:
                    decrypted += decryptor.finalize()
                    decrypted = unpadder.update(decrypted) + unpadder.finalize()
                yield decrypted
    return generate 