import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev_secret')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://cryptovault:password@db:5432/cryptovault')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ALGORITHM = 'RS256'
    JWT_PRIVATE_KEY = os.environ.get('JWT_PRIVATE_KEY', 'keys/jwt_private.pem')
    JWT_PUBLIC_KEY = os.environ.get('JWT_PUBLIC_KEY', 'keys/jwt_public.pem')
    AES_KEY = os.environ.get('AES_KEY', 'changemechangemechangemechangeme')  # 32 bytes
    SSL_CERT = os.environ.get('SSL_CERT', 'certs/server.crt')
    SSL_KEY = os.environ.get('SSL_KEY', 'certs/server.key')
    ENCRYPTED_FILE_DIR = os.environ.get('ENCRYPTED_FILE_DIR', 'encrypted_uploads')
