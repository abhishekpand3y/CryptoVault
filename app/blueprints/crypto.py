from flask import Blueprint, request, jsonify, Response, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models.user import User
from app.models.file import File
from app import db
from app.services.crypto_utils import encrypt_pii, decrypt_pii, sign_data, verify_signature
import os
import base64
from app.services.log_service import create_log
import secrets
from app.services.key_management import rotate_keys, get_latest_key_version, get_key
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from app.models.log import Log
import json

crypto_bp = Blueprint('crypto', __name__)

@crypto_bp.route('/encrypt_pii', methods=['POST'])
@jwt_required()
def encrypt_user_pii():
    user_id = get_jwt_identity()
    data = request.get_json()
    pii = data.get('pii')
    if not pii:
        return jsonify({'msg': 'Missing PII'}), 400
    user = User.query.get(user_id)
    user.pii = encrypt_pii(pii)
    db.session.commit()
    return jsonify({'msg': 'PII encrypted and stored'}), 200

@crypto_bp.route('/decrypt_pii', methods=['GET'])
@jwt_required()
def decrypt_user_pii():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.pii:
        return jsonify({'msg': 'No PII found'}), 404
    pii = decrypt_pii(user.pii)
    return jsonify({'pii': pii}), 200

@crypto_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    if 'file' not in request.files:
        return jsonify({'msg': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'msg': 'No selected file'}), 400
    user_id = get_jwt_identity()
    filename = file.filename
    encrypted_path, iv, key_version = save_encrypted_file(file.stream, filename)
    new_file = File(
        filename=filename,
        user_id=user_id,
        encrypted_path=encrypted_path,
        iv=iv,
        key_version=key_version
    )
    db.session.add(new_file)
    db.session.commit()
    create_log(user_id, 'file_upload', f'File {filename} uploaded and encrypted')
    return jsonify({'msg': 'File uploaded and encrypted', 'file_id': new_file.id}), 201

@crypto_bp.route('/download/<int:file_id>', methods=['GET'])
@jwt_required()
def download_file(file_id):
    user_id = get_jwt_identity()
    file = File.query.get(file_id)
    if not file or file.user_id != user_id:
        return jsonify({'msg': 'File not found or access denied'}), 404
    generator = stream_decrypted_file(file.encrypted_path, file.iv, file.key_version)
    response = Response(generator(), mimetype='application/octet-stream')
    response.headers.set('Content-Disposition', 'attachment', filename=file.filename)
    create_log(user_id, 'file_download', f'File {file.filename} downloaded and decrypted')
    return response 

@crypto_bp.route('/sign/<int:file_id>', methods=['POST'])
@jwt_required()
def sign_file(file_id):
    user_id = get_jwt_identity()
    file = File.query.get(file_id)
    if not file or file.user_id != user_id:
        return jsonify({'msg': 'File not found or access denied'}), 404
    with open(file.encrypted_path, 'rb') as f:
        file_data = f.read()
    signature = sign_data(file_data)
    file.signature = signature
    db.session.commit()
    create_log(user_id, 'file_sign', f'File {file.filename} signed')
    return jsonify({'msg': 'File signed', 'signature': base64.b64encode(signature).decode()}), 200 

@crypto_bp.route('/verify/<int:file_id>', methods=['GET'])
@jwt_required()
def verify_file_signature(file_id):
    user_id = get_jwt_identity()
    file = File.query.get(file_id)
    if not file or file.user_id != user_id:
        return jsonify({'msg': 'File not found or access denied'}), 404
    if not file.signature:
        return jsonify({'msg': 'File not signed'}), 400
    with open(file.encrypted_path, 'rb') as f:
        file_data = f.read()
    is_valid = verify_signature(file_data, file.signature)
    create_log(user_id, 'file_verify', f'File {file.filename} signature verified: {is_valid}')
    return jsonify({'file_id': file_id, 'signature_valid': is_valid}), 200 

@crypto_bp.route('/admin/rotate_keys', methods=['POST'])
@jwt_required()
def admin_rotate_keys():
    user_id = get_jwt_identity()
    if user_id != 1:
        return jsonify({'msg': 'Admin only'}), 403
    # Generate new AES key
    new_key = secrets.token_bytes(32)
    new_version = rotate_keys(new_key.hex())
    # Re-encrypt all files
    files = File.query.all()
    for file in files:
        # Decrypt with old key
        old_key = get_key(file.key_version)
        if isinstance(old_key, str):
            old_key = bytes.fromhex(old_key) if len(old_key) == 64 else old_key.encode()
        old_key = old_key[:32]
        backend = default_backend()
        cipher = Cipher(algorithms.AES(old_key), modes.CBC(file.iv), backend=backend)
        decryptor = cipher.decryptor()
        with open(file.encrypted_path, 'rb') as f:
            ct = f.read()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        # Encrypt with new key and new IV
        new_iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(new_key), modes.CBC(new_iv), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        new_ct = encryptor.update(padded_data) + encryptor.finalize()
        with open(file.encrypted_path, 'wb') as f:
            f.write(new_ct)
        file.iv = new_iv
        file.key_version = new_version
    db.session.commit()
    create_log(user_id, 'key_rotation', f'Rotated AES key to version {new_version}')
    return jsonify({'msg': f'Key rotated to version {new_version}', 'files_updated': len(files)}), 200 

@crypto_bp.route('/admin/logs', methods=['GET'])
@jwt_required()
def admin_list_logs():
    user_id = get_jwt_identity()
    if user_id != 1:
        return jsonify({'msg': 'Admin only'}), 403
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    return jsonify([
        {
            'id': log.id,
            'user_id': log.user_id,
            'action': log.action,
            'details': log.details,
            'timestamp': log.timestamp.isoformat(),
        } for log in logs
    ]), 200

@crypto_bp.route('/admin/logs/verify', methods=['GET'])
@jwt_required()
def admin_verify_logs():
    user_id = get_jwt_identity()
    if user_id != 1:
        return jsonify({'msg': 'Admin only'}), 403
    logs = Log.query.all()
    results = []
    for log in logs:
        log_data = {
            'user_id': log.user_id,
            'action': log.action,
            'details': log.details,
            'timestamp': log.timestamp.isoformat()
        }
        log_str = json.dumps(log_data, sort_keys=True).encode()
        valid = verify_signature(log_str, log.signature)
        results.append({'log_id': log.id, 'valid': valid})
    return jsonify(results), 200

@crypto_bp.route('/admin/files', methods=['GET'])
@jwt_required()
def admin_list_files():
    user_id = get_jwt_identity()
    if user_id != 1:
        return jsonify({'msg': 'Admin only'}), 403
    files = File.query.order_by(File.uploaded_at.desc()).all()
    return jsonify([
        {
            'id': file.id,
            'user_id': file.user_id,
            'filename': file.filename,
            'encrypted_path': file.encrypted_path,
            'key_version': file.key_version,
            'uploaded_at': file.uploaded_at.isoformat(),
        } for file in files
    ]), 200 