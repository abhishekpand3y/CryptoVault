from flask import Blueprint, request, jsonify, Response, send_file, render_template, redirect, url_for
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models.user import User
from app.models.file import File
from app import db
from app.services.crypto_utils import encrypt_pii, decrypt_pii, sign_data, verify_signature
from app.services.file_storage import save_encrypted_file, stream_decrypted_file
from app.services.log_service import create_log
import os
import base64
from datetime import datetime

crypto_bp = Blueprint('crypto', __name__)

# --- File Upload (UI + API) ---
@crypto_bp.route('/upload', methods=['GET', 'POST'])
def upload_file():
    user_id = 1  # For demo, use user_id=1. In real app, use session or JWT.
    message = None
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            message = 'No file selected.'
        else:
            encrypted_path, iv, key_version = save_encrypted_file(file.stream, file.filename)
            new_file = File(
                filename=file.filename,
                user_id=user_id,
                encrypted_path=encrypted_path,
                iv=iv,
                key_version=key_version,
                uploaded_at=datetime.utcnow()
            )
            db.session.add(new_file)
            db.session.commit()
            create_log(user_id, 'file_upload', f'File {file.filename} uploaded and encrypted')
            message = f'File {file.filename} uploaded and encrypted.'
    return render_template('upload.html', message=message)

# --- List Files ---
@crypto_bp.route('/files', methods=['GET'])
def list_files():
    user_id = 1  # For demo, use user_id=1
    files = File.query.filter_by(user_id=user_id).order_by(File.uploaded_at.desc()).all()
    return render_template('files.html', files=files)

# --- Download File ---
@crypto_bp.route('/download/<int:file_id>', methods=['GET'])
def download_file(file_id):
    user_id = 1  # For demo, use user_id=1
    file = File.query.get(file_id)
    if not file or file.user_id != user_id:
        return "File not found or access denied", 404
    generator = stream_decrypted_file(file.encrypted_path, file.iv, file.key_version)
    response = Response(generator(), mimetype='application/octet-stream')
    response.headers.set('Content-Disposition', 'attachment', filename=file.filename)
    create_log(user_id, 'file_download', f'File {file.filename} downloaded and decrypted')
    return response

# --- Sign File (UI) ---
@crypto_bp.route('/sign/<int:file_id>', methods=['GET'])
def sign_file_ui(file_id):
    user_id = 1  # For demo, use user_id=1
    file = File.query.get(file_id)
    message = None
    signature = None
    if not file or file.user_id != user_id:
        message = "File not found or access denied"
    else:
        with open(file.encrypted_path, 'rb') as f:
            file_data = f.read()
        signature = base64.b64encode(sign_data(file_data)).decode()
        file.signature = base64.b64decode(signature)
        db.session.commit()
        create_log(user_id, 'file_sign', f'File {file.filename} signed')
        message = f'File {file.filename} signed.'
    return render_template('sign.html', message=message, signature=signature)

# --- Verify File Signature (UI) ---
@crypto_bp.route('/verify/<int:file_id>', methods=['GET'])
def verify_file_signature_ui(file_id):
    user_id = 1  # For demo, use user_id=1
    file = File.query.get(file_id)
    message = None
    signature_valid = None
    if not file or file.user_id != user_id:
        message = "File not found or access denied"
    elif not file.signature:
        message = "File not signed"
    else:
        with open(file.encrypted_path, 'rb') as f:
            file_data = f.read()
        signature_valid = verify_signature(file_data, file.signature)
        create_log(user_id, 'file_verify', f'File {file.filename} signature verified: {signature_valid}')
    return render_template('verify.html', message=message, signature_valid=signature_valid)

# --- Logs (UI) ---
@crypto_bp.route('/logs', methods=['GET'])
def logs_ui():
    logs = db.session.execute(db.select(db.Model).where(db.Model.__tablename__ == 'log')).scalars().all() if hasattr(db.Model, '__tablename__') else []
    # Fallback for SQLAlchemy 1.x:
    if not logs:
        from app.models.log import Log
        logs = Log.query.order_by(Log.timestamp.desc()).all()
    return render_template('logs.html', logs=logs) 