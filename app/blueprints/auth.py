from flask import Blueprint, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import create_access_token
from app.models.user import User
from app import db
from app.services.crypto_utils import hash_password, verify_password
from app.config import Config
import jwt
from app.services.log_service import create_log

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    pii = data.get('pii')
    if not username or not password or not pii:
        return jsonify({'msg': 'Missing fields'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'msg': 'User exists'}), 409
    hashed_pw = hash_password(password)
    user = User(username=username, password_hash=hashed_pw, pii=pii)
    db.session.add(user)
    db.session.commit()
    create_log(user.id, 'register', f'User {username} registered')
    return jsonify({'msg': 'User registered'}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if not user or not verify_password(password, user.password_hash):
        return jsonify({'msg': 'Invalid credentials'}), 401
    access_token = create_access_token(identity=user.id)
    create_log(user.id, 'login', f'User {username} logged in')
    return jsonify({'access_token': access_token}), 200 