from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import create_access_token
from app.models.user import User
from app import db
from app.services.crypto_utils import hash_password, verify_password
from app.config import Config
import jwt
from app.services.log_service import create_log

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('registration.html', message=None)
    data = request.form if request.form else request.get_json()
    username = data.get('username')
    password = data.get('password')
    pii = data.get('pii')
    if not username or not password or not pii:
        msg = 'Missing fields'
        if request.form:
            return render_template('registration.html', message=msg)
        return jsonify({'msg': msg}), 400
    if User.query.filter_by(username=username).first():
        msg = 'User exists'
        if request.form:
            return render_template('registration.html', message=msg)
        return jsonify({'msg': msg}), 409
    hashed_pw = hash_password(password)
    user = User(username=username, password_hash=hashed_pw, pii=pii)
    db.session.add(user)
    db.session.commit()
    create_log(user.id, 'register', f'User {username} registered')
    msg = 'User registered successfully! Please login.'
    if request.form:
        return redirect(url_for('auth.login', message=msg))
    return jsonify({'msg': 'User registered'}), 201

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        message = request.args.get('message')
        return render_template('login.html', message=message)
    data = request.form if request.form else request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if not user or not verify_password(password, user.password_hash):
        msg = 'Invalid credentials'
        if request.form:
            return render_template('login.html', message=msg)
        return jsonify({'msg': msg}), 401
    access_token = create_access_token(identity=user.id)
    create_log(user.id, 'login', f'User {username} logged in')
    msg = 'Login successful! Use your token for API requests.'
    if request.form:
        return render_template('login.html', message=msg)
    return jsonify({'access_token': access_token}), 200 