from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from app.config import Config
from app.blueprints.auth import auth_bp
from app.blueprints.crypto import crypto_bp
from app.utils.secure_headers import set_secure_headers

# Initialize extensions
jwt = JWTManager()
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(crypto_bp, url_prefix='/crypto')

    # Secure headers
    app.after_request(set_secure_headers)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, ssl_context=(Config.SSL_CERT, Config.SSL_KEY))
