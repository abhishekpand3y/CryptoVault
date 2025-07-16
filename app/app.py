from flask import Flask, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from app.config import Config
from app.blueprints.auth import auth_bp
from app.blueprints.crypto import crypto_bp
from app.utils.secure_headers import set_secure_headers
from app import db  # Use the shared db instance

# Initialize extensions
jwt = JWTManager()


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

    # Add default route
    @app.route('/')
    def index():
        # Show a friendly landing page with API usage instructions and links
        return '''
        <html>
        <head><title>CryptoVault API</title></head>
        <body>
            <h1>Welcome to CryptoVault</h1>
            <p>This is a demonstration API for cryptography use cases.</p>
            <ul>
                <li>Register: <a href="/auth/register">Register here</a></li>
                <li>Login: <a href="/auth/login">Login here</a></li>
                <li>See the README for all endpoints and usage.</li>
            </ul>
            <p><b>Note:</b> This API is for learning/demo only. Use a tool like Postman or curl to interact with the endpoints.</p>
        </body>
        </html>
        '''

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, ssl_context=(Config.SSL_CERT, Config.SSL_KEY))
