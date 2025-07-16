# CryptoVault

> **DISCLAIMER:** This project is for demonstration and educational purposes only. It is **NOT** recommended for production use. The code and configuration are intentionally simplified to illustrate cryptographic concepts and may lack the robustness, security hardening, and operational controls required for real-world deployments.

A secure, containerized Flask web application demonstrating real-world cryptography use cases for sensitive data, files, and audit logs.

## Features
- User registration & login with bcrypt password hashing
- JWT-based authentication (RS256, asymmetric)
- AES-256 encryption/decryption of user PII and uploaded files (encrypt-before-store, decrypt-before-use)
- File upload (AES-256 encrypted at rest)
- File download (real-time AES-256 decryption)
- Document signing (RSA private key)
- Signature verification (RSA public key)
- Logging of all sensitive actions, with cryptographic signatures for integrity
- Key rotation simulation (versioned AES keys, admin-triggered re-encryption)
- Admin/audit endpoints for logs, log verification, and file metadata
- Secure headers, HTTPS (self-signed certs or reverse proxy)
- Modular Flask app with blueprints and services
- Runs as a non-root user in Docker

## Project Structure
- `app/` - Main application code
  - `blueprints/` - Modular route blueprints (auth, crypto, admin)
  - `models/` - SQLAlchemy models (User, File, Log)
  - `services/` - Crypto, file storage, key management, logging
  - `utils/` - Security headers
  - `routes/`, `schemas/` - Ready for future expansion
  - `config.py` - Loads config from environment variables
- `requirements.txt` — All dependencies
- `Dockerfile` — Non-root, production-ready, HTTPS via Gunicorn
- `docker-compose.yml` — Flask app + PostgreSQL, volumes for certs/keys, env vars
- `certs/`, `keys/` — Mount your SSL and JWT keys here

## Setup
1. **Generate SSL certs and JWT keys**
   - Place your self-signed certs in `certs/` and RSA keys in `keys/`.
2. **Copy `.env`**
   - Set environment variables (see `docker-compose.yml` for required vars).
3. **Build and run:**
   ```sh
   docker-compose build
   docker-compose up
   ```
4. The app will be available at https://localhost:5000

## API Endpoints (Summary)
### Auth
- `POST /auth/register` — Register user (username, password, pii)
- `POST /auth/login` — Login, returns JWT

### User Crypto
- `POST /crypto/encrypt_pii` — Encrypt and store user PII
- `GET /crypto/decrypt_pii` — Decrypt and retrieve user PII
- `POST /crypto/upload` — Upload and encrypt file (JWT required)
- `GET /crypto/download/<file_id>` — Download and decrypt file (JWT required)
- `POST /crypto/sign/<file_id>` — Sign file with RSA private key
- `GET /crypto/verify/<file_id>` — Verify file signature

### Admin/Audit (JWT, user_id=1 required)
- `POST /crypto/admin/rotate_keys` — Rotate AES key, re-encrypt all files
- `GET /crypto/admin/logs` — List all logs
- `GET /crypto/admin/logs/verify` — Verify all log signatures
- `GET /crypto/admin/files` — List all files and metadata

## Security Notes
- All secrets/keys managed via environment variables or Docker secrets in production
- App runs as a non-root user in the container
- All sensitive data is encrypted at rest and in transit
- All sensitive actions are logged and signed for integrity
- Key rotation and versioning supported for AES encryption

## Next Steps
- Add automated tests or OpenAPI docs
- Integrate with a reverse proxy (Caddy/Nginx) for production TLS
- Expand with more cryptographic use cases as needed

---

**CryptoVault** is a reference platform for secure, auditable, and cryptographically robust web applications. 