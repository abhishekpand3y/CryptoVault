from app.models import db
from datetime import datetime

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_path = db.Column(db.String(512), nullable=False)
    iv = db.Column(db.LargeBinary, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    signature = db.Column(db.LargeBinary, nullable=True)
    key_version = db.Column(db.Integer, nullable=False, default=1)

    user = db.relationship('User', backref=db.backref('files', lazy=True)) 