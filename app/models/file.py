from app import db
from sqlalchemy import Column, Integer, String, LargeBinary, DateTime, ForeignKey
from datetime import datetime

class File(db.Model):
    id = Column(Integer, primary_key=True)
    filename = Column(String(256), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    encrypted_path = Column(String(512), nullable=False)
    iv = Column(LargeBinary, nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    signature = Column(LargeBinary, nullable=True)
    key_version = Column(Integer, nullable=False, default=1) 