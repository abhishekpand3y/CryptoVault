from app import db
from sqlalchemy import Column, Integer, String, Text, DateTime, LargeBinary, ForeignKey
from datetime import datetime

class Log(db.Model):
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    action = Column(String(64), nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    signature = Column(LargeBinary, nullable=False) 