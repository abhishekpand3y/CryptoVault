from app import db
from sqlalchemy import Column, Integer, String, LargeBinary
from sqlalchemy.orm import relationship, backref

class User(db.Model):
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    pii = Column(LargeBinary, nullable=True)
    files = relationship('File', backref=backref('user', lazy=True))
    logs = relationship('Log', backref=backref('user', lazy=True)) 