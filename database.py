from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
db = SQLAlchemy()
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False) 
class DownloadRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    file_hash = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="Pending")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  

    def __init__(self, username, file_hash, status="Pending", timestamp=None):
        self.username = username
        self.file_hash = file_hash
        self.status = status
        self.timestamp = timestamp or datetime.utcnow()
