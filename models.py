from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from extensions import db

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    role = db.Column(db.Enum('admin', 'user'), default='user', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_blocked    = db.Column(db.Boolean, default=False, nullable=False)
    blocked_at    = db.Column(db.DateTime)
    block_until   = db.Column(db.DateTime)
    block_reason  = db.Column(db.Text)
    failed_attempts = db.Column(db.Integer, default=0)
    
    login_failed_attempts = db.Column(db.Integer, default=0)
    login_blocked_at = db.Column(db.DateTime)
    login_block_until = db.Column(db.DateTime)
    login_is_blocked = db.Column(db.Boolean, default=False)

class History(db.Model):
    __tablename__ = 'history'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_user = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    file_name = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(15), nullable=False)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, nullable=False)
    key_image = db.Column(db.String(100), nullable=True)

class Pertanyaan(db.Model):
    __tablename__ = 'faq'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    pertanyaan = db.Column(db.Text, nullable=False)
    jawaban = db.Column(db.Text, nullable=False)


class OtpRequest(db.Model):
    __tablename__ = 'otp_requests'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user = db.relationship('User', backref=db.backref('otp_requests', lazy=True))

# ───────────────────────────────────────────────────────────────────────────── #