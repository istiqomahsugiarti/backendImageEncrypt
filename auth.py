from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from extensions import db,mail 
from models import User, OtpRequest
from flask import render_template_string
from datetime import datetime, timedelta
from flask_mail import Message
import random

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/api/register', methods=['POST'])

def register():   
    
    
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if not username or not email or not password:
        return jsonify({'error': 'Semua field wajib diisi'}), 400

    # Cek apakah user sudah ada
    if User.query.filter(User.email == email).first():
        return jsonify({'error': 'Email sudah terdaftar'}), 400

    hashed_password = generate_password_hash(password)

    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Registrasi berhasil'}), 201


@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    # Cek apakah email terdaftar
    if not user:
        return jsonify({"error": "Email belum terdaftar, silahkan daftar terlebih dahulu"}), 401

    # 1) Cek apakah sedang diblokir
    if user.login_block_until and user.login_block_until > datetime.utcnow():
        # Konversi waktu UTC ke waktu Indonesia (UTC+7)
        block_until_wib = user.login_block_until
        return jsonify({
            "datetime" : datetime.now(),
            "error": "Akun Anda diblokir sementara karena terlalu banyak percobaan login gagal.",
            "block_until": block_until_wib.strftime("%Y-%m-%d %H:%M:%S")
        }), 403

    # 2) Validasi password
    if not check_password_hash(user.password, password):
        # Jika password salah, naikkan login_failed_attempts
        user.login_failed_attempts += 1

        # aturan blokir: 5x -> 1 menit, 10x -> 5 menit
        if user.login_failed_attempts > 15:
            block_duration = timedelta(hours=1)
        elif user.login_failed_attempts == 15:
            block_duration = timedelta(minutes=15)
        elif user.login_failed_attempts == 10:
            send_warning_email(user.email)
            block_duration = timedelta(minutes=5)
        elif user.login_failed_attempts == 5:
            block_duration = timedelta(minutes=1)
        else:
            block_duration = None

        if block_duration:
            # Simpan waktu dalam UTC+7 (WIB)
            now_wib = datetime.utcnow() + timedelta(hours=7)
            user.login_blocked_at = now_wib
            user.login_block_until = now_wib + block_duration
            user.login_is_blocked = True

        db.session.commit()

        return jsonify({"error": "Password salah, coba lagi"}), 401

    # 3) Jika login sukses, reset semua counter/blokir
    user.login_failed_attempts = 0
    user.login_is_blocked       = False
    user.login_blocked_at       = None
    user.login_block_until      = None
    db.session.commit()

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role, "username": user.username}
    )
    return jsonify({
        'token': access_token,
        'role': user.role,
        'username': user.username,
        'user_email': user.email
    }), 200

@auth_bp.route('/api/login-block-status', methods=['GET'])
def login_block_status():
    email = request.args.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'is_blocked': False, 'block_until': None}), 200

    # auto-reset jika sudah lewat
    now_wib = datetime.utcnow() + timedelta(hours=7)
    if user.login_block_until and user.login_block_until <= now_wib:
        user.login_is_blocked       = False
        user.login_blocked_at       = None
        user.login_block_until      = None
        db.session.commit()

    is_blocked = bool(user.login_block_until and user.login_block_until > now_wib)
    return jsonify({
        'datetime':now_wib,
        'is_blocked': is_blocked,
        'block_until': user.login_block_until.strftime("%Y-%m-%d %H:%M:%S") if user.login_block_until else None,
        'failed_attempts': user.login_failed_attempts
    }), 200

@auth_bp.route('/api/getcurrentuser', methods=['GET'])
@jwt_required()
def get_user():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User tidak ditemukan'}), 404

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'created_at': user.created_at
    }), 200


def send_warning_email(to_email, username="pengguna"):
    logo_url = "https://iili.io/3efgCSn.png"  # Ganti dengan URL logo asli kamu

    html_content = render_template_string('''
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f8f9fa;
                padding: 20px;
                color: #212529;
            }
            .email-container {
                max-width: 600px;
                margin: auto;
                background-color: #ffffff;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 6px rgba(0,0,0,0.05);
            }
            .logo {
                text-align: center;
                margin-bottom: 20px;
            }
            .logo img {
                max-height: 60px;
            }
            h2 {
                color: #d9534f;
                text-align: center;
            }
            p {
                font-size: 16px;
                line-height: 1.6;
            }
            .footer {
                margin-top: 30px;
                font-size: 13px;
                color: #6c757d;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="logo">
                <img src="{{ logo_url }}" alt="PIcrypt Logo">
            </div>
            <h2>Peringatan Keamanan Akun</h2>
            <p>Halo <strong>{{ username }}</strong>,</p>
            <p>Kami mendeteksi beberapa <strong>percobaan login yang gagal</strong> dari akun Anda.</p>
            <p>Sebagai tindakan pengamanan, sistem kami telah <strong>memblokir login sementara</strong>.</p>
            <p>Silakan coba login kembali beberapa saat lagi. Jika ini bukan Anda, harap segera ubah kata sandi setelah berhasil login.</p>
            <div class="footer">
                &copy; {{ year }} PIcrypt. Semua hak dilindungi.
            </div>
        </div>
    </body>
    </html>
    ''', username=username, logo_url=logo_url, year=datetime.now().year)

    plain_text = f"""Halo {username},

Kami mendeteksi beberapa percobaan login yang gagal dari akun Anda.

Sebagai tindakan pengamanan, sistem kami telah memblokir login sementara.
Silakan coba login kembali beberapa saat lagi.

Salam,
Tim Keamanan PIcrypt
"""

    msg = Message(
        subject='[PIcrypt] Peringatan Blokir Akun',
        recipients=[to_email],
        body=plain_text,
        html=html_content
    )
    mail.send(msg)
    

@auth_bp.route('/api/send-otp', methods=['POST'])
def send_otp():
    """
    Endpoint untuk generate OTP (6 digit) dan simpan di tabel otp_requests.
    Request JSON: { "email": "<email_user>" }
    """
    data = request.get_json() or {}
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email wajib diisi'}), 400

    # Cari user berdasarkan email
    user = User.query.filter_by(email=email).first()
    if not user:
        # Untuk alasan keamanan: meski user tidak ditemukan, 
        # tetap kembalikan 200 agar attacker tidak bisa tau user terdaftar atau tidak.
        return jsonify({'message': 'OTP telah dikirim jika email terdaftar'}), 200

    # 1) Generate OTP 6 digit (string)
    otp_code = f"{random.randint(0, 999999):06d}"
    # 2) Expire waktu 10 menit sejak sekarang (UTC)
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    # 3) Simpan ke tabel otp_requests
    new_otp = OtpRequest(
        user_id = user.id,
        otp_code = otp_code,
        expires_at = expires_at,
        used = False
    )
    db.session.add(new_otp)
    db.session.commit()

    # 4) Siapkan isi email (HTML + Plain)
    html_content = render_template_string('''
    <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; background: #f8f9fa; padding: 20px; }
          .container { background: #fff; padding: 20px; border-radius: 8px; max-width: 600px; margin: auto; }
          h2 { color: #333; }
          .otp-code { font-size: 32px; font-weight: bold; margin: 20px 0; }
          .footer { font-size: 12px; color: #666; margin-top: 30px; text-align: center; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Reset Password Anda</h2>
          <p>Halo <strong>{{ username }}</strong>,</p>
          <p>Anda (atau seseorang) telah meminta untuk mereset kata sandi akun Anda. 
             Gunakan kode OTP di bawah ini untuk melanjutkan proses reset password. 
             Kode ini akan kedaluwarsa dalam <strong>10 menit</strong>:</p>
          <div class="otp-code">{{ otp_code }}</div>
          <p>Jika Anda tidak merasa meminta reset password, silakan abaikan email ini.</p>
          <div class="footer">
            &copy; {{ year }} Aplikasi Anda. Semua hak cipta dilindungi.
          </div>
        </div>
      </body>
    </html>
    ''',
    username=user.username,
    otp_code=otp_code,
    year=datetime.utcnow().year)

    plain_text = f"""
    Reset Password Anda

    Halo {user.username},

    Berikut kode OTP untuk mereset password: {otp_code}

    OTP ini akan kedaluwarsa dalam 10 menit.

    Jika Anda tidak merasa meminta reset password, abaikan pesan ini.
    """

    # 5) Kirim email
    msg = Message(
        subject='[Aplikasi Anda] Kode OTP Reset Password',
        recipients=[email],
        body=plain_text,
        html=html_content
    )
    mail.send(msg)

    return jsonify({'message': 'OTP telah dikirim jika email terdaftar'}), 200


@auth_bp.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    """
    Endpoint untuk verifikasi OTP dan mengganti password.
    Request JSON: 
      {
        "email": "<email_user>",
        "otp": "<kode_otp>",
        "new_password": "<password_baru>"
      }
    """
    data = request.get_json() or {}
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')

    # Validasi input
    if not (email and otp and new_password):
        return jsonify({'error': 'Email, OTP, dan password baru wajib diisi'}), 400

    # 1) Cari user berdasarkan email
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Email atau OTP tidak valid'}), 400

    # 2) Cari record OTP paling baru untuk user ini dengan kode yang cocok, belum expired, dan belum digunakan
    now = datetime.utcnow()
    otp_record = (
        OtpRequest.query
        .filter_by(user_id=user.id, otp_code=otp, used=False)
        .filter(OtpRequest.expires_at >= now)
        .order_by(OtpRequest.created_at.desc())
        .first()
    )

    if not otp_record:
        return jsonify({'error': 'OTP tidak valid atau sudah kedaluwarsa'}), 400

    # 3) Semua valid → hash password baru, simpan ke tabel users
    hashed_pw = generate_password_hash(new_password)
    user.password = hashed_pw

    # 4) Hapus OTP yang sudah digunakan
    db.session.delete(otp_record)

    db.session.commit()
    return jsonify({'message': 'Password berhasil direset'}), 200