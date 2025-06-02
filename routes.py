from flask import Blueprint, request, send_file, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from encrypt_utils import encrypt_image, decrypt_image
from models import db, History, User
import filetype
import io
from datetime import datetime, timedelta
from flask import render_template_string
from extensions import mail
from flask_mail import Message

routes_bp = Blueprint('routes', __name__, url_prefix='/api')

# Tambahkan dictionary untuk menyimpan kesalahan dan waktu jeda
failed_attempts_cache = {}

@routes_bp.route('/encrypt', methods=['POST'])
@jwt_required()
def encrypt():
    try:
        file = request.files['file']
        vigenere_key = request.form['key']
        # ➡️ baca mode: basic (default) atau advanced
        method = request.form.get('method', 'basic').lower()
        user_id = int(get_jwt_identity())

        caesar_shift = sum(bytearray(vigenere_key.encode()))
        image_data = file.read()

        # ➡️ oper ke util: sekarang ada arg method
        encrypted_data = encrypt_image(image_data, vigenere_key, caesar_shift, method)

        # simpan history...
        history_entry = History(
            id_user=user_id,
            file_name=file.filename,
            action=f'encrypt-{method}',  # misal simpan 'encrypt-basic' / 'encrypt-advanced'
            key_image=vigenere_key
        )
        db.session.add(history_entry)
        db.session.commit()

        return send_file(
            io.BytesIO(encrypted_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name='encrypted.jpg'
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 400


@routes_bp.route('/decrypt', methods=['POST'])
@jwt_required()
def decrypt():
    try:
        file = request.files["file"]
        key = request.form["key"]
        # ➡️ baca mode juga di decrypt
        method = request.form.get('method', 'basic').lower()
        user_id = int(get_jwt_identity())

        # Ambil user dari database
        user = User.query.get(user_id)

        # cek blokir...
        if user.block_until and user.block_until > datetime.utcnow():
            return jsonify({
                "error": "Akun Anda diblokir sementara karena terlalu banyak kesalahan. Coba lagi nanti.",
                "block_until": user.block_until.strftime("%Y-%m-%d %H:%M:%S")
            }), 403
        
        shift = sum(bytearray(key.encode()))
        encrypted_data = file.read()

        # ➡️ panggil decrypt_image dengan mode
        decrypted_data = decrypt_image(encrypted_data, key, shift, method)

        kind = filetype.guess(decrypted_data)
        
        # Jika gagal dekripsi
        if not kind or not kind.mime.startswith("image/"):
            user.failed_attempts += 1

            # Blokir jika gagal >= 5x
            if user.failed_attempts >= 5:
                user.is_blocked = True
                # Gunakan waktu Indonesia (UTC+7)
                waktu_sekarang = datetime.utcnow() + timedelta(hours=7)
                user.blocked_at = waktu_sekarang
                user.block_until = waktu_sekarang + timedelta(minutes=5)
                user.block_reason = "Terlalu banyak percobaan dekripsi yang gagal"
                
                # Kirim email peringatan
                send_decrypt_warning_email(user.email, user.username)
            
            db.session.commit()
            return jsonify({"error": "Key salah atau hasil dekripsi bukan gambar"}), 400

        # Jika berhasil, reset semua info blokir
        user.failed_attempts = 0
        user.is_blocked = False
        user.blocked_at = None
        user.block_until = None
        user.block_reason = None
        db.session.commit()
        # reset block info, simpan history
        history_entry = History(
            id_user=user_id,
            file_name=file.filename,
            action=f'decrypt-{method}',
            key_image=key
        )
        db.session.add(history_entry)
        db.session.commit()

        return send_file(
            io.BytesIO(decrypted_data),
            mimetype=kind.mime,
            as_attachment=True,
            download_name=f'decrypted-{method}.{kind.extension}'
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 400

def send_decrypt_warning_email(to_email, username="pengguna"):
    logo_url = "https://iili.io/3efgCSn.png"

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
            <h2>Peringatan Keamanan Dekripsi</h2>
            <p>Halo <strong>{{ username }}</strong>,</p>
            <p>Kami mendeteksi beberapa <strong>percobaan dekripsi yang gagal</strong> dari akun Anda.</p>
            <p>Sebagai tindakan pengamanan, sistem kami telah <strong>memblokir akses dekripsi sementara</strong>.</p>
            <p>Silakan coba dekripsi kembali beberapa saat lagi. Jika ini bukan Anda, harap segera hubungi administrator.</p>
            <div class="footer">
                &copy; {{ year }} PIcrypt. Semua hak dilindungi.
            </div>
        </div>
    </body>
    </html>
    ''', username=username, logo_url=logo_url, year=datetime.now().year)

    plain_text = f"""Halo {username},

Kami mendeteksi beberapa percobaan dekripsi yang gagal dari akun Anda.

Sebagai tindakan pengamanan, sistem kami telah memblokir akses dekripsi sementara.
Silakan coba dekripsi kembali beberapa saat lagi.

Salam,
Tim Keamanan PIcrypt
"""

    msg = Message(
        subject='[PIcrypt] Peringatan Blokir Dekripsi',
        recipients=[to_email],
        body=plain_text,
        html=html_content
    )
    mail.send(msg)

@routes_bp.route('/history', methods=['GET'])
@jwt_required()
def view_history():
    try:
        user_id = int(get_jwt_identity())

        # Ambil semua history milik user ini
        histories = History.query.filter_by(id_user=user_id).order_by(History.created_at.desc()).all()

        result = []
        for history in histories:
            result.append({
                "file_name": history.file_name,
                "action": history.action,
                "key_image": history.key_image,
                "created_at": history.created_at.strftime("%Y-%m-%d %H:%M:%S")
            })

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@routes_bp.route('/user-status', methods=['GET'])
@jwt_required()
def check_user_status():
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)

        # Periksa apakah pengguna diblokir dan waktu blokirnya sudah berlalu
        if user.is_blocked and user.block_until and user.block_until <= datetime.utcnow() + timedelta(hours=7):
            # Hapus status blokir
            user.is_blocked = False
            user.blocked_at = None
            user.block_until = None
            user.block_reason = None
            db.session.commit()

        status = "blocked" if user.is_blocked else "active"

        return jsonify({
            "username": user.username,
            "status": status,
            "block_until": user.block_until.strftime("%Y-%m-%d %H:%M:%S")
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400
