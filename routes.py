from flask import Blueprint, request, send_file, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from encrypt_utils import encrypt_image, decrypt_image
from models import db, History
import filetype
import io

routes_bp = Blueprint('routes', __name__, url_prefix='/api')

@routes_bp.route('/encrypt', methods=['POST'])
@jwt_required()
def encrypt():
    try:
        file = request.files['file']
        vigenere_key = request.form['key']
        user_id = int(get_jwt_identity())

        caesar_shift = sum(bytearray(vigenere_key.encode()))
        image_data = file.read()
        encrypted_data = encrypt_image(image_data, vigenere_key, caesar_shift)

        # Simpan ke history
        history_entry = History(
            id_user=user_id,
            file_name=file.filename,
            action='encrypt',
            key_image=vigenere_key
        )
        db.session.add(history_entry)
        db.session.commit()

        return send_file(
            io.BytesIO(encrypted_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name='encrypted.img'
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 400


@routes_bp.route('/decrypt', methods=['POST'])
@jwt_required()
def decrypt():
    try:
        file = request.files["file"]
        key = request.form["key"]
        user_id = int(get_jwt_identity())

        shift = sum(bytearray(key.encode()))
        encrypted_data = file.read()

        decrypted_data = decrypt_image(encrypted_data, key, shift)

        # Cek hasil dekripsi valid atau tidak
        kind = filetype.guess(decrypted_data)
        if not kind or not kind.mime.startswith("image/"):
            return jsonify({"error": "Key salah atau hasil dekripsi bukan gambar"}), 400

        # Simpan ke history
        history_entry = History(
            id_user=user_id,
            file_name=file.filename,
            action='decrypt',
            key_image=key
        )
        db.session.add(history_entry)
        db.session.commit()

        return send_file(
            io.BytesIO(decrypted_data),
            mimetype=kind.mime,
            as_attachment=True,
            download_name=f'decrypted.{kind.extension}'
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400

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
