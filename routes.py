from flask import Blueprint, request, send_file, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from encrypt_utils import encrypt_image, decrypt_image
from models import db, EncryptedImage, User
import magic
import io

routes_bp = Blueprint('routes', __name__, url_prefix='/api')

@routes_bp.route('/encrypt', methods=['POST'])
@jwt_required()
def encrypt():
    try:
        file = request.files['file']
        vigenere_key = request.form['key']
        save_option = request.form.get('save', 'false').lower() == 'true'
        user_id = int(get_jwt_identity())

        caesar_shift = sum(bytearray(vigenere_key.encode()))
        image_data = file.read()
        encrypted_data = encrypt_image(image_data, vigenere_key, caesar_shift)

        # Kalau user pilih untuk menyimpan
        if save_option:
            # Cek batas maksimum 5 gambar
            image_count = EncryptedImage.query.filter_by(user_id=user_id).count()
            if image_count >= 5:
                return jsonify({"error": "Maksimal 5 gambar terenkripsi per pengguna"}), 403

            new_image = EncryptedImage(
                filename=file.filename,
                encrypted_data=encrypted_data,
                user_id=user_id
            )
            db.session.add(new_image)
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
        shift = sum(bytearray(key.encode()))
        encrypted_data = file.read()

        decrypted_data = decrypt_image(encrypted_data, key, shift)

        # Cek apakah hasil dekripsi adalah gambar
        mime_type = magic.from_buffer(decrypted_data, mime=True)
        if not mime_type.startswith("image/"):
            return jsonify({"error": "Key salah atau hasil dekripsi bukan gambar"}), 400

        return send_file(
            io.BytesIO(decrypted_data),
            mimetype=mime_type,
            as_attachment=True,
            download_name='decrypted.jpg'
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400
