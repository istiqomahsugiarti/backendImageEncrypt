from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from models import db, User, EncryptedImage

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
    if User.query.filter((User.email == email) | (User.username == username)).first():
        return jsonify({'error': 'Username atau email sudah terdaftar'}), 400

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

    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Email atau password salah'}), 401

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={
            "role": user.role,
            "username": user.username
        }
    )

    return jsonify({'token': access_token, 'role': user.role, 'username': user.username, 'user_id': user.id}), 200

@auth_bp.route('/api/user/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
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

@auth_bp.route('/api/user/<int:user_id>/encrypted_images', methods=['GET'])
@jwt_required()
def get_user_encrypted_images(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User tidak ditemukan'}), 404

    encrypted_images = EncryptedImage.query.filter_by(user_id=user_id).all()
    images_data = [{
        'id': image.id,
        'filename': image.filename,
        'created_at': image.created_at
    } for image in encrypted_images]

    return jsonify(images_data), 200
