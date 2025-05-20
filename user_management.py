from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from models import User
from extensions import db

user_mgmt_bp = Blueprint('user_mgmt', __name__)

@user_mgmt_bp.route('/api/users', methods=['GET'])
@jwt_required()
def get_all_users():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Akses ditolak, hanya admin yang dapat melihat data user.'}), 403

    users = User.query.all()
    user_list = []
    for user in users:
        user_list.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'created_at': user.created_at,
            'is_blocked': user.is_blocked,
            'login_is_blocked': user.login_is_blocked
        })
    return jsonify({'users': user_list}), 200

@user_mgmt_bp.route('/api/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def edit_user(user_id):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Akses ditolak, hanya admin yang dapat edit user.'}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User tidak ditemukan'}), 404
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    role = data.get('role')
    is_blocked = data.get('is_blocked')
    if username:
        user.username = username
    if email:
        user.email = email
    if role:
        user.role = role
    if is_blocked is not None:
        user.is_blocked = is_blocked
    db.session.commit()
    return jsonify({'message': 'User berhasil diupdate'}), 200

@user_mgmt_bp.route('/api/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Akses ditolak, hanya admin yang dapat hapus user.'}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User tidak ditemukan'}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User berhasil dihapus'}), 200
