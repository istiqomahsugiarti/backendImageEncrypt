from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from models import User, History
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

@user_mgmt_bp.route('/api/users/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_data():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Akses ditolak, hanya admin yang dapat melihat data dashboard.'}), 403
    
    # Mengambil semua user kecuali admin
    users = User.query.filter(User.role != 'admin').all()
    
    # Menghitung total percobaan login dan dekripsi yang gagal
    total_login_failed = sum(user.login_failed_attempts for user in users)
    total_decrypt_failed = sum(user.failed_attempts for user in users)
    
    # Mengambil semua user (non-admin) dan mengurutkan berdasarkan created_at
    users_created = User.query.filter(User.role != 'admin').order_by(User.created_at.desc()).all()
    
    # Membuat list untuk menyimpan data user yang akan direturn
    user_list = []
    for user in users_created:
        user_data = {
            'username': user.username,
            'email': user.email,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        user_list.append(user_data)
    
    # Mengambil total history
    total_history = History.query.count()
    
    return jsonify({
        'total_login_failed': total_login_failed,
        'total_decrypt_failed': total_decrypt_failed,
        'users': user_list,
        'total_users': len(user_list),
        'total_history': total_history
    }), 200
