from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from models import Pertanyaan
from extensions import db

faq_bp = Blueprint('faq', __name__)

# Ambil semua FAQ
@faq_bp.route('/api/faq', methods=['GET'])
@jwt_required()
def get_all_faq():
    faqs = Pertanyaan.query.all()
    result = []
    for faq in faqs:
        result.append({
            'id': faq.id,
            'pertanyaan': faq.pertanyaan,
            'jawaban': faq.jawaban
        })
    return jsonify({'faq': result}), 200

# Tambah FAQ
@faq_bp.route('/api/faq', methods=['POST'])
@jwt_required()
def add_faq():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Akses hanya untuk admin'}), 403
    data = request.get_json()
    pertanyaan = data.get('pertanyaan')
    jawaban = data.get('jawaban')
    if not pertanyaan or not jawaban:
        return jsonify({'error': 'Pertanyaan dan jawaban wajib diisi'}), 400
    faq = Pertanyaan(pertanyaan=pertanyaan, jawaban=jawaban)
    db.session.add(faq)
    db.session.commit()
    return jsonify({'message': 'FAQ berhasil ditambahkan'}), 201

# Edit FAQ
@faq_bp.route('/api/faq/<int:faq_id>', methods=['PUT'])
@jwt_required()
def update_faq(faq_id):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Akses hanya untuk admin'}), 403
    data = request.get_json()
    pertanyaan = data.get('pertanyaan')
    jawaban = data.get('jawaban')
    faq = Pertanyaan.query.get(faq_id)
    if not faq:
        return jsonify({'error': 'FAQ tidak ditemukan'}), 404
    if pertanyaan:
        faq.pertanyaan = pertanyaan
    if jawaban:
        faq.jawaban = jawaban
    db.session.commit()
    return jsonify({'message': 'FAQ berhasil diupdate'}), 200

# Hapus FAQ
@faq_bp.route('/api/faq/<int:faq_id>', methods=['DELETE'])
@jwt_required()
def delete_faq(faq_id):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Akses hanya untuk admin'}), 403
    faq = Pertanyaan.query.get(faq_id)
    if not faq:
        return jsonify({'error': 'FAQ tidak ditemukan'}), 404
    db.session.delete(faq)
    db.session.commit()
    return jsonify({'message': 'FAQ berhasil dihapus'}), 200
