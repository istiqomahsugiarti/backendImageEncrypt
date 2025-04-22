# encrypt_utils.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import os

def caesar_encrypt(data, shift):
    shift = shift % 256
    return bytes((b + shift) % 256 for b in data)

def caesar_decrypt(data, shift):
    shift = shift % 256
    return bytes((b - shift) % 256 for b in data)

def vigenere_encrypt(data, key):
    key_bytes = key.encode()
    return bytes((data[i] + key_bytes[i % len(key_bytes)]) % 256 for i in range(len(data)))

def vigenere_decrypt(data, key):
    key_bytes = key.encode()
    return bytes((data[i] - key_bytes[i % len(key_bytes)]) % 256 for i in range(len(data)))

def encrypt_image(image_data, vigenere_key, caesar_shift):
    aes_key = os.urandom(16)
    aes_iv = os.urandom(16)

    data = caesar_encrypt(image_data, caesar_shift)
    data = vigenere_encrypt(data, vigenere_key)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    encrypted = cipher.encryptor().update(padded_data) + cipher.encryptor().finalize()

    return aes_key + aes_iv + encrypted  # simpan key & IV di awal

def decrypt_image(encrypted_data, vigenere_key, caesar_shift):
    aes_key = encrypted_data[:16]
    aes_iv = encrypted_data[16:32]
    encrypted_data = encrypted_data[32:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    decrypted = cipher.decryptor().update(encrypted_data) + cipher.decryptor().finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted) + unpadder.finalize()

    data = vigenere_decrypt(data, vigenere_key)
    data = caesar_decrypt(data, caesar_shift)
    return data
