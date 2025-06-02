from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

### 🔐 —————————— CAESAR —————————— 🔐

def caesar_encrypt(data: bytes, shift: int) -> bytes:
    return bytes((b + shift) % 256 for b in data)

def caesar_decrypt(data: bytes, shift: int) -> bytes:
    return bytes((b - shift) % 256 for b in data)


### 🔐 —————————— VIGENÈRE —————————— 🔐

def vigenere_encrypt(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    return bytes((b + key_bytes[i % len(key_bytes)]) % 256 for i, b in enumerate(data))

def vigenere_decrypt(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    return bytes((b - key_bytes[i % len(key_bytes)]) % 256 for i, b in enumerate(data))


### 🔐 —————————— AES-CBC —————————— 🔐

def aes_cbc_encrypt(data: bytes) -> tuple[bytes, bytes, bytes]:
    key = os.urandom(16)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encrypted = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    return key, iv, encrypted

def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decrypted = cipher.decryptor().update(data) + cipher.decryptor().finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted) + unpadder.finalize()


### 🔐 —————————— AES-GCM —————————— 🔐

def aes_gcm_encrypt(data: bytes) -> tuple[bytes, bytes, bytes]:
    key = os.urandom(16)
    nonce = os.urandom(12)

    aesgcm = aead.AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, data, None)

    return key, nonce, encrypted

def aes_gcm_decrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    aesgcm = aead.AESGCM(key)
    return aesgcm.decrypt(nonce, data, None)


### 🚀 —————————— HIGH-LEVEL ENCRYPT / DECRYPT —————————— 🚀

def encrypt_basic(image_data: bytes, vigenere_key: str, caesar_shift: int) -> bytes:
    step1 = caesar_encrypt(image_data, caesar_shift)
    step2 = vigenere_encrypt(step1, vigenere_key)
    aes_key, aes_iv, encrypted = aes_cbc_encrypt(step2)
    return aes_key + aes_iv + encrypted

def decrypt_basic(encrypted_data: bytes, vigenere_key: str, caesar_shift: int) -> bytes:
    aes_key = encrypted_data[:16]
    aes_iv = encrypted_data[16:32]
    encrypted = encrypted_data[32:]

    decrypted_aes = aes_cbc_decrypt(aes_key, aes_iv, encrypted)
    step1 = vigenere_decrypt(decrypted_aes, vigenere_key)
    step2 = caesar_decrypt(step1, caesar_shift)
    return step2


def encrypt_advanced(image_data: bytes, vigenere_key: str, caesar_shift: int) -> bytes:
    basic = encrypt_basic(image_data, vigenere_key, caesar_shift)
    gcm_key, nonce, encrypted = aes_gcm_encrypt(basic)
    return gcm_key + nonce + encrypted

def decrypt_advanced(encrypted_data: bytes, vigenere_key: str, caesar_shift: int) -> bytes:
    gcm_key = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    encrypted = encrypted_data[28:]

    decrypted_basic = aes_gcm_decrypt(gcm_key, nonce, encrypted)
    return decrypt_basic(decrypted_basic, vigenere_key, caesar_shift)


### 📦 —————————— ROUTER —————————— 📦

def encrypt_image(image_data, vigenere_key, caesar_shift, method='basic'):
    if method == 'advanced':
        return encrypt_advanced(image_data, vigenere_key, caesar_shift)
    return encrypt_basic(image_data, vigenere_key, caesar_shift)

def decrypt_image(encrypted_data, vigenere_key, caesar_shift, method='basic'):
    if method == 'advanced':
        return decrypt_advanced(encrypted_data, vigenere_key, caesar_shift)
    return decrypt_basic(encrypted_data, vigenere_key, caesar_shift) 