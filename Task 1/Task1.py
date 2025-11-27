"""
Mini Encrypted Messaging App
Task 1 – RSA + AES-256

Requirements:
- User A generates RSA key pair and shares public key.
- User B encrypts message with AES-256 and encrypts AES key with RSA.
- User A decrypts AES key with RSA private key and then decrypts the message.
"""

import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend


# -----------------------------
# Helper functions
# -----------------------------

def generate_rsa_key_pair():
    """
    Generate RSA key pair for User A.
    Returns (private_key, public_key) objects.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_rsa_keys(private_key, public_key,
                  private_path="rsa_private_key.pem",
                  public_path="rsa_public_key.pem"):
    """
    Save RSA private and public keys to PEM files.
    """
    # Private key (PEM, PKCS8, no password)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_path, "wb") as f:
        f.write(pem_private)

    # Public key (PEM, SubjectPublicKeyInfo)
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_path, "wb") as f:
        f.write(pem_public)


def load_rsa_private_key(path="rsa_private_key.pem"):
    with open(path, "rb") as f:
        data = f.read()
    private_key = serialization.load_pem_private_key(
        data,
        password=None,
        backend=default_backend()
    )
    return private_key


def load_rsa_public_key(path="rsa_public_key.pem"):
    with open(path, "rb") as f:
        data = f.read()
    public_key = serialization.load_pem_public_key(
        data,
        backend=default_backend()
    )
    return public_key


def aes_encrypt(plaintext: bytes, key: bytes):
    """
    AES-256-CBC encryption with PKCS7 padding.
    Returns (iv, ciphertext).
    """
    # 16 bytes IV for AES block size
    iv = os.urandom(16)

    # Add PKCS7 padding
    padder = sym_padding.PKCS7(128).padder()  # 128 bit block size
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv, ciphertext


def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes):
    """
    AES-256-CBC decryption with PKCS7 unpadding.
    Returns plaintext bytes.
    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


def rsa_encrypt_with_public_key(data: bytes, public_key):
    """
    Encrypt small data (AES key) using RSA OAEP with SHA-256.
    """
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def rsa_decrypt_with_private_key(ciphertext: bytes, private_key):
    """
    Decrypt RSA OAEP with SHA-256.
    """
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted


# -----------------------------
# Main flow (A + B in one script)
# -----------------------------

def main():
    # -------------------------
    # User A: generate RSA keys
    # -------------------------
    print("[User A] Generating RSA key pair...")
    private_key, public_key = generate_rsa_key_pair()
    save_rsa_keys(private_key, public_key)
    print("[User A] RSA keys saved as rsa_private_key.pem and rsa_public_key.pem")

    # -------------------------
    # Prepare message.txt
    # -------------------------
    message_file = "message.txt"
    if not os.path.exists(message_file):
        # Create a default message file if not present
        with open(message_file, "w", encoding="utf-8") as f:
            f.write("Never trust, always verify. This is a secret message.")
        print(f"[Info] {message_file} did not exist, created a sample one.")

    with open(message_file, "r", encoding="utf-8") as f:
        message = f.read().encode("utf-8")  # convert to bytes

    print(f"[User B] Loaded message from {message_file}.")

    # -------------------------
    # User B: AES-256 encryption
    # -------------------------
    # 32 bytes = 256 bits
    aes_key = os.urandom(32)
    print("[User B] Generated random AES-256 key.")

    iv, ciphertext = aes_encrypt(message, aes_key)
    # Save IV + ciphertext in one file: first 16 bytes are IV, rest is ciphertext
    with open("encrypted_message.bin", "wb") as f:
        f.write(iv + ciphertext)
    print("[User B] Encrypted message saved to encrypted_message.bin")

    # -------------------------
    # User B: RSA encrypt AES key with User A's public key
    # -------------------------
    user_a_public_key = load_rsa_public_key("rsa_public_key.pem")
    aes_key_encrypted = rsa_encrypt_with_public_key(aes_key, user_a_public_key)
    with open("aes_key_encrypted.bin", "wb") as f:
        f.write(aes_key_encrypted)
    print("[User B] AES key encrypted with User A's public RSA key and saved to aes_key_encrypted.bin")

    # -------------------------
    # User A: decrypt AES key using private RSA key
    # -------------------------
    user_a_private_key = load_rsa_private_key("rsa_private_key.pem")
    with open("aes_key_encrypted.bin", "rb") as f:
        aes_key_encrypted_from_file = f.read()

    aes_key_decrypted = rsa_decrypt_with_private_key(aes_key_encrypted_from_file, user_a_private_key)
    print("[User A] AES key decrypted using RSA private key.")

    # -------------------------
    # User A: decrypt message using decrypted AES key
    # -------------------------
    with open("encrypted_message.bin", "rb") as f:
        data = f.read()
    iv_from_file = data[:16]
    ciphertext_from_file = data[16:]

    decrypted_message = aes_decrypt(iv_from_file, ciphertext_from_file, aes_key_decrypted)
    with open("decrypted_message.txt", "w", encoding="utf-8") as f:
        f.write(decrypted_message.decode("utf-8"))

    print("[User A] Message decrypted and saved to decrypted_message.txt")
    print("Done.")


if __name__ == "__main__":
    main()
