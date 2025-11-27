"""
Task 2 – Secure File Exchange Using RSA + AES

Scenario:
Alice wants to send Bob a secret file securely using hybrid encryption (RSA + AES-256).

This script:
- Generates RSA key pair for Bob (public.pem, private.pem)
- Creates or reads alice_message.txt (Alice's plaintext)
- Encrypts the file with AES-256 (encrypted_file.bin)
- Encrypts AES key with Bob's RSA public key (aes_key_encrypted.bin)
- Decrypts AES key with Bob's RSA private key
- Decrypts the file to decrypted_message.txt
- Computes SHA-256 hashes of original and decrypted files and compares them
"""

import os
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend


# -----------------------------
# RSA helper functions (for Bob)
# -----------------------------

def generate_rsa_key_pair():
    """Generate RSA key pair for Bob (2048 bits)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_rsa_keys(private_key, public_key,
                  private_path="private.pem",
                  public_path="public.pem"):
    """Save RSA private and public keys to PEM files."""
    # Private key (PKCS8, no password)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_path, "wb") as f:
        f.write(pem_private)

    # Public key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_path, "wb") as f:
        f.write(pem_public)


def load_rsa_private_key(path="private.pem"):
    with open(path, "rb") as f:
        data = f.read()
    private_key = serialization.load_pem_private_key(
        data,
        password=None,
        backend=default_backend()
    )
    return private_key


def load_rsa_public_key(path="public.pem"):
    with open(path, "rb") as f:
        data = f.read()
    public_key = serialization.load_pem_public_key(
        data,
        backend=default_backend()
    )
    return public_key


# -----------------------------
# AES helper functions (Alice & Bob)
# -----------------------------

def aes_encrypt(plaintext: bytes, key: bytes):
    """
    AES-256-CBC encryption with PKCS7 padding.
    Returns (iv, ciphertext).
    """
    iv = os.urandom(16)  # 16 bytes for AES block size

    # PKCS7 padding
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
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

    # Remove padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


def rsa_encrypt_with_public_key(data: bytes, public_key):
    """Encrypt small data (AES key) using RSA OAEP with SHA-256."""
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
    """Decrypt RSA OAEP with SHA-256."""
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted


def sha256_file(path: str) -> str:
    """Compute SHA-256 hash of a file and return hex string."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# -----------------------------
# Main flow: Alice & Bob
# -----------------------------

def main():
    # -------------------------
    # 1. Bob: Generate RSA key pair
    # -------------------------
    print("[Bob] Generating RSA key pair...")
    private_key, public_key = generate_rsa_key_pair()
    save_rsa_keys(private_key, public_key, private_path="private.pem", public_path="public.pem")
    print("[Bob] Keys saved as private.pem and public.pem")

    # -------------------------
    # 2. Alice: Create plaintext file alice_message.txt
    # -------------------------
    alice_file = "alice_message.txt"
    if not os.path.exists(alice_file):
        with open(alice_file, "w", encoding="utf-8") as f:
            f.write("Hello Bob, this is a secret file from Alice. Never trust, always verify.")
        print(f"[Alice] {alice_file} did not exist, created sample message.")
    else:
        print(f"[Alice] Using existing {alice_file}.")

    # Read Alice's plaintext
    with open(alice_file, "rb") as f:
        alice_plain = f.read()

    # Compute original hash for integrity check
    original_hash = sha256_file(alice_file)
    print(f"[Info] SHA-256 of original file: {original_hash}")

    # -------------------------
    # 3. Alice: Generate AES-256 key and IV
    # -------------------------
    aes_key = os.urandom(32)  # 32 bytes = 256 bits
    print("[Alice] Generated random AES-256 key.")

    # -------------------------
    # 4. Alice: Encrypt file with AES-256
    # -------------------------
    iv, ciphertext = aes_encrypt(alice_plain, aes_key)
    # Store IV + ciphertext together
    with open("encrypted_file.bin", "wb") as f:
        f.write(iv + ciphertext)
    print("[Alice] Encrypted file saved as encrypted_file.bin")

    # -------------------------
    # 5. Alice: Encrypt AES key with Bob's public key
    # -------------------------
    bob_public_key = load_rsa_public_key("public.pem")
    aes_key_encrypted = rsa_encrypt_with_public_key(aes_key, bob_public_key)
    with open("aes_key_encrypted.bin", "wb") as f:
        f.write(aes_key_encrypted)
    print("[Alice] AES key encrypted with Bob's public key and saved as aes_key_encrypted.bin")

    # At this point, Alice would send:
    # - encrypted_file.bin
    # - aes_key_encrypted.bin
    # - IV is already inside encrypted_file.bin (first 16 bytes)

    # -------------------------
    # 6. Bob: Decrypt AES key with RSA private key
    # -------------------------
    bob_private_key = load_rsa_private_key("private.pem")
    with open("aes_key_encrypted.bin", "rb") as f:
        aes_key_encrypted_from_file = f.read()

    aes_key_decrypted = rsa_decrypt_with_private_key(aes_key_encrypted_from_file, bob_private_key)
    print("[Bob] AES key decrypted with RSA private key.")

    # -------------------------
    # 7. Bob: Decrypt file with AES-256 + IV
    # -------------------------
    with open("encrypted_file.bin", "rb") as f:
        data = f.read()
    iv_from_file = data[:16]
    ciphertext_from_file = data[16:]

    decrypted_plain = aes_decrypt(iv_from_file, ciphertext_from_file, aes_key_decrypted)

    # Save decrypted file as decrypted_message.txt
    with open("decrypted_message.txt", "wb") as f:
        f.write(decrypted_plain)
    print("[Bob] Decrypted file saved as decrypted_message.txt")

    # -------------------------
    # 8. Integrity check with SHA-256
    # -------------------------
    decrypted_hash = sha256_file("decrypted_message.txt")
    print(f"[Info] SHA-256 of decrypted file: {decrypted_hash}")

    if original_hash == decrypted_hash:
        print("[Result] Integrity check PASSED: hashes match.")
    else:
        print("[Result] Integrity check FAILED: hashes do NOT match.")


if __name__ == "__main__":
    main()
