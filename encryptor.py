# Author: Raisa Methila
"""
encryptor.py — Minimal AES-GCM file encrypt/decrypt CLI with PBKDF2 key derivation.

Usage:
  Encrypt: python encryptor.py encrypt -i secret.pdf -o secret.enc
  Decrypt: python encryptor.py decrypt -i secret.enc -o secret.pdf
"""

import argparse
import getpass
import os
import sys
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b"ENC1"           # file signature + format version
SALT_LEN = 16             # 128-bit salt for PBKDF2
NONCE_LEN = 12            # 96-bit nonce for AES-GCM
KEY_LEN = 32              # 256-bit AES key
PBKDF2_ITERS = 200_000    # For local CLI; (adjustable)
CHUNK_SIZE = 1024 * 1024  # 1 MB (read file fully for AESGCM; kept for future streaming)

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(password)

def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def write_file(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)

def encrypt_file(in_path: str, out_path: str, password: bytes, aad: bytes = None) -> None:
    plaintext = read_file(in_path)
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    # File format: MAGIC | SALT | NONCE | CIPHERTEXT+TAG
    blob = MAGIC + salt + nonce + ciphertext
    write_file(out_path, blob)

def parse_header(blob: bytes) -> Tuple[bytes, bytes, bytes]:
    if len(blob) < len(MAGIC) + SALT_LEN + NONCE_LEN + 16:
        raise ValueError("Corrupted or too-short encrypted file.")
    magic = blob[:len(MAGIC)]
    if magic != MAGIC:
        raise ValueError("Unrecognized file format (bad magic).")
    salt_start = len(MAGIC)
    salt_end = salt_start + SALT_LEN
    nonce_end = salt_end + NONCE_LEN
    salt = blob[salt_start:salt_end]
    nonce = blob[salt_end:nonce_end]
    ciphertext = blob[nonce_end:]
    if len(ciphertext) < 16:
        raise ValueError("Ciphertext too short (missing GCM tag).")
    return salt, nonce, ciphertext

def decrypt_file(in_path: str, out_path: str, password: bytes, aad: bytes = None) -> None:
    blob = read_file(in_path)
    salt, nonce, ciphertext = parse_header(blob)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    write_file(out_path, plaintext)

def ask_password(confirm: bool = False) -> bytes:
    pwd = getpass.getpass("Password: ").encode("utf-8")
    if confirm:
        again = getpass.getpass("Confirm password: ").encode("utf-8")
        if pwd != again:
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(2)
    if len(pwd) == 0:
        print("Empty passwords are not allowed.", file=sys.stderr)
        sys.exit(2)
    return pwd

def main():
    parser = argparse.ArgumentParser(
        description="Encrypt/Decrypt files with AES-256-GCM using PBKDF2-HMAC-SHA256."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("-i", "--input", required=True, help="Path to input file")
    p_enc.add_argument("-o", "--output", required=True, help="Path to output .enc file")
    p_enc.add_argument("--aad", help="Optional associated data (binds metadata)")

    p_dec = sub.add_parser("decrypt", help="Decrypt a file")
    p_dec.add_argument("-i", "--input", required=True, help="Path to input .enc file")
    p_dec.add_argument("-o", "--output", required=True, help="Path to decrypted output file")
    p_dec.add_argument("--aad", help="Associated data used during encryption (must match)")

    args = parser.parse_args()

    try:
        if args.cmd == "encrypt":
            password = ask_password(confirm=True)
            aad = args.aad.encode("utf-8") if args.aad else None
            encrypt_file(args.input, args.output, password, aad)
            print(f"✅ Encrypted '{args.input}' → '{args.output}'")
        elif args.cmd == "decrypt":
            password = ask_password(confirm=False)
            aad = args.aad.encode("utf-8") if args.aad else None
            decrypt_file(args.input, args.output, password, aad)
            print(f"✅ Decrypted '{args.input}' → '{args.output}'")
        else:
            parser.print_help()
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
